import argparse
from datetime import datetime
from ipaddress import IPv4Network
import queue
import tkinter as tk
from tkinter import messagebox, ttk

from scapy.all import conf, get_if_addr

from .bootp import ServerConfig
from .network import Workbench


class Application:
    def __init__(self, root, oui_file=None):
        self.root = root
        self.oui_file = oui_file
        self.worker = None
        self.events = queue.Queue(maxsize=4096)
        self.closing = False
        root.title("Workbench Device Discovery — EtherNet/IP")
        root.geometry("1200x620")
        root.protocol("WM_DELETE_WINDOW", self.close)
        panel = ttk.Frame(root, padding=10)
        panel.pack(fill="both", expand=True)
        interfaces = list(conf.ifaces.values())
        self.interfaces = {f"{item.name} — {item.description}": item
                           for item in interfaces}
        self.adapter = tk.StringVar()
        self.subnet = tk.StringVar(value="192.168.1.0/24")
        self.first = tk.StringVar(value="192.168.1.100")
        self.last = tk.StringVar(value="192.168.1.150")
        self.target = tk.StringVar()
        self.serve = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Select a wired adapter, then start before powering the device.")
        ttk.Label(panel, text="Adapter").grid(row=0, column=0, sticky="w")
        self.adapter_box = ttk.Combobox(
            panel, textvariable=self.adapter, values=list(self.interfaces),
            state="readonly", width=60)
        self.adapter_box.grid(row=0, column=1, columnspan=3, sticky="ew")
        self.adapter_box.bind("<<ComboboxSelected>>", self.select_adapter)
        self.start_button = ttk.Button(panel, text="Start listening", command=self.start)
        self.start_button.grid(row=0, column=4, padx=5)
        self.stop_button = ttk.Button(panel, text="Stop", command=self.stop, state="disabled")
        self.stop_button.grid(row=0, column=5)
        fields = [("Scan / service subnet", self.subnet),
                  ("Pool start", self.first), ("Pool end", self.last)]
        self.config_widgets = [self.adapter_box]
        for column, (label, variable) in enumerate(fields):
            ttk.Label(panel, text=label).grid(row=1, column=column * 2, sticky="w", pady=8)
            entry = ttk.Entry(panel, textvariable=variable, width=20)
            entry.grid(row=1, column=column * 2 + 1, sticky="ew")
            self.config_widgets.append(entry)
        self.service_box = ttk.Checkbutton(
            panel, text="Enable BOOTP + DHCP (isolated switch ONLY)", variable=self.serve)
        self.service_box.grid(row=2, column=0, columnspan=4, sticky="w")
        self.config_widgets.append(self.service_box)
        ttk.Label(panel, text="Known IPv4 (blank = subnet scan)").grid(
            row=3, column=0, columnspan=2, sticky="w", pady=8)
        ttk.Entry(panel, textvariable=self.target).grid(row=3, column=2, sticky="ew")
        self.scan_button = ttk.Button(panel, text="Probe EIP + ARP", command=self.probe,
                                      state="disabled")
        self.scan_button.grid(row=3, column=3, padx=5)
        ttk.Label(
            panel, text="Observed IP ≠ requested/offered IP. Off-subnet devices may need a laptop "
                        "IP alias before probing.\nA completely silent device cannot be guaranteed "
                        "discoverable; boot broadcasts must reach this switch port.",
            wraplength=1100).grid(row=4, column=0, columnspan=6, sticky="w", pady=8)
        columns = ("mac", "ip", "candidate", "manufacturer", "protocol", "identity", "seen")
        self.table = ttk.Treeview(panel, columns=columns, show="headings")
        titles = ("MAC", "Observed IP", "Unconfirmed address", "Manufacturer (OUI)",
                  "Evidence", "EIP identity", "Last seen")
        widths = (140, 125, 190, 175, 130, 260, 85)
        for column, title, width in zip(columns, titles, widths):
            self.table.heading(column, text=title)
            self.table.column(column, width=width)
        self.table.grid(row=5, column=0, columnspan=6, sticky="nsew")
        scroll = ttk.Scrollbar(panel, orient="vertical", command=self.table.yview)
        scroll.grid(row=5, column=6, sticky="ns")
        horizontal = ttk.Scrollbar(panel, orient="horizontal", command=self.table.xview)
        horizontal.grid(row=6, column=0, columnspan=6, sticky="ew")
        self.table.configure(yscrollcommand=scroll.set, xscrollcommand=horizontal.set)
        ttk.Label(panel, textvariable=self.status, wraplength=1100).grid(
            row=7, column=0, columnspan=6, sticky="w", pady=10)
        panel.rowconfigure(5, weight=1)
        for column in range(6):
            panel.columnconfigure(column, weight=1)
        if self.interfaces:
            preferred = next((label for label, item in self.interfaces.items()
                              if item == conf.iface), next(iter(self.interfaces)))
            self.adapter.set(preferred)
            self.select_adapter()
        root.after(100, self.poll)

    def select_adapter(self, event=None):
        interface = self.interfaces.get(self.adapter.get())
        if interface:
            ip = get_if_addr(interface)
            if ip != "0.0.0.0":
                subnet = IPv4Network(f"{ip}/24", strict=False)
                self.subnet.set(str(subnet))
                self.first.set(str(subnet.network_address + 100))
                self.last.set(str(subnet.network_address + 150))
            self.status.set(f"Adapter IPv4: {ip}. Check subnet and pool before starting.")

    def start(self):
        try:
            interface = self.interfaces[self.adapter.get()]
            config = None
            if self.serve.get():
                config = ServerConfig(get_if_addr(interface), self.subnet.get(),
                                      self.first.get(), self.last.get())
                config.validate()
                if not messagebox.askyesno(
                    "Address assignment",
                    "Use only on an authorized isolated switch with NO other DHCP/BOOTP "
                    "server. This may change device addresses. Continue?"):
                    return
            self.worker = Workbench(interface, self.events, config, self.oui_file)
        except (ValueError, KeyError, OSError) as error:
            messagebox.showerror("Cannot start", str(error))
            return
        self.table.delete(*self.table.get_children())
        for widget in self.config_widgets:
            widget.configure(state="disabled")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status.set("Opening packet capture…")
        self.worker.start()

    def stop(self):
        if self.worker:
            self.status.set("Stopping…")
            self.worker.stop()
            self.stop_button.configure(state="disabled")
            self.scan_button.configure(state="disabled")

    def probe(self):
        if self.worker:
            try:
                self.worker.probe(self.target.get().strip(), self.subnet.get().strip())
                self.status.set("Probe queued…")
            except ValueError as error:
                messagebox.showerror("Cannot probe", str(error))

    def poll(self):
        for _ in range(500):
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "device":
                *values, timestamp = value
                values.append(datetime.fromtimestamp(timestamp).strftime("%H:%M:%S"))
                if self.table.exists(values[0]):
                    self.table.item(values[0], values=values)
                else:
                    self.table.insert("", "end", iid=values[0], values=values)
            elif kind in ("status", "error"):
                self.status.set(value)
                if kind == "status" and value.startswith("Listening"):
                    self.scan_button.configure(state="normal")
                if kind == "error" and not self.closing:
                    messagebox.showerror(
                        "Network error", value + "\nCheck capture permissions / Npcap.")
            elif kind == "stopped":
                self.worker = None
                if self.closing:
                    self.root.destroy()
                    return
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
                self.scan_button.configure(state="disabled")
                for widget in self.config_widgets:
                    widget.configure(state="normal")
                self.adapter_box.configure(state="readonly")
        self.root.after(100, self.poll)

    def close(self):
        self.closing = True
        if self.worker:
            self.stop()
        else:
            self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description="Offline EtherNet/IP workbench discovery")
    parser.add_argument("--oui-file", help="Optional local Wireshark-format manuf database")
    args = parser.parse_args()
    root = tk.Tk()
    Application(root, args.oui_file)
    root.mainloop()
