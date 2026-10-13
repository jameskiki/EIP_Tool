import argparse
import ctypes
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from scapy.all import conf, get_if_addr

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    __package__ = "eip_tool"

from .bootp import ServerConfig
from .device_io import DeviceIOTestDialog
from .discovery import usable_ip
from .interface_address import (
    add_temporary_ipv4_alias, find_ready_adapter_address, remove_temporary_ipv4_alias,
)
from .network import Workbench
from .xport_config import (
    apply_static_xport_address, set_bootp_mode, validate_static_parameters,
)


def _is_windows_admin():
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def _relaunch_as_admin():
    parameters = subprocess.list2cmdline(["-m", "eip_tool", *sys.argv[1:]])
    workspace = str(Path(__file__).resolve().parent.parent)
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, parameters, workspace, 1)
    return result > 32


def ensure_windows_admin():
    if os.name != "nt" or _is_windows_admin():
        return True
    if not _relaunch_as_admin():
        ctypes.windll.user32.MessageBoxW(
            None, "Administrator access is required for this tool.", "EIP Tool", 0x10)
    return False


class XPortConfigurationGuide:
    ACTIONS = ("Assign IP via BOOTP", "Set static IPv4", "Enable BOOTP", "Disable BOOTP")

    def __init__(self, root, mac, observed_ip, interface, adapter_ip, network,
                 evidence="", reserve_ip=None, add_adapter_alias=None,
                 remove_adapter_alias=None, find_adapter_address=None):
        self.root = root
        self.mac = mac
        self.observed_ip = observed_ip
        self.interface = interface
        self.adapter_ip = adapter_ip
        self.network = network
        self.evidence = evidence
        self.reserve_ip = reserve_ip
        self.add_adapter_alias = add_adapter_alias
        self.remove_adapter_alias = remove_adapter_alias
        self.find_adapter_address = find_adapter_address
        self.original_adapter_ip = adapter_ip
        self.original_network = network
        self.adapter_aliases = []
        self.window = tk.Toplevel(root)
        self.window.title("XPort EtherNet/IP configuration")
        self.window.transient(root)
        self.window.resizable(False, False)
        panel = ttk.Frame(self.window, padding=12)
        panel.pack(fill="both", expand=True)

        ttk.Label(panel, text=f"Device MAC: {mac}").grid(row=0, column=0, sticky="w")
        self.ip_label = tk.StringVar(value=f"Observed IPv4: {observed_ip or 'not observed'}")
        ttk.Label(panel, textvariable=self.ip_label).grid(
            row=1, column=0, sticky="w", pady=(0, 8))
        ttk.Label(panel, text="Operation").grid(row=2, column=0, sticky="w")
        default_action = self.ACTIONS[1] if usable_ip(observed_ip) else self.ACTIONS[0]
        self.action = tk.StringVar(value=default_action)
        self.action_box = ttk.Combobox(
            panel, textvariable=self.action, values=self.ACTIONS, state="readonly", width=28)
        self.action_box.grid(row=2, column=1, sticky="w", padx=8)
        self.action_box.bind("<<ComboboxSelected>>", self.update_instructions)

        address_frame = ttk.Frame(panel)
        address_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=8)
        self.static_values = {
            "IPv4 address": tk.StringVar(),
            "Subnet mask": tk.StringVar(value="255.255.255.0"),
            "Gateway (optional)": tk.StringVar(),
        }
        self.static_entries = []
        for column, (label, variable) in enumerate(self.static_values.items()):
            ttk.Label(address_frame, text=label).grid(row=0, column=column, sticky="w")
            entry = ttk.Entry(address_frame, textvariable=variable, width=18)
            entry.grid(row=1, column=column, sticky="ew", padx=(0, 8))
            self.static_entries.append(entry)

        self.instructions = tk.StringVar()
        ttk.Label(panel, textvariable=self.instructions, wraplength=590, justify="left").grid(
            row=4, column=0, columnspan=2, sticky="w", pady=8)
        ttk.Label(
            panel,
              text="Network changes can interrupt this connection. The app writes CIP TCP/IP "
                  "settings directly; verify the address after the device restarts.",
            wraplength=590, justify="left").grid(
                row=5, column=0, columnspan=2, sticky="w", pady=(0, 8))
        self.access_hint = tk.StringVar(value=self._access_hint())
        ttk.Label(panel, textvariable=self.access_hint, wraplength=590, justify="left").grid(
            row=6, column=0, columnspan=2, sticky="w")
        self.status = tk.StringVar()
        ttk.Label(panel, textvariable=self.status).grid(
            row=7, column=0, columnspan=2, sticky="w")
        buttons = ttk.Frame(panel)
        buttons.grid(row=8, column=0, columnspan=2, sticky="e", pady=(8, 0))
        self.alias_button = ttk.Button(
            buttons, text="Add laptop IP alias", command=self.toggle_adapter_alias,
            state="disabled")
        self.alias_button.pack(side="left", padx=(0, 8))
        self.apply_button = ttk.Button(
            buttons, text="Apply", command=self.apply_selected_operation,
            state="disabled")
        self.apply_button.pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="Close", command=self.close).pack(side="left")
        self.window.protocol("WM_DELETE_WINDOW", self.close)
        self.events = queue.Queue()
        self._poll_job = self.root.after(50, self._poll_events)
        self.update_instructions()

    def _poll_events(self):
        try:
            if not hasattr(self, "window") or not self.window.winfo_exists():
                self._poll_job = None
                return
            while True:
                try:
                    kind, payload = self.events.get_nowait()
                except queue.Empty:
                    break
                if kind == "error":
                    self._apply_failed(payload)
                elif kind == "success":
                    action, address = payload
                    self._apply_succeeded(action, address)
            if self._poll_job is not None:
                try:
                    self.root.after_cancel(self._poll_job)
                except tk.TclError:
                    pass
            self._poll_job = self.root.after(50, self._poll_events)
        except tk.TclError:
            self._poll_job = None

    def _access_hint(self):
        if usable_ip(self.observed_ip):
            return "EtherNet/IP configuration is available at the observed address."
        if "BOOTP" in self.evidence or "DHCP" in self.evidence:
            return ("No IP observed, but this device sent a BOOTP/DHCP request. Assign an IP to "
                    "this MAC and restart it while the responder is listening.")
        return ("No IP or BOOTP request observed. Assigning by BOOTP requires a device request; "
                "a silent, unaddressed device needs its hardware/vendor recovery method.")

    def update_instructions(self, event=None):
        action = self.action.get()
        if action == "Assign IP via BOOTP":
            message = (
                "Choose an unused address in the service subnet. The app will reserve it for "
                "this MAC, start its BOOTP responder, then wait for the device to request an IP. "
                "Power-cycle the device after the responder is listening.")
        elif action == "Set static IPv4":
            message = (
                "First selects stored/static startup mode, then writes the IP address, mask, and "
                "gateway to the EtherNet/IP TCP/IP Interface Object. For a new subnet, the app "
                "adds a temporary laptop address for readback verification.")
        elif action == "Enable BOOTP":
            message = (
                "Selects BOOTP at startup through the EtherNet/IP TCP/IP Interface Object. "
                "Start a BOOTP responder before power-cycling; an offer alone is not confirmation.")
        else:
            message = (
                "Selects the stored network configuration at startup. Use Set static IPv4 to "
                "change the saved address, then power-cycle and verify the result.")
        self.instructions.set(message)
        alias_available = self.add_adapter_alias is not None and usable_ip(self.observed_ip)
        if alias_available and not self.adapter_aliases:
            try:
                alias_available = IPv4Address(self.observed_ip) not in IPv4Network(
                    self.network, strict=False)
            except ValueError:
                alias_available = False
        if self.adapter_aliases:
            self.alias_button.configure(text="Remove laptop IP alias", state="normal")
        else:
            self.alias_button.configure(
                text="Add laptop IP alias", state="normal" if alias_available else "disabled")
        for entry in self.static_entries:
            entry.configure(state="normal" if action in
                            ("Assign IP via BOOTP", "Set static IPv4") else "disabled")
        labels = {
            "Assign IP via BOOTP": "Start BOOTP assignment",
            "Set static IPv4": "Apply static IPv4",
            "Enable BOOTP": "Enable BOOTP",
            "Disable BOOTP": "Disable BOOTP",
        }
        can_apply = ((action == "Assign IP via BOOTP" and usable_ip(self.adapter_ip))
                     or (action != "Assign IP via BOOTP" and usable_ip(self.observed_ip)))
        self.apply_button.configure(
            text=labels[action], state="normal" if can_apply else "disabled")

    def _suggest_alias(self, network_ip, netmask):
        target_network = IPv4Network(f"{network_ip}/{netmask}", strict=False)
        current_network = IPv4Network(self.original_network, strict=False)
        if IPv4Address(self.original_adapter_ip) in current_network:
            host_offset = int(IPv4Address(self.original_adapter_ip)) - int(
                current_network.network_address)
        else:
            host_offset = 20
        candidate = target_network.network_address + host_offset
        if candidate in (target_network.network_address, target_network.broadcast_address,
                         IPv4Address(network_ip)):
            candidate = target_network.network_address + 1
            if candidate == IPv4Address(network_ip):
                candidate += 1
        return str(candidate)

    def toggle_adapter_alias(self):
        if self.adapter_aliases:
            if not self.remove_adapter_alias:
                messagebox.showerror(
                    "Cannot remove laptop IP alias", "The alias cleanup action is unavailable.")
                return
            failed = []
            for alias_ip, netmask in reversed(self.adapter_aliases):
                try:
                    self.remove_adapter_alias(self.interface, alias_ip, netmask)
                except (ValueError, RuntimeError, OSError) as error:
                    failed.append((alias_ip, netmask))
                    messagebox.showerror("Could not remove laptop IP alias", str(error))
            self.adapter_aliases = list(reversed(failed))
            if self.adapter_aliases:
                return
            self.adapter_ip = self.original_adapter_ip
            self.network = self.original_network
            self.access_hint.set("Temporary laptop IP alias removed; original address remains.")
            self.update_instructions()
            return
        if not self.add_adapter_alias or not usable_ip(self.observed_ip):
            return
        try:
            default_mask = str(IPv4Network(self.original_network, strict=False).netmask)
            default_ip = self._suggest_alias(self.observed_ip, default_mask)
        except ValueError as error:
            messagebox.showerror("Cannot suggest laptop address", str(error))
            return
        alias_ip = simpledialog.askstring(
            "Temporary laptop IP alias",
            f"Enter an unused laptop IPv4 address in the subnet containing {self.observed_ip}.",
            initialvalue=default_ip, parent=self.window)
        if not alias_ip:
            return
        netmask = simpledialog.askstring(
            "Temporary laptop IP alias", "Subnet mask for the device network:",
            initialvalue=default_mask, parent=self.window)
        if not netmask:
            return
        if not messagebox.askyesno(
                "Add temporary laptop address",
                f"Add {alias_ip} as a secondary address on this adapter? The existing IP, "
                "gateway, and DNS settings will be preserved.", parent=self.window):
            return
        try:
            network = self.add_adapter_alias(
                self.interface, self.observed_ip, self.original_adapter_ip,
                alias_ip.strip(), netmask.strip())
        except (ValueError, RuntimeError, OSError) as error:
            messagebox.showerror("Could not add laptop IP alias", str(error))
            return
        self.adapter_ip = alias_ip.strip()
        self.network = str(network)
        self.adapter_aliases.append((alias_ip.strip(), netmask.strip()))
        self.access_hint.set(
            f"Temporary adapter address {self.adapter_ip} added. Original address preserved.")
        self.update_instructions()

    def _ensure_static_destination_alias(self, address, netmask):
        target_network = IPv4Network(f"{address}/{netmask}", strict=False)
        if (IPv4Address(self.adapter_ip) in target_network
                and IPv4Network(self.network, strict=False) == target_network):
            return True
        if self.find_adapter_address:
            try:
                existing_ip = self.find_adapter_address(self.interface, target_network)
            except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
                messagebox.showerror("Could not inspect laptop addresses", str(error))
                return False
            if existing_ip and existing_ip != address:
                self.adapter_ip = existing_ip
                self.network = str(target_network)
                self.access_hint.set(f"Using existing laptop address {existing_ip} for verification.")
                return True
        for alias_ip, _ in self.adapter_aliases:
            if IPv4Address(alias_ip) in target_network:
                self.adapter_ip = alias_ip
                self.network = str(target_network)
                return True
        if not self.add_adapter_alias:
            messagebox.showerror(
                "Laptop address required",
                "Add a temporary laptop IP alias in the new device subnet before applying.")
            return False
        try:
            default_ip = self._suggest_alias(address, netmask)
        except ValueError as error:
            messagebox.showerror("Cannot suggest laptop address", str(error))
            return False
        alias_ip = simpledialog.askstring(
            "Laptop address for new subnet",
            f"Enter an unused laptop address in {target_network} for readback verification.",
            initialvalue=default_ip, parent=self.window)
        if not alias_ip:
            return False
        if not messagebox.askyesno(
                "Add temporary laptop address",
                f"Add {alias_ip} to this adapter before changing the device? The existing "
                "address, gateway, and DNS settings will be preserved.", parent=self.window):
            return False
        try:
            network = self.add_adapter_alias(
                self.interface, address, self.original_adapter_ip,
                alias_ip.strip(), netmask)
        except (ValueError, RuntimeError, OSError) as error:
            messagebox.showerror("Could not add laptop IP alias", str(error))
            return False
        self.adapter_aliases.append((alias_ip.strip(), netmask))
        self.adapter_ip = alias_ip.strip()
        self.network = str(network)
        self.access_hint.set(
            f"Temporary address {self.adapter_ip} added for verification in the new subnet.")
        self.update_instructions()
        return True

    def close(self):
        if self._poll_job is not None:
            try:
                self.root.after_cancel(self._poll_job)
            except tk.TclError:
                pass
            self._poll_job = None
        if self.adapter_aliases:
            self.toggle_adapter_alias()
            if self.adapter_aliases:
                return
        try:
            self.window.destroy()
        except tk.TclError:
            pass

    def apply_selected_operation(self):
        action = self.action.get()
        address = self.static_values["IPv4 address"].get().strip()
        netmask = self.static_values["Subnet mask"].get().strip()
        gateway = self.static_values["Gateway (optional)"].get().strip()
        if action == "Assign IP via BOOTP":
            if not self.reserve_ip:
                messagebox.showerror("Cannot start BOOTP", "The reservation workflow is unavailable.")
                return
            if not address:
                messagebox.showerror("Invalid reservation", "Enter the IPv4 address to reserve.")
                return
            self.apply_button.configure(state="disabled")
            self.status.set("Starting the BOOTP responder for this MAC…")
            if self.reserve_ip(self.mac, address):
                self.close()
            else:
                self.apply_button.configure(state="normal")
            return
        if not usable_ip(self.observed_ip):
            messagebox.showerror("No observed IP", "Use a BOOTP tool to assign an IP, then rescan the device.")
            return
        if action == "Set static IPv4":
            try:
                validate_static_parameters(
                    self.adapter_ip, self.network, address, netmask, gateway, self.mac)
            except ValueError as error:
                messagebox.showerror("Invalid static settings", str(error))
                return
            prompt = (f"Save {address} to XPort {self.mac} with the supplied mask/gateway? "
                      "The device may disconnect as its IP changes.")
        else:
            mode = "enable" if action == "Enable BOOTP" else "disable"
            prompt = f"{mode.capitalize()} BOOTP startup on XPort {self.mac}?"
        if not messagebox.askyesno(action, prompt):
            return
        if (action == "Set static IPv4"
                and not self._ensure_static_destination_alias(address, netmask)):
            return
        self.apply_button.configure(state="disabled")
        self.status.set(f"Applying {action} through EtherNet/IP...")
        threading.Thread(
            target=self._apply_operation_worker,
            args=(action, address, netmask, gateway), daemon=True).start()

    def _apply_operation_worker(self, action, address, netmask, gateway):
        try:
            if action == "Set static IPv4":
                apply_static_xport_address(
                    self.interface, self.adapter_ip, self.network, self.mac,
                    self.observed_ip, address, netmask, gateway)
            else:
                set_bootp_mode(self.observed_ip, enable=action == "Enable BOOTP")
        except Exception as error:
            print(f"XPort EtherNet/IP configuration failed: {error}", file=sys.stderr, flush=True)
            self.events.put(("error", str(error)))
        else:
            self.events.put(("success", (action, address)))

    def _apply_failed(self, error):
        try:
            if not self.window.winfo_exists():
                return
            self.apply_button.configure(state="normal")
            self.status.set("Device did not confirm the requested EtherNet/IP configuration.")
            messagebox.showerror("Configuration not applied", str(error), parent=self.window)
        except tk.TclError:
            pass

    def _apply_succeeded(self, action, address):
        try:
            if not self.window.winfo_exists():
                return
            if action == "Set static IPv4":
                self.observed_ip = address
                self.ip_label.set(f"Configured IPv4: {address} (rediscovery pending)")
                self.access_hint.set("Static settings were acknowledged via EtherNet/IP. Rescan to verify traffic.")
            elif action == "Enable BOOTP":
                self.access_hint.set("BOOTP mode enabled. Power-cycle while a BOOTP responder is listening.")
            else:
                self.access_hint.set("BOOTP mode disabled. Power-cycle to verify the stored address remains.")
            self.status.set(f"{action} acknowledged by the device.")
            self.update_instructions()
        except tk.TclError:
            pass


class Application:
    def __init__(self, root, oui_file=None):
        self.root = root
        self.oui_file = oui_file
        self.worker = None
        self.reservation = None
        self.adapter_aliases = []
        self.events = queue.Queue(maxsize=4096)
        self.closing = False
        root.title("Workbench Device Discovery — EtherNet/IP")
        root.geometry("1200x700")
        root.protocol("WM_DELETE_WINDOW", self.close)
        panel = ttk.Frame(root, padding=10)
        panel.pack(fill="both", expand=True)
        interfaces = list(conf.ifaces.values())
        self.interfaces = {f"{item.name} — {item.description}": item
                           for item in interfaces}
        self.adapter = tk.StringVar()
        self.subnet = tk.StringVar(value="192.168.1.0/24")
        self.service_subnet = tk.StringVar(value="192.168.1.0/24")
        self.first = tk.StringVar(value="192.168.1.100")
        self.last = tk.StringVar(value="192.168.1.150")
        self.eip_targets = tk.StringVar()
        self.arp_targets = tk.StringVar()
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
        self.config_widgets: list[ttk.Combobox | ttk.Entry | ttk.Checkbutton] = [self.adapter_box]
        service_frame = ttk.LabelFrame(panel, text="BOOTP/DHCP service", padding=6)
        service_frame.grid(row=1, column=0, columnspan=6, sticky="ew", pady=6)
        self.service_box = ttk.Checkbutton(
            service_frame, text="Enable (isolated switch ONLY)", variable=self.serve)
        self.service_box.grid(row=0, column=0, columnspan=2, sticky="w")
        self.config_widgets.append(self.service_box)
        self.service_entries = []
        for index, (label, variable) in enumerate((
                ("Service subnet", self.service_subnet),
                ("Pool start", self.first), ("Pool end", self.last))):
            column = 2 + index * 2
            ttk.Label(service_frame, text=label).grid(
                row=0, column=column, sticky="w", padx=(8, 2))
            entry = ttk.Entry(service_frame, textvariable=variable, width=16)
            entry.grid(row=0, column=column + 1, sticky="ew")
            self.service_entries.append(entry)
            self.config_widgets.append(entry)
        ttk.Label(panel, text="Default scan subnet").grid(row=2, column=0, sticky="w", pady=6)
        self.subnet_entry = ttk.Entry(panel, textvariable=self.subnet, width=18)
        self.subnet_entry.grid(row=2, column=1, sticky="ew")
        self.config_widgets.append(self.subnet_entry)
        self.factory_alias_button = ttk.Button(
            panel, text="Add factory alias...", command=self.add_factory_alias)
        self.factory_alias_button.grid(row=2, column=2, padx=4)
        self.alias_cleanup_button = ttk.Button(
            panel, text="Remove laptop alias...", command=self.remove_selected_adapter_alias,
            state="disabled")
        self.alias_cleanup_button.grid(row=2, column=3, padx=4)
        self.configure_button = ttk.Button(
            panel, text="Configure selected", command=self.configure_selected, state="disabled")
        self.configure_button.grid(row=2, column=4, padx=4)
        self.test_io_button = ttk.Button(
            panel, text="Test device I/O", command=self.test_selected_io, state="disabled")
        self.test_io_button.grid(row=2, column=5, padx=4)
        eip_frame = ttk.LabelFrame(panel, text="EtherNet/IP", padding=6)
        eip_frame.grid(row=3, column=0, columnspan=3, sticky="ew", padx=(0, 4))
        self.broadcast_button = ttk.Button(
            eip_frame, text="Broadcast", command=self.probe_eip_broadcast, state="disabled")
        self.broadcast_button.grid(row=0, column=0, padx=(0, 6))
        ttk.Label(eip_frame, text="Targets").grid(row=0, column=1, sticky="w")
        self.eip_target_entry = ttk.Entry(eip_frame, textvariable=self.eip_targets)
        self.eip_target_entry.grid(row=0, column=2, sticky="ew", padx=4)
        self.targeted_button = ttk.Button(
            eip_frame, text="Targeted scan", command=self.probe_eip_targeted, state="disabled")
        self.targeted_button.grid(row=0, column=3)
        eip_frame.columnconfigure(2, weight=1)
        arp_frame = ttk.LabelFrame(panel, text="Other discovery", padding=6)
        arp_frame.grid(row=3, column=3, columnspan=3, sticky="ew", padx=(4, 0))
        ttk.Label(arp_frame, text="ARP targets").grid(row=0, column=0, sticky="w")
        self.arp_target_entry = ttk.Entry(arp_frame, textvariable=self.arp_targets)
        self.arp_target_entry.grid(row=0, column=1, sticky="ew", padx=4)
        self.arp_button = ttk.Button(
            arp_frame, text="ARP scan", command=self.probe_arp_scan, state="disabled")
        self.arp_button.grid(row=0, column=2, padx=(0, 6))
        self.xport_button = ttk.Button(
            arp_frame, text="XPort discovery", command=self.probe_xport, state="disabled")
        self.xport_button.grid(row=0, column=3)
        arp_frame.columnconfigure(1, weight=1)
        ttk.Label(panel, text="Targets accept IP, CIDR, or ranges; blank uses the default scan subnet.").grid(
            row=4, column=0, columnspan=6, sticky="w", pady=(4, 0))
        ttk.Label(panel, text="Start listening → choose a probe → select a device → Configure selected.").grid(
            row=5, column=0, columnspan=6, sticky="w", pady=(2, 6))
        self.probe_buttons = (
            self.broadcast_button, self.targeted_button, self.arp_button, self.xport_button)
        columns = ("mac", "ip", "candidate", "manufacturer", "protocol", "identity",
               "ip_history", "first_seen", "seen")
        self.table = ttk.Treeview(panel, columns=columns, show="headings")
        titles = ("MAC", "Latest observed IP", "Unconfirmed address", "Manufacturer (OUI)",
              "Evidence", "EIP identity", "Observed IP history", "First seen", "Last seen")
        widths = (140, 140, 190, 175, 130, 260, 260, 155, 155)
        for column, title, width in zip(columns, titles, widths):
            self.table.heading(column, text=title)
            self.table.column(column, width=width)
        self.table.grid(row=6, column=0, columnspan=6, sticky="nsew")
        self.table.bind("<<TreeviewSelect>>", self.update_configuration_button)
        scroll = ttk.Scrollbar(panel, orient="vertical", command=self.table.yview)
        scroll.grid(row=6, column=6, sticky="ns")
        horizontal = ttk.Scrollbar(panel, orient="horizontal", command=self.table.xview)
        horizontal.grid(row=7, column=0, columnspan=6, sticky="ew")
        self.table.configure(yscrollcommand=scroll.set, xscrollcommand=horizontal.set)
        ttk.Label(panel, textvariable=self.status, wraplength=1100).grid(
            row=8, column=0, columnspan=6, sticky="w", pady=10)
        panel.rowconfigure(6, weight=1)
        for column in range(6):
            panel.columnconfigure(column, weight=1)
        if self.interfaces:
            preferred = next((label for label, item in self.interfaces.items()
                              if item == conf.iface), next(iter(self.interfaces)))
            self.adapter.set(preferred)
            self.select_adapter()
        root.after(100, self.poll)

    def select_adapter(self, event=None):
        if event is not None and self.reservation:
            self.reservation = None
            self.serve.set(False)
        interface = self.interfaces.get(self.adapter.get())
        if interface:
            ip = get_if_addr(interface)
            if ip != "0.0.0.0":
                subnet = IPv4Network(f"{ip}/24", strict=False)
                self.subnet.set(str(subnet))
                self.service_subnet.set(str(subnet))
                self.first.set(str(subnet.network_address + 100))
                self.last.set(str(subnet.network_address + 150))
            self.status.set(f"Adapter IPv4: {ip}. Check subnet and pool before starting.")
        self._refresh_alias_cleanup_button()

    def _adapter_ipv4_addresses(self, interface):
        if os.name == "nt":
            result = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "addresses",
                 f"name={interface.name}"],
                capture_output=True, text=True, timeout=10, check=False)
            if result.returncode == 0:
                addresses = re.findall(
                    r"^\s*IP(?:-Adresse| Address):\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$",
                    result.stdout, flags=re.IGNORECASE | re.MULTILINE)
                if addresses:
                    return addresses[0], addresses[1:]
        primary = get_if_addr(interface)
        addresses = list(getattr(interface, "ips", {}).get(4, []))
        if primary not in addresses and usable_ip(primary):
            addresses.insert(0, primary)
        return primary, [str(address) for address in addresses if address != primary]

    def _refresh_alias_cleanup_button(self):
        interface = self.interfaces.get(self.adapter.get())
        if not interface:
            self.alias_cleanup_button.configure(state="disabled")
            return
        try:
            _, secondary = self._adapter_ipv4_addresses(interface)
        except (OSError, subprocess.TimeoutExpired):
            secondary = []
        has_tracked_alias = any(name == interface.name
                                for name, _, _ in self.adapter_aliases)
        self.alias_cleanup_button.configure(
            state="normal" if secondary or has_tracked_alias else "disabled")

    def start(self):
        try:
            interface = self.interfaces[self.adapter.get()]
            if self.reservation and not self.serve.get():
                if not messagebox.askyesno(
                        "Discard BOOTP reservation?",
                        "Starting without the BOOTP/DHCP service will discard the selected-MAC "
                        "reservation, which is stored only in memory. Continue in passive mode?"):
                    return False
                self.reservation = None
            config = None
            if self.serve.get():
                config = ServerConfig(get_if_addr(interface), self.service_subnet.get(),
                                      self.first.get(), self.last.get(),
                                      reservation_mac=self.reservation[0] if self.reservation else "",
                                      reservation_ip=self.reservation[1] if self.reservation else "")
                config.validate()
                if not messagebox.askyesno(
                    "Address assignment",
                    "Use only on an authorized isolated switch with NO other DHCP/BOOTP "
                    "server. This may change device addresses. Continue?"):
                    return False
            self.worker = Workbench(interface, self.events, config, self.oui_file)
        except (ValueError, KeyError, OSError) as error:
            messagebox.showerror("Cannot start", str(error))
            return False
        self.table.delete(*self.table.get_children())
        self.configure_button.configure(state="disabled")
        self.test_io_button.configure(state="disabled")
        for widget in self.config_widgets:
            widget.configure(state="disabled")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status.set("Opening packet capture…")
        self.worker.start()
        return True

    def stop(self):
        if self.worker:
            self.status.set("Stopping…")
            self.worker.stop()
            self.stop_button.configure(state="disabled")
            for button in self.probe_buttons:
                button.configure(state="disabled")

    def _queue_probe(self, callback, *args):
        if self.worker:
            try:
                callback(*args)
                self.status.set("Probe queued…")
            except ValueError as error:
                messagebox.showerror("Cannot probe", str(error))

    def probe_eip_broadcast(self):
        if self.worker:
            self._queue_probe(self.worker.eip_broadcast)

    def probe_eip_targeted(self):
        if self.worker:
            self._queue_probe(
                self.worker.eip_targeted,
                self.eip_targets.get().strip(), self.subnet.get().strip())

    def probe_arp_scan(self):
        if self.worker:
            self._queue_probe(
                self.worker.arp_scan,
                self.arp_targets.get().strip(), self.subnet.get().strip())

    def probe_xport(self):
        if self.worker:
            self._queue_probe(self.worker.xport_discovery)

    def update_configuration_button(self, event=None):
        state = "normal" if self.table.selection() else "disabled"
        self.configure_button.configure(state=state)
        self.test_io_button.configure(state=state)

    def test_selected_io(self):
        selection = self.table.selection()
        if not selection:
            return
        values = self.table.item(selection[0], "values")
        mac = values[0]
        ip = values[1]
        identity = values[5] if len(values) > 5 else ""
        if not ip or not usable_ip(ip):
            messagebox.showerror(
                "No observed IP",
                "The selected device does not have an observed IP address yet.\n"
                "Assign or discover an IP address before testing I/O.", parent=self.root)
            return
        DeviceIOTestDialog(self.root, mac, ip, identity)

    def reserve_selected_ip(self, mac, address):
        if self.worker:
            messagebox.showerror("Stop listening first", "Stop the current session before creating a reservation.")
            return False
        interface = self.interfaces.get(self.adapter.get())
        if not interface:
            return False
        address = address.strip()
        try:
            config = ServerConfig(
                get_if_addr(interface), self.service_subnet.get(), self.first.get(), self.last.get(),
                reservation_mac=mac, reservation_ip=address)
            config.validate()
        except ValueError as error:
            messagebox.showerror("Invalid reservation", str(error))
            return False
        self.reservation = (mac, address)
        self.serve.set(True)
        return self.start()

    def configure_selected(self):
        selection = self.table.selection()
        if not selection:
            return
        values = self.table.item(selection[0], "values")
        interface = self.interfaces.get(self.adapter.get())
        if not interface:
            return
        XPortConfigurationGuide(
            self.root, values[0], values[1], interface, get_if_addr(interface),
            self.subnet.get(), values[4], self.reserve_selected_ip,
            self.add_adapter_alias, self.remove_adapter_alias,
            find_adapter_address=find_ready_adapter_address)

    def add_factory_alias(self):
        interface = self.interfaces.get(self.adapter.get())
        if not interface:
            return
        factory_network = IPv4Network("192.168.0.0/24")
        try:
            existing = find_ready_adapter_address(interface, factory_network)
            if existing:
                self.status.set(f"Factory subnet already available through {existing}.")
                return
            current_ip = get_if_addr(interface)
            host_number = int(IPv4Address(current_ip)) & 255 if usable_ip(current_ip) else 20
            if host_number in (0, 255):
                host_number = 20
            alias_ip = simpledialog.askstring(
                "Factory subnet laptop address",
                "Enter a known-free laptop address in 192.168.0.0/24 (not the device's IP):",
                initialvalue=f"192.168.0.{host_number}", parent=self.root)
            if not alias_ip:
                return
            alias_ip = str(IPv4Address(alias_ip.strip()))
            if IPv4Address(alias_ip) not in factory_network:
                raise ValueError("The factory alias must be in 192.168.0.0/24.")
            if not messagebox.askyesno(
                    "Add factory subnet alias?",
                    f"Add temporary address {alias_ip}/24 to {interface.name}? "
                    "Existing addresses remain unchanged. Use only on the isolated switch.",
                    parent=self.root):
                return
            reference_ip = "192.168.0.1" if alias_ip != "192.168.0.1" else "192.168.0.2"
            self.add_adapter_alias(
                interface, reference_ip, current_ip, alias_ip, "255.255.255.0")
            self.status.set(f"Factory subnet alias {alias_ip}/24 is ready.")
        except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired) as error:
            messagebox.showerror("Could not add factory alias", str(error))

    def add_adapter_alias(self, interface, observed_ip, current_ip, alias_ip, netmask):
        interface_name = interface.name
        network = add_temporary_ipv4_alias(
            interface_name, observed_ip, current_ip, alias_ip, netmask)
        alias = (interface_name, alias_ip, netmask)
        if alias not in self.adapter_aliases:
            self.adapter_aliases.append(alias)
        self._refresh_alias_cleanup_button()
        return network

    def remove_adapter_alias(self, interface, alias_ip, netmask):
        interface_name = interface.name
        remove_temporary_ipv4_alias(interface_name, alias_ip, netmask)
        alias = (interface_name, alias_ip, netmask)
        if alias in self.adapter_aliases:
            self.adapter_aliases.remove(alias)
        self._refresh_alias_cleanup_button()

    def remove_selected_adapter_alias(self):
        interface = self.interfaces.get(self.adapter.get())
        if not interface:
            return
        try:
            primary, secondary = self._adapter_ipv4_addresses(interface)
        except (OSError, subprocess.TimeoutExpired) as error:
            messagebox.showerror("Could not inspect adapter addresses", str(error))
            return
        masks = {address: netmask for name, address, netmask in self.adapter_aliases
                 if name == interface.name}
        candidates = sorted(
            set(secondary) | set(masks), key=lambda address: int(IPv4Address(address)))
        if not candidates:
            self._refresh_alias_cleanup_button()
            return
        address = simpledialog.askstring(
            "Remove laptop IP alias",
            f"Secondary addresses on {interface.name}: {', '.join(candidates)}\n"
            "Enter the exact temporary alias to remove. The first adapter address is kept.",
            initialvalue=candidates[0], parent=self.root)
        if not address:
            return
        try:
            address = str(IPv4Address(address.strip()))
        except ValueError:
            messagebox.showerror("Invalid alias", "Enter a valid IPv4 address.")
            return
        if address not in candidates:
            messagebox.showerror("Not a secondary alias", "Choose one of the listed secondary addresses.")
            return
        if not messagebox.askyesno(
                "Remove laptop IP alias?",
                f"Remove {address} from {interface.name}? The first adapter address "
                f"({primary}) will be kept.", parent=self.root):
            return
        netmask = masks.get(address, "255.255.255.0")
        if address not in masks and sys.platform != "win32":
            try:
                default_mask = str(IPv4Network(self.subnet.get(), strict=False).netmask)
            except ValueError:
                default_mask = "255.255.255.0"
            netmask = simpledialog.askstring(
                "Alias subnet mask", f"Enter the subnet mask for {address}:",
                initialvalue=default_mask, parent=self.root)
            if not netmask:
                return
        try:
            remove_temporary_ipv4_alias(interface.name, address, netmask)
        except (ValueError, RuntimeError, OSError) as error:
            messagebox.showerror("Could not remove laptop IP alias", str(error))
            return
        self.adapter_aliases = [
            alias for alias in self.adapter_aliases
            if (alias[0], alias[1]) != (interface.name, address)]
        self.status.set(f"Removed temporary laptop address {address}.")
        self._refresh_alias_cleanup_button()

    def _restore_adapter_aliases(self):
        errors = []
        remaining = []
        for interface, address, netmask in reversed(self.adapter_aliases):
            try:
                remove_temporary_ipv4_alias(interface, address, netmask)
            except (ValueError, RuntimeError, OSError) as error:
                errors.append(f"{address} on {interface}: {error}")
                remaining.append((interface, address, netmask))
        self.adapter_aliases = list(reversed(remaining))
        self._refresh_alias_cleanup_button()
        if errors:
            messagebox.showwarning(
                "Laptop address cleanup incomplete",
                "Remove these temporary adapter addresses manually:\n" + "\n".join(errors),
                parent=self.root)

    def poll(self):
        for _ in range(500):
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "device":
                *values, first_seen, last_seen = value
                values.extend(datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                              for timestamp in (first_seen, last_seen))
                if self.table.exists(values[0]):
                    self.table.item(values[0], values=values)
                else:
                    self.table.insert("", "end", iid=values[0], values=values)
            elif kind in ("status", "error"):
                self.status.set(value)
                if kind == "status" and value.startswith("Listening"):
                    for button in self.probe_buttons:
                        button.configure(state="normal")
                if kind == "error" and not self.closing:
                    messagebox.showerror(
                        "Network error", value + "\nCheck capture permissions / Npcap.")
            elif kind == "assignment_confirmed":
                mac, address = value
                self.status.set(f"Confirmed: {mac} sent traffic from {address}.")
            elif kind == "stopped":
                self.worker = None
                if self.closing:
                    self._restore_adapter_aliases()
                    self.root.destroy()
                    return
                self.start_button.configure(state="normal")
                self.stop_button.configure(state="disabled")
                for button in self.probe_buttons:
                    button.configure(state="disabled")
                for widget in self.config_widgets:
                    widget.configure(state="normal")
                self.adapter_box.configure(state="readonly")
                self.update_configuration_button()
        self.root.after(100, self.poll)

    def close(self):
        self.closing = True
        if self.worker:
            self.stop()
        else:
            self._restore_adapter_aliases()
            self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description="Offline EtherNet/IP workbench discovery")
    parser.add_argument("--oui-file", help="Optional local Wireshark-format manuf database")
    args = parser.parse_args()
    if not ensure_windows_admin():
        return
    root = tk.Tk()
    Application(root, args.oui_file)
    root.mainloop()


if __name__ == "__main__":
    main()
