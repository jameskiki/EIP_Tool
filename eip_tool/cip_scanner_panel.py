"""CIP Scanner tab: runs cip_scanner in a worker thread and shows a class/instance/attribute tree."""

import csv
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from .cip_scanner import (
    CIPScanError, ScanOptions, class_name, parse_class_ranges, scan_device,
)

RAW_PREVIEW_BYTES = 48


class CIPScannerPanel:
    def __init__(self, parent, root, get_target, open_in_device_io):
        """get_target() -> (mac, ip, identity) or None; open_in_device_io(target, cls, inst, attr)."""
        self.root = root
        self.get_target = get_target
        self.open_in_device_io = open_in_device_io
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.scanning = False
        self.target = None
        self.rows = []
        self.paths = {}

        controls = ttk.Frame(parent)
        controls.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.scan_button = ttk.Button(
            controls, text="Scan selected device", command=self.start, state="disabled")
        self.scan_button.pack(side="left")
        self.stop_button = ttk.Button(
            controls, text="Stop", command=self.stop, state="disabled")
        self.stop_button.pack(side="left", padx=6)
        ttk.Label(controls, text="Classes").pack(side="left", padx=(12, 2))
        self.classes = tk.StringVar(value="0x01-0xFF")
        ttk.Entry(controls, textvariable=self.classes, width=22).pack(side="left")
        self.use_router = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            controls, text="Message Router list", variable=self.use_router).pack(
                side="left", padx=(8, 0))
        ttk.Label(controls, text="Max instance").pack(side="left", padx=(12, 2))
        self.instance_limit = tk.StringVar(value="200")
        ttk.Spinbox(controls, from_=1, to=65535, textvariable=self.instance_limit,
                    width=6).pack(side="left")
        ttk.Label(controls, text="Max attribute").pack(side="left", padx=(12, 2))
        self.attribute_limit = tk.StringVar(value="32")
        ttk.Spinbox(controls, from_=1, to=255, textvariable=self.attribute_limit,
                    width=5).pack(side="left")

        progress_row = ttk.Frame(parent)
        progress_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=4)
        self.progress = ttk.Progressbar(progress_row, length=180, maximum=1)
        self.progress.pack(side="left")
        self.status = tk.StringVar(
            value="Read-only scan (Get_Attribute_Single). Select a device with an observed IP.")
        ttk.Label(progress_row, textvariable=self.status).pack(side="left", padx=8)

        self.tree = ttk.Treeview(
            parent, columns=("name", "status", "size", "value", "raw"), show="tree headings")
        self.tree.heading("#0", text="Class / Instance / Attribute")
        self.tree.column("#0", width=230, minwidth=120, stretch=False)
        for column, title, width, stretch in (
                ("name", "Name", 170, False), ("status", "Status", 150, False),
                ("size", "Bytes", 50, False), ("value", "Decoded value", 330, True),
                ("raw", "Raw (hex)", 260, False)):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, minwidth=40, stretch=stretch)
        self.tree.grid(row=2, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        scroll.grid(row=2, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.bind("<<TreeviewSelect>>", self._update_actions)
        self.tree.bind("<Double-1>", lambda event: self.send_to_device_io())

        actions = ttk.Frame(parent)
        actions.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        self.io_button = ttk.Button(
            actions, text="Open in Device I/O", command=self.send_to_device_io, state="disabled")
        self.io_button.pack(side="left")
        self.export_button = ttk.Button(
            actions, text="Export CSV...", command=self.export_csv, state="disabled")
        self.export_button.pack(side="left", padx=6)
        ttk.Label(actions, text="Double-click an attribute to read/write it in Device I/O.").pack(
            side="left", padx=8)
        parent.rowconfigure(2, weight=1)
        parent.columnconfigure(0, weight=1)

    def set_target_available(self, available):
        self.scan_button.configure(
            state="normal" if available and not self.scanning else "disabled")

    def _limits(self):
        try:
            classes = parse_class_ranges(self.classes.get())
            instance_limit = int(self.instance_limit.get())
            attribute_limit = int(self.attribute_limit.get())
        except ValueError as error:
            raise ValueError(str(error) or "Limits must be whole numbers.") from error
        if not (1 <= instance_limit <= 65535 and 1 <= attribute_limit <= 255):
            raise ValueError("Max instance must be 1-65535 and max attribute 1-255.")
        if not classes and not self.use_router.get():
            raise ValueError("Enter a class range or enable the Message Router list.")
        return ScanOptions(classes, self.use_router.get(), instance_limit, attribute_limit)

    def start(self):
        target = self.get_target()
        if self.scanning or target is None:
            return
        try:
            options = self._limits()
        except ValueError as error:
            messagebox.showerror("Invalid scan settings", str(error), parent=self.root)
            return
        self.target = target
        self.tree.delete(*self.tree.get_children())
        self.rows, self.paths = [], {}
        self.stop_event = threading.Event()
        self.scanning = True
        self.scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.export_button.configure(state="disabled")
        self.progress.configure(value=0, maximum=1)
        self.status.set(f"Connecting to {target[1]}...")
        threading.Thread(
            target=self._worker, args=(target[1], options, self.stop_event, self.events),
            daemon=True).start()
        self.root.after(50, self._poll)

    def stop(self):
        self.stop_event.set()
        self.stop_button.configure(state="disabled")
        self.status.set("Stopping after the current request...")

    def close(self):
        self.stop_event.set()

    @staticmethod
    def _worker(address, options, stop_event, events):
        def progress(message, done=None, total=None):
            events.put(("progress", (message, done, total)))
        try:
            for result in scan_device(address, options, progress, stop_event):
                events.put(("class", result))
        except (CIPScanError, ValueError) as error:
            events.put(("error", str(error)))
        events.put(("done", None))

    def _poll(self):
        try:
            while True:
                try:
                    kind, payload = self.events.get_nowait()
                except queue.Empty:
                    break
                if kind == "progress":
                    message, done, total = payload
                    self.status.set(message)
                    if total:
                        self.progress.configure(maximum=total, value=done)
                elif kind == "class":
                    self._insert_class(payload)
                elif kind == "error":
                    self.status.set(f"Scan aborted: {payload}")
                    messagebox.showerror("CIP scan failed", payload, parent=self.root)
                elif kind == "done":
                    self._finished()
                    return
            self.root.after(50, self._poll)
        except tk.TclError:
            pass

    def _finished(self):
        self.scanning = False
        self.stop_button.configure(state="disabled")
        self.scan_button.configure(state="normal" if self.get_target() else "disabled")
        self.export_button.configure(state="normal" if self.rows else "disabled")
        classes = len(self.tree.get_children())
        self.status.set(f"{self.status.get()}  Found {classes} class(es).")

    def _insert_class(self, result):
        label = f"{result.class_code:#06x} {result.name}"
        node = self.tree.insert(
            "", "end", text=label, open=True,
            values=("", f"via {result.source}", "", "; ".join(result.notes), ""))
        if result.class_attributes:
            class_node = self.tree.insert(
                node, "end", text="Class attributes (instance 0)", open=False)
            for item in result.class_attributes:
                self._insert_attribute(class_node, item)
        for instance in result.instances:
            instance_node = self.tree.insert(
                node, "end", text=f"Instance {instance.instance}",
                open=len(result.instances) <= 4,
                values=("", "", "", f"{sum(a.readable for a in instance.attributes)} readable "
                                    f"attribute(s)", ""))
            for item in instance.attributes:
                self._insert_attribute(instance_node, item)

    def _insert_attribute(self, parent, item):
        raw = item.data[:RAW_PREVIEW_BYTES].hex(" ")
        if len(item.data) > RAW_PREVIEW_BYTES:
            raw += " ..."
        iid = self.tree.insert(
            parent, "end", text=f"Attribute {item.attribute}",
            values=(item.name, "OK" if item.readable else f"{item.status:#04x}",
                    len(item.data) if item.readable else "", item.value, raw))
        self.paths[iid] = (item.class_code, item.instance, item.attribute)
        self.rows.append(item)

    def _update_actions(self, event=None):
        selection = self.tree.selection()
        self.io_button.configure(
            state="normal" if selection and selection[0] in self.paths else "disabled")

    def send_to_device_io(self):
        selection = self.tree.selection()
        if not selection or selection[0] not in self.paths or self.target is None:
            return
        self.open_in_device_io(self.target, *self.paths[selection[0]])

    def export_csv(self):
        path = filedialog.asksaveasfilename(
            parent=self.root, defaultextension=".csv", filetypes=[("CSV", "*.csv")],
            initialfile=f"cip_scan_{self.target[1].replace('.', '_')}.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as handle:
                writer = csv.writer(handle)
                writer.writerow(("device_mac", "device_ip", "class", "class_name", "instance",
                                 "attribute", "attribute_name", "status", "bytes", "value", "raw_hex"))
                for item in self.rows:
                    writer.writerow((
                        self.target[0], self.target[1], f"{item.class_code:#06x}",
                        class_name(item.class_code),
                        item.instance, item.attribute, item.name, f"{item.status:#04x}",
                        len(item.data), item.value, item.data.hex(" ")))
        except OSError as error:
            messagebox.showerror("Export failed", str(error), parent=self.root)
            return
        self.status.set(f"Exported {len(self.rows)} attribute(s) to {path}")
