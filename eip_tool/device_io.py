"""EtherNet/IP CIP Assembly Object data read/write helpers for peripheral testing."""

import queue
import struct
import threading
import time
import tkinter as tk
from datetime import datetime
from ipaddress import IPv4Address
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Optional

from pycomm3 import CIPDriver, Services

from .discovery import usable_ip
from .io_connection import IOConnection, IOConnectionConfig


class CIPDeviceIOError(RuntimeError):
    pass


PRESETS = [
    # VT-015131 CVC 650 EIP
    {
        "name": "VT-015131 CVC 650 EIP — Input (Inst 101) [54 words / 108 bytes]",
        "device": "VT-015131 CVC 650 EIP",
        "class_code": 0x04,
        "instance": 101,
        "attribute": 3,
        "expected_words": 54,
        "expected_bytes": 108,
        "alive_word": 27,
        "description": "VT-015131 CVC 650 EIP: Input 54 words (108 bytes) — Word 27 (bytes 54-55): Alive Counter",
    },
    {
        "name": "VT-015131 CVC 650 EIP — Output (Inst 102) [16 words / 32 bytes]",
        "device": "VT-015131 CVC 650 EIP",
        "class_code": 0x04,
        "instance": 102,
        "attribute": 3,
        "expected_words": 16,
        "expected_bytes": 32,
        "alive_word": None,
        "description": "VT-015131 CVC 650 EIP: Output 16 words (32 bytes)",
    },
    # MAI 114 / 314 Group (identical assembly mapping)
    {
        "name": "VT-016246/016403 MAI 114 / 314 EIP — Input (Inst 101) [8 words / 16 bytes]",
        "device": "MAI 114 / 314 EIP",
        "class_code": 0x04,
        "instance": 101,
        "attribute": 3,
        "expected_words": 8,
        "expected_bytes": 16,
        "alive_word": 7,
        "description": "MAI 114 / 314 EIP: Input 8 words (16 bytes) — Word 7 (bytes 14-15): Alive Counter",
    },
    {
        "name": "VT-016246/016403 MAI 114 / 314 EIP — Output (Inst 102) [6 words / 12 bytes]",
        "device": "MAI 114 / 314 EIP",
        "class_code": 0x04,
        "instance": 102,
        "attribute": 3,
        "expected_words": 6,
        "expected_bytes": 12,
        "alive_word": None,
        "description": "MAI 114 / 314 EIP: Output 6 words (12 bytes)",
    },
    # VT-019279 MAI 315 EIP
    {
        "name": "VT-019279 MAI 315 EIP — Input (Inst 101) [12 words / 24 bytes]",
        "device": "VT-019279 MAI 315 EIP",
        "class_code": 0x04,
        "instance": 101,
        "attribute": 3,
        "expected_words": 12,
        "expected_bytes": 24,
        "alive_word": 7,
        "description": "VT-019279 MAI 315 EIP: Input 12 words (24 bytes) — Word 7 (bytes 14-15): Alive Counter",
    },
    {
        "name": "VT-019279 MAI 315 EIP — Output (Inst 102) [8 words / 16 bytes]",
        "device": "VT-019279 MAI 315 EIP",
        "class_code": 0x04,
        "instance": 102,
        "attribute": 3,
        "expected_words": 8,
        "expected_bytes": 16,
        "alive_word": None,
        "description": "VT-019279 MAI 315 EIP: Output 8 words (16 bytes)",
    },
    # Configuration Object & Custom
    {
        "name": "Configuration Object — Inst 128 (0x80) [0 words]",
        "device": "Generic",
        "class_code": 0x04,
        "instance": 128,
        "attribute": 3,
        "expected_words": 0,
        "expected_bytes": 0,
        "alive_word": None,
        "description": "Configuration Object - Instance 128 (0x80) [0 words]",
    },
    {
        "name": "Custom CIP Assembly / Object",
        "device": "Custom",
        "class_code": 0x04,
        "instance": 101,
        "attribute": 3,
        "expected_words": 0,
        "expected_bytes": 0,
        "alive_word": None,
        "description": "Custom CIP assembly / object",
    },
]


def read_cip_data(address: str, class_code: int = 0x04, instance: int = 101,
                  attribute: int = 3, timeout: float = 3.0) -> bytes:
    """Read data from a CIP object attribute (Get_Attribute_Single 0x0E)."""
    if not usable_ip(address):
        raise ValueError(f"Invalid or unusable target IPv4 address: {address}")
    try:
        with CIPDriver(address) as driver:
            response = driver.generic_message(
                service=Services.get_attribute_single,
                class_code=class_code,
                instance=instance,
                attribute=attribute,
                connected=False,
                unconnected_send=False,
                route_path=False,
                name=f"Read Class {class_code:#x} Inst {instance} Attr {attribute}",
            )
    except Exception as error:
        raise CIPDeviceIOError(f"Connection to {address} failed: {error}") from error

    if response is None or response.error:
        detail = response.error if response is not None else "no response from device"
        raise CIPDeviceIOError(
            f"Read failed on Class {class_code:#x} Instance {instance} Attribute {attribute}: {detail}")

    if response.value is None:
        return b""
    return bytes(response.value)


def write_cip_data(address: str, data: bytes, class_code: int = 0x04,
                   instance: int = 102, attribute: int = 3,
                   timeout: float = 3.0) -> None:
    """Write data to a CIP object attribute (Set_Attribute_Single 0x10)."""
    if not usable_ip(address):
        raise ValueError(f"Invalid or unusable target IPv4 address: {address}")
    try:
        with CIPDriver(address) as driver:
            response = driver.generic_message(
                service=Services.set_attribute_single,
                class_code=class_code,
                instance=instance,
                attribute=attribute,
                request_data=data,
                connected=False,
                unconnected_send=False,
                route_path=False,
                name=f"Write Class {class_code:#x} Inst {instance} Attr {attribute}",
            )
    except Exception as error:
        raise CIPDeviceIOError(f"Connection to {address} failed: {error}") from error

    if response is None or response.error:
        detail = response.error if response is not None else "no response from device"
        raise CIPDeviceIOError(
            f"Write failed on Class {class_code:#x} Instance {instance} Attribute {attribute}: {detail}")


def format_hexdump(data: bytes, bytes_per_line: int = 16) -> str:
    """Format bytes into canonical hex dump with byte offsets and printable ASCII."""
    if not data:
        return "(empty response / 0 bytes)"
    lines = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset + bytes_per_line]
        hex_parts = [f"{byte:02X}" for byte in chunk]
        if len(hex_parts) > 8:
            hex_str = " ".join(hex_parts[:8]) + "  " + " ".join(hex_parts[8:])
        else:
            hex_str = " ".join(hex_parts)
        # Pad spacing if chunk is shorter than bytes_per_line
        expected_len = bytes_per_line * 3 + (1 if bytes_per_line > 8 else 0) - 1
        hex_str = hex_str.ljust(expected_len)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:04X}   {hex_str}   |{ascii_str}|")
    return "\n".join(lines)


def format_word_view(data: bytes, words_per_line: int = 8, little_endian: bool = True,
                     annotations: Optional[dict[int, str]] = None) -> str:
    """Format bytes as 16-bit industrial words (hex, unsigned decimal, signed integer)."""
    if not data:
        return "(empty response / 0 bytes)"
    word_count = len(data) // 2
    fmt = "<H" if little_endian else ">H"
    signed_fmt = "<h" if little_endian else ">h"
    lines = []
    lines.append(f"Total: {len(data)} bytes ({word_count} complete 16-bit words, endian: {'Little' if little_endian else 'Big'})")
    lines.append("-" * 72)
    lines.append("Word Offset   Hex Value    Unsigned Dec    Signed Dec")
    lines.append("-" * 72)
    for i in range(word_count):
        raw_word = data[i * 2: i * 2 + 2]
        u_val = struct.unpack(fmt, raw_word)[0]
        s_val = struct.unpack(signed_fmt, raw_word)[0]
        line = f"Word {i:03d} (0x{i * 2:02X})   0x{u_val:04X}       {u_val:<12d}    {s_val:<12d}"
        if annotations and i in annotations:
            line += f"   <-- {annotations[i]}"
        lines.append(line)
    if len(data) % 2 != 0:
        trailing = data[-1]
        lines.append(f"Trailing byte at 0x{len(data)-1:02X}: 0x{trailing:02X} ({trailing})")
    return "\n".join(lines)


def parse_data_input(text: str) -> bytes:
    """Parse flexible user input: space/comma separated hex (00 0A 1F) or 0x-prefixed values."""
    cleaned = text.strip()
    if not cleaned:
        return b""
    # Replace commas, semicolons, brackets with spaces
    for sep in (",", ";", "[", "]", "(", ")"):
        cleaned = cleaned.replace(sep, " ")
    tokens = cleaned.split()
    byte_list = []
    for token in tokens:
        t = token.strip()
        if not t:
            continue
        if t.lower().startswith("0x"):
            t = t[2:]
        if len(t) % 2 != 0:
            t = "0" + t
        # Convert chunks of 2 characters as hex bytes
        for i in range(0, len(t), 2):
            val = int(t[i:i+2], 16)
            byte_list.append(val)
    return bytes(byte_list)


def format_raw_hex(data: bytes) -> str:
    """Format bytes as space-separated hex bytes."""
    if not data:
        return "(empty response / 0 bytes)"
    return " ".join(f"{b:02X}" for b in data)


class DeviceIOTestDialog:
    """Dialog for testing peripheral functionality (reading/writing CIP Assembly data)."""

    def __init__(self, root, mac: str, ip: str, identity: str = "", inline: bool = False):
        self.root = root
        self.mac = mac
        self.ip = ip
        self.identity = identity
        self.inline = inline
        self.polling = False
        self.poll_thread = None
        self.last_data = b""
        self.last_alive_val = None
        self.alive_tick_count = 0
        self.event_queue = queue.Queue()
        self._poll_job = None

        if inline:
            self.window = ttk.Frame(root)
            self.window.pack(fill="both", expand=True)
        else:
            self.window = tk.Toplevel(root)
            self.window.title(f"Device I/O Test — {ip} ({mac})")
            self.window.geometry("860x720")
            self.window.transient(root)
            self.window.protocol("WM_DELETE_WINDOW", self.close)

        panel = ttk.Frame(self.window, padding=0 if inline else 10)
        panel.pack(fill="both", expand=True)

        # Device info header
        header = ttk.LabelFrame(panel, text="Target Device", padding=6)
        header.pack(fill="x", pady=(0, 6))
        info_text = f"Device MAC: {mac}   |   IP: {ip}"
        if identity:
            info_text += f"\nIdentity: {identity}"
        ttk.Label(header, text=info_text, justify="left").pack(anchor="w")

        # Object / Assembly selection frame
        obj_frame = ttk.LabelFrame(panel, text="CIP Assembly / Object Selection", padding=6)
        obj_frame.pack(fill="x", pady=(0, 6))

        ttk.Label(obj_frame, text="Preset:").grid(row=0, column=0, sticky="w", padx=(0, 4))
        self.preset_var = tk.StringVar(value=PRESETS[0]["name"])
        preset_names = [p["name"] for p in PRESETS]
        self.preset_combo = ttk.Combobox(
            obj_frame, textvariable=self.preset_var, values=preset_names,
            state="readonly", width=68)
        self.preset_combo.grid(row=0, column=1, columnspan=5, sticky="ew", pady=(0, 4))
        self.preset_combo.bind("<<ComboboxSelected>>", self._on_preset_selected)

        # Parameters
        ttk.Label(obj_frame, text="Class:").grid(row=1, column=0, sticky="w", padx=(0, 4))
        self.class_var = tk.StringVar(value="0x04")
        self.class_entry = ttk.Entry(obj_frame, textvariable=self.class_var, width=10)
        self.class_entry.grid(row=1, column=1, sticky="w", padx=(0, 10))

        ttk.Label(obj_frame, text="Instance:").grid(row=1, column=2, sticky="w", padx=(0, 4))
        self.inst_var = tk.StringVar(value="101")
        self.inst_entry = ttk.Entry(obj_frame, textvariable=self.inst_var, width=10)
        self.inst_entry.grid(row=1, column=3, sticky="w", padx=(0, 10))

        ttk.Label(obj_frame, text="Attribute:").grid(row=1, column=4, sticky="w", padx=(0, 4))
        self.attr_var = tk.StringVar(value="3")
        self.attr_entry = ttk.Entry(obj_frame, textvariable=self.attr_var, width=10)
        self.attr_entry.grid(row=1, column=5, sticky="w")

        self.expected_label_var = tk.StringVar(
            value=PRESETS[0].get("description", "Expected data: 54 words (108 bytes)"))
        ttk.Label(obj_frame, textvariable=self.expected_label_var, foreground="#555").grid(
            row=2, column=0, columnspan=6, sticky="w", pady=(4, 0))

        # Cyclic Class 1 I/O connection (like a PLC owning the device)
        self.io_connection = None
        self._io_last_push = 0.0
        self._io_last_data = None
        io_frame = ttk.LabelFrame(
            panel, text="Cyclic I/O connection (Class 1, like a PLC)", padding=6)
        io_frame.pack(fill="x", pady=(0, 6))
        self.io_input_inst = tk.StringVar(value="101")
        self.io_input_size = tk.StringVar(value="108")
        self.io_output_inst = tk.StringVar(value="102")
        self.io_output_size = tk.StringVar(value="32")
        self.io_config_inst = tk.StringVar(value="128")
        self.io_rpi = tk.StringVar(value="500")
        column = 0
        for label, var, width in (
                ("Input inst", self.io_input_inst, 6), ("bytes", self.io_input_size, 5),
                ("Output inst", self.io_output_inst, 6), ("bytes", self.io_output_size, 5),
                ("Config inst", self.io_config_inst, 6)):
            ttk.Label(io_frame, text=label).grid(row=0, column=column, sticky="w", padx=(0, 3))
            ttk.Entry(io_frame, textvariable=var, width=width).grid(
                row=0, column=column + 1, sticky="w", padx=(0, 10))
            column += 2
        ttk.Label(io_frame, text="RPI (ms)").grid(row=0, column=column, sticky="w", padx=(0, 3))
        ttk.Combobox(io_frame, textvariable=self.io_rpi, width=6,
                     values=["100", "200", "500", "1000", "1500", "2000"]).grid(
            row=0, column=column + 1, sticky="w")
        io_ctrl = ttk.Frame(io_frame)
        io_ctrl.grid(row=1, column=0, columnspan=column + 2, sticky="ew", pady=(4, 0))
        self.io_button = ttk.Button(
            io_ctrl, text="Open I/O connection", command=self.toggle_io_connection)
        self.io_button.pack(side="left")
        self.io_run_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(io_ctrl, text="Run mode (outputs active)", variable=self.io_run_var,
                        command=self._on_io_run_changed).pack(side="left", padx=(10, 0))
        self.io_status_var = tk.StringVar(
            value="Not connected. Open a connection if explicit reads only return zeros.")
        self.io_status_lbl = ttk.Label(io_ctrl, textvariable=self.io_status_var)
        self.io_status_lbl.pack(side="left", padx=(10, 0))
        self._apply_io_sizes(PRESETS[0])

        # Read Panel
        read_frame = ttk.LabelFrame(panel, text="Read Peripheral Data (Get_Attribute_Single)", padding=6)
        read_frame.pack(fill="both", expand=True, pady=(0, 6))

        read_ctrl = ttk.Frame(read_frame)
        read_ctrl.pack(fill="x", pady=(0, 4))

        self.read_btn = ttk.Button(read_ctrl, text="Read Once", command=self.read_once)
        self.read_btn.pack(side="left", padx=(0, 8))

        self.poll_btn = ttk.Button(read_ctrl, text="Start Polling", command=self.toggle_polling)
        self.poll_btn.pack(side="left", padx=(0, 8))

        ttk.Label(read_ctrl, text="Interval (s):").pack(side="left", padx=(0, 4))
        self.poll_interval_var = tk.StringVar(value="1.0")
        self.poll_interval = ttk.Combobox(
            read_ctrl, textvariable=self.poll_interval_var,
            values=["0.2", "0.5", "1.0", "2.0", "5.0"], width=6, state="readonly")
        self.poll_interval.pack(side="left", padx=(0, 16))

        ttk.Label(read_ctrl, text="View:").pack(side="left", padx=(0, 4))
        self.view_var = tk.StringVar(value="words")
        for val, txt in (("words", "16-Bit Words"), ("hexdump", "Hex Dump"), ("raw", "Raw Hex")):
            r = ttk.Radiobutton(
                read_ctrl, text=txt, value=val, variable=self.view_var,
                command=self._refresh_data_display)
            r.pack(side="left", padx=(0, 6))

        # Alive Counter Monitor Bar
        alive_bar = ttk.Frame(read_frame)
        alive_bar.pack(fill="x", pady=(2, 6))
        self.alive_title_var = tk.StringVar(value="Alive Counter (Word 27):")
        ttk.Label(alive_bar, textvariable=self.alive_title_var, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 4))
        self.alive_val_var = tk.StringVar(value="--")
        ttk.Label(alive_bar, textvariable=self.alive_val_var, font=("Consolas", 10, "bold"), foreground="#0066cc").pack(side="left", padx=(0, 10))
        self.alive_status_var = tk.StringVar(value="(Click 'Read Once' or 'Start Polling')")
        self.alive_status_lbl = ttk.Label(alive_bar, textvariable=self.alive_status_var, font=("Segoe UI", 9))
        self.alive_status_lbl.pack(side="left")

        self.data_text = ScrolledText(
            read_frame, height=6 if inline else 12, wrap="none", font=("Consolas", 10))
        self.data_text.pack(fill="both", expand=True, pady=(0, 4))
        self.data_text.insert("1.0", "(No data read yet. Click 'Read Once' or 'Start Polling')")
        self.data_text.configure(state="disabled")

        self.read_status_var = tk.StringVar(value="Ready")
        ttk.Label(read_frame, textvariable=self.read_status_var, relief="sunken", anchor="w").pack(fill="x")

        # Write Panel (For Output Assembly e.g. Instance 102)
        write_frame = ttk.LabelFrame(panel, text="Write Peripheral Data (Set_Attribute_Single)", padding=6)
        write_frame.pack(fill="x", pady=(0, 6))

        write_ctrl = ttk.Frame(write_frame)
        write_ctrl.pack(fill="x", pady=(0, 4))

        self.write_btn = ttk.Button(write_ctrl, text="Write to Device", command=self.write_data)
        self.write_btn.pack(side="left", padx=(0, 8))

        ttk.Button(write_ctrl, text="Fill Expected Zeroes", command=self._fill_expected_zeroes).pack(side="left", padx=(0, 4))
        ttk.Button(write_ctrl, text="6w (12B)", command=self._fill_zeroes_6).pack(side="left", padx=(0, 2))
        ttk.Button(write_ctrl, text="8w (16B)", command=self._fill_zeroes_8).pack(side="left", padx=(0, 2))
        ttk.Button(write_ctrl, text="16w (32B)", command=self._fill_zeroes_16).pack(side="left", padx=(0, 2))
        ttk.Button(write_ctrl, text="54w (108B)", command=self._fill_zeroes_54).pack(side="left", padx=(0, 4))
        ttk.Button(write_ctrl, text="Fill Pattern", command=self._fill_pattern).pack(side="left", padx=(0, 4))
        ttk.Button(write_ctrl, text="Clear", command=self._clear_write_input).pack(side="left", padx=(0, 8))

        self.write_size_var = tk.StringVar(value="Input length: 0 bytes (0 words)")
        ttk.Label(write_ctrl, textvariable=self.write_size_var, foreground="#555").pack(side="right")

        self.write_text = ttk.Entry(write_frame, font=("Consolas", 10))
        self.write_text.pack(fill="x", pady=(0, 4))
        self.write_text.bind("<KeyRelease>", self._on_write_text_change)

        self.write_status_var = tk.StringVar(value="Enter hex bytes (e.g. '00 01 02') and click 'Write to Device'")
        ttk.Label(write_frame, textvariable=self.write_status_var, relief="sunken", anchor="w").pack(fill="x")

        # Bottom Close Button
        if not inline:
            btn_box = ttk.Frame(panel)
            btn_box.pack(fill="x", pady=(4, 0))
            ttk.Button(btn_box, text="Close", command=self.close).pack(side="right")

        self._poll_job = self.root.after(50, self._poll_event_queue)

    def _poll_event_queue(self):
        try:
            if not hasattr(self, "window") or not self.window.winfo_exists():
                self._poll_job = None
                return
            while True:
                try:
                    kind, payload = self.event_queue.get_nowait()
                except queue.Empty:
                    break
                if kind == "read_success":
                    self._on_read_success(payload)
                elif kind == "read_error":
                    self._on_read_error(payload)
                elif kind == "write_success":
                    self._on_write_success(payload)
                elif kind == "write_error":
                    self._on_write_error(payload)
                elif kind == "io_started":
                    self._on_io_started(payload)
                elif kind == "io_data":
                    self._on_io_data_ui(payload)
                elif kind == "io_event":
                    self._on_io_event(*payload)
                elif kind == "io_error":
                    self._on_io_error(payload)
                elif kind == "io_closed":
                    self._on_io_closed(payload)
            if self._poll_job is not None:
                try:
                    self.root.after_cancel(self._poll_job)
                except tk.TclError:
                    pass
            self._poll_job = self.root.after(50, self._poll_event_queue)
        except tk.TclError:
            self._poll_job = None

    def _parse_int(self, val_str: str) -> int:
        s = val_str.strip()
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s, 10)

    def _current_preset(self):
        name = self.preset_var.get()
        for p in PRESETS:
            if p["name"] == name:
                return p
        return None

    def _on_preset_selected(self, event=None):
        p = self._current_preset()
        if p:
            self.class_var.set(f"0x{p['class_code']:02X}")
            self.inst_var.set(str(p["instance"]))
            self.attr_var.set(str(p["attribute"]))
            if "description" in p:
                self.expected_label_var.set(p["description"])
            elif p["expected_words"] > 0:
                self.expected_label_var.set(
                    f"Expected data: {p['expected_words']} words ({p['expected_bytes']} bytes)")
            else:
                self.expected_label_var.set("Configurable CIP assembly / object")

            # Update Alive Counter title label according to model
            alive_w = p.get("alive_word")
            if alive_w is not None:
                self.alive_title_var.set(f"Alive Counter (Word {alive_w}, bytes {alive_w*2}-{alive_w*2+1}):")
            else:
                self.alive_title_var.set("Alive Counter:")
            self.last_alive_val = None
            self.alive_val_var.set("--")
            self.alive_status_var.set("(Click 'Read Once' or 'Start Polling')")
            self.alive_status_lbl.configure(foreground="#333333")
            if self.io_connection is None:
                self._apply_io_sizes(p)

    def _apply_io_sizes(self, preset):
        """Fill the I/O connection sizes from the input/output presets of the same device model."""
        device = preset.get("device")
        if device in (None, "Generic", "Custom"):
            return
        for p in PRESETS:
            if p.get("device") == device and p["instance"] == 101:
                self.io_input_inst.set("101")
                self.io_input_size.set(str(p["expected_bytes"]))
            elif p.get("device") == device and p["instance"] == 102:
                self.io_output_inst.set("102")
                self.io_output_size.set(str(p["expected_bytes"]))

    def select_target(self, class_code: int, instance: int, attribute: int):
        """Switch to the custom preset and target the given CIP path (used by the scanner)."""
        if self.polling:
            self.toggle_polling()
        self.preset_var.set(PRESETS[-1]["name"])
        self._on_preset_selected()
        self.class_var.set(f"0x{class_code:02X}")
        self.inst_var.set(str(instance))
        self.attr_var.set(str(attribute))
        self.expected_label_var.set(
            f"From CIP scanner: Class 0x{class_code:02X}, Instance {instance}, Attribute {attribute}")

    def _get_cip_targets(self):
        try:
            class_code = self._parse_int(self.class_var.get())
            instance = self._parse_int(self.inst_var.get())
            attribute = self._parse_int(self.attr_var.get())
            return class_code, instance, attribute
        except ValueError as err:
            raise ValueError(f"Invalid Class, Instance, or Attribute: {err}") from err

    def read_once(self):
        try:
            class_code, instance, attribute = self._get_cip_targets()
        except ValueError as err:
            messagebox.showerror("Invalid Parameters", str(err), parent=self.window)
            return

        self.read_btn.configure(state="disabled")
        self.read_status_var.set(f"Reading Class {class_code:#x} Inst {instance} Attr {attribute}...")

        def worker():
            try:
                data = read_cip_data(self.ip, class_code, instance, attribute)
                self.event_queue.put(("read_success", data))
            except Exception as err:
                self.event_queue.put(("read_error", str(err)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_read_success(self, data: bytes, source: str = ""):
        try:
            if not self.window.winfo_exists():
                return
            self.read_btn.configure(state="normal")
            self.last_data = data
            now_str = datetime.now().strftime("%H:%M:%S")
            words = len(data) // 2
            self.read_status_var.set(
                f"{source or 'Last read'}: {len(data)} bytes ({words} words) at {now_str} — Success")

            # Check alive counter for the current model
            preset = self._current_preset()
            alive_w = preset.get("alive_word") if preset else None
            # If no preset or custom, auto-detect between word 27 (CVC 650) and word 7 (MAI series)
            if alive_w is None:
                if len(data) >= 56:
                    alive_w = 27
                elif len(data) >= 16:
                    alive_w = 7

            if alive_w is not None and len(data) >= (alive_w + 1) * 2:
                byte_off = alive_w * 2
                val_alive = struct.unpack("<H", data[byte_off:byte_off + 2])[0]
                self.alive_title_var.set(f"Alive Counter (Word {alive_w}, bytes {byte_off}-{byte_off+1}):")
                if self.last_alive_val is not None:
                    diff = (val_alive - self.last_alive_val) & 0xFFFF
                    if diff > 0:
                        self.alive_tick_count += 1
                        self.alive_status_var.set(f"Ticking! (+{diff}, updates: {self.alive_tick_count})")
                        self.alive_status_lbl.configure(foreground="#008800")
                    elif diff == 0:
                        self.alive_status_var.set("Static / not incremented since last read")
                        self.alive_status_lbl.configure(foreground="#cc6600")
                    else:
                        self.alive_status_var.set(f"Changed (new value: {val_alive})")
                        self.alive_status_lbl.configure(foreground="#008800")
                else:
                    self.alive_status_var.set("Initial read recorded")
                    self.alive_status_lbl.configure(foreground="#333333")
                self.last_alive_val = val_alive
                self.alive_val_var.set(f"{val_alive} (0x{val_alive:04X})")
            else:
                self.alive_val_var.set("N/A")
                model_name = preset.get("device", "This device") if preset else "This device"
                self.alive_status_var.set(
                    f"{model_name} response is {len(data)} bytes ({words} words) — no counter mapped")
                self.alive_status_lbl.configure(foreground="#666666")

            self._refresh_data_display()
        except tk.TclError:
            pass

    def _on_read_error(self, err_msg: str):
        try:
            if not self.window.winfo_exists():
                return
            self.read_btn.configure(state="normal")
            self.read_status_var.set(f"Read error: {err_msg}")
            if not self.polling:
                messagebox.showerror("Read Failed", err_msg, parent=self.window)
        except tk.TclError:
            pass

    def _refresh_data_display(self):
        try:
            if not self.window.winfo_exists():
                return
            annotations = {}
            try:
                class_code, instance, attribute = self._get_cip_targets()
                preset = self._current_preset()
                alive_w = preset.get("alive_word") if preset else None
                if alive_w is not None:
                    annotations[alive_w] = f"Alive Counter (Word {alive_w}, bytes {alive_w*2}-{alive_w*2+1})"
                elif instance == 101:
                    # Generic input assembly fallback
                    if len(self.last_data) >= 56:
                        annotations[27] = "Alive Counter (Word 27, bytes 54-55)"
                    if len(self.last_data) >= 16:
                        annotations[7] = "Alive Counter for MAI series (Word 7, bytes 14-15)"
            except ValueError:
                pass

            mode = self.view_var.get()
            if mode == "words":
                formatted = format_word_view(self.last_data, annotations=annotations)
            elif mode == "hexdump":
                formatted = format_hexdump(self.last_data)
            else:
                formatted = format_raw_hex(self.last_data)

            self.data_text.configure(state="normal")
            self.data_text.delete("1.0", "end")
            self.data_text.insert("1.0", formatted)
            self.data_text.configure(state="disabled")
        except tk.TclError:
            pass

    def toggle_polling(self):
        if self.polling:
            self.polling = False
            self.poll_btn.configure(text="Start Polling")
            self.read_btn.configure(state="normal")
        else:
            try:
                # Validate parameters first
                self._get_cip_targets()
                interval = float(self.poll_interval_var.get())
                if interval < 0.1:
                    interval = 0.1
            except ValueError as err:
                messagebox.showerror("Invalid Interval / Parameters", str(err), parent=self.window)
                return

            self.polling = True
            self.poll_btn.configure(text="Stop Polling")
            self.read_btn.configure(state="disabled")
            self.poll_thread = threading.Thread(target=self._poll_worker, args=(interval,), daemon=True)
            self.poll_thread.start()

    def _poll_worker(self, interval: float):
        while self.polling:
            try:
                class_code, instance, attribute = self._get_cip_targets()
                data = read_cip_data(self.ip, class_code, instance, attribute)
                self.event_queue.put(("read_success", data))
            except Exception as err:
                self.event_queue.put(("read_error", str(err)))

            # Sleep in small increments so stopping is instant
            steps = max(1, int(interval / 0.1))
            for _ in range(steps):
                if not self.polling:
                    break
                time.sleep(0.1)

    def _on_write_text_change(self, event=None):
        text = self.write_text.get()
        data = parse_data_input(text)
        words = len(data) // 2
        self.write_size_var.set(f"Input length: {len(data)} bytes ({words} words)")

    def _fill_expected_zeroes(self):
        preset = self._current_preset()
        words = preset.get("expected_words", 0) if preset else 0
        byte_count = words * 2 if words > 0 else 32
        self.write_text.delete(0, "end")
        self.write_text.insert(0, " ".join("00" for _ in range(byte_count)))
        self._on_write_text_change()

    def _fill_zeroes_6(self):
        self.write_text.delete(0, "end")
        self.write_text.insert(0, " ".join("00" for _ in range(12)))
        self._on_write_text_change()

    def _fill_zeroes_8(self):
        self.write_text.delete(0, "end")
        self.write_text.insert(0, " ".join("00" for _ in range(16)))
        self._on_write_text_change()

    def _fill_zeroes_16(self):
        self.write_text.delete(0, "end")
        self.write_text.insert(0, " ".join("00" for _ in range(32)))
        self._on_write_text_change()

    def _fill_zeroes_54(self):
        self.write_text.delete(0, "end")
        self.write_text.insert(0, " ".join("00" for _ in range(108)))
        self._on_write_text_change()

    def _fill_pattern(self):
        preset = self._current_preset()
        words = preset.get("expected_words", 0) if preset else 0
        byte_count = words * 2 if words > 0 else 32
        self.write_text.delete(0, "end")
        self.write_text.insert(0, " ".join(f"{((i % 255) + 1):02X}" for i in range(byte_count)))
        self._on_write_text_change()

    def _clear_write_input(self):
        self.write_text.delete(0, "end")
        self._on_write_text_change()

    def write_data(self):
        try:
            class_code, instance, attribute = self._get_cip_targets()
        except ValueError as err:
            messagebox.showerror("Invalid Parameters", str(err), parent=self.window)
            return

        raw_input = self.write_text.get().strip()
        data = parse_data_input(raw_input)
        if not data:
            messagebox.showwarning("Empty Write Data", "Please enter data to write (in hex format).", parent=self.window)
            return

        if self.io_connection is not None and self.io_connection.running:
            size = self.io_connection.config.output_size
            prompt = (f"Send {len(data)} bytes as cyclic output data of the I/O connection?\n"
                      f"Device IP: {self.ip}, Output instance "
                      f"{self.io_connection.config.output_instance} ({size} bytes"
                      f"{', shorter data is zero-padded' if len(data) < size else ''}"
                      f"{', longer data is truncated' if len(data) > size else ''}).\n\n"
                      + ("Run mode is ON: the peripheral outputs will follow this data."
                         if self.io_run_var.get() else
                         "Run mode is OFF: the device receives the data but keeps outputs idle."))
            if not messagebox.askyesno("Confirm I/O Output", prompt, parent=self.window):
                return
            sent = self.io_connection.set_output(data)
            now_str = datetime.now().strftime("%H:%M:%S")
            self.write_status_var.set(
                f"I/O connection output set to {len(sent)} bytes at {now_str} (sent every RPI)")
            return

        words = len(data) // 2
        prompt = (f"Are you sure you want to write {len(data)} bytes ({words} words) to:\n"
                  f"Device IP: {self.ip}\n"
                  f"Class {class_code:#x}, Instance {instance}, Attribute {attribute}?\n\n"
                  "This will directly update the peripheral device outputs.")
        if not messagebox.askyesno("Confirm CIP Write", prompt, parent=self.window):
            return

        self.write_btn.configure(state="disabled")
        self.write_status_var.set(f"Writing {len(data)} bytes to Class {class_code:#x} Inst {instance}...")

        def worker():
            try:
                write_cip_data(self.ip, data, class_code, instance, attribute)
                self.event_queue.put(("write_success", len(data)))
            except Exception as err:
                self.event_queue.put(("write_error", str(err)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_write_success(self, byte_count: int):
        try:
            if not self.window.winfo_exists():
                return
            self.write_btn.configure(state="normal")
            now_str = datetime.now().strftime("%H:%M:%S")
            self.write_status_var.set(f"Successfully written {byte_count} bytes at {now_str}")
            messagebox.showinfo("Write Succeeded", f"Successfully wrote {byte_count} bytes to device.", parent=self.window)
        except tk.TclError:
            pass

    def _on_write_error(self, err_msg: str):
        try:
            if not self.window.winfo_exists():
                return
            self.write_btn.configure(state="normal")
            self.write_status_var.set(f"Write error: {err_msg}")
            messagebox.showerror("Write Failed", err_msg, parent=self.window)
        except tk.TclError:
            pass

    def _io_config(self) -> IOConnectionConfig:
        try:
            config = IOConnectionConfig(
                input_instance=self._parse_int(self.io_input_inst.get()),
                input_size=self._parse_int(self.io_input_size.get()),
                output_instance=self._parse_int(self.io_output_inst.get()),
                output_size=self._parse_int(self.io_output_size.get()),
                config_instance=self._parse_int(self.io_config_inst.get()),
                rpi_ms=float(self.io_rpi.get()))
        except ValueError as err:
            raise ValueError(f"Invalid I/O connection setting: {err}") from err
        config.validate()
        return config

    def _set_io_status(self, text, color="#333333"):
        self.io_status_var.set(text)
        self.io_status_lbl.configure(foreground=color)

    def toggle_io_connection(self):
        if self.io_connection is not None:
            connection, self.io_connection = self.io_connection, None
            self.io_button.configure(state="disabled")
            self._set_io_status("Closing I/O connection...")
            threading.Thread(
                target=lambda: self.event_queue.put(("io_closed", connection.stop())),
                daemon=True).start()
            return
        try:
            config = self._io_config()
        except ValueError as err:
            messagebox.showerror("Invalid I/O Connection", str(err), parent=self.window)
            return
        if self.polling:
            self.toggle_polling()
        connection = IOConnection(
            self.ip, config, on_data=self._on_io_data,
            on_event=lambda kind, text: self.event_queue.put(("io_event", (kind, text))))
        connection.set_run(self.io_run_var.get())
        self.io_connection = connection
        self._io_last_data = None
        self.io_button.configure(state="disabled")
        self._set_io_status(f"Opening I/O connection (Forward_Open) to {self.ip}...")

        def worker():
            try:
                info = connection.start()
            except Exception as err:
                self.event_queue.put(("io_error", (connection, str(err))))
                return
            if connection is not self.io_connection:
                connection.stop()  # panel was closed while Forward_Open was in progress
                return
            self.event_queue.put(("io_started", (connection, info)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_io_data(self, data: bytes):
        # Runs on the I/O thread at the RPI; forward changes immediately, otherwise twice a second.
        now = time.monotonic()
        if data != self._io_last_data or now - self._io_last_push >= 0.5:
            self._io_last_data = data
            self._io_last_push = now
            self.event_queue.put(("io_data", data))

    def _on_io_run_changed(self):
        if self.io_connection is not None:
            self.io_connection.set_run(self.io_run_var.get())

    def _on_io_started(self, payload):
        connection, info = payload
        if connection is not self.io_connection:
            threading.Thread(target=connection.stop, daemon=True).start()
            return
        self.io_button.configure(state="normal", text="Close I/O connection")
        mode = "multicast" if connection.multicast else "point-to-point"
        self._set_io_status(
            f"Connected ({mode}, RPI {connection.config.rpi_ms:g} ms). Waiting for input...",
            "#0066cc")
        self.write_status_var.set(
            f"Cyclic output: {connection.config.output_size} zero bytes until you click "
            "'Write to Device'")

    def _on_io_data_ui(self, data: bytes):
        connection = self.io_connection
        if connection is None:
            return
        self._on_read_success(data, "I/O connection")
        self._set_io_status(
            f"Connected — {connection.rx_count} input / {connection.tx_count} output packets"
            f" ({'Run' if connection.run else 'Idle'})", "#008800")

    def _on_io_event(self, kind, text):
        if self.io_connection is None:
            return
        if kind == "input_resumed":
            self._set_io_status(text, "#008800")
            return
        self._set_io_status(text, "#cc6600" if kind == "no_input" else "#cc0000")
        if kind == "error":
            self.toggle_io_connection()

    def _on_io_error(self, payload):
        connection, message = payload
        if connection is not self.io_connection:
            return
        self.io_connection = None
        self.io_button.configure(state="normal", text="Open I/O connection")
        self._set_io_status(f"Not connected: {message}", "#cc0000")
        messagebox.showerror("I/O Connection Failed", message, parent=self.window)

    def _on_io_closed(self, closed: bool):
        self.io_button.configure(state="normal", text="Open I/O connection")
        self._set_io_status(
            "I/O connection closed." if closed else
            "I/O traffic stopped; Forward_Close got no confirmation (device will time out).")

    def close(self):
        self.polling = False
        if self.io_connection is not None:
            connection, self.io_connection = self.io_connection, None
            connection.stop()
        if self._poll_job is not None:
            try:
                self.root.after_cancel(self._poll_job)
            except tk.TclError:
                pass
            self._poll_job = None
        try:
            self.window.destroy()
        except tk.TclError:
            pass

