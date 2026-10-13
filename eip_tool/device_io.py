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
        "description": "VT-015131 CVC 650 EIP: Input Assembly 54 words (108 bytes) — Word 27: Alive Counter",
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
        "description": "VT-015131 CVC 650 EIP: Output Assembly 16 words (32 bytes)",
    },
    # VT-016246 MAI 114 EIP
    {
        "name": "VT-016246 MAI 114 EIP — Input (Inst 101) [8 words / 16 bytes]",
        "device": "VT-016246 MAI 114 EIP",
        "class_code": 0x04,
        "instance": 101,
        "attribute": 3,
        "expected_words": 8,
        "expected_bytes": 16,
        "alive_word": None,
        "description": "VT-016246 MAI 114 EIP: Input Assembly 8 words (16 bytes)",
    },
    {
        "name": "VT-016246 MAI 114 EIP — Output (Inst 102) [6 words / 12 bytes]",
        "device": "VT-016246 MAI 114 EIP",
        "class_code": 0x04,
        "instance": 102,
        "attribute": 3,
        "expected_words": 6,
        "expected_bytes": 12,
        "alive_word": None,
        "description": "VT-016246 MAI 114 EIP: Output Assembly 6 words (12 bytes)",
    },
    # VT-016403 MAI 314 EIP
    {
        "name": "VT-016403 MAI 314 EIP — Input (Inst 101) [8 words / 16 bytes]",
        "device": "VT-016403 MAI 314 EIP",
        "class_code": 0x04,
        "instance": 101,
        "attribute": 3,
        "expected_words": 8,
        "expected_bytes": 16,
        "alive_word": None,
        "description": "VT-016403 MAI 314 EIP: Input Assembly 8 words (16 bytes)",
    },
    {
        "name": "VT-016403 MAI 314 EIP — Output (Inst 102) [6 words / 12 bytes]",
        "device": "VT-016403 MAI 314 EIP",
        "class_code": 0x04,
        "instance": 102,
        "attribute": 3,
        "expected_words": 6,
        "expected_bytes": 12,
        "alive_word": None,
        "description": "VT-016403 MAI 314 EIP: Output Assembly 6 words (12 bytes)",
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
        "alive_word": None,
        "description": "VT-019279 MAI 315 EIP: Input Assembly 12 words (24 bytes)",
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
        "description": "VT-019279 MAI 315 EIP: Output Assembly 8 words (16 bytes)",
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

    def __init__(self, root, mac: str, ip: str, identity: str = ""):
        self.root = root
        self.mac = mac
        self.ip = ip
        self.identity = identity
        self.polling = False
        self.poll_thread = None
        self.last_data = b""
        self.last_word27_val = None
        self.alive_tick_count = 0
        self.event_queue = queue.Queue()
        self._poll_job = None

        self.window = tk.Toplevel(root)
        self.window.title(f"Device I/O Test — {ip} ({mac})")
        self.window.geometry("860x720")
        self.window.transient(root)
        self.window.protocol("WM_DELETE_WINDOW", self.close)

        panel = ttk.Frame(self.window, padding=10)
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
        ttk.Label(alive_bar, text="Alive Counter (Word 27):", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 4))
        self.alive_val_var = tk.StringVar(value="--")
        ttk.Label(alive_bar, textvariable=self.alive_val_var, font=("Consolas", 10, "bold"), foreground="#0066cc").pack(side="left", padx=(0, 10))
        self.alive_status_var = tk.StringVar(value="(Click 'Read Once' or 'Start Polling')")
        self.alive_status_lbl = ttk.Label(alive_bar, textvariable=self.alive_status_var, font=("Segoe UI", 9))
        self.alive_status_lbl.pack(side="left")

        self.data_text = ScrolledText(read_frame, height=12, wrap="none", font=("Consolas", 10))
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

    def _on_read_success(self, data: bytes):
        try:
            if not self.window.winfo_exists():
                return
            self.read_btn.configure(state="normal")
            self.last_data = data
            now_str = datetime.now().strftime("%H:%M:%S")
            words = len(data) // 2
            self.read_status_var.set(f"Last read: {len(data)} bytes ({words} words) at {now_str} — Success")

            # Check alive counter at Word 27 (bytes 54-55)
            preset = self._current_preset()
            if len(data) >= 56:
                val_w27 = struct.unpack("<H", data[54:56])[0]
                if self.last_word27_val is not None:
                    diff = (val_w27 - self.last_word27_val) & 0xFFFF
                    if diff > 0:
                        self.alive_tick_count += 1
                        self.alive_status_var.set(f"Ticking! (+{diff}, updates: {self.alive_tick_count})")
                        self.alive_status_lbl.configure(foreground="#008800")
                    elif diff == 0:
                        self.alive_status_var.set("Static / not incremented since last read")
                        self.alive_status_lbl.configure(foreground="#cc6600")
                    else:
                        self.alive_status_var.set(f"Changed (new value: {val_w27})")
                        self.alive_status_lbl.configure(foreground="#008800")
                else:
                    self.alive_status_var.set("Initial read recorded")
                    self.alive_status_lbl.configure(foreground="#333333")
                self.last_word27_val = val_w27
                self.alive_val_var.set(f"{val_w27} (0x{val_w27:04X}) [Word 27, bytes 54-55]")
            else:
                self.alive_val_var.set("N/A")
                model_name = preset.get("device", "This device") if preset else "This device"
                self.alive_status_var.set(
                    f"{model_name} response is {len(data)} bytes ({words} words) — Word 27 is not in this model's mapping")
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
                if instance == 101:
                    annotations[27] = "Alive Counter (0-indexed Word 27, bytes 54-55)"
                    annotations[26] = "Word 26 (27th word if 1-indexed, bytes 52-53)"
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

    def close(self):
        self.polling = False
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

