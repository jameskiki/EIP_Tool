"""Read-only Lantronix XPort setup/status diagnostics over Telnet port 9999."""

import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText


def _strip_telnet_commands(data: bytes) -> bytes:
    output = bytearray()
    index = 0
    while index < len(data):
        if data[index] != 0xFF:
            output.append(data[index])
            index += 1
            continue
        if index + 1 >= len(data):
            break
        command = data[index + 1]
        if command == 0xFF:
            output.append(0xFF)
            index += 2
        elif command in (0xFB, 0xFC, 0xFD, 0xFE):
            index += 3
        elif command == 0xFA:
            end = data.find(b"\xff\xf0", index + 2)
            index = len(data) if end < 0 else end + 2
        else:
            index += 2
    return bytes(output).replace(b"\x00", b"")


def read_lantronix_diagnostics(address: str, port: int = 9999,
                               timeout: float = 4.0) -> str:
    """Read the Lantronix setup banner and status menu; send Enter only."""
    if not address:
        raise ValueError("An observed device IP is required to read diagnostics.")
    raw = bytearray()
    prompt = b"Press Enter for Setup Mode"
    menu_started = False
    last_received = 0.0
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((address, port), timeout=timeout) as connection:
            connection.settimeout(0.2)
            while time.monotonic() < deadline and len(raw) < 65536:
                try:
                    chunk = connection.recv(4096)
                except socket.timeout:
                    if menu_started and time.monotonic() - last_received >= 0.4:
                        break
                    continue
                if not chunk:
                    break
                raw.extend(chunk)
                last_received = time.monotonic()
                if not menu_started and prompt.lower() in _strip_telnet_commands(raw).lower():
                    connection.sendall(b"\r")
                    menu_started = True
                    deadline = time.monotonic() + timeout
            if not menu_started:
                raise RuntimeError(
                    "The device did not present a Lantronix setup prompt on port 9999. "
                    "Confirm this is a Lantronix device and that Telnet Setup is enabled.")
    except ConnectionRefusedError as error:
        raise RuntimeError(
            f"Lantronix diagnostics unavailable at {address}:{port}: the device refused "
            "the TCP connection. Port 9999 setup/Telnet access may be disabled or unsupported. "
            "This does not by itself indicate that the IP address or EtherNet/IP service is down.") from error
    except (OSError, socket.timeout) as error:
        raise RuntimeError(f"Could not read Lantronix diagnostics from {address}:{port}: {error}") from error

    text = _strip_telnet_commands(raw).decode("latin-1", errors="replace")
    lines = [line.rstrip() for line in text.replace("\r", "\n").split("\n")]
    return "\n".join(line for line in lines if line.strip())


class LantronixDiagnosticsDialog:
    """Read-only UI for the Lantronix setup/status menu."""

    def __init__(self, root, mac: str, address: str, inline: bool = False):
        self.root = root
        self.address = address
        self.inline = inline
        self.events = queue.Queue()
        self.poll_job = None
        if inline:
            self.window = ttk.Frame(root)
            self.window.pack(fill="both", expand=True)
        else:
            self.window = tk.Toplevel(root)
            self.window.title(f"Device diagnostics — {address}")
            self.window.geometry("760x520")
            self.window.transient(root)
            self.window.protocol("WM_DELETE_WINDOW", self.close)

        panel = ttk.Frame(self.window, padding=0 if inline else 10)
        panel.pack(fill="both", expand=True)
        ttk.Label(panel, text=f"Lantronix setup/status menu | MAC {mac} | {address}").pack(
            anchor="w", pady=(0, 6))
        ttk.Label(panel, text="Read-only query. The app sends Enter to display status; it makes no changes.").pack(
            anchor="w", pady=(0, 6))
        controls = ttk.Frame(panel)
        controls.pack(fill="x", pady=(0, 6))
        self.read_button = ttk.Button(
            controls, text="Refresh" if inline else "Read diagnostics", command=self.read)
        self.read_button.pack(side="left")
        self.status = tk.StringVar(value="Ready")
        ttk.Label(controls, textvariable=self.status).pack(side="left", padx=8)
        self.output = ScrolledText(panel, wrap="none", font=("Consolas", 10))
        self.output.pack(fill="both", expand=True)
        self.output.insert("1.0", "Click Read diagnostics to query port 9999.")
        self.output.configure(state="disabled")
        self.poll_job = self.window.after(50, self._poll)

    def read(self):
        self.read_button.configure(state="disabled")
        self.status.set(f"Connecting to {self.address}:9999...")

        def worker():
            try:
                result = read_lantronix_diagnostics(self.address)
                self.events.put(("success", result))
            except Exception as error:
                self.events.put(("error", str(error)))

        threading.Thread(target=worker, daemon=True).start()

    def _poll(self):
        try:
            if not self.window.winfo_exists():
                self.poll_job = None
                return
            while True:
                try:
                    kind, result = self.events.get_nowait()
                except queue.Empty:
                    break
                self.read_button.configure(state="normal")
                self.status.set("Diagnostics received." if kind == "success" else "Query failed.")
                self.output.configure(state="normal")
                self.output.delete("1.0", "end")
                self.output.insert("1.0", result)
                self.output.configure(state="disabled")
                if kind == "error" and not self.inline:
                    messagebox.showerror("Device diagnostics failed", result, parent=self.window)
            self.poll_job = self.window.after(50, self._poll)
        except tk.TclError:
            self.poll_job = None

    def close(self):
        if self.poll_job is not None:
            try:
                self.window.after_cancel(self.poll_job)
            except tk.TclError:
                pass
            self.poll_job = None
        try:
            self.window.destroy()
        except tk.TclError:
            pass
