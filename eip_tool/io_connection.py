"""Class 1 (implicit, cyclic) EtherNet/IP I/O connection, acting like a PLC/scanner.

Many adapters - including Modbus gateways such as the Lantronix XPort-EIP-MB - only
refresh their input assembly while an I/O connection owns them, so explicit
Get_Attribute_Single reads return zeros. This module opens such a connection with
Forward_Open, exchanges cyclic UDP packets on port 2222, and closes it with Forward_Close.
"""

import random
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from pycomm3 import CIPDriver

from .discovery import usable_ip

IO_PORT = 2222
CONNECTION_MANAGER = 0x06
FORWARD_OPEN = 0x54
FORWARD_CLOSE = 0x4E
ITEM_CONNECTED_DATA = 0x00B1
ITEM_SEQUENCED_ADDRESS = 0x8002
ITEM_SOCKADDR_O_T = 0x8000
ITEM_SOCKADDR_T_O = 0x8001
ORIGINATOR_VENDOR = 0xFFFE  # not a registered vendor; identifies this bench tool
POINT_TO_POINT = 2
MULTICAST = 1
PRIORITY_SCHEDULED = 2
TRANSPORT_CLASS1_CYCLIC = 0x01
RUN = 0x00000001

EXTENDED_STATUS = {
    0x0100: "connection in use or duplicate Forward_Open",
    0x0103: "transport class/trigger combination not supported",
    0x0106: "ownership conflict - another scanner/PLC already owns the outputs",
    0x0107: "target connection not found",
    0x0108: "invalid network connection parameter",
    0x0109: "invalid connection size",
    0x0110: "target for connection not configured",
    0x0111: "RPI not supported",
    0x0113: "device is out of connections",
    0x0114: "vendor ID or product code mismatch",
    0x0115: "device type mismatch",
    0x0116: "revision mismatch",
    0x0117: "invalid produced or consumed application path",
    0x0118: "invalid or inconsistent configuration application path",
    0x0119: "non-listen-only connection not opened",
    0x011A: "target object out of connections",
    0x011B: "RPI is smaller than the production inhibit time",
    0x0123: "invalid O->T network connection type",
    0x0124: "invalid T->O network connection type",
    0x0125: "invalid O->T connection size",
    0x0126: "invalid T->O connection size",
    0x0127: "invalid configuration application path",
    0x0128: "invalid consuming (output) application path",
    0x0129: "invalid producing (input) application path",
    0x012D: "inconsistent application path combination",
    0x0203: "connection timed out",
    0x0204: "unconnected request timed out",
    0x0315: "invalid segment in connection path",
}


class IOConnectionError(RuntimeError):
    pass


@dataclass
class IOConnectionConfig:
    input_instance: int = 101    # T->O, produced by the device
    input_size: int = 24         # data bytes
    output_instance: int = 102   # O->T, consumed by the device
    output_size: int = 16
    config_instance: int = 128
    rpi_ms: float = 100.0
    multicast: bool = False      # T->O; point-to-point is tried first
    timeout_multiplier: int = 2  # 0..7 -> RPI x 4, 8, 16, ...
    output_header: bool = True   # 32-bit run/idle header in O->T
    input_header: bool = False   # T->O is normally "modeless"

    def validate(self):
        for name in ("input_instance", "output_instance", "config_instance"):
            if not 1 <= getattr(self, name) <= 0xFFFF:
                raise ValueError(f"{name.replace('_', ' ').capitalize()} must be 1-65535.")
        if not (0 <= self.input_size and 0 <= self.output_size):
            raise ValueError("Sizes must not be negative.")
        if self.o_t_size > 0x1FF or self.t_o_size > 0x1FF:
            raise ValueError("Connection size exceeds 511 bytes (Large Forward_Open not supported).")
        if not 1 <= self.rpi_ms <= 10000:
            raise ValueError("RPI must be between 1 and 10000 ms.")
        if not 0 <= self.timeout_multiplier <= 7:
            raise ValueError("Timeout multiplier must be 0-7.")

    @property
    def o_t_size(self):
        return self.output_size + 2 + (4 if self.output_header else 0)

    @property
    def t_o_size(self):
        return self.input_size + 2 + (4 if self.input_header else 0)

    @property
    def rpi_us(self):
        return int(self.rpi_ms * 1000)

    @property
    def timeout_s(self):
        return self.rpi_ms / 1000 * (4 << self.timeout_multiplier)


def _logical_instance(segment, value):
    # segment: 0x24 instance / 0x2C connection point; +1 selects the 16-bit form.
    if value <= 0xFF:
        return bytes((segment, value))
    return bytes((segment + 1, 0)) + struct.pack("<H", value)


def connection_path(config: IOConnectionConfig) -> bytes:
    return (b"\x20\x04" + _logical_instance(0x24, config.config_instance)
            + _logical_instance(0x2C, config.output_instance)
            + _logical_instance(0x2C, config.input_instance))


def network_parameters(size: int, multicast: bool = False) -> int:
    kind = MULTICAST if multicast else POINT_TO_POINT
    return (kind << 13) | (PRIORITY_SCHEDULED << 10) | (size & 0x1FF)


def build_forward_open(config: IOConnectionConfig, t_o_id: int, serial: int,
                       originator_serial: int, multicast: bool = False) -> bytes:
    path = connection_path(config)
    return b"".join((
        struct.pack("<BB", 0x0A, 0x0E),  # priority/time tick, timeout ticks (~14 s)
        struct.pack("<II", 0, t_o_id),
        struct.pack("<HHI", serial, ORIGINATOR_VENDOR, originator_serial),
        struct.pack("<B3x", config.timeout_multiplier),
        struct.pack("<IH", config.rpi_us, network_parameters(config.o_t_size)),
        struct.pack("<IH", config.rpi_us, network_parameters(config.t_o_size, multicast)),
        struct.pack("<BB", TRANSPORT_CLASS1_CYCLIC, len(path) // 2),
        path,
    ))


def build_forward_close(config: IOConnectionConfig, serial: int, originator_serial: int) -> bytes:
    path = connection_path(config)
    return (struct.pack("<BBHHIBx", 0x0A, 0x0E, serial, ORIGINATOR_VENDOR,
                        originator_serial, len(path) // 2) + path)


def cip_reply(raw: bytes):
    """(general status, [extended status words], data) of a SendRRData reply."""
    if raw is None or len(raw) < 44:
        raise IOConnectionError("No or truncated reply from device.")
    status, ext_words = raw[42], raw[43]
    ext_end = 44 + 2 * ext_words
    extended = list(struct.unpack(f"<{ext_words}H", raw[44:ext_end]))
    return status, extended, raw[ext_end:]


def describe_failure(status: int, extended) -> str:
    text = f"CIP status {status:#04x}"
    if extended:
        code = extended[0]
        text += f", extended {code:#06x}"
        if code in EXTENDED_STATUS:
            text += f" ({EXTENDED_STATUS[code]})"
        if code == 0x0109 and len(extended) > 1:
            text += f"; device supports {extended[1]} bytes"
    return text


def cpf_sockaddrs(raw: bytes) -> dict:
    """Sockaddr info items appended to a Forward_Open reply: {item type: (ip, port)}."""
    result = {}
    try:
        count = struct.unpack_from("<H", raw, 30)[0]
        offset = 32
        for _ in range(count):
            item_type, length = struct.unpack_from("<HH", raw, offset)
            body = raw[offset + 4:offset + 4 + length]
            if item_type in (ITEM_SOCKADDR_O_T, ITEM_SOCKADDR_T_O) and len(body) >= 8:
                port = struct.unpack_from(">H", body, 2)[0]
                result[item_type] = (socket.inet_ntoa(body[4:8]), port)
            offset += 4 + length
    except struct.error:
        pass
    return result


def parse_forward_open_reply(raw: bytes):
    status, extended, data = cip_reply(raw)
    if status != 0:
        raise IOConnectionError(f"Forward_Open rejected: {describe_failure(status, extended)}")
    if len(data) < 26:
        raise IOConnectionError("Forward_Open reply is too short.")
    o_t_id, t_o_id, _serial, _vendor, _orig, o_t_api, t_o_api = struct.unpack_from(
        "<IIHHIII", data)
    return {"o_t_id": o_t_id, "t_o_id": t_o_id, "o_t_api_us": o_t_api,
            "t_o_api_us": t_o_api, "sockaddrs": cpf_sockaddrs(raw)}


def build_output_packet(connection_id: int, sequence: int, cip_sequence: int,
                        data: bytes, run: bool, header: bool = True) -> bytes:
    payload = struct.pack("<H", cip_sequence & 0xFFFF)
    if header:
        payload += struct.pack("<I", RUN if run else 0)
    payload += data
    return (struct.pack("<H", 2)
            + struct.pack("<HHII", ITEM_SEQUENCED_ADDRESS, 8, connection_id, sequence & 0xFFFFFFFF)
            + struct.pack("<HH", ITEM_CONNECTED_DATA, len(payload)) + payload)


def parse_input_packet(packet: bytes, connection_id: int, header: bool = False):
    """Return (cip sequence, data) for a T->O packet of this connection, else None."""
    try:
        count = struct.unpack_from("<H", packet)[0]
        offset, matched, data = 2, False, None
        for _ in range(count):
            item_type, length = struct.unpack_from("<HH", packet, offset)
            body = packet[offset + 4:offset + 4 + length]
            if item_type == ITEM_SEQUENCED_ADDRESS and len(body) >= 8:
                matched = struct.unpack_from("<I", body)[0] == connection_id
            elif item_type == ITEM_CONNECTED_DATA and len(body) >= 2:
                data = body
            offset += 4 + length
    except struct.error:
        return None
    if not matched or data is None:
        return None
    sequence = struct.unpack_from("<H", data)[0]
    return sequence, bytes(data[6:] if header else data[2:])


class IOConnection:
    """Owns one Class 1 connection. on_data(bytes) and on_event(kind, text) run on the I/O thread."""

    def __init__(self, address: str, config: IOConnectionConfig,
                 on_data: Optional[Callable[[bytes], None]] = None,
                 on_event: Optional[Callable[[str, str], None]] = None,
                 driver_factory=CIPDriver, local_port: int = IO_PORT,
                 target_port: int = IO_PORT):
        if not usable_ip(address):
            raise ValueError(f"Invalid or unusable target IPv4 address: {address}")
        config.validate()
        self.address = address
        self.config = config
        self.on_data = on_data or (lambda data: None)
        self.on_event = on_event or (lambda kind, text: None)
        self.driver_factory = driver_factory
        self.local_port = local_port
        self.target_port = target_port
        self.output = bytes(config.output_size)
        self.run = False
        self.tx_count = 0
        self.rx_count = 0
        self.last_input = b""
        self.info = None
        self.multicast = False
        self._driver = None
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._serial = random.randint(1, 0xFFFF)
        self._originator_serial = random.randint(1, 0xFFFFFFFF)

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def set_output(self, data: bytes) -> bytes:
        data = bytes(data[:self.config.output_size]).ljust(self.config.output_size, b"\x00")
        with self._lock:
            self.output = data
        return data

    def set_run(self, run: bool):
        self.run = bool(run)

    def start(self):
        try:
            self._driver = self.driver_factory(self.address)
            self._driver.open()
        except Exception as error:
            self._close_driver()
            raise IOConnectionError(f"Connection to {self.address} failed: {error}") from error
        try:
            try:
                self.info = self._forward_open(self.config.multicast)
                self.multicast = self.config.multicast
            except IOConnectionError as error:
                # Some adapters only produce multicast inputs.
                if self.config.multicast or not any(
                        code in str(error) for code in ("0x0124", "0x0108")):
                    raise
                self.info = self._forward_open(True)
                self.multicast = True
            self._sock = self._open_socket()
        except Exception:
            if self.info is not None:
                self._forward_close()
            self._close_driver()
            raise
        self._thread = threading.Thread(target=self._run, daemon=True, name="eip-io")
        self._thread.start()
        return self.info

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        closed = self.info is None or self._forward_close()
        self._close_driver()
        return closed

    def _forward_open(self, multicast):
        t_o_id = random.randint(1, 0xFFFFFFFF)
        response = self._driver.generic_message(
            service=FORWARD_OPEN, class_code=CONNECTION_MANAGER, instance=1,
            request_data=build_forward_open(
                self.config, t_o_id, self._serial, self._originator_serial, multicast),
            connected=False, unconnected_send=False, route_path=False,
            return_response_packet=True, name="io_forward_open")
        packet = getattr(response, "value", None)
        raw = getattr(packet, "raw", None)
        if raw is None:
            raise IOConnectionError(
                f"Forward_Open failed: {getattr(response, 'error', None) or 'no reply'}")
        return parse_forward_open_reply(raw)

    def _forward_close(self):
        request = build_forward_close(self.config, self._serial, self._originator_serial)
        for attempt in range(2):
            try:
                if attempt:
                    self._close_driver()
                    self._driver = self.driver_factory(self.address)
                    self._driver.open()
                response = self._driver.generic_message(
                    service=FORWARD_CLOSE, class_code=CONNECTION_MANAGER, instance=1,
                    request_data=request, connected=False, unconnected_send=False,
                    route_path=False, return_response_packet=True, name="io_forward_close")
                raw = getattr(getattr(response, "value", None), "raw", None)
                if raw is not None and cip_reply(raw)[0] == 0:
                    self.info = None
                    return True
            except Exception:
                pass
        return False

    def _close_driver(self):
        if self._driver is not None:
            try:
                self._driver.close()
            except Exception:
                pass
            self._driver = None

    def _local_ip(self):
        try:
            return self._driver._sock.sock.getsockname()[0]
        except Exception:
            return "0.0.0.0"

    def _open_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if hasattr(socket, "SIO_UDP_CONNRESET"):
                # Ignore ICMP "port unreachable" resets on Windows.
                sock.ioctl(socket.SIO_UDP_CONNRESET, False)
            sock.bind(("", self.local_port))
            if self.multicast:
                group = self.info["sockaddrs"].get(ITEM_SOCKADDR_T_O)
                if not group:
                    raise IOConnectionError("Device chose multicast but sent no T->O address.")
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, struct.pack(
                    "4s4s", socket.inet_aton(group[0]), socket.inet_aton(self._local_ip())))
        except OSError as error:
            sock.close()
            raise IOConnectionError(
                f"Cannot listen on UDP port {self.local_port} (is another EtherNet/IP "
                f"tool or scanner running?): {error}") from error
        except Exception:
            sock.close()
            raise
        return sock

    def _run(self):
        rpi = self.config.rpi_ms / 1000
        watchdog = max(self.config.timeout_s, 1.0)
        started = last_rx = time.monotonic()
        next_send = started
        warned = False
        sequence = 0
        try:
            while not self._stop.is_set():
                now = time.monotonic()
                if now >= next_send:
                    sequence += 1
                    with self._lock:
                        data = self.output
                    self._sock.sendto(build_output_packet(
                        self.info["o_t_id"], sequence, sequence, data, self.run,
                        self.config.output_header), (self.address, self.target_port))
                    self.tx_count += 1
                    next_send += rpi
                    if next_send < now:
                        next_send = now + rpi
                wait = max(0.0, min(next_send - time.monotonic(), 0.05))
                readable, _, _ = select.select([self._sock], [], [], wait)
                if readable:
                    try:
                        packet, source = self._sock.recvfrom(2048)
                    except (ConnectionResetError, BlockingIOError):
                        continue
                    if source[0] != self.address:
                        continue
                    parsed = parse_input_packet(
                        packet, self.info["t_o_id"], self.config.input_header)
                    if parsed is None:
                        continue
                    last_rx = time.monotonic()
                    self.rx_count += 1
                    self.last_input = parsed[1]
                    if warned:
                        warned = False
                        self.on_event("input_resumed", "Input packets are arriving again.")
                    self.on_data(parsed[1])
                elif not warned and time.monotonic() - last_rx > watchdog:
                    warned = True
                    self.on_event("no_input", (
                        f"No input packets from {self.address} for {watchdog:.1f} s. The device "
                        "may have dropped the connection, or Windows Firewall is blocking "
                        "inbound UDP 2222 for Python."))
        except OSError as error:
            if not self._stop.is_set():
                self.on_event("error", f"I/O connection failed: {error}")
