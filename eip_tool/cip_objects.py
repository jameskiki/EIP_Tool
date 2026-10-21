"""Read-only CIP object browser: Identity (0x01), TCP/IP (0xF5), Ethernet Link (0xF6)."""

from dataclasses import dataclass
from ipaddress import IPv4Address
import struct

from pycomm3 import CIPDriver, Services

from .discovery import usable_ip


class CIPObjectError(RuntimeError):
    pass


@dataclass(frozen=True)
class AttributeRow:
    instance: int
    attribute: int
    name: str
    value: str
    raw: str = ""


def _need(data, size):
    if len(data) < size:
        raise ValueError(f"expected {size} bytes, got {len(data)}")


def _uint(data, size):
    _need(data, size)
    return int.from_bytes(data[:size], "little")


def _short_string(data):
    _need(data, 1)
    _need(data, 1 + data[0])
    return data[1:1 + data[0]].decode("latin-1")


def _string(data):
    length = _uint(data, 2)
    _need(data, 2 + length)
    return data[2:2 + length].decode("latin-1")


def _ip(data):
    _need(data, 4)
    return str(IPv4Address(int.from_bytes(data[:4], "little")))


def _flags(value, names):
    active = [name for bit, name in names if value >> bit & 1]
    return f"{value:#010x}" + (f" ({', '.join(active)})" if active else "")


def _named(table, value):
    return f"{value} ({table[value]})" if value in table else f"{value}"


DEVICE_TYPES = {
    0x00: "Generic Device", 0x02: "AC Drive", 0x07: "General Purpose Discrete I/O",
    0x0C: "Communications Adapter", 0x0E: "Programmable Logic Controller",
    0x2B: "Generic Device (keyable)",
}
IDENTITY_STATES = {
    0: "Nonexistent", 1: "Device self testing", 2: "Standby", 3: "Operational",
    4: "Major recoverable fault", 5: "Major unrecoverable fault", 255: "Default",
}


def _vendor(data):
    value = _uint(data, 2)
    return f"{value:#06x} ({value})" + (" — Rockwell Automation/Allen-Bradley" if value == 1 else "")


def _revision(data):
    _need(data, 2)
    return f"{data[0]}.{data[1]:03d}"


def _identity_status(data):
    value = _uint(data, 2)
    text = _flags(value, (
        (0, "owned"), (2, "configured"), (8, "minor recoverable fault"),
        (9, "minor unrecoverable fault"), (10, "major recoverable fault"),
        (11, "major unrecoverable fault")))
    return f"{text}, extended status {value >> 4 & 0xF:#x}"


IDENTITY_ATTRIBUTES = (
    (1, "Vendor ID", _vendor),
    (2, "Device Type", lambda d: _named(DEVICE_TYPES, _uint(d, 2))),
    (3, "Product Code", lambda d: str(_uint(d, 2))),
    (4, "Revision", _revision),
    (5, "Status", _identity_status),
    (6, "Serial Number", lambda d: f"{_uint(d, 4):#010x} ({_uint(d, 4)})"),
    (7, "Product Name", _short_string),
    (8, "State", lambda d: _named(IDENTITY_STATES, _uint(d, 1))),
    (9, "Configuration Consistency Value", lambda d: str(_uint(d, 2))),
    (10, "Heartbeat Interval (s)", lambda d: str(_uint(d, 1))),
)


def _tcpip_status(data):
    value = _uint(data, 4)
    state = {0: "not configured", 1: "valid configuration (BOOTP/DHCP/stored)",
             2: "valid configuration (hardware)"}.get(value & 0xF, f"reserved {value & 0xF}")
    return _flags(value, ((4, "multicast config pending"), (5, "ACD active"),
                          (6, "ACD fault"))) + f", {state}"


def _tcpip_capability(data):
    return _flags(_uint(data, 4), (
        (0, "BOOTP client"), (1, "DNS client"), (2, "DHCP client"),
        (3, "DHCP-DNS update"), (4, "configurable"), (5, "hardware configurable"),
        (6, "change requires reset"), (7, "ACD capable")))


def _tcpip_control(data):
    value = _uint(data, 4)
    mode = {0: "static/stored", 1: "BOOTP", 2: "DHCP"}.get(value & 0xF, f"reserved {value & 0xF}")
    return f"{value:#010x} (startup: {mode}{', DNS enabled' if value & 0x10 else ''})"


def _path(data):
    words = _uint(data, 2)
    _need(data, 2 + words * 2)
    path = data[2:2 + words * 2]
    if len(path) >= 4 and path[0] == 0x20 and path[2] == 0x24:
        return f"Class {path[1]:#x}, Instance {path[3]}"
    return path.hex(" ") or "empty"


def _interface_config(data):
    _need(data, 20)
    labels = ("IP address", "Subnet mask", "Gateway", "Name server 1", "Name server 2")
    parts = [f"{label}: {_ip(data[index * 4:])}" for index, label in enumerate(labels)]
    parts.append(f"Domain: {_string(data[20:]) or '-'}")
    return "; ".join(parts)


TCPIP_ATTRIBUTES = (
    (1, "Status", _tcpip_status),
    (2, "Configuration Capability", _tcpip_capability),
    (3, "Configuration Control", _tcpip_control),
    (4, "Physical Link Object", _path),
    (5, "Interface Configuration", _interface_config),
    (6, "Host Name", _string),
    (8, "TTL Value", lambda d: str(_uint(d, 1))),
    (13, "Encapsulation Inactivity Timeout (s)", lambda d: str(_uint(d, 2))),
)

LINK_COUNTERS_IN = ("In octets", "In unicast packets", "In non-unicast packets",
                    "In discards", "In errors", "In unknown protocols",
                    "Out octets", "Out unicast packets", "Out non-unicast packets",
                    "Out discards", "Out errors")
LINK_COUNTERS_MEDIA = ("Alignment errors", "FCS errors", "Single collisions",
                       "Multiple collisions", "SQE test errors", "Deferred transmissions",
                       "Late collisions", "Excessive collisions", "MAC transmit errors",
                       "Carrier sense errors", "Frame too long", "MAC receive errors")
NEGOTIATION = {0: "auto-negotiation in progress", 1: "speed/duplex failed, defaults used",
               2: "auto-negotiation failed, speed detected", 3: "successfully negotiated",
               4: "auto-negotiation not attempted, forced"}
LINK_TYPES = {0: "unknown", 1: "internal", 2: "twisted pair", 3: "optical fiber"}


def _link_flags(data):
    value = _uint(data, 4)
    text = f"link {'up' if value & 1 else 'down'}, {'full' if value & 2 else 'half'} duplex"
    text += f", {NEGOTIATION.get(value >> 2 & 7, 'reserved')}"
    for bit, name in ((5, "manual reset required"), (6, "local hardware fault")):
        if value >> bit & 1:
            text += f", {name}"
    return f"{value:#010x} ({text})"


def _counters(names):
    def parse(data):
        _need(data, len(names) * 4)
        values = struct.unpack_from(f"<{len(names)}I", data)
        return "; ".join(f"{name}: {value}" for name, value in zip(names, values))
    return parse


def _link_control(data):
    _need(data, 4)
    control, speed = struct.unpack_from("<HH", data)
    mode = "auto-negotiate" if not control & 1 else (
        f"forced {speed} Mbps {'full' if control & 2 else 'half'} duplex")
    return f"{control:#06x} ({mode})"


ETHERNET_LINK_ATTRIBUTES = (
    (1, "Interface Speed (Mbps)", lambda d: str(_uint(d, 4))),
    (2, "Interface Flags", _link_flags),
    (3, "Physical Address", lambda d: (_need(d, 6), d[:6].hex("-").upper())[1]),
    (4, "Interface Counters", _counters(LINK_COUNTERS_IN)),
    (5, "Media Counters", _counters(LINK_COUNTERS_MEDIA)),
    (6, "Interface Control", _link_control),
    (7, "Interface Type", lambda d: _named(LINK_TYPES, _uint(d, 1))),
    (8, "Interface State", lambda d: str(_uint(d, 1))),
    (9, "Admin State", lambda d: str(_uint(d, 1))),
    (10, "Interface Label", _short_string),
)

OBJECTS = {
    "Identity": (0x01, IDENTITY_ATTRIBUTES),
    "TCP/IP": (0xF5, TCPIP_ATTRIBUTES),
    "Ethernet Link": (0xF6, ETHERNET_LINK_ATTRIBUTES),
}
MAX_LINK_INSTANCES = 4


def format_attribute(parser, data):
    try:
        return parser(data)
    except (ValueError, struct.error) as error:
        return f"Could not decode ({error})"


def _get(driver, class_code, instance, attribute):
    response = driver.generic_message(
        service=Services.get_attribute_single, class_code=class_code,
        instance=instance, attribute=attribute, connected=False,
        unconnected_send=False, route_path=False,
        name=f"Read Class {class_code:#x} Inst {instance} Attr {attribute}")
    if response is None or response.error or response.value is None:
        return None
    return bytes(response.value)


def read_cip_object(address, object_name):
    """Read every known attribute; unsupported attributes are reported, not fatal."""
    if object_name not in OBJECTS:
        raise ValueError(f"Unknown CIP object: {object_name}")
    if not usable_ip(address):
        raise ValueError(f"Invalid or unusable target IPv4 address: {address}")
    class_code, attributes = OBJECTS[object_name]
    rows = []
    try:
        with CIPDriver(address) as driver:
            instances = [1]
            if class_code == 0xF6:
                maximum = _get(driver, class_code, 0, 2)
                if maximum and len(maximum) >= 2:
                    instances = range(1, min(_uint(maximum, 2), MAX_LINK_INSTANCES) + 1)
            for instance in instances:
                for attribute, name, parser in attributes:
                    data = _get(driver, class_code, instance, attribute)
                    if data is None:
                        rows.append(AttributeRow(instance, attribute, name, "Not supported / no data"))
                    else:
                        rows.append(AttributeRow(
                            instance, attribute, name, format_attribute(parser, data),
                            data.hex(" ")))
    except Exception as error:
        raise CIPObjectError(f"EtherNet/IP request to {address} failed: {error}") from error
    if rows and all(row.raw == "" for row in rows):
        raise CIPObjectError(
            f"{address} did not answer any attribute of class {class_code:#x}.")
    return rows
