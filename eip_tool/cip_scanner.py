"""Read-only CIP object scanner: discovers classes, instances, and readable attributes.

Only Get_Attribute_Single (0x0E) requests are sent. Existence is inferred from the
CIP general status: 0x04/0x05/0x16 mean the path does not exist, while e.g. 0x14
(attribute not supported) proves the class/instance itself exists.
"""

from dataclasses import dataclass, field
import re
import struct
import threading

from pycomm3 import CIPDriver, Services

from .cip_objects import OBJECTS, format_attribute
from .discovery import usable_ip


class CIPScanError(RuntimeError):
    pass


SUCCESS_STATUSES = {0x00, 0x06}
NOT_FOUND_STATUSES = {0x04, 0x05, 0x16}
# Statuses that say nothing about whether an attribute exists; such attributes are hidden.
UNSUPPORTED_ATTRIBUTE_STATUSES = NOT_FOUND_STATUSES | {0x08, 0x14}

STATUS_NAMES = {
    0x00: "Success", 0x02: "Resource unavailable", 0x04: "Path segment error",
    0x05: "Path destination unknown", 0x06: "Partial transfer", 0x08: "Service not supported",
    0x09: "Invalid attribute value", 0x0C: "Object state conflict", 0x0F: "Privilege violation",
    0x10: "Device state conflict", 0x11: "Reply data too large", 0x13: "Not enough data",
    0x14: "Attribute not supported", 0x15: "Too much data", 0x16: "Object does not exist",
    0x1E: "Embedded service error", 0x1F: "Vendor specific error", 0x20: "Invalid parameter",
}

CLASS_NAMES = {
    0x01: "Identity", 0x02: "Message Router", 0x03: "DeviceNet", 0x04: "Assembly",
    0x05: "Connection", 0x06: "Connection Manager", 0x07: "Register",
    0x08: "Discrete Input Point", 0x09: "Discrete Output Point",
    0x0A: "Analog Input Point", 0x0B: "Analog Output Point", 0x0F: "Parameter",
    0x10: "Parameter Group", 0x12: "Group", 0x29: "Control Supervisor",
    0x2A: "AC/DC Drive", 0x2B: "Acknowledge Handler", 0x37: "File", 0x43: "Time Sync",
    0x44: "Modbus", 0x47: "Device Level Ring", 0x48: "QoS", 0x67: "PCCC",
    0xF4: "Port", 0xF5: "TCP/IP Interface", 0xF6: "Ethernet Link",
}

CLASS_ATTRIBUTE_NAMES = {
    1: "Revision", 2: "Max Instance", 3: "Number of Instances",
    4: "Optional Attribute List", 5: "Optional Service List",
    6: "Max Class Attribute ID", 7: "Max Instance Attribute ID",
}

INSTANCE_ATTRIBUTE_NAMES = {
    0x02: {1: "Object List", 2: "Number Available", 3: "Number Active", 4: "Active Connections"},
    0x04: {1: "Number of Members", 2: "Member List", 3: "Data", 4: "Size"},
}
_KNOWN_PARSERS = {
    (class_code, attribute): (name, parser)
    for class_code, attributes in OBJECTS.values()
    for attribute, name, parser in attributes
}


def class_name(class_code):
    if class_code in CLASS_NAMES:
        return CLASS_NAMES[class_code]
    if 0x64 <= class_code <= 0xC7 or 0x300 <= class_code <= 0x4FF:
        return "Vendor specific"
    return "Unknown"


def status_text(status):
    return f"{status:#04x} {STATUS_NAMES.get(status, 'CIP error')}"


def attribute_name(class_code, instance, attribute):
    if instance == 0:
        return CLASS_ATTRIBUTE_NAMES.get(attribute, "")
    if (class_code, attribute) in _KNOWN_PARSERS:
        return _KNOWN_PARSERS[(class_code, attribute)][0]
    return INSTANCE_ATTRIBUTE_NAMES.get(class_code, {}).get(attribute, "")


def guess_value(data):
    """Best-effort decoding of an unknown attribute's raw bytes."""
    if not data:
        return "(empty)"
    size = len(data)
    if size >= 2 and data[0] == size - 1 and _printable(data[1:]):
        return f'"{data[1:].decode("latin-1")}" (SHORT_STRING)'
    if size >= 3 and int.from_bytes(data[:2], "little") == size - 2 and _printable(data[2:]):
        return f'"{data[2:].decode("latin-1")}" (STRING)'
    if size == 1:
        return f"{data[0]} (USINT)"
    if size == 2:
        return f"{struct.unpack('<H', data)[0]} (UINT)"
    if size == 4:
        return f"{struct.unpack('<I', data)[0]} (UDINT)"
    if size % 2 == 0 and size <= 64:
        words = struct.unpack(f"<{size // 2}H", data)
        return f"{size // 2} words: " + " ".join(str(word) for word in words)
    return f"{size} bytes"


def _printable(data):
    return bool(data) and all(32 <= byte < 127 for byte in data)


def decode_value(class_code, instance, attribute, data):
    if instance != 0 and (class_code, attribute) in _KNOWN_PARSERS:
        return format_attribute(_KNOWN_PARSERS[(class_code, attribute)][1], data)
    if instance == 0 and attribute in (1, 2, 3, 6, 7) and len(data) == 2:
        return str(int.from_bytes(data, "little"))
    return guess_value(data)


def parse_class_ranges(text):
    """Parse '0x01-0xFF, 0x300, 100-110' into a sorted list of class IDs."""
    classes = set()
    for token in filter(None, (part.strip() for part in re.split(r"[,;\s]+", text))):
        bounds = token.split("-")
        if len(bounds) > 2:
            raise ValueError(f"Invalid class range: {token}")
        try:
            low, high = (int(bound, 0) for bound in (bounds[0], bounds[-1]))
        except ValueError as error:
            raise ValueError(f"Invalid class number in {token!r}; use decimal or 0x hex.") from error
        if not 1 <= low <= high <= 0xFFFF:
            raise ValueError(f"Class range {token!r} must be within 0x0001-0xFFFF.")
        classes.update(range(low, high + 1))
    if len(classes) > 4096:
        raise ValueError("Limit a scan to at most 4096 classes.")
    return sorted(classes)


@dataclass
class AttributeResult:
    class_code: int
    instance: int
    attribute: int
    status: int
    data: bytes = b""

    @property
    def readable(self):
        return self.status in SUCCESS_STATUSES

    @property
    def name(self):
        return attribute_name(self.class_code, self.instance, self.attribute)

    @property
    def value(self):
        if not self.readable:
            return status_text(self.status)
        return decode_value(self.class_code, self.instance, self.attribute, self.data)


@dataclass
class InstanceResult:
    instance: int
    attributes: list = field(default_factory=list)


@dataclass
class ClassResult:
    class_code: int
    source: str
    class_attributes: list = field(default_factory=list)
    instances: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def name(self):
        return class_name(self.class_code)


@dataclass
class ScanOptions:
    classes: list
    use_message_router: bool = True
    instance_limit: int = 200
    attribute_limit: int = 32


class _Session:
    def __init__(self, driver, stop_event):
        self.driver = driver
        self.stop_event = stop_event
        self.requests = 0

    def get(self, class_code, instance, attribute):
        if self.stop_event.is_set():
            raise _Stopped()
        self.requests += 1
        try:
            tag = self.driver.generic_message(
                service=Services.get_attribute_single, class_code=class_code,
                instance=instance, attribute=attribute, connected=False,
                unconnected_send=False, route_path=False, return_response_packet=True,
                name=f"Scan Class {class_code:#x} Inst {instance} Attr {attribute}")
        except Exception as error:
            raise CIPScanError(f"Communication failed during scan: {error}") from error
        response = tag.value
        status = getattr(response, "service_status", None)
        if status is None:
            raise CIPScanError(
                f"No CIP reply for class {class_code:#x} instance {instance} "
                f"attribute {attribute}: {tag.error}")
        data = bytes(response.data or b"") if status in SUCCESS_STATUSES else b""
        return AttributeResult(class_code, instance, attribute, status, data)


class _Stopped(Exception):
    pass


def _message_router_classes(session):
    result = session.get(0x02, 1, 1)
    if not result.readable or len(result.data) < 2:
        return []
    count = int.from_bytes(result.data[:2], "little")
    available = (len(result.data) - 2) // 2
    return list(struct.unpack_from(f"<{min(count, available)}H", result.data, 2))


def _uint_attribute(results, attribute):
    for result in results:
        if result.attribute == attribute and result.readable and len(result.data) >= 2:
            return int.from_bytes(result.data[:2], "little")
    return None


def _instance_exists(session, class_code, instance):
    """Return the first probe result if the instance exists, otherwise None."""
    for attribute in (1, 3):
        result = session.get(class_code, instance, attribute)
        if result.status not in NOT_FOUND_STATUSES:
            return result
    return None


def _scan_class(session, class_code, listed, options, progress):
    first = session.get(class_code, 0, 1)
    if first.status in NOT_FOUND_STATUSES and not listed:
        return None
    # A class is confirmed by the Message Router list, a readable class attribute, or a
    # status proving the path resolved. 0x08 alone is ambiguous, so instance 1 must prove
    # it; this keeps devices that answer 0x08 for every unknown class from exploding the scan.
    confirmed = listed or first.readable or first.status == 0x14
    if not confirmed:
        probe = session.get(class_code, 1, 1)
        if not (probe.readable or probe.status == 0x14):
            return None
    result = ClassResult(class_code, "Message Router" if listed else "Probe")
    class_attributes = [first]
    if first.status not in NOT_FOUND_STATUSES | {0x08}:
        class_attributes += [session.get(class_code, 0, attribute) for attribute in range(2, 8)]
    result.class_attributes = [
        item for item in class_attributes if item.status not in UNSUPPORTED_ATTRIBUTE_STATUSES]

    max_instance = _uint_attribute(class_attributes, 2)
    max_attribute = _uint_attribute(class_attributes, 7)
    instance_count = options.instance_limit
    if max_instance:
        instance_count = min(max_instance, options.instance_limit)
        if max_instance > options.instance_limit:
            result.notes.append(
                f"Max instance {max_instance} exceeds the instance limit; "
                f"only 1-{options.instance_limit} scanned.")
    attribute_count = options.attribute_limit
    if max_attribute and 0 < max_attribute <= 255:
        attribute_count = max_attribute

    for instance in range(1, instance_count + 1):
        progress(f"Class {class_code:#06x} {result.name}: probing instance {instance}/{instance_count}")
        if _instance_exists(session, class_code, instance) is None:
            continue
        instance_result = InstanceResult(instance)
        for attribute in range(1, attribute_count + 1):
            item = session.get(class_code, instance, attribute)
            if item.status not in UNSUPPORTED_ATTRIBUTE_STATUSES:
                instance_result.attributes.append(item)
        result.instances.append(instance_result)

    if not result.instances:
        result.notes.append("No instances found within the instance limit.")
    return result


def scan_device(address, options, progress=None, stop_event=None, driver_factory=CIPDriver):
    """Yield a ClassResult for each class found. Raises CIPScanError on communication loss."""
    if not usable_ip(address):
        raise ValueError(f"Invalid or unusable target IPv4 address: {address}")
    if options.instance_limit < 1 or options.attribute_limit < 1:
        raise ValueError("Instance and attribute limits must be at least 1.")
    progress = progress or (lambda message, done=None, total=None: None)
    stop_event = stop_event or threading.Event()
    try:
        with driver_factory(address) as driver:
            session = _Session(driver, stop_event)
            listed = set()
            if options.use_message_router:
                progress("Reading Message Router object list (class 0x02)...")
                listed = set(_message_router_classes(session))
            classes = sorted(set(options.classes) | listed)
            for index, class_code in enumerate(classes):
                progress(f"Class {class_code:#06x} {class_name(class_code)}", index, len(classes))
                found = _scan_class(
                    session, class_code, class_code in listed, options,
                    lambda message: progress(message, index, len(classes)))
                if found is not None:
                    yield found
            progress(f"Scan complete: {session.requests} requests.", len(classes), len(classes))
    except _Stopped:
        progress("Scan stopped.")
    except CIPScanError:
        raise
    except Exception as error:
        raise CIPScanError(f"EtherNet/IP connection to {address} failed: {error}") from error
