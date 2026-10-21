import struct
import threading
import unittest
from types import SimpleNamespace

from eip_tool.cip_scanner import (
    CIPScanError, ScanOptions, guess_value, parse_class_ranges, scan_device,
)


class FakeDevice:
    """Answers Get_Attribute_Single like a real device: 0x05 unknown class, 0x16 unknown
    instance, 0x14 unsupported attribute."""

    def __init__(self, classes, unknown_class_status=0x05, router_list=None):
        self.classes = classes
        self.unknown_class_status = unknown_class_status
        self.router_list = router_list
        self.requests = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def generic_message(self, class_code, instance, attribute, **kwargs):
        assert kwargs["return_response_packet"] is True
        self.requests.append((class_code, instance, attribute))
        status, data = self._answer(class_code, instance, attribute)
        return SimpleNamespace(
            value=SimpleNamespace(service_status=status, data=data),
            error=None if status == 0 else f"status {status:#x}")

    def _answer(self, class_code, instance, attribute):
        if class_code == 0x02 and self.router_list is not None and (instance, attribute) == (1, 1):
            return 0, struct.pack(f"<H{len(self.router_list)}H", len(self.router_list),
                                  *self.router_list)
        if class_code not in self.classes:
            return self.unknown_class_status, b""
        cls = self.classes[class_code]
        attributes = cls["class"] if instance == 0 else cls["instances"].get(instance)
        if attributes is None:
            return 0x16, b""
        if attribute not in attributes:
            return 0x14, b""
        return 0, attributes[attribute]


def uint(value):
    return struct.pack("<H", value)


DEVICE = {
    0x01: {"class": {1: uint(1), 2: uint(1)},
           "instances": {1: {1: uint(1), 7: b"\x05XPort"}}},
    0x04: {"class": {1: uint(2), 2: uint(150)},
           "instances": {101: {3: bytes(16)}, 102: {3: bytes(12)}, 150: {3: b""}}},
}


def scan(device, **options):
    defaults = {"classes": list(range(1, 0x10)), "use_message_router": False}
    defaults.update(options)
    return list(scan_device(
        "192.168.0.10", ScanOptions(**defaults), driver_factory=lambda address: device))


class ScanTests(unittest.TestCase):
    def test_discovers_classes_instances_and_attributes(self):
        results = {result.class_code: result for result in scan(FakeDevice(DEVICE))}
        self.assertEqual(sorted(results), [0x01, 0x04])
        identity = results[0x01]
        self.assertEqual(identity.name, "Identity")
        self.assertEqual([item.attribute for item in identity.class_attributes], [1, 2])
        attributes = {item.attribute: item for item in identity.instances[0].attributes}
        self.assertEqual(sorted(attributes), [1, 7])
        self.assertEqual(attributes[7].name, "Product Name")
        self.assertEqual(attributes[7].value, "XPort")
        assembly = results[0x04]
        self.assertEqual([instance.instance for instance in assembly.instances], [101, 102, 150])
        data = assembly.instances[0].attributes[0]
        self.assertEqual((data.attribute, data.name, len(data.data)), (3, "Data", 16))

    def test_max_instance_bounds_probing_and_limit_is_reported(self):
        device = FakeDevice(DEVICE)
        results = {result.class_code: result for result in scan(device, instance_limit=120)}
        self.assertEqual([i.instance for i in results[0x04].instances], [101, 102])
        self.assertIn("exceeds the instance limit", results[0x04].notes[0])
        # Identity reports max instance 1, so instances 2+ are never probed.
        self.assertNotIn((0x01, 2, 1), device.requests)

    def test_ambiguous_service_not_supported_classes_stay_cheap(self):
        device = FakeDevice(DEVICE, unknown_class_status=0x08)
        results = scan(device, classes=list(range(1, 0x100)))
        self.assertEqual(sorted(result.class_code for result in results), [0x01, 0x04])
        unknown = [request for request in device.requests if request[0] not in (1, 4)]
        self.assertLessEqual(len(unknown), 2 * 253)

    def test_message_router_list_adds_classes_outside_the_range(self):
        device = FakeDevice({**DEVICE, 0x300: {"class": {}, "instances": {1: {5: b"\x2a"}}}},
                            router_list=[0x01, 0x04, 0x300])
        results = {r.class_code: r for r in scan(
            device, classes=[1], use_message_router=True, instance_limit=2)}
        self.assertEqual(sorted(results), [0x01, 0x04, 0x300])
        self.assertEqual(results[0x300].source, "Message Router")
        self.assertEqual(results[0x300].name, "Vendor specific")
        self.assertEqual(results[0x300].instances[0].attributes[0].value, "42 (USINT)")

    def test_stop_event_ends_scan_without_error(self):
        stop = threading.Event()
        stop.set()
        results = list(scan_device(
            "192.168.0.10", ScanOptions([1, 4], False), stop_event=stop,
            driver_factory=lambda address: FakeDevice(DEVICE)))
        self.assertEqual(results, [])

    def test_missing_reply_aborts_with_scan_error(self):
        device = FakeDevice(DEVICE)
        device.generic_message = lambda **kwargs: SimpleNamespace(
            value=SimpleNamespace(service_status=None, data=None), error="timeout")
        with self.assertRaisesRegex(CIPScanError, "timeout"):
            scan(device)

    def test_connection_failure_is_wrapped(self):
        def factory(address):
            raise OSError("refused")
        with self.assertRaisesRegex(CIPScanError, "refused"):
            list(scan_device("192.168.0.10", ScanOptions([1]), driver_factory=factory))

    def test_rejects_unusable_address(self):
        with self.assertRaises(ValueError):
            list(scan_device("0.0.0.0", ScanOptions([1])))


class HelperTests(unittest.TestCase):
    def test_parse_class_ranges(self):
        self.assertEqual(parse_class_ranges("0x01-0x03, 0xF5 246"), [1, 2, 3, 0xF5, 0xF6])
        self.assertEqual(parse_class_ranges(""), [])
        for bad in ("0x00", "5-3", "abc", "1-2-3", "0x10000"):
            with self.assertRaises(ValueError, msg=bad):
                parse_class_ranges(bad)

    def test_guess_value(self):
        self.assertEqual(guess_value(b"\x03abc"), '"abc" (SHORT_STRING)')
        self.assertEqual(guess_value(b"\x03\x00abc"), '"abc" (STRING)')
        self.assertEqual(guess_value(uint(258)), "258 (UINT)")
        self.assertEqual(guess_value(struct.pack("<I", 70000)), "70000 (UDINT)")
        self.assertEqual(guess_value(uint(1) + uint(2) + uint(3)), "3 words: 1 2 3")
        self.assertEqual(guess_value(b""), "(empty)")


if __name__ == "__main__":
    unittest.main()
