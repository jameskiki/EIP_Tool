import struct
import unittest
from unittest.mock import MagicMock, patch

from eip_tool import cip_objects
from eip_tool.cip_objects import CIPObjectError, read_cip_object


def parse(table, attribute, data):
    for number, _, parser in table:
        if number == attribute:
            return cip_objects.format_attribute(parser, data)
    raise KeyError(attribute)


class ParserTests(unittest.TestCase):
    def test_identity_attributes(self):
        table = cip_objects.IDENTITY_ATTRIBUTES
        self.assertIn("Rockwell", parse(table, 1, struct.pack("<H", 1)))
        self.assertIn("Communications Adapter", parse(table, 2, struct.pack("<H", 0x0C)))
        self.assertEqual(parse(table, 4, bytes([2, 7])), "2.007")
        self.assertEqual(parse(table, 7, b"\x05XPort"[:6]), "XPort")
        self.assertIn("Operational", parse(table, 8, b"\x03"))
        self.assertIn("owned", parse(table, 5, struct.pack("<H", 0x0021)))

    def test_tcpip_interface_configuration(self):
        raw = b"".join(struct.pack("<I", int.from_bytes(bytes(map(int, ip.split("."))), "big"))
                       for ip in ("192.168.0.20", "255.255.255.0", "192.168.0.1", "0.0.0.0", "0.0.0.0"))
        raw += struct.pack("<H", 0)
        text = parse(cip_objects.TCPIP_ATTRIBUTES, 5, raw)
        self.assertIn("IP address: 192.168.0.20", text)
        self.assertIn("Subnet mask: 255.255.255.0", text)
        self.assertIn("Gateway: 192.168.0.1", text)

    def test_tcpip_control_and_path(self):
        self.assertIn("BOOTP", parse(cip_objects.TCPIP_ATTRIBUTES, 3, struct.pack("<I", 1)))
        path = struct.pack("<H", 2) + bytes([0x20, 0xF6, 0x24, 0x01])
        self.assertEqual(parse(cip_objects.TCPIP_ATTRIBUTES, 4, path), "Class 0xf6, Instance 1")

    def test_ethernet_link_attributes(self):
        table = cip_objects.ETHERNET_LINK_ATTRIBUTES
        self.assertEqual(parse(table, 1, struct.pack("<I", 100)), "100")
        flags = parse(table, 2, struct.pack("<I", 0x0F))
        self.assertIn("link up", flags)
        self.assertIn("full duplex", flags)
        self.assertEqual(parse(table, 3, bytes.fromhex("0020a1b2c3d4")), "00-20-A1-B2-C3-D4")
        counters = parse(table, 4, struct.pack("<11I", *range(11)))
        self.assertIn("In octets: 0", counters)
        self.assertIn("Out errors: 10", counters)

    def test_truncated_data_is_reported_not_raised(self):
        self.assertIn("Could not decode", parse(cip_objects.TCPIP_ATTRIBUTES, 5, b"\x00"))


class ReadTests(unittest.TestCase):
    def driver(self, answers):
        driver = MagicMock()
        driver.__enter__.return_value = driver

        def generic_message(**kwargs):
            value = answers.get((kwargs["class_code"], kwargs["instance"], kwargs["attribute"]))
            return MagicMock(error=None if value is not None else "unsupported", value=value)

        driver.generic_message.side_effect = generic_message
        return driver

    def test_reports_unsupported_attributes(self):
        driver = self.driver({(1, 1, 1): struct.pack("<H", 1), (1, 1, 7): b"\x04Test"})
        with patch.object(cip_objects, "CIPDriver", return_value=driver):
            rows = read_cip_object("192.168.0.10", "Identity")
        self.assertEqual(len(rows), len(cip_objects.IDENTITY_ATTRIBUTES))
        self.assertEqual(next(r for r in rows if r.attribute == 7).value, "Test")
        self.assertEqual(next(r for r in rows if r.attribute == 3).value, "Not supported / no data")

    def test_ethernet_link_reads_each_reported_instance(self):
        answers = {(0xF6, 0, 2): struct.pack("<H", 2),
                   (0xF6, 1, 1): struct.pack("<I", 100), (0xF6, 2, 1): struct.pack("<I", 10)}
        with patch.object(cip_objects, "CIPDriver", return_value=self.driver(answers)):
            rows = read_cip_object("192.168.0.10", "Ethernet Link")
        speeds = {r.instance: r.value for r in rows if r.attribute == 1}
        self.assertEqual(speeds, {1: "100", 2: "10"})

    def test_no_answers_is_an_error(self):
        with patch.object(cip_objects, "CIPDriver", return_value=self.driver({})):
            with self.assertRaises(CIPObjectError):
                read_cip_object("192.168.0.10", "TCP/IP")

    def test_rejects_unusable_address(self):
        with self.assertRaises(ValueError):
            read_cip_object("0.0.0.0", "Identity")


if __name__ == "__main__":
    unittest.main()
