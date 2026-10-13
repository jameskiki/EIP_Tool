import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from ipaddress import IPv4Address

from scapy.layers.l2 import ARP, Ether
from pycomm3 import Services, UDINT

from eip_tool.xport_config import (
    CIPConfigurationError,
    apply_static_xport_address,
    set_bootp_mode,
    validate_static_parameters,
)


class FakeDriverFactory:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, address):
        return FakeDriver(self, address)


class FakeDriver:
    def __init__(self, factory, address):
        self.factory = factory
        self.address = address

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def generic_message(self, **kwargs):
        self.factory.calls.append((self.address, kwargs))
        response = self.factory.responses.pop(0)
        if isinstance(response, Exception):
            return SimpleNamespace(value=None, error=response)
        return SimpleNamespace(value=response, error=None)


class XPortConfigurationTests(unittest.TestCase):
    @staticmethod
    def interface_config(address, mask, gateway, dns="8.8.8.8"):
        fields = struct.pack("<5I", *(int(IPv4Address(value)) for value in (
            address, mask, gateway, dns, "0.0.0.0")))
        domain = b"bench"
        return fields + len(domain).to_bytes(2, "little") + domain

    def test_static_apply_writes_interface_config_then_static_mode(self):
        original = self.interface_config(
            "192.168.1.20", "255.255.255.0", "192.168.1.1")
        expected = self.interface_config(
            "192.168.1.30", "255.255.255.0", "192.168.1.1")
        drivers = FakeDriverFactory([
            0x11, 1, 1, original, None, 0,
            ConnectionError("connection refused"), expected, 0,
        ])
        with patch("eip_tool.xport_config.CIPDriver", side_effect=drivers), \
                patch("eip_tool.xport_config.srp", return_value=([], [])):
            apply_static_xport_address(
                "wired-interface", "192.168.1.10", "192.168.1.0/24",
                "00:00:bc:01:02:03", "192.168.1.20", "192.168.1.30",
                "255.255.255.0", "192.168.1.1")

        attributes = [call[1]["attribute"] for call in drivers.calls]
        self.assertEqual(attributes, [2, 1, 3, 5, 3, 3, 5, 5, 3])
        self.assertTrue(all(not call[1]["unconnected_send"] for call in drivers.calls))
        self.assertTrue(all(call[1]["route_path"] is False for call in drivers.calls))
        self.assertEqual(drivers.calls[4][1]["service"], Services.set_attribute_single)
        self.assertEqual(drivers.calls[4][1]["request_data"], UDINT.encode(0))
        self.assertEqual(drivers.calls[6][1]["service"], Services.set_attribute_single)
        self.assertEqual(drivers.calls[6][1]["request_data"], expected)
        self.assertEqual(drivers.calls[7][0], "192.168.1.30")

    def test_hardware_selected_network_status_blocks_ip_write(self):
        drivers = FakeDriverFactory([0x11, 2])
        with patch("eip_tool.xport_config.CIPDriver", side_effect=drivers), \
                patch("eip_tool.xport_config.srp", return_value=([], [])):
            with self.assertRaisesRegex(CIPConfigurationError, "hardware-selected"):
                apply_static_xport_address(
                    "wired-interface", "192.168.1.10", "192.168.1.0/24",
                    "00:00:bc:01:02:03", "192.168.1.20", "192.168.1.30",
                    "255.255.255.0", "")
        self.assertEqual([call[1]["attribute"] for call in drivers.calls], [2, 1])

    def test_cross_subnet_readback_retries_without_repeating_write(self):
        original = self.interface_config("192.168.1.20", "255.255.255.0", "0.0.0.0")
        expected = self.interface_config("192.168.0.30", "255.255.255.0", "0.0.0.0")
        drivers = FakeDriverFactory([
            0x11, 1, 0, original, None,
            ConnectionError("switching address"), expected, 0,
        ])
        with patch("eip_tool.xport_config.CIPDriver", side_effect=drivers), \
                patch("eip_tool.xport_config.srp", return_value=([], [])), \
                patch("eip_tool.xport_config.threading.Event") as retry_wait:
            apply_static_xport_address(
                "wired-interface", "192.168.0.10", "192.168.0.0/24",
                "00:00:bc:01:02:03", "192.168.1.20", "192.168.0.30",
                "255.255.255.0", "")
        retry_wait.return_value.wait.assert_called_once_with(1)
        writes = [entry for entry in drivers.calls
                  if entry[1]["service"] == Services.set_attribute_single]
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0][0], "192.168.1.20")
        self.assertEqual(drivers.calls[-1][0], "192.168.0.30")

    def test_unreachable_new_address_is_not_reported_as_success(self):
        original = self.interface_config("192.168.1.20", "255.255.255.0", "0.0.0.0")
        drivers = FakeDriverFactory([
            0x11, 1, 0, original, None,
            *[ConnectionError("connection refused") for _ in range(6)],
        ])
        with patch("eip_tool.xport_config.CIPDriver", side_effect=drivers), \
                patch("eip_tool.xport_config.srp", return_value=([], [])), \
                patch("eip_tool.xport_config.threading.Event") as retry_wait:
            with self.assertRaisesRegex(CIPConfigurationError, "may already have changed address"):
                apply_static_xport_address(
                    "wired-interface", "192.168.0.10", "192.168.0.0/24",
                    "00:00:bc:01:02:03", "192.168.1.20", "192.168.0.30",
                    "255.255.255.0", "")
        self.assertEqual(retry_wait.return_value.wait.call_count, 5)
        self.assertEqual(len(drivers.calls), 11)

    def test_mismatched_readback_never_confirms_static_configuration(self):
        from eip_tool.xport_config import _verify_static_configuration
        expected = self.interface_config("192.168.0.30", "255.255.255.0", "0.0.0.0")
        wrong_mask = self.interface_config("192.168.0.30", "255.255.0.0", "0.0.0.0")
        with patch("eip_tool.xport_config._read_attribute", return_value=wrong_mask) as read, \
                patch("eip_tool.xport_config.threading.Event"):
            with self.assertRaisesRegex(CIPConfigurationError, "do not match"):
                _verify_static_configuration("192.168.0.30", expected)
        self.assertEqual(read.call_count, 6)

    def test_enable_bootp_sets_and_verifies_configuration_control(self):
        drivers = FakeDriverFactory([0x11, 0, None, 1])
        with patch("eip_tool.xport_config.CIPDriver", side_effect=drivers):
            set_bootp_mode("192.168.1.20", enable=True)
        self.assertEqual([call[1]["attribute"] for call in drivers.calls], [2, 3, 3, 3])
        self.assertEqual(drivers.calls[2][1]["service"], Services.set_attribute_single)
        self.assertEqual(drivers.calls[2][1]["request_data"], UDINT.encode(1))

    def test_disable_bootp_preserves_non_mode_control_bits(self):
        drivers = FakeDriverFactory([0x11, 0x11, None, 0x10])
        with patch("eip_tool.xport_config.CIPDriver", side_effect=drivers):
            set_bootp_mode("192.168.1.20", enable=False)
        self.assertEqual(drivers.calls[2][1]["request_data"], UDINT.encode(0x10))

    def test_static_apply_refuses_devices_without_cip_configuration_capability(self):
        drivers = FakeDriverFactory([0x01])
        with patch("eip_tool.xport_config.CIPDriver", side_effect=drivers), \
                patch("eip_tool.xport_config.srp", return_value=([], [])):
            with self.assertRaisesRegex(CIPConfigurationError, "not writable"):
                apply_static_xport_address(
                    "wired-interface", "192.168.1.10", "192.168.1.0/24",
                    "00:00:bc:01:02:03", "192.168.1.20", "192.168.1.30",
                    "255.255.255.0", "")
        self.assertEqual(len(drivers.calls), 1)

    def test_conflicting_address_is_rejected_before_cip_write(self):
        reply = Ether() / ARP(hwsrc="00:11:22:33:44:55", psrc="192.168.1.20")
        with patch("eip_tool.xport_config.srp", return_value=([(None, reply)], [])), \
                patch("eip_tool.xport_config.CIPDriver") as driver:
            with self.assertRaisesRegex(ValueError, "already responds to ARP"):
                apply_static_xport_address(
                    "wired-interface", "192.168.1.10", "192.168.1.0/24",
                    "00:00:bc:01:02:03", "192.168.1.20", "192.168.1.30",
                    "255.255.255.0", "")
        driver.assert_not_called()

    def test_static_address_may_be_outside_current_adapter_subnet(self):
        network = validate_static_parameters(
            "192.168.1.10", "192.168.1.0/24", "192.168.101.173",
            "255.255.255.0", "192.168.101.1", "00:00:bc:01:02:03")
        self.assertEqual(str(network), "192.168.101.0/24")

    def test_scan_subnet_must_contain_current_adapter_address(self):
        with patch("eip_tool.xport_config.srp") as probe, \
                patch("eip_tool.xport_config.CIPDriver") as driver:
            with self.assertRaisesRegex(ValueError, "contain the adapter"):
                apply_static_xport_address(
                    "wired-interface", "192.168.1.10", "192.168.2.0/24",
                    "00:00:bc:01:02:03", "192.168.1.20", "192.168.2.20",
                    "255.255.255.0", "")
        probe.assert_not_called()
        driver.assert_not_called()


if __name__ == "__main__":
    unittest.main()