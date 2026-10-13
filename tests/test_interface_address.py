import subprocess
import unittest
from types import SimpleNamespace
from ipaddress import IPv4Network
from unittest.mock import Mock, patch

from eip_tool.interface_address import (
    add_temporary_ipv4_alias, remove_temporary_ipv4_alias,
    validate_alias_parameters,
)


class InterfaceAddressTests(unittest.TestCase):
    def test_alias_must_be_a_host_in_the_observed_device_subnet(self):
        network = validate_alias_parameters(
            "192.168.101.173", "192.168.20.20", "192.168.101.20", "255.255.255.0")
        self.assertEqual(network, IPv4Network("192.168.101.0/24"))
        for alias in ("192.168.20.30", "192.168.101.173", "192.168.101.255"):
            with self.subTest(alias=alias), self.assertRaises(ValueError):
                validate_alias_parameters(
                    "192.168.101.173", "192.168.20.20", alias, "255.255.255.0")

    def test_add_alias_arp_checks_then_uses_temporary_windows_address(self):
        iphlpapi = SimpleNamespace(AddIPAddress=Mock())

        def add_address(address, mask, index, context, instance):
            context._obj.value = 73
            instance._obj.value = 1
            return 0

        iphlpapi.AddIPAddress.side_effect = add_address
        with patch("eip_tool.interface_address.sys.platform", "win32"), \
                patch("eip_tool.interface_address.srp", return_value=([], [])) as arp_probe, \
                patch("eip_tool.interface_address._windows_adapter_index", return_value=3), \
                patch("eip_tool.interface_address._windows_wait_alias_ready") as ready, \
            patch("eip_tool.interface_address.ctypes.WinDLL",
                  return_value=iphlpapi, create=True):
            network = add_temporary_ipv4_alias(
                "Onboard Ethernet", "192.168.101.173", "192.168.20.20",
                "192.168.101.20", "255.255.255.0")
        self.assertEqual(network, IPv4Network("192.168.101.0/24"))
        ready.assert_called_once_with("Onboard Ethernet", "192.168.101.20", "255.255.255.0")
        arp_probe.assert_called_once()
        self.assertEqual(iphlpapi.AddIPAddress.call_args.args[:3],
                         (int.from_bytes(bytes([192, 168, 101, 20]), "little"),
                          int.from_bytes(bytes([255, 255, 255, 0]), "little"), 3))
        from eip_tool import interface_address
        self.assertIn(("Onboard Ethernet", "192.168.101.20"),
                  interface_address._windows_alias_contexts)

    def test_conflicting_alias_is_not_added(self):
        with patch("eip_tool.interface_address.srp", return_value=([(None, None)], [])), \
                patch("eip_tool.interface_address.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "already responds to ARP"):
                add_temporary_ipv4_alias(
                    "Onboard Ethernet", "192.168.101.173", "192.168.20.20",
                    "192.168.101.20", "255.255.255.0")
        run.assert_not_called()

    def test_windows_alias_waits_until_preferred(self):
        from eip_tool.interface_address import _windows_wait_alias_ready
        tentative = {"IPAddress": "192.168.0.20", "PrefixLength": 24,
                     "State": "Tentative", "SkipAsSource": False}
        preferred = dict(tentative, State="Preferred")
        with patch("eip_tool.interface_address._windows_ipv4_addresses",
                   side_effect=[[tentative], [preferred]]), \
                patch("eip_tool.interface_address.threading.Event") as retry_wait:
            _windows_wait_alias_ready("Onboard Ethernet", "192.168.0.20", "255.255.255.0")
        retry_wait.return_value.wait.assert_called_once_with(1)

    def test_unready_windows_alias_is_removed_before_returning_error(self):
        from eip_tool.interface_address import InterfaceAddressError
        with patch("eip_tool.interface_address.sys.platform", "win32"), \
                patch("eip_tool.interface_address.srp", return_value=([], [])), \
                patch("eip_tool.interface_address._windows_add_alias"), \
                patch("eip_tool.interface_address._windows_wait_alias_ready",
                      side_effect=InterfaceAddressError("Duplicate")), \
                patch("eip_tool.interface_address._windows_remove_alias") as remove:
            with self.assertRaisesRegex(InterfaceAddressError, "Duplicate"):
                add_temporary_ipv4_alias(
                    "Onboard Ethernet", "192.168.0.30", "192.168.20.20",
                    "192.168.0.20", "255.255.255.0")
        remove.assert_called_once_with("Onboard Ethernet", "192.168.0.20")

    def test_remove_alias_uses_active_windows_address(self):
        iphlpapi = SimpleNamespace(DeleteIPAddress=Mock(return_value=0))
        from eip_tool import interface_address
        interface_address._windows_alias_contexts[("Onboard Ethernet", "192.168.101.20")] = 73
        with patch("eip_tool.interface_address.sys.platform", "win32"), \
                patch("eip_tool.interface_address.ctypes.WinDLL",
                    return_value=iphlpapi, create=True):
            remove_temporary_ipv4_alias(
                "Onboard Ethernet", "192.168.101.20", "255.255.255.0")
        iphlpapi.DeleteIPAddress.assert_called_once_with(73)
        self.assertNotIn(("Onboard Ethernet", "192.168.101.20"),
                 interface_address._windows_alias_contexts)

    def test_remove_alias_after_restart_uses_exact_active_store_address(self):
        with patch("eip_tool.interface_address.sys.platform", "win32"), \
                patch("eip_tool.interface_address._windows_adapter_index", return_value=3), \
                patch("eip_tool.interface_address.subprocess.run",
                      return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            remove_temporary_ipv4_alias(
                "Onboard Ethernet", "192.168.88.22", "255.255.255.0")
        command = run.call_args.args[0]
        self.assertEqual(command[:4], [
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command"])
        self.assertIn("-InterfaceIndex 3", command[4])
        self.assertIn("-IPAddress '192.168.88.22'", command[4])
        self.assertIn("-PolicyStore ActiveStore", command[4])

    def test_clean_windows_env_strips_unc_paths(self):
        from eip_tool.interface_address import _clean_windows_env
        fake_paths = r"\\FSVT\Home$\User\Modules;C:\Program Files\Modules;\\OtherShare\Mod"
        with patch.dict("os.environ", {"PSModulePath": fake_paths}):
            env = _clean_windows_env()
        self.assertEqual(env["PSModulePath"], r"C:\Program Files\Modules")
        self.assertNotIn(r"\\FSVT", env["PSModulePath"])


if __name__ == "__main__":
    unittest.main()