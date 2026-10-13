import os
import unittest
from ipaddress import IPv4Network
from types import SimpleNamespace
from unittest.mock import Mock, patch


@unittest.skipUnless(os.environ.get("DISPLAY") or os.name == "nt", "GUI requires a display")
class GuiTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        from eip_tool.gui import Application
        self.root = tk.Tk()
        self.root.withdraw()
        self.app = Application(self.root)
        self.addCleanup(self.root.destroy)

    def test_live_device_events_update_one_row_per_mac(self):
        row = ("00:00:bc:01:02:03", "", "169.254.5.6 (probe)",
               "Rockwell Automation", "ARP", "", "", 1234, 1234)
        self.app.events.put(("device", row))
        self.app.poll()
        self.assertEqual(len(self.app.table.get_children()), 1)
        first_seen = self.app.table.set(row[0], "first_seen")
        self.app.events.put(("device", (
            row[0], "169.254.5.6", "", *row[3:6], "169.254.5.6", 1234, 2234)))
        self.app.poll()
        self.assertEqual(len(self.app.table.get_children()), 1)
        self.assertEqual(self.app.table.item(row[0], "values")[1], "169.254.5.6")
        self.assertEqual(self.app.table.set(row[0], "first_seen"), first_seen)
        self.assertNotEqual(self.app.table.set(row[0], "seen"), first_seen)
        self.app.events.put(("device", (
            row[0], "192.168.0.20", "", *row[3:6],
            "169.254.5.6, 192.168.0.20", 1234, 3234)))
        self.app.poll()
        self.assertEqual(len(self.app.table.get_children()), 1)
        self.assertEqual(self.app.table.set(row[0], "ip_history"),
                         "169.254.5.6, 192.168.0.20")
        self.assertEqual(self.app.table.set(row[0], "ip"), "192.168.0.20")
        self.assertEqual(self.app.table.set(row[0], "first_seen"), first_seen)

    def test_start_stop_and_service_default(self):
        self.assertFalse(self.app.serve.get())
        with patch("eip_tool.gui.Workbench") as worker:
            self.app.start()
            worker.return_value.start.assert_called_once()
            self.assertEqual(str(self.app.start_button["state"]), "disabled")
            self.app.events.put(("status", "Listening — ready"))
            self.app.poll()
            self.assertTrue(all(str(button["state"]) == "normal"
                                for button in self.app.probe_buttons))
            self.app.stop()
            worker.return_value.stop.assert_called_once()
            self.app.events.put(("stopped", None))
            self.app.poll()
            self.assertIsNone(self.app.worker)
            self.assertEqual(str(self.app.start_button["state"]), "normal")
            self.assertTrue(all(str(button["state"]) == "disabled"
                        for button in self.app.probe_buttons))

    def test_passive_start_can_discard_saved_bootp_reservation(self):
        self.app.reservation = ("00:00:bc:01:02:03", "192.168.1.200")
        self.app.serve.set(False)
        with patch("eip_tool.gui.messagebox.askyesno", return_value=True), \
                patch("eip_tool.gui.Workbench") as worker:
            self.assertTrue(self.app.start())
        self.assertIsNone(self.app.reservation)
        self.assertIsNone(worker.call_args.args[2])

    def test_selected_device_opens_configuration_guide(self):
        mac = "00:00:bc:01:02:03"
        ip = "192.168.1.20"
        self.app.table.insert("", "end", iid=mac, values=(
            mac, ip, "", "", "", "XPort-EIP-MB", "192.168.0.20, 192.168.1.20", "", ""))
        self.app.table.selection_set(mac)
        self.app.update_configuration_button()
        self.assertEqual(str(self.app.configure_button["state"]), "normal")
        self.assertEqual(str(self.app.test_io_button["state"]), "normal")
        self.assertEqual(str(self.app.diagnostics_button["state"]), "normal")
        with patch("eip_tool.gui.XPortConfigurationGuide") as guide:
            self.app.configure_selected()
        self.assertEqual(guide.call_args.args[:3], (self.root, mac, ip))

    def test_selected_device_opens_lantronix_diagnostics(self):
        mac = "00:80:a3:d7:b7:f5"
        ip = "192.168.20.200"
        self.app.table.insert("", "end", iid=mac, values=(
            mac, ip, "", "Lantronix", "ARP", "", ip, "", ""))
        self.app.table.selection_set(mac)
        self.app.update_configuration_button()
        self.assertEqual(str(self.app.diagnostics_button["state"]), "normal")
        with patch("eip_tool.gui.LantronixDiagnosticsDialog") as dialog:
            self.app.read_selected_diagnostics()
        dialog.assert_called_once_with(self.root, mac, ip)

    def test_diagnostics_button_requires_observed_ip(self):
        mac = "00:80:a3:d7:b7:f5"
        self.app.table.insert("", "end", iid=mac, values=(
            mac, "", "", "Lantronix", "BOOTP", "", "", "", ""))
        self.app.table.selection_set(mac)
        self.app.update_configuration_button()
        self.assertEqual(str(self.app.diagnostics_button["state"]), "disabled")

    def test_selected_device_opens_device_io_dialog(self):
        mac = "00:00:bc:01:02:03"
        ip = "192.168.1.20"
        self.app.table.insert("", "end", iid=mac, values=(
            mac, ip, "", "", "", "XPort-EIP-MB", "192.168.1.20", "", ""))
        self.app.table.selection_set(mac)
        with patch("eip_tool.gui.DeviceIOTestDialog") as io_dialog:
            self.app.test_selected_io()
        io_dialog.assert_called_once_with(self.root, mac, ip, "XPort-EIP-MB")

    def test_test_selected_io_without_observed_ip_shows_error(self):
        mac = "00:00:bc:01:02:03"
        self.app.table.insert("", "end", iid=mac, values=(
            mac, "", "", "", "", "", "", "", ""))
        self.app.table.selection_set(mac)
        with patch("eip_tool.gui.messagebox.showerror") as err, \
                patch("eip_tool.gui.DeviceIOTestDialog") as io_dialog:
            self.app.test_selected_io()
        err.assert_called_once()
        io_dialog.assert_not_called()

    def test_configure_selected_starts_reserved_bootp_assignment(self):
        from eip_tool.gui import XPortConfigurationGuide
        mac = "00:00:bc:01:02:03"
        self.app.subnet.set("192.168.1.0/24")
        self.app.service_subnet.set("192.168.1.0/24")
        self.app.first.set("192.168.1.100")
        self.app.last.set("192.168.1.150")
        guide = XPortConfigurationGuide(
            self.root, mac, "", None, "192.168.1.10", "192.168.1.0/24",
            evidence="BOOTP", reserve_ip=self.app.reserve_selected_ip)
        self.addCleanup(guide.window.destroy)
        guide.static_values["IPv4 address"].set("192.168.1.200")
        with patch("eip_tool.gui.get_if_addr", return_value="192.168.1.10"), \
                patch("eip_tool.gui.messagebox.askyesno", return_value=True), \
                patch("eip_tool.gui.Workbench") as worker:
            guide.apply_selected_operation()
        self.assertEqual(self.app.reservation, (mac, "192.168.1.200"))
        self.assertTrue(self.app.serve.get())
        config = worker.call_args.args[2]
        self.assertEqual(config.reservation_mac, mac)
        self.assertEqual(config.reservation_ip, "192.168.1.200")
        worker.return_value.start.assert_called_once()

    def test_probe_buttons_use_their_own_target_controls(self):
        from unittest.mock import Mock
        self.app.worker = Mock()
        self.app.subnet.set("192.168.1.0/24")
        self.app.eip_targets.set("192.168.101.173")
        self.app.arp_targets.set("192.168.50.0/24")
        self.app.probe_eip_targeted()
        self.app.probe_arp_scan()
        self.app.probe_eip_broadcast()
        self.app.probe_xport()
        self.app.worker.eip_targeted.assert_called_once_with(
            "192.168.101.173", "192.168.1.0/24")
        self.app.worker.arp_scan.assert_called_once_with(
            "192.168.50.0/24", "192.168.1.0/24")
        self.app.worker.eip_broadcast.assert_called_once_with()
        self.app.worker.xport_discovery.assert_called_once_with()

    def test_static_apply_uses_selected_device_and_values(self):
        from eip_tool.gui import XPortConfigurationGuide
        guide = XPortConfigurationGuide(
            self.root, "00:00:bc:01:02:03", "192.168.1.20", None,
            "192.168.1.10", "192.168.1.0/24")
        self.addCleanup(guide.window.destroy)
        guide.static_values["IPv4 address"].set("192.168.1.20")
        with patch("eip_tool.gui.messagebox.askyesno", return_value=True), \
                patch("eip_tool.gui.threading.Thread") as worker, \
                patch("eip_tool.gui.apply_static_xport_address"):
            guide.apply_selected_operation()
        worker.assert_called_once()
        self.assertEqual(worker.call_args.kwargs["args"], (
            "Set static IPv4", "192.168.1.20", "255.255.255.0", ""))

    def test_static_apply_adds_alias_for_destination_subnet(self):
        from eip_tool.gui import XPortConfigurationGuide
        interface = SimpleNamespace(name="Onboard Ethernet")
        add_alias = Mock(return_value=IPv4Network("192.168.30.0/24"))
        guide = XPortConfigurationGuide(
            self.root, "00:20:4a:87:12:ed", "192.168.101.173", interface,
            "192.168.20.20", "192.168.20.0/24",
            add_adapter_alias=add_alias, remove_adapter_alias=Mock())
        self.addCleanup(guide.window.destroy)
        guide.static_values["IPv4 address"].set("192.168.30.40")
        with patch("eip_tool.gui.simpledialog.askstring", return_value="192.168.30.20"), \
                patch("eip_tool.gui.messagebox.askyesno", side_effect=[True, True]), \
                patch("eip_tool.gui.threading.Thread") as worker, \
                patch("eip_tool.gui.apply_static_xport_address"):
            guide.apply_selected_operation()
        add_alias.assert_called_once_with(
            interface, "192.168.30.40", "192.168.20.20",
            "192.168.30.20", "255.255.255.0")
        self.assertEqual(guide.network, "192.168.30.0/24")
        self.assertEqual(guide.adapter_ip, "192.168.30.20")
        worker.assert_called_once()

    def test_static_apply_reuses_ready_factory_alias(self):
        from eip_tool.gui import XPortConfigurationGuide
        add_alias = Mock()
        guide = XPortConfigurationGuide(
            self.root, "00:20:4a:87:12:ed", "192.168.20.30", None,
            "192.168.20.20", "192.168.20.0/24", add_adapter_alias=add_alias,
            find_adapter_address=Mock(return_value="192.168.0.20"))
        self.addCleanup(guide.window.destroy)
        self.assertTrue(guide._ensure_static_destination_alias("192.168.0.30", "255.255.255.0"))
        self.assertEqual(guide.adapter_ip, "192.168.0.20")
        self.assertEqual(guide.network, "192.168.0.0/24")
        self.assertEqual(guide.adapter_aliases, [])
        add_alias.assert_not_called()

    def test_factory_alias_button_adds_confirmed_factory_address(self):
        with patch("eip_tool.gui.find_ready_adapter_address", return_value=None), \
                patch("eip_tool.gui.get_if_addr", return_value="192.168.20.20"), \
                patch("eip_tool.gui.simpledialog.askstring", return_value="192.168.0.20"), \
                patch("eip_tool.gui.messagebox.askyesno", return_value=True), \
                patch.object(self.app, "add_adapter_alias") as add_alias:
            self.app.add_factory_alias()
        add_alias.assert_called_once_with(
            self.app.interfaces[self.app.adapter.get()], "192.168.0.1",
            "192.168.20.20", "192.168.0.20", "255.255.255.0")

    def test_temporary_adapter_alias_updates_and_restores_configuration_subnet(self):
        from eip_tool.gui import XPortConfigurationGuide
        interface = SimpleNamespace(name="Onboard Ethernet")
        add_alias = Mock(return_value=IPv4Network("192.168.101.0/24"))
        remove_alias = Mock()
        guide = XPortConfigurationGuide(
            self.root, "00:20:4a:87:12:ed", "192.168.101.173", interface,
            "192.168.20.20", "192.168.20.0/24",
            add_adapter_alias=add_alias, remove_adapter_alias=remove_alias)
        self.addCleanup(guide.window.destroy)
        with patch("eip_tool.gui.simpledialog.askstring",
                   side_effect=["192.168.101.20", "255.255.255.0"]), \
                patch("eip_tool.gui.messagebox.askyesno", return_value=True):
            guide.toggle_adapter_alias()
        self.assertEqual(guide.adapter_ip, "192.168.101.20")
        self.assertEqual(guide.network, "192.168.101.0/24")
        self.assertEqual(guide.action_box.get(), "Set static IPv4")
        guide.close()
        remove_alias.assert_called_once_with(
            interface, "192.168.101.20", "255.255.255.0")
        self.assertEqual(guide.adapter_ip, "192.168.20.20")
        self.assertEqual(guide.network, "192.168.20.0/24")

    def test_application_cleanup_removes_registered_adapter_aliases(self):
        self.app.adapter_aliases = [
            ("Onboard Ethernet", "192.168.101.20", "255.255.255.0")]
        self.app.alias_cleanup_button.configure(state="normal")
        with patch("eip_tool.gui.remove_temporary_ipv4_alias") as remove_alias:
            self.app._restore_adapter_aliases()
        remove_alias.assert_called_once_with(
            "Onboard Ethernet", "192.168.101.20", "255.255.255.0")
        self.assertEqual(self.app.adapter_aliases, [])

    def test_manual_alias_cleanup_button_confirms_and_removes_aliases(self):
        from subprocess import CompletedProcess
        interface = SimpleNamespace(
            name="Onboard Ethernet", ips={4: ["192.168.20.20", "192.168.101.20"]})
        self.app.interfaces = {"Onboard Ethernet": interface}
        self.app.adapter.set("Onboard Ethernet")
        with patch("eip_tool.gui.subprocess.run", side_effect=[
                CompletedProcess([], 0,
                                 "IP-Adresse: 192.168.20.20\n"
                                 "IP-Adresse: 192.168.101.20\n", ""),
                CompletedProcess([], 0,
                                 "IP-Adresse: 192.168.20.20\n"
                                 "IP-Adresse: 192.168.101.20\n", ""),
                CompletedProcess([], 0, "IP-Adresse: 192.168.20.20\n", "")]), \
                patch("eip_tool.gui.simpledialog.askstring",
                      return_value="192.168.101.20"), \
                patch("eip_tool.gui.messagebox.askyesno", return_value=True) as confirm, \
                patch("eip_tool.gui.remove_temporary_ipv4_alias") as remove_alias:
            self.app._refresh_alias_cleanup_button()
            self.assertEqual(str(self.app.alias_cleanup_button["state"]), "normal")
            self.app.remove_selected_adapter_alias()
        confirm.assert_called_once()
        remove_alias.assert_called_once_with(
            "Onboard Ethernet", "192.168.101.20", "255.255.255.0")
        self.assertEqual(self.app.adapter_aliases, [])
        self.assertEqual(str(self.app.alias_cleanup_button["state"]), "disabled")

    def test_enable_bootp_routes_to_cip_configuration_worker(self):
        from eip_tool.gui import XPortConfigurationGuide
        guide = XPortConfigurationGuide(
            self.root, "00:00:bc:01:02:03", "192.168.1.20", None,
            "192.168.1.10", "192.168.1.0/24")
        self.addCleanup(guide.window.destroy)
        guide.action.set("Enable BOOTP")
        guide.update_instructions()
        with patch("eip_tool.gui.messagebox.askyesno", return_value=True), \
                patch("eip_tool.gui.threading.Thread") as worker:
            guide.apply_selected_operation()
        self.assertEqual(worker.call_args.kwargs["args"], (
            "Enable BOOTP", "", "255.255.255.0", ""))

    def test_admin_process_does_not_relaunch(self):
        from eip_tool.gui import ensure_windows_admin
        with patch("eip_tool.gui.os.name", "nt"), \
                patch("eip_tool.gui._is_windows_admin", return_value=True), \
                patch("eip_tool.gui._relaunch_as_admin") as relaunch:
            self.assertTrue(ensure_windows_admin())
        relaunch.assert_not_called()

    def test_non_admin_requests_one_elevated_relaunch(self):
        from eip_tool.gui import ensure_windows_admin
        with patch("eip_tool.gui.os.name", "nt"), \
                patch("eip_tool.gui._is_windows_admin", return_value=False), \
                patch("eip_tool.gui._relaunch_as_admin", return_value=True) as relaunch:
            self.assertFalse(ensure_windows_admin())
        relaunch.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
