import queue
import unittest
from unittest.mock import patch

from scapy.all import ARP, BOOTP, Ether, IP, UDP

from eip_tool.bootp import ServerConfig
from eip_tool.discovery import list_identity_request
from eip_tool.network import Workbench
from tests.test_protocols import MAC, request


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.ip_patch = patch("eip_tool.network.get_if_addr", return_value="192.168.1.1")
        self.mac_patch = patch("eip_tool.network.get_if_hwaddr",
                               return_value="02:00:00:00:00:01")
        self.ip_patch.start()
        self.mac_patch.start()
        self.addCleanup(self.ip_patch.stop)
        self.addCleanup(self.mac_patch.stop)
        self.events = queue.Queue()
        self.worker = Workbench("test-adapter", self.events)

    def test_passive_mode_without_ipv4(self):
        with patch("eip_tool.network.get_if_addr", return_value="0.0.0.0"):
            worker = Workbench("test-adapter", self.events)
            self.assertIsNone(worker.server)
            with self.assertRaisesRegex(ValueError, "IPv4"):
                worker.probe("", "192.168.1.0/24")
            with self.assertRaisesRegex(ValueError, "IPv4"):
                Workbench("test-adapter", self.events, ServerConfig(
                    "192.168.1.1", "192.168.1.0/24", "192.168.1.100", "192.168.1.110"))

    def test_server_must_use_adapter_address(self):
        with self.assertRaisesRegex(ValueError, "match"):
            Workbench("test-adapter", self.events, ServerConfig(
                "192.168.1.2", "192.168.1.0/24", "192.168.1.100", "192.168.1.110"))

    def test_known_ip_probe_and_local_scan(self):
        self.worker.probe("192.168.1.25", "192.168.1.0/24")
        self.assertEqual(self.worker.commands.get_nowait(),
                         (["192.168.1.25"], "192.168.1.25"))
        self.worker.probe("", "192.168.1.0/24")
        hosts, destination = self.worker.commands.get_nowait()
        self.assertEqual(destination, "192.168.1.255")
        self.assertNotIn("192.168.1.1", hosts)
        self.assertEqual(len(hosts), 253)

    def test_probe_validation(self):
        for target, network in (
            ("", "192.168.0.0/16"),
            ("", "10.1.0.0/24"),
            ("not-an-ip", "192.168.1.0/24"),
            ("192.168.1.255", "192.168.1.0/24"),
            ("10.1.0.25", "192.168.1.0/24"),
        ):
            with self.assertRaises(ValueError):
                self.worker.probe(target, network)

    def test_probe_transmits_identity_and_arp_on_selected_adapter(self):
        with patch("eip_tool.network.sendp") as send:
            self.worker._send_probe(["192.168.1.25"], "192.168.1.25")
        query = send.call_args_list[0].args[0]
        self.assertEqual(query[IP].dst, "192.168.1.25")
        self.assertEqual(query[UDP].dport, 44818)
        self.assertEqual(bytes(query[UDP].payload)[:8], list_identity_request()[:8])
        arp = send.call_args_list[1].args[0]
        self.assertEqual(arp[ARP].pdst, "192.168.1.25")
        for call in send.call_args_list:
            self.assertEqual(call.kwargs["iface"], "test-adapter")

    def test_capture_failure_is_reported_and_stops(self):
        with patch("eip_tool.network.conf.L2listen", side_effect=PermissionError("denied")):
            self.worker._run()
        self.assertEqual(self.events.get_nowait(), ("error", "denied"))
        self.assertEqual(self.events.get_nowait(), ("stopped", None))

    def test_capture_overflow_does_not_block(self):
        self.worker.packets = queue.Queue(maxsize=1)
        self.worker._capture(Ether())
        self.worker._capture(Ether())
        self.assertTrue(self.worker.dropped)
        self.assertEqual(self.worker.packets.qsize(), 1)

    def test_full_gui_queue_keeps_shutdown_event(self):
        self.worker.events = queue.Queue(maxsize=1)
        self.worker._emit("status", "old update")
        self.worker._emit("stopped", None)
        self.assertEqual(self.worker.events.get_nowait(), ("stopped", None))
        self.assertTrue(self.worker.dropped)

    def test_release_allows_reallocation_after_fresh_conflict_probe(self):
        worker = Workbench("test-adapter", self.events, ServerConfig(
            "192.168.1.1", "192.168.1.0/24", "192.168.1.100", "192.168.1.100"))
        with patch("eip_tool.network.srp", return_value=([], [])) as arp_probe:
            worker.server.respond(request(1))
            worker.registry.observe(
                Ether(src=MAC) / ARP(hwsrc=MAC, psrc="192.168.1.100"))
            release = request(7)
            release[BOOTP].ciaddr = "192.168.1.100"
            worker.registry.observe(release)
            worker.server.respond(release)
            offer = worker.server.respond(request(1, mac="00:00:bc:01:02:04"))
            self.assertEqual(offer[BOOTP].yiaddr, "192.168.1.100")
            self.assertEqual(arp_probe.call_count, 2)

    def test_stale_observation_triggers_fresh_arp_probe(self):
        device = self.worker.registry.observe(
            Ether(src=MAC) / ARP(hwsrc=MAC, psrc="192.168.1.100"))
        device.last_seen = 0
        with patch("eip_tool.network.srp", return_value=([], [])) as probe:
            self.assertFalse(self.worker._in_use("192.168.1.100"))
            probe.assert_called_once()


if __name__ == "__main__":
    unittest.main()
