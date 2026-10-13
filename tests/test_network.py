import queue
import unittest
from unittest.mock import call, patch

from scapy.all import ARP, BOOTP, Ether, IP, UDP

from eip_tool.bootp import ServerConfig
from eip_tool.discovery import Device, list_identity_request
from eip_tool.network import Workbench, assignment_status, build_scan_plan
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
                worker.arp_scan("", "192.168.1.0/24")
            with self.assertRaisesRegex(ValueError, "IPv4"):
                Workbench("test-adapter", self.events, ServerConfig(
                    "192.168.1.1", "192.168.1.0/24", "192.168.1.100", "192.168.1.110"))

    def test_server_must_use_adapter_address(self):
        with self.assertRaisesRegex(ValueError, "match"):
            Workbench("test-adapter", self.events, ServerConfig(
                "192.168.1.2", "192.168.1.0/24", "192.168.1.100", "192.168.1.110"))

    def test_known_ip_probe_and_local_scan(self):
        self.worker.arp_scan("192.168.1.25", "192.168.1.0/24")
        self.assertEqual(self.worker.commands.get_nowait(), ("arp_scan", ["192.168.1.25"]))
        self.worker.arp_scan("", "192.168.1.0/24")
        kind, hosts = self.worker.commands.get_nowait()
        self.assertEqual(kind, "arp_scan")
        self.assertNotIn("192.168.1.1", hosts)
        self.assertEqual(len(hosts), 253)

    def test_scan_plan_accepts_multiple_networks_and_ip_ranges(self):
        plan = build_scan_plan(
            "192.168.10.0/30;192.168.11.20-192.168.11.21,192.168.12.9",
            "192.168.1.0/24", "192.168.1.1")
        self.assertEqual(plan, [
            (["192.168.10.1", "192.168.10.2"], "192.168.10.3"),
            (["192.168.11.20", "192.168.11.21"], "255.255.255.255"),
            (["192.168.12.9"], "192.168.12.9"),
        ])

    def test_targeted_eip_worker_scans_hosts_sequentially(self):
        hosts = ["192.168.10.1", "192.168.20.1"]
        with patch.object(self.worker, "_send_eip_identity") as send_probe:
            self.worker._probe_worker(("eip_targeted", hosts))
        self.assertEqual(send_probe.call_args_list, [call(host) for host in hosts])

    def test_probe_validation(self):
        for target, network in (
            ("", "192.168.0.0/16"),
            ("", "10.1.0.0/24"),
            ("not-an-ip", "192.168.1.0/24"),
            ("192.168.1.255", "192.168.1.0/24"),
        ):
            with self.assertRaises(ValueError):
                self.worker.arp_scan(target, network)
        self.worker.arp_scan("10.1.0.25", "192.168.1.0/24")

    def test_assignment_status_distinguishes_offer_ack_and_bootp(self):
        offer = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst="255.255.255.255") / BOOTP(
            yiaddr="192.168.1.100")
        ack = Ether(dst=MAC) / IP(dst="192.168.1.100") / BOOTP(
            yiaddr="192.168.1.100")
        bootp_reply = Ether(dst=MAC) / IP(dst="192.168.1.100") / BOOTP(
            yiaddr="192.168.1.100")
        self.assertIn("DHCP Offer", assignment_status(request(1), offer))
        self.assertIn("broadcast to 255.255.255.255", assignment_status(request(1), offer))
        self.assertIn("DHCP ACK", assignment_status(
            request(3, requested_addr="192.168.1.100"), ack))
        self.assertIn("unicast to 192.168.1.100", assignment_status(request(), bootp_reply))
        self.assertIn("broadcast flag set", assignment_status(request(), bootp_reply))

    def test_assignment_is_confirmed_only_for_matching_mac_and_ip(self):
        device = Device(MAC, "test", ip="192.168.1.200", last_seen=10, ip_seen=9)
        self.worker.pending_assignments[MAC] = "192.168.1.200"
        self.worker._confirm_assignment(device)
        self.assertIn(MAC, self.worker.pending_assignments)
        self.assertTrue(self.events.empty())

        device.ip_seen = device.last_seen
        self.worker._confirm_assignment(device)
        self.assertEqual(self.events.get_nowait(), (
            "assignment_confirmed", (MAC, "192.168.1.200")))
        self.assertNotIn(MAC, self.worker.pending_assignments)

    def test_device_events_preserve_ip_history_and_first_seen_snapshots(self):
        self.worker._process_packet(Ether(src=MAC) / IP(src="192.168.20.30"))
        first_kind, first_snapshot = self.events.get_nowait()
        self.worker._process_packet(Ether(src=MAC) / IP(src="192.168.0.30"))
        second_kind, second_snapshot = self.events.get_nowait()
        self.assertEqual((first_kind, second_kind), ("device", "device"))
        self.assertEqual(first_snapshot[6], "192.168.20.30")
        self.assertEqual(second_snapshot[6], "192.168.0.30, 192.168.20.30")
        self.assertEqual(first_snapshot[7], second_snapshot[7])
        self.assertEqual(second_snapshot[1], "192.168.0.30")
        self.assertGreaterEqual(second_snapshot[8], first_snapshot[8])

    def test_captured_bootp_request_transmits_reserved_reply(self):
        worker = Workbench("test-adapter", self.events, ServerConfig(
            "192.168.1.1", "192.168.1.0/24", "192.168.1.100", "192.168.1.110",
            reservation_mac=MAC, reservation_ip="192.168.1.105"))
        with patch("eip_tool.network.srp", return_value=([], [])), \
                patch("eip_tool.network.sendp") as send:
            worker._process_packet(request())
        reply = send.call_args.args[0]
        self.assertEqual(send.call_args.kwargs["iface"], "test-adapter")
        self.assertEqual(reply[BOOTP].yiaddr, "192.168.1.105")
        self.assertEqual(worker.pending_assignments[MAC], "192.168.1.105")
        self.assertEqual(self.events.get_nowait()[0], "device")
        self.assertIn("BOOTP reply sent", self.events.get_nowait()[1])

    def test_captured_bootp_request_reports_when_no_reply_is_generated(self):
        worker = Workbench("test-adapter", self.events, ServerConfig(
            "192.168.1.1", "192.168.1.0/24", "192.168.1.100", "192.168.1.110"))
        worker.server.in_use = lambda address: True
        worker._process_packet(request())
        self.assertEqual(self.events.get_nowait()[0], "device")
        self.assertIn("no address reply was generated", self.events.get_nowait()[1])

    def test_eip_broadcast_probe_transmits_only_broadcast_identity(self):
        with patch("eip_tool.network.sendp") as send:
            self.worker._probe_worker(("eip_broadcast", None))
        query = send.call_args.args[0]
        self.assertEqual(query[IP].dst, "255.255.255.255")
        self.assertEqual(query[UDP].dport, 44818)
        self.assertEqual(bytes(query[UDP].payload)[:8], list_identity_request()[:8])

    def test_xport_probe_transmits_only_lantronix_broadcast(self):
        with patch("eip_tool.network.sendp") as send:
            self.worker._probe_worker(("xport_discovery", None))
        ldp = send.call_args.args[0]
        self.assertEqual(ldp[UDP].dport, 30718)
        self.assertEqual(bytes(ldp[UDP].payload), b"\x00\x00\x00\xf6")
        self.assertEqual(send.call_count, 1)

    def test_targeted_eip_probe_sends_only_to_selected_host(self):
        with patch("eip_tool.network.sendp") as send:
            self.worker._probe_worker(("eip_targeted", ["192.168.1.25"]))
        query = send.call_args.args[0]
        self.assertEqual(query[IP].dst, "192.168.1.25")
        self.assertEqual(query[UDP].dport, 44818)
        self.assertEqual(send.call_count, 1)

    def test_arp_probe_sends_only_arp_on_selected_adapter(self):
        with patch("eip_tool.network.sendp") as send:
            self.worker._probe_worker(("arp_scan", ["192.168.1.25"]))
        packet = send.call_args.args[0]
        self.assertEqual(packet[ARP].pdst, "192.168.1.25")
        self.assertNotIn(IP, packet)
        self.assertEqual(send.call_args.kwargs["iface"], "test-adapter")

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
        device.ip_seen = 0
        with patch("eip_tool.network.srp", return_value=([], [])) as probe:
            self.assertFalse(self.worker._in_use("192.168.1.100"))
            probe.assert_called_once()

    def test_boot_retries_do_not_refresh_stale_ip_ownership(self):
        worker = Workbench("test-adapter", self.events, ServerConfig(
            "192.168.1.1", "192.168.1.0/24", "192.168.1.100", "192.168.1.100"))
        device = worker.registry.observe(
            Ether(src=MAC) / ARP(hwsrc=MAC, psrc="192.168.1.100"))
        device.ip_seen = 0
        worker.server.leases[MAC] = ("192.168.1.100", 0)
        with patch("eip_tool.network.srp", return_value=([], [])) as probe:
            for _ in range(3):
                packet = request(1)
                worker.registry.observe(packet)
                self.assertEqual(worker.server.respond(packet)[BOOTP].yiaddr,
                                 "192.168.1.100")
            probe.assert_called_once()
        self.assertEqual(device.ip_seen, 0)
        self.assertGreater(device.last_seen, 0)


if __name__ == "__main__":
    unittest.main()
