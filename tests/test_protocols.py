import struct
import unittest
from unittest.mock import patch

from scapy.all import ARP, BOOTP, DHCP, Ether, IP, UDP, Raw

from eip_tool.bootp import BootpServer, ServerConfig
from eip_tool.discovery import DeviceRegistry, dhcp_options, parse_identity


MAC = "00:00:bc:01:02:03"
SERVER_MAC = "02:00:00:00:00:01"


def request(kind=None, mac=MAC, **options):
    bootp = BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=1234, flags=0x8000)
    packet = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
              / IP(src="0.0.0.0", dst="255.255.255.255")
              / UDP(sport=68, dport=67) / bootp)
    if kind is not None:
        packet /= DHCP(options=[("message-type", kind), *options.items(), "end"])
    return Ether(bytes(packet))


def identity_response(name=b"Test drive"):
    item = (struct.pack("<H", 1)
            + struct.pack("!HH4s8s", 2, 44818, b"\xc0\xa8\x01\x64", b"\0" * 8)
            + struct.pack("<HHHBBHI", 1, 2, 3, 4, 5, 0, 0x12345678)
            + bytes([len(name)]) + name + b"\x03")
    payload = struct.pack("<HH", 0x0C, len(item)) + item
    body = struct.pack("<H", 1) + payload
    return struct.pack("<HHII8sI", 0x63, len(body), 0, 0, b"\0" * 8, 0) + body


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.registry = DeviceRegistry(own_mac=SERVER_MAC)

    def test_bootp_mac_and_offline_oui_without_inventing_ip(self):
        device = self.registry.observe(request())
        self.assertEqual(device.mac, MAC)
        self.assertEqual(device.manufacturer, "Rockwell Automation")
        self.assertEqual(device.ip, "")
        self.assertEqual(device.protocols, {"BOOTP"})

    def test_dhcp_requested_address_is_not_current_ip(self):
        device = self.registry.observe(request(1, requested_addr="10.30.1.4"))
        self.assertEqual(device.ip, "")
        self.assertIn("requested", device.candidate)

    def test_static_arp_and_ip_changes_merge_by_mac(self):
        arp = Ether(src=MAC) / ARP(hwsrc=MAC, psrc="10.99.2.3", pdst="10.99.2.3")
        self.registry.observe(arp)
        device = self.registry.observe(Ether(src=MAC) / IP(src="169.254.2.3"))
        self.assertEqual(device.ip, "169.254.2.3")
        self.assertEqual(len(self.registry.devices), 1)
        self.assertEqual(device.protocols, {"ARP", "IPv4"})

    def test_link_local_probe_is_tentative_until_announcement(self):
        device = self.registry.observe(
            Ether(src=MAC) / ARP(hwsrc=MAC, psrc="0.0.0.0", pdst="169.254.5.6"))
        self.assertEqual(device.ip, "")
        self.assertIn("169.254.5.6", device.candidate)
        device = self.registry.observe(
            Ether(src=MAC) / ARP(hwsrc=MAC, psrc="169.254.5.6", pdst="169.254.5.6"))
        self.assertEqual(device.ip, "169.254.5.6")
        self.assertEqual(device.candidate, "")

    def test_non_ip_ethernet_device_is_discovered(self):
        device = self.registry.observe(Ether(src=MAC, type=0x88CC) / Raw(b"LLDP"))
        self.assertEqual(device.mac, MAC)
        self.assertEqual(device.ip, "")

    def test_replies_and_own_frames_are_not_client_observations(self):
        self.assertIsNone(self.registry.observe(Ether(src=SERVER_MAC) / IP(src="10.1.1.1")))
        packet = request()
        packet[BOOTP].op = 2
        self.assertIsNone(self.registry.observe(packet))
        self.assertIsNone(self.registry.observe(Ether(src="ff:ff:ff:ff:ff:ff")))

    def test_eip_identity_includes_product_and_serial(self):
        packet = (Ether(src=MAC) / IP(src="192.168.1.100")
                  / UDP(sport=44818, dport=44818) / Raw(identity_response()))
        device = self.registry.observe(Ether(bytes(packet)))
        self.assertIn("EtherNet/IP", device.protocols)
        self.assertIn("Test drive", device.identity)
        self.assertIn("12345678", device.identity)

    def test_truncated_identity_and_bad_status_are_ignored(self):
        data = identity_response()
        for length in range(len(data)):
            self.assertEqual(parse_identity(data[:length]), [])
        malformed = bytearray(data)
        struct.pack_into("<I", malformed, 8, 1)
        self.assertEqual(parse_identity(malformed), [])
        malformed = bytearray(data)
        malformed[62] = 255
        self.assertEqual(parse_identity(malformed), [])

    def test_unknown_item_before_identity_is_skipped(self):
        data = identity_response()
        body = struct.pack("<H", 2) + struct.pack("<HH", 0xFFFF, 2) + b"xx" + data[26:]
        header = bytearray(data[:24])
        struct.pack_into("<H", header, 2, len(body))
        self.assertEqual(parse_identity(bytes(header) + body)[0]["name"], "Test drive")


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.config = ServerConfig("192.168.1.1", "192.168.1.0/24",
                                   "192.168.1.100", "192.168.1.101")
        self.server = BootpServer(self.config, SERVER_MAC)

    def test_discover_request_ack_preserves_transaction_and_client(self):
        offer = self.server.respond(request(1))
        self.assertEqual(offer[BOOTP].yiaddr, "192.168.1.100")
        self.assertEqual(offer[BOOTP].xid, 1234)
        self.assertEqual(bytes(offer[BOOTP].chaddr)[:6], bytes.fromhex("0000bc010203"))
        self.assertEqual(dhcp_options(offer)["message-type"], 2)
        ack = self.server.respond(request(
            3, requested_addr="192.168.1.100", server_id="192.168.1.1"))
        self.assertEqual(dhcp_options(ack)["message-type"], 5)
        self.assertEqual(ack[Ether].dst, "ff:ff:ff:ff:ff:ff")
        self.assertNotIn("router", dhcp_options(ack))
        decoded = Ether(bytes(ack))
        self.assertEqual(decoded[BOOTP].yiaddr, "192.168.1.100")
        self.assertEqual(dhcp_options(decoded)["subnet_mask"], "255.255.255.0")

    def test_renewal_ciaddr(self):
        self.server.respond(request(1))
        self.server.respond(request(3, requested_addr="192.168.1.100"))
        renewal = request(3)
        renewal[BOOTP].ciaddr = "192.168.1.100"
        ack = self.server.respond(renewal)
        self.assertEqual(dhcp_options(ack)["message-type"], 5)
        self.assertEqual(ack[IP].dst, "192.168.1.100")
        self.assertEqual(ack[Ether].dst, MAC)

    def test_unicast_reply_when_client_does_not_request_broadcast(self):
        packet = request(1)
        packet[BOOTP].flags = 0
        reply = self.server.respond(packet)
        self.assertEqual(reply[IP].dst, "192.168.1.100")
        self.assertEqual(reply[Ether].dst, MAC)

    def test_bootp_converts_existing_reservation_to_permanent(self):
        self.server.respond(request(1))
        self.server.respond(request())
        self.assertEqual(self.server.leases[MAC][1], float("inf"))

    def test_ignore_other_server_wrong_request_and_unsolicited_request(self):
        self.assertIsNone(self.server.respond(request(3, requested_addr="192.168.1.100")))
        self.server.respond(request(1))
        self.assertIsNone(self.server.respond(request(
            3, requested_addr="192.168.1.100", server_id="192.168.1.2")))
        self.assertIsNone(self.server.respond(request(3, requested_addr="192.168.1.101")))

    def test_bootp_has_vendor_mask_but_no_dhcp_message_type(self):
        reply = self.server.respond(request())
        self.assertEqual(reply[BOOTP].yiaddr, "192.168.1.100")
        decoded = Ether(bytes(reply))
        self.assertEqual(dhcp_options(decoded)["subnet_mask"], "255.255.255.0")
        self.assertNotIn("message-type", dhcp_options(decoded))
        self.assertEqual(self.server.leases[MAC][1], float("inf"))

    def test_conflicting_address_is_skipped(self):
        server = BootpServer(self.config, SERVER_MAC,
                             in_use=lambda ip: ip == "192.168.1.100")
        self.assertEqual(server.respond(request(1))[BOOTP].yiaddr, "192.168.1.101")

    def test_stable_leases_exhaustion_and_release(self):
        self.assertEqual(self.server.respond(request(1))[BOOTP].yiaddr, "192.168.1.100")
        self.assertEqual(self.server.respond(request(1))[BOOTP].yiaddr, "192.168.1.100")
        self.assertEqual(self.server.respond(request(1, mac="00:00:bc:01:02:04"))
                         [BOOTP].yiaddr, "192.168.1.101")
        self.assertIsNone(self.server.respond(request(1, mac="00:00:bc:01:02:05")))
        release = request(7)
        release[BOOTP].ciaddr = "192.168.1.100"
        self.assertIsNone(self.server.respond(release))
        self.assertNotIn(MAC, self.server.leases)
        self.assertEqual(self.server.respond(request(1, mac="00:00:bc:01:02:05"))
                         [BOOTP].yiaddr, "192.168.1.100")

    def test_decline_quarantines_address(self):
        self.server.respond(request(1))
        self.server.respond(request(4, requested_addr="192.168.1.100"))
        self.assertEqual(self.server.respond(request(1))[BOOTP].yiaddr, "192.168.1.101")

    def test_expired_offer_can_be_reused(self):
        with patch("eip_tool.bootp.time.monotonic", return_value=0):
            self.server.respond(request(1))
        with patch("eip_tool.bootp.time.monotonic", return_value=61):
            self.assertIsNone(self.server.respond(
                request(3, requested_addr="192.168.1.100")))
            self.assertEqual(self.server.respond(request(1, mac="00:00:bc:01:02:04"))
                             [BOOTP].yiaddr, "192.168.1.100")

    def test_relay_bad_client_and_wrong_ports_are_ignored(self):
        for field, value in (("giaddr", "192.168.1.2"), ("op", 2),
                             ("htype", 2), ("hlen", 5)):
            packet = request(1)
            setattr(packet[BOOTP], field, value)
            self.assertIsNone(self.server.respond(packet))
        packet = request(1)
        packet[UDP].sport = 67
        self.assertIsNone(self.server.respond(packet))

    def test_configuration_validation(self):
        for start, end, server in (
            ("192.168.1.0", "192.168.1.101", "192.168.1.1"),
            ("192.168.1.100", "192.168.1.255", "192.168.1.1"),
            ("192.168.1.102", "192.168.1.101", "192.168.1.1"),
            ("192.168.1.100", "192.168.1.101", "192.168.1.100"),
            ("10.0.0.1", "10.0.0.10", "192.168.1.1"),
        ):
            with self.assertRaises(ValueError):
                ServerConfig(server, "192.168.1.0/24", start, end).validate()


if __name__ == "__main__":
    unittest.main()
