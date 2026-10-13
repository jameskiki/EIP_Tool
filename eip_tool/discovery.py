"""Packet interpretation without network or GUI side effects."""

from dataclasses import dataclass, field
from ipaddress import IPv4Address
import struct
import time

from manuf.manuf import MacParser
from scapy.all import ARP, BOOTP, DHCP, Ether, IP, UDP


def usable_ip(value):
    try:
        address = IPv4Address(value)
        return not (address.is_unspecified or address.is_multicast
                    or address.is_loopback or int(address) == 0xFFFFFFFF)
    except (ValueError, TypeError):
        return False


def valid_mac(value):
    try:
        raw = bytes.fromhex(value.replace(":", ""))
        return len(raw) == 6 and raw != b"\0" * 6 and not raw[0] & 1
    except (ValueError, AttributeError):
        return False


def dhcp_options(packet):
    if DHCP not in packet:
        return {}
    return {option[0]: option[1] for option in packet[DHCP].options
            if isinstance(option, tuple) and len(option) >= 2}


def list_identity_request(context=b"\0" * 8):
    return struct.pack("<HHII8sI", 0x63, 0, 0, 0, context, 0)


def parse_identity(payload):
    """Read a bounded EtherNet/IP ListIdentity response (including unknown items)."""
    if len(payload) < 26:
        return []
    command, length, session, status, context, options = struct.unpack_from(
        "<HHII8sI", payload)
    if command != 0x63 or status or length < 2 or len(payload) < 24 + length:
        return []
    end = 24 + length
    count = struct.unpack_from("<H", payload, 24)[0]
    offset = 26
    identities = []
    for _ in range(count):
        if offset + 4 > end:
            return []
        item_type, size = struct.unpack_from("<HH", payload, offset)
        offset += 4
        if offset + size > end:
            return []
        item = payload[offset:offset + size]
        offset += size
        if item_type != 0x0C:
            continue
        if size < 34 or 34 + item[32] > size:
            return []
        vendor, device_type, product = struct.unpack_from("<HHH", item, 18)
        identities.append({
            "vendor_id": vendor,
            "device_type": device_type,
            "product_code": product,
            "revision": f"{item[24]}.{item[25]}",
            "serial": f"{struct.unpack_from('<I', item, 28)[0]:08X}",
            "name": item[33:33 + item[32]].decode("utf-8", errors="replace"),
        })
    return identities


@dataclass
class Device:
    mac: str
    manufacturer: str
    ip: str = ""
    candidate: str = ""
    protocols: set = field(default_factory=set)
    identity: str = ""
    last_seen: float = field(default_factory=time.time)
    ip_seen: float = 0
    first_seen: float = field(default_factory=time.time)
    ip_history: dict = field(default_factory=dict)


class DeviceRegistry:
    def __init__(self, own_mac="", oui_file=None):
        self.own_mac = own_mac.lower()
        self.devices = {}
        self.vendors = MacParser(oui_file) if oui_file else MacParser()

    def observe(self, packet):
        if Ether not in packet:
            return None
        mac = packet[Ether].src.lower()
        ip, candidate, protocol, identity = "", "", "Ethernet", ""
        released = False
        if BOOTP in packet:
            bootp = packet[BOOTP]
            if bootp.op != 1 or bootp.htype != 1 or bootp.hlen != 6:
                return None
            mac = bytes(bootp.chaddr)[:6].hex(":")
            options = dhcp_options(packet)
            protocol = "DHCP" if "message-type" in options else "BOOTP"
            released = options.get("message-type") == 7
            if usable_ip(bootp.ciaddr):
                ip = bootp.ciaddr
            requested = options.get("requested_addr")
            if requested and usable_ip(requested):
                candidate = f"{requested} (requested)"
        elif ARP in packet:
            arp = packet[ARP]
            if arp.hwtype != 1 or arp.ptype != 0x0800:
                return None
            mac = str(arp.hwsrc).lower()
            protocol = "ARP"
            if usable_ip(arp.psrc):
                ip = arp.psrc
            elif usable_ip(arp.pdst):
                candidate = f"{arp.pdst} (ARP probe; unconfirmed)"
        elif IP in packet:
            protocol = "IPv4"
            if usable_ip(packet[IP].src):
                ip = packet[IP].src
            if UDP in packet:
                if packet[UDP].sport == 44818:
                    identities = parse_identity(bytes(packet[UDP].payload))
                    if identities:
                        protocol = "EtherNet/IP"
                        item = identities[0]
                        identity = (f"{item['name']} | vendor {item['vendor_id']} | "
                                    f"rev {item['revision']} | serial {item['serial']}")
                elif (packet[UDP].sport == 30718
                      and bytes(packet[UDP].payload).startswith(b"\x00\x00\x00\xf7")):
                    response = bytes(packet[UDP].payload)
                    if len(response) >= 30:
                        advertised_mac = response[24:30].hex(":")
                        if advertised_mac == mac:
                            protocol = "Lantronix LDP"
        if not valid_mac(mac) or mac == self.own_mac:
            return None
        now = time.time()
        if mac not in self.devices:
            if len(self.devices) >= 4096:
                return None
            vendor = self.vendors.get_all(mac)
            manufacturer = (vendor.manuf_long or vendor.manuf) if vendor else "Unknown"
            if int(mac[:2], 16) & 2:
                manufacturer = "Locally administered / unknown"
            self.devices[mac] = Device(mac, manufacturer, first_seen=now, last_seen=now)
        device = self.devices[mac]
        if released:
            device.ip = ""
            device.candidate = ""
            device.ip_seen = 0
        elif ip:
            device.ip = str(ip)
            device.ip_history[device.ip] = now
            device.candidate = ""
            device.ip_seen = now
        elif candidate:
            device.candidate = candidate
        device.protocols.add(protocol)
        if identity:
            device.identity = identity
        device.last_seen = now
        return device
