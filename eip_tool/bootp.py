"""An opt-in, isolated-network BOOTP/DHCP responder."""

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
import time

from scapy.all import BOOTP, DHCP, Ether, IP, UDP

from .discovery import dhcp_options, valid_mac


@dataclass(frozen=True)
class ServerConfig:
    server_ip: str
    network: str
    pool_start: str
    pool_end: str
    lease_seconds: int = 3600

    def validate(self):
        network = IPv4Network(self.network, strict=False)
        server, first, last = map(IPv4Address,
                                  (self.server_ip, self.pool_start, self.pool_end))
        for address in (server, first, last):
            if (address not in network or address in
                    (network.network_address, network.broadcast_address)
                    or address.is_multicast or address.is_loopback
                    or address.is_unspecified):
                raise ValueError("Server and pool must be usable addresses in the subnet.")
        if not first <= last or first <= server <= last:
            raise ValueError("Pool must be ordered and must exclude the laptop address.")
        if int(last) - int(first) >= 1024:
            raise ValueError("Pool is limited to 1024 addresses.")
        if not 60 <= self.lease_seconds <= 86400:
            raise ValueError("Lease must be between 60 and 86400 seconds.")
        return network


class BootpServer:
    def __init__(self, config, server_mac, in_use=lambda ip: False):
        self.network = config.validate()
        self.config = config
        self.server_mac = server_mac
        self.in_use = in_use
        self.leases = {}
        self.blocked = set()

    def _allocate(self, mac, permanent=False):
        now = time.monotonic()
        self.leases = {key: value for key, value in self.leases.items()
                       if value[1] > now}
        if mac in self.leases:
            if permanent:
                self.leases[mac] = (self.leases[mac][0], float("inf"))
            return self.leases[mac][0]
        used = {value[0] for value in self.leases.values()} | self.blocked
        for number in range(int(IPv4Address(self.config.pool_start)),
                            int(IPv4Address(self.config.pool_end)) + 1):
            ip = str(IPv4Address(number))
            if ip in used:
                continue
            if self.in_use(ip):
                self.blocked.add(ip)
                continue
            self.leases[mac] = (ip, float("inf") if permanent else now + 60)
            return ip
        return None

    def respond(self, packet):
        if BOOTP not in packet or UDP not in packet:
            return None
        request = packet[BOOTP]
        if (request.op != 1 or request.htype != 1 or request.hlen != 6
                or request.giaddr != "0.0.0.0"
                or packet[UDP].sport != 68 or packet[UDP].dport != 67):
            return None
        mac = bytes(request.chaddr)[:6].hex(":")
        if not valid_mac(mac) or mac == self.server_mac.lower():
            return None
        options = dhcp_options(packet)
        is_dhcp = DHCP in packet
        kind = options.get("message-type")
        if isinstance(kind, bytes) and len(kind) == 1:
            kind = kind[0]
        if is_dhcp and kind not in (1, 3, 4, 7):
            return None
        selected = options.get("server_id")
        if selected and selected != self.config.server_ip:
            return None
        if is_dhcp and kind in (4, 7):
            lease = self.leases.get(mac)
            claimed = options.get("requested_addr") if kind == 4 else request.ciaddr
            if lease and claimed == lease[0]:
                if kind == 4:
                    self.blocked.add(lease[0])
                del self.leases[mac]
            return None
        if is_dhcp and kind == 3:
            lease = self.leases.get(mac)
            claimed = options.get("requested_addr", request.ciaddr)
            # Only ACK addresses offered by this session; never invent a binding.
            if not lease or lease[1] <= time.monotonic() or claimed != lease[0]:
                return None
            ip = lease[0]
            self.leases[mac] = (ip, time.monotonic() + self.config.lease_seconds)
        else:
            ip = self._allocate(mac, permanent=not is_dhcp)
        if not ip:
            return None
        if request.ciaddr != "0.0.0.0":
            destination_ip, destination_mac = request.ciaddr, mac
        elif int(request.flags) & 0x8000:
            destination_ip, destination_mac = "255.255.255.255", "ff:ff:ff:ff:ff:ff"
        else:
            destination_ip, destination_mac = ip, mac
        reply = (Ether(src=self.server_mac, dst=destination_mac)
                 / IP(src=self.config.server_ip, dst=destination_ip)
                 / UDP(sport=67, dport=68)
                 / BOOTP(op=2, htype=1, hlen=6, xid=request.xid,
                         flags=request.flags, yiaddr=ip,
                         siaddr=self.config.server_ip, chaddr=request.chaddr))
        common = [("subnet_mask", str(self.network.netmask))]
        if is_dhcp:
            reply /= DHCP(options=[
                ("message-type", 2 if kind == 1 else 5),
                ("server_id", self.config.server_ip),
                ("lease_time", self.config.lease_seconds),
                *common, "end"])
        else:
            # RFC 1048 vendor extensions for classic BOOTP, without DHCP type.
            reply[BOOTP].options = (b"\x63\x82\x53\x63\x01\x04"
                                    + self.network.netmask.packed + b"\xff")
        return reply
