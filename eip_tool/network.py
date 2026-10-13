"""Network workers. Tk widgets are only touched by the main thread."""

import os
import queue
import threading
import time
from ipaddress import IPv4Address, IPv4Network

from scapy.all import (
    ARP, AsyncSniffer, BOOTP, Ether, IP, Raw, UDP, conf, get_if_addr,
    get_if_hwaddr, sendp, srp,
)

from .bootp import BootpServer
from .discovery import DeviceRegistry, dhcp_options, list_identity_request, usable_ip

MAX_SCAN_TARGETS = 4096


def assignment_status(request, response):
    address = response[BOOTP].yiaddr
    delivery = "broadcast" if response[Ether].dst == "ff:ff:ff:ff:ff:ff" else "unicast"
    destination = response[IP].dst
    kind = dhcp_options(request).get("message-type")
    if isinstance(kind, bytes) and len(kind) == 1:
        kind = kind[0]
    if kind == 1:
        return (f"DHCP Offer sent for {address} by {delivery} to {destination}; "
                "waiting for the device's DHCP Request.")
    if kind == 3:
        return (f"DHCP ACK sent for {address} by {delivery} to {destination}; "
                "awaiting device traffic to confirm use.")
    broadcast_flag = "set" if int(request[BOOTP].flags) & 0x8000 else "clear"
    return (f"BOOTP reply sent for {address} by {delivery} to {destination} "
            f"(client broadcast flag {broadcast_flag}); acceptance unconfirmed until "
            "device traffic is observed.")


def build_scan_plan(target, network, adapter_ip):
    if not usable_ip(adapter_ip):
        raise ValueError("Configure an IPv4 address before sending active probes.")
    if not target:
        subnet = IPv4Network(network, strict=False)
        if IPv4Address(adapter_ip) not in subnet:
            raise ValueError("The scan subnet must contain the adapter's IPv4 address.")
        if subnet.num_addresses > 1024:
            raise ValueError("Default subnet scans are limited to 1024 addresses.")
        hosts = [str(address) for address in subnet.hosts()
                 if str(address) != adapter_ip]
        return [(hosts, str(subnet.broadcast_address))]

    groups = []
    seen = set()
    total = 0
    tokens = target.replace(";", ",").split(",")
    if any(not token.strip() for token in tokens):
        raise ValueError("Separate scan targets with commas or semicolons.")
    for raw_token in tokens:
        token = raw_token.strip()
        if "/" in token:
            subnet = IPv4Network(token, strict=False)
            count = (subnet.num_addresses if subnet.prefixlen >= 31
                     else subnet.num_addresses - 2)
            destination = str(subnet.broadcast_address)
            addresses = subnet.hosts()
        elif "-" in token:
            first_text, last_text = token.split("-", 1)
            first, last = IPv4Address(first_text.strip()), IPv4Address(last_text.strip())
            if first > last:
                raise ValueError(f"IP range is reversed: {token}")
            count = int(last) - int(first) + 1
            destination = "255.255.255.255"
            addresses = (IPv4Address(number)
                         for number in range(int(first), int(last) + 1))
        else:
            address = IPv4Address(token)
            if not usable_ip(str(address)):
                raise ValueError(f"Scan target is not a usable IPv4 address: {token}")
            selected_subnet = IPv4Network(network, strict=False)
            if (address in selected_subnet and address in
                    (selected_subnet.network_address, selected_subnet.broadcast_address)):
                raise ValueError(f"Scan target is not a host address: {token}")
            count = 1
            destination = str(address)
            addresses = (address,)
        if total + count > MAX_SCAN_TARGETS:
            raise ValueError(f"A scan is limited to {MAX_SCAN_TARGETS} addresses.")
        hosts = []
        for address in addresses:
            host = str(address)
            if host != adapter_ip and host not in seen and usable_ip(host):
                seen.add(host)
                hosts.append(host)
        total += len(hosts)
        if hosts:
            groups.append((hosts, destination))
    if not groups:
        raise ValueError("The scan targets contain no usable addresses.")
    return groups


class Workbench:
    def __init__(self, interface, events, server_config=None, oui_file=None):
        self.interface = interface
        self.events = events
        self.ip = get_if_addr(interface)
        self.mac = get_if_hwaddr(interface)
        self.registry = DeviceRegistry(self.mac, oui_file)
        self.server = None
        self.pending_assignments = {}
        if server_config:
            if not usable_ip(self.ip):
                raise ValueError("Configure an IPv4 address before enabling BOOTP/DHCP.")
            if server_config.server_ip != self.ip:
                raise ValueError("Server IP must match the selected adapter's IPv4 address.")
            self.server = BootpServer(server_config, self.mac, self._in_use)
        self.stop_event = threading.Event()
        self.packets = queue.Queue(maxsize=4096)
        self.commands = queue.Queue(maxsize=4)
        self.thread = None
        self.probe_thread = None
        self.dropped = False

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()

    def _queue_probe(self, command):
        if not usable_ip(self.ip):
            raise ValueError("Configure an IPv4 address before sending active probes.")
        try:
            self.commands.put_nowait(command)
        except queue.Full:
            raise ValueError("Probe queue is full. Wait for the current probe to finish.") from None

    def eip_broadcast(self):
        self._queue_probe(("eip_broadcast", None))

    def eip_targeted(self, target, network):
        plan = build_scan_plan(target, network, self.ip)
        hosts = list(dict.fromkeys(host for group, _ in plan for host in group))
        self._queue_probe(("eip_targeted", hosts))

    def arp_scan(self, target, network):
        plan = build_scan_plan(target, network, self.ip)
        hosts = list(dict.fromkeys(host for group, _ in plan for host in group))
        self._queue_probe(("arp_scan", hosts))

    def xport_discovery(self):
        self._queue_probe(("xport_discovery", None))

    def _capture(self, packet):
        try:
            self.packets.put_nowait(packet)
        except queue.Full:
            self.dropped = True

    def _emit(self, kind, value):
        try:
            self.events.put_nowait((kind, value))
        except queue.Full:
            # Keep memory bounded and favor fresh updates, including shutdown.
            try:
                self.events.get_nowait()
            except queue.Empty:
                pass
            self.dropped = True
            try:
                self.events.put_nowait((kind, value))
            except queue.Full:
                pass

    def _confirm_assignment(self, device):
        if (device.ip and device.ip_seen == device.last_seen
                and self.pending_assignments.get(device.mac) == device.ip):
            del self.pending_assignments[device.mac]
            self._emit("assignment_confirmed", (device.mac, device.ip))

    def _process_packet(self, packet):
        device = self.registry.observe(packet)
        if device:
            self._emit("device", (
                device.mac, device.ip, device.candidate,
                device.manufacturer, ", ".join(sorted(device.protocols)),
                device.identity,
                ", ".join(sorted(device.ip_history, key=IPv4Address)),
                device.first_seen, device.last_seen))
            self._confirm_assignment(device)
        if not self.server:
            return
        response = self.server.respond(packet)
        if response:
            sendp(response, iface=self.interface, verbose=False)
            mac = bytes(packet[BOOTP].chaddr)[:6].hex(":")
            self.pending_assignments[mac] = response[BOOTP].yiaddr
            self._emit("status", assignment_status(packet, response))
        elif BOOTP in packet and packet[BOOTP].op == 1:
            mac = bytes(packet[BOOTP].chaddr)[:6].hex(":")
            self._emit(
                "status",
                f"BOOTP/DHCP request received from {mac}, but no address reply was generated.")

    def _in_use(self, ip):
        if self.stop_event.is_set():
            raise RuntimeError("Address assignment stopped.")
        if any(device.ip == ip and time.time() - device.ip_seen < 60
               for device in self.registry.devices.values()):
            return True
        answers, _ = srp(
            Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")
            / ARP(hwsrc=self.mac, psrc=self.ip, pdst=ip),
            iface=self.interface, timeout=0.3, retry=0, verbose=False)
        for _, response in answers:
            self._capture(response)
        return bool(answers)

    def _send_eip_identity(self, destination):
        query = (Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")
                 / IP(src=self.ip, dst=destination)
                 / UDP(sport=44818, dport=44818)
                 / list_identity_request(os.urandom(8)))
        sendp(query, iface=self.interface, verbose=False)

    def _send_xport_discovery(self):
        sendp(Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")
              / IP(src=self.ip, dst="255.255.255.255")
              / UDP(sport=30718, dport=30718)
              / Raw(load=b"\x00\x00\x00\xf6"),
              iface=self.interface, verbose=False)

    def _send_arp_scan(self, hosts):
        for host in hosts:
            if self.stop_event.is_set():
                break
            sendp(Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")
                  / ARP(hwsrc=self.mac, psrc=self.ip, pdst=host),
                  iface=self.interface, verbose=False)
            # Throttle probes, while the independent sniffer keeps capturing.
            self.stop_event.wait(0.01)

    def _probe_worker(self, command):
        try:
            kind, payload = command
            if kind == "eip_broadcast":
                self._send_eip_identity("255.255.255.255")
                status = "EtherNet/IP broadcast sent; listening for replies."
            elif kind == "eip_targeted":
                for host in payload:
                    if self.stop_event.is_set():
                        break
                    self._send_eip_identity(host)
                    self.stop_event.wait(0.01)
                status = f"Targeted EtherNet/IP probes sent to {len(payload)} address(es)."
            elif kind == "arp_scan":
                self._send_arp_scan(payload)
                status = f"ARP probes sent to {len(payload)} address(es)."
            elif kind == "xport_discovery":
                self._send_xport_discovery()
                status = "Lantronix/XPort discovery broadcast sent; listening for replies."
            else:
                raise ValueError(f"Unknown probe type: {kind}")
            self._emit("status", status)
        except Exception as error:
            self._emit("error", f"Probe failed: {error}")

    def _run(self):
        capture_socket = None
        sniffer = None
        try:
            # Open synchronously inside the worker so startup errors are visible.
            capture_socket = conf.L2listen(iface=self.interface)
            ready = threading.Event()
            sniffer = AsyncSniffer(opened_socket=capture_socket, store=False,
                                   prn=self._capture, started_callback=ready.set,
                                   lfilter=lambda packet: (
                                       Ether in packet
                                       and packet[Ether].src.lower() != self.mac.lower()))
            sniffer.start()
            if not ready.wait(3):
                raise RuntimeError("Packet capture did not start.")
            self._emit("status", "Listening — power-cycle the device now."
                       + (" BOOTP/DHCP enabled." if self.server else " Passive mode."))
            while not self.stop_event.is_set():
                if sniffer.exception:
                    raise sniffer.exception
                if not self.probe_thread or not self.probe_thread.is_alive():
                    try:
                        command = self.commands.get_nowait()
                    except queue.Empty:
                        command = None
                    if command:
                        self.probe_thread = threading.Thread(
                            target=self._probe_worker, args=(command,), daemon=True)
                        self.probe_thread.start()
                try:
                    packet = self.packets.get(timeout=0.05)
                except queue.Empty:
                    continue
                try:
                    self._process_packet(packet)
                except (ValueError, TypeError, IndexError, AttributeError):
                    # Ignore malformed frames; one bad packet must not stop capture.
                    continue
                if self.dropped:
                    self._emit("status", "Queue overflow: some frames or display updates were lost.")
                    self.dropped = False
        except Exception as error:
            self._emit("error", str(error))
        finally:
            self.stop_event.set()
            if self.probe_thread:
                self.probe_thread.join()
            try:
                if sniffer and sniffer.running:
                    sniffer.stop()
            finally:
                if capture_socket:
                    capture_socket.close()
                self._emit("stopped", None)
