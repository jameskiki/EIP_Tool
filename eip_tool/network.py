"""Network workers. Tk widgets are only touched by the main thread."""

import os
import queue
import threading
import time
from ipaddress import IPv4Address, IPv4Network

from scapy.all import (
    ARP, AsyncSniffer, BOOTP, Ether, IP, UDP, conf, get_if_addr,
    get_if_hwaddr, sendp, srp,
)

from .bootp import BootpServer
from .discovery import DeviceRegistry, list_identity_request, usable_ip


class Workbench:
    def __init__(self, interface, events, server_config=None, oui_file=None):
        self.interface = interface
        self.events = events
        self.ip = get_if_addr(interface)
        self.mac = get_if_hwaddr(interface)
        self.registry = DeviceRegistry(self.mac, oui_file)
        self.server = None
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

    def probe(self, target, network):
        if not usable_ip(self.ip):
            raise ValueError("Configure an IPv4 address before sending active probes.")
        subnet = IPv4Network(network, strict=False)
        if IPv4Address(self.ip) not in subnet:
            raise ValueError("The scan subnet must contain the adapter's IPv4 address.")
        if target:
            address = IPv4Address(target)
            if (not usable_ip(str(address)) or address in
                    (subnet.network_address, subnet.broadcast_address)
                    or address not in subnet):
                raise ValueError("Target must be a host in the configured scan subnet.")
            hosts = [str(address)]
            broadcast = str(address)
        else:
            if subnet.num_addresses > 1024:
                raise ValueError("ARP scans are limited to 1024 addresses; use a smaller subnet.")
            hosts = [str(ip) for ip in subnet.hosts() if str(ip) != self.ip]
            broadcast = str(subnet.broadcast_address)
        try:
            self.commands.put_nowait((hosts, broadcast))
        except queue.Full:
            raise ValueError("Scan queue is full. Wait for the current scans to finish.") from None

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

    def _send_probe(self, hosts, destination):
        context = os.urandom(8)
        query = (Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")
                 / IP(src=self.ip, dst=destination)
                 / UDP(sport=44818, dport=44818)
                 / list_identity_request(context))
        sendp(query, iface=self.interface, verbose=False)
        for host in hosts:
            if self.stop_event.is_set():
                break
            sendp(Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")
                  / ARP(hwsrc=self.mac, psrc=self.ip, pdst=host),
                  iface=self.interface, verbose=False)
            # Throttle probes, while the independent sniffer keeps capturing.
            self.stop_event.wait(0.01)
        self._emit("status", "Scan sent; listening for replies.")

    def _probe_worker(self, command):
        try:
            self._send_probe(*command)
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
                    device = self.registry.observe(packet)
                    if device:
                        # Immutable snapshot; no shared mutable GUI/device state.
                        self._emit("device", (
                            device.mac, device.ip, device.candidate,
                            device.manufacturer, ", ".join(sorted(device.protocols)),
                            device.identity, device.last_seen))
                    if self.server:
                        response = self.server.respond(packet)
                        if response:
                            sendp(response, iface=self.interface, verbose=False)
                            self._emit("status",
                                       f"Offered/assigned {response[BOOTP].yiaddr}; "
                                       "waiting for traffic to confirm the device IP.")
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
