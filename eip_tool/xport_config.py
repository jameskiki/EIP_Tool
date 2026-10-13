"""EtherNet/IP TCP/IP Interface Object configuration helpers."""

import struct
import threading
from ipaddress import IPv4Address, IPv4Network

from pycomm3 import CIPDriver, Services, UDINT
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

from .discovery import usable_ip, valid_mac


def validate_static_parameters(adapter_ip, scan_network, address, netmask, gateway, mac):
    if not valid_mac(mac):
        raise ValueError("Select a device with a valid MAC address.")
    if not usable_ip(adapter_ip) or not usable_ip(address):
        raise ValueError("The adapter and static address must be usable IPv4 addresses.")
    adapter_network = IPv4Network(scan_network, strict=False)
    target_network = IPv4Network(f"{address}/{netmask}", strict=False)
    target = IPv4Address(address)
    if IPv4Address(adapter_ip) not in adapter_network:
        raise ValueError("The selected scan subnet must contain the adapter's current address.")
    if (target in (target_network.network_address, target_network.broadcast_address)
            or target == IPv4Address(adapter_ip)):
        raise ValueError("The static address must be an unused host address.")
    if gateway:
        gateway_address = IPv4Address(gateway) if usable_ip(gateway) else None
        if (gateway_address is None
                or IPv4Network(f"{gateway}/{netmask}", strict=False) != target_network
                or gateway_address in (target_network.network_address,
                                       target_network.broadcast_address)):
            raise ValueError("The optional gateway must be a usable address in the static subnet.")
    return target_network


TCP_IP_CLASS = 0xF5
TCP_IP_INSTANCE = 1
CAPABILITY_BOOTP = 0x01
CAPABILITY_CONFIGURABLE = 0x10
CONFIGURATION_MODE_MASK = 0x0F
CONFIGURATION_STATUS_MASK = 0x0F
HARDWARE_CONFIGURATION_STATUS = 2
STATIC_MODE = 0
BOOTP_MODE = 1


class CIPConfigurationError(RuntimeError):
    pass


def _cip_request(address, service, attribute, data_type=None, request_data=b""):
    try:
        with CIPDriver(address) as driver:
            response = driver.generic_message(
                service=service, class_code=TCP_IP_CLASS, instance=TCP_IP_INSTANCE,
                attribute=attribute, request_data=request_data, data_type=data_type,
                connected=False, unconnected_send=False, route_path=False,
                name=f"TCP/IP interface attribute {attribute}")
    except Exception as error:
        raise CIPConfigurationError(f"EtherNet/IP request to {address} failed: {error}") from error
    if response is None or response.error:
        detail = response.error if response is not None else "no response"
        raise CIPConfigurationError(f"TCP/IP interface attribute {attribute}: {detail}")
    return response.value


def _read_attribute(address, attribute, data_type=None):
    return _cip_request(address, Services.get_attribute_single, attribute, data_type)


def _write_attribute(address, attribute, payload):
    return _cip_request(
        address, Services.set_attribute_single, attribute, request_data=payload)


def _validate_interface_config(config):
    if len(config) < 22:
        raise CIPConfigurationError("The device returned a truncated TCP/IP interface configuration.")
    domain_length = struct.unpack_from("<H", config, 20)[0]
    if len(config) < 22 + domain_length:
        raise CIPConfigurationError("The device returned an invalid domain-name field.")


def _updated_interface_config(current, address, netmask, gateway):
    return (struct.pack(
        "<III", int(IPv4Address(address)), int(IPv4Address(netmask)),
        int(IPv4Address(gateway)) if gateway else 0) + current[12:])


def _check_address_conflict(interface, address, mac):
    answers, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=address), iface=interface,
        timeout=1, retry=0, verbose=False)
    for _, response in answers:
        if str(response[ARP].hwsrc).lower() != mac.lower():
            raise ValueError(f"{address} already responds to ARP; choose another address.")


def _verify_static_configuration(address, configuration):
    retry_wait = threading.Event()
    for attempt in range(6):
        try:
            applied = bytes(_read_attribute(address, 5))
            _validate_interface_config(applied)
            if applied[:12] != configuration[:12]:
                raise CIPConfigurationError("Read-back IP/mask/gateway do not match the requested settings.")
            control = int(_read_attribute(address, 3, UDINT))
            if control & CONFIGURATION_MODE_MASK != STATIC_MODE:
                raise CIPConfigurationError("The device did not confirm stored/static startup mode.")
            return
        except CIPConfigurationError:
            if attempt == 5:
                raise
            retry_wait.wait(1)


def apply_static_xport_address(interface, adapter_ip, scan_network, mac,
                               observed_ip, address, netmask, gateway):
    if not usable_ip(observed_ip):
        raise ValueError("Assign an IP with a BOOTP tool first; CIP configuration needs a reachable address.")
    validate_static_parameters(adapter_ip, scan_network, address, netmask, gateway, mac)
    _check_address_conflict(interface, address, mac)

    capability = int(_read_attribute(observed_ip, 2, UDINT))
    if not capability & CAPABILITY_CONFIGURABLE:
        raise CIPConfigurationError(
            "The device reports that its IP configuration is not writable via EtherNet/IP.")
    status = int(_read_attribute(observed_ip, 1, UDINT))
    if status & CONFIGURATION_STATUS_MASK == HARDWARE_CONFIGURATION_STATUS:
        raise CIPConfigurationError(
            "The device reports hardware-selected network settings (status 2); its TCP/IP "
            "object rejects remote IP changes in this state.")
    control = int(_read_attribute(observed_ip, 3, UDINT))
    current_config = bytes(_read_attribute(observed_ip, 5))
    _validate_interface_config(current_config)
    configuration = _updated_interface_config(current_config, address, netmask, gateway)

    static_control = control & ~CONFIGURATION_MODE_MASK
    if control != static_control:
        _write_attribute(observed_ip, 3, UDINT.encode(static_control))
        verified_control = int(_read_attribute(observed_ip, 3, UDINT))
        if verified_control & CONFIGURATION_MODE_MASK != STATIC_MODE:
            raise CIPConfigurationError("The device did not accept stored/static startup mode.")

    write_error = None
    try:
        _write_attribute(observed_ip, 5, configuration)
    except CIPConfigurationError as error:
        write_error = error
    try:
        _verify_static_configuration(address, configuration)
    except CIPConfigurationError as error:
        write_detail = f" Write response: {write_error}." if write_error else ""
        raise CIPConfigurationError(
            f"Verification at {address} failed after 6 attempts: {error}.{write_detail} "
            "The device may already have changed address. Check the laptop alias and rescan "
            "before trying another write.") from error


def set_bootp_mode(address, enable):
    capability = int(_read_attribute(address, 2, UDINT))
    if enable and not capability & CAPABILITY_BOOTP:
        raise CIPConfigurationError("The device does not report BOOTP-client capability.")
    control = int(_read_attribute(address, 3, UDINT))
    mode = BOOTP_MODE if enable else STATIC_MODE
    _write_attribute(address, 3, UDINT.encode(
        (control & ~CONFIGURATION_MODE_MASK) | mode))
    verified_control = int(_read_attribute(address, 3, UDINT))
    if verified_control & CONFIGURATION_MODE_MASK != mode:
        raise CIPConfigurationError("The device did not confirm the requested BOOTP mode.")