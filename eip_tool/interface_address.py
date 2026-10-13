"""Temporary IPv4 aliases for reaching off-subnet devices on a local link."""

import ctypes
import json
import os
import re
import socket
import subprocess
import sys
import threading
from ipaddress import IPv4Address, IPv4Network

from scapy.all import ARP, Ether, conf, srp

from .discovery import usable_ip


class InterfaceAddressError(RuntimeError):
    pass


_windows_alias_contexts = {}


def validate_alias_parameters(observed_ip, current_ip, alias_ip, netmask):
    if not usable_ip(observed_ip) or not usable_ip(alias_ip):
        raise ValueError("Device and laptop alias must be usable IPv4 addresses.")
    try:
        target_network = IPv4Network(f"{observed_ip}/{netmask}", strict=False)
        alias_network = IPv4Network(f"{alias_ip}/{netmask}", strict=False)
        alias = IPv4Address(alias_ip)
    except ValueError as error:
        raise ValueError(f"Invalid IPv4 address or subnet mask: {error}") from error
    if target_network != alias_network:
        raise ValueError("The laptop alias must be in the observed device's subnet.")
    if alias in (target_network.network_address, target_network.broadcast_address):
        raise ValueError("The laptop alias must be a host address in the device subnet.")
    if alias == IPv4Address(observed_ip):
        raise ValueError("The laptop alias must differ from the device address.")
    if usable_ip(current_ip) and alias == IPv4Address(current_ip):
        raise ValueError("The laptop alias is already the adapter's primary address.")
    return target_network


def _platform_command(interface, address, netmask, add):
    if sys.platform.startswith("linux"):
        action = "add" if add else "del"
        prefix = IPv4Network(f"{address}/{netmask}", strict=False).prefixlen
        return ["ip", "-4", "address", action, f"{address}/{prefix}", "dev", interface]
    if sys.platform == "darwin":
        if add:
            return ["ifconfig", interface, "alias", address, "netmask", netmask]
        return ["ifconfig", interface, "-alias", address]
    raise InterfaceAddressError(f"Temporary IPv4 aliases are unsupported on {sys.platform}.")


def _windows_adapter_index(interface):
    for adapter in conf.ifaces.values():
        if adapter.name == interface:
            return int(adapter.index)
    raise InterfaceAddressError(f"Could not resolve Windows adapter {interface!r}.")


def _clean_windows_env():
    env = dict(os.environ)
    ps_key = next((k for k in list(env) if k.upper() == "PSMODULEPATH"), "PSModulePath")
    ps_module_path = env.get(ps_key, "")
    if ps_module_path:
        local_paths = [p for p in ps_module_path.split(";") if p and not p.startswith(r"\\")]
        if not local_paths:
            local_paths = [r"C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules"]
        cleaned = ";".join(local_paths)
        env[ps_key] = cleaned
        env["PSModulePath"] = cleaned
    return env


def _netsh_ipv4_addresses(interface):
    result = subprocess.run([
        "netsh", "interface", "ipv4", "show", "addresses", f"name={interface}"],
        capture_output=True, text=True, errors="replace", timeout=10, check=False)
    if result.returncode != 0:
        return []
    ip_matches = re.findall(r"IP(?:-Adresse| Address):\s*([0-9.]+)", result.stdout, re.IGNORECASE)
    prefix_matches = re.findall(r"/(1?[0-9]|2[0-9]|3[0-2])\b", result.stdout)
    addresses = []
    for i, ip_str in enumerate(ip_matches):
        prefix = int(prefix_matches[i]) if i < len(prefix_matches) else 24
        addresses.append({
            "IPAddress": ip_str,
            "PrefixLength": prefix,
            "State": "Preferred",
            "SkipAsSource": False,
        })
    return addresses


def _windows_ipv4_addresses(interface):
    adapter_index = _windows_adapter_index(interface)
    result = subprocess.run([
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "$ErrorActionPreference='Stop'; Import-Module NetTCPIP -ErrorAction SilentlyContinue; "
        f"@(Get-NetIPAddress -InterfaceIndex {adapter_index} -AddressFamily IPv4 "
        "-PolicyStore ActiveStore | Select-Object IPAddress,PrefixLength,"
        "@{Name='State';Expression={$_.AddressState.ToString()}},SkipAsSource) "
        "| ConvertTo-Json -Compress"],
        capture_output=True, text=True, errors="replace", timeout=10, check=False,
        env=_clean_windows_env())
    if result.returncode:
        fallback = _netsh_ipv4_addresses(interface)
        if fallback:
            return fallback
        raise InterfaceAddressError(result.stderr.strip() or "Could not inspect adapter IPv4 addresses.")
    try:
        addresses = json.loads(result.stdout) if result.stdout.strip() else []
    except ValueError as error:
        fallback = _netsh_ipv4_addresses(interface)
        if fallback:
            return fallback
        raise InterfaceAddressError("Windows returned invalid IPv4 address metadata.") from error
    return [addresses] if isinstance(addresses, dict) else addresses


def find_ready_adapter_address(interface, network):
    if sys.platform == "win32":
        for entry in _windows_ipv4_addresses(interface.name):
            address = entry["IPAddress"]
            if (entry["State"] == "Preferred" and not entry["SkipAsSource"]
                    and IPv4Network(f"{address}/{entry['PrefixLength']}", strict=False) == network):
                return address
        return None
    for address in getattr(interface, "ips", {}).get(4, []):
        if IPv4Address(address) in network:
            return str(address)
    return None


def _windows_wait_alias_ready(interface, address, netmask):
    prefix = IPv4Network(f"{address}/{netmask}", strict=False).prefixlen
    retry_wait = threading.Event()
    for attempt in range(6):
        for entry in _windows_ipv4_addresses(interface):
            if entry["IPAddress"] != address:
                continue
            if entry["State"] in ("Duplicate", "Invalid"):
                raise InterfaceAddressError(f"Windows reports {address} as {entry['State']}.")
            if (entry["State"] == "Preferred" and entry["PrefixLength"] == prefix
                    and not entry["SkipAsSource"]):
                return
        if attempt < 5:
            retry_wait.wait(1)
    raise InterfaceAddressError(f"Temporary address {address}/{prefix} did not become ready in Windows.")


def _windows_add_alias(interface, address, netmask):
    adapter_index = _windows_adapter_index(interface)
    context = ctypes.c_ulong()
    instance = ctypes.c_ulong()
    address_value = int.from_bytes(socket.inet_aton(address), "little")
    mask_value = int.from_bytes(socket.inet_aton(netmask), "little")
    iphlpapi = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
    add_address = iphlpapi.AddIPAddress
    add_address.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    add_address.restype = ctypes.c_uint32
    status = add_address(
        address_value, mask_value, adapter_index,
        ctypes.byref(context), ctypes.byref(instance))
    if status:
        raise InterfaceAddressError(
            f"Windows could not add {address} to adapter {interface!r} (error {status}).")
    _windows_alias_contexts[(interface, address)] = context.value


def _windows_remove_alias(interface, address):
    key = (interface, address)
    context = _windows_alias_contexts.get(key)
    if context is None:
        adapter_index = _windows_adapter_index(interface)
        address = str(IPv4Address(address))
        _run_interface_command([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop'; Import-Module NetTCPIP -ErrorAction SilentlyContinue; "
            f"Remove-NetIPAddress -InterfaceIndex {adapter_index} -IPAddress '{address}' "
            "-PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop"])
        return
    iphlpapi = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
    delete_address = iphlpapi.DeleteIPAddress
    delete_address.argtypes = [ctypes.c_uint32]
    delete_address.restype = ctypes.c_uint32
    status = delete_address(context)
    if status:
        raise InterfaceAddressError(
            f"Windows could not remove temporary address {address} (error {status}).")
    del _windows_alias_contexts[key]


def _run_interface_command(command):
    try:
        env = _clean_windows_env() if sys.platform == "win32" else None
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=20, check=False, env=env)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise InterfaceAddressError(f"Could not change the adapter address: {error}") from error
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise InterfaceAddressError(detail)


def add_temporary_ipv4_alias(interface, observed_ip, current_ip, alias_ip, netmask):
    network = validate_alias_parameters(observed_ip, current_ip, alias_ip, netmask)
    answers, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=alias_ip), iface=interface,
        timeout=0.8, retry=0, verbose=False)
    if answers:
        raise ValueError(f"{alias_ip} already responds to ARP; choose another laptop address.")
    if sys.platform == "win32":
        _windows_add_alias(interface, alias_ip, netmask)
        try:
            _windows_wait_alias_ready(interface, alias_ip, netmask)
        except (InterfaceAddressError, OSError, subprocess.TimeoutExpired) as error:
            try:
                _windows_remove_alias(interface, alias_ip)
            except InterfaceAddressError as cleanup_error:
                raise InterfaceAddressError(
                    f"{error} Cleanup also failed: {cleanup_error}") from error
            raise
    else:
        _run_interface_command(_platform_command(interface, alias_ip, netmask, add=True))
    return network


def remove_temporary_ipv4_alias(interface, alias_ip, netmask):
    if sys.platform == "win32":
        _windows_remove_alias(interface, alias_ip)
    else:
        _run_interface_command(_platform_command(interface, alias_ip, netmask, add=False))