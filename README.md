# Workbench Device Discovery Tool

A Python/Tkinter GUI for discovering IPv4 field devices, including EtherNet/IP
(EIP) devices, on an **authorized, isolated wired switch**. No router, internet,
or existing DHCP server is needed at runtime.

## Install and launch

Requires Python 3.12+, Tkinter, and packet-capture privileges.

```sh
python -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows instead: .venv\Scripts\activate
python -m pip install .
python -m eip_tool
```

Alternatively, with [uv](https://docs.astral.sh/uv/): `uv sync`, then
`uv run python -m eip_tool`. The installed `eip-tool` command also launches the GUI.
Install dependencies before taking the laptop offline.

- **Linux:** install the distribution's Tkinter package (e.g.
  `sudo apt install python3-tk`). Raw Ethernet capture/transmission normally needs
  root or equivalent capture capabilities. For example, from a local desktop:
  `sudo .venv/bin/python -m eip_tool` (your desktop must allow display access).
- **Windows:** install Python with Tcl/Tk and
  [Npcap](https://npcap.com/) (WinPcap-compatible mode), and run an elevated
  terminal if Npcap requires administrator access.
- **macOS:** use a Python distribution with Tk support and grant access to BPF
  capture devices, or launch with appropriate privileges from your desktop.

## Bench workflow

1. Connect only the laptop and test devices to the isolated switch. Select the
   **wired adapter** in the GUI.
2. Click **Start listening** and wait for “Listening — power-cycle the device now.”
   **Then** plug in / power-cycle the field device. Listening is passive by default
   and does not require an IPv4 address on the laptop.
3. Rows appear automatically, keyed by MAC, with observed IPv4, offline OUI
   manufacturer, protocol evidence, EIP identity when available, and last-seen time.
   ARP probe targets and DHCP requested addresses appear separately as
   **unconfirmed**; offers are not proof that a device accepted an address.
4. To query devices, configure a static IPv4 address on the laptop in the same
   subnet, select the scan subnet, and start listening again. Enter a known IPv4
   or leave it blank for a subnet scan, then click **Probe EIP + ARP**. The tool
   sends an EtherNet/IP UDP ListIdentity request (port 44818) and ARP probes on
   the selected adapter. A subnet scan is limited to 1024 addresses. It does not
   change the laptop's network configuration automatically.
5. For an observed old static or link-local IP, first configure the laptop in
   that address range (e.g. `169.254.10.1/16`), reselect the adapter, and set the
   correct scan subnet. A **known-IP** query works with larger subnets; a broad
   scan is deliberately restricted. Some devices require a matching laptop
   subnet before responding to EIP.
6. Click **Stop** before changing adapters, subnet, or service configuration.
   Stopping closes capture and ends the service. Rows remain until the next start.

### Opt-in BOOTP/DHCP service

**Do not enable this service on a production, routed, Wi-Fi, or shared LAN.**
Do not run it alongside any other DHCP/BOOTP server, including a local laptop
service. It can change device IP addresses; BOOTP settings may persist in a
device after reboot. It does not disable a device's BOOTP setting.

Set a static laptop address (e.g. `192.168.1.1/24`), scan/service subnet
(`192.168.1.0/24`), and a dedicated, known-free pool (`192.168.1.100` to
`192.168.1.150`). The pool must exclude the laptop, network, and broadcast
addresses. Check **Enable BOOTP + DHCP**, confirm the safety prompt, and start
before powering the device.

The service handles direct Ethernet BOOTP requests and DHCP
Discover/Offer/Request/ACK, renewal, release, and decline. It sends Layer-2
replies on the selected adapter, honoring the client's broadcast flag or current
address, without advertising a gateway or DNS server. Relayed requests and
requests selecting a different DHCP server
are ignored. DHCP requests are acknowledged only for bindings offered by this
running session; clients with an old lease may need to retry discovery.
Addresses are checked against recent (last minute) IP observations and a fresh
ARP probe before offering. Boot requests without an IP do not refresh address
ownership; a DHCP release clears the client's observed address.
**A nonresponsive device may still hold that IP: conflict checks are best-effort,
so use a pool you know is free.**

DHCP leases last one hour; pending offers reserve an address for one minute.
Classic BOOTP reservations and declined addresses are retained until Stop.
Bindings are **in memory only**: restarting loses reservations. Keep the pool
dedicated, and do not restart the service while clients depend on its leases.
This is a small bench responder, not a production DHCP server.

## Discovery coverage and physical limits

- BOOTP/DHCP boot requests reveal a MAC even before the device has an IP.
- Gratuitous ARP and IPv4 source traffic reveal old static and link-local IPs.
  Link-local ARP probes reveal a *candidate* before the device claims it.
- Other Ethernet frames can reveal a MAC even without IPv4.
- Active ARP finds responding devices in a chosen local subnet. EtherNet/IP
  ListIdentity adds product name, vendor ID, revision, and serial for devices
  supporting that command. OUI manufacturer and EIP vendor ID are different
  kinds of evidence; an OUI identifies the registered MAC vendor, not necessarily
  the product brand.
- **There is no universal way to find a completely silent device with an
  arbitrary unknown static IPv4 address.** A switch forwards broadcasts to the
  laptop, but generally does not forward other ports' unicast traffic.
  Promiscuous capture does not bypass this. A device that neither broadcasts at
  boot nor responds to the chosen probes may require its documented default
  address, a known subnet, a direct connection, or a switch mirror/TAP.
- Capture and GUI queues separate networking from Tk's main thread. Capture
  overflow is reported rather than silently claiming complete discovery.

Manufacturer lookup uses the `manuf` package's bundled database, **without
network requests**. Unknown or locally administered MACs are labelled as such.
The bundled database can be dated; supply a trusted, newer local
Wireshark-format database with `python -m eip_tool --oui-file /path/to/manuf`.

## Development checks

Tests use Python's standard library and synthetic Ethernet frames, with no
physical devices or privileges required:

```sh
python -m unittest discover -s tests -v
python -m compileall -q eip_tool
```

GUI tests skip without a display. On Linux with an existing Xvfb installation,
run `xvfb-run -a python -m unittest discover -s tests -v` to exercise them.
Actual boot timing, switch forwarding, firewall/capture-driver behavior, and
vendor interoperability must also be checked on the intended bench hardware.