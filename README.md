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
  [Npcap](https://npcap.com/) (WinPcap-compatible mode). The app requests
  administrator access through UAC at startup for packet capture and XPort setup.
- **macOS:** use a Python distribution with Tk support and grant access to BPF
  capture devices, or launch with appropriate privileges from your desktop.

## Bench workflow

1. Connect only the laptop and test devices to the isolated switch. Select the
   **wired adapter** in the GUI.
2. Click **Start listening** and wait for “Listening — power-cycle the device now.”
   **Then** plug in / power-cycle the field device. Listening is passive by default
   and does not require an IPv4 address on the laptop.
3. Rows appear automatically, keyed by MAC, with latest observed IPv4, offline OUI
  manufacturer, protocol evidence, EIP identity when available, and first/last-seen
  timestamps. **Observed IP history** keeps all source IPs observed under that MAC
  during this listening session, including previous addresses after reconfiguration.
  History does not mean every address is still active; **Configure selected** uses
  **Latest observed IP**. First seen stays fixed until a new listening session starts.
   ARP probe targets and DHCP requested addresses appear separately as
   **unconfirmed**; offers are not proof that a device accepted an address.
4. To query devices, configure a static IPv4 address on the laptop in the same
  subnet and start listening. Use **Broadcast** for EtherNet/IP discovery,
  **Targeted scan** for unicast ListIdentity probes, **ARP scan** for address
  resolution, or **XPort discovery** for Lantronix LDP. The EIP and ARP target
  fields accept IPs, CIDRs, or inclusive ranges; blank uses the default scan
  subnet. Explicit scans are limited to 4096 targets and stay on the selected
  Ethernet segment/VLAN. Probe actions do not change the laptop IP.
5. For an observed old static or link-local IP, first configure the laptop in
   that address range (e.g. `169.254.10.1/16`), reselect the adapter, and set the
   correct scan subnet. A **known-IP** query works with larger subnets; a broad
   scan is deliberately restricted. Some devices require a matching laptop
   subnet before responding to EIP.
6. Click **Stop** before changing adapters, subnet, or service configuration.
   Stopping closes capture and ends the service. Rows remain until the next start.

For a selected device with an observed IP, the **Lantronix diagnostics** tab's
**Read diagnostics (port 9999)** button queries TCP
port `9999` and displays the read-only setup/status menu (model, firmware, and
network settings, when available). It sends Enter only after the setup prompt;
it does not send menu selections or modify the device. A refused connection
means the device has no port 9999 setup service (not a Lantronix device, or
Telnet setup disabled); it says nothing about IP or EtherNet/IP reachability.

Select a device row and click **Configure selected** for EtherNet/IP
configuration. The app accesses the TCP/IP Interface Object (class `0xF5`)
through CIP, checks the device's configuration capability, and verifies writes.
**Apply static IPv4** first selects stored/static startup mode, then writes the
address, mask, and gateway. **Enable BOOTP** and **Disable BOOTP** change the startup mode.
An observed IP is required; use a BOOTP tool to assign one first. After changing
BOOTP mode, power-cycle the device with the responder ready when enabling it.
Rediscover to verify address changes. A BOOTP reply, DHCP Offer, or DHCP ACK is
not by itself confirmation that the device is using the address; the GUI only
marks an assignment confirmed after observing traffic from that MAC at that IP.

For an observed off-subnet device, open **Configure selected** and use
**Add laptop IP alias** to add a secondary address in the device's current subnet.
Use **Add factory alias...** in the main window to prepare a known-free laptop
address in `192.168.0.0/24`, the usual factory network for your bench devices.
The suggested host number follows the laptop's current last octet; confirm that
it is unused and is not the device's address. Windows aliases must become
`Preferred` before the app uses them.
When setting a new static address outside the current subnet, the guide reuses
an existing ready address in the destination subnet or asks for a new temporary
laptop address. Verification retries up to six times after the write, without
repeating the write, and requires matching IP/mask/gateway and static mode.
If verification still fails, the device may already have moved: check the alias
and rediscover it before writing again. The
existing laptop address, gateway, and DNS settings are preserved; the alias is
removed when the guide removes it or the app exits normally. If the app is
forcibly terminated, the active-only alias may need to be removed manually or
will disappear after reboot. Then use **Set static IPv4** to configure the device.

The device table stays visible at the top; Config, Device I/O, Lantronix
diagnostics, CIP Objects, and CIP Scanner are tabs below it (drag the divider to resize). On **CIP Objects**,
**0x01 Identity**, **0xF5 TCP/IP**, and **0xF6 Ethernet Link** (or **Read all**)
read every known attribute of the selected device with read-only
Get_Attribute_Single requests; unsupported attributes are marked as such.

The **CIP Scanner** tab discovers which classes, instances, and attributes the
selected device actually implements, using read-only Get_Attribute_Single probes:
- **Classes** accepts ranges such as `0x01-0xFF`, `0x04, 0xF5-0xF6`, or decimals.
  With **Message Router list** enabled, classes the device advertises in Message
  Router (class `0x02`) attribute 1 are added, including vendor classes above `0xFF`.
- Class attributes (instance 0) are read; *Max Instance* (attribute 2) bounds the
  instance probe and *Max Instance Attribute ID* (attribute 7) the attribute probe.
  **Max instance** / **Max attribute** cap the probe so slow devices stay usable;
  a note is shown when a device reports more instances than the cap.
- CIP status `0x05`/`0x16` means "does not exist" and `0x14` means "instance
  exists, attribute not supported". Devices that answer `0x08` (service not supported)
  for everything are only listed for a class if instance 1 proves it exists.
- Known attributes are named and decoded; others get a best-effort guess
  (SHORT_STRING/STRING/UINT/UDINT/words) plus raw hex. Double-click an attribute
  (or **Open in Device I/O**) to read/write it on the Device I/O tab, and use
  **Export CSV...** to save the result. **Stop** ends the scan after the current request.

Select a discovered device row and click **Load selected device** on the
**Device I/O** tab to test peripheral
communication directly through CIP explicit messaging (Assembly Object class `0x04`):
- **Device Model Presets**:
  - **VT-015131 CVC 650 EIP**: Input Inst 101 = 54 words (108 bytes, Word 27 Alive Counter); Output Inst 102 = 16 words (32 bytes).
  - **VT-016246 MAI 114 EIP**: Input Inst 101 = 8 words (16 bytes); Output Inst 102 = 6 words (12 bytes).
  - **VT-016403 MAI 314 EIP**: Input Inst 101 = 8 words (16 bytes); Output Inst 102 = 6 words (12 bytes).
  - **VT.019279 MAI 315 EIP**: Input Inst 101 = 12 words (24 bytes); Output Inst 102 = 8 words (16 bytes).
  - **Configuration Object**: Instance 128 (`0x80`), 0 words.
  - **Custom CIP Object**: Custom class, instance, and attribute.
- **Input Assembly Reading**:
  Read peripheral inputs once or stream live updates with **Start Polling** (0.2s - 5.0s).
  For CVC 650, Word 27 is tracked with a dedicated live health/ticking indicator.
- **Output Assembly Writing**:
  Test peripheral outputs by writing hex data. Quick buttons fill expected zeroes,
  common word lengths (6w, 8w, 16w, 54w), or test patterns.
- **View formats**: Switch between 16-bit word view (word offsets, hex, unsigned/signed decimal),
  standard hex dump with ASCII, and raw hex bytes.
- **Cyclic I/O connection (Class 1, like a PLC)**: Some adapters - e.g. the Lantronix
  XPort-EIP-MB Modbus gateway - only refresh their input assembly while a scanner owns them,
  so explicit reads return zeros (Identity status bit 0 "Owned" is clear). **Open I/O connection**
  sends a Forward_Open (input = T->O, output = O->T, config instance, RPI; sizes are filled from
  the selected preset) and then exchanges UDP packets on port 2222 at the RPI, showing live input
  data in the view above. Inputs are requested point-to-point, falling back to multicast if the
  device rejects that. While connected, **Write to Device** sets the cyclic output data instead of
  using Set_Attribute_Single; outputs are sent with the *Idle* flag unless **Run mode** is ticked.
  **Close I/O connection** sends Forward_Close. Only one scanner can own a device's outputs, so
  disconnect a PLC first (ownership conflict `0x0106`). If no input packets arrive, allow inbound
  UDP 2222 for Python in Windows Firewall and make sure no other EtherNet/IP tool uses port 2222.
  See [docs/connection-flows.md](docs/connection-flows.md) for flow charts of every step and why it works.
If a device has neither a reachable IP nor BOOTP/DHCP enabled, Ethernet-only
configuration may be impossible; use the board's supported serial or recovery
method.

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

For a specific device, select its row, click **Configure selected**, choose
**Assign IP via BOOTP**, and enter an unused host address in the service subnet.
The app binds that address to the selected MAC and starts its responder; other
clients will skip the reserved address. Power-cycle the device after listening
starts. Stop any other BOOTP/DHCP server first.

The service handles direct Ethernet BOOTP requests and DHCP
Discover/Offer/Request/ACK, renewal, release, and decline. It sends Layer-2
replies on the selected adapter. DHCP replies honor the client's broadcast
flag; initial classic BOOTP replies are broadcast for compatibility with clients
that cannot receive unicast before configuring their address. Replies to an
existing `ciaddr` are unicast. The service does not advertise a gateway or DNS server. Relayed requests and
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
- Lantronix Discovery Protocol replies can reveal XPort IP addresses outside the
  current ARP scan subnet when the device's discovery service is enabled.
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