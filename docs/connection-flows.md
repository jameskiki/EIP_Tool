# How the tool talks to EtherNet/IP devices

This page explains what the tool sends on the network to reach a device, read its data,
and exchange live I/O, and why each step is expected to work. The diagrams use Mermaid
and render on GitHub and in the VS Code Markdown preview.

Contents:

1. [Two kinds of EtherNet/IP traffic](#1-two-kinds-of-ethernetip-traffic)
2. [Explicit messaging (CIP Objects, CIP Scanner, Read Once)](#2-explicit-messaging)
3. [Why explicit reads returned only zeros](#3-why-explicit-reads-returned-only-zeros)
4. [Cyclic I/O connection (Open I/O connection)](#4-cyclic-io-connection)
5. [Packet layouts](#5-packet-layouts)
6. [Troubleshooting map](#6-troubleshooting-map)

---

## 1. Two kinds of EtherNet/IP traffic

| | Explicit messaging | Implicit (cyclic) I/O |
|---|---|---|
| Transport | TCP 44818 | UDP 2222 (set up over TCP 44818) |
| Pattern | Request → reply, on demand | Both sides send every RPI, no replies |
| Used by | CIP Objects, CIP Scanner, Device I/O *Read Once / Polling / Write to Device* (not connected) | Device I/O *Open I/O connection* |
| Device ownership | None; the device does not know a "master" exists | The tool becomes the **owner** of the assemblies, like a PLC |
| Typical use | Configuration, identity, diagnostics | Process data (inputs/outputs) |

```mermaid
flowchart LR
    subgraph Laptop["Laptop (this tool)"]
        E["Explicit client<br/>(pycomm3 CIPDriver)"]
        I["I/O connection<br/>(io_connection.py)"]
    end
    subgraph Device["XPort-EIP-MB"]
        MR["Message Router<br/>TCP 44818"]
        CM["Connection Manager<br/>class 0x06"]
        ASM["Assembly objects<br/>101 in / 102 out"]
        MB["Modbus master<br/>(serial side)"]
    end
    P["Peripheral<br/>e.g. MAI 315"]

    E -- "Get/Set_Attribute_Single" --> MR --> ASM
    I -- "Forward_Open / Forward_Close" --> CM
    I -. "UDP 2222 both directions, every RPI" .- ASM
    ASM <--> MB <--> P
```

---

## 2. Explicit messaging

Every explicit request (one attribute read in CIP Objects, each probe of the CIP Scanner,
Device I/O *Read Once*) follows the same steps:

```mermaid
sequenceDiagram
    autonumber
    participant T as Tool
    participant D as Device (TCP 44818)
    T->>D: TCP connect to port 44818
    T->>D: RegisterSession (encapsulation 0x65)
    D-->>T: Session handle
    T->>D: SendRRData (0x6F), unconnected message:<br/>service 0x0E Get_Attribute_Single, path class/instance/attribute
    D-->>T: Reply: general status (+ extended status) + attribute bytes
    T->>D: UnRegisterSession, TCP close
```

**Why it works:** every EtherNet/IP device must have a Message Router that accepts
unconnected requests on TCP 44818 (CIP Vol. 2). The request path is sent directly to the
target (`route_path=False`), with no backplane routing, because the XPort is the end
device and not a PLC chassis.

How the reply status is read:

```mermaid
flowchart TD
    R[Reply received] --> S{General status}
    S -- "0x00 / 0x06" --> OK["Attribute exists:<br/>decode bytes"]
    S -- "0x05 path destination unknown<br/>0x16 object does not exist" --> NX[Class or instance missing]
    S -- "0x14 attribute not supported" --> NA["Instance exists,<br/>this attribute does not"]
    S -- "0x08 service not supported" --> AMB["Ambiguous: the device rejects the service,<br/>which says nothing about existence"]
    S -- "no reply" --> ERR[Communication error → abort]
```

### CIP Scanner flow

The scanner is explicit messaging in a loop. It only uses reads and never writes.

```mermaid
flowchart TD
    A[Start scan] --> B{Message Router list enabled?}
    B -- yes --> C["Read class 0x02 inst 1 attr 1<br/>(list of classes the device advertises)"]
    B -- no --> D
    C --> D["Candidate classes =<br/>entered range + advertised list"]
    D --> E[Next class]
    E --> F["Read class attribute 1 (Revision)<br/>on instance 0"]
    F --> G{"Class confirmed?<br/>advertised, readable, or 0x14"}
    G -- no --> H["Probe instance 1 attribute 1"]
    H --> H2{readable or 0x14?}
    H2 -- no --> E
    H2 -- yes --> I
    G -- yes --> I["Read class attributes 2..7<br/>(Max Instance, Max Attribute ID ...)"]
    I --> J["Instances 1..min(Max Instance, limit):<br/>probe attr 1, then attr 3"]
    J --> K{"Instance exists?<br/>(status not 0x05/0x16)"}
    K -- yes --> L["Read attributes 1..min(Max Attribute ID, limit)"]
    K -- no --> J
    L --> J
    J -- done --> M[Emit class result to tree] --> E
    E -- no more classes --> Z[Scan finished]
```

**Why the "confirmed?" check matters:** some devices answer `0x08` for *every* unknown
class. Without that check, the scanner would probe up to 200 instances of each of 255
classes that do not exist.

---

## 3. Why explicit reads returned only zeros

The XPort-EIP-MB scan of 192.168.20.25 showed:

- Assembly 101 (input) and 102 (output) exist and have the right sizes (24 / 16 bytes for the MAI 315).
- Both read back as **all zero bytes**. The device really sent zeros; this is not a decoding problem.
- Identity attribute 5 (Status) = `0x0000`, so **bit 0 "Owned" is clear**: no connection owns the device.
- The Molex tool showed zeros too, but a PLC got real data.

```mermaid
flowchart TD
    A["Explicit Get_Attribute_Single<br/>on Assembly 101"] --> B{"Is an I/O connection open?<br/>(Identity status bit 0 'Owned')"}
    B -- "no (our case)" --> C["Gateway does not run its Modbus exchange<br/>→ input image never filled → 00 00 ..."]
    B -- yes --> D["Gateway polls the Modbus peripheral every cycle<br/>→ input image holds live values"]
    D --> E[Explicit read now also returns live data]
```

**Conclusion:** the gateway only exchanges data with the serial peripheral while a scanner
owns its assemblies. That is what a PLC does, and it explains why the PLC saw data and the
explicit tools did not.

> This is inferred from the device's behaviour, not from a vendor document. It was
> confirmed in practice: as soon as the tool opened an I/O connection, real values appeared.

---

## 4. Cyclic I/O connection

### 4.1 Full sequence

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant T as Tool
    participant D as XPort-EIP-MB
    participant P as Peripheral (Modbus)

    U->>T: Open I/O connection
    T->>D: TCP 44818 + RegisterSession
    T->>D: Forward_Open (service 0x54 to Connection Manager 0x06)<br/>path: config 128, consume 102, produce 101<br/>O→T 22 B, T→O 26 B, RPI, class 1 cyclic
    alt accepted
        D-->>T: Success + O→T and T→O connection IDs (+ optional multicast address)
        Note over T: Bind UDP 0.0.0.0:2222
        Note over D: Device is now "Owned"<br/>and starts its Modbus cycle
        loop every RPI
            T-)D: UDP O→T: conn ID, sequence, run/idle, 16 B output
            D->>P: Modbus write outputs / read inputs
            D-)T: UDP T→O: conn ID, sequence, 24 B input
            Note over T: Show input data, alive counter
        end
        U->>T: Close I/O connection
        T->>D: Forward_Close (0x4E), same serial triple
        D-->>T: Success, connection released
        T->>D: UnRegisterSession, TCP close
    else rejected
        D-->>T: Error status + extended status (e.g. 0x0106, 0x0109)
        Note over T: Show reason, close session, nothing left open
    end
```

The sizes shown are for the MAI 315 preset: 16 output bytes + 6 header bytes = 22, and
24 input bytes + 2 = 26.

### 4.2 What the tool does, step by step (decision view)

```mermaid
flowchart TD
    S[Open I/O connection clicked] --> V{"Settings valid?<br/>instances 1-65535, connection size ≤ 511 B,<br/>RPI 1-10000 ms"}
    V -- no --> VX[Show error, do nothing]
    V -- yes --> T1["TCP connect + RegisterSession"]
    T1 -- fails --> TX["'Connection to … failed'"]
    T1 --> FO["Forward_Open, T→O point-to-point"]
    FO --> R{Reply status}
    R -- "0x00" --> U["Bind UDP port 2222"]
    R -- "ext 0x0124 / 0x0108<br/>(T→O type not supported)" --> FM["Retry Forward_Open with T→O multicast"]
    FM --> R2{Reply status}
    R2 -- "0x00" --> U2["Bind UDP 2222 + join multicast group<br/>from the reply's sockaddr item"]
    R2 -- error --> FX
    R -- other error --> FX["Show decoded reason<br/>close TCP session"]
    U --> L
    U2 --> L
    U -- "port busy / blocked" --> UX["Forward_Close, then show<br/>'cannot listen on UDP 2222'"]
    L["I/O loop thread"] --> SEND["Every RPI: send O→T packet<br/>(current output bytes, run/idle flag)"]
    SEND --> RECV{"Packet from device IP<br/>with our T→O connection ID?"}
    RECV -- yes --> SHOW["Update input view<br/>(immediately on change, otherwise every 0.5 s)"]
    RECV -- "nothing for 16 × RPI (at least 1 s)" --> WARN["Warn: no input,<br/>check firewall / connection"]
    SHOW --> SEND
    WARN --> SEND
    L -- "Close clicked / tab closed / app closed" --> FC["Stop loop, close UDP,<br/>Forward_Close (retry once on a new session)"]
```

### 4.3 Why each Forward_Open field is chosen

| Field | Value | Why |
|---|---|---|
| Connection path | `20 04 24 80 2C 66 2C 65` | Class 0x04 Assembly, config instance 128, then the **consumed** point (O→T output 102) and **produced** point (T→O input 101). CIP requires this order. Instances above 255 use 16-bit segments. |
| Transport class/trigger | `0x01` | Class 1, cyclic production, the standard for PLC I/O. |
| O→T size | output bytes + 2 + 4 | 2-byte CIP sequence count plus a 4-byte run/idle header, which is how adapters normally expect outputs. |
| T→O size | input bytes + 2 | Inputs are "modeless": only the sequence count, no run/idle header. |
| Network parameters | point-to-point, scheduled priority, fixed size | Point-to-point avoids needing multicast on the laptop; the multicast retry covers devices that refuse it. |
| RPI | user-selected (default 500 ms) | Slow enough for a Modbus gateway with serial polling behind it. The device may reject an RPI it cannot meet (`0x0111`). |
| Timeout multiplier | 2 → ×16 | The device drops the connection after 16 missing RPIs. This bounds how long outputs stay active if the laptop disappears. |
| O→T connection ID | 0 | The target assigns it and returns it in the reply. |
| T→O connection ID | random | Chosen by the tool and used to recognise its own input packets. |
| Serial / Vendor 0xFFFE / Originator serial | random per connection | Together these identify the connection. Forward_Close must repeat them exactly, so the device knows which connection to release. |

**Why this is expected to work:** this is the same Forward_Open that any EtherNet/IP scanner
(PLC, Molex in scanner mode, etc.) sends. The adapter cannot tell the tool apart from a PLC.
Once it accepts the request, CIP requires it to produce T→O data every RPI and to consume
our O→T data. That is the state in which the XPort runs its Modbus exchange.

### 4.4 Run / Idle

```mermaid
flowchart LR
    W["Output buffer<br/>(zeros until 'Write to Device')"] --> PKT["O→T packet every RPI"]
    RI{"Run mode ticked?"} -- no --> IDLE["run/idle header = 0 (Idle)<br/>device keeps outputs in the idle/safe state"]
    RI -- yes --> RUN["run/idle header = 1 (Run)<br/>device applies the output buffer"]
    IDLE --> PKT
    RUN --> PKT
```

- After *Write to Device*, the bytes stay in the buffer and are resent every RPI until you write something else or close.
- Data shorter than the output size is zero-padded; longer data is truncated.
- What the peripheral does in *Idle* depends on the gateway's configuration (usually it holds or clears its outputs).

### 4.5 Ending the connection safely

```mermaid
flowchart TD
    A{How does it end?}
    A -- "Close button / tab / app closed" --> B["Forward_Close sent<br/>device releases ownership immediately"]
    A -- "Laptop crash, cable pulled" --> C["No O→T packets arrive<br/>device times out after 16 × RPI<br/>(8 s at 500 ms) and releases ownership"]
    A -- "Forward_Close not confirmed" --> C
```

Either way, the device ends up unowned, so a PLC can connect afterwards.

---

## 5. Packet layouts

UDP O→T (tool → device), little-endian:

```text
02 00                                   item count = 2
02 80 08 00 <O→T conn ID:4> <seq:4>     sequenced address item (0x8002)
B1 00 <len:2>                           connected data item (0x00B1)
  <CIP seq:2> <run/idle:4> <output data: N bytes>
```

UDP T→O (device → tool):

```text
02 00
02 80 08 00 <T→O conn ID:4> <seq:4>
B1 00 <len:2>
  <CIP seq:2> <input data: N bytes>
```

The tool ignores packets whose source IP or T→O connection ID does not match.

---

## 6. Troubleshooting map

```mermaid
flowchart TD
    A[Problem] --> B{Which symptom?}
    B -- "Explicit reads all zero" --> C["Expected on the XPort-EIP-MB without an owner<br/>→ open an I/O connection"]
    B -- "Forward_Open rejected" --> D{Extended status}
    D -- "0x0106 ownership conflict / 0x0100 in use" --> D1["Disconnect the PLC or other scanner<br/>(only one owner of the outputs)"]
    D -- "0x0109 / 0x0125 / 0x0126 size" --> D2["Fix the byte counts;<br/>the message shows the size the device accepts"]
    D -- "0x0111 RPI not supported" --> D3[Choose a different RPI]
    D -- "0x0127 / 0x0118 config path" --> D4["Try config instance 1<br/>(128 is unconfirmed on this device)"]
    D -- "0x0117 / 0x0128 / 0x0129 path" --> D5[Check input/output instance numbers]
    B -- "Connected but 'no input packets'" --> E["Allow inbound UDP 2222 for Python in Windows Firewall;<br/>close Molex or other tools using port 2222;<br/>check the laptop's adapter is in the device subnet"]
    B -- "'Cannot listen on UDP port 2222'" --> F[Another program already uses port 2222]
    B -- "Inputs arrive but values look wrong" --> G["Check preset sizes and word mapping<br/>(alive counter word)"]
```

---

Source files: [`eip_tool/io_connection.py`](../eip_tool/io_connection.py) (Forward_Open, UDP loop,
Forward_Close), [`eip_tool/device_io.py`](../eip_tool/device_io.py) (Device I/O tab),
[`eip_tool/cip_scanner.py`](../eip_tool/cip_scanner.py), and
[`eip_tool/cip_objects.py`](../eip_tool/cip_objects.py).
