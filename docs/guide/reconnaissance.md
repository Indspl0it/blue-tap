# Reconnaissance

**Modules:** 13 total (7 CLI-exposed, 6 internal)

All reconnaissance probes are **non-intrusive** and require **no pairing**.

Reconnaissance is the deep-dive phase that follows [Discovery](discovery.md). Where discovery answers "what devices are nearby?", reconnaissance answers "what does this specific target expose?" Each probe reveals a different facet of the target's attack surface: which services it offers, which channels are open, what firmware it runs, and how its Bluetooth stack behaves.

The findings from reconnaissance directly inform which vulnerability checks and exploits apply. For example, if SDP reveals OBEX Object Push on RFCOMM channel 12, you know the target may be vulnerable to Bluesnarfing. If GATT enumeration shows writable characteristics without authentication, the target has a BLE posture weakness.

---

## CLI-Exposed Probes

| Command | Module ID | What It Collects | Key Options |
|---------|-----------|------------------|-------------|
| `recon TARGET sdp` | `reconnaissance.sdp` | SDP services, profiles, channels | `--retries` |
| `recon TARGET gatt` | `reconnaissance.gatt` | BLE GATT services, characteristics | --- |
| `recon TARGET l2cap` | `reconnaissance.l2cap_scan` | Open L2CAP PSMs | `--start-psm` (1), `--end-psm` (4097), `--timeout` (1000ms) |
| `recon TARGET rfcomm` | `reconnaissance.rfcomm_scan` | Open RFCOMM channels | `--start-channel` (1), `--end-channel` (30), `--timeout` (2000ms) |
| `recon TARGET fingerprint` | `reconnaissance.fingerprint` | Device identification | --- |
| `recon TARGET capture` | `reconnaissance.hci_capture` | HCI packet capture | `-d` duration, `-o` output |
| `recon TARGET sniff` | `reconnaissance.sniffer` | Passive BT sniffing | `-m` mode, `-d` duration, `-o` output |

---

## Probe Details

### SDP

Queries the target's Service Discovery Protocol database. SDP is Bluetooth Classic's service registry --- every profile the device supports (A2DP, HFP, OBEX, HID, etc.) is advertised here along with the protocol stack needed to connect.

SDP results tell you exactly what the target does over Bluetooth: which profiles are active, which L2CAP PSMs or RFCOMM channels they use, and what protocol versions are supported. This is the single most informative recon probe for Classic targets.

```bash
blue-tap recon 4C:4F:EE:17:3A:89 sdp
blue-tap recon 4C:4F:EE:17:3A:89 sdp --retries 3
```

!!! example "SDP probe output"
    ```
    $ sudo blue-tap recon 4C:4F:EE:17:3A:89 sdp
    Session: blue-tap_20260416_144012

    ── SDP Services (4C:4F:EE:17:3A:89) ───────────────────────────────────────────

    Service: Audio Source (A2DP)
      Profile:   Advanced Audio Distribution (0x110D) v1.3
      Protocol:  L2CAP > AVDTP
      PSM:       25
      Channel:   ---

    Service: AV Remote Control Target
      Profile:   A/V Remote Control (0x110E) v1.6
      Protocol:  L2CAP > AVCTP
      PSM:       23
      Channel:   ---

    Service: Handsfree Audio Gateway
      Profile:   Hands-Free (0x111E) v1.7
      Protocol:  L2CAP > RFCOMM
      Channel:   2

    Service: OBEX Object Push
      Profile:   Object Push (0x1105) v1.2
      Protocol:  L2CAP > RFCOMM > OBEX
      Channel:   12

    Service: Phonebook Access PSE
      Profile:   Phonebook Access (0x1130) v1.2
      Protocol:  L2CAP > RFCOMM > OBEX
      Channel:   15

    Service: Message Access Server
      Profile:   Message Access (0x1132) v1.0
      Protocol:  L2CAP > RFCOMM > OBEX
      Channel:   16

    Found 6 services on 4C:4F:EE:17:3A:89
    ```

!!! tip "What SDP Findings Mean"
    - **OBEX Object Push** on an IVI means file transfer is available --- potential Bluesnarfing vector
    - **Phonebook Access (PBAP)** means the target syncs phonebooks --- if auth is weak, contacts can be extracted
    - **Message Access (MAP)** means SMS sync is available --- messages may be extractable
    - **Hands-Free** means audio channel access --- can be used for eavesdropping after exploitation
    - **HID** means the target accepts keyboard/mouse input --- relevant for CVE-2023-45866

### GATT

Enumerates BLE GATT services and characteristics. Connects to the target, discovers all services, and reads characteristic properties (read/write/notify flags). GATT is the BLE equivalent of SDP --- it defines what data and operations the device exposes.

```bash
blue-tap recon DE:AD:BE:EF:CA:FE gatt
```

!!! example "GATT enumeration output"
    ```
    $ sudo blue-tap recon DE:AD:BE:EF:CA:FE gatt
    Session: blue-tap_20260416_144130

    ── GATT Services (DE:AD:BE:EF:CA:FE) ──────────────────────────────────────────

    Service: Generic Access (0x1800)
      ├── Device Name (0x2A00)          [read]
      └── Appearance (0x2A01)           [read]

    Service: Battery Service (0x180F)
      └── Battery Level (0x2A19)        [read, notify]

    Service: Human Interface Device (0x1812)
      ├── Report (0x2A4D)               [read, write, notify]
      ├── Report Map (0x2A4B)           [read]
      └── HID Control Point (0x2A4C)    [write-no-response]

    Service: Vendor Specific (0xFFF0)
      ├── Custom Char (0xFFF1)          [read, write]
      └── Custom Char (0xFFF2)          [read, notify]

    Found 4 services, 9 characteristics
    Writable without auth: 3 characteristics (flagged)
    ```

!!! warning "Writable Characteristics"
    Characteristics marked `[write]` or `[write-no-response]` that do not require authentication are a posture finding. The vulnscan `writable_gatt` check flags these automatically, but GATT recon shows you the full picture. Vendor-specific services (UUIDs starting with `0xFFF`) often have custom writable characteristics that were not designed with security in mind.

### L2CAP Scan

Probes L2CAP Protocol/Service Multiplexer (PSM) values to find open channels. L2CAP is the transport layer that most Bluetooth Classic protocols run on. Each service listens on a specific PSM.

This probe iterates through the PSM range and attempts a connection to each. Open PSMs indicate listening services --- some may not be advertised in SDP (intentionally hidden or undocumented). This is analogous to a TCP port scan in network security.

```bash
blue-tap recon 4C:4F:EE:17:3A:89 l2cap
blue-tap recon 4C:4F:EE:17:3A:89 l2cap --start-psm 1 --end-psm 4097 --timeout 500
```

!!! example "L2CAP scan output"
    ```
    $ sudo blue-tap recon 4C:4F:EE:17:3A:89 l2cap --timeout 500
    Session: blue-tap_20260416_144300

    ── L2CAP PSM Scan (4C:4F:EE:17:3A:89) ─────────────────────────────────────────

    PSM 1    (SDP)          OPEN
    PSM 3    (RFCOMM)       OPEN
    PSM 15   (BNEP)         OPEN
    PSM 17   (AVCTP)        OPEN
    PSM 19   (AVDTP)        OPEN
    PSM 23   (AVCTP Brws)   OPEN
    PSM 25   (AVDTP)        OPEN
    PSM 4113 (unknown)      OPEN    ← not in SDP

    Scanned 2049 PSMs: 8 open, 2041 closed/rejected
    ```

!!! tip "Hidden Services"
    PSMs that are open but not advertised in SDP are worth investigating --- they may be debug interfaces, OTA update channels, or vendor-specific services that the manufacturer did not intend to expose. PSM 4113 in the example above would warrant further investigation.

### RFCOMM Scan

Probes RFCOMM channel numbers to find open serial-port-style services. RFCOMM provides a serial port emulation layer over L2CAP. Many legacy Bluetooth services (AT commands, OBEX, SPP) use RFCOMM channels.

This probe is especially useful when SDP is restricted or incomplete --- some devices hide services from SDP but still accept connections on RFCOMM channels.

```bash
blue-tap recon 4C:4F:EE:17:3A:89 rfcomm
blue-tap recon 4C:4F:EE:17:3A:89 rfcomm --start-channel 1 --end-channel 30 --timeout 2000
```

!!! example "RFCOMM scan output"
    ```
    $ sudo blue-tap recon 4C:4F:EE:17:3A:89 rfcomm
    Session: blue-tap_20260416_144420

    ── RFCOMM Channel Scan (4C:4F:EE:17:3A:89) ────────────────────────────────────

    Channel 1   SPP (Serial Port Profile)          OPEN
    Channel 2   Hands-Free                         OPEN
    Channel 12  OBEX Object Push                   OPEN
    Channel 15  Phonebook Access                   OPEN
    Channel 16  Message Access                     OPEN
    Channel 22  (unknown)                          OPEN    ← not in SDP

    Scanned 30 channels: 6 open, 24 closed
    ```

!!! tip "RFCOMM vs SDP"
    Compare RFCOMM scan results with SDP output. Channels that appear in RFCOMM but not in SDP may be undocumented services. Channel 22 in the example above --- not advertised in SDP --- could be a vendor debug console, diagnostic port, or firmware update interface.

### Fingerprint

Identifies the target device by combining multiple signals: device name patterns, OUI lookup, SDP profiles, BLE advertisement data, and LMP feature pages. Produces a device identification report with manufacturer, model, and firmware version when available.

Fingerprinting helps you determine exactly what you are testing. An IVI head unit running Android Auto has a different Bluetooth stack (and different vulnerabilities) than one running QNX or Linux.

```bash
blue-tap recon 4C:4F:EE:17:3A:89 fingerprint
```

!!! example "Fingerprint output"
    ```
    $ sudo blue-tap recon 4C:4F:EE:17:3A:89 fingerprint
    Session: blue-tap_20260416_144530

    ── Device Fingerprint (4C:4F:EE:17:3A:89) ─────────────────────────────────────

    Manufacturer:    Harman International
    Model:           Harman Kardon IVI (MY-CAR-AUDIO)
    Device Type:     In-Vehicle Infotainment (IVI)
    OS Inference:    Linux-based (BlueZ stack)
    BT Version:      5.0 (from LMP features)
    LMP Subversion:  0x220e
    HCI Revision:    0x000b

    LMP Features:
      ├── Secure Simple Pairing:     Supported
      ├── LE Supported (Controller): Supported
      ├── Extended Inquiry Response:  Supported
      ├── Encryption Pause/Resume:   Not Supported
      └── Secure Connections:        Not Supported ← weak

    Assessment Notes:
      [!] BT 5.0 without Secure Connections --- vulnerable to KNOB, BIAS
      [!] No encryption pause/resume --- may accept enc downgrade
      [i] Linux/BlueZ stack --- check CVE-2017-0785, CVE-2022-42896
    ```

!!! info "Why Fingerprinting Matters"
    The fingerprint output directly informs your vulnerability assessment strategy. In the example above, the target lacks Secure Connections support, which means KNOB (CVE-2019-9506) and BIAS (CVE-2020-10135) are likely viable. The "Linux/BlueZ stack" inference tells you to prioritize BlueZ-specific CVEs. Without fingerprinting, you would run all 21 CVE checks blindly; with it, you can focus on the most likely hits.

### HCI Capture

Captures raw HCI packets to/from the target for offline analysis. Output is in btsnoop format, which can be opened in Wireshark.

HCI capture is useful for understanding the protocol exchange in detail --- troubleshooting failed probes, analyzing authentication handshakes, or building evidence for a report.

```bash
blue-tap recon 4C:4F:EE:17:3A:89 capture -d 30 -o capture.btsnoop
```

!!! tip "When to Capture"
    Run a capture during other operations to record the full protocol exchange. For example, capture during `vulnscan` to have packet-level evidence of vulnerability detection, or during `exploit` to document the attack for your report.

### Sniffer

Passive Bluetooth sniffing. Captures over-the-air Bluetooth traffic without establishing a connection. Requires compatible hardware for some modes (particularly LMP sniffing).

```bash
blue-tap recon 4C:4F:EE:17:3A:89 sniff -m ble -d 60 -o sniff.pcap
```

**Sniff modes:**

| Mode | Description | Hardware |
|------|-------------|----------|
| `ble` | BLE advertisement sniffing | Any BLE adapter |
| `ble_connection` | BLE connection event capture | Any BLE adapter |
| `ble_pairing` | BLE pairing exchange capture | Any BLE adapter |
| `lmp` | LMP (Link Manager Protocol) sniffing | DarkFirmware dongle |
| `combined` | All modes simultaneously | DarkFirmware dongle |

!!! warning "LMP Sniffing"
    The `lmp` and `combined` modes require a DarkFirmware-patched RTL8761B dongle. Standard HCI adapters cannot capture LMP frames because they are handled below the HCI layer by the controller firmware. See the DarkFirmware documentation for setup instructions.

---

## Internal Modules

These modules are not directly exposed via CLI commands but are used by automated workflows (`auto`, playbooks) and other modules.

| Module ID | Purpose |
|-----------|---------|
| `reconnaissance.capability_detector` | Detects target capabilities from combined recon data |
| `reconnaissance.correlation` | Correlates findings across multiple recon probes |
| `reconnaissance.capture_analysis` | Analyzes captured packets for protocol insights |
| `reconnaissance.prerequisites` | Checks whether recon prerequisites are met for a target |
| `reconnaissance.spec_interpretation` | Interprets BT spec compliance from observed behavior |
| `reconnaissance.campaign` | Orchestrates a full recon campaign across all probes |

!!! info "Recon Campaign"
    The `auto` command and `recon-all` playbook use `reconnaissance.campaign` to run all applicable probes in sequence. The campaign module determines which probes to run based on the target type (Classic, BLE, or dual-mode) and skips probes that do not apply.

---

## Outcomes

All reconnaissance modules use the same outcome taxonomy:

| Outcome | Meaning |
|---------|---------|
| `observed` | Data was successfully collected |
| `merged` | Results merged from multiple sources |
| `correlated` | Cross-probe correlation produced enriched findings |
| `partial` | Some data collected, but the probe was incomplete (e.g., target went out of range, timeout on some channels) |
| `not_applicable` | Probe does not apply to this target type (e.g., GATT against a Classic-only device) |

!!! note "Partial Results"
    A `partial` outcome does not mean the data is useless. If an L2CAP scan times out after scanning 1000 of 2049 PSMs, you still have results for the first 1000. The outcome tells you the scan was incomplete so you can re-run with a longer timeout or narrower range if needed.

---

## Recommended Recon Workflow

For a thorough assessment of a Classic target:

```bash
# 1. Service enumeration --- most informative, always run first
sudo blue-tap recon 4C:4F:EE:17:3A:89 sdp

# 2. Channel scans --- find hidden services not in SDP
sudo blue-tap recon 4C:4F:EE:17:3A:89 l2cap
sudo blue-tap recon 4C:4F:EE:17:3A:89 rfcomm

# 3. Device identification --- determine stack, version, capabilities
sudo blue-tap recon 4C:4F:EE:17:3A:89 fingerprint
```

For a BLE target:

```bash
# 1. GATT enumeration --- the BLE equivalent of SDP
sudo blue-tap recon DE:AD:BE:EF:CA:FE gatt

# 2. Fingerprint --- determine device type and capabilities
sudo blue-tap recon DE:AD:BE:EF:CA:FE fingerprint
```

---

## What's Next?

With recon data collected, you have a clear picture of the target's attack surface. The next step is vulnerability assessment:

- [Vulnerability Assessment](vulnerability-assessment.md) --- scan for known CVEs and posture weaknesses based on what recon revealed
- [Exploitation](exploitation.md) --- if you already know what to attack, go directly to exploitation
- [CLI Reference](cli-reference.md) --- full command reference
