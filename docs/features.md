# Features

> **[Back to README](../README.md)**

### 1. Discovery and Scanning

Passive and active discovery of Bluetooth Classic and BLE devices in range with full device class decoding and manufacturer identification.

| Command | Description |
|---------|-------------|
| `blue-tap scan classic` | Bluetooth Classic inquiry scan — discovers BR/EDR devices, shows name, MAC, device class |
| `blue-tap scan ble` | BLE scan using bleak — discovers LE advertisers, shows name, MAC, services, manufacturer data |
| `blue-tap scan ble --passive` | Passive BLE scan (no SCAN_REQ sent) — stealthier, only collects advertisement data |
| `blue-tap scan all` | Combined Classic + BLE scan with automatic dual-mode device merging |

**Key capabilities:**
- Full device class decoding: Computer (Desktop/Laptop/Tablet), Phone (Cellular/Smartphone), Audio/Video (Car Audio, Headset, Headphones, Speaker), Peripheral (Remote/Gamepad), Wearable (Wristwatch/Glasses)
- BLE manufacturer identification (30+ vendors: Apple, Samsung, Tesla, Bose, Harman, Continental, etc.)
- RSSI signal strength with distance estimation (log-distance path loss model)
- Name resolution with retry logic for flaky Classic BT connections
- JSON output (`-o results.json`) for scripted pipelines
- Configurable scan duration (`-d 30` for 30 seconds)
- Adapter selection (`-i hci1`) for multi-adapter setups
- All scan results logged to session for report generation

---

### 2. Reconnaissance

Deep service enumeration, device fingerprinting, and radio-level capture. All recon commands support session logging and JSON output.

| Command | Description |
|---------|-------------|
| `blue-tap recon sdp <MAC>` | Browse all SDP service records — profiles, channels, UUIDs, provider strings. Retries on transient failures. |
| `blue-tap recon fingerprint <MAC>` | Device fingerprinting — BT version, LMP features, chipset, IVI confidence scoring, normalized attack surface mapping, vulnerability hints (KNOB, BIAS, BrakTooth, SweynTooth, BlueBorne) |
| `blue-tap recon rfcomm-scan <MAC>` | Scan RFCOMM channels 1-30 with retry logic (`--retries N`), consecutive-unreachable abort threshold, AT/OBEX/raw response classification |
| `blue-tap recon l2cap-scan <MAC>` | Scan well-known L2CAP PSMs; `--dynamic` adds parallel scanning of dynamic range with configurable workers (`--workers 10`) |
| `blue-tap recon gatt <MAC>` | BLE GATT enumeration with connection retry, security posture inference (open/paired/signed/encrypted), automotive service detection, value decoding (Battery, PnP ID, Appearance, Tx Power, Connection Params) |
| `blue-tap recon ssp <MAC>` | Check if device supports Secure Simple Pairing |
| `blue-tap recon pairing-mode <MAC>` | Detect pairing mode (Legacy PIN vs SSP) and IO capabilities |
| `blue-tap recon capture-start` | Start HCI traffic capture via btmon (stale PID detection, atomic state file) |
| `blue-tap recon capture-stop` | Stop btmon capture |

**Reconnaissance (requires specialized hardware):**

| Command | Hardware | Description |
|---------|----------|-------------|
| `blue-tap recon nrf-scan` | nRF52840 dongle | BLE advertisement scanning with raw PDU access |
| `blue-tap recon nrf-sniff` | nRF52840 dongle | Sniff BLE pairing exchanges (capture STK/LTK negotiation) |
| `blue-tap recon usrp-scan` | USRP B210 | Scan for BR/EDR piconets at baseband level |
| `blue-tap recon usrp-follow` | USRP B210 | Follow and capture BR/EDR piconet traffic |
| `blue-tap recon usrp-capture` | USRP B210 | Raw IQ capture for offline analysis |
| `blue-tap recon crack-key` | — | Crack BLE pairing key from captured pcap using Crackle |
| `blue-tap recon extract-link-key` | — | Extract BR/EDR link key from captured pairing exchange |
| `blue-tap recon inject-link-key` | — | Inject recovered link key into BlueZ for reconnection |

---

### 3. Vulnerability Assessment

Vulnerability scanner with heuristic and OTA behavioral checks for known CVEs, protocol weaknesses, and configuration issues. Findings now use the scanner status model `confirmed`, `inconclusive`, `pairing_required`, and `not_applicable`, with some older heuristic checks still returning legacy `potential` / `unverified` statuses. Output and JSON export include structured evidence, confidence, remediation, per-check metadata, and execution logs for both CVE and non-CVE scanner sections.

```
blue-tap vulnscan <MAC>                                # Full vulnerability scan
blue-tap vulnscan <MAC> --phone <PHONE_MAC>            # Add paired-phone context for BIAS auto-reconnect probe
blue-tap vulnscan <MAC> -o findings.json               # Export structured vulnscan JSON
```

`vulnscan` runs the full scanner in one pass. Some checks are invasive and may send pairing attempts, exercise raw ACL paths, or temporarily alter local adapter state. The BIAS auto-reconnect probe uses `--phone` when you want to test reconnect behavior against the target's normally paired phone identity; without it, the rest of the scan still runs and that specific BIAS path is recorded as unmet.

**Coverage reference:** See [Vulnerability Scanner CVE Matrix](vulnscan-cve-matrix.md) for the full list of CVEs actually checked by `vulnscan` and their module ownership.

**High-level checks performed:**

| Check Family | Examples |
|-------------|----------|
| Heuristic CVE checks | KNOB, BLURtooth, BLUFFS, PerfektBlue, BIAS, BlueBorne, BrakTooth |
| Behavioral CVE checks | SDP, BNEP, AVRCP, HID/HOGP, L2CAP, SMP, Airoha RACE, EATT |
| Pairing-gated checks | LE SC reflected-key, BLE legacy pairing bypass, BR/EDR pairing method probes |
| Non-CVE exposure and posture checks | Service exposure, writable GATT, hidden RFCOMM, encryption enforcement, diagnostics exposure, pairing posture, PIN lockout, LMP/device-class posture |

---

### 4. Connection Hijacking and BIAS

Full IVI takeover by impersonating the target's phone. Includes connection retry logic, per-phase rollback on failure, and adapter state verification before each phase transition.

```
blue-tap hijack <IVI_MAC> <PHONE_MAC>
blue-tap hijack <IVI_MAC> <PHONE_MAC> --phone-name "John's iPhone"
blue-tap hijack <IVI_MAC> <PHONE_MAC> --bias          # Use BIAS CVE-2020-10135
blue-tap hijack <IVI_MAC> <PHONE_MAC> --recon-only     # Recon phase only
blue-tap hijack <IVI_MAC> <PHONE_MAC> --skip-audio     # Skip HFP setup
```

**Attack phases:**
1. **Recon** — Fingerprint IVI, enumerate SDP services, identify PBAP/MAP/HFP/AVRCP channels
2. **Impersonate** — Spoof MAC address, adapter name, and device class to match the phone. Fails fast if identity clone is incomplete (MAC spoofed but name/class failed — IVI would reject)
3. **Phase Gate** — Verifies adapter MAC matches target phone before proceeding. Warns if impersonation may not have taken effect
4. **Connect** — Connect to IVI via bluetoothctl with automatic retry on timeout. Catches `TimeoutExpired` and cleans up partial pairing state
5. **PBAP/MAP Extract** — Download phonebook, call history, and SMS/MMS messages
6. **Audio Setup** — Establish HFP Service Level Connection for call interception


**BIAS mode (`--bias`):** When the IVI validates link keys and rejects simple MAC spoofing, the BIAS attack (CVE-2020-10135) exploits a role-switch during reconnection to bypass authentication entirely.

---

### 5. KNOB Attack (CVE-2019-9506)

Negotiate minimum encryption key entropy, then brute force the reduced key space. Brute-force performs actual XOR decryption against captured ACL data with L2CAP header validation — not a demonstration, a real key recovery attack.

```bash
blue-tap knob probe <MAC>                              # Check KNOB vulnerability
blue-tap knob attack <MAC>                             # Full KNOB chain: negotiate + brute force
blue-tap knob attack <MAC> --key-size 1                # Force 1-byte key (256 candidates)
```

**Attack phases:**
1. **Probe** — Check BT version (KNOB affects 2.1-5.0 pre-patch), read current encryption key size if connected, note firmware patch uncertainty
2. **Negotiate** — Set minimum encryption key size via DarkFirmware LMP injection (RTL8761B) or btmgmt fallback, verify setting took effect via ConnectionInspector RAM read, restore adapter defaults after test
3. **Brute force** — Capture encrypted ACL traffic from active connection (60s windows, up to 5 minutes with user-prompted extensions), XOR-decrypt each candidate, validate against L2CAP header structure (length field + CID range). Rich progress bar shows enumeration progress.

Note: Full LMP-level manipulation requires DarkFirmware on RTL8761B (TP-Link UB500). The btmgmt fallback only controls local adapter preferences. HCI response parsing uses multiple regex patterns for cross-chipset compatibility.

---

### 6. SSP Downgrade Attack

Force a device from Secure Simple Pairing to legacy PIN mode, then brute force the PIN. Includes lockout detection (3 consecutive timeouts → abort), PIN range validation, and process cleanup to prevent leaked bluetoothctl processes.

```bash
blue-tap ssp-downgrade probe <MAC>                     # Check if target is vulnerable
blue-tap ssp-downgrade attack <MAC>                    # Downgrade + auto brute force (0000-9999)
blue-tap ssp-downgrade attack <MAC> --pin-start 0 --pin-end 9999  # Full PIN range
blue-tap ssp-downgrade attack <MAC> --delay 1.0        # Slower to avoid lockout
```

**Attack phases:**
1. Set local adapter IO capability to NoInputNoOutput
2. Disable SSP on local adapter (btmgmt with hciconfig fallback)
3. Remove existing pairing with target
4. Initiate pairing — target falls back to legacy PIN mode
5. Brute force PIN with progress logging every 100 attempts, lockout detection (3 consecutive timeouts), and `lockout_detected` flag in results

---

### 6b. BLUFFS Attack (CVE-2023-24023)

Session key derivation downgrade attack. Forces both endpoints to derive a weak, reusable session key by manipulating BR/EDR encryption setup at the LMP layer. Requires DarkFirmware on RTL8761B adapter for LMP injection.

```bash
blue-tap bluffs <MAC> -v probe                     # Check if target is vulnerable [safe]
blue-tap bluffs <MAC> -v key-downgrade             # LSC Central: force minimum key size (A1)
blue-tap bluffs <MAC> -v sc-downgrade              # SC Central: reject SC, force LSC (A3)
blue-tap bluffs <MAC> -v all                       # Run probe → sc-downgrade → key-downgrade
blue-tap bluffs <MAC> -v all --phone BB:CC:DD:EE   # With phone identity cloning
```

**Attack variants:**

| Variant | Mode | Role | Description |
|---------|------|------|-------------|
| A1 | LSC | Central | Force minimum encryption key size via LMP |
| A3 | SC → LSC | Central | Reject Secure Connections, then apply A1 |
| probe | — | — | Check SC downgrade vulnerability (non-destructive) |

**Reference:** Antonioli, "BLUFFS: Bluetooth Forward and Future Secrecy Attacks and Defenses", ACM CCS 2023

---

### 6c. Encryption Downgrade

Alternative encryption downgrade paths beyond KNOB that exploit different link manager code paths. Requires DarkFirmware on RTL8761B adapter.

```bash
blue-tap encryption-downgrade <MAC> -m no-encryption             # Disable encryption entirely
blue-tap encryption-downgrade <MAC> -m force-renegotiation       # Stop/start to weaken params
blue-tap encryption-downgrade <MAC> -m reject-secure-connections # Force Legacy SC (weaker keys)
blue-tap encryption-downgrade <MAC> -m all                       # Run all methods
```

**Methods:**

| Method | LMP PDU | Effect |
|--------|---------|--------|
| no-encryption | `LMP_ENCRYPTION_MODE_REQ(mode=0)` | Requests disabling encryption |
| force-renegotiation | Alternating `LMP_STOP_ENCRYPTION`/`LMP_START_ENCRYPTION` | Forces weaker re-negotiation |
| reject-secure-connections | Reject SC PDUs during re-keying | Forces Legacy Secure Connections |

Requires an active ACL connection to the target. Each method result shows VULNERABLE/Partially Accepted/Rejected status.

---

### 6d. CTKD — Cross-Transport Key Derivation (CVE-2020-15802)

Tests whether a dual-mode (BR/EDR + BLE) target shares key material across transports. A successful Classic Bluetooth attack (e.g., KNOB) can compromise BLE security if the target derives BLE keys from the weakened Classic key — and vice versa. Requires DarkFirmware for connection table inspection.

```bash
sudo blue-tap ctkd <MAC>                                # Probe for CTKD vulnerability
sudo blue-tap ctkd <MAC> -m monitor                     # Continuous key material monitoring
sudo blue-tap ctkd <MAC> -m monitor --interval 5        # Poll every 5 seconds
```

**Probe flow:**
1. Verify DarkFirmware is loaded and hooks are active
2. Snapshot key material across all connection slots (before)
3. Execute KNOB attack on Classic transport to weaken key
4. Snapshot key material again (after)
5. Compare: if BLE slot keys changed after Classic attack → CTKD vulnerable
6. Check for shared key material across BLE and Classic slots

**Reference:** "BLURtooth: Exploiting Cross-Transport Key Derivation in Bluetooth Classic and Bluetooth Low Energy", Bluetooth SIG Advisory 2020

---

### 7. Data Extraction (PBAP / MAP / AT / OPP)

#### PBAP — Phone Book Access Profile

Download phonebook contacts and call history from the IVI's synced phone data.

```
blue-tap pbap pull <MAC>                     # Pull main phonebook
blue-tap pbap pull <MAC> -p telecom/ich.vcf  # Incoming call history
blue-tap pbap pull <MAC> -p telecom/och.vcf  # Outgoing call history
blue-tap pbap pull <MAC> -p telecom/mch.vcf  # Missed call history
blue-tap pbap pull <MAC> -p telecom/cch.vcf  # Combined call history
blue-tap pbap dump <MAC>                     # Dump ALL: contacts + all call logs + favorites + SIM
blue-tap pbap dump <MAC> -o ./pbap_data/     # Custom output directory
```

**What's extracted:**
- vCard 2.1/3.0 contacts (name, phone numbers, email, address, organization)
- Call history with timestamps, durations, and phone numbers
- SIM phonebook entries (if synced)
- Speed dial / favorites

#### MAP — Message Access Profile

Download SMS and MMS messages stored on the IVI.

```
blue-tap map list <MAC>                    # List messages in inbox
blue-tap map list <MAC> --folder sent      # List sent messages
blue-tap map dump <MAC>                    # Dump all messages from all folders
blue-tap map dump <MAC> -o ./messages/     # Custom output directory
```

**Message folders:** inbox, sent, draft, deleted, outbox

#### AT Command Extraction

Direct data extraction via AT commands over RFCOMM (bluesnarfer-style).

```
blue-tap at connect <MAC>                  # Interactive AT command session
blue-tap at dump <MAC>                     # Dump all: phonebook, SMS, device info
blue-tap at snarf <MAC>                    # External bluesnarfer binary
```

**Data available via AT:**
- `AT+CPBR` — Phonebook entries
- `AT+CMGL` — SMS messages
- `AT+CGSN` — IMEI
- `AT+CIMI` — IMSI
- `AT+CBC` — Battery status
- `AT+CSQ` — Signal strength

#### OPP — Object Push Profile

Push files to the IVI via OBEX Object Push.

```
blue-tap opp push <MAC> <file>               # Push any file to device
blue-tap opp vcard <MAC> -n "Test" -p "+1234" # Push a crafted vCard
```

---

### 8. Audio Interception (HFP / A2DP)

#### HFP — Hands-Free Profile

Call audio capture and injection over SCO (Synchronous Connection-Oriented) links. Includes connection retry with backoff, automatic codec negotiation (CVSD 8kHz / mSBC 16kHz wideband), and tolerant AT response parsing. All operations logged to session.

```
blue-tap hfp connect <MAC>                # Establish Service Level Connection (SLC)
blue-tap hfp capture <MAC> -o call.wav    # Capture call audio to WAV
blue-tap hfp inject <MAC> -f audio.wav    # Inject audio into active call
blue-tap hfp at <MAC> -c "AT+COPS?"      # Send raw AT command
blue-tap hfp dtmf <MAC> -t "1234#"       # Send DTMF tones
blue-tap hfp hold <MAC> -a 2             # Call hold/swap
blue-tap hfp redial <MAC>                 # Redial last number
blue-tap hfp voice <MAC> --activate       # Trigger voice assistant
```

**Key capabilities:**
- RFCOMM and SCO connections retry once with 2s backoff on transient failure
- SLC handshake parsing is resilient to malformed AG responses (graceful degradation instead of crash)
- Codec negotiation detects CVSD vs mSBC — audio capture automatically uses the correct sample rate
- Silent call with proper timing (1.5s delay between dial and mute to avoid race condition)
- Empty audio capture detected early — returns failure instead of writing empty WAV file

#### A2DP — Advanced Audio Distribution

Media stream capture, microphone eavesdropping, and audio injection via PulseAudio/PipeWire. Profile switching retries on failure. Sample rate auto-detected from PulseAudio source info (not hardcoded). Loopback modules tracked for reliable cleanup.

```
blue-tap audio devices                     # List Bluetooth audio sources/sinks
blue-tap audio profile <MAC> hfp           # Switch to HFP profile (mic access)
blue-tap audio profile <MAC> a2dp          # Switch to A2DP profile (media)
blue-tap audio record-mic <MAC>            # Record from car's Bluetooth microphone
blue-tap audio live <MAC>                  # Live eavesdrop: car mic → laptop speakers
blue-tap audio capture <MAC>               # Capture A2DP media stream to WAV
blue-tap audio play <MAC> file.mp3         # Play file through car speakers
blue-tap audio loopback <MAC>              # Route laptop mic → car speakers
blue-tap audio loopback-stop               # Stop loopback (cleans up PA module)
blue-tap audio diagnose <MAC>              # Diagnose Bluetooth audio issues
blue-tap audio list                        # List captured audio files
blue-tap audio playback <file>             # Play captured file locally
blue-tap audio review                      # Interactive audio file review
```

---

### 9. AVRCP Media Control

Audio/Video Remote Control Profile attacks via D-Bus (BlueZ MediaPlayer1 interface). Includes connection retry with 2s backoff, proper D-Bus resource cleanup, and all operations logged to session for reporting.

```
blue-tap avrcp play <MAC>                  # Send play command
blue-tap avrcp pause <MAC>                 # Send pause
blue-tap avrcp stop <MAC>                  # Send stop
blue-tap avrcp next <MAC>                  # Skip to next track
blue-tap avrcp prev <MAC>                  # Skip to previous track
blue-tap avrcp volume <MAC> -l 127         # Set volume to max
blue-tap avrcp volume-ramp <MAC> --start 0 --end 127 --step 5
                                           # Gradual volume escalation (works both up AND down)
blue-tap avrcp skip-flood <MAC> -n 100     # Rapid track skip injection (min 10ms interval)
blue-tap avrcp metadata <MAC>              # Show current track metadata + active player app
blue-tap avrcp monitor <MAC>               # Monitor track changes in real-time
```

**Capabilities:** Playback control, absolute volume set (0-127), bidirectional volume ramp, fast-forward/rewind, repeat/shuffle mode, metadata surveillance (title, artist, album, active app name), track change monitoring via D-Bus signal subscription, skip flood DoS.

---

### 10. Protocol Fuzzing

Response-guided, state-aware fuzzing engine designed for discovering 0-day vulnerabilities in automotive IVI Bluetooth stacks. Works purely over-the-air with standard hardware — no firmware access, no special dongles, no target instrumentation required.

The engine combines techniques from published research (AFLNet, BrakTooth, SNIPUZZ, Defensics) with novel approaches (entropy-based leak detection, timing-based coverage proxy, structural self-consistency validation) to detect bugs that traditional blind fuzzers miss.

#### Architecture

```
                        ┌─────────────────────────────────┐
                        │        Campaign Engine           │
                        │   (protocol rotation, transport) │
                        └────────┬──────────┬──────────────┘
                                 │          │
              ┌──────────────────┤          ├──────────────────────┐
              ▼                  ▼          ▼                      ▼
    ┌─────────────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────────┐
    │  State Inference │  │  Mutation  │  │   Response   │  │    Health    │
    │   (AFLNet IPSM)  │  │  Weights   │  │   Analyzer   │  │   Monitor   │
    │  state_inference │  │  field_wt  │  │  response_   │  │  health_    │
    │       .py        │  │  tracker.py│  │  analyzer.py │  │  monitor.py │
    └─────────────────┘  └────────────┘  └──────────────┘  └──────────────┘
      Protocol state       Adaptive        3-layer anomaly    Watchdog reboot
      graph + scoring      field-level     detection: struct  detection, zombie
      + seed selection     mutation        + timing + entropy  state, degradation
```

#### Campaign Mode

```bash
blue-tap fuzz campaign <MAC>                              # Fuzz all protocols
blue-tap fuzz campaign <MAC> -p sdp -p rfcomm             # Specific protocols
blue-tap fuzz campaign <MAC> --strategy targeted           # CVE-targeted mutations
blue-tap fuzz campaign <MAC> --strategy state-machine      # Protocol state violations
blue-tap fuzz campaign <MAC> --strategy coverage           # Response-guided coverage
blue-tap fuzz campaign <MAC> --duration 2h --capture       # 2 hours + pcap capture
blue-tap fuzz campaign <MAC> -n 50000 --delay 0.1          # 50K iterations, fast
blue-tap fuzz campaign --resume                            # Resume previous campaign
```

#### Supported Protocols (14)

| Protocol | Transport | Attack Surface |
|----------|-----------|----------------|
| `sdp` | L2CAP PSM 1 | Service records, continuation state, data elements, PDU parsing |
| `rfcomm` | L2CAP PSM 3 | Frame types, PN/MSC/RPN negotiation, credit flow, FCS |
| `l2cap` | L2CAP PSM 1 | Signaling commands, config options, CID manipulation, echo |
| `obex-pbap` | RFCOMM ch 15 | PBAP headers, app parameters, session lifecycle |
| `obex-map` | RFCOMM ch 16 | MAP headers, message listing, folder traversal |
| `obex-opp` | RFCOMM ch 9 | Object Push headers, large payloads |
| `at-hfp` | RFCOMM ch 10 | HFP SLC handshake, codec negotiation, AT injection |
| `at-phonebook` | RFCOMM ch 1 | AT+CPBR phonebook access |
| `at-sms` | RFCOMM ch 1 | AT+CMGL/CMGR SMS commands |
| `ble-att` | BLE CID 4 | ATT handles, writes, MTU, prepare writes, signed writes |
| `ble-smp` | BLE CID 6 | Pairing, key sizes, ECDH curve points, sequencing |
| `bnep` | L2CAP PSM 15 | Setup connection, ethernet frames, filter lists |
| `lmp` | HCI VSC 0xFE22 | LMP opcodes, key negotiation, feature response, role switch, encryption setup (requires DarkFirmware) |
| `raw-acl` | HCI raw ACL | Below-stack L2CAP injection bypassing BlueZ, malformed frame testing (requires DarkFirmware) |

#### Fuzzing Strategies

| Strategy | Approach | Best For |
|----------|----------|----------|
| `random` | 70% template + 30% corpus byte-level mutation with adaptive field weighting | General exploration, first-pass fuzzing |
| `coverage` | Response-diversity tracking with energy scheduling — inputs producing novel responses get more mutations | Deep exploration, maximizing code path coverage |
| `state-machine` | Protocol state violation attacks — skip steps, go backwards, repeat states | OBEX, HFP, SMP, ATT state machine bugs |
| `targeted` | CVE reproduction + variation — exact reproduction patterns then field mutations | Testing for known vulnerability classes |

### Fuzzing Intelligence

Blue-Tap implements six layers of intelligence that run automatically during every campaign:

**1. Response-Based State Inference** (adapted from [AFLNet](https://mboehme.github.io/paper/ICST20.AFLNet.pdf))

Extracts protocol state IDs from every response (SDP PDU type + error code, ATT opcode + error, L2CAP command + result, RFCOMM frame type, SMP code, OBEX response code, BNEP type, AT result). Builds a directed state graph incrementally. Uses AFLNet's scoring formula to prioritize under-explored states:

```
score = 1000 * 2^(-log10(log10(fuzz_count+1) * selected_times + 1)) * 2^(log(paths_discovered+1))
```

States that produce new transitions get more fuzzing iterations. States that have been heavily explored get fewer.

**2. Anomaly-Guided Field Mutation Weights** (inspired by [BrakTooth](https://asset-group.github.io/papers/BrakTooth.pdf))

Instead of mutating random bytes, the engine knows which fields exist in each protocol packet (SDP `param_length`, ATT `handle`, L2CAP `CID`, RFCOMM `length`, etc.). It tracks which fields produce anomalies and crashes, then increases their mutation probability:

```
weight = 1.0 + (anomaly_ratio * 5.0) + (crash_ratio * 20.0)
```

Fields that cause crashes get 20x the base mutation weight. The fuzzer converges on the fields that matter for each specific target.

**3. Structural Response Validation** (novel — no prior BT fuzzer does this)

Validates every response against protocol-level self-consistency rules that ALL Bluetooth stacks must follow:

- SDP: `ParameterLength` must match actual payload bytes
- ATT: Error codes must be in valid range (0x01-0x14 or 0x80-0xFF)
- L2CAP: Signaling `Length` field must match payload
- RFCOMM: FCS checksum must be correct (CRC-8 computation)
- SMP: Pairing Request/Response must be exactly 7 bytes
- OBEX: Packet length header must match actual size
- AT: Responses must be valid ASCII terminated with `\r\n`

Any violation = the target's parser is confused = potential vulnerability.

**4. Timing-Based Coverage Proxy** (novel — identified as open research gap)

Before fuzzing starts, the engine learns each target's normal response latency per protocol and per opcode. During fuzzing, it detects:

- **Latency spikes**: Response > p99 baseline = different code path reached
- **Latency drops**: Response significantly faster = parser rejected input early
- **Timing clusters**: Groups of similar latencies; new cluster = new code path
- **Consecutive spikes**: 3+ in a row = target may be degrading

**5. Entropy-Based Leak Detection** (novel application to Bluetooth)

Detects information leaks (heap/stack disclosure) without firmware access using:

- **Shannon entropy**: Structured protocol data has entropy 2-5 bits/byte. Leaked heap data has entropy >6.5 bits/byte
- **Renyi entropy**: More sensitive to dominant byte values for partial leaks
- **Sliding window analysis**: Detects localized high-entropy regions in otherwise normal responses
- **Heap pattern scanning**: Detects 0xDEADBEEF, 0xBAADF00D, repeated 4-byte patterns, pointer-like values
- **Response echo detection**: Request bytes appearing in unexpected response positions = buffer reuse

**6. Watchdog Reboot Detection** (adapted from [Defensics](https://www.blackduck.com/blog/break-car-kits-with-bluetooth-fuzz-testing.html))

IVI Bluetooth stacks have watchdog timers that restart the daemon after a crash. This reboot is invisible at the protocol level. The health monitor detects it by:

- Tracking consecutive failures (3+ = trigger health check)
- Probing target with l2ping at exponential backoff (1s, 2s, 4s)
- Detecting the reboot signature: target returns after silence with fresh state
- Tracking reboot count as the highest-confidence crash signal
- Saving the last 10 fuzz payloads before each reboot as crash candidates with confidence scores
- Detecting zombie states: l2ping succeeds but protocol requests fail = upper stack crashed
- Detecting degradation: gradually increasing latency = memory leak on target

#### Live Dashboard

The campaign runs with a real-time Rich terminal dashboard showing:

| Metric | Description |
|--------|-------------|
| Runtime / progress | Elapsed time with progress bar (% of duration or iterations) |
| Test cases / rate | Total iterations and cases per second |
| Crashes found | Count with severity breakdown (CRITICAL, HIGH, MEDIUM, LOW) |
| Protocol breakdown | Per-protocol: test cases sent and crashes detected |
| Last crash | Timestamp, protocol, type, payload hex preview, mutation log |
| **Target health** | ALIVE / DEGRADED / UNREACHABLE / REBOOTED / ZOMBIE (color-coded) |
| **States discovered** | Per-protocol state and transition counts |
| **Timing clusters** | Number of distinct response latency groups per protocol |
| **Anomaly count** | Breakdown by type: structural, timing, leak, behavioral |
| **Hot fields** | Top mutation fields ranked by anomaly/crash weight |

**Keyboard controls:** `SPACE` pause/resume, `S` snapshot, `Q` quit.

#### Crash Management

```bash
blue-tap fuzz crashes list                             # List all crashes
blue-tap fuzz crashes list --severity CRITICAL          # Filter by severity
blue-tap fuzz crashes list --protocol sdp               # Filter by protocol
blue-tap fuzz crashes show 1                           # Full crash details + hexdump
blue-tap fuzz crashes replay 1                         # Replay to verify reproduction
blue-tap fuzz crashes replay 1 --capture               # Replay with pcap capture
blue-tap fuzz crashes export -o crashes.json           # Export for reporting
```

The crash detail view shows: severity, protocol, crash type, full payload hexdump, mutation log (which field was mutated and how), device response hexdump, reproduction status, and analyst notes.

#### Crash Minimization

Reduce crash payloads to the minimum bytes needed to trigger the bug:

```bash
blue-tap fuzz minimize 1                               # Auto-select strategy
blue-tap fuzz minimize 3 --strategy ddmin              # Delta debugging (thorough)
blue-tap fuzz minimize 5 --strategy binary              # Binary search (fast)
blue-tap fuzz minimize 2 --strategy field               # Field-level analysis
```

Three complementary strategies:
- **Binary search**: Halve payload, test, refine — fast, ~8 iterations
- **Delta debugging (ddmin)**: Incrementally remove chunks — thorough, ~50-200 tests
- **Field reducer**: Zero each byte individually, mark essential vs nullable — identifies exact crash-triggering fields

#### Protocol-Specific Fuzzers

Deep protocol fuzzers with targeted mode selection:

```bash
blue-tap fuzz sdp-deep <MAC> --mode continuation       # SDP continuation state (CVE-2017-0785)
blue-tap fuzz sdp-deep <MAC> --mode data-elements      # SDP data element malformation
blue-tap fuzz l2cap-sig <MAC> --mode config            # L2CAP config option parsing
blue-tap fuzz l2cap-sig <MAC> --mode echo              # L2CAP echo flood
blue-tap fuzz rfcomm-raw <MAC> --mode credits          # Credit-based flow control abuse
blue-tap fuzz obex <MAC> -p pbap --mode headers        # OBEX header parsing
blue-tap fuzz obex <MAC> -p map --mode path-traversal  # OBEX path traversal
blue-tap fuzz ble-att <MAC> --mode writes              # BLE ATT write overflow
blue-tap fuzz ble-att <MAC> --mode mtu                 # MTU negotiation boundary
blue-tap fuzz ble-smp <MAC> --mode curve               # Invalid ECDH curve (CVE-2018-5383)
blue-tap fuzz bnep <MAC> --mode setup                  # BNEP setup (CVE-2017-0781)
blue-tap fuzz at-deep <MAC> --category injection       # AT command injection
```

#### CVE Reproduction

Test targets against known Bluetooth vulnerability patterns:

```bash
blue-tap fuzz cve --list                              # List all supported CVE patterns
blue-tap fuzz cve <MAC>                                # Run all CVE patterns
blue-tap fuzz cve <MAC> --cve-id 2017-0785             # Android SDP info leak
blue-tap fuzz cve <MAC> --cve-id 2017-0781             # BNEP heap overflow
blue-tap fuzz cve <MAC> --cve-id 2018-5383             # Invalid ECDH curve
blue-tap fuzz cve <MAC> --cve-id 2024-24746            # NimBLE prepare write loop
```

Supported CVEs: CVE-2017-0785 (BlueBorne SDP), CVE-2017-0781 (BNEP overflow), SweynTooth family, CVE-2018-5383 (Invalid Curve), CVE-2024-24746 (NimBLE), CVE-2024-45431 (PerfektBlue L2CAP).

#### Corpus Management

```bash
blue-tap fuzz corpus generate                          # Generate seeds from protocol builders
blue-tap fuzz corpus generate -p sdp                   # Generate for specific protocol
blue-tap fuzz corpus list                              # Show stats per protocol
blue-tap fuzz corpus minimize                          # Deduplicate by content hash
```

Protocol builders generate 2,900+ seed cases across all protocols (SDP: 858, SMP: 650, BNEP: 580, ATT: 411, RFCOMM: 239, L2CAP: 166).

#### PCAP Replay

Import and replay captured Bluetooth traffic:

```bash
blue-tap fuzz replay capture.btsnoop -t <MAC> --list    # Inspect frames
blue-tap fuzz replay capture.btsnoop -t <MAC>            # Replay all frames
blue-tap fuzz replay capture.btsnoop -t <MAC> -p sdp     # Filter by protocol
blue-tap fuzz replay capture.btsnoop -t <MAC> --mutate   # Replay with mutations
```

Supports btsnoop v1 format with HCI ACL fragmentation reassembly.

#### Report Integration

Campaign results feed directly into the pentest report (`blue-tap report`):

- **Executive summary**: Crash counts, severity breakdown, SVG donut/bar charts
- **Crash details**: Full hexdump, mutation log, reproduction steps per crash
- **Fuzzing intelligence**: State coverage graph, field weight analysis with bar charts, target response baselines, health event timeline
- **Evidence package**: Exportable crash payloads (.bin), pcap captures, crash descriptions

---

### 11. Denial of Service

15 protocol-level DoS attacks targeting different layers of the Bluetooth stack.

#### Pairing-Level

```bash
blue-tap dos pair-flood <MAC>                          # Flood with pairing requests
blue-tap dos name-flood <MAC>                          # Pair with max-length names (memory exhaustion)
blue-tap dos rate-test <MAC>                           # Detect rate limiting on pairing
blue-tap dos pin-brute <MAC>                           # Brute-force legacy PIN pairing
blue-tap dos l2ping-flood <MAC>                        # L2CAP echo request flood (requires root)
```

#### L2CAP Transport

```bash
blue-tap dos l2cap-storm <MAC>                         # Connection storm (rapid connect/disconnect cycling)
blue-tap dos l2cap-cid-exhaust <MAC>                   # CID exhaustion (open and hold parallel connections)
blue-tap dos l2cap-data-flood <MAC>                    # Data flood (large malformed SDP requests at max rate)
```

#### Protocol-Specific

```bash
blue-tap dos sdp-continuation <MAC>                    # SDP continuation state exhaustion (CVE-2017-0785 related)
blue-tap dos sdp-des-bomb <MAC>                        # SDP nested DES bomb (recursive parsing overload)
blue-tap dos rfcomm-sabm-flood <MAC>                   # RFCOMM SABM flood (exhaust all 60 DLCIs)
blue-tap dos rfcomm-mux-flood <MAC>                    # RFCOMM multiplexer command flood (Test echo on DLCI 0)
blue-tap dos obex-connect-flood <MAC>                  # OBEX session exhaustion (open all OBEX services)
blue-tap dos hfp-at-flood <MAC>                        # HFP AT command flood (overwhelm AT parser)
blue-tap dos hfp-slc-confuse <MAC>                     # HFP SLC state machine confusion (out-of-order commands)
```

---

### 12. MAC Spoofing and Adapter Management

#### MAC Address Spoofing

Three spoofing methods with automatic fallback (bdaddr → spooftooph → btmgmt). Hardware rejection detection with 8+ patterns per method. Persistent MAC save/restore with atomic JSON writes and corruption recovery. All operations logged to session.

```
blue-tap spoof mac <TARGET_MAC>                        # Change adapter MAC address (auto-selects method)
blue-tap spoof mac <TARGET_MAC> -m bdaddr              # Force specific method
blue-tap spoof clone <MAC> -n "iPhone 15"              # Full identity clone: MAC + name + device class
blue-tap spoof restore                                 # Restore original MAC from saved state
```

**Adapter safety:** Power commands are return-code checked — adapter won't be left in DOWN state. Sleep timing between reset/down/up prevents race conditions. Original MAC backed up atomically before first spoof; corruption recovery preserves the backup.

#### Adapter Management

```
blue-tap adapter list                                  # List all Bluetooth adapters with chipset info
blue-tap adapter info <hci>                            # Detailed adapter info (features, capabilities)
blue-tap adapter up <hci>                              # Bring adapter up
blue-tap adapter down <hci>                            # Bring adapter down
blue-tap adapter reset <hci>                           # Reset adapter
blue-tap adapter set-name <hci> <name>                 # Set adapter friendly name
blue-tap adapter set-class <hci> <class>               # Set device class (e.g., 0x5a020c for phone)
```

---

### 13. Session Management and Reporting

#### Sessions

Every command automatically logs structured output to the active session.

```
blue-tap -s my_assessment scan classic     # Named session
blue-tap -s my_assessment vulnscan <MAC>   # Same session
blue-tap -s my_assessment pbap dump <MAC>  # Same session
blue-tap session list                       # List all sessions
blue-tap session show my_assessment         # Session details
```

**Session directory structure:**
```
sessions/my_assessment/
  session.json              # Metadata + command log
  001_scan_classic.json     # Scan results
  002_vulnscan.json         # Vulnerability findings
  003_pbap_dump.json        # PBAP extraction log
  pbap/                     # vCard files
  map/                      # bMessage files
  audio/                    # WAV captures
  report.html               # Generated report
```

#### Report Generation

```
blue-tap report                             # Report from current session
blue-tap -s my_assessment report             # Report from named session
blue-tap report ./hijack_output              # Report from specific directory
blue-tap report -f json -o report.json       # JSON format
blue-tap report -f html -o report.html       # HTML format (default)
```

**HTML report includes:**
- Executive summary with severity breakdown
- Vulnerability findings table with CVE references, impact, and remediation
- Extracted data summary (contact count, message count, call history)
- Fuzzing campaign results with crash cards (hex dumps, reproducibility status)
- Dark-themed, standalone HTML (no external dependencies)

---

### 13b. DarkFirmware and Below-HCI Attacks

DarkFirmware is a custom firmware for RTL8761B-based USB Bluetooth adapters (TP-Link UB500, USB ID 2357:0604) that enables direct LMP packet injection and monitoring. This extends Blue-Tap's reach below the HCI boundary to attack link-layer protocols that standard BlueZ cannot access.

#### Firmware Management

```bash
blue-tap adapter firmware-status                     # Check DarkFirmware status
blue-tap adapter firmware-install                    # Install bundled DarkFirmware
blue-tap adapter firmware-install --restore          # Revert to stock Realtek firmware
blue-tap adapter firmware-init                       # Manually initialize all 4 firmware hooks
blue-tap adapter firmware-spoof <MAC>                # BDADDR spoofing via firmware patch
blue-tap adapter firmware-set <addr> <value>         # Direct firmware memory write
blue-tap adapter firmware-dump --addr 0x200000 --len 256  # Dump controller memory
blue-tap adapter connection-inspect                  # Dump connection table from controller RAM
```

> **Note:** DarkFirmware is auto-detected at startup. If an RTL8761B is present without DarkFirmware, Blue-Tap prompts to install. After installation, hooks are initialized automatically and the USB watchdog starts for multi-day fuzzing stability.

#### Capabilities Enabled by DarkFirmware

| Capability | VSC Opcode | Description |
|-----------|------------|-------------|
| LMP Injection | 0xFE22 | Inject arbitrary LMP packets into live connections |
| LMP Monitoring | Event 0xFF | Capture incoming/outgoing LMP, ACL, LC packets (4 hooks: AAAA/TXXX/ACLX/RXLC) |
| Memory Read | 0xFC61 | Read 32-bit-aligned controller memory |
| Memory Write | 0xFC62 | Write 32-bit-aligned controller memory |
| In-flight Modification | Hook 2 modes | 6 modes: passthrough, modify, drop, opcode-drop, persistent-modify, auto-respond |
| Connection Inspection | RAM read | Read encryption state, key material, auth flags across 12 connection slots |
| Raw ACL Injection | VSC + HCI | Bypass BlueZ L2CAP stack for below-stack packet injection |

#### LMP Sniffing and Monitoring

```bash
blue-tap recon lmp-sniff <MAC>                       # Sniff LMP packets on a connection
blue-tap recon lmp-monitor -i hci1                   # Monitor all LMP traffic (DarkFirmware)
blue-tap recon lmp-monitor -i hci1 --dashboard       # With live dashboard
blue-tap recon combined-sniff <MAC>                  # Combined HCI + LMP monitoring
```

#### Attacks That Require DarkFirmware

| Attack | Command | CVE |
|--------|---------|-----|
| BLUFFS session key downgrade | `blue-tap bluffs` | CVE-2023-24023 |
| Encryption downgrade | `blue-tap encryption-downgrade` | — |
| CTKD cross-transport key derivation | `blue-tap ctkd` | CVE-2020-15802 |
| BIAS LMP injection mode | `blue-tap bias attack --method lmp` | CVE-2020-10135 |
| KNOB LMP key negotiation | `blue-tap knob attack` | CVE-2019-9506 |
| LMP-level DoS | `blue-tap dos lmp` | — |
| LMP protocol fuzzing | `blue-tap fuzz campaign -p lmp` | — |
| Raw ACL fuzzing | `blue-tap fuzz campaign -p raw-acl` | — |

#### Required Hardware

**RTL8761B USB adapter** — TP-Link UB500 (USB 2357:0604), ~₹599 / ~$8.

The RTL8761B runs a MIPS16e core with 256KB SRAM. DarkFirmware patches the firmware's LMP handler to redirect incoming packets as HCI vendor events and adds a VSC handler for outbound LMP injection. The original firmware is backed up automatically before patching.

---

### 14. Automation and Orchestration

#### Auto Mode — Full 9-Phase Pentest

Executes a complete Bluetooth penetration test methodology in a single command. Resilient by design — each phase runs independently, failures are logged and skipped, never abort. Skipped phases are tracked in results with explicit reason. Reports are timestamped to avoid overwriting previous runs.

| Phase | Name | What It Does |
|:-----:|------|-------------|
| 1 | Discovery | Scan for nearby devices, identify the phone paired with the IVI |
| 2 | Fingerprinting | BT version, chipset, manufacturer, profiles, attack surface |
| 3 | Reconnaissance | SDP services, RFCOMM channels 1-30, L2CAP PSMs |
| 4 | Vuln Assessment | 20+ CVE and configuration checks (parallel local analysis + sequential active probes) |
| 5 | Pairing Attacks | SSP downgrade probe, KNOB (CVE-2019-9506) probe |
| 6 | Exploitation | Hijack: MAC spoof + identity clone + PBAP/MAP extraction (skipped if no phone found) |
| 7 | Protocol Fuzzing | Coverage-guided fuzzing across sdp, rfcomm, l2cap, ble-att (default: 1 hour) |
| 8 | DoS Testing | L2CAP storm, CID exhaustion, SDP continuation, RFCOMM SABM, HFP AT flood |
| 9 | Report | Timestamped HTML + JSON with all findings, evidence, and fuzzing intelligence |

```bash
blue-tap auto <IVI_MAC>                                # Full 9-phase pentest (1hr fuzz)
blue-tap auto <IVI_MAC> --fuzz-duration 7200           # 2 hour fuzzing phase
blue-tap auto <IVI_MAC> --skip-fuzz                    # Skip fuzzing (faster assessment)
blue-tap auto <IVI_MAC> --skip-dos                     # Skip DoS tests
blue-tap auto <IVI_MAC> --skip-fuzz --skip-dos         # Quick: recon + vuln + exploit only
blue-tap auto <IVI_MAC> -d 60                          # 60-second phone discovery window
blue-tap auto <IVI_MAC> -o ./pentest_output/           # Custom output directory
```

**Phase tracking:** Skipped phases appear in results with `"status": "skipped"` and a reason (e.g., "no phone discovered", "user requested"). Summary shows passed/failed/skipped counts. Duration parameters are validated (must be positive). Reports are saved as `report_YYYYMMDD_HHMMSS.html` with a `report.html` latest copy for convenience.

#### Run Mode (Playbook)

Execute multiple commands in sequence with a single invocation.

```bash
# Inline commands
blue-tap -s assessment run \
  "scan classic" \
  "recon fingerprint TARGET" \
  "recon sdp TARGET" \
  "vulnscan TARGET" \
  "report"

# YAML playbook
blue-tap -s assessment run --playbook blue_tap/playbooks/quick-recon.yaml
```

`TARGET` / `{target}` is a placeholder — you'll be prompted to select a discovered device.

**Built-in playbooks** (in `blue_tap/playbooks/`):

| Playbook | Duration | Risk | Description |
|----------|----------|------|-------------|
| `quick-recon.yaml` | ~2 min | None | Fast scan, fingerprint, SDP, vulnscan |
| `passive-recon.yaml` | ~5 min | None | Passive BLE + Classic scanning only |
| `full-assessment.yaml` | ~15 min | Low | Full recon + vuln assessment + data extraction |
| `ivi-attack.yaml` | ~20 min | High | Recon → exploit → data extraction (requires DarkFirmware) |
| `lmp-fuzzing.yaml` | ~30 min | High | LMP protocol fuzzing campaign (requires DarkFirmware) |

**Example YAML playbook:**
```yaml
name: Quick Reconnaissance
description: Fast, non-destructive scan of a Bluetooth target
duration: ~2 minutes
risk: none

steps:
  - command: scan classic -d 10
    description: Discover nearby Bluetooth Classic devices
  - command: recon fingerprint {target}
    description: Fingerprint target device
  - command: vulnscan {target}
    description: Run vulnerability assessment
```

---
