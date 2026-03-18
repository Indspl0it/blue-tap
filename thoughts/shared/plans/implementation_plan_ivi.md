# Vulnerable IVI Simulator — Detailed Implementation Plan

> Breakdown of `2026-03-15-vulnerable-ivi-simulator.md` into epics, stories, and tasks.
> Reference plan: `thoughts/shared/plans/2026-03-15-vulnerable-ivi-simulator.md`

---

## Epic 1: Project Scaffolding & Infrastructure

### Story 1.1: Directory Structure
- [ ] 1.1.1 Create `target/` directory in repo root
- [ ] 1.1.2 Create `target/data/` directory for canned data files
- [ ] 1.1.3 Create `target/data/messages/inbox/` directory
- [ ] 1.1.4 Create `target/data/messages/sent/` directory
- [ ] 1.1.5 Create `target/data/messages/draft/` directory
- [ ] 1.1.6 Create `target/data/messages/deleted/` directory
- [ ] 1.1.7 Create `target/received/` directory (OPP received files)
- [ ] 1.1.8 Create `target/received/.gitkeep` so directory is tracked
- [ ] 1.1.9 Add `target/received/*` (except .gitkeep) to `.gitignore`
- [ ] 1.1.10 Add `target/.ivi_profile` to `.gitignore`

### Story 1.2: Shared Constants Module
- [ ] 1.2.1 Create `target/ivi_config.py` — shared constants used by all components
- [ ] 1.2.2 Define `IVI_NAME = "SYNC"`
- [ ] 1.2.3 Define `IVI_DEVICE_CLASS = 0x200408`
- [ ] 1.2.4 Define `DEFAULT_PIN = "1234"`
- [ ] 1.2.5 Define `DEFAULT_PHONE_MAC = "AA:BB:CC:DD:EE:FF"`
- [ ] 1.2.6 Define `DEFAULT_PHONE_NAME = "Galaxy S24"`
- [ ] 1.2.7 Define RFCOMM channel map: `CH_SPP=1, CH_HIDDEN=2, CH_OPP=9, CH_HFP=10, CH_PBAP=15, CH_MAP=16`
- [ ] 1.2.8 Define L2CAP PSM list: `PSMS = [7, 23, 25]` (only ones we bind; 1 and 3 are bluetoothd)
- [ ] 1.2.9 Define OBEX UUIDs: `PBAP_UUID = bytes.fromhex("796135f0f0c511d809660800200c9a66")`
- [ ] 1.2.10 Define OBEX UUIDs: `MAP_UUID = bytes.fromhex("bb582b40420c11dbb0de0800200c9a66")`
- [ ] 1.2.11 Define OBEX opcodes: `CONNECT=0x80, DISCONNECT=0x81, PUT=0x82, GET=0x83, SETPATH=0x85, SUCCESS=0xA0, CONTINUE=0x90`
- [ ] 1.2.12 Define OBEX header IDs: `NAME=0x01, TYPE=0x42, TARGET=0x46, BODY=0x48, END_OF_BODY=0x49, WHO=0x4A, APP_PARAMS=0x4C, CONNECTION_ID=0xCB`
- [ ] 1.2.13 Define `DATA_DIR` as path relative to script location
- [ ] 1.2.14 Define `RECEIVED_DIR` as path relative to script location
- [ ] 1.2.15 Define `PROFILE_FILE` path for `.ivi_profile`
- [ ] 1.2.16 Add function `read_profile() -> str` that reads `.ivi_profile` (returns "legacy" or "ssp")
- [ ] 1.2.17 Define HFP AG features bitmask: `HFP_AG_FEATURES = 495`
- [ ] 1.2.18 Define HFP indicator names list: `["service", "call", "callsetup", "callheld", "signal", "roam", "battchg"]`
- [ ] 1.2.19 Define HFP indicator default values: `[1, 0, 0, 0, 4, 0, 5]`
- [ ] 1.2.20 Define fake device info: IMEI, IMSI, subscriber number, operator

### Story 1.3: Logging Infrastructure
- [ ] 1.3.1 Create `target/ivi_log.py` — colorized logging for the IVI daemon
- [ ] 1.3.2 Implement `log_info(component, message)` — `[PBAP] Serving phonebook.vcf`
- [ ] 1.3.3 Implement `log_warn(component, message)` — yellow
- [ ] 1.3.4 Implement `log_error(component, message)` — red
- [ ] 1.3.5 Implement `log_connection(component, addr, action)` — `[RFCOMM:15] Connected: AA:BB:CC:DD:EE:FF`
- [ ] 1.3.6 Implement `log_attack(component, addr, detail)` — red highlight for attack activity
- [ ] 1.3.7 Implement `log_obex(direction, opcode, length)` — `[OBEX] <- GET len=47`
- [ ] 1.3.8 Implement `log_at(direction, command)` — `[AT] <- AT+BRSF=127`
- [ ] 1.3.9 Add timestamp prefix to all log lines
- [ ] 1.3.10 Add `--quiet` flag support (suppress info, keep warn/error/attack)
- [ ] 1.3.11 Add `--verbose` flag support (add hex dumps of OBEX packets)

### Story 1.4: CLI Argument Parsing
- [ ] 1.4.1 In `ivi_daemon.py`: add argparse with `--hci` (default hci0)
- [ ] 1.4.2 Add `--phone-mac` argument (default AA:BB:CC:DD:EE:FF)
- [ ] 1.4.3 Add `--data-dir` argument (default ./data/)
- [ ] 1.4.4 Add `--quiet` / `--verbose` flags
- [ ] 1.4.5 Add `--no-ble` flag to skip BLE GATT (in case adapter doesn't support LE)
- [ ] 1.4.6 Add `--no-l2cap` flag to skip L2CAP listeners (in case PSM bind fails)
- [ ] 1.4.7 In `setup_ivi.sh`: parse positional arg 1 as profile (auto/legacy/ssp/detect)
- [ ] 1.4.8 In `setup_ivi.sh`: parse positional arg 2 as phone MAC
- [ ] 1.4.9 In `setup_ivi.sh`: parse positional arg 3 as HCI adapter name
- [ ] 1.4.10 In `pin_agent.py`: add `--phone-mac` argument
- [ ] 1.4.11 In `pin_agent.py`: add `--hci` argument
- [ ] 1.4.12 In `ble_gatt.py`: add `--hci` argument

---

## Epic 2: Canned Data Generation

### Story 2.1: Contact Generator
- [ ] 2.1.1 Create `target/data/gen_data.py`
- [ ] 2.1.2 Import `random` with seed for reproducibility (`random.seed(42)`)
- [ ] 2.1.3 Define 50 first names (realistic mix: John, Maria, Wei, Aisha, etc.)
- [ ] 2.1.4 Define 50 last names (realistic mix: Smith, Garcia, Chen, Patel, etc.)
- [ ] 2.1.5 Define phone number generator: +1 prefix, 415/650/408 area codes, random 7 digits
- [ ] 2.1.6 Define email generator: firstname.lastname@{gmail,outlook,yahoo,example}.com
- [ ] 2.1.7 Define address generator: random street numbers, street names, cities, states, zips
- [ ] 2.1.8 Implement `generate_vcard(index, first, last, cell, work, email, addr) -> str`
- [ ] 2.1.9 vCard must use VERSION:2.1 (not 3.0 — PBAP default)
- [ ] 2.1.10 Include N, FN, TEL;CELL, TEL;WORK (for 30% of contacts), EMAIL (for 60%), ADR;HOME (for 40%)
- [ ] 2.1.11 Generate 50 contacts, write to `target/data/phonebook.vcf` (all in one file, PBAP format)
- [ ] 2.1.12 Validate: each vCard has BEGIN:VCARD and END:VCARD
- [ ] 2.1.13 Validate: no blank lines inside vCard body (breaks some parsers)

### Story 2.2: Call History Generator
- [ ] 2.2.1 Implement `generate_call_entry(name, number, call_type, timestamp) -> str`
- [ ] 2.2.2 Use X-IRMC-CALL-DATETIME with correct type attribute: RECEIVED, DIALED, MISSED
- [ ] 2.2.3 Generate 20 incoming calls (ich.vcf) with timestamps across last 7 days
- [ ] 2.2.4 Generate 15 outgoing calls (och.vcf) with timestamps
- [ ] 2.2.5 Generate 10 missed calls (mch.vcf) with timestamps
- [ ] 2.2.6 Generate combined call history (cch.vcf) — all 45 entries sorted by timestamp descending
- [ ] 2.2.7 Use contacts from phonebook (random 15 of the 50) for call participants
- [ ] 2.2.8 Add 5 calls from numbers NOT in phonebook (unknown callers)
- [ ] 2.2.9 Write ich.vcf, och.vcf, mch.vcf, cch.vcf to `target/data/`
- [ ] 2.2.10 Validate: timestamp format is YYYYMMDDTHHMMSS

### Story 2.3: SMS Message Generator
- [ ] 2.3.1 Define 20 realistic message bodies (mix of short/long, emoji-free)
- [ ] 2.3.2 Implement `generate_bmessage(index, sender, body, folder, status, msg_type) -> str`
- [ ] 2.3.3 bMessage must include: VERSION:1.0, STATUS, TYPE, FOLDER
- [ ] 2.3.4 bMessage must include embedded VCARD for sender with FN, TEL, N
- [ ] 2.3.5 bMessage must include BENV > BBODY > MSG structure
- [ ] 2.3.6 CHARSET must be UTF-8, LENGTH must match actual body byte length
- [ ] 2.3.7 Generate 10 inbox messages (STATUS:READ for 7, STATUS:UNREAD for 3)
- [ ] 2.3.8 Write to `target/data/messages/inbox/0001.bmsg` through `0010.bmsg`
- [ ] 2.3.9 Generate 5 sent messages (STATUS:READ)
- [ ] 2.3.10 Write to `target/data/messages/sent/0011.bmsg` through `0015.bmsg`
- [ ] 2.3.11 Generate 3 draft messages (STATUS:READ)
- [ ] 2.3.12 Write to `target/data/messages/draft/0016.bmsg` through `0018.bmsg`
- [ ] 2.3.13 Generate 2 deleted messages (STATUS:READ)
- [ ] 2.3.14 Write to `target/data/messages/deleted/0019.bmsg` through `0020.bmsg`
- [ ] 2.3.15 Use contacts from phonebook as senders/recipients (cross-reference)

### Story 2.4: MAP Message Listing XML Generator
- [ ] 2.4.1 Implement `generate_msg_listing_xml(folder, messages) -> str`
- [ ] 2.4.2 XML format: `<?xml version="1.0"?>\n<MAP-msg-listing version="1.0">...</MAP-msg-listing>`
- [ ] 2.4.3 Each message: `<msg handle="XXXX" subject="..." datetime="..." sender_name="..." sender_addressing="..." type="SMS_GSM" size="..." reception_status="complete" read="yes|no"/>`
- [ ] 2.4.4 Generate inbox listing XML → `target/data/messages/inbox_listing.xml`
- [ ] 2.4.5 Generate sent listing XML → `target/data/messages/sent_listing.xml`
- [ ] 2.4.6 Generate draft listing XML → `target/data/messages/draft_listing.xml`
- [ ] 2.4.7 Generate deleted listing XML → `target/data/messages/deleted_listing.xml`
- [ ] 2.4.8 Handles must be zero-padded 4-digit hex: 0001, 0002, ..., 0014

### Story 2.5: AT Command Canned Data
- [ ] 2.5.1 Generate `target/data/at_phonebook.txt` — CPBR format entries from same 50 contacts
- [ ] 2.5.2 Format: `+CPBR: <idx>,"<number>",<type>,"<name>"` per entry
- [ ] 2.5.3 Type 145 for international (+1...), type 129 for national
- [ ] 2.5.4 Generate `target/data/at_sms.txt` — CMGL format entries from same 20 messages
- [ ] 2.5.5 Format: `+CMGL: <idx>,"REC READ|REC UNREAD","<sender>",,"<date>"\n<body>`
- [ ] 2.5.6 Date format: YY/MM/DD,HH:MM:SS+TZ

### Story 2.6: Data Generator CLI
- [ ] 2.6.1 Add `if __name__ == "__main__"` block to gen_data.py
- [ ] 2.6.2 Add `--seed` argument (default 42)
- [ ] 2.6.3 Add `--contacts` argument (default 50)
- [ ] 2.6.4 Add `--messages` argument (default 20)
- [ ] 2.6.5 Add `--output-dir` argument (default ./data/)
- [ ] 2.6.6 Print summary: "Generated X contacts, Y call history entries, Z messages"
- [ ] 2.6.7 Validate all generated files exist after run
- [ ] 2.6.8 Add `--clean` flag to delete existing data before generating

---

## Epic 3: BlueZ Adapter Setup Script

### Story 3.1: Adapter Detection
- [ ] 3.1.1 Create `target/setup_ivi.sh` with `#!/bin/bash` and `set -e`
- [ ] 3.1.2 Parse CLI args: `PROFILE=$1` (auto/legacy/ssp/detect), `PHONE_MAC=$2`, `HCI=$3`
- [ ] 3.1.3 Set defaults: PROFILE=auto, PHONE_MAC=AA:BB:CC:DD:EE:FF, HCI=hci0
- [ ] 3.1.4 Check if running as root (required for hciconfig/btmgmt)
- [ ] 3.1.5 Check `hciconfig $HCI` — exit with error if adapter not found
- [ ] 3.1.6 List available adapters on error: `hciconfig -a | grep "^hci"`
- [ ] 3.1.7 Extract adapter BD address: `grep -oP '(?<=BD Address: )[0-9A-F:]+' `
- [ ] 3.1.8 Read chipset from sysfs: `cat /sys/class/bluetooth/$HCI/device/modalias 2>/dev/null`
- [ ] 3.1.9 Print adapter summary: address, chipset, bus type
- [ ] 3.1.10 Check for required tools: `which hciconfig hcitool sdptool btmgmt bluetoothctl`
- [ ] 3.1.11 Exit with clear error message if any tool is missing, with install hint

### Story 3.2: Adapter Identity Configuration
- [ ] 3.2.1 `hciconfig $HCI up` — bring adapter up
- [ ] 3.2.2 `hciconfig $HCI name "SYNC"` — set IVI name
- [ ] 3.2.3 `hciconfig $HCI class 0x200408` — set Car Audio device class
- [ ] 3.2.4 `hciconfig $HCI piscan` — make discoverable + connectable
- [ ] 3.2.5 Verify name was set: `hciconfig $HCI name | grep SYNC`
- [ ] 3.2.6 Verify class was set: `hciconfig $HCI class | grep 0x200408`
- [ ] 3.2.7 Print confirmation with checkmarks

### Story 3.3: SSP Auto-Detection
- [ ] 3.3.1 Extract adapter index number from HCI name: `echo $HCI | grep -oP '\d+'`
- [ ] 3.3.2 If PROFILE=auto: attempt `btmgmt --index $IDX ssp off`
- [ ] 3.3.3 Wait 500ms for setting to take effect
- [ ] 3.3.4 Read back SSP state: `btmgmt --index $IDX info | grep -oP '(?<=ssp )(on|off)'`
- [ ] 3.3.5 If SSP is off → set PROFILE=legacy
- [ ] 3.3.6 If SSP is still on → set PROFILE=ssp, print Intel warning
- [ ] 3.3.7 If PROFILE=legacy: `btmgmt ssp off`, `btmgmt bondable on`
- [ ] 3.3.8 If PROFILE=ssp: `btmgmt ssp on`, `btmgmt io-cap NoInputNoOutput`, `btmgmt bondable on`
- [ ] 3.3.9 Print which profile was selected and what it means

### Story 3.4: SDP Service Registration
- [ ] 3.4.1 Clear existing SDP records: `sdptool del <handles>` for any pre-existing records
- [ ] 3.4.2 `sdptool add --channel=15 PBAP` — Phonebook Access Profile
- [ ] 3.4.3 `sdptool add --channel=16 MAP` — Message Access Profile
- [ ] 3.4.4 `sdptool add --channel=9 OPP` — Object Push Profile
- [ ] 3.4.5 `sdptool add --channel=10 HFP` — Hands-Free Profile (AG)
- [ ] 3.4.6 `sdptool add --channel=1 SP` — Serial Port Profile
- [ ] 3.4.7 `sdptool add --channel=3 DUN` — Dialup Networking
- [ ] 3.4.8 `sdptool add --channel=11 NAP` — Network Access Point
- [ ] 3.4.9 `sdptool add --channel=12 PANU` — PAN User
- [ ] 3.4.10 Verify registration: `sdptool browse local | grep -c "Service Name"` should be >= 8
- [ ] 3.4.11 Print each registered service with channel number

### Story 3.5: BLE Configuration
- [ ] 3.5.1 Enable LE: `btmgmt --index $IDX le on`
- [ ] 3.5.2 Verify LE is on: `btmgmt --index $IDX info | grep "le on"`
- [ ] 3.5.3 If LE fails (single-mode adapter), print warning but don't exit
- [ ] 3.5.4 Print BLE status

### Story 3.6: Pre-Paired Phone Bond
- [ ] 3.6.1 Get adapter MAC for bond directory path
- [ ] 3.6.2 Create bond directory: `/var/lib/bluetooth/$ADAPTER_MAC/$PHONE_MAC/`
- [ ] 3.6.3 Write `info` file with [General] section: Name, Trusted=true, Blocked=false
- [ ] 3.6.4 Write `info` file with [LinkKey] section: dummy key, Type=4, PINLength=0
- [ ] 3.6.5 Restart bluetooth service: `systemctl restart bluetooth`
- [ ] 3.6.6 Wait 2 seconds for service to fully start
- [ ] 3.6.7 Re-apply adapter settings (restart resets them): up, name, class, piscan
- [ ] 3.6.8 Re-apply SSP settings based on selected profile
- [ ] 3.6.9 Re-register SDP records (restart may clear them)
- [ ] 3.6.10 Verify bond exists: `bluetoothctl paired-devices | grep $PHONE_MAC`
- [ ] 3.6.11 Print pre-paired phone summary

### Story 3.7: Profile Persistence
- [ ] 3.7.1 Write selected profile to `target/.ivi_profile`
- [ ] 3.7.2 Write adapter MAC to `target/.ivi_adapter`
- [ ] 3.7.3 Write phone MAC to `target/.ivi_phone`
- [ ] 3.7.4 These files are read by pin_agent.py and ivi_daemon.py

### Story 3.8: Detect Mode
- [ ] 3.8.1 If PROFILE=detect: run adapter detection only
- [ ] 3.8.2 Print adapter info (MAC, chipset, LMP version)
- [ ] 3.8.3 Test SSP disable capability
- [ ] 3.8.4 Test LE capability
- [ ] 3.8.5 Print expected vuln-scan findings matrix
- [ ] 3.8.6 Do NOT modify adapter settings, exit cleanly

### Story 3.9: Idempotency & Cleanup
- [ ] 3.9.1 Add `--reset` flag to undo all changes (restore adapter to defaults)
- [ ] 3.9.2 Reset: `hciconfig $HCI noscan` (stop discoverable)
- [ ] 3.9.3 Reset: `btmgmt ssp on` (restore SSP)
- [ ] 3.9.4 Reset: remove bond directory for fake phone
- [ ] 3.9.5 Reset: `systemctl restart bluetooth`
- [ ] 3.9.6 Script is idempotent: running twice doesn't break anything

---

## Epic 4: OBEX Protocol Engine

### Story 4.1: OBEX Packet Parser
- [ ] 4.1.1 Create `target/obex_engine.py` — shared OBEX binary protocol implementation
- [ ] 4.1.2 Implement `parse_packet(data: bytes) -> dict` — returns opcode, length, headers
- [ ] 4.1.3 Parse opcode (byte 0) and total length (bytes 1-2, big-endian)
- [ ] 4.1.4 Parse OBEX Connect body: version (byte 3), flags (byte 4), max_packet (bytes 5-6)
- [ ] 4.1.5 Parse OBEX SetPath body: flags byte 0 (0x02 = root), flags byte 1 (reserved)
- [ ] 4.1.6 Implement `parse_headers(data: bytes, offset: int) -> list[tuple[int, bytes]]`
- [ ] 4.1.7 Handle header type 0x00-0x3F: Unicode string (HI + 2-byte length + UTF-16-BE data)
- [ ] 4.1.8 Handle header type 0x40-0x7F: Byte sequence (HI + 2-byte length + data)
- [ ] 4.1.9 Handle header type 0x80-0xBF: 1-byte value (HI + 1 byte)
- [ ] 4.1.10 Handle header type 0xC0-0xFF: 4-byte value (HI + 4 bytes)
- [ ] 4.1.11 Extract Name header (0x01): decode UTF-16-BE, strip null terminator
- [ ] 4.1.12 Extract Type header (0x42): decode ASCII, strip null terminator
- [ ] 4.1.13 Extract Target header (0x46): raw 16-byte UUID
- [ ] 4.1.14 Extract Body header (0x48): raw bytes
- [ ] 4.1.15 Extract End-of-Body header (0x49): raw bytes
- [ ] 4.1.16 Extract ConnectionID header (0xCB): 4-byte big-endian int
- [ ] 4.1.17 Extract AppParams header (0x4C): raw TLV bytes
- [ ] 4.1.18 Handle malformed packets gracefully (don't crash on truncated data)
- [ ] 4.1.19 Handle oversized packets (ignore data beyond declared length)

### Story 4.2: OBEX App Parameters TLV Parser
- [ ] 4.2.1 Implement `parse_app_params(data: bytes) -> dict`
- [ ] 4.2.2 Parse TLV: tag (1 byte), length (1 byte), value (length bytes)
- [ ] 4.2.3 Parse MaxListCount (tag 0x04, 2 bytes big-endian)
- [ ] 4.2.4 Parse ListStartOffset (tag 0x05, 2 bytes big-endian)
- [ ] 4.2.5 Parse Filter (tag 0x06, 8 bytes bitmask)
- [ ] 4.2.6 Parse Format (tag 0x07, 1 byte: 0=vCard2.1, 1=vCard3.0)
- [ ] 4.2.7 Parse SearchAttribute (tag 0x02, 1 byte)
- [ ] 4.2.8 Parse SearchValue (tag 0x03, variable length UTF-8)
- [ ] 4.2.9 Parse Charset (tag 0x14, 1 byte: 1=UTF-8) — MAP
- [ ] 4.2.10 Parse NotificationStatus (tag 0x0E, 1 byte) — MAP
- [ ] 4.2.11 Return unrecognized tags as raw bytes (don't crash)

### Story 4.3: OBEX Packet Builder
- [ ] 4.3.1 Implement `build_response(opcode: int, headers: list[tuple]) -> bytes`
- [ ] 4.3.2 Calculate total packet length including all headers
- [ ] 4.3.3 Build Connect response: opcode + length + version(0x10) + flags(0x00) + max_packet(0xFFFF) + headers
- [ ] 4.3.4 Build simple response (GET/PUT/SetPath/Disconnect): opcode + length + headers
- [ ] 4.3.5 Implement `build_header_unicode(hi: int, text: str) -> bytes` (UTF-16-BE + null term)
- [ ] 4.3.6 Implement `build_header_bytes(hi: int, data: bytes) -> bytes` (raw byte sequence)
- [ ] 4.3.7 Implement `build_header_u8(hi: int, value: int) -> bytes` (1-byte value)
- [ ] 4.3.8 Implement `build_header_u32(hi: int, value: int) -> bytes` (4-byte value)
- [ ] 4.3.9 Implement `build_connection_id(conn_id: int) -> bytes` — shortcut for 0xCB header
- [ ] 4.3.10 Implement `build_body(data: bytes, final: bool) -> bytes` — 0x48 or 0x49
- [ ] 4.3.11 Implement `build_who(uuid: bytes) -> bytes` — 0x4A header
- [ ] 4.3.12 Implement `build_app_params(params: dict) -> bytes` — TLV encoding

### Story 4.4: OBEX Chunked Response
- [ ] 4.4.1 Implement `chunked_response(data: bytes, conn_id: int, max_packet: int) -> list[bytes]`
- [ ] 4.4.2 First N-1 chunks: CONTINUE (0x90) + ConnectionID + Body (0x48) + chunk
- [ ] 4.4.3 Last chunk: SUCCESS (0xA0) + ConnectionID + End-of-Body (0x49) + chunk
- [ ] 4.4.4 Each chunk respects max_packet size (subtract header overhead)
- [ ] 4.4.5 Handle edge case: data fits in single packet (just SUCCESS + End-of-Body)
- [ ] 4.4.6 Handle edge case: empty data (SUCCESS + empty End-of-Body)
- [ ] 4.4.7 Calculate chunk size accounting for OBEX header overhead (~10 bytes)

### Story 4.5: OBEX Connection State Machine
- [ ] 4.5.1 Implement `OBEXSession` class — tracks per-connection state
- [ ] 4.5.2 State: `connected: bool`, `connection_id: int`, `target_uuid: bytes`
- [ ] 4.5.3 State: `current_path: list[str]` (for SetPath navigation)
- [ ] 4.5.4 State: `max_packet: int` (negotiated during Connect)
- [ ] 4.5.5 State: `pending_get_chunks: list[bytes]` (for multi-packet GET responses)
- [ ] 4.5.6 Implement `handle_packet(data: bytes) -> bytes | None` — main dispatch
- [ ] 4.5.7 Dispatch CONNECT (0x80) → handle_connect
- [ ] 4.5.8 Dispatch GET (0x83) → handle_get
- [ ] 4.5.9 Dispatch GET-continue (0x83 with no headers) → send next chunk from pending
- [ ] 4.5.10 Dispatch SETPATH (0x85) → handle_setpath
- [ ] 4.5.11 Dispatch PUT (0x02/0x82) → handle_put
- [ ] 4.5.12 Dispatch DISCONNECT (0x81) → handle_disconnect
- [ ] 4.5.13 Handle unknown opcodes: return 0xD0 (Internal Server Error)

---

## Epic 5: PBAP Server

### Story 5.1: PBAP Connect Handler
- [ ] 5.1.1 In `handle_connect`: verify Target header matches PBAP_UUID
- [ ] 5.1.2 Generate random ConnectionID (4-byte int)
- [ ] 5.1.3 Build SUCCESS response with ConnectionID + Who header (PBAP_UUID)
- [ ] 5.1.4 Set session target to PBAP
- [ ] 5.1.5 Log: `[PBAP] Client connected`

### Story 5.2: PBAP Phonebook Pull
- [ ] 5.2.1 Handle GET with Type=`x-bt/phonebook`
- [ ] 5.2.2 Parse Name header to get requested path (e.g., `telecom/pb.vcf`)
- [ ] 5.2.3 Map path to data file: `telecom/pb.vcf` → `data/phonebook.vcf`
- [ ] 5.2.4 Map `telecom/ich.vcf` → `data/ich.vcf`
- [ ] 5.2.5 Map `telecom/och.vcf` → `data/och.vcf`
- [ ] 5.2.6 Map `telecom/mch.vcf` → `data/mch.vcf`
- [ ] 5.2.7 Map `telecom/cch.vcf` → `data/cch.vcf`
- [ ] 5.2.8 Map `telecom/spd.vcf` → empty (no speed dial data)
- [ ] 5.2.9 Map `telecom/fav.vcf` → subset of phonebook (first 5)
- [ ] 5.2.10 Map `SIM1/telecom/pb.vcf` → empty (no SIM data)
- [ ] 5.2.11 Read file content, chunk with `chunked_response()`
- [ ] 5.2.12 Parse AppParams for MaxListCount and ListStartOffset
- [ ] 5.2.13 If MaxListCount=0: return PhonebookSize AppParam with count only (no body)
- [ ] 5.2.14 Apply ListStartOffset to slice vCards
- [ ] 5.2.15 Apply MaxListCount to limit returned vCards
- [ ] 5.2.16 If file not found, return SUCCESS with empty body (PBAP spec says empty, not error)
- [ ] 5.2.17 Log: `[PBAP] Serving telecom/pb.vcf (50 contacts, 12KB)`

### Story 5.3: PBAP vCard Listing
- [ ] 5.3.1 Handle GET with Type=`x-bt/vcard-listing`
- [ ] 5.3.2 Build XML listing: `<?xml version="1.0"?>\n<vCard-listing version="1.0">...</vCard-listing>`
- [ ] 5.3.3 Each entry: `<card handle="X.vcf" name="Last;First"/>`
- [ ] 5.3.4 Parse AppParams for SearchAttribute and SearchValue (filtering)
- [ ] 5.3.5 If search specified, filter contacts by name/number
- [ ] 5.3.6 Return listing as OBEX response body

### Story 5.4: PBAP Individual vCard
- [ ] 5.4.1 Handle GET with Name like `1.vcf`, `2.vcf` (individual contact)
- [ ] 5.4.2 Extract index from filename
- [ ] 5.4.3 Return single vCard from phonebook by index
- [ ] 5.4.4 Return empty body if index out of range

---

## Epic 6: MAP Server

### Story 6.1: MAP Connect Handler
- [ ] 6.1.1 In `handle_connect`: verify Target header matches MAP_UUID
- [ ] 6.1.2 Generate ConnectionID, return SUCCESS + Who header
- [ ] 6.1.3 Initialize current_path to root
- [ ] 6.1.4 Log: `[MAP] Client connected`

### Story 6.2: MAP SetPath Navigation
- [ ] 6.2.1 Handle SETPATH with flags=0x02 (go to root): reset current_path to []
- [ ] 6.2.2 Handle SETPATH with Name header: append folder to current_path
- [ ] 6.2.3 Handle SETPATH with flags=0x03 (go up one): pop last from current_path
- [ ] 6.2.4 Valid paths: `telecom/msg/inbox`, `telecom/msg/sent`, `telecom/msg/draft`, `telecom/msg/deleted`
- [ ] 6.2.5 Return SUCCESS for valid paths
- [ ] 6.2.6 Return SUCCESS even for unknown paths (lenient, like real IVIs)
- [ ] 6.2.7 Log: `[MAP] SetPath → telecom/msg/inbox`

### Story 6.3: MAP Message Listing
- [ ] 6.3.1 Handle GET with Type=`x-bt/MAP-msg-listing`
- [ ] 6.3.2 Determine current folder from current_path
- [ ] 6.3.3 Read pre-generated listing XML from `data/messages/<folder>_listing.xml`
- [ ] 6.3.4 Parse AppParams for MaxListCount
- [ ] 6.3.5 Chunk response if > max_packet
- [ ] 6.3.6 Log: `[MAP] Listing inbox (10 messages)`

### Story 6.4: MAP Individual Message
- [ ] 6.4.1 Handle GET with Name header (message handle like "0001")
- [ ] 6.4.2 Handle Type=`x-bt/message`
- [ ] 6.4.3 Map handle to bMessage file: `data/messages/<folder>/<handle>.bmsg`
- [ ] 6.4.4 Read bMessage content, return as body
- [ ] 6.4.5 Return NOT_FOUND (0xC4) if handle doesn't exist
- [ ] 6.4.6 Log: `[MAP] Serving message 0001 from inbox`

### Story 6.5: MAP Folder Listing
- [ ] 6.5.1 Handle GET with Type=`x-bt/MAP-msg-listing` at `telecom/msg` level
- [ ] 6.5.2 Return XML listing of available folders: inbox, sent, draft, deleted
- [ ] 6.5.3 Format: `<folder-listing><folder name="inbox"/><folder name="sent"/>...</folder-listing>`

### Story 6.6: MAP Push Message (accept)
- [ ] 6.6.1 Handle PUT with Type=`x-bt/message`
- [ ] 6.6.2 Accept the bMessage body data
- [ ] 6.6.3 Save to `target/received/map_<timestamp>.bmsg`
- [ ] 6.6.4 Return SUCCESS
- [ ] 6.6.5 Log: `[MAP] Received pushed message`

---

## Epic 7: OPP Server

### Story 7.1: OPP Connect
- [ ] 7.1.1 Handle CONNECT with NO Target UUID (OPP is generic OBEX)
- [ ] 7.1.2 Return SUCCESS + ConnectionID
- [ ] 7.1.3 Log: `[OPP] Client connected`

### Story 7.2: OPP PUT Handler
- [ ] 7.2.1 Handle PUT opcode (0x02 for intermediate, 0x82 for final)
- [ ] 7.2.2 Extract filename from Name header
- [ ] 7.2.3 Extract file length from Length header (0xC3) if present
- [ ] 7.2.4 Accumulate Body (0x48) chunks across multiple PUT packets
- [ ] 7.2.5 On End-of-Body (0x49) or PUT-Final: finalize and save
- [ ] 7.2.6 Save to `target/received/<filename>` (sanitize filename, no path traversal)
- [ ] 7.2.7 Respond CONTINUE (0x90) for intermediate chunks
- [ ] 7.2.8 Respond SUCCESS (0xA0) for final chunk
- [ ] 7.2.9 Log: `[OPP] Received file: contact.vcf (1.2KB)`
- [ ] 7.2.10 Handle missing Name header: generate timestamped filename
- [ ] 7.2.11 Handle duplicate filenames: append _1, _2, etc.

---

## Epic 8: HFP AT Command Responder

### Story 8.1: HFP RFCOMM Listener
- [ ] 8.1.1 Listen on RFCOMM channel 10
- [ ] 8.1.2 Accept connections, spawn handler thread per client
- [ ] 8.1.3 Set socket timeout to 5.0 seconds
- [ ] 8.1.4 Read data in a loop, buffer until `\r` or `\r\n` (AT command terminator)
- [ ] 8.1.5 Handle multiple AT commands in a single recv() buffer
- [ ] 8.1.6 Handle partial AT commands across multiple recv() calls
- [ ] 8.1.7 Log: `[HFP] Client connected from XX:XX:XX:XX:XX:XX`

### Story 8.2: SLC Handshake Responses
- [ ] 8.2.1 Implement `handle_at(command: str) -> str` dispatcher
- [ ] 8.2.2 `AT+BRSF=<n>` → `\r\n+BRSF: 495\r\n\r\nOK\r\n`
- [ ] 8.2.3 `AT+CIND=?` → indicator mapping with 7 indicators (service, call, callsetup, callheld, signal, roam, battchg)
- [ ] 8.2.4 `AT+CIND?` → current indicator values: `1,0,0,0,4,0,5`
- [ ] 8.2.5 `AT+CMER=3,0,0,1` → `\r\nOK\r\n`
- [ ] 8.2.6 `AT+CHLD=?` → `\r\n+CHLD: (0,1,2,3,4)\r\n\r\nOK\r\n`
- [ ] 8.2.7 Log each AT command and response

### Story 8.3: Call Control Responses
- [ ] 8.3.1 `ATD<number>;` → `\r\nOK\r\n` (log dialed number)
- [ ] 8.3.2 `ATA` → `\r\nOK\r\n` (answer)
- [ ] 8.3.3 `AT+CHUP` → `\r\nOK\r\n` (hangup)
- [ ] 8.3.4 `AT+CLCC` → `\r\nOK\r\n` (no active calls)
- [ ] 8.3.5 `AT+BLDN` → `\r\nOK\r\n` (redial)

### Story 8.4: Info Query Responses
- [ ] 8.4.1 `AT+COPS?` → `\r\n+COPS: 0,0,"T-Mobile"\r\n\r\nOK\r\n`
- [ ] 8.4.2 `AT+CNUM` → `\r\n+CNUM: ,"+14155559999",145,,4\r\n\r\nOK\r\n`
- [ ] 8.4.3 `AT+CLIP=1` → `\r\nOK\r\n`

### Story 8.5: Volume & Audio Responses
- [ ] 8.5.1 `AT+VGS=<n>` → `\r\nOK\r\n` (log speaker volume)
- [ ] 8.5.2 `AT+VGM=<n>` → `\r\nOK\r\n` (log mic volume)
- [ ] 8.5.3 `AT+NREC=0` → `\r\nOK\r\n`
- [ ] 8.5.4 `AT+BVRA=<n>` → `\r\nOK\r\n`
- [ ] 8.5.5 `AT+VTS=<d>` → `\r\nOK\r\n` (log DTMF digit)

### Story 8.6: Codec Negotiation
- [ ] 8.6.1 `AT+BAC=1,2` → `\r\n+BCS:1\r\n\r\nOK\r\n` (select CVSD)
- [ ] 8.6.2 `AT+BCS=1` → `\r\nOK\r\n` (confirm CVSD)

### Story 8.7: Phonebook via AT (HFP path)
- [ ] 8.7.1 `AT+CPBS="<memory>"` → `\r\nOK\r\n`
- [ ] 8.7.2 `AT+CPBR=<start>,<end>` → CPBR entries from canned data
- [ ] 8.7.3 Read entries from `data/at_phonebook.txt`
- [ ] 8.7.4 Slice entries by start/end range

### Story 8.8: Default Fallback
- [ ] 8.8.1 Any unrecognized `AT+...` → `\r\nOK\r\n` (accept everything — vulnerable!)
- [ ] 8.8.2 Any unrecognized `AT...` (no +) → `\r\nOK\r\n`
- [ ] 8.8.3 Empty line / whitespace only → ignore (no response)
- [ ] 8.8.4 Non-AT data → ignore (don't crash)

---

## Epic 9: SPP / Bluesnarfer AT Responder

### Story 9.1: SPP RFCOMM Listener
- [ ] 9.1.1 Listen on RFCOMM channel 1
- [ ] 9.1.2 Same AT buffering logic as HFP (reuse parsing code)
- [ ] 9.1.3 Log: `[SPP] Client connected`

### Story 9.2: Bluesnarfer-Specific AT Commands
- [ ] 9.2.1 `AT+CPBS=?` → list available memories: ME, SM, DC, RC, MC
- [ ] 9.2.2 `AT+CPBS="ME"` → `\r\nOK\r\n` (select phone memory)
- [ ] 9.2.3 `AT+CPBS="DC"` → `\r\nOK\r\n` (dialed calls — switch data source)
- [ ] 9.2.4 `AT+CPBS="RC"` → `\r\nOK\r\n` (received calls)
- [ ] 9.2.5 `AT+CPBS="MC"` → `\r\nOK\r\n` (missed calls)
- [ ] 9.2.6 `AT+CPBR=<start>,<end>` → entries from currently selected memory
- [ ] 9.2.7 `AT+CMGF=1` → `\r\nOK\r\n` (text mode)
- [ ] 9.2.8 `AT+CMGL="ALL"` → all SMS entries from canned data
- [ ] 9.2.9 `AT+CMGL="REC UNREAD"` → unread messages only
- [ ] 9.2.10 `AT+CMGL="REC READ"` → read messages only

### Story 9.3: Device Info AT Commands
- [ ] 9.3.1 `AT+CGSN` → `\r\n351234567890123\r\n\r\nOK\r\n` (IMEI)
- [ ] 9.3.2 `AT+CIMI` → `\r\n310260123456789\r\n\r\nOK\r\n` (IMSI)
- [ ] 9.3.3 `AT+CNUM` → subscriber number
- [ ] 9.3.4 `AT+CBC` → `\r\n+CBC: 0,85\r\n\r\nOK\r\n` (battery)
- [ ] 9.3.5 `AT+CSQ` → `\r\n+CSQ: 22,99\r\n\r\nOK\r\n` (signal)
- [ ] 9.3.6 `AT+COPS?` → operator name

### Story 9.4: Shared AT Engine
- [ ] 9.4.1 Extract shared AT command parsing into `target/at_engine.py`
- [ ] 9.4.2 Both HFP (ch10) and SPP (ch1) reuse the same parser
- [ ] 9.4.3 HFP-specific commands (BRSF, CIND, CMER, etc.) only on ch10
- [ ] 9.4.4 SPP/Bluesnarfer commands (CPBS, CPBR, CMGL, CGSN, etc.) only on ch1
- [ ] 9.4.5 Common commands (COPS, CNUM) shared by both

---

## Epic 10: L2CAP Listeners

### Story 10.1: L2CAP PSM Binding
- [ ] 10.1.1 Implement `start_l2cap_listener(psm: int)` in ivi_daemon.py
- [ ] 10.1.2 `socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP)`
- [ ] 10.1.3 `bind(("", psm))`
- [ ] 10.1.4 `listen(1)` (backlog of 1 is fine for testing)
- [ ] 10.1.5 Accept loop in dedicated thread
- [ ] 10.1.6 Handle EADDRINUSE: log warning, skip this PSM (bluetoothd may hold it)
- [ ] 10.1.7 Handle EACCES: log error about needing root

### Story 10.2: Data Absorber
- [ ] 10.2.1 On accepted connection: spawn thread with `absorb_data(conn)`
- [ ] 10.2.2 `recv(65535)` in loop until empty or error
- [ ] 10.2.3 Count bytes received, log total on disconnect
- [ ] 10.2.4 Catch all exceptions (socket.error, OSError) — never crash
- [ ] 10.2.5 Close connection in finally block
- [ ] 10.2.6 Log: `[L2CAP:23] Absorbed 65535 bytes from XX:XX:XX:XX:XX:XX`

### Story 10.3: PSM List
- [ ] 10.3.1 Bind PSM 7 (BNEP/PAN) — if not already held by bluetoothd
- [ ] 10.3.2 Bind PSM 23 (AVCTP/AVRCP signaling)
- [ ] 10.3.3 Bind PSM 25 (AVDTP/A2DP streaming)
- [ ] 10.3.4 PSMs 1 (SDP) and 3 (RFCOMM) are held by bluetoothd — don't bind, just log "already handled"

### Story 10.4: Hidden RFCOMM Channel
- [ ] 10.4.1 Listen on RFCOMM channel 2 (NOT registered in SDP)
- [ ] 10.4.2 Accept connections, absorb data (same as L2CAP absorber)
- [ ] 10.4.3 Respond to `\r\n` probe with `OK\r\n` (makes rfcomm-scan classify it as at_modem)
- [ ] 10.4.4 This channel triggers the vuln-scanner's "hidden RFCOMM" finding
- [ ] 10.4.5 Log: `[HIDDEN:2] Connection from XX:XX:XX:XX:XX:XX`

---

## Epic 11: BLE GATT Server

### Story 11.1: D-Bus GATT Application
- [ ] 11.1.1 Create `target/ble_gatt.py`
- [ ] 11.1.2 Import dbus, dbus.service, dbus.mainloop.glib, gi.repository.GLib
- [ ] 11.1.3 Implement `Application(dbus.service.Object)` — GATT application container
- [ ] 11.1.4 Register on `org.bluez.GattManager1` interface
- [ ] 11.1.5 Implement `GetManagedObjects()` → returns all services/characteristics/descriptors

### Story 11.2: Device Information Service (0x180A)
- [ ] 11.2.1 Implement `DeviceInfoService(dbus.service.Object)` with UUID `180A`
- [ ] 11.2.2 Characteristic: Manufacturer Name (0x2A29) = "FakeCar Audio Systems" (read)
- [ ] 11.2.3 Characteristic: Model Number (0x2A24) = "IVI-2026-VULN" (read)
- [ ] 11.2.4 Characteristic: Firmware Revision (0x2A26) = "1.0.0" (read)
- [ ] 11.2.5 Characteristic: Software Revision (0x2A28) = "BlueZ 5.66" (read)
- [ ] 11.2.6 Characteristic: PnP ID (0x2A50) = packed bytes: source=1, VID=0x0046, PID=0x0001, ver=0x0100 (read)
- [ ] 11.2.7 All characteristics: properties = ["read"]

### Story 11.3: Battery Service (0x180F)
- [ ] 11.3.1 Implement `BatteryService` with UUID `180F`
- [ ] 11.3.2 Characteristic: Battery Level (0x2A19) = 85 (uint8, read + notify)
- [ ] 11.3.3 Implement `ReadValue()` → return `[dbus.Byte(85)]`
- [ ] 11.3.4 Implement `StartNotify()` / `StopNotify()` for notification support
- [ ] 11.3.5 Optional: timer that changes battery level periodically (simulate drain)

### Story 11.4: Custom IVI Service
- [ ] 11.4.1 Implement custom service with UUID `12345678-1234-5678-1234-56789abcdef0`
- [ ] 11.4.2 Characteristic: Vehicle Speed — UUID `12345678-1234-5678-1234-56789abcdef1` (read)
- [ ] 11.4.3 Value: `[0x00, 0x00]` (uint16 = 0 km/h, parked)
- [ ] 11.4.4 Characteristic: Diagnostic Data — UUID `12345678-1234-5678-1234-56789abcdef2` (read + write)
- [ ] 11.4.5 Read returns: `b"DTC:P0000 OK"` (no diagnostic trouble codes)
- [ ] 11.4.6 Write accepts any data, logs it: `[BLE] Diagnostic write: <hex>`
- [ ] 11.4.7 Characteristic: OTA Update — UUID `12345678-1234-5678-1234-56789abcdef3` (write)
- [ ] 11.4.8 Intentionally open — no authentication required (attack surface)
- [ ] 11.4.9 Write logs: `[BLE] OTA write attempt: <hex> — VULN: no auth!`

### Story 11.5: BLE Advertising
- [ ] 11.5.1 Implement `Advertisement(dbus.service.Object)` for LE advertising
- [ ] 11.5.2 Set advertising type: `peripheral`
- [ ] 11.5.3 Set local name: "SYNC" (matches Classic name)
- [ ] 11.5.4 Include service UUIDs: 0x180A, 0x180F, custom UUID
- [ ] 11.5.5 Register with `org.bluez.LEAdvertisingManager1`
- [ ] 11.5.6 Handle adapter not supporting LE (log warning, don't crash)

### Story 11.6: GATT Server Lifecycle
- [ ] 11.6.1 Main loop using GLib.MainLoop()
- [ ] 11.6.2 Signal handler for SIGINT/SIGTERM → clean shutdown
- [ ] 11.6.3 Unregister application and advertisement on shutdown
- [ ] 11.6.4 Can run standalone or be imported/started by ivi_daemon.py

---

## Epic 12: Pairing Agent

### Story 12.1: D-Bus Agent Implementation
- [ ] 12.1.1 Create `target/pin_agent.py`
- [ ] 12.1.2 Import dbus, dbus.service, dbus.mainloop.glib
- [ ] 12.1.3 Implement `IVIPairingAgent(dbus.service.Object)` on path `/ivi/agent`
- [ ] 12.1.4 Implement `RequestPinCode(device) -> str` — return "1234"
- [ ] 12.1.5 Implement `RequestPasskey(device) -> uint32` — return 1234
- [ ] 12.1.6 Implement `RequestConfirmation(device, passkey)` — auto-accept (SSP mode)
- [ ] 12.1.7 Implement `AuthorizeService(device, uuid)` — check bond state, reject unbonded
- [ ] 12.1.8 Implement `RequestAuthorization(device)` — check bond state, reject unbonded
- [ ] 12.1.9 Implement `DisplayPinCode(device, pincode)` — log only
- [ ] 12.1.10 Implement `DisplayPasskey(device, passkey, entered)` — log only
- [ ] 12.1.11 Implement `Cancel()` — log cancellation
- [ ] 12.1.12 Implement `Release()` — log release

### Story 12.2: Bond State Checking
- [ ] 12.2.1 Implement `_get_address(device_path) -> str` — extract MAC from D-Bus path
- [ ] 12.2.2 Implement `_is_bonded(addr) -> bool` — query `org.bluez.Device1.Paired` property
- [ ] 12.2.3 Handle D-Bus exceptions when device doesn't exist in BlueZ (return False)
- [ ] 12.2.4 Log bond check result: `[AUTH] XX:XX:XX:XX:XX:XX bonded=True|False`

### Story 12.3: Agent Registration
- [ ] 12.3.1 Get `org.bluez.AgentManager1` interface
- [ ] 12.3.2 Register agent with capability "KeyboardDisplay" (supports PIN + confirmation)
- [ ] 12.3.3 Request default agent
- [ ] 12.3.4 Handle registration failure (another agent already registered)
- [ ] 12.3.5 GLib main loop for D-Bus event processing
- [ ] 12.3.6 Clean unregister on SIGINT/SIGTERM

### Story 12.4: Profile-Aware Behavior
- [ ] 12.4.1 Read `.ivi_profile` on startup
- [ ] 12.4.2 If legacy: `RequestPinCode` returns "1234"
- [ ] 12.4.3 If ssp: `RequestConfirmation` auto-accepts (Just Works)
- [ ] 12.4.4 Both modes: `AuthorizeService` checks bond state
- [ ] 12.4.5 Log which mode is active

---

## Epic 13: IVI Daemon Main Orchestrator

### Story 13.1: Process Startup
- [ ] 13.1.1 Create `target/ivi_daemon.py` main entry point
- [ ] 13.1.2 Parse CLI arguments (Story 1.4)
- [ ] 13.1.3 Check root: `os.geteuid() == 0` (required for RFCOMM/L2CAP bind)
- [ ] 13.1.4 Verify data directory exists and has generated data
- [ ] 13.1.5 Read `.ivi_profile` to determine active profile
- [ ] 13.1.6 Print startup banner with IVI name, MAC, profile, channels

### Story 13.2: RFCOMM Listener Manager
- [ ] 13.2.1 Implement `RFCOMMListener` class — manages a single RFCOMM channel
- [ ] 13.2.2 `socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)`
- [ ] 13.2.3 `bind(("", channel))`
- [ ] 13.2.4 `listen(1)`
- [ ] 13.2.5 Accept loop in dedicated thread
- [ ] 13.2.6 On accept: spawn handler thread with the right protocol handler
- [ ] 13.2.7 Handle EADDRINUSE: log, skip channel
- [ ] 13.2.8 Handle multiple sequential connections (accept loop continues)
- [ ] 13.2.9 Handle simultaneous connections on same channel (one at a time is OK for testing)

### Story 13.3: Service Registration
- [ ] 13.3.1 Start RFCOMM listener on channel 1 (SPP) with AT engine
- [ ] 13.3.2 Start RFCOMM listener on channel 2 (hidden) with absorber
- [ ] 13.3.3 Start RFCOMM listener on channel 9 (OPP) with OBEX engine
- [ ] 13.3.4 Start RFCOMM listener on channel 10 (HFP) with AT engine
- [ ] 13.3.5 Start RFCOMM listener on channel 15 (PBAP) with OBEX engine
- [ ] 13.3.6 Start RFCOMM listener on channel 16 (MAP) with OBEX engine
- [ ] 13.3.7 Start L2CAP listeners on PSMs 7, 23, 25
- [ ] 13.3.8 Optionally start BLE GATT server (unless --no-ble)
- [ ] 13.3.9 Print "IVI ready" with list of all active services

### Story 13.4: Signal Handling & Shutdown
- [ ] 13.4.1 Register SIGINT handler (Ctrl+C)
- [ ] 13.4.2 Register SIGTERM handler
- [ ] 13.4.3 On shutdown: close all RFCOMM sockets
- [ ] 13.4.4 On shutdown: close all L2CAP sockets
- [ ] 13.4.5 On shutdown: stop BLE GATT server
- [ ] 13.4.6 On shutdown: join all threads (timeout 3s each)
- [ ] 13.4.7 Print shutdown summary: connections served, files received, attacks detected

### Story 13.5: Connection Logging
- [ ] 13.5.1 Track total connections per channel
- [ ] 13.5.2 Track unique remote addresses
- [ ] 13.5.3 Track bytes transferred per service
- [ ] 13.5.4 Print periodic status (every 60s or on SIGUSR1)
- [ ] 13.5.5 Log all activity to `target/ivi_daemon.log` (append mode)

---

## Epic 14: Integration & Verification

### Story 14.1: End-to-End Smoke Test Script
- [ ] 14.1.1 Create `target/test_ivi.sh` — runs on attacker machine
- [ ] 14.1.2 Accept IVI_MAC as argument
- [ ] 14.1.3 Test 1: `hcitool scan | grep SYNC` — discovery
- [ ] 14.1.4 Test 2: `sdptool browse $MAC | grep -c "Service Name"` — SDP (expect 8+)
- [ ] 14.1.5 Test 3: `hcitool info $MAC` — get device info (class, LMP version)
- [ ] 14.1.6 Test 4 (if bt-tap available): `bt-tap recon rfcomm-scan $MAC`
- [ ] 14.1.7 Test 5 (if bt-tap available): `bt-tap recon l2cap-scan $MAC`
- [ ] 14.1.8 Print pass/fail summary

### Story 14.2: OBEX Protocol Verification
- [ ] 14.2.1 Manual test: `bt-tap pbap pull $MAC` — verify 50 contacts downloaded
- [ ] 14.2.2 Manual test: `bt-tap map pull $MAC` — verify messages downloaded
- [ ] 14.2.3 Manual test: `bt-tap opp push $MAC test.vcf` — verify file received
- [ ] 14.2.4 Verify chunked transfer works for large phonebook (>4KB)
- [ ] 14.2.5 Verify ConnectionID is echoed correctly

### Story 14.3: AT Command Verification
- [ ] 14.3.1 Manual test: `bt-tap hfp setup $MAC` — SLC completes
- [ ] 14.3.2 Verify all 5 SLC steps succeed (BRSF, CIND=?, CIND?, CMER, CHLD)
- [ ] 14.3.3 Test AT+COPS?, AT+CNUM return realistic data
- [ ] 14.3.4 Test bluesnarfer AT commands on channel 1

### Story 14.4: Vuln-Scanner Verification
- [ ] 14.4.1 Run `bt-tap vuln-scan $MAC` — document all findings
- [ ] 14.4.2 Verify CRITICAL: Unauthenticated OBEX Access present
- [ ] 14.4.3 Verify Hidden RFCOMM finding (channel 2)
- [ ] 14.4.4 Verify Service Exposure findings
- [ ] 14.4.5 Compare actual findings against detect mode predictions

### Story 14.5: Pairing & Hijack Verification
- [ ] 14.5.1 Test PIN brute force (if legacy mode): verify PIN 1234 found
- [ ] 14.5.2 Test unauthorized access: connect with random MAC → verify rejected
- [ ] 14.5.3 Test hijack: spoof phone MAC → verify auto-authorized
- [ ] 14.5.4 Test full hijack chain: `bt-tap hijack $IVI_MAC $PHONE_MAC`

### Story 14.6: Fuzz Resilience
- [ ] 14.6.1 Run `bt-tap fuzz $MAC` — L2CAP null flood
- [ ] 14.6.2 Run `bt-tap fuzz $MAC` — malformed packets
- [ ] 14.6.3 Verify IVI daemon stays running after each fuzz
- [ ] 14.6.4 Verify other services still work after fuzz

### Story 14.7: BLE Verification
- [ ] 14.7.1 Run `bt-tap recon gatt $MAC`
- [ ] 14.7.2 Verify Device Information Service discovered
- [ ] 14.7.3 Verify Battery Level reads 85%
- [ ] 14.7.4 Verify custom characteristics readable/writable

---

## Epic 15: Documentation

### Story 15.1: README
- [ ] 15.1.1 Create `target/README.md`
- [ ] 15.1.2 Write quick-start section: 3-command setup
- [ ] 15.1.3 Document prerequisites (BlueZ, Python, root)
- [ ] 15.1.4 Document `setup_ivi.sh` arguments and profiles
- [ ] 15.1.5 Document `ivi_daemon.py` arguments
- [ ] 15.1.6 Document expected `bt-tap` commands and their results
- [ ] 15.1.7 Document troubleshooting: SSP, adapter not found, PSM bind failure
- [ ] 15.1.8 Document Raspberry Pi specific notes
- [ ] 15.1.9 Document the trust model and hijack test flow
- [ ] 15.1.10 Add architecture diagram

---

## Implementation Order (Critical Path)

```
Phase 1: Epic 1 (scaffolding) + Epic 2 (data gen)     ← no BT needed, testable offline
Phase 2: Epic 3 (setup_ivi.sh)                         ← configures real adapter
Phase 3: Epic 12 (pin_agent.py)                        ← needed before connections
Phase 4: Epic 4 (OBEX engine)                          ← shared by PBAP/MAP/OPP
Phase 5: Epic 5 (PBAP) → Epic 6 (MAP) → Epic 7 (OPP)  ← build on OBEX engine
Phase 6: Epic 8 (HFP) + Epic 9 (SPP)                  ← AT engine shared
Phase 7: Epic 10 (L2CAP) + Epic 11 (BLE GATT)          ← independent, parallel
Phase 8: Epic 13 (orchestrator)                         ← ties everything together
Phase 9: Epic 14 (verification) + Epic 15 (docs)       ← final validation
```

## Task Count Summary

| Epic | Stories | Tasks |
|------|---------|-------|
| 1. Scaffolding | 4 | 44 |
| 2. Data Generation | 6 | 45 |
| 3. Setup Script | 9 | 47 |
| 4. OBEX Engine | 5 | 44 |
| 5. PBAP Server | 4 | 21 |
| 6. MAP Server | 6 | 18 |
| 7. OPP Server | 2 | 11 |
| 8. HFP AT Responder | 8 | 28 |
| 9. SPP AT Responder | 4 | 18 |
| 10. L2CAP Listeners | 4 | 14 |
| 11. BLE GATT | 6 | 25 |
| 12. Pairing Agent | 4 | 19 |
| 13. Daemon Orchestrator | 5 | 22 |
| 14. Integration Tests | 7 | 22 |
| 15. Documentation | 1 | 10 |
| **Total** | **75** | **388** |
