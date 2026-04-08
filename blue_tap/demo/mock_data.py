"""Realistic mock data for Blue-Tap demo mode.

Simulates a Harman Kardon automotive IVI head unit (BT Classic)
paired with a Samsung Galaxy S24, plus nearby ambient devices.
All data mirrors real-world Bluetooth pentest outputs.
"""

# ── Target IVI System ────────────────────────────────────────────────────
IVI_ADDRESS = "4C:87:5D:A1:3E:F0"
IVI_NAME = "Harman-IVI-2024"
IVI_HCI = "hci0"

PHONE_ADDRESS = "B8:27:EB:6C:D4:22"
PHONE_NAME = "Galaxy S24"

# ── Discovered Devices (Phase 1) ─────────────────────────────────────────
SCAN_DEVICES = [
    {
        "address": IVI_ADDRESS,
        "name": IVI_NAME,
        "rssi": -42,
        "type": "Classic",
        "class_info": {
            "major": "Audio/Video",
            "minor": "Car Audio",
            "raw": "0x240404",
            "is_phone": False,
        },
        "distance_m": 0.8,
    },
    {
        "address": PHONE_ADDRESS,
        "name": PHONE_NAME,
        "rssi": -51,
        "type": "Classic",
        "class_info": {
            "major": "Phone",
            "minor": "Smartphone",
            "raw": "0x5a020c",
            "is_phone": True,
        },
        "distance_m": 1.5,
    },
    {
        "address": "F4:5C:89:B2:71:AA",
        "name": "JBL Flip 6",
        "rssi": -67,
        "type": "Classic",
        "class_info": {
            "major": "Audio/Video",
            "minor": "Loudspeaker",
            "raw": "0x240414",
            "is_phone": False,
        },
        "distance_m": 4.2,
    },
    {
        "address": "D0:03:4B:E8:55:10",
        "name": "TPMS-Sensor-FL",
        "rssi": -78,
        "type": "BLE",
        "class_info": {"major": "Miscellaneous", "minor": "Unknown"},
        "distance_m": 1.2,
    },
    {
        "address": "C8:69:CD:3A:90:F7",
        "name": "OBD-Link MX+",
        "rssi": -63,
        "type": "Classic",
        "class_info": {
            "major": "Networking",
            "minor": "Unknown",
            "raw": "0x001f00",
            "is_phone": False,
        },
        "distance_m": 0.6,
    },
]

# ── Fingerprint (Phase 2) ────────────────────────────────────────────────
FINGERPRINT = {
    "name": IVI_NAME,
    "address": IVI_ADDRESS,
    "bt_version": "5.1",
    "lmp_version": "11",
    "lmp_subversion": "0x6109",
    "manufacturer": "Harman International (69)",
    "manufacturer_id": 69,
    "chipset": "Qualcomm QCA6390",
    "profiles": [
        "A2DP Sink (0x110b)",
        "A2DP Source (0x110a)",
        "AVRCP Target (0x110c)",
        "AVRCP Controller (0x110e)",
        "HFP Audio Gateway (0x111f)",
        "PBAP Server (0x112f)",
        "MAP Server (0x1132)",
        "SPP (0x1101)",
        "PAN NAP (0x1116)",
        "OPP Server (0x1105)",
    ],
    "attack_surface": [
        "PBAP (phonebook access)",
        "MAP (message access)",
        "HFP (hands-free control)",
        "A2DP (audio streaming)",
        "SPP (serial port)",
        "OPP (object push)",
    ],
    "features": {
        "secure_simple_pairing": True,
        "le_supported": True,
        "encryption": True,
        "secure_connections": False,
        "role_switch": True,
        "sniff_mode": True,
        "esco_links": True,
        "edr_2mbps": True,
        "edr_3mbps": True,
    },
    "vuln_hints": [
        "Secure Connections not supported - legacy pairing may be negotiated",
        "BT 5.1 with LMP 11 - affected by CVE-2023-24023 (BLUFFS) range",
        "PBAP + MAP exposed - phonebook and message extraction possible",
    ],
    "security_posture": {
        "authentication_required": True,
        "encryption_required": True,
        "min_encryption_key_size": 7,
        "secure_connections_host_support": False,
        "secure_connections_only_mode": False,
        "io_capability": "DisplayYesNo",
        "oob_data_present": False,
    },
}

# ── SDP Services (Phase 3) ───────────────────────────────────────────────
SDP_SERVICES = [
    {"name": "Headset Audio Gateway", "protocol": "RFCOMM", "channel": 1,
     "profile": "HFP AG", "profile_version": "1.7"},
    {"name": "Phonebook Access PSE", "protocol": "RFCOMM", "channel": 19,
     "profile": "PBAP", "profile_version": "1.2"},
    {"name": "Message Access Server", "protocol": "RFCOMM", "channel": 20,
     "profile": "MAP", "profile_version": "1.4"},
    {"name": "OBEX Object Push", "protocol": "RFCOMM", "channel": 12,
     "profile": "OPP", "profile_version": "1.2"},
    {"name": "Audio Source", "protocol": "L2CAP", "channel": 25,
     "profile": "A2DP Source", "profile_version": "1.3"},
    {"name": "Audio Sink", "protocol": "L2CAP", "channel": 25,
     "profile": "A2DP Sink", "profile_version": "1.3"},
    {"name": "AV Remote Control Target", "protocol": "L2CAP", "channel": 23,
     "profile": "AVRCP", "profile_version": "1.6"},
    {"name": "AV Remote Control Controller", "protocol": "L2CAP", "channel": 23,
     "profile": "AVRCP", "profile_version": "1.6"},
    {"name": "Serial Port", "protocol": "RFCOMM", "channel": 3,
     "profile": "SPP", "profile_version": "1.2"},
    {"name": "PAN Network Access Point", "protocol": "L2CAP", "channel": 15,
     "profile": "PAN NAP", "profile_version": "1.0"},
    {"name": "Hands-Free", "protocol": "RFCOMM", "channel": 6,
     "profile": "HFP", "profile_version": "1.7"},
    {"name": "SIM Access", "protocol": "RFCOMM", "channel": 8,
     "profile": "SAP", "profile_version": "1.1"},
]

RFCOMM_CHANNELS = [
    {"channel": 1, "status": "open", "service": "HFP AG"},
    {"channel": 2, "status": "closed"},
    {"channel": 3, "status": "open", "service": "SPP"},
    {"channel": 4, "status": "closed"},
    {"channel": 5, "status": "closed"},
    {"channel": 6, "status": "open", "service": "HFP"},
    {"channel": 7, "status": "closed"},
    {"channel": 8, "status": "open", "service": "SAP"},
    {"channel": 9, "status": "closed"},
    {"channel": 10, "status": "closed"},
    {"channel": 11, "status": "closed"},
    {"channel": 12, "status": "open", "service": "OPP"},
    {"channel": 13, "status": "closed"},
    {"channel": 14, "status": "closed"},
    {"channel": 15, "status": "closed"},
    {"channel": 16, "status": "closed"},
    {"channel": 17, "status": "closed"},
    {"channel": 18, "status": "closed"},
    {"channel": 19, "status": "open", "service": "PBAP"},
    {"channel": 20, "status": "open", "service": "MAP"},
    {"channel": 21, "status": "closed"},
    {"channel": 22, "status": "closed"},
    {"channel": 23, "status": "closed"},
    {"channel": 24, "status": "closed"},
    {"channel": 25, "status": "closed"},
    {"channel": 26, "status": "closed"},
    {"channel": 27, "status": "closed"},
    {"channel": 28, "status": "closed"},
    {"channel": 29, "status": "closed"},
    {"channel": 30, "status": "closed"},
]

L2CAP_RESULTS = [
    {"psm": 1, "name": "SDP", "status": "open"},
    {"psm": 3, "name": "RFCOMM", "status": "open"},
    {"psm": 15, "name": "BNEP", "status": "open"},
    {"psm": 17, "name": "HIDP (Control)", "status": "closed"},
    {"psm": 19, "name": "HIDP (Interrupt)", "status": "closed"},
    {"psm": 23, "name": "AVCTP (Browsing)", "status": "open"},
    {"psm": 25, "name": "AVDTP", "status": "open"},
    {"psm": 0x1001, "name": "Dynamic (A2DP)", "status": "open"},
    {"psm": 0x1003, "name": "Dynamic (AVRCP)", "status": "open"},
    {"psm": 0x1005, "name": "Dynamic (MAP)", "status": "auth_required"},
]

# ── Vulnerability Findings (Phase 4) ─────────────────────────────────────
VULN_FINDINGS = [
    {
        "name": "BLUFFS Session Key Derivation (CVE-2023-24023)",
        "severity": "CRITICAL",
        "status": "confirmed",
        "cve": "CVE-2023-24023",
        "description": "Target accepts session key derivation with entropy reduced to 1 byte. "
                       "Attacker can brute-force session keys in real-time.",
        "evidence": "LMP_encryption_key_size_req accepted min_key_size=1",
        "remediation": "Update firmware to enforce minimum 16-byte entropy per BT 5.4 spec",
    },
    {
        "name": "KNOB Attack (CVE-2019-9506)",
        "severity": "CRITICAL",
        "status": "confirmed",
        "cve": "CVE-2019-9506",
        "description": "Target negotiates encryption key to 1 byte when requested. "
                       "Allows real-time brute force of all encrypted communications.",
        "evidence": "Accepted LMP_encryption_key_size_req with key_size=1 (7 bytes below minimum)",
        "remediation": "Update Bluetooth firmware to enforce minimum 7-byte key length",
    },
    {
        "name": "SSP Downgrade to Legacy PIN",
        "severity": "HIGH",
        "status": "confirmed",
        "cve": "CVE-2020-26555",
        "description": "Target falls back to legacy PIN pairing when SSP is rejected. "
                       "PIN can be brute-forced (4 digits = 10,000 combinations).",
        "evidence": "Rejected SSP IO Capability, target initiated legacy PIN request",
        "remediation": "Disable legacy pairing fallback in IVI Bluetooth stack configuration",
    },
    {
        "name": "PBAP Server Accessible Without Re-auth",
        "severity": "HIGH",
        "status": "confirmed",
        "cve": None,
        "description": "Phonebook Access Profile accepts connections from previously paired "
                       "devices without re-authentication. Spoofed MAC can extract contacts.",
        "evidence": f"OBEX CONNECT to RFCOMM ch19 succeeded with spoofed MAC {PHONE_ADDRESS}",
        "remediation": "Require user confirmation for each PBAP session, not just initial pairing",
    },
    {
        "name": "MAP Server Message Extraction",
        "severity": "HIGH",
        "status": "confirmed",
        "cve": None,
        "description": "Message Access Profile allows bulk download of SMS/MMS messages "
                       "from paired phone via IVI relay without re-authentication.",
        "evidence": "OBEX GET on MAP ch20 returned inbox listing with 247 messages",
        "remediation": "Require explicit user authorization for MAP message access",
    },
    {
        "name": "Secure Connections Not Supported",
        "severity": "MEDIUM",
        "status": "confirmed",
        "cve": None,
        "description": "Target does not support Secure Connections (SC) mode, "
                       "leaving it vulnerable to MITM attacks on the pairing process.",
        "evidence": "LMP features page: secure_connections=0, sc_host_support=0",
        "remediation": "Enable Secure Connections support in Bluetooth controller firmware",
    },
    {
        "name": "Encryption Key Size Below Recommended Minimum",
        "severity": "MEDIUM",
        "status": "confirmed",
        "cve": None,
        "description": "Target accepts encryption key sizes as low as 7 bytes (56 bits), "
                       "below the recommended 16-byte minimum.",
        "evidence": "Negotiated encryption with key_size=7 (requested=16)",
        "remediation": "Configure minimum encryption key size to 16 bytes",
    },
    {
        "name": "SPP Channel Exposes Debug Interface",
        "severity": "MEDIUM",
        "status": "confirmed",
        "cve": None,
        "description": "Serial Port Profile on RFCOMM channel 3 accepts connections and "
                       "responds to AT-style debug commands (firmware version, memory dump).",
        "evidence": "SPP ch3: AT+VER returned 'HK-IVI-FW-2024.03.1-rel'",
        "remediation": "Disable debug SPP interface in production firmware builds",
    },
    {
        "name": "HFP AT Command Injection",
        "severity": "MEDIUM",
        "status": "probable",
        "cve": None,
        "description": "Hands-Free Profile accepts long AT command strings without proper "
                       "length validation. May allow buffer overflow on embedded parser.",
        "evidence": "AT+CHLD=? with 512-byte payload returned partial response (truncated)",
        "remediation": "Validate AT command input length in HFP parser",
    },
    {
        "name": "AVRCP Track Metadata Spoofing",
        "severity": "LOW",
        "status": "confirmed",
        "cve": None,
        "description": "AVRCP controller accepts metadata without validation, "
                       "allowing display of arbitrary text on IVI screen.",
        "evidence": "Injected track title displayed on IVI: 'PWNED_BY_BLUETAP'",
        "remediation": "Sanitize AVRCP metadata before rendering on display",
    },
    {
        "name": "OPP Server Accepts Files Without Confirmation",
        "severity": "LOW",
        "status": "confirmed",
        "cve": None,
        "description": "Object Push Profile accepts incoming vCard/vCalendar files "
                       "without user confirmation prompt.",
        "evidence": "OBEX PUT of test.vcf succeeded without IVI display prompt",
        "remediation": "Require user confirmation for incoming OPP file transfers",
    },
]

# ── SSP Downgrade Probe (Phase 5) ────────────────────────────────────────
SSP_PROBE_RESULT = {
    "target": IVI_ADDRESS,
    "ssp_supported": True,
    "io_capability": "DisplayYesNo",
    "legacy_fallback_possible": True,
    "oob_supported": False,
    "evidence": [
        "Sent IO_Capability_Negative_Reply",
        "Target initiated LMP_in_rand (legacy PIN request)",
        "Legacy PIN fallback confirmed after SSP rejection",
    ],
}

KNOB_PROBE_RESULT = {
    "target": IVI_ADDRESS,
    "likely_vulnerable": True,
    "min_accepted_key_size": 1,
    "max_key_size": 16,
    "negotiated_key_size": 1,
    "evidence": [
        "Sent LMP_encryption_key_size_req(key_size=1)",
        "Target accepted key_size=1 (vulnerable)",
        "Full key space: 256 values, brute-forceable in <1 second",
    ],
}

# ── Exploitation - PBAP Dump (Phase 6) ───────────────────────────────────
PBAP_CONTACTS = {
    "path": "telecom/pb",
    "count": 156,
    "sample_entries": [
        {"fn": "John Doe", "tel": "+1-555-0101", "email": "john.doe@example.com"},
        {"fn": "Jane Smith", "tel": "+1-555-0142", "email": "j.smith@corp.example.com"},
        {"fn": "Service Center", "tel": "+1-800-555-0199"},
        {"fn": "Mike Johnson", "tel": "+1-555-0178", "email": "mike.j@example.net"},
        {"fn": "Emergency Contact", "tel": "+1-555-0911"},
    ],
    "call_history": {
        "incoming": 43,
        "outgoing": 67,
        "missed": 12,
    },
}

MAP_MESSAGES = {
    "inbox_count": 247,
    "sent_count": 189,
    "sample_messages": [
        {"from": "+1-555-0142", "subject": "Meeting tomorrow",
         "snippet": "Hi, can we reschedule the 3pm meeting to...", "timestamp": "2024-03-15T14:22:00"},
        {"from": "+1-555-0101", "subject": "RE: Project update",
         "snippet": "Looks good. I'll review the PR tonight and...", "timestamp": "2024-03-15T13:05:00"},
        {"from": "+1-800-555-0199", "subject": "Service reminder",
         "snippet": "Your vehicle service is due on March 20th...", "timestamp": "2024-03-14T09:00:00"},
    ],
}

HIJACK_RESULT = {
    "status": "success",
    "target_ivi": IVI_ADDRESS,
    "impersonated_phone": PHONE_ADDRESS,
    "spoofed_name": PHONE_NAME,
    "duration_seconds": 34.2,
    "data_extracted": {
        "pbap_contacts": 156,
        "pbap_call_history": 122,
        "map_messages": 436,
        "opp_files_pushed": 0,
    },
    "profiles_accessed": ["PBAP", "MAP", "HFP"],
    "evidence": [
        f"MAC spoofed to {PHONE_ADDRESS}",
        "Paired without user interaction (cached link key)",
        "PBAP: 156 contacts + 122 call log entries extracted",
        "MAP: 247 inbox + 189 sent messages extracted",
        "HFP: AT command channel established",
    ],
}

# ── Fuzzing Results (Phase 7) ────────────────────────────────────────────
FUZZ_RESULTS = {
    "status": "success",
    "strategy": "coverage_guided",
    "duration_seconds": 120,
    "protocols_fuzzed": ["sdp", "rfcomm", "l2cap", "ble-att"],
    "packets_sent": 14_827,
    "crashes": 2,
    "unique_crashes": 2,
    "hangs": 1,
    "coverage_paths": 47,
    "state_transitions": 23,
    "anomalies_detected": 5,
    "protocol_stats": {
        "sdp": {"packets": 3_891, "crashes": 1, "coverage": 12},
        "rfcomm": {"packets": 4_102, "crashes": 0, "coverage": 14},
        "l2cap": {"packets": 3_980, "crashes": 1, "coverage": 11},
        "ble-att": {"packets": 2_854, "crashes": 0, "coverage": 10},
    },
    "crash_details": [
        {
            "id": "crash-001",
            "protocol": "sdp",
            "severity": "HIGH",
            "timestamp": "2024-03-15T15:42:18",
            "description": "SDP continuation state confusion: oversized continuation token "
                          "causes target to return corrupted service record",
            "input_hex": "0601002000240035031901000300190001000400080035050300190100090001"
                        "003500090065000945000000a00100",
            "response": "Target returned truncated response followed by disconnect",
            "reproduction": "Repeatable 3/3 attempts",
        },
        {
            "id": "crash-002",
            "protocol": "l2cap",
            "severity": "MEDIUM",
            "timestamp": "2024-03-15T15:48:33",
            "description": "L2CAP configuration option with invalid MTU causes "
                          "target to reset the ACL link after 3 retransmissions",
            "input_hex": "04050c0040000100020000000100020000",
            "response": "ACL link reset after 3 retransmission timeouts",
            "reproduction": "Repeatable 2/3 attempts",
        },
    ],
}

# ── DoS Results (Phase 8) ────────────────────────────────────────────────
DOS_RESULTS = [
    {
        "test": "L2CAP connection storm",
        "method": "l2cap_connection_storm",
        "result": "target_responsive",
        "packets_sent": 50,
        "response_time_ms": 145,
        "details": "Target handled 50 rapid L2CAP connections without degradation",
    },
    {
        "test": "L2CAP CID exhaustion",
        "method": "cid_exhaustion",
        "result": "target_degraded",
        "packets_sent": 100,
        "response_time_ms": 2340,
        "details": "After 78 concurrent CIDs, target response time increased 16x. "
                   "Recovered after 8 seconds.",
    },
    {
        "test": "SDP continuation exhaustion",
        "method": "sdp_continuation",
        "result": "target_unresponsive",
        "packets_sent": 5,
        "response_time_ms": -1,
        "details": "5 concurrent SDP connections with continuation tokens caused "
                   "target SDP server to stop responding. Bluetooth stack required restart.",
    },
    {
        "test": "RFCOMM SABM flood",
        "method": "rfcomm_sabm",
        "result": "target_responsive",
        "packets_sent": 30,
        "response_time_ms": 89,
        "details": "RFCOMM handled 30 rapid SABM frames without issues",
    },
    {
        "test": "HFP AT command flood",
        "method": "hfp_at_flood",
        "result": "target_degraded",
        "packets_sent": 1000,
        "response_time_ms": 890,
        "details": "After 600+ rapid AT commands, HFP response latency increased to 890ms. "
                   "Audio quality degraded during flood. Recovered within 3 seconds.",
    },
]

# ── LMP Capture Data ─────────────────────────────────────────────────────
LMP_CAPTURES = [
    {
        "opcode": "LMP_features_req",
        "direction": "tx",
        "timestamp": "2024-03-15T15:30:01.234",
        "raw_hex": "01003bfe8f0279038000",
        "decoded": {"features_page": 0, "features": "3bfe8f0279038000"},
    },
    {
        "opcode": "LMP_features_res",
        "direction": "rx",
        "timestamp": "2024-03-15T15:30:01.237",
        "raw_hex": "020007fe8f0278030000",
        "decoded": {"features_page": 0, "features": "07fe8f0278030000"},
    },
    {
        "opcode": "LMP_version_req",
        "direction": "tx",
        "timestamp": "2024-03-15T15:30:01.240",
        "raw_hex": "250b004500006109",
        "decoded": {"version": 11, "company_id": 69, "sub_version": "0x6109"},
    },
    {
        "opcode": "LMP_encryption_key_size_req",
        "direction": "tx",
        "timestamp": "2024-03-15T15:30:02.100",
        "raw_hex": "100001",
        "decoded": {"key_size": 1},
    },
    {
        "opcode": "LMP_accepted",
        "direction": "rx",
        "timestamp": "2024-03-15T15:30:02.103",
        "raw_hex": "030010",
        "decoded": {"opcode_accepted": "LMP_encryption_key_size_req"},
    },
]
