# Vulnerable IVI Simulator & Demo Mode

> **[Back to README](../README.md)**

Blue-Tap ships with a companion **Vulnerable IVI Simulator** in the `target/` directory. This is a real Bluetooth target (not a mock) that runs on any Linux machine with a Bluetooth adapter and behaves like an intentionally vulnerable car infotainment system.

### Purpose

- Practice Blue-Tap commands against a real target
- Demonstrate all attack vectors in a controlled environment
- Validate tool functionality without access to a real vehicle

### Quick Setup

Requires a **separate Linux machine** (Kali laptop, Raspberry Pi, or desktop with Bluetooth adapter).

```bash
# Terminal 1 — Configure adapter
cd target/
sudo ./setup_ivi.sh

# Terminal 2 — Start pairing agent
sudo python3 pin_agent.py

# Terminal 3 — Start IVI daemon
sudo python3 ivi_daemon.py

# Optional Terminal 4 — BLE GATT server
sudo python3 ble_gatt.py
```

### Exposed Services

| Service | Channel/PSM | Data |
|---------|-------------|------|
| PBAP (Phonebook) | RFCOMM 15 | 50 contacts, call history |
| MAP (Messages) | RFCOMM 16 | 20 SMS messages |
| OPP (Object Push) | RFCOMM 9 | Accepts any file |
| HFP (Hands-Free) | RFCOMM 10 | Full SLC handshake |
| SPP (Serial Port) | RFCOMM 1 | AT command responder |
| Hidden Debug | RFCOMM 2 | Not in SDP |
| BNEP (PAN) | L2CAP 7 | Fuzz absorber |
| AVCTP (AVRCP) | L2CAP 23 | Fuzz absorber |
| AVDTP (A2DP) | L2CAP 25 | Fuzz absorber |
| BLE GATT | Multiple | Device Info + Battery + Custom IVI |

### Built-in Vulnerabilities

| Vulnerability | What Blue-Tap Command Finds It |
|---------------|-------------------------------|
| Unauthenticated OBEX | `blue-tap vulnscan` → CRITICAL |
| Legacy PIN "1234" | `blue-tap dos pin-brute` |
| Just Works pairing (SSP) | `blue-tap vulnscan` → HIGH |
| No PIN rate limiting | `blue-tap vulnscan` → MEDIUM |
| Hidden RFCOMM channel | `blue-tap vulnscan` → MEDIUM |
| Permissive AT commands | `blue-tap at connect` |
| Unauthenticated BLE writes | `blue-tap recon gatt` |
| Hijack-vulnerable bond | `blue-tap hijack` |

See [`target/README.md`](target/README.md) for detailed setup instructions, architecture diagrams, and platform-specific notes.

---

## Demo Mode

Run a full simulated pentest with mock IVI data — no hardware or Bluetooth adapter required. Useful for demonstrations, CI pipelines, and validating report generation.

```bash
blue-tap demo                          # Output to demo_output/
blue-tap demo -o ./my-demo/            # Custom output directory
```

Generates complete HTML and JSON reports with simulated scan results, vulnerability findings, fingerprints, data extraction summaries, and fuzzing intelligence — identical in structure to a real assessment report.

---
