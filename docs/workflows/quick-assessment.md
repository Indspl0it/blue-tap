# Quick Assessment Workflow

## Scenario

You have 5 minutes with a Bluetooth target in range. Maybe you spotted an in-vehicle infotainment (IVI) system in a client's parking lot during a physical security assessment, or a smart lock on a conference room door during a red team engagement. You need to answer one question fast: **is this target worth a deeper look?**

This workflow is your triage pass. It identifies exposed services, open channels, and known CVEs without modifying the target's state or triggering pairing prompts. Everything here is either passive or non-intrusive active probing.

**Time estimate:** ~5 minutes
**Risk level:** Low (passive + non-intrusive active probes)

!!! note "Prerequisites"
    - **Root access** on your assessment machine
    - **Bluetooth adapter** (hci0) -- any USB dongle works, DarkFirmware not required
    - **Target in range** (~10 meters for Class 2 devices)
    - No pairing required -- all steps work against unpaired targets

---

## Step 1: Discover Nearby Targets

Scan for both Classic and BLE devices in the area:

```bash
$ sudo blue-tap discover all -d 10
[*] Starting combined Classic + BLE discovery (10s)...
[*] Adapter: hci0 (Cambridge Silicon Radio)

  # | MAC               | Name              | Type    | CoD         | RSSI
 ---|-------------------|-------------------|---------|-------------|------
  1 | AA:BB:CC:DD:EE:FF | IVI-Headunit      | Classic | 0x240404    | -42
  2 | 11:22:33:44:55:66 | Galaxy S24        | Dual    | 0x5A020C    | -58
  3 | 77:88:99:AA:BB:CC | [BLE] TireMonitor | BLE     | --          | -71
  4 | DD:EE:FF:00:11:22 | JBL Flip 6        | Classic | 0x240418    | -63

[+] Found 4 devices in 10.0s
[*] Session: bt-20260416-091523
```

**What happened:** Blue-Tap ran simultaneous Classic inquiry and BLE passive scanning for 10 seconds. The output shows every discoverable device with its MAC address, advertised name, transport type (Classic/BLE/Dual), Class of Device code, and signal strength (RSSI).

**Decision point:**

- **If your target appears in the list** -- note its MAC address and proceed to Step 2.
- **If your target does not appear** -- it may be in non-discoverable mode. Try `sudo blue-tap discover classic -d 30` for a longer scan window, or use `sudo blue-tap recon <MAC> sdp` directly if you already know the MAC from other intelligence (e.g., packet capture, asset inventory).

For this walkthrough, our target is `IVI-Headunit` at `AA:BB:CC:DD:EE:FF`.

---

## Step 2: Enumerate SDP Services

Query the target's Service Discovery Protocol database to see what it advertises:

```bash
$ sudo blue-tap recon AA:BB:CC:DD:EE:FF sdp
[*] Querying SDP services on AA:BB:CC:DD:EE:FF (IVI-Headunit)...

  # | Service                    | UUID   | Channel/PSM | Auth Required
 ---|----------------------------|--------|-------------|---------------
  1 | Headset Gateway            | 0x1112 | RFCOMM 2    | Yes
  2 | Handsfree                  | 0x111F | RFCOMM 3    | Yes
  3 | A2DP Source                | 0x110A | AVDTP       | Yes
  4 | AVRCP Target               | 0x110C | AVCTP       | Yes
  5 | PBAP Server                | 0x112F | RFCOMM 15   | Yes
  6 | MAP Server                 | 0x1132 | RFCOMM 16   | Yes
  7 | OBEX Object Push           | 0x1105 | RFCOMM 12   | No
  8 | Serial Port                | 0x1101 | RFCOMM 1    | No
  9 | PnP Information            | 0x1200 | --          | --

[+] 9 services found. 2 services exposed without authentication.
[*] PnP: Vendor=0x001D (Qualcomm), Product=0x1200, Version=5.2
```

**What happened:** Blue-Tap connected to the SDP server on the target (no pairing needed -- SDP is always accessible) and retrieved every advertised service record. Each record shows the service name, UUID, the transport channel it listens on, and whether it requires authentication.

**Decision point:**

- **If you see services marked "Auth Required: No"** -- these are immediately accessible without pairing. OBEX Object Push and Serial Port without auth are significant findings.
- **If all services require auth** -- you'll need to pair first for post-exploitation. Note the services for later and continue to Step 3.

!!! tip
    The PnP Information record reveals the chipset vendor and Bluetooth version. `Qualcomm` + `Version 5.2` narrows down which CVEs apply. A device advertising Bluetooth 4.x or earlier is likely missing years of security patches.

---

## Step 3: Scan L2CAP PSMs

Probe L2CAP Protocol/Service Multiplexer values to find open channels, including those **not advertised** via SDP:

```bash
$ sudo blue-tap recon AA:BB:CC:DD:EE:FF l2cap
[*] Probing L2CAP PSMs on AA:BB:CC:DD:EE:FF...

  PSM    | Status     | Service          | Auth | Notes
 --------|------------|------------------|------|------------------
  0x0001 | Open       | SDP              | No   | Expected
  0x0003 | Open       | RFCOMM           | Yes  | Multiplexed
  0x000F | Open       | BNEP             | No   | Network access!
  0x0017 | Open       | AVCTP            | Yes  | A/V control
  0x0019 | Open       | AVDTP            | Yes  | A/V data
  0x001B | Rejected   | ATT              | --   | Classic only
  0x1001 | Open       | Unknown          | No   | Vendor-specific
  0x1003 | Open       | Unknown          | No   | Vendor-specific

[+] 8 PSMs probed. 4 open without authentication.
[!] WARNING: 2 unknown vendor-specific PSMs open without authentication.
```

**What happened:** Blue-Tap sent L2CAP connection requests to a range of standard and common vendor-specific PSMs. For each, it reports whether the connection was accepted or rejected, and whether authentication was required. This catches services that are listening but not advertised in SDP -- a common oversight on embedded devices.

**Decision point:**

- **If you see unknown PSMs accepting unauthenticated connections** -- these are high-value targets for fuzzing. Vendor-specific PSMs often lack hardening.
- **If BNEP (0x000F) is open without auth** -- the device may allow Bluetooth networking access, which could be a lateral movement path.

**Reference: Common PSM values**

| PSM | Service | Notes |
|-----|---------|-------|
| 0x0001 | SDP | Always open |
| 0x0003 | RFCOMM | Serial channels |
| 0x000F | BNEP | Bluetooth networking |
| 0x0017 | AVCTP | Audio/video control |
| 0x0019 | AVDTP | Audio/video data |
| 0x001B | ATT | BLE attribute protocol |

!!! warning
    Unauthenticated L2CAP channels that accept connections without pairing are high-value findings. They represent attack surface accessible to any device in radio range.

---

## Step 4: Run Vulnerability Checks

Run all registered CVE and non-CVE assessment checks against the target:

```bash
$ sudo blue-tap vulnscan AA:BB:CC:DD:EE:FF
[*] Running vulnerability assessment on AA:BB:CC:DD:EE:FF (IVI-Headunit)
[*] 23 checks registered, 19 applicable to this target

  Check                       | CVE             | Outcome        | Severity
 -----------------------------|-----------------|----------------|----------
  SDP Info Leak               | CVE-2017-0785   | confirmed      | HIGH
  L2CAP Buffer Overflow       | CVE-2017-1000251| not_applicable | --
  BlueFrag                    | CVE-2020-0022   | not_applicable | --
  KNOB Key Negotiation        | CVE-2019-9506   | confirmed      | HIGH
  HID Injection               | CVE-2023-45866  | inconclusive   | MEDIUM
  BLUFFS Session Key          | CVE-2023-24023  | confirmed      | CRITICAL
  BLE SMP Pairing Bypass      | CVE-2020-26558  | not_applicable | --
  BIAS Impersonation          | CVE-2020-10135  | confirmed      | HIGH
  SSP Enforcement             | non-cve         | confirmed      | MEDIUM
  OBEX Auth Bypass            | non-cve         | confirmed      | HIGH
  Legacy PIN Pairing          | non-cve         | confirmed      | MEDIUM
  ...                         | ...             | ...            | ...

[+] Assessment complete: 6 confirmed, 1 inconclusive, 12 not_applicable
[!] CRITICAL: 1 | HIGH: 3 | MEDIUM: 2
```

**What happened:** Blue-Tap ran each assessment check sequentially. Checks that don't apply to this target's profile (e.g., BLE-only checks against a Classic device) are automatically skipped as `not_applicable`. Each check reports one of four outcomes:

| Outcome | Meaning |
|---------|---------|
| `confirmed` | Vulnerability is present and exploitable |
| `inconclusive` | Could not determine; manual investigation needed |
| `pairing_required` | Check requires an active pairing to complete |
| `not_applicable` | Target is not affected (wrong profile, patched, etc.) |

**Decision point:**

- **If you see `confirmed` results** -- document the finding immediately. You have actionable vulnerabilities.
- **If you see `inconclusive` results** -- re-run with `sudo blue-tap vulnscan AA:BB:CC:DD:EE:FF --active` which sends crafted packets to confirm (slightly higher risk).
- **If everything is `not_applicable`** -- the target may be well-patched, or it may use protocols your checks don't cover yet. Consider fuzzing.

!!! danger
    A `confirmed` result means the target is vulnerable. Document the finding and proceed to exploitation only with authorization.

---

## Step 5: Generate Report

Produce an HTML report covering all results from this session:

```bash
$ sudo blue-tap report --format html -o assessment.html
[*] Generating report for session bt-20260416-091523...
[*] Aggregating: 1 discovery, 2 recon, 1 vulnscan
[+] Report written to assessment.html (47 KB)
```

**What happened:** Blue-Tap aggregated all results from the current session -- discovery, SDP enumeration, L2CAP scan, and vulnerability assessment -- into a single HTML report with findings, evidence, and severity ratings. This is your deliverable for the triage.

---

## Summary

In under 5 minutes, you have:

- Identified all discoverable Bluetooth devices in range
- Enumerated the target's advertised services and transport channels
- Found hidden L2CAP services not listed in SDP
- Checked for 19+ known vulnerabilities and posture weaknesses
- Generated a portable HTML report with all findings

This gives you a clear go/no-go decision: either the target warrants a full penetration test, or it's sufficiently hardened to deprioritize.

---

## What's Next?

| Finding | Recommended follow-up |
|---------|-----------------------|
| Confirmed CVE (KNOB, BLUFFS) | [Encryption Downgrade Workflow](encryption-downgrade.md) -- full exploitation chain |
| Open OBEX/PBAP without auth | [Full Penetration Test](full-pentest.md) -- post-exploitation data extraction |
| Unknown vendor-specific PSMs | [Fuzzing Campaign](fuzzing-campaign.md) -- discover new vulnerabilities |
| Multiple confirmed findings | [Full Penetration Test](full-pentest.md) -- systematic assessment |
| Inconclusive results | Re-run with `--active` flag or see [Custom Playbooks](custom-playbooks.md) for targeted re-testing |
| Clean target, want to verify | [Fuzzing Campaign](fuzzing-campaign.md) -- stress-test for unknown bugs |
