# DoS Check Matrix

`blue-tap dos` runs intrusive checks with recovery monitoring. 30 checks across 4 categories.

!!! danger "Intrusive by Design"
    DoS checks are intrusive. They may crash, freeze, or temporarily disable the target device. Use only with explicit authorization from the device owner. Running these checks against devices you do not own or have written authorization to test is illegal in most jurisdictions.

---

## Classic Checks (10)

These target the Classic Bluetooth (BR/EDR) stack. Most require only an L2CAP connection, which can be established without authentication.

| Check ID | CVE | Protocol | Severity | Description |
|----------|-----|----------|----------|-------------|
| cve_2017_0781_bnep_heap | CVE-2017-0781 | BNEP | :material-alert-circle:{ .critical } Critical | BNEP heap overflow via oversized control frame with uuid_size=0x10 |
| cve_2017_0782_bnep_underflow | CVE-2017-0782 | BNEP | :material-alert-circle:{ .critical } Critical | BNEP integer underflow via Filter Net Type Set with list_len=0xFFFF |
| cve_2022_39177_avdtp_setconf | CVE-2022-39177 | AVDTP | :material-alert:{ .high } High | Malformed AVDTP SET_CONFIGURATION with invalid MEDIA_CODEC capability length |
| cve_2023_27349_avrcp_event | CVE-2023-27349 | AVRCP | :material-alert-circle:{ .critical } Critical | REGISTER_NOTIFICATION with out-of-range event ID (0x0E); crashes bluetoothd |
| cve_2025_0084_sdp_race | CVE-2025-0084 | SDP | :material-alert:{ .high } High | SDP service search race condition via double SDP connection |
| cve_2025_48593_hfp_reconnect | CVE-2025-48593 | HFP | :material-alert:{ .high } High | HFP callback init UAF on rapid RFCOMM reconnect (requires existing bond) |
| l2ping_flood | -- | L2CAP | :material-information:{ .low } Low | L2CAP Echo Request flood |
| pair_flood | -- | Pairing | :material-alert-outline:{ .medium } Medium | Rapid pairing request flood |
| name_flood | -- | Classic | :material-information:{ .low } Low | Oversized/rapid remote name request flood |
| rate_test | -- | Classic | :material-information:{ .info } Info | Rate limiting detection (baseline measurement) |

## BLE Checks (2)

These target BLE (Bluetooth Low Energy) SoC firmware, primarily from the SweynTooth vulnerability family. They exploit parsing bugs in the BLE link layer and SMP implementations found in embedded chipsets (Telink, NXP, Cypress, Dialog, etc.).

| Check ID | CVE | Protocol | Severity | Description |
|----------|-----|----------|----------|-------------|
| cve_2019_19192_att_deadlock | CVE-2019-19192 | BLE ATT | :material-alert:{ .high } High | SweynTooth ATT sequential deadlock via duplicate MTU exchange + abrupt disconnect |
| cve_2019_19196_key_size | CVE-2019-19196 | BLE SMP | :material-alert:{ .high } High | SweynTooth key size overflow via SM_Pairing_Request with max_key_size=253 |

## Raw ACL Checks (1)

These operate below the L2CAP layer, injecting malformed ACL fragments directly. They require a DarkFirmware-capable adapter because the standard Linux HCI interface does not allow sending crafted ACL packets.

| Check ID | CVE | Protocol | Severity | Description |
|----------|-----|----------|----------|-------------|
| cve_2020_0022_bluefrag | CVE-2020-0022 | Raw ACL | :material-alert-circle:{ .critical } Critical | BlueFrag fragmentation boundary crash (requires DarkFirmware adapter) |

## Protocol Checks (17)

These are protocol-level stress tests that target common implementation weaknesses: resource exhaustion, state confusion, and malformed input handling. Most do not have specific CVE assignments but test for classes of bugs that are common across Bluetooth stacks.

| Check ID | CVE | Protocol | Severity | Description |
|----------|-----|----------|----------|-------------|
| hfp_at_flood | -- | HFP | :material-alert-outline:{ .medium } Medium | AT command flood over established HFP connection |
| hfp_slc_confuse | -- | HFP | :material-alert-outline:{ .medium } Medium | SLC renegotiation loop (Service Level Connection state confusion) |
| l2cap_cid_exhaust | -- | L2CAP | :material-alert-outline:{ .medium } Medium | Channel ID exhaustion via rapid L2CAP connection requests |
| l2cap_data_flood | -- | L2CAP | :material-alert-outline:{ .medium } Medium | Data packet flood on established L2CAP channel |
| l2cap_storm | -- | L2CAP | :material-alert-outline:{ .medium } Medium | Configuration option bomb (repeated CONF_REQ with unusual options) |
| lmp_detach_flood | -- | LMP | :material-alert:{ .high } High | LMP_DETACH flood (requires DarkFirmware for LMP injection) |
| lmp_encryption_toggle | -- | LMP | :material-alert:{ .high } High | Rapid encryption on/off toggle via LMP |
| lmp_features_flood | -- | LMP | :material-alert-outline:{ .medium } Medium | LMP features request flood |
| lmp_invalid_opcode | -- | LMP | :material-alert:{ .high } High | Invalid LMP opcode injection |
| lmp_switch_storm | -- | LMP | :material-alert:{ .high } High | Role switch storm via rapid LMP role-switch requests |
| lmp_timing_flood | -- | LMP | :material-alert-outline:{ .medium } Medium | Timing accuracy request flood |
| obex_connect_flood | -- | OBEX | :material-information:{ .low } Low | OBEX CONNECT request flood |
| rfcomm_mux_flood | -- | RFCOMM | :material-alert-outline:{ .medium } Medium | RFCOMM multiplexer flood |
| rfcomm_sabm_flood | -- | RFCOMM | :material-alert-outline:{ .medium } Medium | RFCOMM SABM (Set Asynchronous Balanced Mode) flood |
| sdp_continuation | -- | SDP | :material-alert-outline:{ .medium } Medium | SDP continuation state exhaustion (also CVE-2021-41229 attribution) |
| sdp_des_bomb | -- | SDP | :material-alert-outline:{ .medium } Medium | Nested Data Element Sequence bomb (deeply recursive DES structure) |

!!! info "LMP-level checks"
    LMP-level checks require a DarkFirmware-capable adapter (typically `hci1`) for below-HCI injection. See [Hardware Compatibility](../reference/hardware-compatibility.md).

### Severity Ratings

| Rating | Meaning |
|--------|---------|
| :material-alert-circle:{ .critical } **Critical** | Targets a known RCE or heap corruption CVE. High likelihood of device crash. |
| :material-alert:{ .high } **High** | Targets a known CVE or exploits a protocol state machine flaw. Likely to cause temporary unresponsiveness. |
| :material-alert-outline:{ .medium } **Medium** | Protocol stress test. May cause degraded performance or temporary unavailability on weaker implementations. |
| :material-information:{ .low } **Low** | Flood-based test. Unlikely to crash modern stacks but may reveal rate-limiting deficiencies. |
| :material-information:{ .info } **Info** | Baseline measurement only. Not intrusive. |

---

## Recovery Monitoring

After each intrusive check, Blue-Tap automatically runs transport-aware recovery probes to determine whether the target survived, crashed temporarily, or became permanently unresponsive. This is not just a pass/fail ping -- it is a structured monitoring sequence that provides forensic-quality data about the target's resilience.

### What Happens After Each Check

1. **Trigger phase**: The DoS payload is sent to the target.
2. **Initial probe**: Immediately after the trigger, Blue-Tap sends a lightweight connectivity check (L2CAP ping for Classic, advertisement scan for BLE).
3. **Recovery window**: If the initial probe fails, Blue-Tap enters a timed recovery loop, re-probing every few seconds.
4. **Stack validation**: Once connectivity returns, Blue-Tap sends a deeper probe (name request for Classic, ATT read for BLE) to confirm the full stack is functional -- not just the radio.
5. **Timeout**: If the target does not recover within the window, the run records the check as `unresponsive` and moves to the next check (or aborts if configured to do so).

### Recovery Probe Types

| Probe Type | Transport | What It Does |
|------------|-----------|--------------|
| L2CAP ping | Classic | Sends `l2ping` Echo Requests and checks for responses |
| Remote name | Classic | Requests the remote device name over HCI; success = reachable |
| Advertisement scan | BLE | Monitors for the target's BLE advertisements to reappear |
| ATT request | BLE | Sends an ATT Read Request after advertisements resume; confirms GATT stack is responsive (not just advertising) |
| Composite | Both | Combines multiple probes for dual-mode targets |

Default recovery timeout: **180 seconds**. If the target does not recover within this window, the run aborts remaining checks and records `interrupted_on` and `abort_reason` in the envelope.

---

## Result Semantics

| Status | Meaning |
|--------|---------|
| `success` | Target stayed responsive after the trigger completed |
| `unresponsive` | Target did not recover before the recovery timeout expired |
| `recovered` | Target became unavailable after the trigger but returned during the recovery window |
| `not_applicable` | A hard prerequisite was missing (DarkFirmware, pairing context, service absence) |
| `failed` | Check ran but did not reach its intended trigger path cleanly |
| `error` | Local execution path failed (adapter issue, socket error, etc.) |

---

## Prerequisites

| Requirement | Checks Affected |
|-------------|-----------------|
| DarkFirmware adapter | cve_2020_0022_bluefrag, lmp_* (6 checks) |
| Existing bond / pairing | cve_2025_48593_hfp_reconnect |
| Target supports HFP | hfp_at_flood, hfp_slc_confuse |
| Target supports A2DP/AVDTP | cve_2022_39177_avdtp_setconf |
| Target supports AVRCP | cve_2023_27349_avrcp_event |

---

## Usage

```bash
# Run all applicable DoS checks
sudo blue-tap dos TARGET --yes

# Run specific checks
sudo blue-tap dos TARGET --checks cve_2020_0022_bluefrag,cve_2022_39177_avdtp_setconf --yes

# Custom recovery timeout
sudo blue-tap dos TARGET --recovery-timeout 60 --yes

# With explicit adapter
sudo blue-tap dos TARGET -a hci0 --yes
```

### Example Output

A typical DoS run produces output like this:

```
$ sudo blue-tap dos AA:BB:CC:DD:EE:FF --yes

 DoS Assessment  Target: AA:BB:CC:DD:EE:FF  Adapter: hci0
 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

 [1/30] cve_2017_0781_bnep_heap (CVE-2017-0781)
        Sending BNEP control frame with uuid_size=0x10...
        Target unresponsive after trigger
        Waiting for recovery... 12s elapsed
        Target recovered (L2CAP ping success)
        Result: recovered (12.4s downtime)

 [2/30] cve_2017_0782_bnep_underflow (CVE-2017-0782)
        Sending BNEP Filter Net Type Set with list_len=0xFFFF...
        Target responsive after trigger
        Result: success (target survived)

 [3/30] cve_2022_39177_avdtp_setconf (CVE-2022-39177)
        Skipped: target does not advertise A2DP service
        Result: not_applicable

 ...

 [7/30] lmp_detach_flood
        Skipped: DarkFirmware adapter not available
        Result: not_applicable

 ...

 Summary
 ━━━━━━━
  success:        14
  recovered:       3
  unresponsive:    1
  not_applicable:  9
  failed:          2
  error:           1

  Total runtime: 847.2s
  Worst recovery: 142.8s (l2cap_cid_exhaust)
```
