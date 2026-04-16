# Denial of Service

**Module:** `exploitation.dos` --- 30 checks across 4 categories

**Outcomes:** `success`, `unresponsive`, `recovered`, `not_applicable`, `aborted`

All DoS checks are intrusive. Each check sends crafted packets designed to crash, hang, or degrade the target device, then monitors recovery. The combination of attack and recovery monitoring is what makes this module useful for security assessments: it doesn't just test whether a device *can* be crashed, but how it behaves after a crash --- whether it recovers gracefully, requires a manual reboot, or enters a degraded state.

!!! danger "Intrusive"
    Every check in this module is intrusive by design. The target device may become unresponsive, crash, or require a manual reboot. Always use `--yes` to confirm or run interactively.

---

## Ethical Considerations

Denial-of-service testing against Bluetooth devices raises specific ethical concerns that differ from web or network DoS testing.

**Physical safety implications.** A Bluetooth device that crashes in a vehicle context is not just an IT inconvenience. If an IVI system crashes while providing navigation, or if a hands-free system drops during an emergency call, the consequences are physical. Never run DoS checks against devices that are actively being used in safety-critical contexts (moving vehicles, medical devices, industrial control systems).

**Recovery monitoring is the point.** The goal of DoS testing in a security assessment is not to prove that you can crash a device --- that's usually straightforward. The goal is to characterize the failure mode: Does the device recover automatically? How long does recovery take? Does it come back in a degraded state? Is a manual reboot required? These answers determine the real-world severity of the vulnerability.

**Scope and authorization.** DoS testing should be explicitly authorized in the engagement scope. Document every check that was run, its outcome, and the target's recovery behavior. The [session report](sessions-and-reporting.md) captures all of this automatically.

---

## Categories

### Classic (10 checks)

Classic Bluetooth DoS checks target the BR/EDR protocol stack --- the traditional Bluetooth connection used by phones, cars, and headsets. These checks exploit vulnerabilities in L2CAP, BNEP, AVDTP, AVRCP, SDP, and HFP implementations.

| Check ID | CVE | Description |
|----------|-----|-------------|
| `dos_cve_2017_0781_bnep_heap` | CVE-2017-0781 | BNEP heap overflow via oversized control message |
| `dos_cve_2017_0782_bnep_underflow` | CVE-2017-0782 | BNEP integer underflow in extension headers |
| `dos_cve_2022_39177_avdtp_setconf` | CVE-2022-39177 | AVDTP SETCONF heap overflow (malformed codec capabilities) |
| `dos_cve_2023_27349_avrcp_event` | CVE-2023-27349 | AVRCP event registration out-of-bounds read |
| `dos_cve_2025_0084_sdp_race` | CVE-2025-0084 | SDP service search race condition |
| `dos_cve_2025_48593_hfp_reconnect` | CVE-2025-48593 | HFP reconnect-during-teardown crash |
| `dos_l2ping_flood` | --- | L2CAP echo request flood |
| `dos_pair_flood` | --- | Rapid pairing request flood |
| `dos_name_flood` | --- | Remote name request flood |
| `dos_rate_test` | --- | Connection rate stress test |

**What these target at the protocol level:**

- **BNEP (CVE-2017-0781, CVE-2017-0782):** BNEP sits on top of L2CAP and provides Ethernet-over-Bluetooth for tethering and PAN. The heap overflow sends a BNEP control message with a length field that exceeds the allocated buffer. The integer underflow crafts extension headers whose size calculation wraps around, causing the parser to read/write beyond buffer boundaries.
- **AVDTP (CVE-2022-39177):** AVDTP negotiates audio streaming parameters for A2DP. The SETCONF command includes codec capability descriptors. A malformed descriptor with an oversized capability payload overflows the heap buffer allocated for parsing.
- **AVRCP (CVE-2023-27349):** AVRCP handles media remote control. The event registration handler has an out-of-bounds read when processing a crafted RegisterNotification command with an invalid event ID, leading to a crash.
- **SDP (CVE-2025-0084):** SDP handles service discovery. The race condition occurs when concurrent ServiceSearch and ServiceAttribute requests manipulate shared state without proper locking, causing a use-after-free.
- **HFP (CVE-2025-48593):** HFP manages hands-free calling. The crash occurs when a reconnection attempt arrives while the previous connection's teardown callback is still executing, accessing freed memory.
- **Flood checks (l2ping, pair, name, rate):** These don't exploit specific vulnerabilities. They stress-test the target's ability to handle high-frequency legitimate requests. Many Bluetooth stacks have no rate limiting, and a flood of valid requests can exhaust connection slots, memory, or processing capacity.

### BLE (2 checks)

BLE (Bluetooth Low Energy) DoS checks target the GATT/ATT and SMP layers used by fitness trackers, smartwatches, IoT sensors, and BLE-capable IVI systems.

| Check ID | CVE | Description |
|----------|-----|-------------|
| `dos_cve_2019_19192_att_deadlock` | CVE-2019-19192 | ATT deadlock via malformed indication |
| `dos_cve_2019_19196_key_size` | CVE-2019-19196 | SMP key size overflow |

- **ATT deadlock (CVE-2019-19192):** Part of the SweynTooth family. Sends a malformed ATT Handle Value Indication that triggers a deadlock in the target's ATT state machine. The target stops processing all BLE traffic until rebooted.
- **SMP key size overflow (CVE-2019-19196):** Also SweynTooth. Sends an SMP Pairing Request with a key size field that exceeds the valid range (>16 bytes), causing a buffer overflow in the key generation routine.

### Raw ACL (1 check)

| Check ID | CVE | Description |
|----------|-----|-------------|
| `dos_cve_2020_0022_bluefrag` | CVE-2020-0022 | BlueFrag --- ACL fragment reassembly crash |

**BlueFrag** is one of the most impactful Bluetooth vulnerabilities discovered. It exploits the ACL fragment reassembly logic in Android's Bluetooth stack. By sending carefully crafted ACL fragments whose sizes cause an integer overflow in the reassembly buffer calculation, the attacker triggers either a crash (DoS) or, on Android 8.0--9.0, remote code execution.

!!! warning "DarkFirmware Required"
    `CVE-2020-0022` (BlueFrag) requires a DarkFirmware-patched adapter to inject crafted ACL fragments below the HCI boundary. Standard Bluetooth adapters cannot generate the malformed ACL fragments needed for this check. See [Hardware Setup](../getting-started/hardware-setup.md) for details.

### Protocol (17 checks)

Protocol-level DoS checks stress-test specific protocol behaviors without targeting known CVEs. These checks are useful for finding *new* vulnerabilities in Bluetooth implementations.

| Check ID | Description |
|----------|-------------|
| `dos_hfp_at_flood` | AT command flood over HFP |
| `dos_hfp_slc_confuse` | Service Level Connection renegotiation loop |
| `dos_l2cap_cid_exhaust` | Exhaust available L2CAP channel IDs |
| `dos_l2cap_data_flood` | L2CAP data frame flood |
| `dos_l2cap_storm` | Combined L2CAP signaling + data flood |
| `dos_lmp_detach_flood` | LMP detach request flood |
| `dos_lmp_encryption_toggle` | LMP encryption setup/teardown toggle |
| `dos_lmp_features_flood` | LMP features request flood |
| `dos_lmp_invalid_opcode` | Invalid LMP opcode injection |
| `dos_lmp_switch_storm` | LMP role switch request storm |
| `dos_lmp_timing_flood` | LMP timing accuracy request flood |
| `dos_obex_connect_flood` | OBEX connect request flood |
| `dos_rfcomm_mux_flood` | RFCOMM multiplexer command flood |
| `dos_rfcomm_sabm_flood` | RFCOMM SABM (connection) frame flood |
| `dos_sdp_continuation` | SDP continuation state exhaustion |
| `dos_sdp_des_bomb` | Deeply nested SDP Data Element Sequence |

**What these target:**

- **Resource exhaustion (CID exhaust, continuation state):** These checks open channels or initiate protocol transactions without completing them, consuming limited resources on the target. `l2cap_cid_exhaust` opens L2CAP channels until the target runs out of channel IDs. `sdp_continuation` starts SDP queries that require continuation responses, consuming server-side state.
- **Flood attacks (l2ping, data, storm, AT, SABM, MUX, OBEX):** High-frequency valid requests that overwhelm the target's processing capacity. The `l2cap_storm` combines signaling and data floods for maximum pressure.
- **State confusion (SLC confuse, encryption toggle, role switch):** These exploit the target's protocol state machine by rapidly changing state. `hfp_slc_confuse` renegotiates the SLC repeatedly. `lmp_encryption_toggle` rapidly enables and disables encryption. `lmp_switch_storm` floods role switch requests. These can trigger race conditions and state corruption.
- **Parser stress (DES bomb, invalid opcode):** The `sdp_des_bomb` sends deeply nested Data Element Sequences (DES within DES within DES), testing for stack overflow in recursive parsers. `lmp_invalid_opcode` sends LMP packets with reserved/undefined opcodes to test error handling.

!!! note "LMP Checks"
    The 6 LMP checks (`dos_lmp_*`) require DarkFirmware-patched firmware. LMP operates below the HCI boundary and cannot be accessed through standard Bluetooth APIs.

---

## Execution Model

The `dos_runner` orchestrates each check:

1. **Validate** --- confirms the check is applicable to the target (transport type, DarkFirmware requirement)
2. **Execute** --- runs the check with the configured parameters
3. **Probe recovery** --- monitors whether the target recovers after the attack

---

## Recovery Monitoring

After each check completes, the runner probes the target to determine its state. Recovery monitoring is the most important part of DoS testing --- it tells you the real-world impact.

**Probe types:**

| Probe | Method | Applicable To |
|-------|--------|---------------|
| `classic_l2ping` | L2CAP echo request | Classic devices |
| `classic_name` | Remote name request | Classic devices |
| `ble_advertising` | BLE scan for advertisements | BLE devices |
| `ble_att` | BLE ATT connection attempt | BLE devices |
| `ble_att_request` | BLE ATT read request | BLE devices |

**Recovery status:**

| Status | Meaning | Real-World Implication |
|--------|---------|----------------------|
| `SUCCESS` | Check executed, target remained responsive | Target is resilient to this attack |
| `UNRESPONSIVE` | Target did not recover within timeout | Requires manual reboot; serious DoS vulnerability |
| `RECOVERED` | Target was unresponsive but came back within timeout | Self-healing; temporary disruption only |
| `NOT_APPLICABLE` | Check not applicable to this target type | Skipped (e.g., BLE check against Classic-only device) |

---

## CLI Usage

### Run all applicable DoS checks

```bash
blue-tap dos TARGET
```

### Run specific checks

```bash
blue-tap dos TARGET --checks dos_l2ping_flood,dos_pair_flood
```

### Custom recovery timeout

```bash
blue-tap dos TARGET --recovery-timeout 30
```

### Non-interactive (skip confirmation)

```bash
blue-tap dos TARGET --yes
```

### Example output

```
$ blue-tap dos AA:BB:CC:DD:EE:FF --checks dos_l2ping_flood,dos_sdp_des_bomb,dos_cve_2022_39177_avdtp_setconf --recovery-timeout 20

[16:00:01] DoS module starting
[16:00:01] Target: AA:BB:CC:DD:EE:FF
[16:00:01] Checks: 3 selected (2 Classic, 1 Protocol)
[16:00:01] Recovery timeout: 20s

⚠  These checks are INTRUSIVE. The target may crash or become
   unresponsive. Proceed? [y/N] y

─── Check 1/3: dos_l2ping_flood ──────────────────────────
[16:00:05] Sending L2CAP echo requests (1000 packets, 600B each)...
[16:00:12] Flood complete. 1000 packets sent in 7.1s (140 pkt/s)
[16:00:12] Probing recovery...
[16:00:13] L2CAP echo: response in 8ms
[16:00:13] Remote name: "MyCarAudio" in 45ms
[16:00:13] Result: SUCCESS (target remained responsive)

─── Check 2/3: dos_sdp_des_bomb ──────────────────────────
[16:00:15] Sending nested DES payload (depth: 256, 2048 bytes)...
[16:00:15] Response: timeout after 10s
[16:00:15] Probing recovery...
[16:00:16] L2CAP echo: no response
[16:00:20] L2CAP echo: no response
[16:00:25] L2CAP echo: response in 12ms
[16:00:25] Result: RECOVERED (unresponsive for 10.2s, then recovered)

─── Check 3/3: dos_cve_2022_39177_avdtp_setconf ─────────
[16:00:27] Sending malformed AVDTP SETCONF (oversized codec caps)...
[16:00:27] Connection dropped.
[16:00:27] Probing recovery...
[16:00:32] L2CAP echo: no response
[16:00:37] L2CAP echo: no response
[16:00:42] L2CAP echo: no response
[16:00:47] L2CAP echo: no response (timeout reached)
[16:00:47] Result: UNRESPONSIVE (target did not recover within 20s)

═══════════════════════════════════════════════════════════
  DoS Summary
═══════════════════════════════════════════════════════════
  Target:        AA:BB:CC:DD:EE:FF
  Checks run:    3
  SUCCESS:       1 (dos_l2ping_flood)
  RECOVERED:     1 (dos_sdp_des_bomb --- 10.2s recovery)
  UNRESPONSIVE:  1 (dos_cve_2022_39177_avdtp_setconf)
  NOT_APPLICABLE: 0
═══════════════════════════════════════════════════════════
```

### Interpreting Results

- **SUCCESS** means the target handled the attack without disruption. This is the desired outcome from the target manufacturer's perspective. It does not mean the attack was ineffective --- it means the target is resilient.
- **RECOVERED** indicates a temporary denial of service. Note the recovery time. A 2-second recovery is a minor issue; a 30-second recovery during a phone call is a significant vulnerability.
- **UNRESPONSIVE** is the most severe outcome. The target requires manual intervention (usually a power cycle) to resume operation. This is a high-severity finding in any security assessment.

!!! tip "Recovery Timeout"
    The default recovery timeout is 15 seconds. Increase `--recovery-timeout` for targets that are slow to reboot (e.g., IVI systems with long boot sequences). A typical IVI may take 30--60 seconds to fully restart, so `--recovery-timeout 60` prevents false UNRESPONSIVE results.

---

## Next Steps

- **Correlate with fuzzing**: Crashes found by the [fuzzer](fuzzing.md) can be replayed through the DoS module to confirm denial-of-service impact.
- **Check known CVEs**: Run [vulnerability assessment](vulnerability-assessment.md) first to identify which CVE-based DoS checks are relevant to the target.
- **Full assessment**: Use [auto mode](automation.md) to run DoS checks as part of a complete assessment pipeline.
- **Report findings**: DoS results including recovery status are automatically included in [session reports](sessions-and-reporting.md).
