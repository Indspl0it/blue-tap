# Fuzzing Campaign Workflow

## Scenario

You've completed reconnaissance and vulnerability assessment against a Bluetooth target. The known CVEs are checked, but you want to find **unknown** vulnerabilities -- zero-days in the target's Bluetooth stack. Protocol-aware fuzzing systematically mutates Bluetooth packets and monitors for crashes, hangs, or anomalous responses.

This workflow walks through a complete fuzzing campaign as a narrative: setup, monitoring, handling your first crash, reproducing it, minimizing the input, and exporting the results. The story follows a 4-hour campaign against an automotive IVI head unit where, after 47 minutes, the fuzzer finds a crash in SDP response parsing.

**Time estimate:** 1-24 hours depending on scope
**Risk level:** High (will crash vulnerable targets)

!!! note "Prerequisites"
    - **Root access** on your assessment machine
    - **Bluetooth adapter** (hci0) -- any USB dongle works
    - **Target in range** and responsive (fuzzing requires an active connection)
    - **Patience** -- meaningful coverage takes hours, not minutes
    - Optional: pre-captured traffic (`.btsnoop`) for seed corpus
    - DarkFirmware **not required** -- fuzzing operates at HCI level and above

---

## Step 1: Launch a Fuzzing Campaign

Start a 4-hour campaign against the IVI head unit, targeting the protocols identified during recon:

```bash
$ sudo blue-tap fuzz campaign AA:BB:CC:DD:EE:FF \
    -p sdp -p rfcomm -p bnep \
    --duration 4h \
    --strategy coverage_guided
[*] Starting fuzzing campaign against AA:BB:CC:DD:EE:FF (IVI-Headunit)
[*] Protocols: sdp, rfcomm, bnep
[*] Strategy: coverage_guided
[*] Duration: 4h
[*] Corpus: 6,685 seeds loaded (built-in)
[*] Cooldown: 10ms between packets

[*] Fuzzing started at 2026-04-16 10:00:00
```

**What happened:** Blue-Tap loaded its built-in seed corpus (6,685 protocol-valid packets across all supported protocols), selected seeds relevant to the chosen protocols, and began the mutation loop. Each iteration takes a seed, mutates it according to the strategy, sends it to the target, and observes the response.

**Parameters reference:**

| Flag | Description | Default |
|------|-------------|---------|
| `-p/--protocol` | Protocol to fuzz (repeat for multiple: `-p sdp -p rfcomm`) | All supported |
| `--duration` | Campaign duration (e.g., `30m`, `4h`, `12h`) | 1h |
| `--strategy` | Mutation strategy | `coverage_guided` |
| `--cooldown` | Delay between packets in ms | 10 |
| `--max-crashes` | Stop after N crashes | Unlimited |

**Available strategies:**

| Strategy | Best for | How it works |
|----------|----------|-------------|
| `coverage_guided` | General discovery | Tracks which response patterns the target produces; prioritizes mutations that trigger new patterns |
| `mutation` | Quick broad sweep | Random byte-level mutations of seeds; fast but shallow |
| `generation` | Deep protocol bugs | Generates packets from protocol grammars; finds parser edge cases |
| `havoc` | Stress testing | Aggressive random mutations; finds robustness failures |

!!! tip
    Start with `coverage_guided` for the first run. It's the best default -- it balances speed with depth by automatically focusing on mutations that explore new code paths in the target.

---

## Step 2: Monitor the Live Dashboard

The campaign runs with a Rich terminal panel showing real-time statistics. Here's what it looks like 47 minutes in, right when something interesting happens:

```
+------ Fuzzing: sdp,l2cap,rfcomm,bnep @ AA:BB:CC:DD:EE:FF ------+
| Elapsed: 00:47:12 / 04:00:00                                     |
| Packets/sec: 142     Total: 401,930                               |
| Crashes: 1 (HIGH: 1)                                             |
| Corpus: 6,685 seeds   New paths: 31                              |
|                                                                   |
| Protocol Progress:                                                |
|   sdp     [=========>          ] 47%   1 crash  <<<              |
|   l2cap   [============>       ] 62%   0 crashes                  |
|   rfcomm  [=====>              ] 28%   0 crashes                  |
|   bnep    [==>                 ] 12%   0 crashes                  |
+-------------------------------------------------------------------+

[!] 00:47:12 CRASH DETECTED in SDP (HIGH)
[!] Crash ID: crash-2026-0416-sdp-001
[!] Target unresponsive for 8.2s, then recovered
[*] Crash saved. Continuing fuzzing...
```

**What happened:** After 401,930 packets and 47 minutes, a mutated SDP response triggered a crash. The target became unresponsive for 8.2 seconds before recovering. Blue-Tap automatically saved the crashing input, classified it as HIGH severity (required manual restart would be higher), and continued the campaign.

The dashboard metrics explained:

- **Packets/sec:** Current sending rate. Drops indicate the target is struggling.
- **Total:** Cumulative packets sent across all protocols.
- **Crashes:** Count grouped by severity.
- **New paths:** Number of unique response patterns discovered -- higher means the fuzzer is exploring more of the target's code.
- **Protocol progress:** Percentage of the protocol's grammar coverage explored.

---

## Step 3: Keyboard Controls

While the campaign runs, you can interact:

| Key | Action |
|-----|--------|
| `p` | Pause/resume fuzzing |
| `s` | Show current statistics |
| `c` | Show crash summary |
| `q` | Graceful stop (finishes current packet, saves state) |
| `Ctrl+C` | Immediate stop |

!!! tip
    If the target becomes unresponsive and doesn't recover, press `p` to pause. Wait for the target to come back, then press `p` again to resume. Blue-Tap tracks target liveness and will auto-pause after 3 consecutive timeouts, but manual pause gives you more control.

Let the campaign run. At the 4-hour mark:

```
[*] Campaign duration reached (4h).
[*] Gracefully stopping...

+------ Campaign Summary ------+
| Duration:   04:00:00         |
| Total pkts: 2,043,680        |
| Avg rate:   142 pkt/s        |
| Crashes:    3                 |
|   HIGH:     1                 |
|   MEDIUM:   2                 |
| New paths:  47                |
| Corpus:     6,732 seeds (+47)|
+-------------------------------+

[+] Campaign complete. Results saved to session.
```

---

## Step 4: Triage Crashes

Now the campaign is done. Let's look at what we found:

```bash
$ sudo blue-tap fuzz crashes list --severity HIGH
[*] Filtering crashes: severity >= HIGH

  ID                          | Protocol | Severity | Time     | Recovery
 -----------------------------|----------|----------|----------|---------
  crash-2026-0416-sdp-001     | SDP      | HIGH     | 00:47:12 | 8.2s

[+] 1 HIGH+ crash found.
```

To see all crashes including MEDIUM:

```bash
$ sudo blue-tap fuzz crashes
[*] All crashes from current session:

  ID                          | Protocol | Severity | Time     | Recovery
 -----------------------------|----------|----------|----------|---------
  crash-2026-0416-sdp-001     | SDP      | HIGH     | 00:47:12 | 8.2s
  crash-2026-0416-l2cap-001   | L2CAP    | MEDIUM   | 01:23:45 | 2.1s
  crash-2026-0416-l2cap-002   | L2CAP    | MEDIUM   | 02:58:33 | 1.8s

[+] 3 crashes found.
```

**What happened:** Three crashes total. The SDP crash is the most interesting -- HIGH severity means the target required significant recovery time. The two L2CAP crashes are MEDIUM (disconnected but auto-recovered quickly).

**Severity classification:**

| Severity | Meaning |
|----------|---------|
| `CRITICAL` | Target became permanently unresponsive (potential brick) |
| `HIGH` | Target crashed and required extended recovery or manual restart |
| `MEDIUM` | Target disconnected but recovered automatically |
| `LOW` | Anomalous response but no crash or disconnect |

---

## Step 5: Inspect the SDP Crash

Let's look at the HIGH crash in detail:

```bash
$ sudo blue-tap fuzz crashes show crash-2026-0416-sdp-001
[*] Crash details: crash-2026-0416-sdp-001

  Timestamp:    2026-04-16 10:47:12
  Protocol:     SDP
  Severity:     HIGH
  Recovery:     8.2 seconds

  Triggering Packet (hex):
  0000  02 01 00 48 00 44 00 40  06 00 01 00 3b 35 11 1c  |...H.D.@....;5..|
  0010  00 00 ff ff 00 00 10 00  80 00 00 80 5f 9b 34 fb  |............_.4.|
  0020  ff ff 35 05 0a ff ff ff  ff 00 00 00 00 00 00 00  |..5.............|
  0030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|

  Target State:
    Before: Connected, responding normally
    After:  Unresponsive for 8.2s, then SDP service restarted

  Analysis:
    Mutation: Oversized ServiceSearchAttribute request with 0xFFFF
    in UUID and attribute range fields. Likely triggers integer
    overflow in SDP response size calculation.

  Reproducer:
    sudo blue-tap fuzz crashes replay crash-2026-0416-sdp-001
```

**What happened:** The crash was caused by an SDP ServiceSearchAttribute request with maximum-value fields (0xFFFF) in the UUID and attribute range. This likely triggers an integer overflow or buffer overrun in the target's SDP response handling. The target's SDP service crashed and restarted after 8.2 seconds.

**Decision point:**

- **If the analysis looks like a real bug** -- reproduce it (Step 6) to confirm it's deterministic.
- **If it looks like a fluke** (e.g., timing-related disconnect) -- try reproducing. If it doesn't reproduce, reclassify as LOW.

---

## Step 6: Reproduce the Crash

Confirm the crash is deterministic by replaying the exact packet sequence:

```bash
$ sudo blue-tap fuzz crashes replay crash-2026-0416-sdp-001
[*] Replaying crash-2026-0416-sdp-001 against AA:BB:CC:DD:EE:FF...
[*] Connecting to target...
[*] Sending triggering packet...
[!] Target unresponsive!
[*] Waiting for recovery...
[+] Target recovered after 7.9s

[+] Crash REPRODUCED.
[+] Original recovery: 8.2s, Replay recovery: 7.9s
[+] Classification: DETERMINISTIC
```

**What happened:** The exact same packet caused the same crash. Recovery time is consistent (8.2s vs 7.9s). This is a real, reproducible bug -- not a fluke.

!!! warning
    Reproduction will crash the target again. Ensure the target has recovered from the campaign before replaying.

**Decision point:**

- **Crash reproduced** -- proceed to minimization (Step 7) to find the smallest triggering input.
- **Crash did NOT reproduce** -- mark as `FLAKY` and move on. Some crashes depend on internal target state that isn't easily recreated.

---

## Step 7: Minimize the Crash Input

Reduce the crashing packet to the smallest input that still triggers the bug:

```bash
$ sudo blue-tap fuzz minimize crash-2026-0416-sdp-001 --strategy auto
[*] Minimizing crash-2026-0416-sdp-001...
[*] Original size: 64 bytes
[*] Strategy: auto (trying all strategies)

  Pass 1: byte_removal
    64 → 48 bytes (25% reduction)
    Verified: crash still triggers at 48 bytes

  Pass 2: chunk_removal
    48 → 32 bytes (33% reduction)
    Verified: crash still triggers at 32 bytes

  Pass 3: field_trimming (SDP-aware)
    32 → 24 bytes (25% reduction)
    Verified: crash still triggers at 24 bytes

  Pass 4: field_trimming (final)
    24 → 24 bytes (no further reduction)

[+] Minimization complete.
[+] Original: 64 bytes → Minimized: 24 bytes (62.5% reduction)
[+] Crash database updated with minimized input.

  Minimized Packet (hex):
  0000  06 00 01 00 13 35 11 1c  00 00 ff ff 00 00 10 00  |.....5..........|
  0010  80 00 00 80 5f 9b 34 fb  |...._.4.|
```

**What happened:** The minimizer systematically removed bytes and chunks from the crashing input, verifying at each step that the crash still triggers. It reduced the 64-byte input to 24 bytes -- the minimal SDP ServiceSearchAttribute request that causes the overflow. This is the proof-of-concept you include in your report.

**Minimization strategies:**

| Strategy | Approach |
|----------|----------|
| `auto` | Tries all strategies, picks the smallest result |
| `byte_removal` | Removes bytes one at a time |
| `chunk_removal` | Removes multi-byte chunks |
| `field_trimming` | Protocol-aware field reduction (uses grammar knowledge) |

---

## Step 8: Export Crash Data

Package the findings for your report:

```bash
$ sudo blue-tap fuzz crashes export --format json -o crashes.json
[*] Exporting 3 crashes...
[+] Written to crashes.json (4.2 KB)
```

```bash
$ sudo blue-tap fuzz crashes export --format pcap -o crashes.pcap
[*] Exporting 3 crash packets to PCAP...
[+] Written to crashes.pcap (1.1 KB)
```

**What happened:** Crash data exported in two formats. JSON includes full metadata (timestamps, severity, analysis, reproduction status). PCAP includes just the triggering packets, openable in Wireshark for protocol-level inspection.

| Format | Use case |
|--------|----------|
| `json` | Programmatic analysis, integration with other tools, report appendix |
| `csv` | Spreadsheet review, sorting/filtering |
| `pcap` | Wireshark analysis, sharing with the vendor for debugging |

---

## Step 9: CVE-Specific Fuzzing

Target a known CVE with its proof-of-concept as a seed, mutating around it to find variants:

```bash
$ sudo blue-tap fuzz cve AA:BB:CC:DD:EE:FF --cve CVE-2017-0785
[*] Loading CVE-2017-0785 seed (BlueBorne SDP info leak)
[*] Seed: SDP ServiceSearchAttribute with crafted continuation state
[*] Mutating around CVE pattern...
[*] Duration: 30m (default for CVE-targeted fuzzing)

 Elapsed: 00:30:00 / 00:30:00
 Mutations: 42,180
 Variants found: 2

[+] CVE-specific fuzzing complete.
[+] 2 new variant triggers found (similar root cause, different offsets)
```

**What happened:** Instead of starting from the general corpus, Blue-Tap loaded the known PoC for CVE-2017-0785 and mutated specifically around its structure. This finds **variants** -- inputs that exploit the same root cause but through slightly different paths, which may bypass specific patches.

**Available CVE seeds:**

- `CVE-2017-0785` -- BlueBorne SDP info leak
- `CVE-2017-1000251` -- BlueBorne L2CAP RCE
- `CVE-2020-0022` -- BlueFrag
- `CVE-2023-45866` -- HID injection

---

## Step 10: PCAP Replay and Mutation

Import real Bluetooth traffic and use it as fuzzing seeds:

```bash
$ sudo blue-tap fuzz replay --capture traffic.btsnoop AA:BB:CC:DD:EE:FF
[*] Parsing traffic.btsnoop...
[*] Extracted 1,247 protocol packets:
      SDP: 89, L2CAP: 412, RFCOMM: 298, BNEP: 34, other: 414
[*] Adding to corpus (deduplicated against existing seeds)...
[+] 847 new unique seeds added to corpus.
[*] Starting mutation campaign from captured traffic...
```

**What happened:** Blue-Tap parsed a Bluetooth snoop capture, extracted protocol-level packets, deduplicated them against the existing corpus, and began mutating from real traffic patterns. This is powerful because real traffic exercises protocol state machines in ways synthetic seeds often miss.

!!! tip
    Capture traffic with `btmon` (Linux), Android's HCI snoop log (Developer Options > Enable Bluetooth HCI snoop log), or `hcidump`. Feed it back for protocol-aware mutation that starts from realistic packet sequences.

---

## Tuning Tips

### Corpus Seeding

Pre-load with your own protocol packets for better coverage:

```bash
$ sudo blue-tap fuzz campaign AA:BB:CC:DD:EE:FF \
    -p sdp \
    --seed-dir ./my-sdp-seeds/ \
    --duration 2h
```

### Cooldown Tuning

Different targets need different pacing. Embedded devices with small buffers crash from packet rate alone (not content) if you go too fast:

| Target type | Recommended cooldown |
|-------------|---------------------|
| Desktop/laptop | `5` ms (fast, large buffers) |
| Phone | `10` ms (default) |
| Car head unit | `20-50` ms (moderate, shared CPU) |
| IoT device | `50-100` ms (slow, limited buffers) |

```bash
$ sudo blue-tap fuzz campaign AA:BB:CC:DD:EE:FF --cooldown 50
```

### Strategy Selection Guide

```
Fast broad sweep?          --> --strategy mutation
Deep protocol testing?     --> --strategy generation
Maximum coverage?          --> --strategy coverage_guided
Stress test / robustness?  --> --strategy havoc
```

A typical engagement runs `coverage_guided` for the first long campaign, then `generation` for specific protocols where you want deeper coverage, then `havoc` for a final stress pass.

---

## Campaign Lifecycle

```
1. Select protocols + strategy
        |
2. Load corpus (built-in seeds + optional seed-dir)
        |
3. Begin mutation loop <───────────────┐
        |                              |
4. Send packet --> observe response    |
        |                              |
5a. New coverage path? --> add to corpus
5b. Crash detected? --> save to crash DB
5c. No response? --> check target alive
        |
6. Campaign ends (duration/max-crashes/manual stop)
        |
7. Triage --> Reproduce --> Minimize --> Export
```

---

## Summary

Over the 4-hour campaign, we:

1. **Launched** a coverage-guided fuzzing campaign across 4 protocols
2. **Monitored** real-time progress and detected 3 crashes
3. **Triaged** crashes by severity -- 1 HIGH, 2 MEDIUM
4. **Inspected** the HIGH crash: SDP integer overflow from oversized attribute request
5. **Reproduced** it deterministically -- confirmed it's a real bug
6. **Minimized** the input from 64 bytes to 24 bytes -- the minimal PoC
7. **Exported** crash data in JSON and PCAP for reporting

The SDP crash is a reportable finding: a remotely triggerable denial-of-service via malformed SDP request, no pairing required, reproducible, with a 24-byte proof-of-concept.

---

## What's Next?

- [Quick Assessment](quick-assessment.md) -- run a triage first to identify which protocols are worth fuzzing
- [Full Penetration Test](full-pentest.md) -- integrate fuzzing into a complete engagement
- [Custom Playbooks](custom-playbooks.md) -- automate fuzzing campaigns for regression testing
- [Encryption Downgrade](encryption-downgrade.md) -- if you want to fuzz authenticated-only services, establish a pairing first
