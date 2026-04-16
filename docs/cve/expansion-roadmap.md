# CVE Expansion Roadmap

Current coverage: **25 CVEs in vulnscan** (behavioral + compliance) and **9 CVE-backed DoS checks**, plus heuristic detection for BrakTooth, KNOB, BIAS, BLUFFS, BLURtooth, BlueBorne, PerfektBlue, PIN bypass, and Invalid Curve.

This document organizes the remaining detection candidates by tier, priority, and detection strategy.

---

## The Bluetooth Vulnerability Landscape

Bluetooth security research has accelerated dramatically since 2017, when the BlueBorne family demonstrated that Bluetooth vulnerabilities could be exploited wirelessly, without user interaction, across all major operating systems. Since then, major vulnerability families have continued to emerge:

- **2017-2018**: BlueBorne (Android, Linux, Windows, iOS) -- the wake-up call
- **2019-2020**: SweynTooth (BLE SoC firmware), KNOB/BIAS (protocol-level), BleedingTooth (Linux kernel)
- **2021-2022**: BrakTooth (Classic chipset firmware), Method Confusion (SSP/SMP spec flaws)
- **2023-2024**: BLUFFS (session key derivation), HID injection attacks, EATT/eCred parsing flaws
- **2025-2026**: Vendor-specific bugs (Airoha RACE), new Linux kernel L2CAP UAFs, HFP state machine bugs

The attack surface is large because Bluetooth stacks are complex (the Core Specification is 3,200+ pages), implementations vary widely across vendors, and the radio is always-on in most devices. Blue-Tap's goal is to provide automated, reliable detection for the vulnerabilities that are remotely exploitable over the air.

---

## Tier System

Blue-Tap organizes CVEs into tiers based on the scope of affected targets and the detection approach:

| Tier | Scope | Detection Approach | Example |
|------|-------|--------------------|---------|
| **Tier 1** | All stacks (spec-level flaw) | Protocol probing -- works on any target | CVE-2020-26558 (Passkey Impersonation) |
| **Tier 2** | Android (Fluoride/Gabeldorsche) | Behavioral probe + Android fingerprint | CVE-2020-0022 (BlueFrag) |
| **Tier 3** | Linux kernel / BlueZ | Behavioral probe + BlueZ/kernel version | CVE-2022-42895 (EFS Info Leak) |
| **Tier 4** | BLE SoC firmware (SweynTooth) | Chipset fingerprint + BLE probing | CVE-2019-19192 (ATT Deadlock) |
| **Tier 5** | Vendor-specific (automotive) | Device fingerprint + vendor-specific probe | CVE-2025-20700 (Airoha RACE) |

Higher tiers affect more devices but are harder to confirm (spec-level flaws require understanding the protocol state machine). Lower tiers affect fewer devices but are often more reliably detected (chipset-specific behavior is deterministic).

---

## Coverage by Tier

### Tier 1: Protocol-Spec Level (All Stacks Affected)

Specification-level flaws detectable on any target regardless of OS or stack.

| CVE | Name | Layer | Detection Strategy | Status |
|-----|------|-------|--------------------|--------|
| CVE-2020-10134 | Method Confusion | SSP/SMP | IO capabilities mismatch analysis during fingerprint | Planned |
| CVE-2020-26558 | Passkey Entry Impersonation | SSP/SMP | Reflected public key probe | **Implemented** |
| CVE-2020-9770 | BLESA | BLE LL | BLE reconnection without re-authentication | Planned |
| CVE-2022-25836 | BLE Method Confusion | SMP | BLE + LESC + Passkey Entry capable (BT 4.0-5.3) | Planned |
| CVE-2022-25837 | BR/EDR Method Confusion | LMP/SSP | SC-Only probe via IO caps downgrade | **Implemented** |
| CVE-2020-26556 | Mesh Malleable Commitment | Mesh | Legacy algorithm in Provisioning Start | Planned |
| CVE-2020-26557 | Mesh AuthValue Brute-force | Mesh | OOB size in Capabilities PDU | Planned |
| CVE-2020-26559 | Mesh AuthValue Leak | Mesh | No-OOB public key in Provisioning Start | Planned |
| CVE-2020-26560 | Mesh Provisioning Impersonation | Mesh | Reflected confirmation value | Planned |

### Tier 2: Android Bluetooth Stack (Fluoride/Gabeldorsche)

Detectable via Android OS fingerprinting (BT version string, manufacturer, device class patterns).

**SDP Family:**

| CVE | Year | Description | Detection Strategy |
|-----|------|-------------|-------------------|
| CVE-2017-0785 | 2017 | BlueBorne SDP info leak | **Implemented** (behavioral) |
| CVE-2017-0781/82 | 2017 | BlueBorne BNEP heap/underflow | **Implemented** (DoS) |
| CVE-2017-0783 | 2017 | BlueBorne PAN MITM | **Implemented** (behavioral) |
| CVE-2023-21273 | 2023 | SDP OOB write | Android version fingerprint (surface only) |
| CVE-2025-0075 | 2025 | SDP UAF (server-side) | SDP PDU 0x06 crash monitor |
| CVE-2025-0074 | 2025 | SDP UAF (client-side) | Passive trap -- advertise HFP, observe SDP query |

**L2CAP Family:**

| CVE | Year | Description | Detection Strategy |
|-----|------|-------------|-------------------|
| CVE-2020-0022 | 2020 | BlueFrag heap overflow | **Implemented** (behavioral + DoS) |
| CVE-2018-9359/60/61 | 2018 | L2CAP signalling OOB reads | **Implemented** (behavioral) |

**BLE/GATT Family:**

| CVE | Year | Description | Detection Strategy |
|-----|------|-------------|-------------------|
| CVE-2023-40129 | 2023 | GATT integer underflow RCE | Android + BLE GATT enum + version |
| CVE-2023-35681 | 2023 | EATT integer overflow | **Implemented** (compliance) |
| CVE-2024-49748 | 2024 | GATT server heap overflow | Android 12-15 + GATT server present |
| CVE-2024-0039 | 2024 | ATT OOB write | Android 12-14 + BLE |

**SMP/Pairing Family:**

| CVE | Year | Description | Detection Strategy |
|-----|------|-------------|-------------------|
| CVE-2018-9365 | 2018 | SMP cross-transport OOB | **Implemented** (compliance) |
| CVE-2019-2225 | 2019 | JustWorks silent pairing | **Implemented** (behavioral) |
| CVE-2024-34722 | 2024 | BLE legacy pairing bypass | **Implemented** (compliance) |

**Profile Family:**

| CVE | Year | Description | Detection Strategy |
|-----|------|-------------|-------------------|
| CVE-2021-0507 | 2021 | AVRCP metadata OOB | **Implemented** (compliance) |
| CVE-2021-0316 | 2021 | AVRCP vendor cmd OOB | Share session with CVE-2021-0507 |
| CVE-2022-20229 | 2022 | HFP client OOB write | Skip (client-side); IVI DoS exception |
| CVE-2017-13258/60/61/62 | 2018 | BNEP info leak family | **Implemented** (behavioral) |
| CVE-2023-45866 | 2023 | HID pre-auth write | **Implemented** (compliance) |
| CVE-2025-0084 | 2025 | HFP SDP race | **Implemented** (DoS) |
| CVE-2025-48593 | 2025 | HFP reconnect UAF | **Implemented** (DoS) |
| CVE-2022-20345 | 2022 | eCred overflow RCE | **Implemented** (compliance) |
| CVE-2022-20411 | 2022 | AVDTP reassembly OOB | A2DP UUID surface + DoS crash monitor |
| CVE-2021-0968 | 2021 | osi_malloc integer overflow | Android 9-12 version fingerprint |

**BNEP Info Leak Family:**

| CVE | Year | Detection |
|-----|------|-----------|
| CVE-2017-13258 | 2018 | **Implemented** -- BNEP extension header oracle |
| CVE-2017-13260 | 2018 | Same probe (single commit fix) |
| CVE-2017-13261 | 2018 | Same probe family |
| CVE-2017-13262 | 2018 | Same probe family |

### Tier 3: Linux Kernel / BlueZ

**L2CAP Vulnerabilities (Remote, Over-the-Air):**

| CVE | Year | Description | Detection Strategy |
|-----|------|-------------|-------------------|
| CVE-2020-12351 | 2020 | BleedingTooth/BadKarma type confusion | A2MP support + kernel 4.8+ + BlueZ version |
| CVE-2020-12352 | 2020 | BleedingTooth/BadChoice stack leak | **Implemented** (behavioral) |
| CVE-2020-24490 | 2020 | BleedingTooth/BadVibes heap overflow | LMP >= 0x0A + LE ExtAdv feature bit |
| CVE-2019-3459/60 | 2019 | L2CAP heap info leaks | **Implemented** (behavioral) |
| CVE-2022-3564 | 2022 | L2CAP ERTM UAF | ERTM surface + DoS race |
| CVE-2022-3640 | 2022 | L2CAP A2MP CID UAF | A2MP surface probe + DoS |
| CVE-2022-42895 | 2022 | L2CAP EFS info leak | **Implemented** (behavioral) |
| CVE-2022-42896 | 2022 | L2CAP UAF RCE | **Implemented** (compliance) |
| CVE-2026-23395 | 2026 | L2CAP eCred duplicate ID | **Implemented** (compliance) |
| CVE-2025-21969 | 2025 | L2CAP slab UAF | DoS rapid connect/disconnect cycling |

**BlueZ Userspace (Remote):**

| CVE | Year | Description | Detection Strategy |
|-----|------|-------------|-------------------|
| CVE-2020-0556 | 2020 | HID/HOGP unauthenticated | **Implemented** (behavioral) |
| CVE-2021-41229 | 2021 | SDP memory leak DoS | DoS continuation exhaustion (attributed) |
| CVE-2022-0204 | 2022 | GATT prepare-write overflow | **Implemented** (compliance) |
| CVE-2022-39176 | 2022 | AVRCP OOB read | **Implemented** (behavioral) |
| CVE-2022-39177 | 2022 | AVDTP malformed capabilities | **Implemented** (DoS) |
| CVE-2023-27349 | 2023 | AVRCP event OOB RCE | **Implemented** (DoS) |
| CVE-2023-50229/30 | 2023 | PBAP heap overflow RCE | PBAP service + BlueZ version |
| CVE-2023-51580/89/92 | 2023 | AVRCP CT-role OOB reads | Skip (client-side); surface only |
| CVE-2023-51596 | 2023 | PBAP OBEX aparam overflow | Skip (client-side); surface only |

**SCO/RFCOMM:**

| CVE | Year | Description | Detection Strategy |
|-----|------|-------------|-------------------|
| CVE-2024-27398 | 2024 | SCO UAF | Skip (local-only, no OTA path) |
| CVE-2026-31408 | 2026 | SCO recv_frame UAF | HFP UUID surface + DoS teardown race |

### Tier 4: SweynTooth BLE SoC (Chipset-Level)

| CVE | Year | Description | Detection Strategy |
|-----|------|-------------|-------------------|
| CVE-2019-19194 | 2020 | Zero LTK Installation | LL_ENC_REQ probe; Telink Company ID 0x0211 |
| CVE-2019-19195 | 2020 | Invalid L2CAP fragment (Microchip) | Raw LL transmission (DarkFirmware) |
| CVE-2019-19196 | 2020 | Unexpected public key crash | **Implemented** (DoS) |
| CVE-2019-19192 | 2020 | ATT sequential deadlock | **Implemented** (DoS) |
| CVE-2020-10069 | 2020 | Zephyr invalid channel map | Raw LL injection (DarkFirmware) |
| CVE-2020-10061 | 2020 | Zephyr invalid sequence | Raw LL header manipulation (DarkFirmware) |
| CVE-2020-13593 | 2020 | NXP DHCheck skip | LL_ENC_REQ before SM_DHKey_Check |

### Tier 5: Vendor-Specific (Automotive Relevant)

| CVE | Year | Vendor | Description | Detection Strategy |
|-----|------|--------|-------------|-------------------|
| CVE-2025-20700 | 2025 | Airoha | GATT RACE auth bypass | **Implemented** (behavioral) |
| CVE-2025-20701 | 2025 | Airoha | BR/EDR RACE auth bypass | **Implemented** (behavioral) |
| CVE-2025-20702 | 2025 | Airoha | RACE link-key extraction | **Implemented** (behavioral) |
| CVE-2024-24746 | 2024 | NimBLE | Prepare Write infinite loop | NimBLE fingerprint via BLE behavior |
| CVE-2024-23923 | 2024 | Alpine | Halo9 L2CAP UAF RCE | Device name + COD IVI (no patch exists) |

---

## Priority Ranking

### P0 -- Extend Existing Checks (Low Effort)

These require only extending existing detection functions or adding version/chipset entries. Estimated effort: 1-2 hours each.

| CVE(s) | What to Do |
|--------|------------|
| CVE-2020-12351 (BadKarma) | Add A2MP support + kernel version to existing BlueZ check |
| CVE-2020-24490 (BadVibes) | LMP version + LE ExtAdv feature bit (already fingerprinted) |
| CVE-2023-50229/30 (PBAP RCE) | PBAP service presence + BlueZ version string |
| CVE-2020-10134 (Method Confusion) | IO capabilities already fingerprinted; add analysis logic |
| CVE-2019-19194 (Zero LTK) | Telink Company ID already in chipset map |
| CVE-2020-13593 (DHCheck skip) | Extend SweynTooth chipset entries |
| CVE-2021-0316 (AVRCP vendor OOB) | Share session with existing CVE-2021-0507 probe |
| CVE-2024-24746 (NimBLE DoS) | NimBLE fingerprint via BLE behavior probe |
| CVE-2024-23923 (Alpine Halo9) | Device name + COD matching (always vulnerable) |

### P1 -- New Detection Logic (Medium Effort)

These require new probe functions or detection pipelines. Estimated effort: 4-8 hours each.

| CVE(s) | What to Build |
|--------|---------------|
| CVE-2023-40129 (GATT RCE) | Android version detection + BLE GATT enumeration |
| CVE-2024-49748 (GATT server overflow) | Android 12-15 fingerprint + GATT server presence |
| CVE-2024-0039 (ATT OOB write) | Android 12-14 fingerprint + BLE |
| CVE-2025-0075 (SDP server UAF) | SDP PDU 0x06 crash monitor |
| CVE-2022-3564/3640 (L2CAP UAFs) | ERTM/A2MP surface probes + DoS triggers |
| CVE-2025-21969 (L2CAP slab UAF) | Rapid connect/disconnect DoS cycle |
| CVE-2022-20411 (AVDTP reassembly) | A2DP surface + MIDDLE fragment overflow DoS |
| CVE-2021-0968 (osi_malloc) | Android 9-12 version fingerprint extension |
| CVE-2026-31408 (SCO UAF) | HFP UUID surface + post-auth teardown race |

### P2 -- Completeness

These round out coverage for niche targets or require hardware capabilities not yet available. Estimated effort: 8-16 hours each.

| CVE(s) | What to Build |
|--------|---------------|
| CVE-2020-9770 (BLESA) | Active BLE reconnection probe |
| CVE-2022-25836 (BLE Method Confusion) | BLE pairing mode analysis |
| CVE-2020-26556/57/59/60 (Mesh family) | Mesh provisioning probes (requires mesh-capable target) |
| CVE-2019-19195 (Microchip L2CAP) | Raw LL transmission (DarkFirmware BLE TX path needed) |
| CVE-2020-10069/10061 (Zephyr) | Raw LL injection (DarkFirmware BLE TX path needed) |
| Remaining Android version-gated CVEs | Broader Android version detection matrix |

---

## Detection Strategy Summary

| Detection Method | CVE Count | Effort | Notes |
|------------------|-----------|--------|-------|
| BT version / LMP features | 15 | Low | Extend existing `_run_hcitool_info` |
| BlueZ version string | 18 | Low | Extend existing `_check_blueborne` pattern |
| Android version fingerprint | 25 | Medium | New Android version detection logic |
| Service presence (SDP/GATT) | 12 | Low | Cross-reference with existing enumeration |
| Chipset matching | 10 | Low | Extend existing `_BRAKTOOTH_CHIPSETS` |
| Protocol behavior probe | 8 | Medium | New probe functions per CVE |
| IO capabilities analysis | 3 | Low | Analyze existing fingerprint output |

---

## Totals

| Category | Count |
|----------|-------|
| Currently detected (vulnscan behavioral + compliance) | 25 CVEs |
| Currently detected (heuristic / version-based) | ~17 CVEs |
| Currently detected (DoS module) | 9 CVEs |
| Expansion candidates | ~42 additional CVEs |
| **Projected total after full expansion** | **~79 CVEs** |

> **Note:** Some CVEs are covered by multiple detection methods (e.g., vulnscan behavioral + DoS crash monitor). The projected total counts each unique CVE once.

---

## Contributing a CVE Check

Want to add detection for a CVE not yet covered? Here is the process:

1. **Research the vulnerability.** Read the CVE advisory, find the patch commit, and understand the trigger condition at the packet level. The key question is: "What packet sequence triggers the bug, and can we observe a differential response without crashing the target?"

2. **Classify the detection strategy.** Use the table above to determine which method applies:
    - Can you send a probe and observe a differential response? -> Behavioral check in `vulnscan`
    - Can you send invalid input and check for correct rejection? -> Compliance check in `vulnscan`
    - Is the only observable effect a crash? -> DoS check in `dos`
    - Can you only infer from version/chipset? -> Heuristic check in `vulnscan`

3. **Implement the check.** Follow the [Writing a Module](../developer/writing-a-module.md) guide. Place CVE checks in `blue_tap/modules/assessment/checks/cve_checks_<protocol>.py` for vulnscan, or `blue_tap/modules/exploitation/dos/checks/` for DoS.

4. **Test against a known-vulnerable target.** Every check must be validated against a real device or emulated stack that is confirmed vulnerable. Document the test target and firmware version.

5. **Submit a PR.** Include the CVE number, detection strategy classification, test evidence, and any caveats (e.g., "requires DarkFirmware" or "pairing required").

See the [Detection Matrix](detection-matrix.md) for examples of existing checks and their detection methods.
