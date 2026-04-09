# Denial of Service Guide

Blue-Tap's DoS module is designed for authorized destructive testing. It runs checks one at a time, records structured evidence for each step, and actively verifies whether the target comes back before continuing.

## Design Goals

- Keep destructive logic modular so new protocol or CVE-specific probes can be added without scattering code across the CLI.
- Separate orchestration from trigger logic.
- Preserve operator visibility in the terminal, session logs, HTML reports, and JSON output.
- Stop the sequence when a target remains down after the recovery window.

## Main Commands

```bash
blue-tap dos list
blue-tap dos run <MAC>
blue-tap dos run <MAC> --checks cve_2020_0022_bluefrag,cve_2022_39177_avdtp_setconf
blue-tap dos check cve_2025_48593_hfp_reconnect <MAC> --set attempts=20
blue-tap dos check cve_2020_0022_bluefrag <MAC> -i hci1
```

Use `dos run` for the full sequential battery. Use `dos check` when you want a single manual trigger, adjusted timing, or a narrower blast radius.

## Execution Model

`dos run` resolves the selected check list, runs each check sequentially, and normalizes the result into a stable schema. For each check Blue-Tap records:

- `check_id`, title, protocol, CVE mapping, and default/overridden parameters
- whether DarkFirmware or pairing context is required
- raw result data from the attack primitive
- normalized status
- recovery probe strategy, probe history, and recovery timing

If one check leaves the target unresponsive and the target does not recover before the timeout, Blue-Tap aborts the remaining checks and records `interrupted_on` and `abort_reason` in the DoS run envelope.

## Status Model

- `success`: the trigger completed and post-check reachability remained intact.
- `recovered`: the target became unavailable after the trigger but returned during the recovery window.
- `unresponsive`: the target stayed down until the recovery timeout expired.
- `not_applicable`: a hard prerequisite was missing, such as DarkFirmware, service absence, or a required bond.
- `failed`: the check ran but did not reach its intended path cleanly.
- `error`: the local execution path failed.

## Recovery Monitoring

Recovery is transport-aware. Classic checks use `l2ping` and remote-name probing. BLE checks can use both advertisement reappearance and a real ATT request/response probe so Blue-Tap can distinguish "device is advertising again" from "GATT is actually responsive again".

Default recovery timeout is 180 seconds. If the device still does not return after 3 minutes, the CLI states that explicitly and the run stops.

## Pairing-Gated Checks

Some DoS checks require an existing bond or an active pairing context. Blue-Tap logs this before execution and reports the result as `not_applicable` when the precondition is not met. Example:

```bash
blue-tap dos check cve_2025_48593_hfp_reconnect <MAC> --set attempts=20
```

The CLI will tell you that pairing or a prior bond is required instead of silently failing the check.

## DarkFirmware and Below-HCI Coverage

DarkFirmware-backed checks are explicitly marked in the registry and require the DarkFirmware-capable adapter, typically `hci1`. Current DoS use cases include raw ACL and LMP-backed triggers such as BlueFrag or controller-level flood methods.

Important limitation: the current Blue-Tap DarkFirmware wrapper supports raw ACL transmission and LMP injection, but it does not yet expose a general-purpose raw BLE Link Layer transmit API. That means true pre-connection BLE LL-only DoS probes are not registered unless Blue-Tap has a real, validated TX path for them.

## Current CVE-Backed DoS Coverage

See [DoS CVE Matrix](./dos-cve-matrix.md) for the exact registered list. The current suite includes:

- BlueBorne BNEP crash probes
- SDP continuation exhaustion and SDP race paths
- BlueFrag via raw ACL
- SweynTooth SMP and ATT destructive checks
- BlueZ AVDTP malformed `SET_CONFIGURATION`
- BlueZ AVRCP out-of-range event trigger
- HFP reconnect race with pairing/bond prerequisite

## Reporting and Session Logging

DoS results are stored as a structured `blue_tap.dos.result` envelope. The report generator consumes that envelope directly.

HTML and JSON reporting include:

- run-level summary counts
- selected checks and recovery timeout
- per-check CVE mapping
- pairing requirement
- normalized status
- recovery strategy and elapsed wait
- evidence text and raw result details

This means `dos run` and `dos check` results are suitable for end-to-end session logging and formal reporting without custom parsing.

## Operator Guidance

- Start with `blue-tap dos list` and review requirements before running a destructive batch.
- Use `dos check` first for high-risk checks, especially pairing-gated or DarkFirmware-backed ones.
- Prefer `--checks` to control sequence on unstable targets.
- Watch for `recovered` versus `unresponsive`: a brief crash-and-restart is very different from a persistent outage.
- For BLE targets, rely on ATT-response recovery where possible, not advertisement presence alone.

## Relevant Files

- Runner and result schema: [dos_runner.py](../blue_tap/attack/dos_runner.py), [dos_framework.py](../blue_tap/attack/dos_framework.py)
- Registry: [dos_registry.py](../blue_tap/attack/dos_registry.py)
- Classic CVE-backed checks: [dos_checks_classic.py](../blue_tap/attack/dos_checks_classic.py)
- BLE CVE-backed checks: [dos_checks_ble.py](../blue_tap/attack/dos_checks_ble.py)
- Raw ACL checks: [dos_checks_raw_acl.py](../blue_tap/attack/dos_checks_raw_acl.py)
