# Bluetooth Protocol Lessons for BT-Tap Fuzzing

This file exists as a protocol reference for the fuzzing subsystem. Its job is to capture byte-level and framing-level lessons that are useful when building or reviewing protocol-aware mutations. It is not a changelog, not a release note, and not a substitute for reading the implementation.

## What this document is for

Use this document when you need protocol context that the CLI and the top-level README intentionally do not provide:

- framing conventions
- endianness expectations
- field layout reminders
- protocol-specific mutation ideas
- notes about parser behavior or protocol boundaries that matter during fuzzing

## What this document is not for

Do not use this file as the source of truth for:

- current command availability
- session or workflow behavior
- report output behavior
- optional dependency support
- whether a given protocol vector is fully implemented in BT-Tap today

Those questions belong to:

- [README.md](/mnt/c/Users/santh/Desktop/Projects/personal/BT-Tap/README.md)
- [fuzzer-implementation-plan.md](/mnt/c/Users/santh/Desktop/Projects/personal/BT-Tap/fuzzer-implementation-plan.md)
- the code under `bt_tap/`
- the live CLI help output

## Implementation boundary

Bluetooth protocol theory and Linux execution reality are not the same thing.

In particular, not every mutation that is valid at the specification level is reachable through standard user-space sockets. Some behaviors are managed by the kernel or by BlueZ internals, which means a theoretical attack vector may require:

- a different transport path
- raw HCI access
- external tooling
- firmware assistance
- or an explicit unsupported-path decision in BT-Tap

That boundary should be documented honestly. If implementation diverges from protocol theory, the code and tests win.

## Maintenance guidance

Keep this document useful by treating it as a reference note, not as a dumping ground for roadmap prose.

When updating it:

- prefer precise technical notes over feature claims
- keep implementation status out unless the distinction is operationally important
- update the top-level README separately when user-facing capabilities change
- add regression coverage in code when a new protocol insight affects runtime behavior

## Source of truth rule

If this document conflicts with implemented behavior, trust:

1. the code
2. the tests
3. the live CLI help
4. the README

Then update this file to match reality.
