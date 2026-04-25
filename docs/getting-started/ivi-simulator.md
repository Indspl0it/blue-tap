# IVI Simulator

!!! danger "Currently broken — do not rely on"
    The IVI simulator under `target/` is **not in a working state** and is excluded from the v2.6.x release. All commands and walkthroughs that previously documented it have been removed to avoid sending operators down a dead end. Use real hardware (a paired phone, a development head unit, or a friendly target you have authorization to test) for end-to-end exercises.

The `target/` directory still ships a partial BlueZ-based vulnerable daemon, but its setup script no longer reliably produces a target the assessment, exploitation, and post-exploitation modules can interact with end to end. Re-enabling it is tracked as a future-release task.

For practice runs against a controlled target, see [Hardware Setup](hardware-setup.md) for adapter recommendations and use a phone or development board you own.
