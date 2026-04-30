# Installation

## Prerequisites

Blue-Tap requires a Linux environment with Bluetooth support. It uses raw HCI sockets, D-Bus BlueZ APIs, and Linux-specific Bluetooth tooling -- none of which are available on macOS or Windows. If you are coming from a non-Linux environment, the simplest path is a Kali Linux VM or a dedicated Kali laptop with a USB Bluetooth adapter passed through.

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.10+ | 3.12+ |
| OS | Any Linux with BlueZ | Kali Linux 2024+ |
| BlueZ | 5.x | 5.66+ |
| Privileges | root or sudo | root |
| Adapter | RTL8761B-based USB dongle (TP-Link UB500) | TP-Link UB500 with DarkFirmware |

!!! warning "RTL8761B dongle is required for live operations"
    Blue-Tap currently checks for a Realtek RTL8761B chipset before running any
    command that touches Bluetooth hardware. Stock firmware is sufficient for
    discovery, recon, vulnscan, exploit, dos, extract, and fuzz; DarkFirmware
    is only needed for below-HCI features (LMP injection, controller memory
    R/W, in-flight modification). If no RTL8761B is present, hardware-using
    commands exit with `No RTL8761B / TP-Link UB500 dongle detected`.

    The following commands run without root **and** without any adapter
    (the root and RTL8761B gates share one skip predicate, so anything
    listed here skips both checks):

    - `blue-tap --version`, `blue-tap --help`
    - `blue-tap doctor`
    - `blue-tap demo`
    - `blue-tap session list`, `blue-tap session show <name>`
    - `blue-tap report` (including `blue-tap report <dump-dir>`)
    - `blue-tap fuzz crashes list / show / export`
    - `blue-tap fuzz corpus list / minimize`
    - `blue-tap fuzz minimize`
    - `blue-tap fuzz campaign --dry-run` and `blue-tap fuzz benchmark --dry-run`
      (in-process mock transport — exercises the full pipeline without hardware)
    - `blue-tap run-playbook --list`
    - `blue-tap search`, `blue-tap info`, `blue-tap show-options`, `blue-tap plugins`

!!! warning "Linux Only"
    Blue-Tap uses raw HCI sockets, D-Bus BlueZ APIs, and Linux-specific Bluetooth tooling.
    It does not run on macOS or Windows. WSL2 does not support USB Bluetooth passthrough
    without significant workarounds and is not a supported configuration.

!!! tip "Kali Linux Recommended"
    Kali ships with all required Bluetooth tools pre-installed (`bluez`, `bluez-tools`,
    `bdaddr`, `spooftooph`). On other distributions you may need to install several
    packages manually. Kali also includes kernel modules and firmware blobs for most
    common Bluetooth chipsets out of the box.

## System Tools

Blue-Tap shells out to standard BlueZ utilities for low-level adapter operations, service discovery, and HCI monitoring. These must be on `$PATH` before Blue-Tap will function.

**Required** (provided by `bluez` / `bluez-tools`):

| Tool | Package | Purpose |
|------|---------|---------|
| `bluetoothctl` | bluez | Adapter control, pairing, scanning |
| `hciconfig` | bluez | Low-level adapter management |
| `btmgmt` | bluez | Management API interface |
| `sdptool` | bluez | SDP service discovery |
| `btmon` | bluez | HCI traffic monitoring |

**Optional** (for MAC address spoofing):

| Tool | Package | Purpose |
|------|---------|---------|
| `bdaddr` | bluez-tools or build from source | CSR chipset address change |
| `spooftooph` | spooftooph | Multi-chipset address spoofing |

The spoofing tools are not required for core assessment functionality, but many advanced workflows -- such as impersonating a previously-paired device for connection hijacking -- depend on changing the adapter's MAC address. See [Hardware Setup -- MAC Address Spoofing](hardware-setup.md#mac-address-spoofing) for details on which method works with your chipset.

=== "Kali Linux"

    Kali includes everything pre-installed. This command ensures you have the latest versions:

    ```bash
    sudo apt update && sudo apt install -y bluez bluez-tools spooftooph
    ```

=== "Debian / Ubuntu"

    ```bash
    sudo apt update && sudo apt install -y bluez bluez-tools
    ```

    !!! note "spooftooph on Ubuntu"
        `spooftooph` is not in the default Ubuntu repositories. You can install it from
        source or use `bdaddr` (included in `bluez-tools`) as an alternative for CSR chipsets.

=== "Arch Linux"

    ```bash
    sudo pacman -S bluez bluez-utils
    ```

Verify your tools are installed and accessible:

```bash
$ bluetoothctl --version
bluetoothctl: 5.72

$ hciconfig --version
hciconfig - HCI emulation ver 5.72
```

## Core Dependencies

These Python packages are installed automatically by pip when you install Blue-Tap. They are listed here for reference, so you understand what the toolkit depends on and why.

| Package | Version | Purpose |
|---------|---------|---------|
| click | >=8.1 | CLI framework -- every `blue-tap` subcommand is a Click command |
| rich | >=13.0 | Terminal UI, tables, progress bars, and live status updates |
| rich-click | >=1.8 | Rich-formatted help text for all CLI commands |
| bleak | >=0.21 | Cross-platform BLE scanning (used for `discover ble` and `recon gatt`) |
| dbus-fast | >=2.0 | Async D-Bus for BlueZ APIs -- adapter management and pairing |
| scapy | >=2.5 | Packet crafting for protocol fuzzing and low-level Bluetooth operations |
| pulsectl | >=23.5 | PulseAudio/PipeWire control for audio extraction (A2DP/HFP capture) |
| pyyaml | >=6.0 | Playbook and config parsing |

## Install via pip

The recommended way to install Blue-Tap:

```bash
pip install blue-tap
```

For development (includes pytest, ruff, and other dev tools):

```bash
pip install blue-tap[dev]
```

---

## Install from Source (Alternative)

=== "Standard Install"

    ```bash
    git clone https://github.com/Indspl0it/blue-tap.git
    cd blue-tap
    pip install -e .
    ```

=== "With Dev Dependencies"

    Includes `pytest`, `ruff`, and other development tools:

    ```bash
    git clone https://github.com/Indspl0it/blue-tap.git
    cd blue-tap
    pip install -e ".[dev]"
    ```

The `-e` (editable) flag means changes to the source code take effect immediately without reinstalling. This is the recommended install method for both users and developers.

## Verify Installation

### Version check

```bash
$ blue-tap --version
blue-tap, version 2.6.3
```

If this command fails with `command not found`, ensure the pip install location is on your `$PATH`. On Kali, pip installs to `/usr/local/bin/` by default; on other distributions, it may install to `~/.local/bin/`.

### Environment doctor

`blue-tap doctor` runs a comprehensive environment check that validates your entire setup in one command. It does **not** require root, so you can run it as a quick sanity check before elevating privileges for actual assessments.

```bash
$ blue-tap doctor
```

??? example "Sample doctor output (with adapter present)"

    ```
    Environment Diagnostics
    ────────────────────────────────────────
      ✓  bluetoothctl
      ✓  sdptool
      ✓  hciconfig
      ✓  pactl
      ✓  parecord
      ✓  paplay
      ✓  aplay
      14:32:07  ●  1 Bluetooth adapter(s) detected

      14:32:07  ✔  Environment ready for Bluetooth operations.
    ```

??? example "Sample doctor output (no adapter)"

    ```
    Environment Diagnostics
    ────────────────────────────────────────
      ✓  bluetoothctl
      ✓  sdptool
      ✓  hciconfig
      ✓  pactl
      ✓  parecord
      ✓  paplay
      ✗  aplay
      14:32:07  ⚠  No Bluetooth adapters found

      14:32:07  ⚠  Environment NOT ready: no Bluetooth adapter present.
    ```

The doctor checks for:

- **Bluetooth tooling** -- presence of `bluetoothctl`, `sdptool`, `hciconfig`
- **Audio stack** -- `pactl` / `parecord` / `paplay` / `aplay` for audio extraction
- **Adapters** -- enumerates HCI adapters detected by BlueZ
- **Verdict** -- `Environment ready` only when both tools and at least one adapter are present; `Environment NOT ready` when no adapter is detected; `partially ready` when limitations are reported

A missing `aplay` is reported as `✗` but is not fatal (it's only used for some audio playback paths).

!!! note "Root Not Required for Doctor"
    `blue-tap doctor` deliberately avoids operations that need root so you can run it
    as a quick sanity check before elevating privileges for actual assessments.

!!! tip "First Thing to Run"
    If something is not working, `blue-tap doctor` is always the first diagnostic step.
    Share its output when reporting issues -- it captures everything needed to diagnose
    environment problems.

### Verify Everything Works

After doctor passes, confirm end-to-end functionality with demo mode. Demo mode exercises the full assessment pipeline using mock data -- no Bluetooth hardware or root required:

```bash
$ blue-tap demo
```

??? example "Expected demo output (abbreviated)"

    ```
    ────────────────────── Demo Complete (9/9 phases, 31.2s) ───────────────────────

    ╭───────────────────────────── Assessment Summary ─────────────────────────────╮
    │                                                                              │
    │    Target: Harman-IVI-2024 (4C:87:5D:A1:3E:F0)                               │
    │    Paired Phone: Galaxy S24 (B8:27:EB:6C:D4:22)                              │
    │    Risk Rating: CRITICAL                                                     │
    │    Vulnerabilities: 2 CRITICAL, 3 HIGH, 4 MEDIUM, 2 LOW                      │
    │    Data Extracted: 156 contacts, 122 call logs, 436 messages                 │
    │    Fuzzing: 14,827 packets, 2 crashes                                        │
    │    DoS: 1 unresponsive, 2 degraded out of 5 tests                            │
    │    Total Time: 31.2 seconds                                                  │
    │    Reports: demo_output/report.html                                          │
    │                                                                              │
    ╰──────────────────────────────────────────────────────────────────────────────╯

      ●  DEMO MODE — All data above is simulated. No Bluetooth hardware was used.
      ●  Open demo_output/report.html in a browser for the full report.
    ```

If demo mode completes and produces a report, your Python environment, dependencies, and framework are all working correctly. The next step is to connect real hardware.

## DarkFirmware (Optional, RTL8761B-only feature)

DarkFirmware is the patched controller firmware that enables LMP injection,
controller memory R/W, and in-flight packet modification on RTL8761B dongles.
The base RTL8761B requirement (see the prerequisites table above) is enforced
regardless — DarkFirmware just unlocks the extra below-HCI capabilities used
by BIAS, BLUFFS, KNOB-active, CTKD, and LMP fuzzing.

See [Hardware Setup -- DarkFirmware](hardware-setup.md#darkfirmware-recommended)
for flashing instructions. The first time `blue-tap` detects a stock-firmware
RTL8761B, it offers an interactive prompt to flash DarkFirmware (with the
original blob backed up for restore via `blue-tap adapter firmware-install --restore`).

---

## What's Next?

- **[Hardware Setup](hardware-setup.md)** -- configure your Bluetooth adapter, set up MAC spoofing, and optionally install DarkFirmware
- **[Quick Start](quick-start.md)** -- run your first assessment in five commands
