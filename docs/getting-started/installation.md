# Installation

## Prerequisites

Blue-Tap requires a Linux environment with Bluetooth support. It uses raw HCI sockets, D-Bus BlueZ APIs, and Linux-specific Bluetooth tooling -- none of which are available on macOS or Windows. If you are coming from a non-Linux environment, the simplest path is a Kali Linux VM or a dedicated Kali laptop with a USB Bluetooth adapter passed through.

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.10+ | 3.12+ |
| OS | Any Linux with BlueZ | Kali Linux 2024+ |
| BlueZ | 5.x | 5.66+ |
| Privileges | root or sudo | root |

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
blue-tap, version 2.6.2
```

If this command fails with `command not found`, ensure the pip install location is on your `$PATH`. On Kali, pip installs to `/usr/local/bin/` by default; on other distributions, it may install to `~/.local/bin/`.

### Environment doctor

`blue-tap doctor` runs a comprehensive environment check that validates your entire setup in one command. It does **not** require root, so you can run it as a quick sanity check before elevating privileges for actual assessments.

```bash
$ blue-tap doctor
```

??? example "Full doctor output (everything healthy)"

    ```
    Blue-Tap Environment Check
    ==========================

    System
    ------
      Python .............. 3.12.4 (/usr/bin/python3)
      Platform ............ Linux 6.8.11-amd64 (Kali 2024.3)
      BlueZ ............... 5.72

    Required Tools
    --------------
      bluetoothctl ........ /usr/bin/bluetoothctl (5.72)           [OK]
      hciconfig ........... /usr/bin/hciconfig (5.72)              [OK]
      btmgmt .............. /usr/bin/btmgmt                        [OK]
      sdptool ............. /usr/bin/sdptool (5.72)                [OK]
      btmon ............... /usr/bin/btmon (5.72)                  [OK]

    Optional Tools
    --------------
      bdaddr .............. /usr/bin/bdaddr                        [OK]
      spooftooph .......... /usr/bin/spooftooph (0.5.2)           [OK]

    Bluetooth Adapters
    ------------------
      hci0 ................ Intel AX201 (UP, RUNNING, BLE)        [OK]
      hci1 ................ RTL8761B (UP, RUNNING, BLE)           [OK]

    Audio Stack
    -----------
      PipeWire ............ running (PipeWire 1.0.5)              [OK]

    OBEX Support
    ------------
      obexftp ............. /usr/bin/obexftp                      [OK]

    DarkFirmware
    ------------
      RTL8761B ............ hci1 (TP-Link UB500)                  [DETECTED]
      Firmware ............ DarkFirmware active (hooks installed)  [OK]

    Summary: 13/13 checks passed, 0 warnings
    ```

The doctor checks for:

- **Required tools** -- presence and version of `bluetoothctl`, `hciconfig`, `btmgmt`, `sdptool`, `btmon`
- **Optional tools** -- `bdaddr`, `spooftooph` (warns if missing, does not fail)
- **Bluetooth adapters** -- detects all HCI adapters, reports chipset, status, capabilities
- **Audio stack** -- PulseAudio or PipeWire availability (needed for audio extraction modules)
- **OBEX capability** -- checks for `obexftp` / OBEX push support (needed for data extraction)
- **DarkFirmware** -- detects RTL8761B dongle and firmware state if present

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
    ╭─ Blue-Tap Demo Assessment ─────────────────────────────────╮
    │                                                             │
    │  Target: SYNC (DE:AD:BE:EF:CA:FE)                         │
    │  Adapter: hci0 (simulated)                                  │
    │  Session: demo-20260416-143022                              │
    │                                                             │
    ╰─────────────────────────────────────────────────────────────╯

    Phase 1/9: Discovery ......................................... OK
    Phase 2/9: Fingerprinting .................................... OK
    Phase 3/9: Service Enumeration ............................... OK
    Phase 4/9: RFCOMM / L2CAP Scanning ........................... OK
    Phase 5/9: Vulnerability Assessment .......................... OK
    Phase 6/9: Exploitation Simulation ........................... OK
    Phase 7/9: Data Extraction ................................... OK
    Phase 8/9: DoS Testing ....................................... OK
    Phase 9/9: Report Generation ................................. OK

    Report written to: demo_output/report.html
    JSON export:       demo_output/report.json

    Demo complete. 9/9 phases finished successfully.
    ```

If demo mode completes and produces a report, your Python environment, dependencies, and framework are all working correctly. The next step is to connect real hardware.

## DarkFirmware (Recommended)

If you have a TP-Link UB500 (RTL8761B) adapter and want below-HCI capabilities
(LMP injection, controller memory access, in-flight packet modification), see
[Hardware Setup -- DarkFirmware](hardware-setup.md#darkfirmware-recommended). DarkFirmware is not required for the majority of Blue-Tap's capabilities -- discovery, reconnaissance, assessment, data extraction, and audio capture all work with any supported adapter.

---

## What's Next?

- **[Hardware Setup](hardware-setup.md)** -- configure your Bluetooth adapter, set up MAC spoofing, and optionally install DarkFirmware
- **[Quick Start](quick-start.md)** -- run your first assessment in five commands
- **[IVI Simulator](ivi-simulator.md)** -- set up a deliberately vulnerable practice target
