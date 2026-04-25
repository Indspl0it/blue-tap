# Hardware Setup

Blue-Tap works with any Linux-compatible Bluetooth adapter for host-level operations (discovery, reconnaissance, assessment, exploitation, post-exploitation). For below-HCI capabilities -- LMP injection, link-layer monitoring, controller memory access -- you need an RTL8761B adapter with DarkFirmware installed.

This page covers adapter management, MAC address spoofing, the DarkFirmware installation process, and a recommended two-adapter setup for advanced assessments.

---

## Adapter Management

### Listing Adapters

```bash
$ sudo blue-tap adapter list
```

??? example "Example output"

    ```
    Bluetooth Adapters
    ==================

    HCI   Chipset          Manufacturer     BT Ver   Status       Features
    ────  ───────────────  ───────────────  ───────  ───────────  ─────────────────────────
    hci0  Intel AX201      Intel Corp       5.2      UP RUNNING   Classic, BLE, EDR, SSP, SC
    hci1  RTL8761B         Realtek          5.0      UP RUNNING   Classic, BLE, EDR, SSP
    ```

To inspect a specific adapter in detail:

```bash
$ sudo blue-tap adapter info --hci hci0
```

??? example "Example output"

    ```
    Adapter: hci0
    ─────────────
      Chipset ........... Intel AX201
      Manufacturer ...... Intel Corp
      BT Version ........ 5.2
      Status ............ UP RUNNING
      BD Address ........ AA:BB:CC:11:22:33
      Features:
        Classic ......... Yes
        BLE ............. Yes
        EDR ............. Yes
        SSP ............. Yes
        Secure Conn ..... Yes
      Capabilities:
        Address Change .. btmgmt (limited)
        Inquiry Modes ... Standard, RSSI, Extended
    ```

This tells you exactly what the adapter supports. The **Features** section matters for planning your assessment -- if you need Classic Bluetooth attacks, the adapter must support Classic. For BLE GATT enumeration, it must support BLE. The **Capabilities** section tells you which MAC spoofing method is available.

### Power and Reset

```bash
# Bring adapter up
sudo blue-tap adapter up --hci hci0

# Bring adapter down
sudo blue-tap adapter down --hci hci0

# Reset adapter (power cycle -- useful when adapter enters a bad state)
sudo blue-tap adapter reset --hci hci0
```

!!! tip "When to Reset"
    If an adapter stops responding after a failed fuzzing session or a DarkFirmware
    crash, `adapter reset` is the first recovery step. It power-cycles the adapter
    without requiring a USB replug. For RTL8761B adapters with DarkFirmware, the
    [DarkFirmwareWatchdog](#darkfirmwarewatchdog) handles this automatically.

### Device Identity

Impersonating a specific device type is essential for many Bluetooth attacks. Car IVI systems often have pre-paired device lists that filter by device name and class. By setting your adapter to match a known paired device, you can trigger automatic reconnection on vulnerable targets.

```bash
# Set friendly name (what the target sees during scanning)
sudo blue-tap adapter set-name "Galaxy S24" --hci hci0

# Set device class with a preset name
sudo blue-tap adapter set-class phone --hci hci0
sudo blue-tap adapter set-class laptop --hci hci0
sudo blue-tap adapter set-class headset --hci hci0
sudo blue-tap adapter set-class car --hci hci0

# Set device class with raw hex (e.g., Audio/Video: Car Audio)
sudo blue-tap adapter set-class 0x200408 --hci hci0
```

Available presets: `phone`, `laptop`, `headset`, `headphones`, `speaker`, `keyboard`, `mouse`, `gamepad`, `car`, `watch`, `tablet`, `printer`, `camera`. Use raw hex when you need to match a specific device class observed during reconnaissance -- for example, if SDP enumeration revealed the target expects a particular class code.

### Adapter Selection Priority

When no `--hci` flag is provided, Blue-Tap resolves the active adapter automatically. Understanding the resolution order matters when you have multiple adapters plugged in -- especially in a two-adapter setup where one runs DarkFirmware and the other handles standard operations.

| Priority | Source | When It Applies |
|----------|--------|-----------------|
| 1 | `--hci` argument | Always wins when provided |
| 2 | `BT_TAP_DARKFIRMWARE_HCI` env var | Set at CLI startup after DarkFirmware probe |
| 3 | RTL8761B USB probe | Scans for USB VID:PID `2357:0604` (TP-Link UB500) |
| 4 | First UP adapter | From `hciconfig`, first adapter reporting UP status |
| 5 | `hci0` | Last-resort fallback so callers always get a string |

The resolved adapter is cached for the lifetime of the process. All modules see the same adapter.

!!! warning "Multiple Adapters"
    If you have both a DarkFirmware RTL8761B and a standard adapter, Blue-Tap will
    prefer the RTL8761B by default (priority 3). Use `--hci hci0` explicitly if you
    want to use the standard adapter for a particular command.

---

## Supported Adapters

The table below lists adapters that have been tested with Blue-Tap. Any Linux-compatible Bluetooth adapter will work for basic operations, but spoofing method and DarkFirmware support vary by chipset.

| Adapter | Chipset | VID:PID | Classic | BLE | DarkFirmware | Spoofing Method |
|---------|---------|---------|---------|-----|--------------|-----------------|
| TP-Link UB500 | RTL8761B | 2357:0604 | Yes | Yes | Yes | RAM patch |
| Generic RTL8761B | RTL8761B | 0BDA:8771 | Yes | Yes | Yes | RAM patch |
| CSR 8510 dongle | CSR 8510 A10 | 0A12:0001 | Yes | No | No | bdaddr |
| Intel AX200 | Intel | 8087:0029 | Yes | Yes | No | btmgmt (limited) |
| Intel AX201 | Intel | 8087:0026 | Yes | Yes | No | btmgmt (limited) |
| Intel AX210 | Intel | 8087:0032 | Yes | Yes | No | btmgmt (limited) |
| Intel AX211 | Intel | 8087:0033 | Yes | Yes | No | btmgmt (limited) |
| Broadcom BCM20702 | Broadcom | 0A5C:21E8 | Yes | Yes | No | bdaddr / spooftooph |
| Realtek RTL8821C | Realtek | 0BDA:B00A | Yes | Yes | No | spooftooph |
| Qualcomm QCA61x4 | Atheros | 0CF3:E300 | Yes | Yes | No | spooftooph |

!!! note "Adapter Detection"
    Blue-Tap identifies chipsets by matching USB VID:PID against a built-in lookup table.
    Internal (non-USB) adapters are identified via `hciconfig -a` manufacturer strings.

### Recommended Adapter

The only adapter you need is the **TP-Link UB500** (RTL8761B). It is the only chipset Blue-Tap supports for DarkFirmware, and it handles all standard operations (discovery, reconnaissance, assessment, extraction, fuzzing) equally well.

| Adapter | Chipset | Price | DarkFirmware | Why |
|---------|---------|-------|--------------|-----|
| **TP-Link UB500** | RTL8761B | ~$13 USD / ₹599 INR | Yes | Enables all Blue-Tap capabilities -- host-level and below-HCI |

### Optional Two-Adapter Setup

For extended assessments where you need uninterrupted scanning while running DarkFirmware operations (which can crash or lock the controller), add a second adapter:

- **Adapter 1 (TP-Link UB500):** DarkFirmware operations -- LMP injection, exploitation, controller memory access
- **Adapter 2 (any Classic+BLE adapter):** Passive scanning and monitoring while adapter 1 is engaged

The DarkFirmwareWatchdog automatically recovers the DarkFirmware adapter in the background while you continue working on the other.

```bash
# Use first adapter for scanning
sudo blue-tap discover classic --hci hci0

# Use second adapter for DarkFirmware/LMP monitoring
sudo blue-tap adapter info --hci hci1
```

---

## MAC Address Spoofing

MAC address spoofing is a prerequisite for several attack techniques: connection hijacking (impersonating a previously-paired phone), bond stealing, and evading MAC-based filtering. Blue-Tap supports four spoofing methods, with automatic selection based on your chipset.

### Basic Usage

```bash
$ sudo blue-tap spoof AA:BB:CC:DD:EE:FF --hci hci0
```

??? example "Example output"

    ```
    [*] Adapter: hci0 (Intel AX201)
    [*] Original MAC: 11:22:33:44:55:66
    [*] Original MAC saved to ~/.blue_tap_original_mac.json
    [*] Trying method: btmgmt
    [+] MAC address changed to AA:BB:CC:DD:EE:FF via btmgmt
    [*] Adapter reset required -- cycling hci0
    [+] Spoof complete. Adapter hci0 is UP with address AA:BB:CC:DD:EE:FF
    ```

### Methods

Specify a spoofing method with `--method`:

| Method | Flag | How It Works | Best For |
|--------|------|--------------|----------|
| `auto` | `--method auto` | Tries all methods in priority order | Default, recommended |
| `rtl8761b` | `--method rtl8761b` | Live RAM patch via DarkFirmware VSC | RTL8761B with DarkFirmware |
| `bdaddr` | `--method bdaddr` | CSR chipset BDADDR write | CSR 8510, some Broadcom |
| `spooftooph` | `--method spooftooph` | Multi-chipset spoofing tool | Broadcom, Realtek, Atheros |
| `btmgmt` | `--method btmgmt` | BlueZ management API | Intel (limited success) |

### Auto Method Priority

When `--method auto` (the default), Blue-Tap tries methods in this order and stops at the first success:

1. `rtl8761b` -- DarkFirmware RAM patch (instant, no adapter reset needed)
2. `bdaddr` -- CSR chipset write (requires adapter reset)
3. `spooftooph` -- multi-chipset tool (requires adapter reset)
4. `btmgmt` -- management API fallback (often restricted by kernel)

!!! tip "RTL8761B Spoofing Advantage"
    The DarkFirmware RAM patch method is unique in that it changes the MAC address
    instantly without requiring an adapter reset or power cycle. This means active
    connections on other adapters are not disrupted, and the spoofed address takes
    effect immediately. All other methods require bringing the adapter down and back up.

!!! info "RAM patch verifies before claiming success"
    Blue-Tap reads the adapter's BDADDR after every RAM patch. If the RAM write succeeds
    but the host stack still reports the old cached address, the tool logs the mismatch
    and automatically falls back to the firmware-file method (persistent patch + USB
    reset). `verified=true` in the result now always means the adapter reports the new
    address at the HCI layer.

!!! note "MAC backup file permissions"
    The original MAC is persisted to `~/.blue_tap_original_mac.json` on the first spoof
    attempt. If the file was created under `sudo` in an earlier run and is now
    root-owned, spoofing logs a warning rather than crashing —
    `chown $USER ~/.blue_tap_original_mac.json` to re-enable transparent restoration.

### Original MAC Backup

Before any spoofing attempt, Blue-Tap saves the adapter's original MAC to `~/.blue_tap_original_mac.json`. This allows restoring the original address later:

```bash
# Restore original MAC
$ sudo blue-tap spoof --restore --hci hci0
[*] Restoring original MAC for hci0: 11:22:33:44:55:66
[+] MAC restored to 11:22:33:44:55:66
```

The backup file is per-adapter (keyed by HCI name), so multiple adapters can be spoofed independently.

---

## DarkFirmware (Recommended)

!!! warning "Strongly Recommended"
    The TP-Link UB500 (RTL8761B) with DarkFirmware is the **recommended adapter** for Blue-Tap. While basic discovery and reconnaissance work with any adapter, a significant portion of Blue-Tap's core capabilities -- CVE exploitation, vulnerability checks that require LMP-level probing, protocol fuzzing with crash detection, and all below-HCI operations -- depend on DarkFirmware. Without it, you lose access to approximately 40-45% of the Bluetooth attack surface.

DarkFirmware is a custom firmware for the RTL8761B Bluetooth controller that extends Blue-Tap's capabilities below the HCI boundary. Standard Bluetooth security tools operate at the host level -- they send and receive HCI commands but cannot see or manipulate the Link Manager Protocol (LMP) and Link Controller (LC) traffic that flows between two Bluetooth controllers. DarkFirmware patches the RTL8761B's MIPS16e firmware to hook into these lower layers, enabling a class of attacks and inspections that are otherwise impossible without specialized hardware.

Approximately 40-45% of Bluetooth CVEs target the LMP or LC layers -- BrakTooth, KNOB key negotiation, and various LMP confusion attacks all operate below HCI. Many of Blue-Tap's exploitation modules (KNOB, BIAS, BLUFFS, encryption downgrade), several vulnerability assessment checks, and the protocol fuzzer's crash detection and LMP-level fuzzing all require DarkFirmware to function. Without it, these capabilities are unavailable.

### What DarkFirmware Enables

Each capability below unlocks specific assessment and attack techniques:

| Capability | VSC / Mechanism | Use Case |
|------------|-----------------|----------|
| LMP injection | VSC 0xFE22 | Send arbitrary LMP packets (up to 28 bytes) into a live connection -- enables BrakTooth PoC replay, KNOB key-size manipulation, and custom LMP fuzzing |
| LMP monitoring | Hooks 1-4 via HCI Event 0xFF | Capture incoming and outgoing LMP, ACL, and LC frames -- visibility into the pairing negotiation, encryption setup, and role switching that is invisible at the HCI level |
| In-flight LMP modification | Hook 2 modes 0-5 | Intercept and modify LMP packets before they reach the host -- enables MITM on the LMP layer without a separate relay device |
| Controller memory read | VSC 0xFC61 | Read 32-bit-aligned memory from the Bluetooth controller -- inspect encryption key size, authentication state, link keys stored in controller RAM |
| Controller memory write | VSC 0xFC62 | Write 32-bit-aligned memory on the Bluetooth controller -- patch runtime behavior, modify connection parameters |
| BDADDR live-patch | RAM write at offset 0xAD85 | Change MAC address in RAM without adapter reset -- instant spoofing for connection hijack attacks |
| Connection state inspection | Memory read of connection table | Read encryption key size, auth state, pairing stage, SC flag -- verify whether KNOB or BIAS attacks succeeded at the controller level |
| LMP send length patching | RAM/file patch at 0x8011167E | Increase LMP PDU length from 10 to 17 bytes -- required for BrakTooth-style oversized LMP attacks |

### In-Flight LMP Modification Modes

Hook 2 supports six modification modes controlled via a memory flag. These modes allow progressively more aggressive manipulation of LMP traffic:

| Mode | Value | Behavior | Use Case |
|------|-------|----------|----------|
| Passthrough | 0 | Normal operation, log only | Passive monitoring -- see all LMP traffic without affecting it |
| Rewrite | 1 | Overwrite one byte in the LMP packet (one-shot, auto-clears) | Targeted single-packet modification for testing specific protocol responses |
| Drop | 2 | Drop the next incoming LMP packet entirely (one-shot) | Simulate packet loss to test target's error handling |
| Opcode filter | 3 | Drop only packets matching a specific opcode (persistent) | Block specific LMP messages (e.g., drop all encryption requests) |
| Persistent rewrite | 4 | Same as rewrite but does not auto-clear (sustained) | Sustained modification for downgrade attacks (e.g., force minimum key size) |
| Auto-respond | 5 | Send a pre-loaded response when a trigger opcode is seen | Automated LMP spoofing -- respond to pairing requests with crafted packets |

### Supported Hardware

!!! warning "RTL8761B Only"
    DarkFirmware is currently supported **only** on the RTL8761B chipset.
    The primary tested adapter is the **TP-Link UB500** (USB VID:PID `2357:0604`).
    Generic RTL8761B dongles with VID:PID `0BDA:8771` may also work but have received
    less testing.

- **Firmware location:** `/lib/firmware/rtl_bt/rtl8761bu_fw.bin`
- **Architecture:** MIPS16e (Realtek Bluetooth controller SoC)
- **BDADDR offset:** `0xAD85` in firmware binary
- **Price:** The TP-Link UB500 is widely available for approximately $10-15 USD / 599 INR

### DarkFirmware Installation

The installation process replaces the stock RTL8761B firmware with a patched version that includes the LMP hooks. The original firmware is backed up so you can restore it at any time.

!!! danger "Firmware Replacement"
    This process replaces the Bluetooth controller's firmware. While the original firmware
    is backed up and can be restored, an interrupted installation or power loss during
    firmware loading could leave the adapter in a non-functional state. In that case,
    simply replugging the USB adapter triggers a fresh firmware load from disk.

**Step 1: Verify the adapter is detected**

```bash
$ lsusb | grep -i "bluetooth\|2357:0604\|0bda:8771"
Bus 001 Device 004: ID 2357:0604 TP-Link TP-Link UB500 Adapter
```

```bash
$ sudo blue-tap adapter list
HCI   Chipset          Manufacturer     BT Ver   Status       Features
────  ───────────────  ───────────────  ───────  ───────────  ─────────────────────────
hci1  RTL8761B         Realtek          5.0      UP RUNNING   Classic, BLE, EDR, SSP
```

**Step 2: Back up the stock firmware**

```bash
$ sudo cp /lib/firmware/rtl_bt/rtl8761bu_fw.bin /lib/firmware/rtl_bt/rtl8761bu_fw.bin.stock
$ ls -la /lib/firmware/rtl_bt/rtl8761bu_fw.bin*
-rw-r--r-- 1 root root 24576 Apr 10 12:00 /lib/firmware/rtl_bt/rtl8761bu_fw.bin
-rw-r--r-- 1 root root 24576 Apr 16 09:30 /lib/firmware/rtl_bt/rtl8761bu_fw.bin.stock
```

**Step 3: Install the patched firmware**

The DarkFirmware binary is included in the Blue-Tap repository under `firmware/`:

```bash
$ sudo cp firmware/rtl8761bu_fw_darkfirmware.bin /lib/firmware/rtl_bt/rtl8761bu_fw.bin
```

**Step 4: Reload the firmware**

Unplug and replug the USB adapter, or trigger a firmware reload:

```bash
# Option A: USB replug (most reliable)
# Physically remove and reinsert the TP-Link UB500

# Option B: Software reload
$ sudo modprobe -r btusb && sudo modprobe btusb
```

**Step 5: Verify DarkFirmware is active**

```bash
$ sudo blue-tap doctor
```

Look for the DarkFirmware section in the doctor output:

```
DarkFirmware
------------
  RTL8761B ............ hci1 (TP-Link UB500)                  [DETECTED]
  Firmware ............ DarkFirmware active (hooks installed)  [OK]
```

You can also verify directly by reading the hook backup pointer:

```bash
# Stock firmware returns all zeros at this address
# DarkFirmware returns a non-zero function pointer
$ sudo blue-tap adapter info --hci hci1
```

??? example "DarkFirmware adapter info output"

    ```
    Adapter: hci1
    ─────────────
      Chipset ........... RTL8761B
      Manufacturer ...... Realtek
      BT Version ........ 5.0
      Status ............ UP RUNNING
      BD Address ........ DE:AD:BE:EF:00:01
      Features:
        Classic ......... Yes
        BLE ............. Yes
        EDR ............. Yes
        SSP ............. Yes
        Secure Conn ..... No
      DarkFirmware:
        Status .......... ACTIVE
        Hook 1 .......... Installed (HCI CMD handler)
        Hook 2 .......... Installed (tLC_RX_LMP)
        Hook 3 .......... Installed (tLC_TX)
        Hook 4 .......... Installed (tLC_RX)
        Mod Mode ........ 0 (Passthrough)
    ```

**Restoring stock firmware:**

```bash
$ sudo cp /lib/firmware/rtl_bt/rtl8761bu_fw.bin.stock /lib/firmware/rtl_bt/rtl8761bu_fw.bin
$ sudo modprobe -r btusb && sudo modprobe btusb
```

### Detection and Auto-Setup

At startup, Blue-Tap probes for an RTL8761B adapter via USB VID:PID. If found with stock firmware, it prompts the operator:

```
[*] RTL8761B detected on hci1 (TP-Link UB500)
[!] Stock firmware loaded -- DarkFirmware not active
    Install DarkFirmware for LMP injection and monitoring?
```

DarkFirmware detection uses two firmware-level probes:

1. **Hook 1 backup read** -- reads address `0x80133FFC` via VSC 0xFC61. Stock firmware returns all zeros; DarkFirmware returns a non-zero function pointer.
2. **VSC 0xFE22 echo** -- sends a dummy LMP injection command. DarkFirmware echoes it as a vendor event (0xFF); stock firmware does not.

These probes are non-destructive and take less than 100ms.

### Capabilities: DarkFirmware vs Standard

| Capability | Without DarkFirmware | With DarkFirmware |
|------------|---------------------|-------------------|
| Device discovery | Yes | Yes |
| Service enumeration (SDP, GATT) | Yes | Yes |
| Basic vulnerability scanning (host-level checks) | Yes | Yes |
| Data extraction (PBAP, MAP, OPP) | Yes | Yes |
| Audio streaming/capture | Yes | Yes |
| DoS checks (L2CAP, SDP, RFCOMM, BNEP) | Yes | Yes |
| MAC spoofing | bdaddr/spooftooph/btmgmt | RAM patch (instant) |
| **CVE exploitation (KNOB, BIAS, BLUFFS, enc-downgrade)** | **No** | **Yes** |
| **LMP-level vulnerability checks** | **No** | **Yes** |
| **Protocol fuzzing with LMP crash detection** | **No** | **Yes** |
| LMP packet injection | No | Yes |
| LMP monitoring | No | Yes |
| In-flight LMP modification | No | Yes |
| Controller memory access | No | Yes |
| Connection security inspection | No | Yes |
| BrakTooth-style oversized LMP | No | Yes |
| CVE PoC replay (LMP-level) | No | Yes |

The top section works with any adapter. The **bold rows** represent core pentest capabilities that require DarkFirmware -- not edge cases, but the exploitation and advanced assessment modules that distinguish Blue-Tap from basic scanning tools. The bottom section covers raw below-HCI operations for advanced research.

### DarkFirmwareWatchdog

The watchdog provides automatic recovery after USB disconnect events, kernel resets, or controller crashes. This is particularly important during fuzzing sessions, where malformed packets can lock the RTL8761B controller.

- **Health check interval:** 30 seconds (configurable via `BT_TAP_WATCHDOG_INTERVAL`)
- **udev integration:** listens for USB add/remove events on VID:PID `2357:0604`
- **Recovery actions:** USB reset, firmware reload, HCI re-initialization
- **State preservation:** restores spoofed BDADDR and hook configuration after recovery

!!! note "Watchdog Starts Automatically"
    The DarkFirmwareWatchdog is started automatically whenever Blue-Tap detects an
    RTL8761B adapter with DarkFirmware active. You do not need to start or configure
    it manually. Set `BT_TAP_WATCHDOG_INTERVAL` to change the health check frequency.

### LMP Monitor Hooks

DarkFirmware installs four hooks in the controller firmware. Each hook intercepts a specific firmware function and redirects captured data to the host via HCI vendor events:

| Hook | Function | Backup Address | What It Captures |
|------|----------|----------------|------------------|
| Hook 1 | HCI CMD handler | `0x80133FFC` | Intercepts VSC 0xFE22 for LMP injection |
| Hook 2 | tLC_RX_LMP | `0x80133FF8` | Incoming LMP packets (56-byte log, AAAA marker) |
| Hook 3 | tLC_TX | `0x80133FF4` | Outgoing LMP (12B, TXXX) and ACL (16B, ACLX) |
| Hook 4 | tLC_RX | `0x80133FEC` | All incoming LC frames (14B, RXLC marker) |

Captured packets are reported to the host as HCI Event 0xFF (vendor-specific) and parsed by `blue_tap.hardware.hci_vsc`. The marker bytes (AAAA, TXXX, ACLX, RXLC) allow the parser to distinguish between different frame types in the event stream.

### Memory Regions

For firmware analysis and debugging, the controller memory is organized as:

| Region | Address Range | Size | Purpose |
|--------|---------------|------|---------|
| ROM | `0x80000000` -- `0x80100000` | 1 MB | Read-only firmware code |
| RAM | `0x80100000` -- `0x80134000` | ~208 KB | Writable runtime data |
| Patch area | `0x80110000` -- `0x80120000` | 64 KB | DarkFirmware hook code |
| Hook/backup area | `0x80133F00` -- `0x80134000` | 256 B | Hook backup pointers and control flags |

!!! note "Memory Access Alignment"
    VSC 0xFC61 (read) and 0xFC62 (write) require 32-bit-aligned addresses. Attempting
    to read or write at a non-aligned address will return an HCI error. All addresses
    in the memory map above are aligned.

---

## What's Next?

- **[Quick Start](quick-start.md)** -- run your first assessment with the hardware you just set up
- **[Encryption Downgrade Workflow](../workflows/encryption-downgrade.md)** -- a DarkFirmware-powered attack chain
- **[Hardware Compatibility Reference](../reference/hardware-compatibility.md)** -- full compatibility matrix
