# Troubleshooting

Common issues and resolutions organized by category. Each issue follows the format: **Symptom** (what you see), **Cause** (why it happens), **Fix** (what to do).

---

## Environment Doctor

Before diving into specific issues, run the built-in environment check:

```bash
sudo blue-tap doctor
```

Example output on a healthy system:

```
 Blue-Tap Environment Check
 ===========================

 [PASS] Python 3.12.3
 [PASS] BlueZ 5.72
 [PASS] bluetoothctl available
 [PASS] hciconfig available
 [PASS] btmgmt available
 [PASS] sdptool available
 [PASS] btmon available
 [PASS] D-Bus bluetooth service running
 [PASS] Adapter hci0: UP RUNNING (Intel AX201)
 [PASS] Adapter hci1: UP RUNNING (RTL8761B - DarkFirmware capable)
 [PASS] Root privileges confirmed
 [PASS] BlueZ --compat mode enabled

 11/11 checks passed
```

Example output with problems:

```
 Blue-Tap Environment Check
 ===========================

 [PASS] Python 3.11.2
 [PASS] BlueZ 5.66
 [PASS] bluetoothctl available
 [PASS] hciconfig available
 [PASS] btmgmt available
 [FAIL] sdptool: not found
         Install: sudo apt install bluez
 [PASS] btmon available
 [WARN] D-Bus bluetooth service: running without --compat
         SDP operations will fail. See: blue-tap doctor --fix-compat
 [PASS] Adapter hci0: UP RUNNING (CSR 8510)
 [WARN] No DarkFirmware-capable adapter found
         Recommended: TP-Link UB500 (RTL8761B)
 [FAIL] Not running as root
         Run with: sudo blue-tap doctor

 9/11 checks passed (2 warnings, 2 failures)
```

---

## Adapter Issues

### Adapter not found

**Symptom:** `Error: No Bluetooth adapter found` or `hci0: No such device`.

**Cause:** The adapter is not plugged in, not recognized by the kernel, or the Bluetooth driver module is not loaded.

**Fix:**

```bash
# Check if the adapter is recognized by USB
lsusb | grep -i bluetooth

# Check if the kernel loaded the driver
dmesg | tail -20 | grep -i bluetooth

# Check Blue-Tap's view
blue-tap adapter list
hciconfig -a
```

Blue-Tap resolves adapters in this priority order:

1. Explicit `--hci` flag
2. `BT_TAP_DARKFIRMWARE_HCI` environment variable
3. USB probe (RTL8761B preferred)
4. First adapter in UP state
5. `hci0` fallback

### Permission denied

**Symptom:** `PermissionError: [Errno 1] Operation not permitted` or `Can't open HCI socket`.

**Cause:** HCI operations require root privileges or the `CAP_NET_RAW` capability.

**Fix:**

```bash
# Option 1: Run as root (recommended)
sudo blue-tap doctor

# Option 2: Grant capability to the Python binary
sudo setcap cap_net_raw+eip $(which python3)
```

### Adapter stuck in scanning

**Symptom:** Commands hang or return `Device busy` errors.

**Cause:** A previous scan or connection attempt did not clean up properly, leaving the adapter in an active inquiry or LE scan state.

**Fix:**

```bash
# Reset the adapter
blue-tap adapter reset --hci hci0

# Or directly via hciconfig
hciconfig hci0 reset
```

### Device class won't change

**Symptom:** `blue-tap adapter set-class` reports success but `hciconfig` still shows the old class.

**Cause:** Some chipsets (especially Intel) silently ignore Class of Device (CoD) write commands. The HCI command succeeds at the protocol level but the firmware does not apply the change.

**Fix:**

```bash
# Try setting with raw hex (device class is a positional argument)
blue-tap adapter set-class 0x240404 --hci hci0

# Verify
hciconfig hci0 class
```

If the chipset ignores the write, use a different adapter. RTL8761B and CSR 8510 both support CoD changes.

---

## Scanning Issues

### No devices found

**Symptom:** `blue-tap discover` completes but reports 0 devices.

**Cause:** Scan duration too short, adapter not UP, or target not in discoverable mode.

**Fix:**

```bash
# Increase scan duration (default may be too short in noisy environments)
blue-tap discover classic -d 20

# Verify adapter is UP
hciconfig hci0

# Try separate scans (combined scans can interfere on some adapters)
blue-tap discover classic
blue-tap discover ble
```

### BLE scan fails

**Symptom:** `ImportError: bleak` or `BleakError: Not connected`.

**Cause:** Missing `bleak` dependency or D-Bus Bluetooth service not running.

**Fix:**

```bash
# Check bleak version (requires >=0.21)
pip show bleak

# Verify D-Bus bluetooth service
systemctl status bluetooth

# If not running
sudo systemctl start bluetooth
```

### Classic inquiry timeout

**Symptom:** `Inquiry timed out` or scan returns after a long delay with no results.

**Cause:** The adapter is busy with another operation (leftover from a previous command), or the HCI inquiry parameters are not being applied correctly.

**Fix:**

```bash
# Reset the adapter first
blue-tap adapter reset --hci hci0

# Then retry
blue-tap discover classic
```

---

## Connection Issues

### Pairing failures

**Symptom:** `Pairing failed` or `Authentication rejected`.

**Cause:** Mismatched pairing expectations (PIN vs SSP), IO capability mismatch, or target requires user confirmation.

**Fix:**

```bash
# Check what pairing method the target expects
blue-tap vulnscan TARGET

# Use the SSP downgrade probe to test pairing behavior
blue-tap exploit TARGET ssp-downgrade --method probe
```

### RFCOMM connection refused

**Symptom:** `ConnectionRefusedError: [Errno 111] Connection refused` on RFCOMM connect.

**Cause:** The target channel requires authentication, or no service is listening on that channel.

**Fix:**

```bash
# Discover available channels via SDP
blue-tap recon TARGET sdp

# Scan for hidden RFCOMM channels (not in SDP)
blue-tap recon TARGET rfcomm
```

### L2CAP connection timeout

**Symptom:** Connection attempt hangs and then times out.

**Cause:** The target PSM is not listening, or a firewall/filter is dropping L2CAP connection requests.

**Fix:**

```bash
# Verify which PSMs are accepting connections
blue-tap recon TARGET l2cap
```

---

## SDP Issues

### SDP registration failed / Failed to connect to SDP server

**Symptom:** `Failed to connect to SDP server on FF:FF:FF:00:00:00: No such file or directory` or `sdptool: connect: Host is down`.

**Cause:** BlueZ is not running in compatibility mode. The `--compat` flag enables the legacy SDP server socket that `sdptool` and Blue-Tap's SDP operations require.

**Fix:**

```bash
# Test current state
sudo sdptool browse local

# If it fails, enable --compat mode
sudo sed -i 's|ExecStart=.*/bluetoothd|& --compat|' /lib/systemd/system/bluetooth.service
sudo systemctl daemon-reload
sudo systemctl restart bluetooth

# Verify
sdptool browse local
```

---

## Fuzzing Issues

### Transport error

**Symptom:** `TransportError: Connection reset by peer` or `BrokenPipeError` during fuzzing.

**Cause:** The target crashed from a previous test case and has not recovered yet. The transport (L2CAP/RFCOMM socket) is no longer valid.

**Fix:**

```bash
# Increase cooldown between test cases to allow recovery
blue-tap fuzz campaign TARGET --cooldown 30

# Check recorded crashes to see what triggered it
blue-tap fuzz crashes list
```

### No crashes detected

**Symptom:** Fuzzing campaign completes with 0 crashes after many iterations.

**Cause:** The fuzzing strategy may not be generating inputs that exercise the vulnerable code path, or the transport is not reaching the parser under test.

**Fix:**

```bash
# Try a different strategy
blue-tap fuzz campaign TARGET --strategy coverage_guided
blue-tap fuzz campaign TARGET --strategy state_machine
blue-tap fuzz campaign TARGET --strategy targeted

# Increase campaign duration (accepts 30m, 1h, 2h, etc.)
blue-tap fuzz campaign TARGET --duration 1h

# Validate the transport works by replaying a known CVE pattern
blue-tap fuzz cve TARGET --cve-id 2022-39177
```

### Crash minimization hangs

**Symptom:** Minimization phase does not progress.

**Cause:** Target recovery between minimization attempts is slow. Each minimization step needs the target to be fully responsive before the next variant is sent.

**Fix:** Increase the cooldown period to give the target more time to restart its Bluetooth stack. Some embedded devices take 30+ seconds to reinitialize after a crash.

---

## Audio Issues

### No audio device found

**Symptom:** `Error: No Bluetooth audio device found` when running audio capture.

**Cause:** The audio profile (A2DP or HFP) is not connected, or PulseAudio/PipeWire does not see the Bluetooth device.

**Fix:**

```bash
# Check for Bluetooth audio devices in PulseAudio/PipeWire
pactl list cards | grep bluez

# Ensure the correct profile is active:
#   HFP: requires headset-head-unit profile
#   A2DP: requires a2dp-sink profile
pactl list cards short
```

### Recording is silent

**Symptom:** Audio file is created but contains only silence.

**Cause:** Wrong audio source selected, or the source volume is muted.

**Fix:**

```bash
# List Bluetooth audio sources
pactl list sources | grep bluez_input

# Set the Bluetooth source as default
pactl set-default-source <source_name>

# Check volume is not muted
pactl get-source-volume <source_name>
```

### parecord / paplay not found

**Symptom:** `FileNotFoundError: parecord` or `command not found: paplay`.

**Cause:** PulseAudio utilities are not installed.

**Fix:**

```bash
# Debian / Ubuntu / Kali
sudo apt install pulseaudio-utils

# For PipeWire-based systems
sudo apt install pipewire-pulse
```

---

## MAC Spoofing Issues

### Spoofing failed

**Symptom:** `Error: All spoofing methods failed` or `bdaddr: command not found`.

**Cause:** No supported spoofing tool is installed, or the chipset does not support address changes.

**Fix:**

Blue-Tap tries spoofing methods in this order: `rtl8761b` -> `bdaddr` -> `spooftooph` -> `btmgmt`.

```bash
# Install spoofing tools
sudo apt install spooftooph

# bdaddr may need manual compilation from BlueZ source
# Some chipsets (Intel) do not support address changes at all
```

### MAC reverts after reset

**Symptom:** Spoofed MAC address reverts to the original after adapter reset or USB replug.

**Cause:** Non-DarkFirmware spoofing methods write to volatile memory that is lost on reset.

**Fix:**

For persistent (firmware-level) or volatile (RAM) patching that survives resets, use the RTL8761B with DarkFirmware:

```bash
blue-tap adapter firmware-spoof AA:BB:CC:DD:EE:FF
```

---

## DarkFirmware Issues

### DarkFirmware not detected

**Symptom:** `DarkFirmware: not available` in `blue-tap adapter info`.

**Cause:** No RTL8761B adapter is connected, or the firmware file is missing.

**Fix:**

```bash
# Verify RTL8761B adapter is connected
lsusb | grep 2357:0604

# Check firmware file exists
ls -la /lib/firmware/rtl_bt/rtl8761bu_fw.bin

# If adapter is present but firmware is missing, install it
blue-tap adapter firmware-install
```

### Hooks lost after USB replug

**Symptom:** DarkFirmware operations fail after unplugging and replugging the adapter.

**Cause:** USB replug causes a firmware reload. The `DarkFirmwareWatchdog` should automatically reinitialize hooks, but it may not be running.

**Fix:**

```bash
# Check adapter health
blue-tap adapter info

# If the watchdog is not running, reinitialize manually
blue-tap adapter firmware-init
```

### VSC command failed

**Symptom:** `HCI Vendor-Specific Command failed` or `Status: Unknown HCI Command`.

**Cause:** DarkFirmware is not loaded, or the adapter does not support the requested VSC.

**Fix:**

```bash
# Check firmware status
blue-tap adapter firmware-status

# If not loaded, install it
blue-tap adapter firmware-install
```

---

## Report Issues

### Missing sections in report

**Symptom:** Generated report is missing expected sections (e.g., vulnscan results are not shown).

**Cause:** Commands were run in different sessions. The report generator only collects envelopes from the active session directory.

**Fix:**

```bash
# Use the same session name for all commands
blue-tap -s my-assessment discover classic
blue-tap -s my-assessment vulnscan TARGET
blue-tap -s my-assessment report

# Verify session contents
blue-tap session show my-assessment
```

### Empty report

**Symptom:** Report generates but contains no data sections.

**Cause:** No session data was collected, or the session name is wrong.

**Fix:**

Run assessment commands within a named session before generating the report. Check available sessions:

```bash
blue-tap session list
```
