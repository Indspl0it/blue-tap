# Platform Notes

Platform-specific installation and configuration guidance for Blue-Tap.

---

## Kali Linux (Recommended)

Kali ships with all required Bluetooth tools pre-installed. This is the path of least resistance.

### Setup

```bash
# Install Blue-Tap
pip install blue-tap

# Install optional spoofing tools (not in base Kali)
sudo apt install bdaddr spooftooph
```

### Verification

```bash
# Verify all tools are present
which bluetoothctl hciconfig btmgmt sdptool btmon
# Expected: all paths printed, no "not found"

# Verify BlueZ version (should be 5.66+)
bluetoothctl --version

# Verify Bluetooth service is running
systemctl status bluetooth

# Verify adapter is recognized
hciconfig -a

# Run Blue-Tap's environment check
sudo blue-tap doctor
```

### Platform Details

- BlueZ version: typically 5.66+
- Audio: PipeWire + WirePlumber default since Kali 2023.x
- BlueZ `--compat` mode: typically already enabled in Kali
- Root access: Kali defaults to root user, so no `sudo` needed for most operations

### Complete Setup Script

```bash
#!/bin/bash
# Kali Linux setup for Blue-Tap
set -e

echo "[1/4] Installing Blue-Tap..."
pip install blue-tap

echo "[2/4] Installing optional tools..."
sudo apt install -y bdaddr spooftooph

echo "[3/4] Ensuring BlueZ --compat mode..."
if ! grep -q '\-\-compat' /lib/systemd/system/bluetooth.service 2>/dev/null; then
    sudo sed -i 's|ExecStart=.*/bluetoothd|& --compat|' /lib/systemd/system/bluetooth.service
    sudo systemctl daemon-reload
    sudo systemctl restart bluetooth
    echo "  Enabled --compat mode"
else
    echo "  --compat mode already enabled"
fi

echo "[4/4] Verifying environment..."
sudo blue-tap doctor

echo "Setup complete."
```

---

## Ubuntu / Debian

### Setup

```bash
# Core BlueZ tools
sudo apt install bluez bluez-tools

# Spoofing tools
sudo apt install spooftooph
# bdaddr may need manual build from BlueZ source (see below)

# Audio utilities (for HFP/A2DP capture)
sudo apt install pulseaudio-utils

# Enable bluetooth service
sudo systemctl enable --now bluetooth
```

### BlueZ Compatibility Mode

Required for `sdptool` and SDP operations:

```bash
sudo sed -i 's|ExecStart=.*/bluetoothd|& --compat|' /lib/systemd/system/bluetooth.service
sudo systemctl daemon-reload
sudo systemctl restart bluetooth
```

### Building bdaddr from Source

On Ubuntu/Debian, `bdaddr` is not packaged separately. To build it:

```bash
# Install build dependencies
sudo apt install build-essential libbluetooth-dev

# Download BlueZ source (match your installed version)
BLUEZ_VER=$(bluetoothctl --version | grep -oP '\d+\.\d+')
wget https://www.kernel.org/pub/linux/bluetooth/bluez-${BLUEZ_VER}.tar.xz
tar xf bluez-${BLUEZ_VER}.tar.xz
cd bluez-${BLUEZ_VER}

# Build bdaddr
./configure
make tools/bdaddr
sudo cp tools/bdaddr /usr/local/bin/
```

### Verification

```bash
# Verify tools
which bluetoothctl hciconfig btmgmt sdptool btmon

# Verify BlueZ version
bluetoothctl --version

# Verify --compat mode
sudo sdptool browse local
# Should succeed without errors

# Check Bluetooth service
systemctl status bluetooth

# Check adapters
hciconfig -a

# Blue-Tap environment check
sudo blue-tap doctor
```

### Complete Setup Script

```bash
#!/bin/bash
# Ubuntu / Debian setup for Blue-Tap
set -e

echo "[1/6] Installing system dependencies..."
sudo apt update
sudo apt install -y bluez bluez-tools spooftooph pulseaudio-utils

echo "[2/6] Installing Blue-Tap..."
pip install blue-tap

echo "[3/6] Enabling Bluetooth service..."
sudo systemctl enable --now bluetooth

echo "[4/6] Enabling BlueZ --compat mode..."
if ! grep -q '\-\-compat' /lib/systemd/system/bluetooth.service 2>/dev/null; then
    sudo sed -i 's|ExecStart=.*/bluetoothd|& --compat|' /lib/systemd/system/bluetooth.service
    sudo systemctl daemon-reload
    sudo systemctl restart bluetooth
    echo "  Enabled --compat mode"
else
    echo "  --compat mode already enabled"
fi

echo "[5/6] Verifying sdptool works..."
sudo sdptool browse local > /dev/null 2>&1 && echo "  sdptool: OK" || echo "  sdptool: FAILED (--compat may not have applied)"

echo "[6/6] Running environment check..."
sudo blue-tap doctor

echo "Setup complete."
```

---

## Raspberry Pi

### Hardware Considerations

- **Onboard BCM4345C0**: works for scanning, limited spoofing capability
- **Recommended**: add a USB TP-Link UB500 for full functionality
- **Power**: use a powered USB hub for USB Bluetooth adapters to avoid undervoltage
- **Performance**: adequate for scanning and assessment; fuzzing campaigns may be slow on older Pi models (Pi 3 and below)

### Setup

Installation is the same as Ubuntu/Debian (Raspberry Pi OS is Debian-based):

```bash
# Same as Ubuntu/Debian setup
sudo apt install bluez bluez-tools spooftooph pulseaudio-utils
pip install blue-tap
```

### Verification

```bash
# Check onboard adapter
hciconfig -a
# Should show hci0 with BCM4345C0 or similar

# Check USB adapter (if connected)
lsusb | grep -i bluetooth

# Verify both adapters
blue-tap adapter list

# Environment check
sudo blue-tap doctor
```

### Complete Setup Script

```bash
#!/bin/bash
# Raspberry Pi setup for Blue-Tap
set -e

echo "[1/6] Installing system dependencies..."
sudo apt update
sudo apt install -y bluez bluez-tools spooftooph pulseaudio-utils

echo "[2/6] Installing Blue-Tap..."
pip install blue-tap

echo "[3/6] Enabling Bluetooth service..."
sudo systemctl enable --now bluetooth

echo "[4/6] Enabling BlueZ --compat mode..."
if ! grep -q '\-\-compat' /lib/systemd/system/bluetooth.service 2>/dev/null; then
    sudo sed -i 's|ExecStart=.*/bluetoothd|& --compat|' /lib/systemd/system/bluetooth.service
    sudo systemctl daemon-reload
    sudo systemctl restart bluetooth
fi

echo "[5/6] Checking adapters..."
echo "  Onboard:"
hciconfig hci0 2>/dev/null && echo "    hci0: present" || echo "    hci0: not found"
echo "  USB:"
lsusb | grep -i bluetooth || echo "    No USB Bluetooth adapter detected"

echo "[6/6] Running environment check..."
sudo blue-tap doctor

echo ""
echo "Setup complete."
echo "Tip: For full functionality, connect a TP-Link UB500 via a powered USB hub."
```

### Raspberry Pi Specific Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| `Cannot allocate memory` during fuzzing | Pi has limited RAM (1-4GB) | Reduce corpus size or use `--max-corpus 1000` |
| Adapter resets during long scans | USB undervoltage | Use a powered USB hub |
| Slow scan times | RPi CPU throttling | Check `vcgencmd measure_temp` and ensure adequate cooling |
| Onboard BT interferes with USB adapter | Both adapters try to scan | Use `--hci hci1` to target the USB adapter explicitly |

---

## General Linux Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Kernel | 5.x with `CONFIG_BT`, `CONFIG_BT_HCIBTUSB` | Latest stable |
| BlueZ | 5.50+ | 5.66+ |
| Python | 3.10+ | 3.12+ |
| D-Bus | Running (for OBEX operations via obexd) | - |
| Privileges | Root / sudo for HCI operations | - |

### Verifying Kernel Bluetooth Support

```bash
# Check kernel config for Bluetooth support
zcat /proc/config.gz 2>/dev/null | grep CONFIG_BT || grep CONFIG_BT /boot/config-$(uname -r)
# Should show:
#   CONFIG_BT=m (or =y)
#   CONFIG_BT_HCIBTUSB=m (or =y)

# Check if Bluetooth kernel modules are loaded
lsmod | grep -E "bluetooth|btusb|hci"
# Should show: bluetooth, btusb, btbcm/btrtl/btintel (chipset-specific)

# If modules are not loaded
sudo modprobe bluetooth
sudo modprobe btusb
```

### Full Environment Verification

```bash
# Run Blue-Tap's comprehensive check
sudo blue-tap doctor

# Manual verification steps if doctor is not available:

# 1. Python version
python3 --version  # Must be 3.10+

# 2. BlueZ version
bluetoothctl --version  # Must be 5.50+

# 3. Required tools
for tool in bluetoothctl hciconfig btmgmt sdptool btmon; do
    which $tool > /dev/null 2>&1 && echo "$tool: OK" || echo "$tool: MISSING"
done

# 4. Bluetooth service
systemctl is-active bluetooth && echo "bluetooth service: running" || echo "bluetooth service: NOT running"

# 5. Adapter check
hciconfig -a

# 6. Privileges
[ "$(id -u)" -eq 0 ] && echo "Running as root: YES" || echo "Running as root: NO (use sudo)"

# 7. SDP compatibility
sudo sdptool browse local > /dev/null 2>&1 && echo "sdptool: OK (--compat enabled)" || echo "sdptool: FAILED (enable --compat)"
```
