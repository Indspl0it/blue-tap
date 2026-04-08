# Troubleshooting & Platform Notes

> **[Back to README](../README.md)**

### Adapter Issues

**"No adapters found" / "Adapter not found"**
```bash
# Check if adapter exists
hciconfig -a

# If rfkill is blocking
rfkill list bluetooth
rfkill unblock bluetooth

# If USB dongle not recognized
lsusb | grep -i bluetooth

# Bring adapter up manually
sudo hciconfig hci0 up
```

**"Operation not permitted"**
```bash
# Most Blue-Tap commands require root
sudo blue-tap scan classic

# Or set capabilities (alternative to sudo)
sudo setcap cap_net_raw,cap_net_admin+eip $(which python3)
```

### Scanning Issues

**"No devices found"**
- Ensure target is discoverable (`hciconfig hci0 | grep PSCAN` on target)
- Increase scan duration: `blue-tap scan classic -d 30`
- Try from closer range (Bluetooth range ~10m)
- Check for RF interference

**BLE scan shows no results**
- Ensure BLE is enabled: `sudo btmgmt le on`
- Try passive mode: `blue-tap scan ble --passive`
- Some adapters need LE explicitly enabled in btmgmt

### Connection Issues

**"Connection refused" on RFCOMM**
- Target service may require pairing first
- Check if the channel is correct: `blue-tap recon rfcomm-scan <MAC>`
- Service may have been deregistered

**"Permission denied" on L2CAP**
- L2CAP PSMs below 4096 require root: `sudo blue-tap ...`
- Check if PSM is blocked by the kernel: `cat /proc/sys/net/bluetooth/l2cap_enable_ertm`

**Pairing failures**
- Check pairing mode: `blue-tap recon pairing-mode <MAC>`
- For SSP devices, PIN brute-force won't work
- Try `blue-tap recon ssp <MAC>` to verify

### SDP Issues

**"Failed to connect to SDP server"**
```bash
# Enable BlueZ compatibility mode
sudo sed -i 's|ExecStart=.*/bluetoothd|& --compat|' /lib/systemd/system/bluetooth.service
sudo systemctl daemon-reload
sudo systemctl restart bluetooth
```

### Fuzzing Issues

**"scapy not found"**
```bash
# Install fuzzing dependencies
pip install -e ".[fuzz]"
# or
pip install scapy>=2.5
```

**"No crash database found"**
- Run a fuzz campaign first to create the database
- Specify session: `blue-tap fuzz crashes list -s <session_name>`

**Target becomes unresponsive during fuzzing**
- Increase `--delay` between test cases: `--delay 2.0`
- Increase `--cooldown` after crash: `--cooldown 10`
- Reduce iteration rate with `--timeout 5`
- The target's Bluetooth stack may need manual restart

### Audio Issues

**"PulseAudio: connection refused"**
```bash
# Check PulseAudio/PipeWire is running
pactl info

# Restart audio service
blue-tap audio restart

# Diagnose Bluetooth audio routing
blue-tap audio diagnose <MAC>
```

**No audio sources/sinks visible**
```bash
blue-tap audio devices
# If empty: pair the device first, then switch profile
blue-tap audio profile <MAC> a2dp   # or hfp
```

### MAC Spoofing Issues

**"bdaddr not found"**
```bash
# Install bdaddr (part of bluez-tools or build from source)
sudo apt install bluez-tools
# or
# Build bdaddr from BlueZ source
```

**"Cannot change MAC" / "Operation not supported"**
- Intel adapters typically do not support MAC spoofing
- Use an RTL8761B USB dongle (TP-Link UB500) — supports DarkFirmware for MAC spoofing via firmware patch
- Some adapters require the interface to be down: `sudo hciconfig hci0 down` before spoofing

### Report Issues

**"No session data found"**
- Ensure you used `-s` flag consistently: `blue-tap -s mytest scan classic`
- Check session exists: `blue-tap session list`
- Point to specific directory: `blue-tap report ./my_output_dir/`

---

## Platform Notes

### Kali Linux (Recommended)

- All tools pre-installed (BlueZ, hcitool, sdptool, btmgmt, bluetoothctl)
- May need `--compat` flag for bluetoothd
- Use an external USB adapter (RTL8761B / TP-Link UB500) for full feature access including DarkFirmware

### Ubuntu / Debian

```bash
sudo apt install -y bluez bluez-tools python3-pip python3-dev python3-venv libbluetooth-dev
```


---

## License

Blue-Tap is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

Copyright (C) 2026 Santhosh Ballikonda

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
