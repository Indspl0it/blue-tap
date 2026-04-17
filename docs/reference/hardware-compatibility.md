# Hardware Compatibility

Bluetooth adapter compatibility matrix and chipset-specific notes for Blue-Tap.

---

## Adapter Compatibility Matrix

| Adapter | Chipset | VID:PID | Classic | BLE | DarkFirmware | MAC Spoofing | Notes |
|---------|---------|---------|---------|-----|--------------|--------------|-------|
| TP-Link UB500 | RTL8761B | `2357:0604` | Yes | Yes | Yes | RAM patch (instant) | Best for Blue-Tap -- enables all features |
| Generic CSR 8510 | CSR 8510 A10 | `0A12:0001` | Yes | No | No | bdaddr | Classic only, widely available |
| Intel AX200 | Intel | `8087:0029` | Yes | Yes | No | btmgmt (limited) | Laptop built-in, limited spoofing |
| Intel AX201 | Intel | `8087:0026` | Yes | Yes | No | btmgmt (limited) | Laptop built-in |
| Intel AX210/211 | Intel | `8087:0032` / `8087:0033` | Yes | Yes | No | btmgmt (limited) | WiFi 6E combo |
| Broadcom BCM20702 | Broadcom | `0A5C:21E8` | Yes | Yes | No | bdaddr / spooftooph | Good general-purpose |
| Qualcomm AR3012 | Qualcomm | `0CF3:3004` | Yes | Yes | No | spooftooph | Older USB dongles |
| Realtek RTL8821C | Realtek | `0BDA:B00A` | Yes | Yes | No | spooftooph / btmgmt | Budget BLE dongle |

---

## Buying Guide

### The One Adapter You Need

If you buy one adapter, get the **TP-Link UB500**. It uses the RTL8761B chipset, which is the only chipset Blue-Tap supports for DarkFirmware operations (below-HCI packet injection, firmware-level MAC spoofing, raw ACL transmission). Without it, you lose access to approximately 40% of Blue-Tap's capabilities.

- **Price**: Approximately INR 599 / USD 13
- **Where to buy**: Amazon, any electronics retailer
- **USB**: USB-A 2.0 dongle, compact form factor
- **Bluetooth**: 5.0, dual-mode (Classic + BLE)

### Recommended Two-Adapter Setup

For professional assessments, use two adapters simultaneously:

1. **Primary (TP-Link UB500 / RTL8761B)**: DarkFirmware attacks, MAC spoofing, raw ACL operations, below-HCI fuzzing
2. **Secondary (any Classic+BLE adapter)**: Passive scanning and monitoring while the primary is engaged in active operations

Blue-Tap's `recommend_adapter_roles()` logic automatically assigns scan vs. attack roles when multiple adapters are present.

### Budget Options

| Use Case | Adapter | Approximate Cost |
|----------|---------|-----------------|
| Full Blue-Tap capabilities | TP-Link UB500 | INR 599 / USD 13 |
| Classic-only basic testing | Generic CSR 8510 | INR 200 / USD 5 |
| BLE + Classic scanning | Realtek RTL8821C dongle | INR 400 / USD 8 |
| Laptop built-in (no purchase needed) | Intel AX200/201/210 | Free |

---

## Identifying Your Chipset

If you have an adapter and want to know what chipset it uses:

### USB Adapters

```bash
# List all USB Bluetooth devices
lsusb | grep -i bluetooth

# Example output:
# Bus 001 Device 003: ID 2357:0604 TP-Link UB500
# Bus 001 Device 002: ID 0a12:0001 Cambridge Silicon Radio, Ltd Bluetooth Dongle

# Get detailed chipset info
lsusb -v -d 2357:0604 2>/dev/null | grep -E "idVendor|idProduct|iProduct|iManufacturer"
```

### HCI-Level Identification

```bash
# Show all adapters with chipset details
hciconfig -a

# Get manufacturer and LMP version
hcitool -i hci0 info AA:BB:CC:DD:EE:FF  # (for a connected device)

# Blue-Tap's built-in adapter info
blue-tap adapter list
blue-tap adapter info --hci hci0
```

### RTL8761B Verification

```bash
# Check if the RTL8761B firmware file is present
ls -la /lib/firmware/rtl_bt/rtl8761bu_fw.bin

# Check USB device
lsusb | grep 2357:0604

# Check kernel driver loaded
dmesg | grep -i rtl8761
```

### Checking DarkFirmware Capability

```bash
# Blue-Tap checks this automatically
blue-tap adapter list

# Look for "DarkFirmware: capable" or "DarkFirmware: active" in the output
blue-tap adapter info --hci hci1
```

---

## Recommended Setup

- **Primary adapter**: TP-Link UB500 (RTL8761B) for attacks requiring DarkFirmware, MAC spoofing, and below-HCI operations
- **Secondary adapter**: any Classic+BLE adapter for passive scanning while the primary is engaged in an attack
- Use `blue-tap adapter list` to see all connected adapters and their capabilities
- Blue-Tap's `recommend_adapter_roles()` logic automatically assigns scan vs spoof roles when multiple adapters are present

---

## Known Issues

| Adapter / Chipset | Issue |
|-------------------|-------|
| Intel adapters | Limited MAC spoofing -- `btmgmt public-addr` may not work on all firmware versions |
| CSR 8510 | Classic only, no BLE support |
| Broadcom BCM4345C0 (RPi onboard) | Works for scanning but limited spoofing capability |
| Some adapters | Require `usbreset` after firmware changes or extended fuzzing sessions |

---

## Chipset-Specific Notes

### Realtek (RTL8761B, RTL8821C)

- USB reset required after firmware flash; Blue-Tap handles this automatically
- udev rules may affect auto-detection if custom rules are installed
- RTL8761B is the only chipset with DarkFirmware support for below-HCI operations
- The RTL8761B uses a MIPS16 processor in its Bluetooth controller; DarkFirmware patches are applied to the controller's RAM at load time

### Intel (AX200, AX201, AX210)

- SSP disable may require a kernel module parameter
- MAC spoofing is unreliable -- `btmgmt public-addr` support varies by firmware version
- Built-in laptop adapters work well for scanning and assessment but not for attacks requiring spoofing
- Intel adapters share the WiFi/BT combo card, so WiFi interference can affect Bluetooth operations

### CSR (CSR 8510)

- `bdaddr` tool must be compiled from BlueZ source on some distributions
- Classic-only -- no BLE scanning or BLE-based attacks
- Cheapest option for basic Classic Bluetooth testing
- Very common in USB dongles sold as "Bluetooth 4.0" -- the 4.0 refers to the USB spec, not the Bluetooth version

### Broadcom (BCM20702, BCM4345C0)

- `spooftooph` works best for MAC spoofing
- `bdaddr` may require a specific firmware version to function
- RPi onboard Broadcom is adequate for scanning but not recommended for active attacks
- On Raspberry Pi, the onboard BT shares the SDIO bus with WiFi, which can cause throughput issues under heavy use
