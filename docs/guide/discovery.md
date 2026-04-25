# Discovery

**Module:** `discovery.scanner` (1 module)

**Outcomes:** `observed`, `merged`, `correlated`, `partial`, `not_applicable`

Discovery is the first phase of any Bluetooth assessment. Before you can enumerate services, scan for vulnerabilities, or exploit anything, you need to know what devices are in radio range. The discovery module scans for nearby Bluetooth targets using one or more radio modes, merges results by address, and outputs a unified device list with parsed metadata.

Unlike Wi-Fi scanning, Bluetooth discovery is inherently active for Classic devices --- the inquiry process sends broadcast frames that nearby devices respond to. BLE supports passive scanning where you only listen for advertisements without transmitting.

---

## Scan Modes

### Classic

Uses `hcitool inquiry` with name resolution under a bounded time budget. Classic inquiry works by sending inquiry packets on 32 hop channels; devices in "discoverable" mode respond with their address, clock offset, and Class of Device (CoD).

**Returns per device:**

| Field | Description |
|-------|-------------|
| `address` | BD_ADDR (e.g., `4C:4F:EE:17:3A:89`) |
| `name` | Bluetooth device name (if resolved) |
| `class` | Parsed Class of Device (CoD) --- major, minor, service classes |
| `rssi` | Signal strength in dBm |
| `oui_vendor` | IEEE OUI vendor lookup |
| `clock_offset` | Clock offset from inquiry response |

!!! example "Classic scan output"
    ```
    $ sudo blue-tap discover classic -d 20
    Session: blue-tap_20260416_143022

    ── Classic Scan (20s) ──────────────────────────────────────────────────────────

    ┌─────────────────────┬──────────────────┬────────────────┬───────┬──────────────────┐
    │ Address             │ Name             │ Class          │ RSSI  │ Vendor           │
    ├─────────────────────┼──────────────────┼────────────────┼───────┼──────────────────┤
    │ 4C:4F:EE:17:3A:89  │ MY-CAR-AUDIO     │ Car Audio      │ -45   │ Harman Intl.     │
    │ F8:27:93:A1:D4:12  │ Galaxy S24       │ Smartphone     │ -62   │ Samsung          │
    │ DC:A6:32:8F:11:C0  │ Jabra Elite 85t  │ Headphones     │ -71   │ GN Audio         │
    │ 38:1A:52:00:C7:88  │ ThinkPad X1      │ Laptop         │ -78   │ Lenovo           │
    └─────────────────────┴──────────────────┴────────────────┴───────┴──────────────────┘

    Found 4 Classic devices (1 IVI flagged)
    ```

!!! info "IVI Detection"
    In-Vehicle Infotainment systems are flagged when CoD matches major class `Audio/Video` (`0x04`) with minor class `Car Audio` (`0x08`). Blue-Tap highlights these automatically because IVI systems are high-value targets --- they often have outdated Bluetooth stacks, weak or no authentication, and access to vehicle buses.

!!! note "Non-Discoverable Devices"
    Classic inquiry only finds devices in "discoverable" mode. Many phones and laptops are non-discoverable by default. If you know a target's address from a previous scan or external source, skip discovery and go directly to [Reconnaissance](reconnaissance.md).

### BLE

Uses `bleak.BleakScanner.discover()` for Low Energy scanning. BLE devices broadcast advertisement packets continuously; the scanner captures these and parses the payload.

**Passive mode** (`--passive`): suppresses `SCAN_REQ` packets --- the scanner never contacts the target device. This means you only receive the initial advertisement data, not the scan response. Useful for covert enumeration where you do not want the target's controller to log your presence.

**Returns per device:**

| Field | Description |
|-------|-------------|
| `address` | BLE address (may be random/resolvable) |
| `name` | Local name from advertisement |
| `rssi` | Signal strength in dBm |
| `tx_power` | Transmit power from advertisement (if present) |
| `service_uuids` | Advertised GATT service UUIDs |
| `manufacturer_data` | Keyed by company ID |
| `distance_m` | Estimated distance via log-distance path loss |

!!! example "BLE passive scan output"
    ```
    $ sudo blue-tap discover ble --passive -d 15
    Session: blue-tap_20260416_143205

    ── BLE Scan (15s, passive) ─────────────────────────────────────────────────────

    ┌─────────────────────┬──────────────────┬───────┬──────────┬──────────────────────────────────┐
    │ Address             │ Name             │ RSSI  │ Dist (m) │ Services                         │
    ├─────────────────────┼──────────────────┼───────┼──────────┼──────────────────────────────────┤
    │ DE:AD:BE:EF:CA:FE   │ Smart Lock v2    │ -52   │ 1.8      │ 0xFFF0 (Custom)                  │
    │ 7A:11:8C:D3:02:F1   │ (unknown)        │ -64   │ 4.2      │ 0x180F (Battery), 0x1812 (HID)   │
    │ C4:7C:8D:6B:AA:10   │ MI Band 7        │ -58   │ 2.5      │ 0xFEE0 (Xiaomi), 0x180D (HR)     │
    │ 4F:E1:22:9A:BB:CC   │ AirPods Pro      │ -73   │ 8.1      │ ---                              │
    └─────────────────────┴──────────────────┴───────┴──────────┴──────────────────────────────────┘

    Found 4 BLE devices
    ```

**Known manufacturer IDs:**

| Company ID | Vendor |
|------------|--------|
| `0x004C` | Apple |
| `0x0006` | Microsoft |
| `0x00E0` | Google |
| `0x0075` | Samsung |

!!! tip "BLE Address Types"
    BLE devices often use **random resolvable addresses** that rotate periodically. The address you see during discovery may not be the same address on the next scan. If the device has a public address (common for IoT devices, headphones, and IVI systems), it remains stable. Random addresses are common for phones and wearables.

### Combined (Default)

Runs Classic and BLE scans sequentially, then merges results. This is the default mode when you run `blue-tap discover` or `blue-tap discover all`.

The merge logic works in two stages:

- **Exact-address merge**: same MAC appearing in both scans is unified into a single entry. This happens when a dual-mode device uses the same BD_ADDR for both Classic and BLE.
- **Dual-mode correlation hints**: devices with matching name + vendor and similar signal profile (RSSI within 15 dBm) are flagged as "likely dual-mode" even if their addresses differ. This is a heuristic --- the `dual_mode_hint` field is informational, not authoritative.

!!! example "Combined scan with dual-mode correlation"
    ```
    $ sudo blue-tap discover all -d 30
    Session: blue-tap_20260416_143410

    ── Classic Scan (30s) ──────────────────────────────────────────────────────────
    Found 3 Classic devices

    ── BLE Scan (30s) ──────────────────────────────────────────────────────────────
    Found 5 BLE devices

    ── Merged Results ──────────────────────────────────────────────────────────────

    ┌─────────────────────┬──────────────────┬────────────┬───────┬──────────────────┬────────────┐
    │ Address             │ Name             │ Class      │ RSSI  │ Vendor           │ Dual-mode  │
    ├─────────────────────┼──────────────────┼────────────┼───────┼──────────────────┼────────────┤
    │ 4C:4F:EE:17:3A:89  │ MY-CAR-AUDIO     │ Car Audio  │ -45   │ Harman Intl.     │ confirmed  │
    │ F8:27:93:A1:D4:12  │ Galaxy S24       │ Smartphone │ -62   │ Samsung          │ likely     │
    │ DC:A6:32:8F:11:C0  │ Jabra Elite 85t  │ Headphones │ -71   │ GN Audio         │ confirmed  │
    │ DE:AD:BE:EF:CA:FE   │ Smart Lock v2    │ ---        │ -52   │ ---              │ BLE only   │
    │ C4:7C:8D:6B:AA:10   │ MI Band 7        │ ---        │ -58   │ Xiaomi           │ BLE only   │
    └─────────────────────┴──────────────────┴────────────┴───────┴──────────────────┴────────────┘

    Found 5 unique devices (2 dual-mode confirmed, 1 likely, 2 BLE-only)
    ```

---

## Class of Device (CoD) Parsing

The Class of Device is a 24-bit field that Bluetooth Classic devices include in their inquiry response. Blue-Tap parses it into three components:

**Major device class** (bits 12--8): broad category --- Computer, Phone, Audio/Video, Peripheral, etc.

**Minor device class** (bits 7--2): specific type within the major class. For example, within Audio/Video:

| Minor class value | Name |
|-------------------|------|
| `0x01` | Wearable Headset |
| `0x02` | Hands-Free Device |
| `0x06` | Headphones |
| `0x08` | Car Audio |
| `0x0A` | HiFi Audio |

**Service class bits** (bits 23--13): capabilities the device advertises --- Audio, Telephony, Networking, Object Transfer, etc.

!!! example "CoD parsing example"
    A device reporting CoD `0x5a020c` breaks down as:

    - **Raw**: `0x5a020c`
    - **Major**: Phone (`0x02`)
    - **Minor**: Smartphone (`0x03`)
    - **Service bits**: Audio (bit 21), Telephony (bit 22), Object Transfer (bit 20), Networking (bit 17)

    This tells you it is a smartphone that supports audio streaming, phone calls, file transfer, and network access --- a typical modern Android or iPhone.

!!! tip "Why CoD Matters for Assessment"
    CoD reveals the target's capabilities before you connect to it. A device advertising "Object Transfer" likely supports OBEX/OPP, which means you should run `recon TARGET sdp` and look for OBEX-related services. A device with "Car Audio" is an IVI system worth deeper investigation. A device with "HID" service bits may be vulnerable to CVE-2023-45866 (HOGP pre-auth injection).

---

## CLI Usage

### Discover all nearby devices (Classic + BLE)

```bash
blue-tap discover all
```

### Classic-only scan with 20-second duration

```bash
blue-tap discover classic -d 20
```

### BLE passive scan on a specific adapter

```bash
blue-tap discover ble --passive -a hci1
```

### Extended combined scan

```bash
blue-tap discover all -d 30
```

---

## Distance Estimation

BLE distance is estimated using the log-distance path loss model:

$$
d = 10^{\frac{TX_{power} - RSSI}{10 \cdot n}}
$$

Where:

- `TX_power` is the advertised transmit power (dBm), or -59 dBm default if not present
- `RSSI` is the received signal strength (dBm)
- `n` is the path-loss exponent (default: 2.5 --- tuned for mixed indoor/outdoor)

!!! warning "Accuracy"
    Distance estimates are approximate. Walls, interference, multipath reflections, and antenna orientation significantly affect accuracy. In practice, expect +/- 50% error indoors. Treat values as **relative ordering** (which device is closer), not absolute measurements.

!!! tip "Using Distance Operationally"
    Sort by distance to prioritize targets. A device at 1--2m is likely on your table or in your hand. A device at 8--10m might be in an adjacent room. During an IVI assessment in a parking lot, distance helps you identify which car's head unit you are looking at when multiple are in range.

---

## Output Fields

| Field | Classic | BLE | Combined |
|-------|---------|-----|----------|
| `address` | Yes | Yes | Yes |
| `name` | Yes | Yes | Yes |
| `class` (CoD) | Yes | No | Classic only |
| `rssi` | Yes | Yes | Yes |
| `tx_power` | No | Yes | BLE only |
| `service_uuids` | No | Yes | BLE only |
| `manufacturer_data` | No | Yes | BLE only |
| `distance_m` | No | Yes | BLE only |
| `oui_vendor` | Yes | No | Classic only |
| `clock_offset` | Yes | No | Classic only |
| `dual_mode_hint` | No | No | Yes |

---

## What's Next?

Once you have identified targets, the next step is deep reconnaissance to enumerate their services and capabilities:

- [Reconnaissance](reconnaissance.md) --- enumerate SDP services, GATT characteristics, open L2CAP/RFCOMM channels, and fingerprint the target
- [Vulnerability Assessment](vulnerability-assessment.md) --- if you want to skip recon and go straight to scanning for known CVEs
- [CLI Reference](cli-reference.md) --- full command reference for all Blue-Tap commands
