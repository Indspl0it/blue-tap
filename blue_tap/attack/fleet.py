"""Fleet-wide Bluetooth assessment — scan, classify, assess, and report.

Discovers all nearby Bluetooth devices, classifies them by type (IVI, phone,
headset, etc.), runs vulnerability assessments on selected targets, and
generates a consolidated fleet report.
"""

import time
from datetime import datetime, timezone

from blue_tap.utils.bt_helpers import normalize_mac
from blue_tap.utils.output import error, info, success, warning


# ============================================================================
# Bluetooth device class major categories (bits 12-8 of CoD)
# ============================================================================
_MAJOR_CLASS = {
    0x0100: "computer",
    0x0200: "phone",
    0x0300: "networking",
    0x0400: "audio_video",
    0x0500: "peripheral",
    0x0600: "imaging",
    0x0700: "wearable",
}

# Audio/Video minor classes (bits 7-2 of CoD)
_AV_MINOR_IVI = {0x08}  # Car Audio


# ============================================================================
# Name-based heuristics
# ============================================================================
_IVI_NAME_KEYWORDS = [
    "car", "ivi", "infotainment",
    # OEMs
    "bmw", "toyota", "honda", "ford", "audi", "mercedes", "kia",
    "hyundai", "nissan",
    # Head-unit / audio vendors common in vehicles
    "harman", "bose", "jbl", "pioneer", "alpine", "kenwood",
    "denso", "bosch",
]

_PHONE_NAME_KEYWORDS = [
    "galaxy", "iphone", "pixel", "oneplus", "xiaomi", "huawei",
]

_HEADSET_NAME_KEYWORDS = [
    "airpods", "buds", "headphone", "earphone", "headset", "earbuds",
    "wh-1000", "wf-1000", "jabra", "plantronics", "beats",
]

# HFP Audio Gateway UUID indicates car kit / IVI
_HFP_AG_UUID = "0x111f"


# ============================================================================
# DeviceClassifier
# ============================================================================

class DeviceClassifier:
    """Classify a scanned Bluetooth device into a category."""

    CATEGORIES = ("ivi", "phone", "headset", "computer", "wearable", "unknown")

    def classify(self, device: dict) -> str:
        """Return one of: ivi, phone, headset, computer, wearable, unknown."""
        # 1. Check service UUIDs first (strongest signal)
        service_uuids = device.get("service_uuids") or []
        for uuid in service_uuids:
            if str(uuid).lower() == _HFP_AG_UUID:
                return "ivi"

        # 2. Check Bluetooth device class
        raw_class = device.get("class")
        if raw_class:
            try:
                cod = int(raw_class, 16) if isinstance(raw_class, str) else int(raw_class)
            except (ValueError, TypeError):
                cod = 0

            major = cod & 0x1F00
            minor = (cod >> 2) & 0x3F

            if major == 0x0400 and minor in _AV_MINOR_IVI:
                return "ivi"
            if major == 0x0200:
                return "phone"
            if major == 0x0100:
                return "computer"
            if major == 0x0700:
                return "wearable"
            # Audio/Video non-IVI — likely headset/speaker
            if major == 0x0400:
                return "headset"

        # 3. Name heuristics (weakest signal)
        name = (device.get("name") or "").lower()
        if name:
            if any(kw in name for kw in _IVI_NAME_KEYWORDS):
                return "ivi"
            if any(kw in name for kw in _PHONE_NAME_KEYWORDS):
                return "phone"
            if any(kw in name for kw in _HEADSET_NAME_KEYWORDS):
                return "headset"

        return "unknown"


# ============================================================================
# FleetAssessment
# ============================================================================

class FleetAssessment:
    """Scan, classify, assess, and report on all nearby Bluetooth devices."""

    def __init__(self, hci: str = "hci0", scan_duration: int = 15):
        self.hci = hci
        self.scan_duration = scan_duration
        self._classifier = DeviceClassifier()
        self._scan_results: list[dict] = []
        self._assessment_results: list[dict] = []

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    def scan(self) -> list[dict]:
        """Run classic + BLE scan, classify all discovered devices.

        Returns a list sorted by classification then RSSI, each entry:
        {address, name, rssi, type, classification, services_found}
        """
        from blue_tap.core.scanner import scan_all

        info(f"Fleet scan: discovering devices for {self.scan_duration}s on {self.hci}...")
        raw_devices = scan_all(self.scan_duration, self.hci)

        results = []
        for dev in raw_devices:
            classification = self._classifier.classify(dev)
            results.append({
                "address": dev.get("address", ""),
                "name": dev.get("name", "Unknown"),
                "rssi": dev.get("rssi", "N/A"),
                "type": dev.get("type", "Unknown"),
                "classification": classification,
                "services_found": dev.get("service_uuids", []),
            })

        # Sort: IVIs first, then by classification alpha, then RSSI descending
        class_order = {c: i for i, c in enumerate(DeviceClassifier.CATEGORIES)}
        results.sort(key=lambda d: (
            class_order.get(d["classification"], 99),
            -(d["rssi"] if isinstance(d["rssi"], (int, float)) else -999),
        ))

        self._scan_results = results
        success(f"Fleet scan complete: {len(results)} device(s) discovered")
        for cat in DeviceClassifier.CATEGORIES:
            count = sum(1 for d in results if d["classification"] == cat)
            if count:
                info(f"  {cat}: {count}")
        return results

    # ------------------------------------------------------------------
    # Assess
    # ------------------------------------------------------------------

    def assess(
        self,
        targets: list[str] | None = None,
        device_class: str = "ivi",
    ) -> list[dict]:
        """Run fingerprint + vuln scan on each target.

        Args:
            targets: Explicit list of MAC addresses. If None, assess all
                     devices matching *device_class* from the last scan.
            device_class: Device classification to auto-select (default "ivi").

        Returns:
            Per-device assessment results.
        """
        from blue_tap.recon.fingerprint import fingerprint_device
        from blue_tap.attack.vuln_scanner import scan_vulnerabilities

        # Resolve target list
        if targets:
            target_addrs = []
            for t in targets:
                try:
                    target_addrs.append(normalize_mac(t))
                except ValueError:
                    warning(f"Skipping invalid MAC: {t}")
                    continue
        else:
            if not self._scan_results:
                warning("No scan results — run scan() first or provide explicit targets")
                return []
            target_addrs = [
                d["address"] for d in self._scan_results
                if d["classification"] == device_class
            ]

        if not target_addrs:
            warning(f"No devices matching class '{device_class}' to assess")
            return []

        info(f"Assessing {len(target_addrs)} device(s)...")
        results = []

        for i, addr in enumerate(target_addrs):
            if i > 0:
                time.sleep(2)  # rate-limit between devices

            info(f"[{i + 1}/{len(target_addrs)}] Assessing {addr}...")
            device_result: dict = {
                "address": addr,
                "name": "",
                "classification": device_class,
                "fingerprint": {},
                "findings": [],
                "risk_rating": "UNKNOWN",
                "error": None,
            }

            # Look up name from scan results
            for d in self._scan_results:
                if d["address"].upper() == addr.upper():
                    device_result["name"] = d["name"]
                    device_result["classification"] = d["classification"]
                    break

            try:
                # Fingerprint
                fp = fingerprint_device(addr, hci=self.hci)
                device_result["fingerprint"] = fp
                device_result["name"] = fp.get("name") or device_result["name"]

                # Vulnerability scan
                findings = scan_vulnerabilities(addr, hci=self.hci)
                device_result["findings"] = findings

                # Rate per device
                device_result["risk_rating"] = self._rate_device(findings)
                success(f"  {addr}: {device_result['risk_rating']} "
                        f"({len(findings)} finding(s))")

            except Exception as exc:
                device_result["error"] = str(exc)
                error(f"  {addr}: assessment failed — {exc}")

            results.append(device_result)

        self._assessment_results = results
        return results

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def report(self) -> dict:
        """Generate consolidated fleet report.

        Returns:
            FleetReport dict with scan summary, per-device findings,
            and overall risk rating.
        """
        classifications: dict[str, int] = {}
        for dev in self._scan_results:
            cls = dev["classification"]
            classifications[cls] = classifications.get(cls, 0) + 1

        devices = []
        for result in self._assessment_results:
            devices.append({
                "address": result["address"],
                "name": result["name"],
                "classification": result["classification"],
                "findings": result["findings"],
                "risk_rating": result["risk_rating"],
                **({"error": result["error"]} if result.get("error") else {}),
            })

        overall_risk = self._rate_fleet(self._assessment_results)

        report: dict = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "total_devices": len(self._scan_results),
            "classifications": classifications,
            "assessed": len(self._assessment_results),
            "devices": devices,
            "overall_risk": overall_risk,
        }
        return report

    # ------------------------------------------------------------------
    # Risk rating helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rate_device(findings: list[dict]) -> str:
        """Rate a single device based on its findings."""
        if not findings:
            return "INFO"
        severities = {f.get("severity", "").upper() for f in findings}
        if "CRITICAL" in severities:
            return "CRITICAL"
        if "HIGH" in severities:
            return "HIGH"
        if "MEDIUM" in severities:
            return "MEDIUM"
        if "LOW" in severities:
            return "LOW"
        return "INFO"

    @staticmethod
    def _rate_fleet(results: list[dict]) -> str:
        """Rate overall fleet risk from per-device ratings."""
        if not results:
            return "UNKNOWN"
        ratings = {r.get("risk_rating", "UNKNOWN") for r in results}
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            if level in ratings:
                return level
        return "UNKNOWN"
