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
                from blue_tap.utils.output import verbose
                verbose(f"Could not parse device class: {raw_class}")
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

    def __init__(self, hci: str | None = None, scan_duration: int = 15):
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        self.hci = hci
        self.scan_duration = scan_duration
        self._classifier = DeviceClassifier()
        self._scan_results: list[dict] = []
        self._scan_envelope: dict = {}
        self._assessment_results: list[dict] = []

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    def scan(self) -> list[dict]:
        """Run classic + BLE scan, classify all discovered devices.

        Returns a list sorted by classification then RSSI, each entry:
        {address, name, rssi, type, classification, services_found}
        """
        from blue_tap.hardware.scanner import scan_all_result

        info(f"Fleet scan: discovering devices for {self.scan_duration}s on {self.hci}...")
        self._scan_envelope = scan_all_result(self.scan_duration, self.hci)
        raw_devices = self._scan_envelope.get("module_data", {}).get("devices", [])

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
        from blue_tap.modules.reconnaissance.fingerprint import fingerprint_device
        from blue_tap.modules.assessment.vuln_scanner import run_vulnerability_scan

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
                "vulnscan": {},
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
                vulnscan = run_vulnerability_scan(addr, hci=self.hci, active=True)
                findings = vulnscan.get("module_data", {}).get("findings", [])
                device_result["findings"] = findings
                device_result["vulnscan"] = vulnscan

                # Rate per device
                device_result["risk_rating"] = self._rate_device(findings)
                success(f"  {addr}: {device_result['risk_rating']} "
                        f"({len(findings)} finding(s))")

            except (OSError, TimeoutError, ConnectionError, ValueError) as exc:
                device_result["error"] = str(exc)
                error(f"  {addr}: assessment failed — {exc}")
            except Exception as exc:
                device_result["error"] = f"unexpected: {exc}"
                error(f"  {addr}: unexpected error during assessment — {exc}")
                warning(f"  This may indicate a bug — please report with: blue-tap --version")

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
                **({"vulnscan": result["vulnscan"]} if result.get("vulnscan") else {}),
                "risk_rating": result["risk_rating"],
                **({"error": result["error"]} if result.get("error") else {}),
            })

        overall_risk = self._rate_fleet(self._assessment_results)

        report: dict = {
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "total_devices": len(self._scan_results),
            "classifications": classifications,
            "assessed": len(self._assessment_results),
            "scan_run": self._scan_envelope,
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


# ============================================================================
# Module wrapper — adapts FleetAssessment to the standard Module interface
# ============================================================================

class FleetModule:
    """Module entry point for assessment.fleet.

    Wraps FleetAssessment in the standard run(ctx)/check(ctx) interface.
    Registered as assessment.fleet in the module registry.
    """

    # Satisfy Invoker.resolve() without auto-registering via Module.__init_subclass__
    _is_blue_tap_module = True

    from blue_tap.framework.module.options import OptString, OptInt
    options = (
        OptString("HCI", default="", required=False, description="Local HCI adapter"),
        OptInt("DURATION", default=15, required=False, description="Scan duration in seconds"),
        OptString("CLASS", default="ivi", required=False,
                  description="Device class to assess (ivi, phone, headset, etc.)"),
    )

    def run(self, ctx) -> dict:
        from blue_tap.framework.contracts.result_schema import (
            build_run_envelope, make_evidence, make_execution, make_run_id, now_iso,
        )
        from blue_tap.hardware.adapter import resolve_active_hci
        hci = ctx.options.get("HCI") or resolve_active_hci()
        duration = ctx.options.get("DURATION", 15) or 15
        device_class = ctx.options.get("CLASS", "ivi") or "ivi"

        started = now_iso()
        run_id = make_run_id("assessment.fleet")

        fleet = FleetAssessment(hci=hci, scan_duration=int(duration))
        fleet.scan()
        fleet.assess(device_class=device_class)
        report = fleet.report()

        total = report.get("total_devices", 0)
        assessed = report.get("assessed", 0)
        overall = report.get("overall_risk", "UNKNOWN")

        # Fleet is an assessment family module — allowed outcomes are
        # confirmed / inconclusive / pairing_required / not_applicable.
        if total == 0:
            outcome = "not_applicable"
        elif assessed == 0:
            outcome = "inconclusive"
        elif overall in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            outcome = "confirmed"
        else:
            outcome = "inconclusive"

        completed = now_iso()
        execution = make_execution(
            execution_id="fleet_scan",
            kind="phase",
            id="fleet_scan",
            title=f"Fleet assessment ({device_class})",
            module="assessment.fleet",
            module_id="assessment.fleet",
            protocol="Discovery",
            execution_status="completed",
            module_outcome=outcome,
            evidence=make_evidence(
                summary=(
                    f"Scanned {total} device(s), assessed {assessed} as "
                    f"{device_class}. Overall risk: {overall}"
                ),
                confidence="high" if assessed > 0 else "medium",
                observations=[
                    f"total_devices={total}",
                    f"assessed={assessed}",
                    f"device_class={device_class}",
                    f"overall_risk={overall}",
                ],
                module_evidence={
                    "classifications": report.get("classifications", {}),
                },
            ),
            started_at=started,
            completed_at=completed,
            destructive=False,
            requires_pairing=False,
            tags=["fleet", device_class],
        )

        return build_run_envelope(
            schema="blue_tap.fleet.result",
            module="assessment.fleet",
            target="nearby",
            adapter=hci,
            operator_context={"device_class": device_class, "duration": duration},
            summary={
                "total_devices": total,
                "assessed": assessed,
                "overall_risk": overall,
                "outcome": outcome,
            },
            executions=[execution],
            module_data=report,
            started_at=started,
            completed_at=completed,
            run_id=run_id,
        )

    def cleanup(self, ctx) -> None:  # noqa: D102
        pass
