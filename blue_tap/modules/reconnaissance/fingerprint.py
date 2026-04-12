"""Device fingerprinting — BT version, chipset, profiles, and attack surface.

IVI (In-Vehicle Infotainment) systems rarely advertise their make/model over
Bluetooth. The device name is usually generic ("CAR-AUDIO", "My Car", or a
random string), and the OUI maps to a chipset vendor (Broadcom, Qualcomm),
not the vehicle OEM.

What IS reliable:
  - BT/LMP version and chipset vendor (from hcitool info)
  - OUI-based chipset manufacturer (from MAC prefix)
  - SDP service profiles (HFP AG, A2DP Sink, PBAP, MAP, etc.)
  - Device class (Car Audio = 0x04/0x08)
  - Attack surface derived from the above

What is NOT reliable:
  - Determining if something is definitely an IVI vs a Bluetooth speaker
  - Identifying the car make/model/OEM from BT data alone
  - Manufacturer attribution beyond the chipset vendor

The `ivi_likely` field is a heuristic hint — never use it to gate workflows.
"""

import re

from blue_tap.utils.bt_helpers import lookup_oui, run_cmd
from blue_tap.modules.reconnaissance.sdp import browse_services
from blue_tap.utils.output import info, success


# Bluetooth profiles typically found on automotive IVIs
IVI_PROFILES = {
    "HFP AG": "Hands-Free Audio Gateway - call audio",
    "A2DP Sink": "Audio sink - receives media from phone",
    "AVRCP": "Media control - play/pause/skip",
    "AVRCP Controller": "Media control - IVI controls phone playback",
    "PBAP PSE": "Phone Book server - provides phonebook download",
    "MAP MAS": "Message Access server - provides SMS access",
    "SPP": "Serial Port - diagnostic/AT commands",
    "OPP": "Object Push - file transfer",
    "DUN": "Dialup Networking - tethered internet",
    "PnP Information": "Device identification - vendor/product IDs",
}

# IVI-typical Bluetooth device class values
IVI_DEVICE_CLASSES = {
    0x200408: "Audio/Video: Car Audio",
    0x200404: "Audio/Video: Portable Audio",
    0x240404: "Audio: Loudspeaker + Rendering",
    0x240408: "Audio: Car Audio + Rendering",
}


def fingerprint_device(address: str, hci: str = "hci0") -> dict:
    """Fingerprint a Bluetooth device — version, chipset, profiles, attack surface.

    Gathers: name, device class, BT version, LMP features, chipset manufacturer,
    SDP services, and maps the full attack surface.

    Does NOT attempt to identify the vehicle make/model — IVIs rarely expose
    that information over Bluetooth.
    """
    from blue_tap.utils.bt_helpers import ensure_adapter_ready
    if not ensure_adapter_ready(hci):
        return {"address": address, "name": "", "manufacturer": "Unknown",
                "is_ivi": False, "ivi_likely": False,
                "profiles": [], "attack_surface": [],
                "vuln_hints": [], "error": "adapter not ready"}

    info(f"Fingerprinting {address}...")

    fp = {
        "address": address,
        "name": "",
        "manufacturer": "Unknown",  # Chipset vendor, not car OEM
        "manufacturer_name": "Unknown",
        "manufacturer_id": "",
        "manufacturer_sources": [],
        "is_ivi": False,            # Kept for backward compat (= ivi_likely)
        "ivi_likely": False,        # Heuristic hint, never gate on this
        "device_class": None,
        "device_class_raw": None,
        "device_class_info": {},
        "bt_version": None,
        "hci_version_raw": None,
        "hci_subversion": None,
        "lmp_version": None,
        "lmp_version_raw": None,
        "lmp_subversion": None,
        "features": [],
        "extended_features": [],
        "profiles": [],
        "attack_surface": [],
        "vuln_hints": [],
        "ivi_signals": [],          # Why we think it might be an IVI
        "evidence_classes": {"observed": [], "inferred": [], "heuristic": []},
    }

    # Resolve name
    name_result = run_cmd(["hcitool", "-i", hci, "name", address], timeout=10)
    if name_result.returncode == 0:
        fp["name"] = name_result.stdout.strip()

    # Get device info (class, manufacturer, LMP version) — single hcitool call
    info_result = run_cmd(["hcitool", "-i", hci, "info", address], timeout=10)
    if info_result.returncode == 0:
        _parse_hcitool_info(info_result.stdout, fp)

    # Parse device class if we got one
    if fp.get("device_class"):
        from blue_tap.hardware.scanner import parse_device_class
        fp["device_class_info"] = parse_device_class(fp["device_class"])
        fp["evidence_classes"]["observed"].append("device_class")

    oui_vendor = lookup_oui(address)
    if oui_vendor:
        fp["manufacturer_sources"].append({"source": "oui", "value": oui_vendor})
        if fp["manufacturer"] == "Unknown":
            fp["manufacturer"] = oui_vendor
            fp["manufacturer_name"] = oui_vendor
        fp["evidence_classes"]["inferred"].append("oui_vendor")

    # Enumerate services
    services = browse_services(address)
    for svc in services:
        profile = svc.get("profile", "")
        fp["profiles"].append({
            "name": svc.get("name", "Unknown"),
            "profile": profile,
            "channel": svc.get("channel"),
            "protocol": svc.get("protocol"),
            "version": svc.get("profile_version"),
            "provider": svc.get("provider"),
            "class_ids": svc.get("class_ids", []),
        })
    if fp["profiles"]:
        fp["evidence_classes"]["observed"].append("sdp_profiles")

    # Heuristic IVI detection (signals only — not definitive)
    _detect_ivi_signals(fp)

    # Map attack surface (works regardless of IVI detection)
    _map_attack_surface(fp, services)

    # Check for vulnerability hints based on BT version
    _check_vuln_hints(fp)

    if fp["ivi_likely"]:
        success(f"Likely IVI: {fp['name']} — {len(fp['ivi_signals'])} signal(s)")
        for sig in fp["ivi_signals"]:
            info(f"  hint: {sig}")
    else:
        info(f"Device: {fp['name']} (chipset: {fp['manufacturer']})")

    return fp


def _parse_hcitool_info(output: str, fp: dict):
    """Parse hcitool info output for device class, manufacturer, features.

    The 'Manufacturer' field from hcitool info is the *chipset* vendor
    (Broadcom, Qualcomm, Intel), not the car/device OEM.
    """
    for line in output.splitlines():
        if "Manufacturer:" in line:
            manufacturer = line.split(":", 1)[1].strip()
            fp["manufacturer"] = manufacturer
            fp["manufacturer_name"] = manufacturer
            fp["manufacturer_sources"].append({"source": "hcitool_info", "value": manufacturer})
            manufacturer_id_match = re.search(r"\((0x[0-9A-Fa-f]+|\d+)\)", line)
            if manufacturer_id_match:
                fp["manufacturer_id"] = manufacturer_id_match.group(1)
            fp["evidence_classes"]["observed"].append("manufacturer")
        elif "LMP Version:" in line:
            m = re.search(r"LMP Version:\s*(.+)", line)
            if m:
                value = m.group(1).strip()
                fp["lmp_version"] = value
                fp["lmp_version_raw"] = value
                fp["evidence_classes"]["observed"].append("lmp_version")
            sub_m = re.search(r"Subversion:\s*(0x[0-9A-Fa-f]+|\d+)", line)
            if sub_m:
                fp["lmp_subversion"] = sub_m.group(1)
        elif "HCI Version:" in line:
            m = re.search(r"HCI Version:\s*(.+)", line)
            if m:
                value = m.group(1).strip()
                fp["bt_version"] = value
                fp["hci_version_raw"] = value
                fp["evidence_classes"]["observed"].append("hci_version")
            sub_m = re.search(r"Subversion:\s*(0x[0-9A-Fa-f]+|\d+)", line)
            if sub_m:
                fp["hci_subversion"] = sub_m.group(1)
        elif "Class:" in line:
            m = re.search(r"Class:\s*(0x[0-9A-Fa-f]+)", line)
            if m:
                fp["device_class"] = m.group(1)
                fp["device_class_raw"] = m.group(1)
        elif "Device Class:" in line:
            m = re.search(r"Device Class:\s*(0x[0-9A-Fa-f]+)", line)
            if m:
                fp["device_class"] = m.group(1)
                fp["device_class_raw"] = m.group(1)
        elif "Features:" in line:
            features = re.findall(r"0x[0-9A-Fa-f]+", line)
            if features:
                fp["features"].extend(features)
                fp["evidence_classes"]["observed"].append("features")


def _detect_ivi_signals(fp: dict):
    """Collect heuristic signals that suggest the device might be an IVI.

    Each signal is recorded with its reasoning. The more signals present,
    the more likely it's an IVI — but none are definitive. A Bluetooth
    speakerphone with HFP AG + A2DP Sink looks identical to an IVI.

    Uses normalized profile UUIDs where possible for reliable matching,
    falling back to name matching for non-standard profiles.
    """
    signals = []

    # Signal 1: Device class = Car Audio (minor class 0x08 under Audio/Video)
    class_info = fp.get("device_class_info", {})
    if class_info.get("is_ivi"):
        signals.append("Device class: Car Audio (0x04/0x08)")

    # Normalize profiles for reliable matching
    # Build a set of normalized profile identifiers from both profile field and name
    profile_ids = set()
    for p in fp["profiles"]:
        profile = (p.get("profile") or "").lower()
        name = (p.get("name") or "").lower()
        combined = profile + " " + name

        # Map to canonical identifiers
        if any(k in combined for k in ("hfp ag", "audio gateway", "hands-free ag", "handsfree ag")):
            profile_ids.add("hfp_ag")
        if any(k in combined for k in ("hfp", "hands-free", "handsfree")) and "ag" not in combined:
            profile_ids.add("hfp")
        if "a2dp" in combined and "sink" in combined:
            profile_ids.add("a2dp_sink")
        if "a2dp" in combined and "source" in combined:
            profile_ids.add("a2dp_source")
        if any(k in combined for k in ("pbap", "phonebook", "phone book")):
            profile_ids.add("pbap")
        if any(k in combined for k in ("message access", "map mas", "map mns")):
            profile_ids.add("map")
        elif "map" == profile.strip():
            profile_ids.add("map")
        if "avrcp" in combined or "a/v remote" in combined:
            profile_ids.add("avrcp")
        if any(k in combined for k in ("spp", "serial port")):
            profile_ids.add("spp")
        if any(k in combined for k in ("opp", "object push")):
            profile_ids.add("opp")
        if any(k in combined for k in ("dun", "dialup")):
            profile_ids.add("dun")
        if any(k in combined for k in ("hid", "human interface")):
            profile_ids.add("hid")
        if any(k in combined for k in ("pnp", "device id")):
            profile_ids.add("pnp")

    fp["_profile_ids"] = sorted(profile_ids)  # Store for reuse in attack surface

    # Signal 2: IVI-typical profile combinations
    if "hfp_ag" in profile_ids and "a2dp_sink" in profile_ids:
        signals.append("Profiles: HFP AG + A2DP Sink (audio gateway pattern)")
    if "pbap" in profile_ids:
        signals.append("Profiles: PBAP (phonebook access — common on IVIs)")
    if "map" in profile_ids:
        signals.append("Profiles: MAP (message access — common on IVIs)")

    # Signal 3: Multiple IVI-typical profiles (even without HFP AG)
    ivi_profile_count = sum(1 for pid in ("hfp_ag", "a2dp_sink", "pbap", "map", "avrcp")
                            if pid in profile_ids)
    if ivi_profile_count >= 4:
        signals.append(f"Profile density: {ivi_profile_count}/5 IVI-typical profiles present")

    # Signal 4: Name hints (very weak — most IVIs use generic names)
    name_lower = fp["name"].lower()
    ivi_name_hints = [
        "car", "auto", "vehicle", "ivi", "infotainment", "head unit",
        "carplay", "android auto", "sync", "uconnect", "mbux",
        "idrive", "sensus", "entune", "mylink", "intellilink",
        "starlink", "mazda connect", "honda connect", "nissan connect",
    ]
    matched_hints = [h for h in ivi_name_hints if h in name_lower]
    if matched_hints:
        signals.append(f"Name contains: {', '.join(matched_hints)} (weak signal)")

    fp["ivi_signals"] = signals
    fp["ivi_confidence"] = min(len(signals) / 4.0, 1.0)  # 0.0 to 1.0
    fp["ivi_likely"] = len(signals) >= 2
    fp["is_ivi"] = fp["ivi_likely"]  # backward compat
    if signals:
        fp["evidence_classes"]["heuristic"].append("ivi_likely")


def _map_attack_surface(fp: dict, services: list[dict]):
    """Map the full attack surface based on discovered profiles.

    This works on ANY Bluetooth device, not just IVIs. Every device with
    PBAP has a phonebook attack surface, regardless of whether we think
    it's an IVI.

    Uses normalized profile IDs when available, falls back to string
    matching on raw service data.
    """
    profile_ids = set(fp.get("_profile_ids", []))

    # If _detect_ivi_signals hasn't run yet, build from raw data
    if not profile_ids:
        profile_names = [p.get("profile", "") + " " + p.get("name", "") for p in fp["profiles"]]
        profile_text = " ".join(profile_names).lower()
        class_ids_text = " ".join(
            " ".join(s.get("class_ids", [])) for s in services
        ).lower()
        combined = profile_text + " " + class_ids_text
    else:
        combined = ""

    # Map profile IDs to attack descriptions
    attack_by_id = {
        "pbap": "PBAP: Phonebook + call log download (contacts, call history, favorites)",
        "map": "MAP: SMS/MMS message extraction",
        "hfp": "HFP: Call audio eavesdropping, call injection, AT commands",
        "hfp_ag": "HFP AG: Audio gateway — call routing, AT command injection",
        "a2dp_sink": "A2DP: Media audio interception (music, navigation audio)",
        "a2dp_source": "A2DP Source: Audio injection to device",
        "avrcp": "AVRCP: Media control injection (play/pause/skip/volume)",
        "opp": "OPP: File push to device (malicious files, vCards)",
        "spp": "SPP: Serial port access (AT commands, diagnostics, potential RCE)",
        "dun": "DUN: Dialup networking (internet tethering abuse)",
        "hid": "HID: Input injection (keyboard/mouse events)",
        "pnp": "PnP: Device identification (vendor/product for targeted exploits)",
    }

    for pid, desc in attack_by_id.items():
        if pid in profile_ids:
            fp["attack_surface"].append(desc)

    # Fallback string matching for profiles not captured by normalization
    fallback_patterns = [
        ("sim", "sim access", "SAP: SIM Access Profile (SIM data extraction)"),
        ("ftp", "file transfer", "FTP: File Transfer Profile (browse/download filesystem)"),
    ]
    if combined:
        for keywords_tuple in fallback_patterns:
            *keywords, description = keywords_tuple
            if any(kw in combined for kw in keywords):
                fp["attack_surface"].append(description)
    else:
        # Use raw service data for fallback
        raw_text = " ".join(
            (s.get("profile", "") + " " + s.get("name", "") + " " +
             " ".join(s.get("class_ids", [])))
            for s in services
        ).lower()
        for keywords_tuple in fallback_patterns:
            *keywords, description = keywords_tuple
            if any(kw in raw_text for kw in keywords):
                fp["attack_surface"].append(description)

    # Note open RFCOMM channels as additional attack surface
    rfcomm_channels = [
        s.get("channel") for s in services
        if s.get("protocol") == "RFCOMM" and s.get("channel")
    ]
    if rfcomm_channels:
        fp["attack_surface"].append(
            f"RFCOMM: {len(rfcomm_channels)} open channel(s): {rfcomm_channels}"
        )


def _check_vuln_hints(fp: dict):
    """Check for known vulnerability indicators based on BT version and features."""
    lmp = fp.get("lmp_version", "") or ""

    # Extract numeric version
    ver_m = re.search(r"(\d+\.\d+)", lmp)
    if not ver_m:
        return
    ver = float(ver_m.group(1))

    if ver < 5.1:
        fp["vuln_hints"].append(
            f"KNOB (CVE-2019-9506): BT {ver} < 5.1 — Key Negotiation attack, "
            f"entropy reduction to 1 byte. High severity."
        )
    if ver < 5.3:
        fp["vuln_hints"].append(
            f"BIAS (CVE-2020-10135): BT {ver} < 5.3 — Impersonation via "
            f"role-switch/auth downgrade. Critical for hijack."
        )
    if ver < 5.1:
        fp["vuln_hints"].append(
            f"BlueBorne (CVE-2017-0785): BT {ver} — check if firmware is patched. "
            f"RCE via L2CAP info leak."
        )
    if ver <= 4.0:
        fp["vuln_hints"].append(
            f"Legacy pairing: BT {ver} — may use fixed PIN. "
            f"PIN brute-force feasible."
        )
    if ver < 5.4:
        fp["vuln_hints"].append(
            f"BrakTooth (multiple CVEs): BT {ver} < 5.4 — LMP/baseband "
            f"fuzzing vulnerabilities in many chipsets. Check vendor patches."
        )
    if ver < 5.1:
        fp["vuln_hints"].append(
            f"SweynTooth (multiple CVEs): BT {ver} — BLE link layer "
            f"vulnerabilities. Crash/deadlock via malformed LL packets."
        )

    # Check for profiles that increase risk
    profile_ids = set(fp.get("_profile_ids", []))
    if "spp" in profile_ids:
        fp["vuln_hints"].append(
            "SPP exposed: Serial port may accept AT commands without auth. "
            "Test for unauthenticated access."
        )
    if "pbap" in profile_ids and ver < 5.0:
        fp["vuln_hints"].append(
            "PBAP on legacy BT: Phonebook access may be exploitable "
            "without proper pairing (BlueBorne + PBAP combo)."
        )
