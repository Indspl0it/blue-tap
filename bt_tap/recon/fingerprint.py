"""Device fingerprinting and IVI identification."""

import re

from bt_tap.utils.bt_helpers import run_cmd
from bt_tap.recon.sdp import browse_services, get_device_bt_version
from bt_tap.utils.output import info, success, warning


# Known IVI manufacturer patterns
IVI_PATTERNS = {
    "Harman": ["JBL", "Harman", "Samsung Harman", "Harman Kardon"],
    "Bosch": ["Bosch"],
    "Continental": ["Continental"],
    "Denso": ["Denso", "DENSO"],
    "Alpine": ["Alpine"],
    "Pioneer": ["Pioneer", "Carrozzeria"],
    "Kenwood": ["Kenwood", "JVC", "JVCKENWOOD"],
    "Sony": ["Sony"],
    "Panasonic": ["Panasonic", "Matsushita"],
    "LG": ["LG Electronics", "LG Display"],
    "Hyundai Mobis": ["Mobis", "MOBIS"],
    "Visteon": ["Visteon"],
    "Tesla": ["Tesla"],
    "Aptiv": ["Aptiv", "Delphi"],
    "Clarion": ["Clarion"],
    "Garmin": ["Garmin"],
    "Blaupunkt": ["Blaupunkt"],
    "Magneti Marelli": ["Magneti", "Marelli"],
    "Bose": ["Bose"],
    "Bang & Olufsen": ["Bang & Olufsen", "B&O"],
    "Burmester": ["Burmester"],
    "Mark Levinson": ["Mark Levinson", "Lexus"],
    "Faurecia": ["Faurecia"],
    "Valeo": ["Valeo"],
    "NXP": ["NXP"],
}

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
    """Fingerprint a Bluetooth device to identify IVI characteristics.

    Gathers: name, device class, BT version, LMP features, manufacturer,
    SDP services, and maps the full attack surface.
    """
    from bt_tap.utils.bt_helpers import ensure_adapter_ready
    if not ensure_adapter_ready(hci):
        return {"address": address, "name": "", "manufacturer": "Unknown",
                "is_ivi": False, "profiles": [], "attack_surface": [],
                "vuln_hints": [], "error": "adapter not ready"}

    info(f"Fingerprinting {address}...")

    fp = {
        "address": address,
        "name": "",
        "manufacturer": "Unknown",
        "is_ivi": False,
        "device_class": None,
        "device_class_info": {},
        "bt_version": None,
        "lmp_version": None,
        "profiles": [],
        "attack_surface": [],
        "vuln_hints": [],
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
        from bt_tap.core.scanner import parse_device_class
        fp["device_class_info"] = parse_device_class(fp["device_class"])
        if fp["device_class_info"].get("is_ivi"):
            fp["is_ivi"] = True

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
        })

    # Determine if this is an IVI
    _detect_ivi(fp)

    # Map attack surface
    _map_attack_surface(fp, services)

    # Check for vulnerability hints based on BT version
    _check_vuln_hints(fp)

    # Identify manufacturer
    _identify_manufacturer(fp)

    if fp["is_ivi"]:
        success(f"Identified as IVI: {fp['name']} ({fp['manufacturer']})")
    else:
        info(f"Device: {fp['name']} ({fp['manufacturer']}) - not identified as IVI")

    return fp


def _parse_hcitool_info(output: str, fp: dict):
    """Parse hcitool info output for device class, manufacturer, features."""
    for line in output.splitlines():
        if "Manufacturer:" in line:
            fp["manufacturer"] = line.split(":", 1)[1].strip()
        elif "LMP Version:" in line:
            m = re.search(r"LMP Version:\s*(.+)", line)
            if m:
                fp["lmp_version"] = m.group(1).strip()
        elif "HCI Version:" in line:
            m = re.search(r"HCI Version:\s*(.+)", line)
            if m:
                fp["bt_version"] = m.group(1).strip()
        elif "Class:" in line:
            m = re.search(r"Class:\s*(0x[0-9A-Fa-f]+)", line)
            if m:
                fp["device_class"] = m.group(1)
        elif "Device Class:" in line:
            m = re.search(r"Device Class:\s*(0x[0-9A-Fa-f]+)", line)
            if m:
                fp["device_class"] = m.group(1)


def _detect_ivi(fp: dict):
    """Detect if the device is an automotive IVI based on multiple signals."""
    # Signal 1: Name patterns
    name_lower = fp["name"].lower()
    ivi_name_patterns = [
        "car", "auto", "vehicle", "ivi", "infotainment", "head unit",
        "carplay", "android auto", "sync", "uconnect", "mbux",
        "idrive", "sensus", "entune", "mylink", "intellilink",
        "starlink", "mazda connect", "honda connect", "nissan connect",
    ]
    if any(pat in name_lower for pat in ivi_name_patterns):
        fp["is_ivi"] = True

    # Signal 2: Device class = Car Audio
    if fp.get("device_class_info", {}).get("is_ivi"):
        fp["is_ivi"] = True

    # Signal 3: IVI-typical profile combination
    profile_names = [p.get("profile", "") + " " + p.get("name", "") for p in fp["profiles"]]
    profile_text = " ".join(profile_names).lower()

    has_hfp_ag = (
        ("hfp" in profile_text and "ag" in profile_text) or
        ("hands-free" in profile_text and ("audio gateway" in profile_text or "ag" in profile_text))
    )
    has_a2dp_sink = "a2dp" in profile_text and "sink" in profile_text
    has_pbap = "pbap" in profile_text or "phonebook" in profile_text or "phone book" in profile_text
    has_avrcp = "avrcp" in profile_text or "a/v remote" in profile_text
    has_map = "map" in profile_text and ("message" in profile_text or "mas" in profile_text)

    # IVIs typically have HFP AG + A2DP Sink + at least one of PBAP/AVRCP
    if has_hfp_ag and has_a2dp_sink:
        fp["is_ivi"] = True
    if has_hfp_ag and has_pbap:
        fp["is_ivi"] = True

    # Signal 4: Device class major = Audio/Video with minor = Car Audio
    class_info = fp.get("device_class_info", {})
    if class_info.get("major") == "Audio/Video" and "car" in class_info.get("minor", "").lower():
        fp["is_ivi"] = True


def _map_attack_surface(fp: dict, services: list[dict]):
    """Map the full attack surface based on discovered profiles."""
    profile_names = [p.get("profile", "") + " " + p.get("name", "") for p in fp["profiles"]]
    profile_text = " ".join(profile_names).lower()
    class_ids_text = " ".join(
        " ".join(s.get("class_ids", [])) for s in services
    ).lower()
    combined = profile_text + " " + class_ids_text

    attack_map = [
        ("pbap", "phonebook", "PBAP: Phonebook + call log download (contacts, call history, favorites)"),
        ("map", "message access", "MAP: SMS/MMS message extraction"),
        ("hfp", "hands-free", "HFP: Call audio eavesdropping, call injection, AT commands"),
        ("a2dp", "advanced audio", "A2DP: Media audio interception (music, navigation audio)"),
        ("avrcp", "a/v remote", "AVRCP: Media control injection (play/pause/skip/volume)"),
        ("opp", "object push", "OPP: File push to IVI (malicious files, vCards)"),
        ("spp", "serial port", "SPP: Serial port access (AT commands, diagnostics, potential RCE)"),
        ("dun", "dialup", "DUN: Dialup networking (internet tethering abuse)"),
        ("hid", "human interface", "HID: Input injection (keyboard/mouse events)"),
        ("sim", "sim access", "SAP: SIM Access Profile (SIM data extraction)"),
        ("ftp", "file transfer", "FTP: File Transfer Profile (browse/download IVI filesystem)"),
        ("pnp", "device id", "PnP: Device identification (vendor/product for targeted exploits)"),
    ]

    for keywords_tuple in attack_map:
        *keywords, description = keywords_tuple
        if any(kw in combined for kw in keywords):
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


def _identify_manufacturer(fp: dict):
    """Identify IVI manufacturer from name, SDP provider, and hcitool data."""
    search_strings = [
        fp.get("name", ""),
        fp.get("manufacturer", ""),
    ]
    # Also check SDP provider names
    for p in fp.get("profiles", []):
        if p.get("provider"):
            search_strings.append(p["provider"])

    combined = " ".join(search_strings).lower()

    for mfr, patterns in IVI_PATTERNS.items():
        if any(pat.lower() in combined for pat in patterns):
            fp["manufacturer"] = mfr
            return
