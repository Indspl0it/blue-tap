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

from bt_tap.utils.bt_helpers import run_cmd
from bt_tap.recon.sdp import browse_services
from bt_tap.utils.output import info, success, warning


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
    from bt_tap.utils.bt_helpers import ensure_adapter_ready
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
        "is_ivi": False,            # Kept for backward compat (= ivi_likely)
        "ivi_likely": False,        # Heuristic hint, never gate on this
        "device_class": None,
        "device_class_info": {},
        "bt_version": None,
        "lmp_version": None,
        "profiles": [],
        "attack_surface": [],
        "vuln_hints": [],
        "ivi_signals": [],          # Why we think it might be an IVI
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


def _detect_ivi_signals(fp: dict):
    """Collect heuristic signals that suggest the device might be an IVI.

    Each signal is recorded with its reasoning. The more signals present,
    the more likely it's an IVI — but none are definitive. A Bluetooth
    speakerphone with HFP AG + A2DP Sink looks identical to an IVI.
    """
    signals = []

    # Signal 1: Device class = Car Audio (minor class 0x08 under Audio/Video)
    class_info = fp.get("device_class_info", {})
    if class_info.get("is_ivi"):
        signals.append("Device class: Car Audio (0x04/0x08)")

    # Signal 2: IVI-typical profile combination
    # HFP AG + A2DP Sink is the strongest profile signal, but also matches
    # any hands-free speakerphone. PBAP/MAP support increases confidence.
    profile_names = [p.get("profile", "") + " " + p.get("name", "") for p in fp["profiles"]]
    profile_text = " ".join(profile_names).lower()

    has_hfp_ag = (
        ("hfp" in profile_text and "ag" in profile_text) or
        ("hands-free" in profile_text and ("audio gateway" in profile_text or "ag" in profile_text))
    )
    has_a2dp_sink = "a2dp" in profile_text and "sink" in profile_text
    has_pbap = "pbap" in profile_text or "phonebook" in profile_text or "phone book" in profile_text
    has_map = re.search(r'\bmap\b', profile_text) and ("message" in profile_text or "mas" in profile_text)

    if has_hfp_ag and has_a2dp_sink:
        signals.append("Profiles: HFP AG + A2DP Sink (audio gateway pattern)")
    if has_pbap:
        signals.append("Profiles: PBAP (phonebook access — common on IVIs)")
    if has_map:
        signals.append("Profiles: MAP (message access — common on IVIs)")

    # Signal 3: Name hints (very weak — most IVIs use generic names)
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
    fp["ivi_likely"] = len(signals) >= 2
    fp["is_ivi"] = fp["ivi_likely"]  # backward compat


def _map_attack_surface(fp: dict, services: list[dict]):
    """Map the full attack surface based on discovered profiles.

    This works on ANY Bluetooth device, not just IVIs. Every device with
    PBAP has a phonebook attack surface, regardless of whether we think
    it's an IVI.
    """
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
