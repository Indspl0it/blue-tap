"""Device fingerprinting and IVI identification."""

import re

from bt_tap.utils.bt_helpers import run_cmd
from bt_tap.recon.sdp import browse_services
from bt_tap.utils.output import info, success, warning

# Known IVI manufacturer patterns
IVI_PATTERNS = {
    "Harman": ["JBL", "Harman", "Samsung Harman"],
    "Bosch": ["Bosch"],
    "Continental": ["Continental"],
    "Denso": ["Denso", "DENSO"],
    "Alpine": ["Alpine"],
    "Pioneer": ["Pioneer", "Carrozzeria"],
    "Kenwood": ["Kenwood", "JVC"],
    "Sony": ["Sony"],
    "Panasonic": ["Panasonic", "Matsushita"],
    "LG": ["LG Electronics"],
    "Hyundai Mobis": ["Mobis", "MOBIS"],
    "Visteon": ["Visteon"],
    "Tesla": ["Tesla"],
}

# Bluetooth profiles typically found on automotive IVIs
IVI_PROFILES = {
    "HFP AG": "Hands-Free Audio Gateway - call audio",
    "A2DP Sink": "Audio sink - receives media from phone",
    "AVRCP": "Media control - play/pause/skip",
    "PBAP PSE": "Phone Book server - provides phonebook download",
    "MAP MAS": "Message Access server - provides SMS access",
    "SPP": "Serial Port - diagnostic/AT commands",
    "OPP": "Object Push - file transfer",
}


def fingerprint_device(address: str) -> dict:
    """Fingerprint a Bluetooth device to identify IVI characteristics."""
    info(f"Fingerprinting {address}...")

    fp = {
        "address": address,
        "name": "",
        "manufacturer": "Unknown",
        "is_ivi": False,
        "profiles": [],
        "attack_surface": [],
    }

    # Resolve name
    name_result = run_cmd(["hcitool", "name", address], timeout=10)
    if name_result.returncode == 0:
        fp["name"] = name_result.stdout.strip()

    # Get device info
    info_result = run_cmd(["hcitool", "info", address], timeout=10)
    if info_result.returncode == 0:
        # Parse manufacturer, features
        for line in info_result.stdout.splitlines():
            if "Manufacturer:" in line:
                fp["manufacturer"] = line.split(":", 1)[1].strip()

    # Enumerate services
    services = browse_services(address)
    for svc in services:
        profile = svc.get("profile", "")
        fp["profiles"].append({
            "name": svc.get("name", "Unknown"),
            "profile": profile,
            "channel": svc.get("channel"),
            "protocol": svc.get("protocol"),
        })

    # Determine if this is an IVI
    name_lower = fp["name"].lower()
    ivi_indicators = ["car", "auto", "vehicle", "ivi", "infotainment", "head unit",
                      "carplay", "android auto"]
    if any(ind in name_lower for ind in ivi_indicators):
        fp["is_ivi"] = True

    # Check profiles for IVI-typical combination
    profile_names = [p["profile"] for p in fp["profiles"]]
    has_hfp_ag = any(("HFP" in p or "Hands-Free" in p) and "AG" in p for p in profile_names)
    has_a2dp_sink = any("A2DP" in p and "Sink" in p for p in profile_names)
    has_pbap = any("PBAP" in p or "Phonebook" in p for p in profile_names)

    if has_hfp_ag and has_a2dp_sink:
        fp["is_ivi"] = True

    # Map attack surface
    if has_pbap:
        fp["attack_surface"].append("PBAP: Phonebook/call log download")
    if any("MAP" in p for p in profile_names):
        fp["attack_surface"].append("MAP: SMS/MMS message access")
    if has_hfp_ag:
        fp["attack_surface"].append("HFP: Call audio interception/injection")
    if has_a2dp_sink:
        fp["attack_surface"].append("A2DP: Media audio interception")
    if any("OPP" in p or "Object Push" in p for p in profile_names):
        fp["attack_surface"].append("OPP: File push to IVI")
    if any("SPP" in p or "Serial" in p for p in profile_names):
        fp["attack_surface"].append("SPP: Serial port (AT commands, diagnostics)")

    # Check manufacturer
    for mfr, patterns in IVI_PATTERNS.items():
        if any(pat.lower() in fp["name"].lower() or pat.lower() in fp["manufacturer"].lower()
               for pat in patterns):
            fp["manufacturer"] = mfr

    if fp["is_ivi"]:
        success(f"Identified as IVI: {fp['name']} ({fp['manufacturer']})")
    else:
        info(f"Device: {fp['name']} ({fp['manufacturer']}) - not identified as IVI")

    return fp
