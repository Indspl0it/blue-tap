"""Blue-Tap CLI entry point — modular Bluetooth security toolkit.

Phase-verb architecture: top-level commands map to assessment phases.
"""

from __future__ import annotations

import os
import sys

import rich_click as click

from blue_tap import __version__
from blue_tap.interfaces.cli.shared import LoggedCommand, LoggedGroup
from blue_tap.utils.output import banner, info, error, warning

# ── Rich-Click Configuration ─────────────────────────────────────────
click.rich_click.USE_RICH_MARKUP = True
click.rich_click.MAX_WIDTH = 120
click.rich_click.USE_CLICK_SHORT_HELP = False
click.rich_click.SHOW_ARGUMENTS = True
click.rich_click.GROUP_ARGUMENTS_OPTIONS = True
click.rich_click.STYLE_OPTION = "bold"
click.rich_click.STYLE_ARGUMENT = "bold"
click.rich_click.STYLE_COMMAND = "bold"

# Command grouping — pentest workflow order with sub-command panels
click.rich_click.COMMAND_GROUPS = {
    "blue-tap": [
        {"name": "Blue-Tap Workflow", "commands": [
            "discover", "recon", "vulnscan", "exploit", "dos", "extract", "fuzz", "report",
        ]},
        {"name": "Discovery  (blue-tap discover …)", "commands": [
            "discover-classic", "discover-ble", "discover-all",
        ]},
        {"name": "Reconnaissance  (blue-tap recon TARGET …)", "commands": [
            "recon-auto", "recon-sdp", "recon-gatt", "recon-rfcomm",
            "recon-l2cap", "recon-fingerprint",
            "recon-hci-capture", "recon-sniffer",
            "recon-capabilities", "recon-analyze", "recon-correlate", "recon-interpret",
        ]},
        {"name": "Vulnerability Assessment  (blue-tap vulnscan TARGET)", "commands": [
            "vuln-cve-2017-0783", "vuln-cve-2017-0785",
            "vuln-cve-2017-13258", "vuln-cve-2018-9359", "vuln-cve-2018-9365",
            "vuln-cve-2019-2225", "vuln-cve-2019-3459",
            "vuln-cve-2020-0022", "vuln-cve-2020-0556", "vuln-cve-2020-12352",
            "vuln-cve-2020-26558",
            "vuln-cve-2021-0507", "vuln-cve-2022-0204", "vuln-cve-2022-20345",
            "vuln-cve-2022-25837", "vuln-cve-2022-39176", "vuln-cve-2022-42895",
            "vuln-cve-2022-42896",
            "vuln-cve-2023-35681", "vuln-cve-2023-45866",
            "vuln-cve-2024-34722",
            "vuln-cve-2025-20700", "vuln-cve-2025-20701", "vuln-cve-2025-20702",
            "vuln-cve-2026-23395",
            "vuln-service-exposure", "vuln-hidden-rfcomm", "vuln-encryption",
            "vuln-writable-gatt", "vuln-eatt", "vuln-pairing-method",
            "vuln-pin-lockout", "vuln-device-class", "vuln-lmp-features",
            "vuln-obex-auth", "vuln-automotive-diag",
        ]},
        {"name": "Exploitation  (blue-tap exploit TARGET …)", "commands": [
            "exploit-bias", "exploit-bluffs", "exploit-knob", "exploit-ctkd",
            "exploit-enc-downgrade", "exploit-ssp-downgrade",
            "exploit-hijack", "exploit-pin-brute",
        ]},
        {"name": "Post-Exploitation  (blue-tap extract TARGET …)", "commands": [
            "extract-contacts", "extract-messages", "extract-audio",
            "extract-stream", "extract-media",
            "extract-push", "extract-snarf", "extract-at",
        ]},
        {"name": "DoS Probes  (blue-tap dos TARGET --checks <id>)", "commands": [
            "dos-cve-2020-0022", "dos-cve-2017-0781", "dos-cve-2017-0782",
            "dos-cve-2019-19192", "dos-cve-2019-19196",
            "dos-cve-2022-39177", "dos-cve-2023-27349",
            "dos-cve-2025-0084", "dos-cve-2025-48593",
            "dos-l2cap", "dos-sdp", "dos-rfcomm", "dos-obex",
            "dos-hfp", "dos-lmp", "dos-pairing",
        ]},
        {"name": "Fuzzing  (blue-tap fuzz …)", "commands": [
            "fuzz-campaign", "fuzz-sdp-deep", "fuzz-l2cap-sig", "fuzz-rfcomm-raw",
            "fuzz-ble-att", "fuzz-ble-smp", "fuzz-bnep", "fuzz-obex", "fuzz-at-deep",
            "fuzz-crashes", "fuzz-minimize", "fuzz-replay", "fuzz-corpus",
        ]},
        {"name": "Automation", "commands": ["auto", "fleet"]},
        {"name": "Utilities", "commands": ["adapter", "session", "doctor", "spoof"]},
    ],
    "blue-tap discover": [
        {"name": "Discovery", "commands": ["classic", "ble", "all"]},
    ],
    "blue-tap exploit *": [
        {"name": "Crypto & Key Attacks", "commands": [
            "bias", "bluffs", "knob", "ctkd", "enc-downgrade", "ssp-downgrade",
        ]},
        {"name": "Full Chain", "commands": ["hijack", "pin-brute"]},
    ],
    "blue-tap extract *": [
        {"name": "Contacts", "commands": ["contacts", "messages"]},
        {"name": "Media", "commands": ["audio", "media"]},
        {"name": "Files", "commands": ["push", "snarf", "at"]},
    ],
    "blue-tap fuzz": [
        {"name": "Protocols", "commands": [
            "campaign", "sdp-deep", "l2cap-sig", "rfcomm-raw", "ble-att", "ble-smp",
            "bnep", "obex", "at-deep",
        ]},
        {"name": "Analysis", "commands": ["crashes", "minimize", "cve", "replay"]},
        {"name": "Corpus", "commands": ["corpus"]},
    ],
}


@click.group(cls=LoggedGroup)
@click.version_option(version=__version__)
@click.option("-v", "--verbose", count=True, help="Verbosity: -v verbose, -vv debug")
@click.option("-s", "--session", "session_name", default=None,
              help="Session name (default: auto-generated). Use to resume a session.")
def cli(verbose, session_name):
    """Blue-Tap: Bluetooth Security Toolkit for Automotive & IoT.

    \b
    Quick start:
      blue-tap discover classic                       # 1. Find targets
      blue-tap recon AA:BB:CC:DD:EE:FF sdp            # 2. Enumerate services
      blue-tap vulnscan AA:BB:CC:DD:EE:FF             # 3. Vulnerability scan
      blue-tap exploit AA:BB:CC:DD:EE:FF knob         # 4. Run exploit
      blue-tap extract AA:BB:CC:DD:EE:FF contacts     # 5. Extract data
      blue-tap report                                 # 6. Generate report

    \b
    Sessions (automatic — all output is always saved):
      blue-tap -s mytest vulnscan TARGET              # named session
      blue-tap session list                           # see all sessions
      blue-tap report                                 # report from latest session
    """
    from blue_tap.utils.output import set_verbosity
    set_verbosity(verbose)

    # Skip session for read-only commands
    ctx = click.get_current_context()
    invoked = ctx.invoked_subcommand or ""

    if not invoked:
        return

    _NO_SESSION_COMMANDS = {
        "session", "report", "adapter", "plugins", "doctor",
        "run", "run-playbook", "search", "info", "show-options",
    }
    if not session_name and invoked in _NO_SESSION_COMMANDS:
        return
    # run-playbook --list doesn't run anything, no session needed
    if invoked == "run-playbook" and "--list" in sys.argv:
        return

    # Create session for active commands
    from blue_tap.framework.sessions.store import Session, set_session
    from datetime import datetime
    if not session_name:
        session_name = datetime.now().strftime("blue-tap_%Y%m%d_%H%M%S")
    session = Session(session_name)
    set_session(session)
    info(f"Session: [bold]{session_name}[/bold]")


def _init_darkfirmware_hooks(dongle_hci: str) -> None:
    """Initialize DarkFirmware hooks and start watchdog on the detected dongle."""
    os.environ["BT_TAP_DARKFIRMWARE_HCI"] = dongle_hci

    from blue_tap.hardware.firmware import DarkFirmwareManager, DarkFirmwareWatchdog

    fw = DarkFirmwareManager()
    hook_status = fw.init_hooks(dongle_hci)
    if hook_status.get("all_ok"):
        info(f"[bt.green]DarkFirmware ready[/bt.green] on {dongle_hci}")
    else:
        active = [k for k in ("hook1", "hook2", "hook3", "hook4") if hook_status.get(k)]
        warning(f"DarkFirmware partial: {', '.join(active)} active")

    watchdog = DarkFirmwareWatchdog(dongle_hci, poll_interval=30.0)
    watchdog.start()


# ── Import and register commands ─────────────────────────────────────────────

# Assessment workflow
from blue_tap.interfaces.cli.discover import discover  # noqa: E402
from blue_tap.interfaces.cli.recon import recon  # noqa: E402
from blue_tap.interfaces.cli.vulnscan import vulnscan  # noqa: E402
from blue_tap.interfaces.cli.exploit import exploit  # noqa: E402
from blue_tap.interfaces.cli.dos import dos  # noqa: E402
from blue_tap.interfaces.cli.extract import extract  # noqa: E402
from blue_tap.interfaces.cli.fuzz import fuzz  # noqa: E402
from blue_tap.interfaces.cli.reporting import report_cmd, run_playbook_cmd, session  # noqa: E402

cli.add_command(discover)
cli.add_command(recon)
cli.add_command(vulnscan)
cli.add_command(exploit)
cli.add_command(dos)
cli.add_command(extract)
cli.add_command(fuzz)
cli.add_command(report_cmd)

# Automation
from blue_tap.interfaces.cli.auto import auto  # noqa: E402
from blue_tap.interfaces.cli.fleet import fleet  # noqa: E402

cli.add_command(auto)
cli.add_command(fleet)

# Utilities
from blue_tap.interfaces.cli.adapter import adapter  # noqa: E402
from blue_tap.interfaces.cli.doctor import doctor  # noqa: E402
from blue_tap.interfaces.cli.spoof import spoof  # noqa: E402

cli.add_command(adapter)
cli.add_command(session)
cli.add_command(doctor)
cli.add_command(spoof)

# ── Sub-command proxy registrations ─────────────────────────────────────────
# Register each phase's sub-commands at the top level so they appear in
# the main --help output grouped by phase. Each proxy is a thin wrapper
# that just prints usage guidance pointing to the real command path.


_COMMAND_GROUP_ALIASES: dict[str, str] = {
    "vuln": "vulnscan",
}

_SUBCOMMAND_ALIASES: dict[tuple[str, str], str] = {
    ("recon", "hci-capture"): "capture",
    ("recon", "sniffer"): "sniff",
}

# Maps vuln-* proxy names to the assessment module short name that
# vulnscan --cve maps to ``assessment.<short_name>``. Only listed where
# the proxy name differs from the module short name.
_VULN_CHECK_ALIASES: dict[str, str] = {
    "encryption": "encryption_enforcement",
    "eatt": "eatt_support",
    "obex-auth": "authorization_model",
    "automotive-diag": "automotive_diagnostics",
}


def _make_proxy(parent_name: str, sub_name: str, help_text: str):
    """Create a proxy command that shows usage for a sub-command."""
    real_parent = _COMMAND_GROUP_ALIASES.get(parent_name, parent_name)
    real_sub = _SUBCOMMAND_ALIASES.get((parent_name, sub_name), sub_name)

    @click.command(f"{parent_name}-{sub_name}", cls=LoggedCommand, help=help_text)
    def _proxy():
        if parent_name == "dos":
            click.echo(f"Usage: blue-tap dos TARGET --checks {real_sub} [OPTIONS]")
            click.echo("\nThe dos command takes CVE/check names via --checks (comma-separated):")
            click.echo(f"  blue-tap dos TARGET --checks {real_sub}")
            click.echo("\nRun: blue-tap dos --help")
        elif parent_name == "vuln":
            if sub_name.startswith("cve-"):
                cve_id = sub_name.upper()
                click.echo(f"Usage: blue-tap vulnscan TARGET --cve {cve_id} [OPTIONS]")
                click.echo(f"\nRun: blue-tap vulnscan TARGET --cve {cve_id} --help")
            else:
                check_name = _VULN_CHECK_ALIASES.get(sub_name, sub_name.replace("-", "_"))
                click.echo(f"Usage: blue-tap vulnscan TARGET --cve {check_name} [OPTIONS]")
                click.echo("\nRun: blue-tap vulnscan --help")
        elif parent_name in ("discover", "fuzz"):
            click.echo(f"Usage: blue-tap {real_parent} {real_sub} [OPTIONS]")
            click.echo(f"\nRun: blue-tap {real_parent} {real_sub} --help")
        else:
            click.echo(f"Usage: blue-tap {real_parent} TARGET {real_sub} [OPTIONS]")
            click.echo(f"\nRun: blue-tap {real_parent} TARGET {real_sub} --help")

    return _proxy


# Discovery sub-commands
for _n, _h in [
    ("classic", "Scan for Classic Bluetooth (BR/EDR) devices"),
    ("ble", "Scan for BLE (Low Energy) devices"),
    ("all", "Scan for all Bluetooth devices (Classic + BLE)"),
]:
    cli.add_command(_make_proxy("discover", _n, _h))

# Recon sub-commands
for _n, _h in [
    ("auto", "Run all reconnaissance collectors against the target"),
    ("sdp", "SDP service enumeration — discover profiles and channels"),
    ("gatt", "BLE GATT attribute discovery — services, characteristics"),
    ("rfcomm", "RFCOMM channel scanning — find open serial channels"),
    ("l2cap", "L2CAP channel scanning — probe for open PSM channels"),
    ("fingerprint", "Device fingerprinting — OS, chipset, firmware version"),
    ("hci-capture", "HCI traffic capture via btmon — save to pcap"),
    ("sniffer", "BLE/LMP sniffing via nRF52840 or DarkFirmware"),
    ("capabilities", "Detect supported profiles, transports, and features"),
    ("analyze", "Analyze captured pcap — protocol breakdown and anomalies"),
    ("correlate", "Correlate findings from multiple collectors"),
    ("interpret", "Interpret Bluetooth spec data — flags, versions, class codes"),
]:
    cli.add_command(_make_proxy("recon", _n, _h))

# Exploit sub-commands
for _n, _h in [
    ("bias", "BIAS impersonation attack — CVE-2020-10135"),
    ("bluffs", "BLUFFS session key downgrade — CVE-2023-24023"),
    ("knob", "KNOB key negotiation attack — CVE-2019-9506"),
    ("ctkd", "Cross-transport key derivation — CVE-2020-15802"),
    ("enc-downgrade", "Encryption mode downgrade via LMP injection"),
    ("ssp-downgrade", "SSP → legacy PIN downgrade with brute-force"),
    ("hijack", "Full connection hijack (spoof → connect → MITM)"),
    ("pin-brute", "Legacy PIN brute-force attack"),
]:
    cli.add_command(_make_proxy("exploit", _n, _h))

# Extract sub-commands
for _n, _h in [
    ("contacts", "PBAP phonebook extraction (contacts, call logs)"),
    ("messages", "MAP message extraction (SMS, MMS)"),
    ("audio", "HFP call audio — dial, record, eavesdrop"),
    ("stream", "A2DP audio streaming — capture, record, eavesdrop, loopback"),
    ("media", "AVRCP media control — play, pause, volume, track info"),
    ("push", "OPP file push to target device"),
    ("snarf", "Bluesnarfer data extraction (legacy OBEX)"),
    ("at", "AT command probing via RFCOMM"),
]:
    cli.add_command(_make_proxy("extract", _n, _h))

# Vulnerability assessment proxies — CVE checks run by vulnscan
for _n, _h in [
    ("cve-2017-0783", "BNEP role-swap authorization bypass"),
    ("cve-2017-0785", "SDP continuation-state replay info leak"),
    ("cve-2017-13258", "BNEP heap oracle info leak family"),
    ("cve-2018-9359", "Android L2CAP heap jitter OOB read"),
    ("cve-2018-9365", "SMP cross-transport OOB pairing bypass"),
    ("cve-2019-2225", "JustWorks silent pairing without user consent"),
    ("cve-2019-3459", "Linux L2CAP CONF_REQ MTU pointer leak"),
    ("cve-2020-0022", "BlueFrag ACL fragment boundary probe"),
    ("cve-2020-0556", "HID/HOGP unauthenticated connection"),
    ("cve-2020-12352", "BadChoice A2MP heap info leak"),
    ("cve-2020-26558", "Passkey reflected public-key MITM"),
    ("cve-2021-0507", "AVRCP metadata OOB read"),
    ("cve-2022-0204", "BlueZ GATT prepare-write heap overflow"),
    ("cve-2022-20345", "eCred 6-CID L2CAP overflow"),
    ("cve-2022-25837", "BR/EDR method confusion pairing bypass"),
    ("cve-2022-39176", "AVRCP GetCapabilities OOB leak"),
    ("cve-2022-42895", "L2CAP EFS option info leak"),
    ("cve-2022-42896", "LE credit-based PSM zero UAF"),
    ("cve-2023-35681", "Android EATT integer overflow"),
    ("cve-2023-45866", "HOGP unbonded HID write"),
    ("cve-2024-34722", "BLE legacy pairing bypass"),
    ("cve-2025-20700", "Airoha RACE unauthenticated GATT access"),
    ("cve-2025-20701", "Airoha RACE unauthenticated BR/EDR access"),
    ("cve-2025-20702", "Airoha RACE link-key extraction"),
    ("cve-2026-23395", "eCred duplicate-identifier L2CAP overflow"),
    ("service-exposure", "Sensitive RFCOMM service reachability (OBEX, serial, diagnostics)"),
    ("hidden-rfcomm", "Unadvertised RFCOMM channel scanning"),
    ("encryption", "RFCOMM encryption enforcement posture"),
    ("writable-gatt", "Writable GATT characteristic surface analysis"),
    ("eatt", "EATT (Enhanced ATT) capability posture"),
    ("pairing-method", "Pairing method posture with IO-capability context"),
    ("pin-lockout", "Legacy PIN lockout and throttling behavior"),
    ("device-class", "Device class profile posture and corroboration"),
    ("lmp-features", "LMP feature flags posture and prerequisites"),
    ("obex-auth", "OBEX authorization model and access control posture"),
    ("automotive-diag", "Automotive diagnostic surface exposure (OBD, serial)"),
]:
    cli.add_command(_make_proxy("vuln", _n, _h))

# DoS check proxies — CVE-backed crash probes + protocol stress tests
for _n, _h in [
    ("cve-2020-0022", "BlueFrag raw ACL fragment mismatch crash"),
    ("cve-2017-0781", "BlueBorne BNEP heap overflow probe"),
    ("cve-2017-0782", "BlueBorne BNEP filter length underflow"),
    ("cve-2019-19192", "SweynTooth ATT deadlock (BlueNRG)"),
    ("cve-2019-19196", "SweynTooth SMP key-size overflow"),
    ("cve-2022-39177", "AVDTP malformed SET_CONFIGURATION crash"),
    ("cve-2023-27349", "AVRCP REGISTER_NOTIFICATION OOB crash"),
    ("cve-2025-0084", "SDP double-connection HFP discovery race"),
    ("cve-2025-48593", "HFP post-pairing rapid RFCOMM reconnect race"),
    ("l2cap", "L2CAP storm, CID exhaust, data flood, l2ping flood"),
    ("sdp", "SDP continuation-state exhaustion + nested DES bomb"),
    ("rfcomm", "RFCOMM SABM/mux flood — exhaust multiplexer resources"),
    ("obex", "OBEX concurrent session flood"),
    ("hfp", "HFP AT flood + SLC state confusion"),
    ("lmp", "LMP detach/switch/feature/opcode/encryption/timing floods"),
    ("pairing", "Pair flood, name flood, and rate-test probes"),
]:
    cli.add_command(_make_proxy("dos", _n, _h))

# Fuzz sub-commands
for _n, _h in [
    ("campaign", "Run a multi-protocol fuzzing campaign"),
    ("sdp-deep", "Deep SDP protocol fuzzing"),
    ("l2cap-sig", "L2CAP signaling fuzzing via DarkFirmware"),
    ("rfcomm-raw", "Raw RFCOMM protocol fuzzing"),
    ("ble-att", "BLE ATT protocol fuzzing"),
    ("ble-smp", "BLE SMP pairing protocol fuzzing"),
    ("bnep", "BNEP network encapsulation fuzzing"),
    ("obex", "OBEX protocol fuzzing"),
    ("at-deep", "AT command injection fuzzing"),
    ("crashes", "List and analyze discovered crashes"),
    ("minimize", "Minimize a crash test case"),
    ("cve", "Replay a known CVE fuzz pattern"),
    ("replay", "Replay a crash for reproduction"),
    ("corpus", "Manage the fuzzing corpus"),
]:
    cli.add_command(_make_proxy("fuzz", _n, _h))


# Hidden power-user commands (not shown in --help, still functional)
from blue_tap.interfaces.cli.runner import run_cmd, search_cmd, info_cmd, show_options_cmd  # noqa: E402
from blue_tap.interfaces.cli.plugins import plugins  # noqa: E402

cli.add_command(run_cmd, "run")
cli.add_command(search_cmd, "search")
cli.add_command(info_cmd, "info")
cli.add_command(show_options_cmd, "show-options")
cli.add_command(plugins)
cli.add_command(run_playbook_cmd)

# Mark hidden
for _name in ("run", "search", "info", "show-options", "plugins", "run-playbook"):
    _cmd = cli.commands.get(_name)
    if _cmd:
        _cmd.hidden = True


# ── Demo command (hidden) ─────────────────────────────────────────────────────

@cli.command("demo", hidden=True)
@click.option("-o", "--output", default="demo_output", help="Output directory")
def demo_cmd(output):
    """Run a demo with simulated data (no hardware needed)."""
    from blue_tap.demo.runner import run_demo
    run_demo(output_dir=output)


# ── Entry point ───────────────────────────────────────────────────────────────

def _check_privileges() -> bool:
    """Check if running with root/sudo."""
    return os.geteuid() == 0


_NO_ROOT_COMMANDS = {
    "--help", "-h", "--version", "demo", "doctor",
    "search", "info", "show-options", "plugins",
}


def _check_rtl_dongle() -> None:
    """Detect RTL8761B dongle at startup and offer to flash DarkFirmware."""
    try:
        from blue_tap.hardware.firmware import DarkFirmwareManager
        from blue_tap.utils.output import console
        from rich.prompt import Confirm
    except ImportError:
        return

    fw = DarkFirmwareManager()

    try:
        dongle_hci = fw.find_rtl8761b_hci()
    except Exception:
        dongle_hci = None

    if dongle_hci is None:
        console.print(
            "[bold red]No RTL8761B / TP-Link UB500 dongle detected.[/bold red] "
            "Blue-tap requires a Realtek RTL8761B chipset."
        )
        sys.exit(1)

    try:
        from blue_tap.utils.bt_helpers import get_hci_adapters
        adapters = {a["name"]: a for a in get_hci_adapters()}
        if adapters.get(dongle_hci, {}).get("status") != "UP":
            return
    except Exception:
        pass

    try:
        df_loaded = fw.is_darkfirmware_loaded(dongle_hci)
    except Exception:
        info(f"[dim]RTL8761B detected on {dongle_hci} — firmware status unavailable[/dim]")
        return

    if df_loaded:
        _init_darkfirmware_hooks(dongle_hci)
        return

    console.print()
    console.print(
        f"[bold bt.yellow]RTL8761B dongle detected[/bold bt.yellow] on [bold]{dongle_hci}[/bold] "
        f"— [bt.yellow]stock firmware[/bt.yellow] is loaded."
    )
    console.print(
        "  DarkFirmware enables LMP injection, BDADDR spoofing, and below-HCI attacks\n"
        "  (BIAS, BLUFFS, KNOB, CTKD, LMP fuzzing).\n"
        "  The bundled firmware binary is a patched Realtek image with four hook points;\n"
        "  original firmware is backed up and restorable via [bold]blue-tap adapter firmware-install --restore[/bold]."
    )
    console.print()

    try:
        flash = Confirm.ask(
            "  [bold]Flash DarkFirmware now?[/bold] (original will be backed up)",
            default=False,
        )
    except (EOFError, KeyboardInterrupt):
        info(f"[dim]Skipping firmware flash (non-interactive). "
             f"Run: blue-tap adapter firmware-install[/dim]")
        console.print()
        return

    console.print()
    if not flash:
        info(
            "[dim]Continuing with stock firmware. "
            "Run [bold]blue-tap adapter firmware-install[/bold] to enable LMP-level features.[/dim]"
        )
        console.print()
        return

    info(f"Installing DarkFirmware on {dongle_hci}…")
    try:
        ok = fw.install_firmware()
    except Exception as exc:
        error(f"Firmware install failed: {exc}")
        console.print()
        return

    if not ok:
        error(
            "Firmware install returned failure. "
            "Retry manually: [bold]sudo blue-tap adapter firmware-install[/bold]"
        )
        console.print()
        return

    info("Resetting USB dongle to load new firmware…")
    try:
        fw.usb_reset()
    except Exception as exc:
        warning(f"USB reset failed ({exc}). Unplug and re-plug the dongle to activate DarkFirmware.")
        console.print()
        return

    info(f"[bold green]DarkFirmware installed and active on {dongle_hci}.[/bold green]")
    console.print()


def main():
    """Entry point — shows banner and loads modules."""
    _first_arg = sys.argv[1] if len(sys.argv) > 1 else ""
    _SILENT_COMMANDS = {
        "search", "info", "show-options", "plugins",
        "adapter", "session", "report", "doctor",
    }
    _is_silent = (
        _first_arg in _SILENT_COMMANDS or
        _first_arg in {"--version", "--help", "-h"} or
        (_first_arg == "run-playbook" and "--list" in sys.argv)
    )

    if not _is_silent:
        banner()

    # Load modules
    try:
        from blue_tap.framework.module import autoload_builtin_modules
        from blue_tap.framework.module.loader import get_plugin_registry
        from blue_tap.framework.registry import get_registry

        autoload_builtin_modules()

        registry = get_registry()
        total = len([m for m in registry.list_all() if not getattr(m, "internal", False)])

        if not _is_silent:
            plugin_registry = get_plugin_registry()
            if plugin_registry:
                loaded = [n for n, d in plugin_registry.items() if d.get("loaded")]
                failed = [n for n, d in plugin_registry.items() if not d.get("loaded")]
                if loaded:
                    info(f"[dim]{total} modules loaded (+{len(loaded)} plugin(s))[/dim]")
                for name in failed:
                    warning(f"[dim]Plugin '{name}' failed to load[/dim]")
            else:
                info(f"[dim]{total} modules loaded[/dim]")

    except Exception as e:
        warning(f"Module loading failed: {e}")

    # Root check
    args_lower = {a.lower().lstrip("-") for a in sys.argv[1:]}
    raw_args = set(sys.argv[1:])

    skip_root = (
        not sys.argv[1:] or
        raw_args & {"--help", "-h", "--version"} or
        args_lower & {"help", "version", "demo", "doctor",
                      "search", "info", "show-options", "plugins"}
    )

    if not skip_root and not _check_privileges():
        error(
            "Blue-Tap requires root for Bluetooth operations.\n"
            "\n"
            "  Run with: [bold]sudo blue-tap[/bold] <command>\n"
            "\n"
            "  Or: sudo setcap cap_net_raw+eip $(which python3)\n"
            "\n"
            "  [dim]No root needed: --help, doctor, search, plugins[/dim]"
        )
        sys.exit(1)

    # RTL8761B dongle detection
    _hw_skip_commands = {
        "session", "report", "plugins", "doctor",
        "search", "info", "show-options",
    }
    _skip_hw = (
        _first_arg in _hw_skip_commands or
        (_first_arg == "run-playbook" and "--list" in sys.argv)
    )
    if not skip_root and not _skip_hw:
        _check_rtl_dongle()

    cli()


if __name__ == "__main__":
    main()
