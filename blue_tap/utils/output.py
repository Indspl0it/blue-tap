"""Blue-Tap Rich UI — styled console output with phase tracking and verbosity."""

import time
from contextlib import contextmanager
from datetime import datetime

from rich import box as rich_box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ── Color Palette ──────────────────────────────────────────────────────────
# Muted, professional palette. Color conveys meaning, not decoration.
# Raw hex for Style objects; theme names (bt.*) for Rich markup strings.

CYAN   = "#5B9FD4"   # steel blue  — primary / info
GREEN  = "#4BAE82"   # sage green  — success / ok
YELLOW = "#C99A3E"   # warm amber  — warning / caution
RED    = "#C85F5F"   # muted red   — error / destructive
PURPLE = "#8E7FC0"   # soft violet — addresses / secondary
DIM    = "#6E7681"   # neutral gray
BLUE   = "#5A8FC4"   # medium blue — alternate accent
ORANGE = "#C07848"   # muted rust  — tertiary accent
PINK   = "#B87AAE"   # soft rose   — unused / spare

_THEME = Theme(
    {
        "bt.cyan":   CYAN,
        "bt.green":  GREEN,
        "bt.yellow": YELLOW,
        "bt.red":    RED,
        "bt.purple": PURPLE,
        "bt.dim":    DIM,
        "bt.blue":   BLUE,
        "bt.orange": ORANGE,
        "bt.pink":   PINK,
    }
)

console = Console(theme=_THEME)

# ── Verbosity ──────────────────────────────────────────────────────────────

_VERBOSITY = 0  # 0 = normal, 1 = verbose (-v), 2 = debug (-vv)


def set_verbosity(level: int):
    """Set global verbosity: 0=normal, 1=verbose, 2=debug."""
    global _VERBOSITY
    _VERBOSITY = max(0, min(2, level))


def get_verbosity() -> int:
    return _VERBOSITY


# ── Banner ─────────────────────────────────────────────────────────────────

_LOGO = """\
  [bold #5B9FD4]██████╗ ██╗     ██╗   ██╗███████╗[/bold #5B9FD4] [bold #8E7FC0]████████╗ █████╗ ██████╗[/bold #8E7FC0]
  [bold #5B9FD4]██╔══██╗██║     ██║   ██║██╔════╝[/bold #5B9FD4] [bold #8E7FC0]╚══██╔══╝██╔══██╗██╔══██╗[/bold #8E7FC0]
  [bold #5B9FD4]██████╔╝██║     ██║   ██║█████╗  [/bold #5B9FD4] [bold #8E7FC0]   ██║   ███████║██████╔╝[/bold #8E7FC0]
  [bold #5B9FD4]██╔══██╗██║     ██║   ██║██╔══╝  [/bold #5B9FD4] [bold #8E7FC0]   ██║   ██╔══██║██╔═══╝[/bold #8E7FC0]
  [bold #5B9FD4]██████╔╝███████╗╚██████╔╝███████╗[/bold #5B9FD4] [bold #8E7FC0]   ██║   ██║  ██║██║[/bold #8E7FC0]
  [dim]╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝    ╚═╝   ╚═╝  ╚═╝╚═╝[/dim]"""

_BANNER_SHOWN = False

def banner():
    """Print the Blue-Tap ASCII art banner (once per process)."""
    global _BANNER_SHOWN
    if _BANNER_SHOWN:
        return
    _BANNER_SHOWN = True
    console.print()
    console.print(_LOGO, highlight=False)
    console.print(
        "  [bt.dim]──────────────────────────────────────────────────────[/bt.dim]",
        highlight=False,
    )
    from blue_tap import __version__
    console.print(
        f"  [bt.dim]Bluetooth Security Toolkit  ·  v{__version__}[/bt.dim]",
        highlight=False,
    )
    console.print()


# ── Timestamp helper ───────────────────────────────────────────────────────

def _ts() -> str:
    """Return a dim HH:MM:SS timestamp."""
    return datetime.now().strftime("%H:%M:%S")


# ── Core log functions ─────────────────────────────────────────────────────

def _safe_print(formatted: str, fallback_plain: str) -> None:
    """Print a Rich-markup string; fall back to plain text on MarkupError.

    User-provided strings (device names, error text, target addresses) may
    contain stray brackets that Rich interprets as malformed markup. Instead of
    forcing every caller to escape, we catch MarkupError and re-print with
    markup disabled so the operator still sees the message.
    """
    from rich.errors import MarkupError
    try:
        console.print(formatted)
    except MarkupError:
        console.print(fallback_plain, markup=False)


def info(msg: str):
    """Informational message — cyan [*]."""
    _safe_print(
        f"  [bt.dim]{_ts()}[/bt.dim]  [bt.cyan]●[/bt.cyan]  {msg}",
        f"  {_ts()}  ●  {msg}",
    )


def success(msg: str):
    """Success message — green [+]."""
    _safe_print(
        f"  [bt.dim]{_ts()}[/bt.dim]  [bt.green]✔[/bt.green]  {msg}",
        f"  {_ts()}  ✔  {msg}",
    )


def warning(msg: str):
    """Warning message — amber [!]."""
    _safe_print(
        f"  [bt.dim]{_ts()}[/bt.dim]  [bt.yellow]⚠[/bt.yellow]  {msg}",
        f"  {_ts()}  ⚠  {msg}",
    )


def error(msg: str):
    """Error message — red [-]."""
    _safe_print(
        f"  [bt.dim]{_ts()}[/bt.dim]  [bt.red]✖[/bt.red]  {msg}",
        f"  {_ts()}  ✖  {msg}",
    )


def verbose(msg: str):
    """Only printed when -v or higher."""
    if _VERBOSITY >= 1:
        _safe_print(
            f"  [bt.dim]{_ts()}[/bt.dim]  [bt.dim]·[/bt.dim]  [bt.dim]{msg}[/bt.dim]",
            f"  {_ts()}  ·  {msg}",
        )


def debug(msg: str):
    """Only printed when -vv."""
    if _VERBOSITY >= 2:
        _safe_print(
            f"  [bt.dim]{_ts()}[/bt.dim]  [bt.dim]⋯[/bt.dim]  [dim]{msg}[/dim]",
            f"  {_ts()}  ⋯  {msg}",
        )


# ── Target highlighting ───────────────────────────────────────────────────

def target(address: str) -> str:
    """Wrap a MAC address in purple styling for inline use."""
    return f"[bt.purple]{address}[/bt.purple]"


def highlight(text: str, style: str = "bt.cyan") -> str:
    """Wrap text in a style for inline use."""
    return f"[{style}]{text}[/{style}]"


# ── Phase / Step tracking ─────────────────────────────────────────────────

@contextmanager
def phase(name: str, number: int = None, total: int = None):
    """Context manager for a numbered attack/recon phase.

    Usage:
        with phase("Reconnaissance", 1, 5):
            info("Scanning...")
            ...

    Prints a styled header on entry, elapsed time + status on exit.
    """
    if number is not None and total is not None:
        counter = f"[bt.dim]{number}/{total}[/bt.dim]  "
    elif number is not None:
        counter = f"[bt.dim]{number}[/bt.dim]  "
    else:
        counter = ""

    header = f"{counter}[bold]{name}[/bold]"
    console.print()
    console.rule(header, style="dim")
    t0 = time.time()
    try:
        yield
    except Exception:
        elapsed = time.time() - t0
        console.print(
            f"  [bt.dim]{_ts()}[/bt.dim]  [bt.red]✖[/bt.red]  "
            f"Phase failed [bt.dim]({elapsed:.1f}s)[/bt.dim]"
        )
        raise
    else:
        elapsed = time.time() - t0
        console.print(
            f"  [bt.dim]{_ts()}[/bt.dim]  [bt.green]✔[/bt.green]  "
            f"Phase complete [bt.dim]({elapsed:.1f}s)[/bt.dim]"
        )


@contextmanager
def step(description: str):
    """Context manager for a sub-step within a phase.

    Usage:
        with step("Fingerprinting target"):
            ...  # work

    Shows a spinner while running, then elapsed time on completion.
    """
    t0 = time.time()
    console.print(f"  [bt.dim]{_ts()}[/bt.dim]  [bt.dim]├─[/bt.dim] {description}")
    try:
        yield
    except Exception:
        elapsed = time.time() - t0
        console.print(
            f"  [bt.dim]{_ts()}[/bt.dim]  [bt.dim]│[/bt.dim]  "
            f"[bt.red]└ failed[/bt.red] [bt.dim]({elapsed:.1f}s)[/bt.dim]"
        )
        raise
    else:
        elapsed = time.time() - t0
        if _VERBOSITY >= 1:
            console.print(
                f"  [bt.dim]{_ts()}[/bt.dim]  [bt.dim]│[/bt.dim]  "
                f"[bt.green]└ done[/bt.green] [bt.dim]({elapsed:.1f}s)[/bt.dim]"
            )


def substep(msg: str):
    """Print an indented sub-step line (always visible)."""
    console.print(f"  [bt.dim]{_ts()}[/bt.dim]  [bt.dim]│  ·[/bt.dim] {msg}")


# ── Section headers ────────────────────────────────────────────────────────

def section(title: str, style: str = "bt.cyan"):
    """Print a styled section divider."""
    console.print()
    console.rule(f"[bold {style}]{title}[/bold {style}]", style="dim")


# ── Summary panel ──────────────────────────────────────────────────────────

def summary_panel(title: str, items: dict, style: str = "cyan"):
    """Print a summary block with key-value pairs.

    Usage:
        summary_panel("Recon Results", {
            "Target": "AA:BB:CC:DD:EE:FF",
            "Services": "12 found",
            "PBAP Channel": "19",
        })
    """
    console.print(f"\n[bold]{title}[/bold]")
    console.print(f"[bt.dim]{'─' * 50}[/bt.dim]")
    for key, value in items.items():
        console.print(f"  [bt.dim]{key:<20}[/bt.dim]{value}")
    console.print()


# ── Result box ─────────────────────────────────────────────────────────────

def result_box(title: str, content: str, style: str = "green"):
    """Small result block for single-value outcomes."""
    console.print(f"\n[bold]{title}[/bold]  {content}\n")


# ── Progress helpers ───────────────────────────────────────────────────────

def get_progress(**kwargs) -> Progress:
    """Create a styled Rich Progress bar."""
    return Progress(
        SpinnerColumn("dots", style=CYAN),
        TextColumn(f"[{CYAN}]{{task.description}}[/{CYAN}]"),
        BarColumn(bar_width=30, style=DIM, complete_style=CYAN, finished_style=GREEN),
        TextColumn(f"[{DIM}]{{task.percentage:>3.0f}}%[/{DIM}]"),
        TimeElapsedColumn(),
        console=console,
        **kwargs,
    )


def get_spinner(description: str = "Working..."):
    """Create a simple spinner status."""
    return console.status(f"[bt.cyan]{description}", spinner="dots")


# ── Tables ─────────────────────────────────────────────────────────────────

_CIRCLED = "①②③④⑤⑥⑦⑧⑨"

_HDR = "bt.dim"       # column header style
_PAD = (0, 2)         # cell padding: 0 vertical, 2 horizontal gives breathing room


def _idx(i: int) -> str:
    return _CIRCLED[i - 1] if 1 <= i <= len(_CIRCLED) else f"{i}."


def bare_table() -> Table:
    """A borderless table with dim headers and comfortable column padding.

    Wrap in a Panel via ``print_table()`` to get the rich_click-style outer
    border without internal column or row separators.
    """
    return Table(
        box=None,
        show_header=True,
        show_lines=False,
        header_style=_HDR,
        padding=_PAD,
        pad_edge=False,
    )


def print_table(table: Table, *, con: "Console | None" = None, expand: bool = False) -> None:
    """Print a Rich table wrapped in a rich_click-style rounded Panel.

    Moves the table's title into the Panel border (``╭─ Title ───╮``) and
    prints with a blank line of breathing space above and below.

    ``expand=False`` (default) shrinks the Panel to content width — ideal
    for narrow data tables (adapter lists, host lists, etc.).
    ``expand=True`` fills the full terminal width — use when columns contain
    long text that should wrap naturally (list-modules, etc.).
    """
    _con = con or console
    title = table.title
    table.title = None
    panel = Panel(
        table,
        title=title,
        title_align="left",
        border_style=DIM,
        box=rich_box.ROUNDED,
        padding=(0, 1),
        expand=expand,
    )
    _con.print()
    _con.print(panel)
    _con.print()


def device_table(devices: list[dict], title: str = "Discovered Devices") -> None:
    """Print an aligned device summary."""
    t = bare_table()
    t.title = f"[bold]{title}[/bold]  [bt.dim]({len(devices)} found)[/bt.dim]"
    t.add_column("")                          # circled index, narrow
    t.add_column("Address", style="bt.purple")
    t.add_column("Name")
    t.add_column("RSSI", justify="right")
    t.add_column("Type", style="bt.dim")
    t.add_column("Class / Mfr", style="bt.dim")

    for i, dev in enumerate(devices, 1):
        address = dev.get("address", "N/A")
        name = dev.get("name", "Unknown")
        name_cell = f"[bold]{name}[/bold]" if name != "Unknown" else f"[bt.dim]{name}[/bt.dim]"

        rssi_raw = dev.get("rssi")
        if rssi_raw is not None:
            try:
                val = int(rssi_raw)
                clr = "bt.green" if val > -50 else ("bt.yellow" if val > -70 else "bt.red")
                rssi_cell = f"[{clr}]{val} dBm[/{clr}]"
            except (ValueError, TypeError):
                rssi_cell = str(rssi_raw)
        else:
            rssi_cell = "[bt.dim]—[/bt.dim]"

        dev_type = dev.get("type", "Classic")

        class_info = dev.get("class_info", {}) or {}
        extra = class_info.get("minor", "") or class_info.get("major", "")
        if not extra or extra == "Unknown":
            extra = dev.get("manufacturer_name") or dev.get("oui_vendor") or ""
        if not extra:
            mfr_data = dev.get("manufacturer_data") or []
            extra = mfr_data[0].get("company_hex", "") if mfr_data else ""

        t.add_row(_idx(i), address, name_cell, rssi_cell, dev_type, extra)

    print_table(t)


def service_table(services: list[dict], title: str = "Services") -> None:
    """Print an aligned service summary."""
    t = bare_table()
    t.title = f"[bold]{title}[/bold]  [bt.dim]({len(services)} found)[/bt.dim]"
    t.add_column("#", style="bt.dim", justify="right")
    t.add_column("Ch / PSM", style="bt.yellow", justify="right")
    t.add_column("Protocol", style="bt.cyan")
    t.add_column("Name")
    t.add_column("Ver", style="bt.dim")

    for i, svc in enumerate(services, 1):
        ch_val = svc.get("channel") or svc.get("psm")
        proto = svc.get("protocol", "N/A")
        ch_label = ("ch " if "channel" in svc else "psm ") if ch_val is not None else ""
        ch_cell = f"{ch_label}{ch_val}" if ch_val is not None else "—"
        name = svc.get("name", "Unknown")
        ver = svc.get("profile_version") or svc.get("version") or ""
        t.add_row(str(i), ch_cell, proto, f"[bold]{name}[/bold]", ver)

    print_table(t)


def vuln_table(findings: list[dict], title: str = "Vulnerability Findings") -> None:
    """Print an aligned vulnerability findings summary."""
    t = bare_table()
    t.title = f"[bold]{title}[/bold]  [bt.dim]({len(findings)} found)[/bt.dim]"
    t.add_column("Severity")
    t.add_column("Status")
    t.add_column("Name")
    t.add_column("CVE", style="bt.dim")

    _sev_color = {"critical": "bt.red", "high": "bt.red", "medium": "bt.yellow"}
    _status_color = {
        "confirmed": "bt.green",
        "inconclusive": "bt.yellow",
        "pairing_required": "bt.yellow",
        "potential": "bt.yellow",
    }

    for v in findings:
        sev = v.get("severity", "info").lower()
        clr = _sev_color.get(sev, "bt.dim")
        sev_cell = f"[{clr}]■ {sev.upper()}[/{clr}]"

        status = v.get("status", "potential")
        st_clr = _status_color.get(status, "bt.dim")
        status_cell = f"[{st_clr}]{status}[/{st_clr}]"

        t.add_row(sev_cell, status_cell, f"[bold]{v.get('name', '')}[/bold]", v.get("cve") or "")

    print_table(t)


def channel_table(results: list[dict], title: str = "Channel Scan") -> None:
    """Print an aligned channel scan summary."""
    is_rfcomm = any("channel" in r for r in results) if results else True

    t = bare_table()
    t.title = f"[bold]{title}[/bold]"
    t.add_column("CH" if is_rfcomm else "PSM", style="bt.yellow", justify="right")
    t.add_column("Status")
    t.add_column("Service")

    _status_display = {
        "open":             "[bt.green]● open[/bt.green]",
        "auth_required":    "[bt.yellow]◐ auth required[/bt.yellow]",
        "closed":           "[bt.dim]○ closed[/bt.dim]",
        "timeout":          "[bt.orange]◌ timeout[/bt.orange]",
        "host_unreachable": "[bt.red]✖ unreachable[/bt.red]",
    }

    for r in results:
        ch = str(r.get("channel", r.get("psm", "?")))
        status = r.get("status", "closed")
        name = r.get("name", r.get("response_type", ""))
        t.add_row(ch, _status_display.get(status, f"[bt.dim]{status}[/bt.dim]"), name)

    print_table(t)
