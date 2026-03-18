"""Fuzz CLI commands -- campaign dashboard and crash management.

Registers the ``fuzz campaign`` command with a Rich Live dashboard and
the ``fuzz crashes`` subgroup (list, show, replay, export) onto the
existing ``fuzz`` Click group defined in ``cli.py``.
"""

from __future__ import annotations

import json
import os
import select
import signal
import socket
import sys
import termios
import threading
import time
import tty
from datetime import datetime
from typing import Any

import click
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.style import Style

from bt_tap.utils.output import (
    console,
    info,
    success,
    error,
    warning,
    section,
    summary_panel,
    CYAN,
    GREEN,
    YELLOW,
    RED,
    DIM,
    PURPLE,
    ORANGE,
)
from bt_tap.utils.interactive import resolve_address
from bt_tap.utils.session import get_session

from bt_tap.fuzz.engine import (
    FuzzCampaign,
    CampaignStats,
    parse_duration,
    _format_duration,
    _check_target_alive,
    PROTOCOL_TRANSPORT_MAP,
    CRASH_SEVERITY,
)
from bt_tap.fuzz.corpus import Corpus, generate_full_corpus


def ensure_corpus(session_dir: str, protocols: list[str] | None = None) -> Corpus:
    """Ensure the fuzzing corpus is generated before any fuzz command.

    Called at the start of every fuzz command.  If seeds already exist for
    the requested protocols, this is a no-op.  Otherwise it generates the
    full corpus with a Rich progress display.

    Args:
        session_dir: Session directory (corpus stored in ``<session>/fuzz/corpus/``).
        protocols: Protocol names to generate for, or None for all.

    Returns:
        A :class:`Corpus` instance with seeds populated.
    """
    import os
    corpus_dir = os.path.join(session_dir, "fuzz", "corpus")
    corpus = Corpus(corpus_dir)
    generate_full_corpus(corpus, protocols=protocols, show_progress=True)
    return corpus


# ---------------------------------------------------------------------------
# Keyboard listener for pause / resume
# ---------------------------------------------------------------------------

class _KeyboardListener:
    """Non-blocking keyboard listener for pause/resume during fuzzing.

    Press 'p' to pause, 'p' again (or 'r') to resume.
    Press 'q' to gracefully stop the campaign.
    Press 's' to print a snapshot of current stats.

    Runs in a daemon thread so it doesn't block the main loop.
    Works by putting the terminal into raw/cbreak mode and polling stdin.
    """

    def __init__(self):
        self.paused = False
        self.quit_requested = False
        self.snapshot_requested = False
        self._running = False
        self._thread: threading.Thread | None = None
        self._old_settings = None

    def start(self) -> None:
        """Start listening for keypresses in a background thread."""
        if not sys.stdin.isatty():
            return  # Not a terminal (piped input), skip
        self._running = True
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the listener and restore terminal settings."""
        self._running = False
        if self._old_settings is not None:
            try:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._old_settings)
            except (termios.error, OSError):
                pass
            self._old_settings = None

    def wait_if_paused(self) -> None:
        """Block the calling thread while paused. Call this in the main fuzz loop."""
        while self.paused and self._running and not self.quit_requested:
            time.sleep(0.2)

    @property
    def status_text(self) -> str:
        if self.paused:
            return "[PAUSED] Press 'p' to resume, 'q' to stop"
        return "Press 'p' to pause, 'q' to stop, 's' for stats"

    def _listen(self) -> None:
        try:
            fd = sys.stdin.fileno()
            self._old_settings = termios.tcgetattr(fd)
            tty.setcbreak(fd)
        except (termios.error, OSError, ValueError):
            return  # Can't set cbreak mode

        try:
            while self._running:
                # Poll stdin with 0.3s timeout
                if select.select([sys.stdin], [], [], 0.3)[0]:
                    ch = sys.stdin.read(1)
                    if ch in ("p", "P"):
                        self.paused = not self.paused
                    elif ch in ("r", "R"):
                        self.paused = False
                    elif ch in ("q", "Q"):
                        self.quit_requested = True
                        self.paused = False  # Unblock if paused
                    elif ch in ("s", "S"):
                        self.snapshot_requested = True
        except (OSError, ValueError):
            pass
        finally:
            if self._old_settings is not None:
                try:
                    termios.tcsetattr(fd, termios.TCSADRAIN, self._old_settings)
                except (termios.error, OSError):
                    pass


# ---------------------------------------------------------------------------
# Dashboard builder
# ---------------------------------------------------------------------------

def _progress_bar(fraction: float, width: int = 20) -> str:
    """Render a text-based progress bar using Unicode block characters."""
    filled = int(fraction * width)
    remainder = fraction * width - filled
    bar = "\u2588" * filled
    if remainder > 0.5 and filled < width:
        bar += "\u2593"
        filled += 1
    bar += "\u2591" * (width - len(bar))
    # Ensure exactly `width` characters
    bar = bar[:width].ljust(width, "\u2591")
    return bar


def _severity_breakdown(crashes: list[dict]) -> str:
    """Summarise crash severities as e.g. ``CRITICAL:1 HIGH:2``."""
    counts: dict[str, int] = {}
    for c in crashes:
        sev = c.get("severity", "MEDIUM")
        counts[sev] = counts.get(sev, 0) + 1
    if not counts:
        return ""
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    parts = []
    for s in sev_order:
        if s in counts:
            parts.append(f"{s}:{counts[s]}")
    return "  ".join(parts)


def _build_dashboard(
    *,
    target: str,
    strategy: str,
    protocols: list[str],
    session_dir: str,
    capture_path: str | None,
    stats: CampaignStats,
    duration: float | None,
    max_iterations: int | None,
    crashes: list[dict],
    crash_counts_by_protocol: dict[str, int],
    last_crash: dict | None,
    paused: bool = False,
    keyboard_hint: str = "",
) -> Table:
    """Build the Rich renderable for the live campaign dashboard."""
    # Title changes when paused
    if paused:
        title_text = f"[bold {YELLOW}]BT-Tap Fuzzer -- PAUSED[/bold {YELLOW}]"
        border = YELLOW
    else:
        title_text = f"[bold {CYAN}]BT-Tap Fuzzer -- Campaign Dashboard[/bold {CYAN}]"
        border = CYAN

    # Outer table acts as the panel layout
    outer = Table(
        show_header=False,
        show_edge=True,
        show_lines=True,
        border_style=border,
        title=title_text,
        title_style=Style(bold=True, color=YELLOW if paused else CYAN),
        caption=f"[{DIM}]{keyboard_hint}[/{DIM}]" if keyboard_hint else None,
        caption_style=Style(color=DIM),
        padding=(0, 1),
        expand=True,
    )
    outer.add_column(ratio=1)

    # ── Row 1: Target info ────────────────────────────────────────────
    info_text = Text()
    info_text.append("  Target:     ", style="bold white")
    info_text.append(f"{target}\n", style=PURPLE)
    info_text.append("  Strategy:   ", style="bold white")
    info_text.append(f"{strategy}\n", style=YELLOW)
    info_text.append("  Protocols:  ", style="bold white")
    info_text.append(f"{', '.join(protocols)}\n", style=CYAN)
    info_text.append("  Session:    ", style="bold white")
    info_text.append(f"{session_dir}\n", style=DIM)
    if capture_path:
        info_text.append("  Capture:    ", style="bold white")
        info_text.append(capture_path, style=DIM)
    else:
        # Remove trailing newline from session line
        pass
    outer.add_row(info_text)

    # ── Row 2: Stats grid ─────────────────────────────────────────────
    stats_table = Table(
        show_header=False,
        show_edge=False,
        show_lines=False,
        border_style=DIM,
        padding=(0, 1),
        expand=True,
    )
    stats_table.add_column("Metric", style="bold white", min_width=16)
    stats_table.add_column("Value", style=CYAN, min_width=16)
    stats_table.add_column("Detail", min_width=30)

    # Runtime + progress
    elapsed = stats.runtime_seconds
    if duration and duration > 0:
        fraction = min(elapsed / duration, 1.0)
        pct = int(fraction * 100)
        bar = _progress_bar(fraction)
        runtime_detail = f"[{CYAN}]{bar}[/{CYAN}] [{GREEN}]{pct}%[/{GREEN}]"
    elif max_iterations and max_iterations > 0:
        fraction = min(stats.iterations / max_iterations, 1.0)
        pct = int(fraction * 100)
        bar = _progress_bar(fraction)
        runtime_detail = f"[{CYAN}]{bar}[/{CYAN}] [{GREEN}]{pct}%[/{GREEN}]"
    else:
        runtime_detail = f"[{DIM}]no limit set[/{DIM}]"

    stats_table.add_row(
        "Runtime",
        f"[{CYAN}]{_format_duration(elapsed)}[/{CYAN}]",
        runtime_detail,
    )

    pps = stats.packets_per_second
    stats_table.add_row(
        "Test Cases",
        f"[{CYAN}]{stats.iterations:,}[/{CYAN}]",
        f"[{YELLOW}]{pps:.1f} cases/sec[/{YELLOW}]",
    )

    sev_str = _severity_breakdown(crashes) if crashes else ""
    crash_style = RED if stats.crashes > 0 else GREEN
    stats_table.add_row(
        "Crashes Found",
        f"[{crash_style}]{stats.crashes}[/{crash_style}]",
        f"[{RED}]{sev_str}[/{RED}]" if sev_str else "",
    )

    stats_table.add_row(
        "Reconnects",
        f"[{YELLOW}]{stats.reconnects}[/{YELLOW}]",
        "",
    )

    # Current / next protocol
    idx = stats.iterations % len(protocols) if protocols else 0
    next_idx = (idx + 1) % len(protocols) if protocols else 0
    current_proto = stats.current_protocol or (protocols[idx] if protocols else "")
    next_proto = protocols[next_idx] if protocols else ""
    stats_table.add_row(
        "Current Proto",
        f"[{PURPLE}]{current_proto}[/{PURPLE}]",
        f"[{DIM}]Next: {next_proto}[/{DIM}]",
    )

    outer.add_row(stats_table)

    # ── Row 3: Last crash info ────────────────────────────────────────
    if last_crash:
        crash_text = Text()
        ts = last_crash.get("timestamp", "")
        if ts and len(ts) > 10:
            ts_short = ts[11:19] if "T" in ts else ts[:8]
        else:
            ts_short = ts
        proto = last_crash.get("protocol", "?")
        ctype = last_crash.get("crash_type", "?")
        payload_len = last_crash.get("payload_len", 0)
        payload_hex = last_crash.get("payload_hex", "")
        mutation = last_crash.get("mutation_log", "")

        crash_text.append(f"  Last Crash: ", style="bold white")
        crash_text.append(f"[{ts_short}] ", style=DIM)
        crash_text.append(f"{proto} ", style=PURPLE)
        crash_text.append(f"{ctype} ", style=YELLOW)
        crash_text.append(f"{payload_len} bytes\n", style="white")

        # Show first 32 hex bytes of payload
        preview = payload_hex[:64]  # 32 bytes = 64 hex chars
        if len(payload_hex) > 64:
            preview += "..."
        # Format as spaced hex pairs
        hex_spaced = " ".join(preview[i:i + 2] for i in range(0, len(preview), 2))
        crash_text.append("  Payload:    ", style="bold white")
        crash_text.append(f"{hex_spaced}\n", style=ORANGE)

        if mutation:
            first_line = mutation.split("\n")[0][:60]
            crash_text.append("  Mutation:   ", style="bold white")
            crash_text.append(first_line, style=DIM)
    else:
        crash_text = Text()
        crash_text.append("  No crashes detected yet.", style=DIM)

    outer.add_row(crash_text)

    # ── Row 4: Protocol breakdown ─────────────────────────────────────
    if stats.protocol_breakdown:
        # Arrange in 2-column pairs
        proto_items = sorted(stats.protocol_breakdown.items(), key=lambda x: x[1], reverse=True)
        parts = []
        for proto_name, sent_count in proto_items:
            crash_n = crash_counts_by_protocol.get(proto_name, 0)
            crash_color = RED if crash_n > 0 else GREEN
            parts.append(
                f"[{PURPLE}]{proto_name}[/{PURPLE}]: "
                f"[{CYAN}]{sent_count:,}[/{CYAN}] sent "
                f"[{DIM}]|[/{DIM}] "
                f"[{crash_color}]{crash_n}[/{crash_color}] crash"
            )

        # Two per line
        lines = []
        for i in range(0, len(parts), 2):
            pair = parts[i:i + 2]
            lines.append("  " + "     ".join(pair))

        breakdown_text = Text.from_markup("\n".join(lines))
        breakdown_panel = Panel(
            breakdown_text,
            title=f"[bold {CYAN}]Protocol Breakdown[/bold {CYAN}]",
            border_style=DIM,
            padding=(0, 1),
        )
        outer.add_row(breakdown_panel)
    else:
        outer.add_row(Text("  Waiting for first test case...", style=DIM))

    return outer


# ---------------------------------------------------------------------------
# TASK 4.1: Campaign Command
# ---------------------------------------------------------------------------

def _find_latest_session_dir() -> str | None:
    """Find the most recent session directory."""
    sessions_dir = "sessions"
    if not os.path.isdir(sessions_dir):
        return None
    entries = []
    for name in os.listdir(sessions_dir):
        path = os.path.join(sessions_dir, name)
        if os.path.isdir(path):
            entries.append((os.path.getmtime(path), path))
    if not entries:
        return None
    entries.sort(reverse=True)
    return entries[0][1]


def _resolve_session_dir(session_name: str | None) -> str | None:
    """Resolve a session name to its directory path.

    If session_name is None, returns the active session's dir or the latest
    session dir. If given, looks up ``sessions/<name>``.
    """
    if session_name:
        candidate = os.path.join("sessions", session_name)
        if os.path.isdir(candidate):
            return candidate
        # Maybe it's already a full path
        if os.path.isdir(session_name):
            return session_name
        error(f"Session not found: {session_name}")
        return None

    sess = get_session()
    if sess is not None:
        return sess.dir
    return _find_latest_session_dir()


def _open_crash_db(session_dir: str):
    """Open the CrashDB for the given session directory."""
    from bt_tap.fuzz.crash_db import CrashDB
    db_path = os.path.join(session_dir, "fuzz", "crashes.db")
    if not os.path.exists(db_path):
        error(f"No crash database found at {db_path}")
        return None
    return CrashDB(db_path)


# ── Campaign command ──────────────────────────────────────────────────────

def _campaign_command(fuzz_group):
    """Create and register the campaign command on the fuzz group."""

    @fuzz_group.command("campaign")
    @click.argument("address", required=False, default=None)
    @click.option(
        "--protocol", "-p", "protocols", multiple=True, default=("all",),
        type=click.Choice([
            "sdp", "obex-pbap", "obex-map", "obex-opp",
            "at-hfp", "at-phonebook", "at-sms",
            "ble-att", "ble-smp", "bnep", "rfcomm", "all",
        ], case_sensitive=False),
        help="Protocols to fuzz (repeat for multiple, default: all).",
    )
    @click.option(
        "--strategy", "-s", default="random",
        type=click.Choice(["random", "targeted", "coverage", "state-machine"]),
        help="Mutation strategy.",
    )
    @click.option("--duration", "-d", default="1h", help="Duration: 30s, 5m, 1h, 24h, 7d")
    @click.option("--iterations", "-n", default=None, type=int,
                  help="Max test cases (overrides duration)")
    @click.option("--delay", default=0.5, type=float,
                  help="Delay between test cases in seconds (default 0.5)")
    @click.option("--timeout", default=5.0, type=float,
                  help="Response timeout per test case (seconds)")
    @click.option("--cooldown", default=10, type=int,
                  help="Seconds to wait after crash detection")
    @click.option("--capture/--no-capture", default=False,
                  help="Enable btsnoop pcap capture during fuzzing")
    @click.option("--resume", is_flag=True,
                  help="Resume previous campaign from session")
    def campaign(
        address, protocols, strategy, duration, iterations,
        delay, timeout, cooldown, capture, resume,
    ):
        """Run a multi-protocol fuzzing campaign with live dashboard.

        \b
        Examples:
          bt-tap fuzz campaign AA:BB:CC:DD:EE:FF
          bt-tap fuzz campaign -p sdp -p rfcomm --duration 30m
          bt-tap fuzz campaign --strategy targeted --capture
          bt-tap fuzz campaign --resume
        """
        import signal

        # ── Session directory ─────────────────────────────────────────
        sess = get_session()
        if sess is None:
            error("No active session. Run with -s <name> or let auto-session create one.")
            return
        session_dir = sess.dir
        fuzz_dir = os.path.join(session_dir, "fuzz")
        os.makedirs(fuzz_dir, exist_ok=True)

        # ── Resume mode ───────────────────────────────────────────────
        if resume:
            try:
                cam = FuzzCampaign.resume(session_dir)
            except FileNotFoundError:
                error("No saved campaign state found in this session.")
                return
            except (json.JSONDecodeError, KeyError) as exc:
                error(f"Corrupt campaign state: {exc}")
                return
            address = cam.target
            info(f"Resuming campaign against [bt.purple]{address}[/bt.purple]")
        else:
            # ── Resolve target ────────────────────────────────────────
            address = resolve_address(address)
            if not address:
                return

            # ── Resolve protocols ─────────────────────────────────────
            proto_list: list[str]
            if "all" in protocols:
                proto_list = list(PROTOCOL_TRANSPORT_MAP.keys())
            else:
                proto_list = list(protocols)

            # ── Parse duration ────────────────────────────────────────
            dur_seconds: float | None = None
            if iterations is None:
                try:
                    dur_seconds = parse_duration(duration)
                except ValueError as exc:
                    error(str(exc))
                    return

            # ── Create campaign ───────────────────────────────────────
            cam = FuzzCampaign(
                target=address,
                protocols=proto_list,
                strategy=strategy,
                duration=dur_seconds,
                max_iterations=iterations,
                session_dir=session_dir,
                cooldown=float(cooldown),
            )

        # ── Pcap capture ──────────────────────────────────────────────
        hci_capture = None
        capture_path: str | None = None
        if capture:
            from bt_tap.recon.hci_capture import HCICapture
            capture_path = os.path.join(fuzz_dir, "capture.btsnoop")
            hci_capture = HCICapture()
            if not hci_capture.start(capture_path, pcap=True):
                warning("Pcap capture failed to start; continuing without capture.")
                hci_capture = None
                capture_path = None

        # ── Prepare campaign internals (transport, corpus) ────────────
        # We drive the main loop ourselves for dashboard control.
        cam._running = True
        cam.stats = CampaignStats()
        cam._setup_transports()

        if not cam._transports:
            error("No valid transports configured. Check protocol names.")
            _cleanup_capture(hci_capture)
            return

        # Connect transports
        for proto, transport in cam._transports.items():
            try:
                connected = transport.connect()
                if connected:
                    success(f"Connected: [bt.cyan]{proto}[/bt.cyan]")
                else:
                    warning(f"Could not connect: [bt.cyan]{proto}[/bt.cyan] (will retry)")
            except OSError as exc:
                warning(f"Transport setup failed for {proto}: {exc}")

        # Generate full fuzzing corpus with Rich progress
        section("Generating Fuzzing Corpus")
        results = generate_full_corpus(cam.corpus, protocols=cam.protocols, show_progress=True)
        # Fall back to engine's builtin seeds for any protocol not covered
        for proto in cam.protocols:
            if cam.corpus.seed_count(proto) == 0:
                cam._generate_initial_seeds(proto)
        total_seeds = sum(cam.corpus.seed_count(p) for p in cam.protocols)
        info(f"Corpus ready: [bold]{total_seeds:,}[/bold] seeds across {len(cam.protocols)} protocols")

        # Track crashes for dashboard
        all_crashes: list[dict] = []
        crash_counts_by_proto: dict[str, int] = {}

        # Keyboard listener for pause/resume/quit
        kb = _KeyboardListener()
        kb.start()

        # Signal handling
        interrupted = False
        prev_handler = signal.getsignal(signal.SIGINT)

        def _on_interrupt(signum, frame):
            nonlocal interrupted
            interrupted = True
            cam._running = False

        try:
            signal.signal(signal.SIGINT, _on_interrupt)
        except ValueError:
            pass  # Not main thread

        # ── Main loop with Live dashboard ─────────────────────────────
        try:
            with Live(
                _build_dashboard(
                    target=address,
                    strategy=cam.strategy,
                    protocols=cam.protocols,
                    session_dir=fuzz_dir,
                    capture_path=capture_path,
                    stats=cam.stats,
                    duration=cam.duration,
                    max_iterations=cam.max_iterations,
                    crashes=all_crashes,
                    crash_counts_by_protocol=crash_counts_by_proto,
                    last_crash=None,
                    paused=False,
                    keyboard_hint=kb.status_text,
                ),
                console=console,
                refresh_per_second=1,
                transient=False,
            ) as live:
                last_dashboard_update = time.time()

                while cam._should_continue() and not interrupted and not kb.quit_requested:
                    # ── Pause check ──
                    if kb.paused:
                        # Update dashboard to show PAUSED state
                        live.update(
                            _build_dashboard(
                                target=address, strategy=cam.strategy,
                                protocols=cam.protocols, session_dir=fuzz_dir,
                                capture_path=capture_path, stats=cam.stats,
                                duration=cam.duration, max_iterations=cam.max_iterations,
                                crashes=all_crashes,
                                crash_counts_by_protocol=crash_counts_by_proto,
                                last_crash=all_crashes[-1] if all_crashes else None,
                                paused=True,
                                keyboard_hint=kb.status_text,
                            )
                        )
                        kb.wait_if_paused()
                        if kb.quit_requested or interrupted:
                            break
                        continue  # Re-check loop condition after unpause

                    # ── Snapshot request ──
                    if kb.snapshot_requested:
                        kb.snapshot_requested = False
                        # The next dashboard update will show current state

                    protocol = cam._next_protocol()
                    cam.stats.current_protocol = protocol
                    transport = cam._transports.get(protocol)

                    if transport is None:
                        cam.stats.iterations += 1
                        continue

                    # Generate fuzz case
                    fuzz_case, mutation_log = cam._generate_fuzz_case(protocol)

                    # Send and observe
                    try:
                        _is_conn = (
                            transport.connected
                            if hasattr(transport, "connected")
                            and isinstance(
                                type(transport).__dict__.get("connected"), property
                            )
                            else transport.is_connected()
                            if hasattr(transport, "is_connected")
                            else False
                        )
                        if not _is_conn:
                            if not transport.connect():
                                cam.stats.errors += 1
                                cam.stats.iterations += 1
                                continue

                        transport.send(fuzz_case)
                        cam.stats.packets_sent += 1
                        cam.stats.protocol_breakdown[protocol] = (
                            cam.stats.protocol_breakdown.get(protocol, 0) + 1
                        )

                        response = transport.recv()
                        cam._analyze_response(protocol, fuzz_case, response, mutation_log)

                    except ConnectionResetError:
                        _record_crash(
                            cam, "connection_drop", protocol, fuzz_case, mutation_log,
                            all_crashes, crash_counts_by_proto,
                        )
                    except BrokenPipeError:
                        _record_crash(
                            cam, "connection_drop", protocol, fuzz_case, mutation_log,
                            all_crashes, crash_counts_by_proto,
                        )
                    except socket.timeout:
                        _record_crash(
                            cam, "timeout", protocol, fuzz_case, mutation_log,
                            all_crashes, crash_counts_by_proto,
                        )
                    except OSError as exc:
                        if "Host is down" in str(exc) or "No route" in str(exc):
                            _record_crash(
                                cam, "device_disappeared", protocol, fuzz_case, mutation_log,
                                all_crashes, crash_counts_by_proto,
                            )
                        else:
                            cam.stats.errors += 1

                    cam.stats.iterations += 1

                    # Update dashboard approximately once per second
                    now = time.time()
                    if now - last_dashboard_update >= 1.0:
                        last_crash = all_crashes[-1] if all_crashes else None
                        live.update(
                            _build_dashboard(
                                target=address,
                                strategy=cam.strategy,
                                protocols=cam.protocols,
                                session_dir=fuzz_dir,
                                capture_path=capture_path,
                                stats=cam.stats,
                                duration=cam.duration,
                                max_iterations=cam.max_iterations,
                                crashes=all_crashes,
                                crash_counts_by_protocol=crash_counts_by_proto,
                                last_crash=last_crash,
                                paused=kb.paused,
                                keyboard_hint=kb.status_text,
                            )
                        )
                        last_dashboard_update = now

                    # Delay between test cases
                    if delay > 0 and cam._should_continue() and not interrupted:
                        time.sleep(delay)

        except Exception as exc:
            error(f"Campaign error: {exc}")
        finally:
            # Stop keyboard listener and restore terminal
            kb.stop()
            # Restore signal handler
            try:
                signal.signal(signal.SIGINT, prev_handler)
            except ValueError:
                pass

        # ── Finalize ──────────────────────────────────────────────────
        cam._finalize()
        _cleanup_capture(hci_capture)

        if interrupted or kb.quit_requested:
            warning("Campaign stopped by user.")
        else:
            success("Campaign complete.")

    return campaign


def _record_crash(
    cam: FuzzCampaign,
    crash_type: str,
    protocol: str,
    payload: bytes,
    mutation_log: list[str],
    all_crashes: list[dict],
    crash_counts_by_proto: dict[str, int],
) -> None:
    """Record a crash in both the campaign and our dashboard tracking list."""
    severity = CRASH_SEVERITY.get(crash_type, "MEDIUM")

    # Log to campaign's crash database
    try:
        cam.crash_db.log_crash(
            cam.target,
            protocol,
            payload,
            crash_type,
            severity=severity,
            mutation_log="\n".join(mutation_log),
        )
    except Exception:
        pass

    cam.stats.crashes += 1
    crash_counts_by_proto[protocol] = crash_counts_by_proto.get(protocol, 0) + 1

    # Add to our tracking list for the dashboard
    all_crashes.append({
        "timestamp": datetime.now().isoformat(),
        "protocol": protocol,
        "crash_type": crash_type,
        "severity": severity,
        "payload_hex": payload.hex(),
        "payload_len": len(payload),
        "mutation_log": "\n".join(mutation_log),
    })

    # Cooldown
    if cam.cooldown > 0:
        time.sleep(cam.cooldown)

    # Verify target alive
    if not _check_target_alive(cam.target):
        time.sleep(min(cam.cooldown * 2, 30))
        if not _check_target_alive(cam.target):
            cam._running = False
            return

    # Reconnect transport
    transport = cam._transports.get(protocol)
    if transport is not None:
        try:
            transport.close()
        except Exception:
            pass
        cam.stats.reconnects += 1


def _cleanup_capture(hci_capture) -> None:
    """Stop pcap capture if running."""
    if hci_capture is not None:
        try:
            hci_capture.stop()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# TASK 4.3: Crash Management Commands
# ---------------------------------------------------------------------------

def _crash_commands(fuzz_group):
    """Create and register the crashes subgroup on the fuzz group."""

    @fuzz_group.group("crashes")
    def fuzz_crashes():
        """Manage fuzz crashes -- list, show, replay, export."""

    # ── crashes list ──────────────────────────────────────────────────

    @fuzz_crashes.command("list")
    @click.option("--session", "-s", "session_name", default=None,
                  help="Session name (default: current/latest)")
    @click.option("--protocol", default=None, help="Filter by protocol")
    @click.option("--severity", default=None,
                  type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]))
    def crashes_list(session_name, protocol, severity):
        """List crashes from a fuzzing session.

        \b
        Examples:
          bt-tap fuzz crashes list
          bt-tap fuzz crashes list --protocol sdp
          bt-tap fuzz crashes list --severity CRITICAL
          bt-tap fuzz crashes list -s my_session
        """
        session_dir = _resolve_session_dir(session_name)
        if not session_dir:
            error("No session found. Run a fuzz campaign first.")
            return

        db = _open_crash_db(session_dir)
        if db is None:
            return

        try:
            crashes = db.get_crashes(protocol=protocol, severity=severity)
        finally:
            db.close()

        if not crashes:
            info("No crashes found matching the filter criteria.")
            return

        table = Table(
            title=f"[bold {RED}]Fuzz Crashes ({len(crashes)})[/bold {RED}]",
            show_lines=True,
            border_style=DIM,
            header_style=Style(bold=True, color=RED),
            title_style=Style(bold=True, color=RED),
        )
        table.add_column("ID", style=DIM, width=5, justify="right")
        table.add_column("Timestamp", style=DIM, min_width=20)
        table.add_column("Protocol", style=PURPLE, min_width=12)
        table.add_column("Type", style=f"bold {YELLOW}", min_width=18)
        table.add_column("Severity", min_width=10)
        table.add_column("Payload", min_width=36)
        table.add_column("Repro?", width=6, justify="center")

        sev_styles = {
            "CRITICAL": f"bold {RED}",
            "HIGH": RED,
            "MEDIUM": YELLOW,
            "LOW": GREEN,
            "INFO": DIM,
        }

        for crash in crashes:
            sev = crash.get("severity", "MEDIUM")
            sev_style = sev_styles.get(sev, DIM)
            sev_display = f"[{sev_style}]{sev}[/{sev_style}]"

            # Payload preview: first 16 bytes as hex
            payload_hex = crash.get("payload_hex", "")
            preview = payload_hex[:32]  # 16 bytes = 32 hex chars
            hex_spaced = " ".join(preview[i:i + 2] for i in range(0, len(preview), 2))
            if len(payload_hex) > 32:
                hex_spaced += "..."

            reproduced = crash.get("reproduced", 0)
            repro_str = f"[{GREEN}]yes[/{GREEN}]" if reproduced else f"[{DIM}]no[/{DIM}]"

            table.add_row(
                str(crash.get("id", "?")),
                crash.get("timestamp", ""),
                crash.get("protocol", ""),
                crash.get("crash_type", "unknown"),
                sev_display,
                hex_spaced,
                repro_str,
            )

        console.print(table)

    # ── crashes show ──────────────────────────────────────────────────

    @fuzz_crashes.command("show")
    @click.argument("crash_id", type=int)
    @click.option("--session", "-s", "session_name", default=None,
                  help="Session name (default: current/latest)")
    def crashes_show(crash_id, session_name):
        """Show detailed info for a single crash.

        \b
        Examples:
          bt-tap fuzz crashes show 1
          bt-tap fuzz crashes show 3 -s my_session
        """
        session_dir = _resolve_session_dir(session_name)
        if not session_dir:
            error("No session found.")
            return

        db = _open_crash_db(session_dir)
        if db is None:
            return

        try:
            crash = db.get_crash_by_id(crash_id)
        finally:
            db.close()

        if crash is None:
            error(f"Crash ID {crash_id} not found.")
            return

        # Build a detailed display
        sev = crash.get("severity", "MEDIUM")
        sev_styles = {
            "CRITICAL": f"bold {RED}",
            "HIGH": RED,
            "MEDIUM": YELLOW,
            "LOW": GREEN,
            "INFO": DIM,
        }
        sev_style = sev_styles.get(sev, DIM)

        detail = Text()
        detail.append(f"  Crash ID:      ", style="bold white")
        detail.append(f"{crash_id}\n", style=CYAN)
        detail.append(f"  Timestamp:     ", style="bold white")
        detail.append(f"{crash.get('timestamp', 'N/A')}\n", style=DIM)
        detail.append(f"  Target:        ", style="bold white")
        detail.append(f"{crash.get('target_addr', 'N/A')}\n", style=PURPLE)
        detail.append(f"  Protocol:      ", style="bold white")
        detail.append(f"{crash.get('protocol', 'N/A')}\n", style=CYAN)
        detail.append(f"  Crash Type:    ", style="bold white")
        detail.append(f"{crash.get('crash_type', 'N/A')}\n", style=YELLOW)
        detail.append(f"  Severity:      ", style="bold white")
        detail.append(f"{sev}\n", style=sev_style)
        detail.append(f"  Payload Size:  ", style="bold white")
        detail.append(f"{crash.get('payload_len', 0)} bytes\n", style="white")
        reproduced = crash.get("reproduced", 0)
        repro_label = "Yes" if reproduced else "No"
        repro_color = GREEN if reproduced else DIM
        detail.append(f"  Reproduced:    ", style="bold white")
        detail.append(f"{repro_label}\n", style=repro_color)

        console.print(Panel(
            detail,
            title=f"[bold {RED}]Crash #{crash_id}[/bold {RED}]",
            border_style=RED,
            padding=(1, 2),
        ))

        # Full hex dump
        payload_hex = crash.get("payload_hex", "")
        if payload_hex:
            hex_lines = _format_hex_dump(payload_hex)
            console.print(Panel(
                hex_lines,
                title=f"[bold {ORANGE}]Payload Hex Dump[/bold {ORANGE}]",
                border_style=ORANGE,
                padding=(0, 2),
            ))

        # Mutation log
        mutation_log = crash.get("mutation_log", "")
        if mutation_log:
            console.print(Panel(
                mutation_log,
                title=f"[bold {YELLOW}]Mutation Log[/bold {YELLOW}]",
                border_style=YELLOW,
                padding=(0, 2),
            ))

        # Response
        response_hex = crash.get("response_hex", "")
        if response_hex:
            resp_lines = _format_hex_dump(response_hex)
            console.print(Panel(
                resp_lines,
                title=f"[bold {CYAN}]Response Hex Dump[/bold {CYAN}]",
                border_style=CYAN,
                padding=(0, 2),
            ))

        # Notes
        notes = crash.get("notes", "")
        if notes:
            console.print(Panel(
                notes,
                title=f"[bold {DIM}]Notes[/bold {DIM}]",
                border_style=DIM,
                padding=(0, 2),
            ))

    # ── crashes replay ────────────────────────────────────────────────

    @fuzz_crashes.command("replay")
    @click.argument("crash_id", type=int)
    @click.option("--session", "-s", "session_name", default=None,
                  help="Session name (default: current/latest)")
    @click.option("--capture/--no-capture", default=True,
                  help="Capture pcap during replay (default: on)")
    def crashes_replay(crash_id, session_name, capture):
        """Replay a specific crash to verify reproducibility.

        \b
        Examples:
          bt-tap fuzz crashes replay 1
          bt-tap fuzz crashes replay 3 --no-capture
        """
        session_dir = _resolve_session_dir(session_name)
        if not session_dir:
            error("No session found.")
            return

        from bt_tap.fuzz.crash_db import CrashDB
        db_path = os.path.join(session_dir, "fuzz", "crashes.db")
        if not os.path.exists(db_path):
            error(f"No crash database found at {db_path}")
            return

        db = CrashDB(db_path)
        crash = db.get_crash_by_id(crash_id)
        if crash is None:
            error(f"Crash ID {crash_id} not found.")
            db.close()
            return

        # Show crash details
        section(f"Replay Crash #{crash_id}", style="bt.red")
        info(f"Protocol: [bt.cyan]{crash.get('protocol', '?')}[/bt.cyan]")
        info(f"Type: [bt.yellow]{crash.get('crash_type', '?')}[/bt.yellow]")
        info(f"Severity: [bt.red]{crash.get('severity', '?')}[/bt.red]")
        info(f"Payload: {crash.get('payload_len', 0)} bytes")

        payload_hex = crash.get("payload_hex", "")
        try:
            payload = bytes.fromhex(payload_hex)
        except ValueError:
            error("Corrupt payload hex in crash record.")
            db.close()
            return

        # Show payload preview
        preview = " ".join(payload_hex[i:i + 2] for i in range(0, min(len(payload_hex), 64), 2))
        if len(payload_hex) > 64:
            preview += "..."
        info(f"Payload hex: [bt.orange]{preview}[/bt.orange]")

        # Setup pcap capture
        hci_capture = None
        replay_capture_path = None
        if capture:
            from bt_tap.recon.hci_capture import HCICapture
            fuzz_dir = os.path.join(session_dir, "fuzz")
            os.makedirs(fuzz_dir, exist_ok=True)
            replay_capture_path = os.path.join(fuzz_dir, f"replay_{crash_id}.btsnoop")
            hci_capture = HCICapture()
            if not hci_capture.start(replay_capture_path, pcap=True):
                warning("Pcap capture failed; continuing without capture.")
                hci_capture = None
                replay_capture_path = None

        # Setup transport based on crash protocol
        protocol = crash.get("protocol", "")
        target_addr = crash.get("target_addr", "")
        if not target_addr:
            error("No target address in crash record.")
            _cleanup_capture(hci_capture)
            db.close()
            return

        spec = PROTOCOL_TRANSPORT_MAP.get(protocol)
        if spec is None:
            error(f"Unknown protocol in crash record: {protocol}")
            _cleanup_capture(hci_capture)
            db.close()
            return

        # Create transport
        try:
            from bt_tap.fuzz.transport import L2CAPTransport, RFCOMMTransport, BLETransport
            ttype = spec["type"]
            if ttype == "l2cap":
                transport = L2CAPTransport(target_addr, psm=spec["psm"])
            elif ttype == "rfcomm":
                transport = RFCOMMTransport(target_addr, channel=spec["channel"])
            elif ttype == "ble":
                transport = BLETransport(target_addr, cid=spec["cid"])
            else:
                error(f"Unsupported transport type: {ttype}")
                _cleanup_capture(hci_capture)
                db.close()
                return
        except ImportError:
            # Fall back to stub transport from engine
            from bt_tap.fuzz.engine import _StubTransport
            transport = _StubTransport(
                target_addr,
                transport_type=spec["type"],
                psm=spec.get("psm", 1),
                channel=spec.get("channel", 1),
                cid=spec.get("cid", 4),
            )

        # Replay
        info("Connecting to target...")
        try:
            if not transport.connect():
                error("Failed to connect to target.")
                _cleanup_capture(hci_capture)
                db.close()
                return

            info("Sending crash payload...")
            transport.send(payload)
            info("Waiting for response...")
            response = transport.recv()

            if response is None:
                # Connection closed -- crash reproduced
                success(f"Crash #{crash_id} [bold {GREEN}]REPRODUCED[/bold {GREEN}] -- connection closed by remote")
                db.mark_reproduced(crash_id, True)
            elif response == b"":
                warning(f"Crash #{crash_id} -- response timeout, checking target...")
                if not _check_target_alive(target_addr):
                    success(f"Crash #{crash_id} [bold {GREEN}]REPRODUCED[/bold {GREEN}] -- target unresponsive")
                    db.mark_reproduced(crash_id, True)
                else:
                    info(f"Crash #{crash_id} NOT reproduced -- target still alive")
            else:
                info(f"Crash #{crash_id} NOT reproduced -- got {len(response)} byte response")

        except (ConnectionResetError, BrokenPipeError, ConnectionError):
            success(f"Crash #{crash_id} [bold {GREEN}]REPRODUCED[/bold {GREEN}] -- connection dropped")
            db.mark_reproduced(crash_id, True)
        except OSError as exc:
            if not _check_target_alive(target_addr):
                success(f"Crash #{crash_id} [bold {GREEN}]REPRODUCED[/bold {GREEN}] -- device disappeared")
                db.mark_reproduced(crash_id, True)
            else:
                error(f"OSError during replay: {exc}")
        finally:
            try:
                transport.close()
            except Exception:
                pass
            _cleanup_capture(hci_capture)
            db.close()

        if replay_capture_path and os.path.exists(replay_capture_path):
            info(f"Replay capture saved to: {replay_capture_path}")

    # ── crashes export ────────────────────────────────────────────────

    @fuzz_crashes.command("export")
    @click.option("--session", "-s", "session_name", default=None,
                  help="Session name (default: current/latest)")
    @click.option("--format", "fmt", default="json",
                  type=click.Choice(["json"]))
    @click.option("--output", "-o", default=None,
                  help="Output file path (default: <session>/fuzz/crashes_export.json)")
    def crashes_export(session_name, fmt, output):
        """Export crashes to a JSON file.

        \b
        Examples:
          bt-tap fuzz crashes export
          bt-tap fuzz crashes export -o /tmp/crashes.json
          bt-tap fuzz crashes export -s my_session
        """
        session_dir = _resolve_session_dir(session_name)
        if not session_dir:
            error("No session found.")
            return

        db = _open_crash_db(session_dir)
        if db is None:
            return

        if output is None:
            output = os.path.join(session_dir, "fuzz", "crashes_export.json")

        try:
            db.export_json(output)
            success(f"Crashes exported to: {output}")
            crash_count = db.crash_count()
            info(f"Total crashes exported: {crash_count}")
        except OSError as exc:
            error(f"Export failed: {exc}")
        finally:
            db.close()

    return fuzz_crashes


# ---------------------------------------------------------------------------
# Hex dump helper
# ---------------------------------------------------------------------------

def _format_hex_dump(hex_str: str, bytes_per_line: int = 16) -> str:
    """Format a hex string into a traditional hex dump with ASCII sidebar.

    Produces output like::

        00000000  80 00 1a 10 00 ff ff 46  00 13 79 61 35 f0 ab cd  |.......F..ya5...|
    """
    raw = bytes.fromhex(hex_str) if hex_str else b""
    lines = []
    for offset in range(0, len(raw), bytes_per_line):
        chunk = raw[offset:offset + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Add spacing in the middle
        if len(chunk) > 8:
            hex_part = (
                " ".join(f"{b:02x}" for b in chunk[:8])
                + "  "
                + " ".join(f"{b:02x}" for b in chunk[8:])
            )
        hex_part = hex_part.ljust(3 * bytes_per_line + 1)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part} |{ascii_part}|")
    return "\n".join(lines) if lines else "(empty)"


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_fuzz_commands(fuzz_group) -> None:
    """Register all new fuzz commands onto the existing fuzz Click group.

    Called from ``cli.py`` after the legacy fuzz commands are defined::

        from bt_tap.fuzz.cli_commands import register_fuzz_commands
        register_fuzz_commands(fuzz)
    """
    _campaign_command(fuzz_group)
    _crash_commands(fuzz_group)

    # Register per-protocol commands and corpus management from cli_extra
    try:
        from bt_tap.fuzz.cli_extra import register_extra_commands
        register_extra_commands(fuzz_group)
    except ImportError:
        pass  # cli_extra not yet available
