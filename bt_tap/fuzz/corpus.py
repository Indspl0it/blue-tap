"""Seed corpus management for Bluetooth protocol fuzzing.

Provides persistent storage and retrieval of seed inputs organised by
protocol.  Seeds can be loaded from disk, generated from built-in
templates, or imported from pcap/btsnoop captures.  Interesting inputs
discovered during fuzzing are saved separately for triage.
"""

from __future__ import annotations

import hashlib
import os
import random
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# CorpusStats — summary statistics
# ---------------------------------------------------------------------------

@dataclass
class CorpusStats:
    """Summary statistics for a :class:`Corpus` instance."""

    total_seeds: int = 0
    protocols: list[str] = field(default_factory=list)
    interesting_count: int = 0
    size_bytes: int = 0


# ---------------------------------------------------------------------------
# Corpus — seed corpus manager
# ---------------------------------------------------------------------------

class Corpus:
    """Manage seed inputs on disk, organised by protocol.

    Directory layout::

        base_dir/
          <protocol>/
            <name>.bin            # seed files
            interesting/
              <reason>_<hash>.bin # inputs that triggered new behaviour
    """

    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir
        self.seeds: dict[str, list[bytes]] = {}
        Path(self.base_dir).mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_from_directory(self, path: str) -> int:
        """Load ``.bin`` files from *path* into the corpus.

        Files are expected to be in ``<path>/<protocol>/<name>.bin``
        layout.  Returns the number of seeds loaded.
        """
        loaded = 0
        root = Path(path)
        if not root.is_dir():
            return 0

        for proto_dir in sorted(root.iterdir()):
            if not proto_dir.is_dir():
                continue
            protocol = proto_dir.name
            if protocol == "interesting":
                continue
            for bin_file in sorted(proto_dir.glob("*.bin")):
                try:
                    data = bin_file.read_bytes()
                    if data:
                        self.seeds.setdefault(protocol, []).append(data)
                        loaded += 1
                except OSError:
                    continue
        return loaded

    # ------------------------------------------------------------------
    # Adding seeds
    # ------------------------------------------------------------------

    def add_seed(self, protocol: str, data: bytes, name: str = "") -> None:
        """Add a seed to the corpus and persist it to disk.

        Saved as ``base_dir/<protocol>/<name>.bin``.  If *name* is empty
        a SHA-256 hash of the data is used.
        """
        if not data:
            return

        self.seeds.setdefault(protocol, []).append(data)

        proto_dir = Path(self.base_dir) / protocol
        proto_dir.mkdir(parents=True, exist_ok=True)

        if not name:
            name = hashlib.sha256(data).hexdigest()[:16]
        if not name.endswith(".bin"):
            name += ".bin"

        dest = proto_dir / name
        dest.write_bytes(data)

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get_random_seed(self, protocol: str) -> bytes | None:
        """Return a random seed for *protocol*, or ``None`` if none exist."""
        pool = self.seeds.get(protocol)
        if not pool:
            return None
        return random.choice(pool)

    def get_all_seeds(self, protocol: str) -> list[bytes]:
        """Return all seeds for a given protocol."""
        return list(self.seeds.get(protocol, []))

    # ------------------------------------------------------------------
    # Interesting inputs
    # ------------------------------------------------------------------

    def save_interesting(self, protocol: str, data: bytes, reason: str) -> None:
        """Save an interesting input to ``base_dir/<protocol>/interesting/``.

        The filename encodes the *reason* and a content hash for
        deduplication.
        """
        if not data:
            return

        interesting_dir = Path(self.base_dir) / protocol / "interesting"
        interesting_dir.mkdir(parents=True, exist_ok=True)

        content_hash = hashlib.sha256(data).hexdigest()[:16]
        safe_reason = "".join(c if c.isalnum() or c in "-_" else "_" for c in reason)
        filename = f"{safe_reason}_{content_hash}.bin"

        dest = interesting_dir / filename
        if not dest.exists():
            dest.write_bytes(data)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def seed_count(self, protocol: str | None = None) -> int:
        """Return the number of seeds, optionally filtered by *protocol*."""
        if protocol is not None:
            return len(self.seeds.get(protocol, []))
        return sum(len(v) for v in self.seeds.values())

    def list_protocols(self) -> list[str]:
        """Return protocols that have at least one seed."""
        return sorted(p for p, seeds in self.seeds.items() if seeds)

    def stats(self) -> CorpusStats:
        """Compute summary statistics for the corpus."""
        total = 0
        size = 0
        interesting = 0

        for protocol, seeds in self.seeds.items():
            total += len(seeds)
            size += sum(len(s) for s in seeds)

        # Count interesting files on disk
        base = Path(self.base_dir)
        if base.is_dir():
            for proto_dir in base.iterdir():
                if not proto_dir.is_dir():
                    continue
                int_dir = proto_dir / "interesting"
                if int_dir.is_dir():
                    interesting += sum(1 for f in int_dir.glob("*.bin"))

        return CorpusStats(
            total_seeds=total,
            protocols=self.list_protocols(),
            interesting_count=interesting,
            size_bytes=size,
        )

    # ------------------------------------------------------------------
    # Deduplication
    # ------------------------------------------------------------------

    def minimize(self) -> int:
        """Deduplicate seeds by SHA-256 content hash.

        Returns the number of duplicates removed.
        """
        removed = 0
        for protocol in list(self.seeds):
            seen: set[str] = set()
            unique: list[bytes] = []
            for seed in self.seeds[protocol]:
                h = hashlib.sha256(seed).hexdigest()
                if h not in seen:
                    seen.add(h)
                    unique.append(seed)
                else:
                    removed += 1
            self.seeds[protocol] = unique
        return removed

    # ------------------------------------------------------------------
    # Built-in seed generation
    # ------------------------------------------------------------------

    def generate_builtin_seeds(self, protocol: str) -> list[bytes]:
        """Generate seeds for *protocol* using the real protocol builders.

        Delegates to :func:`generate_full_corpus` which uses the actual
        protocol-aware packet construction libraries from
        ``bt_tap.fuzz.protocols.*``.  This method is a convenience wrapper
        for single-protocol generation.

        Returns:
            List of seed bytes generated and added to the corpus.
        """
        results = generate_full_corpus(self, protocols=[protocol], show_progress=False)
        count = results.get(protocol, 0)
        return self.get_all_seeds(protocol) if count > 0 else []

    # Placeholder seed generators removed — all seed generation now uses
    # the real protocol builders via generate_full_corpus().


# ---------------------------------------------------------------------------
# Full corpus generator using real protocol builders
# ---------------------------------------------------------------------------

# Maps protocol names used in CLI to their generator functions.
# Loaded lazily to avoid circular imports.
_PROTOCOL_GENERATORS: dict[str, tuple[str, str, str | None]] = {
    # (module_path, function_name, argument_or_None)
    "sdp":          ("bt_tap.fuzz.protocols.sdp",         "generate_all_sdp_fuzz_cases",    None),
    "obex-pbap":    ("bt_tap.fuzz.protocols.obex",        "generate_all_obex_fuzz_cases",   "pbap"),
    "obex-map":     ("bt_tap.fuzz.protocols.obex",        "generate_all_obex_fuzz_cases",   "map"),
    "obex-opp":     ("bt_tap.fuzz.protocols.obex",        "generate_all_obex_fuzz_cases",   "opp"),
    "at-hfp":       ("bt_tap.fuzz.protocols.at_commands",  "ATCorpus.generate_hfp_slc_corpus", None),
    "at-phonebook": ("bt_tap.fuzz.protocols.at_commands",  "ATCorpus.generate_phonebook_corpus", None),
    "at-sms":       ("bt_tap.fuzz.protocols.at_commands",  "ATCorpus.generate_sms_corpus",  None),
    "at-injection": ("bt_tap.fuzz.protocols.at_commands",  "ATCorpus.generate_injection_corpus", None),
    "ble-att":      ("bt_tap.fuzz.protocols.att",         "generate_all_att_fuzz_cases",    None),
    "ble-smp":      ("bt_tap.fuzz.protocols.smp",         "generate_all_smp_fuzz_cases",    None),
    "bnep":         ("bt_tap.fuzz.protocols.bnep",        "generate_all_bnep_fuzz_cases",   None),
    "rfcomm":       ("bt_tap.fuzz.protocols.rfcomm",      "generate_all_rfcomm_fuzz_cases", None),
    "l2cap":        ("bt_tap.fuzz.protocols.l2cap",       "generate_all_l2cap_fuzz_cases",  None),
}

# All protocol families (used for "generate all")
ALL_PROTOCOL_FAMILIES = list(_PROTOCOL_GENERATORS.keys())


def _load_generator(module_path: str, func_name: str):
    """Lazily import and return a generator function."""
    import importlib
    mod = importlib.import_module(module_path)
    # Handle ATCorpus.method_name pattern
    if "." in func_name:
        cls_name, method_name = func_name.split(".", 1)
        cls = getattr(mod, cls_name)
        return getattr(cls, method_name)
    return getattr(mod, func_name)


def generate_full_corpus(
    corpus: "Corpus",
    protocols: list[str] | None = None,
    show_progress: bool = True,
) -> dict[str, int]:
    """Generate the complete fuzzing corpus from all protocol builders.

    Automatically invoked before any fuzz command.  Shows a Rich progress
    display so the user can see what's being generated.  Press Ctrl-C to
    skip remaining protocols (seeds already generated are kept).

    Args:
        corpus: The Corpus instance to populate.
        protocols: List of protocol names to generate for, or None for all.
        show_progress: Whether to show Rich progress bar.

    Returns:
        Dict mapping protocol name to number of seeds generated.
    """
    if protocols is None:
        protocols = ALL_PROTOCOL_FAMILIES

    # Skip protocols that already have seeds
    needed = []
    for proto in protocols:
        if corpus.seed_count(proto) > 0:
            continue
        if proto not in _PROTOCOL_GENERATORS:
            continue
        needed.append(proto)

    if not needed:
        return {}  # Already generated

    results: dict[str, int] = {}

    if show_progress:
        try:
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
            from bt_tap.utils.output import console, CYAN, GREEN, YELLOW

            with Progress(
                SpinnerColumn(style=CYAN),
                TextColumn(f"[bold {CYAN}]Generating fuzzing corpus[/bold {CYAN}]"),
                BarColumn(bar_width=30, complete_style=GREEN, finished_style=GREEN),
                MofNCompleteColumn(),
                TextColumn("[bold]{task.fields[current]}[/bold]"),
                console=console,
                transient=False,
            ) as progress:
                task = progress.add_task(
                    "Generating",
                    total=len(needed),
                    current="",
                )
                for proto in needed:
                    progress.update(task, current=proto)
                    try:
                        count = _generate_protocol_seeds(corpus, proto)
                        results[proto] = count
                    except KeyboardInterrupt:
                        progress.update(task, current="[interrupted]")
                        break
                    except Exception as exc:
                        results[proto] = 0
                    progress.advance(task)

                # Final message
                total = sum(results.values())
                progress.update(task, current=f"[{GREEN}]done — {total:,} seeds[/{GREEN}]")

        except ImportError:
            # Rich not available, fall back to silent generation
            for proto in needed:
                try:
                    results[proto] = _generate_protocol_seeds(corpus, proto)
                except KeyboardInterrupt:
                    break
                except Exception:
                    results[proto] = 0
    else:
        for proto in needed:
            try:
                results[proto] = _generate_protocol_seeds(corpus, proto)
            except KeyboardInterrupt:
                break
            except Exception:
                results[proto] = 0

    return results


def _generate_protocol_seeds(corpus: "Corpus", protocol: str) -> int:
    """Generate seeds for a single protocol using its builder."""
    if protocol not in _PROTOCOL_GENERATORS:
        return 0

    module_path, func_name, arg = _PROTOCOL_GENERATORS[protocol]
    gen_func = _load_generator(module_path, func_name)

    if arg is not None:
        cases = gen_func(arg)
    else:
        cases = gen_func()

    # Filter to bytes only (skip list[bytes] multi-step sequences)
    count = 0
    for i, case in enumerate(cases):
        if isinstance(case, bytes) and len(case) > 0:
            corpus.add_seed(protocol, case, name=f"gen_{i:04d}")
            count += 1
        elif isinstance(case, list):
            # Multi-step: store each step separately
            for j, step in enumerate(case):
                if isinstance(step, bytes) and len(step) > 0:
                    corpus.add_seed(protocol, step, name=f"gen_{i:04d}_step{j}")
                    count += 1

    return count
