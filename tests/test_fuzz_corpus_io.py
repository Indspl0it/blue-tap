"""Corpus tarball export / import — unit + CLI coverage.

Covers:

* ``Corpus.export_to_tarball()`` round-trips the on-disk layout into a
  gzipped tarball whose SHA-256 content set matches the source.
* ``Corpus.import_from_tarball()`` is **idempotent**: importing the same
  tarball twice produces the same seed set on the second pass.
* The CLI subcommands ``fuzz corpus export`` / ``fuzz corpus import``
  surface non-zero exit codes on bad inputs and write per-operation
  envelopes to the active session.
"""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from blue_tap.interfaces.cli.main import cli
from blue_tap.modules.fuzzing.corpus import Corpus


def _populate_corpus(base: Path) -> Corpus:
    """Build a small two-protocol corpus on disk and return a loaded Corpus."""
    corpus = Corpus(str(base))
    corpus.add_seed("sdp", b"\x00\x01seed-A", name="a")
    corpus.add_seed("sdp", b"\x00\x02seed-B", name="b")
    corpus.add_seed("rfcomm", b"\xffrfcomm-seed", name="r")
    corpus.save_interesting("sdp", b"\xffcrash-data", reason="crash")
    return corpus


def _hashes_under(directory: Path) -> set[str]:
    """SHA-256 of every ``*.bin`` (regardless of subdir) under ``directory``."""
    out: set[str] = set()
    for f in directory.rglob("*.bin"):
        try:
            out.add(hashlib.sha256(f.read_bytes()).hexdigest())
        except OSError:
            continue
    return out


# ── Unit tests on Corpus methods ─────────────────────────────────────────


def test_export_round_trips_all_protocols(tmp_path: Path):
    src = tmp_path / "src_corpus"
    corpus = _populate_corpus(src)

    tarball = tmp_path / "out.tar.gz"
    summary = corpus.export_to_tarball(str(tarball))

    assert tarball.is_file(), "Tarball was not produced"
    assert summary["seeds_exported"] >= 3, summary
    assert "sdp" in summary["protocols"]
    assert "rfcomm" in summary["protocols"]

    # The tarball's seed contents (by SHA-256) must equal the source's.
    src_hashes = _hashes_under(src)
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    with tarfile.open(tarball, "r:gz") as tar:
        tar.extractall(extracted, filter="data")
    assert _hashes_under(extracted) == src_hashes, "Tarball content drift"


def test_export_single_protocol_excludes_others(tmp_path: Path):
    src = tmp_path / "src_corpus"
    _populate_corpus(src)
    corpus = Corpus(str(src))
    corpus.load_from_directory(str(src))

    tarball = tmp_path / "sdp_only.tar.gz"
    summary = corpus.export_to_tarball(str(tarball), protocol="sdp")

    assert summary["protocols"] == ["sdp"]
    with tarfile.open(tarball, "r:gz") as tar:
        names = tar.getnames()
    assert any(n.startswith("sdp") for n in names)
    assert not any(n.startswith("rfcomm") for n in names), (
        f"rfcomm leaked into single-protocol export: {names}"
    )


def test_export_unknown_protocol_raises(tmp_path: Path):
    src = tmp_path / "src_corpus"
    _populate_corpus(src)
    corpus = Corpus(str(src))

    with pytest.raises(ValueError, match="No corpus directory"):
        corpus.export_to_tarball(
            str(tmp_path / "nope.tar.gz"), protocol="does_not_exist"
        )


def test_export_missing_base_dir_raises(tmp_path: Path):
    # base_dir is created on Corpus.__init__, so we have to remove it after.
    base = tmp_path / "ghost"
    corpus = Corpus(str(base))
    base.rmdir()  # force missing
    with pytest.raises(FileNotFoundError):
        corpus.export_to_tarball(str(tmp_path / "x.tar.gz"))


def test_import_round_trips_seed_hashes(tmp_path: Path):
    src = tmp_path / "src"
    src_corpus = _populate_corpus(src)
    tarball = tmp_path / "bundle.tar.gz"
    src_corpus.export_to_tarball(str(tarball))

    dst = tmp_path / "dst"
    dst_corpus = Corpus(str(dst))
    summary = dst_corpus.import_from_tarball(str(tarball))

    assert summary["seeds_imported"] >= 3
    assert summary["duplicates_skipped"] == 0
    assert "sdp" in summary["protocols"]

    # Hashes on disk must match the source (regular seed dirs only — interesting
    # files are renamed by save_interesting so direct hash compare is safe).
    src_seed_hashes = _hashes_under(src / "sdp") | _hashes_under(src / "rfcomm")
    dst_seed_hashes = _hashes_under(dst / "sdp") | _hashes_under(dst / "rfcomm")
    assert src_seed_hashes <= dst_seed_hashes, (
        f"Imported seeds missing source content. "
        f"missing={src_seed_hashes - dst_seed_hashes}"
    )


def test_import_is_idempotent(tmp_path: Path):
    src = tmp_path / "src"
    src_corpus = _populate_corpus(src)
    tarball = tmp_path / "bundle.tar.gz"
    src_corpus.export_to_tarball(str(tarball))

    dst = tmp_path / "dst"
    dst_corpus = Corpus(str(dst))

    first = dst_corpus.import_from_tarball(str(tarball))
    second = dst_corpus.import_from_tarball(str(tarball))

    assert first["seeds_imported"] >= 1
    assert second["seeds_imported"] == 0, (
        f"Re-import was not idempotent: {second}"
    )
    assert second["duplicates_skipped"] >= first["seeds_imported"]


def test_import_missing_tarball_raises(tmp_path: Path):
    corpus = Corpus(str(tmp_path / "dst"))
    with pytest.raises(FileNotFoundError):
        corpus.import_from_tarball(str(tmp_path / "ghost.tar.gz"))


def test_import_rejects_path_traversal(tmp_path: Path):
    """A malicious archive with ``../`` in member names must not write outside."""
    # Build a tarball that tries to escape via ../
    evil = tmp_path / "evil.tar.gz"
    payload_dir = tmp_path / "payload"
    payload_dir.mkdir()
    safe_seed = payload_dir / "sdp" / "ok.bin"
    safe_seed.parent.mkdir(parents=True)
    safe_seed.write_bytes(b"safe")
    with tarfile.open(evil, "w:gz") as tar:
        tar.add(str(safe_seed), arcname="sdp/ok.bin")
        # Construct an absolute-path entry by hand
        info = tarfile.TarInfo(name="../evil_outside.bin")
        info.size = 4
        import io
        tar.addfile(info, io.BytesIO(b"BAD!"))

    dst = tmp_path / "dst"
    corpus = Corpus(str(dst))
    summary = corpus.import_from_tarball(str(evil))

    # The safe seed lands; the traversal entry must be silently dropped.
    assert summary["seeds_imported"] == 1
    assert not (tmp_path / "evil_outside.bin").exists(), \
        "Path-traversal protection failed — file escaped tmp dir"


# ── CLI surface ──────────────────────────────────────────────────────────


def _make_runner(tmp_path: Path) -> CliRunner:
    return CliRunner(env={"BT_TAP_SESSIONS_DIR": str(tmp_path)})


def test_cli_export_then_import_round_trip(tmp_path: Path):
    """``fuzz corpus export`` → ``fuzz corpus import`` round-trips end-to-end."""
    runner = _make_runner(tmp_path)

    # Seed a corpus directly on disk so we don't need a real fuzzing run.
    session_dir = tmp_path / "sessions" / "src_session"
    corpus_dir = session_dir / "fuzz" / "corpus"
    corpus_dir.mkdir(parents=True)
    src = Corpus(str(corpus_dir))
    src.add_seed("sdp", b"corpus-cli-seed-1", name="one")
    src.add_seed("sdp", b"corpus-cli-seed-2", name="two")

    # Also create the session.json so the session loader is happy.
    (session_dir / "session.json").write_text(json.dumps({
        "name": "src_session",
        "created": "2026-05-01T00:00:00+00:00",
        "last_updated": "2026-05-01T00:00:00+00:00",
        "commands": [],
        "targets": [],
        "categories": [],
        "files": 0,
        "directory": str(session_dir),
        "metadata": {},
    }))

    tarball = tmp_path / "bundle.tar.gz"
    r1 = runner.invoke(
        cli,
        [
            "-s", "src_session",
            "fuzz", "corpus", "export",
            "-s", "src_session",
            "-o", str(tarball),
        ],
        catch_exceptions=False,
    )
    assert r1.exit_code == 0, f"export failed:\n{r1.output}"
    assert tarball.is_file(), "Tarball not written"

    # Import into a fresh session.
    r2 = runner.invoke(
        cli,
        [
            "-s", "dst_session",
            "fuzz", "corpus", "import",
            str(tarball),
            "-s", "dst_session",
        ],
        catch_exceptions=False,
    )
    assert r2.exit_code == 0, f"import failed:\n{r2.output}"
    assert "Imported" in r2.output

    dst_corpus_dir = tmp_path / "sessions" / "dst_session" / "fuzz" / "corpus"
    dst = Corpus(str(dst_corpus_dir))
    loaded = dst.load_from_directory(str(dst_corpus_dir))
    assert loaded == 2, f"Expected 2 seeds in dst corpus, got {loaded}"


def test_cli_export_missing_corpus_exits_nonzero(tmp_path: Path):
    runner = _make_runner(tmp_path)
    r = runner.invoke(
        cli,
        [
            "-s", "ghost",
            "fuzz", "corpus", "export",
            "-s", "nonexistent_session",
            "-o", str(tmp_path / "out.tar.gz"),
        ],
        catch_exceptions=False,
    )
    assert r.exit_code != 0
    assert "No corpus found" in r.output


def test_cli_import_missing_tarball_exits_nonzero(tmp_path: Path):
    runner = _make_runner(tmp_path)
    r = runner.invoke(
        cli,
        [
            "-s", "dst",
            "fuzz", "corpus", "import",
            str(tmp_path / "does_not_exist.tar.gz"),
        ],
        catch_exceptions=False,
    )
    # Click's exists=True triggers the error before our handler runs.
    assert r.exit_code != 0
    assert "does_not_exist" in r.output or "Invalid value" in r.output
