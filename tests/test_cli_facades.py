"""Tests for CLI facade commands — help text, sub-command registration, and arg validation."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

from blue_tap.interfaces.cli.main import cli


@pytest.fixture
def runner():
    return CliRunner()


# ── discover ─────────────────────────────────────────────────────────────────


def test_discover_help(runner):
    result = runner.invoke(cli, ["discover", "--help"])
    assert result.exit_code == 0
    assert "Find nearby Bluetooth targets" in result.output


def test_discover_subcommands_registered(runner):
    result = runner.invoke(cli, ["discover", "--help"])
    for sub in ("classic", "ble", "all"):
        assert sub in result.output


def test_discover_classic_help(runner):
    result = runner.invoke(cli, ["discover", "classic", "--help"])
    assert result.exit_code == 0
    assert "--duration" in result.output
    assert "--hci" in result.output


def test_discover_ble_help(runner):
    result = runner.invoke(cli, ["discover", "ble", "--help"])
    assert result.exit_code == 0
    assert "--passive" in result.output


def test_discover_all_help(runner):
    result = runner.invoke(cli, ["discover", "all", "--help"])
    assert result.exit_code == 0
    assert "--duration" in result.output


# ── recon ────────────────────────────────────────────────────────────────────


def test_recon_help(runner):
    result = runner.invoke(cli, ["recon", "--help"])
    assert result.exit_code == 0
    assert "Enumerate services and fingerprint a target" in result.output


def test_recon_subcommands_registered(runner):
    result = runner.invoke(cli, ["recon", "--help"])
    for sub in ("sdp", "gatt", "l2cap", "rfcomm", "fingerprint", "capture", "sniff"):
        assert sub in result.output


def test_recon_requires_target(runner):
    result = runner.invoke(cli, ["recon", "sdp"])
    # "sdp" is interpreted as TARGET, so it asks for a sub-command
    assert result.exit_code != 0


def test_recon_sdp_help(runner):
    result = runner.invoke(cli, ["recon", "AA:BB:CC:DD:EE:FF", "sdp", "--help"])
    assert result.exit_code == 0
    assert "--retries" in result.output


def test_recon_sniff_help(runner):
    result = runner.invoke(cli, ["recon", "AA:BB:CC:DD:EE:FF", "sniff", "--help"])
    assert result.exit_code == 0
    assert "--mode" in result.output
    assert "--duration" in result.output


# ── vulnscan ─────────────────────────────────────────────────────────────────


def test_vulnscan_help(runner):
    result = runner.invoke(cli, ["vulnscan", "--help"])
    assert result.exit_code == 0
    assert "Scan target for vulnerabilities" in result.output


def test_vulnscan_accepts_options(runner):
    result = runner.invoke(cli, ["vulnscan", "--help"])
    assert "--cve" in result.output
    assert "--active" in result.output
    assert "--no-active" in result.output
    assert "--phone" in result.output


def test_vulnscan_interactive_picker_when_no_target(runner):
    """Without a target, vulnscan launches the interactive device picker."""
    result = runner.invoke(cli, ["vulnscan"])
    assert "Select target" in result.output or "Device Discovery" in result.output


# ── exploit ──────────────────────────────────────────────────────────────────


def test_exploit_help(runner):
    result = runner.invoke(cli, ["exploit", "--help"])
    assert result.exit_code == 0
    assert "Run exploits against a target" in result.output


def test_exploit_subcommands_registered(runner):
    result = runner.invoke(cli, ["exploit", "--help"])
    for sub in ("knob", "bias", "bluffs", "ctkd", "enc-downgrade",
                "ssp-downgrade", "hijack", "pin-brute"):
        assert sub in result.output


def test_exploit_knob_help(runner):
    result = runner.invoke(cli, ["exploit", "AA:BB:CC:DD:EE:FF", "knob", "--help"])
    assert result.exit_code == 0
    assert "--key-size" in result.output


def test_exploit_bluffs_help(runner):
    result = runner.invoke(cli, ["exploit", "AA:BB:CC:DD:EE:FF", "bluffs", "--help"])
    assert result.exit_code == 0
    assert "--variant" in result.output


def test_exploit_requires_target(runner):
    result = runner.invoke(cli, ["exploit", "knob"])
    # "knob" is consumed as TARGET, then no sub-command
    assert result.exit_code != 0


# ── dos ──────────────────────────────────────────────────────────────────────


def test_dos_help(runner):
    result = runner.invoke(cli, ["dos", "--help"])
    assert result.exit_code == 0
    assert "Denial-of-service" in result.output


def test_dos_accepts_options(runner):
    result = runner.invoke(cli, ["dos", "--help"])
    assert "--checks" in result.output
    assert "--recovery-timeout" in result.output


def test_dos_interactive_picker_when_no_target(runner):
    """Without a target, dos launches the interactive device picker."""
    result = runner.invoke(cli, ["dos"])
    assert "Select target" in result.output or "Device Discovery" in result.output


# ── extract ──────────────────────────────────────────────────────────────────


def test_extract_help(runner):
    result = runner.invoke(cli, ["extract", "--help"])
    assert result.exit_code == 0
    assert "Pull data from a target device" in result.output


def test_extract_subcommands_registered(runner):
    result = runner.invoke(cli, ["extract", "--help"])
    for sub in ("contacts", "messages", "audio", "media", "push", "snarf", "at"):
        assert sub in result.output


def test_extract_contacts_help(runner):
    result = runner.invoke(cli, ["extract", "AA:BB:CC:DD:EE:FF", "contacts", "--help"])
    assert result.exit_code == 0
    assert "--phonebook" in result.output


def test_extract_audio_help(runner):
    result = runner.invoke(cli, ["extract", "AA:BB:CC:DD:EE:FF", "audio", "--help"])
    assert result.exit_code == 0
    assert "--action" in result.output
    assert "--number" in result.output


def test_extract_requires_target(runner):
    result = runner.invoke(cli, ["extract", "contacts"])
    # "contacts" consumed as TARGET, no sub-command
    assert result.exit_code != 0


# ── fuzz ─────────────────────────────────────────────────────────────────────


def test_fuzz_help(runner):
    result = runner.invoke(cli, ["fuzz", "--help"])
    assert result.exit_code == 0
    assert "Protocol-level fuzzing" in result.output


def test_fuzz_campaign_registered(runner):
    result = runner.invoke(cli, ["fuzz", "--help"])
    assert "campaign" in result.output


def test_fuzz_crashes_registered(runner):
    result = runner.invoke(cli, ["fuzz", "--help"])
    assert "crashes" in result.output


def test_fuzz_corpus_registered(runner):
    result = runner.invoke(cli, ["fuzz", "--help"])
    assert "corpus" in result.output


def test_fuzz_protocol_commands_registered(runner):
    result = runner.invoke(cli, ["fuzz", "--help"])
    for proto in ("sdp-deep", "l2cap-sig", "rfcomm-raw", "ble-att", "ble-smp",
                  "bnep", "obex", "at-deep"):
        assert proto in result.output, f"missing fuzz sub-command: {proto}"


def test_fuzz_analysis_commands_registered(runner):
    result = runner.invoke(cli, ["fuzz", "--help"])
    for cmd in ("cve", "replay", "minimize"):
        assert cmd in result.output, f"missing fuzz sub-command: {cmd}"


# ── auto ─────────────────────────────────────────────────────────────────────


def test_auto_help(runner):
    result = runner.invoke(cli, ["auto", "--help"])
    assert result.exit_code == 0
    assert "Four-phase assessment shortcut" in result.output


def test_auto_accepts_options(runner):
    result = runner.invoke(cli, ["auto", "--help"])
    assert "--skip" in result.output
    assert "--yes" in result.output


def test_auto_requires_target(runner):
    """auto runs non-interactively and requires a target address."""
    result = runner.invoke(cli, ["auto"])
    assert result.exit_code != 0


# ── fleet ────────────────────────────────────────────────────────────────────


def test_fleet_help(runner):
    result = runner.invoke(cli, ["fleet", "--help"])
    assert result.exit_code == 0
    assert "Scan, classify, and assess" in result.output


def test_fleet_accepts_options(runner):
    result = runner.invoke(cli, ["fleet", "--help"])
    assert "--duration" in result.output
    assert "--class" in result.output


# ── doctor ───────────────────────────────────────────────────────────────────


def test_doctor_help(runner):
    result = runner.invoke(cli, ["doctor", "--help"])
    assert result.exit_code == 0
    assert "Check host environment readiness" in result.output


def test_doctor_runs_without_crash(runner):
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0
    assert "Environment Diagnostics" in result.output


# ── spoof ────────────────────────────────────────────────────────────────────


def test_spoof_help(runner):
    result = runner.invoke(cli, ["spoof", "--help"])
    assert result.exit_code == 0
    assert "Spoof the local adapter" in result.output


def test_spoof_accepts_options(runner):
    result = runner.invoke(cli, ["spoof", "--help"])
    assert "NEW_MAC" in result.output
    assert "--method" in result.output


def test_spoof_requires_mac(runner):
    result = runner.invoke(cli, ["spoof"])
    assert result.exit_code != 0
