from __future__ import annotations

from blue_tap.cli import _command_needs_darkfirmware_bootstrap


def test_darkfirmware_bootstrap_skips_scan_and_doctor_commands():
    assert _command_needs_darkfirmware_bootstrap("scan", ["scan", "ble", "-i", "hci1"]) is False
    assert _command_needs_darkfirmware_bootstrap("doctor", ["doctor", "profiles"]) is False


def test_darkfirmware_bootstrap_keeps_vulnscan_and_lmp_recon():
    assert _command_needs_darkfirmware_bootstrap("vulnscan", ["vulnscan", "AA:BB:CC:DD:EE:FF"]) is True
    assert _command_needs_darkfirmware_bootstrap("recon", ["recon", "lmp-monitor", "AA:BB:CC:DD:EE:FF"]) is True


def test_darkfirmware_bootstrap_limits_fuzz_to_below_stack_protocols():
    assert _command_needs_darkfirmware_bootstrap("fuzz", ["fuzz", "l2cap-sig", "AA:BB:CC:DD:EE:FF"]) is True
    assert _command_needs_darkfirmware_bootstrap("fuzz", ["fuzz", "ble-att", "AA:BB:CC:DD:EE:FF"]) is False
