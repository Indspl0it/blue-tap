import builtins

from blue_tap.attack.avrcp import AVRCPController
from blue_tap.attack.vuln_scanner import scan_vulnerabilities


def test_vulnscan_adapter_not_ready_returns_empty_list_without_crash(monkeypatch) -> None:
    monkeypatch.setattr("blue_tap.utils.bt_helpers.ensure_adapter_ready", lambda _hci: False)
    findings = scan_vulnerabilities("AA:BB:CC:DD:EE:FF", hci="hci999")
    assert findings == []


def test_avrcp_monitor_metadata_handles_missing_dbus(monkeypatch) -> None:
    controller = AVRCPController("AA:BB:CC:DD:EE:FF")

    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith("dbus") or name.startswith("gi"):
            raise ImportError("simulated missing dependency")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    # Should return cleanly without raising NameError / ImportError.
    controller.monitor_metadata(duration=1)
