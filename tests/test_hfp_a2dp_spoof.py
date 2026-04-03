"""Comprehensive tests for HFP, A2DP, spoofer, and session modules.

Covers:
  - HFPClient indicator parsing and defaults
  - A2DP PulseAudio device naming and detection helpers
  - Spoofer MAC persistence and clone_device_identity
  - Session creation, logging, data collection, summary, and safety
"""

import json
import os
import subprocess
from unittest.mock import patch

import pytest

from blue_tap.attack.hfp import HFPClient
from blue_tap.attack.a2dp import (
    mac_to_pa_id,
    bt_source_name,
    bt_a2dp_source_name,
    bt_sink_name,
    bt_card_name,
    _detect_source_rate,
    list_bt_audio_sources,
    list_bt_audio_sinks,
)
from blue_tap.utils.session import Session


# ============================================================================
# HFP Tests
# ============================================================================


class TestHFPClientInit:
    """Verify HFPClient defaults without connecting."""

    def test_default_audio_rate(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=1)
        assert client.audio_rate == 8000

    def test_default_audio_codec(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=1)
        assert client.audio_codec == "CVSD"

    def test_address_stored(self):
        client = HFPClient("11:22:33:44:55:66", channel=5)
        assert client.address == "11:22:33:44:55:66"
        assert client.channel == 5

    def test_initial_state(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=1)
        assert client.rfcomm_sock is None
        assert client.sco_sock is None
        assert client.indicators == {}
        assert client.indicator_values == {}
        assert client.slc_established is False
        assert client.ag_features == 0


class TestParseIndicatorMapping:
    """Test _parse_indicator_mapping with various +CIND=? responses."""

    def test_normal_response(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=1)
        response = '+CIND: ("service",(0,1)),("call",(0,1)),("signal",(0-5))'
        client._parse_indicator_mapping(response)
        assert client.indicators == {"service": 0, "call": 1, "signal": 2}

    def test_hyphenated_indicator_names(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=1)
        response = '+CIND: ("battery-level",(0-5)),("roam",(0,1))'
        client._parse_indicator_mapping(response)
        assert client.indicators == {"battery-level": 0, "roam": 1}

    def test_empty_response_yields_empty_dict(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=1)
        client._parse_indicator_mapping("")
        assert client.indicators == {}

    def test_no_indicators_found(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=1)
        client._parse_indicator_mapping("+CIND: OK")
        assert client.indicators == {}

    def test_full_realistic_response(self):
        """Real-world AG response with 7 indicators."""
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=1)
        response = (
            '+CIND: ("service",(0,1)),("call",(0,1)),("callsetup",(0-3)),'
            '("callheld",(0-2)),("signal",(0-5)),("roam",(0,1)),'
            '("battchg",(0-5))'
        )
        client._parse_indicator_mapping(response)
        assert len(client.indicators) == 7
        assert client.indicators["service"] == 0
        assert client.indicators["battchg"] == 6

    def test_does_not_crash_on_garbage(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=1)
        client._parse_indicator_mapping("\xff\xfe garbage data")
        assert client.indicators == {}


class TestParseIndicatorValues:
    """Test _parse_indicator_values with various +CIND? responses."""

    def _make_client_with_indicators(self):
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=1)
        client.indicators = {"service": 0, "call": 1, "signal": 2, "roam": 3}
        return client

    def test_normal_response(self):
        client = self._make_client_with_indicators()
        client._parse_indicator_values("+CIND: 1,0,5,0")
        assert client.indicator_values == {
            "service": 1, "call": 0, "signal": 5, "roam": 0,
        }

    def test_more_values_than_indicators(self):
        """Extra values beyond known indicators are silently dropped."""
        client = self._make_client_with_indicators()
        client._parse_indicator_values("+CIND: 1,0,5,0,4,7")
        # Only 4 indicators defined, extra values ignored
        assert len(client.indicator_values) == 4
        assert client.indicator_values["service"] == 1

    def test_fewer_values_than_indicators(self):
        """Fewer values than indicators: partial map."""
        client = self._make_client_with_indicators()
        client._parse_indicator_values("+CIND: 1,0")
        assert client.indicator_values == {"service": 1, "call": 0}

    def test_malformed_no_colon(self):
        """Malformed response without colon does not crash."""
        client = self._make_client_with_indicators()
        client._parse_indicator_values("CIND 1,0,5")
        # Split on ":" with index [1] will get " 1,0,5" from "CIND 1,0,5"
        # Actually "CIND 1,0,5".split(":") = ["CIND 1,0,5"] -> IndexError
        # The method catches IndexError and returns
        assert client.indicator_values == {}

    def test_empty_response(self):
        client = self._make_client_with_indicators()
        client._parse_indicator_values("")
        assert client.indicator_values == {}

    def test_no_indicators_defined(self):
        """Values parsed with no indicator names -> empty map."""
        client = HFPClient("AA:BB:CC:DD:EE:FF", channel=1)
        client.indicators = {}
        client._parse_indicator_values("+CIND: 1,0,5")
        assert client.indicator_values == {}


# ============================================================================
# A2DP Tests
# ============================================================================


class TestMacToPaId:
    def test_standard_mac(self):
        assert mac_to_pa_id("AA:BB:CC:DD:EE:FF") == "AA_BB_CC_DD_EE_FF"

    def test_lowercase_mac(self):
        assert mac_to_pa_id("aa:bb:cc:dd:ee:ff") == "aa_bb_cc_dd_ee_ff"

    def test_no_colons(self):
        assert mac_to_pa_id("AABBCCDDEEFF") == "AABBCCDDEEFF"


class TestBtDeviceNames:
    MAC = "AA:BB:CC:DD:EE:FF"
    PA_ID = "AA_BB_CC_DD_EE_FF"

    def test_bt_source_name(self):
        assert bt_source_name(self.MAC) == f"bluez_input.{self.PA_ID}.0"

    def test_bt_a2dp_source_name(self):
        assert bt_a2dp_source_name(self.MAC) == f"bluez_source.{self.PA_ID}.a2dp_sink"

    def test_bt_sink_name(self):
        assert bt_sink_name(self.MAC) == f"bluez_output.{self.PA_ID}.1"

    def test_bt_card_name(self):
        assert bt_card_name(self.MAC) == f"bluez_card.{self.PA_ID}"


def _make_run_cmd_result(returncode=0, stdout="", stderr=""):
    """Create a mock subprocess.CompletedProcess."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


class TestDetectSourceRate:
    """Test _detect_source_rate with mocked run_cmd."""

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_detects_48000(self, mock_run_cmd):
        mock_run_cmd.return_value = _make_run_cmd_result(
            stdout=(
                "Source #42\n"
                "\tName: bluez_source.AA_BB_CC_DD_EE_FF.a2dp_sink\n"
                "\tSample Specification: s16le 2ch 48000Hz\n"
                "\tVolume: 100%\n"
            ),
        )
        rate = _detect_source_rate("bluez_source.AA_BB_CC_DD_EE_FF.a2dp_sink")
        assert rate == 48000

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_detects_44100(self, mock_run_cmd):
        mock_run_cmd.return_value = _make_run_cmd_result(
            stdout=(
                "Source #1\n"
                "\tName: bluez_source.AA_BB_CC_DD_EE_FF.a2dp_sink\n"
                "\tSample Specification: s16le 2ch 44100Hz\n"
            ),
        )
        rate = _detect_source_rate("bluez_source.AA_BB_CC_DD_EE_FF.a2dp_sink")
        assert rate == 44100

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_failure_returns_default(self, mock_run_cmd):
        mock_run_cmd.return_value = _make_run_cmd_result(returncode=1)
        rate = _detect_source_rate("bluez_source.XX_XX_XX_XX_XX_XX.a2dp_sink")
        assert rate == 44100

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_source_not_found_returns_default(self, mock_run_cmd):
        mock_run_cmd.return_value = _make_run_cmd_result(
            stdout=(
                "Source #1\n"
                "\tName: alsa_input.analog-stereo\n"
                "\tSample Specification: s16le 2ch 44100Hz\n"
            ),
        )
        rate = _detect_source_rate("bluez_source.MISSING.a2dp_sink")
        assert rate == 44100

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_no_sample_spec_line(self, mock_run_cmd):
        """Source found but no Sample Specification line before blank line."""
        mock_run_cmd.return_value = _make_run_cmd_result(
            stdout=(
                "Source #1\n"
                "\tName: bluez_source.AA_BB_CC_DD_EE_FF.a2dp_sink\n"
                "\n"
                "\tSample Specification: s16le 2ch 96000Hz\n"
            ),
        )
        # Blank line ends the target block before Sample Specification
        rate = _detect_source_rate("bluez_source.AA_BB_CC_DD_EE_FF.a2dp_sink")
        assert rate == 44100


class TestListBtAudioSources:
    """Test list_bt_audio_sources with mocked run_cmd."""

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_normal_output(self, mock_run_cmd):
        mock_run_cmd.return_value = _make_run_cmd_result(
            stdout=(
                "42\tbluez_input.AA_BB_CC_DD_EE_FF.0\tmodule-bluez5-device.c\ts16le 1ch 16000Hz\tRUNNING\n"
                "43\tbluez_source.AA_BB_CC_DD_EE_FF.a2dp_sink\tmodule-bluez5-device.c\ts16le 2ch 44100Hz\tIDLE\n"
            ),
        )
        sources = list_bt_audio_sources()
        assert len(sources) == 2
        assert sources[0]["id"] == "42"
        assert sources[0]["name"] == "bluez_input.AA_BB_CC_DD_EE_FF.0"
        assert sources[0]["driver"] == "module-bluez5-device.c"
        assert sources[0]["state"] == "RUNNING"
        assert sources[1]["state"] == "IDLE"

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_malformed_line_skipped(self, mock_run_cmd):
        """Lines with fewer than 5 tab-separated columns are skipped."""
        mock_run_cmd.return_value = _make_run_cmd_result(
            stdout=(
                "42\tbluez_input.AA_BB_CC_DD_EE_FF.0\n"
                "43\tbluez_source.AA_BB_CC_DD_EE_FF.a2dp_sink\tmodule-bluez5-device.c\ts16le 2ch 44100Hz\tIDLE\n"
            ),
        )
        sources = list_bt_audio_sources()
        assert len(sources) == 1
        assert sources[0]["id"] == "43"

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_no_bluez_lines(self, mock_run_cmd):
        mock_run_cmd.return_value = _make_run_cmd_result(
            stdout="1\talsa_input.analog-stereo\tmodule-alsa-card.c\ts16le 2ch 44100Hz\tRUNNING\n",
        )
        sources = list_bt_audio_sources()
        assert sources == []

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_command_failure(self, mock_run_cmd):
        mock_run_cmd.return_value = _make_run_cmd_result(returncode=1)
        sources = list_bt_audio_sources()
        assert sources == []


class TestListBtAudioSinks:
    """Test list_bt_audio_sinks with mocked run_cmd."""

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_normal_output(self, mock_run_cmd):
        mock_run_cmd.return_value = _make_run_cmd_result(
            stdout="10\tbluez_output.AA_BB_CC_DD_EE_FF.1\tmodule-bluez5-device.c\ts16le 2ch 44100Hz\tRUNNING\n",
        )
        sinks = list_bt_audio_sinks()
        assert len(sinks) == 1
        assert sinks[0]["id"] == "10"
        assert sinks[0]["name"] == "bluez_output.AA_BB_CC_DD_EE_FF.1"
        assert sinks[0]["driver"] == "module-bluez5-device.c"

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_malformed_line_skipped(self, mock_run_cmd):
        """Lines with fewer than 3 tab-separated columns are skipped."""
        mock_run_cmd.return_value = _make_run_cmd_result(
            stdout=(
                "10\tbluez_output.AA_BB_CC_DD_EE_FF.1\n"
                "11\tbluez_output.BB_CC_DD_EE_FF_AA.1\tmodule-bluez5-device.c\n"
            ),
        )
        sinks = list_bt_audio_sinks()
        assert len(sinks) == 1
        assert sinks[0]["id"] == "11"

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_no_bluez_lines(self, mock_run_cmd):
        mock_run_cmd.return_value = _make_run_cmd_result(
            stdout="1\talsa_output.analog-stereo\tmodule-alsa-card.c\n",
        )
        sinks = list_bt_audio_sinks()
        assert sinks == []

    @patch("blue_tap.attack.a2dp.run_cmd")
    def test_command_failure(self, mock_run_cmd):
        mock_run_cmd.return_value = _make_run_cmd_result(returncode=1)
        sinks = list_bt_audio_sinks()
        assert sinks == []


# ============================================================================
# Spoofer Tests
# ============================================================================


class TestSaveAndGetOriginalMac:
    """Test save_original_mac / get_original_mac with temp files."""

    def test_save_and_retrieve(self, tmp_path, monkeypatch):
        mac_file = str(tmp_path / "original_mac.json")
        monkeypatch.setattr("blue_tap.core.spoofer._ORIGINAL_MAC_FILE", mac_file)
        monkeypatch.setattr(
            "blue_tap.core.spoofer.get_adapter_address",
            lambda hci: "AA:BB:CC:DD:EE:FF",
        )

        from blue_tap.core.spoofer import save_original_mac, get_original_mac

        save_original_mac("hci0")
        assert get_original_mac("hci0") == "AA:BB:CC:DD:EE:FF"

    def test_different_adapters(self, tmp_path, monkeypatch):
        mac_file = str(tmp_path / "original_mac.json")
        monkeypatch.setattr("blue_tap.core.spoofer._ORIGINAL_MAC_FILE", mac_file)

        from blue_tap.core.spoofer import save_original_mac, get_original_mac

        # Save hci0
        monkeypatch.setattr(
            "blue_tap.core.spoofer.get_adapter_address",
            lambda hci: "AA:BB:CC:DD:EE:FF",
        )
        save_original_mac("hci0")

        # Save hci1 with different MAC
        monkeypatch.setattr(
            "blue_tap.core.spoofer.get_adapter_address",
            lambda hci: "11:22:33:44:55:66",
        )
        save_original_mac("hci1")

        assert get_original_mac("hci0") == "AA:BB:CC:DD:EE:FF"
        assert get_original_mac("hci1") == "11:22:33:44:55:66"

    def test_idempotent_save(self, tmp_path, monkeypatch):
        """Saving the same adapter twice does not overwrite."""
        mac_file = str(tmp_path / "original_mac.json")
        monkeypatch.setattr("blue_tap.core.spoofer._ORIGINAL_MAC_FILE", mac_file)

        from blue_tap.core.spoofer import save_original_mac, get_original_mac

        monkeypatch.setattr(
            "blue_tap.core.spoofer.get_adapter_address",
            lambda hci: "AA:BB:CC:DD:EE:FF",
        )
        save_original_mac("hci0")

        # Now adapter reports a different (spoofed) MAC, but save should not overwrite
        monkeypatch.setattr(
            "blue_tap.core.spoofer.get_adapter_address",
            lambda hci: "99:99:99:99:99:99",
        )
        save_original_mac("hci0")

        # Original MAC preserved
        assert get_original_mac("hci0") == "AA:BB:CC:DD:EE:FF"

    def test_corruption_recovery(self, tmp_path, monkeypatch):
        """Corrupted JSON is backed up and a fresh save works."""
        mac_file = str(tmp_path / "original_mac.json")
        monkeypatch.setattr("blue_tap.core.spoofer._ORIGINAL_MAC_FILE", mac_file)
        monkeypatch.setattr(
            "blue_tap.core.spoofer.get_adapter_address",
            lambda hci: "AA:BB:CC:DD:EE:FF",
        )

        from blue_tap.core.spoofer import save_original_mac, get_original_mac

        # Write corrupt JSON
        with open(mac_file, "w") as f:
            f.write("{invalid json!!")

        save_original_mac("hci0")

        # Backup file should exist
        assert os.path.exists(mac_file + ".bak")
        # Fresh save should work
        assert get_original_mac("hci0") == "AA:BB:CC:DD:EE:FF"

    def test_get_nonexistent_adapter(self, tmp_path, monkeypatch):
        mac_file = str(tmp_path / "original_mac.json")
        monkeypatch.setattr("blue_tap.core.spoofer._ORIGINAL_MAC_FILE", mac_file)

        from blue_tap.core.spoofer import get_original_mac

        assert get_original_mac("hci99") is None

    def test_get_missing_file(self, tmp_path, monkeypatch):
        mac_file = str(tmp_path / "nonexistent.json")
        monkeypatch.setattr("blue_tap.core.spoofer._ORIGINAL_MAC_FILE", mac_file)

        from blue_tap.core.spoofer import get_original_mac

        assert get_original_mac("hci0") is None


class TestCloneDeviceIdentity:
    """Test clone_device_identity with mocked spoofing functions."""

    @patch("blue_tap.core.spoofer.spoof_address", return_value=True)
    @patch("blue_tap.core.adapter.set_device_name", return_value=True)
    @patch("blue_tap.core.adapter.set_device_class", return_value=True)
    def test_all_succeed(self, mock_class, mock_name, mock_spoof):
        from blue_tap.core.spoofer import clone_device_identity

        result = clone_device_identity("hci0", "AA:BB:CC:DD:EE:FF", "MyPhone")
        assert result is True
        mock_spoof.assert_called_once_with("hci0", "AA:BB:CC:DD:EE:FF")
        mock_name.assert_called_once_with("hci0", "MyPhone")
        mock_class.assert_called_once_with("hci0", "0x5a020c")

    @patch("blue_tap.core.spoofer.spoof_address", return_value=False)
    def test_spoof_fails_returns_false_immediately(self, mock_spoof):
        from blue_tap.core.spoofer import clone_device_identity

        result = clone_device_identity("hci0", "AA:BB:CC:DD:EE:FF", "MyPhone")
        assert result is False

    @patch("blue_tap.core.spoofer.spoof_address", return_value=True)
    @patch("blue_tap.core.adapter.set_device_name", return_value=False)
    @patch("blue_tap.core.adapter.set_device_class", return_value=True)
    def test_name_fails_returns_false(self, mock_class, mock_name, mock_spoof):
        from blue_tap.core.spoofer import clone_device_identity

        result = clone_device_identity("hci0", "AA:BB:CC:DD:EE:FF", "MyPhone")
        assert result is False

    @patch("blue_tap.core.spoofer.spoof_address", return_value=True)
    @patch("blue_tap.core.adapter.set_device_name", return_value=True)
    @patch("blue_tap.core.adapter.set_device_class", return_value=False)
    def test_class_fails_returns_false(self, mock_class, mock_name, mock_spoof):
        from blue_tap.core.spoofer import clone_device_identity

        result = clone_device_identity("hci0", "AA:BB:CC:DD:EE:FF", "MyPhone")
        assert result is False

    @patch("blue_tap.core.spoofer.spoof_address", return_value=True)
    @patch("blue_tap.core.adapter.set_device_name", side_effect=RuntimeError("oops"))
    def test_exception_returns_false(self, mock_name, mock_spoof):
        from blue_tap.core.spoofer import clone_device_identity

        result = clone_device_identity("hci0", "AA:BB:CC:DD:EE:FF", "MyPhone")
        assert result is False

    @patch("blue_tap.core.spoofer.spoof_address", return_value=True)
    @patch("blue_tap.core.adapter.set_device_name", return_value=True)
    @patch("blue_tap.core.adapter.set_device_class", return_value=True)
    def test_custom_device_class(self, mock_class, mock_name, mock_spoof):
        from blue_tap.core.spoofer import clone_device_identity

        clone_device_identity("hci0", "AA:BB:CC:DD:EE:FF", "MyPhone", device_class="0x000104")
        mock_class.assert_called_once_with("hci0", "0x000104")


# ============================================================================
# Session Tests (expanded)
# ============================================================================


class TestSessionCreate:
    def test_creates_directory_and_metadata(self, tmp_path):
        session = Session("test_session", base_dir=str(tmp_path))
        assert os.path.isdir(session.dir)
        assert os.path.isfile(session.meta_file)

        with open(session.meta_file) as f:
            meta = json.load(f)
        assert meta["name"] == "test_session"
        assert "created" in meta
        assert meta["commands"] == []
        assert meta["targets"] == []

    def test_resume_existing_session(self, tmp_path):
        s1 = Session("resume_test", base_dir=str(tmp_path))
        s1.log("cmd1", {"data": "one"}, category="scan")

        s2 = Session("resume_test", base_dir=str(tmp_path))
        assert s2.command_count == 1
        assert len(s2.metadata["commands"]) == 1


class TestSessionLog:
    def test_creates_numbered_json_files(self, tmp_path):
        session = Session("log_test", base_dir=str(tmp_path))
        p1 = session.log("scan_classic", [{"addr": "AA:BB"}], category="scan")
        p2 = session.log("vulnscan", {"vulns": []}, category="vuln")

        assert p1.endswith("001_scan_classic.json")
        assert p2.endswith("002_vulnscan.json")
        assert os.path.isfile(p1)
        assert os.path.isfile(p2)

    def test_updates_command_log(self, tmp_path):
        session = Session("cmdlog_test", base_dir=str(tmp_path))
        session.log("scan_classic", [], category="scan", target="AA:BB:CC:DD:EE:FF")

        with open(session.meta_file) as f:
            meta = json.load(f)
        assert len(meta["commands"]) == 1
        assert meta["commands"][0]["command"] == "scan_classic"
        assert meta["commands"][0]["category"] == "scan"
        assert "AA:BB:CC:DD:EE:FF" in meta["targets"]

    def test_tracks_unique_targets(self, tmp_path):
        session = Session("target_test", base_dir=str(tmp_path))
        session.log("cmd1", {}, target="AA:BB:CC:DD:EE:FF")
        session.log("cmd2", {}, target="AA:BB:CC:DD:EE:FF")
        session.log("cmd3", {}, target="11:22:33:44:55:66")

        assert len(session.metadata["targets"]) == 2

    def test_long_command_name_truncated(self, tmp_path):
        session = Session("trunc_test", base_dir=str(tmp_path))
        long_cmd = "a" * 100
        path = session.log(long_cmd, {})
        filename = os.path.basename(path)
        # Command part truncated to 40 chars
        assert len(filename) <= 4 + 40 + 5  # seq_ + cmd + .json


class TestSessionGetAllData:
    def test_organizes_by_category(self, tmp_path):
        session = Session("collect_test", base_dir=str(tmp_path))
        session.log("scan1", {"devices": []}, category="scan")
        session.log("vuln1", {"findings": []}, category="vuln")
        session.log("attack1", {"result": "ok"}, category="attack")
        session.log("misc", {}, category="general")

        data = session.get_all_data()
        assert len(data["scan"]) == 1
        assert len(data["vuln"]) == 1
        assert len(data["attack"]) == 1
        assert len(data["general"]) == 1
        assert data["scan"][0]["command"] == "scan1"

    def test_unknown_category_goes_to_general(self, tmp_path):
        session = Session("unknown_cat", base_dir=str(tmp_path))
        session.log("custom", {}, category="nonexistent")

        data = session.get_all_data()
        assert len(data["general"]) == 1

    def test_missing_data_file_skipped(self, tmp_path):
        session = Session("missing_file", base_dir=str(tmp_path))
        path = session.log("cmd1", {"ok": True}, category="scan")
        os.remove(path)  # Delete the data file

        data = session.get_all_data()
        assert len(data["scan"]) == 0

    def test_includes_raw_files(self, tmp_path):
        session = Session("raw_test", base_dir=str(tmp_path))
        session.save_raw("test.vcf", "BEGIN:VCARD\nEND:VCARD", subdir="pbap")

        data = session.get_all_data()
        assert len(data["raw_files"]) == 1
        assert data["raw_files"][0]["path"] == os.path.join("pbap", "test.vcf")


class TestSessionSummary:
    def test_summary_fields(self, tmp_path):
        session = Session("summary_test", base_dir=str(tmp_path))
        session.log("scan", {}, category="scan", target="AA:BB:CC:DD:EE:FF")
        session.log("vuln", {}, category="vuln", target="AA:BB:CC:DD:EE:FF")
        session.save_raw("file.txt", "content")

        summary = session.summary()
        assert summary["name"] == "summary_test"
        assert summary["total_commands"] == 2
        assert "AA:BB:CC:DD:EE:FF" in summary["targets"]
        assert "scan" in summary["categories"]
        assert "vuln" in summary["categories"]
        assert summary["files"] == 1
        assert summary["directory"] == session.dir

    def test_empty_session_summary(self, tmp_path):
        session = Session("empty_test", base_dir=str(tmp_path))
        summary = session.summary()
        assert summary["total_commands"] == 0
        assert summary["targets"] == []
        assert summary["files"] == 0


class TestSessionSaveRaw:
    def test_save_string_to_subdir(self, tmp_path):
        session = Session("raw_str", base_dir=str(tmp_path))
        path = session.save_raw("contacts.vcf", "BEGIN:VCARD\nEND:VCARD", subdir="pbap")
        assert os.path.isfile(path)
        with open(path) as f:
            assert f.read() == "BEGIN:VCARD\nEND:VCARD"

    def test_save_bytes(self, tmp_path):
        session = Session("raw_bytes", base_dir=str(tmp_path))
        data = b"\x00\x01\x02\x03"
        path = session.save_raw("capture.pcap", data)
        assert os.path.isfile(path)
        with open(path, "rb") as f:
            assert f.read() == data

    def test_save_to_root_dir(self, tmp_path):
        session = Session("raw_root", base_dir=str(tmp_path))
        path = session.save_raw("notes.txt", "hello")
        assert os.path.dirname(path) == session.dir

    def test_updates_files_metadata(self, tmp_path):
        session = Session("raw_meta", base_dir=str(tmp_path))
        session.save_raw("a.txt", "aaa")
        session.save_raw("b.txt", "bbb", subdir="sub")
        assert len(session.metadata["files"]) == 2


class TestSessionPathTraversal:
    def test_rejects_dotdot(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid session name"):
            Session("../evil", base_dir=str(tmp_path))

    def test_rejects_slash(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid session name"):
            Session("foo/bar", base_dir=str(tmp_path))

    def test_backslash_on_linux_is_valid_filename(self, tmp_path):
        # On Linux, backslash is a valid filename character (not a separator)
        # os.path.basename("foo\\bar") returns "foo\\bar" on Linux
        s = Session("foo\\bar", base_dir=str(tmp_path))
        assert s.name == "foo\\bar"

    def test_rejects_empty_name(self, tmp_path):
        with pytest.raises(ValueError, match="Invalid session name"):
            Session("", base_dir=str(tmp_path))

    def test_accepts_valid_names(self, tmp_path):
        for name in ["my-session", "session_01", "TestSession", "a"]:
            s = Session(name, base_dir=str(tmp_path))
            assert s.name == name


class TestSessionCorruptMetadata:
    def test_corrupt_session_json_recreated(self, tmp_path):
        """Corrupt session.json is replaced by fresh metadata."""
        session_dir = tmp_path / "sessions" / "corrupt_test"
        session_dir.mkdir(parents=True)
        meta_file = session_dir / "session.json"
        meta_file.write_text("{invalid json!!")

        session = Session("corrupt_test", base_dir=str(tmp_path))
        assert session.metadata["name"] == "corrupt_test"
        assert session.command_count == 0
