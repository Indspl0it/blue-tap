from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from blue_tap.attack.bluesnarfer import ATClient
from blue_tap.attack.hfp import HFPClient
from blue_tap.attack.map_client import MAPClient, parse_bmessage
from blue_tap.attack.opp import OPPClient
from blue_tap.attack.pbap import PBAPClient
from blue_tap.attack.avrcp import AVRCPController
from blue_tap.attack.a2dp import (
    capture_a2dp,
    play_to_car,
    record_car_mic,
    resolve_a2dp_source,
    resolve_bt_sink,
    resolve_hfp_source,
    set_profile_a2dp,
)
from blue_tap.core.obex_client import ObexError
from blue_tap.cli import _command_succeeded
from blue_tap.cli import main


FIXTURES = Path(__file__).parent / "fixtures" / "profiles"


def _fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_profile_clients_normalize_mac_addresses():
    assert PBAPClient("aa:bb:cc:dd:ee:ff", channel=9).address == "AA:BB:CC:DD:EE:FF"
    assert MAPClient("aa:bb:cc:dd:ee:ff", channel=9).address == "AA:BB:CC:DD:EE:FF"
    assert HFPClient("aa:bb:cc:dd:ee:ff", channel=9).address == "AA:BB:CC:DD:EE:FF"
    assert OPPClient("aa:bb:cc:dd:ee:ff", channel=9).address == "AA:BB:CC:DD:EE:FF"
    assert ATClient("aa:bb:cc:dd:ee:ff", channel=1).address == "AA:BB:CC:DD:EE:FF"


def test_pbap_parse_vcards_extracts_contacts_and_call_timestamps():
    client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=9)
    data = (
        "BEGIN:VCARD\r\n"
        "VERSION:3.0\r\n"
        "FN:Alice Example\r\n"
        "TEL;TYPE=CELL:+123456\r\n"
        "EMAIL:alice@example.com\r\n"
        "ORG:Example Corp\r\n"
        "X-IRMC-CALL-DATETIME:20260410T120000\r\n"
        "END:VCARD\r\n"
    )

    summary = client.summarize_phonebook(data)

    assert summary["entries"] == 1
    assert summary["with_phone"] == 1
    assert summary["with_email"] == 1
    assert summary["with_org"] == 1
    assert summary["with_call_datetime"] == 1
    assert summary["sample_names"] == ["Alice Example"]


def test_pbap_public_fixture_summarizes_real_profile_shaped_vcards():
    client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=9)

    summary = client.summarize_phonebook(_fixture_text("pbap_public_pb.vcf"))

    assert summary["entries"] == 4
    assert summary["with_phone"] == 4
    assert summary["with_email"] == 2
    assert summary["with_org"] == 1


def test_pbap_normalizes_aliases_builds_filters_and_parses_listing():
    client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=9)

    assert client.normalize_path("contacts") == "telecom/pb.vcf"
    assert client.normalize_path("SIM", prefer_listing=True) == "SIM1/telecom/pb"

    filter_bits = client.build_filter_bits(["fn", "tel", "email"])
    assert filter_bits is not None
    assert filter_bits & (1 << 1)
    assert filter_bits & (1 << 7)
    assert filter_bits & (1 << 8)

    listing = """<?xml version="1.0"?>
    <vCard-listing version="1.0">
      <card handle="1.vcf" name="Alice Example"/>
      <card handle="2.vcf" name="Bob Example" />
    </vCard-listing>
    """
    parsed = client.parse_vcard_listing(listing)

    assert parsed == [
        {"handle": "1.vcf", "name": "Alice Example"},
        {"handle": "2.vcf", "name": "Bob Example"},
    ]


def test_pbap_parse_vcard_listing_handles_namespaced_and_truncated_payloads():
    client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=9)

    namespaced = client.parse_vcard_listing(_fixture_text("pbap_listing_namespaced.xml"))
    truncated = client.parse_vcard_listing(_fixture_text("pbap_listing_truncated.xml"))

    assert namespaced == [
        {"handle": "1.vcf", "name": "Alice Example"},
        {"handle": "2.vcf", "name": "Bob & Co"},
    ]
    assert truncated == [{"handle": "10.vcf", "name": "Carol Example"}]


def test_pbap_prefers_obex_session_for_listing(monkeypatch):
    class FakePBAPSession:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def select(self, location: str, phonebook: str):
            return None

        def list(self, filters: dict):
            return [{"handle": "1.vcf", "name": "Alice Example"}]

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.attack.pbap.PBAPSession", FakePBAPSession)

    client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=19)
    assert client.connect() is True

    listing = client.pull_vcard_listing("contacts", max_count=10)

    assert "Alice Example" in listing
    assert client.sock is None


def test_pbap_path_selection_builds_sim_paths():
    client = PBAPClient("AA:BB:CC:DD:EE:FF", channel=19)

    assert client.resolve_path_selection(location="sim", phonebook="pb") == "SIM1/telecom/pb.vcf"
    assert client.resolve_path_selection(location="internal", phonebook="mch", listing=True) == "telecom/mch"


def test_map_client_parses_folder_aliases_and_listing_xml():
    client = MAPClient("AA:BB:CC:DD:EE:FF", channel=12)
    assert client.normalize_folder("sent") == "telecom/msg/sent"
    assert client.normalize_folder("telecom/msg/inbox") == "telecom/msg/inbox"

    listing = """<?xml version="1.0"?>
    <MAP-msg-listing version="1.0">
      <msg handle="200001" subject="hi" sender_name="Alice" recipient_name="Bob" />
      <msg handle="200002" subject="hello" sender_name="Carol" />
    </MAP-msg-listing>
    """
    parsed = client.parse_message_listing(listing)

    assert len(parsed) == 2
    assert parsed[0]["handle"] == "200001"
    assert parsed[0]["sender_name"] == "Alice"


def test_map_parse_message_listing_handles_namespaced_and_truncated_payloads():
    client = MAPClient("AA:BB:CC:DD:EE:FF", channel=12)

    namespaced = client.parse_message_listing(_fixture_text("map_listing_namespaced.xml"))
    truncated = client.parse_message_listing(_fixture_text("map_listing_truncated.xml"))

    assert namespaced[0]["handle"] == "200001"
    assert namespaced[0]["sender_name"] == "Alice"
    assert namespaced[1]["sender_addressing"] == "+1234"
    assert truncated == [{"handle": "300001", "subject": "partially closed", "sender_name": "Alice"}]


def test_map_public_listing_fixture_parses_real_profile_shaped_entries():
    client = MAPClient("AA:BB:CC:DD:EE:FF", channel=12)
    parsed = client.parse_message_listing(_fixture_text("map_public_mlisting.xml"))

    assert parsed[0]["handle"] == "456789"
    assert parsed[0]["type"] == "SMS_GSM"
    assert parsed[1]["handle"] == "0123"
    assert parsed[1]["type"] == "EMAIL"


def test_parse_bmessage_handles_folded_vcards_and_multiple_body_parts():
    parsed = parse_bmessage(_fixture_text("map_bmessage_multipart.txt"))

    assert parsed["version"] == "1.0"
    assert parsed["type"] == "SMS_GSM"
    assert parsed["status"] == "READ"
    assert parsed["folder"] == "telecom/msg/inbox"
    assert parsed["charset"] == "UTF-8"
    assert parsed["length"] == 5
    assert parsed["sender"] == "+123456"
    assert parsed["sender_name"] == "Alice Example"
    assert parsed["sender_email"] == "alice@example.com"
    assert parsed["recipient"] == "+987654"
    assert parsed["recipient_name"] == "Bob Example"
    assert parsed["recipient_email"] == "bob@example.com"
    assert parsed["body_parts"] == ["hello", "world"]
    assert parsed["body"] == "hello\n\nworld"
    assert len(parsed["vcards"]) == 2


def test_parse_bmessage_public_email_and_sms_fixtures():
    email_msg = parse_bmessage(_fixture_text("map_public_0123.bmsg"))
    sms_msg = parse_bmessage(_fixture_text("map_public_456789.bmsg"))

    assert email_msg["type"] == "EMAIL"
    assert email_msg["sender_email"] == "ma@abc.edu"
    assert "Let's go fishing!" in email_msg["body"]
    assert sms_msg["type"] == "SMS_GSM"
    assert sms_msg["sender"] == "00498912345678"
    assert "0191000E9100949821436587000011303231" in sms_msg["body"]


def test_map_prefers_obex_session_for_listing(monkeypatch):
    class FakeMAPSession:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def list_messages(self, folder: str, filters: dict):
            return [{"handle": "200001", "Subject": "Hi", "Sender": "Alice"}]

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.attack.map_client.MAPSession", FakeMAPSession)

    client = MAPClient("AA:BB:CC:DD:EE:FF", channel=20)
    assert client.connect() is True
    listing = client.get_messages_listing("inbox", max_count=10)

    assert "MAP-msg-listing" in listing
    assert "Alice" in listing
    assert client.sock is None


def test_map_dump_uses_message_path_when_handle_missing(monkeypatch, tmp_path):
    client = MAPClient("AA:BB:CC:DD:EE:FF", channel=20)
    monkeypatch.setattr(
        client,
        "get_messages_listing",
        lambda folder="telecom/msg/inbox", **kwargs: '<?xml version="1.0"?><MAP-msg-listing version="1.0"><msg path="/org/bluez/obex/client/session0/message0" subject="hi"/></MAP-msg-listing>',
    )
    monkeypatch.setattr(
        client,
        "get_message",
        lambda message_id: "BEGIN:BMSG\r\nVERSION:1.0\r\nBEGIN:MSG\r\nhi\r\nEND:MSG\r\nEND:BMSG\r\n",
    )

    result = client.dump_all_messages(str(tmp_path))

    inbox = result["telecom/msg/inbox"]
    assert inbox["messages"]
    assert inbox["messages"][0]["handle"].endswith("message0")
    assert inbox["listing_json"].endswith("_listing.json")


def test_map_list_logs_filters(monkeypatch):
    recorded = {}

    class FakeMAPClient:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def get_messages_listing(self, *args, **kwargs):
            return '<?xml version="1.0"?><MAP-msg-listing version="1.0"><msg handle="200001" subject="hi"/></MAP-msg-listing>'

        def parse_message_listing(self, listing_xml: str):
            return [{"handle": "200001", "subject": "hi"}]

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.recon.sdp.find_service_channel", lambda *args, **kwargs: 20)
    monkeypatch.setattr("blue_tap.attack.map_client.MAPClient", FakeMAPClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(
        main,
        ["map", "list", "AA:BB:CC:DD:EE:FF", "--max-count", "10", "--offset", "2", "--sender", "+1234", "--type", "sms"],
    )

    assert result.exit_code == 0
    assert recorded["command"] == "map_list"
    assert recorded["data"]["module_data"]["request"]["max_count"] == 10
    assert recorded["data"]["module_data"]["request"]["offset"] == 2
    assert recorded["data"]["module_data"]["request"]["sender"] == "+1234"
    assert recorded["data"]["module_data"]["request"]["types"] == ["sms"]


def test_map_folders_logs_standardized_data_envelope(monkeypatch):
    recorded = {}

    class FakeMAPClient:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def list_folders(self, folder: str, max_count: int = 100, offset: int = 0):
            return [{"Name": "inbox"}, {"Name": "sent"}]

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.recon.sdp.find_service_channel", lambda *args, **kwargs: 20)
    monkeypatch.setattr("blue_tap.attack.map_client.MAPClient", FakeMAPClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["map", "folders", "AA:BB:CC:DD:EE:FF"])

    assert result.exit_code == 0
    assert recorded["command"] == "map_folders"
    assert recorded["data"]["summary"]["folders"] == 2


def test_map_update_inbox_logs_failure(monkeypatch):
    recorded = {}

    class FakeMAPClient:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def update_inbox(self):
            return False

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.recon.sdp.find_service_channel", lambda *args, **kwargs: 20)
    monkeypatch.setattr("blue_tap.attack.map_client.MAPClient", FakeMAPClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["map", "update-inbox", "AA:BB:CC:DD:EE:FF"])

    assert result.exit_code == 0
    assert recorded["command"] == "map_update_inbox"
    assert recorded["data"]["executions"][0]["module_outcome"] == "failed"


def test_opp_prefers_obex_session_for_push(monkeypatch, tmp_path):
    payload = tmp_path / "contact.vcf"
    payload.write_text("BEGIN:VCARD\nEND:VCARD\n")

    class FakeOPPSession:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def send_file(self, sourcefile: str):
            return ("/org/bluez/obex/client/session0/transfer3", {"Filename": sourcefile})

        def wait_for_transfer(self, transfer_path: str):
            return {"Status": "complete", "Filename": str(payload)}

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.attack.opp.OPPSession", FakeOPPSession)

    client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
    assert client.connect() is True
    assert client.push_file(str(payload)) is True
    assert client.sock is None


def test_opp_dbus_transfer_failure_returns_false_without_raw_socket_crash(monkeypatch, tmp_path):
    payload = tmp_path / "contact.vcf"
    payload.write_text("BEGIN:VCARD\nEND:VCARD\n")

    class FakeOPPSession:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def send_file(self, sourcefile: str):
            return ("/org/bluez/obex/client/session0/transfer3", {"Filename": sourcefile})

        def wait_for_transfer(self, transfer_path: str):
            raise ObexError("remote rejected push")

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.attack.opp.OPPSession", FakeOPPSession)

    client = OPPClient("AA:BB:CC:DD:EE:FF", channel=9)
    assert client.connect() is True
    assert client.push_file(str(payload)) is False
    assert client.last_transfer["status"] == "failed"
    assert "remote rejected push" in str(client.last_transfer["error"])


def test_doctor_profiles_logs_environment_envelope(monkeypatch):
    recorded = {}

    monkeypatch.setattr(
        "blue_tap.utils.env_doctor.detect_profile_environment",
        lambda: {
            "tools": {"bluetoothctl": True, "sdptool": True, "hciconfig": True, "pactl": True, "parecord": True, "paplay": True, "aplay": True},
            "services": {"bluetooth": True, "dbus": True, "pipewire": True, "pipewire-pulse": True, "wireplumber": True, "pulseaudio": False},
            "adapters": [{"name": "hci0"}],
            "obex": {"client_interface_available": True, "errors": []},
            "summary": {"bluetooth_ready": True, "obex_ready": True, "audio_ready": True, "capability_limitations": []},
        },
    )
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["doctor", "profiles"])

    assert result.exit_code == 0
    assert recorded["command"] == "doctor_profiles"
    assert recorded["data"]["summary"]["bluetooth_ready"] is True
    assert recorded["data"]["summary"]["obex_ready"] is True
    assert recorded["data"]["summary"]["audio_ready"] is True


def test_doctor_profiles_logs_capability_limitations(monkeypatch):
    recorded = {}

    monkeypatch.setattr(
        "blue_tap.utils.env_doctor.detect_profile_environment",
        lambda: {
            "tools": {"bluetoothctl": False, "sdptool": False, "hciconfig": True, "pactl": False, "parecord": False, "paplay": False, "aplay": False},
            "services": {"bluetooth": False, "dbus": True, "pipewire": False, "pipewire-pulse": False, "wireplumber": False, "pulseaudio": False},
            "adapters": [],
            "obex": {"client_interface_available": False, "errors": ["obexd unavailable"]},
            "summary": {
                "bluetooth_ready": False,
                "obex_ready": False,
                "audio_ready": False,
                "capability_limitations": [
                    "Bluetooth service is inactive or unavailable",
                    "pactl is unavailable; host audio routing/profile switching cannot be controlled",
                    "obexd unavailable",
                ],
            },
        },
    )
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["doctor", "profiles"])

    assert result.exit_code == 0
    assert recorded["data"]["executions"][0]["evidence"]["capability_limitations"] == [
        "Bluetooth service is inactive or unavailable",
        "pactl is unavailable; host audio routing/profile switching cannot be controlled",
        "obexd unavailable",
    ]


def test_opp_push_logs_failure_when_connection_setup_fails(monkeypatch, tmp_path):
    recorded = {}
    payload = tmp_path / "contact.vcf"
    payload.write_text("BEGIN:VCARD\nEND:VCARD\n")

    class FakeOPPClient:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel
            self.last_backend = ""
            self.last_connect_error = "connect failed"
            self.last_transfer = {}

        def connect(self):
            return False

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.recon.sdp.find_service_channel", lambda *args, **kwargs: 9)
    monkeypatch.setattr("blue_tap.attack.opp.OPPClient", FakeOPPClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["opp", "push", "AA:BB:CC:DD:EE:FF", str(payload)])

    assert result.exit_code == 0
    assert recorded["command"] == "opp_push"
    assert recorded["data"]["executions"][0]["module_outcome"] == "failed"
    assert recorded["data"]["module_data"]["connect_error"] == "connect failed"


def test_map_dump_writes_manifest_artifact(monkeypatch, tmp_path):
    recorded = {}

    class FakeMAPClient:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def dump_all_messages(self, output_dir: str = "map_dump"):
            manifest_target = tmp_path / "inbox"
            manifest_target.mkdir(exist_ok=True)
            return {
                "telecom/msg/inbox": {
                    "listing_file": str(tmp_path / "inbox_listing.xml"),
                    "listing_json": str(tmp_path / "inbox_listing.json"),
                    "messages": [],
                }
            }

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.recon.sdp.find_service_channel", lambda *args, **kwargs: 20)
    monkeypatch.setattr("blue_tap.attack.map_client.MAPClient", FakeMAPClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["map", "dump", "AA:BB:CC:DD:EE:FF", "-o", str(tmp_path)])

    assert result.exit_code == 0
    assert recorded["command"] == "map_dump"
    assert (tmp_path / "map_dump_manifest.json").exists()


def test_map_push_logs_capability_limitations(monkeypatch):
    recorded = {}

    class FakeMAPClient:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel
            self.last_capability_limitations = [
                "BlueZ obexd MAP PushMessage path unavailable or rejected; using raw OBEX fallback"
            ]

        def connect(self):
            return True

        def push_message(self, folder: str, recipient: str, body: str, msg_type: str = "SMS_GSM", **kwargs):
            return True

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.recon.sdp.find_service_channel", lambda *args, **kwargs: 20)
    monkeypatch.setattr("blue_tap.attack.map_client.MAPClient", FakeMAPClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(
        main,
        ["map", "push", "AA:BB:CC:DD:EE:FF", "--recipient", "+1234", "--body", "hello"],
    )

    assert result.exit_code == 0
    assert recorded["command"] == "map_push"
    assert recorded["data"]["executions"][0]["evidence"]["capability_limitations"] == [
        "BlueZ obexd MAP PushMessage path unavailable or rejected; using raw OBEX fallback"
    ]


def test_map_status_logs_failed_outcome(monkeypatch):
    recorded = {}

    class FakeMAPClient:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel
            self.last_capability_limitations = [
                "BlueZ obexd MAP message-property write path unavailable or rejected; using raw OBEX fallback"
            ]

        def connect(self):
            return True

        def set_message_status(self, handle: str, indicator: str, value: bool):
            return False

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.recon.sdp.find_service_channel", lambda *args, **kwargs: 20)
    monkeypatch.setattr("blue_tap.attack.map_client.MAPClient", FakeMAPClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(
        main,
        ["map", "status", "AA:BB:CC:DD:EE:FF", "/org/bluez/obex/client/session0/message0", "--indicator", "read"],
    )

    assert result.exit_code == 0
    assert recorded["command"] == "map_status"
    assert recorded["data"]["executions"][0]["module_outcome"] == "failed"


def test_avrcp_metadata_snapshot_aggregates_player_context(monkeypatch):
    ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")
    ctrl.dbus_path = "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/player0"
    ctrl.player_candidates = [
        {"path": "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/player0", "Name": "Spotify", "Status": "playing", "Browsable": True}
    ]
    ctrl.selected_player = dict(ctrl.player_candidates[0])
    monkeypatch.setattr(ctrl, "get_track_info", lambda: {"Title": "Song", "Artist": "Artist"})
    monkeypatch.setattr(ctrl, "get_status", lambda: "playing")
    monkeypatch.setattr(ctrl, "get_player_info", lambda: {"Name": "Spotify", "Status": "playing"})
    monkeypatch.setattr(ctrl, "get_player_settings", lambda: {"Repeat": "alltracks"})

    snapshot = ctrl.get_metadata_snapshot()

    assert snapshot["status"] == "playing"
    assert snapshot["track"]["Title"] == "Song"
    assert snapshot["player"]["Name"] == "Spotify"
    assert snapshot["settings"]["Repeat"] == "alltracks"
    assert snapshot["active_app"] == "Spotify"
    assert snapshot["selection"]["selected_name"] == "Spotify"
    assert snapshot["selection"]["candidate_count"] == 1


def test_avrcp_player_sort_prefers_playing_named_candidates():
    candidates = [
        {"path": "/p2", "Name": "", "Status": "paused", "Browsable": False},
        {"path": "/p1", "Name": "Spotify", "Status": "playing", "Browsable": True},
        {"path": "/p3", "Name": "USB", "Status": "stopped", "Browsable": True},
    ]

    ranked = sorted(candidates, key=AVRCPController._player_sort_key)

    assert ranked[0]["path"] == "/p1"


def test_avrcp_connect_falls_back_to_next_player_candidate(monkeypatch):
    ctrl = AVRCPController("AA:BB:CC:DD:EE:FF")

    class FakeBus:
        def __init__(self):
            self.seen = []

        async def introspect(self, service, path):
            self.seen.append(path)
            if path == "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/player0":
                raise RuntimeError("broken player")
            return {"path": path}

        def get_proxy_object(self, service, path, introspection):
            class Obj:
                def get_interface(self, name):
                    return object()
            return Obj()

        def disconnect(self):
            return None

    fake_bus = FakeBus()
    ctrl._bus = fake_bus
    candidates = {
        "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/player0": {
            "org.bluez.MediaPlayer1": {"Name": "Broken", "Status": "playing"}
        },
        "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/player1": {
            "org.bluez.MediaPlayer1": {"Name": "Spotify", "Status": "paused"}
        },
    }

    result = __import__("blue_tap.attack.avrcp", fromlist=["_run_async"])._run_async(
        ctrl._find_transport({}, "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF")
    )
    assert result is None

    async def _run():
        ctrl._bus = fake_bus
        objects = candidates
        dev_prefix = "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF"
        collected = []
        for path, interfaces in objects.items():
            if str(path).startswith(dev_prefix) and "org.bluez.MediaPlayer1" in interfaces:
                candidate = {"path": str(path)}
                candidate.update(interfaces["org.bluez.MediaPlayer1"])
                collected.append(candidate)
        ctrl.player_candidates = sorted(collected, key=ctrl._player_sort_key)
        bind_errors = []
        for chosen in ctrl.player_candidates:
            ctrl.dbus_path = chosen["path"]
            try:
                introspection = await ctrl._bus.introspect("org.bluez", ctrl.dbus_path)
                player_obj = ctrl._bus.get_proxy_object("org.bluez", ctrl.dbus_path, introspection)
                ctrl._player_iface = player_obj.get_interface("org.bluez.MediaPlayer1")
                ctrl._props_iface = player_obj.get_interface("org.freedesktop.DBus.Properties")
                ctrl.selected_player = dict(chosen)
                break
            except Exception as e:
                bind_errors.append(f"{ctrl.dbus_path}: {e}")
                ctrl._player_iface = None
                ctrl._props_iface = None
        return bind_errors

    bind_errors = __import__("blue_tap.attack.avrcp", fromlist=["_run_async"])._run_async(_run())
    assert ctrl.dbus_path == "/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/player1"
    assert ctrl._player_iface is not None
    assert ctrl.get_selection_diagnostics()["selected_name"] == "Spotify"
    assert bind_errors == ["/org/bluez/hci0/dev_AA_BB_CC_DD_EE_FF/player0: broken player"]


def test_resolve_bt_audio_endpoints_prefer_exact_mac_matches(monkeypatch):
    entries = [
        {"id": "1", "name": "bluez_input.11_22_33_44_55_66.0", "driver": "", "state": "SUSPENDED"},
        {"id": "2", "name": "bluez_input.AA_BB_CC_DD_EE_FF.0", "driver": "", "state": "RUNNING"},
        {"id": "3", "name": "bluez_source.AA_BB_CC_DD_EE_FF.a2dp_sink", "driver": "", "state": "RUNNING"},
        {"id": "4", "name": "bluez_output.AA_BB_CC_DD_EE_FF.1", "driver": "", "state": "RUNNING"},
    ]

    monkeypatch.setattr(
        "blue_tap.attack.a2dp._list_short",
        lambda kind: [entry for entry in entries if ("output" in entry["name"]) == (kind == "sinks")],
    )

    assert resolve_hfp_source("aa:bb:cc:dd:ee:ff") == "bluez_input.AA_BB_CC_DD_EE_FF.0"
    assert resolve_a2dp_source("AA:BB:CC:DD:EE:FF") == "bluez_source.AA_BB_CC_DD_EE_FF.a2dp_sink"
    assert resolve_bt_sink("AA:BB:CC:DD:EE:FF") == "bluez_output.AA_BB_CC_DD_EE_FF.1"


def test_set_profile_a2dp_verifies_active_profile(monkeypatch):
    calls = {"count": 0}

    class Result:
        returncode = 0
        stderr = ""

    monkeypatch.setattr("blue_tap.attack.a2dp.run_cmd", lambda cmd: Result())

    def _profile(_mac):
        calls["count"] += 1
        return "off" if calls["count"] == 1 else "a2dp-sink"

    monkeypatch.setattr("blue_tap.attack.a2dp.get_active_profile", _profile)
    monkeypatch.setattr("blue_tap.attack.a2dp.time.sleep", lambda *_: None)

    assert set_profile_a2dp("AA:BB:CC:DD:EE:FF") is True


def test_audio_live_logs_failed_audio_envelope(monkeypatch):
    recorded = {}

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.attack.a2dp.live_eavesdrop", lambda mac, auto_setup=True: False)
    monkeypatch.setattr(
        "blue_tap.utils.env_doctor.detect_profile_environment",
        lambda: {"summary": {"capability_limitations": ["No active PipeWire/PulseAudio user service detected"]}},
    )
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["audio", "live", "AA:BB:CC:DD:EE:FF"])

    assert result.exit_code == 0
    assert recorded["command"] == "audio_live"
    assert recorded["data"]["executions"][0]["module_outcome"] == "failed"


def test_command_succeeded_rejects_common_hfp_failure_responses():
    assert _command_succeeded("OK") is True
    assert _command_succeeded("NO CARRIER") is False
    assert _command_succeeded("BUSY") is False
    assert _command_succeeded("NO ANSWER") is False


def test_record_car_mic_returns_empty_on_header_only_file(monkeypatch, tmp_path):
    output = tmp_path / "empty.wav"

    class FakeProc:
        pid = 123

        def terminate(self):
            return None

        def wait(self, timeout=None):
            output.write_bytes(b"R" * 44)
            return 0

    monkeypatch.setattr("blue_tap.attack.a2dp.check_tool", lambda tool: True)
    monkeypatch.setattr("blue_tap.attack.a2dp.detect_mic_channels", lambda mac: 1)
    monkeypatch.setattr("blue_tap.attack.a2dp.resolve_hfp_source", lambda mac: "bluez_input.AA_BB_CC_DD_EE_FF.0")
    monkeypatch.setattr("blue_tap.attack.a2dp.subprocess.Popen", lambda *args, **kwargs: FakeProc())
    monkeypatch.setattr("blue_tap.attack.a2dp.time.sleep", lambda *_: None)

    result = record_car_mic("AA:BB:CC:DD:EE:FF", str(output), duration=1, auto_setup=False)

    assert result == ""


def test_capture_a2dp_returns_empty_on_header_only_file(monkeypatch, tmp_path):
    output = tmp_path / "empty_a2dp.wav"

    class FakeProc:
        pid = 123

        def terminate(self):
            return None

        def wait(self, timeout=None):
            output.write_bytes(b"R" * 44)
            return 0

    monkeypatch.setattr("blue_tap.attack.a2dp._detect_source_rate", lambda source: 44100)
    monkeypatch.setattr("blue_tap.attack.a2dp.subprocess.Popen", lambda *args, **kwargs: FakeProc())
    monkeypatch.setattr("blue_tap.attack.a2dp.time.sleep", lambda *_: None)

    result = capture_a2dp(None, str(output), duration=1, source="bluez_source.demo")

    assert result == ""


def test_play_to_car_returns_false_on_timeout(monkeypatch):
    import subprocess

    monkeypatch.setattr("blue_tap.attack.a2dp.os.path.exists", lambda path: True)
    monkeypatch.setattr("blue_tap.attack.a2dp.set_profile_a2dp", lambda mac: True)
    monkeypatch.setattr("blue_tap.attack.a2dp.set_sink_volume", lambda sink, volume_pct=80: True)
    monkeypatch.setattr("blue_tap.attack.a2dp.time.sleep", lambda *_: None)

    def _raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="paplay", timeout=600)

    monkeypatch.setattr("blue_tap.attack.a2dp.subprocess.run", _raise_timeout)

    assert play_to_car("AA:BB:CC:DD:EE:FF", "tone.wav") is False


def test_hfp_capture_logs_failed_audio_envelope(monkeypatch):
    recorded = {}

    class FakeHFPClient:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def setup_slc(self):
            return True

        def capture_audio(self, output_file="hfp_capture.wav", duration=60):
            return ""

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.recon.sdp.find_service_channel", lambda *args, **kwargs: 7)
    monkeypatch.setattr("blue_tap.attack.hfp.HFPClient", FakeHFPClient)
    monkeypatch.setattr(
        "blue_tap.utils.env_doctor.detect_profile_environment",
        lambda: {
            "summary": {
                "capability_limitations": [
                    "pactl is unavailable; host audio routing/profile switching cannot be controlled"
                ]
            }
        },
    )
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["hfp", "capture", "AA:BB:CC:DD:EE:FF", "-o", "missing.wav", "-d", "1"])

    assert result.exit_code == 0
    assert recorded["command"] == "hfp_capture"
    assert recorded["category"] == "audio"
    assert recorded["data"]["module"] == "audio"
    assert recorded["data"]["executions"][0]["module_outcome"] == "failed"
    assert recorded["data"]["executions"][0]["evidence"]["capability_limitations"] == [
        "pactl is unavailable; host audio routing/profile switching cannot be controlled"
    ]


def test_audio_play_logs_audio_module_failure(monkeypatch):
    recorded = {}

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.attack.a2dp.play_to_car", lambda mac, audio_file, volume_pct=80: False)
    monkeypatch.setattr(
        "blue_tap.utils.env_doctor.detect_profile_environment",
        lambda: {
            "summary": {
                "capability_limitations": [
                    "No active PipeWire/PulseAudio user service detected; audio capture/playback commands may not function"
                ]
            }
        },
    )
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["audio", "play", "AA:BB:CC:DD:EE:FF", "tone.wav"])

    assert result.exit_code == 0
    assert recorded["command"] == "audio_play"
    assert recorded["category"] == "audio"
    assert recorded["data"]["module"] == "audio"
    assert recorded["data"]["executions"][0]["module_outcome"] == "failed"
    assert recorded["data"]["executions"][0]["protocol"] == "A2DP"
    assert recorded["data"]["executions"][0]["evidence"]["capability_limitations"] == [
        "No active PipeWire/PulseAudio user service detected; audio capture/playback commands may not function"
    ]


def test_pbap_size_logs_standardized_data_envelope(monkeypatch):
    recorded = {}

    class FakePBAPClient:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def resolve_path_selection(self, **kwargs):
            return "SIM1/telecom/pb.vcf"

        def get_phonebook_size(self, path: str):
            return 42

        def get_selected_metadata(self, path: str, *, refresh_version: bool = False):
            return {"database_identifier": "A1" * 16}

        def normalize_location(self, location: str | None):
            return "sim1"

        def normalize_phonebook_name(self, phonebook: str | None):
            return "pb"

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.recon.sdp.find_service_channel", lambda *args, **kwargs: 19)
    monkeypatch.setattr("blue_tap.attack.pbap.PBAPClient", FakePBAPClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["pbap", "size", "AA:BB:CC:DD:EE:FF", "--location", "sim", "--phonebook", "pb"])

    assert result.exit_code == 0
    assert recorded["command"] == "pbap_size"
    assert recorded["category"] == "data"
    assert recorded["data"]["summary"]["entries"] == 42
    assert recorded["data"]["module_data"]["selected_metadata"]["database_identifier"]


def test_pbap_list_logs_standardized_data_envelope(monkeypatch):
    recorded = {}

    class FakePBAPClient:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def pull_vcard_listing(self, path: str, **kwargs):
            return (
                '<?xml version="1.0"?><vCard-listing version="1.0">'
                '<card handle="1.vcf" name="Alice Example"/>'
                "</vCard-listing>"
            )

        def resolve_path_selection(self, **kwargs):
            return "telecom/pb"

        def parse_vcard_listing(self, listing_xml: str):
            return [{"handle": "1.vcf", "name": "Alice Example"}]

        def normalize_path(self, path: str, *, prefer_listing: bool = False):
            return "telecom/pb" if prefer_listing else "telecom/pb.vcf"

        def get_selected_metadata(self, path: str, *, refresh_version: bool = False):
            return {}

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.recon.sdp.find_service_channel", lambda *args, **kwargs: 19)
    monkeypatch.setattr("blue_tap.attack.pbap.PBAPClient", FakePBAPClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["pbap", "list", "AA:BB:CC:DD:EE:FF", "-p", "contacts"])

    assert result.exit_code == 0
    assert recorded["command"] == "pbap_list"
    assert recorded["category"] == "data"
    assert recorded["data"]["module"] == "data"
    assert recorded["data"]["summary"]["entries"] == 1


def test_pbap_search_logs_query_and_matches(monkeypatch):
    recorded = {}

    class FakePBAPClient:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def search_phonebook(self, query: str, search_by: str = "name", path: str = "telecom/pb"):
            return (
                '<?xml version="1.0"?><vCard-listing version="1.0">'
                '<card handle="7.vcf" name="Alice Example"/>'
                "</vCard-listing>"
            )

        def resolve_path_selection(self, **kwargs):
            return "telecom/pb"

        def parse_vcard_listing(self, listing_xml: str):
            return [{"handle": "7.vcf", "name": "Alice Example"}]

        def normalize_path(self, path: str, *, prefer_listing: bool = False):
            return "telecom/pb" if prefer_listing else "telecom/pb.vcf"

        def get_selected_metadata(self, path: str, *, refresh_version: bool = False):
            return {}

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.recon.sdp.find_service_channel", lambda *args, **kwargs: 19)
    monkeypatch.setattr("blue_tap.attack.pbap.PBAPClient", FakePBAPClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["pbap", "search", "AA:BB:CC:DD:EE:FF", "Alice"])

    assert result.exit_code == 0
    assert recorded["command"] == "pbap_search"
    assert recorded["category"] == "data"
    assert recorded["data"]["summary"]["query"] == "Alice"
    assert recorded["data"]["summary"]["matches"] == 1


def test_pbap_pull_writes_summary_json_sidecar(monkeypatch, tmp_path):
    recorded = {}

    class FakePBAPClient:
        def __init__(self, address: str, channel: int | None = None):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def resolve_path_selection(self, **kwargs):
            return "telecom/pb.vcf"

        def build_filter_bits(self, fields):
            return None

        def pull_phonebook(self, *args, **kwargs):
            return (
                "BEGIN:VCARD\r\n"
                "VERSION:3.0\r\n"
                "FN:Alice Example\r\n"
                "TEL:+123456\r\n"
                "END:VCARD\r\n"
            )

        def normalize_path(self, path: str, *, prefer_listing: bool = False):
            return "telecom/pb" if prefer_listing else "telecom/pb.vcf"

        def summarize_phonebook(self, data: str):
            return {"entries": 1, "entries_data": [{"full_name": "Alice Example"}]}

        def get_selected_metadata(self, path: str, *, refresh_version: bool = False):
            return {"database_identifier": "B2" * 16, "version_refresh_attempted": refresh_version}

        def normalize_location(self, location: str | None):
            return "int"

        def normalize_phonebook_name(self, phonebook: str | None):
            return "pb"

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.recon.sdp.find_service_channel", lambda *args, **kwargs: 19)
    monkeypatch.setattr("blue_tap.attack.pbap.PBAPClient", FakePBAPClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(
        main,
        ["pbap", "pull", "AA:BB:CC:DD:EE:FF", "-o", str(tmp_path), "--refresh-version"],
    )

    assert result.exit_code == 0
    assert recorded["command"] == "pbap_pull"
    summary_path = tmp_path / "telecom_pb.vcf.json"
    assert summary_path.exists()


def test_opp_push_logs_failed_attack_envelope(monkeypatch, tmp_path):
    recorded = {}
    payload = tmp_path / "contact.vcf"
    payload.write_text("BEGIN:VCARD\nEND:VCARD\n")

    class FakeOPPClient:
        def __init__(self, address: str, channel: int):
            self.address = address
            self.channel = channel
            self.last_backend = "dbus"
            self.last_connect_error = ""
            self.last_transfer = {"status": "failed", "error": "remote rejected push"}

        def connect(self):
            return True

        def push_file(self, filepath: str):
            return False

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.recon.sdp.find_service_channel", lambda *args, **kwargs: 9)
    monkeypatch.setattr("blue_tap.attack.opp.OPPClient", FakeOPPClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["opp", "push", "AA:BB:CC:DD:EE:FF", str(payload)])

    assert result.exit_code == 0
    assert recorded["command"] == "opp_push"
    assert recorded["data"]["module"] == "attack"
    assert recorded["data"]["executions"][0]["module_outcome"] == "failed"


def test_avrcp_play_logs_failed_attack_envelope(monkeypatch):
    recorded = {}

    class FakeAVRCPController:
        def __init__(self, address: str, hci: str = "hci0"):
            self.address = address
            self.hci = hci

        def connect(self):
            return True

        def play(self):
            return False

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.attack.avrcp.AVRCPController", FakeAVRCPController)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["avrcp", "play", "AA:BB:CC:DD:EE:FF"])

    assert result.exit_code == 0
    assert recorded["command"] == "avrcp_play"
    assert recorded["data"]["module"] == "attack"
    assert recorded["data"]["executions"][0]["module_outcome"] == "failed"


def test_at_connect_logs_standardized_data_envelope(monkeypatch):
    recorded = {}

    class FakeATClient:
        def __init__(self, address: str, channel: int = 1):
            self.address = address
            self.channel = channel

        def connect(self):
            return True

        def send_at(self, command: str):
            return "OK"

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.attack.bluesnarfer.ATClient", FakeATClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["at", "connect", "AA:BB:CC:DD:EE:FF"], input="quit\n")

    assert result.exit_code == 0
    assert recorded["command"] == "at_connect"
    assert recorded["category"] == "data"
    assert recorded["data"]["module"] == "data"
    assert recorded["data"]["summary"]["operation"] == "at_connect"


def test_at_dump_logs_failed_data_envelope_when_no_meaningful_data(monkeypatch, tmp_path):
    recorded = {}

    class FakeATClient:
        def __init__(self, address: str, channel: int = 1):
            self.address = address
            self.channel = channel
            self.last_capability_limitations = ["AT+CGSN did not return a parseable IMEI"]

        def connect(self):
            return True

        def dump_all(self, output_dir: str = "at_dump"):
            return {
                "device_info": {
                    "imei": "",
                    "imsi": "",
                    "subscriber_numbers": [],
                    "operator": {"operator": ""},
                    "signal": {"rssi": None, "ber": None},
                    "battery": {"level_percent": None, "millivolts": None},
                }
            }

        def disconnect(self):
            return None

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.attack.bluesnarfer.ATClient", FakeATClient)
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["at", "dump", "AA:BB:CC:DD:EE:FF", "-o", str(tmp_path)])

    assert result.exit_code == 0
    assert recorded["command"] == "at_dump"
    assert recorded["data"]["executions"][0]["module_outcome"] == "failed"
    assert recorded["data"]["executions"][0]["evidence"]["capability_limitations"] == [
        "AT+CGSN did not return a parseable IMEI"
    ]


def test_at_snarf_logs_failure_capability_limitation(monkeypatch):
    recorded = {}

    monkeypatch.setattr("blue_tap.cli.resolve_address", lambda address=None, prompt=None: "AA:BB:CC:DD:EE:FF")
    monkeypatch.setattr("blue_tap.attack.bluesnarfer.bluesnarfer_extract", lambda *args, **kwargs: "")
    monkeypatch.setattr(
        "blue_tap.utils.session.log_command",
        lambda command, data, category="general", target="": recorded.update(
            {"command": command, "data": data, "category": category, "target": target}
        ),
    )

    result = CliRunner().invoke(main, ["at", "snarf", "AA:BB:CC:DD:EE:FF"])

    assert result.exit_code == 0
    assert recorded["command"] == "at_snarf"
    assert recorded["data"]["executions"][0]["module_outcome"] == "failed"
    assert recorded["data"]["executions"][0]["evidence"]["capability_limitations"] == [
        "bluesnarfer extraction failed or the bluesnarfer binary is unavailable on this host"
    ]
