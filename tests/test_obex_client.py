from __future__ import annotations

from pathlib import Path

from blue_tap.hardware.obex_client import MAPSession, OPPSession, PBAPSession, ObexSession, detect_obex_capability, variant_to_python


class FakeClientInterface:
    def __init__(self, bus):
        self.bus = bus

    async def call_create_session(self, destination, args):
        self.bus.create_session_calls.append((destination, args))
        return "/org/bluez/obex/client/session0"

    async def call_remove_session(self, session_path):
        self.bus.removed_sessions.append(session_path)


class FakeSessionInterface:
    async def call_get_capabilities(self):
        return "pbap,map,opp"


class FakePBAPInterface:
    def __init__(self, bus):
        self.bus = bus

    async def call_select(self, location, phonebook):
        self.bus.selected.append((location, phonebook))

    async def call_list(self, filters):
        self.bus.list_filters.append(filters)
        return [{"handle": "1.vcf", "name": "Alice Example"}]

    async def call_search(self, field, value, filters):
        self.bus.search_calls.append((field, value, filters))
        return [("7.vcf", "Alice Example")]

    async def call_pull_all(self, targetfile, filters):
        self.bus.pull_all_calls.append((targetfile, filters))
        return ("/org/bluez/obex/client/session0/transfer0", {"Filename": targetfile})

    async def call_pull(self, vcard, targetfile, filters):
        self.bus.pull_calls.append((vcard, targetfile, filters))
        return ("/org/bluez/obex/client/session0/transfer1", {"Filename": targetfile})

    async def call_get_size(self):
        return 42


class FakePropertiesInterface:
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path

    async def call_get_all(self, interface_name):
        if interface_name == "org.bluez.obex.Session1":
            return {
                "Destination": "AA:BB:CC:DD:EE:FF",
                "Channel": 19,
                "Target": "pbap",
            }
        if interface_name == "org.bluez.obex.Transfer1":
            states = self.bus.transfer_states.setdefault(self.path, [{"Status": "complete"}])
            if len(states) > 1:
                return states.pop(0)
            return states[0]
        if interface_name == "org.bluez.obex.PhonebookAccess1":
            return {"Folder": "pb"}
        if interface_name == "org.bluez.obex.Message1":
            return {"Subject": "hi", "Type": "sms-gsm"}
        return {}


class FakeProxyObject:
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path

    def get_interface(self, interface_name):
        if interface_name == "org.bluez.obex.Client1":
            return FakeClientInterface(self.bus)
        if interface_name == "org.bluez.obex.Session1":
            return FakeSessionInterface()
        if interface_name == "org.bluez.obex.PhonebookAccess1":
            return FakePBAPInterface(self.bus)
        if interface_name == "org.bluez.obex.MessageAccess1":
            return FakeMAPInterface(self.bus)
        if interface_name == "org.bluez.obex.Message1":
            return FakeMessageInterface(self.bus, self.path)
        if interface_name == "org.bluez.obex.ObjectPush1":
            return FakeOPPInterface(self.bus)
        if interface_name == "org.freedesktop.DBus.Properties":
            return FakePropertiesInterface(self.bus, self.path)
        raise AssertionError(f"Unexpected interface requested: {interface_name}")


class FakeMAPInterface:
    def __init__(self, bus):
        self.bus = bus

    async def call_set_folder(self, name):
        self.bus.set_folder_calls.append(name)

    async def call_list_messages(self, folder, filters):
        self.bus.map_list_calls.append((folder, filters))
        return [
            ("/org/bluez/obex/client/session0/message0", {"Subject": "Hi", "Sender": "Alice", "handle": "200001"}),
        ]

    async def call_list_folders(self, filters):
        return [{"Name": "inbox"}, {"Name": "sent"}]

    async def call_list_filter_fields(self):
        return ["Subject", "Sender", "Recipient"]

    async def call_update_inbox(self):
        self.bus.update_inbox_calls += 1

    async def call_push_message(self, sourcefile, folder, args):
        self.bus.map_push_calls.append((sourcefile, folder, args))
        return ("/org/bluez/obex/client/session0/transfer4", {"Filename": sourcefile})


class FakeMessageInterface:
    def __init__(self, bus, path):
        self.bus = bus
        self.path = path

    async def call_get(self, targetfile, attachment):
        self.bus.message_get_calls.append((self.path, targetfile, attachment))
        return ("/org/bluez/obex/client/session0/transfer2", {"Filename": targetfile})

    async def set_read(self, value):
        self.bus.message_flag_sets.append((self.path, "read", value))

    async def set_deleted(self, value):
        self.bus.message_flag_sets.append((self.path, "deleted", value))


class FakeOPPInterface:
    def __init__(self, bus):
        self.bus = bus

    async def call_send_file(self, sourcefile):
        self.bus.opp_send_calls.append(sourcefile)
        return ("/org/bluez/obex/client/session0/transfer3", {"Filename": sourcefile})


class FakeBus:
    def __init__(self):
        self.create_session_calls = []
        self.removed_sessions = []
        self.selected = []
        self.list_filters = []
        self.search_calls = []
        self.pull_all_calls = []
        self.pull_calls = []
        self.set_folder_calls = []
        self.map_list_calls = []
        self.update_inbox_calls = 0
        self.message_get_calls = []
        self.map_push_calls = []
        self.message_flag_sets = []
        self.opp_send_calls = []
        self.transfer_states = {
            "/org/bluez/obex/client/session0/transfer0": [
                {"Status": "active", "Transferred": 5},
                {"Status": "complete", "Filename": "/tmp/pb.vcf", "Transferred": 20},
            ],
            "/org/bluez/obex/client/session0/transfer2": [
                {"Status": "complete", "Filename": "/tmp/message.bmsg", "Transferred": 40},
            ],
            "/org/bluez/obex/client/session0/transfer3": [
                {"Status": "complete", "Filename": "/tmp/contact.vcf", "Transferred": 24},
            ],
            "/org/bluez/obex/client/session0/transfer4": [
                {"Status": "complete", "Filename": "/tmp/push.bmsg", "Transferred": 32},
            ],
        }
        self.disconnected = False

    async def introspect(self, service, path):
        return {"service": service, "path": path}

    def get_proxy_object(self, service, path, introspection):
        return FakeProxyObject(self, path)

    def disconnect(self):
        self.disconnected = True


def test_obex_session_connect_wait_and_disconnect():
    bus = FakeBus()
    session = ObexSession(
        "AA:BB:CC:DD:EE:FF",
        target="pbap",
        channel=19,
        bus_factory=lambda: bus,
    )

    assert session.connect() is True
    assert session.session_path == "/org/bluez/obex/client/session0"
    assert session.session_props["Channel"] == 19

    props = session.wait_for_transfer("/org/bluez/obex/client/session0/transfer0", timeout=1.0, poll_interval=0.0)
    assert props["Status"] == "complete"
    assert props["Filename"] == "/tmp/pb.vcf"

    session.disconnect()
    assert bus.removed_sessions == ["/org/bluez/obex/client/session0"]
    assert bus.disconnected is True


def test_obex_session_tempfile_and_finalize_helpers(tmp_path):
    bus = FakeBus()
    session = ObexSession(
        "AA:BB:CC:DD:EE:FF",
        target="pbap",
        channel=19,
        bus_factory=lambda: bus,
    )
    assert session.connect() is True

    temp_path = session.create_temp_file_path(prefix="blue_tap_test_", suffix=".txt")
    Path(temp_path).write_text("hello", encoding="utf-8")

    filename, final_props = session.finalize_transfer_file(
        "/org/bluez/obex/client/session0/transfer0",
        {"Filename": temp_path},
        fallback_path=temp_path,
        timeout=1.0,
        poll_interval=0.0,
    )
    assert filename == "/tmp/pb.vcf"
    Path(filename).write_text("payload", encoding="utf-8")
    assert session.read_text_file(filename) == "payload"
    assert final_props["Status"] == "complete"


def test_pbap_session_select_list_search_and_pull():
    bus = FakeBus()
    session = PBAPSession("AA:BB:CC:DD:EE:FF", channel=19, bus_factory=lambda: bus)

    assert session.connect() is True
    session.select("int", "pb")
    assert bus.selected == [("int", "pb")]

    listing = session.list({"Order": "alphanumeric", "MaxCount": 10})
    assert listing == [{"handle": "1.vcf", "name": "Alice Example"}]

    search = session.search("name", "Alice", {"MaxCount": 5})
    assert search == [{"handle": "7.vcf", "name": "Alice Example"}]

    transfer_path, props = session.pull_all("/tmp/pb.vcf", {"Format": "vcard30"})
    assert transfer_path.endswith("transfer0")
    assert props["Filename"] == "/tmp/pb.vcf"

    entry_path, entry_props = session.pull("7.vcf", "/tmp/7.vcf", {"Format": "vcard30"})
    assert entry_path.endswith("transfer1")
    assert entry_props["Filename"] == "/tmp/7.vcf"

    assert session.get_size() == 42


def test_detect_obex_capability_reports_available_client_interface():
    capability = detect_obex_capability(bus_factory=lambda: FakeBus())

    assert capability["dbus_fast_available"] is True
    assert capability["obex_service_reachable"] is True
    assert capability["client_interface_available"] is True
    assert capability["errors"] == []


def test_map_session_lists_messages_and_fetches_message():
    bus = FakeBus()
    session = MAPSession("AA:BB:CC:DD:EE:FF", channel=20, bus_factory=lambda: bus)

    assert session.connect() is True
    session.set_folder("inbox")
    assert bus.set_folder_calls == ["inbox"]

    messages = session.list_messages("inbox", {"MaxCount": 10})
    assert messages[0]["path"].endswith("message0")
    assert messages[0]["Subject"] == "Hi"

    transfer_path, props = session.get_message("/org/bluez/obex/client/session0/message0", "/tmp/message.bmsg")
    assert transfer_path.endswith("transfer2")
    assert props["Filename"] == "/tmp/message.bmsg"


def test_map_session_pushes_message_and_sets_flags():
    bus = FakeBus()
    session = MAPSession("AA:BB:CC:DD:EE:FF", channel=20, bus_factory=lambda: bus)

    assert session.connect() is True
    transfer_path, props = session.push_message("/tmp/push.bmsg", "", {"Transparent": False, "Retry": True, "Charset": "UTF-8"})
    assert transfer_path.endswith("transfer4")
    assert props["Filename"] == "/tmp/push.bmsg"
    sourcefile, folder, args = bus.map_push_calls[0]
    assert sourcefile == "/tmp/push.bmsg"
    assert folder == ""
    assert variant_to_python(args) == {"Transparent": False, "Retry": True, "Charset": "UTF-8"}

    session.set_message_read("/org/bluez/obex/client/session0/message0", True)
    session.set_message_deleted("/org/bluez/obex/client/session0/message0", False)
    assert bus.message_flag_sets == [
        ("/org/bluez/obex/client/session0/message0", "read", True),
        ("/org/bluez/obex/client/session0/message0", "deleted", False),
    ]


def test_opp_session_sends_file():
    bus = FakeBus()
    session = OPPSession("AA:BB:CC:DD:EE:FF", channel=9, bus_factory=lambda: bus)

    assert session.connect() is True
    transfer_path, props = session.send_file("/tmp/contact.vcf")
    assert transfer_path.endswith("transfer3")
    assert props["Filename"] == "/tmp/contact.vcf"
    assert bus.opp_send_calls == ["/tmp/contact.vcf"]
