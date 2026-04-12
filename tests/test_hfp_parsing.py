from __future__ import annotations

from blue_tap.modules.post_exploitation.media.hfp import HFPClient


def test_hfp_indicator_mapping_is_one_based_and_ciev_updates_apply():
    client = HFPClient("AA:BB:CC:DD:EE:FF", channel=7)
    client._parse_indicator_mapping(
        '+CIND: ("service",(0,1)),("call",(0,1)),("callsetup",(0-3)),("battchg",(0-5))'
    )
    assert client.indicators == {"service": 1, "call": 2, "callsetup": 3, "battchg": 4}

    updates = client.parse_ciev_updates("+CIEV: 2,1\r\n+CIEV: 3,2\r\n")
    assert updates == [
        {"index": 2, "name": "call", "value": 1},
        {"index": 3, "name": "callsetup", "value": 2},
    ]

    client._ingest_unsolicited_response("+CIEV: 2,1\r\n+CIEV: 3,2\r\n")
    assert client.indicator_values["call"] == 1
    assert client.indicator_values["callsetup"] == 2


def test_hfp_parse_clip_response():
    parsed = HFPClient.parse_clip_response('+CLIP: "+1234567890",145,,,\"Alice Example\"')

    assert parsed == {"number": "+1234567890", "name": "Alice Example", "type": 145}


def test_hfp_parse_clcc_response():
    parsed = HFPClient.parse_clcc_response(
        '+CLCC: 1,1,0,0,0,"+1234567890",145\r\n+CLCC: 2,0,1,0,1\r\nOK\r\n'
    )

    assert parsed == [
        {
            "index": 1,
            "direction": 1,
            "status": 0,
            "mode": 0,
            "multiparty": 0,
            "number": "+1234567890",
            "type": 145,
        },
        {
            "index": 2,
            "direction": 0,
            "status": 1,
            "mode": 0,
            "multiparty": 1,
            "number": "",
            "type": None,
        },
    ]


def test_hfp_send_at_stops_on_busy_without_waiting_for_ok():
    client = HFPClient("AA:BB:CC:DD:EE:FF", channel=7)

    class FakeSock:
        def __init__(self):
            self.recv_calls = 0
            self.sent = []

        def send(self, data):
            self.sent.append(data)

        def recv(self, size):
            self.recv_calls += 1
            if self.recv_calls == 1:
                return b"\r\nBUSY\r\n"
            raise AssertionError("recv called after terminal BUSY response")

    client.rfcomm_sock = FakeSock()
    result = client.send_at("ATD123;")

    assert result == "BUSY"
    assert client.rfcomm_sock.recv_calls == 1
