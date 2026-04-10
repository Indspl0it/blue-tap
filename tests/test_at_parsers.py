from __future__ import annotations

from pathlib import Path

from blue_tap.attack.bluesnarfer import ATClient


FIXTURES = Path(__file__).parent / "fixtures" / "profiles"


def _fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_parse_phonebook_response_from_fixture():
    parsed = ATClient.parse_phonebook_response(_fixture_text("at_cpbr_response.txt"))

    assert parsed == [
        {"index": "1", "number": "+1234567890", "type": "145", "name": "Alice Example"},
        {"index": "2", "number": "5551234", "type": "129", "name": "Bob Example"},
    ]


def test_parse_sms_response_from_fixture():
    parsed = ATClient.parse_sms_response(_fixture_text("at_cmgl_response.txt"))

    assert parsed[0]["index"] == "1"
    assert parsed[0]["status"] == "REC READ"
    assert parsed[0]["sender"] == "+1234567890"
    assert parsed[0]["body"] == "hello world"
    assert parsed[1]["body"] == "line one\nline two"


def test_parse_battery_signal_operator_and_subscriber_from_fixtures():
    battery = ATClient.parse_battery_response(_fixture_text("at_cbc_response.txt"))
    signal = ATClient.parse_signal_response(_fixture_text("at_csq_response.txt"))
    operator = ATClient.parse_operator_response(_fixture_text("at_cops_response.txt"))
    subscribers = ATClient.parse_subscriber_response(_fixture_text("at_cnum_response.txt"))

    assert battery["level_percent"] == 85
    assert battery["millivolts"] == 4100
    assert signal == {"raw": _fixture_text("at_csq_response.txt").strip(), "rssi": 18, "ber": 3}
    assert operator["operator"] == "ExampleTel"
    assert operator["access_technology"] == 7
    assert subscribers == [
        {"label": "Voice", "number": "+1234567890", "type": 145, "speed": "7"},
        {"label": "Alt", "number": "+1987654321", "type": 129, "speed": ""},
    ]


def test_response_indicates_success_rejects_error_variants():
    assert ATClient.response_indicates_success("OK\r\n") is True
    assert ATClient.response_indicates_success("+CSQ: 18,3\r\n\r\nOK\r\n") is True
    assert ATClient.response_indicates_success('+CPBR: 1,"123",129,"A"\r\n') is True
    assert ATClient.response_indicates_success("ERROR\r\n") is False
    assert ATClient.response_indicates_success("NO CARRIER\r\n") is False
    assert ATClient.response_indicates_success("RING\r\n") is False
    assert ATClient.response_indicates_success("") is False
