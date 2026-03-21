import pytest

from blue_tap.utils.bt_helpers import normalize_mac, validate_mac


def test_validate_mac_accepts_standard_mac() -> None:
    assert validate_mac("AA:BB:CC:DD:EE:FF")


def test_validate_mac_rejects_invalid_mac() -> None:
    assert not validate_mac("AA:BB:CC:DD:EE")


def test_normalize_mac_converts_dash_to_colon_uppercase() -> None:
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"


def test_normalize_mac_raises_on_invalid_input() -> None:
    with pytest.raises(ValueError):
        normalize_mac("not-a-mac")
