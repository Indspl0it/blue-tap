from __future__ import annotations

import click
from click.testing import CliRunner

from blue_tap.modules.fuzzing import cli_extra


def _build_fuzz_cli() -> click.Group:
    @click.group()
    def fuzz() -> None:
        pass

    cli_extra.register_extra_commands(fuzz)
    return fuzz


def test_at_deep_all_routes_across_protocol_surfaces(monkeypatch):
    calls: list[tuple[str, dict | None]] = []

    monkeypatch.setattr(cli_extra, "resolve_address", lambda value: value)
    monkeypatch.setattr(cli_extra, "_show_fuzz_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(cli_extra, "_current_adapter", lambda: "hci1")
    monkeypatch.setattr(cli_extra, "_discover_at_surface_channels", lambda address, fallback_channel: {
        "hfp": 7,
        "phonebook": 8,
        "sms": 9,
        "injection": 10,
    })

    monkeypatch.setattr(cli_extra, "_run_via_engine", lambda address, protocol, cases, session_dir="", delay=0.5, timeout=5.0, transport_override=None: (
        calls.append((protocol, transport_override)),
        {"sent": len(cases), "crashes": 0, "errors": 0, "elapsed": 0.0, "total_cases": len(cases), "logged_by_engine": True},
    )[1])

    class FakeATCorpus:
        @staticmethod
        def generate_hfp_slc_corpus():
            return [b"a"]

        @staticmethod
        def generate_hfp_call_corpus():
            return [b"b"]

        @staticmethod
        def generate_hfp_query_corpus():
            return [b"c"]

        @staticmethod
        def generate_phonebook_corpus():
            return [b"d"]

        @staticmethod
        def generate_sms_corpus():
            return [b"e"]

        @staticmethod
        def generate_injection_corpus():
            return [b"f"]

        @staticmethod
        def generate_surface_injection_corpus(surface):
            return [surface.encode()]

        @staticmethod
        def generate_device_info_corpus():
            return [b"g"]

        @staticmethod
        def corpus_stats():
            return {
                "hfp_slc": 1,
                "hfp_call": 1,
                "hfp_query": 1,
                "phonebook": 1,
                "sms": 1,
                "injection": 1,
                "device_info": 1,
            }

    monkeypatch.setattr("blue_tap.modules.fuzzing.protocols.at_commands.ATCorpus", FakeATCorpus)

    runner = CliRunner()
    result = runner.invoke(_build_fuzz_cli(), ["at-deep", "AA:BB:CC:DD:EE:FF", "--category", "all", "--channel", "7", "--no-autodiscover"])
    assert result.exit_code == 0, result.output
    assert [protocol for protocol, _ in calls] == [
        "at-hfp",
        "at-hfp",
        "at-hfp",
        "at-hfp",
        "at-phonebook",
        "at-sms",
        "at-hfp",
        "at-phonebook",
        "at-sms",
    ]
    assert calls[0][1] == {"channel": 7}
    assert calls[4][1] == {"channel": 7}


def test_l2cap_sig_uses_raw_acl_engine_protocol(monkeypatch):
    calls: list[tuple[str, dict | None]] = []

    monkeypatch.setattr(cli_extra, "resolve_address", lambda value: value)
    monkeypatch.setattr(cli_extra, "_show_fuzz_summary", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        cli_extra,
        "_run_via_engine",
        lambda address, protocol, cases, session_dir="", delay=0.5, timeout=5.0, transport_override=None: (
            calls.append((protocol, transport_override)),
            {"sent": len(cases), "crashes": 0, "errors": 0, "elapsed": 0.0, "total_cases": len(cases), "logged_by_engine": True},
        )[1],
    )
    monkeypatch.setattr("blue_tap.modules.fuzzing.protocols.l2cap_raw.generate_all_l2cap_sig_fuzz_cases", lambda: [b"sig"])

    runner = CliRunner()
    result = runner.invoke(_build_fuzz_cli(), ["l2cap-sig", "AA:BB:CC:DD:EE:FF", "--hci", "hci3"])
    assert result.exit_code == 0, result.output
    assert calls == [("l2cap-sig", {"hci_dev": 3})]
