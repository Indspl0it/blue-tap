"""Tests for fuzz CLI batch orchestration helpers."""
from __future__ import annotations

from blue_tap.modules.fuzzing import cli_extra


def test_run_protocol_batch_aggregates_per_protocol_results(monkeypatch):
    calls: list[tuple[str, dict | None]] = []

    def fake_run_via_engine(address, protocol, cases, session_dir="", delay=0.5, timeout=5.0, transport_override=None):
        calls.append((protocol, transport_override))
        return {
            "sent": len(cases),
            "crashes": 1 if protocol == "at-injection" else 0,
            "errors": 0,
            "elapsed": 0.25,
            "total_cases": len(cases),
            "crash_db_path": f"/tmp/{protocol}.db",
        }

    monkeypatch.setattr(cli_extra, "_run_via_engine", fake_run_via_engine)

    result = cli_extra._run_protocol_batch(
        "AA:BB:CC:DD:EE:FF",
        runs=[
            ("at-hfp", [b"AT\r"], {"channel": 7}),
            ("at-phonebook", [b"AT+CPBR=1\r"], None),
            ("at-injection", [b"AT+CMD=\r"], None),
        ],
    )

    assert result["sent"] == 3
    assert result["crashes"] == 1
    assert result["errors"] == 0
    assert result["protocols"]["at-hfp"]["sent"] == 1
    assert result["protocols"]["at-injection"]["crashes"] == 1
    assert calls[0] == ("at-hfp", {"channel": 7})


def test_run_protocol_batch_preserves_distinct_run_names(monkeypatch):
    monkeypatch.setattr(
        cli_extra,
        "_run_via_engine",
        lambda address, protocol, cases, session_dir="", delay=0.5, timeout=5.0, transport_override=None: {
            "sent": len(cases),
            "crashes": 0,
            "errors": 0,
            "elapsed": 0.1,
            "total_cases": len(cases),
            "logged_by_engine": True,
        },
    )

    result = cli_extra._run_protocol_batch(
        "AA:BB:CC:DD:EE:FF",
        runs=[
            {"name": "hfp-slc", "protocol": "at-hfp", "cases": [b"AT+BRSF=0\r"], "transport_override": {"channel": 10}},
            {"name": "hfp-call", "protocol": "at-hfp", "cases": [b"ATD123;\r"], "transport_override": {"channel": 10}},
        ],
    )

    assert set(result["protocols"]) == {"hfp-slc", "hfp-call"}
    assert result["protocols"]["hfp-slc"]["protocol"] == "at-hfp"
