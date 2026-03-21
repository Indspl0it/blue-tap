from blue_tap.utils.session import Session


def test_session_log_and_collect_by_category(tmp_path) -> None:
    session = Session("unit_session", base_dir=str(tmp_path))
    path = session.log("scan_classic", [{"address": "AA:BB:CC:DD:EE:FF"}], category="scan")
    assert path.endswith("001_scan_classic.json")

    collected = session.get_all_data()
    assert len(collected["scan"]) == 1
    assert collected["scan"][0]["command"] == "scan_classic"


def test_session_rejects_path_traversal_name(tmp_path) -> None:
    try:
        Session("../bad_name", base_dir=str(tmp_path))
    except ValueError:
        return
    raise AssertionError("Session should reject unsafe names")
