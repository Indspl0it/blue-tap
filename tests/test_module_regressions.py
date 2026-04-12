from __future__ import annotations

import socket

from blue_tap.modules.assessment.checks import cve_ble_smp as cve_checks_ble_smp, cve_l2cap as cve_checks_l2cap
from blue_tap.modules.exploitation.dos import protocol_dos
from blue_tap.hardware import scanner


class FakeSocket:
    def __init__(self, *, fail_connect: bool = False, fail_recv: bool = False):
        self.fail_connect = fail_connect
        self.fail_recv = fail_recv
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, target):
        if self.fail_connect:
            raise OSError("connect failed")

    def sendall(self, data):
        self.data = data

    def send(self, data):
        self.data = data
        return len(data)

    def recv(self, size):
        if self.fail_recv:
            raise OSError("recv failed")
        return b""

    def close(self):
        self.closed = True

    def fileno(self):
        return 1


def test_scan_result_helpers_emit_run_completed(monkeypatch):
    events = []

    monkeypatch.setattr(scanner, "emit_cli_event", lambda **kwargs: events.append(kwargs))
    monkeypatch.setattr(scanner, "scan_classic", lambda duration, hci: [{"address": "AA:BB:CC:DD:EE:FF"}])
    monkeypatch.setattr(scanner, "scan_ble_sync", lambda duration, passive=False, adapter="": [{"address": "11:22:33:44:55:66"}])
    monkeypatch.setattr(
        scanner,
        "_merge_scan_results",
        lambda classic, ble: (classic + ble, [{"classic_address": "AA:BB:CC:DD:EE:FF", "ble_address": "11:22:33:44:55:66"}]),
    )

    classic_result = scanner.scan_classic_result()
    ble_result = scanner.scan_ble_result_sync()
    all_result = scanner.scan_all_result()

    assert classic_result["module"] == "scan"
    assert ble_result["module"] == "scan"
    assert all_result["module"] == "scan"
    assert sum(1 for event in events if event["event_type"] == "run_completed") == 3


def test_connect_ble_smp_closes_socket_on_exception(monkeypatch):
    fake_sock = FakeSocket()

    monkeypatch.setattr(cve_checks_ble_smp, "_libc", object())
    monkeypatch.setattr(cve_checks_ble_smp.socket, "socket", lambda *args: fake_sock)

    result = cve_checks_ble_smp._connect_ble_smp("NOT-A-MAC")

    assert result is None
    assert fake_sock.closed is True


def test_connect_ble_fixed_channel_closes_socket_on_exception(monkeypatch):
    fake_sock = FakeSocket()

    monkeypatch.setattr(cve_checks_l2cap, "_libc", object())
    monkeypatch.setattr(cve_checks_l2cap.socket, "socket", lambda *args: fake_sock)

    result = cve_checks_l2cap._connect_ble_fixed_channel("NOT-A-MAC", cid=0x0005)

    assert result is None
    assert fake_sock.closed is True


def test_l2cap_heap_jitter_closes_socket_on_recv_failure(monkeypatch):
    sockets: list[FakeSocket] = []

    def fake_socket(*args):
        sock = FakeSocket(fail_recv=True)
        sockets.append(sock)
        return sock

    monkeypatch.setattr(cve_checks_l2cap.socket, "socket", fake_socket)
    monkeypatch.setattr(cve_checks_l2cap.time, "sleep", lambda _: None)

    cve_checks_l2cap._check_android_l2cap_heap_jitter("AA:BB:CC:DD:EE:FF")

    assert sockets
    assert all(sock.closed for sock in sockets)


def test_a2mp_heap_jitter_closes_socket_on_recv_failure(monkeypatch):
    sockets: list[FakeSocket] = []

    def fake_socket(*args):
        sock = FakeSocket(fail_recv=True)
        sockets.append(sock)
        return sock

    monkeypatch.setattr(cve_checks_l2cap.socket, "socket", fake_socket)
    monkeypatch.setattr(cve_checks_l2cap.time, "sleep", lambda _: None)

    cve_checks_l2cap._check_a2mp_heap_jitter("AA:BB:CC:DD:EE:FF")

    assert sockets
    assert all(sock.closed for sock in sockets)


def test_protocol_dos_l2cap_connect_closes_socket_on_connect_failure(monkeypatch):
    fake_sock = FakeSocket(fail_connect=True)

    monkeypatch.setattr(protocol_dos, "_l2cap_raw_socket", lambda hci="hci0": fake_sock)

    try:
        protocol_dos._l2cap_connect("AA:BB:CC:DD:EE:FF", protocol_dos.PSM_SDP)
    except OSError:
        pass
    else:
        raise AssertionError("expected OSError")

    assert fake_sock.closed is True


def test_protocol_dos_cid_exhaustion_closes_failed_socket(monkeypatch):
    created: list[FakeSocket] = []

    def fake_socket_factory(hci="hci0"):
        sock = FakeSocket(fail_connect=(len(created) == 1))
        created.append(sock)
        return sock

    monkeypatch.setattr(protocol_dos, "_l2cap_raw_socket", fake_socket_factory)
    monkeypatch.setattr(protocol_dos.time, "sleep", lambda _: None)

    protocol_dos.L2CAPDoS("AA:BB:CC:DD:EE:FF").cid_exhaustion(count=2)

    assert len(created) == 2
    assert created[1].closed is True


def test_protocol_dos_connect_flood_closes_failed_socket(monkeypatch):
    created: list[FakeSocket] = []

    def fake_socket(*args):
        sock = FakeSocket(fail_connect=(len(created) == 1))
        created.append(sock)
        return sock

    monkeypatch.setattr(protocol_dos.socket, "socket", fake_socket)
    monkeypatch.setattr(protocol_dos.OBEXDoS, "_find_obex_channels", lambda self: [3])
    monkeypatch.setattr(protocol_dos.time, "sleep", lambda _: None)

    protocol_dos.OBEXDoS("AA:BB:CC:DD:EE:FF").connect_flood(count=2)

    assert len(created) == 2
    assert created[1].closed is True


def test_protocol_dos_setpath_loop_closes_failed_channel_socket(monkeypatch):
    created: list[FakeSocket] = []

    def fake_socket(*args):
        sock = FakeSocket(fail_connect=(len(created) == 0))
        created.append(sock)
        return sock

    monkeypatch.setattr(protocol_dos.socket, "socket", fake_socket)
    monkeypatch.setattr(protocol_dos.OBEXDoS, "_find_obex_channels", lambda self: [3, 4])

    result = protocol_dos.OBEXDoS("AA:BB:CC:DD:EE:FF").setpath_loop(count=0)

    assert result["result"] == "success"
    assert len(created) >= 2
    assert created[0].closed is True
