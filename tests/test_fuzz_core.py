"""Comprehensive tests for fuzz core modules.

Covers: engine, transport, corpus, crash_db, mutators, minimizer,
pcap_replay, legacy.  All socket/hardware operations are mocked.
"""

from __future__ import annotations

import io
import json
import os
import random
import struct
import tempfile
import time
import warnings
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# ===================================================================
# Module imports
# ===================================================================

from blue_tap.fuzz.engine import (
    CampaignStats,
    FuzzCampaign,
    parse_duration,
    _format_duration,
    PROTOCOL_TRANSPORT_MAP,
    CRASH_SEVERITY,
)
from blue_tap.fuzz.transport import (
    BluetoothTransport,
    BLETransport,
    L2CAPTransport,
    RFCOMMTransport,
    TransportStats,
    AF_BLUETOOTH,
    BTPROTO_L2CAP,
    BTPROTO_RFCOMM,
)
from blue_tap.fuzz.corpus import Corpus, CorpusStats
from blue_tap.fuzz.crash_db import CrashDB, CrashSeverity, CrashType
from blue_tap.fuzz.mutators import (
    CorpusMutator,
    FieldMutator,
    IntegerMutator,
    LengthMutator,
    MutationLog,
    PacketField,
    ProtocolMutator,
    _serialise_value,
)
from blue_tap.fuzz.minimizer import (
    BinarySearchReducer,
    CrashMinimizer,
    DeltaDebugReducer,
    FieldReducer,
    MinimizationResult,
)
from blue_tap.fuzz.pcap_replay import (
    BtsnoopParser,
    BtsnoopRecord,
    CaptureReplayer,
    L2CAPFrame,
    classify_protocol,
    extract_l2cap_frames,
    import_btsnoop_to_corpus,
    _BTSNOOP_EPOCH_OFFSET,
)
from blue_tap.fuzz.legacy import (
    L2CAPFuzzer,
    RFCOMMFuzzer,
    SDPFuzzer,
    _check_target_alive,
    bss_wrapper,
)


# ===================================================================
# Helpers
# ===================================================================

def _make_btsnoop_file(records: list[tuple[bytes, int, int]], datalink: int = 1002) -> bytes:
    """Build a minimal btsnoop v1 file from (data, flags, timestamp) tuples."""
    buf = io.BytesIO()
    # Header: magic(8) + version(4) + datalink(4)
    buf.write(b"btsnoop\x00")
    buf.write(struct.pack(">II", 1, datalink))
    for data, flags, ts in records:
        orig_len = len(data)
        incl_len = len(data)
        drops = 0
        buf.write(struct.pack(">IIIIQ", orig_len, incl_len, flags, drops, ts))
        buf.write(data)
    return buf.getvalue()


def _make_acl_l2cap_packet(handle: int, cid: int, payload: bytes, pb_flag: int = 0b10) -> bytes:
    """Build a raw HCI ACL packet containing an L2CAP frame."""
    l2cap_hdr = struct.pack("<HH", len(payload), cid)
    acl_payload = l2cap_hdr + payload
    handle_field = (handle & 0x0FFF) | (pb_flag << 12)
    acl_hdr = struct.pack("<HH", handle_field, len(acl_payload))
    return acl_hdr + acl_payload


# ===================================================================
# TransportStats
# ===================================================================

class TestTransportStats:
    def test_defaults(self):
        s = TransportStats()
        assert s.bytes_sent == 0
        assert s.packets_sent == 0
        assert s.errors == 0
        assert s.reconnects == 0
        assert s.connection_drops == 0

    def test_packets_per_second(self):
        s = TransportStats()
        s.packets_sent = 100
        s.start_time = time.time() - 10
        pps = s.packets_per_second
        assert 9 <= pps <= 11

    def test_elapsed(self):
        s = TransportStats()
        s.start_time = time.time() - 5
        assert 4.5 <= s.elapsed <= 6.0

    def test_reset(self):
        s = TransportStats()
        s.bytes_sent = 100
        s.packets_sent = 50
        s.errors = 3
        s.reconnects = 2
        s.connection_drops = 1
        s.reset()
        assert s.bytes_sent == 0
        assert s.packets_sent == 0
        assert s.errors == 0
        assert s.reconnects == 0
        assert s.connection_drops == 0

    def test_to_dict(self):
        s = TransportStats()
        s.packets_sent = 10
        d = s.to_dict()
        assert "bytes_sent" in d
        assert "packets_per_second" in d
        assert "elapsed_seconds" in d
        assert d["packets_sent"] == 10


# ===================================================================
# L2CAPTransport (mocked sockets)
# ===================================================================

class TestL2CAPTransport:
    def test_init(self):
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=3)
        assert t.address == "AA:BB:CC:DD:EE:FF"
        assert t.psm == 3
        assert t.connected is False

    def test_repr(self):
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        r = repr(t)
        assert "L2CAPTransport" in r
        assert "psm=1" in r
        assert "disconnected" in r

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_connect_success(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        result = t.connect()
        assert result is True
        assert t.connected is True
        mock_sock.connect.assert_called_once_with(("AA:BB:CC:DD:EE:FF", 1))

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_connect_failure(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("Connection refused")
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        result = t.connect()
        assert result is False
        assert t.connected is False

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_send_success(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.send.return_value = 10
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        t.connect()
        sent = t.send(b"\x00" * 10)
        assert sent == 10
        assert t.stats.packets_sent == 1
        assert t.stats.bytes_sent == 10

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_send_not_connected_raises(self, mock_sock_cls):
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1, max_reconnects=0)
        with pytest.raises(ConnectionError):
            t.send(b"\x01")

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_send_broken_pipe(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.send.side_effect = BrokenPipeError("broken")
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        t.connect()
        with pytest.raises(BrokenPipeError):
            t.send(b"\x00")
        assert t.stats.errors == 1
        assert t.stats.connection_drops == 1
        assert t.connected is False

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_send_os_error_returns_zero(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.send.side_effect = OSError("generic")
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        t.connect()
        sent = t.send(b"\x00")
        assert sent == 0
        assert t.stats.errors == 1

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_recv_success(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x01\x02\x03"
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        t.connect()
        data = t.recv()
        assert data == b"\x01\x02\x03"
        assert t.stats.packets_received == 1
        assert t.stats.bytes_received == 3

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_recv_timeout(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        t.connect()
        data = t.recv()
        assert data == b""

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_recv_empty_means_closed(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        t.connect()
        data = t.recv()
        assert data is None
        assert t.connected is False

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_recv_not_connected(self, mock_sock_cls):
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        assert t.recv() is None

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_recv_with_custom_timeout(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\xff"
        mock_sock.gettimeout.return_value = 5.0
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        t.connect()
        data = t.recv(recv_timeout=1.0)
        assert data == b"\xff"
        mock_sock.settimeout.assert_any_call(1.0)

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_recv_connection_reset(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = ConnectionResetError
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        t.connect()
        data = t.recv()
        assert data is None
        assert t.stats.connection_drops == 1

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_close(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        t.connect()
        assert t.connected is True
        t.close()
        assert t.connected is False
        mock_sock.close.assert_called_once()

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_context_manager(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        with L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1) as t:
            assert t.connected is True
        assert t.connected is False

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_context_manager_connect_fail(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("fail")
        mock_sock_cls.return_value = mock_sock
        with pytest.raises(ConnectionError):
            with L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1) as t:
                pass

    @patch("blue_tap.fuzz.transport.run_cmd")
    def test_is_alive(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        assert t.is_alive() is True

    @patch("blue_tap.fuzz.transport.run_cmd")
    def test_is_alive_false(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="")
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1)
        assert t.is_alive() is False

    @patch("blue_tap.fuzz.transport.time.sleep")
    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_reconnect_success(self, mock_sock_cls, mock_sleep):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1, max_reconnects=2)
        result = t.reconnect()
        assert result is True
        assert t.stats.reconnects == 1

    @patch("blue_tap.fuzz.transport.time.sleep")
    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_reconnect_all_fail(self, mock_sock_cls, mock_sleep):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("fail")
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1, max_reconnects=2)
        result = t.reconnect()
        assert result is False

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_set_mtu(self, mock_sock_cls):
        mock_sock = MagicMock()
        # Return 12-byte struct for getsockopt
        mock_sock.getsockopt.return_value = struct.pack("<HHHBBBBH", 672, 672, 65535, 0, 0, 0, 0, 0)
        mock_sock_cls.return_value = mock_sock
        t = L2CAPTransport("AA:BB:CC:DD:EE:FF", psm=1, mtu=1024)
        t.connect()
        # Should have called setsockopt to set the MTU
        assert mock_sock.setsockopt.called


# ===================================================================
# RFCOMMTransport
# ===================================================================

class TestRFCOMMTransport:
    def test_init(self):
        t = RFCOMMTransport("AA:BB:CC:DD:EE:FF", channel=5)
        assert t.channel == 5
        assert t.address == "AA:BB:CC:DD:EE:FF"

    def test_repr(self):
        t = RFCOMMTransport("AA:BB:CC:DD:EE:FF", channel=3)
        r = repr(t)
        assert "RFCOMMTransport" in r
        assert "ch=3" in r

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_connect(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        t = RFCOMMTransport("AA:BB:CC:DD:EE:FF", channel=1)
        assert t.connect() is True
        mock_sock.connect.assert_called_with(("AA:BB:CC:DD:EE:FF", 1))


# ===================================================================
# BLETransport
# ===================================================================

class TestBLETransport:
    def test_init(self):
        t = BLETransport("AA:BB:CC:DD:EE:FF", cid=4)
        assert t.cid == 4
        assert t.address_type == 1  # BDADDR_LE_PUBLIC

    def test_repr_att(self):
        t = BLETransport("AA:BB:CC:DD:EE:FF", cid=BLETransport.ATT_CID)
        assert "ATT" in repr(t)

    def test_repr_smp(self):
        t = BLETransport("AA:BB:CC:DD:EE:FF", cid=BLETransport.SMP_CID)
        assert "SMP" in repr(t)

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_connect(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        t = BLETransport("AA:BB:CC:DD:EE:FF", cid=4)
        assert t.connect() is True

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_is_alive_success(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        t = BLETransport("AA:BB:CC:DD:EE:FF", cid=4)
        assert t.is_alive() is True

    @patch("blue_tap.fuzz.transport.socket.socket")
    def test_is_alive_failure(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("fail")
        mock_sock_cls.return_value = mock_sock
        t = BLETransport("AA:BB:CC:DD:EE:FF", cid=4)
        assert t.is_alive() is False


# ===================================================================
# Corpus
# ===================================================================

class TestCorpus:
    def test_add_seed_and_retrieve(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        c.add_seed("sdp", b"\x01\x02\x03")
        assert c.seed_count("sdp") == 1
        seeds = c.get_all_seeds("sdp")
        assert b"\x01\x02\x03" in seeds

    def test_add_empty_seed_ignored(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        c.add_seed("sdp", b"")
        assert c.seed_count("sdp") == 0

    def test_add_seed_with_name(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        c.add_seed("sdp", b"\xaa\xbb", name="test_seed")
        assert (tmp_path / "corpus" / "sdp" / "test_seed.bin").exists()

    def test_get_random_seed(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        c.add_seed("sdp", b"\x01")
        c.add_seed("sdp", b"\x02")
        seed = c.get_random_seed("sdp")
        assert seed in (b"\x01", b"\x02")

    def test_get_random_seed_empty(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        assert c.get_random_seed("sdp") is None

    def test_list_protocols(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        c.add_seed("sdp", b"\x01")
        c.add_seed("rfcomm", b"\x02")
        protos = c.list_protocols()
        assert "sdp" in protos
        assert "rfcomm" in protos

    def test_seed_count_all(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        c.add_seed("sdp", b"\x01")
        c.add_seed("rfcomm", b"\x02")
        assert c.seed_count() == 2

    def test_load_from_directory(self, tmp_path):
        # Create corpus directory structure
        proto_dir = tmp_path / "seeds" / "sdp"
        proto_dir.mkdir(parents=True)
        (proto_dir / "seed1.bin").write_bytes(b"\x01\x02")
        (proto_dir / "seed2.bin").write_bytes(b"\x03\x04")

        c = Corpus(str(tmp_path / "corpus"))
        loaded = c.load_from_directory(str(tmp_path / "seeds"))
        assert loaded == 2
        assert c.seed_count("sdp") == 2

    def test_load_from_nonexistent_directory(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        loaded = c.load_from_directory(str(tmp_path / "nonexistent"))
        assert loaded == 0

    def test_save_interesting(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        c.save_interesting("sdp", b"\xde\xad", "crash_timeout")
        int_dir = tmp_path / "corpus" / "sdp" / "interesting"
        assert int_dir.exists()
        bins = list(int_dir.glob("*.bin"))
        assert len(bins) == 1
        assert b"\xde\xad" == bins[0].read_bytes()

    def test_save_interesting_empty_ignored(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        c.save_interesting("sdp", b"", "reason")
        int_dir = tmp_path / "corpus" / "sdp" / "interesting"
        assert not int_dir.exists()

    def test_save_interesting_dedup(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        c.save_interesting("sdp", b"\xde\xad", "reason1")
        c.save_interesting("sdp", b"\xde\xad", "reason1")
        int_dir = tmp_path / "corpus" / "sdp" / "interesting"
        bins = list(int_dir.glob("*.bin"))
        assert len(bins) == 1

    def test_minimize_dedup(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        c.add_seed("sdp", b"\x01\x02")
        c.add_seed("sdp", b"\x01\x02")  # duplicate
        c.add_seed("sdp", b"\x03\x04")
        removed = c.minimize()
        assert removed == 1
        assert c.seed_count("sdp") == 2

    def test_stats(self, tmp_path):
        c = Corpus(str(tmp_path / "corpus"))
        c.add_seed("sdp", b"\x01\x02")
        c.add_seed("rfcomm", b"\x03\x04\x05")
        s = c.stats()
        assert s.total_seeds == 2
        assert s.size_bytes == 5
        assert "sdp" in s.protocols
        assert "rfcomm" in s.protocols


# ===================================================================
# CrashDB
# ===================================================================

class TestCrashDB:
    def test_log_and_retrieve(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            cid = db.log_crash(
                target="AA:BB:CC:DD:EE:FF",
                protocol="sdp",
                payload=b"\x01\x02\x03",
                crash_type=CrashType.CONNECTION_DROP,
                severity=CrashSeverity.HIGH,
            )
            assert cid >= 1
            crash = db.get_crash_by_id(cid)
            assert crash is not None
            assert crash["protocol"] == "sdp"
            assert crash["severity"] == "HIGH"
            assert crash["payload_hex"] == "010203"

    def test_dedup_by_payload_hash(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            id1 = db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01\x02",
                               CrashType.CONNECTION_DROP)
            id2 = db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01\x02",
                               CrashType.CONNECTION_DROP)
            assert id1 == id2  # same payload -> same ID

    def test_different_payload_different_id(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            id1 = db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01",
                               CrashType.CONNECTION_DROP)
            id2 = db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x02",
                               CrashType.CONNECTION_DROP)
            assert id1 != id2

    def test_get_crashes_filtered(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01",
                         CrashType.CONNECTION_DROP, severity=CrashSeverity.HIGH)
            db.log_crash("AA:BB:CC:DD:EE:FF", "rfcomm", b"\x02",
                         CrashType.TIMEOUT, severity=CrashSeverity.MEDIUM)
            sdp_crashes = db.get_crashes(protocol="sdp")
            assert len(sdp_crashes) == 1
            high_crashes = db.get_crashes(severity=CrashSeverity.HIGH)
            assert len(high_crashes) == 1

    def test_get_crashes_limit(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            for i in range(5):
                db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", bytes([i]),
                             CrashType.CONNECTION_DROP)
            results = db.get_crashes(limit=2)
            assert len(results) == 2

    def test_get_unique_crashes(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01",
                         CrashType.CONNECTION_DROP)
            # Different target, same payload
            db.log_crash("11:22:33:44:55:66", "sdp", b"\x01",
                         CrashType.CONNECTION_DROP)
            unique = db.get_unique_crashes()
            assert len(unique) == 1  # same payload_hash

    def test_crash_count(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01",
                         CrashType.CONNECTION_DROP)
            db.log_crash("AA:BB:CC:DD:EE:FF", "rfcomm", b"\x02",
                         CrashType.TIMEOUT)
            assert db.crash_count() == 2
            assert db.crash_count("sdp") == 1

    def test_mark_reproduced(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            cid = db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01",
                               CrashType.CONNECTION_DROP)
            db.mark_reproduced(cid, True)
            crash = db.get_crash_by_id(cid)
            assert crash["reproduced"] == 1

    def test_update_severity(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            cid = db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01",
                               CrashType.CONNECTION_DROP,
                               severity=CrashSeverity.LOW)
            db.update_severity(cid, CrashSeverity.CRITICAL)
            crash = db.get_crash_by_id(cid)
            assert crash["severity"] == "CRITICAL"

    def test_add_notes(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            cid = db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01",
                               CrashType.CONNECTION_DROP)
            db.add_notes(cid, "first note")
            db.add_notes(cid, "second note")
            crash = db.get_crash_by_id(cid)
            assert "first note" in crash["notes"]
            assert "second note" in crash["notes"]

    def test_add_notes_nonexistent(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            db.add_notes(9999, "nothing")  # should not raise

    def test_crash_summary(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01",
                         CrashType.CONNECTION_DROP, severity=CrashSeverity.HIGH)
            db.log_crash("AA:BB:CC:DD:EE:FF", "rfcomm", b"\x02",
                         CrashType.TIMEOUT, severity=CrashSeverity.MEDIUM)
            summary = db.crash_summary()
            assert summary["total"] == 2
            assert "sdp" in summary["by_protocol"]
            assert "HIGH" in summary["by_severity"]
            assert summary["unique_payloads"] == 2

    def test_export_json(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        json_path = str(tmp_path / "export.json")
        with CrashDB(db_path) as db:
            db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01",
                         CrashType.CONNECTION_DROP)
            db.export_json(json_path)
        with open(json_path) as f:
            data = json.load(f)
        assert data["total_crashes"] == 1
        assert len(data["crashes"]) == 1

    def test_get_crash_by_id_not_found(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            assert db.get_crash_by_id(999) is None

    def test_repr(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            r = repr(db)
            assert "CrashDB" in r

    def test_context_manager(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01",
                         CrashType.CONNECTION_DROP)
        # After __exit__, connection should be closed

    def test_reproduce_crash(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            cid = db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01\x02",
                               CrashType.CONNECTION_DROP)
            # Mock transport that simulates connection drop on send
            transport = MagicMock()
            transport.connect.return_value = True
            transport.send.side_effect = ConnectionResetError("dropped")
            transport.is_alive.return_value = False
            result = db.reproduce_crash(cid, transport)
            assert result is True
            crash = db.get_crash_by_id(cid)
            assert crash["reproduced"] == 1

    def test_reproduce_crash_not_found(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            transport = MagicMock()
            result = db.reproduce_crash(999, transport)
            assert result is False

    def test_reproduce_crash_connect_fail_alive(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            cid = db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01",
                               CrashType.CONNECTION_DROP)
            transport = MagicMock()
            transport.connect.return_value = False
            transport.is_alive.return_value = True
            result = db.reproduce_crash(cid, transport)
            assert result is False

    def test_reproduce_crash_recv_none(self, tmp_path):
        """recv returns None = connection closed -> reproduced."""
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            cid = db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01",
                               CrashType.CONNECTION_DROP)
            transport = MagicMock()
            transport.connect.return_value = True
            transport.send.return_value = 1
            transport.recv.return_value = None
            result = db.reproduce_crash(cid, transport)
            assert result is True

    def test_log_crash_with_string_enums(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            cid = db.log_crash("AA:BB:CC:DD:EE:FF", "sdp", b"\x01",
                               "connection_drop", severity="HIGH")
            crash = db.get_crash_by_id(cid)
            assert crash["crash_type"] == "connection_drop"
            assert crash["severity"] == "HIGH"


# ===================================================================
# CrashSeverity and CrashType enums
# ===================================================================

class TestCrashEnums:
    def test_severity_values(self):
        assert CrashSeverity.CRITICAL.value == "CRITICAL"
        assert CrashSeverity.HIGH.value == "HIGH"
        assert CrashSeverity.MEDIUM.value == "MEDIUM"
        assert CrashSeverity.LOW.value == "LOW"
        assert CrashSeverity.INFO.value == "INFO"

    def test_crash_type_values(self):
        assert CrashType.CONNECTION_DROP.value == "connection_drop"
        assert CrashType.TIMEOUT.value == "timeout"
        assert CrashType.DEVICE_DISAPPEARED.value == "device_disappeared"
        assert CrashType.HANG.value == "hang"


# ===================================================================
# FieldMutator
# ===================================================================

class TestFieldMutator:
    def test_bitflip_returns_bytes(self):
        result = FieldMutator.bitflip(b"\x00\x00\x00\x00", num_bits=1)
        assert isinstance(result, bytes)
        assert result != b"\x00\x00\x00\x00"

    def test_bitflip_empty(self):
        assert FieldMutator.bitflip(b"") == b""

    def test_byte_insert(self):
        result = FieldMutator.byte_insert(b"\x01\x02", pos=1, value=0xFF)
        assert result == b"\x01\xff\x02"

    def test_byte_insert_random(self):
        result = FieldMutator.byte_insert(b"\x01\x02")
        assert len(result) == 3

    def test_byte_delete(self):
        result = FieldMutator.byte_delete(b"\x01\x02\x03", pos=1)
        assert result == b"\x01\x03"

    def test_byte_delete_empty(self):
        assert FieldMutator.byte_delete(b"") == b""

    def test_byte_replace(self):
        result = FieldMutator.byte_replace(b"\x01\x02\x03", pos=1, value=0xFF)
        assert result == b"\x01\xff\x03"

    def test_byte_replace_empty(self):
        assert FieldMutator.byte_replace(b"") == b""

    def test_chunk_duplicate(self):
        result = FieldMutator.chunk_duplicate(b"\x01\x02\x03\x04", start=0, length=2)
        assert result == b"\x01\x02\x01\x02\x03\x04"

    def test_chunk_duplicate_empty(self):
        assert FieldMutator.chunk_duplicate(b"") == b""

    def test_chunk_shuffle(self):
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        result = FieldMutator.chunk_shuffle(data, chunk_size=4)
        assert isinstance(result, bytes)
        assert len(result) == len(data)

    def test_chunk_shuffle_empty(self):
        assert FieldMutator.chunk_shuffle(b"") == b""

    def test_chunk_shuffle_zero_size(self):
        assert FieldMutator.chunk_shuffle(b"\x01\x02", chunk_size=0) == b"\x01\x02"

    def test_truncate(self):
        result = FieldMutator.truncate(b"\x01\x02\x03\x04", new_len=2)
        assert result == b"\x01\x02"

    def test_truncate_empty(self):
        assert FieldMutator.truncate(b"") == b""

    def test_extend(self):
        result = FieldMutator.extend(b"\x01", extra=5)
        assert len(result) == 6

    def test_extend_random(self):
        result = FieldMutator.extend(b"\x01")
        assert len(result) > 1


# ===================================================================
# IntegerMutator
# ===================================================================

class TestIntegerMutator:
    def test_boundary_values_8(self):
        bv = IntegerMutator.boundary_values(8)
        assert 0 in bv
        assert 255 in bv
        assert 256 in bv  # max+1

    def test_boundary_values_16(self):
        bv = IntegerMutator.boundary_values(16)
        assert 0 in bv
        assert 0xFFFF in bv

    def test_boundary_values_zero_width(self):
        bv = IntegerMutator.boundary_values(0)
        assert bv == [0]

    def test_mutate_produces_valid_range(self):
        for _ in range(50):
            result = IntegerMutator.mutate(100, 8)
            assert 0 <= result <= 255

    def test_mutate_zero_width(self):
        assert IntegerMutator.mutate(5, 0) == 0

    def test_interesting_values_8(self):
        vals = IntegerMutator.interesting_values_8()
        assert 0 in vals
        assert 0xFF in vals

    def test_interesting_values_16(self):
        vals = IntegerMutator.interesting_values_16()
        assert 0xFFFF in vals

    def test_interesting_values_32(self):
        vals = IntegerMutator.interesting_values_32()
        assert 0xFFFFFFFF in vals


# ===================================================================
# LengthMutator
# ===================================================================

class TestLengthMutator:
    def test_mutate_returns_within_range(self):
        for _ in range(50):
            result = LengthMutator.mutate(100, bit_width=16)
            assert 0 <= result <= 0xFFFF

    def test_strategies_list(self):
        strats = LengthMutator.strategies()
        assert "zero" in strats
        assert "maximum" in strats
        assert len(strats) == 7


# ===================================================================
# PacketField and MutationLog
# ===================================================================

class TestPacketField:
    def test_creation(self):
        f = PacketField("test_field", 42, bit_width=8, field_type="uint")
        assert f.name == "test_field"
        assert f.value == 42
        assert f.bit_width == 8
        assert f.field_type == "uint"

    def test_raw_field(self):
        f = PacketField("payload", b"\x01\x02", field_type="raw")
        assert isinstance(f.value, bytes)


class TestMutationLog:
    def test_empty_log(self):
        ml = MutationLog()
        assert ml.to_string() == "(no mutations)"
        assert ml.to_dict()["mutation_count"] == 0

    def test_add_entries(self):
        ml = MutationLog()
        ml.add("field1", 0, 255, "boundary")
        ml.add("field2", b"\x00", b"\xff", "bitflip")
        assert len(ml.entries) == 2
        s = ml.to_string()
        assert "field1" in s
        assert "field2" in s

    def test_to_dict(self):
        ml = MutationLog()
        ml.add("f1", 0, 255, "boundary")
        d = ml.to_dict()
        assert d["mutation_count"] == 1
        assert d["mutations"][0]["field"] == "f1"


class TestSerialiseValue:
    def test_bytes(self):
        assert _serialise_value(b"\xde\xad") == "dead"

    def test_int(self):
        assert _serialise_value(42) == 42

    def test_other(self):
        result = _serialise_value([1, 2])
        assert isinstance(result, str)


# ===================================================================
# ProtocolMutator
# ===================================================================

class TestProtocolMutator:
    def test_mutate_packet_uint(self):
        fields = [
            PacketField("id", 0x01, bit_width=8, field_type="uint"),
            PacketField("len", 10, bit_width=16, field_type="length"),
            PacketField("data", b"\x01\x02\x03", field_type="raw"),
        ]
        pm = ProtocolMutator()
        mutated, log = pm.mutate_packet(fields, num_mutations=1)
        assert len(mutated) == 3
        assert len(log) >= 1

    def test_mutate_packet_empty(self):
        pm = ProtocolMutator()
        mutated, log = pm.mutate_packet([])
        assert mutated == []
        assert log == []

    def test_serialize_fields_big_endian(self):
        fields = [
            PacketField("id", 0x42, bit_width=8, field_type="uint"),
            PacketField("len", 0x0100, bit_width=16, field_type="length"),
            PacketField("data", b"\xAA\xBB", field_type="raw"),
        ]
        result = ProtocolMutator.serialize_fields(fields, endian="big")
        assert result == b"\x42\x01\x00\xAA\xBB"

    def test_serialize_fields_little_endian(self):
        fields = [
            PacketField("val", 0x0102, bit_width=16, field_type="uint"),
        ]
        result = ProtocolMutator.serialize_fields(fields, endian="little")
        assert result == b"\x02\x01"

    def test_mutate_packet_enum_flags(self):
        fields = [
            PacketField("flags", 0x03, bit_width=8, field_type="flags"),
            PacketField("mode", 0x01, bit_width=8, field_type="enum"),
        ]
        pm = ProtocolMutator()
        mutated, log = pm.mutate_packet(fields, num_mutations=2)
        assert len(mutated) == 2

    def test_mutate_packet_empty_raw(self):
        fields = [PacketField("data", b"", field_type="raw")]
        pm = ProtocolMutator()
        mutated, log = pm.mutate_packet(fields, num_mutations=1)
        assert len(log) >= 1  # should log noop


# ===================================================================
# CorpusMutator
# ===================================================================

class TestCorpusMutator:
    def test_mutate_returns_bytes(self):
        result = CorpusMutator.mutate(b"\x01\x02\x03\x04", num_mutations=1)
        assert isinstance(result, bytes)

    def test_mutate_batch(self):
        variants = CorpusMutator.mutate_batch(b"\x01\x02\x03\x04", count=5)
        assert len(variants) == 5
        for v in variants:
            assert isinstance(v, bytes)

    def test_havoc_returns_bytes(self):
        result = CorpusMutator.havoc(b"\x01\x02\x03\x04")
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_havoc_empty_input(self):
        result = CorpusMutator.havoc(b"")
        assert isinstance(result, bytes)
        assert len(result) > 0


# ===================================================================
# Minimizer: BinarySearchReducer
# ===================================================================

class TestBinarySearchReducer:
    def test_reduce_to_half(self):
        # Crash triggered by first byte being 0xDE
        payload = b"\xDE" + b"\x00" * 15
        def crash_test(data):
            return len(data) > 0 and data[0] == 0xDE
        reducer = BinarySearchReducer()
        result, log = reducer.reduce(payload, crash_test, min_size=1)
        assert len(result) < len(payload)
        assert result[0] == 0xDE

    def test_reduce_single_byte(self):
        payload = b"\xFF"
        def crash_test(data):
            return data == b"\xFF"
        reducer = BinarySearchReducer()
        result, log = reducer.reduce(payload, crash_test)
        assert result == b"\xFF"

    def test_reduce_no_crash(self):
        payload = b"\x01\x02\x03\x04"
        def crash_test(data):
            return data == b"\x01\x02\x03\x04"  # only full payload
        reducer = BinarySearchReducer()
        result, log = reducer.reduce(payload, crash_test)
        assert result == payload


# ===================================================================
# Minimizer: DeltaDebugReducer
# ===================================================================

class TestDeltaDebugReducer:
    def test_reduce_removes_irrelevant_chunks(self):
        # Crash requires first 2 bytes
        payload = b"\xDE\xAD" + b"\x00" * 14
        def crash_test(data):
            return len(data) >= 2 and data[:2] == b"\xDE\xAD"
        reducer = DeltaDebugReducer()
        result, log = reducer.reduce(payload, crash_test)
        assert len(result) <= len(payload)
        assert result[:2] == b"\xDE\xAD"

    def test_split(self):
        chunks = DeltaDebugReducer._split(b"\x01\x02\x03\x04", 2)
        assert len(chunks) == 2
        assert b"".join(chunks) == b"\x01\x02\x03\x04"

    def test_split_zero(self):
        chunks = DeltaDebugReducer._split(b"\x01\x02", 0)
        assert chunks == [b"\x01\x02"]

    def test_remove_chunk(self):
        chunks = [b"\x01\x02", b"\x03\x04", b"\x05\x06"]
        result = DeltaDebugReducer._remove_chunk(b"\x01\x02\x03\x04\x05\x06", chunks, 1)
        assert result == b"\x01\x02\x05\x06"

    def test_max_iterations(self):
        payload = b"\x01" * 100
        call_count = 0
        def crash_test(data):
            nonlocal call_count
            call_count += 1
            return True  # always crashes
        reducer = DeltaDebugReducer()
        result, log = reducer.reduce(payload, crash_test, max_iterations=5)
        # Should stop after max_iterations


# ===================================================================
# Minimizer: FieldReducer
# ===================================================================

class TestFieldReducer:
    def test_identify_essential_bytes(self):
        # Byte 0 is essential (must be 0xDE), bytes 1-3 are not
        payload = b"\xDE\x00\x00\x00"
        def crash_test(data):
            return len(data) >= 1 and data[0] == 0xDE
        reducer = FieldReducer()
        result, log, mask = reducer.reduce(payload, crash_test)
        assert mask[0] == 0xFF  # byte 0 is essential
        # Other bytes may or may not be essential depending on test

    def test_zero_byte_handling(self):
        # Test that zero bytes are also tested (by replacing with 0xFF)
        payload = b"\x00\xFF"
        def crash_test(data):
            return len(data) >= 2 and data[0] == 0x00 and data[1] == 0xFF
        reducer = FieldReducer()
        result, log, mask = reducer.reduce(payload, crash_test)
        assert mask[0] == 0xFF  # 0x00 is essential
        assert mask[1] == 0xFF  # 0xFF is essential


# ===================================================================
# MinimizationResult
# ===================================================================

class TestMinimizationResult:
    def test_summary(self):
        r = MinimizationResult(
            original=b"\x01\x02\x03\x04",
            minimized=b"\x01\x02",
            essential_mask=b"\xFF\x00",
            original_size=4,
            minimized_size=2,
            reduction_percent=50.0,
            tests_performed=10,
            strategy_used="binary",
        )
        s = r.summary()
        assert "50.0%" in s
        assert "binary" in s

    def test_essential_bytes_hex(self):
        r = MinimizationResult(
            original=b"\xDE\xAD\xBE\xEF",
            minimized=b"\xDE\xAD\xBE\xEF",
            essential_mask=b"\xFF\x00\xFF\x00",
            original_size=4,
            minimized_size=4,
            reduction_percent=0.0,
            tests_performed=4,
            strategy_used="field",
        )
        hex_str = r.essential_bytes_hex()
        assert "de" in hex_str
        assert "??" in hex_str

    def test_essential_bytes_hex_no_mask(self):
        r = MinimizationResult(
            original=b"\x01\x02",
            minimized=b"\x01\x02",
            essential_mask=b"",
            original_size=2,
            minimized_size=2,
            reduction_percent=0.0,
            tests_performed=0,
            strategy_used="none",
        )
        hex_str = r.essential_bytes_hex()
        assert "01" in hex_str

    def test_failed_result(self):
        r = MinimizationResult(
            original=b"\x01",
            minimized=b"\x01",
            essential_mask=b"",
            original_size=1,
            minimized_size=1,
            reduction_percent=0.0,
            tests_performed=1,
            strategy_used="auto",
            success=False,
        )
        assert "FAILED" in r.summary()


# ===================================================================
# CrashMinimizer (orchestrator)
# ===================================================================

class TestCrashMinimizer:
    def test_minimize_binary(self):
        # Always crashes when first byte is 0xDE
        def make_transport():
            t = MagicMock()
            t.connect.return_value = True
            t.send.return_value = 1
            t.recv.return_value = None  # connection closed = crash
            t.close.return_value = None
            t.is_alive.return_value = True
            return t

        minimizer = CrashMinimizer(
            target="AA:BB:CC:DD:EE:FF",
            transport_factory=make_transport,
            timeout=0.1,
            cooldown=0.0,
            max_retries=1,
        )
        payload = b"\xDE" + b"\x00" * 15
        result = minimizer.minimize(payload, strategy="binary")
        assert result.success is True
        assert result.minimized_size <= result.original_size

    def test_minimize_invalid_strategy(self):
        minimizer = CrashMinimizer(
            target="AA:BB:CC:DD:EE:FF",
            transport_factory=MagicMock,
            timeout=0.1,
            cooldown=0.0,
        )
        with pytest.raises(ValueError, match="Unknown strategy"):
            minimizer.minimize(b"\x01", strategy="bogus")

    def test_minimize_not_reproducible(self):
        def make_transport():
            t = MagicMock()
            t.connect.return_value = True
            t.send.return_value = 1
            t.recv.return_value = b"\x00"  # valid response = no crash
            t.close.return_value = None
            t.is_alive.return_value = True
            return t

        minimizer = CrashMinimizer(
            target="AA:BB:CC:DD:EE:FF",
            transport_factory=make_transport,
            timeout=0.1,
            cooldown=0.0,
            max_retries=1,
        )
        result = minimizer.minimize(b"\x01\x02\x03", strategy="binary")
        assert result.success is False

    def test_minimize_from_db(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")

        def make_transport():
            t = MagicMock()
            t.connect.return_value = True
            t.send.return_value = 1
            t.recv.return_value = None  # crash
            t.close.return_value = None
            t.is_alive.return_value = True
            return t

        with CrashDB(db_path) as db:
            cid = db.log_crash("AA:BB:CC:DD:EE:FF", "sdp",
                               b"\x01\x02\x03\x04",
                               CrashType.CONNECTION_DROP)

            minimizer = CrashMinimizer(
                target="AA:BB:CC:DD:EE:FF",
                transport_factory=make_transport,
                timeout=0.1,
                cooldown=0.0,
                max_retries=1,
            )
            result = minimizer.minimize_from_db(db, cid, strategy="binary")
            assert result.success is True
            # Notes should be updated
            crash = db.get_crash_by_id(cid)
            assert "[minimizer]" in crash["notes"]

    def test_minimize_from_db_not_found(self, tmp_path):
        db_path = str(tmp_path / "crashes.db")
        with CrashDB(db_path) as db:
            minimizer = CrashMinimizer(
                target="AA:BB:CC:DD:EE:FF",
                transport_factory=MagicMock,
            )
            with pytest.raises(ValueError, match="not found"):
                minimizer.minimize_from_db(db, 9999)


# ===================================================================
# BtsnoopParser
# ===================================================================

class TestBtsnoopParser:
    def test_parse_valid_file(self, tmp_path):
        # Build a minimal btsnoop file with one ACL record
        acl_pkt = _make_acl_l2cap_packet(0x001, cid=0x0001, payload=b"\x01\x02")
        ts = _BTSNOOP_EPOCH_OFFSET + 1_000_000  # 1 second after epoch
        file_data = _make_btsnoop_file([(acl_pkt, 0x00, ts)])
        fpath = str(tmp_path / "test.btsnoop")
        Path(fpath).write_bytes(file_data)

        parser = BtsnoopParser(fpath)
        records = parser.parse()
        assert len(records) == 1
        assert records[0].is_sent is True
        assert records[0].is_data is True

    def test_parse_invalid_magic(self, tmp_path):
        fpath = str(tmp_path / "bad.btsnoop")
        Path(fpath).write_bytes(b"not_btsnoop_data_at_all!!")
        parser = BtsnoopParser(fpath)
        with pytest.raises(ValueError, match="Not a btsnoop"):
            parser.parse()

    def test_parse_invalid_version(self, tmp_path):
        fpath = str(tmp_path / "bad.btsnoop")
        header = b"btsnoop\x00" + struct.pack(">II", 99, 1002)
        Path(fpath).write_bytes(header)
        parser = BtsnoopParser(fpath)
        with pytest.raises(ValueError, match="Unsupported btsnoop version"):
            parser.parse()

    def test_parse_empty_file(self, tmp_path):
        fpath = str(tmp_path / "empty.btsnoop")
        file_data = _make_btsnoop_file([])
        Path(fpath).write_bytes(file_data)
        parser = BtsnoopParser(fpath)
        records = parser.parse()
        assert len(records) == 0

    def test_parse_truncated_header(self, tmp_path):
        fpath = str(tmp_path / "trunc.btsnoop")
        Path(fpath).write_bytes(b"btsn")
        parser = BtsnoopParser(fpath)
        with pytest.raises(ValueError, match="header too short"):
            parser.parse()

    def test_len_and_iter(self, tmp_path):
        acl_pkt = _make_acl_l2cap_packet(0x001, cid=0x0001, payload=b"\x01")
        ts = _BTSNOOP_EPOCH_OFFSET + 1_000_000
        file_data = _make_btsnoop_file([
            (acl_pkt, 0x00, ts),
            (acl_pkt, 0x01, ts + 1000),
        ])
        fpath = str(tmp_path / "test.btsnoop")
        Path(fpath).write_bytes(file_data)
        parser = BtsnoopParser(fpath)
        parser.parse()
        assert len(parser) == 2
        assert len(list(parser)) == 2


# ===================================================================
# BtsnoopRecord
# ===================================================================

class TestBtsnoopRecord:
    def test_is_sent(self):
        r = BtsnoopRecord(10, 10, 0x00, 0, _BTSNOOP_EPOCH_OFFSET, b"\x00")
        assert r.is_sent is True
        assert r.is_received is False

    def test_is_received(self):
        r = BtsnoopRecord(10, 10, 0x01, 0, _BTSNOOP_EPOCH_OFFSET, b"\x00")
        assert r.is_sent is False
        assert r.is_received is True

    def test_is_data(self):
        r = BtsnoopRecord(10, 10, 0x00, 0, _BTSNOOP_EPOCH_OFFSET, b"\x00")
        assert r.is_data is True
        r2 = BtsnoopRecord(10, 10, 0x02, 0, _BTSNOOP_EPOCH_OFFSET, b"\x00")
        assert r2.is_data is False

    def test_timestamp_seconds(self):
        r = BtsnoopRecord(10, 10, 0x00, 0, _BTSNOOP_EPOCH_OFFSET + 2_000_000, b"\x00")
        assert abs(r.timestamp_seconds - 2.0) < 0.001


# ===================================================================
# L2CAP Frame extraction and protocol classification
# ===================================================================

class TestExtractL2CAPFrames:
    def test_single_frame(self):
        payload = b"\x01\x02\x03"
        acl_pkt = _make_acl_l2cap_packet(0x001, cid=0x0001, payload=payload)
        ts = _BTSNOOP_EPOCH_OFFSET + 1_000_000
        record = BtsnoopRecord(len(acl_pkt), len(acl_pkt), 0x00, 0, ts, acl_pkt)
        frames = extract_l2cap_frames([record])
        assert len(frames) == 1
        assert frames[0].payload == payload
        assert frames[0].cid == 0x0001
        assert frames[0].direction == "sent"

    def test_fragmented_reassembly(self):
        # First fragment: L2CAP header + partial data
        full_payload = b"\x01\x02\x03\x04\x05\x06"
        l2cap_hdr = struct.pack("<HH", len(full_payload), 0x0040)
        first_data = l2cap_hdr + full_payload[:3]
        second_data = full_payload[3:]

        handle = 0x001
        # First auto-flush packet
        h1 = (handle & 0x0FFF) | (0b10 << 12)
        acl1 = struct.pack("<HH", h1, len(first_data)) + first_data
        # Continuation packet
        h2 = (handle & 0x0FFF) | (0b01 << 12)
        acl2 = struct.pack("<HH", h2, len(second_data)) + second_data

        ts = _BTSNOOP_EPOCH_OFFSET
        rec1 = BtsnoopRecord(len(acl1), len(acl1), 0x00, 0, ts, acl1)
        rec2 = BtsnoopRecord(len(acl2), len(acl2), 0x00, 0, ts + 1000, acl2)

        frames = extract_l2cap_frames([rec1, rec2])
        assert len(frames) == 1
        assert frames[0].payload == full_payload

    def test_monitor_datalink(self):
        payload = b"\x01\x02"
        acl_pkt = _make_acl_l2cap_packet(0x001, cid=0x0004, payload=payload)
        # Add 2-byte monitor opcode prefix
        monitor_pkt = b"\x00\x00" + acl_pkt
        ts = _BTSNOOP_EPOCH_OFFSET
        record = BtsnoopRecord(len(monitor_pkt), len(monitor_pkt), 0x00, 0, ts, monitor_pkt)
        frames = extract_l2cap_frames([record], datalink_type=2001)
        assert len(frames) == 1


class TestClassifyProtocol:
    def test_fixed_cid_att(self):
        frame = L2CAPFrame(0x001, 10, 0x0004, b"\x01\x02", "sent", 0.0)
        assert classify_protocol(frame) == "ble-att"

    def test_fixed_cid_smp(self):
        frame = L2CAPFrame(0x001, 10, 0x0006, b"\x01\x02", "sent", 0.0)
        assert classify_protocol(frame) == "ble-smp"

    def test_fixed_cid_signaling(self):
        frame = L2CAPFrame(0x001, 10, 0x0001, b"\x01\x02", "sent", 0.0)
        assert classify_protocol(frame) == "l2cap-signaling"

    def test_sdp_classification(self):
        # SDP response: pdu_id=0x03, tid=0x0001, param_len=5
        payload = bytes([0x03, 0x00, 0x01]) + struct.pack(">H", 5) + b"\x00" * 5
        frame = L2CAPFrame(0x001, len(payload), 0x0040, payload, "received", 0.0)
        assert classify_protocol(frame) == "sdp"

    def test_at_command_classification(self):
        payload = b"AT+BRSF=0\r\n"
        frame = L2CAPFrame(0x001, len(payload), 0x0040, payload, "sent", 0.0)
        assert classify_protocol(frame) == "at-hfp"

    def test_unknown_protocol(self):
        frame = L2CAPFrame(0x001, 2, 0x0040, b"\xFE\xFE", "sent", 0.0)
        assert classify_protocol(frame) == "unknown"

    def test_empty_payload(self):
        frame = L2CAPFrame(0x001, 0, 0x0040, b"", "sent", 0.0)
        assert classify_protocol(frame) == "unknown"


# ===================================================================
# import_btsnoop_to_corpus
# ===================================================================

class TestImportBtsnoopToCorpus:
    def test_import(self, tmp_path):
        # Create a btsnoop file with an ATT frame
        att_payload = b"\x01\x02\x03"
        acl_pkt = _make_acl_l2cap_packet(0x001, cid=0x0004, payload=att_payload)
        ts = _BTSNOOP_EPOCH_OFFSET + 1_000_000
        file_data = _make_btsnoop_file([(acl_pkt, 0x00, ts)])
        fpath = str(tmp_path / "capture.btsnoop")
        Path(fpath).write_bytes(file_data)

        corpus = Corpus(str(tmp_path / "corpus"))
        counts = import_btsnoop_to_corpus(fpath, corpus)
        assert "ble-att" in counts
        assert counts["ble-att"] == 1


# ===================================================================
# CaptureReplayer
# ===================================================================

class TestCaptureReplayer:
    def _make_capture(self, tmp_path, payloads_cids):
        """Helper to create btsnoop file with given (payload, cid) pairs."""
        records = []
        ts = _BTSNOOP_EPOCH_OFFSET + 1_000_000
        for i, (payload, cid) in enumerate(payloads_cids):
            acl_pkt = _make_acl_l2cap_packet(0x001, cid=cid, payload=payload)
            records.append((acl_pkt, 0x00, ts + i * 1000))  # sent
        file_data = _make_btsnoop_file(records)
        fpath = str(tmp_path / "capture.btsnoop")
        Path(fpath).write_bytes(file_data)
        return fpath

    def test_load(self, tmp_path):
        fpath = self._make_capture(tmp_path, [(b"\x01\x02", 0x0004)])
        replayer = CaptureReplayer(fpath, "AA:BB:CC:DD:EE:FF")
        count = replayer.load()
        assert count == 1

    def test_list_frames(self, tmp_path):
        fpath = self._make_capture(tmp_path, [(b"\x01\x02", 0x0004)])
        replayer = CaptureReplayer(fpath, "AA:BB:CC:DD:EE:FF")
        replayer.load()
        frames = replayer.list_frames()
        assert len(frames) == 1
        assert frames[0]["protocol"] == "ble-att"

    def test_summary(self, tmp_path):
        fpath = self._make_capture(tmp_path, [
            (b"\x01\x02", 0x0004),
            (b"\x03\x04", 0x0006),
        ])
        replayer = CaptureReplayer(fpath, "AA:BB:CC:DD:EE:FF")
        replayer.load()
        s = replayer.summary()
        assert s["total_frames"] == 2
        assert s["sent_frames"] == 2

    def test_replay_all_dry_run(self, tmp_path):
        fpath = self._make_capture(tmp_path, [(b"\x01\x02", 0x0004)])
        replayer = CaptureReplayer(fpath, "AA:BB:CC:DD:EE:FF")
        replayer.load()
        result = replayer.replay_all(delay=0)
        assert result["sent"] == 1

    def test_replay_all_with_transport(self, tmp_path):
        fpath = self._make_capture(tmp_path, [(b"\x01\x02", 0x0004)])
        replayer = CaptureReplayer(fpath, "AA:BB:CC:DD:EE:FF")
        replayer.load()

        mock_transport = MagicMock()
        mock_transport.connect.return_value = True
        result = replayer.replay_all(
            transport_factory=lambda t: mock_transport,
            delay=0,
        )
        assert result["sent"] == 1
        mock_transport.send.assert_called_once()

    def test_replay_frame(self, tmp_path):
        fpath = self._make_capture(tmp_path, [(b"\x01\x02", 0x0004)])
        replayer = CaptureReplayer(fpath, "AA:BB:CC:DD:EE:FF")
        replayer.load()
        transport = MagicMock()
        result = replayer.replay_frame(0, transport)
        assert result["success"] is True

    def test_replay_frame_out_of_range(self, tmp_path):
        fpath = self._make_capture(tmp_path, [(b"\x01\x02", 0x0004)])
        replayer = CaptureReplayer(fpath, "AA:BB:CC:DD:EE:FF")
        replayer.load()
        transport = MagicMock()
        result = replayer.replay_frame(99, transport)
        assert result["success"] is False

    def test_replay_frame_no_frames(self, tmp_path):
        fpath = self._make_capture(tmp_path, [(b"\x01\x02", 0x0004)])
        replayer = CaptureReplayer(fpath, "AA:BB:CC:DD:EE:FF")
        # Don't call load()
        transport = MagicMock()
        result = replayer.replay_frame(0, transport)
        assert result["success"] is False

    def test_replay_with_mutations_dry_run(self, tmp_path):
        fpath = self._make_capture(tmp_path, [(b"\x01\x02\x03\x04", 0x0004)])
        replayer = CaptureReplayer(fpath, "AA:BB:CC:DD:EE:FF")
        replayer.load()
        result = replayer.replay_with_mutations(num_mutations=2, delay=0)
        assert result["sent"] >= 0
        assert result["mutations_applied"] >= 1

    def test_replay_all_filtered_by_protocol(self, tmp_path):
        fpath = self._make_capture(tmp_path, [
            (b"\x01\x02", 0x0004),  # ble-att
            (b"\x01\x02", 0x0006),  # ble-smp
        ])
        replayer = CaptureReplayer(fpath, "AA:BB:CC:DD:EE:FF")
        replayer.load()
        result = replayer.replay_all(protocol="ble-att", delay=0)
        assert result["sent"] == 1

    def test_replay_all_with_connect_fail(self, tmp_path):
        fpath = self._make_capture(tmp_path, [(b"\x01", 0x0004)])
        replayer = CaptureReplayer(fpath, "AA:BB:CC:DD:EE:FF")
        replayer.load()
        mock_transport = MagicMock()
        mock_transport.connect.return_value = False
        result = replayer.replay_all(
            transport_factory=lambda t: mock_transport,
            delay=0,
        )
        assert result["errors"] >= 1


# ===================================================================
# parse_duration
# ===================================================================

class TestParseDuration:
    def test_seconds(self):
        assert parse_duration("30s") == 30.0

    def test_minutes(self):
        assert parse_duration("30m") == 1800.0

    def test_hours(self):
        assert parse_duration("1h") == 3600.0
        assert parse_duration("2h") == 7200.0

    def test_days(self):
        assert parse_duration("7d") == 604800.0

    def test_float_value(self):
        assert parse_duration("1.5h") == 5400.0

    def test_case_insensitive(self):
        assert parse_duration("1H") == 3600.0
        assert parse_duration("30S") == 30.0

    def test_invalid_format(self):
        with pytest.raises(ValueError):
            parse_duration("abc")

    def test_invalid_unit(self):
        with pytest.raises(ValueError):
            parse_duration("30x")


# ===================================================================
# _format_duration
# ===================================================================

class TestFormatDuration:
    def test_zero(self):
        assert _format_duration(0) == "00:00:00"

    def test_one_hour(self):
        assert _format_duration(3600) == "01:00:00"

    def test_complex(self):
        assert _format_duration(3661) == "01:01:01"


# ===================================================================
# CampaignStats
# ===================================================================

class TestCampaignStats:
    def test_defaults(self):
        s = CampaignStats()
        assert s.iterations == 0
        assert s.packets_sent == 0
        assert s.crashes == 0

    def test_runtime_seconds(self):
        s = CampaignStats()
        s.start_time = time.time() - 10
        assert 9 <= s.runtime_seconds <= 11

    def test_runtime_with_prior(self):
        s = CampaignStats()
        s.prior_elapsed = 100.0
        s.start_time = time.time() - 5
        assert 104 <= s.runtime_seconds <= 106

    def test_packets_per_second(self):
        s = CampaignStats()
        s.packets_sent = 100
        s.start_time = time.time() - 10
        pps = s.packets_per_second
        assert 9 <= pps <= 11

    def test_crash_rate(self):
        s = CampaignStats()
        s.crashes = 5
        s.packets_sent = 1000
        assert s.crash_rate == 5.0

    def test_crash_rate_zero_packets(self):
        s = CampaignStats()
        assert s.crash_rate == 0.0


# ===================================================================
# FuzzCampaign (mocked, no real BT hardware)
# ===================================================================

class TestFuzzCampaign:
    def test_init_valid(self, tmp_path):
        campaign = FuzzCampaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["sdp", "rfcomm"],
            session_dir=str(tmp_path),
        )
        assert campaign.target == "AA:BB:CC:DD:EE:FF"
        assert "sdp" in campaign.protocols
        assert "rfcomm" in campaign.protocols

    def test_init_no_valid_protocols(self, tmp_path):
        with pytest.raises(ValueError, match="No valid protocols"):
            FuzzCampaign(
                target="AA:BB:CC:DD:EE:FF",
                protocols=["nonexistent_protocol"],
                session_dir=str(tmp_path),
            )

    def test_init_filters_unknown_protocols(self, tmp_path):
        campaign = FuzzCampaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["sdp", "bogus_proto"],
            session_dir=str(tmp_path),
        )
        assert "sdp" in campaign.protocols
        assert "bogus_proto" not in campaign.protocols

    def test_should_continue_duration(self, tmp_path):
        campaign = FuzzCampaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["sdp"],
            duration=1.0,
            session_dir=str(tmp_path),
        )
        campaign._running = True
        campaign.stats.start_time = time.time() - 2
        assert campaign._should_continue() is False

    def test_should_continue_iterations(self, tmp_path):
        campaign = FuzzCampaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["sdp"],
            max_iterations=10,
            session_dir=str(tmp_path),
        )
        campaign._running = True
        campaign.stats.iterations = 10
        assert campaign._should_continue() is False

    def test_should_continue_not_running(self, tmp_path):
        campaign = FuzzCampaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["sdp"],
            session_dir=str(tmp_path),
        )
        campaign._running = False
        assert campaign._should_continue() is False

    def test_next_protocol_round_robin(self, tmp_path):
        campaign = FuzzCampaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["sdp", "rfcomm"],
            session_dir=str(tmp_path),
        )
        # No crashes -> round robin
        campaign.stats.iterations = 0
        assert campaign._next_protocol() == "sdp"
        campaign.stats.iterations = 1
        assert campaign._next_protocol() == "rfcomm"

    def test_next_protocol_weighted(self, tmp_path):
        campaign = FuzzCampaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["sdp", "rfcomm"],
            session_dir=str(tmp_path),
        )
        campaign._proto_crash_counts["sdp"] = 100
        campaign._proto_crash_counts["rfcomm"] = 0
        # With 100 crashes on sdp, it should be heavily favored
        # Run 100 picks and check sdp gets majority
        sdp_count = sum(
            1 for _ in range(100)
            if campaign._next_protocol() == "sdp"
        )
        assert sdp_count > 70

    def test_setup_transports(self, tmp_path):
        campaign = FuzzCampaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["sdp", "ble-att"],
            session_dir=str(tmp_path),
        )
        transports = campaign._setup_transports()
        assert "sdp" in transports
        assert "ble-att" in transports

    def test_generate_fuzz_case(self, tmp_path):
        campaign = FuzzCampaign(
            target="AA:BB:CC:DD:EE:FF",
            protocols=["sdp"],
            session_dir=str(tmp_path),
        )
        fuzz_case, mutation_log = campaign._generate_fuzz_case("sdp")
        assert isinstance(fuzz_case, bytes)
        assert len(fuzz_case) > 0


# ===================================================================
# Legacy fuzzers (mocked sockets)
# ===================================================================

class TestL2CAPFuzzer:
    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_oversized_mtu(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.send.return_value = 1000
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = L2CAPFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.oversized_mtu(psm=1, size=1000)
        assert result["result"] == "sent"

    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_oversized_mtu_error(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("fail")
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = L2CAPFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.oversized_mtu()
        assert result["result"] == "error"

    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_malformed_packets(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.send.return_value = 1
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = L2CAPFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.malformed_packets(count=5)
        assert result["result"] == "complete"
        assert result["sent"] == 5

    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_malformed_packets_connect_error(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("fail")
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = L2CAPFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.malformed_packets(count=5)
        assert result["result"] == "error"

    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_null_flood(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.send.return_value = 0
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = L2CAPFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.null_flood(count=10)
        assert result["result"] == "complete"
        assert result["sent"] == 10

    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_null_flood_connect_error(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("fail")
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = L2CAPFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.null_flood(count=10)
        assert result["result"] == "error"

    def test_deprecation_warning(self):
        with pytest.warns(DeprecationWarning, match="deprecated"):
            L2CAPFuzzer("AA:BB:CC:DD:EE:FF")


class TestRFCOMMFuzzer:
    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_channel_exhaustion(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = RFCOMMFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.channel_exhaustion(max_channels=3)
        assert result["result"] == "complete"
        assert result["opened"] == 3

    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_large_payload(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.send.return_value = 100
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = RFCOMMFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.large_payload(channel=1, size=100)
        assert result["result"] == "sent"

    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_large_payload_error(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("fail")
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = RFCOMMFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.large_payload()
        assert result["result"] == "error"

    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_at_fuzz(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.send.return_value = 1
        mock_sock.recv.side_effect = TimeoutError
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = RFCOMMFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.at_fuzz(channel=1)
        assert result["result"] == "complete"
        assert result["sent"] == 5  # 5 default patterns

    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_at_fuzz_connect_error(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("fail")
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = RFCOMMFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.at_fuzz()
        assert result["result"] == "error"

    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_at_fuzz_custom_patterns(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.send.return_value = 1
        mock_sock.recv.return_value = b"OK\r\n"
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = RFCOMMFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.at_fuzz(patterns=["AT\r\n", "AT+TEST\r\n"])
        assert result["sent"] == 2

    def test_deprecation_warning(self):
        with pytest.warns(DeprecationWarning, match="deprecated"):
            RFCOMMFuzzer("AA:BB:CC:DD:EE:FF")


class TestSDPFuzzer:
    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_probe_continuation_state(self, mock_sock_cls):
        mock_sock = MagicMock()
        # Return a valid SDP response with continuation state
        sdp_resp = bytes([0x07, 0x00, 0x01]) + struct.pack(">H", 6) + b"\x00" * 5
        sdp_resp += bytes([1, 0x42])  # continuation state: 1 byte = 0x42
        mock_sock.recv.return_value = sdp_resp
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = SDPFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.probe_continuation_state()
        assert result["probes_sent"] >= 1

    @patch("blue_tap.fuzz.legacy.socket.socket")
    def test_probe_connect_error(self, mock_sock_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = OSError("fail")
        mock_sock_cls.return_value = mock_sock
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            fuzzer = SDPFuzzer("AA:BB:CC:DD:EE:FF")
        result = fuzzer.probe_continuation_state()
        assert result["probes_sent"] == 0

    def test_deprecation_warning(self):
        with pytest.warns(DeprecationWarning, match="deprecated"):
            SDPFuzzer("AA:BB:CC:DD:EE:FF")


class TestLegacyHelpers:
    @patch("blue_tap.fuzz.legacy.run_cmd")
    def test_check_target_alive_true(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        assert _check_target_alive("AA:BB:CC:DD:EE:FF") is True

    @patch("blue_tap.fuzz.legacy.run_cmd")
    def test_check_target_alive_false(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        assert _check_target_alive("AA:BB:CC:DD:EE:FF") is False

    @patch("blue_tap.fuzz.legacy.run_cmd")
    @patch("blue_tap.fuzz.legacy.check_tool")
    def test_bss_wrapper_tool_missing(self, mock_check, mock_run):
        mock_check.return_value = False
        assert bss_wrapper("AA:BB:CC:DD:EE:FF") is False

    @patch("blue_tap.fuzz.legacy.run_cmd")
    @patch("blue_tap.fuzz.legacy.check_tool")
    def test_bss_wrapper_success(self, mock_check, mock_run):
        mock_check.return_value = True
        mock_run.return_value = MagicMock(returncode=0, stdout="done")
        assert bss_wrapper("AA:BB:CC:DD:EE:FF", mode="l2cap") is True

    @patch("blue_tap.fuzz.legacy.run_cmd")
    @patch("blue_tap.fuzz.legacy.check_tool")
    def test_bss_wrapper_failure(self, mock_check, mock_run):
        mock_check.return_value = True
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        assert bss_wrapper("AA:BB:CC:DD:EE:FF") is False

    @patch("blue_tap.fuzz.legacy.run_cmd")
    @patch("blue_tap.fuzz.legacy.check_tool")
    def test_bss_wrapper_rfcomm(self, mock_check, mock_run):
        mock_check.return_value = True
        mock_run.return_value = MagicMock(returncode=0, stdout="done")
        assert bss_wrapper("AA:BB:CC:DD:EE:FF", mode="rfcomm") is True
        # Check rfcomm mode was passed
        args = mock_run.call_args[0][0]
        assert "-p" in args
        assert "rfcomm" in args
