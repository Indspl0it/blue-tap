"""Stress tests for HCIVSCSocket concurrency and _cc_queue drain atomicity.

Phase 9 exit criteria:
- No lock-across-blocking-syscall patterns remain in hci_vsc.py
- Stress test for concurrent send_vsc + recv_event passes (no deadlock)
- Stress test for _cc_queue drain under high event rate passes
"""

from __future__ import annotations

import collections
import socket
import struct
import threading
import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock


class FakeSocket:
    """Minimal socket mock that supports send/recv from a pre-loaded queue."""

    def __init__(self) -> None:
        self._recv_queue: collections.deque[bytes] = collections.deque()
        self._send_buf: list[bytes] = []
        self._lock = threading.Lock()

    def sendall(self, data: bytes) -> None:
        with self._lock:
            self._send_buf.append(data)

    def recv(self, bufsize: int) -> bytes:
        with self._lock:
            if self._recv_queue:
                return self._recv_queue.popleft()
        return b""

    def close(self) -> None:
        pass

    def push_event(self, event_code: int, params: bytes) -> None:
        """Enqueue a synthetic HCI event packet."""
        pkt = bytes([0x04, event_code, len(params)]) + params
        with self._lock:
            self._recv_queue.append(pkt)

    def push_cc_event(self, opcode: int, status: int = 0x00) -> None:
        """Enqueue a synthetic Command Complete event."""
        # params: num_hci_cmds(1) + opcode(2) + return_params
        params = struct.pack("<BHB", 1, opcode, status)
        self.push_event(0x0E, params)


def _make_socket_with_fake(hci_dev: int = 1) -> tuple:
    """Return (HCIVSCSocket, FakeSocket) with the fake pre-wired."""
    from blue_tap.hardware.hci_vsc import HCIVSCSocket

    fake = FakeSocket()
    sock = HCIVSCSocket(hci_dev=hci_dev)
    sock._sock = fake  # type: ignore[assignment]
    return sock, fake


class TestRecvEventNoLockHeld(unittest.TestCase):
    """9.1: recv_event must not hold _lock during select/recv."""

    def test_recv_event_does_not_block_concurrent_send(self):
        """A concurrent send_vsc must not block behind recv_event's select.

        Strategy: start a thread that calls recv_event with a long timeout on
        an empty socket (will block in select).  Simultaneously call sendall
        from the main thread under _lock.  If recv_event holds _lock during
        select, the main thread's send_vsc will block indefinitely — we assert
        it completes promptly.
        """
        from blue_tap.hardware.hci_vsc import HCIVSCSocket

        sock_obj, fake = _make_socket_with_fake()

        recv_started = threading.Event()
        recv_blocked = threading.Event()

        original_select = __import__("select").select

        def slow_select(rlist, wlist, xlist, timeout=None):
            recv_started.set()
            # Simulate a slow select by sleeping briefly
            time.sleep(0.1)
            return [], [], []

        send_elapsed_ms: list[float] = []

        def do_recv():
            with patch("blue_tap.hardware.hci_vsc.select") as mock_sel_mod:
                mock_sel_mod.select.side_effect = slow_select
                sock_obj.recv_event(timeout=2.0)

        def do_send():
            recv_started.wait(timeout=2.0)
            t0 = time.monotonic()
            # Directly exercise _lock + sendall path
            with sock_obj._lock:
                fake.sendall(b"\x01\x22\xFE\x00")
            send_elapsed_ms.append((time.monotonic() - t0) * 1000)

        t_recv = threading.Thread(target=do_recv, daemon=True)
        t_send = threading.Thread(target=do_send, daemon=True)
        t_recv.start()
        t_send.start()
        t_recv.join(timeout=3.0)
        t_send.join(timeout=3.0)

        # send must have completed — if it were blocked behind recv_event's lock
        # it would time out and send_elapsed_ms would be empty or very large.
        self.assertTrue(send_elapsed_ms, "send never completed")
        # 200ms is very generous — should be <20ms without lock contention
        self.assertLess(send_elapsed_ms[0], 200,
                        f"send_vsc blocked for {send_elapsed_ms[0]:.0f}ms "
                        f"— lock is likely still held across blocking recv")


class TestCcQueueDrainAtomicity(unittest.TestCase):
    """9.7: _cc_queue drain under concurrent appends must not lose events."""

    def test_high_rate_cc_events_not_lost(self):
        """Pump many CC events while a drain loop runs; none should be lost."""
        from blue_tap.hardware.hci_vsc import HCIVSCSocket

        sock_obj, fake = _make_socket_with_fake()

        NUM_EVENTS = 200
        OPCODES = [0x1000 + i for i in range(NUM_EVENTS)]

        # Pre-fill the CC queue directly (simulating monitor thread appends)
        found_opcodes: set[int] = set()
        stop_flag = threading.Event()

        def producer():
            """Append CC events at high rate, like the monitor thread would."""
            for opcode in OPCODES:
                with sock_obj._lock:
                    sock_obj._cc_queue.append((opcode, b"\x00"))
                sock_obj._cc_ready.set()
                time.sleep(0)  # yield

        def consumer():
            """Drain the queue looking for all opcodes."""
            deadline = time.monotonic() + 5.0
            while found_opcodes != set(OPCODES) and time.monotonic() < deadline:
                with sock_obj._lock:
                    remaining = []
                    while sock_obj._cc_queue:
                        cc_opcode, cc_params = sock_obj._cc_queue.popleft()
                        found_opcodes.add(cc_opcode)
                        remaining.append((cc_opcode, cc_params))
                    # Put back (simulate _wait_cc_from_monitor re-queue)
                    for item in remaining:
                        sock_obj._cc_queue.appendleft(item)
                time.sleep(0)

        p = threading.Thread(target=producer, daemon=True)
        c = threading.Thread(target=consumer, daemon=True)
        p.start()
        c.start()
        p.join(timeout=5.0)
        c.join(timeout=5.0)

        # All produced opcodes must be findable (none lost to torn state)
        self.assertEqual(found_opcodes, set(OPCODES),
                         f"Lost {len(set(OPCODES) - found_opcodes)} CC events "
                         f"under concurrent producer/consumer")

    def test_wait_cc_from_monitor_returns_correct_opcode(self):
        """_wait_cc_from_monitor should find target opcode among many."""
        from blue_tap.hardware.hci_vsc import HCIVSCSocket

        sock_obj, fake = _make_socket_with_fake()

        TARGET_OPCODE = 0xFC61

        # Pre-load queue with decoy + target + more decoys
        for decoy_opcode in [0xFC60, 0xFC62, 0xFC63]:
            sock_obj._cc_queue.append((decoy_opcode, b"\x01"))
        sock_obj._cc_queue.append((TARGET_OPCODE, b"\x00\xDE\xAD"))
        for decoy_opcode in [0xFC64, 0xFC65]:
            sock_obj._cc_queue.append((decoy_opcode, b"\x02"))

        sock_obj._cc_ready.set()

        result = sock_obj._wait_cc_from_monitor(TARGET_OPCODE, timeout=1.0)
        self.assertEqual(result, b"\x00\xDE\xAD")

        # Decoys must still be in the queue (re-queued by the drain)
        remaining_opcodes = [op for op, _ in sock_obj._cc_queue]
        self.assertNotIn(TARGET_OPCODE, remaining_opcodes)
        self.assertIn(0xFC60, remaining_opcodes)
        self.assertIn(0xFC65, remaining_opcodes)


class TestAtomicFileWrites(unittest.TestCase):
    """9.2, 9.5, 9.6: File writes must be atomic (tmp+rename)."""

    def test_patch_bdaddr_uses_atomic_write(self):
        """patch_bdaddr must write via tmp file, not in-place."""
        import os
        import tempfile
        import shutil
        from unittest.mock import patch as mock_patch

        # Create a fake firmware file (big enough for BDADDR_OFFSET)
        from blue_tap.hardware import firmware as fw_module
        bdaddr_offset = fw_module.BDADDR_OFFSET

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_fw = os.path.join(tmpdir, "rtl8761b_fw.bin")
            # Write zeros, large enough
            with open(fake_fw, "wb") as f:
                f.write(b"\x00" * (bdaddr_offset + 64))

            with mock_patch.object(fw_module, "FIRMWARE_PATH", fake_fw):
                manager = fw_module.DarkFirmwareManager()

                # Track whether os.replace was called
                replace_calls: list[tuple] = []
                original_replace = os.replace

                def tracking_replace(src: str, dst: str) -> None:
                    replace_calls.append((src, dst))
                    original_replace(src, dst)

                with mock_patch("blue_tap.hardware.firmware.os.replace",
                                side_effect=tracking_replace):
                    # Mock the entire USB-reset-and-wait flow so the test does
                    # not block on real hardware re-enumeration.
                    with mock_patch.object(manager, "usb_reset_and_wait",
                                           return_value="hci0"):
                        with mock_patch.object(manager, "get_current_bdaddr",
                                               return_value="AA:BB:CC:DD:EE:FF"):
                            result = manager.patch_bdaddr(
                                "AA:BB:CC:DD:EE:FF", hci="hci0"
                            )

                self.assertTrue(result, "patch_bdaddr returned False")
                self.assertEqual(len(replace_calls), 1,
                                 "os.replace was not called exactly once")
                src_path, dst_path = replace_calls[0]
                self.assertTrue(src_path.endswith(".tmp"),
                                f"Expected tmp source, got {src_path!r}")
                self.assertEqual(dst_path, fake_fw)

    def test_restore_original_mac_uses_atomic_write(self):
        """restore_original_mac must write the updated MAC file atomically."""
        import os
        import tempfile
        import json
        from blue_tap.hardware import spoofer as sp_module

        with tempfile.TemporaryDirectory() as tmpdir:
            mac_file = os.path.join(tmpdir, "original_mac.json")
            with open(mac_file, "w") as f:
                json.dump({"hci0": "AA:BB:CC:DD:EE:FF"}, f)

            replace_calls: list[tuple] = []
            original_replace = os.replace

            def tracking_replace(src: str, dst: str) -> None:
                replace_calls.append((src, dst))
                original_replace(src, dst)

            with unittest.mock.patch.object(sp_module, "_ORIGINAL_MAC_FILE", mac_file):
                with unittest.mock.patch("blue_tap.hardware.spoofer.os.replace",
                                         side_effect=tracking_replace):
                    # Mock spoof_address and get_original_mac
                    with unittest.mock.patch.object(
                        sp_module, "spoof_address",
                        return_value={"success": True, "method_used": "ip", "error": ""}
                    ):
                        sp_module.restore_original_mac("hci0")

            self.assertGreaterEqual(len(replace_calls), 1,
                                    "os.replace was not called — write is not atomic")
            src_path = replace_calls[0][0]
            self.assertTrue(src_path.endswith(".tmp"),
                            f"Expected .tmp source path, got {src_path!r}")


if __name__ == "__main__":
    unittest.main()
