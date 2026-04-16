"""CVE detection checks for pairing and method-negotiation weaknesses."""

from __future__ import annotations

import os
import select
import socket
import subprocess
import tempfile
import time

from blue_tap.modules.assessment.cve_framework import make_cve_finding as _finding
from blue_tap.modules.assessment.checks.cve_ble_smp import _connect_ble_smp
from blue_tap.modules.fuzzing.protocols.smp import (
    AUTH_MITM,
    AUTH_SC,
    AUTH_SC_BOND_MITM,
    IO_DISPLAY_ONLY,
    IO_DISPLAY_YESNO,
    IO_KEYBOARD_DISPLAY,
    IO_KEYBOARD_ONLY,
    SMP_PAIRING_FAILED,
    SMP_PAIRING_PUBLIC_KEY,
    build_pairing_public_key,
    build_pairing_request,
)
from blue_tap.modules.reconnaissance.hci_capture import HCICapture
from blue_tap.utils.bt_helpers import run_cmd


def _pair_attempt(address: str, hci: str, agent: str, wait_seconds: float = 8.0) -> dict:
    """Run one bluetoothctl pairing attempt while capturing btmon text."""
    result = {
        "success": False,
        "pairing_method": "Unknown",
        "user_confirmation_seen": False,
        "auth_failure_seen": False,
        "pairing_failed_seen": False,
        "raw_excerpt": "",
        "stdout": "",
        "duration": 0.0,
    }

    tmp = tempfile.NamedTemporaryFile(prefix="bttap_pair_", suffix=".log", delete=False)
    tmp_path = tmp.name
    tmp.close()

    cap = HCICapture()
    started = cap.start(tmp_path, hci=hci)
    if not started:
        result["raw_excerpt"] = "btmon capture could not be started"
        return result

    proc = None
    start = time.time()
    try:
        run_cmd(["bluetoothctl", "cancel-pairing", address], timeout=5)
        run_cmd(["bluetoothctl", "remove", address], timeout=5)

        time.sleep(1.0)
        proc = subprocess.Popen(
            ["bluetoothctl"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        commands = [
            f"select {hci}",
            "agent off",
            f"agent {agent}",
            "default-agent",
            f"pair {address}",
        ]
        for cmd in commands:
            proc.stdin.write((cmd + "\n").encode())
            proc.stdin.flush()
            time.sleep(0.3)

        deadline = start + wait_seconds
        out = ""
        while time.time() < deadline:
            ready, _, _ = select.select([proc.stdout], [], [], 0.3)
            if ready:
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                out += chunk.decode("utf-8", errors="replace")
                if "Pairing successful" in out:
                    result["success"] = True
                    break
                if "Failed to pair" in out or "AuthenticationFailed" in out:
                    result["pairing_failed_seen"] = True
                    break

        result["stdout"] = out
        result["duration"] = time.time() - start
    finally:
        if proc is not None:
            try:
                proc.stdin.write(b"quit\n")
                proc.stdin.flush()
            except Exception:
                pass
            try:
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        cap.stop()

        try:
            with open(tmp_path, errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            lines = []
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

        relevant = []
        for line in lines:
            lower = line.lower()
            if "user confirmation request" in lower:
                result["user_confirmation_seen"] = True
                relevant.append(line.rstrip())
            if "authentication failure" in lower:
                result["auth_failure_seen"] = True
                relevant.append(line.rstrip())
            if "just works" in lower:
                result["pairing_method"] = "Just Works"
                relevant.append(line.rstrip())
            elif "passkey entry" in lower:
                result["pairing_method"] = "Passkey Entry"
                relevant.append(line.rstrip())
            elif "numeric comparison" in lower:
                result["pairing_method"] = "Numeric Comparison"
                relevant.append(line.rstrip())
            elif "simple pairing complete" in lower or "pair device complete" in lower:
                relevant.append(line.rstrip())
        result["raw_excerpt"] = "\n".join(relevant[:20])

        run_cmd(["bluetoothctl", "cancel-pairing", address], timeout=5)
        run_cmd(["bluetoothctl", "remove", address], timeout=5)

    return result


def _check_justworks_silent_pair(address: str, hci: str) -> list[dict]:
    """CVE-2019-2225: active JustWorks bonding should not complete silently."""
    attempt = _pair_attempt(address, hci, agent="NoInputNoOutput", wait_seconds=8.0)
    if not attempt["stdout"] and not attempt["raw_excerpt"]:
        return [_finding(
            "INFO", "CVE-2019-2225: Pairing Required",
            "Silent JustWorks probe requires the target to be discoverable and actively "
            "accepting BR/EDR pairing.",
            cve="CVE-2019-2225", status="pairing_required", confidence="high",
            evidence="No BR/EDR pairing negotiation was observed",
        )]

    if attempt["success"] and attempt["duration"] <= 5.0 and not attempt["user_confirmation_seen"]:
        return [_finding(
            "MEDIUM", "CVE-2019-2225: Inconclusive",
            "JustWorks bonding completed quickly from a NoInputNoOutput agent, but Blue-Tap "
            "cannot directly observe whether the target displayed and the user accepted a local "
            "confirmation prompt. The session matches the vulnerable timing profile but is not "
            "a definitive silent-pair proof.",
            cve="CVE-2019-2225", status="inconclusive", confidence="medium",
            evidence=(
                f"Pairing succeeded in {attempt['duration']:.1f}s with agent=NoInputNoOutput; "
                f"method={attempt['pairing_method']}; no local confirmation event captured"
            ),
        )]

    if attempt["user_confirmation_seen"] or attempt["auth_failure_seen"] or attempt["pairing_failed_seen"]:
        return []

    return [_finding(
        "MEDIUM", "CVE-2019-2225: Inconclusive",
        "The JustWorks probe reached the target, but the pairing outcome did not cleanly "
        "match either silent success or the documented patched failure path.",
        cve="CVE-2019-2225", status="inconclusive", confidence="medium",
        evidence=attempt["raw_excerpt"] or attempt["stdout"][:120],
    )]


def _check_bredr_method_confusion(address: str, hci: str) -> list[dict]:
    """CVE-2022-25837: compare strong-capability vs. downgraded BR/EDR pairing."""
    strong = _pair_attempt(address, hci, agent="KeyboardOnly", wait_seconds=10.0)
    if not strong["stdout"] and not strong["raw_excerpt"]:
        return [_finding(
            "INFO", "CVE-2022-25837: Pairing Required",
            "BR/EDR method-confusion probe requires the target to be pairable during the scan.",
            cve="CVE-2022-25837", status="pairing_required", confidence="high",
            evidence="No BR/EDR pairing negotiation was observed",
        )]

    if strong["pairing_method"] not in {"Passkey Entry", "Numeric Comparison"}:
        return [_finding(
            "INFO", "CVE-2022-25837: Not Applicable",
            "The target did not negotiate a strong SSP association model in the baseline probe, "
            "so the BR/EDR downgrade differential is not reachable in this session.",
            cve="CVE-2022-25837", status="not_applicable", confidence="high",
            evidence=f"Baseline method={strong['pairing_method']}",
        )]

    weak = _pair_attempt(address, hci, agent="NoInputNoOutput", wait_seconds=10.0)
    weak_downgrade = (
        weak["success"]
        and not weak["user_confirmation_seen"]
        and (weak["pairing_method"] == "Just Works" or weak["duration"] <= 5.0)
    )
    if weak_downgrade:
        return [_finding(
            "MEDIUM", "CVE-2022-25837: Inconclusive",
            "The target exposed a stronger SSP path and also accepted a weaker NoInputNoOutput "
            "pairing attempt, which indicates missing downgrade resistance. The CVE itself is a "
            "MITM method-confusion issue, so this unilateral probe is not enough to confirm the "
            "full vulnerability on its own.",
            cve="CVE-2022-25837", status="inconclusive", confidence="medium",
            evidence=(
                f"Baseline method={strong['pairing_method']}; downgraded probe succeeded "
                f"in {weak['duration']:.1f}s with method={weak['pairing_method']}"
            ),
        )]

    if weak["user_confirmation_seen"] or weak["auth_failure_seen"] or weak["pairing_failed_seen"]:
        return []

    return [_finding(
        "MEDIUM", "CVE-2022-25837: Inconclusive",
        "The target exposed a stronger SSP path, but the downgraded BR/EDR probe did not "
        "produce a clean acceptance-or-rejection differential.",
        cve="CVE-2022-25837", status="inconclusive", confidence="medium",
        evidence=weak["raw_excerpt"] or weak["stdout"][:120],
    )]


def _check_reflected_public_key(address: str) -> list[dict]:
    """CVE-2020-26558: echo the target's own LE SC public key back during pairing."""
    sock = _connect_ble_smp(address, timeout=10.0)
    if sock is None:
        return [_finding(
            "INFO", "CVE-2020-26558: Pairing Required",
            "Reflected public-key probe requires the target to accept a BLE Secure Connections "
            "pairing session on the SMP fixed channel.",
            cve="CVE-2020-26558", status="pairing_required", confidence="high",
            evidence="BLE SMP fixed CID 0x0006 was not reachable",
        )]

    try:
        req = build_pairing_request(
            io_cap=IO_KEYBOARD_ONLY,
            oob=0x00,
            auth_req=AUTH_SC_BOND_MITM,
            max_key_size=16,
            init_key_dist=0x07,
            resp_key_dist=0x07,
        )
        sock.sendall(req)
        rsp = sock.recv(256)
        if not rsp:
            return [_finding(
                "INFO", "CVE-2020-26558: Pairing Required",
                "No SMP Pairing Response was returned to the Secure Connections Passkey probe.",
                cve="CVE-2020-26558", status="pairing_required", confidence="high",
                evidence="No SMP Pairing Response",
            )]
        if rsp[0] == SMP_PAIRING_FAILED:
            return [_finding(
                "INFO", "CVE-2020-26558: Pairing Required",
                "Target rejected or was not ready for the Secure Connections Passkey probe.",
                cve="CVE-2020-26558", status="pairing_required", confidence="high",
                evidence=f"SMP Pairing Failed reason 0x{rsp[1]:02X}" if len(rsp) > 1 else "SMP Pairing Failed",
            )]
        if rsp[0] != 0x02 or len(rsp) < 7:
            return [_finding(
                "MEDIUM", "CVE-2020-26558: Inconclusive",
                "Secure Connections probe received an unexpected SMP response to Pairing Request.",
                cve="CVE-2020-26558", status="inconclusive", confidence="medium",
                evidence=f"Unexpected SMP opcode 0x{rsp[0]:02X}",
            )]

        io_cap = rsp[1]
        auth_req = rsp[4]
        if not (auth_req & AUTH_SC):
            return [_finding(
                "INFO", "CVE-2020-26558: Not Applicable",
                "Target did not negotiate LE Secure Connections in the pairing response.",
                cve="CVE-2020-26558", status="not_applicable", confidence="high",
                evidence=f"Pairing Response auth_req=0x{auth_req:02X}",
            )]
        if not (auth_req & AUTH_MITM) or io_cap not in {
            IO_DISPLAY_ONLY, IO_DISPLAY_YESNO, IO_KEYBOARD_DISPLAY,
        }:
            return [_finding(
                "INFO", "CVE-2020-26558: Not Applicable",
                "The pairing response did not indicate a Secure Connections Passkey-capable path.",
                cve="CVE-2020-26558", status="not_applicable", confidence="high",
                evidence=f"Pairing Response io_cap=0x{io_cap:02X}, auth_req=0x{auth_req:02X}",
            )]

        public_key = None
        deadline = time.time() + 8.0
        while time.time() < deadline:
            pkt = sock.recv(256)
            if not pkt:
                break
            if pkt[0] == SMP_PAIRING_FAILED:
                return []
            if pkt[0] == SMP_PAIRING_PUBLIC_KEY and len(pkt) >= 65:
                public_key = pkt[1:65]
                break

        if public_key is None:
            return [_finding(
                "MEDIUM", "CVE-2020-26558: Inconclusive",
                "Secure Connections pairing began, but the target did not provide a public key "
                "within the probe window.",
                cve="CVE-2020-26558", status="inconclusive", confidence="medium",
                evidence="No SMP Pairing Public Key received",
            )]

        # The spec and patch both reject any peer key with the same X coordinate.
        # Echoing the target's exact key back is sufficient to exercise that check.
        reflected = build_pairing_public_key(public_key[:32], public_key[32:64])
        sock.sendall(reflected)

        deadline = time.time() + 5.0
        while time.time() < deadline:
            pkt = sock.recv(256)
            if not pkt:
                break
            if pkt[0] == SMP_PAIRING_FAILED:
                return []
            if pkt[0] in {0x03, 0x04, 0x0D}:
                return [_finding(
                    "HIGH",
                    "Reflected Public Key Accepted During LE SC Pairing (CVE-2020-26558)",
                    "The target continued the Secure Connections pairing flow after receiving a "
                    "public key with the same X coordinate as its own, indicating the reflected-key "
                    "check is absent.",
                    cve="CVE-2020-26558",
                    impact="Passkey Entry impersonation via reflected public-key acceptance",
                    remediation="Reject peer Secure Connections public keys whose X coordinate matches the local key.",
                    status="confirmed",
                    confidence="high",
                    evidence=f"Target proceeded with SMP opcode 0x{pkt[0]:02X} after echoed public key",
                )]

        return [_finding(
            "MEDIUM", "CVE-2020-26558: Inconclusive",
            "The reflected public-key probe reached the target, but the post-key behavior did "
            "not clearly match either rejection or continued Secure Connections pairing.",
            cve="CVE-2020-26558", status="inconclusive", confidence="medium",
            evidence="No decisive SMP progress or failure after echoed public key",
        )]
    except OSError as exc:
        return [_finding(
            "MEDIUM", "CVE-2020-26558: Inconclusive",
            "Reflected public-key probe did not complete cleanly.",
            cve="CVE-2020-26558", status="inconclusive", confidence="medium",
            evidence=str(exc),
        )]
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Native Module classes
# ---------------------------------------------------------------------------

from typing import Any

from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import OptAddress, OptString
from blue_tap.modules.assessment.base import CveCheckModule


class Cve20192225Module(CveCheckModule):
    """CVE-2019-2225: JustWorks silent pairing vulnerability."""

    module_id = "assessment.cve_2019_2225"
    name = "JustWorks Silent Pair"
    description = "CVE-2019-2225: JustWorks bonding completes without user confirmation"
    protocols = ("Classic", "SMP")
    requires = ("classic_target", "adapter")
    destructive = False
    requires_pairing = True
    references = ("CVE-2019-2225",)
    options = (
        OptAddress("RHOST", required=True, description="Target BR/EDR address"),
        OptString("HCI", default="", description="Local HCI adapter"),
    )

    check_fn = staticmethod(_check_justworks_silent_pair)
    option_param_map = {"RHOST": "address", "HCI": "hci"}


class Cve202225837Module(CveCheckModule):
    """CVE-2022-25837: BR/EDR pairing method confusion."""

    module_id = "assessment.cve_2022_25837"
    name = "BR/EDR Method Confusion"
    description = "CVE-2022-25837: BR/EDR pairing downgraded to weaker method"
    protocols = ("Classic", "SMP")
    requires = ("classic_target", "adapter")
    destructive = False
    requires_pairing = True
    references = ("CVE-2022-25837",)
    options = (
        OptAddress("RHOST", required=True, description="Target BR/EDR address"),
        OptString("HCI", default="", description="Local HCI adapter"),
    )

    check_fn = staticmethod(_check_bredr_method_confusion)
    option_param_map = {"RHOST": "address", "HCI": "hci"}


class Cve202026558Module(CveCheckModule):
    """CVE-2020-26558: Reflected public key (Passkey Entry impersonation)."""

    module_id = "assessment.cve_2020_26558"
    name = "Reflected Public Key"
    description = "CVE-2020-26558: Reflected LE SC public key, Passkey impersonation"
    protocols = ("BLE", "SMP")
    requires = ("ble_target",)
    destructive = False
    requires_pairing = True
    references = ("CVE-2020-26558",)
    options = (OptAddress("RHOST", required=True, description="Target BLE address"),)

    check_fn = staticmethod(_check_reflected_public_key)
    option_param_map = {"RHOST": "address"}
