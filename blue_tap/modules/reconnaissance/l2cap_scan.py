"""L2CAP PSM Scanner — probe standard and dynamic PSM values.

Owns both the ``L2CAPScanner`` class (used by exploitation and campaign
orchestration) and the native ``L2capScanModule`` registered Module
subclass for ``reconnaissance.l2cap_scan``.
"""

import errno
import logging
import socket

from blue_tap.framework.contracts.result_schema import (
    build_run_envelope,
    make_evidence,
    make_execution,
)
from blue_tap.framework.module import Module, RunContext
from blue_tap.framework.module.options import OptAddress, OptInt, OptString
from blue_tap.framework.registry import ModuleFamily
from blue_tap.modules.reconnaissance.spec_interpretation import interpret_l2cap_probe
from blue_tap.utils.output import info, success, error, warning, verbose

logger = logging.getLogger(__name__)


KNOWN_PSMS = {
    1: "SDP",
    3: "RFCOMM",
    5: "TCS-BIN",
    7: "BNEP (PAN)",
    15: "HID-Control",
    17: "HID-Interrupt",
    23: "AVCTP (AVRCP signaling)",
    25: "AVDTP (A2DP streaming)",
    27: "AVCTP-Browse (AVRCP browsing)",
    31: "ATT (BLE Attribute Protocol)",
    33: "3DSP (3D Synchronization)",
    35: "IPSP (Internet Protocol Support)",
    37: "OTS (Object Transfer Service)",
}


class L2CAPScanner:
    """Scan L2CAP Protocol/Service Multiplexer values on a remote device."""

    def __init__(self, address: str):
        self.address = address
        self._local_addr: str | None = None

    # Well-known PSMs to scan first (fast), before full range
    PRIORITY_PSMS = [1, 3, 5, 7, 15, 17, 23, 25, 27, 31, 33, 35, 37]

    def scan_standard_psms(self, timeout: float = 1.0, full: bool = False,
                            hci: str | None = None) -> list[dict]:
        """Scan L2CAP PSMs in the standard range.

        By default, scans only well-known PSMs (fast, ~13 probes).
        With full=True, scans all odd PSMs 1-4095 (~2048 probes, slow).

        Returns list of dicts with: psm, status, name.
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        from blue_tap.utils.bt_helpers import ensure_adapter_ready, get_adapter_address
        if not ensure_adapter_ready(hci):
            return []
        self._local_addr = get_adapter_address(hci)
        if full:
            psm_list = list(range(1, 4096, 2))
            info(f"Full L2CAP PSM scan (1-4095, ~{len(psm_list)} probes) on {self.address}...")
        else:
            psm_list = self.PRIORITY_PSMS
            info(f"Scanning {len(psm_list)} well-known L2CAP PSMs on {self.address}...")

        return self._scan_psm_list(psm_list, timeout)

    def scan_dynamic_psms(
        self, start: int = 4097, end: int = 32767, timeout: float = 1.0,
        workers: int = 10,
    ) -> list[dict]:
        """Scan the dynamic PSM range for vendor-specific services.

        Dynamic PSMs are odd values >= 4097.
        Uses parallel probing with configurable worker count to speed up
        large range scans.
        """
        if start % 2 == 0:
            start += 1

        psm_list = list(range(start, end + 1, 2))
        probe_count = len(psm_list)
        est_minutes = probe_count * timeout / 60 / max(workers, 1)
        info(f"Scanning dynamic L2CAP PSMs ({start}-{end}, ~{probe_count} probes, "
             f"{workers} workers) on {self.address}...")
        if est_minutes > 5:
            warning(f"Estimated time: ~{est_minutes:.0f} minutes")

        if workers > 1:
            return self._scan_psm_list_parallel(psm_list, timeout, workers)
        return self._scan_psm_list(psm_list, timeout)

    def _scan_psm_list(self, psm_list: list[int], timeout: float,
                        unreachable_threshold: int = 3) -> list[dict]:
        """Scan a list of PSM values and return results.

        Includes progress feedback for long scans and aborts after
        consecutive unreachable probes.
        """
        results = []
        consecutive_unreachable = 0
        total = len(psm_list)

        for i, psm in enumerate(psm_list, 1):
            result = self._probe_psm(psm, timeout)
            tag = result["status"]
            name = result["name"]

            if tag == "open":
                success(f"  PSM {psm:>5}: OPEN — {name}")
                results.append(result)
                consecutive_unreachable = 0
            elif tag == "auth_required":
                warning(f"  PSM {psm:>5}: AUTH REQUIRED — {name}")
                results.append(result)
                consecutive_unreachable = 0
            elif tag == "timeout":
                results.append(result)
                consecutive_unreachable = 0
            elif tag == "host_unreachable":
                consecutive_unreachable += 1
                error(f"  PSM {psm:>5}: HOST UNREACHABLE — device gone")
                results.append(result)
                if unreachable_threshold > 0 and consecutive_unreachable >= unreachable_threshold:
                    warning(
                        f"Aborting scan — {unreachable_threshold} consecutive "
                        f"unreachable probes"
                    )
                    break
            else:
                consecutive_unreachable = 0

            # Progress feedback every 50 probes or 10% of total (visible with -v)
            interval = max(50, total // 10)
            if total > 20 and i % interval == 0:
                pct = i * 100 // total
                verbose(f"Progress: {i}/{total} PSMs scanned ({pct}%)")

        open_count = sum(1 for r in results if r["status"] == "open")
        auth_count = sum(1 for r in results if r["status"] == "auth_required")
        success(
            f"Scan complete — {open_count} open, "
            f"{auth_count} auth-required PSM(s)"
        )
        return results

    def _scan_psm_list_parallel(self, psm_list: list[int], timeout: float,
                                  workers: int = 10) -> list[dict]:
        """Scan PSMs in parallel using a thread pool.

        Sacrifices ordered output for speed. Results are sorted by PSM
        after collection.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results = []
        total = len(psm_list)
        completed = 0
        abort = False

        def probe_one(psm):
            return self._probe_psm(psm, timeout)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(probe_one, psm): psm for psm in psm_list}
            unreachable_count = 0

            for future in as_completed(futures):
                if abort:
                    break
                result = future.result()
                completed += 1
                tag = result["status"]
                name = result["name"]

                if tag == "open":
                    success(f"  PSM {result['psm']:>5}: OPEN — {name}")
                    results.append(result)
                    unreachable_count = 0
                elif tag == "auth_required":
                    warning(f"  PSM {result['psm']:>5}: AUTH REQUIRED — {name}")
                    results.append(result)
                    unreachable_count = 0
                elif tag == "host_unreachable":
                    results.append(result)
                    unreachable_count += 1
                    if unreachable_count >= 5:
                        warning("Aborting parallel scan — device unreachable")
                        abort = True
                else:
                    unreachable_count = 0

                # Progress every 10% (visible with -v)
                interval = max(100, total // 10)
                if completed % interval == 0:
                    pct = completed * 100 // total
                    verbose(f"Progress: {completed}/{total} PSMs ({pct}%)")

        results.sort(key=lambda r: r["psm"])
        open_count = sum(1 for r in results if r["status"] == "open")
        auth_count = sum(1 for r in results if r["status"] == "auth_required")
        success(f"Parallel scan complete — {open_count} open, {auth_count} auth-required PSM(s)")
        return results

    def _probe_psm(self, psm: int, timeout: float) -> dict:
        """Probe a single L2CAP PSM value.

        Returns dict with psm, status (open/closed/auth_required/host_unreachable), name.
        """
        import time

        result = {
            "psm": psm,
            "status": "closed",
            "name": KNOWN_PSMS.get(psm, f"Dynamic/Vendor (0x{psm:04x})"),
            "protocol_family": _protocol_family(psm),
            "behavior_hint": "",
            "evidence": "",
            "connect_latency_ms": None,
            "status_reason": "",
        }

        sock = socket.socket(
            socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP
        )
        sock.settimeout(timeout)
        if self._local_addr:
            sock.bind((self._local_addr, 0))

        try:
            connect_started = time.time()
            sock.connect((self.address, psm))
            result["connect_latency_ms"] = round((time.time() - connect_started) * 1000, 1)
            result["status"] = "open"
            result["behavior_hint"] = _classify_l2cap_behavior(psm, "open")
            result["status_reason"] = "remote accepted l2cap connection"
            result["evidence"] = f"l2cap connect accepted on psm 0x{psm:04x}"
        except OSError as exc:
            if exc.errno == errno.ECONNREFUSED:
                result["status"] = "closed"
                result["behavior_hint"] = _classify_l2cap_behavior(psm, "closed")
                result["status_reason"] = "actively refused"
                result["evidence"] = "remote refused l2cap connection"
            elif exc.errno == errno.EACCES:
                result["status"] = "auth_required"
                result["behavior_hint"] = _classify_l2cap_behavior(psm, "auth_required")
                result["status_reason"] = "authentication gate"
                result["evidence"] = "remote requires authentication or pairing"
            elif exc.errno in (errno.EHOSTDOWN, errno.EHOSTUNREACH, errno.ENETDOWN):
                result["status"] = "host_unreachable"
                result["behavior_hint"] = _classify_l2cap_behavior(psm, "host_unreachable")
                result["status_reason"] = "transport unreachable"
                result["evidence"] = "host unreachable during l2cap connect"
            elif isinstance(exc, socket.timeout):
                result["status"] = "timeout"
                result["behavior_hint"] = _classify_l2cap_behavior(psm, "timeout")
                result["status_reason"] = "no response"
                result["evidence"] = "l2cap connect timed out"
            else:
                result["status"] = "closed"
                result["behavior_hint"] = _classify_l2cap_behavior(psm, "closed")
                result["status_reason"] = "generic failure"
                result["evidence"] = str(exc)
        finally:
            sock.close()

        result["spec_interpretation"] = interpret_l2cap_probe(result, advertised=False)
        return result


def _protocol_family(psm: int) -> str:
    if psm in {1, 3, 5, 7}:
        return "classic_core"
    if psm in {15, 17}:
        return "hid"
    if psm in {23, 25, 27}:
        return "media_control"
    if psm in {31, 35, 37}:
        return "ble_or_ip"
    if psm >= 4097:
        return "dynamic_vendor"
    return "other"


def _classify_l2cap_behavior(psm: int, status: str) -> str:
    if status == "open":
        if psm == 1:
            return "sdp_reachable"
        if psm == 31:
            return "att_or_ble_att"
        if psm in {15, 17}:
            return "hid_surface"
        if psm in {23, 25, 27}:
            return "media_surface"
        if psm >= 4097:
            return "vendor_dynamic_surface"
        return "service_reachable"
    if status == "auth_required":
        return "protected_surface"
    if status == "timeout":
        return "slow_or_filtered"
    if status == "host_unreachable":
        return "link_unreachable"
    return "refused_surface"


# ── Native Module class ─────────────────────────────────────────────────────

class L2capScanModule(Module):
    """L2CAP Channel Scan.

    Probe L2CAP PSM space and classify open channels on a Classic Bluetooth
    target. Dispatches to ``L2CAPScanner.scan_standard_psms`` for the
    standard range (PSM < 4097) and ``scan_dynamic_psms`` for the dynamic
    range (PSM >= 4097). A single scan can cover both by splitting the
    requested range at the dynamic boundary.
    """

    module_id = "reconnaissance.l2cap_scan"
    family = ModuleFamily.RECONNAISSANCE
    name = "L2CAP Channel Scan"
    description = "Probe L2CAP PSM space and classify open channels"
    protocols = ("Classic", "L2CAP")
    requires = ("classic_target",)
    destructive = False
    requires_pairing = False
    schema_prefix = "blue_tap.recon.result"
    has_report_adapter = True
    references = ()
    options = (
        OptAddress("RHOST", required=True, description="Target BR/EDR address"),
        OptString("HCI", default="", description="Local HCI adapter"),
        OptInt("START_PSM", default=1, description="Start PSM for scan range"),
        OptInt("END_PSM", default=0x1001, description="End PSM for scan range"),
        OptInt("TIMEOUT_MS", default=1000, description="Per-probe timeout in milliseconds"),
    )

    def run(self, ctx: RunContext) -> dict:
        target = str(ctx.options.get("RHOST", ""))
        hci = str(ctx.options.get("HCI", ""))
        start_psm = int(ctx.options.get("START_PSM", 1))
        end_psm = int(ctx.options.get("END_PSM", 0x1001))
        timeout_ms = int(ctx.options.get("TIMEOUT_MS", 1000))
        timeout_s = max(timeout_ms / 1000.0, 0.1)
        started_at = ctx.started_at

        error_msg: str | None = None
        results: list[dict] = []
        try:
            scanner = L2CAPScanner(target)
            # Standard portion (1..4095) — only odd PSMs are valid
            if start_psm < 4097:
                std_start = max(1, start_psm)
                std_end = min(4095, end_psm)
                if std_end >= std_start:
                    # Directly probe the requested sub-range (fast, targeted).
                    from blue_tap.utils.bt_helpers import (
                        ensure_adapter_ready,
                        get_adapter_address,
                    )
                    if not ensure_adapter_ready(hci):
                        error_msg = f"adapter {hci} not ready"
                    else:
                        scanner._local_addr = get_adapter_address(hci)
                        psm_list = list(range(std_start if std_start % 2 else std_start + 1,
                                              std_end + 1, 2))
                        results.extend(scanner._scan_psm_list(psm_list, timeout_s))
            # Dynamic portion (>= 4097)
            if error_msg is None and end_psm >= 4097:
                dyn_start = max(4097, start_psm)
                dyn_end = end_psm
                if dyn_end >= dyn_start:
                    results.extend(scanner.scan_dynamic_psms(
                        start=dyn_start,
                        end=dyn_end,
                        timeout=timeout_s,
                    ))
        except Exception as exc:
            logger.exception("L2CAP scan failed for %s", target)
            error_msg = str(exc)

        open_channels = [r for r in results if r.get("status") == "open"]
        auth_required = [r for r in results if r.get("status") == "auth_required"]
        probe_count = len(results)

        if error_msg:
            execution_status = "failed"
            outcome = "not_applicable"
        else:
            execution_status = "completed"
            outcome = "observed" if open_channels or auth_required else "not_applicable"

        summary_text = (
            f"L2CAP scan error: {error_msg}"
            if error_msg
            else f"Probed {probe_count} PSMs, {len(open_channels)} open, {len(auth_required)} auth-required"
        )

        return build_run_envelope(
            schema=self.schema_prefix,
            module=self.module_id,
            target=target,
            adapter=hci,
            started_at=started_at,
            executions=[
                make_execution(
                    execution_id="l2cap_scan",
                    kind="collector",
                    id="l2cap_scan",
                    title="L2CAP PSM Scan",
                    execution_status=execution_status,
                    module_outcome=outcome,
                    evidence=make_evidence(
                        raw={
                            "probe_count": probe_count,
                            "open_count": len(open_channels),
                            "auth_required_count": len(auth_required),
                            "error": error_msg,
                        },
                        summary=summary_text,
                    ),
                    destructive=False,
                    requires_pairing=False,
                )
            ],
            summary={
                "outcome": outcome,
                "probe_count": probe_count,
                "open_count": len(open_channels),
                "auth_required_count": len(auth_required),
                "error": error_msg,
            },
            module_data={
                "open_psms": open_channels,
                "auth_required_psms": auth_required,
                "all_probes": results,
            },
            run_id=ctx.run_id,
        )
