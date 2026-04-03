"""L2CAP PSM Scanner — probe standard and dynamic PSM values."""

import errno
import socket

from blue_tap.utils.output import info, success, error, warning, verbose


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
                            hci: str = "hci0") -> list[dict]:
        """Scan L2CAP PSMs in the standard range.

        By default, scans only well-known PSMs (fast, ~13 probes).
        With full=True, scans all odd PSMs 1-4095 (~2048 probes, slow).

        Returns list of dicts with: psm, status, name.
        """
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
        result = {
            "psm": psm,
            "status": "closed",
            "name": KNOWN_PSMS.get(psm, f"Dynamic/Vendor (0x{psm:04x})"),
        }

        sock = socket.socket(
            socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP
        )
        sock.settimeout(timeout)
        if self._local_addr:
            sock.bind((self._local_addr, 0))

        try:
            sock.connect((self.address, psm))
            result["status"] = "open"
        except OSError as exc:
            if exc.errno == errno.ECONNREFUSED:
                result["status"] = "closed"
            elif exc.errno == errno.EACCES:
                result["status"] = "auth_required"
            elif exc.errno in (errno.EHOSTDOWN, errno.EHOSTUNREACH, errno.ENETDOWN):
                result["status"] = "host_unreachable"
            elif isinstance(exc, socket.timeout):
                result["status"] = "timeout"
            else:
                result["status"] = "closed"
        finally:
            sock.close()

        return result
