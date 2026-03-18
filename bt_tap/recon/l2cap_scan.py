"""L2CAP PSM Scanner — probe standard and dynamic PSM values."""

import errno
import socket

from bt_tap.utils.output import info, success, error, warning


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
        from bt_tap.utils.bt_helpers import ensure_adapter_ready, get_adapter_address
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
        self, start: int = 4097, end: int = 32767, timeout: float = 1.0
    ) -> list[dict]:
        """Scan the dynamic PSM range for vendor-specific services.

        Dynamic PSMs are odd values >= 4097.
        WARNING: Full range (4097-32767) = ~14k probes. At 1s timeout each,
        this takes ~4 hours. Consider narrowing the range.
        """
        # Ensure we start on an odd value
        if start % 2 == 0:
            start += 1

        probe_count = (end - start) // 2 + 1
        est_minutes = probe_count * timeout / 60
        info(f"Scanning dynamic L2CAP PSMs ({start}-{end}, ~{probe_count} probes) on {self.address}...")
        if est_minutes > 5:
            warning(f"Estimated time: ~{est_minutes:.0f} minutes")

        return self._scan_psm_list(list(range(start, end + 1, 2)), timeout)

    def _scan_psm_list(self, psm_list: list[int], timeout: float) -> list[dict]:
        """Scan a list of PSM values and return non-closed results."""
        results = []

        for psm in psm_list:
            result = self._probe_psm(psm, timeout)
            tag = result["status"]
            name = result["name"]

            if tag == "open":
                success(f"  PSM {psm:>5}: OPEN — {name}")
                results.append(result)
            elif tag == "auth_required":
                warning(f"  PSM {psm:>5}: AUTH REQUIRED — {name}")
                results.append(result)
            elif tag == "host_unreachable":
                error(f"  PSM {psm:>5}: HOST UNREACHABLE — device gone")
                results.append(result)
                warning("Aborting scan — device unreachable")
                break

        open_count = sum(1 for r in results if r["status"] == "open")
        auth_count = sum(1 for r in results if r["status"] == "auth_required")
        success(
            f"Scan complete — {open_count} open, "
            f"{auth_count} auth-required PSM(s)"
        )
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
                result["status"] = "closed"
            else:
                result["status"] = "closed"
        finally:
            sock.close()

        return result
