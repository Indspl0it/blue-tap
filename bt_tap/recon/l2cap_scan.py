"""L2CAP PSM Scanner — probe standard and dynamic PSM values."""

import errno
import socket

from bt_tap.utils.output import info, success, error, warning


KNOWN_PSMS = {
    1: "SDP",
    3: "RFCOMM",
    5: "TCS-BIN",
    7: "BNEP",
    15: "HID-Control",
    17: "HID-Interrupt",
    23: "AVCTP",
    25: "AVDTP",
    27: "AVCTP-Browse",
}


class L2CAPScanner:
    """Scan L2CAP Protocol/Service Multiplexer values on a remote device."""

    def __init__(self, address: str):
        self.address = address

    # Well-known PSMs to scan first (fast), before full range
    PRIORITY_PSMS = [1, 3, 5, 7, 15, 17, 23, 25, 27, 31, 33, 35, 37]

    def scan_standard_psms(self, timeout: float = 1.0, full: bool = False) -> list[dict]:
        """Scan L2CAP PSMs in the standard range.

        By default, scans only well-known PSMs (fast, ~13 probes).
        With full=True, scans all odd PSMs 1-4095 (~2048 probes, slow).

        Returns list of dicts with: psm, status, name.
        """
        if full:
            psm_list = list(range(1, 4096, 2))
            info(f"Full L2CAP PSM scan (1-4095) on {self.address}...")
        else:
            psm_list = self.PRIORITY_PSMS
            info(f"Scanning {len(psm_list)} well-known L2CAP PSMs on {self.address}...")

        results = []

        for psm in psm_list:
            result = self._probe_psm(psm, timeout)
            if result["status"] != "closed":
                tag = result["status"]
                name = result["name"]
                if tag == "open":
                    success(f"  PSM {psm:>5}: OPEN — {name}")
                elif tag == "auth_required":
                    warning(f"  PSM {psm:>5}: AUTH REQUIRED — {name}")
                results.append(result)

        open_count = sum(1 for r in results if r["status"] == "open")
        auth_count = sum(1 for r in results if r["status"] == "auth_required")
        success(
            f"Standard scan complete — {open_count} open, "
            f"{auth_count} auth-required PSM(s)"
        )
        return results

    def scan_dynamic_psms(
        self, start: int = 4097, end: int = 32767, timeout: float = 1.0
    ) -> list[dict]:
        """Scan the dynamic PSM range for vendor-specific services.

        Dynamic PSMs are odd values >= 4097.
        Returns list of dicts with: psm, status, name.
        """
        # Ensure we start on an odd value
        if start % 2 == 0:
            start += 1

        info(f"Scanning dynamic L2CAP PSMs ({start}-{end}) on {self.address}...")
        results = []

        for psm in range(start, end + 1, 2):
            result = self._probe_psm(psm, timeout)
            if result["status"] != "closed":
                tag = result["status"]
                if tag == "open":
                    success(f"  PSM {psm:>5}: OPEN — {result['name']}")
                elif tag == "auth_required":
                    warning(f"  PSM {psm:>5}: AUTH REQUIRED — {result['name']}")
                results.append(result)

        open_count = sum(1 for r in results if r["status"] == "open")
        auth_count = sum(1 for r in results if r["status"] == "auth_required")
        success(
            f"Dynamic scan complete — {open_count} open, "
            f"{auth_count} auth-required PSM(s)"
        )
        return results

    def _probe_psm(self, psm: int, timeout: float) -> dict:
        """Probe a single L2CAP PSM value.

        Returns dict with psm, status (open/closed/auth_required), and name.
        Checks errno to distinguish refused vs auth-required connections.
        """
        result = {
            "psm": psm,
            "status": "closed",
            "name": KNOWN_PSMS.get(psm, "Unknown"),
        }

        sock = socket.socket(
            socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP
        )
        sock.settimeout(timeout)

        try:
            sock.connect((self.address, psm))
            result["status"] = "open"
        except OSError as exc:
            if exc.errno == errno.ECONNREFUSED:
                result["status"] = "closed"
            elif exc.errno == errno.EACCES:
                result["status"] = "auth_required"
            elif isinstance(exc, socket.timeout):
                result["status"] = "closed"
            else:
                # Other errors (host down, no route, etc.) treat as closed
                result["status"] = "closed"
        finally:
            sock.close()

        return result
