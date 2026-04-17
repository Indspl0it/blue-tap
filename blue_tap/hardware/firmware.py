"""DarkFirmware management for RTL8761B (TP-Link UB500).

Detects the RTL8761B adapter, checks whether DarkFirmware custom firmware is
loaded, patches the BDADDR in the firmware binary, and manages USB resets.

DarkFirmware extends the RTL8761B with vendor-specific HCI commands for:
  - LMP packet injection (VSC 0xFE22)
  - Controller memory read/write (VSC 0xFC61 / 0xFC62)
  - Passive LMP monitoring via HCI Event 0xFF

The BDADDR offset (0xAD85) was found by diffing the DarkFirmware 1337 and
1338 firmware variants.  DarkFirmware is detected via two probes:
  1. Hook 1 backup at 0x80133FFC is non-zero (stock returns all zeros)
  2. VSC 0xFE22 echoes payload as vendor event 0xFF (stock does not)
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import time

from blue_tap.utils.bt_helpers import run_cmd
from blue_tap.utils.output import error, info, success, warning

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FIRMWARE_PATH = "/lib/firmware/rtl_bt/rtl8761bu_fw.bin"
FIRMWARE_ORIG = "/lib/firmware/rtl_bt/rtl8761bu_fw.bin.orig"
BDADDR_OFFSET = 0xAD85
USB_VID_PID = "2357:0604"
# Known RTL8761B-bearing dongles: TP-Link UB500 (2357:0604) and generic Realtek (0BDA:8771).
RTL8761B_VID_PIDS = ("2357:0604", "0bda:8771")

# Hook backup addresses and expected values (from DarkFirmware RE)
# Hook 1: HCI CMD handler — intercepts VSC 0xFE22 for LMP injection
HOOK1_BACKUP_ADDR = 0x80133FFC
HOOK1_EXPECTED = 0x8010D891       # Original OGF_3F handler saved by hook installer

# Hook 2: LMP RX handler — logs incoming LMP + modification modes 0-5
HOOK2_BACKUP_ADDR = 0x80133FF8
HOOK2_EXPECTED = 0x8010DFB1       # Original tLMP handler saved by hook installer

# Hook 3: tLC_TX — logs outgoing LMP (TXXX) + ACL (ACLX) packets
# Shim code is in firmware binary but needs backup pointer written to RAM after boot.
HOOK3_BACKUP_ADDR = 0x80133FF4
HOOK3_ORIGINAL = 0x80042421       # ROM assoc_w_tLC_TX (+1 ISA bit for MIPS16e)

# Hook 4: tLC_RX — logs all incoming Link Controller packets (LMP + BLE LL + ACL + SCO)
# Same as Hook 3: shim present in binary, backup pointer needs RAM write.
HOOK4_BACKUP_ADDR = 0x80133FEC
HOOK4_ORIGINAL = 0x80042189       # ROM assoc_w_tLC_RX (+1 ISA bit for MIPS16e)

# In-flight LMP modification control (Hook 2 modes)
MOD_FLAG_ADDR = 0x80133FF0        # 1 byte: mode (0=passthrough, 1-5=modify/drop/etc.)
MOD_TABLE_ADDR = 0x80133FE0       # 3 bytes: [byte_offset, new_value, target_opcode]
AUTO_RESP_TRIGGER_ADDR = 0x80133FD8  # 2 bytes: [trigger_opcode, conn_index]

# Modification modes
MOD_PASSTHROUGH = 0    # Normal operation (log only)
MOD_MODIFY = 1         # Overwrite data_buf[offset] with new_value (one-shot, auto-clears)
MOD_DROP = 2           # Drop next incoming LMP packet entirely (one-shot)
MOD_OPCODE_DROP = 3    # Drop only if opcode matches target_opcode (persistent)
MOD_PERSISTENT = 4     # Same as MOD_MODIFY but does NOT auto-clear (sustained)
MOD_AUTO_RESPOND = 5   # Send pre-loaded response when trigger_opcode seen, then passthrough

# Backward compatibility aliases
DARKFIRMWARE_CHECK_ADDR = HOOK1_BACKUP_ADDR
DARKFIRMWARE_CHECK_VALUE = HOOK1_EXPECTED

# Patchable instruction locations in DarkFirmware (verified from live firmware + file)
# Both RAM addresses (for runtime patching) and file offsets (for persistent patching).
# POC code starts at RAM 0x8011160C; g_poc_buf is appended at end of firmware file.
#
# Instruction sequence at g_poc_buf+0x6E (verified pattern: 00 6C 47 0D 0A 6E 03 6F):
#   li $a0, 0      — connection index
#   <branch>
#   li $a2, 0x0A   — send_LMP_reply length
#   li $a3, 3      — unknown param
LMP_SEND_LENGTH_ADDR = 0x8011167E       # RAM address of li $a2, <length>
LMP_SEND_LENGTH_FILE_OFFSET = 0xADFE    # File offset of the same byte in firmware binary
LMP_SEND_LENGTH_DEFAULT = 0x0A          # Original: 10 bytes
LMP_SEND_LENGTH_MAX_SPEC = 0x11         # BT Core Spec max LMP PDU: 17 bytes
LMP_SEND_LENGTH_VERIFY_BYTE = 0x6E      # MIPS16e opcode byte for 'li $a2' (safety check)

LMP_CONNECTION_INDEX_ADDR = 0x8011167A      # RAM address of li $a0, <index>
LMP_CONNECTION_INDEX_FILE_OFFSET = 0xADFA   # File offset of the same byte
LMP_CONNECTION_INDEX_DEFAULT = 0x00         # Original: connection slot 0
LMP_CONNECTION_INDEX_VERIFY_BYTE = 0x6C     # MIPS16e opcode byte for 'li $a0'

# Memory region presets for firmware dumping
MEMORY_REGIONS: dict[str, tuple[int, int]] = {
    "rom": (0x80000000, 0x80100000),    # 1MB ROM
    "ram": (0x80100000, 0x80134000),    # ~200KB RAM
    "patch": (0x80110000, 0x80120000),  # 64KB patch area
    "hooks": (0x80133F00, 0x80134000),  # 256B hook/backup area
}

# Connection table layout in firmware RAM (from RE: param_1 * 0x2B8)
CONNECTION_TABLE_BASE = 0x8012DC50  # bos[] array base address
CONNECTION_SLOT_SIZE = 0x2B8        # 696 bytes per slot (confirmed via decompiled code)
CONNECTION_MAX_SLOTS = 12           # RTL8761B supports up to 12 connections
SECONDARY_PTR_OFFSET = 0x58        # Offset to secondary struct pointer in each slot

# Secondary struct field offsets (from decompiled send_LMP_reply, LMP_COMB_KEY, etc.)
SEC_OFF_STATE_BYTE = 0x01          # Connection state machine phase
SEC_OFF_KEY_MATERIAL_SRC = 0x02    # 16 bytes: key material source
SEC_OFF_PAIRING_STAGE = 0x12       # Pairing stage
SEC_OFF_KEY_SIZE = 0x23            # Negotiated encryption key size (1-16 bytes)
SEC_OFF_ENC_ENABLED = 0x26         # Encryption enabled boolean
SEC_OFF_AUTH_STATE = 0x50          # Authentication state machine phase
SEC_OFF_KEY_MATERIAL_COPY = 0x51   # 16 bytes: link key material (copied during COMB_KEY)
SEC_OFF_SC_FLAG = 0x214            # Secure Connections enabled flag


def _cleanup_tmp(path: str) -> None:
    """Remove a leftover tmp file, silently ignoring errors."""
    try:
        os.unlink(path)
    except OSError:
        pass


class DarkFirmwareManager:
    """Manage DarkFirmware installation, detection, and BDADDR patching."""

    def find_rtl8761b_hci(self) -> str | None:
        """Discover the HCI interface that belongs to the RTL8761B dongle.

        Does NOT accept an hci argument — it finds the right adapter by USB
        identity so the caller never has to guess hci0/hci1/hci2.

        Strategy:
          1. ``lsusb -d 2357:0604`` — fast-fail if the USB device is absent.
          2. Walk ``/sys/class/bluetooth/hci*`` — for each interface read its
             USB modalias and match VID:PID ``2357:0604`` (TP-Link UB500) or
             ``0BDA:8771`` (generic Realtek RTL8761B).
          3. Fallback: ``hciconfig -a`` manufacturer string ("Realtek" / "(93)").

        Returns the HCI name (e.g. ``<hciX>``) or ``None`` if the dongle is not
        present or cannot be mapped.
        """
        import glob

        # Step 1: confirm at least one RTL8761B-bearing USB device exists before touching sysfs
        usb_present = False
        for vid_pid in RTL8761B_VID_PIDS:
            lsusb_result = run_cmd(["lsusb", "-d", vid_pid])
            if lsusb_result.returncode == 0 and lsusb_result.stdout.strip():
                usb_present = True
                break
        if not usb_present:
            return None

        # Step 2: map USB VID:PID → HCI via sysfs modalias
        for hci_path in sorted(glob.glob("/sys/class/bluetooth/hci*")):
            hci_name = os.path.basename(hci_path)
            device_link = os.path.join(hci_path, "device")
            if not os.path.islink(device_link):
                continue
            real_path = os.path.realpath(device_link)
            for parent in (real_path, os.path.dirname(real_path)):
                modalias_file = os.path.join(parent, "modalias")
                if not os.path.exists(modalias_file):
                    continue
                try:
                    with open(modalias_file) as f:
                        modalias = f.read().strip().lower()
                    # USB modalias format: usb:v2357p0604d...
                    if "v2357p0604" in modalias or "v0bdap8771" in modalias:
                        return hci_name
                except OSError:
                    continue

        # Step 3: fallback — hciconfig manufacturer string
        for hci_path in sorted(glob.glob("/sys/class/bluetooth/hci*")):
            hci_name = os.path.basename(hci_path)
            result = run_cmd(["hciconfig", "-a", hci_name])
            if result.returncode != 0:
                continue
            mfr_m = re.search(r"Manufacturer:\s*(.+)", result.stdout)
            if mfr_m:
                mfr = mfr_m.group(1).strip().lower()
                if "realtek" in mfr or "(93)" in mfr:
                    return hci_name

        return None

    def detect_rtl8761b(self, hci: str | None = None) -> bool:
        """Return True if an RTL8761B is present and maps to ``hci`` (or any HCI if None).

        Prefer ``find_rtl8761b_hci()`` for discovery — this method exists for
        backwards-compatibility and targeted per-adapter checks.
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        found = self.find_rtl8761b_hci()
        if found is None:
            return False
        if hci is not None and found != hci:
            return False
        return True

    def _resolve_hci(self, hci: str | None) -> str | None:
        """Return ``hci`` if given, otherwise discover the RTL8761B HCI via USB VID:PID."""
        if hci is not None:
            return hci
        return self.find_rtl8761b_hci()

    def is_darkfirmware_loaded(self, hci: str | None = None) -> bool:
        """Check if DarkFirmware is active using two firmware-level probes.

        Primary: Read Hook 1 backup at 0x80133FFC via VSC 0xFC61.  Stock
        firmware returns all zeros; DarkFirmware returns non-zero (the
        original function pointer saved by the hook installer).

        Fallback: Send VSC 0xFE22 (LMP TX) with a dummy payload.
        DarkFirmware echoes it back as a vendor event (0xFF) before the
        command-complete; stock firmware returns only the command-complete.
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        hci = self._resolve_hci(hci)
        if hci is None:
            return False

        try:
            from blue_tap.hardware.hci_vsc import HCIVSCSocket

            hci_idx = int(hci.replace("hci", ""))
            with HCIVSCSocket(hci_dev=hci_idx) as sock:
                # Primary: Hook 1 backup — non-zero means hooks are installed.
                # Firmware returns 1-2 bytes (not always 4), so check any data.
                data = sock.read_memory(DARKFIRMWARE_CHECK_ADDR, 4)
                if data and any(b != 0 for b in data):
                    success(
                        f"DarkFirmware confirmed on {hci} "
                        f"(Hook 1 backup = {data.hex()})"
                    )
                    return True

                # Fallback: LMP TX vendor-event probe.
                # DarkFirmware echoes the payload as HCI Event 0xFF before
                # returning Command Complete.  Stock firmware does not.
                if self._probe_lmp_tx_echo(sock, hci):
                    return True

        except PermissionError:
            warning(f"Cannot probe DarkFirmware on {hci} — need root or CAP_NET_RAW")
        except OSError as exc:
            warning(f"HCI socket error probing DarkFirmware on {hci}: {exc}")
        except Exception as exc:
            warning(f"DarkFirmware probe failed on {hci}: {exc}")

        info(f"DarkFirmware not detected on {hci}")
        return False

    @staticmethod
    def _probe_lmp_tx_echo(sock: object, hci: str) -> bool:
        """Send VSC 0xFE22 with a dummy payload and check for vendor event echo.

        DarkFirmware processes LMP TX by echoing the payload as an HCI
        vendor event (0xFF) before the command-complete.  Stock Realtek
        firmware returns only the command-complete with status 0x01.
        """
        import select as _select

        probe_payload = b"\xAA\xBB\xCC"
        opcode = 0xFE22
        pkt = (
            bytes([0x01])
            + struct.pack("<H", opcode)
            + bytes([len(probe_payload)])
            + probe_payload
        )

        raw_sock = sock.raw_socket()
        if raw_sock is None:
            return False

        raw_sock.sendall(pkt)

        # Collect events for up to 2 seconds
        deadline = time.monotonic() + 2.0
        saw_vendor_event = False
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            ready, _, _ = _select.select([raw_sock], [], [], min(remaining, 0.3))
            if not ready:
                if saw_vendor_event:
                    break
                continue

            data = raw_sock.recv(512)
            if len(data) < 3:
                continue

            event_code = data[1]
            if event_code == 0xFF:
                saw_vendor_event = True
            elif event_code == 0x0E:
                # Command Complete — done collecting
                break

        if saw_vendor_event:
            success(f"DarkFirmware confirmed on {hci} (LMP TX vendor-event echo)")
        return saw_vendor_event

    def init_hooks(self, hci: str | None = None) -> dict:
        """Activate Hooks 3+4 by writing backup pointers to RAM.

        Hooks 1+2 are persistent in the firmware binary — they survive USB
        resets because the hook installer writes them into the patch area.

        Hooks 3+4 have their shim code baked into the firmware binary, but
        the boot process reinitializes the tLC_TX/tLC_RX function pointers
        from ROM *after* patch loading.  The shim code reads the original
        handler address from backup RAM locations to chain back.  We must
        write those backup pointers here (<10ms, 2 memory writes).

        Returns:
            {"hook1": bool, "hook2": bool, "hook3": bool, "hook4": bool,
             "all_ok": bool}
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        result = {
            "hook1": False, "hook2": False,
            "hook3": False, "hook4": False,
            "all_ok": False,
        }

        hci = self._resolve_hci(hci)
        if hci is None:
            return result

        try:
            from blue_tap.hardware.hci_vsc import HCIVSCSocket

            hci_idx = int(hci.replace("hci", ""))
            with HCIVSCSocket(hci_dev=hci_idx) as sock:
                # Verify Hooks 1+2 are already active (persistent)
                h1_data = sock.read_memory(HOOK1_BACKUP_ADDR, 4)
                h2_data = sock.read_memory(HOOK2_BACKUP_ADDR, 4)

                result["hook1"] = bool(h1_data and any(b != 0 for b in h1_data))
                result["hook2"] = bool(h2_data and any(b != 0 for b in h2_data))

                if not result["hook1"]:
                    warning(f"Hook 1 not active on {hci} — DarkFirmware may not be loaded")
                    return result

                # Write Hook 3 backup: original tLC_TX handler
                ok3 = sock.write_memory(
                    HOOK3_BACKUP_ADDR,
                    struct.pack("<I", HOOK3_ORIGINAL),
                )
                if ok3:
                    # Verify
                    verify = sock.read_memory(HOOK3_BACKUP_ADDR, 4)
                    result["hook3"] = bool(verify and any(b != 0 for b in verify))
                    if result["hook3"]:
                        info(f"Hook 3 (tLC_TX) activated on {hci}")
                    else:
                        warning(f"Hook 3 write succeeded but verify failed on {hci}")
                else:
                    warning(f"Hook 3 backup write failed on {hci}")

                # Write Hook 4 backup: original tLC_RX handler
                ok4 = sock.write_memory(
                    HOOK4_BACKUP_ADDR,
                    struct.pack("<I", HOOK4_ORIGINAL),
                )
                if ok4:
                    verify = sock.read_memory(HOOK4_BACKUP_ADDR, 4)
                    result["hook4"] = bool(verify and any(b != 0 for b in verify))
                    if result["hook4"]:
                        info(f"Hook 4 (tLC_RX) activated on {hci}")
                    else:
                        warning(f"Hook 4 write succeeded but verify failed on {hci}")
                else:
                    warning(f"Hook 4 backup write failed on {hci}")

                result["all_ok"] = all(
                    result[k] for k in ("hook1", "hook2", "hook3", "hook4")
                )

                if result["all_ok"]:
                    success(f"All 4 DarkFirmware hooks active on {hci}")
                else:
                    active = [k for k in ("hook1", "hook2", "hook3", "hook4") if result[k]]
                    failed = [k for k in ("hook1", "hook2", "hook3", "hook4") if not result[k]]
                    warning(
                        f"DarkFirmware hooks on {hci}: "
                        f"active=[{', '.join(active)}] failed=[{', '.join(failed)}]"
                    )

        except PermissionError:
            warning(f"Cannot init hooks on {hci} — need root or CAP_NET_RAW")
        except OSError as exc:
            warning(f"HCI socket error during hook init on {hci}: {exc}")
        except Exception as exc:
            warning(f"Hook init failed on {hci}: {exc}")

        return result

    def get_firmware_status(self, hci: str | None = None) -> dict:
        """Return firmware status information.

        Returns:
            {installed: bool, loaded: bool, bdaddr: str,
             original_backed_up: bool, capabilities: list[str],
             hooks: dict}
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        status: dict = {
            "installed": os.path.exists(FIRMWARE_PATH),
            "loaded": False,
            "bdaddr": "",
            "original_backed_up": os.path.exists(FIRMWARE_ORIG),
            "capabilities": [],
            "hooks": {},
        }

        hci = self._resolve_hci(hci)
        if hci is None:
            return status

        status["bdaddr"] = self.get_current_bdaddr(hci)

        if self.detect_rtl8761b(hci):
            if self.is_darkfirmware_loaded(hci):
                status["loaded"] = True
                status["capabilities"] = [
                    "lmp_injection",
                    "lmp_monitoring",
                    "memory_rw",
                    "bdaddr_patch",
                ]
                # Check individual hook status by reading backup addresses
                try:
                    from blue_tap.hardware.hci_vsc import HCIVSCSocket

                    hci_idx = int(hci.replace("hci", ""))
                    with HCIVSCSocket(hci_dev=hci_idx) as sock:
                        for name, addr in (
                            ("hook1_hci_cmd", HOOK1_BACKUP_ADDR),
                            ("hook2_lmp_rx", HOOK2_BACKUP_ADDR),
                            ("hook3_lc_tx", HOOK3_BACKUP_ADDR),
                            ("hook4_lc_rx", HOOK4_BACKUP_ADDR),
                        ):
                            data = sock.read_memory(addr, 4)
                            status["hooks"][name] = bool(
                                data and any(b != 0 for b in data)
                            )
                except Exception:
                    pass  # Non-fatal — hooks info is optional

        return status

    def get_current_bdaddr(self, hci: str | None = None) -> str:
        """Read BDADDR from hciconfig output for the given HCI device."""
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        hci = self._resolve_hci(hci)
        if hci is None:
            return ""
        result = run_cmd(["hciconfig", hci])
        if result.returncode != 0:
            return ""
        m = re.search(r"BD Address:\s+([0-9A-Fa-f:]{17})", result.stdout)
        return m.group(1) if m else ""

    def patch_bdaddr(self, target_mac: str, hci: str | None = None) -> bool:
        """Patch BDADDR in firmware file and USB reset to apply.

        Steps:
          1. Validate MAC format (XX:XX:XX:XX:XX:XX)
          2. Reverse byte order: AA:BB:CC:DD:EE:FF -> bytes FF EE DD CC BB AA
          3. Write 6 bytes at BDADDR_OFFSET in FIRMWARE_PATH
          4. Call usb_reset()
          5. Sleep 2.5 seconds for firmware reload
          6. Verify via get_current_bdaddr()

        Requires root for firmware file write.
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        hci = self._resolve_hci(hci)
        if hci is None:
            return False

        # Validate MAC format
        from blue_tap.utils.bt_helpers import validate_mac, normalize_mac
        target_mac = normalize_mac(target_mac)
        if not validate_mac(target_mac):
            error(f"Invalid MAC address: {target_mac}")
            return False

        if not os.path.exists(FIRMWARE_PATH):
            error(f"Firmware file not found: {FIRMWARE_PATH}")
            return False

        # Validate firmware file is large enough for the BDADDR offset
        fw_size = os.path.getsize(FIRMWARE_PATH)
        if fw_size < BDADDR_OFFSET + 6:
            error(
                f"Firmware file too small ({fw_size} bytes) for BDADDR offset "
                f"0x{BDADDR_OFFSET:04X} — file may be corrupt"
            )
            return False

        # Parse MAC and reverse byte order for firmware binary
        mac_bytes = bytes(int(b, 16) for b in target_mac.split(":"))
        mac_reversed = mac_bytes[::-1]  # AA:BB:CC:DD:EE:FF -> FF EE DD CC BB AA

        info(f"Patching BDADDR in firmware: {target_mac} (offset 0x{BDADDR_OFFSET:X})")

        # Atomic patch: copy → modify tmp → os.replace so the target is never
        # in a partially-written state even if the process is killed mid-patch.
        tmp_path = FIRMWARE_PATH + ".tmp"
        try:
            shutil.copy2(FIRMWARE_PATH, tmp_path)
            with open(tmp_path, "r+b") as fw:
                fw.seek(BDADDR_OFFSET)
                fw.write(mac_reversed)
            os.replace(tmp_path, FIRMWARE_PATH)
            success(f"Firmware BDADDR patched to {target_mac}")
        except PermissionError:
            _cleanup_tmp(tmp_path)
            error(f"Permission denied writing to {FIRMWARE_PATH} — run as root")
            return False
        except OSError as exc:
            _cleanup_tmp(tmp_path)
            error(f"Failed to patch firmware: {exc}")
            return False

        # USB reset to reload firmware
        if not self.usb_reset():
            warning("USB reset failed — firmware may not reload until manual replug")
            return False

        # Wait for firmware to reload
        info("Waiting for firmware reload after USB reset...")
        time.sleep(2.5)

        # Verify the address changed
        new_addr = self.get_current_bdaddr(hci)
        if new_addr and new_addr.upper() == target_mac.upper():
            success(f"BDADDR verified: {hci} = {new_addr}")
            return True
        else:
            warning(f"BDADDR after reset: {new_addr} (expected {target_mac})")
            warning("Adapter may need additional time or manual replug to apply")
            return False

    def patch_bdaddr_ram(self, target_mac: str, hci: str | None = None) -> bool:
        """Live-patch BDADDR in controller RAM without modifying the firmware file.

        Writes the new BDADDR to all known locations in the RTL8761B's RAM
        where the controller stores address copies.  This is instant (no USB
        reset, no firmware reload) and volatile — the change is lost on
        adapter reset or replug.

        Requires DarkFirmware for memory write access (VSC 0xFC62).

        Discovery method:
          The BDADDR locations were found by scanning RAM 0x80100000-0x80134000
          for the current BDADDR pattern.  RTL8761B stores 5 copies:
            - 0x80111605: patch area (firmware's own BDADDR for LMP)
            - 0x801200A0: HCI state (controller's active BD_ADDR)
            - 0x80120470: HCI state (advertising/scan response)
            - 0x80122DFC: HCI state (page scan address)
            - 0x8012384E: HCI state (event filter address)

        Steps:
          1. Read current BDADDR from RAM to find all copies dynamically
          2. Write new BDADDR (reversed) to each location
          3. Verify each write by reading back
          4. Reset HCI device to refresh host stack cache

        Args:
            target_mac: Target MAC address (XX:XX:XX:XX:XX:XX).
            hci: HCI device name (default "<hciX>").

        Returns:
            True if all RAM writes succeeded and verification passed.
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        from blue_tap.utils.bt_helpers import validate_mac, normalize_mac

        target_mac = normalize_mac(target_mac)
        if not validate_mac(target_mac):
            error(f"Invalid MAC address: {target_mac}")
            return False

        if not self.is_darkfirmware_loaded(hci):
            error("DarkFirmware not loaded — RAM BDADDR patch requires VSC memory access")
            return False

        # Parse current and target MAC bytes (reversed for firmware storage)
        current_addr = self.get_current_bdaddr(hci)
        if not current_addr:
            error("Cannot read current BDADDR — adapter may be down")
            return False

        current_bytes = bytes(int(b, 16) for b in current_addr.split(":"))[::-1]
        target_bytes = bytes(int(b, 16) for b in target_mac.split(":"))[::-1]

        info(f"RAM BDADDR patch: {current_addr} → {target_mac}")

        # Known BDADDR locations in RTL8761B RAM (DarkFirmware binary, v1).
        # Discovered by prior full-RAM scan; using fixed addresses is ~instant
        # vs. the 53K VSC reads a dynamic scan requires (which times out).
        _KNOWN_BDADDR_ADDRS = [
            0x80111605,  # patch area — firmware's own BDADDR for LMP
            0x801200A0,  # HCI state — controller active BD_ADDR
            0x80120470,  # HCI state — advertising/scan response
            0x80122DFC,  # HCI state — page scan address
            0x8012384E,  # HCI state — event filter address
        ]

        hci_idx = int(hci.replace("hci", "")) if hci.startswith("hci") else 0

        try:
            from blue_tap.hardware.hci_vsc import HCIVSCSocket

            with HCIVSCSocket(hci_dev=hci_idx) as sock:
                # Write new BDADDR to each known location and verify.
                patched = 0
                verified = 0
                for loc in _KNOWN_BDADDR_ADDRS:
                    ok = self._write_bdaddr_at(sock, loc, target_bytes)
                    if ok:
                        patched += 1
                        readback = self._read_bytes_at(sock, loc, 6)
                        if readback == target_bytes:
                            verified += 1
                        else:
                            warning(f"  Verify failed at {loc:#010x}")
                    else:
                        warning(f"  Write failed at {loc:#010x}")

                if patched == 0:
                    error("All RAM BDADDR writes failed")
                    return False

                info(f"Patched {patched}/{len(_KNOWN_BDADDR_ADDRS)} locations, "
                     f"{verified} verified")

        except PermissionError:
            error("Cannot access HCI socket — need root or CAP_NET_RAW")
            return False
        except Exception as exc:
            error(f"RAM BDADDR patch failed: {exc}")
            return False

        # Step 4: Reset HCI to refresh host stack's cached address
        info("Resetting HCI device to refresh host stack...")
        run_cmd(["sudo", "hciconfig", hci, "reset"])
        time.sleep(1)
        run_cmd(["sudo", "hciconfig", hci, "up"])
        time.sleep(0.5)

        # Verify via hciconfig
        new_addr = self.get_current_bdaddr(hci)
        if new_addr and new_addr.upper() == target_mac.upper():
            success(f"RAM BDADDR patch verified: {hci} = {new_addr}")
            return True
        else:
            warning(
                f"RAM patched but hciconfig shows {new_addr} (expected {target_mac}). "
                f"Host stack may need btmgmt power cycle to refresh."
            )
            # Try btmgmt power cycle as fallback
            idx = hci.replace("hci", "")
            run_cmd(["sudo", "btmgmt", "--index", idx, "power", "off"])
            time.sleep(0.5)
            run_cmd(["sudo", "btmgmt", "--index", idx, "power", "on"])
            time.sleep(0.5)

            new_addr = self.get_current_bdaddr(hci)
            if new_addr and new_addr.upper() == target_mac.upper():
                success(f"RAM BDADDR patch verified after power cycle: {hci} = {new_addr}")
                return True

            warning(f"BDADDR still shows {new_addr} — RAM patch applied but host cache stale")
            return False

    @staticmethod
    def _write_bdaddr_at(sock: object, addr: int, mac_bytes: bytes) -> bool:
        """Write 6 BDADDR bytes at a potentially unaligned address.

        Memory writes on RTL8761B must be 4-byte aligned.  For an unaligned
        6-byte write we do read-modify-write on the boundary words.
        """
        align_offset = addr & 3
        aligned_addr = addr & ~3

        if align_offset == 0:
            # Perfectly aligned: write first 4 bytes, then read-modify-write last 2
            ok1 = sock.write_memory(aligned_addr, mac_bytes[:4])
            # Read the next word, replace first 2 bytes
            existing = sock.read_memory(aligned_addr + 4, 4)
            if not existing or len(existing) < 4:
                return False
            modified = mac_bytes[4:6] + existing[2:]
            ok2 = sock.write_memory(aligned_addr + 4, modified)
            return ok1 and ok2

        elif align_offset == 1:
            # 1 byte into a word: read word, replace bytes 1-3, write back
            w0 = sock.read_memory(aligned_addr, 4)
            if not w0 or len(w0) < 4:
                return False
            modified0 = bytes([w0[0]]) + mac_bytes[:3]
            ok1 = sock.write_memory(aligned_addr, modified0)
            # Next word: replace bytes 0-2
            w1 = sock.read_memory(aligned_addr + 4, 4)
            if not w1 or len(w1) < 4:
                return False
            modified1 = mac_bytes[3:6] + bytes([w1[3]])
            ok2 = sock.write_memory(aligned_addr + 4, modified1)
            return ok1 and ok2

        elif align_offset == 2:
            # 2 bytes into a word: read word, replace bytes 2-3
            w0 = sock.read_memory(aligned_addr, 4)
            if not w0 or len(w0) < 4:
                return False
            modified0 = w0[:2] + mac_bytes[:2]
            ok1 = sock.write_memory(aligned_addr, modified0)
            # Next word: full 4 bytes
            ok2 = sock.write_memory(aligned_addr + 4, mac_bytes[2:6])
            return ok1 and ok2

        else:  # align_offset == 3
            # 3 bytes into a word: read word, replace byte 3
            w0 = sock.read_memory(aligned_addr, 4)
            if not w0 or len(w0) < 4:
                return False
            modified0 = w0[:3] + mac_bytes[:1]
            ok1 = sock.write_memory(aligned_addr, modified0)
            # Next word: full 4 bytes
            ok2 = sock.write_memory(aligned_addr + 4, mac_bytes[1:5])
            # Third word: read, replace byte 0
            w2 = sock.read_memory(aligned_addr + 8, 4)
            if not w2 or len(w2) < 4:
                return False
            modified2 = mac_bytes[5:6] + w2[1:]
            ok3 = sock.write_memory(aligned_addr + 8, modified2)
            return ok1 and ok2 and ok3

    @staticmethod
    def _read_bytes_at(sock: object, addr: int, length: int) -> bytes:
        """Read *length* bytes from a potentially unaligned address."""
        result = b""
        aligned_start = addr & ~3
        total_words = ((addr + length) - aligned_start + 3) // 4

        for i in range(total_words):
            word = sock.read_memory(aligned_start + i * 4, 4)
            result += word if word else b"\x00" * 4

        offset = addr - aligned_start
        return result[offset:offset + length]

    def install_firmware(self, source_path: str | None = None) -> bool:
        """Install DarkFirmware, backing up the original first.

        If *source_path* is not given, uses the pre-patched firmware
        bundled with the Blue-Tap package (includes DarkFirmware hooks
        + LMP send limit raised to 17 bytes).

        Requires root for writing to ``/lib/firmware/``.

        Args:
            source_path: Path to a DarkFirmware binary, or ``None`` to use
                         the bundled version.

        Returns:
            True on success, False on failure.
        """
        if source_path is None:
            from blue_tap.firmware import get_firmware_path
            source_path = get_firmware_path("rtl8761bu_fw_darkfirmware.bin")
            info(f"Using bundled DarkFirmware: {source_path}")
        else:
            info(f"Installing DarkFirmware from {source_path}")

        if not os.path.exists(source_path):
            error(f"Source firmware not found: {source_path}")
            return False

        # Backup original firmware if not already backed up (idempotent)
        if os.path.exists(FIRMWARE_PATH) and not os.path.exists(FIRMWARE_ORIG):
            try:
                shutil.copy2(FIRMWARE_PATH, FIRMWARE_ORIG)
                success(f"Original firmware backed up to {FIRMWARE_ORIG}")
            except OSError as exc:
                error(f"Failed to backup original firmware: {exc}")
                return False

        # Copy DarkFirmware to system firmware path
        try:
            shutil.copy2(source_path, FIRMWARE_PATH)
            success(f"DarkFirmware installed to {FIRMWARE_PATH}")
            return True
        except PermissionError:
            error(f"Permission denied writing to {FIRMWARE_PATH} — run as root")
            return False
        except OSError as exc:
            error(f"Failed to install firmware: {exc}")
            return False

    def restore_firmware(self) -> bool:
        """Restore original firmware from backup.

        Returns:
            True on success, False on failure.
        """
        info("Restoring original firmware from backup")
        if not os.path.exists(FIRMWARE_ORIG):
            error(f"No original firmware backup found at {FIRMWARE_ORIG}")
            return False

        try:
            shutil.copy2(FIRMWARE_ORIG, FIRMWARE_PATH)
            success(f"Original firmware restored from {FIRMWARE_ORIG}")
            return True
        except PermissionError:
            error(f"Permission denied writing to {FIRMWARE_PATH} — run as root")
            return False
        except OSError as exc:
            error(f"Failed to restore firmware: {exc}")
            return False

    def usb_reset(self) -> bool:
        """Reset the USB device to force firmware reload.

        Runs ``usbreset`` on the USB VID:PID.

        Returns:
            True on success, False on failure.
        """
        info(f"Resetting USB device {USB_VID_PID}...")
        result = run_cmd(["usbreset", USB_VID_PID], timeout=10)
        if result.returncode == 0:
            success(f"USB reset complete for {USB_VID_PID}")
            return True
        else:
            warning(f"usbreset failed (rc={result.returncode}): {result.stderr.strip()}")
            return False

    # ------------------------------------------------------------------
    # Runtime firmware patching (write_memory to modify running firmware)
    # ------------------------------------------------------------------

    def _patch_firmware_byte(
        self,
        file_offset: int,
        ram_addr: int,
        new_value: int,
        verify_opcode_byte: int,
        label: str,
        hci: str | None = None,
    ) -> bool:
        """Patch a single byte in both the firmware file (persistent) and RAM (immediate).

        Patches the on-disk firmware so every future reset/replug loads the
        patched value automatically.  Also applies the change to live RAM so
        the current session takes effect immediately without a reset.

        Safety: verifies the MIPS16e instruction opcode byte at offset+1
        before writing to prevent corruption if the firmware layout changes.

        Args:
            file_offset: Byte offset in the firmware file.
            ram_addr: Corresponding RAM address for live patching.
            new_value: New byte value to write (0-255).
            verify_opcode_byte: Expected MIPS16e opcode byte at offset+1.
            label: Human-readable name for logging (e.g. "send length").
            hci: HCI device name.

        Returns:
            True if both file and RAM patches succeeded.
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        hci = self._resolve_hci(hci)

        # --- Step 1: Patch the firmware FILE (persistent across resets) ---
        if not os.path.exists(FIRMWARE_PATH):
            error(f"Firmware file not found: {FIRMWARE_PATH}")
            return False

        fw_size = os.path.getsize(FIRMWARE_PATH)
        if fw_size < file_offset + 2:
            error(f"Firmware file too small for {label} patch at offset 0x{file_offset:04X}")
            return False

        # Read current value from file for verification
        with open(FIRMWARE_PATH, "rb") as f:
            f.seek(file_offset)
            current_bytes = f.read(2)

        current_value = current_bytes[0]
        opcode_byte = current_bytes[1]

        if opcode_byte != verify_opcode_byte:
            error(
                f"Unexpected instruction opcode at file offset 0x{file_offset:04X}: "
                f"0x{opcode_byte:02X} (expected 0x{verify_opcode_byte:02X}). "
                f"Firmware layout may have changed — aborting to avoid corruption."
            )
            return False

        info(f"Current {label}: {current_value} (file offset 0x{file_offset:04X})")

        if current_value == new_value:
            info(f"{label.capitalize()} already set to {new_value} in firmware file")
        else:
            # Atomic patch: copy → modify tmp → os.replace, same as patch_bdaddr.
            tmp_path = FIRMWARE_PATH + ".tmp"
            try:
                shutil.copy2(FIRMWARE_PATH, tmp_path)
                with open(tmp_path, "r+b") as f:
                    f.seek(file_offset)
                    f.write(bytes([new_value]))
                os.replace(tmp_path, FIRMWARE_PATH)
            except OSError as exc:
                _cleanup_tmp(tmp_path)
                error(f"Atomic firmware byte patch failed: {exc}")
                return False

            # Verify file write
            with open(FIRMWARE_PATH, "rb") as f:
                f.seek(file_offset)
                verify = f.read(1)

            if verify[0] != new_value:
                error(f"File write verification failed for {label}")
                return False

            success(f"{label.capitalize()} patched in firmware file: {current_value} → {new_value}")

        # --- Step 2: Patch live RAM (immediate effect, no reset needed) ---
        if hci is None:
            return True  # File patch succeeded; no adapter to RAM-patch

        hci_idx = int(hci.replace("hci", ""))

        try:
            from blue_tap.hardware.hci_vsc import HCIVSCSocket

            with HCIVSCSocket(hci_idx) as vsc:
                # Read current RAM to get the next 2 bytes (preserve them)
                current_ram = vsc.read_memory(ram_addr, size=4)
                if len(current_ram) != 4:
                    warning(f"Could not read 4 bytes of RAM at 0x{ram_addr:08X} (got {len(current_ram)}) — "
                            f"file patched but RAM not updated. Reset adapter to apply.")
                    return True  # File patch succeeded

                ram_opcode = current_ram[1] if len(current_ram) > 1 else 0
                if ram_opcode != verify_opcode_byte:
                    warning(
                        f"RAM instruction mismatch at 0x{ram_addr:08X}: 0x{ram_opcode:02X}. "
                        f"File patched OK. Reset adapter to apply."
                    )
                    return True

                # Write: [new_value] [opcode_byte] [next 2 bytes preserved]
                next_bytes = current_ram[2:4]
                patch_data = bytes([new_value, verify_opcode_byte]) + next_bytes
                ok = vsc.write_memory(ram_addr, patch_data)

                if ok:
                    info(f"{label.capitalize()} also applied to live RAM at 0x{ram_addr:08X}")
                else:
                    warning(f"RAM write failed — file patched OK. Reset adapter to apply.")

        except Exception as exc:
            warning(f"RAM patch skipped ({exc}) — file patched OK. Reset adapter to apply.")

        return True

    def patch_send_length(self, new_length: int, hci: str | None = None) -> bool:
        """Patch the LMP send length limit — persistent across resets.

        Patches both the firmware file on disk AND the live RAM.  Every
        future USB reset, replug, or reboot automatically loads the patched
        value.  No watchdog or manual re-patching needed.

        DarkFirmware hardcodes ``li $a2, 0x0A`` (10 bytes) before calling
        ``send_LMP_reply()``.  The BT Core Spec max LMP PDU is 17 bytes
        (opcode + 16 params).  Values >17 enable oversized fuzzing.

        Verified safe on RTL8761BUV: 17-byte sends confirmed working with
        full echo-back via HCI Event 0xFF.

        Args:
            new_length: New LMP send length (1-255).  17 recommended.
            hci: HCI device name.

        Returns:
            True if the persistent patch was applied.
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        if not 1 <= new_length <= 255:
            error(f"Send length must be 1-255, got {new_length}")
            return False

        return self._patch_firmware_byte(
            file_offset=LMP_SEND_LENGTH_FILE_OFFSET,
            ram_addr=LMP_SEND_LENGTH_ADDR,
            new_value=new_length,
            verify_opcode_byte=LMP_SEND_LENGTH_VERIFY_BYTE,
            label="LMP send length",
            hci=hci,
        )

    def restore_send_length(self, hci: str | None = None) -> bool:
        """Restore the original 10-byte LMP send length limit."""
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        return self.patch_send_length(LMP_SEND_LENGTH_DEFAULT, hci)

    def patch_connection_index(self, index: int, hci: str | None = None) -> bool:
        """Patch which ACL connection slot receives LMP injection — persistent.

        Patches both firmware file and live RAM.  Connection index survives
        USB resets and replugs.

        Args:
            index: Connection slot index (0-11).
            hci: HCI device name.

        Returns:
            True if the persistent patch was applied.
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        if not 0 <= index <= 11:
            error(f"Connection index must be 0-11, got {index}")
            return False

        return self._patch_firmware_byte(
            file_offset=LMP_CONNECTION_INDEX_FILE_OFFSET,
            ram_addr=LMP_CONNECTION_INDEX_ADDR,
            new_value=index,
            verify_opcode_byte=LMP_CONNECTION_INDEX_VERIFY_BYTE,
            label="connection index",
            hci=hci,
        )

    def restore_connection_index(self, hci: str | None = None) -> bool:
        """Restore the original connection index 0."""
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        return self.patch_connection_index(LMP_CONNECTION_INDEX_DEFAULT, hci)

    # ------------------------------------------------------------------
    # Memory dumping
    # ------------------------------------------------------------------

    def dump_memory(self, start: int, end: int, output: str, hci: str | None = None) -> bool:
        """Dump controller memory range to a file via sequential VSC 0xFC61 reads.

        Reads 4 bytes at a time. Invalid memory returns 0xDEADBEEF. Progress
        is displayed via Rich progress bar.

        Args:
            start: Start address (e.g., 0x80000000 for ROM).
            end: End address (exclusive).
            output: Output file path for raw binary dump.
            hci: HCI device name.

        Returns:
            True on success, False on failure.
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        hci = self._resolve_hci(hci)
        if hci is None:
            return False

        if end <= start:
            error(f"End address (0x{end:08X}) must be greater than start (0x{start:08X})")
            return False

        total_bytes = end - start
        info(
            f"Dumping memory 0x{start:08X} - 0x{end:08X} "
            f"({total_bytes:,} bytes) to {output}"
        )

        hci_idx = int(hci.replace("hci", ""))
        valid_bytes = 0
        invalid_regions: list[tuple[int, int]] = []  # (region_start, region_end)
        in_invalid = False
        invalid_start = 0
        last_pct = -1

        try:
            from blue_tap.hardware.hci_vsc import HCIVSCSocket
            from rich.progress import Progress

            with HCIVSCSocket(hci_dev=hci_idx) as sock, \
                 open(output, "wb") as f, \
                 Progress() as progress:
                task = progress.add_task(
                    f"[cyan]Dumping 0x{start:08X}..0x{end:08X}",
                    total=total_bytes,
                )

                addr = start
                while addr < end:
                    chunk_size = min(4, end - addr)
                    try:
                        data = sock.read_memory(addr, chunk_size)
                    except (OSError, TimeoutError) as exc:
                        error(f"Memory read failed at 0x{addr:08X}: {exc}")
                        return False

                    if len(data) < chunk_size:
                        # Pad short reads with 0xDE to maintain alignment
                        warning(f"Short read at 0x{addr:08X}: got {len(data)} bytes, expected {chunk_size}")
                        data = data + b"\xde" * (chunk_size - len(data))

                    # Check for invalid memory marker
                    is_dead = (chunk_size == 4 and data[:4] == b"\xef\xbe\xad\xde")
                    if is_dead:
                        if not in_invalid:
                            in_invalid = True
                            invalid_start = addr
                    else:
                        if in_invalid:
                            in_invalid = False
                            invalid_regions.append((invalid_start, addr))
                            warning(
                                f"Invalid memory at 0x{invalid_start:08X} - "
                                f"0x{addr:08X} (0xDEADBEEF)"
                            )
                        valid_bytes += chunk_size

                    f.write(data[:chunk_size])
                    addr += chunk_size
                    progress.update(task, advance=chunk_size)

                    # Log progress every 10%
                    pct = ((addr - start) * 100) // total_bytes
                    if pct // 10 > last_pct // 10 and pct > 0:
                        last_pct = pct
                        done_kb = (addr - start) // 1024
                        total_kb = total_bytes // 1024
                        info(
                            f"Progress: {pct}% ({done_kb}KB / {total_kb}KB), "
                            f"{len(invalid_regions)} invalid regions skipped"
                        )

                # Close trailing invalid region
                if in_invalid:
                    invalid_regions.append((invalid_start, addr))
                    warning(
                        f"Invalid memory at 0x{invalid_start:08X} - "
                        f"0x{addr:08X} (0xDEADBEEF)"
                    )

        except PermissionError:
            error(f"Cannot open HCI socket on {hci} — need root or CAP_NET_RAW")
            return False
        except OSError as exc:
            error(f"HCI socket error on {hci}: {exc}")
            return False
        except Exception as exc:
            error(f"Memory dump failed: {exc}")
            return False

        invalid_bytes = total_bytes - valid_bytes
        success(
            f"Memory dump complete: {total_bytes:,} bytes written to {output} "
            f"({valid_bytes:,} valid, {invalid_bytes:,} invalid/0xDEADBEEF, "
            f"{len(invalid_regions)} invalid region(s))"
        )
        return True

    # ------------------------------------------------------------------
    # Connection state inspection
    # ------------------------------------------------------------------

    def dump_connections(self, hci: str | None = None) -> list[dict]:
        """Read all 12 connection slots from firmware RAM.

        Reads the bos[] array at CONNECTION_TABLE_BASE. Each slot is
        CONNECTION_SLOT_SIZE bytes. Returns parsed connection info for
        slots that appear active (non-zero BD address).

        Returns:
            List of dicts with keys: slot, raw_hex, bd_addr (if parseable),
            active (bool based on non-zero check).
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        hci = self._resolve_hci(hci)
        if hci is None:
            return []

        hci_idx = int(hci.replace("hci", ""))
        results: list[dict] = []
        active_count = 0

        try:
            from blue_tap.hardware.hci_vsc import HCIVSCSocket

            with HCIVSCSocket(hci_dev=hci_idx) as sock:
                for slot_idx in range(CONNECTION_MAX_SLOTS):
                    info(f"Reading connection slot {slot_idx + 1}/{CONNECTION_MAX_SLOTS}...")
                    slot_addr = CONNECTION_TABLE_BASE + (slot_idx * CONNECTION_SLOT_SIZE)

                    # Read first 64 bytes (the interesting part)
                    data = b""
                    for offset in range(0, 64, 4):
                        try:
                            chunk = sock.read_memory(slot_addr + offset, 4)
                            data += chunk[:4] if len(chunk) >= 4 else chunk + b"\x00" * (4 - len(chunk))
                        except (OSError, TimeoutError) as exc:
                            warning(f"Read failed at slot {slot_idx} offset {offset}: {exc}")
                            data += b"\x00" * 4

                    # Probe candidate BD_ADDR offsets within the slot.
                    # RTL8761B struct (0x2B8 bytes) — offset 0 contains other
                    # fields; BD_ADDR is typically at 0x04 or 0x08.
                    # We try [0x04, 0x08, 0x00] in order and accept the first
                    # that looks like a real OUI-bearing address.
                    bd_addr = ""
                    active = False
                    for bd_off in (0x04, 0x08, 0x00):
                        if len(data) < bd_off + 6:
                            continue
                        bd = data[bd_off:bd_off + 6]
                        # Reject: all-zero, all-FF, or OUI (upper 3 bytes) is
                        # all-zero or all-FF — those are padding / uninit memory.
                        if all(b == 0x00 for b in bd):
                            continue
                        if all(b == 0xFF for b in bd):
                            continue
                        oui = bd[3:]  # MSB end in little-endian layout
                        if all(b == 0x00 for b in oui) or all(b == 0xFF for b in oui):
                            continue
                        bd_addr = ":".join(f"{b:02X}" for b in reversed(bd))
                        active = True
                        break

                    entry: dict = {
                        "slot": slot_idx,
                        "raw_hex": data.hex(),
                        "bd_addr": bd_addr,
                        "active": active,
                        "address": f"0x{slot_addr:08X}",
                    }
                    results.append(entry)

                    if active:
                        active_count += 1
                        info(f"  Slot {slot_idx}: ACTIVE — BD_ADDR {bd_addr}")
                    else:
                        info(f"  Slot {slot_idx}: inactive")

        except PermissionError:
            error(f"Cannot open HCI socket on {hci} — need root or CAP_NET_RAW")
            return []
        except OSError as exc:
            error(f"HCI socket error on {hci}: {exc}")
            return []
        except Exception as exc:
            error(f"Connection table read failed: {exc}")
            return []

        info(
            f"Connection table: {active_count} active, "
            f"{CONNECTION_MAX_SLOTS - active_count} inactive out of "
            f"{CONNECTION_MAX_SLOTS} slots"
        )
        return results

    def dump_connection_raw(
        self, slot: int, hci: str | None = None
    ) -> bytes:
        """Raw hex dump of a specific connection slot.

        Args:
            slot: Slot index (0-11).
            hci: HCI device name.

        Returns:
            Raw bytes of the full slot (CONNECTION_SLOT_SIZE bytes),
            or empty bytes on failure.
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        hci = self._resolve_hci(hci)
        if hci is None:
            return b""

        if not 0 <= slot < CONNECTION_MAX_SLOTS:
            error(f"Slot index must be 0-{CONNECTION_MAX_SLOTS - 1}, got {slot}")
            return b""

        slot_addr = CONNECTION_TABLE_BASE + (slot * CONNECTION_SLOT_SIZE)
        info(f"Dumping connection slot {slot} at 0x{slot_addr:08X} ({CONNECTION_SLOT_SIZE} bytes)...")

        hci_idx = int(hci.replace("hci", ""))
        data = b""

        try:
            from blue_tap.hardware.hci_vsc import HCIVSCSocket

            with HCIVSCSocket(hci_dev=hci_idx) as sock:
                for offset in range(0, CONNECTION_SLOT_SIZE, 4):
                    try:
                        chunk = sock.read_memory(slot_addr + offset, 4)
                        data += chunk[:4] if len(chunk) >= 4 else chunk + b"\x00" * (4 - len(chunk))
                    except (OSError, TimeoutError) as exc:
                        warning(f"Read failed at slot {slot} offset {offset}: {exc}")
                        data += b"\x00" * 4

        except PermissionError:
            error(f"Cannot open HCI socket on {hci} — need root or CAP_NET_RAW")
            return b""
        except OSError as exc:
            error(f"HCI socket error on {hci}: {exc}")
            return b""
        except Exception as exc:
            error(f"Connection slot dump failed: {exc}")
            return b""

        success(f"Slot {slot} dump complete: {len(data)} bytes from 0x{slot_addr:08X}")
        return data


# ---------------------------------------------------------------------------
# Connection State Inspector
# ---------------------------------------------------------------------------

class ConnectionInspector:
    """Read and manipulate live connection security state from RTL8761B RAM.

    Uses VSC 0xFC61/0xFC62 to read the firmware's internal connection table.
    The table has 12 slots at CONNECTION_TABLE_BASE (0x8012DC50), each
    CONNECTION_SLOT_SIZE (0x2B8 = 696) bytes.  Each slot has a pointer at
    +0x58 to a secondary struct containing encryption state, key material,
    and authentication state.

    All offsets were determined via Ghidra reverse engineering of the
    RTL8761B ROM and patch firmware (decompiled send_LMP_reply,
    LMP_ENCRYPTION_KEY_SIZE_REQ, LMP_COMB_KEY, LMP_AU_RAND).

    Requires DarkFirmware loaded and root/CAP_NET_RAW for HCI socket access.
    """

    def _read_byte(self, sock: object, addr: int) -> int | None:
        """Read a single byte from controller memory.

        Uses aligned 4-byte read via VSC 0xFC61 and extracts the target
        byte.  Handles firmware returning fewer than 4 bytes.
        """
        aligned = addr & ~3
        offset = addr & 3
        data = sock.read_memory(aligned, 4)
        if not data:
            return None
        if offset < len(data):
            return data[offset]
        return None

    def _read_bytes(self, sock: object, addr: int, count: int) -> bytes:
        """Read N bytes from controller memory via sequential aligned reads.

        Handles unaligned starting addresses correctly by tracking actual
        bytes extracted (not assuming 4 per read).
        """
        result = bytearray()
        pos = 0  # bytes collected so far
        while pos < count:
            cur_addr = addr + pos
            aligned = cur_addr & ~3
            byte_offset = cur_addr & 3
            data = sock.read_memory(aligned, 4)
            if data and len(data) >= 4:
                # Extract bytes from this word starting at byte_offset
                available = 4 - byte_offset
                needed = count - pos
                chunk = data[byte_offset:byte_offset + min(available, needed)]
                result.extend(chunk)
                pos += len(chunk)
            elif data:
                # Short read — take what we can
                if byte_offset < len(data):
                    chunk = data[byte_offset:]
                    result.extend(chunk[:count - pos])
                    pos += min(len(chunk), count - pos)
                else:
                    result.append(0)
                    pos += 1
            else:
                result.append(0)
                pos += 1
        return bytes(result[:count])

    def _write_byte(self, sock: object, addr: int, val: int) -> bool:
        """Write a single byte via read-modify-write on aligned 4-byte word.

        Reads the 4-byte aligned word, replaces one byte, writes back.
        """
        aligned = addr & ~3
        data = sock.read_memory(aligned, 4)
        if not data or len(data) < 4:
            # Pad short reads to 4 bytes
            if data:
                data = data + b"\x00" * (4 - len(data))
            else:
                return False
        word = struct.unpack("<I", data[:4])[0]
        shift = (addr & 3) * 8
        mask = ~(0xFF << shift) & 0xFFFFFFFF
        new_word = (word & mask) | ((val & 0xFF) << shift)
        return sock.write_memory(aligned, struct.pack("<I", new_word))

    def _get_secondary_ptr(self, sock: object, conn_index: int) -> int | None:
        """Read the secondary struct pointer for a connection slot."""
        bos_addr = CONNECTION_TABLE_BASE + conn_index * CONNECTION_SLOT_SIZE
        ptr_data = sock.read_memory(bos_addr + SECONDARY_PTR_OFFSET, 4)
        if not ptr_data or len(ptr_data) < 4:
            return None
        sec_ptr = struct.unpack("<I", ptr_data[:4])[0]
        # Validate pointer is in controller memory range
        if sec_ptr < 0x80000000 or sec_ptr > 0x80140000:
            return None
        return sec_ptr

    def inspect_connection(self, sock: object, conn_index: int) -> dict:
        """Read security state for a connection slot.

        Args:
            sock: Open HCIVSCSocket instance.
            conn_index: Connection slot (0-11).

        Returns:
            Dict with keys: active, conn_index, bdaddr, secondary_ptr,
            enc_key_size, enc_enabled, auth_state, secure_connections,
            state_machine_phase, pairing_stage,
            key_material_src (16B hex), key_material_copy (16B hex).
        """
        result: dict = {"active": False, "conn_index": conn_index}

        bos_addr = CONNECTION_TABLE_BASE + conn_index * CONNECTION_SLOT_SIZE

        # Read BD_ADDR (first 6 bytes of slot, stored little-endian)
        bdaddr_data = self._read_bytes(sock, bos_addr, 8)
        bdaddr = bdaddr_data[:6]

        # Slot is empty if BD_ADDR is all-zeros, all-FF, or the common
        # initialized-but-unconnected pattern (00:00:00:FF:FF:FF or FF:FF:FF:00:00:00)
        nonzero = sum(1 for b in bdaddr if b != 0)
        non_ff = sum(1 for b in bdaddr if b != 0xFF)
        if nonzero == 0 or non_ff == 0 or (nonzero <= 3 and non_ff <= 3):
            return result  # Empty or unconnected slot

        result["active"] = True
        result["bdaddr"] = ":".join(f"{b:02X}" for b in reversed(bdaddr))

        # Get secondary struct pointer
        sec_ptr = self._get_secondary_ptr(sock, conn_index)
        if sec_ptr is None:
            result["error"] = "invalid secondary pointer"
            return result
        result["secondary_ptr"] = f"0x{sec_ptr:08X}"

        # Read security-critical fields
        fields = {
            "state_machine_phase": SEC_OFF_STATE_BYTE,
            "pairing_stage": SEC_OFF_PAIRING_STAGE,
            "enc_key_size": SEC_OFF_KEY_SIZE,
            "enc_enabled": SEC_OFF_ENC_ENABLED,
            "auth_state": SEC_OFF_AUTH_STATE,
        }
        for name, offset in fields.items():
            val = self._read_byte(sock, sec_ptr + offset)
            result[name] = val

        # Secure Connections flag (at larger offset, may be in different word)
        sc = self._read_byte(sock, sec_ptr + SEC_OFF_SC_FLAG)
        result["secure_connections"] = sc

        # Key material (16-byte blocks)
        key_src = self._read_bytes(sock, sec_ptr + SEC_OFF_KEY_MATERIAL_SRC, 16)
        key_copy = self._read_bytes(sock, sec_ptr + SEC_OFF_KEY_MATERIAL_COPY, 16)
        result["key_material_src"] = key_src.hex()
        result["key_material_copy"] = key_copy.hex()

        return result

    def scan_all_connections(self, sock: object) -> list[dict]:
        """Scan all 12 connection slots and return active ones with security state."""
        results = []
        for i in range(CONNECTION_MAX_SLOTS):
            conn = self.inspect_connection(sock, i)
            if conn.get("active"):
                results.append(conn)
        return results

    # ------------------------------------------------------------------
    # State manipulation (for security research)
    # ------------------------------------------------------------------

    def force_encryption(self, sock: object, conn_index: int, enable: bool) -> bool:
        """Set or clear the encryption enabled flag in controller RAM."""
        sec_ptr = self._get_secondary_ptr(sock, conn_index)
        if sec_ptr is None:
            error(f"No valid connection at slot {conn_index}")
            return False
        val = 1 if enable else 0
        ok = self._write_byte(sock, sec_ptr + SEC_OFF_ENC_ENABLED, val)
        if ok:
            info(f"Slot {conn_index}: enc_enabled → {val}")
        return ok

    def force_auth_state(self, sock: object, conn_index: int, state: int = 0x04) -> bool:
        """Force authentication state (0x04 = authenticated in RE)."""
        sec_ptr = self._get_secondary_ptr(sock, conn_index)
        if sec_ptr is None:
            error(f"No valid connection at slot {conn_index}")
            return False
        ok = self._write_byte(sock, sec_ptr + SEC_OFF_AUTH_STATE, state)
        if ok:
            info(f"Slot {conn_index}: auth_state → 0x{state:02X}")
        return ok

    def clear_secure_connections(self, sock: object, conn_index: int) -> bool:
        """Clear the Secure Connections flag (downgrade to legacy pairing)."""
        sec_ptr = self._get_secondary_ptr(sock, conn_index)
        if sec_ptr is None:
            error(f"No valid connection at slot {conn_index}")
            return False
        ok = self._write_byte(sock, sec_ptr + SEC_OFF_SC_FLAG, 0x00)
        if ok:
            info(f"Slot {conn_index}: SC flag cleared")
        return ok

    def set_key_size(self, sock: object, conn_index: int, size: int) -> bool:
        """Set negotiated encryption key size (1-16 bytes)."""
        if not 1 <= size <= 16:
            error(f"Key size must be 1-16, got {size}")
            return False
        sec_ptr = self._get_secondary_ptr(sock, conn_index)
        if sec_ptr is None:
            error(f"No valid connection at slot {conn_index}")
            return False
        ok = self._write_byte(sock, sec_ptr + SEC_OFF_KEY_SIZE, size)
        if ok:
            info(f"Slot {conn_index}: key_size → {size}")
        return ok

    def write_key_material(self, sock: object, conn_index: int, key: bytes) -> bool:
        """Write 16-byte link key material to the connection slot."""
        if len(key) != 16:
            error(f"Key must be 16 bytes, got {len(key)}")
            return False
        sec_ptr = self._get_secondary_ptr(sock, conn_index)
        if sec_ptr is None:
            error(f"No valid connection at slot {conn_index}")
            return False
        # Write in 4-byte chunks
        for off in range(0, 16, 4):
            addr = sec_ptr + SEC_OFF_KEY_MATERIAL_COPY + off
            chunk = key[off:off + 4]
            if not sock.write_memory(addr, chunk):
                error(f"Key write failed at offset {off}")
                return False
        info(f"Slot {conn_index}: key material written ({key.hex()})")
        return True

    def zero_key_material(self, sock: object, conn_index: int) -> bool:
        """Zero out link key material."""
        return self.write_key_material(sock, conn_index, b"\x00" * 16)


# ---------------------------------------------------------------------------
# DarkFirmware Watchdog — auto-reinit hooks after USB reset/replug
# ---------------------------------------------------------------------------

class DarkFirmwareWatchdog:
    """Background watchdog that re-initializes DarkFirmware hooks after USB events.

    During long fuzzing sessions (hours/days), the USB adapter may be
    unplugged, replugged, or USB-reset by other operations.  When this
    happens, the firmware is reloaded from ``/lib/firmware/`` — Hooks 1+2
    survive (persistent in the binary) but Hooks 3+4 backup pointers in
    RAM are zeroed and mod mode settings are lost.

    The watchdog uses two complementary detection methods:

    1. **udevadm monitor** — Watches for USB add/remove events on the
       RTL8761B VID:PID (2357:0604).  Fires immediately on reconnect.
    2. **Periodic health check** — Every *poll_interval* seconds, reads
       Hook 3 backup address.  If zeroed, re-initializes all hooks.
       Catches events that udevadm missed.

    Usage::

        watchdog = DarkFirmwareWatchdog("<hciX>")
        watchdog.start()      # Background threads start
        # ... long fuzzing session ...
        watchdog.stop()       # Clean shutdown
    """

    def __init__(
        self,
        hci: str | None = None,
        poll_interval: float = 30.0,
        on_reinit: object | None = None,
    ) -> None:
        """
        Args:
            hci:           HCI device to monitor.
            poll_interval: Seconds between health checks (default 30s).
            on_reinit:     Optional callback ``(hci: str, event: str) -> None``
                           called after successful re-initialization.
        """
        if hci is None:

            from blue_tap.hardware.adapter import resolve_active_hci

            hci = resolve_active_hci()
        import threading

        if hci is None:
            hci = DarkFirmwareManager().find_rtl8761b_hci()

        self.hci = hci
        self.poll_interval = poll_interval
        self.on_reinit = on_reinit
        self._stop_event = threading.Event()
        self._udev_thread: threading.Thread | None = None
        self._poll_thread: threading.Thread | None = None
        self._fw = DarkFirmwareManager()
        self._reinit_lock = threading.Lock()
        self._reinit_count = 0
        self._last_reinit: float = 0.0
        self._reinit_in_progress = False

    @property
    def reinit_count(self) -> int:
        """Number of times hooks have been re-initialized."""
        with self._reinit_lock:
            return self._reinit_count

    def start(self) -> None:
        """Start both watchdog threads (udev monitor + periodic health check)."""
        import threading

        if self._poll_thread is not None:
            return  # Already running

        self._stop_event.clear()

        self._poll_thread = threading.Thread(
            target=self._health_check_loop,
            name="darkfw-health",
            daemon=True,
        )
        self._poll_thread.start()

        self._udev_thread = threading.Thread(
            target=self._udev_monitor_loop,
            name="darkfw-udev",
            daemon=True,
        )
        self._udev_thread.start()

        info(
            f"DarkFirmware watchdog started on {self.hci} "
            f"(poll={self.poll_interval}s, udev=realtime)"
        )

    def stop(self) -> None:
        """Stop both watchdog threads."""
        self._stop_event.set()

        if self._poll_thread is not None:
            self._poll_thread.join(timeout=5.0)
            self._poll_thread = None

        if self._udev_thread is not None:
            self._udev_thread.join(timeout=5.0)
            self._udev_thread = None

        with self._reinit_lock:
            final_count = self._reinit_count
        info(f"DarkFirmware watchdog stopped (reinit_count={final_count})")

    def _reinit_hooks(self, event: str) -> None:
        """Re-initialize hooks and notify."""
        with self._reinit_lock:
            now = time.monotonic()
            if self._reinit_in_progress:
                return
            if now - self._last_reinit < 5.0:
                return
            self._reinit_in_progress = True

        try:
            warning(f"DarkFirmware watchdog: {event} — re-initializing hooks on {self.hci}")

            time.sleep(3.0)

            if not self._fw.is_darkfirmware_loaded(self.hci):
                warning(
                    f"DarkFirmware not detected on {self.hci} after {event} — "
                    f"firmware may have been replaced"
                )
                return

            result = self._fw.init_hooks(self.hci)
        finally:
            with self._reinit_lock:
                self._last_reinit = time.monotonic()
                self._reinit_in_progress = False

        if result.get("all_ok"):
            with self._reinit_lock:
                self._reinit_count += 1
                count = self._reinit_count
            success(
                f"DarkFirmware watchdog: hooks re-initialized on {self.hci} "
                f"(total reinits: {count})"
            )
            if self.on_reinit:
                try:
                    self.on_reinit(self.hci, event)
                except Exception:
                    pass
        else:
            active = [k for k in ("hook1", "hook2", "hook3", "hook4") if result.get(k)]
            failed = [k for k in ("hook1", "hook2", "hook3", "hook4") if not result.get(k)]
            warning(
                f"DarkFirmware watchdog: partial reinit on {self.hci} — "
                f"active=[{', '.join(active)}] failed=[{', '.join(failed)}]"
            )

    def _health_check_loop(self) -> None:
        """Periodic health check: read Hook 3 backup, reinit if zeroed."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self.poll_interval)
            if self._stop_event.is_set():
                break

            try:
                from blue_tap.hardware.hci_vsc import HCIVSCSocket

                hci_idx = int(self.hci.replace("hci", ""))
                with HCIVSCSocket(hci_dev=hci_idx) as sock:
                    # Check Hook 3 backup — zeroed means USB reset happened
                    data = sock.read_memory(HOOK3_BACKUP_ADDR, 4)
                    if not data or all(b == 0 for b in data):
                        self._reinit_hooks("health check detected zeroed Hook 3")
            except OSError:
                # HCI device may be temporarily unavailable during USB event
                pass
            except Exception:
                pass

    def _udev_monitor_loop(self) -> None:
        """Watch udevadm monitor for USB add/remove events on RTL8761B.

        Spawns a single ``udevadm monitor`` subprocess and consumes its stdout.
        The process is always terminated on exit (clean stop or error) so
        watchdog teardown does not leak a zombie reader. If udevadm is missing
        or the subprocess dies unexpectedly the loop falls back to polling-only
        mode instead of respawning in a tight loop.
        """
        import subprocess

        while not self._stop_event.is_set():
            try:
                proc = subprocess.Popen(
                    ["udevadm", "monitor", "--udev", "--subsystem-match=usb"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
            except FileNotFoundError:
                # udevadm not available — fall back to polling only
                info("DarkFirmware watchdog: udevadm not found, using polling only")
                return
            except Exception as exc:
                warning(f"DarkFirmware watchdog: failed to start udevadm ({exc}); polling only")
                return

            try:
                while not self._stop_event.is_set():
                    line = proc.stdout.readline() if proc.stdout else ""
                    if not line:
                        # EOF or subprocess died — escape outer respawn loop.
                        break

                    # Look for RTL8761B VID:PID in udev events
                    # Format: "UDEV  [timestamp] add /devices/... (usb)"
                    line_lower = line.lower()
                    if "2357" in line and "0604" in line:
                        if "add" in line_lower or "bind" in line_lower:
                            info(f"DarkFirmware watchdog: USB reconnect detected")
                            self._reinit_hooks("USB reconnect (udev add)")
                        elif "remove" in line_lower or "unbind" in line_lower:
                            warning(f"DarkFirmware watchdog: USB disconnect detected on {self.hci}")
            except Exception:
                pass
            finally:
                try:
                    proc.terminate()
                    proc.wait(timeout=2.0)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            # Subprocess exited without a stop signal — don't respawn, the
            # periodic health check loop still covers the watchdog purpose.
            if not self._stop_event.is_set():
                info("DarkFirmware watchdog: udev monitor exited; using polling only")
            return
