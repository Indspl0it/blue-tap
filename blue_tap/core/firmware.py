"""DarkFirmware management for RTL8761B (TP-Link UB500).

Detects the RTL8761B adapter, checks whether DarkFirmware custom firmware is
loaded, patches the BDADDR in the firmware binary, and manages USB resets.

DarkFirmware extends the RTL8761B with vendor-specific HCI commands for:
  - LMP packet injection (VSC 0xFE22)
  - Controller memory read/write (VSC 0xFC61 / 0xFC62)
  - Passive LMP monitoring via HCI Event 0xFF

The BDADDR offset (0xAD85) was found by diffing the DarkFirmware 1337 and
1338 firmware variants.  The DarkFirmware presence check reads Hook 1's
backup location (0x80133FFC) which should contain 0x8010D891 when the
custom firmware hooks are active.
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

# Hook 1 backup address — should contain 0x8010D891 if DarkFirmware active
DARKFIRMWARE_CHECK_ADDR = 0x80133FFC
DARKFIRMWARE_CHECK_VALUE = 0x8010D891

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

# Connection table layout in firmware RAM
CONNECTION_TABLE_BASE = 0x8012DC50  # bos[] array base address
CONNECTION_SLOT_SIZE = 500          # ~500 bytes per slot (approximate)
CONNECTION_MAX_SLOTS = 12           # RTL8761B supports up to 12 connections


class DarkFirmwareManager:
    """Manage DarkFirmware installation, detection, and BDADDR patching."""

    def detect_rtl8761b(self, hci: str = "hci1") -> bool:
        """Detect RTL8761B via sysfs modalias or hciconfig manufacturer.

        Checks USB VID:PID 2357:0604 or Manufacturer ID 93 (Realtek).
        """
        # Method 1: Check sysfs modalias for USB VID:PID
        sys_path = f"/sys/class/bluetooth/{hci}/device"
        if os.path.islink(sys_path):
            real_path = os.path.realpath(sys_path)
            for parent in [real_path, os.path.dirname(real_path)]:
                modalias_file = os.path.join(parent, "modalias")
                if os.path.exists(modalias_file):
                    try:
                        with open(modalias_file) as f:
                            modalias = f.read().strip()
                        # USB modalias: usb:v2357p0604...
                        if "v2357p0604" in modalias.upper().replace("V", "v").replace("P", "p"):
                            info(f"RTL8761B detected on {hci} via sysfs modalias")
                            return True
                        # Also check for Realtek RTL8761B generic VID
                        if "v0BDAp8771" in modalias.upper().replace("V", "v").replace("P", "p"):
                            info(f"RTL8761B detected on {hci} via sysfs modalias (Realtek VID)")
                            return True
                    except OSError:
                        pass

        # Method 2: Check hciconfig manufacturer
        result = run_cmd(["hciconfig", "-a", hci])
        if result.returncode == 0:
            output = result.stdout
            # Manufacturer ID 93 = Realtek
            mfr_m = re.search(r"Manufacturer:\s*(.+)", output)
            if mfr_m:
                manufacturer = mfr_m.group(1).strip().lower()
                if "realtek" in manufacturer or "(93)" in manufacturer:
                    info(f"RTL8761B detected on {hci} via manufacturer: {mfr_m.group(1).strip()}")
                    return True

        # Method 3: Check lsusb for VID:PID
        result = run_cmd(["lsusb", "-d", USB_VID_PID])
        if result.returncode == 0 and result.stdout.strip():
            info(f"RTL8761B detected via lsusb ({USB_VID_PID})")
            return True

        warning(f"RTL8761B not detected on {hci}")
        return False

    def is_darkfirmware_loaded(self, hci: str = "hci1") -> bool:
        """Check if DarkFirmware is active by reading controller memory.

        Reads memory at DARKFIRMWARE_CHECK_ADDR via HCIVSCSocket.  If the
        value matches DARKFIRMWARE_CHECK_VALUE, DarkFirmware is confirmed.
        Falls back to checking if the BDADDR contains a 13:37 pattern
        (default DarkFirmware address marker).
        """
        # Primary: read Hook 1 backup via HCI VSC memory read
        try:
            from blue_tap.core.hci_vsc import HCIVSCSocket

            hci_idx = int(hci.replace("hci", ""))
            with HCIVSCSocket(hci_dev=hci_idx) as sock:
                data = sock.read_memory(DARKFIRMWARE_CHECK_ADDR, 4)
                if len(data) >= 4:
                    value = struct.unpack("<I", data[:4])[0]
                    if value == DARKFIRMWARE_CHECK_VALUE:
                        info(f"DarkFirmware confirmed on {hci} (Hook 1 backup = 0x{value:08X})")
                        return True
                    else:
                        warning(
                            f"Hook 1 backup at 0x{DARKFIRMWARE_CHECK_ADDR:08X} = "
                            f"0x{value:08X} (expected 0x{DARKFIRMWARE_CHECK_VALUE:08X})"
                        )
        except PermissionError:
            warning(f"Cannot read controller memory on {hci} — need root or CAP_NET_RAW")
        except OSError as exc:
            warning(f"HCI socket error checking DarkFirmware on {hci}: {exc}")
        except Exception as exc:
            warning(f"DarkFirmware memory check failed on {hci}: {exc}")

        # Fallback: check if BDADDR matches exact DarkFirmware default patterns
        _DARKFIRMWARE_DEFAULT_ADDRS = {"13:37:13:37:13:37", "13:38:13:38:13:38"}
        bdaddr = self.get_current_bdaddr(hci)
        if bdaddr and bdaddr.upper() in _DARKFIRMWARE_DEFAULT_ADDRS:
            info(f"DarkFirmware likely active on {hci} (BDADDR matches default: {bdaddr})")
            return True

        info(f"DarkFirmware not detected on {hci}")
        return False

    def get_firmware_status(self, hci: str = "hci1") -> dict:
        """Return firmware status information.

        Returns:
            {installed: bool, loaded: bool, bdaddr: str,
             original_backed_up: bool, capabilities: list[str]}
        """
        status: dict = {
            "installed": os.path.exists(FIRMWARE_PATH),
            "loaded": False,
            "bdaddr": "",
            "original_backed_up": os.path.exists(FIRMWARE_ORIG),
            "capabilities": [],
        }

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

        return status

    def get_current_bdaddr(self, hci: str = "hci1") -> str:
        """Read BDADDR from hciconfig output for the given HCI device."""
        result = run_cmd(["hciconfig", hci])
        if result.returncode != 0:
            return ""
        m = re.search(r"BD Address:\s+([0-9A-Fa-f:]{17})", result.stdout)
        return m.group(1) if m else ""

    def patch_bdaddr(self, target_mac: str, hci: str = "hci1") -> bool:
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

        try:
            with open(FIRMWARE_PATH, "r+b") as fw:
                fw.seek(BDADDR_OFFSET)
                fw.write(mac_reversed)
            success(f"Firmware BDADDR patched to {target_mac}")
        except PermissionError:
            error(f"Permission denied writing to {FIRMWARE_PATH} — run as root")
            return False
        except OSError as exc:
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
        hci: str = "hci1",
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
            # Write the new value to the firmware file
            with open(FIRMWARE_PATH, "r+b") as f:
                f.seek(file_offset)
                f.write(bytes([new_value]))

            # Verify file write
            with open(FIRMWARE_PATH, "rb") as f:
                f.seek(file_offset)
                verify = f.read(1)

            if verify[0] != new_value:
                error(f"File write verification failed for {label}")
                return False

            success(f"{label.capitalize()} patched in firmware file: {current_value} → {new_value}")

        # --- Step 2: Patch live RAM (immediate effect, no reset needed) ---
        hci_idx = int(hci.replace("hci", "")) if hci.startswith("hci") else 1

        try:
            from blue_tap.core.hci_vsc import HCIVSCSocket

            with HCIVSCSocket(hci_idx) as vsc:
                # Read current RAM to get the next 2 bytes (preserve them)
                current_ram = vsc.read_memory(ram_addr, size=4)
                if len(current_ram) < 4:
                    warning(f"Could not read RAM at 0x{ram_addr:08X} — file patched but RAM not updated. "
                            f"Reset adapter to apply.")
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

    def patch_send_length(self, new_length: int, hci: str = "hci1") -> bool:
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

    def restore_send_length(self, hci: str = "hci1") -> bool:
        """Restore the original 10-byte LMP send length limit."""
        return self.patch_send_length(LMP_SEND_LENGTH_DEFAULT, hci)

    def patch_connection_index(self, index: int, hci: str = "hci1") -> bool:
        """Patch which ACL connection slot receives LMP injection — persistent.

        Patches both firmware file and live RAM.  Connection index survives
        USB resets and replugs.

        Args:
            index: Connection slot index (0-11).
            hci: HCI device name.

        Returns:
            True if the persistent patch was applied.
        """
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

    def restore_connection_index(self, hci: str = "hci1") -> bool:
        """Restore the original connection index 0."""
        return self.patch_connection_index(LMP_CONNECTION_INDEX_DEFAULT, hci)

    # ------------------------------------------------------------------
    # Memory dumping
    # ------------------------------------------------------------------

    def dump_memory(self, start: int, end: int, output: str, hci: str = "hci1") -> bool:
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
        if end <= start:
            error(f"End address (0x{end:08X}) must be greater than start (0x{start:08X})")
            return False

        total_bytes = end - start
        info(
            f"Dumping memory 0x{start:08X} - 0x{end:08X} "
            f"({total_bytes:,} bytes) to {output}"
        )

        hci_idx = int(hci.replace("hci", "")) if hci.startswith("hci") else 1
        valid_bytes = 0
        invalid_regions: list[tuple[int, int]] = []  # (region_start, region_end)
        in_invalid = False
        invalid_start = 0
        last_pct = -1

        try:
            from blue_tap.core.hci_vsc import HCIVSCSocket
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

    def dump_connections(self, hci: str = "hci1") -> list[dict]:
        """Read all 12 connection slots from firmware RAM.

        Reads the bos[] array at CONNECTION_TABLE_BASE. Each slot is
        CONNECTION_SLOT_SIZE bytes. Returns parsed connection info for
        slots that appear active (non-zero BD address).

        Returns:
            List of dicts with keys: slot, raw_hex, bd_addr (if parseable),
            active (bool based on non-zero check).
        """
        hci_idx = int(hci.replace("hci", "")) if hci.startswith("hci") else 1
        results: list[dict] = []
        active_count = 0

        try:
            from blue_tap.core.hci_vsc import HCIVSCSocket

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

                    # Parse BD address from first 6 bytes (offset may vary)
                    bd_bytes = data[:6]
                    all_zero = all(b == 0 for b in bd_bytes)
                    all_ff = all(b == 0xFF for b in bd_bytes)
                    active = not all_zero and not all_ff

                    bd_addr = ":".join(f"{b:02X}" for b in reversed(bd_bytes)) if active else ""

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
                        info(f"  Slot {slot_idx}: ACTIVE — BD_ADDR {bd_addr} (may be wrong offset)")
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
        self, slot: int, hci: str = "hci1"
    ) -> bytes:
        """Raw hex dump of a specific connection slot.

        Args:
            slot: Slot index (0-11).
            hci: HCI device name.

        Returns:
            Raw bytes of the full slot (CONNECTION_SLOT_SIZE bytes),
            or empty bytes on failure.
        """
        if not 0 <= slot < CONNECTION_MAX_SLOTS:
            error(f"Slot index must be 0-{CONNECTION_MAX_SLOTS - 1}, got {slot}")
            return b""

        slot_addr = CONNECTION_TABLE_BASE + (slot * CONNECTION_SLOT_SIZE)
        info(f"Dumping connection slot {slot} at 0x{slot_addr:08X} ({CONNECTION_SLOT_SIZE} bytes)...")

        hci_idx = int(hci.replace("hci", "")) if hci.startswith("hci") else 1
        data = b""

        try:
            from blue_tap.core.hci_vsc import HCIVSCSocket

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
