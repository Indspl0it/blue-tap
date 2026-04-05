"""Bundled firmware binaries for RTL8761B (TP-Link UB500).

Contains:
  - rtl8761bu_fw_darkfirmware.bin: DarkFirmware-patched firmware with:
      - LMP injection via VSC 0xFE22
      - LMP RX monitoring via HCI Event 0xFF
      - Controller memory read/write (VSC 0xFC61/0xFC62)
      - LMP send limit raised to 17 bytes (BT spec max)
      - BDADDR set to 00:1A:7D:DA:71:13 (patchable at offset 0xAD85)
  - rtl8761bu_fw_original.bin: Stock Realtek firmware (0xD922) for restoration

These files are installed to /lib/firmware/rtl_bt/ via:
    sudo blue-tap adapter firmware-install
"""

from importlib import resources


def get_firmware_path(name: str = "rtl8761bu_fw_darkfirmware.bin") -> str:
    """Return the absolute path to a bundled firmware file."""
    return str(resources.files(__package__).joinpath(name))
