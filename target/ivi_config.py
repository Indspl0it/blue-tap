"""Shared constants for the Vulnerable IVI Simulator.

All components (ivi_daemon, pin_agent, ble_gatt, setup_ivi) import from here
so channel assignments, UUIDs, and device identity are defined in one place.
"""

import os
import struct

# ── Script-relative paths ──────────────────────────────────────────────────

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(_SCRIPT_DIR, "data")
RECEIVED_DIR = os.path.join(_SCRIPT_DIR, "received")
PROFILE_FILE = os.path.join(_SCRIPT_DIR, ".ivi_profile")
ADAPTER_FILE = os.path.join(_SCRIPT_DIR, ".ivi_adapter")
PHONE_FILE = os.path.join(_SCRIPT_DIR, ".ivi_phone")


# ── IVI Identity ───────────────────────────────────────────────────────────

IVI_NAME = "SYNC"
IVI_DEVICE_CLASS = 0x200408          # Audio/Video: Car Audio
DEFAULT_PIN = "1234"
DEFAULT_PHONE_MAC = "AA:BB:CC:DD:EE:FF"
DEFAULT_PHONE_NAME = "Galaxy S24"


# ── RFCOMM Channel Map ─────────────────────────────────────────────────────

CH_SPP = 1          # Serial Port Profile (bluesnarfer target)
CH_HIDDEN = 2       # Hidden debug channel (NOT in SDP — vuln-scan finding)
CH_OPP = 9          # Object Push Profile
CH_HFP = 10         # Hands-Free Profile (Audio Gateway)
CH_PBAP = 15        # Phone Book Access Profile
CH_MAP = 16         # Message Access Profile

ALL_RFCOMM_CHANNELS = [CH_SPP, CH_HIDDEN, CH_OPP, CH_HFP, CH_PBAP, CH_MAP]


# ── L2CAP PSMs ─────────────────────────────────────────────────────────────
# PSM 1 (SDP) and PSM 3 (RFCOMM) are owned by bluetoothd — we don't bind them.

PSM_BNEP = 7        # PAN / BNEP
PSM_AVCTP = 23      # AVRCP signaling
PSM_AVDTP = 25      # A2DP streaming

CUSTOM_L2CAP_PSMS = [PSM_BNEP, PSM_AVCTP, PSM_AVDTP]


# ── OBEX Protocol Constants ────────────────────────────────────────────────

# Opcodes
OBEX_CONNECT = 0x80
OBEX_DISCONNECT = 0x81
OBEX_PUT = 0x02
OBEX_PUT_FINAL = 0x82
OBEX_GET = 0x03
OBEX_GET_FINAL = 0x83
OBEX_SETPATH = 0x85
OBEX_SUCCESS = 0xA0
OBEX_CONTINUE = 0x90
OBEX_BAD_REQUEST = 0xC0
OBEX_UNAUTHORIZED = 0xC1
OBEX_NOT_FOUND = 0xC4
OBEX_INTERNAL_ERROR = 0xD0

# Header IDs — high 2 bits indicate encoding:
#   0x00-0x3F = Unicode string (2-byte length)
#   0x40-0x7F = Byte sequence (2-byte length)
#   0x80-0xBF = 1-byte value
#   0xC0-0xFF = 4-byte value
HDR_NAME = 0x01            # Unicode string: object name / path
HDR_TYPE = 0x42            # Byte sequence: MIME-like content type
HDR_TARGET = 0x46          # Byte sequence: target service UUID
HDR_BODY = 0x48            # Byte sequence: object body chunk
HDR_END_OF_BODY = 0x49     # Byte sequence: final body chunk
HDR_WHO = 0x4A             # Byte sequence: identifies service (in Connect response)
HDR_APP_PARAMS = 0x4C      # Byte sequence: application parameters (TLV)
HDR_CONNECTION_ID = 0xCB   # 4-byte value: session identifier
HDR_LENGTH = 0xC3          # 4-byte value: object length (OPP)

# Target UUIDs (16 bytes each)
PBAP_UUID = bytes.fromhex("796135f0f0c511d809660800200c9a66")
MAP_UUID = bytes.fromhex("bb582b40420c11dbb0de0800200c9a66")


# ── PBAP Content Types ─────────────────────────────────────────────────────

PBAP_TYPE_PHONEBOOK = "x-bt/phonebook"
PBAP_TYPE_VCARD_LISTING = "x-bt/vcard-listing"
PBAP_TYPE_VCARD = "x-bt/vcard"

# PBAP AppParam tags
PBAP_TAG_MAX_LIST_COUNT = 0x04
PBAP_TAG_LIST_START_OFFSET = 0x05
PBAP_TAG_FILTER = 0x06
PBAP_TAG_FORMAT = 0x07
PBAP_TAG_PHONEBOOK_SIZE = 0x08
PBAP_TAG_SEARCH_ATTRIBUTE = 0x02
PBAP_TAG_SEARCH_VALUE = 0x03


# ── MAP Content Types ──────────────────────────────────────────────────────

MAP_TYPE_MSG_LISTING = "x-bt/MAP-msg-listing"
MAP_TYPE_MESSAGE = "x-bt/message"
MAP_TYPE_MSG_STATUS = "x-bt/messageStatus"
MAP_TYPE_NOTIFICATION = "x-bt/MAP-NotificationRegistration"
MAP_TYPE_FOLDER_LISTING = "x-obex/folder-listing"

# MAP AppParam tags
MAP_TAG_MAX_LIST_COUNT = 0x01
MAP_TAG_CHARSET = 0x14
MAP_TAG_NOTIFICATION_STATUS = 0x0E
MAP_TAG_STATUS_INDICATOR = 0x17
MAP_TAG_STATUS_VALUE = 0x18

# MAP folders
MAP_FOLDERS = ["inbox", "sent", "draft", "deleted"]


# ── HFP Constants ──────────────────────────────────────────────────────────

# AG (Audio Gateway) supported features bitmask
# Bits: EC/NR(0) | 3-way(1) | CLI(2) | VoiceRec(3) | Reject(4) |
#       EnhStatus(5) | EnhControl(6) | CodecNeg(7) | HFIndicator(8)
HFP_AG_FEATURES = 495  # 0x01EF = bits 0-8 except bit 8

HFP_INDICATOR_NAMES = ["service", "call", "callsetup", "callheld", "signal", "roam", "battchg"]
HFP_INDICATOR_VALUES = [1, 0, 0, 0, 4, 0, 5]  # In service, no call, signal 4/5, battery 5/5

HFP_OPERATOR = "T-Mobile"
HFP_SUBSCRIBER = "+14155559999"


# ── Fake Device Info (for bluesnarfer AT responses) ────────────────────────

FAKE_IMEI = "351234567890123"
FAKE_IMSI = "310260123456789"
FAKE_BATTERY = 85          # percent
FAKE_SIGNAL = 22           # CSQ value (0-31)
FAKE_OPERATOR = "T-Mobile"
FAKE_SUBSCRIBER = "+14155559999"


# ── BLE GATT UUIDs ─────────────────────────────────────────────────────────

BLE_DEVICE_INFO_SVC = "0000180a-0000-1000-8000-00805f9b34fb"
BLE_BATTERY_SVC = "0000180f-0000-1000-8000-00805f9b34fb"
BLE_CUSTOM_IVI_SVC = "12345678-1234-5678-1234-56789abcdef0"

BLE_MANUFACTURER_NAME_CHR = "00002a29-0000-1000-8000-00805f9b34fb"
BLE_MODEL_NUMBER_CHR = "00002a24-0000-1000-8000-00805f9b34fb"
BLE_FIRMWARE_REV_CHR = "00002a26-0000-1000-8000-00805f9b34fb"
BLE_SOFTWARE_REV_CHR = "00002a28-0000-1000-8000-00805f9b34fb"
BLE_PNP_ID_CHR = "00002a50-0000-1000-8000-00805f9b34fb"
BLE_BATTERY_LEVEL_CHR = "00002a19-0000-1000-8000-00805f9b34fb"

BLE_VEHICLE_SPEED_CHR = "12345678-1234-5678-1234-56789abcdef1"
BLE_DIAG_DATA_CHR = "12345678-1234-5678-1234-56789abcdef2"
BLE_OTA_UPDATE_CHR = "12345678-1234-5678-1234-56789abcdef3"

BLE_MANUFACTURER_NAME = "FakeCar Audio Systems"
BLE_MODEL_NUMBER = "IVI-2026-VULN"
BLE_FIRMWARE_REV = "1.0.0"
BLE_SOFTWARE_REV = "BlueZ 5.66"
# PnP ID: Source=BT SIG(1), VID=0x0046, PID=0x0001, Ver=0x0100
BLE_PNP_ID = struct.pack("<BHHH", 1, 0x0046, 0x0001, 0x0100)
BLE_BATTERY_LEVEL = 85


# ── Helpers ────────────────────────────────────────────────────────────────

def read_profile() -> str:
    """Read the active profile from .ivi_profile (written by setup_ivi.sh)."""
    try:
        with open(PROFILE_FILE) as f:
            return f.read().strip()
    except OSError:
        return "legacy"  # default if file doesn't exist


def read_phone_mac() -> str:
    """Read the pre-paired phone MAC from .ivi_phone."""
    try:
        with open(PHONE_FILE) as f:
            return f.read().strip()
    except OSError:
        return DEFAULT_PHONE_MAC
