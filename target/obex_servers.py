"""PBAP, MAP, and OPP server sessions for the Vulnerable IVI Simulator.

Each class subclasses OBEXSession from obex_engine and implements
profile-specific on_connect / on_get / on_put behavior.

Usage:
    from obex_servers import PBAPSession, MAPSession, OPPSession

    session = PBAPSession()
    response = session.handle_packet(raw_obex_bytes)
"""

import os
import re

from obex_engine import (
    OBEXSession,
    parse_app_params,
    build_connect_response,
    build_connection_id,
    build_who,
    build_body,
    build_app_params_header,
    build_response,
)
from ivi_config import (
    PBAP_UUID, MAP_UUID,
    OBEX_SUCCESS,
    PBAP_TYPE_PHONEBOOK, PBAP_TYPE_VCARD_LISTING, PBAP_TYPE_VCARD,
    MAP_TYPE_MSG_LISTING, MAP_TYPE_MESSAGE, DATA_DIR, RECEIVED_DIR, MAP_FOLDERS,
)
from ivi_log import log

# Module-level data dir — set by ivi_daemon before creating sessions
_data_dir = DATA_DIR
_received_dir = RECEIVED_DIR


def set_data_dir(data_dir: str, received_dir: str | None = None):
    """Override data directory (called by ivi_daemon before creating sessions)."""
    global _data_dir, _received_dir
    _data_dir = data_dir
    if received_dir:
        _received_dir = received_dir


# ============================================================================
# Helpers
# ============================================================================

def _read_file(path: str) -> bytes | None:
    """Read a file, returning bytes or None if missing."""
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def _split_vcards(data: bytes) -> list[bytes]:
    """Split a vCard file into individual vCard entries.

    Each entry starts with BEGIN:VCARD and ends with END:VCARD.
    Returns list of complete vCard byte strings (including delimiters).
    """
    text = data.decode("utf-8", errors="replace")
    # Split on BEGIN:VCARD, keeping the delimiter
    parts = re.split(r"(?=BEGIN:VCARD)", text)
    vcards = [p.encode("utf-8") for p in parts if p.strip()]
    return vcards


def _count_vcards(data: bytes) -> int:
    """Count vCards in file data by counting BEGIN:VCARD occurrences."""
    return data.count(b"BEGIN:VCARD")


def _unique_path(base_path: str) -> str:
    """Return a unique file path, appending _1, _2, etc. if needed."""
    if not os.path.exists(base_path):
        return base_path
    root, ext = os.path.splitext(base_path)
    counter = 1
    while True:
        candidate = f"{root}_{counter}{ext}"
        if not os.path.exists(candidate):
            return candidate
        counter += 1


# ============================================================================
# PBAP Session
# ============================================================================

# Map PBAP virtual paths to actual data files
_PBAP_PATH_MAP = {
    "telecom/pb.vcf": "phonebook.vcf",
    "telecom/ich.vcf": "ich.vcf",
    "telecom/och.vcf": "och.vcf",
    "telecom/mch.vcf": "mch.vcf",
    "telecom/cch.vcf": "cch.vcf",
}

# Paths that return empty responses
_PBAP_EMPTY_PATHS = {"telecom/spd.vcf", "telecom/fav.vcf"}


class PBAPSession(OBEXSession):
    """Phone Book Access Profile session handler.

    Serves phonebook data (vCards), call history, and contact listings
    from the data/ directory.
    """

    def __init__(self):
        super().__init__(profile_name="PBAP")

    def on_connect(self, pkt: dict) -> bytes:
        headers = pkt.get("headers", {})
        target = headers.get("target")

        if target and target != PBAP_UUID:
            log.warn(self.profile,
                     f"Connect with wrong Target UUID: {target.hex()}")

        log.connection(self.profile, "", "PBAP OBEX Connect")

        response_headers = build_connection_id(self.connection_id)
        response_headers += build_who(PBAP_UUID)
        resp = build_connect_response(OBEX_SUCCESS, response_headers)
        log.obex("send", OBEX_SUCCESS, len(resp))
        return resp

    def on_get(self, pkt: dict) -> bytes | None:
        headers = pkt.get("headers", {})
        content_type = headers.get("type")
        name = headers.get("name", "")

        # Parse application parameters
        app_params = {}
        if headers.get("app_params"):
            app_params = parse_app_params(headers["app_params"])

        if content_type == PBAP_TYPE_PHONEBOOK:
            return self._get_phonebook(name, app_params)

        elif content_type == PBAP_TYPE_VCARD_LISTING:
            return self._get_vcard_listing(name)

        elif content_type == PBAP_TYPE_VCARD:
            return self._get_single_vcard(name)

        elif name and name.endswith(".vcf"):
            # Name header looks like "N.vcf" — treat as single vCard request
            return self._get_single_vcard(name)

        else:
            log.warn(self.profile,
                     f"Unknown GET type={content_type!r} name={name!r}")
            return None

    def _get_phonebook(self, name: str, app_params: dict) -> bytes | None:
        """Handle x-bt/phonebook GET requests."""
        # Normalize path — strip leading slashes
        path = name.lstrip("/") if name else ""

        # Build the full virtual path from SetPath + Name
        if path:
            virtual_path = path
        elif self.current_path:
            virtual_path = "/".join(self.current_path)
        else:
            virtual_path = "telecom/pb.vcf"

        log.info(self.profile, f"GET phonebook: {virtual_path}")

        # Check if it's a SIM1 path or empty-response path
        if virtual_path.startswith("SIM1/"):
            log.info(self.profile, "SIM1 path — returning empty")
            return b""
        if virtual_path in _PBAP_EMPTY_PATHS:
            log.info(self.profile, f"{virtual_path} — returning empty")
            return b""

        # Map virtual path to real file
        real_name = _PBAP_PATH_MAP.get(virtual_path)
        if real_name is None:
            log.warn(self.profile, f"Unknown phonebook path: {virtual_path}")
            return None

        file_path = os.path.join(_data_dir, real_name)
        data = _read_file(file_path)
        if data is None:
            log.warn(self.profile, f"File not found: {file_path}")
            return None

        # MaxListCount == 0 means "just tell me the size, no body"
        # PBAP spec: response = SUCCESS + AppParams(PhonebookSize) + empty EOB
        # Blue-Tap parses the raw response for AppParams header (tag 0x08)
        max_list_count = app_params.get("max_list_count")
        if max_list_count == 0:
            count = _count_vcards(data)
            log.info(self.profile,
                     f"PhonebookSize query: {count} contacts")
            ap = build_app_params_header({"phonebook_size": count})
            # Return a pre-built OBEX packet — _dispatch_get detects this
            # (starts with valid response opcode + matching length) and sends directly
            return build_response(
                OBEX_SUCCESS,
                build_connection_id(self.connection_id),
                ap,
                build_body(b"", final=True),
            )

        # Slice vCards according to offset and count
        vcards = _split_vcards(data)
        offset = app_params.get("list_start_offset", 0)

        if max_list_count is not None and max_list_count > 0:
            vcards = vcards[offset:offset + max_list_count]
        elif offset > 0:
            vcards = vcards[offset:]

        result = b"".join(vcards)
        log.info(self.profile,
                 f"Serving {len(vcards)} vCards ({len(result)} bytes)")
        return result

    def _get_vcard_listing(self, name: str) -> bytes | None:
        """Build XML listing of contacts from the phonebook."""
        file_path = os.path.join(_data_dir, "phonebook.vcf")
        data = _read_file(file_path)
        if data is None:
            return None

        vcards = _split_vcards(data)

        xml_parts = [
            '<?xml version="1.0"?>',
            '<!DOCTYPE vcard-listing SYSTEM "vcard-listing.dtd">',
            '<vCard-listing version="1.0">',
        ]
        for i, vcard in enumerate(vcards):
            text = vcard.decode("utf-8", errors="replace")
            # Extract FN (full name) from the vCard
            fn_match = re.search(r"FN:(.+)", text)
            fn = fn_match.group(1).strip() if fn_match else f"Contact {i}"
            # Extract first TEL
            handle = f"{i + 1}.vcf"
            xml_parts.append(
                f'  <card handle="{handle}" name="{fn}" />'
            )
        xml_parts.append("</vCard-listing>")

        result = "\n".join(xml_parts).encode("utf-8")
        log.info(self.profile,
                 f"Serving vCard listing ({len(vcards)} entries)")
        return result

    def _get_single_vcard(self, name: str) -> bytes | None:
        """Return a single vCard by index (e.g. '3.vcf' or 'N.vcf')."""
        file_path = os.path.join(_data_dir, "phonebook.vcf")
        data = _read_file(file_path)
        if data is None:
            return None

        # Extract the numeric index from the name (e.g. "3.vcf" -> 2)
        match = re.match(r"(\d+)\.vcf", name if name else "")
        if not match:
            log.warn(self.profile, f"Invalid vCard name: {name!r}")
            return None

        index = int(match.group(1)) - 1  # 1-based to 0-based
        vcards = _split_vcards(data)

        if 0 <= index < len(vcards):
            log.info(self.profile, f"Serving vCard #{index + 1}")
            return vcards[index]
        else:
            log.warn(self.profile,
                     f"vCard index {index + 1} out of range "
                     f"(have {len(vcards)})")
            return None


# ============================================================================
# MAP Session
# ============================================================================

class MAPSession(OBEXSession):
    """Message Access Profile session handler.

    Serves message listings, individual bMessage objects, and folder
    listings from data/messages/.
    """

    def __init__(self):
        super().__init__(profile_name="MAP")

    def on_connect(self, pkt: dict) -> bytes:
        headers = pkt.get("headers", {})
        target = headers.get("target")

        if target and target != MAP_UUID:
            log.warn(self.profile,
                     f"Connect with wrong Target UUID: {target.hex()}")

        log.connection(self.profile, "", "MAP OBEX Connect")

        response_headers = build_connection_id(self.connection_id)
        response_headers += build_who(MAP_UUID)
        resp = build_connect_response(OBEX_SUCCESS, response_headers)
        log.obex("send", OBEX_SUCCESS, len(resp))
        return resp

    @property
    def _current_folder(self) -> str:
        """Determine the current MAP folder from the path stack."""
        if self.current_path:
            # Last path element is the folder name
            return self.current_path[-1]
        return "inbox"

    def on_get(self, pkt: dict) -> bytes | None:
        headers = pkt.get("headers", {})
        content_type = headers.get("type", "")
        name = headers.get("name", "")

        if content_type == MAP_TYPE_MSG_LISTING:
            return self._get_msg_listing()

        elif content_type == MAP_TYPE_MESSAGE:
            return self._get_message(name)

        elif content_type and "folder" in content_type.lower():
            return self._get_folder_listing()

        else:
            log.warn(self.profile,
                     f"Unknown GET type={content_type!r} name={name!r}")
            return None

    def _get_msg_listing(self) -> bytes | None:
        """Return the message listing XML for the current folder."""
        folder = self._current_folder
        listing_file = os.path.join(
            DATA_DIR, "messages", f"{folder}_listing.xml"
        )
        data = _read_file(listing_file)
        if data is None:
            log.warn(self.profile,
                     f"No listing for folder: {folder}")
            return None

        log.info(self.profile,
                 f"Serving {folder} message listing ({len(data)} bytes)")
        return data

    def _get_message(self, name: str) -> bytes | None:
        """Return a single bMessage by handle (e.g. '0001')."""
        if not name:
            log.warn(self.profile, "GET message with no handle")
            return None

        folder = self._current_folder
        # The handle might come as just "0001" or "0001.bmsg"
        handle = name.replace(".bmsg", "")
        msg_file = os.path.join(
            DATA_DIR, "messages", folder, f"{handle}.bmsg"
        )
        data = _read_file(msg_file)
        if data is None:
            # Try all folders if not found in current
            for try_folder in MAP_FOLDERS:
                msg_file = os.path.join(
                    DATA_DIR, "messages", try_folder, f"{handle}.bmsg"
                )
                data = _read_file(msg_file)
                if data is not None:
                    folder = try_folder
                    break

        if data is None:
            log.warn(self.profile, f"Message not found: {handle}")
            return None

        log.info(self.profile,
                 f"Serving message {handle} from {folder} ({len(data)} bytes)")
        return data

    def _get_folder_listing(self) -> bytes | None:
        """Return an XML listing of available MAP folders."""
        xml_parts = [
            '<?xml version="1.0"?>',
            '<!DOCTYPE folder-listing SYSTEM "obex-folder-listing.dtd">',
            '<folder-listing version="1.0">',
        ]
        for folder in MAP_FOLDERS:
            xml_parts.append(f'  <folder name="{folder}" />')
        xml_parts.append("</folder-listing>")

        result = "\n".join(xml_parts).encode("utf-8")
        log.info(self.profile, "Serving folder listing")
        return result

    def on_put(self, name: str, data: bytes, pkt: dict) -> bool:
        """Accept pushed messages and save to received/."""
        if not name:
            name = "message.bmsg"

        # Sanitize filename
        safe_name = os.path.basename(name)
        if not safe_name:
            safe_name = "message.bmsg"

        os.makedirs(_received_dir, exist_ok=True)
        save_path = _unique_path(os.path.join(_received_dir, safe_name))

        try:
            with open(save_path, "wb") as f:
                f.write(data)
            log.info(self.profile,
                     f"Saved pushed message: {save_path} ({len(data)} bytes)")
            return True
        except OSError as e:
            log.error(self.profile, f"Failed to save message: {e}")
            return False


# ============================================================================
# OPP Session
# ============================================================================

class OPPSession(OBEXSession):
    """Object Push Profile session handler.

    Accepts arbitrary file pushes (vCards, photos, etc.) and saves
    them to the received/ directory.
    """

    def __init__(self):
        super().__init__(profile_name="OPP")

    def on_connect(self, pkt: dict) -> bytes:
        """OPP does not use a Target UUID — accept any connection."""
        log.connection(self.profile, "", "OPP OBEX Connect")

        response_headers = build_connection_id(self.connection_id)
        resp = build_connect_response(OBEX_SUCCESS, response_headers)
        log.obex("send", OBEX_SUCCESS, len(resp))
        return resp

    def on_put(self, name: str, data: bytes, pkt: dict) -> bool:
        """Save pushed file to received/ directory."""
        if not name:
            name = "unnamed_object"

        # Sanitize: use only the basename to prevent path traversal
        safe_name = os.path.basename(name)
        if not safe_name:
            safe_name = "unnamed_object"

        os.makedirs(_received_dir, exist_ok=True)
        save_path = _unique_path(os.path.join(_received_dir, safe_name))

        try:
            with open(save_path, "wb") as f:
                f.write(data)
            log.info(self.profile,
                     f"Received file: {os.path.basename(save_path)} "
                     f"({len(data)} bytes)")
            return True
        except OSError as e:
            log.error(self.profile, f"Failed to save file: {e}")
            return False
