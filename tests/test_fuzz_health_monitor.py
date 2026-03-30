"""Tests for Phase 6: Watchdog Reboot Detection."""

import pytest

from blue_tap.fuzz.health_monitor import (
    HealthEvent,
    HealthStatus,
    TargetHealthMonitor,
)


class TestHealthStatus:
    def test_enum_values(self):
        assert HealthStatus.ALIVE.value == "alive"
        assert HealthStatus.UNREACHABLE.value == "unreachable"
        assert HealthStatus.REBOOTED.value == "rebooted"
        assert HealthStatus.DEGRADED.value == "degraded"
        assert HealthStatus.ZOMBIE.value == "zombie"


class TestHealthEvent:
    def test_creation(self):
        evt = HealthEvent(
            timestamp=1000.0,
            status=HealthStatus.REBOOTED,
            details="Target rebooted",
            iteration=500,
            last_fuzz_cases=[b"\x01\x02"],
        )
        assert evt.status == HealthStatus.REBOOTED

    def test_serialization(self):
        evt = HealthEvent(
            timestamp=1000.0,
            status=HealthStatus.REBOOTED,
            details="test",
            iteration=1,
            last_fuzz_cases=[b"\xDE\xAD"],
        )
        d = evt.to_dict()
        assert d["status"] == "rebooted"
        evt2 = HealthEvent.from_dict(d)
        assert evt2.status == HealthStatus.REBOOTED
        assert evt2.iteration == 1


class TestTargetHealthMonitor:
    def test_creation(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF")
        assert mon.target == "AA:BB:CC:DD:EE:FF"
        assert mon._reboot_count == 0

    def test_should_check_interval(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF", check_interval=10)
        assert mon.should_check(10) is True
        assert mon.should_check(5) is False
        assert mon.should_check(20) is True

    def test_should_check_always_when_not_alive(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF", check_interval=100)
        mon._last_status = HealthStatus.UNREACHABLE
        assert mon.should_check(1) is True

    def test_record_fuzz_case(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF")
        for i in range(15):
            mon.record_fuzz_case(bytes([i]))
        # Ring buffer maxlen=10
        assert len(mon._recent_fuzz_cases) == 10

    def test_get_cooldown(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF")
        assert mon.get_cooldown() == 10.0
        mon._reboot_count = 1
        assert mon.get_cooldown() == 15.0
        mon._reboot_count = 2
        assert mon.get_cooldown() == 20.0
        mon._reboot_count = 5
        assert mon.get_cooldown() == 30.0

    def test_get_crash_candidates_empty(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF")
        candidates = mon.get_crash_candidates()
        assert candidates == []

    def test_get_crash_candidates_with_data(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF")
        mon.record_fuzz_case(b"\x01")
        mon.record_fuzz_case(b"\x02")
        mon.record_fuzz_case(b"\x03")
        candidates = mon.get_crash_candidates()
        assert len(candidates) == 3
        # Last case should have highest confidence
        payloads = [p for p, _ in candidates]
        confidences = [c for _, c in candidates]
        assert confidences[0] > confidences[-1]

    def test_get_stats(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF")
        stats = mon.get_stats()
        assert stats["reboot_count"] == 0
        assert stats["current_status"] == "alive"

    def test_get_events_empty(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF")
        assert mon.get_events() == []

    def test_degradation_not_triggered_with_few_samples(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF")
        for i in range(5):
            mon._latency_trend.append(float(i))
        assert mon._check_degradation() is False

    def test_degradation_triggered_with_increasing_latency(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF")
        for i in range(100):
            mon._latency_trend.append(float(i))  # slope = 1.0 > 0.5
        assert mon._check_degradation() is True

    def test_degradation_not_triggered_with_stable_latency(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF")
        for _ in range(100):
            mon._latency_trend.append(5.0)
        assert mon._check_degradation() is False

    def test_zombie_detection(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF")
        # Can't fully test without BT hardware, but verify method signature
        result = mon._check_zombie({"sdp": False, "rfcomm": False})
        # Will return False because check_alive will fail without hardware
        assert isinstance(result, bool)

    def test_serialization_roundtrip(self):
        mon = TargetHealthMonitor("AA:BB:CC:DD:EE:FF")
        mon.record_fuzz_case(b"\x01\x02\x03")
        mon._reboot_count = 2
        d = mon.to_dict()
        mon2 = TargetHealthMonitor.from_dict(d)
        assert mon2._reboot_count == 2
        assert mon2.target == "AA:BB:CC:DD:EE:FF"
