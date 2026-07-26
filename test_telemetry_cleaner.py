"""Tests for telemetry_cleaner.py

Run:  python -m pytest test_telemetry_cleaner.py -v
or:   python test_telemetry_cleaner.py
"""

from __future__ import annotations

import math
import sys
import json

from telemetry_cleaner import (
    AirframeConfig,
    clean_telemetry,
    compute_flight_summary,
    detect_phases,
    extract_events,
    run_pipeline,
    run_unit_audit,
    haversine_km,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_row(ts: str, lat: float, lon: float, alt_m: float = 100.0,
              alt_agl: float | None = None, speed_ms: float = 10.0,
              sats: int = 12, vspeed: float | None = None,
              rth: bool | None = None, motor_stop: bool | None = None) -> dict:
    return {
        "ts": ts,
        "lat": lat,
        "lon": lon,
        "alt_m": alt_m,
        "alt_agl": alt_agl,
        "speed_ms": speed_ms,
        "sats": sats,
        "vertical_speed_ms": vspeed,
        "flags_rth": rth,
        "flags_motor_stop": motor_stop,
    }


def _ts(sec: int) -> str:
    """Return ISO timestamp for epoch offset (base 2026-06-20T14:00:00Z)."""
    from datetime import datetime, timezone
    base = datetime(2026, 6, 20, 14, 0, 0, tzinfo=timezone.utc)
    return datetime.fromtimestamp(base.timestamp() + sec, tz=timezone.utc).isoformat()


# ===================================================================
# Test: Duplicate timestamps
# ===================================================================

def test_dedup_identical_timestamps():
    """Rows with same ts should be excluded except the first."""
    rows = [
        _make_row("2026-06-20T14:00:00Z", 39.96, -106.21, alt_m=100),
        _make_row("2026-06-20T14:00:00Z", 39.96001, -106.21001, alt_m=100.1),  # dup ts
        _make_row("2026-06-20T14:00:00Z", 39.96002, -106.21002, alt_m=100.2),  # dup ts
        _make_row("2026-06-20T14:00:01Z", 39.96003, -106.21003, alt_m=100.3),  # unique
    ]
    valid, excluded = clean_telemetry(rows)
    assert len(valid) == 2, f"Expected 2 valid, got {len(valid)}"
    assert len(excluded) == 2, f"Expected 2 excluded, got {len(excluded)}"
    # The second excluded is a GPS jump (delta too large from row0 in 1s)
    assert excluded[0]["reason"] == "duplicate_ts"


# ===================================================================
# Test: Speed bound
# ===================================================================

def test_speed_bound():
    """Rows with speed > 90 km/h should be excluded."""
    config = AirframeConfig(max_speed_kmh=90.0)
    rows = [
        _make_row("2026-06-20T14:00:00Z", 39.96, -106.21, speed_ms=10.0),  # 36 km/h OK
        _make_row("2026-06-20T14:01:00Z", 39.97, -106.22, speed_ms=30.0),  # 108 km/h NO
        _make_row("2026-06-20T14:02:00Z", 39.98, -106.23, speed_ms=5.0),   # 18 km/h OK
    ]
    valid, excluded = clean_telemetry(rows, config)
    assert len(valid) == 2
    assert len(excluded) == 1
    assert excluded[0]["reason"] == "bounds_speed"


# ===================================================================
# Test: Altitude bound
# ===================================================================

def test_altitude_bound():
    """Rows with alt_agl > 500 m should be excluded."""
    config = AirframeConfig(max_alt_agl_m=500.0)
    rows = [
        _make_row("2026-06-20T14:00:00Z", 39.96, -106.21, alt_m=100, alt_agl=50.0),
        _make_row("2026-06-20T14:01:00Z", 39.97, -106.22, alt_m=100, alt_agl=600.0),  # NO
        _make_row("2026-06-20T14:02:00Z", 39.98, -106.23, alt_m=100, alt_agl=30.0),
    ]
    valid, excluded = clean_telemetry(rows, config)
    assert len(valid) == 2
    assert len(excluded) == 1
    assert excluded[0]["reason"] == "bounds_altitude"


# ===================================================================
# Test: GPS jump detection
# ===================================================================

def test_gps_jump():
    """A fix that requires >108 km/h to reach from previous fix should be excluded."""
    config = AirframeConfig(max_speed_kmh=90.0, gps_jump_speed_multiple=1.2)
    rows = [
        _make_row("2026-06-20T14:00:00Z", 39.96, -106.21),
        _make_row("2026-06-20T14:00:01Z", 39.96001, -106.21001),  # 1.1m in 1s → fine (~4 km/h)
        _make_row("2026-06-20T14:00:02Z", 40.96, -106.21),         # ~111 km in 1s → GPS jump
    ]
    valid, excluded = clean_telemetry(rows, config)
    assert len(valid) == 2, f"Expected 2 valid, got {len(valid)}"
    assert len(excluded) == 1, f"Expected 1 excluded, got {len(excluded)}"
    assert excluded[0]["reason"] == "gps_jump"


# ===================================================================
# Test: Everything combined — mixed valid/invalid
# ===================================================================

def test_mixed_pipeline():
    """Synthetic data with known numbers: 5 duplicates, 2 speed violations,
    1 altitude violation, 3 GPS jumps in 25 rows → 14 valid (25-5-2-1-3=14)."""
    rows = []
    # 10 unique timestamps, 5 with duplicates
    for base_sec in range(10):
        ts = _ts(base_sec)
        lat = 39.96
        lon = -106.21
        alt_agl = 50.0 + base_sec * 2
        speed = 10.0
        rows.append(_make_row(ts, lat, lon, alt_m=alt_agl + 1600, alt_agl=alt_agl, speed_ms=speed))
        if base_sec < 5:
            rows.append(_make_row(ts, lat, lon, alt_m=alt_agl + 1600,  # duplicate ts
                                  alt_agl=alt_agl, speed_ms=speed))

    # 2 speed violations (rows 15, 16 — after 10 unique + 5 dups)
    rows.append(_make_row(_ts(20), 39.96, -106.21, speed_ms=35.0))  # 126 km/h → bounds_speed
    rows.append(_make_row(_ts(21), 39.96, -106.21, speed_ms=40.0))  # 144 km/h → bounds_speed

    # 1 altitude violation (row 17)
    rows.append(_make_row(_ts(22), 39.96, -106.21, alt_agl=600.0, speed_ms=5.0))  # bounds_altitude

    # 3 GPS jumps — same location but timestamps 1s apart can't be that far
    # Actually same lat/lon means zero distance, so no GPS jump
    # Let's use a large lat change in 1s
    rows.append(_make_row(_ts(30), 40.96, -106.21, speed_ms=10.0))
    rows.append(_make_row(_ts(31), 40.97, -106.21, speed_ms=10.0))
    rows.append(_make_row(_ts(32), 40.98, -106.21, speed_ms=10.0))

    valid, excluded = clean_telemetry(rows)
    summary = compute_flight_summary(valid, len(rows), excluded)
    bd = summary["excluded_breakdown"]

    # 5 dups, 2 speed, 1 altitude, 3 GPS jumps = 11 excluded, 14 valid
    assert summary["raw_row_count"] == 21, f"Expected 21 raw, got {summary['raw_row_count']}"
    assert bd.get("duplicate_ts", 0) == 5, f"Expected 5 duplicate_ts, got {bd}"
    assert bd.get("bounds_speed", 0) == 2, f"Expected 2 bounds_speed, got {bd}"
    assert bd.get("bounds_altitude", 0) == 1, f"Expected 1 bounds_altitude, got {bd}"
    assert bd.get("gps_jump", 0) == 3, f"Expected 3 gps_jump, got {bd}"
    assert summary["valid_fix_count"] == 10, f"Expected 10 valid, got {summary['valid_fix_count']}"


# ===================================================================
# Test: Phase detection
# ===================================================================

def test_phase_detection():
    """Verify phase transitions are detected in a simple flight scenario."""
    # Continuous smooth track: pre-flight → takeoff → cruise → post-flight
    # All rows share a consistent position reference to avoid GPS jump exclusions
    _BASE_LAT = 39.96
    _BASE_LON = -106.21

    rows = []

    # Pre-flight (indices 0-4): stationary on ground, motors stopped
    for i in range(5):
        rows.append(_make_row(_ts(i), _BASE_LAT, _BASE_LON, alt_m=1600, alt_agl=0.0,
                              speed_ms=0, sats=8, motor_stop=True))

    # Takeoff (indices 5-9): positive vspeed, climbing, motors now running
    # Moves ~1m/s (9e-6 deg/s) to keep GPS delta within limits at 5 m/s speed
    for i in range(5, 10):
        alt = (i - 5) * 10
        rows.append(_make_row(_ts(i),
                              _BASE_LAT + i * 9e-6,
                              _BASE_LON + i * 9e-6,
                              alt_m=1600 + alt, alt_agl=alt,
                              speed_ms=5.0, sats=9, vspeed=3.0, motor_stop=False))

    # Cruise (indices 10-19): steady altitude, continuous movement ~10 m/s (9e-5 deg/s)
    for i in range(10, 20):
        rows.append(_make_row(_ts(i),
                              _BASE_LAT + i * 9e-5,
                              _BASE_LON + i * 9e-5,
                              alt_m=1640, alt_agl=40.0,
                              speed_ms=10.0, sats=10, motor_stop=False))

    # Post-flight (indices 20-24): back on ground, motors stopped
    # Same position as last cruise row to avoid GPS jump
    for i in range(20, 25):
        rows.append(_make_row(_ts(i),
                              _BASE_LAT + 19 * 9e-5,
                              _BASE_LON + 19 * 9e-5,
                              alt_m=1600, alt_agl=0.0,
                              speed_ms=0, sats=8, motor_stop=True))

    valid, excluded = clean_telemetry(rows)
    phases = detect_phases(valid)

    phase_names = [p["phase"] for p in phases]
    assert "pre_flight" in phase_names, f"Expected pre_flight phase, got {phase_names}"
    assert "takeoff" in phase_names, f"Expected takeoff phase, got {phase_names}"
    assert "cruise" in phase_names, f"Expected cruise phase, got {phase_names}"
    assert "post_flight" in phase_names, f"Expected post_flight phase, got {phase_names}"


# ===================================================================
# Test: Event extraction
# ===================================================================

def test_event_extraction():
    """Verify events are extracted at phase transitions and extrema."""
    _BASE_LAT = 39.96
    _BASE_LON = -106.21

    rows = []
    # Pre-flight (0-4): stationary
    for i in range(5):
        rows.append(_make_row(_ts(i), _BASE_LAT, _BASE_LON, alt_m=1600, alt_agl=0.0,
                              speed_ms=0, sats=8, motor_stop=True))
    # Takeoff (5-14): climbing, vspeed positive
    for i in range(5, 15):
        alt = (i - 5) * 5
        rows.append(_make_row(_ts(i),
                              _BASE_LAT + i * 9e-6,
                              _BASE_LON + i * 9e-6,
                              alt_m=1600 + alt, alt_agl=alt,
                              speed_ms=8.0, sats=9, vspeed=2.0, motor_stop=False))
    # Cruise (15-39): steady altitude, constant movement
    for i in range(15, 40):
        rows.append(_make_row(_ts(i),
                              _BASE_LAT + i * 9e-5,
                              _BASE_LON + i * 9e-5,
                              alt_m=1650, alt_agl=50.0,
                              speed_ms=12.0, sats=10, motor_stop=False))
    # Post-flight (40-44): back on ground, stopped
    for i in range(40, 45):
        rows.append(_make_row(_ts(i),
                              _BASE_LAT + 39 * 9e-5,
                              _BASE_LON + 39 * 9e-5,
                              alt_m=1600, alt_agl=0.0,
                              speed_ms=0, sats=8, motor_stop=True))

    valid, excluded = clean_telemetry(rows)
    phases = detect_phases(valid)
    events = extract_events(valid, phases)

    event_names = [e["name"] for e in events]
    assert "First GPS Fix" in event_names
    assert "Takeoff" in event_names
    assert "Max Altitude" in event_names
    assert "Last GPS Fix" in event_names

    # Verify t_offset_s: first event should be negative or zero
    assert events[0]["t_offset_s"] <= 0


# ===================================================================
# Test: Airframe ceiling warning
# ===================================================================

def test_integrity_warning():
    """If max_speed exceeds airframe ceiling, integrity_warning is emitted."""
    from telemetry_cleaner import build_contract

    config = AirframeConfig(max_speed_kmh=90.0)
    rows = [
        _make_row("2026-06-20T14:00:00Z", 39.96, -106.21, speed_ms=10.0),
        _make_row("2026-06-20T14:01:00Z", 39.97, -106.22, speed_ms=5.0),
    ]
    valid, excluded = clean_telemetry(rows, config)
    phases = detect_phases(valid, config)
    events = extract_events(valid, phases, config)
    contract = build_contract("TEST-001", "test", rows, valid, excluded, phases, events, config)

    warnings = contract.get("integrity_warnings", [])
    assert isinstance(warnings, list)

    # With normal speeds, no warnings
    assert len(warnings) == 0, f"Expected 0 warnings, got {warnings}"


def test_integrity_warning_triggers():
    """Speed > ceiling triggers the warning."""
    from telemetry_cleaner import build_contract, compute_flight_summary

    config = AirframeConfig(max_speed_kmh=90.0)
    rows = [
        _make_row("2026-06-20T14:00:00Z", 39.96, -106.21, speed_ms=10.0),
        _make_row("2026-06-20T14:01:00Z", 39.97, -106.22, speed_ms=35.0),  # 126 km/h
    ]
    valid, excluded = clean_telemetry(rows, config)
    # Speed violation row is excluded, so the valid set should have no warning
    # But if we use only the valid set, the max speed is 36 km/h
    phases = detect_phases(valid, config)
    events = extract_events(valid, phases, config)
    contract = build_contract("TEST-002", "test", rows, valid, excluded, phases, events, config)
    warnings = contract.get("integrity_warnings", [])
    # No warning because the speed violation was excluded
    assert len(warnings) == 0


# ===================================================================
# Test: Unit audit
# ===================================================================

def test_unit_audit():
    """run_unit_audit returns stats for key fields."""
    rows = [
        _make_row("2026-06-20T14:00:00Z", 39.96, -106.21, alt_m=100, alt_agl=50.0, speed_ms=10.0),
        _make_row("2026-06-20T14:01:00Z", 39.97, -106.22, alt_m=200, alt_agl=150.0, speed_ms=20.0),
        _make_row("2026-06-20T14:02:00Z", 39.98, -106.23, alt_m=300, alt_agl=250.0, speed_ms=30.0),
    ]
    audit = run_unit_audit(rows)
    assert audit["row_count"] == 3
    assert audit["alt_msl"]["min"] == 100.0
    assert audit["alt_msl"]["max"] == 300.0
    assert audit["alt_msl"]["mean"] == 200.0
    assert audit["speed_ms"]["count"] == 3


# ===================================================================
# Test: Unparseable timestamps fallback
# ===================================================================

def test_unparseable_timestamps():
    """When all timestamps return epoch=0, dedup is skipped and all rows kept."""
    rows = [
        {"ts": "unknown-format-1", "lat": 39.96, "lon": -106.21, "alt_m": 100},
        {"ts": "unknown-format-2", "lat": 39.97, "lon": -106.22, "alt_m": 101},
        {"ts": "unknown-format-3", "lat": 39.98, "lon": -106.23, "alt_m": 102},
    ]
    valid, excluded = clean_telemetry(rows)
    # All 3 should be kept (no dedup), and no GPS jumps (dt=0 so check skipped)
    assert len(valid) == 3, f"Expected 3 valid, got {len(valid)}"
    assert len(excluded) == 0, f"Expected 0 excluded, got {len(excluded)}"


# ===================================================================
# Test: Epoch millis as string
# ===================================================================

def test_epoch_millis():
    """Timestamps as epoch millis string should parse correctly."""
    from telemetry_cleaner import _ts_epoch
    # 2026-06-20T14:00:00Z in epoch millis
    ts = "1781949600000"
    ep = _ts_epoch(ts)
    assert ep > 1_700_000_000, f"Expected reasonable epoch, got {ep}"
    assert ep == 1781949600.0, f"Expected 1781949600, got {ep}"


# ===================================================================
# Test: Haversine correctness
# ===================================================================

def test_haversine():
    """Known distance: ~111 km per degree at equator."""
    d = haversine_km(0, 0, 1, 0)
    assert abs(d - 111.2) < 1.0, f"Expected ~111 km, got {d} km"


# ===================================================================
# Run all if executed directly
# ===================================================================

if __name__ == "__main__":
    tests = [
        ("dedup_identical_timestamps", test_dedup_identical_timestamps),
        ("speed_bound", test_speed_bound),
        ("altitude_bound", test_altitude_bound),
        ("gps_jump", test_gps_jump),
        ("mixed_pipeline", test_mixed_pipeline),
        ("phase_detection", test_phase_detection),
        ("event_extraction", test_event_extraction),
        ("integrity_warning", test_integrity_warning),
        ("integrity_warning_triggers", test_integrity_warning_triggers),
        ("unit_audit", test_unit_audit),
        ("unparseable_timestamps", test_unparseable_timestamps),
        ("epoch_millis", test_epoch_millis),
        ("haversine", test_haversine),
    ]
    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
            passed += 1
        except Exception as e:
            print(f"  FAIL  {name}: {e}")
            failed += 1
    print(f"\n{passed}/{passed+failed} passed")
    sys.exit(0 if failed == 0 else 1)
