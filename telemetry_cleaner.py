"""telemetry_cleaner.py

Cleaning pipeline for drone telemetry data.
Transforms raw_telemetry_rows[] into:

  - valid_fixes[]       — deduplicated, bounds-checked GPS fixes
  - excluded_rows[]     — rows that failed validation, with reason codes
  - flight_summary      — sane aggregate stats from valid_fixes only
  - flight_events[]     — phase-tagged, severity-tagged forensic events

Usage:
    from telemetry_cleaner import run_pipeline
    result = run_pipeline(raw_rows, case_id="CF-2026-047", source_file="image.E01")
"""

from __future__ import annotations

import math
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Airframe config — adjust per drone model
# ---------------------------------------------------------------------------

@dataclass
class AirframeConfig:
    """Tunable thresholds per airframe.  Default to DJI Mavic 3 Pro."""
    max_speed_kmh: float = 90.0          # sport-mode ceiling
    max_alt_agl_m: float = 500.0          # typical legal ceiling
    min_lock_sats: int = 6
    takeoff_aom_m: float = 2.0
    landing_aom_m: float = 3.0
    landing_sustain_n: int = 5
    baseline_window_n: int = 10
    gps_jump_speed_multiple: float = 1.2  # delta/dt must be <= max_speed * this
    anomaly_sats_threshold: int = 5
    anomaly_sats_consecutive: int = 2
    crash_vertical_speed_ms: float = -5.0
    crash_alt_drop_m: float = 10.0
    crash_alt_drop_window_s: float = 3.0
    post_flight_idle_n: int = 5
    max_path_points: int = 2000


# ---------------------------------------------------------------------------
# Step 0 — Unit audit
# ---------------------------------------------------------------------------

def run_unit_audit(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Log min/max/mean of key fields and consecutive lat/lon deltas.

    Returns a dict that can be included in the API response for diagnostics.
    """
    if not rows:
        return {"error": "No rows to audit"}

    alt_msl_vals   = [r.get("alt_m") for r in rows if r.get("alt_m") is not None]
    alt_agl_vals   = [r.get("alt_agl") for r in rows if r.get("alt_agl") is not None]
    speed_vals     = [r.get("speed_ms") for r in rows if r.get("speed_ms") is not None]
    vert_vals      = [r.get("vertical_speed_ms") for r in rows if r.get("vertical_speed_ms") is not None]
    sats_vals      = [r.get("sats") for r in rows if r.get("sats") is not None]

    lats = [r.get("lat") for r in rows if r.get("lat") is not None]
    lons = [r.get("lon") for r in rows if r.get("lon") is not None]

    deltas_km = []
    for i in range(1, min(len(lats), len(lons))):
        d = haversine_km(lats[i-1], lons[i-1], lats[i], lons[i])
        deltas_km.append(d)

    audit = {
        "row_count": len(rows),
        "alt_msl": _stats(alt_msl_vals),
        "alt_agl": _stats(alt_agl_vals) if alt_agl_vals else None,
        "speed_ms": _stats(speed_vals),
        "vertical_speed_ms": _stats(vert_vals) if vert_vals else None,
        "sats": _stats(sats_vals) if sats_vals else None,
        "lat_lon_delta_km": _stats(deltas_km) if deltas_km else None,
    }

    logger.info("=== UNIT AUDIT ===")
    for k, v in audit.items():
        logger.info("  %s: %s", k, v)

    return audit


# ---------------------------------------------------------------------------
# Step 2 — Cleaning stage
# ---------------------------------------------------------------------------

def clean_telemetry(
    rows: List[Dict[str, Any]],
    config: Optional[AirframeConfig] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Deduplicate, bounds-check, and GPS-jump filter telemetry rows.

    Returns (valid_fixes, excluded_rows).
    Each row gets a ``row_id`` (int) assigned.
    """
    if config is None:
        config = AirframeConfig()

    # 1. Assign row_id
    for i, r in enumerate(rows):
        r["row_id"] = i

    # 2. Parse timestamps
    for r in rows:
        r["_epoch"] = _ts_epoch(r.get("ts", ""))

    # Detect if timestamps are reliable: if 90%+ of rows have the same epoch,
    # the format is probably not being parsed correctly — skip ts-based dedup
    epoch_counts: Dict[float, int] = {}
    for r in rows:
        ep = r["_epoch"]
        epoch_counts[ep] = epoch_counts.get(ep, 0) + 1
    dominant_epoch, dominant_count = max(epoch_counts.items(), key=lambda x: x[1])
    ts_reliable = dominant_count < len(rows) * 0.9
    if not ts_reliable:
        logger.warning(
            "Timestamp parsing unreliable: %d/%d rows share epoch=%.0f. "
            "Skipping timestamp-based dedup. Check CSV timestamp format.",
            dominant_count, len(rows), dominant_epoch,
        )

    # 3. Sort by ts ascending (or row_id if timestamps are unreliable)
    if ts_reliable:
        rows_sorted = sorted(rows, key=lambda r: r["_epoch"])
        if _has_non_monotonic_ts(rows):
            logger.warning(
                "Timestamps are not monotonic — file may have clock reset or log corruption. "
                "Rows were sorted by timestamp for processing."
            )
    else:
        rows_sorted = sorted(rows, key=lambda r: r["row_id"])
        logger.info("Using row order instead of timestamps for sort.")

    valid: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []

    prev = None

    for r in rows_sorted:
        # ── Dedup by ts (only if timestamps are reliable) ─────────────
        if ts_reliable and prev is not None and r["_epoch"] == prev["_epoch"]:
            excluded.append(_excl(r, "duplicate_ts", "Duplicate timestamp"))
            continue

        # ── Speed bound (convert speed_ms → km/h) ──────────────────────
        spd_ms = r.get("speed_ms")
        if spd_ms is not None:
            spd_kmh = spd_ms * 3.6
            if spd_kmh > config.max_speed_kmh:
                excluded.append(_excl(
                    r, "bounds_speed",
                    f"Speed {spd_kmh:.1f} km/h exceeds ceiling {config.max_speed_kmh} km/h"
                ))
                continue
        # If speed is None we let it through (can't check)

        # ── Altitude bound ──────────────────────────────────────────────
        alt_agl_val = r.get("alt_agl")
        if alt_agl_val is not None and alt_agl_val > config.max_alt_agl_m:
            excluded.append(_excl(
                r, "bounds_altitude",
                f"Altitude {alt_agl_val:.1f} m exceeds ceiling {config.max_alt_agl_m} m"
            ))
            continue
        # Fallback: check alt_m (MSL) if no AGL available — only flag if absurd
        alt_m_val = r.get("alt_m")
        if alt_agl_val is None and alt_m_val is not None:
            if alt_m_val > 9000:  # commercial jets fly above 9000m
                excluded.append(_excl(
                    r, "bounds_altitude",
                    f"MSL altitude {alt_m_val:.0f} m is physically implausible"
                ))
                continue

        # ── GPS jump detection (needs a previous valid fix) ─────────────
        if prev is not None:
            dt = r["_epoch"] - prev["_epoch"]
            if dt > 0:
                d_km = haversine_km(
                    prev.get("lat", 0), prev.get("lon", 0),
                    r.get("lat", 0), r.get("lon", 0),
                )
                speed_required_kmh = (d_km / (dt / 3600.0)) if dt > 0 else 0
                max_allowed = config.max_speed_kmh * config.gps_jump_speed_multiple
                if speed_required_kmh > max_allowed:
                    excluded.append(_excl(
                        r, "gps_jump",
                        f"GPS delta {d_km*1000:.0f}m in {dt:.0f}s requires {speed_required_kmh:.0f} km/h "
                        f"(max {max_allowed:.0f} km/h)"
                    ))
                    continue

        valid.append(r)
        prev = r

    return valid, excluded


# ---------------------------------------------------------------------------
# Step 3 — Aggregate stats
# ---------------------------------------------------------------------------

def compute_flight_summary(
    valid_fixes: List[Dict[str, Any]],
    raw_row_count: int,
    excluded_rows: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute summary stats from valid_fixes only."""
    if not valid_fixes:
        return {
            "duration_s": 0,
            "distance_m": 0,
            "max_alt_agl_m": 0,
            "max_speed_kmh": 0,
            "avg_speed_kmh": 0,
            "raw_row_count": raw_row_count,
            "valid_fix_count": 0,
            "excluded_count": len(excluded_rows),
            "excluded_breakdown": _breakdown(excluded_rows),
        }

    # Distance
    dist_m = 0.0
    for i in range(1, len(valid_fixes)):
        dist_m += haversine_km(
            valid_fixes[i-1].get("lat", 0), valid_fixes[i-1].get("lon", 0),
            valid_fixes[i].get("lat", 0), valid_fixes[i].get("lon", 0),
        ) * 1000

    # Altitude — prefer alt_agl, fallback to alt_m - baseline
    baseline = _compute_baseline(valid_fixes)
    alt_vals = []
    for r in valid_fixes:
        agl = r.get("alt_agl")
        if agl is not None:
            alt_vals.append(agl)
        else:
            m = r.get("alt_m")
            if m is not None:
                alt_vals.append(m - baseline)

    # Speed — convert m/s to km/h
    speeds_kmh = []
    for r in valid_fixes:
        s = r.get("speed_ms")
        if s is not None and s > 0:
            speeds_kmh.append(s * 3.6)

    # Duration — fall back to fix-count estimate when timestamps are unparseable
    t0 = _ts_epoch(valid_fixes[0].get("ts", ""))
    t1 = _ts_epoch(valid_fixes[-1].get("ts", ""))
    dur = max(0, t1 - t0)
    if dur == 0 and len(valid_fixes) > 1:
        # Timestamps couldn't be parsed — estimate ~1 Hz GPS logging rate
        dur = len(valid_fixes)

    return {
        "duration_s": round(dur, 1),
        "distance_m": round(dist_m, 2),
        "max_alt_agl_m": round(max(alt_vals), 2) if alt_vals else 0,
        "max_speed_kmh": round(max(speeds_kmh), 2) if speeds_kmh else 0,
        "avg_speed_kmh": round(sum(speeds_kmh) / len(speeds_kmh), 2) if speeds_kmh else 0,
        "raw_row_count": raw_row_count,
        "valid_fix_count": len(valid_fixes),
        "excluded_count": len(excluded_rows),
        "excluded_breakdown": _breakdown(excluded_rows),
    }


# ---------------------------------------------------------------------------
# Step 4 — Phase detection
# ---------------------------------------------------------------------------

def detect_phases(
    valid_fixes: List[Dict[str, Any]],
    config: Optional[AirframeConfig] = None,
) -> List[Dict[str, Any]]:
    """Assign a phase label to each valid fix.

    Returns a list of phase blocks:
        [{"fix_index_start": int, "fix_index_end": int, "phase": str}, ...]
    """
    if config is None:
        config = AirframeConfig()
    if not valid_fixes:
        return []

    n = len(valid_fixes)

    # Determine baseline altitude for deriving AGL
    baseline = _compute_baseline(valid_fixes)

    # Pre-compute derived fields
    for r in valid_fixes:
        if r.get("alt_agl") is None and r.get("alt_m") is not None:
            r["_alt_agl_derived"] = r["alt_m"] - baseline
        else:
            r["_alt_agl_derived"] = r.get("alt_agl") or 0
        if r.get("vertical_speed_ms") is None:
            r["_vspeed"] = 0
        else:
            r["_vspeed"] = r["vertical_speed_ms"]

    # Assign phase per fix
    labels = _compute_phase_labels(valid_fixes, config)

    # Collapse consecutive same-phase into blocks
    phases = []
    start = 0
    for i in range(1, n):
        if labels[i] != labels[start]:
            phases.append({
                "fix_index_start": start,
                "fix_index_end": i - 1,
                "phase": labels[start],
            })
            start = i
    phases.append({
        "fix_index_start": start,
        "fix_index_end": n - 1,
        "phase": labels[start],
    })

    return phases


def _compute_phase_labels(
    valid_fixes: List[Dict[str, Any]],
    config: AirframeConfig,
) -> List[str]:
    """Rule-based phase assignment, evaluated per fix (first match wins)."""
    n = len(valid_fixes)
    labels = ["cruise"] * n

    # Find first motor_stop == false (i.e. motors armed) or first sat lock
    first_armed = None
    first_lock = None
    for i, r in enumerate(valid_fixes):
        if first_armed is None and r.get("flags_motor_stop") is False:
            first_armed = i
        if first_lock is None and (r.get("sats") or 0) >= config.min_lock_sats:
            first_lock = i

    # Pre-flight: before armed AND before lock
    pre_flight_end = -1
    if first_armed is not None:
        pre_flight_end = first_armed
    elif first_lock is not None:
        pre_flight_end = first_lock
    if pre_flight_end >= 0:
        for i in range(min(pre_flight_end + 1, n)):
            labels[i] = "pre_flight"

    # Post-flight: motor stopped + alt/speed near 0
    # Walk backward from the end. When we find `post_flight_idle_n` consecutive
    # rows meeting the criteria, the FIRST of those (in forward order) is the
    # start of the post-flight phase. Since we walk backward, `i` already points
    # to that first row when the count reaches the threshold.
    post_flight_start = None
    consecutive_idle = 0
    for i in range(n - 1, -1, -1):
        r = valid_fixes[i]
        motor_stopped = r.get("flags_motor_stop") is True
        alt_near_zero = abs(r["_alt_agl_derived"]) < config.takeoff_aom_m
        spd_near_zero = (r.get("speed_ms") or 0) < 1.0
        if motor_stopped and alt_near_zero and spd_near_zero:
            consecutive_idle += 1
            if consecutive_idle >= config.post_flight_idle_n:
                post_flight_start = i
                break
        else:
            consecutive_idle = 0

    if post_flight_start is not None:
        for i in range(post_flight_start, n):
            labels[i] = "post_flight"

    # Anomaly / RTH
    anomaly_run = 0
    for i in range(n):
        r = valid_fixes[i]
        is_rth = r.get("flags_rth") is True
        sats_low = (r.get("sats") or 99) < config.anomaly_sats_threshold
        if is_rth:
            labels[i] = "anomaly_rth"
            anomaly_run = 0
        elif sats_low:
            anomaly_run += 1
            if anomaly_run >= config.anomaly_sats_consecutive:
                labels[i] = "anomaly_rth"
        else:
            anomaly_run = 0

    # Crash / landing detection
    for i in range(1, n):
        if labels[i] in ("post_flight", "anomaly_rth"):
            continue
        r = valid_fixes[i]
        prev = valid_fixes[i-1]
        vs = r.get("_vspeed", 0)
        alt_drop = prev["_alt_agl_derived"] - r["_alt_agl_derived"]
        dt = max(0.001, r["_epoch"] - prev["_epoch"])
        if (vs < config.crash_vertical_speed_ms or
            (alt_drop > config.crash_alt_drop_m and dt < config.crash_alt_drop_window_s)):
            labels[i] = "crash_landing"

    # Takeoff: after pre_flight, from first positive vspeed or altitude climb
    takeoff_start = max(0, pre_flight_end + 1)
    if post_flight_start is not None:
        takeoff_end = min(post_flight_start, n)
    else:
        takeoff_end = n

    for i in range(takeoff_start, takeoff_end):
        if labels[i] in ("anomaly_rth", "crash_landing", "post_flight"):
            continue
        r = valid_fixes[i]
        positive_climb = r.get("_vspeed", 0) > 0 or r["_alt_agl_derived"] > config.takeoff_aom_m
        if positive_climb:
            # Takeoff phase lasts ~15 seconds or until altitude stabilizes
            to_end = i
            for j in range(i, min(i + 30, takeoff_end)):
                if labels[j] in ("anomaly_rth", "crash_landing", "post_flight"):
                    to_end = j
                    break
                if abs(valid_fixes[j].get("_vspeed", 0)) < 1.0 and j > i + 5:
                    to_end = j
                    break
            for j in range(i, min(to_end + 1, takeoff_end)):
                labels[j] = "takeoff"
            break

    return labels


# ---------------------------------------------------------------------------
# Step 5 — Event extraction
# ---------------------------------------------------------------------------

def extract_events(
    valid_fixes: List[Dict[str, Any]],
    phases: List[Dict[str, Any]],
    config: Optional[AirframeConfig] = None,
) -> List[Dict[str, Any]]:
    """Emit meaningful events from valid_fixes and phase blocks."""
    if config is None:
        config = AirframeConfig()
    if not valid_fixes:
        return []

    takeoff_epoch = _find_takeoff_epoch(valid_fixes, phases)

    events: List[Dict[str, Any]] = []

    # First valid fix
    _add_event(events, valid_fixes, 0, takeoff_epoch, "pre_flight",
               "First GPS Fix", "normal", "GPS lock acquired")

    # Phase transitions
    for phase in phases:
        idx = phase["fix_index_start"]
        # Skip first-fix which is already added as "First GPS Fix"
        if idx == 0:
            if phase["phase"] != "pre_flight":
                _add_phase_event(events, valid_fixes, idx, takeoff_epoch, phase["phase"])
            continue

        _add_phase_event(events, valid_fixes, idx, takeoff_epoch, phase["phase"])

    # Local extrema
    _add_extrema_events(events, valid_fixes, takeoff_epoch)

    # Last valid fix
    _add_event(events, valid_fixes, len(valid_fixes) - 1, takeoff_epoch,
               phases[-1]["phase"] if phases else "unknown",
               "Last GPS Fix", "normal",
               f"End of recorded telemetry ({len(valid_fixes)} valid fixes)")

    # Deduplicate by name (e.g. don't emit Takeoff twice if phase transition matches)
    seen_names: set = set()
    deduped = []
    for ev in events:
        key = (ev["name"], ev.get("raw_ref", {}).get("row_start"))
        if key not in seen_names:
            seen_names.add(key)
            deduped.append(ev)

    return deduped


def _add_event(
    events: List[Dict[str, Any]], fixes: List[Dict[str, Any]],
    idx: int, takeoff_epoch: float, phase: str,
    name: str, severity: str, description: str,
) -> None:
    r = fixes[idx]
    ts = r.get("ts", "")
    t_off = (r["_epoch"] - takeoff_epoch) if takeoff_epoch else 0
    events.append({
        "ts": ts,
        "t_offset_s": round(t_off, 1),
        "phase": phase,
        "name": name,
        "lat": r.get("lat"),
        "lon": r.get("lon"),
        "alt_agl": r.get("_alt_agl_derived", r.get("alt_agl", r.get("alt_m"))),
        "speed": r.get("speed_ms"),
        "sats": r.get("sats"),
        "severity": severity,
        "description": description,
        "raw_ref": {"row_start": r.get("row_id", idx), "row_end": r.get("row_id", idx)},
    })


def _add_phase_event(
    events: List[Dict[str, Any]], fixes: List[Dict[str, Any]],
    idx: int, takeoff_epoch: float, phase: str,
) -> None:
    name_map = {
        "pre_flight": "Pre-Flight",
        "takeoff": "Takeoff",
        "cruise": "Flight",
        "anomaly_rth": "Return-to-Home / Anomaly",
        "crash_landing": "Crash / Hard Landing",
        "post_flight": "Post-Flight",
    }
    severity_map = {
        "pre_flight": "normal",
        "takeoff": "normal",
        "cruise": "normal",
        "anomaly_rth": "anomaly",
        "crash_landing": "crash",
        "post_flight": "normal",
    }
    desc_map = {
        "pre_flight": "Aircraft on ground, motors not armed",
        "takeoff": "Aircraft departing from ground",
        "cruise": "Normal flight",
        "anomaly_rth": "Anomaly detected or Return-to-Home activated",
        "crash_landing": "Rapid descent detected — possible crash or hard landing",
        "post_flight": "Aircraft on ground after flight",
    }
    _add_event(
        events, fixes, idx, takeoff_epoch, phase,
        name_map.get(phase, phase),
        severity_map.get(phase, "normal"),
        desc_map.get(phase, ""),
    )


def _add_extrema_events(
    events: List[Dict[str, Any]], fixes: List[Dict[str, Any]],
    takeoff_epoch: float,
) -> None:
    """Add max altitude and max speed events."""
    if not fixes:
        return

    # Max altitude
    alt_vals = [(i, r.get("_alt_agl_derived", r.get("alt_agl", r.get("alt_m", 0))))
                for i, r in enumerate(fixes)]
    max_idx = max(alt_vals, key=lambda x: x[1])[0]
    _add_event(events, fixes, max_idx, takeoff_epoch, "cruise",
               "Max Altitude", "normal",
               f"Peak altitude {alt_vals[max_idx][1]:.1f} m")

    # Max speed
    spd_vals = [(i, r.get("speed_ms", 0)) for i, r in enumerate(fixes)
                if r.get("speed_ms") is not None]
    if spd_vals:
        max_spd_idx = max(spd_vals, key=lambda x: x[1])[0]
        _add_event(events, fixes, max_spd_idx, takeoff_epoch, "cruise",
                   "Max Speed", "normal",
                   f"Peak speed {spd_vals[max_spd_idx][1]*3.6:.1f} km/h")


# ---------------------------------------------------------------------------
# Step 6 — Contract builder
# ---------------------------------------------------------------------------

def build_contract(
    case_id: str,
    source_file: str,
    raw_rows: List[Dict[str, Any]],
    valid_fixes: List[Dict[str, Any]],
    excluded_rows: List[Dict[str, Any]],
    phases: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
    config: Optional[AirframeConfig] = None,
) -> Dict[str, Any]:
    """Assemble the full JSON contract for the frontend."""
    if config is None:
        config = AirframeConfig()

    summary = compute_flight_summary(valid_fixes, len(raw_rows), excluded_rows)

    # Integrity warnings
    integrity_warnings: List[str] = []
    if summary["max_speed_kmh"] > config.max_speed_kmh:
        integrity_warnings.append(
            f"Max speed {summary['max_speed_kmh']} km/h exceeds airframe ceiling "
            f"{config.max_speed_kmh} km/h — verify decoder unit scaling"
        )
    if summary["max_alt_agl_m"] > config.max_alt_agl_m:
        integrity_warnings.append(
            f"Max altitude {summary['max_alt_agl_m']} m exceeds legal ceiling "
            f"{config.max_alt_agl_m} m — verify data"
        )

    return {
        "case_id": case_id,
        "source_file": source_file,
        "flight_summary": summary,
        "flight_events": events,
        "integrity_warnings": integrity_warnings,
    }


# ---------------------------------------------------------------------------
# Orchestrator — run the full pipeline
# ---------------------------------------------------------------------------

def run_pipeline(
    raw_rows: List[Dict[str, Any]],
    case_id: str = "",
    source_file: str = "",
    config: Optional[AirframeConfig] = None,
) -> Dict[str, Any]:
    """Run the full cleaning pipeline: audit → clean → phases → events.

    Returns the section-6 contract dict.
    """
    if config is None:
        config = AirframeConfig()

    # Step 0 — audit
    audit = run_unit_audit(raw_rows)
    logger.info("Unit audit complete: %s", audit)

    # Step 2 — clean
    valid_fixes, excluded_rows = clean_telemetry(raw_rows, config)
    logger.info(
        "Cleaning complete: %d valid, %d excluded",
        len(valid_fixes), len(excluded_rows),
    )

    # Step 4 — phases
    phases = detect_phases(valid_fixes, config)
    logger.info("Phase detection complete: %d phases", len(phases))

    # Step 5 — events
    events = extract_events(valid_fixes, phases, config)
    logger.info("Event extraction complete: %d events", len(events))

    # Step 6 — contract
    contract = build_contract(
        case_id, source_file, raw_rows,
        valid_fixes, excluded_rows, phases, events, config,
    )

    # Include audit in response for diagnostics
    contract["_audit"] = audit

    return contract


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Haversine distance in km."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _ts_epoch(ts_str: Any) -> float:
    """Parse timestamp string to epoch seconds. Returns 0 on failure."""
    if not ts_str:
        return 0
    if isinstance(ts_str, (int, float)):
        return float(ts_str)
    s = str(ts_str).strip()
    if not s:
        return 0

    # Epoch seconds or milliseconds as a numeric string
    if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
        val = float(s)
        if val > 1e12:  # milliseconds
            return val / 1000.0
        return val

    # Normalise timezone suffix
    use_utc = False
    if s.endswith("Z") or s.endswith("z"):
        s = s[:-1]
        use_utc = True
    elif " " in s and (s.endswith("UTC") or s.endswith("utc")):
        s = s[:-3].strip()
        use_utc = True

    # Strip numeric timezone offsets: +HH:MM, -HH:MM, +HHMM, -HHMM
    import re
    tz_clean = re.sub(r"[+-]\d{2}:?\d{2}$", "", s)
    if tz_clean != s:
        s = tz_clean.strip()
        # Treat as UTC (don't know offset sign without full parsing)
        use_utc = True

    # Strip trailing Z/UTC again after cleanup
    s = s.rstrip("Zz ")

    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%dT%H:%M:%S",
        "%d-%m-%YT%H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%YT%H:%M:%S",
        "%Y%m%d %H:%M:%S:%f",
        "%Y%m%dT%H%M%S",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(s, fmt)
            if use_utc:
                return dt.replace(tzinfo=timezone.utc).timestamp()
            return dt.timestamp()
        except ValueError:
            pass
    # Last resort: try pandas if available
    try:
        import pandas as pd
        ts = pd.Timestamp(s)
        if ts is not pd.NaT:
            return ts.timestamp()
    except Exception:
        pass
    return 0


def _has_non_monotonic_ts(rows: List[Dict[str, Any]]) -> bool:
    """Check if timestamps are not monotonically increasing."""
    prev = float("-inf")
    for r in rows:
        cur = _ts_epoch(r.get("ts", ""))
        if cur < prev:
            return True
        prev = cur
    return False


def _stats(vals: List[float]) -> Dict[str, float]:
    if not vals:
        return {"min": None, "max": None, "mean": None, "count": 0}
    return {
        "min": round(min(vals), 4),
        "max": round(max(vals), 4),
        "mean": round(sum(vals) / len(vals), 4),
        "count": len(vals),
    }


def _excl(row: Dict[str, Any], reason: str, detail: str) -> Dict[str, Any]:
    return {
        "row_id": row.get("row_id"),
        "ts": row.get("ts"),
        "lat": row.get("lat"),
        "lon": row.get("lon"),
        "reason": reason,
        "detail": detail,
    }


def _breakdown(excluded: List[Dict[str, Any]]) -> Dict[str, int]:
    bd: Dict[str, int] = {}
    for e in excluded:
        r = e.get("reason", "unknown")
        bd[r] = bd.get(r, 0) + 1
    return bd


def _compute_baseline(valid_fixes: List[Dict[str, Any]], window: int = 10) -> float:
    """Average altitude from first N valid fixes as ground baseline."""
    if not valid_fixes:
        return 0
    n = min(window, len(valid_fixes))
    alts = [valid_fixes[i].get("alt_m") or 0 for i in range(n)]
    return sum(alts) / n


def _find_takeoff_epoch(
    fixes: List[Dict[str, Any]], phases: List[Dict[str, Any]],
) -> float:
    """Find the epoch of the first takeoff fix for offset computation."""
    for p in phases:
        if p["phase"] == "takeoff":
            return fixes[p["fix_index_start"]]["_epoch"]
    return fixes[0]["_epoch"] if fixes else 0
