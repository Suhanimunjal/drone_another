"""Stage 5: Flight Data Analysis

Analyzes converted CSV flight logs to detect takeoff, landing, trajectory,
and compute flight statistics.

Algorithm is EXACT per spec section 5 — do not deviate.

Input: successfully-converted CSV from Stage 4
Output: analysis JSON per flight
"""

import os
import json
import csv
from datetime import datetime, timezone

from . import manifest_db


# ── Constants (spec section 5) ───────────────────────────────────────────

ALT_THRESHOLD_M = 2.0     # meters above baseline to count as "airborne"
CONSECUTIVE_ROWS = 5      # consecutive rows required for takeoff/landing detection


def analyze_flight(csv_path):
    """Analyze a flight CSV. EXACT algorithm per spec section 5.

    Required columns: time, latitude, longitude, altitude
    Optional: speed, velocityX/Y/Z, battery_percent, satellites, flightMode

    Returns analysis dict or None on failure.
    """
    if not os.path.isfile(csv_path):
        return None

    # Read CSV
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except Exception:
        return None

    if not rows:
        return None

    # Find column names (handle name variations)
    lat_col = _find_col(rows[0], ["latitude", "lat", "Latitude", "LAT"])
    lon_col = _find_col(rows[0], ["longitude", "lon", "lng", "Longitude", "LON"])
    alt_col = _find_col(rows[0], ["altitude", "alt", "alt_rel", "alt_msl", "Alt", "ALT"])
    time_col = _find_col(rows[0], ["time", "timestamp", "Time", "TIME", "datetime"])
    speed_col = _find_col(rows[0], ["speed", "velocity", "vel", "Speed", "SPEED", "ground_speed"])

    if not all([lat_col, lon_col, alt_col]):
        return None

    # Parse and filter valid GPS rows (spec: drop NaN, drop 0,0)
    valid_rows = []
    for row in rows:
        try:
            lat = float(row[lat_col])
            lon = float(row[lon_col])
            alt = float(row[alt_col])
            if lat == 0 and lon == 0:
                continue
            if abs(lat) > 90 or abs(lon) > 180:
                continue
            valid_rows.append({
                "time": row.get(time_col, "") if time_col else "",
                "latitude": lat,
                "longitude": lon,
                "altitude": alt,
                "speed": float(row[speed_col]) if speed_col and row.get(speed_col) else None,
            })
        except (ValueError, KeyError):
            continue

    if len(valid_rows) < 5:
        return None

    # Baseline altitude = avg of first 5 valid readings (spec)
    baseline_altitude = sum(r["altitude"] for r in valid_rows[:5]) / 5

    # Relative altitude and airborne flag (spec)
    for r in valid_rows:
        r["rel_altitude"] = r["altitude"] - baseline_altitude
        r["airborne"] = r["rel_altitude"] > ALT_THRESHOLD_M

    # Takeoff: first index where airborne=True for 5+ consecutive rows (spec)
    takeoff_idx = None
    n = len(valid_rows)
    for i in range(n - CONSECUTIVE_ROWS + 1):
        if all(valid_rows[j]["airborne"] for j in range(i, i + CONSECUTIVE_ROWS)):
            takeoff_idx = i
            break

    # Landing: last index where airborne=True, followed by 5+ consecutive False (spec)
    landing_idx = None
    for i in range(n - 1, 0, -1):
        if valid_rows[i]["airborne"]:
            end_check = min(i + 1 + CONSECUTIVE_ROWS, n)
            if not any(valid_rows[j]["airborne"] for j in range(i + 1, end_check)):
                landing_idx = i
                break

    # Build trajectory
    trajectory = [
        {"time": r["time"], "latitude": r["latitude"],
         "longitude": r["longitude"], "altitude": r["altitude"]}
        for r in valid_rows
    ]

    # Max altitude and speed
    max_alt = max(r["rel_altitude"] for r in valid_rows)
    speeds = [r["speed"] for r in valid_rows if r["speed"] is not None]
    max_speed = max(speeds) if speeds else None

    # Flight duration
    flight_duration = None
    if takeoff_idx is not None and landing_idx is not None:
        t0 = _parse_time(valid_rows[takeoff_idx]["time"])
        t1 = _parse_time(valid_rows[landing_idx]["time"])
        if t0 and t1:
            flight_duration = (t1 - t0).total_seconds()

    result = {
        "baseline_altitude_m": round(baseline_altitude, 2),
        "takeoff": {
            "timestamp": valid_rows[takeoff_idx]["time"] if takeoff_idx is not None else None,
            "latitude": valid_rows[takeoff_idx]["latitude"] if takeoff_idx is not None else None,
            "longitude": valid_rows[takeoff_idx]["longitude"] if takeoff_idx is not None else None,
        },
        "landing": {
            "timestamp": valid_rows[landing_idx]["time"] if landing_idx is not None else None,
            "latitude": valid_rows[landing_idx]["latitude"] if landing_idx is not None else None,
            "longitude": valid_rows[landing_idx]["longitude"] if landing_idx is not None else None,
        },
        "max_altitude_m": round(max_alt, 2),
        "max_speed": round(max_speed, 2) if max_speed is not None else None,
        "flight_duration_seconds": round(flight_duration, 1) if flight_duration else None,
        "trajectory": trajectory,
    }

    return result


def _find_col(header, candidates):
    """Find a column name from candidates list."""
    keys = list(header.keys())
    for candidate in candidates:
        for key in keys:
            if key.strip().lower() == candidate.lower():
                return key
    return None


def _parse_time(time_str):
    """Parse time string to datetime."""
    if not time_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(time_str.strip(), fmt)
        except ValueError:
            continue
    return None


def run_stage5(case_id, conversions, log_cb=None):
    """Execute Stage 5: analyze all successful CSV conversions.

    Args:
        case_id: case UUID
        conversions: list of conversion records from Stage 4
        log_cb: optional callback(level, message)

    Returns:
        dict with analysis stats
    """
    def log(level, msg):
        if log_cb:
            log_cb(level, msg)
        print(f"[Stage 5] [{level}] {msg}")

    log("stage", "Analyzing flight data")

    stats = {"total": len(conversions), "analyzed": 0, "no_takeoff": 0, "failed": 0}
    analyses = []

    for conv in conversions:
        if conv.get("status") != "SUCCESS":
            log("info", f"  Skipping non-successful conversion: {conv.get('id')}")
            continue

        csv_path = conv.get("csv_path")
        if not csv_path or not os.path.isfile(csv_path):
            log("warn", f"  CSV not found: {csv_path}")
            stats["failed"] += 1
            continue

        log("info", f"  Analyzing: {os.path.basename(csv_path)}")

        result = analyze_flight(csv_path)
        if result is None:
            log("warn", f"  Analysis failed for {csv_path}")
            stats["failed"] += 1
            continue

        # Determine if takeoff was detected
        if result["takeoff"]["latitude"] is None:
            stats["no_takeoff"] += 1
            log("info", f"  Takeoff: NOT DETECTED (airborne phase not found)")
        else:
            stats["analyzed"] += 1
            log("info", f"  Takeoff: ({result['takeoff']['latitude']:.5f}, {result['takeoff']['longitude']:.5f})")
            log("info", f"  Landing: ({result['landing']['latitude']:.5f}, {result['landing']['longitude']:.5f})")
            log("info", f"  Max alt: {result['max_altitude_m']}m, Max speed: {result['max_speed']} km/h")
            log("info", f"  Duration: {result['flight_duration_seconds']}s, Points: {len(result['trajectory'])}")

        # Store in DB
        analysis_id = manifest_db.new_analysis_id()
        analysis_row = {
            "id": analysis_id,
            "case_id": case_id,
            "conversion_id": conv["id"],
            "baseline_altitude_m": result["baseline_altitude_m"],
            "takeoff_timestamp": result["takeoff"]["timestamp"],
            "takeoff_latitude": result["takeoff"]["latitude"],
            "takeoff_longitude": result["takeoff"]["longitude"],
            "landing_timestamp": result["landing"]["timestamp"],
            "landing_latitude": result["landing"]["latitude"],
            "landing_longitude": result["landing"]["longitude"],
            "max_altitude_m": result["max_altitude_m"],
            "max_speed": result["max_speed"],
            "flight_duration_seconds": result["flight_duration_seconds"],
            "trajectory_json": json.dumps(result["trajectory"]),
            "analysis_json": json.dumps(result),
        }
        manifest_db.insert_flight_analysis(analysis_row)

        analyses.append({"id": analysis_id, "csv_path": csv_path, "analysis": result})

    log("info", f"Analysis complete: {stats['analyzed']} analyzed, {stats['no_takeoff']} no takeoff, {stats['failed']} failed")

    manifest_db.update_case_stage(case_id, "stage5", 90)

    return {"stats": stats, "analyses": analyses}
