"""D2 — Flight Reconstruction.

Reads TSK_DAT_CONVERTED artifacts from D1, analyzes the CSV files
for takeoff/landing/trajectory, and emits TSK_FLIGHT_ANALYSIS artifacts.

Ported from stage5_flight_analysis.py with the same exact algorithm.
"""

import os
import json
import csv
from datetime import datetime

from ..base import IngestModule, Artifact
from ... import manifest_db

ALT_THRESHOLD_M = 2.0
CONSECUTIVE_ROWS = 5


def _find_col(header_row, candidates):
    keys = list(header_row.keys())
    for candidate in candidates:
        for key in keys:
            if key.strip().lower() == candidate.lower():
                return key
    return None


def _parse_time(time_str):
    if not time_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(time_str.strip(), fmt)
        except ValueError:
            continue
    return None


def _analyze_flight(csv_path):
    """EXACT algorithm per spec section 5. Returns analysis dict or None."""
    if not os.path.isfile(csv_path):
        return None

    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except Exception:
        return None

    if not rows:
        return None

    lat_col = _find_col(rows[0], ["latitude", "lat", "Latitude", "LAT"])
    lon_col = _find_col(rows[0], ["longitude", "lon", "lng", "Longitude", "LON"])
    alt_col = _find_col(rows[0], ["altitude", "alt", "alt_rel", "alt_msl", "Alt", "ALT"])
    time_col = _find_col(rows[0], ["time", "timestamp", "Time", "TIME", "datetime"])
    speed_col = _find_col(rows[0], ["speed", "velocity", "vel", "Speed", "SPEED", "ground_speed"])

    if not all([lat_col, lon_col, alt_col]):
        return None

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

    baseline_altitude = sum(r["altitude"] for r in valid_rows[:5]) / 5

    for r in valid_rows:
        r["rel_altitude"] = r["altitude"] - baseline_altitude
        r["airborne"] = r["rel_altitude"] > ALT_THRESHOLD_M

    takeoff_idx = None
    n = len(valid_rows)
    for i in range(n - CONSECUTIVE_ROWS + 1):
        if all(valid_rows[j]["airborne"] for j in range(i, i + CONSECUTIVE_ROWS)):
            takeoff_idx = i
            break

    landing_idx = None
    for i in range(n - 1, 0, -1):
        if valid_rows[i]["airborne"]:
            end_check = min(i + 1 + CONSECUTIVE_ROWS, n)
            if not any(valid_rows[j]["airborne"] for j in range(i + 1, end_check)):
                landing_idx = i
                break

    trajectory = [
        {"time": r["time"], "latitude": r["latitude"],
         "longitude": r["longitude"], "altitude": r["altitude"]}
        for r in valid_rows
    ]

    max_alt = max(r["rel_altitude"] for r in valid_rows)
    speeds = [r["speed"] for r in valid_rows if r["speed"] is not None]
    max_speed = max(speeds) if speeds else None

    flight_duration = None
    if takeoff_idx is not None and landing_idx is not None:
        t0 = _parse_time(valid_rows[takeoff_idx]["time"])
        t1 = _parse_time(valid_rows[landing_idx]["time"])
        if t0 and t1:
            flight_duration = (t1 - t0).total_seconds()

    return {
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


class FlightReconstructionModule(IngestModule):
    """D2 — Reconstruct flight from converted CSV data."""

    name = "flight_reconstruction"
    depends_on = ["dat_parser"]  # Needs D1 artifacts first
    applies_to = "case_level"     # We read D1 artifacts ourselves

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        """Case-level run: read all TSK_DAT_CONVERTED artifacts, analyze each CSV."""
        if not case_context:
            return []

        case_id = case_context.get("case_id")
        if not case_id:
            return []

        artifacts = []
        dat_converted = manifest_db.get_artifacts(case_id, artifact_type="TSK_DAT_CONVERTED")

        for art in dat_converted:
            details = art.get("details_json")
            try:
                details = json.loads(details) if isinstance(details, str) else (details or {})
            except (json.JSONDecodeError, TypeError):
                continue

            csv_path = details.get("csv_path")
            method = details.get("method", "?")
            error = details.get("error")

            if not csv_path or error:
                # D1 failed for this file — skip or flag
                continue

            analysis = _analyze_flight(csv_path)
            if analysis is None:
                continue

            has_takeoff = analysis["takeoff"]["latitude"] is not None
            severity = "info" if has_takeoff else "low"

            artifacts.append(Artifact(
                artifact_type="TSK_FLIGHT_ANALYSIS",
                case_id=case_id,
                module_name=self.name,
                file_id=art.get("file_id"),
                parent_artifact_id=art.get("id"),
                severity=severity,
                title=f"Flight analysis: {os.path.basename(csv_path)}",
                description=(
                    f"Takeoff ({analysis['takeoff']['latitude']:.5f}, {analysis['takeoff']['longitude']:.5f}), "
                    f"Landing ({analysis['landing']['latitude']:.5f}, {analysis['landing']['longitude']:.5f}), "
                    f"Duration: {analysis['flight_duration_seconds']}s"
                    if has_takeoff else
                    "No takeoff detected (airborne phase not found)"
                ),
                details={
                    "csv_path": csv_path,
                    "conversion_method": method,
                    **analysis,
                },
                ts_ref=analysis["takeoff"]["timestamp"] if has_takeoff else analysis.get("landing", {}).get("timestamp"),
                lat=analysis["takeoff"]["latitude"] if has_takeoff else None,
                lon=analysis["takeoff"]["longitude"] if has_takeoff else None,
            ))

        return artifacts
