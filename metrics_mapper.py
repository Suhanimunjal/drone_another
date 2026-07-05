"""metrics_mapper.py

Maps DroneFlightViewer's rich parse_log() output to the dashboard's simple
metrics shape expected by forensics_dashboard.html's loadFlightLogs().

Dashboard expects via /api/flight-logs:
    {
        "telemetry_available": bool,
        "metrics": {
            "takeoff": {"lat", "lon", "alt"},
            "landing": {"lat", "lon", "alt"},
            "home_alt_m": float,
            "total_distance_km": float,
            "total_distance_m": float,
            "max_altitude_m": float,
            "max_speed_kmh": float,
            "max_speed_ms": float,
            "avg_speed_kmh": float,
            "avg_speed_ms": float,
            "gps_fixes": int,
            "coverage_km2": float,
        },
        "timeline": [...],
        "converted_files": [...],
        ...
    }
"""

from __future__ import annotations

import math
from typing import Any


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Haversine distance in km between two lat/lon points."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def compute_coverage_km2(track: list[dict]) -> float:
    """Approximate bounding-box coverage in km²."""
    if not track:
        return 0.0
    lats = [p["lat"] for p in track]
    lons = [p["lon"] for p in track]
    dlat_km = (max(lats) - min(lats)) * 111.0
    dlon_km = (max(lons) - min(lons)) * 111.0 * math.cos(math.radians((max(lats) + min(lats)) / 2))
    return round(dlat_km * dlon_km, 2)


def detect_takeoff_from_track(track: list[dict], home_alt: float | None = None) -> dict:
    """Detect takeoff point from track.

    Strategy: find the first point where altitude > home_alt + 2m,
    or falls back to track[0].
    """
    if not track:
        return {"lat": 0, "lon": 0, "alt": 0}

    if home_alt is None:
        home_alt = track[0]["alt"]

    for p in track:
        if p["alt"] and p["alt"] > home_alt + 2:
            return {"lat": p["lat"], "lon": p["lon"], "alt": round(p["alt"], 1)}

    return {"lat": track[0]["lat"], "lon": track[0]["lon"], "alt": round(track[0]["alt"], 1)}


def detect_landing_from_track(track: list[dict], home_alt: float | None = None) -> dict:
    """Detect landing point from track.

    Strategy: find the last sustained point near home altitude.
    """
    if not track:
        return {"lat": 0, "lon": 0, "alt": 0}

    if home_alt is None:
        home_alt = track[0]["alt"]

    landing_idx = len(track) - 1
    for i in range(len(track) - 1, -1, -1):
        alt = track[i].get("alt")
        if alt and alt > home_alt + 2:
            landing_idx = min(i + 2, len(track) - 1)
            break

    p = track[landing_idx]
    return {"lat": p["lat"], "lon": p["lon"], "alt": round(p["alt"], 1)}


def map_to_dashboard_metrics(parsed_log: dict[str, Any]) -> dict[str, Any] | None:
    """Convert DroneFlightViewer parse_log() dict to dashboard metrics shape.

    Returns None if no track data is available.
    """
    track = parsed_log.get("track", [])
    if not track:
        return None

    home = parsed_log.get("home")
    home_alt = home["alt"] if home else track[0]["alt"]
    stats = parsed_log.get("stats", {})

    takeoff = detect_takeoff_from_track(track, home_alt)
    landing = detect_landing_from_track(track, home_alt)

    total_dist_m = stats.get("total_distance_m", 0)
    if not total_dist_m and len(track) > 1:
        total_dist_m = sum(
            haversine_km(a["lat"], a["lon"], b["lat"], b["lon"]) * 1000
            for a, b in zip(track, track[1:])
        )

    max_alt = stats.get("max_alt", max((p.get("alt") or 0 for p in track), default=0))
    max_spd = stats.get("max_speed", max((p.get("spd") or 0 for p in track), default=0))

    speeds = [p["spd"] for p in track if p.get("spd") and p["spd"] > 0]
    avg_spd = sum(speeds) / len(speeds) if speeds else 0

    return {
        "takeoff": takeoff,
        "landing": landing,
        "home_alt_m": round(home_alt, 1),
        "total_distance_m": round(total_dist_m, 1),
        "total_distance_km": round(total_dist_m / 1000, 2),
        "max_altitude_m": round(max_alt, 1),
        "max_speed_ms": round(max_spd, 2),
        "max_speed_kmh": round(max_spd * 3.6, 2),
        "avg_speed_ms": round(avg_spd, 2),
        "avg_speed_kmh": round(avg_spd * 3.6, 2),
        "gps_fixes": stats.get("gps_points", len(track)),
        "coverage_km2": compute_coverage_km2(track),
    }
