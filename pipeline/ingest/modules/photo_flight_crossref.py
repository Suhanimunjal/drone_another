"""D4 — Photo / Flight Cross-Reference.

Matches geo-tagged photos (TSK_EXIF_DATA) against flight trajectories
(TSK_FLIGHT_ANALYSIS). Finds photos taken within time range and
within proximity distance of a flight's trajectory path.
"""

import os
import json
from math import radians, sin, cos, sqrt, asin
from ..base import IngestModule, Artifact
from ... import manifest_db

MAX_DISTANCE_M = 500.0   # max meters from flight path
TIME_BUFFER_S = 300       # +/- 5 min window for time match


def _haversine_km(lat1, lon1, lat2, lon2):
    """Haversine distance in km between two lat/lon points."""
    R = 6371.0
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = sin(dlat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    return R * 2 * asin(min(1.0, sqrt(a)))


def _parse_time(ts_str):
    """Parse various timestamp formats to epoch seconds."""
    if not ts_str:
        return None
    from datetime import datetime
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S.%f", "%H:%M:%S"):
        try:
            return datetime.strptime(ts_str.strip(), fmt).timestamp()
        except ValueError:
            continue
    return None


def _min_distance_to_trajectory(lat, lon, trajectory):
    """Find minimum haversine distance (km) from a point to any trajectory point."""
    min_dist = float("inf")
    for pt in trajectory:
        plat = pt.get("latitude")
        plon = pt.get("longitude")
        if plat is not None and plon is not None:
            dist = _haversine_km(lat, lon, plat, plon)
            if dist < min_dist:
                min_dist = dist
    return min_dist


class PhotoFlightCrossrefModule(IngestModule):
    name = "photo_flight_crossref"
    depends_on = ["exif_parser", "flight_reconstruction"]
    applies_to = "case_level"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not case_context:
            return []

        case_id = case_context.get("case_id")
        if not case_id:
            return []

        photo_arts = manifest_db.get_artifacts(case_id, artifact_type="TSK_EXIF_DATA")
        flight_arts = manifest_db.get_artifacts(case_id, artifact_type="TSK_FLIGHT_ANALYSIS")

        if not photo_arts or not flight_arts:
            return []

        result = []

        for photo in photo_arts:
            photo_details = photo.get("details_json")
            try:
                photo_details = json.loads(photo_details) if isinstance(photo_details, str) else (photo_details or {})
            except (json.JSONDecodeError, TypeError):
                continue

            photo_lat = photo.get("lat")
            photo_lon = photo.get("lon")
            photo_ts = _parse_time(photo.get("ts_ref"))
            if photo_lat is None or photo_lon is None:
                continue

            best_match = None
            best_dist = float("inf")

            for flight in flight_arts:
                flight_details = flight.get("details_json")
                try:
                    flight_details = json.loads(flight_details) if isinstance(flight_details, str) else (flight_details or {})
                except (json.JSONDecodeError, TypeError):
                    continue

                trajectory = flight_details.get("trajectory", [])
                if not trajectory:
                    continue

                takeoff_ts = _parse_time(flight_details.get("takeoff", {}).get("timestamp"))
                landing_ts = _parse_time(flight_details.get("landing", {}).get("timestamp"))

                # Time check
                if photo_ts and takeoff_ts and landing_ts:
                    if photo_ts < (takeoff_ts - TIME_BUFFER_S) or photo_ts > (landing_ts + TIME_BUFFER_S):
                        continue

                # Distance check
                min_dist_km = _min_distance_to_trajectory(photo_lat, photo_lon, trajectory)
                min_dist_m = min_dist_km * 1000

                if min_dist_m <= MAX_DISTANCE_M and min_dist_m < best_dist:
                    best_dist = min_dist_m
                    best_match = {
                        "flight_artifact_id": flight.get("id"),
                        "trajectory_point_count": len(trajectory),
                        "distance_m": round(min_dist_m, 1),
                        "takeoff": flight_details.get("takeoff"),
                        "landing": flight_details.get("landing"),
                    }

            if best_match:
                result.append(Artifact(
                    artifact_type="TSK_PHOTO_FLIGHT_MATCH",
                    case_id=case_id,
                    module_name=self.name,
                    file_id=photo.get("file_id"),
                    parent_artifact_id=photo.get("id"),
                    severity="medium",
                    title=f"Photo matched to flight ({best_match['distance_m']}m)",
                    description=f"Photo at ({photo_lat}, {photo_lon}) is {best_match['distance_m']}m from flight path",
                    details={
                        "photo_details": photo_details,
                        "flight_match": best_match,
                    },
                    ts_ref=photo.get("ts_ref"),
                    lat=photo_lat,
                    lon=photo_lon,
                ))

        return result
