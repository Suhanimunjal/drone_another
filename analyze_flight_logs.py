"""
analyze_flight_logs.py
Parse telemetry and remote GPS Excel files, extract flight metrics.
"""
import pandas as pd
import numpy as np
import json, math
from datetime import datetime

DB_DIR = r"D:\new_WEBSITE\Drone-DATABASE"

def parse_telemetry():
    """Parse Master_telmetry_june_2018.xlsx and return flight stats."""
    df = pd.read_excel(f"{DB_DIR}/Master_telmetry_june_2018.xlsx", sheet_name="42-Telemetry")
    df.columns = [c.strip() for c in df.columns]

    valid = df[(df["latitude"] != 0) & (df["longitude"] != 0) & (df["latitude"].abs() < 90)].copy()
    if valid.empty:
        valid = df[df["latitude"].abs() < 90].copy()

    # Parse timestamp from Column1
    def parse_ts(val):
        try:
            val = str(val).strip()
            return datetime.strptime(val, "%Y%m%d %H:%M:%S:%f")
        except:
            return None

    valid["_ts"] = valid["Column1"].apply(parse_ts)
    valid = valid.dropna(subset=["_ts"]).sort_values("_ts")

    # Compute distance using Haversine
    def haversine(lat1, lon1, lat2, lon2):
        R = 6371000
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlam = math.radians(lon2 - lon1)
        a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    lats = valid["latitude"].values
    lons = valid["longitude"].values
    alts = valid["altitude"].values
    speeds = valid["tas"].values
    timestamps = valid["_ts"].values

    total_distance = 0
    max_alt = 0
    max_speed = 0
    takeoff_lat = lats[0] if len(lats) > 0 else 0
    takeoff_lon = lons[0] if len(lons) > 0 else 0
    takeoff_alt = alts[0] if len(alts) > 0 else 0

    for i in range(1, len(lats)):
        d = haversine(lats[i-1], lons[i-1], lats[i], lons[i])
        total_distance += d

    max_alt = float(np.nanmax(alts)) if len(alts) > 0 else 0
    # Filter speeds > 0 for max
    pos_speeds = speeds[(speeds > 0) & (speeds < 100)] if len(speeds) > 0 else speeds
    max_speed = float(np.nanmax(pos_speeds)) if len(pos_speeds) > 0 else 0
    avg_speed = float(np.nanmean(pos_speeds)) if len(pos_speeds) > 0 else 0

    duration_s = pd.Timedelta(timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) > 1 else 0

    # Takeoff detection: first point where altitude > 1m above home
    home_alt = float(alts[0]) if len(alts) > 0 else 0
    takeoff_idx = 0
    for i, a in enumerate(alts):
        if a > home_alt + 2:
            takeoff_idx = i
            break
    takeoff_lat = float(lats[takeoff_idx]) if len(lats) > 0 else 0
    takeoff_lon = float(lons[takeoff_idx]) if len(lons) > 0 else 0
    takeoff_alt = float(alts[takeoff_idx]) if len(alts) > 0 else 0

    # Landing detection: last sustained point near home altitude
    landing_idx = len(alts) - 1
    for i in range(len(alts) - 1, -1, -1):
        if alts[i] > home_alt + 2:
            landing_idx = min(i + 5, len(alts) - 1)
            break
    landing_lat = float(lats[landing_idx]) if len(lats) > 0 else 0
    landing_lon = float(lons[landing_idx]) if len(lons) > 0 else 0

    # Trajectory (downsampled for display)
    step = max(1, len(valid) // 200)
    trajectory = []
    for i in range(0, len(valid), step):
        r = valid.iloc[i]
        trajectory.append({
            "lat": float(r["latitude"]),
            "lon": float(r["longitude"]),
            "alt": float(r["altitude"]),
            "ts": str(r["_ts"]),
            "speed": float(r["tas"]),
        })

    return {
        "drone_id": "Telemetry Drone",
        "source": "Master_telmetry_june_2018.xlsx (42-Telemetry)",
        "rows": len(df),
        "valid_gps_rows": len(valid),
        "takeoff": {"lat": float(takeoff_lat), "lon": float(takeoff_lon), "alt": float(takeoff_alt)},
        "landing": {"lat": float(landing_lat), "lon": float(landing_lon)},
        "home_alt_m": round(home_alt, 1),
        "total_distance_m": round(total_distance, 1),
        "total_distance_km": round(total_distance / 1000, 2),
        "max_altitude_m": round(max_alt, 1),
        "max_speed_ms": round(max_speed, 2),
        "max_speed_kmh": round(max_speed * 3.6, 2),
        "avg_speed_ms": round(avg_speed, 2),
        "avg_speed_kmh": round(avg_speed * 3.6, 2),
        "duration_seconds": int(duration_s),
        "duration_formatted": f"{int(duration_s//60)}m {int(duration_s%60)}s",
        "fix_types": [int(x) for x in sorted(valid["fix_type"].unique())],
        "satellites_avg": round(float(valid["satellites_num"].mean()), 1),
        "first_fix": str(timestamps[0]) if len(timestamps) > 0 else "",
        "last_fix": str(timestamps[-1]) if len(timestamps) > 0 else "",
        "trajectory": trajectory,
    }


def parse_remote_gps():
    """Parse Master_remote_gps_june_2018.xlsx and return flight stats."""
    df = pd.read_excel(f"{DB_DIR}/Master_remote_gps_june_2018.xlsx", sheet_name="80-RemoteGPS")
    df.columns = [c.strip() for c in df.columns]

    # Filter rows that have actual data (not header rows)
    data = df.dropna(subset=["Column2"]).copy()
    data = data[data["Column2"] != "lon"].copy()

    for c in ["Column2", "Column3", "Column4", "Column5", "Column6", "Column7"]:
        data[c] = pd.to_numeric(data[c], errors="coerce")

    data = data.dropna(subset=["Column2", "Column3"])

    def parse_ts(val):
        try:
            val = str(val).strip()
            return datetime.strptime(val, "%Y%m%d %H:%M:%S:%f")
        except:
            return None

    data["_ts"] = data["Column1"].apply(parse_ts)
    data = data.dropna(subset=["_ts"]).sort_values("_ts")

    def haversine(lat1, lon1, lat2, lon2):
        R = 6371000
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlam = math.radians(lon2 - lon1)
        a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    lats = data["Column3"].values
    lons = data["Column2"].values
    alts = data["Column4"].values
    speeds = data["Column6"].values
    timestamps = data["_ts"].values

    total_distance = 0
    takeoff_lat = float(lats[0]) if len(lats) > 0 else 0
    takeoff_lon = float(lons[0]) if len(lons) > 0 else 0

    for i in range(1, len(lats)):
        d = haversine(lats[i-1], lons[i-1], lats[i], lons[i])
        total_distance += d

    max_alt = float(np.nanmax(alts)) if len(alts) > 0 else 0
    pos_speeds = speeds[(speeds > 0) & (speeds < 100)] if len(speeds) > 0 else speeds
    max_speed = float(np.nanmax(pos_speeds)) if len(pos_speeds) > 0 else 0
    avg_speed = float(np.nanmean(pos_speeds)) if len(pos_speeds) > 0 else 0

    duration_s = pd.Timedelta(timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) > 1 else 0

    # Takeoff detection: first point with altitude > home+2m
    home_alt = float(alts[0]) if len(alts) > 0 else 0
    takeoff_idx = 0
    for i, a in enumerate(alts):
        if a > home_alt + 2:
            takeoff_idx = i
            break
    takeoff_lat = float(lats[takeoff_idx]) if len(lats) > 0 else 0
    takeoff_lon = float(lons[takeoff_idx]) if len(lons) > 0 else 0
    takeoff_alt = float(alts[takeoff_idx]) if len(alts) > 0 else 0

    landing_idx = len(alts) - 1
    for i in range(len(alts) - 1, -1, -1):
        if alts[i] > home_alt + 2:
            landing_idx = min(i + 5, len(alts) - 1)
            break
    landing_lat = float(lats[landing_idx]) if len(lats) > 0 else 0
    landing_lon = float(lons[landing_idx]) if len(lons) > 0 else 0

    # Trajectory (downsampled)
    step = max(1, len(data) // 200)
    trajectory = []
    for i in range(0, len(data), step):
        r = data.iloc[i]
        trajectory.append({
            "lat": float(r["Column3"]),
            "lon": float(r["Column2"]),
            "alt": float(r["Column4"]),
            "ts": str(r["_ts"]),
            "speed": float(r["Column6"]) if pd.notna(r.get("Column6")) else 0,
        })

    return {
        "drone_id": "Remote GPS Drone",
        "source": "Master_remote_gps_june_2018.xlsx (80-RemoteGPS)",
        "rows": len(df),
        "valid_gps_rows": len(data),
        "takeoff": {"lat": takeoff_lat, "lon": takeoff_lon, "alt": float(alts[0]) if len(alts) > 0 else 0},
        "landing": {"lat": landing_lat, "lon": landing_lon},
        "home_alt_m": round(home_alt, 1),
        "total_distance_m": round(total_distance, 1),
        "total_distance_km": round(total_distance / 1000, 2),
        "max_altitude_m": round(max_alt, 1),
        "max_speed_ms": round(max_speed, 2),
        "max_speed_kmh": round(max_speed * 3.6, 2),
        "avg_speed_ms": round(avg_speed, 2),
        "avg_speed_kmh": round(avg_speed * 3.6, 2),
        "duration_seconds": int(duration_s),
        "duration_formatted": f"{int(duration_s//60)}m {int(duration_s%60)}s",
        "first_fix": str(timestamps[0]) if len(timestamps) > 0 else "",
        "last_fix": str(timestamps[-1]) if len(timestamps) > 0 else "",
        "trajectory": trajectory,
    }


if __name__ == "__main__":
    tel = parse_telemetry()
    rgps = parse_remote_gps()

    print("=" * 60)
    print("  FLIGHT LOG ANALYSIS")
    print("=" * 60)

    for label, data in [("Telemetry Drone", tel), ("Remote GPS Drone", rgps)]:
        print(f"\n--- {label} ---")
        print(f"  Rows: {data['rows']} (valid GPS: {data['valid_gps_rows']})")
        print(f"  Takeoff: ({data['takeoff']['lat']:.4f}, {data['takeoff']['lon']:.4f}), alt {data['takeoff']['alt']:.1f}m")
        print(f"  Distance: {data['total_distance_km']} km")
        print(f"  Max Alt: {data['max_altitude_m']} m")
        print(f"  Max Speed: {data['max_speed_kmh']} km/h")
        print(f"  Avg Speed: {data['avg_speed_kmh']} km/h")
        print(f"  Duration: {data['duration_formatted']}")
        print(f"  Trajectory points: {len(data['trajectory'])}")
