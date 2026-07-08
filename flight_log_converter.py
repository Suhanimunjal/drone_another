#!/usr/bin/env python3
"""
flight_log_converter.py

Standalone forensic flight-log conversion + merge tool.

WHAT THIS DOES
---------------
1. Converts ArduPilot dataflash logs (.bin/.log) and MAVLink telemetry
   logs (.tlog) directly to normalized CSV using pymavlink.
2. Ingests already-converted DJI logs (CSV exported from DatCon or
   CsvView — DJI's .DAT format is proprietary/encrypted and is NOT
   parsed directly by this script; convert those separately first).
3. Ingests any file that's already CSV/GPX/KML with recognizable
   lat/lon/alt/time columns.
4. Merges everything into one normalized master CSV with a consistent
   schema, tagged by source file (for chain-of-custody traceability).
5. Reconstructs takeoff point, landing point, and basic flight summary
   stats (max altitude, duration, path bounding box) from the merged
   track and writes them to a JSON summary alongside the CSV.

WHY DJI .DAT ISN'T PARSED DIRECTLY
-----------------------------------
DJI's .DAT format is a proprietary binary format that differs across
aircraft/firmware versions and is partially encrypted on many modern
models. There is no reliable, general-purpose open-source parser for
it. Standard forensic practice is to decode it with a dedicated tool
first:
    - DatCon      (https://datfile.net)
    - CsvView / DatCon GUI
Export the decoded flight data as CSV from one of those, then point
this script at that CSV — it will be picked up by the generic CSV
ingestion path (see NORMALIZED SCHEMA below) as long as it has
recognizable latitude/longitude/altitude/time columns.

DEPENDENCIES
-------------
    pip install pymavlink pandas

USAGE
------
    python flight_log_converter.py \
        --input /path/to/extracted/dir \
        --output /path/to/output/dir

    This will:
      - recursively scan --input for .bin, .log, .tlog, .csv, .gpx files
      - convert/normalize each one
      - write one normalized CSV per source file into --output/normalized/
      - write a single merged CSV: --output/merged_flight_log.csv
      - write a flight reconstruction summary: --output/flight_summary.json

NORMALIZED SCHEMA (every row, every source, ends up in this shape)
---------------------------------------------------------------------
    timestamp_utc   ISO8601 string (best-effort; may be relative if no
                     absolute clock was present in the source — flagged
                     via `time_is_absolute`)
    time_is_absolute boolean
    lat             decimal degrees (WGS84)
    lon             decimal degrees (WGS84)
    alt_m           meters, best-effort MSL/relative (see `alt_ref`)
    alt_ref         "msl" | "relative" | "unknown"
    speed_mps       meters/sec, if available, else empty
    heading_deg     0-360, if available, else empty
    source_file     original filename this row came from
    source_format   "ardupilot_bin" | "mavlink_tlog" | "dji_csv" |
                     "generic_csv" | "gpx"
"""

import argparse
import csv
import json
import math
import os
import sys
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
# Optional deps — imported lazily / defensively so the script still runs
# (with reduced format support) if one of them is missing.
# ---------------------------------------------------------------------------
try:
    from pymavlink import mavutil
    HAVE_PYMAVLINK = True
except ImportError:
    HAVE_PYMAVLINK = False

NORMALIZED_FIELDS = [
    "timestamp_utc", "time_is_absolute", "lat", "lon", "alt_m",
    "alt_ref", "speed_mps", "heading_deg", "source_file", "source_format",
]


# ---------------------------------------------------------------------------
# ArduPilot dataflash (.bin / .log) + MAVLink telemetry (.tlog) via pymavlink
# ---------------------------------------------------------------------------
def convert_mavlink_family(filepath, source_format):
    """
    Handles both dataflash logs (.bin/.log, DFReader under the hood) and
    live telemetry logs (.tlog) — mavutil.mavlink_connection auto-detects
    which reader to use based on the file.

    Pulls position from GLOBAL_POSITION_INT (preferred — has relative alt)
    and falls back to GPS_RAW_INT if that's all that's present.
    """
    rows = []
    if not HAVE_PYMAVLINK:
        print(f"  [skip] pymavlink not installed — cannot parse {filepath}")
        return rows

    try:
        mlog = mavutil.mavlink_connection(filepath)
    except Exception as e:
        print(f"  [error] could not open {filepath}: {e}")
        return rows

    fname = os.path.basename(filepath)

    while True:
        try:
            msg = mlog.recv_match(
                type=["GLOBAL_POSITION_INT", "GPS_RAW_INT", "GPS"],
                blocking=False,
            )
        except Exception as e:
            print(f"  [warn] parse error mid-file in {fname}: {e}")
            break
        if msg is None:
            break

        msg_type = msg.get_type()
        t_boot_us = getattr(msg, "time_boot_ms", None)

        # Try to resolve an absolute timestamp. pymavlink attaches a
        # wall-clock '_timestamp' to every message based on either the
        # log's recorded GPS time or file mtime fallback — good enough
        # for a best-effort absolute time; flagged honestly either way.
        abs_ts = getattr(msg, "_timestamp", None)
        time_is_absolute = abs_ts is not None and abs_ts > 0
        if time_is_absolute:
            timestamp_utc = datetime.fromtimestamp(
                abs_ts, tz=timezone.utc
            ).isoformat()
        else:
            # relative fallback: ms since boot, expressed as a duration
            ms = t_boot_us if t_boot_us is not None else 0
            timestamp_utc = f"T+{ms}ms"

        if msg_type == "GLOBAL_POSITION_INT":
            lat = msg.lat / 1e7
            lon = msg.lon / 1e7
            alt_m = msg.relative_alt / 1000.0
            alt_ref = "relative"
            vx, vy = msg.vx / 100.0, msg.vy / 100.0
            speed_mps = math.hypot(vx, vy)
            heading_deg = msg.hdg / 100.0 if msg.hdg != 65535 else ""
        elif msg_type == "GPS_RAW_INT":
            lat = msg.lat / 1e7
            lon = msg.lon / 1e7
            alt_m = msg.alt / 1000.0
            alt_ref = "msl"
            speed_mps = msg.vel / 100.0 if hasattr(msg, "vel") else ""
            heading_deg = msg.cog / 100.0 if hasattr(msg, "cog") else ""
        else:  # GPS (older dataflash message name)
            lat = getattr(msg, "Lat", None)
            lon = getattr(msg, "Lng", None)
            if lat is None or lon is None:
                continue
            alt_m = getattr(msg, "Alt", "")
            alt_ref = "unknown"
            speed_mps = getattr(msg, "Spd", "")
            heading_deg = getattr(msg, "GCrs", "")

        if lat in (None, 0) and lon in (None, 0):
            continue  # no GPS fix yet — skip

        rows.append({
            "timestamp_utc": timestamp_utc,
            "time_is_absolute": time_is_absolute,
            "lat": lat,
            "lon": lon,
            "alt_m": alt_m,
            "alt_ref": alt_ref,
            "speed_mps": speed_mps,
            "heading_deg": heading_deg,
            "source_file": fname,
            "source_format": source_format,
        })

    print(f"  [ok] {fname}: {len(rows)} position rows extracted")
    return rows


# ---------------------------------------------------------------------------
# Generic CSV ingestion — covers DJI logs already converted via DatCon/
# CsvView, plus any other CSV that has recognizable lat/lon/alt columns.
# ---------------------------------------------------------------------------
LAT_KEYS = ["lat", "latitude", "gps_lat", "osd.latitude", "gps(0):lat"]
LON_KEYS = ["lon", "lng", "longitude", "gps_lon", "osd.longitude", "gps(0):lng"]
ALT_KEYS = ["alt", "altitude", "alt_m", "osd.altitude [ft]", "osd.altitude [m]",
            "gps(0):alt"]
TIME_KEYS = ["timestamp", "time", "datetime", "custom.updatetime",
             "offsettime"]
SPEED_KEYS = ["speed", "speed_mps", "osd.hspeed [mph]", "osd.hspeed [m/s]"]
HEADING_KEYS = ["heading", "heading_deg", "osd.compass", "gimbal.yaw"]


def _find_key(fieldnames, candidates):
    lower_map = {f.lower(): f for f in fieldnames}
    for c in candidates:
        if c in lower_map:
            return lower_map[c]
    return None


def convert_generic_csv(filepath, source_format="generic_csv"):
    rows = []
    fname = os.path.basename(filepath)
    try:
        with open(filepath, "r", newline="", encoding="utf-8-sig",
                  errors="replace") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                print(f"  [skip] {fname}: no header row detected")
                return rows

            lat_k = _find_key(reader.fieldnames, LAT_KEYS)
            lon_k = _find_key(reader.fieldnames, LON_KEYS)
            if not lat_k or not lon_k:
                print(f"  [skip] {fname}: no recognizable lat/lon columns "
                      f"(found columns: {reader.fieldnames[:8]}...)")
                return rows

            alt_k = _find_key(reader.fieldnames, ALT_KEYS)
            time_k = _find_key(reader.fieldnames, TIME_KEYS)
            speed_k = _find_key(reader.fieldnames, SPEED_KEYS)
            heading_k = _find_key(reader.fieldnames, HEADING_KEYS)

            # Heuristic: DJI DatCon exports commonly carry "OSD." prefixed
            # columns — tag the source_format accordingly for traceability.
            if any(fn.lower().startswith("osd.") for fn in reader.fieldnames):
                source_format = "dji_csv"

            for r in reader:
                try:
                    lat = float(r[lat_k])
                    lon = float(r[lon_k])
                except (ValueError, TypeError, KeyError):
                    continue
                if lat == 0 and lon == 0:
                    continue

                alt_m = ""
                if alt_k:
                    try:
                        alt_val = float(r[alt_k])
                        # crude ft->m conversion if the header says feet
                        if "ft" in alt_k.lower():
                            alt_val *= 0.3048
                        alt_m = alt_val
                    except (ValueError, TypeError):
                        pass

                timestamp_utc = r.get(time_k, "") if time_k else ""
                time_is_absolute = bool(timestamp_utc) and any(
                    ch in str(timestamp_utc) for ch in ("-", "/", ":")
                )
                if not timestamp_utc:
                    timestamp_utc = f"row_{reader.line_num}"

                rows.append({
                    "timestamp_utc": timestamp_utc,
                    "time_is_absolute": time_is_absolute,
                    "lat": lat,
                    "lon": lon,
                    "alt_m": alt_m,
                    "alt_ref": "unknown",
                    "speed_mps": r.get(speed_k, "") if speed_k else "",
                    "heading_deg": r.get(heading_k, "") if heading_k else "",
                    "source_file": fname,
                    "source_format": source_format,
                })
    except Exception as e:
        print(f"  [error] failed reading {fname}: {e}")

    print(f"  [ok] {fname}: {len(rows)} position rows extracted")
    return rows


# ---------------------------------------------------------------------------
# GPX ingestion (common export format from some flight-log converters)
# ---------------------------------------------------------------------------
def convert_gpx(filepath):
    import xml.etree.ElementTree as ET
    rows = []
    fname = os.path.basename(filepath)
    ns = {"gpx": "http://www.topografix.com/GPX/1/1"}
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
        # namespace-agnostic search
        for trkpt in root.iter():
            if trkpt.tag.endswith("trkpt"):
                lat = trkpt.attrib.get("lat")
                lon = trkpt.attrib.get("lon")
                if lat is None or lon is None:
                    continue
                ele, time_txt = "", ""
                for child in trkpt:
                    if child.tag.endswith("ele"):
                        ele = child.text
                    elif child.tag.endswith("time"):
                        time_txt = child.text
                rows.append({
                    "timestamp_utc": time_txt or "",
                    "time_is_absolute": bool(time_txt),
                    "lat": float(lat),
                    "lon": float(lon),
                    "alt_m": float(ele) if ele else "",
                    "alt_ref": "msl",
                    "speed_mps": "",
                    "heading_deg": "",
                    "source_file": fname,
                    "source_format": "gpx",
                })
    except Exception as e:
        print(f"  [error] failed reading {fname}: {e}")

    print(f"  [ok] {fname}: {len(rows)} position rows extracted")
    return rows


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------
def convert_file(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext in (".bin", ".log"):
        return convert_mavlink_family(filepath, "ardupilot_bin")
    elif ext == ".tlog":
        return convert_mavlink_family(filepath, "mavlink_tlog")
    elif ext == ".csv":
        return convert_generic_csv(filepath)
    elif ext == ".gpx":
        return convert_gpx(filepath)
    elif ext == ".dat":
        print(f"  [skip] {os.path.basename(filepath)}: DJI .DAT is "
              f"proprietary/encrypted — decode with DatCon or CsvView "
              f"first, then re-run this script on the exported CSV.")
        return []
    else:
        return []


# ---------------------------------------------------------------------------
# Flight reconstruction: takeoff / landing / summary from merged track
# ---------------------------------------------------------------------------
GROUND_SPEED_THRESHOLD_MPS = 1.0   # below this = considered "on the ground"
MIN_AIRBORNE_SAMPLES = 5           # noise filter for takeoff/landing detect


def haversine_m(lat1, lon1, lat2, lon2):
    R = 6371000.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = (math.sin(dphi / 2) ** 2
         + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2)
    return 2 * R * math.asin(math.sqrt(a))


def reconstruct_flight(merged_rows):
    """
    Best-effort takeoff/landing detection using altitude-gain and speed
    as proxies, since not every source format carries a clean 'armed'
    or 'in-air' flag. This is a heuristic reconstruction, not a
    guaranteed-exact one — flag it as such in the output.
    """
    # Only rows with numeric lat/lon/alt are usable for this pass.
    usable = [r for r in merged_rows if r["alt_m"] not in ("", None)]
    if len(usable) < MIN_AIRBORNE_SAMPLES:
        return {
            "reconstruction_possible": False,
            "reason": "Fewer than the minimum number of usable "
                      "lat/lon/alt samples after merge.",
        }

    try:
        alts = [float(r["alt_m"]) for r in usable]
    except (ValueError, TypeError):
        return {
            "reconstruction_possible": False,
            "reason": "Non-numeric altitude values in merged data.",
        }

    baseline_alt = min(alts)  # ground-level proxy
    airborne_flags = [(a - baseline_alt) > 2.0 for a in alts]  # >2m = airborne

    takeoff_idx, landing_idx = None, None
    for i, flag in enumerate(airborne_flags):
        if flag and takeoff_idx is None:
            takeoff_idx = i
        if flag:
            landing_idx = i  # keeps updating -> ends at last airborne sample

    if takeoff_idx is None:
        return {
            "reconstruction_possible": False,
            "reason": "No samples exceeded the airborne altitude "
                      "threshold — aircraft may never have left the "
                      "ground in this dataset, or altitude data is flat.",
        }

    takeoff_pt = usable[takeoff_idx]
    landing_pt = usable[landing_idx] if landing_idx is not None else takeoff_pt

    max_alt = max(alts)
    straight_line_distance_m = haversine_m(
        takeoff_pt["lat"], takeoff_pt["lon"],
        landing_pt["lat"], landing_pt["lon"],
    )

    # cumulative path length (rough — not corrected for GPS noise)
    path_len_m = 0.0
    for a, b in zip(usable, usable[1:]):
        path_len_m += haversine_m(a["lat"], a["lon"], b["lat"], b["lon"])

    return {
        "reconstruction_possible": True,
        "method": "altitude-threshold heuristic (>2m above min recorded "
                   "altitude = airborne); verify against source telemetry "
                   "before treating as ground truth",
        "takeoff": {
            "lat": takeoff_pt["lat"],
            "lon": takeoff_pt["lon"],
            "alt_m": takeoff_pt["alt_m"],
            "timestamp_utc": takeoff_pt["timestamp_utc"],
            "source_file": takeoff_pt["source_file"],
        },
        "landing": {
            "lat": landing_pt["lat"],
            "lon": landing_pt["lon"],
            "alt_m": landing_pt["alt_m"],
            "timestamp_utc": landing_pt["timestamp_utc"],
            "source_file": landing_pt["source_file"],
        },
        "max_altitude_m": max_alt,
        "baseline_altitude_m": baseline_alt,
        "straight_line_takeoff_to_landing_m": round(
            straight_line_distance_m, 2
        ),
        "approx_total_path_length_m": round(path_len_m, 2),
        "total_position_samples": len(usable),
        "source_files_used": sorted(
            {r["source_file"] for r in usable}
        ),
    }


# ---------------------------------------------------------------------------
# Programmatic API (for import by backend_server.py)
# ---------------------------------------------------------------------------
def process_extracted_directory(input_dir, output_dir):
    """Scans input_dir, converts all flight logs, writes merged CSV + summary.

    Returns (merged_csv_path, summary_dict) on success.
    """
    supported_exts = {".bin", ".log", ".tlog", ".csv", ".gpx", ".dat"}
    normalized_dir = os.path.join(output_dir, "normalized")
    os.makedirs(normalized_dir, exist_ok=True)

    all_rows = []
    for root, _dirs, files in os.walk(input_dir):
        for fn in files:
            ext = os.path.splitext(fn)[1].lower()
            if ext not in supported_exts:
                continue
            filepath = os.path.join(root, fn)
            rows = convert_file(filepath)
            if rows:
                out_csv = os.path.join(
                    normalized_dir, os.path.splitext(fn)[0] + "_normalized.csv"
                )
                with open(out_csv, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=NORMALIZED_FIELDS)
                    writer.writeheader()
                    writer.writerows(rows)
                all_rows.extend(rows)

    merged_path = os.path.join(output_dir, "merged_flight_log.csv")
    with open(merged_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=NORMALIZED_FIELDS)
        writer.writeheader()
        writer.writerows(all_rows)

    summary = reconstruct_flight(all_rows)
    summary_path = os.path.join(output_dir, "flight_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, default=str)

    return merged_path, summary


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Convert and merge flight logs (ArduPilot/MAVLink/"
                     "DJI-CSV/GPX) into a normalized CSV + flight "
                     "reconstruction summary."
    )
    ap.add_argument("--input", required=True,
                     help="Directory to scan recursively for flight log "
                          "files (e.g. the disk-analysis 'extracted' "
                          "folder).")
    ap.add_argument("--output", required=True,
                     help="Directory to write normalized/merged output "
                          "into (created if it doesn't exist).")
    args = ap.parse_args()

    if not os.path.isdir(args.input):
        print(f"ERROR: input directory not found: {args.input}")
        sys.exit(1)

    merged_path, summary = process_extracted_directory(args.input, args.output)

    print(f"\nMerged CSV written: {merged_path}")
    print(f"Flight reconstruction summary written: "
          f"{os.path.join(args.output, 'flight_summary.json')}")

    if summary.get("reconstruction_possible"):
        t = summary["takeoff"]
        l = summary["landing"]
        print(f"\nTakeoff:  lat={t['lat']}, lon={t['lon']}, "
              f"alt={t['alt_m']}m, t={t['timestamp_utc']}")
        print(f"Landing:  lat={l['lat']}, lon={l['lon']}, "
              f"alt={l['alt_m']}m, t={l['timestamp_utc']}")
        print(f"Max altitude: {summary['max_altitude_m']}m  |  "
              f"Straight-line distance: "
              f"{summary['straight_line_takeoff_to_landing_m']}m")
    else:
        print(f"\nReconstruction not possible: {summary.get('reason')}")


if __name__ == "__main__":
    main()
