import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sqlite3
from datetime import datetime, timezone

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

from disk_image_analyzer import DiskImageAnalyzer, FlightLogParser, FlightReconstructor, FlightParseError

image_id = 16
_DISK_IMG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads", "disk_images")

# 1. Get image row + resolve path
img_row = dict(conn.execute("SELECT * FROM DiskImages WHERE id=?", (image_id,)).fetchone())
image_path = img_row["filepath"]
print(f"Image: {image_path}, exists: {os.path.isfile(image_path)}")

# 2. Get CSV candidates
candidates = [dict(r) for r in conn.execute(
    "SELECT id, partition_id, name, full_path, inode, extracted_path FROM DiskFileTree "
    "WHERE image_id=? AND entry_type='file' AND name LIKE '%.csv'",
    (image_id,)
).fetchall()]
print(f"CSV candidates: {len(candidates)}")

# 3. Extract all CSVs
now = datetime.now(timezone.utc).isoformat()
extracted_ids = []
for row in candidates:
    part_row = conn.execute(
        "SELECT start_sector FROM DiskPartitions WHERE id=?",
        (row["partition_id"],)
    ).fetchone() if row.get("partition_id") else None
    start_sector = part_row["start_sector"] if part_row else 0

    safe_name = row["name"].replace("/", "_").replace("\\", "_")
    dest_dir = os.path.join(_DISK_IMG_DIR, str(image_id), "extracted")
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = os.path.join(dest_dir, str(row["id"]) + "_" + safe_name)

    print(f"  [{len(extracted_ids)+1}/{len(candidates)}] {row['name']}...", end=" ")
    try:
        written = DiskImageAnalyzer.extract_file(image_path, start_sector, row["inode"], dest_path)
        from hashlib import md5 as _md5, sha256 as _sha256
        def _chash(p):
            m = _md5(); s = _sha256()
            with open(p,"rb") as f:
                for chunk in iter(lambda: f.read(65536), b""): m.update(chunk); s.update(chunk)
            return m.hexdigest(), s.hexdigest()
        md5v, sha256v = _chash(dest_path)
        conn.execute("UPDATE DiskFileTree SET extracted_path=?, md5=?, sha256=? WHERE id=?",
                     (dest_path, md5v, sha256v, row["id"]))
        conn.execute("INSERT INTO DiskExtractionLog (image_id,file_id,action,timestamp,md5,sha256) VALUES (?,?,?,?,?,?)",
                     (image_id, row["id"], "extract", now, md5v, sha256v))
        conn.commit()
        extracted_ids.append(row["id"])
        print(f"OK ({written} bytes)")
    except Exception as e:
        print(f"FAILED: {e}")

conn.close()

# 4. Parse and merge
print(f"\nParsing {len(extracted_ids)} extracted files...")
conn2 = sqlite3.connect(db_path)
conn2.row_factory = sqlite3.Row
detected = [dict(r) for r in conn2.execute(
    "SELECT id, name, full_path, extracted_path FROM DiskFileTree "
    "WHERE image_id=? AND entry_type='file' AND extracted_path IS NOT NULL AND name LIKE '%.csv'",
    (image_id,)
).fetchall()]

detected = DiskImageAnalyzer.detect_flight_logs(detected)
print(f"Flight log candidates: {len(detected)}")

all_rows = []
for row in detected:
    fpath = row.get("extracted_path")
    if not fpath or not os.path.isfile(fpath):
        continue
    fmt = FlightLogParser._detect_fmt(fpath)
    try:
        rows_data = FlightLogParser.parse(fpath, fmt)
        if rows_data:
            all_rows.extend(rows_data)
            print(f"  {row['name']}: {len(rows_data)} rows")
    except Exception as e:
        print(f"  {row['name']}: FAILED - {str(e)[:100]}")

print(f"\nTotal merged rows: {len(all_rows)}")

# 5. Reconstruct
recon = FlightReconstructor.reconstruct(all_rows)
takeoff = recon.get("takeoff") or {}
landing = recon.get("landing") or {}
stats = recon.get("stats") or {}
path = recon.get("path") or []

print(f"Takeoff: {takeoff}")
print(f"Landing: {landing}")
print(f"Stats: distance={stats.get('total_dist_m',0)}m, max_alt={stats.get('max_alt_m',0)}m, duration={stats.get('duration_s',0)}s")
print(f"Path points: {len(path)}")

# 6. Save merged CSV and JSON
xlsx_base = os.path.join(_DISK_IMG_DIR, str(image_id), "flight_exports")
os.makedirs(xlsx_base, exist_ok=True)

merged_csv = os.path.join(xlsx_base, "merged_flight_log.csv")
if all_rows:
    import csv as _csv
    with open(merged_csv, "w", newline="", encoding="utf-8") as f:
        writer = _csv.DictWriter(f, fieldnames=all_rows[0].keys())
        writer.writeheader()
        writer.writerows(all_rows)
    print(f"Merged CSV saved: {merged_csv} ({os.path.getsize(merged_csv)} bytes)")

result = {
    "telemetry_available": True,
    "merged_rows": len(all_rows),
    "num_files": len(detected),
    "metrics": {
        "takeoff": takeoff,
        "landing": landing,
        "home_alt_m": takeoff.get("alt_m", 0),
        "total_distance_m": stats.get("total_dist_m", 0),
        "total_distance_km": round((stats.get("total_dist_m", 0) or 0) / 1000, 3),
        "max_altitude_m": stats.get("max_alt_m", 0),
        "max_speed_ms": stats.get("max_speed_ms", 0),
        "max_speed_kmh": round((stats.get("max_speed_ms", 0) or 0) * 3.6, 1),
        "avg_speed_ms": stats.get("avg_speed_ms", 0),
        "avg_speed_kmh": round((stats.get("avg_speed_ms", 0) or 0) * 3.6, 1),
        "gps_fixes": len(all_rows),
        "coverage_km2": 0,
        "duration_s": stats.get("duration_s", 0),
    }
}

result_path = os.path.join(xlsx_base, "flight_log_merged_result.json")
with open(result_path, "w") as f:
    json.dump(result, f, indent=2, default=str)
print(f"\nResult saved: {result_path}")
print("\n--- DONE ---")
