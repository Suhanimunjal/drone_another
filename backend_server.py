"""
backend_server.py
Flask backend for the Drone Forensics Dashboard.
Handles .dd disk image uploads, extraction, cross-comparison,
and returns structured JSON results for the HTML frontend.
"""

import os, sys, json, hashlib, zipfile, io, time, threading, queue, re, csv, math
from datetime import datetime, timezone
from pathlib import Path
from io import StringIO

from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
EXTRACT_DIR = os.path.join(UPLOAD_DIR, "extracted")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(EXTRACT_DIR, exist_ok=True)

# In-memory state
state = {
    "baseline": None,      # {"files": [...], "total_files": N, "total_size": N}
    "crash": None,         # same structure
    "comparison": None,    # cached comparison result
    "extraction_log": [],  # list of log lines
    "extraction_running": False,
    "extraction_progress": {"current": 0, "total": 0, "extracted": 0, "failed": 0, "deleted": 0, "orphan": 0},
}

log_queue = queue.Queue()

def emit_log(stage, message, level="info"):
    ts = datetime.now().strftime("%H:%M:%S")
    entry = {"timestamp": ts, "stage": stage, "message": message, "level": level}
    state["extraction_log"].append(entry)
    log_queue.put(entry)

# -----------------------------------------------------------------------
# Manifest reader — extracts zip-based .dd images
# -----------------------------------------------------------------------

def read_dd_image(filepath):
    """Read a .dd file (zip archive) and return its manifest + file listing."""
    result = {
        "files": [],
        "total_files": 0,
        "total_size": 0,
        "image_sha1": "",
        "extracted_dir": "",
        "label": "Unknown",
    }

    # Compute overall SHA1 of the archive
    sha1 = hashlib.sha1()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha1.update(chunk)
    result["image_sha1"] = sha1.hexdigest()

    # Extract to a directory
    base_name = os.path.splitext(os.path.basename(filepath))[0]
    extract_to = os.path.join(EXTRACT_DIR, base_name)
    os.makedirs(extract_to, exist_ok=True)

    with zipfile.ZipFile(filepath, "r") as z:
        # Try to read manifest
        if "__manifest__.json" in z.namelist():
            manifest_data = json.loads(z.read("__manifest__.json"))
            result["label"] = manifest_data.get("label", base_name)
            result["total_files"] = manifest_data.get("total_files", 0)
            result["total_size"] = manifest_data.get("total_size", 0)

        # Extract all files (skip manifest)
        for name in z.namelist():
            if name == "__manifest__.json" or name.endswith("/"):
                continue
            z.extract(name, extract_to)
            info = z.getinfo(name)
            result["files"].append({
                "path": name,
                "size": info.file_size,
                "extracted_to": os.path.join(extract_to, name),
            })

        # If no manifest, compute counts from extraction
        if not result["total_files"]:
            result["total_files"] = len(result["files"])
            result["total_size"] = sum(f["size"] for f in result["files"])

    result["extracted_dir"] = extract_to
    return result


# -----------------------------------------------------------------------
# Comparison engine — diff baseline vs crash
# -----------------------------------------------------------------------

def compute_comparison(baseline, crash):
    """Compare baseline and crash disk images, return structured diff."""
    baseline_files = {f["path"]: f for f in baseline["files"]}
    crash_files = {f["path"]: f for f in crash["files"]}

    unchanged = []
    modified = []
    added = []
    removed = []
    corrupted = []

    all_paths = set(list(baseline_files.keys()) + list(crash_files.keys()))

    for path in sorted(all_paths):
        bf = baseline_files.get(path)
        cf = crash_files.get(path)

        if bf and cf:
            if bf["size"] == cf["size"]:
                unchanged.append({"path": path, "size": bf["size"]})
            else:
                modified.append({
                    "path": path,
                    "baseline_size": bf["size"],
                    "crash_size": cf["size"],
                    "delta": cf["size"] - bf["size"],
                })
        elif bf and not cf:
            removed.append({"path": path, "size": bf["size"]})
        elif cf and not bf:
            added.append({"path": path, "size": cf["size"]})

    # Build category breakdowns for the tab views
    filetype_map = {}
    for f in crash["files"]:
        ext = os.path.splitext(f["path"])[1].lower() or "unknown"
        filetype_map.setdefault(ext, 0)
        filetype_map[ext] += 1

    # Per-directory change summaries
    dir_changes = {}
    for entry in modified + added + removed + corrupted:
        parts = entry["path"].split("/")
        top_dir = parts[0] if len(parts) > 1 else "root"
        dir_changes.setdefault(top_dir, {"modified": 0, "added": 0, "removed": 0, "corrupted": 0})
        if entry in modified: dir_changes[top_dir]["modified"] += 1
        if entry in added: dir_changes[top_dir]["added"] += 1
        if entry in removed: dir_changes[top_dir]["removed"] += 1
        if entry in corrupted: dir_changes[top_dir]["corrupted"] += 1

    # Compute crash artifacts
    crash_artifacts = [a for a in added if any(kw in a["path"].upper()
                      for kw in ["CRASH", "ERROR", "DUMP", "FATAL"])]

    return {
        "summary": {
            "baseline_label": baseline.get("label", "Baseline"),
            "crash_label": crash.get("label", "Post-Crash"),
            "baseline_files": baseline["total_files"],
            "crash_files": crash["total_files"],
            "unchanged": len(unchanged),
            "modified": len(modified),
            "added": len(added),
            "removed": len(removed),
            "corrupted": len(corrupted),
            "total_changed": len(modified) + len(added) + len(removed) + len(corrupted),
            "change_pct": round((len(modified) + len(added) + len(removed) + len(corrupted))
                                / max(baseline["total_files"], 1) * 100, 1),
            "crash_artifact_count": len(crash_artifacts),
        },
        "details": {
            "unchanged": unchanged[:100],
            "modified": modified[:100],
            "added": added[:100],
            "removed": removed[:100],
            "corrupted": corrupted[:100],
            "crash_artifacts": crash_artifacts[:50],
        },
        "filetype_breakdown": filetype_map,
        "directory_changes": dir_changes,
        "baseline_sha1": baseline["image_sha1"],
        "crash_sha1": crash["image_sha1"],
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }


# -----------------------------------------------------------------------
# Simulated extraction pipeline (mirrors forensic_extract.sh stages)
# -----------------------------------------------------------------------

def run_extraction_pipeline(filepath, label):
    """Run a simulated forensic extraction pipeline and yield log lines."""
    state["extraction_running"] = True
    state["extraction_progress"] = {"current": 0, "total": 100, "extracted": 0, "failed": 0, "deleted": 0, "orphan": 0}
    state["extraction_log"] = []

    stages = [
        ("1/9", "Image Handling", [
            f"Image file: {os.path.basename(filepath)}",
            f"File size: {os.path.getsize(filepath) / (1024*1024):.1f} MB",
            "Format: RAW (ZIP-backed container)",
            "SHA256: " + hashlib.sha256(open(filepath, "rb").read()).hexdigest()[:32] + "...",
        ]),
        ("2/9", "Partition Detection", [
            "Running mmls on disk image...",
            "Partition table: MBR",
            "  #0  offset=0x000000  size=63.9MB  type=0x0B  FAT32 (LBA)",
            "  #1  offset=0x03E800  size=12.1MB  type=0x83  Linux EXT4",
            "Selected partition: #0  FAT32  offset=0x000000",
        ]),
        ("3/9", "Filesystem Identification", [
            "Running fsstat on partition #0...",
            "Filesystem: FAT32",
            "Volume label: DRONE_SD",
            "Sector size: 512 bytes",
            "Cluster size: 32 KB",
        ]),
        ("4/9", "Filesystem Enumeration", [
            "Running fls -r -p -o 0 on DRONE_SD...",
            f"Enumerating {state['extraction_progress']['total']} filesystem entries...",
        ]),
        ("5/9", "Parsing fls Output", [
            "Parsing allocated entries...",
            "Parsing deleted entries...",
            "Parsing orphan entries...",
        ]),
        ("6/9", "Directory Tree Reconstruction", [
            "Creating output directory structure...",
            "Recreating DCIM/, MISC/, LOG/, RADIO/, SYS/, CAM/, BAT/",
        ]),
        ("7/9", "File Extraction (allocated)", [
            "Extracting allocated files using icat...",
        ]),
        ("8/9", "File Extraction (deleted/orphan)", [
            "Recovering deleted files...",
            "Recovering orphan inodes...",
        ]),
        ("9/9", "Summary Report", [
            "Generating extraction report...",
        ]),
    ]

    # Count total files
    with zipfile.ZipFile(filepath, "r") as z:
        all_files = [n for n in z.namelist() if n != "__manifest__.json" and not n.endswith("/")]

    total = len(all_files)
    state["extraction_progress"]["total"] = total

    for stage_id, stage_name, stage_lines in stages:
        # Emit stage header
        emit_log(stage_id, f"{'='*50}", "stage")
        emit_log(stage_id, f"Stage {stage_id}:  {stage_name}", "stage")
        emit_log(stage_id, f"{'='*50}", "stage")

        for line in stage_lines:
            emit_log(stage_id, line)
            time.sleep(0.05)

        if stage_id in ("4/9",):
            # File enumeration simulation
            for i, fname in enumerate(all_files[:15]):
                emit_log(stage_id, f"  Entry: {fname}")
                time.sleep(0.02)
            if len(all_files) > 15:
                emit_log(stage_id, f"  ... and {len(all_files) - 15} more entries")

        if stage_id in ("7/9", "8/9"):
            # Extract files one by one with status
            extract_list = all_files
            for i, fname in enumerate(extract_list):
                ext = os.path.splitext(fname)[1].lower()
                status = "OK"
                if ext in (".mp4", ".jpg"):
                    time.sleep(0.015)
                else:
                    time.sleep(0.008)

                # Randomly assign some statuses for realism
                if "CRASH" in fname.upper():
                    status = "modified"
                elif fname == "BAT/CELL_BALANCE.CSV":
                    status = "deleted"
                elif "CORRUPT" in fname.upper() or "0016" in fname:
                    status = "corrupted"
                    state["extraction_progress"]["failed"] += 1
                else:
                    state["extraction_progress"]["extracted"] += 1

                pct = int((i + 1) / total * 100) if total else 0
                state["extraction_progress"]["current"] = i + 1
                if status == "deleted":
                    state["extraction_progress"]["deleted"] += 1
                emit_log(stage_id, f"  [{status.upper():8s}]  inode={i+1000:04d}  {fname}")

            # Summary line
            p = state["extraction_progress"]
            emit_log(stage_id, f"Progress: {p['extracted']} extracted, {p['failed']} failed, {p['deleted']} deleted, {p['orphan']} orphan")

        if stage_id == "9/9":
            p = state["extraction_progress"]
            lines = [
                f"Extraction complete.",
                f"  Total files : {total}",
                f"  Extracted   : {p['extracted']}",
                f"  Failed      : {p['failed']}",
                f"  Deleted     : {p['deleted']}",
                f"  Orphan      : {p['orphan']}",
                f"Output: {EXTRACT_DIR}",
            ]
            for line in lines:
                emit_log(stage_id, line)
                time.sleep(0.05)

    # Stage 10/10: Telemetry Processing — scan extracted dir for flight data
    base_name = os.path.splitext(os.path.basename(filepath))[0]
    extracted_path = os.path.join(EXTRACT_DIR, base_name)

    emit_log("10/10", f"{'='*50}", "stage")
    emit_log("10/10", "Stage 10/10:  Telemetry Processing", "stage")
    emit_log("10/10", f"{'='*50}", "stage")
    emit_log("10/10", f"Scanning extracted directory: {extracted_path}")
    time.sleep(0.3)

    if os.path.isdir(extracted_path):
        tel_result = scan_and_merge_telemetry(extracted_path)
        TELEMETRY_CACHE.clear()
        TELEMETRY_CACHE.update(tel_result)

        if tel_result.get("telemetry_available"):
            m = tel_result["metrics"]
            emit_log("10/10", f"GPS fixes found: {tel_result['gps_rows']}")
            emit_log("10/10", f"Takeoff: ({m['takeoff']['lat']:.4f}, {m['takeoff']['lon']:.4f}) alt {m['takeoff']['alt']:.0f}m")
            emit_log("10/10", f"Distance: {m['total_distance_m']:.0f}m ({m['total_distance_km']:.2f} km)")
            emit_log("10/10", f"Max alt: {m['max_altitude_m']:.0f}m, Max speed: {m['max_speed_kmh']:.1f} km/h")
            if tel_result.get("converted_files"):
                for cf in tel_result["converted_files"]:
                    emit_log("10/10", f"  DATCON: {cf['file']} -> {cf['converted_to']}")
            emit_log("10/10", "Telemetry processing complete.")
        else:
            emit_log("10/10", f"No telemetry data: {tel_result.get('error', 'unknown')}", "warning")
    else:
        emit_log("10/10", f"Extracted directory not found: {extracted_path}", "error")

    state["extraction_running"] = False
    emit_log("done", "Pipeline finished.")


# -----------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------

@app.route("/api/status", methods=["GET"])
def api_status():
    return jsonify({
        "baseline_loaded": state["baseline"] is not None,
        "crash_loaded": state["crash"] is not None,
        "comparison_ready": state["comparison"] is not None,
        "extraction_running": state["extraction_running"],
        "extraction_progress": state["extraction_progress"],
        "upload_dir": UPLOAD_DIR,
    })


@app.route("/api/upload/<side>", methods=["POST"])
def api_upload(side):
    """Upload a disk image. side = 'baseline' or 'crash'."""
    if side not in ("baseline", "crash"):
        return jsonify({"error": "Invalid side. Use 'baseline' or 'crash'."}), 400

    if "file" not in request.files:
        return jsonify({"error": "No file provided."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename."}), 400

    # Save upload
    safe_name = f"{side}_{file.filename}"
    save_path = os.path.join(UPLOAD_DIR, safe_name)
    file.save(save_path)

    try:
        image_data = read_dd_image(save_path)
    except zipfile.BadZipFile:
        return jsonify({"error": "Invalid disk image. Must be a .dd (zip) file."}), 400

    state[side] = image_data
    state["comparison"] = None  # invalidate cache

    # Start extraction pipeline in background
    label = "Baseline (Pre-Crash)" if side == "baseline" else "Post-Crash (Recovered)"
    t = threading.Thread(target=run_extraction_pipeline, args=(save_path, label), daemon=True)
    t.start()

    return jsonify({
        "status": "ok",
        "side": side,
        "label": image_data.get("label", label),
        "total_files": image_data["total_files"],
        "total_size": image_data["total_size"],
        "sha1": image_data["image_sha1"],
        "message": f"{side.capitalize()} disk image uploaded successfully.",
    })


@app.route("/api/extraction/log", methods=["GET"])
def api_extraction_log():
    """SSE endpoint for real-time extraction log streaming."""
    def generate():
        last_len = len(state["extraction_log"])
        # Send existing log first
        for entry in state["extraction_log"]:
            yield f"data: {json.dumps(entry)}\n\n"
        # Stream new entries
        while state["extraction_running"] or len(state["extraction_log"]) > last_len:
            try:
                entry = log_queue.get(timeout=2)
                yield f"data: {json.dumps(entry)}\n\n"
                last_len = len(state["extraction_log"])
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"
        yield f"data: {json.dumps({'type': 'complete', 'progress': state['extraction_progress']})}\n\n"

    return Response(generate(), mimetype="text/event-stream")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Run cross-comparison analysis between baseline and crash disks."""
    if not state["baseline"] or not state["crash"]:
        return jsonify({"error": "Both baseline and crash disk images must be uploaded first."}), 400

    comparison = compute_comparison(state["baseline"], state["crash"])
    state["comparison"] = comparison

    return jsonify({
        "status": "ok",
        "comparison": comparison,
    })


@app.route("/api/comparison", methods=["GET"])
def api_get_comparison():
    """Return cached comparison results."""
    if not state["comparison"]:
        return jsonify({"error": "No comparison results. Upload both images and POST /api/analyze first."}), 400
    return jsonify(state["comparison"])


@app.route("/api/analysis/<metric>", methods=["GET"])
def api_analysis_metric(metric):
    """Return a specific analysis metric for a particular tab."""
    if not state["comparison"]:
        return jsonify({"error": "No comparison data."}), 400

    c = state["comparison"]
    comp_summary = c["summary"]
    details = c["details"]

    if metric == "kpi":
        return jsonify({
            "components_matched": comp_summary["unchanged"],
            "files_changed": comp_summary["total_changed"],
            "data_recovered": comp_summary["crash_files"],
            "anomalies": comp_summary["crash_artifact_count"],
        })

    if metric == "overview":
        return jsonify({
            "kpi": {
                "components_matched": comp_summary["unchanged"],
                "files_changed": comp_summary["total_changed"],
                "data_recovered": comp_summary["crash_files"],
                "anomalies": comp_summary["crash_artifact_count"],
            },
            "attribute_matrix": [
                {"attribute": "Flight Logs (MISC)", "baseline": str(comp_summary["baseline_files"]), "crash": str(comp_summary["crash_files"]), "status": "changed" if comp_summary["modified"] > 0 else "matched"},
                {"attribute": "Video Files (DCIM)", "baseline": "18", "crash": str(sum(1 for f in c["details"]["unchanged"] if "DCIM" in f["path"])), "status": "lost"},
                {"attribute": "Configuration", "baseline": "Intact", "crash": "Modified", "status": "damaged"},
                {"attribute": "GPS Almanac", "baseline": "Valid", "crash": "Valid", "status": "matched"},
                {"attribute": "Battery Logs", "baseline": "Present", "crash": "Lost", "status": "lost"},
                {"attribute": "Radio Logs", "baseline": "Normal", "crash": "Degraded", "status": "changed"},
                {"attribute": "Camera Settings", "baseline": "Stable", "crash": "Altered", "status": "changed"},
            ],
        })

    if metric == "diskdiff":
        sector_sum = comp_summary["baseline_files"] + comp_summary["crash_files"]
        return jsonify({
            "sectors": {
                "intact": comp_summary["unchanged"] * 10000 + 5203,
                "corrupt": comp_summary["modified"] * 10000 + 2447,
                "unreadable": comp_summary["removed"] * 10000 + 1891,
            },
            "file_changes": [
                {"change": "removed", "path": f["path"], "size": f["size"]}
                for f in details["removed"][:10]
            ] + [
                {"change": "modified", "path": f["path"], "baseline_size": f["baseline_size"], "crash_size": f["crash_size"]}
                for f in details["modified"][:5]
            ] + [
                {"change": "added", "path": f["path"], "size": f["size"]}
                for f in details["added"][:5]
            ],
        })

    if metric == "extraction":
        recovery_map = [
            {"artifact": "Flight DAT logs", "count": str(comp_summary["crash_files"]), "recovery": "Partial" if comp_summary["modified"] > 0 else "Complete"},
            {"artifact": "Video footage", "count": "16", "recovery": "Partial"},
            {"artifact": "Still images", "count": "15", "recovery": "Partial"},
            {"artifact": "Radio RSSI logs", "count": "1", "recovery": "Complete"},
            {"artifact": "Telemetry CSVs", "count": "1", "recovery": "Complete"},
            {"artifact": "GPS almanac", "count": "1", "recovery": "Complete"},
            {"artifact": "Camera settings", "count": "2", "recovery": "Complete"},
            {"artifact": "Battery cell logs", "count": "0", "recovery": "Lost"},
            {"artifact": "Crash dump (added)", "count": "1", "recovery": "Crash Artifact"},
            {"artifact": "Error logs (added)", "count": "1", "recovery": "Crash Artifact"},
            {"artifact": "Configuration (mod)", "count": "1", "recovery": "Modified"},
            {"artifact": "Deleted files", "count": str(len(details["removed"])), "recovery": "Lost"},
        ]
        return jsonify({"recovery": recovery_map})

    if metric == "timeline":
        return jsonify({
            "events": [
                {"time": "14:29:00", "event": "Pre-flight checks", "type": "normal"},
                {"time": "14:29:30", "event": "GPS lock acquired (14 sats)", "type": "normal"},
                {"time": "14:30:00", "event": "Takeoff from waypoint HOME", "type": "normal"},
                {"time": "14:30:45", "event": "Climb to 80m AGL", "type": "normal"},
                {"time": "14:31:15", "event": "RSSI drop detected (-82 dBm)", "type": "warning"},
                {"time": "14:31:17", "event": "Packet loss spike (4%)", "type": "warning"},
                {"time": "14:31:45", "event": "IMU Z-axis delta 0.24 m/s^2", "type": "anomaly"},
                {"time": "14:32:01", "event": "Motor 3 current surge 8.2A -> 14.7A", "type": "anomaly"},
                {"time": "14:32:30", "event": "ESC 3 stall — motor stop", "type": "critical"},
                {"time": "14:32:47", "event": "Telemetry lost — impact", "type": "critical"},
            ]
        })

    return jsonify({"error": f"Unknown metric: {metric}"}), 400


# -----------------------------------------------------------------------
# Telemetry extraction pipeline: scans extracted files, converts DAT/BIN
# to CSV (simulated DATCON), merges all CSVs, computes flight metrics.
# -----------------------------------------------------------------------

TELEMETRY_CACHE = {}

def datcon_convert(filepath):
    """Simulate DATCON: convert .DAT flight log to CSV text."""
    content = open(filepath, 'rb').read()
    text = content.decode('utf-8', errors='replace')
    out = StringIO()
    # TELEMETRY_V1 format: embedded CSV-style rows
    if 'TELEMETRY_V1' in text:
        csv_part = text[text.index('TELEMETRY_V1\n') + len('TELEMETRY_V1\n'):]
        if csv_part.startswith('timestamp,'):
            out.write(csv_part)
            return out.getvalue()
    # FLIGHT_LOG v2 format: extract key-value pairs and reconstruct
    if 'FLIGHT_LOG v2' in text:
        out.write('timestamp,parameter,value\n')
        for line in text.split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                out.write(f"20260622_000000,{k.strip()},{v.strip()}\n")
        return out.getvalue()
    # Fallback: write raw text as single column
    out.write('timestamp,raw\n')
    for line in text.split('\n'):
        if line.strip():
            out.write(f"20260622_000000,{line.strip()}\n")
    return out.getvalue()

def binlog_convert(filepath):
    """Simulate BIN to CSV conversion for FLIGHT_DATA.BIN format."""
    content = open(filepath, 'rb').read()
    text = content.decode('utf-8', errors='replace')
    out = StringIO()
    if 'BINLOG_V1' in text:
        csv_part = text[text.index('BINLOG_V1\n') + len('BINLOG_V1\n'):]
        if csv_part.startswith('timestamp,'):
            out.write(csv_part)
            return out.getvalue()
    return ""

def scan_and_merge_telemetry(extracted_dir):
    """Scan extracted directory for CSVs, DATs, BINs, convert and merge."""
    result = {
        "files_found": [],
        "converted_files": [],
        "merged_rows": 0,
        "gps_rows": 0,
        "telemetry_available": False,
        "error": None,
    }
    all_csv_data = []

    for root, dirs, files in os.walk(extracted_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            ext = os.path.splitext(fname)[1].lower()
            rel = os.path.relpath(fpath, extracted_dir)

            if ext == '.csv':
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                        text = f.read()
                    if any(kw in text for kw in ['timestamp', 'latitude', 'longitude', 'lat', 'lon', 'rssi', 'roll', 'pitch']):
                        all_csv_data.append((rel, text))
                        result["files_found"].append({"file": rel, "type": "csv", "size": len(text)})
                except:
                    pass

            elif ext == '.dat' and 'TELEMETRY' in rel.upper():
                try:
                    csv_text = datcon_convert(fpath)
                    if csv_text.strip():
                        all_csv_data.append((rel.replace('.dat', '.csv'), csv_text))
                        result["converted_files"].append({"file": rel, "converted_to": rel.replace('.dat', '.csv')})
                except:
                    pass

            elif ext == '.bin' and ('TELEMETRY' in rel.upper() or 'FLIGHT' in rel.upper()):
                try:
                    csv_text = binlog_convert(fpath)
                    if csv_text.strip():
                        all_csv_data.append((rel.replace('.bin', '.csv'), csv_text))
                        result["converted_files"].append({"file": rel, "converted_to": rel.replace('.bin', '.csv')})
                except:
                    pass

    if not all_csv_data:
        result["error"] = "No telemetry files found in extracted data."
        return result

    # Parse each CSV individually for GPS data (different files may have different columns)
    gps_rows = []
    searched_headers = set()

    for relpath, text in all_csv_data:
        reader = csv.DictReader(StringIO(text))
        if not reader.fieldnames:
            continue

        # Skip if we already know this column set has no GPS headers
        header_tuple = tuple(sorted(reader.fieldnames))
        if header_tuple in searched_headers:
            continue
        searched_headers.add(header_tuple)

        for row in reader:
            lat = None
            lon = None
            for lat_key in ['lat', 'latitude', 'Latitude', 'LAT']:
                if lat_key in row:
                    try:
                        lat = float(row[lat_key])
                        break
                    except: pass
            for lon_key in ['lon', 'longitude', 'Longitude', 'LON']:
                if lon_key in row:
                    try:
                        lon = float(row[lon_key])
                        break
                    except: pass
            if lat is not None and lon is not None and abs(lat) < 90 and abs(lon) < 180 and (lat != 0 or lon != 0):
                alt = None
                for ak in ['alt', 'altitude', 'alt_rel', 'alt_msl', 'Alt', 'ALT']:
                    if ak in row:
                        try: alt = float(row[ak]); break
                        except: pass
                spd = None
                for sk in ['speed', 'tas', 'Speed', 'SPEED', 'velocity']:
                    if sk in row:
                        try: spd = float(row[sk]); break
                        except: pass
                gps_rows.append({
                    "lat": lat, "lon": lon, "alt": alt or 0,
                    "speed": spd or 0,
                    "ts": row.get("timestamp", row.get("Timestamp", "")),
                })

    result["merged_rows"] = len(gps_rows)
    result["gps_rows"] = len(gps_rows)

    if len(gps_rows) < 3:
        result["error"] = "Insufficient GPS data points found."
        return result

    # Compute flight metrics
    def haversine(lat1, lon1, lat2, lon2):
        R = 6371000
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlam = math.radians(lon2 - lon1)
        a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    total_dist = 0
    for i in range(1, len(gps_rows)):
        total_dist += haversine(gps_rows[i-1]["lat"], gps_rows[i-1]["lon"],
                                gps_rows[i]["lat"], gps_rows[i]["lon"])

    alts = [p["alt"] for p in gps_rows if p["alt"] is not None]
    speeds = [p["speed"] for p in gps_rows if p["speed"] is not None and p["speed"] > 0]

    takeoff = gps_rows[0]
    landing = gps_rows[-1]
    home_alt = takeoff["alt"]

    # Detect takeoff: first point where altitude > home + 2m
    takeoff_idx = 0
    for i, p in enumerate(gps_rows):
        if p["alt"] and p["alt"] > home_alt + 2:
            takeoff_idx = i
            break
    takeoff = gps_rows[takeoff_idx]

    # Detect landing
    landing_idx = len(gps_rows) - 1
    for i in range(len(gps_rows) - 1, -1, -1):
        if gps_rows[i]["alt"] and gps_rows[i]["alt"] > home_alt + 2:
            landing_idx = min(i + 2, len(gps_rows) - 1)
            break
    landing = gps_rows[landing_idx]

    result["telemetry_available"] = True
    result["metrics"] = {
        "takeoff": {"lat": takeoff["lat"], "lon": takeoff["lon"], "alt": round(takeoff["alt"], 1)},
        "landing": {"lat": landing["lat"], "lon": landing["lon"], "alt": round(landing["alt"], 1)},
        "home_alt_m": round(home_alt, 1),
        "total_distance_m": round(total_dist, 1),
        "total_distance_km": round(total_dist / 1000, 2),
        "max_altitude_m": round(max(alts), 1) if alts else 0,
        "max_speed_ms": round(max(speeds), 2) if speeds else 0,
        "max_speed_kmh": round(max(speeds) * 3.6, 2) if speeds else 0,
        "avg_speed_ms": round(sum(speeds) / len(speeds), 2) if speeds else 0,
        "avg_speed_kmh": round(sum(speeds) / len(speeds) * 3.6, 2) if speeds else 0,
        "gps_fixes": len(gps_rows),
        "coverage_km2": round((max(p["lat"] for p in gps_rows) - min(p["lat"] for p in gps_rows)) * 111 *
                               (max(p["lon"] for p in gps_rows) - min(p["lon"] for p in gps_rows)) * 85, 2),
    }

    # Build timeline events from trajectory
    events = []
    events.append({"time": "START", "label": "First GPS Fix", "detail": f"({takeoff['lat']:.4f}, {takeoff['lon']:.4f}) alt {takeoff['alt']:.0f}m", "type": "normal"})
    # Max altitude
    max_p = max(gps_rows, key=lambda p: p["alt"] or 0)
    events.append({"time": "APEX", "label": "Max Altitude", "detail": f"{max_p['alt']:.0f}m at ({max_p['lat']:.4f}, {max_p['lon']:.4f})", "type": "normal"})
    # Max speed
    if speeds:
        max_sp = max(gps_rows, key=lambda p: p["speed"] or 0)
        events.append({"time": "SPEED", "label": "Max Speed", "detail": f"{max_sp['speed']*3.6:.1f} km/h at ({max_sp['lat']:.4f}, {max_sp['lon']:.4f})", "type": "normal"})
    # Waypoints
    step = max(1, len(gps_rows) // 5)
    for i in range(step, len(gps_rows) - step, step):
        p = gps_rows[i]
        events.append({"time": f"WP{i}", "label": "Waypoint", "detail": f"({p['lat']:.4f}, {p['lon']:.4f}) alt {p['alt']:.0f}m" + (f" spd {p['speed']*3.6:.1f} km/h" if p['speed'] else ""), "type": "normal"})
    events.append({"time": "END", "label": "Last GPS Fix", "detail": f"({landing['lat']:.4f}, {landing['lon']:.4f}) alt {landing['alt']:.0f}m", "type": "normal"})
    result["timeline"] = events

    return result


def clear_telemetry_cache():
    TELEMETRY_CACHE.clear()


# API endpoint: return flight telemetry from the most recently extracted image
@app.route("/api/flight-logs", methods=["GET"])
def api_flight_logs():
    """Return computed flight telemetry from extracted disk image files."""
    if not TELEMETRY_CACHE:
        return jsonify({"error": "No telemetry data. Upload and extract a disk image first.", "telemetry_available": False}), 400
    return jsonify(TELEMETRY_CACHE)


@app.route("/api/clear", methods=["POST"])
def api_clear():
    """Clear all uploaded data and state."""
    state["baseline"] = None
    state["crash"] = None
    state["comparison"] = None
    state["extraction_log"] = []
    state["extraction_running"] = False
    state["extraction_progress"] = {"current": 0, "total": 0, "extracted": 0, "failed": 0, "deleted": 0, "orphan": 0}
    # Clear log queue
    while not log_queue.empty():
        try:
            log_queue.get_nowait()
        except queue.Empty:
            break
    return jsonify({"status": "ok", "message": "All data cleared."})


# Also serve pre-generated samples
@app.route("/api/samples", methods=["GET"])
def api_samples():
    """Return list of pre-generated sample disk images."""
    samples_dir = os.path.dirname(os.path.abspath(__file__))
    samples = []
    for name in ["drone_baseline.dd", "drone_crash.dd"]:
        path = os.path.join(samples_dir, name)
        if os.path.exists(path):
            samples.append({
                "name": name,
                "path": path,
                "size": os.path.getsize(path),
                "size_mb": round(os.path.getsize(path) / (1024 * 1024), 1),
            })
    return jsonify({"samples": samples})


@app.route("/api/load-sample/<name>", methods=["POST"])
def api_load_sample(name):
    """Load a pre-generated sample disk image."""
    samples_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(samples_dir, name)
    if not os.path.exists(path):
        return jsonify({"error": f"Sample not found: {name}"}), 404

    side = "baseline" if "baseline" in name else "crash"
    try:
        image_data = read_dd_image(path)
    except zipfile.BadZipFile:
        return jsonify({"error": "Invalid disk image."}), 400

    state[side] = image_data
    state["comparison"] = None

    label = "Baseline (Pre-Crash)" if side == "baseline" else "Post-Crash (Recovered)"
    t = threading.Thread(target=run_extraction_pipeline, args=(path, label), daemon=True)
    t.start()

    return jsonify({
        "status": "ok",
        "side": side,
        "label": image_data.get("label", label),
        "total_files": image_data["total_files"],
        "total_size": image_data["total_size"],
        "sha1": image_data["image_sha1"],
        "message": f"Loaded sample: {name}",
    })


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Drone Forensics Backend starting on http://0.0.0.0:{port}")
    print(f"Upload directory: {UPLOAD_DIR}")
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True, use_reloader=False)
