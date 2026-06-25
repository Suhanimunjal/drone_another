"""
backend_server.py
Flask backend for the Drone Forensics Dashboard.
Handles .dd disk image uploads, extraction, cross-comparison,
and returns structured JSON results for the HTML frontend.
"""

import os, sys, json, hashlib, zipfile, io, time, threading, queue, re, csv, math, sqlite3, uuid
from datetime import datetime, timezone
from io import StringIO

from flask import Flask, request, jsonify, Response, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
CORS(app)

# -----------------------------------------------------------------------
# Simple token-based auth (in-memory)
# -----------------------------------------------------------------------
TOKENS = {}  # {token_hex: {"username": ..., "role": ..., "display_name": ...}}

def require_auth(*roles):
    """Decorator: validates Bearer token, optionally checks role(s)."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
            user = TOKENS.get(token)
            if not user:
                return jsonify({"error": "auth_required"}), 401
            request.current_user = user
            if roles and user.get("role") not in roles:
                return jsonify({"error": "forbidden"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
EXTRACT_DIR = os.path.join(UPLOAD_DIR, "extracted")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(EXTRACT_DIR, exist_ok=True)

# -----------------------------------------------------------------------
# SQLite Database
# -----------------------------------------------------------------------

_db_lock = threading.RLock()

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=60)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS Cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_number TEXT UNIQUE,
        analyst TEXT DEFAULT 'Dr. A. Sharma',
        status TEXT DEFAULT 'open',
        drone_model TEXT,
        company TEXT,
        created_at TEXT,
        updated_at TEXT,
        notes TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS Evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES Cases(id),
        filename TEXT,
        filepath TEXT,
        file_type TEXT,
        side TEXT,
        md5 TEXT,
        sha1 TEXT,
        sha256 TEXT,
        size_bytes INTEGER,
        uploaded_at TEXT,
        verified INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS DroneRegistry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        model_name TEXT,
        company TEXT,
        type TEXT,
        category TEXT,
        country TEXT,
        endurance TEXT,
        range_km TEXT,
        weight TEXT,
        payload TEXT,
        speed TEXT,
        ceiling TEXT,
        width TEXT,
        length TEXT,
        height TEXT,
        UNIQUE(model_name, company)
    );
    CREATE TABLE IF NOT EXISTS FlightData (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES Cases(id),
        takeoff_lat REAL, takeoff_lon REAL, takeoff_alt REAL,
        landing_lat REAL, landing_lon REAL, landing_alt REAL,
        total_distance_km REAL, max_altitude_m REAL, max_speed_kmh REAL,
        avg_speed_kmh REAL, gps_fixes INTEGER, coverage_km2 REAL,
        home_alt_m REAL, raw_metrics_json TEXT
    );
    CREATE TABLE IF NOT EXISTS TimelineEvents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES Cases(id),
        time_label TEXT, label TEXT, detail TEXT,
        event_type TEXT, source TEXT
    );
    CREATE TABLE IF NOT EXISTS Findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES Cases(id),
        category TEXT, severity TEXT, description TEXT,
        evidence_ref TEXT, auto_generated INTEGER DEFAULT 1,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS CaseAudit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES Cases(id),
        action TEXT, detail TEXT, user TEXT DEFAULT 'system', timestamp TEXT
    );
    CREATE TABLE IF NOT EXISTS Reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER REFERENCES Cases(id),
        report_type TEXT DEFAULT 'full_forensic',
        generated_at TEXT, format TEXT DEFAULT 'pdf',
        filepath TEXT, file_size INTEGER
    );
    CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        display_name TEXT DEFAULT '',
        role TEXT DEFAULT 'analyst',
        must_change_password INTEGER DEFAULT 0,
        created_at TEXT,
        last_login TEXT
    );
    CREATE TABLE IF NOT EXISTS LoginAudit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT,
        ip_address TEXT,
        timestamp TEXT
    );
    """)
    conn.commit()

    # Bootstrap default admin
    existing = conn.execute("SELECT id FROM Users WHERE username='admin'").fetchone()
    if not existing:
        conn.execute("INSERT INTO Users (username, password_hash, display_name, role, must_change_password, created_at) VALUES (?,?,?,?,?,?)",
            ("admin", generate_password_hash("admin"), "Administrator", "admin", 0, datetime.now(timezone.utc).isoformat()))
        conn.commit()
        print("\n" + "="*60)
        print("  DEFAULT ADMIN ACCOUNT")
        print("  Username: admin  |  Password: admin")
        print("="*60 + "\n")

    conn.close()

ROLE_PERMISSIONS = {
    "user": ["read"],
    "analyst": ["read", "write", "upload", "export"],
    "admin": ["read", "write", "upload", "export", "manage_users", "audit"],
}

def compute_hashes(filepath):
    md5 = hashlib.md5()
    sha1_h = hashlib.sha1()
    sha256_h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            md5.update(chunk)
            sha1_h.update(chunk)
            sha256_h.update(chunk)
    return md5.hexdigest(), sha1_h.hexdigest(), sha256_h.hexdigest()

def auto_create_case():
    conn = get_db()
    row = conn.execute("SELECT id FROM Cases WHERE status='open' ORDER BY id DESC LIMIT 1").fetchone()
    if row:
        case_id = row["id"]
        conn.close()
        return case_id
    now = datetime.now(timezone.utc).isoformat()
    count = conn.execute("SELECT count(*) as c FROM Cases").fetchone()["c"]
    case_num = f"DRN-{datetime.now().year}-{count+1:03d}"
    conn.execute("INSERT INTO Cases (case_number, analyst, status, created_at, updated_at) VALUES (?,?,?,?,?)",
                 (case_num, "Dr. A. Sharma", "open", now, now))
    conn.commit()
    case_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.execute("INSERT INTO CaseAudit (case_id, action, detail, timestamp) VALUES (?,?,?,?)",
                 (case_id, "case_created", f"Case {case_num} auto-created", now))
    conn.commit()
    conn.close()
    return case_id

def audit_log(case_id, action, detail=""):
    with _db_lock:
        conn = get_db()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("INSERT INTO CaseAudit (case_id, action, detail, timestamp) VALUES (?,?,?,?)",
                     (case_id, action, detail, now))
        conn.commit()
        conn.close()

def import_drone_registry():
    conn = get_db()
    if conn.execute("SELECT count(*) as c FROM DroneRegistry").fetchone()["c"] > 0:
        conn.close()
        return
    conn.close()
    try:
        import openpyxl
        xlsx = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Drone-DATABASE", "DATABASE.xlsx")
        if not os.path.exists(xlsx):
            return
        wb = openpyxl.load_workbook(xlsx, read_only=True)
        ws = wb[wb.sheetnames[0]]
        rows = list(ws.iter_rows(min_row=1, values_only=True))
        wb.close()
        if not rows:
            return
        headers = [str(h).strip() if h else f"col_{i}" for i, h in enumerate(rows[0])]
        conn = get_db()
        for row in rows[1:]:
            if not row or not row[0]:
                continue
            def col(name):
                idx = headers.index(name) if name in headers else -1
                return str(row[idx]).strip() if idx >= 0 and idx < len(row) and row[idx] else None
            try:
                conn.execute("""INSERT OR IGNORE INTO DroneRegistry
                    (model_name, company, type, category, country, endurance, range_km, weight, payload, speed, ceiling, width, length, height)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (col("MODEL NAME"), col("COMPANY"), col("TYPE"), col("CATEGORY"), col("COUNTRY"),
                     col("ENDURANCE"), col("RANGE"), col("WEIGHT"), col("PAYLOAD "), col("SPEED"),
                     col("CEILING"), col("WIDTH"), col("LENGTH"), col("HEIGHT")))
            except:
                pass
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Registry import error: {e}")

init_db()
import_drone_registry()

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
            # Save flight data to DB
            try:
                cid = None
                gps_count = 0
                with _db_lock:
                    conn = get_db()
                    try:
                        row = conn.execute("SELECT id FROM Cases WHERE status='open' ORDER BY id DESC LIMIT 1").fetchone()
                        if row:
                            cid = row["id"]
                            conn.execute("""INSERT INTO FlightData
                                (case_id, takeoff_lat, takeoff_lon, takeoff_alt, landing_lat, landing_lon, landing_alt,
                                 total_distance_km, max_altitude_m, max_speed_kmh, avg_speed_kmh, gps_fixes, coverage_km2, home_alt_m, raw_metrics_json)
                                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                                (cid, m["takeoff"]["lat"], m["takeoff"]["lon"], m["takeoff"]["alt"],
                                 m["landing"]["lat"], m["landing"]["lon"], m["landing"]["alt"],
                                 m["total_distance_km"], m["max_altitude_m"], m["max_speed_kmh"],
                                 m["avg_speed_kmh"], m["gps_fixes"], m["coverage_km2"], m["home_alt_m"],
                                 json.dumps(m)))
                            for ev in tel_result.get("timeline", []):
                                conn.execute("INSERT INTO TimelineEvents (case_id, time_label, label, detail, event_type, source) VALUES (?,?,?,?,?,?)",
                                    (cid, ev.get("time",""), ev.get("label",""), ev.get("detail",""), ev.get("type","normal"), "telemetry"))
                            conn.commit()
                            gps_count = tel_result.get('gps_rows', 0)
                    finally:
                        conn.close()
                if cid:
                    audit_log(cid, "telemetry_extracted", f"{gps_count} GPS fixes")
            except Exception as e:
                print(f"Flight data DB save error: {e}")
        else:
            emit_log("10/10", f"No telemetry data: {tel_result.get('error', 'unknown')}", "warning")
    else:
        emit_log("10/10", f"Extracted directory not found: {extracted_path}", "error")

    state["extraction_running"] = False
    emit_log("done", "Pipeline finished.")

    # Auto-detect drone model from extracted files
    try:
        detect_drone_model(extracted_path)
    except Exception as e:
        print(f"Model detection error (non-fatal): {e}")


def detect_drone_model(extracted_dir):
    """Detect drone model from extracted PARAM.CFG and cross-reference with DroneRegistry."""
    if not os.path.isdir(extracted_dir):
        return None
    param_path = None
    for root, dirs, files in os.walk(extracted_dir):
        for f in files:
            if f.upper() == "PARAM.CFG":
                param_path = os.path.join(root, f)
                break
        if param_path:
            break
    if not param_path:
        emit_log("model", "No PARAM.CFG found for model detection", "warning")
        return None

    model_name = None
    company = None
    try:
        with open(param_path, "r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline().strip()
        if first_line.startswith("#") and "Parameter" in first_line:
            raw = first_line.lstrip("# ").split("Parameter")[0].strip()
            if raw:
                model_name = raw
    except Exception as e:
        print(f"Error reading PARAM.CFG: {e}")
        return None

    if not model_name:
        emit_log("model", "Could not parse model name from PARAM.CFG", "warning")
        return None

    emit_log("model", f"Detected model: {model_name}", "stage")

    case_id = None
    matched = None
    with _db_lock:
        conn = get_db()
        try:
            row = conn.execute("SELECT * FROM DroneRegistry WHERE model_name = ?", (model_name,)).fetchone()
            if row:
                matched = dict(row)
            else:
                for kw in model_name.split():
                    if len(kw) < 3:
                        continue
                    rows = conn.execute("SELECT * FROM DroneRegistry WHERE model_name LIKE ?", (f"%{kw}%",)).fetchall()
                    if rows:
                        matched = dict(rows[0])
                        break
                parts = model_name.split(None, 1)
                if not matched and len(parts) == 2:
                    rows = conn.execute("SELECT * FROM DroneRegistry WHERE company LIKE ? AND model_name LIKE ?",
                        (f"%{parts[0]}%", f"%{parts[1]}%")).fetchall()
                    if rows:
                        matched = dict(rows[0])
            if matched:
                company = matched.get("company")
                case = conn.execute("SELECT id FROM Cases WHERE status='open' ORDER BY id DESC LIMIT 1").fetchone()
                if case:
                    case_id = case["id"]
                    conn.execute("UPDATE Cases SET drone_model=?, company=?, updated_at=? WHERE id=?",
                        (model_name, company, datetime.now(timezone.utc).isoformat(), case_id))
        finally:
            conn.commit()
            conn.close()
    if case_id:
        audit_log(case_id, "model_detected", f"Detected: {model_name} ({company})")
        emit_log("model", f"Case #{case_id} updated: {model_name} ({company})", "stage")
    if matched:
        emit_log("model", f"Registry match: {matched.get('model_name')} by {matched.get('company')}", "stage")
        return {"model_name": model_name, "company": company, "registry": matched}
    else:
        emit_log("model", f"No registry match for '{model_name}'", "warning")
        return {"model_name": model_name, "company": company, "registry": None}


# -----------------------------------------------------------------------
# Simple Authentication Routes
# -----------------------------------------------------------------------

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM Users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401
    token = uuid.uuid4().hex
    TOKENS[token] = {"username": user["username"], "display_name": user["display_name"], "role": user["role"]}
    return jsonify({"token": token, "user": {"username": user["username"], "display_name": user["display_name"], "role": user["role"]}})

@app.route("/api/logout", methods=["POST"])
def api_logout():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "") if auth.startswith("Bearer ") else ""
    TOKENS.pop(token, None)
    return jsonify({"status": "ok"})

# -----------------------------------------------------------------------
# User Management (Admin Only)
# -----------------------------------------------------------------------

@app.route("/api/users", methods=["GET"])
@require_auth("admin")
def api_list_users():
    conn = get_db()
    rows = conn.execute("SELECT id, username, display_name, role, must_change_password, created_at, last_login FROM Users ORDER BY id").fetchall()
    conn.close()
    return jsonify({"users": [dict(r) for r in rows]})

@app.route("/api/users", methods=["POST"])
@require_auth("admin")
def api_create_user():
    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    display_name = (data.get("display_name") or username).strip()
    role = data.get("role", "analyst")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if role not in ROLE_PERMISSIONS:
        return jsonify({"error": f"Invalid role. Choose from: {', '.join(ROLE_PERMISSIONS.keys())}"}), 400
    conn = get_db()
    existing = conn.execute("SELECT id FROM Users WHERE username=?", (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "Username already exists"}), 409
    conn.execute("INSERT INTO Users (username, password_hash, display_name, role, must_change_password, created_at) VALUES (?,?,?,?,?,?)",
        (username, generate_password_hash(password), display_name, role, 1, datetime.now(timezone.utc).isoformat()))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": f"User '{username}' created with role '{role}'"})

@app.route("/api/users/<int:user_id>", methods=["PUT"])
@require_auth("admin")
def api_update_user(user_id):
    data = request.get_json(force=True, silent=True) or {}
    conn = get_db()
    user = conn.execute("SELECT * FROM Users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    new_role = data.get("role")
    # Prevent demoting the last admin
    if new_role and new_role != "admin" and user["role"] == "admin":
        admin_count = conn.execute("SELECT count(*) as c FROM Users WHERE role='admin'").fetchone()["c"]
        if admin_count <= 1:
            conn.close()
            return jsonify({"error": "Cannot demote the last admin user"}), 400

    updates = []
    vals = []
    if "display_name" in data:
        updates.append("display_name=?")
        vals.append(data["display_name"])
    if new_role and new_role in ROLE_PERMISSIONS:
        updates.append("role=?")
        vals.append(new_role)
    if "password" in data and data["password"]:
        updates.append("password_hash=?")
        vals.append(generate_password_hash(data["password"]))
        updates.append("must_change_password=?")
        vals.append(1)
    if not updates:
        conn.close()
        return jsonify({"error": "No fields to update"}), 400
    vals.append(user_id)
    conn.execute(f"UPDATE Users SET {','.join(updates)} WHERE id=?", vals)
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@require_auth("admin")
def api_delete_user(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM Users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    # Prevent deleting the last admin
    if user["role"] == "admin":
        admin_count = conn.execute("SELECT count(*) as c FROM Users WHERE role='admin'").fetchone()["c"]
        if admin_count <= 1:
            conn.close()
            return jsonify({"error": "Cannot delete the last admin user"}), 400
    conn.execute("DELETE FROM Users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": f"User '{user['username']}' deleted"})

@app.route("/api/login-audit", methods=["GET"])
@require_auth("admin")
def api_login_audit():
    conn = get_db()
    rows = conn.execute("SELECT * FROM LoginAudit ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return jsonify({"audit": [dict(r) for r in rows]})

# -----------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------

@app.route("/api/status", methods=["GET"])
@require_auth()
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
@require_auth("admin", "analyst")
def api_upload(side):
    """Upload a disk image. side = 'baseline' or 'crash'."""
    if side not in ("baseline", "crash"):
        return jsonify({"error": "Invalid side. Use 'baseline' or 'crash'."}), 400

    if "file" not in request.files:
        return jsonify({"error": "No file provided."}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename."}), 400

    # Validate file extension
    allowed_exts = {".dd", ".img", ".raw", ".e01", ".bin", ".zip"}
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in allowed_exts:
        return jsonify({"error": f"Invalid file type '{ext}'. Allowed: {', '.join(sorted(allowed_exts))}"}), 400

    # Validate content size
    max_bytes = 500 * 1024 * 1024
    if request.content_length and request.content_length > max_bytes:
        return jsonify({"error": "File too large (max 500 MB)."}), 400

    # Save upload with UUID filename
    safe_name = f"{side}_{uuid.uuid4().hex[:16]}{ext}"
    save_path = os.path.join(UPLOAD_DIR, safe_name)
    file.save(save_path)

    try:
        image_data = read_dd_image(save_path)
    except zipfile.BadZipFile:
        return jsonify({"error": "Invalid disk image. Must be a .dd (zip) file."}), 400

    state[side] = image_data
    state["comparison"] = None  # invalidate cache

    # Compute hashes and store in DB
    md5, sha1_h, sha256_h = compute_hashes(save_path)
    case_id = auto_create_case()
    side_label = "recovered" if side == "crash" else "baseline"
    try:
        with _db_lock:
            conn = get_db()
            conn.execute("""INSERT INTO Evidence (case_id, filename, filepath, file_type, side, md5, sha1, sha256, size_bytes, uploaded_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (case_id, file.filename, save_path, "disk_image", side_label,
                 md5, sha1_h, sha256_h, os.path.getsize(save_path), datetime.now(timezone.utc).isoformat()))
            conn.commit()
            conn.close()
            audit_log(case_id, "evidence_uploaded", f"{file.filename} ({side_label})")
    except Exception as e:
        print(f"DB insert error: {e}")

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
        "md5": md5,
        "sha256": sha256_h,
        "case_id": case_id,
        "message": f"{side.capitalize()} disk image uploaded successfully.",
    })


@app.route("/api/extraction/log", methods=["GET"])
@require_auth()
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
@require_auth("admin", "analyst")
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
@require_auth()
def api_get_comparison():
    """Return cached comparison results."""
    if not state["comparison"]:
        return jsonify({"error": "No comparison results. Upload both images and POST /api/analyze first."}), 400
    return jsonify(state["comparison"])


@app.route("/api/analysis/<metric>", methods=["GET"])
@require_auth()
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
@require_auth()
def api_flight_logs():
    """Return computed flight telemetry from extracted disk image files."""
    if not TELEMETRY_CACHE:
        return jsonify({"error": "No telemetry data. Upload and extract a disk image first.", "telemetry_available": False}), 400
    return jsonify(TELEMETRY_CACHE)


@app.route("/api/clear", methods=["POST"])
@require_auth("admin", "analyst")
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
@app.route("/api/drone-database", methods=["GET"])
@require_auth()
def api_drone_database():
    """Read DATABASE.xlsx and return drone entries, optionally filtered by company."""
    import openpyxl
    company = request.args.get("company", "").strip().upper()
    xlsx_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Drone-DATABASE", "DATABASE.xlsx")
    if not os.path.exists(xlsx_path):
        return jsonify({"error": "DATABASE.xlsx not found"}), 404

    wb = openpyxl.load_workbook(xlsx_path, read_only=True)
    ws = wb[wb.sheetnames[0]]
    rows = list(ws.iter_rows(min_row=1, values_only=True))
    wb.close()

    if not rows:
        return jsonify({"drones": [], "columns": [], "common": {}})

    headers = [str(h).strip() if h else f"col_{i}" for i, h in enumerate(rows[0])]
    drones = []
    for row in rows[1:]:
        if not row or not row[0]:
            continue
        drone_company = str(row[2]).strip().upper() if row[2] else ""
        if company and company not in drone_company:
            continue
        attrs = {}
        for i, h in enumerate(headers):
            if i < len(row) and row[i] is not None and str(row[i]).strip():
                attrs[h] = str(row[i]).strip()
        if attrs:
            drones.append(attrs)

    # Compute common attributes (same value across all drones)
    common = {}
    if drones:
        all_keys = set()
        for d in drones:
            all_keys.update(d.keys())
        for key in all_keys:
            vals = set(d.get(key) for d in drones if key in d)
            if len(vals) == 1 and len(drones) > 1:
                common[key] = next(iter(vals))

    return jsonify({
        "drones": drones,
        "columns": headers,
        "common": common,
        "total": len(drones),
        "company_filter": company or "ALL",
    })


@app.route("/api/samples", methods=["GET"])
@require_auth()
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
@require_auth("admin", "analyst")
def api_load_sample(name):
    """Load a pre-generated sample disk image."""
    allowed_samples = {"drone_baseline.dd", "drone_crash.dd"}
    if name not in allowed_samples:
        return jsonify({"error": f"Unknown sample: {name}"}), 400
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

    # Compute hashes and store in DB
    md5, sha1_h, sha256_h = compute_hashes(path)
    case_id = auto_create_case()
    side_label = "recovered" if side == "crash" else "baseline"
    try:
        with _db_lock:
            conn = get_db()
            conn.execute("""INSERT INTO Evidence (case_id, filename, filepath, file_type, side, md5, sha1, sha256, size_bytes, uploaded_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (case_id, name, path, "disk_image", side_label,
                 md5, sha1_h, sha256_h, os.path.getsize(path), datetime.now(timezone.utc).isoformat()))
            conn.commit()
            conn.close()
            audit_log(case_id, "evidence_uploaded", f"{name} ({side_label} sample)")
    except Exception as e:
        print(f"DB insert error: {e}")

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
        "md5": md5,
        "sha256": sha256_h,
        "case_id": case_id,
        "message": f"Loaded sample: {name}",
    })


# -----------------------------------------------------------------------
# Case Management API
# -----------------------------------------------------------------------

@app.route("/api/cases", methods=["GET"])
@require_auth()
def api_list_cases():
    conn = get_db()
    cases = [dict(r) for r in conn.execute("SELECT * FROM Cases ORDER BY id DESC").fetchall()]
    for c in cases:
        c["evidence_count"] = conn.execute("SELECT count(*) as c FROM Evidence WHERE case_id=?", (c["id"],)).fetchone()["c"]
        c["findings_count"] = conn.execute("SELECT count(*) as c FROM Findings WHERE case_id=?", (c["id"],)).fetchone()["c"]
        crit = conn.execute("SELECT count(*) as c FROM Findings WHERE case_id=? AND severity='critical'", (c["id"],)).fetchone()["c"]
        warn = conn.execute("SELECT count(*) as c FROM Findings WHERE case_id=? AND severity='warning'", (c["id"],)).fetchone()["c"]
        c["critical_count"] = crit
        c["warning_count"] = warn
    conn.close()
    return jsonify({"cases": cases})

@app.route("/api/cases", methods=["POST"])
@require_auth("admin", "analyst")
def api_create_case():
    data = request.get_json() or {}
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    count = conn.execute("SELECT count(*) as c FROM Cases").fetchone()["c"]
    case_num = f"DRN-{datetime.now().year}-{count+1:03d}"
    conn.execute("INSERT INTO Cases (case_number, analyst, drone_model, company, status, created_at, updated_at, notes) VALUES (?,?,?,?,?,?,?,?)",
        (case_num, data.get("analyst", "Dr. A. Sharma"), data.get("drone_model", ""),
         data.get("company", ""), "open", now, now, data.get("notes", "")))
    conn.commit()
    case_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    audit_log(case_id, "case_created", f"Case {case_num} created manually")
    conn.close()
    return jsonify({"status": "ok", "case_id": case_id, "case_number": case_num})

@app.route("/api/cases/<int:case_id>", methods=["GET"])
@require_auth()
def api_get_case(case_id):
    conn = get_db()
    case = dict(conn.execute("SELECT * FROM Cases WHERE id=?", (case_id,)).fetchone() or {})
    if not case:
        conn.close()
        return jsonify({"error": "Case not found"}), 404
    case["evidence"] = [dict(r) for r in conn.execute("SELECT * FROM Evidence WHERE case_id=?", (case_id,)).fetchall()]
    case["findings"] = [dict(r) for r in conn.execute("SELECT * FROM Findings WHERE case_id=? ORDER BY severity", (case_id,)).fetchall()]
    case["audit"] = [dict(r) for r in conn.execute("SELECT * FROM CaseAudit WHERE case_id=? ORDER BY timestamp", (case_id,)).fetchall()]
    case["flight_data"] = dict(conn.execute("SELECT * FROM FlightData WHERE case_id=? ORDER BY id DESC LIMIT 1", (case_id,)).fetchone() or {})
    conn.close()
    return jsonify(case)

@app.route("/api/cases/<int:case_id>", methods=["PUT"])
@require_auth("admin", "analyst")
def api_update_case(case_id):
    data = request.get_json() or {}
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    fields = []
    vals = []
    for f in ["analyst", "drone_model", "company", "status", "notes"]:
        if f in data:
            fields.append(f"{f}=?")
            vals.append(data[f])
    fields.append("updated_at=?")
    vals.append(now)
    vals.append(case_id)
    conn.execute(f"UPDATE Cases SET {','.join(fields)} WHERE id=?", vals)
    audit_log(case_id, "case_updated", json.dumps({k: v for k, v in data.items() if k in ["analyst","drone_model","company","status","notes"]}))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/api/cases/<int:case_id>/close", methods=["POST"])
@require_auth("admin", "analyst")
def api_close_case(case_id):
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db()
    conn.execute("UPDATE Cases SET status='closed', updated_at=? WHERE id=?", (now, case_id))
    audit_log(case_id, "case_closed", "Case closed")
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/api/cases/current", methods=["GET"])
@require_auth()
def api_current_case():
    conn = get_db()
    row = conn.execute("SELECT id FROM Cases WHERE status='open' ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    if row:
        return jsonify({"case_id": row["id"]})
    return jsonify({"case_id": None})


@app.route("/api/cases/<int:case_id>/drone-identification", methods=["GET"])
@require_auth()
def api_drone_identification(case_id):
    """Return detected drone model + full specs from DroneRegistry."""
    conn = get_db()
    case = conn.execute("SELECT * FROM Cases WHERE id=?", (case_id,)).fetchone()
    if not case:
        conn.close()
        return jsonify({"error": "Case not found"}), 404
    case = dict(case)
    result = {
        "detected": case.get("drone_model"),
        "company": case.get("company"),
    }
    if case.get("drone_model"):
        row = conn.execute("SELECT * FROM DroneRegistry WHERE model_name = ?", (case["drone_model"],)).fetchone()
        if row:
            result["registry"] = dict(row)
        else:
            # fuzzy fallback
            for kw in case["drone_model"].split():
                if len(kw) < 3:
                    continue
                rows = conn.execute("SELECT * FROM DroneRegistry WHERE model_name LIKE ?", (f"%{kw}%",)).fetchall()
                if rows:
                    result["registry"] = dict(rows[0])
                    break
    conn.close()
    return jsonify(result)


@app.route("/api/cases/<int:case_id>/flight-points", methods=["GET"])
@require_auth()
def api_get_flight_points(case_id):
    conn = get_db()
    row = conn.execute("SELECT takeoff_lat, takeoff_lon, takeoff_alt, landing_lat, landing_lon, landing_alt FROM FlightData WHERE case_id=? ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
    conn.close()
    if row:
        return jsonify({k: row[k] for k in row.keys()})
    return jsonify({})

@app.route("/api/cases/<int:case_id>/flight-points", methods=["POST"])
@require_auth("admin", "analyst")
def api_save_flight_points(case_id):
    data = request.get_json() or {}
    fields = ["takeoff_lat", "takeoff_lon", "takeoff_alt", "landing_lat", "landing_lon", "landing_alt"]
    updates = {k: data.get(k) for k in fields if k in data}
    if not updates:
        return jsonify({"error": "No valid fields provided"}), 400
    with _db_lock:
        conn = get_db()
        existing = conn.execute("SELECT id FROM FlightData WHERE case_id=? ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
        if existing:
            set_clause = ", ".join(f"{k}=?" for k in updates)
            vals = list(updates.values()) + [existing["id"], case_id]
            conn.execute(f"UPDATE FlightData SET {set_clause} WHERE id=? AND case_id=?", vals)
        else:
            keys = ", ".join(updates.keys())
            placeholders = ", ".join("?" for _ in updates)
            vals = list(updates.values()) + [case_id]
            conn.execute(f"INSERT INTO FlightData ({keys}, case_id) VALUES ({placeholders}, ?)", vals)
        conn.commit()
        conn.close()
        audit_log(case_id, "flight_points_updated", json.dumps(updates))
    return jsonify({"status": "ok", "updated": updates})

# -----------------------------------------------------------------------
# Evidence API
# -----------------------------------------------------------------------

@app.route("/api/evidence", methods=["GET"])
@require_auth()
def api_list_evidence():
    case_id = request.args.get("case_id")
    conn = get_db()
    if case_id:
        rows = [dict(r) for r in conn.execute("SELECT * FROM Evidence WHERE case_id=? ORDER BY uploaded_at", (case_id,)).fetchall()]
    else:
        rows = [dict(r) for r in conn.execute("SELECT * FROM Evidence ORDER BY uploaded_at DESC").fetchall()]
    conn.close()
    return jsonify({"evidence": rows})

@app.route("/api/evidence/<int:evid_id>/verify", methods=["GET"])
@require_auth()
def api_verify_evidence(evid_id):
    conn = get_db()
    row = conn.execute("SELECT * FROM Evidence WHERE id=?", (evid_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Evidence not found"}), 404
    filepath = row["filepath"]
    if not os.path.exists(filepath):
        conn.close()
        return jsonify({"error": "File not found on disk", "verified": False}), 404
    md5, sha1_h, sha256_h = compute_hashes(filepath)
    match = (md5 == row["md5"] and sha1_h == row["sha1"] and sha256_h == row["sha256"])
    conn.execute("UPDATE Evidence SET verified=? WHERE id=?", (1 if match else 0, evid_id))
    audit_log(row["case_id"], "hash_verified", f"{row['filename']} — {'MATCH' if match else 'MISMATCH'}")
    conn.commit()
    conn.close()
    return jsonify({
        "verified": match,
        "stored": {"md5": row["md5"], "sha1": row["sha1"], "sha256": row["sha256"]},
        "current": {"md5": md5, "sha1": sha1_h, "sha256": sha256_h},
    })

# -----------------------------------------------------------------------
# Drone Registry API
# -----------------------------------------------------------------------

@app.route("/api/drone-registry", methods=["GET"])
@require_auth()
def api_drone_registry():
    company = request.args.get("company", "").strip().upper()
    model = request.args.get("model", "").strip()
    conn = get_db()
    if model:
        rows = [dict(r) for r in conn.execute("SELECT * FROM DroneRegistry WHERE model_name LIKE ?", (f"%{model}%",)).fetchall()]
    elif company:
        rows = [dict(r) for r in conn.execute("SELECT * FROM DroneRegistry WHERE company LIKE ?", (f"%{company}%",)).fetchall()]
    else:
        rows = [dict(r) for r in conn.execute("SELECT * FROM DroneRegistry").fetchall()]
    conn.close()
    return jsonify({"drones": rows, "total": len(rows)})

@app.route("/api/drone-registry/match", methods=["GET"])
@require_auth()
def api_match_drone():
    model = request.args.get("model", "").strip()
    if not model:
        return jsonify({"error": "Provide ?model= parameter"}), 400
    conn = get_db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM DroneRegistry").fetchall()]
    conn.close()
    best_match = None
    best_score = 0
    for r in rows:
        name = (r.get("model_name") or "").lower()
        score = 0
        words = model.lower().split()
        for w in words:
            if w in name:
                score += 1
        if score > best_score:
            best_score = score
            best_match = r
    confidence = round(best_score / max(len(model.split()), 1) * 100) if best_match else 0
    return jsonify({"match": best_match, "confidence": min(confidence, 99)})

# -----------------------------------------------------------------------
# Findings API
# -----------------------------------------------------------------------

@app.route("/api/findings", methods=["GET"])
@require_auth()
def api_findings():
    case_id = request.args.get("case_id")
    conn = get_db()
    if case_id:
        rows = [dict(r) for r in conn.execute("SELECT * FROM Findings WHERE case_id=? ORDER BY severity, created_at DESC", (case_id,)).fetchall()]
    else:
        rows = [dict(r) for r in conn.execute("SELECT * FROM Findings ORDER BY severity, created_at DESC").fetchall()]
    conn.close()
    return jsonify({"findings": rows})

@app.route("/api/findings/generate", methods=["POST"])
@require_auth("admin", "analyst")
def api_generate_findings():
    data = request.get_json() or {}
    case_id = data.get("case_id")
    if not case_id:
        return jsonify({"error": "case_id required"}), 400

    findings = []
    now = datetime.now(timezone.utc).isoformat()

    if TELEMETRY_CACHE.get("telemetry_available"):
        m = TELEMETRY_CACHE.get("metrics", {})
        if m.get("max_altitude_m", 0) > 120:
            findings.append(("EXCESSIVE_ALTITUDE", "warning", f"Max altitude {m['max_altitude_m']}m exceeds 120m limit", +10))
        if m.get("max_speed_kmh", 0) > 80:
            findings.append(("OVERSPEED", "warning", f"Max speed {m['max_speed_kmh']} km/h exceeds normal range", +10))

    if state.get("comparison"):
        s = state["comparison"]["summary"]
        if s.get("crash_artifact_count", 0) > 0:
            findings.append(("CRASH_ARTIFACTS", "critical", f"{s['crash_artifact_count']} crash artifact files found", +30))
        if s.get("removed", 0) > 5:
            findings.append(("FILES_DELETED", "warning", f"{s['removed']} files missing from post-crash image", +10))
        if s.get("modified", 0) > 3:
            findings.append(("CONFIG_MODIFIED", "warning", f"{s['modified']} files modified between baseline and crash", +5))
        change_pct = s.get("change_pct", 0)
        if change_pct > 30:
            findings.append(("MAJOR_FILESYSTEM_CHANGES", "critical", f"Filesystem changed by {change_pct}%", +20))

    conn = get_db()
    try:
        conn.execute("DELETE FROM Findings WHERE case_id=?", (case_id,))
        total_score = 0
        for cat, sev, desc, pts in findings:
            conn.execute("INSERT INTO Findings (case_id, category, severity, description, auto_generated, created_at) VALUES (?,?,?,?,1,?)",
                (case_id, cat, sev, desc, now))
            total_score += pts
        crash_score = min(total_score, 100)
        if crash_score <= 25:
            crash_severity = "LOW"
        elif crash_score <= 50:
            crash_severity = "MEDIUM"
        elif crash_score <= 75:
            crash_severity = "HIGH"
        else:
            crash_severity = "CRITICAL"
        conn.commit()
    finally:
        conn.close()
    audit_log(case_id, "findings_generated", f"{len(findings)} findings, score: {crash_score}% ({crash_severity})")
    return jsonify({"status": "ok", "findings_count": len(findings), "crash_score": crash_score, "crash_severity": crash_severity})

# -----------------------------------------------------------------------
# Audit Trail API
# -----------------------------------------------------------------------

@app.route("/api/audit/<int:case_id>", methods=["GET"])
@require_auth()
def api_audit(case_id):
    conn = get_db()
    rows = [dict(r) for r in conn.execute("SELECT * FROM CaseAudit WHERE case_id=? ORDER BY timestamp", (case_id,)).fetchall()]
    conn.close()
    return jsonify({"audit": rows})

# -----------------------------------------------------------------------
# Timeline API
# -----------------------------------------------------------------------

@app.route("/api/timeline", methods=["GET"])
@require_auth()
def api_timeline():
    conn = get_db()
    case = conn.execute("SELECT id FROM Cases WHERE status='open' ORDER BY id DESC LIMIT 1").fetchone()
    if not case:
        conn.close()
        return jsonify({"events": []})
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM TimelineEvents WHERE case_id=? ORDER BY id", (case["id"],)).fetchall()]
    conn.close()
    return jsonify({"events": rows})

# -----------------------------------------------------------------------
# Dashboard summary
# -----------------------------------------------------------------------

@app.route("/api/dashboard", methods=["GET"])
@require_auth()
def api_dashboard():
    conn = get_db()
    case = conn.execute("SELECT * FROM Cases WHERE status='open' ORDER BY id DESC LIMIT 1").fetchone()
    if not case:
        conn.close()
        return jsonify({"case": None, "evidence": [], "findings": [], "crash_score": 0, "crash_severity": "NONE"})
    case = dict(case)
    evidence = [dict(r) for r in conn.execute("SELECT * FROM Evidence WHERE case_id=?", (case["id"],)).fetchall()]
    findings = [dict(r) for r in conn.execute("SELECT * FROM Findings WHERE case_id=?", (case["id"],)).fetchall()]
    total_score = 0
    severity_map = {"EXCESSIVE_ALTITUDE": 10, "OVERSPEED": 10, "GPS_SIGNAL_LOSS": 30, "BATTERY_CRITICAL": 40,
                    "MOTOR_CURRENT_SPIKE": 20, "RC_SIGNAL_DEGRADATION": 15, "SUDDEN_DESCENT": 25,
                    "CRASH_ARTIFACTS": 30, "CONFIG_MODIFIED": 5, "FILES_DELETED": 10, "MAJOR_FILESYSTEM_CHANGES": 20}
    for f in findings:
        total_score += severity_map.get(f["category"], 5)
    crash_score = min(total_score, 100)
    if crash_score <= 25: crash_sev = "LOW"
    elif crash_score <= 50: crash_sev = "MEDIUM"
    elif crash_score <= 75: crash_sev = "HIGH"
    else: crash_sev = "CRITICAL"
    critical = sum(1 for f in findings if f["severity"] == "critical")
    warning = sum(1 for f in findings if f["severity"] == "warning")
    # Drone identification from DroneRegistry
    drone_id = None
    if case.get("drone_model"):
        drone_id = conn.execute("SELECT * FROM DroneRegistry WHERE model_name = ?", (case["drone_model"],)).fetchone()
        if not drone_id:
            for kw in case["drone_model"].split():
                if len(kw) < 3:
                    continue
                rows = conn.execute("SELECT * FROM DroneRegistry WHERE model_name LIKE ?", (f"%{kw}%",)).fetchall()
                if rows:
                    drone_id = rows[0]
                    break
        if drone_id:
            drone_id = dict(drone_id)
    total_cases = conn.execute("SELECT count(*) as c FROM Cases").fetchone()["c"]
    total_evidence = conn.execute("SELECT count(*) as c FROM Evidence").fetchone()["c"]
    total_findings = conn.execute("SELECT count(*) as c FROM Findings").fetchone()["c"]
    samples_loaded = {"baseline": state.get("baseline") is not None, "crash": state.get("crash") is not None}
    recent = [dict(r) for r in conn.execute("SELECT id, case_number, drone_model as name FROM Cases ORDER BY id DESC LIMIT 5").fetchall()]
    conn.close()
    return jsonify({
        "case": case, "evidence": evidence, "findings": findings,
        "crash_score": crash_score, "crash_severity": crash_sev,
        "critical_count": critical, "warning_count": warning,
        "findings_count": len(findings),
        "drone_identification": drone_id,
        "total_cases": total_cases,
        "total_evidence": total_evidence,
        "total_findings": total_findings,
        "samples_loaded": samples_loaded,
        "recent_cases": recent
    })


# Serve the dashboard HTML at the root URL
@app.route("/")
def serve_dashboard():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "forensics_dashboard.html")

@app.route("/static/<path:filename>")
def serve_static(filename):
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    resp = send_from_directory(static_dir, filename)
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Drone Forensics Backend starting on http://0.0.0.0:{port}")
    print(f"Upload directory: {UPLOAD_DIR}")
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True, use_reloader=False)
