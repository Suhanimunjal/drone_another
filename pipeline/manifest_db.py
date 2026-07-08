"""Manifest database — stores case metadata, file manifest, conversion results, and flight analysis.

Each pipeline stage writes its output here. The frontend reads from here.
"""

import sqlite3
import json
import os
import threading
import uuid
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pipeline.db")
_lock = threading.RLock()


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=60)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables if they don't exist."""
    with _lock:
        conn = get_db()
        try:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;

                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,
                    source_file TEXT NOT NULL,
                    detected_format TEXT NOT NULL,
                    hash_algorithm TEXT,
                    hash_value TEXT,
                    hash_source TEXT,
                    acquisition_date TEXT,
                    media_size_bytes INTEGER,
                    block_access_path TEXT,
                    status TEXT DEFAULT 'uploading',
                    stage TEXT DEFAULT 'uploading',
                    progress_pct INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    inode TEXT,
                    path TEXT NOT NULL,
                    extracted_path TEXT,
                    size_bytes INTEGER DEFAULT 0,
                    is_deleted INTEGER DEFAULT 0,
                    mtime TEXT,
                    atime TEXT,
                    ctime TEXT,
                    crtime TEXT,
                    sha256 TEXT,
                    file_type TEXT,
                    recovery_status TEXT DEFAULT 'ok',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS conversions (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    source_file_id TEXT NOT NULL,
                    csv_path TEXT,
                    status TEXT DEFAULT 'pending',
                    row_count INTEGER DEFAULT 0,
                    columns TEXT,
                    error_message TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(id),
                    FOREIGN KEY (source_file_id) REFERENCES files(id)
                );

                CREATE TABLE IF NOT EXISTS flight_analysis (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    conversion_id TEXT NOT NULL,
                    baseline_altitude_m REAL,
                    takeoff_timestamp TEXT,
                    takeoff_latitude REAL,
                    takeoff_longitude REAL,
                    landing_timestamp TEXT,
                    landing_latitude REAL,
                    landing_longitude REAL,
                    max_altitude_m REAL,
                    max_speed REAL,
                    flight_duration_seconds REAL,
                    trajectory_json TEXT,
                    analysis_json TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(id),
                    FOREIGN KEY (conversion_id) REFERENCES conversions(id)
                );

                CREATE TABLE IF NOT EXISTS module_runs (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    files_processed INTEGER DEFAULT 0,
                    artifacts_created INTEGER DEFAULT 0,
                    errors INTEGER DEFAULT 0,
                    started_at TEXT,
                    finished_at TEXT,
                    run_order INTEGER DEFAULT 0,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );

                CREATE TABLE IF NOT EXISTS artifacts (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    file_id TEXT,
                    parent_artifact_id TEXT,
                    source TEXT,
                    title TEXT,
                    description TEXT,
                    severity TEXT DEFAULT 'info',
                    details_json TEXT,
                    ts_ref TEXT,
                    lat REAL,
                    lon REAL,
                    alt REAL,
                    hash_value TEXT,
                    matched_text TEXT,
                    byte_offset INTEGER,
                    ignore_in_ui INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(id),
                    FOREIGN KEY (file_id) REFERENCES files(id)
                );
                CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);
                CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(artifact_type);
                CREATE INDEX IF NOT EXISTS idx_artifacts_file ON artifacts(file_id);
                CREATE INDEX IF NOT EXISTS idx_artifacts_severity ON artifacts(severity);

                -- Cross-case repository index
                CREATE TABLE IF NOT EXISTS cross_case_index (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    artifact_id TEXT,
                    artifact_type TEXT NOT NULL,
                    module_name TEXT,
                    file_path TEXT,
                    file_id TEXT,
                    lat REAL,
                    lon REAL,
                    ts_ref TEXT,
                    hash_value TEXT,
                    matched_text TEXT,
                    title TEXT,
                    description TEXT,
                    severity TEXT,
                    indexed_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );
                CREATE INDEX IF NOT EXISTS idx_cci_artifact_type ON cross_case_index(artifact_type);
                CREATE INDEX IF NOT EXISTS idx_cci_hash ON cross_case_index(hash_value);
                CREATE INDEX IF NOT EXISTS idx_cci_matched_text ON cross_case_index(matched_text);
                CREATE INDEX IF NOT EXISTS idx_cci_ts ON cross_case_index(ts_ref);

                -- Tags
                CREATE TABLE IF NOT EXISTS tags (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    color TEXT DEFAULT '#3388ff',
                    description TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_tags_name_case ON tags(case_id, name);

                CREATE TABLE IF NOT EXISTS artifact_tags (
                    artifact_id TEXT NOT NULL,
                    tag_id TEXT NOT NULL,
                    tagged_at TEXT NOT NULL,
                    PRIMARY KEY (artifact_id, tag_id),
                    FOREIGN KEY (artifact_id) REFERENCES artifacts(id),
                    FOREIGN KEY (tag_id) REFERENCES tags(id)
                );

                -- YARA rules
                CREATE TABLE IF NOT EXISTS yara_rules (
                    id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    rule_text TEXT NOT NULL,
                    source_file TEXT,
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                );
            """)
            conn.commit()
        finally:
            conn.close()


def new_case_id():
    return str(uuid.uuid4())


def new_file_id():
    return str(uuid.uuid4())


def new_conversion_id():
    return str(uuid.uuid4())


def new_analysis_id():
    return str(uuid.uuid4())


def insert_case(case_id, source_file, detected_format, hash_algorithm, hash_value,
                hash_source, media_size_bytes, block_access_path):
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO cases (id, source_file, detected_format, hash_algorithm, "
                "hash_value, hash_source, media_size_bytes, block_access_path, "
                "status, stage, progress_pct, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (case_id, source_file, detected_format, hash_algorithm, hash_value,
                 hash_source, media_size_bytes, block_access_path,
                 "processing", "stage1", 10, now, now))
            conn.commit()
        finally:
            conn.close()


def update_case_stage(case_id, stage, progress_pct, status=None):
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db()
        try:
            if status:
                conn.execute("UPDATE cases SET stage=?, progress_pct=?, status=?, updated_at=? WHERE id=?",
                             (stage, progress_pct, status, now, case_id))
            else:
                conn.execute("UPDATE cases SET stage=?, progress_pct=?, updated_at=? WHERE id=?",
                             (stage, progress_pct, now, case_id))
            conn.commit()
        finally:
            conn.close()


def insert_file(file_row):
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO files (id, case_id, inode, path, extracted_path, size_bytes, "
                "is_deleted, mtime, atime, ctime, crtime, sha256, file_type, "
                "recovery_status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (file_row["id"], file_row["case_id"], file_row.get("inode"),
                 file_row["path"], file_row.get("extracted_path"),
                 file_row.get("size_bytes", 0), file_row.get("is_deleted", 0),
                 file_row.get("mtime"), file_row.get("atime"),
                 file_row.get("ctime"), file_row.get("crtime"),
                 file_row.get("sha256"), file_row.get("file_type"),
                 file_row.get("recovery_status", "ok"), now))
            conn.commit()
        finally:
            conn.close()


def update_file_type(file_id, file_type):
    with _lock:
        conn = get_db()
        try:
            conn.execute("UPDATE files SET file_type=? WHERE id=?", (file_type, file_id))
            conn.commit()
        finally:
            conn.close()


def update_file_sha256(file_id, sha256):
    with _lock:
        conn = get_db()
        try:
            conn.execute("UPDATE files SET sha256=? WHERE id=?", (sha256, file_id))
            conn.commit()
        finally:
            conn.close()


def insert_conversion(conv_row):
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO conversions (id, case_id, source_file_id, csv_path, "
                "status, row_count, columns, error_message, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (conv_row["id"], conv_row["case_id"], conv_row["source_file_id"],
                 conv_row.get("csv_path"), conv_row.get("status", "pending"),
                 conv_row.get("row_count", 0), conv_row.get("columns"),
                 conv_row.get("error_message"), now))
            conn.commit()
        finally:
            conn.close()


def update_conversion(conv_id, **kwargs):
    sets = []
    vals = []
    for k, v in kwargs.items():
        sets.append(f"{k}=?")
        vals.append(v)
    vals.append(conv_id)
    with _lock:
        conn = get_db()
        try:
            conn.execute(f"UPDATE conversions SET {', '.join(sets)} WHERE id=?", vals)
            conn.commit()
        finally:
            conn.close()


def insert_flight_analysis(analysis_row):
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO flight_analysis (id, case_id, conversion_id, "
                "baseline_altitude_m, takeoff_timestamp, takeoff_latitude, takeoff_longitude, "
                "landing_timestamp, landing_latitude, landing_longitude, "
                "max_altitude_m, max_speed, flight_duration_seconds, "
                "trajectory_json, analysis_json, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (analysis_row["id"], analysis_row["case_id"],
                 analysis_row["conversion_id"],
                 analysis_row.get("baseline_altitude_m"),
                 analysis_row.get("takeoff_timestamp"),
                 analysis_row.get("takeoff_latitude"),
                 analysis_row.get("takeoff_longitude"),
                 analysis_row.get("landing_timestamp"),
                 analysis_row.get("landing_latitude"),
                 analysis_row.get("landing_longitude"),
                 analysis_row.get("max_altitude_m"),
                 analysis_row.get("max_speed"),
                 analysis_row.get("flight_duration_seconds"),
                 analysis_row.get("trajectory_json"),
                 analysis_row.get("analysis_json"),
                 now))
            conn.commit()
        finally:
            conn.close()


def get_case(case_id):
    with _lock:
        conn = get_db()
        try:
            row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def get_case_files(case_id):
    with _lock:
        conn = get_db()
        try:
            rows = conn.execute("SELECT * FROM files WHERE case_id=? ORDER BY path", (case_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def get_file(file_id):
    with _lock:
        conn = get_db()
        try:
            row = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def get_conversions(case_id):
    with _lock:
        conn = get_db()
        try:
            rows = conn.execute("SELECT * FROM conversions WHERE case_id=?", (case_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def get_flight_analysis(case_id):
    with _lock:
        conn = get_db()
        try:
            rows = conn.execute("SELECT * FROM flight_analysis WHERE case_id=?", (case_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def get_flight_analysis_by_id(analysis_id):
    with _lock:
        conn = get_db()
        try:
            row = conn.execute("SELECT * FROM flight_analysis WHERE id=?", (analysis_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


# ── Artifact / Module Run helpers ────────────────────────────────────────────

def new_module_run_id():
    return str(uuid.uuid4())

def new_artifact_id():
    return str(uuid.uuid4())

def insert_module_run(run_row):
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO module_runs (id, case_id, module_name, status, "
                "files_processed, artifacts_created, errors, started_at, run_order) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (run_row["id"], run_row["case_id"], run_row["module_name"],
                 run_row.get("status", "running"),
                 run_row.get("files_processed", 0),
                 run_row.get("artifacts_created", 0),
                 run_row.get("errors", 0),
                 now, run_row.get("run_order", 0)))
            conn.commit()
        finally:
            conn.close()

def finish_module_run(run_id, status="completed"):
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db()
        try:
            conn.execute("UPDATE module_runs SET status=?, finished_at=? WHERE id=?",
                         (status, now, run_id))
            conn.commit()
        finally:
            conn.close()

def insert_artifact(art_row):
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db()
        try:
            import json
            conn.execute(
                "INSERT INTO artifacts (id, case_id, module_name, artifact_type, "
                "file_id, parent_artifact_id, source, title, description, severity, "
                "details_json, ts_ref, lat, lon, alt, hash_value, matched_text, "
                "byte_offset, ignore_in_ui, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (art_row["id"], art_row["case_id"], art_row["module_name"],
                 art_row["artifact_type"],
                 art_row.get("file_id"),
                 art_row.get("parent_artifact_id"),
                 art_row.get("source"),
                 art_row.get("title"),
                 art_row.get("description"),
                 art_row.get("severity", "info"),
                 json.dumps(art_row.get("details", {})) if art_row.get("details") else None,
                 art_row.get("ts_ref"),
                 art_row.get("lat"),
                 art_row.get("lon"),
                 art_row.get("alt"),
                 art_row.get("hash_value"),
                 art_row.get("matched_text"),
                 art_row.get("byte_offset"),
                 1 if art_row.get("ignore_in_ui") else 0,
                 now))
            conn.commit()
        finally:
            conn.close()

def get_artifacts(case_id, artifact_type=None, file_id=None, severity=None):
    with _lock:
        conn = get_db()
        try:
            clauses = ["case_id=?"]
            params = [case_id]
            if artifact_type:
                clauses.append("artifact_type=?")
                params.append(artifact_type)
            if file_id:
                clauses.append("file_id=?")
                params.append(file_id)
            if severity:
                clauses.append("severity=?")
                params.append(severity)
            sql = "SELECT * FROM artifacts WHERE " + " AND ".join(clauses) + " ORDER BY created_at"
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

def get_artifact_count_by_type(case_id):
    """Return dict of artifact_type -> count for the Timeline/Findings views."""
    with _lock:
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT artifact_type, count(*) as cnt FROM artifacts WHERE case_id=? "
                "AND ignore_in_ui=0 GROUP BY artifact_type ORDER BY cnt DESC",
                (case_id,)).fetchall()
            return {r["artifact_type"]: r["cnt"] for r in rows}
        finally:
            conn.close()

def get_artifact_timeline(case_id):
    """Return all artifacts with timestamps for the master timeline view."""
    with _lock:
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT a.*, f.path as file_path FROM artifacts a "
                "LEFT JOIN files f ON a.file_id=f.id "
                "WHERE a.case_id=? AND a.ignore_in_ui=0 "
                "ORDER BY a.created_at", (case_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ── Cross-case index helpers ────────────────────────────────────────────────

def new_cci_id():
    return str(uuid.uuid4())

def insert_cci_row(row):
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO cross_case_index "
                "(id, case_id, artifact_id, artifact_type, module_name, file_path, "
                "file_id, lat, lon, ts_ref, hash_value, matched_text, "
                "title, description, severity, indexed_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (row["id"], row["case_id"], row.get("artifact_id"),
                 row["artifact_type"], row.get("module_name"),
                 row.get("file_path"), row.get("file_id"),
                 row.get("lat"), row.get("lon"), row.get("ts_ref"),
                 row.get("hash_value"), row.get("matched_text"),
                 row.get("title"), row.get("description"),
                 row.get("severity", "info"), now))
            conn.commit()
        finally:
            conn.close()

def query_cross_case(artifact_type=None, hash_value=None, matched_text=None, limit=100):
    with _lock:
        conn = get_db()
        try:
            clauses = []
            params = []
            if artifact_type:
                clauses.append("artifact_type=?")
                params.append(artifact_type)
            if hash_value:
                clauses.append("hash_value=?")
                params.append(hash_value)
            if matched_text:
                clauses.append("matched_text LIKE ?")
                params.append(f"%{matched_text}%")
            where = " WHERE " + " AND ".join(clauses) if clauses else ""
            rows = conn.execute(
                f"SELECT * FROM cross_case_index{where} ORDER BY indexed_at DESC LIMIT ?",
                params + [limit]).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ── Tag helpers ─────────────────────────────────────────────────────────────

def new_tag_id():
    return str(uuid.uuid4())

def create_tag(case_id, name, color="#3388ff", description=""):
    now = datetime.now(timezone.utc).isoformat()
    tag_id = new_tag_id()
    with _lock:
        conn = get_db()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO tags (id, case_id, name, color, description, created_at) "
                "VALUES (?,?,?,?,?,?)", (tag_id, case_id, name, color, description, now))
            conn.commit()
            row = conn.execute("SELECT * FROM tags WHERE id=?", (tag_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

def get_tags(case_id):
    with _lock:
        conn = get_db()
        try:
            rows = conn.execute("SELECT * FROM tags WHERE case_id=? ORDER BY name", (case_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

def tag_artifact(artifact_id, tag_id):
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO artifact_tags (artifact_id, tag_id, tagged_at) VALUES (?,?,?)",
                (artifact_id, tag_id, now))
            conn.commit()
        finally:
            conn.close()

def untag_artifact(artifact_id, tag_id):
    with _lock:
        conn = get_db()
        try:
            conn.execute("DELETE FROM artifact_tags WHERE artifact_id=? AND tag_id=?",
                         (artifact_id, tag_id))
            conn.commit()
        finally:
            conn.close()

def get_artifact_tags(artifact_id):
    with _lock:
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT t.* FROM tags t JOIN artifact_tags at ON t.id=at.tag_id "
                "WHERE at.artifact_id=? ORDER BY t.name", (artifact_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ── YARA rule helpers ───────────────────────────────────────────────────────

def new_yara_rule_id():
    return str(uuid.uuid4())

def insert_yara_rule(row):
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO yara_rules (id, case_id, name, rule_text, source_file, enabled, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (row["id"], row["case_id"], row["name"], row["rule_text"],
                 row.get("source_file"), 1 if row.get("enabled", True) else 0, now))
            conn.commit()
        finally:
            conn.close()

def get_yara_rules(case_id):
    with _lock:
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT * FROM yara_rules WHERE case_id=? AND enabled=1 ORDER BY name",
                (case_id,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# Initialize on import
init_db()
