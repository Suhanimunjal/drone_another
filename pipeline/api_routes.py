"""Stage 6: REST API endpoints per spec contract.

Registers a Flask Blueprint at /api/cases.
"""

import os
import json
import sqlite3
import threading
from pathlib import Path
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, send_file, Response, current_app

from . import manifest_db
from .orchestrator import run_pipeline

cases_bp = Blueprint("cases", __name__)


@cases_bp.route("/api/cases/upload", methods=["POST"])
def upload_image():
    """Upload a disk image and start the forensic pipeline.

    POST /api/cases/upload
    Body: multipart/form-data with field "image"
    """
    if "image" not in request.files:
        return jsonify({"error": "No image file provided"}), 400

    file = request.files["image"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    upload_dir = current_app.config.get("UPLOAD_DIR", "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    # Save the uploaded file
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    safe_name = f"{ts}_{file.filename}"
    save_path = os.path.join(upload_dir, safe_name)
    file.save(save_path)

    # Create case output directory
    case_id = manifest_db.new_case_id()
    output_dir = os.path.join(upload_dir, "cases", case_id)
    os.makedirs(output_dir, exist_ok=True)

    # Start pipeline in background
    import threading
    def _run():
        try:
            run_pipeline(save_path, output_dir)
        except Exception as e:
            print(f"[pipeline] Background pipeline failed: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    return jsonify({
        "status": "ok",
        "case_id": case_id,
        "message": "Pipeline started",
        "source_file": file.filename,
    }), 202


@cases_bp.route("/api/cases", methods=["GET"])
def list_cases():
    """List all cases."""
    conn = manifest_db.get_db()
    try:
        rows = conn.execute("SELECT id, source_file, detected_format, status, stage, progress_pct, created_at, updated_at FROM cases ORDER BY created_at DESC").fetchall()
        return jsonify({"status": "ok", "cases": [dict(r) for r in rows]})
    finally:
        conn.close()


@cases_bp.route("/api/cases/<case_id>", methods=["GET"])
def get_case(case_id):
    """Get case metadata."""
    case = manifest_db.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify({"status": "ok", "case": case})


@cases_bp.route("/api/cases/<case_id>/status", methods=["GET"])
def get_case_status(case_id):
    """Get case processing status."""
    case = manifest_db.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    return jsonify({
        "status": "ok",
        "case_id": case_id,
        "pipeline_stage": case.get("stage"),
        "progress_pct": case.get("progress_pct"),
        "overall_status": case.get("status"),
        "updated_at": case.get("updated_at"),
    })


@cases_bp.route("/api/cases/<case_id>/files", methods=["GET"])
def list_files(case_id):
    """List all extracted files with file tree structure."""
    case = manifest_db.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404

    files = manifest_db.get_case_files(case_id)

    # Build file tree structure
    tree = {}
    for f in files:
        parts = f["path"].strip("/").split("/")
        node = tree
        for i, part in enumerate(parts):
            if i == len(parts) - 1:
                is_dir = False
                if "children" not in node:
                    node[part] = {
                        "id": f["id"],
                        "path": f["path"],
                        "size_bytes": f["size_bytes"],
                        "file_type": f["file_type"],
                        "is_deleted": bool(f["is_deleted"]),
                        "sha256": f["sha256"],
                        "recovery_status": f["recovery_status"],
                    }
            else:
                if part not in node:
                    node[part] = {"children": {}}
                node = node[part]["children"]

    def _tree_to_list(name, node):
        if "children" in node:
            return {"name": name, "type": "directory", "children": [_tree_to_list(k, v) for k, v in node["children"].items()]}
        return {"name": name, "type": "file", **node}

    file_tree = [_tree_to_list(k, v) for k, v in tree.items()]

    # Stats
    stats = {
        "total": len(files),
        "dat_log": sum(1 for f in files if f.get("file_type") == "DAT_LOG"),
        "deleted": sum(1 for f in files if f.get("is_deleted")),
        "total_size_bytes": sum(f.get("size_bytes", 0) for f in files),
    }

    return jsonify({"status": "ok", "files": files, "tree": file_tree, "stats": stats})


@cases_bp.route("/api/cases/<case_id>/files/<file_id>/download", methods=["GET"])
def download_file(case_id, file_id):
    """Download an extracted file."""
    case = manifest_db.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404

    file_row = manifest_db.get_file(file_id)
    if not file_row:
        return jsonify({"error": "File not found"}), 404

    extracted_path = file_row.get("extracted_path")
    if not extracted_path or not os.path.isfile(extracted_path):
        return jsonify({"error": "File not available on disk"}), 404

    return send_file(
        extracted_path,
        as_attachment=True,
        download_name=os.path.basename(file_row["path"]),
    )


@cases_bp.route("/api/cases/<case_id>/files/<file_id>/convert", methods=["POST"])
def convert_file(case_id, file_id):
    """Convert a DAT file to CSV."""
    from . import stage4_dat_to_csv

    case = manifest_db.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404

    file_row = manifest_db.get_file(file_id)
    if not file_row:
        return jsonify({"error": "File not found"}), 404

    if file_row.get("file_type") not in ("DAT_LOG", "DAT_UNKNOWN"):
        return jsonify({"error": "File is not a DAT flight log"}), 400

    dat_path = file_row.get("extracted_path")
    if not dat_path or not os.path.isfile(dat_path):
        return jsonify({"error": "DAT file not found on disk"}), 404

    output_dir = os.path.join(os.path.dirname(dat_path), "..", "csv")
    os.makedirs(output_dir, exist_ok=True)

    csv_name = Path(file_row["path"]).stem + ".csv"
    csv_path = os.path.join(output_dir, csv_name)

    conv_id = manifest_db.new_conversion_id()
    conv_row = {
        "id": conv_id,
        "case_id": case_id,
        "source_file_id": file_id,
        "csv_path": csv_path,
        "status": "converting",
    }
    manifest_db.insert_conversion(conv_row)

    success, out_path, error_msg, row_count, columns = stage4_dat_to_csv.convert_with_datcon(dat_path, csv_path)
    if not success:
        success, out_path, error_msg, row_count, columns = stage4_dat_to_csv.convert_with_djilogparser(dat_path, csv_path)
    if not success:
        success, out_path, error_msg, row_count, columns = stage4_dat_to_csv.convert_raw_scan(dat_path, csv_path)

    if success:
        status = "EMPTY_OUTPUT" if error_msg == "EMPTY_OUTPUT" else "SUCCESS"
        manifest_db.update_conversion(conv_id,
            status=status,
            csv_path=csv_path,
            row_count=row_count,
            columns=json.dumps(columns) if columns else None,
            error_message=error_msg if error_msg else None,
        )
        return jsonify({"status": "ok", "conversion_id": conv_id, "result": status, "row_count": row_count})
    else:
        manifest_db.update_conversion(conv_id, status="FAILED", error_message=error_msg)
        return jsonify({"status": "error", "conversion_id": conv_id, "error": error_msg}), 500


@cases_bp.route("/api/cases/<case_id>/conversions", methods=["GET"])
def list_conversions(case_id):
    """List all DAT->CSV conversions."""
    case = manifest_db.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404

    conversions = manifest_db.get_conversions(case_id)
    return jsonify({"status": "ok", "conversions": conversions})


@cases_bp.route("/api/cases/<case_id>/csv/<conv_id>/download", methods=["GET"])
def download_csv(case_id, conv_id):
    """Download a converted CSV file."""
    case = manifest_db.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404

    conversions = manifest_db.get_conversions(case_id)
    conv = next((c for c in conversions if c["id"] == conv_id), None)
    if not conv:
        return jsonify({"error": "Conversion not found"}), 404

    csv_path = conv.get("csv_path")
    if not csv_path or not os.path.isfile(csv_path):
        return jsonify({"error": "CSV file not found on disk"}), 404

    return send_file(
        csv_path,
        as_attachment=True,
        download_name=os.path.basename(csv_path),
        mimetype="text/csv",
    )


@cases_bp.route("/api/cases/<case_id>/analysis", methods=["GET"])
def get_analysis(case_id):
    """Get flight analysis results."""
    case = manifest_db.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404

    analyses = manifest_db.get_flight_analysis(case_id)

    # Parse JSON fields
    for a in analyses:
        if a.get("trajectory_json"):
            try:
                a["trajectory"] = json.loads(a["trajectory_json"])
            except (json.JSONDecodeError, TypeError):
                a["trajectory"] = []
            del a["trajectory_json"]
        if a.get("analysis_json"):
            try:
                a["analysis"] = json.loads(a["analysis_json"])
            except (json.JSONDecodeError, TypeError):
                a["analysis"] = {}
            del a["analysis_json"]

    return jsonify({"status": "ok", "analyses": analyses})


@cases_bp.route("/api/cases/<case_id>/analysis/<analysis_id>/trajectory", methods=["GET"])
def get_trajectory(case_id, analysis_id):
    """Get trajectory as GeoJSON."""
    case = manifest_db.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404

    analysis = manifest_db.get_flight_analysis_by_id(analysis_id)
    if not analysis:
        return jsonify({"error": "Analysis not found"}), 404

    trajectory_json = analysis.get("trajectory_json")
    if not trajectory_json:
        return jsonify({"error": "No trajectory data"}), 404

    try:
        trajectory = json.loads(trajectory_json)
    except (json.JSONDecodeError, TypeError):
        return jsonify({"error": "Invalid trajectory data"}), 500

    features = []
    for pt in trajectory:
        lat = pt.get("latitude")
        lon = pt.get("longitude")
        if lat is not None and lon is not None:
            features.append({
                "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [lon, lat]},
                "properties": {
                    "time": pt.get("time", ""),
                    "altitude_m": pt.get("altitude"),
                },
            })

    geojson = {
        "type": "FeatureCollection",
        "features": features,
    }

    return jsonify({"status": "ok", "geojson": geojson, "count": len(features)})


@cases_bp.route("/api/cases/<case_id>", methods=["DELETE"])
def delete_case(case_id):
    """Delete a case and all associated data."""
    case = manifest_db.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404

    conn = manifest_db.get_db()
    try:
        conn.execute("DELETE FROM flight_analysis WHERE case_id=?", (case_id,))
        conn.execute("DELETE FROM conversions WHERE case_id=?", (case_id,))
        conn.execute("DELETE FROM files WHERE case_id=?", (case_id,))
        conn.execute("DELETE FROM cases WHERE id=?", (case_id,))
        conn.commit()
    finally:
        conn.close()

    # Clean up extracted files
    upload_dir = current_app.config.get("UPLOAD_DIR", "uploads")
    case_dir = os.path.join(upload_dir, "cases", case_id)
    if os.path.isdir(case_dir):
        import shutil
        shutil.rmtree(case_dir, ignore_errors=True)

    return jsonify({"status": "ok", "message": f"Case {case_id} deleted"})


@cases_bp.route("/api/cases/<case_id>/pipeline/log", methods=["GET"])
def pipeline_log(case_id):
    """SSE endpoint for pipeline log streaming."""
    case = manifest_db.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404

    def generate():
        yield f"data: {json.dumps({'type': 'connected', 'case_id': case_id})}\n\n"
        last_progress = 0
        while True:
            case = manifest_db.get_case(case_id)
            if not case:
                yield f"data: {json.dumps({'type': 'error', 'message': 'Case deleted'})}\n\n"
                break

            progress = case.get("progress_pct", 0) or 0
            stage = case.get("stage", "unknown")
            status = case.get("status", "processing")

            if progress != last_progress:
                last_progress = progress
                yield f"data: {json.dumps({'type': 'progress', 'progress': progress, 'stage': stage})}\n\n"

            if status == "completed":
                yield f"data: {json.dumps({'type': 'complete', 'progress': 100, 'stage': stage})}\n\n"
                break
            elif status == "failed":
                yield f"data: {json.dumps({'type': 'error', 'message': 'Pipeline failed', 'stage': stage})}\n\n"
                break

            import time
            time.sleep(1)

    return Response(generate(), mimetype="text/event-stream")


# ── File Navigation Tree — Count Query Endpoint ────────────────────────────

STATIC_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static"
)
EXTENSION_CATEGORIES_PATH = os.path.join(STATIC_DIR, "extension_categories.json")
ARTIFACT_CATEGORIES_PATH = os.path.join(STATIC_DIR, "artifact_categories.json")

_FORENSICS_DB_LOCK = threading.RLock()


def _get_forensics_db():
    """Connect to the main forensics.db (for Evidence, Reports tables)."""
    if os.environ.get("VERCEL") and os.path.exists("/tmp/forensics.db"):
        db_path = "/tmp/forensics.db"
    else:
        db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "forensics.db")
    conn = sqlite3.connect(db_path, timeout=60)
    conn.row_factory = sqlite3.Row
    return conn


def _load_extension_categories():
    """Load the static extension classification config."""
    try:
        with open(EXTENSION_CATEGORIES_PATH, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _load_artifact_categories():
    """Load artifact type → category mapping from config. Returns (data_types, analysis_types)."""
    try:
        with open(ARTIFACT_CATEGORIES_PATH, "r") as f:
            raw = json.load(f)
        return (
            tuple(raw.get("Data Artifacts", [])),
            tuple(raw.get("Analysis Results", [])),
        )
    except (FileNotFoundError, json.JSONDecodeError):
        return (
            ("TSK_EXIF_METADATA", "TSK_GPS_TRACKPOINT",
             "TSK_FLIGHT_TRAJECTORY_POINT", "TSK_FLIGHT_TAKEOFF", "TSK_FLIGHT_LANDING"),
            ("TSK_HASH_MATCH_BAD", "TSK_EXTENSION_MISMATCH",
             "TSK_INTERESTING_FILE_HIT", "TSK_KEYWORD_HIT",
             "TSK_FLIGHT_ANOMALY", "TSK_YARA_HIT"),
        )


def _get_ext(path):
    """Extract the file extension from a path (lowercase, no dot)."""
    if not path:
        return ""
    name = path.rstrip("/").split("/")[-1]
    if "." in name:
        return name.rsplit(".", 1)[-1].lower()
    return ""


def _flatten_category_exts(category, exts):
    """Walk the category config and return all extensions as a flat set."""
    if isinstance(exts, list):
        return set(ex.lower() for ex in exts)
    elif isinstance(exts, dict):
        result = set()
        for sub in exts.values():
            result.update(ex.lower() for ex in sub)
        return result
    return set()


def _count_by_extension(files, ext_set):
    """Count how many files have an extension in ext_set."""
    count = 0
    for f in files:
        ext = _get_ext(f.get("path", ""))
        if ext in ext_set:
            count += 1
    return count


def _build_by_extension_counts(files, cats):
    """Recursively count files for each category/sub-category."""
    result = {}
    for cat_name, cat_value in cats.items():
        if isinstance(cat_value, list):
            ext_set = set(ex.lower() for ex in cat_value)
            result[cat_name] = _count_by_extension(files, ext_set)
        elif isinstance(cat_value, dict):
            sub = {}
            for sub_name, sub_exts in cat_value.items():
                ext_set = set(ex.lower() for ex in sub_exts)
                sub[sub_name] = _count_by_extension(files, ext_set)
            result[cat_name] = sub
    return result


@cases_bp.route("/api/cases/<case_id>/tree-counts", methods=["GET"])
def tree_counts(case_id):
    """Return all counts for the file navigation tree in one response.

    Queries both pipeline.db (files, artifacts, tags) and forensics.db
    (evidence, reports) for a complete tree state.
    """
    case = manifest_db.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404

    cats = _load_extension_categories()

    # ── Files from pipeline.db ────────────────────────────────────────
    files = manifest_db.get_case_files(case_id)

    # ── 2a. By Extension counts ────────────────────────────────────────
    by_extension = _build_by_extension_counts(files, cats)

    # ── 2b. By MIME Type (from artifacts table) ───────────────────────
    mime_rows = []
    pipeline_conn = manifest_db.get_db()
    try:
        mime_rows = pipeline_conn.execute(
            "SELECT json_extract(details_json, '$.mime_type') AS mime_type, COUNT(*) AS cnt "
            "FROM artifacts WHERE case_id=? AND artifact_type='TSK_FILE_TYPE_SIG' "
            "AND ignore_in_ui=0 AND details_json IS NOT NULL "
            "GROUP BY mime_type ORDER BY mime_type",
            (case_id,)
        ).fetchall()
    finally:
        pipeline_conn.close()

    by_mime_type = []
    c1_has_run = False
    for row in mime_rows:
        mt = row["mime_type"]
        if mt:
            c1_has_run = True
            by_mime_type.append({"mime_type": mt, "count": row["cnt"]})

    mime_note = None
    if not c1_has_run:
        if len(files) > 0:
            mime_note = "C1 (File Type ID) has not run yet"
        # if no files either, just empty

    # ── 4. Deleted Files ──────────────────────────────────────────────
    file_system_deleted = sum(1 for f in files if f.get("is_deleted"))

    # Carved files: look for TSK_CARVED_FILE artifacts
    pipeline_conn2 = manifest_db.get_db()
    try:
        carved_artifact_count = pipeline_conn2.execute(
            "SELECT COUNT(DISTINCT file_id) AS cnt FROM artifacts "
            "WHERE case_id=? AND artifact_type='TSK_CARVED_FILE' AND file_id IS NOT NULL",
            (case_id,)
        ).fetchone()["cnt"]
    finally:
        pipeline_conn2.close()

    all_deleted = file_system_deleted + carved_artifact_count

    # ── 5. File Size buckets ──────────────────────────────────────────
    def _size_bucket_count(lo, hi):
        if hi is None:
            return sum(1 for f in files if (f.get("size_bytes") or 0) > lo)
        return sum(1 for f in files if lo <= (f.get("size_bytes") or 0) <= hi)

    size_0_50mb = _size_bucket_count(0, 52428800)
    size_50_200mb = _size_bucket_count(52428801, 209715200)
    size_200mb_1gb = _size_bucket_count(209715201, 1073741824)
    size_1gb_plus = _size_bucket_count(1073741824, None)

    # ── 6. Data Artifacts vs Analysis Results (from config) ────────────
    data_artifact_types, analysis_result_types = _load_artifact_categories()

    pipeline_conn3 = manifest_db.get_db()
    try:
        data_artifacts_count = pipeline_conn3.execute(
            "SELECT COUNT(*) AS cnt FROM artifacts WHERE case_id=? AND artifact_type IN ({}) AND ignore_in_ui=0".format(
                ",".join("?" for _ in data_artifact_types)
            ),
            (case_id, *data_artifact_types)
        ).fetchone()["cnt"]

        analysis_results_count = pipeline_conn3.execute(
            "SELECT COUNT(*) AS cnt FROM artifacts WHERE case_id=? AND artifact_type IN ({}) AND ignore_in_ui=0".format(
                ",".join("?" for _ in analysis_result_types)
            ),
            (case_id, *analysis_result_types)
        ).fetchone()["cnt"]

        # Notable score: any analysis result with severity >= 'medium'
        has_bad_score = pipeline_conn3.execute(
            "SELECT COUNT(*) AS cnt FROM artifacts WHERE case_id=? AND artifact_type IN ({}) "
            "AND severity IN ('medium','high','critical') AND ignore_in_ui=0 LIMIT 1".format(
                ",".join("?" for _ in analysis_result_types)
            ),
            (case_id, *analysis_result_types)
        ).fetchone()["cnt"] > 0

        # OS Accounts count
        os_accounts_count = pipeline_conn3.execute(
            "SELECT COUNT(DISTINCT file_id) AS cnt FROM artifacts "
            "WHERE case_id=? AND artifact_type='TSK_OS_ACCOUNT' AND ignore_in_ui=0",
            (case_id,)
        ).fetchone()["cnt"]

        # Tags count
        tags_count = pipeline_conn3.execute(
            "SELECT COUNT(*) AS cnt FROM tags WHERE case_id=?",
            (case_id,)
        ).fetchone()["cnt"]
    finally:
        pipeline_conn3.close()

    # ── 1. Data Sources (evidence items from forensics.db) ────────────
    data_sources_count = 0
    try:
        fconn = _get_forensics_db()
        try:
            data_sources_count = fconn.execute(
                "SELECT COUNT(*) AS cnt FROM Evidence WHERE case_id=? OR case_id IN "
                "(SELECT id FROM Cases WHERE case_number=? OR drone_model IS NOT NULL)",
                (case_id, case_id)
            ).fetchone()["cnt"]
        finally:
            fconn.close()
    except Exception:
        pass

    # ── Reports from forensics.db ─────────────────────────────────────
    reports_list = []
    try:
        fconn2 = _get_forensics_db()
        try:
            report_rows = fconn2.execute(
                "SELECT report_type, generated_at, format, filepath, file_size "
                "FROM Reports WHERE case_id=? ORDER BY generated_at DESC",
                (case_id,)
            ).fetchall()
            reports_list = [dict(r) for r in report_rows]
        finally:
            fconn2.close()
    except Exception:
        pass

    # ── Assemble response ─────────────────────────────────────────────
    response = {
        "data_sources": {"count": data_sources_count},
        "file_views": {
            "by_extension": by_extension,
            "by_mime_type": {
                "items": by_mime_type,
                "note": mime_note,
            },
            "deleted_files": {
                "file_system": file_system_deleted,
                "all": all_deleted,
            },
            "file_size": {
                "0_50mb": size_0_50mb,
                "50_200mb": size_50_200mb,
                "200mb_1gb": size_200mb_1gb,
                "1gb_plus": size_1gb_plus,
            },
        },
        "data_artifacts": data_artifacts_count,
        "analysis_results": analysis_results_count,
        "os_accounts": os_accounts_count,
        "tags": tags_count,
        "score": {
            "has_bad_score": has_bad_score,
        },
        "reports": reports_list,
    }

    return jsonify(response)
