"""Pipeline orchestrator — runs Stages 1-5 sequentially.

Usage:
    from pipeline.orchestrator import run_pipeline
    result = run_pipeline(file_path, output_dir, log_cb=my_logger)
"""

import os
import json
import time
from pathlib import Path

from . import manifest_db
from . import stage1_format_detect
from . import stage2_fs_extract
from . import stage3_dat_identify
from . import stage4_dat_to_csv
from . import stage5_flight_analysis
from .ingest import run_pipeline as run_ingest


def _make_log_cb(emit_log):
    """Convert the (stage, message, level) emit_log to (level, message) format."""
    if emit_log is None:
        return None
    def cb(level, message):
        stage_map = {
            "stage": "pipeline",
            "info": "info",
            "warning": "warning",
            "warn": "warning",
            "error": "error",
        }
        mapped_level = stage_map.get(level, "info")
        emit_log(mapped_level, message, mapped_level)
    return cb


def run_pipeline(file_path, output_dir, emit_log=None):
    """Run the full 6-stage forensic pipeline.

    Args:
        file_path: path to the disk image (.e01, .dd, .raw, etc.)
        output_dir: working directory for this case
        emit_log: function(stage, message, level) for SSE logging

    Returns:
        dict with keys:
            success: bool
            case_id: str (UUID)
            stage1: dict or None
            stage2: dict or None
            stage3: dict or None
            stage4: dict or None
            stage5: dict or None
            error: str or None
    """
    if emit_log:
        emit_log("pipeline", "Starting forensic pipeline", "stage")

    log = _make_log_cb(emit_log)

    case_id = manifest_db.new_case_id()

    manifest_db.init_db()

    result = {
        "success": False,
        "case_id": case_id,
        "stage1": None,
        "stage2": None,
        "stage3": None,
        "stage4": None,
        "stage5": None,
        "error": None,
    }

    # ── Stage 1: Format Detection ────────────────────────────────────────
    if emit_log:
        emit_log("1/6", "Format Detection", "stage")
    try:
        stage1_result = stage1_format_detect.run_stage1(file_path, case_id, output_dir)
        result["stage1"] = stage1_result
        if emit_log:
            emit_log("1/6", f"Format: {stage1_result['detected_format']}", "info")
            emit_log("1/6", f"Hash: {stage1_result['hash_value'][:16]}... ({stage1_result['hash_algorithm']}, {stage1_result['hash_source']})", "info")
    except Exception as e:
        result["error"] = f"Stage 1 failed: {e}"
        if emit_log:
            emit_log("1/6", f"FAILED: {e}", "error")
            emit_log("pipeline", "Pipeline aborted at Stage 1", "error")
        manifest_db.update_case_stage(case_id, "stage1", 10, status="failed")
        return result

    # ── Stage 2: Filesystem Extraction ───────────────────────────────────
    if emit_log:
        emit_log("2/6", "Filesystem Extraction", "stage")
    try:
        stage2_result = stage2_fs_extract.run_stage2(
            stage1_result, case_id, output_dir, log_cb=log
        )
        result["stage2"] = stage2_result
        if emit_log:
            emit_log("2/6", f"Extracted: {stage2_result.get('extracted', 0)} files", "info")
            emit_log("2/6", f"Deleted: {stage2_result.get('deleted', 0)}, Failed: {stage2_result.get('failed', 0)}", "info")
    except Exception as e:
        result["error"] = f"Stage 2 failed: {e}"
        if emit_log:
            emit_log("2/6", f"FAILED: {e}", "error")
            emit_log("pipeline", "Pipeline aborted at Stage 2", "error")
        manifest_db.update_case_stage(case_id, "stage2", 40, status="failed")
        return result

    # ── Stage 3: DAT Identification ──────────────────────────────────────
    if emit_log:
        emit_log("3/6", "DAT File Identification", "stage")
    try:
        stage3_result = stage3_dat_identify.run_stage3(case_id, log_cb=log)
        result["stage3"] = stage3_result
        if emit_log:
            dat_files = stage3_result.get("dat_files", [])
            emit_log("3/6", f"DAT flight logs identified: {len(dat_files)}", "info")
            for df in dat_files:
                emit_log("3/6", f"  {df['path']}", "info")
    except Exception as e:
        result["error"] = f"Stage 3 failed: {e}"
        if emit_log:
            emit_log("3/6", f"FAILED: {e}", "error")
            emit_log("pipeline", "Pipeline aborted at Stage 3", "error")
        manifest_db.update_case_stage(case_id, "stage3", 50, status="failed")
        return result

    # ── Stage 4: DAT -> CSV Conversion ────────────────────────────────────
    dat_files = (stage3_result or {}).get("dat_files", [])
    if emit_log:
        emit_log("4/6", f"DAT -> CSV Conversion ({len(dat_files)} files)", "stage")
    stage4_result = {"stats": {"total": 0, "success": 0, "failed": 0, "empty": 0}, "conversions": []}
    if dat_files:
        try:
            stage4_result = stage4_dat_to_csv.run_stage4(case_id, dat_files, output_dir, log_cb=log)
            if emit_log:
                s = stage4_result["stats"]
                emit_log("4/6", f"Converted: {s['success']} success, {s['failed']} failed, {s['empty']} empty", "info")
        except Exception as e:
            if emit_log:
                emit_log("4/6", f"Conversion error: {e}", "warning")
    else:
        if emit_log:
            emit_log("4/6", "No DAT files to convert — skipping", "info")
    result["stage4"] = stage4_result

    # ── Stage 5: Flight Data Analysis ────────────────────────────────────
    conversions = stage4_result.get("conversions", [])
    if emit_log:
        emit_log("5/6", f"Flight Data Analysis ({len(conversions)} conversions)", "stage")
    stage5_result = {"stats": {"total": 0, "analyzed": 0, "no_takeoff": 0, "failed": 0}, "analyses": []}
    if conversions:
        try:
            stage5_result = stage5_flight_analysis.run_stage5(case_id, conversions, log_cb=log)
            if emit_log:
                s = stage5_result["stats"]
                emit_log("5/6", f"Analyzed: {s['analyzed']}, No takeoff: {s['no_takeoff']}, Failed: {s['failed']}", "info")
        except Exception as e:
            if emit_log:
                emit_log("5/6", f"Analysis error: {e}", "warning")
    else:
        if emit_log:
            emit_log("5/6", "No conversions to analyze — skipping", "info")
    result["stage5"] = stage5_result

    # ── Stage 6: Module Ingest Pipeline ───────────────────────────────────
    if emit_log:
        emit_log("6/6", "Module Ingest Pipeline (C1-C3, D1-D4)", "stage")
    try:
        file_rows = manifest_db.get_files(case_id)
        ingest_result = run_ingest(case_id, file_rows, case_context={
            "output_dir": output_dir,
            "image_path": file_path,
            "stage1_result": stage1_result,
        }, log_cb=log)
        result["ingest"] = ingest_result
        total = sum(r.get("artifacts_created", 0) for r in ingest_result.values())
        if emit_log:
            emit_log("6/6", f"Artifacts created: {total}", "info")
    except Exception as e:
        if emit_log:
            emit_log("6/6", f"Ingest error (non-fatal): {e}", "warning")
        result["ingest"] = {"error": str(e)}

    # ── Complete ─────────────────────────────────────────────────────────
    result["success"] = True
    manifest_db.update_case_stage(case_id, "completed", 100, status="completed")

    if emit_log:
        emit_log("pipeline", "Pipeline complete", "done")

    return result
