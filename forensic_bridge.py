"""forensic_bridge.py

Bridges the offline forensic_extract_windows.py pipeline with the web backend.
Runs real pytsk3-based extraction on uploaded E01/DD/IMG/RAW images,
then feeds the extracted files into real_telemetry_parser.

Usage:
    from forensic_bridge import run_real_extraction
    result = run_real_extraction("uploads/drone.E01", "uploads/extracted/drone/")
"""

from __future__ import annotations

import os
import sys
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from real_telemetry_parser import find_and_parse_logs
from metrics_mapper import map_to_dashboard_metrics
from timeline_mapper import map_to_timeline_events
from file_tree_exporter import get_extraction_stats


# Try to import the real forensic engine
try:
    from forensic_extract_windows import ForensicPipeline, TSK_AVAILABLE
    REAL_TSK = TSK_AVAILABLE
except ImportError:
    REAL_TSK = False
    ForensicPipeline = None


# Callback hooks
_on_log: Callable | None = None
_on_progress: Callable | None = None
_on_stage: Callable | None = None

log_queue: list[dict] = []


def emit_log(level: str, message: str, stage: str = "") -> None:
    entry = {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "level": level,
        "message": message,
        "stage": stage,
    }
    log_queue.append(entry)
    if _on_log:
        _on_log(level, message)


def is_e01(path: str | Path) -> bool:
    return Path(path).suffix.lower() == '.e01'


def run_real_extraction(
    image_path: str | Path,
    output_dir: str | Path,
    log_cb: Callable | None = None,
    progress_cb: Callable | None = None,
    cancel_flag: threading.Event | None = None,
) -> dict[str, Any]:
    """Run real forensic extraction using pytsk3, then parse telemetry.

    Args:
        image_path: Path to .e01, .dd, .img, or .raw file
        output_dir: Where to extract files
        log_cb: Callback(level, message) for live logging
        progress_cb: Callback(current, total, label) for progress bar
        cancel_flag: threading.Event to signal cancellation

    Returns:
        {
            "status": "ok" | "failed",
            "extraction_stats": {...},
            "telemetry": {...} or None,
            "errors": [...],
        }
    """
    global _on_log, _on_progress
    _on_log = log_cb
    _on_progress = progress_cb

    image_path = Path(image_path)
    output_dir = Path(output_dir)
    result: dict[str, Any] = {
        "status": "failed",
        "extraction_stats": None,
        "telemetry": None,
        "errors": [],
        "logs_found": [],
    }

    start = time.time()

    # ── Stage 1: Real forensic extraction ───────────────────────────────
    if REAL_TSK and ForensicPipeline is not None:
        emit_log("stage", f"Starting forensic extraction of {image_path.name}")
        emit_log("info", f"Image: {image_path}")
        emit_log("info", f"Output: {output_dir}")

        try:
            pipeline = ForensicPipeline(
                image_path=str(image_path),
                output_dir=str(output_dir),
                max_jobs=4,
                compute_hash=True,
                compute_filetype=True,
            )

            def plog(level, msg):
                emit_log(level, msg)
            pipeline.on_log = plog

            ext_result = pipeline.run()
            emit_log("stage", f"Extraction complete: {ext_result.get('extracted', 0)} files extracted")
        except Exception as e:
            emit_log("error", f"Forensic extraction failed: {e}")
            result["errors"].append(f"Extraction: {e}")
            result["status"] = "failed"
            return result
    else:
        # No pytsk3 — try simple file copy for non-E01 images
        if is_e01(image_path):
            emit_log("error", "E01 images require pytsk3 + ewfexport. Install: pip install pytsk3")
            result["errors"].append("E01 not supported without pytsk3")
            return result

        # For .dd/.img/.raw that are actually zip archives (samples), skip extraction
        emit_log("warn", "pytsk3 not available — using filesystem as-is")
        emit_log("info", f"Output directory: {output_dir}")

    # ── Stage 2: Parse telemetry ───────────────────────────────────────
    emit_log("stage", "Scanning extracted filesystem for MAVLink logs")
    parse_result = find_and_parse_logs(output_dir, cache_dir=output_dir / ".telemetry_cache")
    merged = parse_result.get("merged")

    result["logs_found"] = parse_result["logs_found"]
    result["errors"].extend(parse_result["errors"])

    if parse_result["logs_found"]:
        emit_log("info", f"Found {len(parse_result['logs_found'])} MAVLink logs: {', '.join(parse_result['logs_found'])}")
    if parse_result.get("errors"):
        for err in parse_result["errors"]:
            emit_log("warn", f"Parse error: {err['file']}: {err['error']}")

    if merged is not None:
        metrics = map_to_dashboard_metrics(merged)
        timeline = map_to_timeline_events(merged)

        stats = merged.get("stats", {})
        emit_log("info", f"GPS points: {stats.get('gps_points', 0)} | "
                         f"Duration: {stats.get('duration_s', 0):.1f}s | "
                         f"Anomalies: {stats.get('anomalies', 0)} | "
                         f"Events: {stats.get('events', 0)}")

        if metrics:
            emit_log("info", f"Takeoff: ({metrics['takeoff']['lat']:.5f}, {metrics['takeoff']['lon']:.5f}) "
                             f"alt {metrics['takeoff']['alt']:.0f}m")
            emit_log("info", f"Landing: ({metrics['landing']['lat']:.5f}, {metrics['landing']['lon']:.5f}) "
                             f"alt {metrics['landing']['alt']:.0f}m")
            emit_log("info", f"Distance: {metrics['total_distance_km']:.2f} km | "
                             f"Max alt: {metrics['max_altitude_m']:.0f}m | "
                             f"Max speed: {metrics['max_speed_kmh']:.1f} km/h")

        result["telemetry"] = {
            "merged": merged,
            "metrics": metrics,
            "timeline": timeline,
            "parsed_logs": parse_result["parsed_logs"],
            "logs_found": parse_result["logs_found"],
        }
    else:
        emit_log("warn", "No real MAVLink logs found — telemetry data unavailable")

    # ── Stage 3: Stats ─────────────────────────────────────────────────
    result["extraction_stats"] = get_extraction_stats(output_dir)
    result["status"] = "ok"
    result["elapsed"] = round(time.time() - start, 1)

    emit_log("stage", f"Pipeline finished in {result['elapsed']}s")
    return result
