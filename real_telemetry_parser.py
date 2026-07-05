"""real_telemetry_parser.py

Scans an extracted filesystem for real ArduPilot MAVLink logs (.bin, .tlog, .log)
and parses them using DroneFlightViewer's parse_log(). Supports mtime-based caching.

Usage:
    from real_telemetry_parser import find_and_parse_logs
    results = find_and_parse_logs("uploads/extracted/crash123/")
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from typing import Any


# Lazy-import parse_log so pymavlink isn't required unless a real parse happens.
_parse_log = None

def _get_parse_log():
    global _parse_log
    if _parse_log is None:
        try:
            from parse import parse_log
            _parse_log = parse_log
        except ImportError:
            from DroneFlightViewer.parse import parse_log
            _parse_log = parse_log
    return _parse_log


MAVLINK_MAGIC_BYTES = {0xFE, 0xFD}  # MAVLink 1.0 and 2.0
DATAFLASH_HEADERS = {0xFE, 0xA3}  # ArduPilot DataFlash format headers


def is_valid_mavlink_log(path: Path) -> bool:
    """Quick check: first 2 bytes should be DataFlash or MAVLink magic."""
    if not path.is_file() or path.stat().st_size < 16:
        return False
    try:
        with open(path, 'rb') as f:
            header = f.read(4)
        if len(header) < 2:
            return False
        # DataFlash: first byte is 0xFE or 0xA3
        if header[0] in DATAFLASH_HEADERS:
            return True
        # MAVLink 1.0: 0xFE, 2.0: 0xFD
        if header[0] in MAVLINK_MAGIC_BYTES:
            return True
        # Some .log files start with text, skip binary-looking ones
        return False
    except Exception:
        return False


def find_log_files(extracted_dir: Path) -> list[Path]:
    """Recursively find .bin, .tlog, .log files with valid MAVLink headers."""
    seen = set()
    found = []
    for ext in ('*.bin', '*.tlog', '*.log', '*.BIN', '*.TLOG', '*.LOG'):
        for f in extracted_dir.rglob(ext):
            resolved = f.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            if f.stat().st_size > 64 and is_valid_mavlink_log(f):
                found.append(f)
    return found


def parse_log_file(path: Path, cache_dir: Path | None = None) -> dict[str, Any] | None:
    """Parse one log file using DroneFlightViewer, with optional mtime cache.

    If cache_dir is given, writes/reads <filename>.json cache.
    """
    if cache_dir is not None:
        cache_dir = Path(cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_path = cache_dir / f"{path.name}.json"
        if cache_path.is_file() and cache_path.stat().st_mtime >= path.stat().st_mtime:
            try:
                return json.loads(cache_path.read_text())
            except Exception:
                pass

    try:
        parse_log = _get_parse_log()
        data = parse_log(path)
    except Exception as e:
        print(f"[real_telemetry_parser] parse failed for {path}: {e}", file=sys.stderr)
        return None

    if cache_dir is not None and data is not None:
        try:
            cache_path.write_text(json.dumps(data, default=str))
        except Exception:
            pass

    return data


def merge_parsed_logs(parsed_list: list[dict]) -> dict[str, Any] | None:
    """Merge multiple parsed logs into one combined result.

    Picks the one with the most GPS points. In future this could stitch
    multiple logs together chronologically.
    """
    if not parsed_list:
        return None
    if len(parsed_list) == 1:
        return parsed_list[0]
    return max(parsed_list, key=lambda d: d.get("stats", {}).get("gps_points", 0))


def find_and_parse_logs(
    extracted_dir: str | Path,
    cache_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Main entry point: scan extracted_dir, parse all real MAVLink logs.

    Returns:
        {
            "parsed_logs": list of per-file parse results,
            "merged": the best merged result or None,
            "logs_found": [filenames...],
            "errors": [{ "file": ..., "error": ... }],
        }
    """
    extracted_dir = Path(extracted_dir)
    if not extracted_dir.is_dir():
        return {"parsed_logs": [], "merged": None, "logs_found": [], "errors": [{"file": str(extracted_dir), "error": "directory not found"}]}

    log_files = find_log_files(extracted_dir)
    parsed_logs = []
    errors = []

    for lf in log_files:
        try:
            data = parse_log_file(lf, cache_dir=cache_dir)
            if data is not None:
                parsed_logs.append(data)
            else:
                errors.append({"file": str(lf.relative_to(extracted_dir)), "error": "parse returned None"})
        except Exception as e:
            errors.append({"file": str(lf.relative_to(extracted_dir)), "error": str(e)})

    merged = merge_parsed_logs(parsed_logs)

    return {
        "parsed_logs": parsed_logs,
        "merged": merged,
        "logs_found": [str(f.relative_to(extracted_dir)) for f in log_files],
        "errors": errors,
    }
