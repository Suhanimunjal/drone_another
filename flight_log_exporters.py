"""
flight_log_exporters.py
=======================
Export normalized flight telemetry to .xlsx files.

Sheet 1: Raw normalized telemetry rows
Sheet 2: Summary statistics (takeoff / landing / flight stats)
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import openpyxl
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    from openpyxl.utils import get_column_letter
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False


def export_to_xlsx(
    rows: List[Dict[str, Any]],
    dest_path: str,
    session_meta: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Write normalized telemetry rows to an Excel file.

    Args:
        rows:         list of dicts from FlightLogParser.parse()
        dest_path:    absolute path where the .xlsx should be written
        session_meta: optional dict with takeoff/landing/stats from FlightReconstructor

    Returns:
        dest_path (unchanged)

    Raises:
        ImportError if neither openpyxl nor pandas is available
        IOError if the file cannot be written
    """
    if not HAS_OPENPYXL and not HAS_PANDAS:
        raise ImportError(
            "Neither openpyxl nor pandas is installed. "
            "Run: pip install openpyxl"
        )

    os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)

    if HAS_OPENPYXL:
        return _export_openpyxl(rows, dest_path, session_meta)
    else:
        return _export_pandas(rows, dest_path, session_meta)


# ---------------------------------------------------------------------------
# openpyxl implementation (preferred)
# ---------------------------------------------------------------------------

_HEADER_FILL  = PatternFill("solid", fgColor="1A2640") if HAS_OPENPYXL else None
_HEADER_FONT  = Font(color="FFFFFF", bold=True, size=10) if HAS_OPENPYXL else None
_ACCENT_FILL  = PatternFill("solid", fgColor="1E3A5F") if HAS_OPENPYXL else None
_LABEL_FONT   = Font(bold=True, size=10) if HAS_OPENPYXL else None
_THIN          = Side(style="thin", color="334155") if HAS_OPENPYXL else None
_BORDER        = Border(left=_THIN, right=_THIN, top=_THIN, bottom=_THIN) if HAS_OPENPYXL else None


def _col_width(ws, col: int, width: float):
    ws.column_dimensions[get_column_letter(col)].width = width


def _export_openpyxl(
    rows: List[Dict[str, Any]],
    dest_path: str,
    meta: Optional[Dict[str, Any]],
) -> str:
    wb = openpyxl.Workbook()

    # ── Sheet 1: Telemetry ───────────────────────────────────────────────────
    ws1 = wb.active
    ws1.title = "Telemetry"

    COLS = [
        ("Timestamp",       "ts",          22),
        ("Latitude",        "lat",         14),
        ("Longitude",       "lon",         14),
        ("Altitude (m)",    "alt_m",       14),
        ("Speed (m/s)",     "speed_ms",    14),
        ("Heading (°)",     "heading",     13),
        ("Battery (%)",     "battery_pct", 13),
        ("Satellites",      "sats",        12),
        ("Flight Mode",     "mode",        16),
    ]

    # Header row
    for ci, (header, _, width) in enumerate(COLS, 1):
        cell = ws1.cell(row=1, column=ci, value=header)
        cell.font      = _HEADER_FONT
        cell.fill      = _HEADER_FILL
        cell.alignment = Alignment(horizontal="center", vertical="center")
        cell.border    = _BORDER
        _col_width(ws1, ci, width)
    ws1.row_dimensions[1].height = 18

    # Data rows
    for ri, row in enumerate(rows, 2):
        for ci, (_, key, _) in enumerate(COLS, 1):
            val  = row.get(key)
            cell = ws1.cell(row=ri, column=ci, value=val)
            cell.border    = _BORDER
            cell.alignment = Alignment(horizontal="center")
            # Alternate row shading
            if ri % 2 == 0:
                cell.fill = PatternFill("solid", fgColor="0F172A")

    # Freeze header + auto-filter
    ws1.freeze_panes = "A2"
    ws1.auto_filter.ref = f"A1:{get_column_letter(len(COLS))}1"

    # ── Sheet 2: Summary ────────────────────────────────────────────────────
    ws2 = wb.create_sheet("Summary")
    _write_summary_sheet(ws2, meta, len(rows))

    wb.save(dest_path)
    return dest_path


def _write_summary_sheet(ws, meta: Optional[Dict[str, Any]], row_count: int):
    ws.column_dimensions["A"].width = 28
    ws.column_dimensions["B"].width = 32

    def _hdr(row, text):
        c = ws.cell(row=row, column=1, value=text)
        c.font = _HEADER_FONT
        c.fill = _HEADER_FILL
        ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=2)
        c.alignment = Alignment(horizontal="left", vertical="center")
        ws.row_dimensions[row].height = 16

    def _row(row, label, value):
        lc = ws.cell(row=row, column=1, value=label)
        lc.font   = _LABEL_FONT
        lc.border = _BORDER
        vc = ws.cell(row=row, column=2, value=value)
        vc.border = _BORDER
        vc.alignment = Alignment(horizontal="left")

    cur = 1
    _hdr(cur, "Flight Log Export Summary"); cur += 1
    _row(cur, "Generated at",
         datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")); cur += 1
    _row(cur, "Total telemetry rows", row_count); cur += 1
    cur += 1

    if not meta:
        return

    # Takeoff
    _hdr(cur, "Takeoff"); cur += 1
    tkf = meta.get("takeoff") or {}
    _row(cur, "Takeoff timestamp",   tkf.get("ts",  "Not determined")); cur += 1
    _row(cur, "Takeoff latitude",    tkf.get("lat", "Not determined")); cur += 1
    _row(cur, "Takeoff longitude",   tkf.get("lon", "Not determined")); cur += 1
    _row(cur, "Takeoff altitude (m)",tkf.get("alt_m","Not determined")); cur += 1
    cur += 1

    # Landing
    _hdr(cur, "Landing"); cur += 1
    lnd = meta.get("landing") or {}
    _row(cur, "Landing timestamp",    lnd.get("ts",   "Not determined")); cur += 1
    _row(cur, "Landing latitude",     lnd.get("lat",  "Not determined")); cur += 1
    _row(cur, "Landing longitude",    lnd.get("lon",  "Not determined")); cur += 1
    _row(cur, "Landing altitude (m)", lnd.get("alt_m","Not determined")); cur += 1
    cur += 1

    # Stats
    _hdr(cur, "Flight Statistics"); cur += 1
    stats = meta.get("stats") or {}
    dur = stats.get("duration_s")
    dur_str = f"{int(dur//60)}m {int(dur%60)}s" if dur else "Unknown"
    _row(cur, "Duration",             dur_str); cur += 1
    _row(cur, "Max altitude (m)",     stats.get("max_alt_m")); cur += 1
    _row(cur, "Max distance from takeoff (m)", stats.get("max_dist_m")); cur += 1
    _row(cur, "Total path distance (m)",       stats.get("total_dist_m")); cur += 1
    _row(cur, "Average speed (m/s)",  stats.get("avg_speed_ms")); cur += 1
    _row(cur, "Max speed (m/s)",      stats.get("max_speed_ms")); cur += 1
    _row(cur, "GPS point count",      stats.get("point_count")); cur += 1
    _row(cur, "Baseline altitude (m)",stats.get("baseline_alt_m")); cur += 1
    cur += 1

    # Status
    _hdr(cur, "Parse Status"); cur += 1
    _row(cur, "Status", meta.get("status", "unknown")); cur += 1
    _row(cur, "Notes",  meta.get("notes") or ""); cur += 1


# ---------------------------------------------------------------------------
# pandas fallback (if openpyxl unavailable but pandas+xlsxwriter installed)
# ---------------------------------------------------------------------------

def _export_pandas(
    rows: List[Dict[str, Any]],
    dest_path: str,
    meta: Optional[Dict[str, Any]],
) -> str:
    df = pd.DataFrame(rows)
    df = df.rename(columns={
        "ts": "Timestamp", "lat": "Latitude", "lon": "Longitude",
        "alt_m": "Altitude (m)", "speed_ms": "Speed (m/s)",
        "heading": "Heading (°)", "battery_pct": "Battery (%)",
        "sats": "Satellites", "mode": "Flight Mode",
    })
    with pd.ExcelWriter(dest_path, engine="openpyxl") as writer:
        df.to_excel(writer, sheet_name="Telemetry", index=False)
    return dest_path
