"""Stage 4: DAT -> CSV Conversion

Converts DJI .DAT flight log files to CSV using available tools.
Tries DatCon (Java), falls back to dji-log-parser (Python), then raw binary scan.

Input: DAT_LOG files from Stage 3
Output: CSV files + conversion records in DB
"""

import os
import subprocess
import json
import csv
from pathlib import Path

from . import manifest_db


def find_datcon():
    """Locate DatCon.jar."""
    candidates = [
        os.path.join(os.path.dirname(__file__), "..", "tools", "DatCon.jar"),
        os.path.join(os.path.dirname(__file__), "..", "DatCon.jar"),
        os.path.join(os.path.dirname(__file__), "..", "..", "tools", "DatCon.jar"),
        os.path.join(os.path.dirname(__file__), "..", "tools", "DatCon", "DatCon.4.3.0.jar"),
        r"C:\tools\DatCon.jar",
        r"C:\DatCon\DatCon.jar",
    ]
    for c in candidates:
        abs_c = os.path.abspath(c)
        if os.path.isfile(abs_c):
            return abs_c
    return None


def convert_with_datcon(dat_path, csv_path):
    """Convert DAT to CSV using DatCon (Java CLI).

    Returns (success, csv_path, error_message, row_count, columns).
    """
    datcon_jar = find_datcon()
    if not datcon_jar:
        return False, None, "DatCon.jar not found", 0, None

    if os.path.getsize(dat_path) < 1024:
        return False, None, "File too small for DatCon", 0, None
    java_bin = "java"
    try:
        result = subprocess.run(
            [java_bin, "-jar", datcon_jar,
             "-infile", dat_path,
             "-outfile", csv_path,
             "-timezone", "UTC"],
            capture_output=True, text=True, timeout=30
        )

        if result.returncode != 0:
            return False, None, f"DatCon failed: {result.stderr[:500]}", 0, None

        if not os.path.isfile(csv_path):
            # DatCon may output to a different name
            alt = csv_path.replace(".csv", "-C.csv")
            if os.path.isfile(alt):
                os.rename(alt, csv_path)
            else:
                return False, None, "DatCon produced no output file", 0, None

        # Verify CSV
        return _verify_csv(csv_path)

    except FileNotFoundError:
        return False, None, "Java not found — install JRE to use DatCon", 0, None
    except subprocess.TimeoutExpired:
        return False, None, "DatCon timed out after 300s", 0, None


def convert_with_djilogparser(dat_path, csv_path):
    """Convert DAT to CSV using dji-log-parser Python bindings.

    Returns (success, csv_path, error_message, row_count, columns).
    """
    try:
        from dji_log_parser import DJIFlightLog
    except ImportError:
        return False, None, "dji-log-parser not installed", 0, None

    try:
        log = DJIFlightLog(dat_path)
        df = log.to_dataframe()

        if df is None or df.empty:
            return False, None, "dji-log-parser returned empty data", 0, None

        df.to_csv(csv_path, index=False)
        return _verify_csv(csv_path)
    except Exception as e:
        return False, None, f"dji-log-parser error: {e}", 0, None


def convert_raw_scan(dat_path, csv_path):
    """Last resort: scan DAT file for embedded CSV-like data.

    DJI DAT files sometimes contain readable ASCII sections.
    This is a rough fallback — not reliable for all firmware versions.
    """
    try:
        with open(dat_path, "rb") as f:
            raw = f.read()

        # Look for CSV-like sections (latitude/longitude patterns)
        text = raw.decode("ascii", errors="ignore")
        lines = text.split("\n")
        csv_lines = []
        header_found = False

        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            # Look for header-like lines with common CSV column names
            if not header_found:
                lower = stripped.lower()
                if any(kw in lower for kw in ["time", "latitude", "longitude", "alt"]):
                    header_found = True
                    csv_lines.append(stripped)
                continue
            # After header, collect data lines (comma-separated numbers)
            parts = stripped.split(",")
            if len(parts) >= 3:
                try:
                    [float(p.strip()) for p in parts[:4]]
                    csv_lines.append(stripped)
                except ValueError:
                    if csv_lines:
                        break  # End of data section

        if len(csv_lines) > 2:
            with open(csv_path, "w", newline="") as f:
                f.write("\n".join(csv_lines) + "\n")
            return _verify_csv(csv_path)

        return False, None, "No readable CSV data found in DAT file", 0, None
    except Exception as e:
        return False, None, f"Raw scan failed: {e}", 0, None


def _verify_csv(csv_path):
    """Verify CSV has header + data rows. Returns (success, csv_path, error, row_count, columns)."""
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                return False, csv_path, "CSV has no header row", 0, None

            row_count = sum(1 for _ in reader)

            if row_count == 0:
                return True, csv_path, "EMPTY_OUTPUT", 0, header

            return True, csv_path, None, row_count, header
    except Exception as e:
        return False, csv_path, f"CSV verification failed: {e}", 0, None


def run_stage4(case_id, dat_files, output_dir, log_cb=None):
    """Execute Stage 4: convert all DAT_LOG files to CSV.

    Args:
        case_id: case UUID
        dat_files: list of file manifest rows (from Stage 3)
        output_dir: working directory
        log_cb: optional callback(level, message)

    Returns:
        dict with conversion stats
    """
    def log(level, msg):
        if log_cb:
            log_cb(level, msg)
        print(f"[Stage 4] [{level}] {msg}")

    log("stage", "Converting DAT -> CSV")

    csv_dir = os.path.join(output_dir, "csv")
    os.makedirs(csv_dir, exist_ok=True)

    stats = {"total": len(dat_files), "success": 0, "failed": 0, "empty": 0}
    conversions = []

    for dat_file in dat_files:
        dat_path = dat_file.get("extracted_path")
        if not dat_path or not os.path.isfile(dat_path):
            log("warn", f"DAT file not found on disk: {dat_file['path']}")
            stats["failed"] += 1
            continue

        csv_name = Path(dat_file["path"]).stem + ".csv"
        csv_path = os.path.join(csv_dir, csv_name)

        log("info", f"Converting: {dat_file['path']}")

        conv_id = manifest_db.new_conversion_id()
        conv_row = {
            "id": conv_id,
            "case_id": case_id,
            "source_file_id": dat_file["id"],
            "csv_path": csv_path,
            "status": "converting",
        }
        manifest_db.insert_conversion(conv_row)

        # Try conversion methods in order
        success = False
        error_msg = None
        row_count = 0
        columns = None

        # Method 1: DatCon
        success, out_path, error_msg, row_count, columns = convert_with_datcon(dat_path, csv_path)
        if success:
            method = "DatCon"
        else:
            log("info", f"  DatCon: {error_msg}")

        # Method 2: dji-log-parser
        if not success:
            success, out_path, error_msg, row_count, columns = convert_with_djilogparser(dat_path, csv_path)
            if success:
                method = "dji-log-parser"
            else:
                log("info", f"  dji-log-parser: {error_msg}")

        # Method 3: raw scan
        if not success:
            success, out_path, error_msg, row_count, columns = convert_raw_scan(dat_path, csv_path)
            if success:
                method = "raw_scan"
            else:
                log("info", f"  raw_scan: {error_msg}")

        # Record result
        if success:
            if error_msg == "EMPTY_OUTPUT":
                status = "EMPTY_OUTPUT"
                stats["empty"] += 1
                log("warn", f"  Conversion produced empty CSV: {dat_file['path']}")
            else:
                status = "SUCCESS"
                stats["success"] += 1
                log("info", f"  OK: {row_count} rows, columns={columns[:5] if columns else 'unknown'}")

            manifest_db.update_conversion(conv_id,
                status=status,
                csv_path=csv_path,
                row_count=row_count,
                columns=json.dumps(columns) if columns else None,
                error_message=error_msg if error_msg else None,
            )
        else:
            stats["failed"] += 1
            manifest_db.update_conversion(conv_id,
                status="FAILED",
                error_message=error_msg,
            )
            log("error", f"  FAILED: {error_msg}")

        conversions.append({"id": conv_id, "status": status if success else "FAILED"})

    log("info", f"Conversion complete: {stats['success']} success, {stats['failed']} failed, {stats['empty']} empty")

    manifest_db.update_case_stage(case_id, "stage4", 70)

    return {"stats": stats, "conversions": conversions}
