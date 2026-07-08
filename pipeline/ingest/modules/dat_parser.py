"""D1 — DAT Flight Log Parser.

Per-file conversion of DJI .DAT flight logs to CSV.
Chains existing Stage 4 logic: DatCon -> dji-log-parser -> raw scan.
"""

import os
import json
import csv
import subprocess
from pathlib import Path

from ..base import IngestModule, Artifact


# ── Conversion helpers (ported from stage4_dat_to_csv) ──────────────────────

def _find_datcon():
    candidates = [
        os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools", "DatCon.jar"),
        os.path.join(os.path.dirname(__file__), "..", "..", "DatCon.jar"),
        r"C:\tools\DatCon.jar",
        r"C:\DatCon\DatCon.jar",
    ]
    for c in candidates:
        abs_c = os.path.abspath(c)
        if os.path.isfile(abs_c):
            return abs_c
    return None


def _verify_csv(csv_path):
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                return False, 0, header
            row_count = sum(1 for _ in reader)
            return True, row_count, header
    except Exception:
        return False, 0, None


def _convert_datcon(dat_path, csv_path):
    jar = _find_datcon()
    if not jar:
        return None
    # Skip tiny files (real DJI DAT is at least 1 MB)
    if os.path.getsize(dat_path) < 1024:
        return None, "File too small for DatCon"
    try:
        result = subprocess.run(
            ["java", "-jar", jar, "-infile", dat_path, "-outfile", csv_path, "-timezone", "UTC"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return None, f"DatCon: {result.stderr[:200]}"
        if not os.path.isfile(csv_path):
            alt = csv_path.replace(".csv", "-C.csv")
            if os.path.isfile(alt):
                os.rename(alt, csv_path)
            else:
                return None, "DatCon produced no output"
        ok, rc, hdr = _verify_csv(csv_path)
        if ok:
            return {"method": "DatCon", "row_count": rc, "columns": hdr[:10]}, None
        return None, "DatCon: unreadable CSV"
    except FileNotFoundError:
        return None, "Java not found"
    except subprocess.TimeoutExpired:
        return None, "DatCon timed out"


def _convert_djilogparser(dat_path, csv_path):
    try:
        from dji_log_parser import DJIFlightLog
    except ImportError:
        return None, "dji-log-parser not installed"
    try:
        log = DJIFlightLog(dat_path)
        df = log.to_dataframe()
        if df is None or df.empty:
            return None, "dji-log-parser empty"
        df.to_csv(csv_path, index=False)
        ok, rc, hdr = _verify_csv(csv_path)
        if ok:
            return {"method": "dji-log-parser", "row_count": rc, "columns": hdr[:10]}, None
        return None, "dji-log-parser: unreadable CSV"
    except Exception as e:
        return None, f"dji-log-parser: {e}"


def _convert_raw_scan(dat_path, csv_path):
    try:
        with open(dat_path, "rb") as f:
            raw = f.read()
        text = raw.decode("ascii", errors="ignore")
        lines = text.split("\n")
        csv_lines = []
        header_found = False
        for line in lines:
            s = line.strip()
            if not s:
                continue
            if not header_found:
                if any(kw in s.lower() for kw in ["time", "latitude", "longitude", "alt"]):
                    header_found = True
                    csv_lines.append(s)
                continue
            parts = s.split(",")
            if len(parts) >= 3:
                try:
                    [float(p.strip()) for p in parts[:4]]
                    csv_lines.append(s)
                except ValueError:
                    if csv_lines:
                        break
        if len(csv_lines) > 2:
            with open(csv_path, "w", newline="") as f:
                f.write("\n".join(csv_lines) + "\n")
            ok, rc, hdr = _verify_csv(csv_path)
            if ok:
                return {"method": "raw_scan", "row_count": rc, "columns": hdr[:10]}, None
        return None, "No CSV data found"
    except Exception as e:
        return None, f"raw_scan: {e}"


# ── Module ──────────────────────────────────────────────────────────────────

class DatParserModule(IngestModule):
    """D1 — Convert DJI .DAT flight logs to CSV."""

    name = "dat_parser"
    depends_on = []
    applies_to = "specific_extension"
    supported_types = [".dat"]

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not file_manifest_row:
            return []

        case_id = file_manifest_row.get("case_id")
        file_id = file_manifest_row.get("id")
        dat_path = file_manifest_row.get("extracted_path")
        rel_path = file_manifest_row.get("path", "")

        if not dat_path or not os.path.isfile(dat_path):
            return [Artifact.error(case_id, self.name, file_id, "DAT file not on disk")]

        output_dir = (case_context or {}).get("output_dir", os.path.dirname(dat_path))
        csv_dir = os.path.join(output_dir, "csv")
        os.makedirs(csv_dir, exist_ok=True)
        csv_path = os.path.join(csv_dir, Path(rel_path).stem + ".csv")

        for fn in [_convert_datcon, _convert_djilogparser, _convert_raw_scan]:
            result, err = fn(dat_path, csv_path)
            if result is not None:
                return [
                    Artifact(
                        artifact_type="TSK_DAT_CONVERTED",
                        case_id=case_id,
                        module_name=self.name,
                        file_id=file_id,
                        title=f"DAT -> CSV: {Path(rel_path).name}",
                        description=f"Converted via {result['method']}: {result['row_count']} rows",
                        details={
                            "csv_path": csv_path,
                            "method": result["method"],
                            "row_count": result["row_count"],
                            "columns": result["columns"],
                        },
                    )
                ]

        return [
            Artifact(
                artifact_type="TSK_DAT_CONVERTED",
                case_id=case_id,
                module_name=self.name,
                file_id=file_id,
                severity="warning",
                title=f"DAT conversion failed: {Path(rel_path).name}",
                description=f"All conversion methods failed for this DAT. Last error: {err}",
                details={"error": err, "csv_path": csv_path},
            )
        ]
