"""D3 — GPX Export from flight analysis data.

Reads TSK_FLIGHT_ANALYSIS artifacts and writes GPX track files.
"""

import os
import json
from datetime import datetime, timezone
from ..base import IngestModule, Artifact
from ... import manifest_db


def _gpx_timestamp(ts_str):
    """Convert a timestamp string to ISO-8601 for GPX."""
    if not ts_str:
        return datetime.now(timezone.utc).isoformat()
    return ts_str


def _build_gpx(flight_analysis, output_path):
    """Generate a GPX 1.1 track file from a flight analysis dict."""
    details = flight_analysis.get("details") or {}
    trajectory = details.get("trajectory", [])

    gpx = []
    gpx.append('<?xml version="1.0" encoding="UTF-8"?>')
    gpx.append('<gpx version="1.1" creator="Drone Forensic Pipeline"')
    gpx.append('  xmlns="http://www.topografix.com/GPX/1/1"')
    gpx.append('  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"')
    gpx.append('  xsi:schemaLocation="http://www.topografix.com/GPX/1/1 http://www.topografix.com/GPX/1/1/gpx.xsd">')
    gpx.append('  <trk>')
    gpx.append(f'    <name>Flight {os.path.splitext(os.path.basename(output_path))[0]}</name>')
    gpx.append('    <trkseg>')

    for pt in trajectory:
        lat = pt.get("latitude")
        lon = pt.get("longitude")
        alt = pt.get("altitude", 0)
        ts = pt.get("time", "")
        if lat is not None and lon is not None:
            gpx.append(f'      <trkpt lat="{lat}" lon="{lon}">')
            gpx.append(f'        <ele>{alt}</ele>')
            gpx.append(f'        <time>{_gpx_timestamp(ts)}</time>')
            gpx.append('      </trkpt>')

    gpx.append('    </trkseg>')
    gpx.append('  </trk>')
    gpx.append('</gpx>')

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(gpx) + "\n")


class GpxExportModule(IngestModule):
    name = "gpx_export"
    depends_on = ["flight_reconstruction"]
    applies_to = "case_level"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not case_context:
            return []

        case_id = case_context.get("case_id")
        output_dir = case_context.get("output_dir", "")
        if not case_id:
            return []

        artifacts = []
        flight_arts = manifest_db.get_artifacts(case_id, artifact_type="TSK_FLIGHT_ANALYSIS")

        gpx_dir = os.path.join(output_dir, "gpx")
        os.makedirs(gpx_dir, exist_ok=True)

        for i, art in enumerate(flight_arts):
            details = art.get("details_json")
            try:
                details = json.loads(details) if isinstance(details, str) else (details or {})
            except (json.JSONDecodeError, TypeError):
                continue

            gpx_name = f"flight_{i+1}.gpx"
            gpx_path = os.path.join(gpx_dir, gpx_name)

            try:
                art_dict = dict(art)
                art_dict["details"] = details
                _build_gpx(art_dict, gpx_path)
                artifacts.append(Artifact(
                    artifact_type="TSK_GPX_EXPORTED",
                    case_id=case_id,
                    module_name=self.name,
                    file_id=art.get("file_id"),
                    parent_artifact_id=art.get("id"),
                    title=f"GPX: {gpx_name}",
                    description=f"GPX track exported ({len(details.get('trajectory', []))} points)",
                    details={"gpx_path": gpx_path, "point_count": len(details.get("trajectory", []))},
                ))
            except Exception as e:
                artifacts.append(Artifact.error(case_id, self.name, art.get("file_id"), f"GPX export failed: {e}"))

        return artifacts
