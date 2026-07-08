"""P4 — Report Generator.

Generates an HTML/Markdown report summarizing all case findings.
Emits TSK_REPORT artifact pointing to the generated report file.
"""

import os
import json
from datetime import datetime, timezone
from ..base import IngestModule, Artifact
from ... import manifest_db

REPORT_DIR = "reports"


class ReportingModule(IngestModule):
    name = "reporting"
    depends_on = []
    applies_to = "case_level"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not case_context:
            return []

        case_id = case_context.get("case_id")
        output_dir = case_context.get("output_dir", "")
        if not case_id:
            return []

        case = manifest_db.get_case(case_id)
        if not case:
            return []

        all_arts = manifest_db.get_artifacts(case_id)
        files = manifest_db.get_case_files(case_id)
        tags = manifest_db.get_tags(case_id)
        type_counts = manifest_db.get_artifact_count_by_type(case_id)

        # Group artifacts by type
        by_type = {}
        for art in all_arts:
            by_type.setdefault(art.get("artifact_type", "OTHER"), []).append(art)

        report_dir = os.path.join(output_dir, REPORT_DIR)
        os.makedirs(report_dir, exist_ok=True)

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Build Markdown report
        md = []
        md.append(f"# Forensic Case Report: {os.path.basename(case.get('source_file',''))}")
        md.append(f"**Case ID:** {case_id}")
        md.append(f"**Generated:** {now}")
        md.append(f"**Status:** {case.get('status','')} (Stage: {case.get('stage','')})")
        md.append("")
        md.append("## Case Metadata")
        md.append(f"- Source file: `{case.get('source_file','')}`")
        md.append(f"- Detected format: {case.get('detected_format','')}")
        md.append(f"- Hash: {case.get('hash_algorithm','')} = `{case.get('hash_value','')[:32]}...`")
        md.append(f"- Media size: {case.get('media_size_bytes',0):,} bytes")
        md.append("")
        md.append("## Files")
        md.append(f"- Total extracted: {len(files)}")
        md.append(f"- Deleted files: {sum(1 for f in files if f.get('is_deleted'))}")
        md.append(f"- DAT flight logs: {type_counts.get('DAT_LOG', 0)}")
        md.append("")
        md.append("## Artifact Summary")
        md.append(f"| Type | Count |")
        md.append(f"|------|-------|")
        for atype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            md.append(f"| {atype} | {count} |")
        md.append("")
        md.append("## Findings by Severity")
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for art in all_arts:
            sev = art.get("severity", "info")
            if sev in severities:
                severities[sev] += 1
        for sev, count in severities.items():
            if count:
                md.append(f"- **{sev.upper()}**: {count}")
        md.append("")
        md.append("## Flights Detected")
        flight_arts = [a for a in all_arts if a.get("artifact_type") == "TSK_FLIGHT_ANALYSIS"]
        if flight_arts:
            for fa in flight_arts:
                d = fa.get("details_json")
                try:
                    d = json.loads(d) if isinstance(d, str) else (d or {})
                except Exception:
                    d = {}
                to = d.get("takeoff", {})
                lo = d.get("landing", {})
                md.append(f"- {fa.get('title','')}")
                md.append(f"  - Takeoff: ({to.get('latitude','?')}, {to.get('longitude','?')}) @ {to.get('timestamp','?')}")
                md.append(f"  - Landing: ({lo.get('latitude','?')}, {lo.get('longitude','?')}) @ {lo.get('timestamp','?')}")
                md.append(f"  - Max alt: {d.get('max_altitude_m','?')}m, Duration: {d.get('flight_duration_seconds','?')}s")
        else:
            md.append("- No flights detected")
        md.append("")
        md.append("## Tags Applied")
        if tags:
            for t in tags:
                art_count = sum(1 for a in all_arts if any(
                    True for at in (manifest_db.get_artifact_tags(a["id"]) or [])
                    if at.get("id") == t["id"]
                ))
                md.append(f"- **{t['name']}** (`{t.get('color','')}`) — {art_count} artifacts")
        md.append("")
        md.append("---")
        md.append("*Report generated automatically by Drone Forensic Pipeline*")

        report_name = f"case_report_{case_id[:8]}.md"
        report_path = os.path.join(report_dir, report_name)
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md))

        return [
            Artifact(
                artifact_type="TSK_REPORT",
                case_id=case_id,
                module_name=self.name,
                severity="info",
                title=f"Case report: {report_name}",
                description=f"Markdown report with {len(all_arts)} artifacts, {len(files)} files",
                details={
                    "report_path": report_path,
                    "report_format": "markdown",
                    "artifact_count": len(all_arts),
                    "file_count": len(files),
                    "tag_count": len(tags),
                },
            )
        ]
