"""C8 — Timeline Builder.

Reads all artifacts with a ts_ref from the blackboard and emits
TSK_TIMELINE_ENTRY artifacts sorted by timestamp.
"""

import json
from ..base import IngestModule, Artifact
from ... import manifest_db

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sort_key(art):
    ts = str(art.get("ts_ref") or "")
    sev = SEVERITY_ORDER.get(art.get("severity", "info"), 99)
    return (ts, sev)


class TimelineModule(IngestModule):
    name = "timeline"
    depends_on = []  # We read existing artifacts, so dependency is implicit
    applies_to = "case_level"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not case_context:
            return []

        case_id = case_context.get("case_id")
        if not case_id:
            return []

        # Build timeline from every other module's output
        timeline_arts = manifest_db.get_artifact_timeline(case_id)

        # Collect unique artifact types (exclude our own and internal ones)
        exclude_types = {"TSK_TIMELINE_ENTRY", "TSK_MODULE_ERROR", "TSK_HASH_HIT"}
        seen = set()
        entries = []

        for art in timeline_arts:
            if art.get("artifact_type") in exclude_types:
                continue
            key = art.get("id")
            if key in seen:
                continue
            seen.add(key)

            ts_ref = art.get("ts_ref")
            if not ts_ref:
                continue

            entries.append(Artifact(
                artifact_type="TSK_TIMELINE_ENTRY",
                case_id=case_id,
                module_name=self.name,
                file_id=art.get("file_id"),
                parent_artifact_id=art.get("id"),
                severity=art.get("severity", "info"),
                title=art.get("title", ""),
                description=f"[{art.get('artifact_type','?')}] {art.get('description','')}",
                details={
                    "source_artifact_id": art.get("id"),
                    "source_artifact_type": art.get("artifact_type"),
                    "source_module": art.get("module_name"),
                    "source_title": art.get("title"),
                    "file_path": art.get("file_path"),
                },
                ts_ref=ts_ref,
                lat=art.get("lat"),
                lon=art.get("lon"),
            ))

        # Sort by timestamp then severity
        entries.sort(key=_sort_key)
        return entries
