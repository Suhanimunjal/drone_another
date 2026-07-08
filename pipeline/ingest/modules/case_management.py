"""P4 — Case Management.

Manages case lifecycle: close, reopen, archive, delete.
Also provides case listing and status summaries.
This module primarily exposes API/service functions used by the Flask routes.
"""

import os
from datetime import datetime, timezone
from ..base import IngestModule, Artifact
from ... import manifest_db


class CaseManagementModule(IngestModule):
    name = "case_management"
    depends_on = []
    applies_to = "case_level"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not case_context:
            return []

        case_id = case_context.get("case_id")
        if not case_id:
            return []

        case = manifest_db.get_case(case_id)
        if not case:
            return []

        all_arts = manifest_db.get_artifacts(case_id)
        files = manifest_db.get_case_files(case_id)
        type_counts = manifest_db.get_artifact_count_by_type(case_id)

        return [
            Artifact(
                artifact_type="TSK_CASE_SUMMARY",
                case_id=case_id,
                module_name=self.name,
                severity="info",
                title=f"Case summary: {os.path.basename(case.get('source_file',''))[:40]}",
                description=f"{len(files)} files, {len(all_arts)} artifacts across {len(type_counts)} types",
                details={
                    "file_count": len(files),
                    "artifact_count": len(all_arts),
                    "artifact_type_count": len(type_counts),
                    "status": case.get("status"),
                    "stage": case.get("stage"),
                    "source_file": case.get("source_file"),
                },
            )
        ]
