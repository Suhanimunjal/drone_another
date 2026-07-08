"""P3 — Cross-Case Repository.

Indexes all artifacts from a case into a shared cross_case_index table,
enabling searching across multiple cases for common hashes, emails, etc.
"""

import json
from ..base import IngestModule, Artifact
from ... import manifest_db


class CrossCaseRepoModule(IngestModule):
    name = "cross_case_repo"
    depends_on = []
    applies_to = "case_level"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not case_context:
            return []

        case_id = case_context.get("case_id")
        if not case_id:
            return []

        # Index all artifacts from this case
        all_arts = manifest_db.get_artifacts(case_id)
        indexed = 0

        for art in all_arts:
            if art.get("ignore_in_ui"):
                continue

            file_path = None
            if art.get("file_id"):
                f = manifest_db.get_file(art["file_id"])
                if f:
                    file_path = f.get("path")

            manifest_db.insert_cci_row({
                "id": manifest_db.new_cci_id(),
                "case_id": case_id,
                "artifact_id": art.get("id"),
                "artifact_type": art.get("artifact_type"),
                "module_name": art.get("module_name"),
                "file_path": file_path,
                "file_id": art.get("file_id"),
                "lat": art.get("lat"),
                "lon": art.get("lon"),
                "ts_ref": art.get("ts_ref"),
                "hash_value": art.get("hash_value"),
                "matched_text": art.get("matched_text"),
                "title": art.get("title"),
                "description": art.get("description"),
                "severity": art.get("severity"),
            })
            indexed += 1

        return [
            Artifact(
                artifact_type="TSK_CROSS_CASE_INDEXED",
                case_id=case_id,
                module_name=self.name,
                severity="info",
                title=f"Cross-case index: {indexed} artifacts",
                description=f"Indexed {indexed} artifacts from case {case_id[:8]} into shared repository",
                details={"indexed_count": indexed, "case_id": case_id},
            )
        ]
