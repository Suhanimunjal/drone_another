"""IngestModule base class — every module implements this contract.

Modules write Artifact rows to the shared blackboard (artifacts table).
Other modules read artifacts via query functions.
"""

import json
import traceback
from datetime import datetime, timezone
from pipeline import manifest_db


class Artifact:
    """A single forensic finding from an ingest module.

    Fields map to the `artifacts` table columns.
    """

    def __init__(self, artifact_type, case_id, module_name, file_id=None,
                 parent_artifact_id=None, source=None, title=None,
                 description=None, severity="info", details=None,
                 ts_ref=None, lat=None, lon=None, alt=None,
                 hash_value=None, matched_text=None, byte_offset=None,
                 ignore_in_ui=False):
        self.artifact_type = artifact_type
        self.case_id = case_id
        self.module_name = module_name
        self.file_id = file_id
        self.parent_artifact_id = parent_artifact_id
        self.source = source
        self.title = title
        self.description = description
        self.severity = severity
        self.details = details or {}
        self.ts_ref = ts_ref
        self.lat = lat
        self.lon = lon
        self.alt = alt
        self.hash_value = hash_value
        self.matched_text = matched_text
        self.byte_offset = byte_offset
        self.ignore_in_ui = ignore_in_ui

    def to_row(self):
        """Convert to dict for manifest_db.insert_artifact()."""
        return {
            "id": manifest_db.new_artifact_id(),
            "case_id": self.case_id,
            "module_name": self.module_name,
            "artifact_type": self.artifact_type,
            "file_id": self.file_id,
            "parent_artifact_id": self.parent_artifact_id,
            "source": self.source,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "details": self.details,
            "ts_ref": self.ts_ref,
            "lat": self.lat,
            "lon": self.lon,
            "alt": self.alt,
            "hash_value": self.hash_value,
            "matched_text": self.matched_text,
            "byte_offset": self.byte_offset,
            "ignore_in_ui": self.ignore_in_ui,
        }

    def save(self):
        """Write this artifact to the DB."""
        manifest_db.insert_artifact(self.to_row())

    @staticmethod
    def error(case_id, module_name, file_id, message):
        """Create a standardized TSK_MODULE_ERROR artifact."""
        return Artifact(
            artifact_type="TSK_MODULE_ERROR",
            case_id=case_id,
            module_name=module_name,
            file_id=file_id,
            severity="error",
            title=f"{module_name}: per-file error",
            description=message,
        )


class IngestModule:
    """Base class for all ingest modules.

    Subclasses must set:
        name: str              — unique module identifier
        depends_on: list[str]  — module names that must run first
        applies_to: str        — "all_files" | "specific_extension" | "case_level" | "post_extraction"
        supported_types: list  — file_types or extensions this module handles (for applies_to=specific_extension)
    """

    name = "unnamed_module"
    depends_on = []
    applies_to = "all_files"
    supported_types = []

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        """Run this module. Returns list[Artifact].

        Must not raise on a single bad file — catch per-file errors,
        emit a TSK_MODULE_ERROR artifact, and continue.
        """
        raise NotImplementedError

    def run_batch(self, case_id, file_rows, case_context=None, log_cb=None):
        """Batch wrapper: creates a module_run record, runs per-file (or case-level),
        writes artifacts to DB, updates run stats.

        Returns dict with stats: {files_processed, artifacts_created, errors}
        """
        from .. import manifest_db as db

        run_id = db.new_module_run_id()
        run_row = {
            "id": run_id,
            "case_id": case_id,
            "module_name": self.name,
            "status": "running",
            "files_processed": 0,
            "artifacts_created": 0,
            "errors": 0,
        }
        db.insert_module_run(run_row)

        files_processed = 0
        artifacts_created = 0
        errors = 0

        if self.applies_to == "case_level":
            # Run once for the whole case
            try:
                artifacts = self.run(file_manifest_row=None, case_context=case_context, log_cb=log_cb)
                for art in artifacts:
                    art.save()
                    artifacts_created += 1
            except Exception as e:
                errors += 1
                if log_cb:
                    log_cb("error", f"[{self.name}] case-level error: {e}")
                Artifact.error(case_id, self.name, None, traceback.format_exc()).save()
                artifacts_created += 1
            files_processed = 1  # case-level = 1 unit of work

        else:
            # Per-file processing
            filtered = []
            if self.applies_to == "specific_extension":
                filtered = [f for f in file_rows if self._matches_file(f)]
            else:
                filtered = file_rows

            for f in filtered:
                try:
                    artifacts = self.run(file_manifest_row=f, case_context=case_context, log_cb=log_cb)
                    for art in artifacts:
                        art.save()
                        artifacts_created += 1
                    files_processed += 1
                except Exception as e:
                    errors += 1
                    if log_cb:
                        log_cb("error", f"[{self.name}] error on {f.get('path','?')}: {e}")
                    Artifact.error(case_id, self.name, f.get("id"), traceback.format_exc()).save()
                    artifacts_created += 1

        # Update run record
        db.finish_module_run(run_id, "completed" if errors == 0 else "completed_with_errors")
        with db._lock:
            conn = db.get_db()
            try:
                conn.execute(
                    "UPDATE module_runs SET files_processed=?, artifacts_created=?, errors=? WHERE id=?",
                    (files_processed, artifacts_created, errors, run_id))
                conn.commit()
            finally:
                conn.close()

        if log_cb:
            log_cb("info", f"[{self.name}] done: {files_processed} files, {artifacts_created} artifacts, {errors} errors")

        return {"files_processed": files_processed, "artifacts_created": artifacts_created, "errors": errors}

    def _matches_file(self, f):
        """Check if a file matches this module's supported_types."""
        if not self.supported_types:
            return True
        ext = (f.get("path") or "").lower()
        ftype = (f.get("file_type") or "").upper()
        for t in self.supported_types:
            if ext.endswith(t.lower()) or ftype == t.upper():
                return True
        return False
