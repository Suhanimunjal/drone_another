"""C2 — Extension Mismatch Detector.

Flags files where the claimed extension doesn't match the detected MIME type.
Compares C1's TSK_FILE_TYPE_SIG artifact against the file's extension.
"""

import os
from ..base import IngestModule, Artifact
from ... import manifest_db

# Known extension -> expected MIME types (maintained mapping table)
EXTENSION_MAP = {
    ".jpg":  {"image/jpeg", "image/jpg"},
    ".jpeg": {"image/jpeg", "image/jpg"},
    ".png":  {"image/png"},
    ".gif":  {"image/gif"},
    ".bmp":  {"image/bmp"},
    ".tiff": {"image/tiff"},
    ".tif":  {"image/tiff"},
    ".dng":  {"image/x-adobe-dng", "image/dng"},
    ".mp4":  {"video/mp4"},
    ".mov":  {"video/quicktime"},
    ".avi":  {"video/x-msvideo"},
    ".mkv":  {"video/x-matroska"},
    ".zip":  {"application/zip"},
    ".gz":   {"application/gzip"},
    ".tar":  {"application/x-tar"},
    ".7z":   {"application/x-7z-compressed"},
    ".rar":  {"application/vnd.rar"},
    ".pdf":  {"application/pdf"},
    ".doc":  {"application/msword"},
    ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    ".xls":  {"application/vnd.ms-excel"},
    ".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    ".xml":  {"text/xml", "application/xml"},
    ".json": {"application/json"},
    ".csv":  {"text/csv", "text/plain"},
    ".txt":  {"text/plain"},
    ".html": {"text/html"},
    ".htm":  {"text/html"},
    ".exe":  {"application/x-dosexec", "application/x-msdownload", "application/vnd.microsoft.portable-executable"},
    ".dll":  {"application/x-msdownload"},
    ".bin":  {"application/octet-stream", "application/x-binary"},
    ".dat":  {"application/octet-stream"},
    ".log":  {"text/plain"},
    ".cfg":  {"text/plain"},
    ".ini":  {"text/plain"},
    ".srt":  {"text/plain", "application/x-subrip"},
}


class ExtensionMismatchModule(IngestModule):
    name = "extension_mismatch"
    depends_on = ["file_type_id"]  # Needs C1's TSK_FILE_TYPE_SIG artifacts first
    applies_to = "all_files"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not file_manifest_row:
            return []

        file_id = file_manifest_row.get("id")
        case_id = file_manifest_row.get("case_id")
        path = file_manifest_row.get("path") or ""
        ext = os.path.splitext(path)[1].lower()

        if not ext or ext not in EXTENSION_MAP:
            return []

        expected_mimes = EXTENSION_MAP[ext]

        # Read C1 artifact for this file
        arts = manifest_db.get_artifacts(case_id, artifact_type="TSK_FILE_TYPE_SIG", file_id=file_id)

        for art in arts:
            details = art.get("details_json")
            import json
            try:
                details = json.loads(details) if isinstance(details, str) else (details or {})
            except (json.JSONDecodeError, TypeError):
                continue

            actual_mime = details.get("mime_type", "")
            if actual_mime and actual_mime not in expected_mimes:
                return [
                    Artifact(
                        artifact_type="TSK_EXTENSION_MISMATCH",
                        case_id=case_id,
                        module_name=self.name,
                        file_id=file_id,
                        parent_artifact_id=art.get("id"),
                        severity="medium",
                        title=f"Extension mismatch: {ext} -> {actual_mime}",
                        description=f"File ends with '{ext}' but content is '{actual_mime}'",
                        details={
                            "extension": ext,
                            "expected_mimes": list(expected_mimes),
                            "actual_mime": actual_mime,
                            "path": path,
                        },
                    )
                ]

        return []
