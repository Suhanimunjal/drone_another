"""C1 — File Type Identification via libmagic (content-based, not extension).

Every file: detect true MIME type via python-magic, store as
TSK_FILE_TYPE_SIG artifact alongside Stage 3's extension-based guess.
"""

import os
import traceback
from ..base import IngestModule, Artifact


class FileTypeIdModule(IngestModule):
    name = "file_type_id"
    depends_on = []
    applies_to = "all_files"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not file_manifest_row:
            return []

        file_path = file_manifest_row.get("extracted_path")
        if not file_path or not os.path.isfile(file_path):
            return []

        mime_type = None
        try:
            import magic
            mime_type = magic.from_file(file_path, mime=True)
        except ImportError:
            # No python-magic — try file command as fallback
            try:
                import subprocess
                result = subprocess.run(
                    ["file", "--mime-type", "-b", file_path],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    mime_type = result.stdout.strip()
            except Exception:
                pass
        except Exception:
            pass

        if not mime_type:
            return []

        ext_guess = file_manifest_row.get("file_type") or "OTHER"

        return [
            Artifact(
                artifact_type="TSK_FILE_TYPE_SIG",
                case_id=file_manifest_row.get("case_id"),
                module_name=self.name,
                file_id=file_manifest_row.get("id"),
                source="libmagic",
                title=f"Detected: {mime_type}",
                description=f"Signature-based type: {mime_type} (extension guess: {ext_guess})",
                details={
                    "mime_type": mime_type,
                    "extension_guess": ext_guess,
                    "size_bytes": file_manifest_row.get("size_bytes"),
                },
                ignore_in_ui=False,
            )
        ]
