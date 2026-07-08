"""C7 — Interesting Files Detector.

Flags files by path pattern: hidden files, temp files, configs with credentials,
executables in user dirs, archive files in unusual locations, etc.
"""

import os
import re
from ..base import IngestModule, Artifact

RULES = [
    ("HIDDEN_FILE", r"(^|[/\\])\.[^/\\]+", "Hidden file (dotfile)"),
    ("TEMP_FILE", r"(\.tmp$|\.temp$|~$)", "Temporary file"),
    ("CONFIG_CRED", r"(config|credential|password|secret|\.env|\.key|token)", "Config/credential file (path match)"),
    ("BACKUP_FILE", r"(\.bak$|\.backup$|\.old$|\.orig$)", "Backup file"),
    ("EXECUTABLE_USER_DIR", r"(Users|home|Documents|Desktop|Downloads).+\.(exe|dll|bat|ps1|sh)$", "Executable in user directory"),
    ("ARCHIVE_ORPHAN", r".+\.(zip|rar|7z|tar\.gz|tgz)$", "Archive file"),
    ("DAT_ORPHAN", r".+\.dat$", "DAT file (flight log candidate)"),
    ("LOG_FILE", r".+\.log$", "Log file"),
    ("RECYCLE_BIN", r"(\\\$Recycle\.Bin|\\\.Trash|\\RECYCLER)", "File in recycle/trash"),
    ("PAGE_FILE", r"(pagefile\.sys|swapfile\.sys|hiberfil\.sys)", "System page/swap file"),
]


class InterestingFilesModule(IngestModule):
    name = "interesting_files"
    depends_on = []
    applies_to = "all_files"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not file_manifest_row:
            return []

        path = file_manifest_row.get("path", "")
        case_id = file_manifest_row.get("case_id")
        file_id = file_manifest_row.get("id")

        results = []
        for rule_name, pattern, description in RULES:
            if re.search(pattern, path, re.IGNORECASE):
                results.append(Artifact(
                    artifact_type="TSK_INTERESTING_FILE",
                    case_id=case_id,
                    module_name=self.name,
                    file_id=file_id,
                    severity="low",
                    title=f"{description}: {os.path.basename(path)}",
                    description=f"Matched rule '{rule_name}' for {path}",
                    details={
                        "rule_name": rule_name,
                        "rule_description": description,
                        "matched_path": path,
                    },
                ))
        return results
