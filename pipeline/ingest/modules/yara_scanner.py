"""P3 — YARA Rule Scanner.

Scans files against YARA rules stored in the case DB or loaded from .yar files.
"""

import os
import json
from ..base import IngestModule, Artifact
from ... import manifest_db

YARA_DIRS = ["yara_rules", "rules", "../yara_rules", "../rules"]


def _load_yara_rules(case_id):
    """Load YARA rules from DB and from .yar files on disk."""
    rules = []

    # From DB
    db_rules = manifest_db.get_yara_rules(case_id)
    for r in db_rules:
        rules.append({"name": r["name"], "text": r["rule_text"], "source": "db"})

    # From .yar files
    for d in YARA_DIRS:
        resolved = os.path.join(os.getcwd(), d)
        if os.path.isdir(resolved):
            for fname in os.listdir(resolved):
                if fname.endswith((".yar", ".yara")):
                    fpath = os.path.join(resolved, fname)
                    try:
                        with open(fpath, "r") as f:
                            text = f.read()
                        rules.append({"name": fname, "text": text, "source": fpath})
                    except Exception:
                        continue

    return rules


class YaraScannerModule(IngestModule):
    name = "yara_scanner"
    depends_on = []
    applies_to = "all_files"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not file_manifest_row:
            return []

        file_path = file_manifest_row.get("extracted_path")
        case_id = file_manifest_row.get("case_id")
        file_id = file_manifest_row.get("id")
        rel_path = file_manifest_row.get("path", "")

        if not file_path or not os.path.isfile(file_path):
            return []

        try:
            import yara
        except ImportError:
            return []

        rules = _load_yara_rules(case_id)
        if not rules:
            return []

        results = []
        for rule_entry in rules:
            try:
                compiled = yara.compile(source=rule_entry["text"])
                matches = compiled.match(file_path)
                for m in matches:
                    results.append(Artifact(
                        artifact_type="TSK_YARA_MATCH",
                        case_id=case_id,
                        module_name=self.name,
                        file_id=file_id,
                        severity="high",
                        title=f"YARA: {m.rule}",
                        description=f"Matched rule '{m.rule}' in {os.path.basename(rel_path)}",
                        details={
                            "rule_name": m.rule,
                            "rule_source": rule_entry["source"],
                            "strings": [(str(s.identifier), s.instances[0].offset, s.instances[0].matched_data.decode("utf-8", errors="replace"))
                                        for s in m.strings] if hasattr(m, "strings") else [],
                            "tags": list(m.tags) if hasattr(m, "tags") else [],
                        },
                    ))
            except Exception:
                continue

        return results
