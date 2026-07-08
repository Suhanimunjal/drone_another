"""P4 — Automated Tagging.

Applies tags to artifacts based on rules:
- High-severity artifacts get "needs_review" tag
- Flight analysis artifacts get "flight" tag
- Keyword hits get "keyword" tag
- Extension mismatches get "anomaly" tag
- Carved files get "carved" tag
"""

from ..base import IngestModule, Artifact
from ... import manifest_db

TAG_RULES = {
    "needs_review": {"types": [], "min_severity": "high", "color": "#ff4444"},
    "flight": {"types": ["TSK_FLIGHT_ANALYSIS", "TSK_DAT_CONVERTED", "TSK_GPX_EXPORTED"], "color": "#44aaff"},
    "keyword": {"types": ["TSK_KEYWORD_HIT"], "color": "#ffaa00"},
    "anomaly": {"types": ["TSK_EXTENSION_MISMATCH"], "color": "#ff6600"},
    "carved": {"types": ["TSK_CARVED_FILE"], "color": "#aa44ff"},
    "geo_photo": {"types": ["TSK_EXIF_DATA"], "color": "#44ff66"},
    "correlation": {"types": ["TSK_TIMELINE_CORRELATION", "TSK_PHOTO_FLIGHT_MATCH"], "color": "#ff44aa"},
}


class TaggingModule(IngestModule):
    name = "tagging"
    depends_on = []
    applies_to = "case_level"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not case_context:
            return []

        case_id = case_context.get("case_id")
        if not case_id:
            return []

        SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        # Ensure all tag definitions exist
        tag_ids = {}
        for tag_name, rule in TAG_RULES.items():
            tag = manifest_db.create_tag(case_id, tag_name, color=rule.get("color", "#3388ff"))
            if tag:
                tag_ids[tag_name] = tag["id"]
            else:
                existing = manifest_db.get_tags(case_id)
                for t in existing:
                    if t["name"] == tag_name:
                        tag_ids[tag_name] = t["id"]
                        break

        # Apply tags to matching artifacts
        all_arts = manifest_db.get_artifacts(case_id)
        tag_count = 0

        for art in all_arts:
            art_type = art.get("artifact_type", "")
            art_sev = art.get("severity", "info")

            for tag_name, rule in TAG_RULES.items():
                tag_id = tag_ids.get(tag_name)
                if not tag_id:
                    continue

                match = False
                if rule.get("types") and art_type in rule["types"]:
                    match = True
                if "min_severity" in rule:
                    if SEVERITY_RANK.get(art_sev, 99) <= SEVERITY_RANK.get(rule["min_severity"], 99):
                        match = True

                if match:
                    manifest_db.tag_artifact(art["id"], tag_id)
                    tag_count += 1

        return [
            Artifact(
                artifact_type="TSK_TAGGING_COMPLETE",
                case_id=case_id,
                module_name=self.name,
                severity="info",
                title=f"Auto-tagging: {tag_count} tags applied",
                description=f"Applied {tag_count} automated tags across {len(all_arts)} artifacts",
                details={"tag_count": tag_count, "artifact_count": len(all_arts)},
            )
        ]
