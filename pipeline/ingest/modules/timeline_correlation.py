"""P3 — Timeline Correlation.

Cross-correlates timeline events to detect patterns:
- Media files created just before/after flight events
- Keyword hits near flight takeoff/landing coordinates
- Multiple events clustered in time
"""

import json
from datetime import datetime
from ..base import IngestModule, Artifact
from ... import manifest_db

PROXIMITY_WINDOW_S = 600  # 10 min
MEDIA_TYPES = {"TSK_EXIF_DATA", "TSK_CARVED_FILE"}
FLIGHT_TYPES = {"TSK_FLIGHT_ANALYSIS"}
KEYWORD_TYPES = {"TSK_KEYWORD_HIT"}


def _parse_ts(ts_str):
    if not ts_str:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S.%f", "%H:%M:%S"):
        try:
            return datetime.strptime(ts_str.strip(), fmt)
        except ValueError:
            continue
    return None


def _ts_delta_seconds(a, b):
    ta = _parse_ts(a)
    tb = _parse_ts(b)
    if ta and tb:
        return abs((ta - tb).total_seconds())
    return None


class TimelineCorrelationModule(IngestModule):
    name = "timeline_correlation"
    depends_on = ["timeline", "flight_reconstruction"]
    applies_to = "case_level"

    def run(self, file_manifest_row=None, case_context=None, log_cb=None):
        if not case_context:
            return []

        case_id = case_context.get("case_id")
        if not case_id:
            return []

        artifacts = []

        # Get all artifacts with timestamps
        all_arts = manifest_db.get_artifact_timeline(case_id)

        # Group by type
        media = [a for a in all_arts if a.get("artifact_type") in MEDIA_TYPES and a.get("ts_ref")]
        flights = [a for a in all_arts if a.get("artifact_type") in FLIGHT_TYPES and a.get("ts_ref")]
        keywords = [a for a in all_arts if a.get("artifact_type") in KEYWORD_TYPES]

        # Media near flights
        for m in media:
            for f in flights:
                delta = _ts_delta_seconds(m.get("ts_ref"), f.get("ts_ref"))
                if delta is not None and delta <= PROXIMITY_WINDOW_S:
                    artifacts.append(Artifact(
                        artifact_type="TSK_TIMELINE_CORRELATION",
                        case_id=case_id,
                        module_name=self.name,
                        file_id=m.get("file_id"),
                        parent_artifact_id=m.get("id"),
                        severity="medium",
                        title=f"Media near flight: {m.get('title','')[:40]}",
                        description=(f"Media {delta:.0f}s from flight event — "
                                     f"photo may document the flight"),
                        details={
                            "correlation_type": "media_near_flight",
                            "delta_seconds": round(delta, 1),
                            "media_artifact_id": m.get("id"),
                            "media_type": m.get("artifact_type"),
                            "flight_artifact_id": f.get("id"),
                            "flight_title": f.get("title"),
                        },
                        ts_ref=m.get("ts_ref"),
                        lat=m.get("lat"),
                        lon=m.get("lon"),
                    ))

        # Keywords near flight coordinates
        for kw in keywords:
            kw_details = kw.get("details_json")
            try:
                kw_details = json.loads(kw_details) if isinstance(kw_details, str) else (kw_details or {})
            except (json.JSONDecodeError, TypeError):
                continue

            kw_text = kw_details.get("matched_text", "")
            if not kw_text:
                continue

            for f in flights:
                f_details = f.get("details_json")
                try:
                    f_details = json.loads(f_details) if isinstance(f_details, str) else (f_details or {})
                except (json.JSONDecodeError, TypeError):
                    continue

                # Check if keyword matched text appears to be location-related
                if any(kw in kw_text.lower() for kw in ["lat", "lon", "coord", "gps", "drone", "dji"]):
                    artifacts.append(Artifact(
                        artifact_type="TSK_TIMELINE_CORRELATION",
                        case_id=case_id,
                        module_name=self.name,
                        file_id=kw.get("file_id"),
                        parent_artifact_id=kw.get("id"),
                        severity="low",
                        title=f"Keyword near flight data: {kw_text[:40]}",
                        description=f"Keyword '{kw_text[:60]}' in file near flight analysis",
                        details={
                            "correlation_type": "keyword_near_flight",
                            "keyword": kw_text[:100],
                            "keyword_artifact_id": kw.get("id"),
                            "flight_artifact_id": f.get("id"),
                            "flight_title": f.get("title"),
                        },
                    ))

        return artifacts
