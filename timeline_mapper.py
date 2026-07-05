"""timeline_mapper.py

Maps DroneFlightViewer's events[], anomalies[], and modes[] to the dashboard's
TimelineEvents format.

Dashboard JS expects (via /api/flight-logs → data.timeline):
    [{"time", "label", "detail", "type", ...}]

DB save reads the same events and maps to columns:
    time_label <- time, event_type <- type
"""

from __future__ import annotations

from typing import Any


def _resolve_time(time_label: str) -> str:
    return time_label


def _resolve_type(event_type: str) -> str:
    if event_type == "anomaly":
        return "warning"
    return event_type


def map_to_timeline_events(parsed_log: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert parse_log() events/modes/anomalies to dashboard timeline format."""
    events: list[dict[str, Any]] = []
    started_at = parsed_log.get("started_at")

    # Convert raw events (STATUSTEXT, MSG, ERR, EV)
    for ev in parsed_log.get("events", []):
        t = ev.get("t")
        time_label = _fmt_time(t, started_at)
        severity = ev.get("severity")

        if severity is not None and severity <= 3:
            event_type = "critical"
        elif severity is not None and severity <= 5:
            event_type = "warning"
        else:
            event_type = "normal"

        events.append(_ev(time_label, ev.get("type", "EVENT"), ev.get("message", ""), event_type, "telemetry"))

    # Convert mode changes
    for mode in parsed_log.get("modes", []):
        t = mode.get("t")
        time_label = _fmt_time(t, started_at)
        name = mode.get("name") or f"Mode {mode.get('num', '?')}"
        events.append(_ev(time_label, f"Mode: {name}", f"Flight mode changed to {name}", "normal", "telemetry"))

    # Convert anomalies
    for anom in parsed_log.get("anomalies", []):
        t = anom.get("t")
        time_label = _fmt_time(t, started_at) if t is not None else "--"
        kind = anom.get("kind", "anomaly")

        if kind in ("gps_gap",):
            event_type = "warning"
        elif kind in ("gps_jump", "alt_jump", "battery_anomaly"):
            event_type = "critical"
        elif kind == "waypoint_outlier":
            event_type = "anomaly"
        else:
            event_type = "warning"

        events.append(_ev(time_label, kind, anom.get("detail", ""), event_type, "forensic"))

    # Add flight summary markers
    track = parsed_log.get("track", [])
    if track:
        events.insert(0, _ev(
            _fmt_time(0, started_at),
            "First GPS Fix",
            f"({track[0]['lat']:.5f}, {track[0]['lon']:.5f}) alt {track[0]['alt']:.0f}m",
            "normal", "telemetry",
        ))
        events.append(_ev(
            _fmt_time(track[-1].get("t", 0), started_at),
            "Last GPS Fix",
            f"({track[-1]['lat']:.5f}, {track[-1]['lon']:.5f}) alt {track[-1]['alt']:.0f}m",
            "normal", "telemetry",
        ))

    # Sort by time_label
    events.sort(key=lambda e: e.get("time_label", ""))

    return events


def _ev(time_label: str, label: str, detail: str, event_type: str, source: str) -> dict[str, Any]:
    """Build an event dict with BOTH sets of keys for dashboard JS and DB save."""
    return {
        "time": time_label,
        "label": label,
        "detail": detail,
        "type": event_type,
        "time_label": time_label,
        "event_type": event_type,
        "source": source,
    }


def _fmt_time(t: float | None, started_at: str | None = None) -> str:
    """Format relative time T+XXXs or wall-clock."""
    if t is None:
        return "--"
    return f"T+{t:.1f}s"
