"""timeline_mapper.py

Maps DroneFlightViewer's events[], anomalies[], and modes[] to the dashboard's
TimelineEvents format.

Dashboard JS expects (via /api/flight-logs → data.timeline):
    [{"time", "label", "detail", "type", ...}]

DB save reads the same events and maps to columns:
    time_label <- time, event_type <- type
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


def _resolve_time(time_label: str) -> str:
    return time_label


def _resolve_type(event_type: str) -> str:
    if event_type == "anomaly":
        return "warning"
    return event_type


def map_to_timeline_events(parsed_log: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert parse_log() events/modes/anomalies OR merged flight data to dashboard timeline format."""
    events: list[dict[str, Any]] = []
    started_at = parsed_log.get("started_at")
    source_type = parsed_log.get("_source", "raw")  # "raw" (droneview) or "merged" (flight-log-merged)

    # ── Branch: merged flight log data (path + takeoff/landing/stats) ───────
    path = parsed_log.get("path", [])
    takeoff = parsed_log.get("takeoff", {})
    landing = parsed_log.get("landing", {})
    stats = parsed_log.get("stats", {})

    if path and (takeoff or landing):
        def _rel_ts(ts_str, ref_str):
            """Return relative seconds string 'T+42s' from two timestamp strings."""
            if not ts_str or not ref_str:
                return None
            for fmt in ("%Y-%m-%dT%H:%M:%S","%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S","%Y%m%d %H:%M:%S:%f"):
                try:
                    t = datetime.strptime(str(ts_str).strip(), fmt)
                    r = datetime.strptime(str(ref_str).strip(), fmt)
                    return f"T+{(t - r).total_seconds():.0f}s"
                except ValueError:
                    pass
            return None

        # Reference start time from first path point
        t0 = path[0].get("ts") if path else None

        # First GPS fix from path
        fp = path[0]
        events.append(_ev("T+0s", "First GPS Fix",
            f"({fp.get('lat',0):.5f}, {fp.get('lon',0):.5f}) alt {fp.get('alt_m',0):.0f}m",
            "normal", "telemetry"))

        # Takeoff event
        if takeoff.get("lat"):
            to_ts = _rel_ts(takeoff.get("ts"), t0) or "T+0s"
            events.append(_ev(to_ts, "Takeoff",
                f"({takeoff['lat']:.5f}, {takeoff['lon']:.5f}) alt {takeoff.get('alt_m',0):.1f}m",
                "normal", "telemetry"))

        # Aggregate stats at flight end
        dur = stats.get("duration_s", 0)
        t_end = f"T+{dur:.0f}s" if dur else "--"

        if dur:
            events.append(_ev(t_end, "Flight Duration",
                f"{dur:.0f}s ({dur/60:.1f} min)", "normal", "telemetry"))

        max_dist = stats.get("total_dist_m", 0)
        if max_dist:
            events.append(_ev(t_end, "Total Distance",
                f"{max_dist:.0f}m ({max_dist/1000:.3f} km)", "normal", "telemetry"))

        max_alt = stats.get("max_alt_m", 0)
        if max_alt:
            events.append(_ev(t_end, "Max Altitude",
                f"{max_alt:.1f}m AGL", "normal", "telemetry"))

        max_spd = stats.get("max_speed_ms", 0)
        if max_spd:
            events.append(_ev(t_end, "Max Speed",
                f"{max_spd:.1f} m/s ({max_spd*3.6:.1f} km/h)", "normal", "telemetry"))

        # Last GPS fix
        lp = path[-1]
        events.append(_ev(t_end, "Last GPS Fix",
            f"({lp.get('lat',0):.5f}, {lp.get('lon',0):.5f}) alt {lp.get('alt_m',0):.0f}m",
            "normal", "telemetry"))

        # Landing event
        if landing.get("lat"):
            ld_ts = _rel_ts(landing.get("ts"), t0) or t_end
            events.append(_ev(ld_ts, "Landing",
                f"({landing['lat']:.5f}, {landing['lon']:.5f}) alt {landing.get('alt_m',0):.1f}m",
                "normal", "telemetry"))

    # ── Original branch: raw parsed_log events/modes/anomalies/track ───────
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

    # Also handle original track-based markers (for DroneFlightViewer data)
    track = parsed_log.get("track", [])
    if track and not path:
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
