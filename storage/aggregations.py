"""
Section 6.4 — Backend-agnostic analytics helpers.

Pure functions over list[dict] rows (the format BOTH stores return),
used by the dashboard (Section 8) and evaluation (Section 9). This is
our "Kibana aggregation layer": the same analytics run on SQLite or
Elasticsearch results without modification.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from core.event import SEVERITY_LEVELS


def top_by(rows: list[dict], field: str, n: int = 10) -> list[dict]:
    """Top-N values by frequency: [{'value': x, 'count': c}, ...]"""
    counts = Counter(str(r.get(field, "")) for r in rows if r.get(field))
    return [{"value": v, "count": c} for v, c in counts.most_common(n)]


def timeseries_buckets(rows: list[dict], bucket_seconds: int = 60
                       ) -> list[dict]:
    """Bucket rows by ts into [{ts, count}] for time charts."""
    buckets: dict[int, int] = {}
    for r in rows:
        b = int(float(r.get("ts", 0)) // bucket_seconds) * bucket_seconds
        buckets[b] = buckets.get(b, 0) + 1
    return [{"ts": b, "count": c} for b, c in sorted(buckets.items())]


def severity_breakdown(alerts: list[dict]) -> list[dict]:
    """Severity distribution, ordered INFO → CRITICAL (for pie charts)."""
    counts = Counter(a.get("severity", "UNKNOWN") for a in alerts)
    return [{"severity": s, "count": counts.get(s, 0)}
            for s in SEVERITY_LEVELS if counts.get(s, 0)]


def build_summary(events: list[dict], alerts: list[dict]) -> dict:
    """One-call SOC overview for the dashboard header cards."""
    if not events:
        return {"total_events": 0, "total_alerts": 0, "attackers": 0,
                "targets": 0, "critical_alerts": 0, "top_attacker": None,
                "top_target": None}
    return {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "attackers": len({e.get("src_ip") for e in events}),
        "targets": len({e.get("dst_ip") for e in events}),
        "critical_alerts": sum(1 for a in alerts
                               if a.get("severity") == "CRITICAL"),
        "top_attacker": top_by(events, "src_ip", 1)[0],
        "top_target": top_by(events, "dst_ip", 1)[0],
    }


def dedupe_alerts(alerts: Iterable[dict]) -> list[dict]:
    """Drop duplicate alert_ids (multi-backend safety)."""
    seen, out = set(), []
    for a in alerts:
        key = a.get("alert_id") or (a.get("event_type"), a.get("src_ip"),
                                    a.get("ts"))
        if key not in seen:
            seen.add(key)
            out.append(a)
    return out
