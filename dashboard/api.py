"""
Section 8.2 — REST API for the dashboard frontend.

Endpoints:
  GET  /api/summary              → KPI cards + storage stats
  GET  /api/events?...filters    → searchable event table
  GET  /api/alerts?...           → alert feed
  GET  /api/top/<field>?n=       → aggregation (src_ip/dst_ip/dst_port/…)
  GET  /api/timeseries?bucket=   → events+alerts over time
  POST /api/demo/run             → inject simulated attacks through the
                                    FULL pipeline (sensor→detect→store)
  POST /api/reset                → wipe the index

`/api/demo/run` exists for the live demo/viva: it proves the entire
system end-to-end with one click from the browser.
"""
from __future__ import annotations

from flask import Blueprint, jsonify, request

from core.config import get_config
from core.logger import get_logger
from storage.base_store import get_store
from storage.aggregations import (build_summary, dedupe_alerts,
                                  severity_breakdown, top_by)

api_bp = Blueprint("api", __name__, url_prefix="/api")
_log = get_logger("api")

# one shared store per process
_store = None


def get_api_store():
    global _store
    if _store is None:
        _store = get_store()
    return _store


# --------------------------------------------------------------------------- #
#  READ endpoints                                                              #
# --------------------------------------------------------------------------- #
@api_bp.get("/summary")
def summary():
    store = get_api_store()
    events = store.query_events(limit=5000)
    alerts = dedupe_alerts(store.query_alerts(limit=5000))
    payload = build_summary(events, alerts)
    payload["stats"] = store.stats()
    payload["severity_breakdown"] = severity_breakdown(alerts)
    return jsonify(payload)


@api_bp.get("/events")
def events():
    limit = request.args.get("limit", 50, type=int)
    filters = {k: request.args.get(k)
               for k in ("src_ip", "dst_ip", "dst_port", "proto", "label")
               if request.args.get(k)}
    if request.args.get("search"):
        filters["search"] = request.args["search"]
    return jsonify(get_api_store().query_events(limit=limit, **filters))


@api_bp.get("/alerts")
def alerts():
    limit = request.args.get("limit", 50, type=int)
    min_sev = request.args.get("min_severity", "INFO").upper()
    event_type = request.args.get("event_type")
    rows = get_api_store().query_alerts(limit=limit,
                                        min_severity=min_sev,
                                        event_type=event_type)
    return jsonify(dedupe_alerts(rows))


@api_bp.get("/top/<field>")
def top(field):
    n = request.args.get("n", 10, type=int)
    try:
        return jsonify(get_api_store().top_events(field, n))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@api_bp.get("/timeseries")
def series():
    bucket = request.args.get("bucket", 60, type=int)
    return jsonify(get_api_store().timeseries(bucket_seconds=bucket))


# --------------------------------------------------------------------------- #
#  ACTION endpoints                                                            #
# --------------------------------------------------------------------------- #
@api_bp.post("/demo/run")
def demo_run():
    """Inject simulated attacks through the complete live pipeline."""
    payload = request.get_json(silent=True) or {}
    attacks = payload.get("attacks") or ["port_scan", "dos", "c2", "exfil"]
    normal = payload.get("normal_events", 300)

    # imported here on purpose: heavy modules load only for the demo
    from sensors.traffic_simulator import TrafficSimulator
    from detection.registry import build_detectors
    from detection.slips_adapter import SlipsAdapter
    from processing.normalizer import Normalizer
    from processing.enrichers import Enricher
    from alerting.alert_manager import AlertManager
    from core.pipeline import Pipeline

    store = get_api_store()
    simulator = TrafficSimulator(normal_events=normal, attacks=attacks)
    pipeline = Pipeline(
        sensor=simulator,
        normalizer=Normalizer(),
        enricher=Enricher(),
        detectors=build_detectors(),
        slips_adapter=SlipsAdapter(),
        store=store,
        alert_manager=AlertManager(channels=[JsonlFallback()]),
    )
    stats = pipeline.run()
    _log.info("demo run complete: %s", stats)
    return jsonify({"ok": True, "attacks": attacks, "pipeline_stats": stats})


class JsonlFallback:
    """Silent alert sink for demo runs (dashboard shows alerts from the
    store; console output would clutter the web server log)."""
    def handle(self, alert):
        from alerting.base_alerter import JsonlAlerter
        JsonlAlerter().send(alert)


@api_bp.post("/reset")
def reset():
    get_api_store().clear()
    _log.warning("index cleared via dashboard")
    return jsonify({"ok": True})
