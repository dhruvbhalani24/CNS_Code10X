"""
Section 8.3 — Live alert stream (Server-Sent Events).

Provides a tiny in-process pub/sub bus. Anything can publish alerts
(the AlertManager can be given a BusAlerter channel), and the browser
subscribes via:

    new EventSource('/api/live/alerts')

…receiving a push the instant an alert fires — no polling. Falls back
silently: the frontend ALSO polls /api/alerts, so the dashboard works
even if SSE is proxied away in production.
"""
from __future__ import annotations

import json
import queue
import time
from typing import Set

from flask import Blueprint, Response

from core.logger import get_logger

live_bp = Blueprint("live", __name__, url_prefix="/api/live")
_log = get_logger("live")


class AlertBus:
    """Minimal fan-out bus: publish → every subscriber queue."""

    def __init__(self) -> None:
        self._subscribers: Set["queue.Queue[dict]"] = set()

    def subscribe(self) -> "queue.Queue[dict]":
        q: "queue.Queue[dict]" = queue.Queue(maxsize=200)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: "queue.Queue[dict]") -> None:
        self._subscribers.discard(q)

    def publish(self, alert_dict: dict) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(alert_dict)
            except queue.Full:
                pass                       # slow client: drop, never block


bus = AlertBus()


class BusAlerter:
    """Drop-in channel for AlertManager that feeds the live stream."""
    name = "live_bus"

    def send(self, alert) -> None:
        bus.publish(alert.to_dict())


# --------------------------------------------------------------------------- #
@live_bp.get("/alerts")
def stream_alerts():
    """SSE endpoint: streams alerts as `data: {...}` events, with a
    15s heartbeat comment to keep connections alive through proxies."""
    q = bus.subscribe()

    def generate():
        try:
            yield "retry: 3000\n\n"
            while True:
                try:
                    alert = q.get(timeout=15)
                    yield f"data: {json.dumps(alert)}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"        # heartbeat
        finally:
            bus.unsubscribe(q)

    resp = Response(generate(), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"        # disable nginx buffering
    return resp
