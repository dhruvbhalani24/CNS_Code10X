"""
Section 1.4 — Pipeline orchestrator (the heart of the system).

Flow per event:
    sensor → [normalizer] → [enricher] → detectors → [slips] → [store]
                                                            ↘ alert manager

All stages are OPTIONAL and injected via the constructor, so the pipeline
is testable with stubs and works incrementally as sections are added.
"""
from __future__ import annotations

import time
from typing import Callable, Iterable, Optional

from core.event import Alert, ConnectionEvent
from core.logger import get_logger

# Type aliases for injectable stages (defined by later sections)
Normalizer = Callable[[ConnectionEvent], ConnectionEvent]
Enricher = Callable[[ConnectionEvent], ConnectionEvent]


class Pipeline:
    """Wires sensors, processing, detection, storage and alerting together."""

    def __init__(self,
                 sensor: Optional[Any] = None,
                 normalizer: Optional[Normalizer] = None,
                 enricher: Optional[Enricher] = None,
                 detectors: Optional[list[Any]] = None,
                 slips_adapter: Optional[Any] = None,
                 store: Optional[Any] = None,
                 alert_manager: Optional[Any] = None) -> None:
        self.sensor = sensor
        self.normalizer = normalizer
        self.enricher = enricher
        self.detectors = list(detectors) if detectors else []
        self.slips_adapter = slips_adapter
        self.store = store
        self.alert_manager = alert_manager
        self.log = get_logger("pipeline")

        # ---- live statistics ------------------------------------------------
        self.stats = {
            "events_seen": 0,
            "alerts_raised": 0,
            "processing_time_total": 0.0,
            "started_at": None,
            "last_alert_latency": 0.0,   # event.ts -> alert.ts (seconds)
        }

    # ------------------------------------------------------------------ #
    def process_event(self, event: ConnectionEvent) -> list[Alert]:
        """Push one event through every stage. Returns alerts raised."""
        t0 = time.perf_counter()
        if self.normalizer:
            event = self.normalizer(event)
        if self.enricher:
            event = self.enricher(event)

        alerts: list[Alert] = []
        for detector in self.detectors:
            try:
                alerts.extend(detector.process(event))
            except Exception as exc:            # a faulty detector must
                self.log.error("detector %s failed: %s",                # never kill
                               getattr(detector, "name", detector), exc)  # the pipe
        if self.slips_adapter:
            try:
                alerts.extend(self.slips_adapter.analyze([event]))
            except Exception as exc:
                self.log.warning("slips adapter failed: %s", exc)

        if self.store:
            self.store.index_event(event)
        for alert in alerts:
            latency = max(0.0, alert.ts - event.ts)
            self.stats["last_alert_latency"] = latency
            if self.store:
                self.store.index_alert(alert)
            if self.alert_manager:
                self.alert_manager.handle(alert)

        self.stats["events_seen"] += 1
        self.stats["alerts_raised"] += len(alerts)
        self.stats["processing_time_total"] += time.perf_counter() - t0
        return alerts

    # ------------------------------------------------------------------ #
    def run(self) -> dict:
        """Consume the sensor stream forever (or until it ends)."""
        if self.sensor is None:
            raise RuntimeError("Pipeline.run() called with no sensor attached.")
        self.stats["started_at"] = time.time()
        self.log.info("pipeline started — sensor=%s, detectors=%d",
                      type(self.sensor).__name__, len(self.detectors))
        for event in self.sensor.stream():
            self.process_event(event)
        self.log.info("pipeline finished — %s", self.stats)
        return dict(self.stats)

    def run_batch(self, events: Iterable[ConnectionEvent]) -> dict:
        """Process an in-memory collection (used by simulator & evaluation)."""
        self.stats["started_at"] = self.stats["started_at"] or time.time()
        for event in events:
            self.process_event(event)
        return dict(self.stats)
