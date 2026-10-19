"""
Section 5.4 — Logstash-style processing engine.

Architecture copied from Logstash:
    INPUT (files / event iterables)
      → FILTERS (normalize, enrich, drop, mutate…)
      → OUTPUTS (store index, detector feed, webhooks…)

Filters are plain callables `event -> event | None` (None = drop event).
Outputs are plain callables `event -> None`. Everything is pluggable and
the engine reports throughput (events/sec) like Logstash does.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Iterable, Optional

from core.event import ConnectionEvent
from core.logger import get_logger
from processing.normalizer import Normalizer
from processing.enrichers import Enricher
from processing.parsers import ZeekDirectoryIngester

Filter = Callable[[ConnectionEvent], Optional[ConnectionEvent]]
Output = Callable[[ConnectionEvent], None]


class LogstashEngine:
    """Input → Filter → Output batch processor with live metrics."""

    def __init__(self, filters: list[Filter] | None = None,
                 outputs: list[Output] | None = None,
                 batch_size: int = 100) -> None:
        self.filters: list[Filter] = filters if filters is not None else []
        self.outputs: list[Output] = outputs if outputs is not None else []
        self.batch_size = batch_size
        self.log = get_logger("logstash")
        self.stats = {"events_in": 0, "events_out": 0, "dropped": 0,
                      "errors": 0, "duration": 0.0, "eps": 0.0}

    # ------------------------------------------------------------------ #
    def add_filter(self, fn: Filter) -> "LogstashEngine":
        self.filters.append(fn)
        return self                                       # chainable

    def add_output(self, fn: Output) -> "LogstashEngine":
        self.outputs.append(fn)
        return self

    @classmethod
    def default(cls) -> "LogstashEngine":
        """Standard pipeline: normalize + enrich, outputs added by caller."""
        return cls().add_filter(Normalizer()).add_filter(Enricher())

    # ------------------------------------------------------------------ #
    def process(self, events: Iterable[ConnectionEvent]) -> dict:
        """Run a batch of events through filters → outputs."""
        t0 = time.perf_counter()
        for event in events:
            self.stats["events_in"] += 1
            for flt in self.filters:
                try:
                    event = flt(event)
                except Exception as exc:                  # bad filter ≠ crash
                    self.stats["errors"] += 1
                    self.log.error("filter %s failed: %s", flt, exc)
                    event = None
                if event is None:
                    break
            if event is None:
                self.stats["dropped"] += 1
                continue
            for out in self.outputs:
                try:
                    out(event)
                except Exception as exc:
                    self.stats["errors"] += 1
                    self.log.error("output %s failed: %s", out, exc)
            self.stats["events_out"] += 1
        self.stats["duration"] = time.perf_counter() - t0
        self.stats["eps"] = (self.stats["events_out"] /
                             self.stats["duration"]) if self.stats["duration"] else 0.0
        return dict(self.stats)

    # ------------------------------------------------------------------ #
    def process_zeek_dir(self, log_dir: str | Path) -> dict:
        """INPUT plugin: process an entire Zeek log directory."""
        self.log.info("ingesting Zeek logs from %s", log_dir)
        return self.process(ZeekDirectoryIngester(log_dir).stream())
