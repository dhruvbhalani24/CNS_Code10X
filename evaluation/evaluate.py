"""
Section 9.3 — The evaluation engine.

For every scenario:
  1. build a FRESH pipeline (fresh detectors, in-memory store, silent
     alert manager) — no state leaks between scenarios
  2. push events one-by-one, timing each event (processing time) and
     the first malicious-event → matching-alert interval (latency)
  3. read all alerts back from the store and match against ground truth
"""
from __future__ import annotations

import time

from core.logger import get_logger
from core.pipeline import Pipeline
from alerting.alert_manager import AlertManager
from detection.registry import build_detectors
from detection.slips_adapter import SlipsAdapter
from evaluation.attack_scenarios import SCENARIOS, Scenario, build_scenario, ground_truth
from evaluation.metrics import ScenarioResult
from processing.enrichers import Enricher
from processing.normalizer import Normalizer
from storage.local_index import LocalIndex


class Evaluator:
    """Runs the full evaluation suite and returns per-scenario results."""

    def __init__(self, scenarios: list[Scenario] | None = None) -> None:
        self.scenarios = scenarios if scenarios is not None else SCENARIOS
        self.log = get_logger("evaluator")

    # ------------------------------------------------------------------ #
    def run_scenario(self, scenario: Scenario) -> ScenarioResult:
        events = build_scenario(scenario)
        truth = ground_truth(events)

        store = LocalIndex(":memory:")                    # throwaway index
        pipeline = Pipeline(
            normalizer=Normalizer(),
            enricher=Enricher(),
            detectors=build_detectors(),                  # fresh detectors
            slips_adapter=SlipsAdapter(),
            store=store,
            alert_manager=AlertManager(channels=[]),      # silent
        )

        matched = False
        latency_ms: float | None = None
        t_malicious_start: float | None = None
        proc_times: list[float] = []
        t_run_start = time.perf_counter()

        for event in events:
            if event.label != "normal" and t_malicious_start is None:
                t_malicious_start = time.perf_counter()
            t0 = time.perf_counter()
            alerts = pipeline.process_event(event)
            proc_times.append(time.perf_counter() - t0)

            if not matched and truth["malicious_srcs"]:
                for alert in alerts:
                    if alert.src_ip in truth["malicious_srcs"]:
                        matched = True
                        if t_malicious_start is not None:
                            latency_ms = (time.perf_counter()
                                          - t_malicious_start) * 1000.0
                        break

        wall = time.perf_counter() - t_run_start
        all_alerts = store.query_alerts(limit=100000)
        store.close()

        return ScenarioResult(
            name=scenario.name,
            labels=truth["labels"],
            n_events=len(events),
            n_alerts=len(all_alerts),
            matched=matched if truth["malicious_srcs"] else True,
            latency_ms=latency_ms,
            avg_proc_ms=1000.0 * sum(proc_times) / len(proc_times),
            max_proc_ms=1000.0 * max(proc_times),
            false_alerts=len(all_alerts) if not truth["malicious_srcs"] else 0,
            eps=len(events) / wall if wall else 0.0,
            attack_categories=list(scenario.attacks),
        )

    # ------------------------------------------------------------------ #
    def run_all(self) -> list[ScenarioResult]:
        self.log.info("running %d evaluation scenarios…", len(self.scenarios))
        results = []
        for scenario in self.scenarios:
            result = self.run_scenario(scenario)
            self.log.info("%-16s events=%-5d alerts=%-3d detected=%s "
                          "latency=%sms",
                          result.name, result.n_events, result.n_alerts,
                          result.matched,
                          f"{result.latency_ms:.1f}"
                          if result.latency_ms is not None else "n/a")
            results.append(result)
        return results
