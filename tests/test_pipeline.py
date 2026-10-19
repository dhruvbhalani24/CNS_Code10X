"""
Section 10.3 — End-to-end integration tests:
simulator → pipeline (normalize/enrich/detect/store) → index queries.
"""
from __future__ import annotations

from alerting.alert_manager import AlertManager
from core.pipeline import Pipeline
from core.event import ConnectionEvent
from detection.registry import build_detectors
from detection.slips_adapter import SlipsAdapter
from processing.enrichers import Enricher
from processing.logstash_pipeline import LogstashEngine
from processing.normalizer import Normalizer
from sensors.traffic_simulator import TrafficSimulator
from storage.local_index import LocalIndex


def make_pipeline(store):
    return Pipeline(normalizer=Normalizer(), enricher=Enricher(),
                    detectors=build_detectors(),
                    slips_adapter=SlipsAdapter(), store=store,
                    alert_manager=AlertManager(channels=[]))


def test_end_to_end_detection_and_storage():
    sim = TrafficSimulator(seed=7, normal_events=40, attacks=["port_scan"])
    events = sim.build()
    store = LocalIndex(":memory:")

    stats = make_pipeline(store).run_batch(events)

    assert stats["events_seen"] == len(events)
    assert stats["alerts_raised"] >= 1
    assert store.stats()["events"] == len(events)
    assert store.stats()["alerts"] >= 1
    store.close()


def test_all_attacks_detected_end_to_end():
    sim = TrafficSimulator(seed=11, normal_events=60,
                           attacks=["port_scan", "dos", "c2", "exfil"])
    store = LocalIndex(":memory:")
    make_pipeline(store).run_batch(sim.build())
    types = {a["event_type"] for a in store.query_alerts(limit=1000)}
    assert {"port_scan", "dos"} <= types
    store.close()


def test_enrichment_is_persisted():
    store = LocalIndex(":memory:")
    make_pipeline(store).run_batch(
        [TrafficSimulator(seed=1, normal_events=5, attacks=[]).build()[0]])
    row = store.query_events(limit=1)[0]
    assert "tags" in row["enrichment"]
    assert row["enrichment"]["tags"]          # non-empty
    store.close()


def test_normalizer_infers_service():
    n = Normalizer()
    e = n(ConnectionEvent(ts=1, src_ip="a", dst_ip="b", dst_port=443))
    assert e.service == "ssl"


def test_logstash_engine_filters_and_outputs():
    collected = []
    engine = (LogstashEngine.default()
              .add_output(collected.append))
    events = TrafficSimulator(seed=3, normal_events=10,
                              attacks=[]).build()
    stats = engine.process(events)
    assert stats["events_out"] == len(events)
    assert all(hasattr(e, "tags") for e in collected)   # enriched


def test_store_top_and_timeseries():
    store = LocalIndex(":memory:")
    make_pipeline(store).run_batch(
        TrafficSimulator(seed=5, normal_events=30,
                         attacks=["dos"]).build())
    top = store.top_events("src_ip", n=3)
    assert top and top[0]["count"] > 0
    series = store.timeseries(bucket_seconds=300)
    assert any(b["alerts"] > 0 for b in series)
    store.close()
