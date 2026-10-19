"""
Section 6.3 — Elasticsearch backend (real Elastic Stack integration).

Uses the official `elasticsearch` Python client (v8). Maps every
BaseStore method onto native ES queries/aggregations — the same
analytics the Kibana dashboard would run:
  * query_events   → bool filter query, sort by ts
  * query_alerts   → severity terms filter
  * top_events     → terms aggregation
  * timeseries     → date_histogram aggregation
  * stats          → count APIs

If the library or cluster is unavailable, the factory in base_store.py
falls back to LocalIndex automatically — zero data loss.
"""
from __future__ import annotations

from typing import Any, Optional

from core.config import get_config
from core.event import SEVERITY_LEVELS, Alert, ConnectionEvent, severity_rank
from core.logger import get_logger
from storage.base_store import EVENT_FIELDS, BaseStore

try:
    from elasticsearch import Elasticsearch
    _HAS_ES = True
except ImportError:
    _HAS_ES = False


class ElasticsearchStore(BaseStore):
    """Real Elasticsearch backend (events + alerts as separate indices)."""

    def __init__(self) -> None:
        if not _HAS_ES:
            raise ImportError("pip install elasticsearch>=8.0")
        cfg = get_config()
        self.log = get_logger("storage.es")
        self.prefix = cfg.storage.index_prefix
        self.es = Elasticsearch(cfg.storage.es_hosts, request_timeout=5)
        if not self.es.ping():
            raise ConnectionError(f"ES cluster unreachable at "
                                  f"{cfg.storage.es_hosts}")
        self._ensure_mappings()
        self.log.info("connected to Elasticsearch: %s", cfg.storage.es_hosts)

    # ------------------------------------------------------------------ #
    def _ensure_mappings(self) -> None:
        for idx in (f"{self.prefix}-events", f"{self.prefix}-alerts"):
            if not self.es.indices.exists(index=idx):
                self.es.indices.create(index=idx, body={
                    "mappings": {"properties": {
                        "ts": {"type": "date", "format": "epoch_second"}}}})

    @property
    def _events(self) -> str: return f"{self.prefix}-events"
    @property
    def _alerts(self) -> str: return f"{self.prefix}-alerts"

    # ---- writes --------------------------------------------------------- #
    def index_event(self, event: ConnectionEvent) -> None:
        doc = event.to_dict()
        doc["tags"] = list(getattr(event, "tags", []))
        doc["geo"] = getattr(event, "geo", "Unknown")
        self.es.index(index=self._events, document=doc)

    def index_alert(self, alert: Alert) -> None:
        self.es.index(index=self._alerts, document=alert.to_dict())

    # ---- queries --------------------------------------------------------- #
    def query_events(self, limit: int = 100, **filters: Any) -> list[dict]:
        must = [{"match": {k: str(v)}} for k, v in filters.items()
                if k in EVENT_FIELDS and v is not None]
        if filters.get("since"):
            must.append({"range": {"ts": {"gte": filters["since"]}}})
        if filters.get("search"):
            must.append({"query_string": {"query": f"*{filters['search']}*"}})
        resp = self.es.search(index=self._events, query={"bool": {"must": must}},
                              sort=[{"ts": "desc"}], size=int(limit))
        return [h["_source"] for h in resp["hits"]["hits"]]

    def query_alerts(self, limit: int = 100,
                     min_severity: Optional[str] = None,
                     event_type: Optional[str] = None) -> list[dict]:
        must = []
        if min_severity:
            allowed = SEVERITY_LEVELS[severity_rank(min_severity):]
            must.append({"terms": {"severity": allowed}})
        if event_type:
            must.append({"match": {"event_type": event_type}})
        resp = self.es.search(index=self._alerts,
                              query={"bool": {"must": must}},
                              sort=[{"ts": "desc"}], size=int(limit))
        return [h["_source"] for h in resp["hits"]["hits"]]

    def top_events(self, field: str, n: int = 10) -> list[dict]:
        if field not in EVENT_FIELDS:
            raise ValueError(f"unsupported field {field!r}")
        resp = self.es.search(index=self._events, size=0, aggs={
            "top": {"terms": {"field": f"{field}.keyword", "size": n}}})
        return [{"value": b["key"], "count": b["doc_count"]}
                for b in resp["aggregations"]["top"]["buckets"]]

    def timeseries(self, bucket_seconds: int = 60) -> list[dict]:
        interval = f"{bucket_seconds}s"
        out: list[dict] = []
        for idx, key in ((self._events, "events"), (self._alerts, "alerts")):
            resp = self.es.search(index=idx, size=0, aggs={
                "hist": {"date_histogram": {"field": "ts",
                                            "fixed_interval": interval}}})
            for b in resp["aggregations"]["hist"]["buckets"]:
                out.append({"ts": b["key"] / 1000, key: b["doc_count"]})
        return sorted(out, key=lambda d: d["ts"])

    def stats(self) -> dict:
        return {
            "events": self.es.count(index=self._events)["count"],
            "alerts": self.es.count(index=self._alerts)["count"],
            "backend": "elasticsearch",
        }

    def clear(self) -> None:
        for idx in (self._events, self._alerts):
            if self.es.indices.exists(index=idx):
                self.es.delete_by_query(index=idx, query={"match_all": {}},
                                        refresh=True)

    def close(self) -> None:
        self.es.close()
