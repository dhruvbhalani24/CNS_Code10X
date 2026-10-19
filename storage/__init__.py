"""
Section 6 — Storage layer (the "Elasticsearch layer").

Two interchangeable backends behind one interface:
  * LocalIndex          — zero-dependency SQLite index (default, offline)
  * ElasticsearchStore  — real Elastic Stack backend

`get_store()` is the factory used everywhere else; it honours
storage.backend in config and degrades gracefully to SQLite if
Elasticsearch is unreachable (a SIEM should never lose events).
"""
from storage.base_store import BaseStore
from storage.local_index import LocalIndex
from storage.elasticsearch_store import ElasticsearchStore
from storage.aggregations import (top_by, timeseries_buckets,
                                  severity_breakdown, build_summary)
from storage.base_store import get_store

__all__ = ["BaseStore", "LocalIndex", "ElasticsearchStore", "get_store",
           "top_by", "timeseries_buckets", "severity_breakdown", "build_summary"]
