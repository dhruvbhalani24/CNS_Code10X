"""
Section 6.1 — Storage abstract base + factory.

Defines the contract every backend must honour. The dashboard and
evaluation sections depend ONLY on this interface, so switching
SQLite ↔ Elasticsearch is a one-line config change.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from core.config import get_config
from core.event import Alert, ConnectionEvent
from core.logger import get_logger

EVENT_FIELDS = ("src_ip", "dst_ip", "dst_port", "proto", "service", "label")


class BaseStore(ABC):
    """Contract for event + alert storage with query/aggregation support."""

    # ---- writes --------------------------------------------------------- #
    @abstractmethod
    def index_event(self, event: ConnectionEvent) -> None: ...

    @abstractmethod
    def index_alert(self, alert: Alert) -> None: ...

    # ---- queries (always return plain dicts, backend-agnostic) ---------- #
    @abstractmethod
    def query_events(self, limit: int = 100, **filters: Any) -> list[dict]: ...

    @abstractmethod
    def query_alerts(self, limit: int = 100,
                     min_severity: Optional[str] = None,
                     event_type: Optional[str] = None) -> list[dict]: ...

    @abstractmethod
    def top_events(self, field: str, n: int = 10) -> list[dict]: ...

    @abstractmethod
    def timeseries(self, bucket_seconds: int = 60) -> list[dict]: ...

    @abstractmethod
    def stats(self) -> dict: ...

    # ---- lifecycle ------------------------------------------------------- #
    def clear(self) -> None: ...
    def close(self) -> None: ...


# ------------------------------------------------------------------------- #
def get_store(settings: Optional[dict] = None):
    """Factory: build the configured backend, falling back to SQLite."""
    log = get_logger("storage")
    cfg = get_config()
    backend = (settings or {}).get("backend", cfg.storage.backend)

    if backend == "elasticsearch":
        try:
            from storage.elasticsearch_store import ElasticsearchStore
            store = ElasticsearchStore()
            log.info("storage backend: elasticsearch")
            return store
        except Exception as exc:
            log.warning("Elasticsearch unavailable (%s) — "
                        "falling back to SQLite LocalIndex", exc)

    from storage.local_index import LocalIndex
    log.info("storage backend: sqlite (local)")
    return LocalIndex()
