"""
Section 6.2 — SQLite-backed index (default offline backend).

Thread-safe (a single lock guards the connection — the Flask dashboard
and the pipeline may write from different threads). Persists events,
alerts and their enrichment payloads, and implements every query /
aggregation of the BaseStore contract in SQL.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Optional

from core.config import get_config
from core.event import SEVERITY_LEVELS, Alert, ConnectionEvent, severity_rank
from core.logger import get_logger
from storage.base_store import EVENT_FIELDS, BaseStore

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    src_ip      TEXT, dst_ip TEXT, dst_port INTEGER,
    proto       TEXT, service TEXT, duration REAL,
    orig_bytes  INTEGER, resp_bytes INTEGER, conn_state TEXT,
    dns_query   TEXT, http_host TEXT, sensor TEXT, label TEXT,
    enrichment  TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts   ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src  ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dstp ON events(dst_port);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id    TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    event_type  TEXT, severity TEXT,
    src_ip      TEXT, dst_ip TEXT,
    description TEXT, detected_by TEXT,
    evidence    TEXT,
    indexed_at  REAL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts  ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);
"""


def _enrichment_payload(event: ConnectionEvent) -> str:
    return json.dumps({
        "tags": list(getattr(event, "tags", [])),
        "geo": getattr(event, "geo", "Unknown"),
        "reputation": getattr(event, "reputation", "unknown"),
    })


class LocalIndex(BaseStore):
    """Zero-dependency persistent index (default SIEM backend)."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        cfg = get_config()
        self.db_path = Path(db_path or cfg.general.db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.log = get_logger("storage.sqlite")
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.db_path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock, self._db:
            self._db.executescript(_SCHEMA)
        self.log.info("LocalIndex ready: %s", self.db_path)

    # ---- writes --------------------------------------------------------- #
    def index_event(self, event: ConnectionEvent) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO events (ts, src_ip, dst_ip, dst_port, proto,"
                " service, duration, orig_bytes, resp_bytes, conn_state,"
                " dns_query, http_host, sensor, label, enrichment)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (event.ts, event.src_ip, event.dst_ip, event.dst_port,
                 event.proto, event.service, event.duration,
                 event.orig_bytes, event.resp_bytes, event.conn_state,
                 event.dns_query, event.http_host, event.sensor,
                 event.label, _enrichment_payload(event)))

    def index_alert(self, alert: Alert) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO alerts (alert_id, ts, event_type,"
                " severity, src_ip, dst_ip, description, detected_by,"
                " evidence, indexed_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (alert.alert_id, alert.ts, alert.event_type, alert.severity,
                 alert.src_ip, alert.dst_ip, alert.description,
                 alert.detected_by, json.dumps(alert.evidence),
                 __import__("time").time()))

    # ---- queries --------------------------------------------------------- #
    def query_events(self, limit: int = 100, **filters: Any) -> list[dict]:
        where, params = [], []
        for field in EVENT_FIELDS:
            if filters.get(field) is not None:
                where.append(f"{field} = ?")
                params.append(filters[field])
        if filters.get("since"):
            where.append("ts >= ?"); params.append(filters["since"])
        if filters.get("search"):
            where.append("(src_ip LIKE ? OR dst_ip LIKE ? OR dns_query"
                         " LIKE ? OR http_host LIKE ?)")
            like = f"%{filters['search']}%"
            params += [like, like, like, like]
        sql = "SELECT * FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        return [self._row_to_event_dict(r) for r in rows]

    def query_alerts(self, limit: int = 100,
                     min_severity: Optional[str] = None,
                     event_type: Optional[str] = None) -> list[dict]:
        where, params = [], []
        if min_severity:
            allowed = SEVERITY_LEVELS[severity_rank(min_severity):]
            where.append(f"severity IN ({','.join('?' * len(allowed))})")
            params += list(allowed)
        if event_type:
            where.append("event_type = ?"); params.append(event_type)
        sql = "SELECT * FROM alerts"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(int(limit))
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        return [dict(r, evidence=json.loads(r["evidence"] or "{}")) for r in rows]

    def top_events(self, field: str, n: int = 10) -> list[dict]:
        if field not in EVENT_FIELDS:
            raise ValueError(f"unsupported field {field!r}")
        with self._lock:
            rows = self._db.execute(
                f"SELECT {field} AS value, COUNT(*) AS count FROM events"
                f" GROUP BY {field} ORDER BY count DESC LIMIT ?", (n,)).fetchall()
        return [dict(r) for r in rows]

    def timeseries(self, bucket_seconds: int = 60) -> list[dict]:
        with self._lock:
            ev = self._db.execute(
                "SELECT CAST(ts/? AS INTEGER)*? AS b, COUNT(*) AS c"
                " FROM events GROUP BY b ORDER BY b",
                (bucket_seconds, bucket_seconds)).fetchall()
            al = self._db.execute(
                "SELECT CAST(ts/? AS INTEGER)*? AS b, COUNT(*) AS c"
                " FROM alerts GROUP BY b ORDER BY b",
                (bucket_seconds, bucket_seconds)).fetchall()
        alert_map = {r["b"]: r["c"] for r in al}
        merged = {r["b"]: {"ts": r["b"], "events": r["c"],
                           "alerts": alert_map.get(r["b"], 0)} for r in ev}
        for b, c in alert_map.items():                     # alert-only buckets
            merged.setdefault(b, {"ts": b, "events": 0, "alerts": c})
        return [merged[k] for k in sorted(merged)]

    def stats(self) -> dict:
        with self._lock:
            one = lambda q: self._db.execute(q).fetchone()[0]  # noqa: E731
            return {
                "events": one("SELECT COUNT(*) FROM events"),
                "alerts": one("SELECT COUNT(*) FROM alerts"),
                "unique_src": one("SELECT COUNT(DISTINCT src_ip) FROM events"),
                "unique_dst": one("SELECT COUNT(DISTINCT dst_ip) FROM events"),
                "first_ts": one("SELECT MIN(ts) FROM events"),
                "last_ts": one("SELECT MAX(ts) FROM events"),
                "backend": "sqlite",
            }

    # ---- lifecycle -------------------------------------------------------- #
    def clear(self) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM events")
            self._db.execute("DELETE FROM alerts")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ---- helpers ----------------------------------------------------------- #
    @staticmethod
    def _row_to_event_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["enrichment"] = json.loads(d.get("enrichment") or "{}")
        return d
