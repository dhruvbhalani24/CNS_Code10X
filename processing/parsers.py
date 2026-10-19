"""
Section 5.1 — Log parsers (INPUT plugins).

Auto-detecting parser supporting:
  * Zeek classic TSV   (#separator / #fields headers)
  * Zeek JSON logs     (one JSON object per line)
  * Raw JSON lines     (any producer)

`record_to_event` converts a raw parsed record into the canonical
ConnectionEvent model — this is the canonical converter for BATCH
processing; the streaming ZeekSensor (Section 2) has its own lighter
inline version.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, Optional

from core.event import ConnectionEvent
from core.logger import get_logger

_LOG = get_logger("parsers")


def _num(value, default=0.0) -> float:
    """Zeek writes '-' for missing numerics."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# ------------------------------------------------------------------------- #
class LogParser:
    """Stateful per-file parser: remembers the #fields header of TSV logs."""

    def __init__(self) -> None:
        self._fields: list[str] = []

    # -- one raw line -> dict (or None if unparseable) --------------------- #
    def parse_line(self, line: str) -> Optional[dict]:
        line = line.rstrip("\n")
        if not line:
            return None
        if line.startswith("#"):
            if line.startswith("#fields"):
                self._fields = line.split("\t")[1:]
            return None
        if line.startswith("{"):                              # JSON log
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                return None
        if self._fields:                                      # Zeek TSV
            values = line.split("\t")
            return dict(zip(self._fields, values))
        return None

    def parse_file(self, path: str | Path) -> Iterator[dict]:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                rec = self.parse_line(line)
                if rec is not None:
                    yield rec


# ------------------------------------------------------------------------- #
def record_to_event(rec: dict, logtype: str = "conn",
                    sensor: str = "zeek") -> Optional[ConnectionEvent]:
    """Convert a raw Zeek record into a ConnectionEvent (or None)."""
    src, dst = rec.get("id.orig_h"), rec.get("id.resp_h")
    if not src or not dst:
        return None
    event = ConnectionEvent(
        ts=_num(rec.get("ts"), 0.0),
        src_ip=src, dst_ip=dst,
        dst_port=int(_num(rec.get("id.resp_p"), 0)),
        proto=(rec.get("proto") or "tcp").lower(),
        service=rec.get("service") or "-",
        duration=_num(rec.get("duration"), 0.0),
        orig_bytes=int(_num(rec.get("orig_bytes"), 0)),
        resp_bytes=int(_num(rec.get("resp_bytes"), 0)),
        conn_state=rec.get("conn_state") or "-",
        sensor=sensor,
    )
    if logtype == "dns":
        event.dns_query = (rec.get("query") or "").strip().lower()
        event.service, event.proto, event.dst_port = "dns", "udp", 53
    elif logtype == "http":
        event.http_host = (rec.get("host") or "").strip().lower()
        event.service = "http"
    return event


# ------------------------------------------------------------------------- #
class ZeekDirectoryIngester:
    """INPUT plugin: walk a Zeek log directory, yield ConnectionEvents."""

    def __init__(self, log_dir: str | Path) -> None:
        self.log_dir = Path(log_dir)
        if not self.log_dir.is_dir():
            raise FileNotFoundError(f"Zeek log dir not found: {self.log_dir}")

    def stream(self) -> Iterator[ConnectionEvent]:
        for path in sorted(self.log_dir.glob("*.log")):
            logtype = path.name.split(".")[0]          # conn / dns / http
            parser = LogParser()
            n = 0
            for rec in parser.parse_file(path):
                event = record_to_event(rec, logtype)
                if event:
                    yield event
                    n += 1
            _LOG.info("parsed %s: %d records", path.name, n)
