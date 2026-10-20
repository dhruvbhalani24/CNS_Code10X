"""
Section 2.2 — Zeek log sensor.

Reads Zeek's classic TSV logs (conn.log, dns.log, http.log) and also
supports Zeek's JSON format. In `tail=True` mode it behaves like
`tail -f`, sleeping and re-reading for a true live pipeline.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterator, Optional

from core.config import get_config
from core.event import ConnectionEvent
from core.logger import get_logger
from sensors.base_sensor import BaseSensor

# Zeek field name -> ConnectionEvent field
_CONN_MAP = {
    "ts": "ts", "id.orig_h": "src_ip", "id.resp_h": "dst_ip",
    "id.resp_p": "dst_port", "proto": "proto", "service": "service",
    "duration": "duration", "orig_bytes": "orig_bytes",
    "resp_bytes": "resp_bytes", "conn_state": "conn_state",
}


def _num(value, default=0.0):
    """Zeek writes '-' for missing numerics."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class ZeekSensor(BaseSensor):
    """Streams ConnectionEvents from a directory of Zeek logs."""

    name = "zeek"

    def __init__(self, log_dir: Optional[str] = None, tail: Optional[bool] = None):
        super().__init__()
        cfg = get_config()
        self.log_dir = Path(log_dir or cfg.sensors.zeek_log_dir)
        self.tail = cfg.sensors.tail if tail is None else tail
        self.poll = cfg.sensors.tail_poll_seconds
        if not self.log_dir.is_dir():
            raise FileNotFoundError(f"Zeek log directory not found: {self.log_dir}")
        self.log.info("Zeek sensor watching %s (tail=%s)", self.log_dir, self.tail)

    # ------------------------------------------------------------------ #
    def stream(self) -> Iterator[ConnectionEvent]:
        """Yield events; in tail mode, keeps following files forever."""
        self._running = True
        offsets: dict[Path, int] = {}
        while self._running:
            new_data = False
            for path in sorted(self.log_dir.glob("*.log")):
                for event, pos in self._read_file(path, offsets.get(path, 0)):
                    new_data = True
                    offsets[path] = pos
                    yield event
            if not self.tail:
                break
            if not new_data:
                time.sleep(self.poll)

    # ------------------------------------------------------------------ #
    def _read_file(self, path: Path, offset: int):
        """Read one log file from `offset`; yield (event, new_offset)."""
        logtype = path.name.split(".")[0]          # conn / dns / http
        fields: list[str] = []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            while True:
                line = fh.readline()
                if not line:
                    break
                stripped = line.rstrip("\n")
                if not stripped:
                    continue
                if stripped.startswith("#fields"):
                    fields = stripped.split("\t")[1:]
                    continue
                if stripped.startswith("#"):
                    continue
                if stripped.startswith("{"):                       # JSON log
                    record = json.loads(stripped)
                else:                                              # TSV log
                    if not fields:
                        continue
                    values = stripped.split("\t")
                    record = dict(zip(fields, values))
                event = self._to_event(record, logtype)
                if event:
                    yield event, fh.tell()
            last_offset = fh.tell()
        # allow tail mode to notice files with no parsable rows yet
        yield from self._yield_nothing(last_offset)

    @staticmethod
    def _yield_nothing(offset: int):
        return iter(())

    # ------------------------------------------------------------------ #
    @staticmethod
    def _to_event(rec: dict, logtype: str) -> Optional[ConnectionEvent]:
        """Convert one raw Zeek record into a ConnectionEvent (or None)."""
        src = rec.get("id.orig_h")
        dst = rec.get("id.resp_h")
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
            sensor="zeek",
        )
        if logtype == "dns":
            event.dns_query = rec.get("query") or ""
            event.service = "dns"
            event.proto = "udp"
            event.dst_port = 53
        elif logtype == "http":
            event.http_host = rec.get("host") or ""
            event.service = "http"
        return event
