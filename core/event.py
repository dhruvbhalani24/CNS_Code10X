"""
Section 1.3 — Canonical data models.

Every stage of the pipeline speaks these two types:
  * ConnectionEvent : one normalized network connection (Zeek-style)
  * Alert           : one security finding produced by a detector
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITY_LEVELS = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def severity_rank(severity: str) -> int:
    """Return comparable numeric rank; unknown severity sorts lowest."""
    try:
        return SEVERITY_LEVELS.index(severity.upper())
    except ValueError:
        return -1


@dataclass
class ConnectionEvent:
    """A single network connection, normalized across all sensor types.

    `label` carries ground truth when events come from the attack
    simulator (used by the evaluation section to compute metrics).
    """
    ts: float                       # unix epoch seconds
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str = "tcp"              # tcp | udp | icmp
    service: str = "-"              # zeek service: http, ssl, dns...
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    conn_state: str = "SF"          # SF, S0, REJ, RSTR, ...
    dns_query: str = ""             # filled from dns.log
    http_host: str = ""             # filled from http.log
    sensor: str = "zeek"            # zeek | simulator | pcap
    label: str = "unknown"          # ground truth: normal | port_scan | ...

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ConnectionEvent":
        valid = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in valid})


@dataclass
class Alert:
    """A security finding emitted by any detector or by Slips."""
    event_type: str                 # port_scan | dos | c2_beacon | anomaly | ...
    severity: str                   # one of SEVERITY_LEVELS
    description: str
    src_ip: str = ""
    dst_ip: str = ""
    detected_by: str = "builtin"    # detector name or "slips"
    evidence: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    alert_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Alert":
        valid = set(cls.__dataclass_fields__.keys())  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in valid})
