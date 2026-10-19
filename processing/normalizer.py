"""
Section 5.2 — Field normalizer (FILTER plugin).

Guarantees that every event entering detection/storage has:
  * correct Python types (int/float/str)
  * canonical protocol & service names
  * inferred service from well-known ports when Zeek reported '-'
  * clean, lowercase DNS/HTTP host strings

Signature-compatible with the pipeline's `Normalizer` callable type.
"""
from __future__ import annotations

from core.event import ConnectionEvent

WELL_KNOWN_PORTS: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 69: "tftp", 80: "http", 110: "pop3",
    123: "ntp", 143: "imap", 443: "ssl", 445: "smb", 465: "smtps",
    587: "smtp", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9092: "kafka", 27017: "mongodb",
}

VALID_PROTOS = {"tcp", "udp", "icmp"}


class Normalizer:
    """Stateless filter: one event in → one clean event out."""

    def __call__(self, event: ConnectionEvent) -> ConnectionEvent:
        return self.normalize(event)

    def normalize(self, event: ConnectionEvent) -> ConnectionEvent:
        # ---- protocol -----------------------------------------------------
        proto = (event.proto or "tcp").strip().lower()
        event.proto = proto if proto in VALID_PROTOS else "tcp"

        # ---- service inference ---------------------------------------------
        event.service = (event.service or "-").strip().lower()
        if event.service in ("-", ""):
            event.service = WELL_KNOWN_PORTS.get(event.dst_port, "-")

        # ---- numeric coercion ----------------------------------------------
        event.dst_port = int(max(0, event.dst_port or 0))
        event.duration = float(max(0.0, event.duration or 0.0))
        event.orig_bytes = int(max(0, event.orig_bytes or 0))
        event.resp_bytes = int(max(0, event.resp_bytes or 0))
        event.ts = float(event.ts or 0.0)

        # ---- string hygiene -------------------------------------------------
        event.dns_query = (event.dns_query or "").strip().lower()
        event.http_host = (event.http_host or "").strip().lower()
        event.conn_state = (event.conn_state or "-").strip().upper()
        return event
