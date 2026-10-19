"""
Section 5.3 — Event enricher (FILTER plugin).

Attaches derived context to each event:
  * network classification (internal / external / server)
  * direction tag (outbound / inbound / lateral)
  * threat-intel tag (bad-domain list from config)
  * high-port tag
  * demo geo lookup (static map — swap for a real GeoLite2 DB in prod)

Enrichment attributes (.tags, .geo, .reputation) are attached as dynamic
attributes; the storage layer (Section 6) persists them automatically.
"""
from __future__ import annotations

from core.config import get_config
from core.event import ConnectionEvent

# Demo geo map — replace with maxminddb GeoLite2 in production.
_GEO_DEMO: dict[str, str] = {
    "93.184.216.34": "Cambridge, US", "142.250.183.14": "Mountain View, US",
    "104.16.132.229": "San Francisco, US", "185.220.101.7": "Amsterdam, NL",
    "45.33.10.99": "Fremont, US", "203.0.113.9": "External (unlocated)",
}
_SERVER_PREFIX = ("10.0.0.",)


def _netclass(ip: str) -> str:
    if ip.startswith(_SERVER_PREFIX):
        return "server"
    if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                      "172.19.", "172.2", "172.30.", "172.31.")):
        return "internal"
    return "external"


class Enricher:
    """Stateless enrichment filter; callable for pipeline compatibility."""

    def __init__(self, bad_domains: list[str] | None = None) -> None:
        cfg = get_config()
        self.bad_domains = {d.lower() for d in
                            (bad_domains if bad_domains is not None
                             else cfg.detection.c2.bad_domains)}

    def __call__(self, event: ConnectionEvent) -> ConnectionEvent:
        return self.enrich(event)

    def enrich(self, event: ConnectionEvent) -> ConnectionEvent:
        tags: list[str] = []
        src_cls, dst_cls = _netclass(event.src_ip), _netclass(event.dst_ip)

        # ---- direction -----------------------------------------------------
        if src_cls == "external":
            tags.append("inbound")
        elif dst_cls == "external":
            tags.append("outbound")
        else:
            tags.append("lateral")

        # ---- protocol context ------------------------------------------------
        if event.service == "dns" or event.dns_query:
            tags.append("dns")
        if event.service in ("http", "http-proxy"):
            tags.append("web")
        if event.service == "ssl":
            tags.append("encrypted")
        if event.dst_port >= 8000 and event.service == "-":
            tags.append("high-port")

        # ---- threat intel ------------------------------------------------------
        reputation = "unknown"
        host = event.dns_query or event.http_host
        if host and any(host == b or host.endswith("." + b)
                        for b in self.bad_domains):
            tags.append("threat-intel")
            reputation = "malicious"
        if event.conn_state in ("S0", "REJ", "RSTR"):
            tags.append("incomplete-handshake")

        # ---- attach enrichment (persisted by storage layer) ---------------
        event.tags = tags                                     # type: ignore[attr-defined]
        event.geo = _GEO_DEMO.get(event.dst_ip, "Unknown")     # type: ignore[attr-defined]
        event.reputation = reputation                          # type: ignore[attr-defined]
        return event
