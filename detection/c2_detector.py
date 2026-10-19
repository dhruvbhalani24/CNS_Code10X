"""
Section 4.1 — Command & Control (C2) beacon detector.

Detects command-and-control channels using a two-stage approach:
  1. Threat Intel: matching DNS queries and HTTP host headers against known
     malicious domains (CRITICAL severity).
  2. Statistical Beaconing: detecting regular-interval periodic connections
     (low coefficient of variation / jitter) to destination ports (HIGH severity).
"""
from __future__ import annotations

from collections import deque
from typing import Any, Optional

from core.event import Alert, ConnectionEvent
from detection.base_detector import BaseDetector


class C2BeaconDetector(BaseDetector):
    """Detects periodic C2 beaconing and threat-intel domain matches."""

    name: str = "c2_beacon"
    DEFAULTS: dict[str, Any] = {
        "min_beacons": 6,
        "jitter": 0.30,
        "dst_ports": [443, 8443, 8080],
        "bad_domains": [],
    }

    def __init__(self, cfg: Optional[dict[str, Any]] = None) -> None:
        super().__init__(cfg)
        self.min_beacons: int = int(self.cfg.get("min_beacons", 6))
        self.jitter: float = float(self.cfg.get("jitter", 0.30))
        self.dst_ports: set[int] = {int(p) for p in self.cfg.get("dst_ports", [443, 8443, 8080])}
        self.bad_domains: list[str] = [
            str(d).strip().lower().rstrip(".") for d in self.cfg.get("bad_domains", []) if d
        ]
        self._max_keys: int = int(self.cfg.get("max_keys", 5000))

        # Maps (src_ip, dst_ip, dst_port) -> deque(maxlen=12) of timestamps
        self._beacon_history: dict[tuple[str, str, int], deque[float]] = {}
        self._last_seen: dict[tuple[str, str, int], float] = {}

    def process(self, event: ConnectionEvent) -> list[Alert]:
        alerts: list[Alert] = []
        try:
            src_ip = getattr(event, "src_ip", "")
            dst_ip = getattr(event, "dst_ip", "")
            dst_port = int(getattr(event, "dst_port", 0) or 0)
            ts = float(getattr(event, "ts", 0.0))

            # ------------------------------------------------------------- #
            #  1. THREAT INTEL FIRST (before beacon logic, ignoring ports)  #
            # ------------------------------------------------------------- #
            queries = [
                str(getattr(event, "dns_query", "") or "").strip().lower().rstrip("."),
                str(getattr(event, "http_host", "") or "").strip().lower().rstrip("."),
            ]
            for query in queries:
                if not query:
                    continue
                for bad in self.bad_domains:
                    if query == bad or query.endswith("." + bad):
                        ti_key = ("ti", src_ip, bad)
                        if not self.is_in_cooldown(ti_key, ts, cooldown=self.cooldown):
                            self.mark_alerted(ti_key, ts)
                            evidence = {
                                "matched_domain": bad,
                                "queried_host": query,
                                "detection_type": "threat_intel",
                            }
                            alerts.append(
                                self._alert(
                                    event=event,
                                    event_type="c2_beacon",
                                    severity="CRITICAL",
                                    description=(
                                        f"Threat-intel hit: {src_ip} queried known C2 domain {bad}"
                                    ),
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    evidence=evidence,
                                )
                            )
                        break

            # ------------------------------------------------------------- #
            #  2. STATISTICAL BEACONING (only for configured dst_ports)     #
            # ------------------------------------------------------------- #
            if dst_port not in self.dst_ports:
                return alerts

            key = (src_ip, dst_ip, dst_port)
            if key not in self._beacon_history:
                if len(self._beacon_history) >= self._max_keys:
                    self._evict_stale_keys()
                self._beacon_history[key] = deque(maxlen=12)

            dq = self._beacon_history[key]
            dq.append(ts)
            self._last_seen[key] = ts

            if len(dq) >= self.min_beacons:
                ts_list = list(dq)
                intervals = [t2 - t1 for t1, t2 in zip(ts_list[:-1], ts_list[1:])]
                if intervals:
                    mean = sum(intervals) / len(intervals)
                    if mean > 0:
                        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
                        std = variance ** 0.5
                        cv = std / mean

                        if cv <= self.jitter:
                            cooldown_seconds = 12.0 * mean
                            beacon_key = ("beacon", src_ip, dst_ip, dst_port)
                            if not self.is_in_cooldown(beacon_key, ts, cooldown=cooldown_seconds):
                                self.mark_alerted(beacon_key, ts)
                                evidence = {
                                    "cv": round(cv, 4),
                                    "jitter_threshold": self.jitter,
                                    "mean_interval_sec": round(mean, 2),
                                    "std_interval_sec": round(std, 2),
                                    "beacon_count": len(dq),
                                    "cooldown_sec": round(cooldown_seconds, 2),
                                    "dst_port": dst_port,
                                }
                                alerts.append(
                                    self._alert(
                                        event=event,
                                        event_type="c2_beacon",
                                        severity="HIGH",
                                        description=(
                                            f"Periodic C2 beaconing detected: {src_ip} -> "
                                            f"{dst_ip}:{dst_port} every ~{mean:.1f}s "
                                            f"(CV={cv:.2f} <= {self.jitter})"
                                        ),
                                        src_ip=src_ip,
                                        dst_ip=dst_ip,
                                        evidence=evidence,
                                    )
                                )

            return alerts
        except Exception:
            return []

    def _evict_stale_keys(self) -> None:
        """Evict oldest keys to keep memory within max_keys."""
        if len(self._beacon_history) >= self._max_keys:
            sorted_keys = sorted(self._last_seen.items(), key=lambda kv: kv[1])
            for k, _ in sorted_keys[: max(1, len(sorted_keys) // 10)]:
                self._beacon_history.pop(k, None)
                self._last_seen.pop(k, None)

    def reset(self) -> None:
        super().reset()
        self._beacon_history.clear()
        self._last_seen.clear()
