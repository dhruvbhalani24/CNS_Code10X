"""
Section 4.3 — Data exfiltration detector.

Monitors outbound data transfers from internal hosts to external destinations.
Emits an exfiltration alert when cumulative transferred bytes and connection count
within an event-time window exceed configured thresholds.
"""
from __future__ import annotations

import ipaddress
from collections import deque
from typing import Any, Optional

from core.event import Alert, ConnectionEvent
from detection.base_detector import BaseDetector
from detection.sliding_window import prune_deque


def _is_private(ip_str: str) -> bool:
    """Return True if ip_str is a valid private/RFC1918 address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def _is_public(ip_str: str) -> bool:
    """Return True if ip_str is a routable public Internet address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


class ExfilDetector(BaseDetector):
    """Detects abnormal outbound data volume transfer."""

    name: str = "exfiltration"
    DEFAULTS: dict[str, Any] = {
        "window": 600,
        "bytes_threshold": 100_000_000,
        "min_connections": 3,
    }

    def __init__(self, cfg: Optional[dict[str, Any]] = None) -> None:
        super().__init__(cfg)
        self.window: float = float(self.cfg.get("window", 600))
        self.bytes_threshold: int = int(self.cfg.get("bytes_threshold", 100_000_000))
        self.min_connections: int = int(self.cfg.get("min_connections", 3))
        self._max_keys: int = int(self.cfg.get("max_keys", 5000))

        # Maps (src_ip, dst_ip) -> deque of (ts, orig_bytes)
        self._history: dict[tuple[str, str], deque[tuple[float, int]]] = {}
        self._last_seen: dict[tuple[str, str], float] = {}

    def process(self, event: ConnectionEvent) -> list[Alert]:
        try:
            src_ip = getattr(event, "src_ip", "")
            dst_ip = getattr(event, "dst_ip", "")
            ts = float(getattr(event, "ts", 0.0))
            orig_bytes = int(getattr(event, "orig_bytes", 0) or 0)

            # 1. OUTBOUND ONLY: src_ip must be private AND dst_ip must be public
            if not (_is_private(src_ip) and _is_public(dst_ip)):
                return []

            # 2. Track per-(src_ip, dst_ip) history
            key = (src_ip, dst_ip)
            if key not in self._history:
                if len(self._history) >= self._max_keys:
                    self._evict_stale_keys(ts)
                self._history[key] = deque()

            dq = self._history[key]
            dq.append((ts, orig_bytes))
            self._last_seen[key] = ts
            prune_deque(dq, ts, self.window, ts_extractor=lambda entry: entry[0])

            # 3. Check connection count and byte thresholds
            total_bytes = sum(entry[1] for entry in dq)
            if len(dq) >= self.min_connections and total_bytes >= self.bytes_threshold:
                # 4. Check cooldown
                if self.is_in_cooldown(key, ts, cooldown=self.window):
                    return []

                self.mark_alerted(key, ts)
                severity = "CRITICAL" if total_bytes >= 2 * self.bytes_threshold else "HIGH"
                evidence = {
                    "total_bytes": total_bytes,
                    "bytes_threshold": self.bytes_threshold,
                    "connection_count": len(dq),
                    "min_connections": self.min_connections,
                    "window": self.window,
                }
                alert = self._alert(
                    event=event,
                    event_type="exfiltration",
                    severity=severity,
                    description=(
                        f"Data exfiltration detected: {src_ip} transferred {total_bytes:,} bytes "
                        f"to external {dst_ip} across {len(dq)} connections in {self.window}s"
                    ),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    evidence=evidence,
                )
                return [alert]

            return []
        except Exception:
            return []

    def _evict_stale_keys(self, current_ts: float) -> None:
        """Evict expired or oldest keys to bound memory within max_keys."""
        keys = list(self._history.keys())
        for k in keys:
            dq = self._history[k]
            prune_deque(dq, current_ts, self.window, ts_extractor=lambda entry: entry[0])
            if not dq:
                self._history.pop(k, None)
                self._last_seen.pop(k, None)

        if len(self._history) >= self._max_keys:
            sorted_keys = sorted(self._last_seen.items(), key=lambda kv: kv[1])
            for k, _ in sorted_keys[: max(1, len(sorted_keys) // 10)]:
                self._history.pop(k, None)
                self._last_seen.pop(k, None)

    def reset(self) -> None:
        super().reset()
        self._history.clear()
        self._last_seen.clear()
