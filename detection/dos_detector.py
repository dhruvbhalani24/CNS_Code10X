"""
Section 3.4 — Denial of Service (DoS) flood detector.

Tracks high-frequency connection bursts against destination services
(dst_ip, dst_port) within a sliding event-time window.
Emits a DoS alert with severity CRITICAL if >70% of requests are incomplete
handshakes, otherwise HIGH.
"""
from __future__ import annotations

from collections import Counter, deque
from typing import Any, Optional

from core.event import Alert, ConnectionEvent
from detection.base_detector import BaseDetector
from detection.sliding_window import prune_deque


class DosDetector(BaseDetector):
    """Detects connection flooding / DoS attacks against targets."""

    name: str = "dos"
    DEFAULTS: dict[str, Any] = {
        "window": 10,
        "rate_threshold": 80,
    }

    def __init__(self, cfg: Optional[dict[str, Any]] = None) -> None:
        super().__init__(cfg)
        self.window: float = float(self.cfg.get("window", 10))
        self.rate_threshold: int = int(self.cfg.get("rate_threshold", 80))
        self._max_keys: int = int(self.cfg.get("max_keys", 5000))
        # Maps (dst_ip, dst_port) -> deque of (ts, src_ip, conn_state)
        self._history: dict[tuple[str, int], deque[tuple[float, str, str]]] = {}
        self._last_seen: dict[tuple[str, int], float] = {}

    def process(self, event: ConnectionEvent) -> list[Alert]:
        try:
            dst_ip = getattr(event, "dst_ip", "")
            dst_port = getattr(event, "dst_port", 0)
            src_ip = getattr(event, "src_ip", "")
            conn_state = (getattr(event, "conn_state", "") or "").upper()
            ts = float(getattr(event, "ts", 0.0))

            key = (dst_ip, dst_port)
            if key not in self._history:
                if len(self._history) >= self._max_keys:
                    self._evict_stale_keys(ts)
                self._history[key] = deque()

            dq = self._history[key]
            dq.append((ts, src_ip, conn_state))
            self._last_seen[key] = ts
            prune_deque(dq, ts, self.window, ts_extractor=lambda entry: entry[0])

            if len(dq) < self.rate_threshold:
                return []

            if self.is_in_cooldown(key, ts, cooldown=self.window):
                return []

            # Determine dominant attacker source IP
            src_counts = Counter(entry[1] for entry in dq)
            attacker_ip = src_counts.most_common(1)[0][0] if src_counts else src_ip

            # Incomplete handshakes check (>70% -> CRITICAL, else HIGH)
            incomplete = sum(1 for entry in dq if entry[2] in ("S0", "REJ", "RSTR"))
            ratio = incomplete / len(dq) if dq else 0.0
            severity = "CRITICAL" if ratio > 0.70 else "HIGH"

            self.mark_alerted(key, ts)

            evidence = {
                "rate": len(dq),
                "rate_threshold": self.rate_threshold,
                "window": self.window,
                "incomplete_ratio": round(ratio, 3),
                "attacker_count": src_counts[attacker_ip],
                "dst_port": dst_port,
            }
            alert = self._alert(
                event=event,
                event_type="dos",
                severity=severity,
                description=(
                    f"DoS flood detected against {dst_ip}:{dst_port}: "
                    f"{len(dq)} conns in {self.window}s from dominant src {attacker_ip}"
                ),
                src_ip=attacker_ip,
                dst_ip=dst_ip,
                evidence=evidence,
            )
            return [alert]
        except Exception:
            return []

    def _evict_stale_keys(self, current_ts: float) -> None:
        """Prune empty keys or drop oldest keys to respect memory limit."""
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


# Support both naming conventions
DoSDetector = DosDetector
