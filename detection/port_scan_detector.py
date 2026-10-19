"""
Section 3.3 — Vertical & horizontal port scan detector.

Tracks failed connection states (S0, REJ, RSTR) across destination ports
within a sliding event-time window. Emits an alert when the number of
unique destination ports targeted by a source exceeds `port_threshold`.
"""
from __future__ import annotations

from typing import Any, Optional

from core.event import Alert, ConnectionEvent
from detection.base_detector import BaseDetector
from detection.sliding_window import SlidingWindow


class PortScanDetector(BaseDetector):
    """Detects rapid scanning across multiple destination ports."""

    name: str = "port_scan"
    DEFAULTS: dict[str, Any] = {
        "window": 60,
        "port_threshold": 15,
        "fail_states": ["S0", "REJ", "RSTR"],
    }

    def __init__(self, cfg: Optional[dict[str, Any]] = None) -> None:
        super().__init__(cfg)
        self.window: float = float(self.cfg.get("window", 60))
        self.port_threshold: int = int(self.cfg.get("port_threshold", 15))
        self.fail_states: set[str] = {
            str(s).upper() for s in self.cfg.get("fail_states", ["S0", "REJ", "RSTR"])
        }
        self._max_keys: int = int(self.cfg.get("max_keys", 5000))
        self._sw = SlidingWindow(window=self.window, max_keys=self._max_keys)

    def process(self, event: ConnectionEvent) -> list[Alert]:
        try:
            conn_state = (getattr(event, "conn_state", "") or "").upper()
            if conn_state not in self.fail_states:
                return []

            src_ip = getattr(event, "src_ip", "")
            dst_ip = getattr(event, "dst_ip", "")
            dst_port = getattr(event, "dst_port", 0)
            ts = float(getattr(event, "ts", 0.0))

            key = (src_ip, dst_ip)

            # Record destination port under key and prune entries older than ts - window
            self._sw.append(key, dst_port, ts)

            if self.is_in_cooldown(key, ts, cooldown=self.window):
                return []

            distinct_ports = set(self._sw.get_items(key, ts))
            if len(distinct_ports) >= self.port_threshold:
                self.mark_alerted(key, ts)
                evidence = {
                    "distinct_ports": len(distinct_ports),
                    "port_threshold": self.port_threshold,
                    "window": self.window,
                    "scanned_ports": sorted(distinct_ports)[:10],
                    "conn_state": conn_state,
                }
                alert = self._alert(
                    event=event,
                    event_type="port_scan",
                    severity="HIGH",
                    description=(
                        f"Port scan detected: {src_ip} probed {len(distinct_ports)} "
                        f"distinct ports on {dst_ip} in {self.window}s"
                    ),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    evidence=evidence,
                )
                return [alert]

            return []
        except Exception:
            return []

    def reset(self) -> None:
        super().reset()
        self._sw.clear()
