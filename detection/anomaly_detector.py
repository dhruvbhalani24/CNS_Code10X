"""
Section 4.2 — Statistical anomaly detector.

Learns a rolling baseline of connection volume (orig_bytes) across the network.
Calculates one-sided z-scores to detect statistically anomalous traffic spikes
without poisoning the baseline with outlier data.
"""
from __future__ import annotations

from collections import deque
from typing import Any, Optional

from core.event import Alert, ConnectionEvent
from detection.base_detector import BaseDetector
from detection.sliding_window import prune_deque


class AnomalyDetector(BaseDetector):
    """Detects volume spikes using running baseline and z-score."""

    name: str = "anomaly"
    DEFAULTS: dict[str, Any] = {
        "window": 200,
        "zscore": 3.0,
        "min_samples": 20,
    }

    def __init__(self, cfg: Optional[dict[str, Any]] = None) -> None:
        super().__init__(cfg)
        self.window: float = float(self.cfg.get("window", 200))
        self.zscore: float = float(self.cfg.get("zscore", 3.0))
        self.min_samples: int = int(self.cfg.get("min_samples", 20))
        self.cooldown_seconds: float = float(self.cfg.get("cooldown", 60.0))

        # Global rolling baseline of (ts, orig_bytes)
        self._baseline: deque[tuple[float, int]] = deque()

    def process(self, event: ConnectionEvent) -> list[Alert]:
        try:
            ts = float(getattr(event, "ts", 0.0))
            orig_bytes = int(getattr(event, "orig_bytes", 0) or 0)
            src_ip = getattr(event, "src_ip", "")
            dst_ip = getattr(event, "dst_ip", "")

            # 1. Global baseline: prune entries older than ts - window
            prune_deque(self._baseline, ts, self.window, ts_extractor=lambda entry: entry[0])

            # 2. If fewer than min_samples, learn baseline and return []
            if len(self._baseline) < self.min_samples:
                self._baseline.append((ts, orig_bytes))
                return []

            # 3. Compute mean and population std over baseline only
            values = [entry[1] for entry in self._baseline]
            n = len(values)
            mean = sum(values) / n
            variance = sum((x - mean) ** 2 for x in values) / n
            std = max(1.0, 0.01 * mean, variance ** 0.5)

            # One-sided z-score
            z = (orig_bytes - mean) / std

            # 4. Outlier detection
            if z >= self.zscore:
                # Do NOT add outlier to baseline
                if self.is_in_cooldown(src_ip, ts, cooldown=self.cooldown_seconds):
                    return []

                self.mark_alerted(src_ip, ts)
                evidence = {
                    "value": orig_bytes,
                    "mean": round(mean, 2),
                    "std": round(std, 2),
                    "zscore": round(z, 2),
                    "threshold": self.zscore,
                    "baseline_samples": n,
                    "window": self.window,
                }
                alert = self._alert(
                    event=event,
                    event_type="anomaly",
                    severity="MEDIUM",
                    description=(
                        f"Traffic volume anomaly detected from {src_ip}: {orig_bytes:,} bytes "
                        f"(mean={mean:.1f}, std={std:.1f}, z={z:.1f} >= {self.zscore})"
                    ),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    evidence=evidence,
                )
                return [alert]

            # 5. Normal event: add to baseline
            self._baseline.append((ts, orig_bytes))
            return []
        except Exception:
            return []

    def reset(self) -> None:
        super().reset()
        self._baseline.clear()
