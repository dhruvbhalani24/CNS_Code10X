"""
Section 4.2 — Statistical anomaly detector (Placeholder).
"""
from __future__ import annotations

from typing import Any, Optional

from core.event import Alert, ConnectionEvent
from detection.base_detector import BaseDetector


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

    def process(self, event: ConnectionEvent) -> list[Alert]:
        return []
