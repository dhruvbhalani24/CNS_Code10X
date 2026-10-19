"""
Section 4.3 — Data exfiltration detector (Placeholder).
"""
from __future__ import annotations

from typing import Any, Optional

from core.event import Alert, ConnectionEvent
from detection.base_detector import BaseDetector


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

    def process(self, event: ConnectionEvent) -> list[Alert]:
        return []
