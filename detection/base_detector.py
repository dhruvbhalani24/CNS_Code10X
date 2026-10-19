"""
Section 3.1 — Base detector abstraction.

All intrusion detectors inherit from BaseDetector. Each detector:
  * declares a unique `name` and `DEFAULTS` dictionary
  * merges runtime config safely over DEFAULTS
  * maintains internal state using event time (never wall-clock)
  * tracks per-key alert cooldowns to avoid alert storms
  * provides `_alert()` helper to construct canonical Alert objects
"""
from __future__ import annotations

import copy
from abc import ABC, abstractmethod
from typing import Any, Optional

from core.event import Alert, ConnectionEvent
from core.logger import get_logger


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge `override` dictionary into `base`."""
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value) if isinstance(value, (dict, list)) else value
    return base


class BaseDetector(ABC):
    """Abstract base class for all network intrusion detectors."""

    name: str = "base"
    DEFAULTS: dict[str, Any] = {}

    def __init__(self, cfg: Optional[dict[str, Any]] = None) -> None:
        merged = copy.deepcopy(self.DEFAULTS)
        if cfg is not None:
            if hasattr(cfg, "as_dict"):
                override = cfg.as_dict()
            elif isinstance(cfg, dict):
                override = cfg
            else:
                override = {}
            _deep_merge(merged, override)
        self.cfg: dict[str, Any] = merged

        self.log = get_logger(f"detector.{self.name}")
        self._last_alert: dict[Any, float] = {}

        # Default cooldown equals the detector window or 60.0s
        self.cooldown: float = float(self.cfg.get("cooldown", self.cfg.get("window", 60.0)))
        self._max_cooldown_keys: int = 5_000

    # ------------------------------------------------------------------ #
    #  Alert generation helper                                             #
    # ------------------------------------------------------------------ #
    def _alert(
        self,
        event: ConnectionEvent,
        event_type: str,
        severity: str,
        description: str,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        evidence: Optional[dict[str, Any]] = None,
    ) -> Alert:
        """Construct a canonical Alert anchored to the event's timestamp.

        Ensures `detected_by` matches `self.name` and `ts` equals `event.ts`.
        `src_ip` must be the offending attacker IP.
        """
        return Alert(
            event_type=event_type,
            severity=severity,
            description=description,
            src_ip=src_ip if src_ip is not None else getattr(event, "src_ip", ""),
            dst_ip=dst_ip if dst_ip is not None else getattr(event, "dst_ip", ""),
            detected_by=self.name,
            evidence=dict(evidence) if evidence else {},
            ts=float(getattr(event, "ts", 0.0)),
        )

    # ------------------------------------------------------------------ #
    #  Cooldown management (anti alert-storm)                              #
    # ------------------------------------------------------------------ #
    def is_in_cooldown(self, key: Any, current_ts: float, cooldown: Optional[float] = None) -> bool:
        """Check if an alert for `key` was emitted within the cooldown window."""
        cd = float(cooldown if cooldown is not None else self.cooldown)
        last_ts = self._last_alert.get(key)
        if last_ts is None:
            return False
        return 0.0 <= (current_ts - last_ts) < cd

    def mark_alerted(self, key: Any, current_ts: float) -> None:
        """Record an alert timestamp for `key` to activate cooldown."""
        if len(self._last_alert) >= self._max_cooldown_keys:
            self._prune_cooldowns(current_ts)
        self._last_alert[key] = current_ts

    def _prune_cooldowns(self, current_ts: float) -> None:
        """Prune expired cooldown keys to bound memory usage."""
        expired = [
            k for k, last_ts in self._last_alert.items()
            if (current_ts - last_ts) >= self.cooldown
        ]
        for k in expired:
            self._last_alert.pop(k, None)

        if len(self._last_alert) >= self._max_cooldown_keys:
            # Drop oldest entries if still over capacity
            sorted_keys = sorted(self._last_alert.items(), key=lambda kv: kv[1])
            for k, _ in sorted_keys[: len(sorted_keys) // 5]:
                self._last_alert.pop(k, None)

    def reset(self) -> None:
        """Reset internal detector state (useful between test runs)."""
        self._last_alert.clear()

    # ------------------------------------------------------------------ #
    #  Detector contract                                                   #
    # ------------------------------------------------------------------ #
    @abstractmethod
    def process(self, event: ConnectionEvent) -> list[Alert]:
        """Process one normalized connection event and return zero or more alerts.

        Must never raise exceptions on unexpected event inputs.
        """
        raise NotImplementedError
