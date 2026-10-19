"""
Section 7.3 — Alert manager: the brain of the alerting layer.

Responsibilities (in order, per alert):
  1. SEVERITY GATE  — below min_severity? drop.
  2. ESCALATION     — repeat offences get bumped (Section 7.2);
                      escalated alerts BYPASS the cooldown.
  3. DEDUP/COOLDOWN — same (event_type, src_ip) inside the cooldown
                      window is suppressed (anti alert-storm).
  4. DISPATCH       — fan out to every registered channel
                      (console, JSONL, Telegram, live bus…).

Every decision is counted, so evaluation (Section 9) can report
exactly how many alerts were suppressed vs delivered.
"""
from __future__ import annotations

from typing import Optional

from core.config import get_config
from core.event import Alert, severity_rank
from core.logger import get_logger
from alerting.base_alerter import Alerter, ConsoleAlerter, JsonlAlerter
from alerting.escalation import EscalationPolicy
from alerting.telegram_alerter import TelegramAlerter


class AlertManager:
    """Central alert routing with gating, escalation and dedup."""

    def __init__(self,
                 min_severity: Optional[str] = None,
                 cooldown: Optional[float] = None,
                 channels: Optional[list[Alerter]] = None,
                 escalation: Optional[EscalationPolicy] = None) -> None:
        cfg = get_config()
        self.min_rank = severity_rank(min_severity or cfg.alerting.min_severity)
        self.cooldown = float(cooldown if cooldown is not None
                              else cfg.alerting.cooldown)
        self.channels: list[Alerter] = channels if channels is not None else []
        self.escalation = escalation if escalation is not None \
            else EscalationPolicy()
        self.log = get_logger("alert_manager")
        self._last_sent: dict[tuple, float] = {}
        self.counters = {"received": 0, "dispatched": 0,
                         "suppressed_severity": 0, "suppressed_duplicate": 0,
                         "escalated": 0}

    # ------------------------------------------------------------------ #
    @classmethod
    def default(cls) -> "AlertManager":
        """Standard channel set: console + JSONL + Telegram (if enabled)."""
        channels: list[Alerter] = [ConsoleAlerter(), JsonlAlerter()]
        cfg = get_config()
        if cfg.alerting.telegram.enabled:
            channels.append(TelegramAlerter())
            # ensure Telegram only receives its own min severity +
            return cls(min_severity=cfg.alerting.min_severity,
                       channels=channels)
        return cls(channels=channels)

    # ------------------------------------------------------------------ #
    def handle(self, alert: Alert) -> bool:
        """Process one alert. Returns True if it was dispatched."""
        self.counters["received"] += 1

        # 1 — severity gate -------------------------------------------------
        if severity_rank(alert.severity) < self.min_rank:
            self.counters["suppressed_severity"] += 1
            return False

        # 2 — escalation ------------------------------------------------------
        alert, escalated = self.escalation.apply(alert)
        if escalated:
            self.counters["escalated"] += 1
            self.log.warning("ESCALATED %s from %s → %s",
                             alert.event_type,
                             alert.evidence.get("escalated_from"),
                             alert.severity)

        # 3 — dedup / cooldown (bypassed when escalated) ----------------------
        if not escalated:
            key = (alert.event_type, alert.src_ip)
            if alert.ts - self._last_sent.get(key, 0.0) < self.cooldown:
                self.counters["suppressed_duplicate"] += 1
                return False
            self._last_sent[key] = alert.ts

        # 4 — dispatch ---------------------------------------------------------
        for channel in self.channels:
            try:
                channel.send(alert)
            except Exception as exc:
                self.log.error("channel %s failed: %s", channel.name, exc)
        self.counters["dispatched"] += 1
        return True

    def reset(self) -> None:
        self.escalation.reset()
        self._last_sent.clear()
        for k in self.counters:
            self.counters[k] = 0
