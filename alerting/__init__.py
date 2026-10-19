"""
Section 7 — Alerting layer.

  * base_alerter.py    — channel ABC + console & JSONL audit channels
  * alert_manager.py   — severity gate, dedup/cooldown, dispatch, escalation
  * escalation.py      — repeat-offence severity escalation policy
  * telegram_alerter.py— Telegram bot notifications with rate limiting
"""
from alerting.base_alerter import Alerter, ConsoleAlerter, JsonlAlerter
from alerting.escalation import EscalationPolicy
from alerting.alert_manager import AlertManager
from alerting.telegram_alerter import TelegramAlerter

__all__ = ["Alerter", "ConsoleAlerter", "JsonlAlerter",
           "EscalationPolicy", "AlertManager", "TelegramAlerter"]
