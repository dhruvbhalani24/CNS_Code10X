"""
Section 7.4 — Telegram bot notifications.

Sends high-priority findings to a configured Telegram chat:
  * severity-tagged, emoji-marked, HTML-formatted message
  * built-in RATE LIMIT (Telegram caps bots at ~30 msg/s; we stay far
    below with a 20/minute budget so a flood cannot spam the analyst)
  * graceful no-op when token/chat_id are unset (demo machines)

Setup: talk to @BotFather → /newbot → paste token below or into
config.yaml under alerting.telegram.
"""
from __future__ import annotations

import html
import time
from collections import deque
from typing import Optional

import requests

from core.config import get_config
from core.event import Alert
from alerting.base_alerter import Alerter

_API = "https://api.telegram.org/bot{token}/sendMessage"
_EMOJI = {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "🔔",
          "LOW": "ℹ️", "INFO": "📝"}


class TelegramAlerter(Alerter):
    """Telegram channel with rate limiting and safe fallbacks."""

    name = "telegram"

    def __init__(self, token: Optional[str] = None,
                 chat_id: Optional[str] = None,
                 rate_per_minute: int = 20) -> None:
        super().__init__()
        cfg = get_config().alerting.telegram
        self.token = token or cfg.token
        self.chat_id = chat_id or cfg.chat_id
        self.timeout = cfg.timeout
        self._sent_times: deque[float] = deque()
        self.rate_limit = rate_per_minute
        self._warned = False

    # ------------------------------------------------------------------ #
    @property
    def configured(self) -> bool:
        return bool(self.token and self.chat_id)

    # ------------------------------------------------------------------ #
    def send(self, alert: Alert) -> None:
        if not self.configured:
            if not self._warned:
                self.log.info("Telegram not configured — messages "
                              "would go to chat %s", self.chat_id or "(none)")
                self._warned = True
            return
        if not self._rate_ok():
            self.log.warning("Telegram rate limit hit — dropping alert %s",
                             alert.alert_id)
            return
        try:
            requests.post(_API.format(token=self.token),
                          json={"chat_id": self.chat_id,
                                "text": self.format(alert),
                                "parse_mode": "HTML",
                                "disable_web_page_preview": True},
                          timeout=self.timeout)
        except requests.RequestException as exc:
            self.log.error("Telegram send failed: %s", exc)

    # ------------------------------------------------------------------ #
    def _rate_ok(self) -> bool:
        now = time.time()
        while self._sent_times and now - self._sent_times[0] > 60:
            self._sent_times.popleft()
        if len(self._sent_times) >= self.rate_limit:
            return False
        self._sent_times.append(now)
        return True

    # ------------------------------------------------------------------ #
    @staticmethod
    def format(alert: Alert) -> str:
        """Human-readable HTML message (all fields escaped)."""
        e = html.escape
        when = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(alert.ts))
        ev = alert.evidence or {}
        lines = [
            f"{_EMOJI.get(alert.severity, '🔔')} "
            f"<b>{e(alert.severity)} — {e(alert.event_type.upper())}</b>",
            f"🛡 CodeX10 NIDS-SIEM",
            "",
            f"<b>Source:</b> <code>{e(alert.src_ip)}</code>"
            f" → <b>Target:</b> <code>{e(alert.dst_ip)}</code>",
            f"<b>Detected by:</b> {e(alert.detected_by)}",
            f"<b>Time:</b> {when}",
            f"<b>Reason:</b> {e(alert.description)}",
        ]
        if ev.get("escalated"):
            lines.append(f"⏫ <i>Escalated after "
                         f"{ev.get('repeat_count', '?')} repeats</i>")
        return "\n".join(lines)
