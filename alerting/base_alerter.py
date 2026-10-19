"""
Section 7.1 — Alert channel abstraction.

An "Alerter" is any delivery channel: console, JSONL audit file,
Telegram, the live dashboard bus (Section 8), email, webhook…
The AlertManager fans every qualifying alert out to all channels.
"""
from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from core.config import get_config
from core.event import Alert
from core.logger import get_logger

_SEV_COLOR = {"CRITICAL": "\033[91m", "HIGH": "\033[93m",
              "MEDIUM": "\033[94m", "LOW": "\033[92m",
              "INFO": "\033[90m"}
_RESET = "\033[0m"


class Alerter(ABC):
    """Base class for every alert delivery channel."""

    name: str = "base"

    def __init__(self) -> None:
        self.log = get_logger(f"alerter.{self.name}")

    @abstractmethod
    def send(self, alert: Alert) -> None:
        """Deliver one alert. Must never raise (log failures instead)."""
        raise NotImplementedError


class ConsoleAlerter(Alerter):
    """Pretty-printed console notifications (default channel)."""

    name = "console"

    def send(self, alert: Alert) -> None:
        color = _SEV_COLOR.get(alert.severity, "")
        print(f"{color}[{alert.severity:^8}]{_RESET} "
              f"{alert.event_type:<16} {alert.src_ip:<15} → "
              f"{alert.dst_ip:<15} {alert.description}")


class JsonlAlerter(Alerter):
    """Appends every alert to a JSONL audit file (SIEM evidence trail)."""

    name = "jsonl"

    def __init__(self, path: Optional[str] = None) -> None:
        super().__init__()
        cfg = get_config()
        self.path = Path(path or "data/alerts.jsonl")
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, alert: Alert) -> None:
        try:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"received_at": time.time(),
                                     **alert.to_dict()}) + "\n")
        except OSError as exc:
            self.log.error("failed to write audit file: %s", exc)
