"""Section 2.1 — Sensor abstract base class."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from core.event import ConnectionEvent
from core.logger import get_logger


class BaseSensor(ABC):
    """A sensor is anything that yields a stream of ConnectionEvents."""

    name: str = "base"

    def __init__(self) -> None:
        self.log = get_logger(f"sensor.{self.name}")
        self._running = False

    @abstractmethod
    def stream(self) -> Iterator[ConnectionEvent]:
        """Yield events. In live mode this may block forever."""
        raise NotImplementedError

    # -- optional lifecycle hooks (override in live sensors) --------------
    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    # -- context manager so sensors are always cleaned up ------------------
    def __enter__(self) -> "BaseSensor":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()
