"""
Section 7.2 — Repeat-offence escalation policy.

A single MEDIUM alert is noise; the SAME alert type from the SAME
source firing again and again is a live incident. This policy counts
repeats inside a sliding window and bumps severity:

    repeats ≥  N      →  one level up   (e.g. MEDIUM → HIGH)
    repeats ≥ 2N      →  two levels up  (e.g. MEDIUM → CRITICAL)

Escalated alerts bypass the dedup cooldown in AlertManager — urgent
findings must always reach the analyst.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Optional

from core.event import SEVERITY_LEVELS, Alert


class EscalationPolicy:
    """Counts repeated alerts per (event_type, src_ip) and escalates."""

    def __init__(self, repeats_per_level: int = 3,
                 window_seconds: float = 600.0) -> None:
        self.repeats_per_level = repeats_per_level
        self.window = window_seconds
        self._history: dict[tuple, deque[float]] = defaultdict(deque)

    # ------------------------------------------------------------------ #
    def apply(self, alert: Alert) -> tuple[Alert, bool]:
        """Count this alert, maybe raise its severity. Returns
        (possibly-modified alert, escalated?)."""
        key = (alert.event_type, alert.src_ip)
        hist = self._history[key]
        hist.append(alert.ts)
        # prune repeats older than the window
        while hist and alert.ts - hist[0] > self.window:
            hist.popleft()

        repeats = len(hist)
        if repeats < self.repeats_per_level:
            return alert, False

        levels_up = min(2, repeats // self.repeats_per_level)
        try:
            rank = SEVERITY_LEVELS.index(alert.severity)
        except ValueError:
            rank = 0
        new_rank = min(len(SEVERITY_LEVELS) - 1, rank + levels_up)
        if new_rank == rank:
            return alert, False

        alert.severity = SEVERITY_LEVELS[new_rank]
        alert.evidence = alert.evidence or {}
        alert.evidence["escalated"] = True
        alert.evidence["repeat_count"] = repeats
        alert.evidence["escalated_from"] = SEVERITY_LEVELS[rank]
        return alert, True

    def reset(self) -> None:
        self._history.clear()
