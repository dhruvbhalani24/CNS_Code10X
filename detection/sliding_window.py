"""
Section 3.2 — Sliding window state management.

Provides bounded, event-time sliding windows and deque pruning utilities.
Ensures memory safety across high-throughput event streams by:
  * pruning expired records using event timestamps (never wall-clock)
  * bounding deques with maxlen or timestamp cutoffs
  * capping maximum tracked keys in dictionaries
"""
from __future__ import annotations

from collections import deque
from typing import Any, Callable, Iterator, Optional


def prune_deque(
    dq: deque[Any],
    current_ts: float,
    window: float,
    ts_extractor: Optional[Callable[[Any], float]] = None,
) -> None:
    """Prune items from the left of `dq` older than `current_ts - window` in-place.

    Args:
        dq: The deque to prune.
        current_ts: Current event timestamp.
        window: Window duration in seconds.
        ts_extractor: Optional callable returning a float timestamp for an item.
                      Defaults to item[0] if tuple/list, item.ts if attribute,
                      or float(item) if numeric.
    """
    if ts_extractor is None:
        def _default_extractor(entry: Any) -> float:
            if isinstance(entry, (int, float)):
                return float(entry)
            if isinstance(entry, (tuple, list)) and entry:
                return float(entry[0])
            if hasattr(entry, "ts"):
                return float(entry.ts)
            return float(entry)
        ts_extractor = _default_extractor

    cutoff = current_ts - window
    while dq and ts_extractor(dq[0]) < cutoff:
        dq.popleft()


class SlidingWindow:
    """Bounded, time-pruned sliding window dictionary keyed by arbitrary identifier.

    Maintains a separate deque of `(ts, payload)` entries per key, automatically
    pruning entries outside the time window `[current_ts - window, current_ts]`.
    """

    def __init__(self, window: float, max_keys: int = 10_000) -> None:
        self.window = float(window)
        self.max_keys = max_keys
        self._data: dict[Any, deque[tuple[float, Any]]] = {}
        self._last_seen: dict[Any, float] = {}

    def append(self, key: Any, item: Any, ts: float) -> deque[tuple[float, Any]]:
        """Add `item` at timestamp `ts` under `key`, pruning expired records."""
        if key not in self._data:
            if len(self._data) >= self.max_keys:
                self._evict_stale_keys(ts)
            self._data[key] = deque()

        dq = self._data[key]
        dq.append((ts, item))
        self._last_seen[key] = ts
        prune_deque(dq, ts, self.window, ts_extractor=lambda entry: entry[0])
        return dq

    def get_entries(self, key: Any, current_ts: Optional[float] = None) -> list[tuple[float, Any]]:
        """Return all active `(ts, item)` tuples for `key`."""
        dq = self._data.get(key)
        if dq is None:
            return []
        if current_ts is not None:
            prune_deque(dq, current_ts, self.window, ts_extractor=lambda entry: entry[0])
        return list(dq)

    def get_items(self, key: Any, current_ts: Optional[float] = None) -> list[Any]:
        """Return all active items (without ts) for `key`."""
        return [entry[1] for entry in self.get_entries(key, current_ts)]

    def count(self, key: Any, current_ts: Optional[float] = None) -> int:
        """Return the number of unexpired entries for `key`."""
        dq = self._data.get(key)
        if dq is None:
            return 0
        if current_ts is not None:
            prune_deque(dq, current_ts, self.window, ts_extractor=lambda entry: entry[0])
        return len(dq)

    def prune_key(self, key: Any, current_ts: float) -> None:
        """Prune expired items for `key`; drop the key if its deque becomes empty."""
        dq = self._data.get(key)
        if dq is not None:
            prune_deque(dq, current_ts, self.window, ts_extractor=lambda entry: entry[0])
            if not dq:
                self._data.pop(key, None)
                self._last_seen.pop(key, None)

    def prune_all(self, current_ts: float) -> None:
        """Prune all keys across the dictionary and remove empty ones."""
        keys = list(self._data.keys())
        for k in keys:
            self.prune_key(k, current_ts)

    def clear(self) -> None:
        """Clear all stored state."""
        self._data.clear()
        self._last_seen.clear()

    def _evict_stale_keys(self, current_ts: float) -> None:
        """Remove empty or oldest keys to keep dictionary size under `max_keys`."""
        self.prune_all(current_ts)
        if len(self._data) >= self.max_keys:
            # Drop the oldest 10% of keys by last access
            sorted_keys = sorted(self._last_seen.items(), key=lambda kv: kv[1])
            drop_count = max(1, len(sorted_keys) // 10)
            for k, _ in sorted_keys[:drop_count]:
                self._data.pop(k, None)
                self._last_seen.pop(k, None)


class TimeWindow:
    """Single-stream sliding time window (unkeyed).

    Useful for tracking overall event rates or sample baselines.
    """

    def __init__(self, window: float, maxlen: Optional[int] = None) -> None:
        self.window = float(window)
        self._dq: deque[tuple[float, Any]] = deque(maxlen=maxlen)

    def append(self, item: Any, ts: float) -> None:
        self._dq.append((ts, item))
        prune_deque(self._dq, ts, self.window, ts_extractor=lambda entry: entry[0])

    def items(self, current_ts: Optional[float] = None) -> list[Any]:
        if current_ts is not None:
            prune_deque(self._dq, current_ts, self.window, ts_extractor=lambda entry: entry[0])
        return [entry[1] for entry in self._dq]

    def count(self, current_ts: Optional[float] = None) -> int:
        if current_ts is not None:
            prune_deque(self._dq, current_ts, self.window, ts_extractor=lambda entry: entry[0])
        return len(self._dq)

    def clear(self) -> None:
        self._dq.clear()
