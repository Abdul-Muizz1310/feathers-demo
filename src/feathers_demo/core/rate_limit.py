"""In-process fixed-window rate limiting.

One counter per key per window, held in this process's memory: right for a single
instance, reset on restart. Keys are chosen by the caller (see
``platform_token.rate_limit_key``).
"""

from __future__ import annotations

import time
from collections.abc import Callable


class FixedWindowLimiter:
    """Allow at most ``limit`` hits per key in each ``window_s``-second window."""

    def __init__(
        self,
        *,
        limit: int,
        window_s: float,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 10_000,
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if window_s <= 0:
            raise ValueError("window_s must be positive")
        if max_keys < 1:
            raise ValueError("max_keys must be at least 1")
        self._limit = limit
        self._window_s = window_s
        self._clock = clock
        self._max_keys = max_keys
        self._windows: dict[str, tuple[float, int]] = {}

    def allow(self, key: str) -> bool:
        """Count a hit for ``key``; False once ``key`` is over its limit in this window."""
        now = self._clock()
        start, count = self._windows.get(key, (now, 0))
        if now - start >= self._window_s:
            start, count = now, 0
        if count >= self._limit:
            return False
        if key not in self._windows and len(self._windows) >= self._max_keys:
            self._forget_expired(now)
        self._windows[key] = (start, count + 1)
        return True

    @property
    def tracked_keys(self) -> int:
        """How many keys currently hold a window (memory bound check)."""
        return len(self._windows)

    def _forget_expired(self, now: float) -> None:
        window_s = self._window_s
        self._windows = {k: w for k, w in self._windows.items() if now - w[0] < window_s}
