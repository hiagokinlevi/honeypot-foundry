from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict


@dataclass(frozen=True)
class RateLimitDecision:
    triggered: bool
    count_in_window: int
    threshold: int
    window_seconds: float


class InMemoryPerIPRateLimiter:
    """Lightweight sliding-window per-IP burst detector.

    This limiter is intentionally in-memory and process-local for honeypot telemetry.
    It can be used in observe-only mode (emit events but allow flow) or enforcement mode.
    """

    def __init__(self, threshold: int, window_seconds: float) -> None:
        self.threshold = max(1, int(threshold))
        self.window_seconds = max(0.001, float(window_seconds))
        self._buckets: Dict[str, Deque[float]] = defaultdict(deque)

    def hit(self, source_ip: str, now: float | None = None) -> RateLimitDecision:
        ts = time.monotonic() if now is None else now
        q = self._buckets[source_ip]
        cutoff = ts - self.window_seconds
        while q and q[0] < cutoff:
            q.popleft()
        q.append(ts)
        count = len(q)
        return RateLimitDecision(
            triggered=count > self.threshold,
            count_in_window=count,
            threshold=self.threshold,
            window_seconds=self.window_seconds,
        )
