"""Token-bucket + counter rate limiter."""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """Per-key token-bucket + cumulative counters.

    Keys are strings — typically 'session:tool:X' or 'user:Y' etc.
    """

    def __init__(self, default_rate_per_minute: int = 60, capacity: int = 60):
        self.rate = default_rate_per_minute
        self.capacity = capacity
        self._buckets: dict[str, _Bucket] = defaultdict(
            lambda: _Bucket(capacity, time.time())
        )
        self._counts: dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0,
              rate_per_minute: int | None = None,
              capacity: int | None = None) -> tuple[bool, str]:
        rate = rate_per_minute or self.rate
        cap = capacity or self.capacity
        with self._lock:
            b = self._buckets[key]
            now = time.time()
            elapsed = now - b.updated
            b.tokens = min(cap, b.tokens + elapsed * rate / 60.0)
            b.updated = now
            if b.tokens < cost:
                return False, f"rate limit exceeded for {key} (tokens={b.tokens:.2f})"
            b.tokens -= cost
            self._counts[key] += 1
            return True, ""

    def count(self, key: str) -> int:
        return self._counts[key]
