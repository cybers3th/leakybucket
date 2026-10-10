"""Token-bucket + counter rate limiter."""
from __future__ import annotations

import math
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

    def __init__(self, default_rate_per_minute: int = 60, capacity: int = 60,
                 max_keys: int = 10_000):
        if default_rate_per_minute <= 0 or capacity <= 0 or max_keys <= 0:
            raise ValueError("rate limiter limits must be positive")
        self.max_keys = max_keys
        self.rate = default_rate_per_minute
        self.capacity = capacity
        self._buckets: dict[str, _Bucket] = defaultdict(
            lambda: _Bucket(capacity, time.monotonic())
        )
        self._counts: dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0,
              rate_per_minute: int | None = None,
              capacity: int | None = None) -> tuple[bool, str]:
        rate = self.rate if rate_per_minute is None else rate_per_minute
        cap = self.capacity if capacity is None else capacity
        if not all(isinstance(v, (int, float)) and math.isfinite(v) and v > 0
                   for v in (cost, rate, cap)):
            return False, "invalid or disabled rate limit"
        with self._lock:
            if len(key) > 4096 or (key not in self._buckets and len(self._buckets) >= self.max_keys):
                return False, "rate limiter state budget exceeded"
            b = self._buckets[key]
            now = time.monotonic()
            elapsed = now - b.updated
            b.tokens = min(cap, b.tokens + elapsed * rate / 60.0)
            b.updated = now
            if b.tokens < cost:
                return False, f"rate limit exceeded for {key} (tokens={b.tokens:.2f})"
            b.tokens -= cost
            self._counts[key] += 1
            return True, ""

    def count(self, key: str) -> int:
        with self._lock:
            return self._counts.get(key, 0)
