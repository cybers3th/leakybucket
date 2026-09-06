"""Distributed state layer — in-memory + Redis backends.

BehaviorEngine and RateLimiter currently keep state in-process. In a
multi-pod deployment that means a session pinned to pod A gets fresh state
on pod B. This backend is an abstract KV interface with two concrete
implementations. Callers that want shared state pass a RedisState;
tests and local dev use InMemoryState.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Any


class StateBackend(ABC):
    @abstractmethod
    def get(self, key: str) -> str | None: ...
    @abstractmethod
    def set(self, key: str, value: str, ttl_s: int | None = None) -> None: ...
    @abstractmethod
    def incr(self, key: str, by: int = 1, ttl_s: int | None = None) -> int: ...
    @abstractmethod
    def rpush(self, key: str, value: str, cap: int | None = None) -> None: ...
    @abstractmethod
    def lrange(self, key: str, start: int = 0, end: int = -1) -> list[str]: ...
    @abstractmethod
    def delete(self, key: str) -> None: ...


class InMemoryState(StateBackend):
    def __init__(self):
        self._kv: dict[str, tuple[str, float | None]] = {}
        self._lists: dict[str, list[str]] = defaultdict(list)
        self._lock = threading.Lock()

    def _expired(self, exp: float | None) -> bool:
        return exp is not None and time.time() > exp

    def get(self, key: str) -> str | None:
        with self._lock:
            v = self._kv.get(key)
            if v is None: return None
            val, exp = v
            if self._expired(exp):
                del self._kv[key]
                return None
            return val

    def set(self, key: str, value: str, ttl_s: int | None = None) -> None:
        with self._lock:
            exp = time.time() + ttl_s if ttl_s else None
            self._kv[key] = (value, exp)

    def incr(self, key: str, by: int = 1, ttl_s: int | None = None) -> int:
        with self._lock:
            v = self._kv.get(key)
            cur = int(v[0]) if v and not self._expired(v[1]) else 0
            new = cur + by
            exp = time.time() + ttl_s if ttl_s else (v[1] if v else None)
            self._kv[key] = (str(new), exp)
            return new

    def rpush(self, key: str, value: str, cap: int | None = None) -> None:
        with self._lock:
            self._lists[key].append(value)
            if cap and len(self._lists[key]) > cap:
                self._lists[key] = self._lists[key][-cap:]

    def lrange(self, key: str, start: int = 0, end: int = -1) -> list[str]:
        with self._lock:
            lst = self._lists.get(key, [])
            if end == -1:
                return list(lst[start:])
            return list(lst[start:end+1])

    def delete(self, key: str) -> None:
        with self._lock:
            self._kv.pop(key, None)
            self._lists.pop(key, None)


class RedisState(StateBackend):
    """Redis backend. Lazy imports redis so it's optional.

    Uses the sync `redis` client wrapped by threadpool for use from asyncio
    contexts. If your redis client is async, adapt accordingly.
    """
    def __init__(self, url: str = "redis://localhost:6379/0", prefix: str = "lb:"):
        try:
            import redis
        except ImportError as e:
            raise RuntimeError("pip install redis[hiredis] to use RedisState") from e
        self.r = redis.from_url(url, decode_responses=True)
        self.p = prefix

    def _k(self, key: str) -> str: return self.p + key

    def get(self, key): return self.r.get(self._k(key))

    def set(self, key, value, ttl_s=None):
        if ttl_s: self.r.setex(self._k(key), ttl_s, value)
        else: self.r.set(self._k(key), value)

    def incr(self, key, by=1, ttl_s=None):
        pipe = self.r.pipeline()
        pipe.incrby(self._k(key), by)
        if ttl_s:
            pipe.expire(self._k(key), ttl_s)
        return pipe.execute()[0]

    def rpush(self, key, value, cap=None):
        pipe = self.r.pipeline()
        pipe.rpush(self._k(key), value)
        if cap:
            pipe.ltrim(self._k(key), -cap, -1)
        pipe.execute()

    def lrange(self, key, start=0, end=-1):
        return self.r.lrange(self._k(key), start, end)

    def delete(self, key):
        self.r.delete(self._k(key))
