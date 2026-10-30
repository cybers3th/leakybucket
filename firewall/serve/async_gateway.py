"""Bounded asynchronous admission around a shared synchronous gateway."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
import threading
import time
from collections import deque

from firewall import Gateway
from firewall.core.deadline import InspectionTimeout, inspection_budget, positive_seconds, remaining_seconds
from firewall.core.events import SecurityEvent


class GatewayOverloaded(RuntimeError):
    pass


class GatewayClosed(RuntimeError):
    pass


class AsyncGateway:
    def __init__(self, gateway: Gateway | None = None, max_workers: int = 1,
                 max_concurrent: int = 16, inspection_timeout: float = 10):
        if (type(max_workers) is not int or type(max_concurrent) is not int
                or min(max_workers, max_concurrent) <= 0):
            raise ValueError('Worker and admission limits must be positive integers')
        self.inspection_timeout = positive_seconds(inspection_timeout)
        self.gw = gateway or Gateway()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='lb-gw-')
        self._capacity = max_concurrent
        self._state_lock = threading.Lock()
        self._gateway_lock = threading.Lock()
        self._active = 0
        self._latencies = deque(maxlen=1024)
        self._closed = False
        self._audit_closed = False
        self._stats = dict(admitted=0, rejected=0, completed=0, timed_out=0, failed=0)

    def snapshot(self) -> dict:
        healthy = getattr(getattr(self.gw, "audit", None), "healthy", True)
        with self._state_lock:
            samples = sorted(self._latencies)
            return {**self._stats, 'in_flight': self._active,
                    'capacity': self._capacity, 'closed': self._closed, 'healthy': healthy,
                    'latency_samples': len(samples),
                    'p50_seconds': samples[int((len(samples)-1)*.5)] if samples else None,
                    'p95_seconds': samples[int((len(samples)-1)*.95)] if samples else None}

    def _release(self, _future):
        with self._state_lock:
            self._active -= 1
            self._stats['completed'] += 1
            if self._closed and not self._active and not self._audit_closed:
                self.gw.close()
                self._audit_closed = True

    async def _run(self, operation):
        with self._state_lock:
            if self._closed:
                raise GatewayClosed('Gateway is shutting down')
            if self._active >= self._capacity:
                self._stats['rejected'] += 1
                raise GatewayOverloaded('Inspection capacity exhausted')
            self._active += 1
            self._stats['admitted'] += 1
        deadline = time.monotonic() + self.inspection_timeout
        def work():
            with inspection_budget(max(deadline - time.monotonic(), 1e-9)):
                if time.monotonic() >= deadline:
                    raise InspectionTimeout('Inspection expired in queue')
                if not self._gateway_lock.acquire(timeout=remaining_seconds()):
                    raise InspectionTimeout('Inspection expired waiting for gateway')
                try:
                    remaining_seconds()
                    result = operation()
                    remaining_seconds()
                    return result
                finally:
                    self._gateway_lock.release()
        try:
            future = self._executor.submit(copy_context().run, work)
        except BaseException:
            with self._state_lock:
                self._active -= 1
            raise
        future.add_done_callback(self._release)
        wrapped = asyncio.wrap_future(future)
        # A caller timeout cannot terminate a Python thread. Retain admission
        # until the worker exits so repeated timeouts cannot grow the queue.
        wrapped.add_done_callback(lambda f: None if f.cancelled() else f.exception())
        try:
            done, _ = await asyncio.wait({wrapped}, timeout=self.inspection_timeout)
            if not done:
                raise InspectionTimeout('Inspection deadline exceeded')
            return wrapped.result()
        except (asyncio.TimeoutError, InspectionTimeout) as error:
            with self._state_lock:
                self._stats['timed_out'] += 1
            raise InspectionTimeout('Inspection deadline exceeded') from error
        except Exception:
            with self._state_lock:
                self._stats['failed'] += 1
            raise
        finally:
            with self._state_lock:
                self._latencies.append(time.monotonic() - (deadline - self.inspection_timeout))

    async def process_input(self, event: SecurityEvent) -> SecurityEvent:
        return await self._run(lambda: self.gw.process_input(event))

    async def process_output(self, event: SecurityEvent) -> SecurityEvent:
        return await self._run(lambda: self.gw.process_output(event))

    async def request_tool(self, actor, tool, arguments, source=None):
        return await self._run(lambda: self.gw.request_tool(actor=actor, tool=tool,
                                                          arguments=arguments, source=source))

    async def close(self) -> None:
        with self._state_lock:
            self._closed = True
            if not self._active and not self._audit_closed:
                self.gw.close()
                self._audit_closed = True
        self._executor.shutdown(wait=False, cancel_futures=True)
