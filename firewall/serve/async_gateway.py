"""Async wrapper around the sync Gateway.

Runs the CPU-bound detector chain in a threadpool so the event loop stays
free. All public methods are `async def`. Uses an asyncio.Semaphore to
cap concurrent detector work (backpressure).
"""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from firewall import Gateway
from firewall.core.events import SecurityEvent


class AsyncGateway:
    def __init__(
        self,
        gateway: Gateway | None = None,
        max_workers: int = 16,
        max_concurrent: int = 128,
    ):
        self.gw = gateway or Gateway()
        self._executor = ThreadPoolExecutor(max_workers=max_workers,
                                              thread_name_prefix="lb-gw-")
        self._sem = asyncio.Semaphore(max_concurrent)

    async def process_input(self, event: SecurityEvent) -> SecurityEvent:
        async with self._sem:
            return await asyncio.get_running_loop().run_in_executor(
                self._executor, self.gw.process_input, event)

    async def process_output(self, event: SecurityEvent) -> SecurityEvent:
        async with self._sem:
            return await asyncio.get_running_loop().run_in_executor(
                self._executor, self.gw.process_output, event)

    async def request_tool(self, actor, tool, arguments, source=None):
        async with self._sem:
            return await asyncio.get_running_loop().run_in_executor(
                self._executor,
                lambda: self.gw.request_tool(actor=actor, tool=tool,
                                              arguments=arguments, source=source))

    async def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)
        self.gw.close()
