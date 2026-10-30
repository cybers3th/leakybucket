"""Cooperative deadlines shared by inspection stages and blocking adapters."""
from contextlib import contextmanager
from contextvars import ContextVar
import math
import time


_deadline = ContextVar('inspection_deadline', default=None)


class InspectionTimeout(TimeoutError):
    pass


def positive_seconds(value: float) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or value <= 0:
        raise ValueError('Timeout must be finite and positive')
    return float(value)


def remaining_seconds(limit: float | None = None) -> float | None:
    deadline = _deadline.get()
    remaining = None if deadline is None else deadline - time.monotonic()
    if remaining is not None and remaining <= 0:
        raise InspectionTimeout('Inspection deadline exceeded')
    if limit is None:
        return remaining
    return min(remaining, limit) if remaining is not None else limit


@contextmanager
def inspection_budget(timeout: float):
    timeout = positive_seconds(timeout)
    parent = _deadline.get()
    deadline = time.monotonic() + timeout
    token = _deadline.set(min(parent, deadline) if parent is not None else deadline)
    try:
        remaining_seconds()
        yield
        remaining_seconds()
    finally:
        _deadline.reset(token)
