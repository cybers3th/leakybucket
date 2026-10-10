"""Streaming SSE inspection with hard-cut mid-response.

The upstream LLM returns Server-Sent Events (Chat Completions-style
streaming). We ingest each chunk as it arrives, maintain a rolling window
of decoded output, run the OUTPUT-side detectors on the window as it
grows, and terminate the stream the moment any critical detection fires.
The client sees a clean stream, then a `data: {"error": ...}` terminator.

Detectors run on windows, not per token, because a secret or SQLi pattern
must be seen as a contiguous span; token boundaries in streamed responses
split payloads across chunks (this is exactly what makes streaming attacks
work — the naive approach of scanning per-chunk misses everything).
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import AsyncIterator, Callable

from firewall.core.events import (
    Actor, DataClassification, Decision, Detection, SecurityEvent, Source,
    SourceKind, TrustLevel,
)


class HardCut(Exception):
    """Raised inside the stream when a critical detection fires."""
    def __init__(self, event: SecurityEvent, reason: str):
        super().__init__(reason)
        self.event = event
        self.reason = reason


@dataclass
class _WindowState:
    buf: str = ""
    total_chars: int = 0
    total_chunks: int = 0
    detections: list[Detection] = field(default_factory=list)
    finalized: bool = False


class StreamingInspector:
    """Wraps a Gateway and inspects an async chunk-stream in real time."""

    def __init__(
        self,
        gateway,
        actor: Actor,
        model: str = "",
        provider: str = "",
        # window sizing — smaller = lower latency but riskier for split payloads
        window_chars: int = 4096,
        overlap_chars: int = 512,
        # run the detectors at least this often (chars added)
        scan_stride_chars: int = 256,
        # cap total output length to avoid runaway generation
        max_output_chars: int = 200_000,
        # optional caller callback fired when a detection lands
        on_detection: Callable[[Detection], None] | None = None,
        buffer_until_verified: bool = True,
    ):
        if min(window_chars, scan_stride_chars, max_output_chars) <= 0 or overlap_chars < 0:
            raise ValueError("stream limits must be positive")
        constraints = gateway.output_constraints
        if not buffer_until_verified and (constraints.schema is not None or
                constraints.forbidden_literals or constraints.forbidden_markers or
                constraints.forbidden_action_prefixes or gateway.output_validators):
            raise ValueError("Application output constraints require buffered verification")
        self.buffer_until_verified = buffer_until_verified
        self.gateway = gateway
        self.actor = actor
        self.model = model
        self.provider = provider
        self.window_chars = window_chars
        self.overlap_chars = overlap_chars
        self.scan_stride_chars = scan_stride_chars
        self.max_output_chars = max_output_chars
        self.on_detection = on_detection

    async def inspect(
        self,
        chunks: AsyncIterator[str],
    ) -> AsyncIterator[str]:
        """Yields inspected chunks. Raises HardCut on a critical detection.

        The caller is expected to catch HardCut, close the upstream, and
        emit a terminator to the client (see build_openai_app for wiring).
        """
        st = _WindowState()
        last_scan_at = 0
        pending = []
        async for chunk in chunks:
            if not chunk:
                continue
            st.total_chunks += 1
            st.buf += chunk
            st.total_chars += len(chunk)

            if st.total_chars > self.max_output_chars:
                raise HardCut(
                    self._make_event(st, "max_output"),
                    f"max_output_chars ({self.max_output_chars}) exceeded",
                )

            # Keep the buffer trimmed to (window + overlap)
            excess = len(st.buf) - (self.window_chars + self.overlap_chars)
            if excess > 0:
                st.buf = st.buf[excess:]

            # Decide whether to run detectors on the current buffer
            if st.total_chars - last_scan_at >= self.scan_stride_chars \
                    or _endswith_boundary(chunk):
                last_scan_at = st.total_chars
                critical = self._scan(st)
                if critical is not None:
                    raise HardCut(self._make_event(st, critical.subcategory or "critical"),
                                   f"{critical.category}/{critical.subcategory} {critical.message}")

            # Chunk is safe to pass through (nothing critical up to here)
            if self.buffer_until_verified:
                pending.append(chunk)
            else:
                yield chunk

        # Final pass on tail
        st.finalized = True
        crit = self._scan(st)
        if crit is not None:
            raise HardCut(self._make_event(st, crit.subcategory or "critical"),
                           f"{crit.category}/{crit.subcategory} {crit.message}")

        if self.buffer_until_verified:
            # The complete response is inspected before any content is released.
            # This also covers payloads longer than a rolling window.
            complete = _WindowState(buf="".join(pending), total_chars=st.total_chars)
            complete.detections = st.detections
            critical = self._scan(complete, complete=True)
            if critical is not None:
                raise HardCut(self._make_event(complete, critical.subcategory),
                              f"{critical.category}/{critical.subcategory}")
            for chunk in pending:
                yield chunk

    # ----- internals -----
    def _scan(self, st: _WindowState, complete: bool = False) -> Detection | None:
        ev = SecurityEvent(
            actor=self.actor,
            source=Source(kind=SourceKind.MODEL_OUTPUT, origin=self.model),
            output_text=st.buf,
            model=self.model,
            provider=self.provider,
            stage="stream_output",
        )
        # Run only the output-relevant detectors — no need to re-run
        # prompt-injection on the model's own output.
        for d in self.gateway.dlp.scan(ev): ev.add_detection(d)
        for d in self.gateway.out_sec.scan(ev): ev.add_detection(d)
        for d in self.gateway.sys_leak.scan(ev): ev.add_detection(d)
        for d in self.gateway.misinfo.scan(ev): ev.add_detection(d)
        for d in self.gateway.ai_spec.scan(ev): ev.add_detection(d)
        for d in self.gateway.infra.scan(ev): ev.add_detection(d)
        for d in self.gateway.agentic.scan(ev): ev.add_detection(d)

        self.gateway._validate_output(ev, complete=complete)

        # Deduplicate against what we've already seen this stream
        seen_keys = {(d.subcategory, d.evidence[:60]) for d in st.detections}
        for d in ev.detections:
            k = (d.subcategory, d.evidence[:60])
            if k in seen_keys:
                continue
            seen_keys.add(k)
            st.detections.append(d)
            if self.on_detection:
                try: self.on_detection(d)
                except Exception: pass

        self.gateway._score_and_decide(ev)
        # No approval/sanitization can be applied to an already-emitted stream.
        if ev.decision != Decision.ALLOW and ev.detections:
            return max(ev.detections, key=lambda d: d.severity_int)

        # Trigger hard cut on critical
        for d in ev.detections:
            if d.severity == "critical" or d.subcategory in ("secret", "reverse_shell", "curl_pipe_sh"):
                return d
        return None

    def _make_event(self, st: _WindowState, reason: str) -> SecurityEvent:
        ev = SecurityEvent(
            actor=self.actor,
            source=Source(kind=SourceKind.MODEL_OUTPUT, origin=self.model),
            output_text=st.buf,
            model=self.model,
            provider=self.provider,
            stage="stream_output",
            decision=Decision.BLOCK,
        )
        for d in st.detections:
            ev.add_detection(d)
        ev.reasons.append(f"hard_cut:{reason}")
        return ev


_BOUNDARY = re.compile(r"[\n\r.!?)}\]>]")


def _endswith_boundary(chunk: str) -> bool:
    if not chunk:
        return False
    tail = chunk[-4:]
    return bool(_BOUNDARY.search(tail))
