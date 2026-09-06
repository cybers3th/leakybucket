"""Wire-compatible OpenAI-format proxy.

Clients point their SDK at this server:

    OpenAI(base_url="https://firewall.corp/v1")

Anything else that speaks the OpenAI Chat Completions shape (many local
runtimes, gateway products, and hosted providers do) works with the same
endpoint by pointing that client at this proxy too.

The proxy:
  1. Parses the request in the OpenAI Chat Completions shape
  2. Runs the INPUT pipeline (system prompt + user messages + tool defs)
  3. If ALLOW: forwards to upstream
  4. Streams the SSE response through StreamingInspector, hard-cutting on
     critical detection
  5. On BLOCK / APPROVAL: returns a native-shape error the SDK understands

Uses aiohttp. Real deployment usually fronts it with envoy / nginx / an
ingress terminating TLS.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, AsyncIterator

from firewall import Gateway
from firewall.core.events import Actor, SecurityEvent, Source, SourceKind
from firewall.serve.async_gateway import AsyncGateway
from firewall.serve.stream    import HardCut, StreamingInspector


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _actor_from_headers(headers: dict) -> Actor:
    """Extract an Actor from standard proxy-provided headers.

    Real deployment mints these headers at the ingress after auth.
    """
    return Actor(
        user_id=headers.get("x-lb-user", "anonymous"),
        tenant=headers.get("x-lb-tenant", "default"),
        session_id=headers.get("x-lb-session", ""),
        agent_id=headers.get("x-lb-agent", ""),
        application_id=headers.get("x-lb-app", ""),
        roles=(headers.get("x-lb-roles", "") or "").split(","),
        authenticated="x-lb-authenticated" in headers,
    )


def _deny_error(reason: str, code: str = "content_policy_violation") -> dict:
    return {"error": {
        "message": f"blocked by firewall: {reason}",
        "type": "invalid_request_error",
        "param": None,
        "code": code,
    }}


def _sse_terminator(reason: str) -> bytes:
    payload = json.dumps(_deny_error(reason, "content_cut_off"))
    return f"data: {payload}\n\ndata: [DONE]\n\n".encode()


# ---------------------------------------------------------------------------
# Body -> SecurityEvent
# ---------------------------------------------------------------------------

def _event_from_body(body: dict, actor: Actor) -> SecurityEvent:
    """Parse OpenAI-shape Chat Completions request body → SecurityEvent."""
    messages = body.get("messages", []) or []
    sys_prompt = "\n".join(m.get("content", "") for m in messages
                             if m.get("role") == "system" and isinstance(m.get("content"), str))
    user_texts = []
    for m in messages:
        if m.get("role") == "user":
            c = m.get("content", "")
            if isinstance(c, str):
                user_texts.append(c)
            elif isinstance(c, list):
                for part in c:
                    if isinstance(part, dict) and part.get("type") == "text":
                        user_texts.append(part.get("text", ""))
    return SecurityEvent(
        actor=actor,
        model=body.get("model", ""),
        provider="upstream",
        system_prompt=sys_prompt,
        input_text="\n".join(user_texts),
        source=Source(kind=SourceKind.USER, origin="client"),
        destination=f"model:{body.get('model','')}",
    )


# ---------------------------------------------------------------------------
# Upstream forwarding — pluggable, so tests can inject a stub
# ---------------------------------------------------------------------------

class UpstreamClient:
    """Abstract upstream. Real impl calls the actual API; tests inject stubs."""
    async def stream(self, body: dict, auth: str, base_url: str) -> AsyncIterator[bytes]: ...
    async def call(self, body: dict, auth: str, base_url: str) -> dict: ...


class AiohttpUpstream(UpstreamClient):
    def __init__(self):
        try:
            import aiohttp
        except ImportError as e:
            raise RuntimeError("pip install aiohttp to use AiohttpUpstream") from e
        self._aiohttp = aiohttp

    async def stream(self, body, auth, base_url):
        headers = {"Authorization": auth, "Content-Type": "application/json"}
        url = base_url.rstrip("/") + "/chat/completions"
        async with self._aiohttp.ClientSession() as sess:
            async with sess.post(url, headers=headers, json=body,
                                   timeout=self._aiohttp.ClientTimeout(total=120)) as resp:
                async for line in resp.content:
                    if line:
                        yield line

    async def call(self, body, auth, base_url):
        headers = {"Authorization": auth, "Content-Type": "application/json"}
        url = base_url.rstrip("/") + "/chat/completions"
        async with self._aiohttp.ClientSession() as sess:
            async with sess.post(url, headers=headers, json=body,
                                   timeout=self._aiohttp.ClientTimeout(total=120)) as resp:
                return await resp.json()


# ---------------------------------------------------------------------------
# SSE chunk decoding — extract the text delta from the upstream stream
# ---------------------------------------------------------------------------

def _delta_from_chunk(line: bytes) -> str:
    """Return the assistant text delta from one SSE line, or ''."""
    s = line.decode("utf-8", "replace").strip()
    if not s.startswith("data:"):
        return ""
    data = s[5:].strip()
    if not data or data == "[DONE]":
        return ""
    try:
        obj = json.loads(data)
    except Exception:
        return ""
    for choice in obj.get("choices", []) or []:
        delta = choice.get("delta") or {}
        content = delta.get("content")
        if isinstance(content, str):
            return content
    return ""


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

async def _run(request_body: dict, auth: str, headers: dict,
                gateway: AsyncGateway, upstream: UpstreamClient,
                base_url: str) -> tuple[int, bytes | AsyncIterator[bytes], dict]:
    actor = _actor_from_headers(headers)
    event = _event_from_body(request_body, actor)
    await gateway.process_input(event)
    if event.decision.value in ("block", "require_approval"):
        return (403 if event.decision.value == "block" else 428,
                json.dumps(_deny_error("input blocked: " + "; ".join(event.reasons[:3]))).encode(),
                {"Content-Type": "application/json"})
    if event.decision.value == "sanitize" and event.sanitized_text:
        for m in reversed(request_body.get("messages") or []):
            if m.get("role") == "user":
                m["content"] = event.sanitized_text
                break

    if request_body.get("stream"):
        async def _gen():
            inspector = StreamingInspector(gateway.gw, actor,
                                             model=request_body.get("model", ""),
                                             provider="upstream")
            queue_lines: list[bytes] = []
            async def _line_stream():
                async for line in upstream.stream(request_body, auth, base_url):
                    queue_lines.append(line)
                    yield _delta_from_chunk(line)
            try:
                async for _delta in inspector.inspect(_line_stream()):
                    while queue_lines:
                        yield queue_lines.pop(0)
            except HardCut as hc:
                yield _sse_terminator(hc.reason)
                return
            while queue_lines:
                yield queue_lines.pop(0)
        return (200, _gen(), {"Content-Type": "text/event-stream"})

    resp = await upstream.call(request_body, auth, base_url)
    text = ""
    try:
        text = resp["choices"][0]["message"]["content"] or ""
    except Exception:
        pass
    if text:
        out_ev = SecurityEvent(actor=actor, model=request_body.get("model", ""),
                                provider="upstream", output_text=text)
        await gateway.process_output(out_ev)
        if out_ev.decision.value == "block":
            return (403, json.dumps(_deny_error("output blocked: "
                    + "; ".join(out_ev.reasons[:3]))).encode(),
                    {"Content-Type": "application/json"})
        if out_ev.decision.value in ("sanitize", "require_approval") and out_ev.sanitized_text:
            resp["choices"][0]["message"]["content"] = out_ev.sanitized_text
    return 200, json.dumps(resp).encode(), {"Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# aiohttp app factory
# ---------------------------------------------------------------------------

def build_openai_app(
    gateway: AsyncGateway | None = None,
    upstream: UpstreamClient | None = None,
    upstream_base_url: str = "http://localhost:8000/v1",
):
    """Return an aiohttp Application speaking the OpenAI Chat Completions shape."""
    try:
        from aiohttp import web
    except ImportError as e:
        raise RuntimeError("pip install aiohttp to use build_openai_app") from e

    gw = gateway or AsyncGateway()
    up = upstream or AiohttpUpstream()

    async def handle(request):
        auth = request.headers.get("Authorization", "")
        body = await request.json()
        headers = {k.lower(): v for k, v in request.headers.items()}
        status, payload, resp_headers = await _run(
            body, auth, headers, gw, up, upstream_base_url,
        )
        if isinstance(payload, (bytes, bytearray)):
            return web.Response(status=status, body=payload, headers=resp_headers)
        stream = web.StreamResponse(status=status, headers=resp_headers)
        await stream.prepare(request)
        async for chunk in payload:
            await stream.write(chunk)
        await stream.write_eof()
        return stream

    app = web.Application()
    app.router.add_post("/v1/chat/completions", handle)
    return app


__all__ = [
    "AiohttpUpstream", "UpstreamClient",
    "build_openai_app",
]
