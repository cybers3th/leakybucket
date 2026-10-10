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
import inspect

from firewall import Gateway
from firewall.core.events import Actor, SecurityEvent, Source, SourceKind, Message
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
        authenticated=headers.get("x-lb-authenticated", "").lower() == "true",
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
        messages=[Message(role=m.get("role", "user"), content=m.get("content", ""))
                  for m in messages if isinstance(m.get("content"), str)],
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
    except Exception as error:
        raise ValueError("Malformed upstream SSE JSON") from error
    texts = []
    for choice in obj.get("choices", []) or []:
        delta = choice.get("delta") or {}
        if delta.get("tool_calls") or delta.get("function_call"):
            raise ValueError("Tool-call streams require a separate enforced tool gateway")
        content = delta.get("content")
        if isinstance(content, str):
            texts.append(content)
        for key in ("reasoning_content", "reasoning", "refusal"):
            if isinstance(delta.get(key), str):
                texts.append(delta[key])
    return "\n".join(texts)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

async def _run(request_body: dict, auth: str, headers: dict,
                gateway: AsyncGateway, upstream: UpstreamClient,
                base_url: str, actor: Actor | None = None) -> tuple[int, bytes | AsyncIterator[bytes], dict]:
    # Client-supplied identity headers are not an authentication boundary.
    actor = actor or Actor()
    if not isinstance(request_body, dict) or not isinstance(request_body.get("messages"), list):
        return 400, json.dumps(_deny_error("Invalid request body")).encode(), {"Content-Type": "application/json"}
    for message in request_body["messages"]:
        if not isinstance(message, dict) or not isinstance(message.get("content", ""), (str, list)):
            return 400, json.dumps(_deny_error("Invalid message")).encode(), {"Content-Type": "application/json"}
    event = _event_from_body(request_body, actor)
    await gateway.process_input(event)
    if event.decision.value in ("block", "require_approval"):
        return (403 if event.decision.value == "block" else 428,
                json.dumps(_deny_error("input blocked: " + "; ".join(event.reasons[:3]))).encode(),
                {"Content-Type": "application/json"})
    if event.decision.value == "sanitize":
        return 403, json.dumps(_deny_error("Input requires reviewed sanitization")).encode(), {"Content-Type": "application/json"}

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
            except (HardCut, ValueError) as hc:
                yield _sse_terminator("stream content withheld")
                return
            while queue_lines:
                yield queue_lines.pop(0)
        return (200, _gen(), {"Content-Type": "text/event-stream"})

    resp = await upstream.call(request_body, auth, base_url)
    if not isinstance(resp, dict) or not isinstance(resp.get("choices"), list):
        return 502, json.dumps(_deny_error("Malformed upstream response")).encode(), {"Content-Type": "application/json"}
    for choice in resp["choices"]:
        if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
            return 502, json.dumps(_deny_error("Malformed upstream choice")).encode(), {"Content-Type": "application/json"}
        message = choice["message"]
        if message.get("tool_calls") or message.get("function_call"):
            return 403, json.dumps(_deny_error("Tool calls require an enforced tool gateway")).encode(), {"Content-Type": "application/json"}
        text = "\n".join(value for value in message.values() if isinstance(value, str))
        out_ev = SecurityEvent(actor=actor, model=request_body.get("model", ""),
                               provider="upstream", output_text=text,
                               system_prompt=event.system_prompt,
                               developer_prompt=event.developer_prompt)
        await gateway.process_output(out_ev)
        if out_ev.decision.value != "allow":
            return 403, json.dumps(_deny_error("Output requires security review")).encode(), {"Content-Type": "application/json"}

    return 200, json.dumps(resp).encode(), {"Content-Type": "application/json"}


# ---------------------------------------------------------------------------
# aiohttp app factory
# ---------------------------------------------------------------------------

def build_openai_app(
    gateway: AsyncGateway | None = None,
    upstream: UpstreamClient | None = None,
    upstream_base_url: str = "http://localhost:8000/v1",
    actor_resolver=None,
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
        try:
            body = await request.json()
        except (ValueError, UnicodeError):
            return web.json_response(_deny_error("Invalid JSON"), status=400)
        actor = Actor()
        if actor_resolver is not None:
            try:
                actor = actor_resolver(request)
                if inspect.isawaitable(actor):
                    actor = await actor
                if not isinstance(actor, Actor) or not actor.authenticated:
                    return web.json_response(_deny_error("Authentication required"), status=401)
            except Exception:
                return web.json_response(_deny_error("Authentication failed"), status=401)
        headers = {k.lower(): v for k, v in request.headers.items()}
        status, payload, resp_headers = await _run(
            body, auth, headers, gw, up, upstream_base_url, actor=actor,
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
