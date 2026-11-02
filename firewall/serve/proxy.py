"""OpenAI-compatible Chat Completions proxy using aiohttp.
Inspect requests before forwarding and responses before delivery.
Client identity must come from a trusted authentication layer."""
from __future__ import annotations

import asyncio
import json
import time
import math
import uuid
import urllib.parse
from typing import AsyncIterator
import inspect
from functools import cache

from firewall.core.events import Actor, SecurityEvent, Source, SourceKind, Message
from firewall.serve.auth import verified_actor
from firewall.serve.async_gateway import AsyncGateway, GatewayOverloaded, GatewayClosed
from firewall.core.deadline import InspectionTimeout, positive_seconds
from firewall.util.json import strict_json_loads as _strict_json
from firewall.enforcement.rate_limits import RateLimiter


_REQUEST_ACTOR = object()


@cache
def proxy_state_key():
    from aiohttp import web
    return web.AppKey('leakybucket.proxy_state', object)


# Utilities

def _deny_error(reason: str, code: str = "content_policy_violation") -> dict:
    return {"error": {
        "message": f"blocked by firewall: {reason}",
        "type": "invalid_request_error",
        "param": None,
        "code": code,
    }}


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
        developer_prompt="\n".join(m["content"] for m in messages if m["role"] == "developer"),
        input_text="\n".join(user_texts),
        messages=[Message(role=m.get("role", "user"), content=m.get("content", ""))
                  for m in messages if isinstance(m.get("content"), str)],
        source=Source(kind=SourceKind.USER, origin="client"),
        destination=f"model:{body.get('model','')}",
    )


# Upstream forwarding — pluggable, so tests can inject a stub

class UpstreamClient:
    """Abstract upstream. Real impl calls the actual API; tests inject stubs."""
    async def stream(self, body: dict, auth: str, base_url: str) -> AsyncIterator[bytes]: ...
    async def call(self, body: dict, auth: str, base_url: str) -> dict: ...


class AiohttpUpstream(UpstreamClient):
    def __init__(self, max_response_bytes=1_048_576):
        import aiohttp
        self._aiohttp = aiohttp
        self.max_response_bytes = max_response_bytes
        self._session = None

    def _get_session(self):
        if self._session is None or self._session.closed:
            self._session = self._aiohttp.ClientSession(
                timeout=self._aiohttp.ClientTimeout(total=60, connect=5, sock_read=15),
                connector=self._aiohttp.TCPConnector(limit=32, limit_per_host=32),
                trust_env=False)
        return self._session

    async def close(self):
        if self._session is not None:
            await self._session.close()

    async def stream(self, body, auth, base_url):
        async with self._get_session().post(base_url.rstrip('/') + '/chat/completions',
                headers={"Authorization": auth}, json=body, allow_redirects=False) as response:
            if response.status != 200:
                raise ValueError("Upstream rejected request")
            total = 0
            async for chunk in response.content.iter_chunked(8192):
                total += len(chunk)
                if total > self.max_response_bytes:
                    raise ValueError("Upstream response exceeds byte limit")
                yield chunk

    async def call(self, body, auth, base_url):
        async with self._get_session().post(base_url.rstrip('/') + '/chat/completions',
                headers={"Authorization": auth}, json=body, allow_redirects=False) as response:
            if response.status != 200:
                raise ValueError("Upstream rejected request")
            content = bytearray()
            async for chunk in response.content.iter_chunked(8192):
                content.extend(chunk)
                if len(content) > self.max_response_bytes:
                    raise ValueError("Upstream response exceeds byte limit")
            return _strict_json(content.decode('utf-8'))


def _validate_request(body):
    allowed = {"messages", "model", "stream", "temperature", "top_p", "max_tokens",
               "max_completion_tokens", "seed", "stop", "presence_penalty",
               "frequency_penalty", "n", "stream_options", "response_format"}
    if not isinstance(body, dict) or set(body) - allowed:
        raise ValueError("Unsupported request field")
    messages = body.get("messages")
    if not isinstance(messages, list) or not 1 <= len(messages) <= 128:
        raise ValueError("Invalid message count")
    total = 0
    for message in messages:
        if (not isinstance(message, dict) or set(message) - {"role", "content"}
                or message.get("role") not in {"system", "developer", "user", "assistant"}
                or not isinstance(message.get("content"), str)):
            raise ValueError("Only text messages are supported")
        total += len(message["content"])
    if total > 50_000:
        raise ValueError("Text request exceeds inspection budget")
    if "model" in body and (not isinstance(body["model"], str) or not 1 <= len(body["model"]) <= 256):
        raise ValueError("Invalid model")
    if "stream" in body and type(body["stream"]) is not bool:
        raise ValueError("Invalid stream flag")
    for key, low, high in [("temperature", 0, 2), ("top_p", 0, 1),
                           ("presence_penalty", -2, 2), ("frequency_penalty", -2, 2)]:
        if key in body and (type(body[key]) not in {int, float} or not math.isfinite(body[key])
                            or not low <= body[key] <= high):
            raise ValueError("Invalid sampling parameter")
    for key in ("max_tokens", "max_completion_tokens"):
        if key in body and (type(body[key]) is not int or not 1 <= body[key] <= 32768):
            raise ValueError("Invalid token limit")
    if "seed" in body and (type(body["seed"]) is not int or not -(2**63) <= body["seed"] < 2**63):
        raise ValueError("Invalid seed")
    if "n" in body and (type(body["n"]) is not int or not 1 <= body["n"] <= 4):
        raise ValueError("Invalid choice count")
    if body.get("stream") and body.get("n", 1) != 1:
        raise ValueError("Streaming supports one choice")
    if "stop" in body:
        stops = body["stop"] if isinstance(body["stop"], list) else [body["stop"]]
        if not 1 <= len(stops) <= 4 or any(not isinstance(x, str) or not 1 <= len(x) <= 256 for x in stops):
            raise ValueError("Invalid stop sequence")
    if "response_format" in body and body["response_format"] not in ({"type": "text"}, {"type": "json_object"}):
        raise ValueError("Structured schemas must be configured at the application boundary")
    if "stream_options" in body and body["stream_options"] != {"include_usage": True}:
        raise ValueError("Unsupported streaming options")


def _safe_usage(usage):
    counts = {'prompt_tokens', 'completion_tokens', 'total_tokens'}
    details = {
        'prompt_tokens_details': {'cached_tokens', 'audio_tokens'},
        'completion_tokens_details': {'reasoning_tokens', 'audio_tokens', 'accepted_prediction_tokens', 'rejected_prediction_tokens'},
    }
    if not isinstance(usage, dict) or set(usage) - counts - details.keys():
        raise ValueError('Unsupported usage schema')
    for key, value in usage.items():
        if key in details:
            if value is None:
                continue
            if not isinstance(value, dict) or set(value) - details[key]:
                raise ValueError('Unsupported usage details')
            values = value.values()
        else:
            values = (value,)
        if any(type(item) is not int or not 0 <= item <= 2**53 for item in values):
            raise ValueError('Unsupported usage count')
    return {key: value for key, value in usage.items() if key in counts}


def _validate_response_envelope(response):
    allowed = {"id", "object", "created", "model", "choices", "usage", "system_fingerprint", "service_tier", "timings"}
    if set(response) - allowed:
        raise ValueError("Unsupported upstream response carrier")
    for key, value in response.items():
        if key == "choices":
            continue
        if key == "usage":
            if value is not None:
                _safe_usage(value)
        elif key == 'timings':
            fields = {'cache_n', 'prompt_n', 'prompt_ms', 'prompt_per_token_ms', 'prompt_per_second',
                      'predicted_n', 'predicted_ms', 'predicted_per_token_ms', 'predicted_per_second'}
            if (not isinstance(value, dict) or set(value) - fields
                    or any(type(item) not in (int, float) or not 0 <= item <= 2**53
                           or not math.isfinite(item) for item in value.values())):
                raise ValueError('Unsupported provider timing metadata')
        elif value is not None and not isinstance(value, (str, int)):
            raise ValueError("Invalid response metadata")
        elif isinstance(value, str) and (len(value) > 256 or any(not (c.isalnum() or c in '._:/@-') for c in value)):
            raise ValueError("Invalid response metadata")
    for choice in response["choices"]:
        if set(choice) - {"index", "message", "finish_reason", "logprobs"}:
            raise ValueError("Unsupported choice carrier")
        if type(choice.get("index", 0)) is not int or not 0 <= choice.get("index", 0) <= 3:
            raise ValueError("Invalid choice index")
        if choice.get("logprobs") is not None:
            raise ValueError("Logprobs require a separate inspection adapter")
        if choice.get("finish_reason") not in {None, "stop", "length", "content_filter"}:
            raise ValueError("Unsupported finish reason")


def _safe_envelope(response, response_id=None, model="upstream"):
    result = {"id": response_id or "chatcmpl-" + uuid.uuid4().hex,
              "object": "chat.completion.chunk" if response_id else "chat.completion",
              "created": int(time.time()), "model": model, "choices": response["choices"]}
    usage = response.get("usage")
    if usage is not None:
        result["usage"] = _safe_usage(usage)
    return result


async def _buffer_sse(chunks, model="upstream"):
    raw = bytearray()
    frames = []
    pending = bytearray()
    texts = []
    events = 0
    done = False
    seen_choice = False
    seen_finish = False
    response_id = "chatcmpl-" + uuid.uuid4().hex
    async for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise ValueError("Invalid SSE transport chunk")
        raw.extend(chunk)
        pending.extend(chunk)
        if len(raw) > 1_048_576:
            raise ValueError("SSE byte budget exceeded")
        while b"\n" in pending:
            line, _, rest = pending.partition(b"\n")
            pending = bytearray(rest)
            if len(line) > 65_536:
                raise ValueError("SSE line budget exceeded")
            line = line.rstrip(b"\r")
            if not line or line.startswith(b":"):
                continue
            if not line.startswith(b"data:") or done:
                raise ValueError("Unsupported SSE framing")
            events += 1
            if events > 4096:
                raise ValueError("SSE event budget exceeded")
            data = line[5:].strip()
            if data == b"[DONE]":
                done = True
                frames.append(b"data: [DONE]\n\n")
                continue
            obj = _strict_json(data.decode('utf-8'))
            if not isinstance(obj, dict) or not isinstance(obj.get('choices'), list):
                raise ValueError("Invalid SSE envelope")
            envelope = dict(obj)
            envelope['choices'] = []
            _validate_response_envelope(envelope)
            if len(obj['choices']) > 1:
                raise ValueError("Multiple streaming choices")
            for choice in obj['choices']:
                if (not isinstance(choice, dict) or choice.get('index', 0) != 0
                        or set(choice) - {'index', 'delta', 'finish_reason', 'logprobs'}
                        or choice.get('logprobs') is not None
                        or choice.get('finish_reason') not in {None, 'stop', 'length', 'content_filter'}):
                    raise ValueError("Unsupported SSE choice")
                if choice.get('finish_reason') is not None:
                    seen_finish = True
                delta = choice.get('delta')
                if not isinstance(delta, dict) or set(delta) - {'role', 'content', 'refusal', 'reasoning_content', 'reasoning'}:
                    raise ValueError("Unsupported SSE delta")
                if delta.get('role', 'assistant') != 'assistant':
                    raise ValueError("Invalid response role")
                for key, value in delta.items():
                    if value is not None and not isinstance(value, str):
                        raise ValueError("Unsupported SSE content")
                    if key != 'role' and value:
                        texts.append(value)
                seen_choice = True
            safe = _safe_envelope(obj, response_id, model)
            frames.append(('data: ' + json.dumps(safe) + '\n\n').encode())
        if len(pending) > 65_536:
            raise ValueError("SSE line budget exceeded")
    if pending.strip() or not done or not seen_choice or not seen_finish:
        raise ValueError("Incomplete SSE response")
    text = ''.join(texts)
    if len(text) > 200_000:
        raise ValueError("SSE text budget exceeded")
    return b"".join(frames), text


# Handler

async def _run(request_body: dict, auth: str, headers: dict,
                gateway: AsyncGateway, upstream: UpstreamClient,
                base_url: str, actor: Actor | None = None) -> tuple[int, bytes | AsyncIterator[bytes], dict]:
    # Client-supplied identity headers are not an authentication boundary.
    actor = actor or Actor()
    try:
        _validate_request(request_body)
    except (ValueError, TypeError, RecursionError):
        return 400, json.dumps(_deny_error("Unsupported or invalid text request")).encode(), {"Content-Type": "application/json"}
    event = _event_from_body(request_body, actor)
    await gateway.process_input(event)
    if any(d.subcategory == "semantic_inspection_failed" for d in event.detections):
        return 503, json.dumps(_deny_error("Semantic inspection unavailable", "inspection_unavailable")).encode(), {"Content-Type": "application/json", "Retry-After": "1"}
    if event.decision.value in ("block", "require_approval"):
        return (403 if event.decision.value == "block" else 428,
                json.dumps(_deny_error("Input requires security review")).encode(),
                {"Content-Type": "application/json"})
    if event.decision.value == "sanitize":
        return 403, json.dumps(_deny_error("Input requires reviewed sanitization")).encode(), {"Content-Type": "application/json"}

    if request_body.get("stream"):
        # Preserve SSE framing, but release no upstream bytes before full inspection.
        raw, text = await _buffer_sse(upstream.stream(request_body, auth, base_url), request_body.get("model", "upstream"))
        out_event = SecurityEvent(actor=actor, model=request_body.get("model", ""),
                                  output_text=text, system_prompt=event.system_prompt,
                                  developer_prompt=event.developer_prompt)
        await gateway.process_output(out_event)
        if out_event.decision.value != "allow":
            return 403, json.dumps(_deny_error("Output requires security review")).encode(), {"Content-Type": "application/json"}
        return 200, raw, {"Content-Type": "text/event-stream"}

    resp = await upstream.call(request_body, auth, base_url)
    if not isinstance(resp, dict) or not isinstance(resp.get("choices"), list) or not 1 <= len(resp["choices"]) <= 4:
        return 502, json.dumps(_deny_error("Malformed upstream response")).encode(), {"Content-Type": "application/json"}
    if len(json.dumps(resp, allow_nan=False).encode()) > 1_048_576:
        raise ValueError("Upstream response exceeds byte limit")
    # Include keys and auxiliary fields in content inspection; do not silently
    # relay uninspected structured or provider-specific response carriers.
    _validate_response_envelope(resp)
    for choice in resp["choices"]:
        if not isinstance(choice, dict) or not isinstance(choice.get("message"), dict):
            return 502, json.dumps(_deny_error("Malformed upstream choice")).encode(), {"Content-Type": "application/json"}
        message = choice["message"]
        if message.get("role", "assistant") != "assistant":
            raise ValueError("Invalid response role")
        if message.get("tool_calls") or message.get("function_call"):
            return 403, json.dumps(_deny_error("Tool calls require an enforced tool gateway")).encode(), {"Content-Type": "application/json"}
        if any(key not in {"role", "content", "refusal", "reasoning_content", "reasoning"} for key in message):
            raise ValueError("Unsupported upstream message field")
        if any(value is not None and not isinstance(value, str) for value in message.values()):
            raise ValueError("Unsupported structured upstream content")
        text = "\n".join(value for key, value in message.items() if key != "role" and isinstance(value, str))
        out_ev = SecurityEvent(actor=actor, model=request_body.get("model", ""),
                               provider="upstream", output_text=text,
                               system_prompt=event.system_prompt,
                               developer_prompt=event.developer_prompt)
        await gateway.process_output(out_ev)
        if out_ev.decision.value != "allow":
            return 403, json.dumps(_deny_error("Output requires security review")).encode(), {"Content-Type": "application/json"}

    return 200, json.dumps(_safe_envelope(resp, model=request_body.get("model", "upstream"))).encode(), {"Content-Type": "application/json"}


# aiohttp app factory

def build_openai_app(
    gateway: AsyncGateway | None = None,
    upstream: UpstreamClient | None = None,
    upstream_base_url: str = "http://localhost:8000/v1",
    actor_resolver=None,
    *,
    allow_anonymous: bool = False,
    request_timeout: float = 60,
    max_in_flight: int = 32,
    max_request_bytes: int = 262_144,
    upstream_authorization: str = "",
    request_rate_per_minute: int = 120,
    request_burst: int = 30,
):
    """Build a bounded text proxy; authenticated identities are required by default."""
    from aiohttp import web
    request_timeout = positive_seconds(request_timeout)
    if type(max_in_flight) is not int or max_in_flight <= 0:
        raise ValueError("Admission limit must be a positive integer")
    if type(max_request_bytes) is not int or max_request_bytes <= 0:
        raise ValueError("Body limit must be a positive integer")
    if actor_resolver is None and not allow_anonymous:
        raise ValueError("Configure actor_resolver; anonymous mode requires explicit opt-in")
    parsed = urllib.parse.urlsplit(upstream_base_url)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError("Invalid administrator-configured upstream URL")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Non-loopback upstreams require HTTPS")
    if not isinstance(upstream_authorization, str) or "\r" in upstream_authorization or "\n" in upstream_authorization:
        raise ValueError("Invalid upstream authorization")
    gw = gateway or AsyncGateway()
    up = upstream or AiohttpUpstream()
    request_limiter = RateLimiter(default_rate_per_minute=request_rate_per_minute, capacity=request_burst)
    active = 0

    async def authorize(request, handler):
        actor = Actor()
        if actor_resolver is not None:
            try:
                actor = actor_resolver(request)
                if inspect.isawaitable(actor):
                    actor = await actor
                if not verified_actor(actor):
                    return web.json_response(_deny_error("Authentication required"), status=401)
            except Exception:
                return web.json_response(_deny_error("Authentication failed"), status=401)
        key = json.dumps([actor.tenant, actor.user_id])
        permitted, _ = request_limiter.allow(key)
        if not permitted:
            return web.json_response(_deny_error("Request quota exhausted", "rate_limited"),
                                     status=429, headers={"Retry-After": "1"})
        request[_REQUEST_ACTOR] = actor
        return await handler(request)

    async def execute(request):
        if request.content_type != "application/json":
            return web.json_response(_deny_error("Content-Type must be application/json"), status=415)
        actor = request[_REQUEST_ACTOR]
        try:
            body = _strict_json(await request.text())
        except (ValueError, UnicodeError, RecursionError):
            return web.json_response(_deny_error("Invalid JSON"), status=400)
        status, payload, response_headers = await _run(body, upstream_authorization,
            {}, gw, up, upstream_base_url, actor=actor)
        return web.Response(status=status, body=payload, headers=response_headers)

    @web.middleware
    async def authenticate_and_limit(request, handler):
        if request.path != '/v1/chat/completions':
            return await handler(request)
        return await handle(request, handler)

    async def handle(request, handler):
        nonlocal active
        if active >= max_in_flight:
            return web.json_response(_deny_error("Request capacity exhausted", "overloaded"),
                                     status=503, headers={"Retry-After": "1"})
        active += 1
        try:
            return await asyncio.wait_for(authorize(request, handler), request_timeout)
        except (asyncio.TimeoutError, InspectionTimeout):
            return web.json_response(_deny_error("Request deadline exceeded", "timeout"), status=504)
        except (GatewayOverloaded, GatewayClosed):
            return web.json_response(_deny_error("Inspection unavailable", "overloaded"),
                                     status=503, headers={"Retry-After": "1"})
        except web.HTTPRequestEntityTooLarge:
            return web.json_response(_deny_error("Request body exceeds byte limit"), status=413)
        except web.HTTPException as error:
            return web.Response(status=error.status, text=error.text, headers=error.headers)
        except Exception:
            return web.json_response(_deny_error("Request withheld after processing failure"), status=502)
        finally:
            active -= 1

    def snapshot():
        state = gw.snapshot()
        ready = state['healthy'] and not state['closed'] and state['in_flight'] < state['capacity'] and active < max_in_flight
        return {**state, 'ready': ready, 'http_in_flight': active, 'http_capacity': max_in_flight}

    async def health(request):
        ready = snapshot()['ready']
        return web.json_response({'ready': ready}, status=200 if ready else 503)

    async def cleanup(app):
        await gw.close()
        if upstream is None:
            await up.close()

    @web.middleware
    async def security_headers(request, handler):
        response = await handler(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    app = web.Application(client_max_size=max_request_bytes, middlewares=[security_headers, authenticate_and_limit])
    app[proxy_state_key()] = snapshot
    app.router.add_post("/v1/chat/completions", execute)
    app.router.add_get("/health/ready", health)
    app.on_cleanup.append(cleanup)
    return app


__all__ = ["AiohttpUpstream", "UpstreamClient", "build_openai_app"]
