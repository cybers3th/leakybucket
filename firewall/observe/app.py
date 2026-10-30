"""Authenticated trace APIs for the CLI and enforcing chat proxy."""
from __future__ import annotations

import asyncio
import inspect
import math
import time
import uuid
from contextvars import ContextVar
from urllib.parse import urlsplit

from aiohttp import ClientSession, ClientTimeout, web

from firewall.serve.auth import verified_actor
from firewall.serve.proxy import AiohttpUpstream, build_openai_app
from firewall.util.json import strict_json_loads

from .policy import load_policy
from .store import TraceStore

_current = ContextVar('lb_trace', default=None)
OBSERVATION_KEY = web.AppKey('observation', object)


def _span(kind, start, **details):
    trace = _current.get()
    if trace is not None and '_clock' in trace:
        if len(trace['spans']) >= 256:
            if kind == 'stream_chunk':
                return
            trace['spans'].pop()
        trace['spans'].append({'kind': kind, 'offset_ms': (start - trace['_clock']) * 1000,
                               'duration_ms': (time.monotonic() - start) * 1000, **details})


def _usage(response):
    usage = response.get('usage') if isinstance(response, dict) else None
    if not isinstance(usage, dict):
        return
    trace = _current.get()
    if trace is None:
        return
    for source, target in [('prompt_tokens', 'prompt_tokens'), ('completion_tokens', 'completion_tokens')]:
        value = usage.get(source)
        if type(value) is int and 0 <= value <= 2**53:
            trace[target] = value


def _delivered_content(response):
    if response.content_type != 'text/event-stream':
        result = strict_json_loads(response.body)
        return [choice['message']['content'] for choice in result.get('choices', [])]
    pieces = {}
    for line in response.body.splitlines():
        if not line.startswith(b'data:') or line[5:].strip() == b'[DONE]':
            continue
        event = strict_json_loads(line[5:].strip())
        for choice in event.get('choices', []):
            pieces.setdefault(choice['index'], []).append(choice.get('delta', {}).get('content') or '')
    return [''.join(pieces[index]) for index in sorted(pieces)]


class TracedUpstream:
    def __init__(self, upstream):
        self.upstream = upstream

    async def call(self, *args):
        started = time.monotonic()
        try:
            result = await self.upstream.call(*args)
            _usage(result)
            return result
        finally:
            _span('provider_call', started, attempt=1)

    async def stream(self, *args):
        started = time.monotonic()
        buffer = b''
        count = 0
        try:
            async for chunk in self.upstream.stream(*args):
                count += 1
                _span('stream_chunk', time.monotonic(), index=count, bytes=len(chunk))
                buffer += chunk
                if len(buffer) <= 131072:
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        if line.startswith(b'data:'):
                            try:
                                _usage(strict_json_loads(line[5:].strip()))
                            except (ValueError, UnicodeError, RecursionError):
                                pass
                else:
                    buffer = b''
                yield chunk
        finally:
            _span('provider_call', started, attempt=1, chunks=count)


class Observation:
    def __init__(self, store, policy_path, resolver, capture_content, slack_url):
        self.store = store
        self.policy_path = policy_path
        self.policy = load_policy(policy_path)
        self.policy_healthy = True
        self.storage_healthy = True
        self.resolver = resolver
        self.capture_content = capture_content
        self.slack_url = slack_url
        self.clients = {}
        self.alerts = asyncio.Queue(maxsize=32)
        self.alert_failures = 0
        self.alert_drops = 0
        self.active = 0
        self.database_jobs = set()
        self.tasks = []
        self.upstream_url = None
        self.inspection_mode = 'unknown'

    def database_done(self, job):
        self.database_jobs.discard(job)
        if not job.cancelled() and job.exception() is not None:
            self.storage_healthy = False

    async def database(self, method, *args, **kwargs):
        if len(self.database_jobs) >= 48:
            raise web.HTTPServiceUnavailable(text='Trace storage capacity exhausted')
        job = asyncio.create_task(asyncio.to_thread(method, *args, **kwargs))
        self.database_jobs.add(job)
        job.add_done_callback(self.database_done)
        return await asyncio.shield(job)

    async def actor(self, request):
        try:
            actor = self.resolver(request)
            if inspect.isawaitable(actor):
                actor = await actor
            if verified_actor(actor):
                return actor
        except Exception:
            pass
        raise web.HTTPUnauthorized(text='Authentication required')

    def publish(self, tenant, event):
        for target, queue in tuple(self.clients.values()):
            if target == tenant:
                if queue.full():
                    queue.get_nowait()
                queue.put_nowait(event)

    async def reload(self):
        while True:
            await asyncio.sleep(1)
            try:
                policy = await asyncio.to_thread(load_policy, self.policy_path)
                self.policy = policy
                self.policy_healthy = True
            except Exception:
                self.policy_healthy = False

    async def deliver_alerts(self):
        async with ClientSession(timeout=ClientTimeout(total=5), trust_env=False) as session:
            while True:
                message = await self.alerts.get()
                try:
                    async with session.post(self.slack_url, json={'text': message}, allow_redirects=False) as response:
                        if response.status != 200:
                            self.alert_failures += 1
                except Exception:
                    self.alert_failures += 1
                finally:
                    self.alerts.task_done()

    async def start(self, app):
        self.tasks.append(asyncio.create_task(self.reload()))
        if self.slack_url:
            self.tasks.append(asyncio.create_task(self.deliver_alerts()))

    async def shutdown(self, app):
        for _, queue in tuple(self.clients.values()):
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(None)

    async def stop(self, app):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await asyncio.gather(*tuple(self.database_jobs), return_exceptions=True)
        await asyncio.to_thread(self.store.close)

    @web.middleware
    async def middleware(self, request, handler):
        if request.path == '/health/ready':
            if not self.policy_healthy or not self.storage_healthy:
                return web.json_response({'ready': False}, status=503)
            return await handler(request)
        if request.path != '/v1/chat/completions':
            return await handler(request)
        actor = await self.actor(request)
        if self.active >= 32:
            raise web.HTTPServiceUnavailable(text='Trace admission exhausted')
        if not self.policy_healthy or not self.storage_healthy:
            raise web.HTTPServiceUnavailable(text='Policy or trace storage unavailable')
        self.active += 1
        token = None
        try:
            try:
                body = strict_json_loads(await asyncio.wait_for(request.read(), timeout=10))
            except asyncio.TimeoutError:
                raise web.HTTPRequestTimeout(text='Request body deadline exceeded')
            except (ValueError, UnicodeError, RecursionError):
                raise web.HTTPBadRequest(text='Invalid JSON')
            if not isinstance(body, dict):
                raise web.HTTPBadRequest(text='JSON object required')
            policy = self.policy
            trace = {'id': uuid.uuid4().hex, 'tenant': actor.tenant,
                     'model': str(body.get('model', ''))[:256], 'started': time.time(),
                     'prompt_tokens': None, 'completion_tokens': None, 'cost_usd': None,
                     'policy_version': policy.digest, 'spans': [], '_clock': time.monotonic()}
            token = _current.set(trace)
            self.publish(actor.tenant, {'event': 'started', 'id': trace['id'], 'model': trace['model']})
            started = time.monotonic()
            matched = policy.evaluate(body)
            _span('policy', started, matches=matched)
            if any(rule['action'] == 'block' for rule in matched):
                response = web.json_response({'error': {'message': 'Blocked by configured policy', 'code': 'policy_block'}}, status=403)
            else:
                processing = time.monotonic()
                response = await handler(request)
                _span('firewall_and_provider', processing)
            trace['status'] = response.status
            trace['latency_ms'] = (time.monotonic() - trace.pop('_clock')) * 1000
            trace['cost_usd'] = policy.cost(trace['model'], trace['prompt_tokens'], trace['completion_tokens'])
            trace['content_captured'] = self.capture_content
            if self.capture_content:
                trace['prompt'] = body.get('messages', [])
                if response.status == 200:
                    try:
                        trace['response'] = _delivered_content(response)
                    except (ValueError, KeyError, TypeError):
                        trace['response'] = None
            try:
                await self.database(self.store.insert, trace)
            except web.HTTPServiceUnavailable:
                raise
            except Exception:
                self.storage_healthy = False
                raise web.HTTPServiceUnavailable(text='Trace persistence failed; response withheld')
            self.publish(actor.tenant, {'event': 'completed', 'id': trace['id']})
            breached = ((policy.latency_ms is not None and trace['latency_ms'] > policy.latency_ms)
                        or (policy.cost_usd is not None and trace['cost_usd'] is not None and trace['cost_usd'] > policy.cost_usd))
            if breached and self.slack_url:
                try:
                    self.alerts.put_nowait(f"LeakyBucket threshold exceeded; trace={trace['id']} latency_ms={trace['latency_ms']:.1f} cost_usd={trace['cost_usd']}")
                except asyncio.QueueFull:
                    self.alert_drops += 1
            response.headers['X-LeakyBucket-Trace'] = trace['id']
            return response
        finally:
            if token is not None:
                _current.reset(token)
            self.active -= 1

    async def traces(self, request):
        actor = await self.actor(request)
        allowed = {'model', 'since', 'until', 'min_cost', 'limit', 'offset'}
        if set(request.query) - allowed or any(len(request.query.getall(k)) != 1 for k in request.query):
            raise web.HTTPBadRequest(text='Unsupported or duplicate filter')
        params = {}
        try:
            for key in ('since', 'until', 'min_cost'):
                if key in request.query:
                    value = float(request.query[key])
                    if not math.isfinite(value) or value < 0 or value > 253402300799:
                        raise ValueError()
                    params[key] = value
            for key, default, maximum in [('limit', 100, 200), ('offset', 0, 100000)]:
                value = int(request.query.get(key, default))
                if not (1 if key == 'limit' else 0) <= value <= maximum:
                    raise ValueError()
                params[key] = value
            if 'model' in request.query:
                if len(request.query['model']) > 256:
                    raise ValueError()
                params['model'] = request.query['model']
        except ValueError:
            raise web.HTTPBadRequest(text='Invalid trace filter')
        try:
            rows = await self.database(self.store.query, actor.tenant, **params)
            return web.json_response({'traces': rows})
        except Exception:
            raise web.HTTPServiceUnavailable(text='Trace query unavailable')

    async def detail(self, request):
        actor = await self.actor(request)
        try:
            row = await self.database(self.store.get, actor.tenant, request.match_info['id'])
        except Exception:
            raise web.HTTPServiceUnavailable(text='Trace query unavailable')
        if row is None:
            raise web.HTTPNotFound()
        return web.json_response(row)

    async def status(self, request):
        await self.actor(request)
        return web.json_response({'policy_healthy': self.policy_healthy, 'storage_healthy': self.storage_healthy,
                                  'policy_version': self.policy.digest, 'content_captured': self.capture_content,
                                  'alert_failures': self.alert_failures, 'alert_drops': self.alert_drops,
                                  'upstream_url': self.upstream_url, 'inspection_mode': self.inspection_mode})

    async def live(self, request):
        origin = request.headers.get('Origin')
        if origin and origin != f'{request.scheme}://{request.host}':
            raise web.HTTPForbidden(text='Cross-origin WebSocket denied')
        if len(self.clients) >= 64:
            raise web.HTTPServiceUnavailable(text='Live subscriber capacity exhausted')
        ws = web.WebSocketResponse(heartbeat=20, max_msg_size=8192)
        await ws.prepare(request)
        key = uuid.uuid4().hex
        queue = asyncio.Queue(maxsize=32)
        self.clients[key] = ('', queue)
        try:
            try:
                credentials = await asyncio.wait_for(ws.receive_json(), timeout=5)
                if not isinstance(credentials, dict) or set(credentials) != {'token'} or not isinstance(credentials['token'], str):
                    raise ValueError()
                from types import SimpleNamespace
                actor = await self.actor(SimpleNamespace(headers={'Authorization': 'Bearer ' + credentials['token']}))
                self.clients[key] = (actor.tenant, queue)
            except Exception:
                await ws.close(code=1008, message=b'Authentication required')
                return ws
            await ws.send_json({'event': 'connected'})
            reader = asyncio.create_task(ws.receive())
            try:
                while not ws.closed:
                    next_event = asyncio.create_task(queue.get())
                    try:
                        done, _ = await asyncio.wait((reader, next_event), return_when=asyncio.FIRST_COMPLETED)
                        if reader in done:
                            break
                        event = next_event.result()
                        if event is None:
                            break
                        await asyncio.wait_for(ws.send_json(event), timeout=5)
                    finally:
                        next_event.cancel()
                        await asyncio.gather(next_event, return_exceptions=True)
            finally:
                reader.cancel()
                await asyncio.gather(reader, return_exceptions=True)
        finally:
            self.clients.pop(key, None)
            await ws.close()
        return ws


def attach_observation(app, *, actor_resolver, policy_path, database='traces.sqlite3', capture_content=False, slack_url=None):
    if slack_url:
        parsed = urlsplit(slack_url)
        if (parsed.scheme != 'https' or parsed.hostname != 'hooks.slack.com' or parsed.port not in (None, 443)
                or parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.path.startswith('/services/')):
            raise ValueError('Expected an HTTPS hooks.slack.com/services/ webhook')
    store = TraceStore(database)
    try:
        observation = Observation(store, policy_path, actor_resolver, capture_content, slack_url)
    except Exception:
        store.close()
        raise
    app[OBSERVATION_KEY] = observation
    app.middlewares.append(observation.middleware)
    app.router.add_get('/api/traces', observation.traces)
    app.router.add_get('/api/traces/{id}', observation.detail)
    app.router.add_get('/api/status', observation.status)
    app.router.add_get('/api/live', observation.live)
    app.on_startup.append(observation.start)
    app.on_shutdown.append(observation.shutdown)
    app.on_cleanup.append(observation.stop)
    return observation


def build_observed_app(*, actor_resolver, policy_path, database='traces.sqlite3', capture_content=False, slack_url=None, upstream=None, **kwargs):
    original = upstream or AiohttpUpstream()
    app = build_openai_app(upstream=TracedUpstream(original), actor_resolver=actor_resolver, **kwargs)
    observation = attach_observation(app, actor_resolver=actor_resolver, policy_path=policy_path,
                                     database=database, capture_content=capture_content, slack_url=slack_url)
    observation.upstream_url = kwargs.get('upstream_base_url', 'http://localhost:8000/v1')
    gateway = kwargs.get('gateway')
    classifier = getattr(getattr(gateway, 'gw', None), 'semantic', None)
    observation.inspection_mode = 'semantic_and_rules' if classifier is not None else 'rules'
    if upstream is None:
        async def close_upstream(app):
            await original.close()
        app.on_cleanup.append(close_upstream)
    return app
