"""Admission, deadline, identity, and transport enforcement at serving boundaries."""
import asyncio
from contextlib import suppress
import json
import threading
import time
from types import SimpleNamespace

import pytest

from firewall import Gateway
from firewall.core.behavior import BehaviorEngine
from firewall.core.deadline import InspectionTimeout, inspection_budget, remaining_seconds
from firewall.core.events import Actor, Decision, Message, SecurityEvent, ToolDefinition
from firewall.ml.classifier import MLDetector
from firewall.ml.semantic import LocalSemanticClassifier
from firewall.serve.async_gateway import AsyncGateway, GatewayClosed, GatewayOverloaded
from firewall.serve.auth import StaticTokenAuthenticator
from firewall.serve.proxy import UpstreamClient, _buffer_sse, build_openai_app


TOKEN = 'test-only-service-credential-0123456789'


def actor():
    return Actor(user_id='service', tenant='company', session_id='issued-session',
                 authenticated=True, roles=['reader'])


class Upstream(UpstreamClient):
    def __init__(self, response=None, chunks=None, gate=None):
        self.response = response or {'choices': [{'message': {'role': 'assistant', 'content': 'Hello'}}]}
        self.chunks = chunks
        self.gate = gate
        self.calls = []

    async def call(self, body, auth, base_url):
        self.calls.append((body, auth))
        if self.gate is not None:
            await self.gate.wait()
        return self.response

    async def stream(self, body, auth, base_url):
        self.calls.append((body, auth))
        for chunk in self.chunks:
            yield chunk


def sse(content='Hello', **delta):
    return (('data: ' + json.dumps({'choices': [{'index': 0,
        'delta': {'content': content, **delta}, 'finish_reason': 'stop'}]})
        + '\n\ndata: [DONE]\n\n').encode())


async def client_for(upstream, **options):
    from aiohttp.test_utils import TestClient, TestServer
    resolver = options.pop('actor_resolver', StaticTokenAuthenticator({TOKEN: actor()}))
    client = TestClient(TestServer(build_openai_app(upstream=upstream,
        actor_resolver=resolver, **options)))
    await client.start_server()
    return client


def post(client, body=None, **kwargs):
    return client.post('/v1/chat/completions', json=body or {
        'messages': [{'role': 'user', 'content': 'Hello'}]},
        headers=kwargs.pop('headers', {'Authorization': 'Bearer ' + TOKEN}), **kwargs)


def test_authentication_is_required_by_default():
    with pytest.raises(ValueError, match='actor_resolver'):
        build_openai_app()


@pytest.mark.parametrize('token', ['', 'Bearer wrong', 'Basic whatever'])
def test_spoofed_identity_never_reaches_upstream(token):
    async def run():
        up = Upstream()
        async with await client_for(up) as client:
            response = await post(client, headers={'Authorization': token, 'x-lb-user': 'admin',
                                                  'x-lb-authenticated': 'true'})
            assert response.status == 401
            assert not up.calls
    asyncio.run(run())


def test_service_identity_is_copied_and_upstream_credential_is_separate():
    resolver = StaticTokenAuthenticator({TOKEN: actor()})
    request = SimpleNamespace(headers={'Authorization': 'Bearer ' + TOKEN})
    first = resolver(request)
    first.roles.append('admin')
    assert resolver(request).roles == ['reader']
    async def run():
        up = Upstream()
        async with await client_for(up, upstream_authorization='Bearer upstream-only') as client:
            response = await post(client)
            assert response.status == 200
            assert up.calls[0][1] == 'Bearer upstream-only'
        up = Upstream()
        async with await client_for(up) as client:
            assert (await post(client)).status == 200
            assert up.calls[0][1] == ''
    asyncio.run(run())


@pytest.mark.parametrize('body', [
    {'messages': [{'role': 'user', 'content': [{'type': 'image_url', 'image_url': 'hidden'}]}]},
    {'messages': [{'role': 'tool', 'content': 'untrusted'}]},
    {'messages': [{'role': 'user', 'content': 'Hello', 'tool_calls': [{'hidden': 'payload'}]}]},
    {'messages': [], 'tools': [{'function': {'description': 'hidden'}}]},
    {'messages': [{'role': 'user', 'content': 'Hello'}], 'temperature': float('nan')},
    {'messages': [{'role': 'user', 'content': 'Hello'}], 'n': 1000000},
    {'messages': [{'role': 'user', 'content': 'Hello'}], 'response_format': {'type': 'json_schema'}},
    {'messages': [{'role': 'user', 'content': 'x' * 50001}]},
])
def test_unsupported_request_carriers_never_forward(body):
    async def run():
        up = Upstream()
        async with await client_for(up) as client:
            assert (await post(client, body)).status == 400
            assert not up.calls
    asyncio.run(run())


def test_duplicate_keys_and_body_limits():
    async def run():
        up = Upstream()
        async with await client_for(up, max_request_bytes=256) as client:
            response = await client.post('/v1/chat/completions', data='{"messages":[],"messages":[]}',
                headers={'Authorization': 'Bearer ' + TOKEN, 'Content-Type': 'application/json'})
            assert response.status == 400
            response = await post(client, {'messages': [{'role': 'user', 'content': 'x' * 1000}]})
            assert response.status == 413
            assert not up.calls
    asyncio.run(run())


@pytest.mark.parametrize('response', [
    {'choices': []},
    {'choices': [{'message': {'content': [{'text': 'hidden'}]}}]},
    {'choices': [{'message': {'content': 'Hello', 'audio': {'data': 'hidden'}}}]},
    {'choices': [{'message': {'content': 'Hello'}, 'logprobs': {'tokens': ['hidden']}}]},
    {'choices': [{'message': {'content': 'Hello'}}], 'hidden': 'uninspected'},
    {'choices': [{'message': {'role': 'system', 'content': 'Hello'}}]},
    {'choices': [{'message': {'content': 'Hello'}}], 'usage': {'secret-field': 1}},
])
def test_unsupported_responses_are_withheld(response):
    async def run():
        async with await client_for(Upstream(response=response)) as client:
            result = await post(client)
            assert result.status == 502
            assert b'hidden' not in await result.read()
    asyncio.run(run())


def test_sse_fragmentation_and_metadata_are_not_content_bypasses():
    async def run():
        payload = sse('Hello')
        chunks = [payload[i:i+3] for i in range(0, len(payload), 3)]
        async with await client_for(Upstream(chunks=chunks)) as client:
            response = await post(client, {'messages': [{'role': 'user', 'content': 'Hello'}], 'stream': True})
            assert response.status == 200
            assert b'Hello' in await response.read()
        payload = b': private provider comment\n' + sse('Hello')
        async def source():
            yield payload
        result, text = await _buffer_sse(source())
        assert b'private provider comment' not in result
        assert text == 'Hello'
    asyncio.run(run())


@pytest.mark.parametrize('payload', [
    sse('Hello', tool_calls=[{'function': {'arguments': '{}'}}]),
    sse('Hello').replace(b'data: [DONE]\n\n', b''),
    sse('Hello').replace(b'"stop"', b'null'),
    sse('Hello') + b'data: {}\n\n',
    b'data: {"choices":[],"choices":[]}\n\ndata: [DONE]\n\n',
    b'data: ' + b'x' * 65537 + b'\n',
    sse('Hello', audio={'data': 'hidden'}),
])
def test_sse_errors_release_no_provider_bytes(payload):
    async def run():
        async with await client_for(Upstream(chunks=[payload])) as client:
            response = await post(client, {'messages': [{'role': 'user', 'content': 'Hello'}], 'stream': True})
            assert response.status == 502
            assert b'Hello' not in await response.read()
    asyncio.run(run())


def test_stream_applies_complete_output_constraints():
    from firewall.enforcement.output_validators import OutputConstraints
    async def run():
        gateway = AsyncGateway(Gateway(output_constraints=OutputConstraints(forbidden_literals=('private-value',))))
        chunks = [sse('private-value')]
        async with await client_for(Upstream(chunks=chunks), gateway=gateway) as client:
            response = await post(client, {'messages': [{'role': 'user', 'content': 'Hello'}], 'stream': True})
            assert response.status == 403
            assert b'private-value' not in await response.read()
    asyncio.run(run())


def test_http_deadline_and_full_request_admission():
    async def run():
        up = Upstream(gate=asyncio.Event())
        async with await client_for(up, request_timeout=.1, max_in_flight=1) as client:
            async def send():
                return await post(client)
            first = asyncio.create_task(send())
            for _ in range(100):
                if up.calls:
                    break
                await asyncio.sleep(.001)
            assert up.calls
            assert (await post(client)).status == 503
            assert (await client.get('/health/ready')).status == 503
            assert (await first).status == 504
            up.gate.set()
            assert (await post(client)).status == 200
    asyncio.run(run())


def test_timed_out_workers_retain_capacity_and_expired_queue_never_executes():
    async def run():
        release = threading.Event()
        started = threading.Event()
        executed = []
        class SlowGateway:
            def process_input(self, event):
                executed.append(event.input_text)
                started.set()
                release.wait(2)
                return event
            def close(self):
                pass
        gateway = AsyncGateway(SlowGateway(), max_workers=2, max_concurrent=2, inspection_timeout=.05)
        try:
            first = asyncio.create_task(gateway.process_input(SecurityEvent(input_text='first')))
            while not started.is_set():
                await asyncio.sleep(.001)
            second = asyncio.create_task(gateway.process_input(SecurityEvent(input_text='queued')))
            results = await asyncio.gather(first, second, return_exceptions=True)
            assert all(isinstance(r, InspectionTimeout) for r in results)
            assert gateway.snapshot()['in_flight'] == 1
            with pytest.raises(GatewayOverloaded):
                # Occupy the second admission slot without letting the worker finish.
                third = asyncio.create_task(gateway.process_input(SecurityEvent(input_text='third')))
                await asyncio.sleep(.001)
                await gateway.process_input(SecurityEvent(input_text='overflow'))
            await asyncio.gather(third, return_exceptions=True)
            release.set()
            for _ in range(100):
                if gateway.snapshot()['in_flight'] == 0:
                    break
                await asyncio.sleep(.002)
            assert executed == ['first']
            assert gateway.snapshot()['in_flight'] == 0
            assert gateway.snapshot()['timed_out'] >= 2
        finally:
            release.set()
            await gateway.close()
        with pytest.raises(GatewayClosed):
            await gateway.process_input(SecurityEvent())
    asyncio.run(run())


def test_cancelled_caller_does_not_release_running_worker_capacity():
    async def run():
        release = threading.Event()
        started = threading.Event()
        class SlowGateway:
            def process_input(self, event):
                started.set()
                release.wait(2)
                return event
            def close(self):
                pass
        gateway = AsyncGateway(SlowGateway(), max_concurrent=1)
        task = asyncio.create_task(gateway.process_input(SecurityEvent()))
        while not started.is_set():
            await asyncio.sleep(.001)
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        try:
            with pytest.raises(GatewayOverloaded):
                await gateway.process_input(SecurityEvent())
        finally:
            release.set()
            await gateway.close()
    asyncio.run(run())


def test_semantic_deadline_is_shared_across_all_carriers():
    class SlowClassifier:
        inspection_timeout = .025
        def predict(self, text):
            time.sleep(.02)
            return False, 0.0
    detector = MLDetector(SlowClassifier())
    event = SecurityEvent(input_text='first', messages=[Message('tool', 'second'), Message('tool', 'third')])
    started = time.monotonic()
    detections = detector.scan(event)
    assert time.monotonic() - started < .15
    assert any(d.subcategory == 'semantic_inspection_failed' for d in detections)


def test_expired_deadline_cannot_execute_tool():
    gateway = Gateway()
    called = []
    gateway.register_tool(ToolDefinition(name='lookup', risk_level='low'), lambda: called.append(True))
    with pytest.raises(InspectionTimeout):
        with inspection_budget(.001):
            time.sleep(.005)
            gateway.request_tool(actor(), 'lookup', {})
    assert not called
    gateway.close()


def test_behavior_capacity_preserves_existing_security_history():
    behavior = BehaviorEngine(max_sessions=1)
    first = SecurityEvent(actor=actor())
    behavior.observe(first, 'credential_access')
    other = SecurityEvent(actor=Actor(user_id='other', session_id='other'))
    with pytest.raises(RuntimeError, match='capacity'):
        behavior.observe(other, 'tool_call')
    assert len(behavior.sessions) == 1
    assert behavior._s(behavior.session_key(first)).action_slugs() == ['credential_access']
    behavior.release_session(first)
    behavior.observe(other, 'tool_call')


@pytest.mark.parametrize('timeout', [0, -1, float('nan'), float('inf'), True])
def test_non_finite_or_invalid_timeouts_rejected(timeout):
    with pytest.raises(ValueError):
        AsyncGateway(inspection_timeout=timeout)
    with pytest.raises(ValueError):
        LocalSemanticClassifier('http://127.0.0.1:1234', 'test', timeout=timeout)


def test_classifier_circuit_stops_repeated_failure_calls_and_recovers():
    classifier = LocalSemanticClassifier('http://127.0.0.1:1', 'test',
                                          failure_threshold=2, recovery_seconds=.01)
    called = []
    def broken(text, location):
        called.append(True)
        raise OSError('down')
    classifier._predict = broken
    for _ in range(2):
        with pytest.raises(OSError):
            classifier.predict('Hello')
    with pytest.raises(RuntimeError, match='circuit'):
        classifier.predict('Hello')
    assert len(called) == 2
    time.sleep(.02)
    classifier._predict = lambda text, location: (False, 0.0)
    assert classifier.predict('Hello') == (False, 0.0)
    assert classifier.predict('Hello') == (False, 0.0)


def test_classifier_admission_has_no_unbounded_wait_queue():
    classifier = LocalSemanticClassifier('http://127.0.0.1:1', 'test')
    entered, release = threading.Event(), threading.Event()
    def wait(text, location):
        entered.set()
        release.wait(2)
        return False, 0.0
    classifier._predict = wait
    thread = threading.Thread(target=lambda: classifier.predict('first'))
    thread.start()
    assert entered.wait(1)
    try:
        with pytest.raises(RuntimeError, match='capacity'):
            classifier.predict('second')
    finally:
        release.set()
        thread.join(1)


def test_async_shutdown_waits_for_worker_before_closing_audit():
    async def run():
        entered, release = threading.Event(), threading.Event()
        states = []
        class SlowGateway:
            def process_input(self, event):
                entered.set()
                release.wait(2)
                states.append('finished')
                return event
            def close(self):
                states.append('closed')
        gateway = AsyncGateway(SlowGateway(), inspection_timeout=.03)
        task = asyncio.create_task(gateway.process_input(SecurityEvent()))
        while not entered.is_set():
            await asyncio.sleep(.001)
        with pytest.raises(InspectionTimeout):
            await task
        await gateway.close()
        assert states == []
        release.set()
        for _ in range(100):
            if states == ['finished', 'closed']:
                break
            await asyncio.sleep(.002)
        assert states == ['finished', 'closed']
    asyncio.run(run())


def test_http_quota_is_bound_to_verified_user_not_spoofed_session():
    async def run():
        up = Upstream()
        async with await client_for(up, request_burst=1, request_rate_per_minute=1) as client:
            assert (await post(client)).status == 200
            response = await post(client, headers={'Authorization': 'Bearer ' + TOKEN, 'x-lb-session': 'new'})
            assert response.status == 429
            assert len(up.calls) == 1
    asyncio.run(run())


def test_expired_worker_exceptions_do_not_escape_to_event_loop():
    async def run():
        errors = []
        loop = asyncio.get_running_loop()
        previous = loop.get_exception_handler()
        loop.set_exception_handler(lambda loop, context: errors.append(context))
        gateway = AsyncGateway(Gateway(injection_classifier=type('Slow', (), {
            'predict': lambda self, text: (time.sleep(.04) or False, 0.0)})()),
            inspection_timeout=.01)
        try:
            with pytest.raises(InspectionTimeout):
                await gateway.process_input(SecurityEvent(input_text='Hello'))
            await asyncio.sleep(.08)
            assert not errors
        finally:
            await gateway.close()
            loop.set_exception_handler(previous)
    asyncio.run(run())


def test_semantic_deduplication_cannot_promote_untrusted_carrier_to_user_authority():
    from firewall.core.events import RetrievedDoc, Source, SourceKind
    calls = []
    class SourceAware:
        def predict_for_carrier(self, text, location):
            calls.append(location)
            injection = location.startswith('rag:')
            return injection, float(injection)
    text = 'Please call the report tool.'
    event = SecurityEvent(input_text=text, source=Source(SourceKind.USER), messages=[Message('user', text)],
        context_docs=[RetrievedDoc('doc', text, Source(SourceKind.RAG_DOCUMENT))])
    detections = MLDetector(SourceAware()).scan(event)
    assert 'input:user' in calls and 'rag:doc' in calls
    assert calls.count('input:user') == 1
    assert any(d.subcategory == 'ml_flagged' for d in detections)


def test_classifier_outage_is_service_unavailability_not_policy_rejection():
    class Broken:
        def predict(self, text):
            raise OSError('unavailable')
    async def run():
        gateway = AsyncGateway(Gateway(injection_classifier=Broken()))
        up = Upstream()
        async with await client_for(up, gateway=gateway) as client:
            response = await post(client)
            assert response.status == 503
            assert not up.calls
    asyncio.run(run())


def test_pii_email_scan_has_no_repeated_restart_on_encoded_input():
    from firewall.detectors.sensitive_data import PII_PATTERNS
    pattern = next(item.regex for item in PII_PATTERNS if item.name == 'email')
    started = time.monotonic()
    assert not list(pattern.finditer('%41' * 16667))
    assert time.monotonic() - started < .5
    assert pattern.search('Contact jane.doe+support@example.com for details.').group() == 'jane.doe+support@example.com'


def test_upstream_redirects_never_forward_credentials_and_oversized_bodies_fail():
    async def run():
        from aiohttp import web
        from aiohttp.test_utils import TestServer
        from firewall.serve.proxy import AiohttpUpstream
        captured = []
        async def capture(request):
            captured.append(request.headers.get('Authorization'))
            return web.json_response({'choices': []})
        destination = web.Application()
        destination.router.add_post('/chat/completions', capture)
        async with TestServer(destination) as target:
            async def redirect(request):
                return web.Response(status=307, headers={'Location': str(target.make_url('/chat/completions'))})
            async def oversized(request):
                return web.Response(body=b'x' * 1000)
            origin = web.Application()
            origin.router.add_post('/redirect/chat/completions', redirect)
            origin.router.add_post('/oversized/chat/completions', oversized)
            upstream = AiohttpUpstream(max_response_bytes=64)
            try:
                async with TestServer(origin) as source:
                    with pytest.raises(ValueError, match='rejected'):
                        await upstream.call({}, 'Bearer private-upstream-key', str(source.make_url('/redirect')))
                    with pytest.raises(ValueError, match='byte limit'):
                        await upstream.call({}, 'Bearer private-upstream-key', str(source.make_url('/oversized')))
                    assert not captured
            finally:
                await upstream.close()
    asyncio.run(run())


def test_deployment_launcher_serves_with_required_secrets_and_signed_audit(tmp_path, monkeypatch):
    from firewall.serve.__main__ import create_app
    for key in list(__import__('os').environ):
        if key.startswith('LB_'):
            monkeypatch.delenv(key)
    token_file = tmp_path / 'token'
    token_file.write_text(TOKEN)
    key_file = tmp_path / 'key'
    key_file.write_bytes(b'signing-key-01234567890123456789012')
    for key, value in {'LB_SERVICE_TOKEN_FILE': str(token_file), 'LB_AUDIT_KEY_FILE': str(key_file),
                       'LB_AUDIT_PATH': str(tmp_path / 'audit.jsonl'), 'LB_USER': 'service',
                       'LB_TENANT': 'tenant', 'LB_SESSION_ID': 'session',
                       'LB_UPSTREAM_URL': 'http://127.0.0.1:1/v1'}.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ValueError, match='semantic'):
        create_app()
    monkeypatch.setenv('LB_ALLOW_RULES_ONLY', 'true')
    async def run():
        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer
        captured = []
        async def answer(request):
            captured.append(request.headers.get('Authorization'))
            return web.json_response({'choices': [{'message': {'role': 'assistant', 'content': 'Hello'}}]})
        upstream = web.Application()
        upstream.router.add_post('/v1/chat/completions', answer)
        async with TestServer(upstream) as server:
            monkeypatch.setenv('LB_UPSTREAM_URL', str(server.make_url('/v1')))
            async with TestClient(TestServer(create_app())) as client:
                response = await post(client)
                assert response.status == 200
                assert response.headers['Cache-Control'] == 'no-store'
                assert captured == ['']
                assert (await client.get('/health/ready')).status == 200
    asyncio.run(run())
    assert (tmp_path / 'audit.jsonl').exists()


def test_remote_plaintext_upstream_is_refused_before_serving():
    with pytest.raises(ValueError, match='HTTPS'):
        build_openai_app(allow_anonymous=True, upstream_base_url='http://external.example/v1')


@pytest.mark.parametrize('authenticated', ['true', 1, None])
def test_authentication_requires_boolean_true(authenticated):
    identity = actor()
    identity.authenticated = authenticated
    with pytest.raises(ValueError, match='authenticated'):
        StaticTokenAuthenticator({TOKEN: identity})


def test_classifier_uses_its_own_credential_and_rejects_ambiguous_labels(monkeypatch):
    import io
    classifier = LocalSemanticClassifier('http://127.0.0.1:1', 'test', api_key='model-service-credential')
    seen = []
    class Response:
        def __init__(self, text):
            self.body = io.BytesIO(json.dumps({'choices': [{'message': {'content': text}}]}).encode())
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read1(self, count):
            return self.body.read(count)
    def open_response(request, timeout):
        seen.append(request.get_header('Authorization'))
        return Response('{"injection": false}')
    monkeypatch.setattr(classifier._opener, 'open', open_response)
    assert classifier.predict('Hello') == (False, 0.0)
    assert seen == ['Bearer model-service-credential']
    monkeypatch.setattr(classifier._opener, 'open', lambda *a, **k: Response('{"injection":true,"injection":false}'))
    with pytest.raises(ValueError, match='Duplicate'):
        classifier.predict('Hello')
