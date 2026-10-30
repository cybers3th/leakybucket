"""Bounded authenticated trace client for terminal operations."""
from __future__ import annotations

import asyncio
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from firewall.util.json import strict_json_loads


def safe(value, width=180):
    text = str(value)
    return ''.join(c if c.isprintable() else c.encode('unicode_escape').decode('ascii') for c in text)[:width]


def summary(trace):
    tokens = 'unknown'
    if trace.get('prompt_tokens') is not None and trace.get('completion_tokens') is not None:
        tokens = str(trace['prompt_tokens'] + trace['completion_tokens'])
    cost = 'unknown' if trace.get('cost_usd') is None else f"${trace['cost_usd']:.6f}"
    return (f"{safe(trace['id'], 32):32}  {safe(trace['model'], 28):28}  {trace['status']:3}  "
            f"{trace['latency_ms']:9.1f} ms  {tokens:>9}  {cost}")


def print_trace(trace, as_json=False):
    if as_json:
        print(json.dumps(trace, ensure_ascii=True, allow_nan=False))
        return
    print(summary(trace))
    print('Policy: ' + safe(trace.get('policy_version', 'unknown')))
    for span in sorted(trace.get('spans', []), key=lambda item: item['offset_ms']):
        print(f"  +{span['offset_ms']:9.1f} ms  {span['duration_ms']:9.1f} ms  {safe(span['kind'])}")
        for match in span.get('matches', []):
            print('    ' + safe(match['name']) + ': ' + safe(match['action']))
        for key in ('attempt', 'chunks', 'index', 'bytes'):
            if key in span:
                print(f'    {key}: {safe(span[key])}')
    if trace.get('content_captured'):
        print('Prompt: ' + json.dumps(trace.get('prompt'), ensure_ascii=True))
        print('Response: ' + json.dumps(trace.get('response'), ensure_ascii=True))
    else:
        print('Content capture is disabled.')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


class TraceClient:
    def __init__(self, base_url, token_file, ca_file=None):
        parsed = urllib.parse.urlsplit(base_url)
        if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or parsed.path not in ('', '/')
                or parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1', '::1')):
            raise ValueError('Trace server requires HTTPS outside loopback and a root URL')
        token = Path(token_file).read_text().strip()
        if not 32 <= len(token) <= 4096 or not token.isascii() or any(c.isspace() for c in token):
            raise ValueError('Invalid service token file')
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.ssl = ssl.create_default_context(cafile=ca_file)
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}),
                                                 urllib.request.HTTPSHandler(context=self.ssl))

    def get(self, path):
        return self._request(path)

    def chat(self, model, prompt, max_tokens=256):
        return self._request('/v1/chat/completions', {'model': model, 'messages': [{'role': 'user', 'content': prompt}], 'max_tokens': max_tokens})

    def _request(self, path, body=None):
        if not (path.startswith('/api/') or path == '/v1/chat/completions'):
            raise ValueError('Unsupported trace API path')
        headers = {'Authorization': 'Bearer ' + self.token}
        payload = None
        if body is not None:
            headers['Content-Type'] = 'application/json'
            payload = json.dumps(body, ensure_ascii=True, allow_nan=False).encode()
        request = urllib.request.Request(self.base_url + path, data=payload, headers=headers)
        try:
            with self.opener.open(request, timeout=65 if body is not None else 10) as response:
                payload = response.read(2_097_153)
                self.last_trace_id = response.headers.get('X-LeakyBucket-Trace')
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            if body is not None and code == 403:
                raise ValueError('Request blocked by LeakyBucket. Use leakybucket trace to inspect the decision.') from None
            if body is not None and code in (502, 503, 504):
                raise ValueError(f'Model request failed (HTTP {code}). Run leakybucket doctor to check the provider and service.') from None
            raise ValueError(f'Trace service returned HTTP {code}') from None
        except urllib.error.URLError:
            raise ValueError(f'Service is not reachable at {self.base_url}. Run leakybucket start, or check --url.') from None
        if len(payload) > 2_097_152:
            raise ValueError('Trace response exceeds 2 MiB')
        return strict_json_loads(payload)

    async def watch(self, *, as_json=False, count=None):
        from aiohttp import ClientError

        try:
            return await self._watch(as_json=as_json, count=count)
        except ClientError:
            raise ValueError('Live trace connection failed; check service availability and authentication') from None

    async def _watch(self, *, as_json=False, count=None):
        from aiohttp import ClientSession, ClientTimeout, TraceConfig, WSMsgType

        url = self.base_url.replace('https://', 'wss://', 1).replace('http://', 'ws://', 1) + '/api/live'
        delivered = 0
        redirects = TraceConfig()

        async def deny_redirect(*args):
            raise ValueError('Trace server redirects are not allowed')

        redirects.on_request_redirect.append(deny_redirect)
        async with ClientSession(timeout=ClientTimeout(total=None, sock_connect=5, sock_read=30), trust_env=False, trace_configs=[redirects]) as session:
            async with session.ws_connect(url, ssl=self.ssl, heartbeat=15, max_msg_size=8192) as socket:
                await socket.send_json({'token': self.token})
                first = await asyncio.wait_for(socket.receive(), timeout=10)
                if first.type != WSMsgType.TEXT or strict_json_loads(first.data).get('event') != 'connected':
                    raise ValueError('Live trace authentication failed')
                if not as_json:
                    print('Watching completed requests. Ctrl-C stops. Use traces to recover missed events.', flush=True)
                async for message in socket:
                    if message.type == WSMsgType.TEXT:
                        event = strict_json_loads(message.data)
                        if event.get('event') != 'completed':
                            continue
                        trace_id = urllib.parse.quote(event['id'], safe='')
                        trace = await asyncio.to_thread(self.get, '/api/traces/' + trace_id)
                        print(json.dumps(trace, ensure_ascii=True, allow_nan=False) if as_json else summary(trace), flush=True)
                        delivered += 1
                        if count is not None and delivered >= count:
                            return
                    elif message.type == WSMsgType.ERROR:
                        raise ValueError('Live trace connection failed')
                raise ValueError('Live trace connection closed; reconnect and query persisted traces')
