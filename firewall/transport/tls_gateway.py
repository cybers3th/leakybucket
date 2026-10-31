"""Fail-closed custom-JSON inspection hooks for an explicit TLS proxy."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import json
import re
import socket
import urllib.parse

from firewall.core.events import Actor, Decision, SecurityEvent, Source, SourceKind
from firewall.enforcement.conntrack import ConnTracker, ConnectionRejected, ConnectionState
from firewall.serve.async_gateway import AsyncGateway
from firewall.transport.custom_json import extract_json_text


def ensure_tls_runtime():
    import importlib.metadata
    import brotli
    if not re.fullmatch(r'1\.2\.[1-9][0-9]*', brotli.__version__):
        raise RuntimeError('TLS inspection requires patched Brotli 1.2.1 or newer in the 1.2 series')
    if not re.fullmatch(r'6\.6(?:\.[0-9]+)?', importlib.metadata.version('tornado')):
        raise RuntimeError('TLS inspection requires patched Tornado 6.6')
    if not re.fullmatch(r'0\.6\.(?:[5-9]|[1-9][0-9]+)', importlib.metadata.version('pyasn1')):
        raise RuntimeError('TLS inspection requires patched pyasn1 0.6.5 or newer in the 0.6 series')
    if importlib.metadata.version('mitmproxy') != '12.3.0+leakybucket.2':
        raise RuntimeError('Install the reviewed TLS dependency wheel; upstream dependency constraints are unsafe')


def hostname(value):
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError('Invalid provider hostname')
    host = value.rstrip('.').encode('idna').decode('ascii').lower()
    if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                  for label in host.split('.')):
        raise ValueError('Use exact DNS hostnames, without wildcards, URLs, or ports')
    return host


@dataclass(frozen=True)
class CustomProvider:
    host: str
    paths: frozenset[str]
    ports: frozenset[int] = frozenset({443})
    approved_ips: frozenset[str] = frozenset()

    def __post_init__(self):
        object.__setattr__(self, 'host', hostname(self.host))
        object.__setattr__(self, 'paths', frozenset(self.paths))
        object.__setattr__(self, 'ports', frozenset(self.ports))
        if (not self.paths or any(not isinstance(path, str) or not path.startswith('/')
                or path.startswith('//') or any(c in path for c in '?\\#\r\n') for path in self.paths)):
            raise ValueError('Configure exact request paths without query strings')
        if not self.ports or any(type(port) is not int or not 1 <= port <= 65535 for port in self.ports):
            raise ValueError('Invalid provider ports')
        object.__setattr__(self, 'approved_ips', frozenset(str(ipaddress.ip_address(ip)) for ip in self.approved_ips))

    def validate_addresses(self, addresses):
        if not 1 <= len(addresses) <= 16:
            raise ValueError('DNS results exceed bounds or are empty')
        result = []
        for value in addresses:
            address = ipaddress.ip_address(value)
            if isinstance(address, ipaddress.IPv6Address) and address.scope_id is not None:
                raise ValueError('Scoped IP addresses are unsupported')
            canonical = str(address)
            if self.approved_ips and canonical not in self.approved_ips:
                raise ValueError('Resolved address is not explicitly approved')
            mapped = getattr(address, 'ipv4_mapped', None) or address
            if not mapped.is_global and canonical not in self.approved_ips:
                raise ValueError('Private destinations require explicit per-provider IP approval')
            if canonical not in result:
                result.append(canonical)
        return tuple(result)


async def resolve(host, port):
    results = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
        host, port, type=socket.SOCK_STREAM), 2)
    return list(dict.fromkeys(record[4][0] for record in results))


_AUTH_HEADERS = {'authorization', 'proxy-authorization', 'cookie', 'x-api-key', 'api-key', 'x-goog-api-key'}


def header_text(headers, request=False):
    parts = []
    total = 0
    for key, value in headers.items(multi=True):
        if request and key.lower() in _AUTH_HEADERS:
            continue
        total += len(key) + len(value) + 2
        if total > 16_384:
            raise ValueError('Header inspection budget exceeded')
        parts.append(key + ': ' + value)
    return '\n'.join(parts)


class TLSInspectionGateway:
    def __init__(self, providers, gateway: AsyncGateway, tenant: str, user_id: str,
                 tracker: ConnTracker | None = None, resolver=resolve, max_pending=128):
        ensure_tls_runtime()
        providers = tuple(providers)
        if not providers or len({p.host for p in providers}) != len(providers):
            raise ValueError('Configure unique, explicit provider hosts')
        if not all(isinstance(value, str) and 1 <= len(value) <= 128 for value in (tenant, user_id)):
            raise ValueError('Configure a tenant and authenticated proxy username')
        if type(max_pending) is not int or max_pending <= 0:
            raise ValueError('Invalid request admission limit')
        if gateway.gw.output_constraints.schema is not None:
            raise ValueError('Custom-JSON TLS extraction does not support model response schemas')
        self.providers = {p.host: p for p in providers}
        self.gateway, self.tenant, self.user_id = gateway, tenant, user_id
        self.tracker, self.resolver = tracker or ConnTracker(), resolver
        self.max_pending, self._pending = max_pending, {}
        self._pins = {}

    def _deny(self, flow, status=403):
        from mitmproxy import http
        flow.response = http.Response.make(status, json.dumps({'error': 'Traffic withheld by inspection gateway'}).encode(),
            {'Content-Type': 'application/json', 'Cache-Control': 'no-store'})
        flow.metadata['lb_denied'] = True
        self._finish(flow)

    def _finish(self, flow):
        self._pending.pop(flow.id, None)
        self.tracker.finish(self.tenant, flow.client_conn.id, flow.id)

    def client_connected(self, client):
        try:
            self.tracker.open(self.tenant, client.id, client.peername)
        except Exception:
            client.error = 'Connection admission refused'

    def client_disconnected(self, client):
        for flow_id, connection_id in list(self._pending.items()):
            if connection_id == client.id:
                del self._pending[flow_id]
        for server_id, pin in list(self._pins.items()):
            if pin[0] == client.id:
                del self._pins[server_id]
        self.tracker.close(self.tenant, client.id)

    def http_connect(self, flow):
        if flow.response is not None:
            flow.metadata['lb_denied'] = True
            return
        try:
            identity = flow.metadata.get('proxyauth')
            if not identity or identity[0] != self.user_id:
                self._deny(flow, 407)
                return
            host = hostname(flow.request.host)
            provider = self.providers[host]
            if flow.request.port not in provider.ports:
                raise ValueError('Unapproved port')
            self.tracker.bind(self.tenant, flow.client_conn.id, host, flow.request.port)
        except Exception:
            self.tracker.block(self.tenant, flow.client_conn.id)
            self._deny(flow)

    def tls_established_client(self, data):
        try:
            record = self.tracker.lookup(self.tenant, data.conn.id)
            if hostname(data.conn.sni) != record.host:
                raise ValueError('TLS SNI differs from the approved CONNECT target')
            self.tracker.establish(self.tenant, data.conn.id)
        except Exception:
            self.tracker.block(self.tenant, data.conn.id)
            data.conn.error = 'TLS connection is outside inspection scope'

    async def server_connect(self, data):
        try:
            record = self.tracker.lookup(self.tenant, data.client.id)
            if record.state != ConnectionState.ESTABLISHED:
                raise ConnectionRejected('Upstream connections require inspected client TLS')
            provider = self.providers[record.host]
            addresses = provider.validate_addresses(await asyncio.wait_for(self.resolver(record.host, record.port), 2))
            current = self.tracker.lookup(self.tenant, data.client.id)
            if (current.host, current.port, current.state) != (record.host, record.port, ConnectionState.ESTABLISHED):
                raise ConnectionRejected('Connection changed during DNS validation')
            # Pin the actual socket destination while preserving certificate/SNI verification.
            if len(self._pins) >= self.tracker.max_connections:
                raise ConnectionRejected('Upstream connection capacity exhausted')
            data.server.address = (addresses[0], record.port)
            data.server.sni = record.host
            self._pins[data.server.id] = (data.client.id, addresses[0])
        except Exception:
            data.server.error = 'Upstream destination validation failed'

    def server_disconnected(self, data):
        self._pins.pop(data.server.id, None)

    def server_connect_error(self, data):
        self._pins.pop(data.server.id, None)

    def requestheaders(self, flow):
        if flow.response is not None:
            flow.metadata['lb_denied'] = True
            return
        try:
            record = self.tracker.lookup(self.tenant, flow.client_conn.id)
            provider = self.providers[record.host]
            authority = urllib.parse.urlsplit('https://' + (flow.request.host_header or ''))
            if (authority.username is not None or authority.password is not None or authority.path
                    or authority.query or authority.fragment or hostname(authority.hostname) != record.host
                    or (authority.port or 443) != record.port):
                raise ValueError('HTTP authority differs from the approved TLS target')
            if (not flow.client_conn.tls_established or flow.request.scheme != 'https'
                    or (hostname(flow.request.host), flow.request.port) != (record.host, record.port)
                    or flow.request.method != 'POST' or flow.request.path not in provider.paths
                    or flow.request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json'
                    or flow.request.headers.get('content-encoding', 'identity').lower() != 'identity'
                    or flow.request.headers.get('upgrade') or flow.request.headers.get('expect')):
                raise ValueError('Unsupported request protocol or destination')
            length = flow.request.headers.get('content-length')
            if length is not None and not 0 < int(length) <= 262_144:
                raise ValueError('Request byte limit exceeded')
            if len(self._pending) >= self.max_pending:
                self._deny(flow, 503)
                return
            self.tracker.begin(self.tenant, flow.client_conn.id, flow.id)
            self._pending[flow.id] = flow.client_conn.id
            flow.request.stream = False
            flow.request.headers['accept-encoding'] = 'identity'
            flow.request.headers.pop('proxy-authorization', None)
        except Exception:
            self._deny(flow)

    async def request(self, flow):
        if flow.response is not None:
            flow.metadata['lb_denied'] = True
            return
        try:
            if self._pending.get(flow.id) != flow.client_conn.id:
                raise ConnectionRejected('Request was not admitted')
            content = flow.request.raw_content
            self.tracker.account(self.tenant, flow.client_conn.id, flow.id, 'request', len(content))
            text = extract_json_text(content) + '\n' + header_text(flow.request.headers, request=True)
            if len(text) > 50_000:
                raise ValueError('Request inspection budget exceeded')
            actor = Actor(user_id=self.user_id, tenant=self.tenant, session_id=flow.client_conn.id, authenticated=True)
            event = SecurityEvent(actor=actor, input_text=text,
                source=Source(SourceKind.USER, origin='tls-custom-json'), destination=flow.request.host)
            result = await self.gateway.process_input(event)
            if result.decision != Decision.ALLOW:
                self._deny(flow, 503 if any(d.subcategory == 'semantic_inspection_failed' for d in result.detections) else 403)
                return
            flow.metadata['lb_request_allowed'] = True
        except Exception:
            self._deny(flow, 503)

    def responseheaders(self, flow):
        if flow.metadata.get('lb_denied'):
            return
        try:
            flow.response.stream = False
            headers = flow.response.headers
            length = headers.get('content-length')
            if (not 200 <= flow.response.status_code < 300
                    or headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json'
                    or headers.get('content-encoding', 'identity').lower() != 'identity'
                    or (length is not None and not 0 < int(length) <= 262_144)):
                raise ValueError('Unsupported response transport')
        except Exception:
            flow.metadata['lb_denied'] = True
            self._finish(flow)
            flow.kill()

    async def response(self, flow):
        if flow.metadata.get('lb_denied'):
            return
        try:
            if not flow.metadata.get('lb_request_allowed') or flow.metadata.get('lb_bad_response'):
                raise ValueError('Response is unsupported or request was not allowed')
            content = flow.response.raw_content
            self.tracker.account(self.tenant, flow.client_conn.id, flow.id, 'response', len(content))
            flow.response.headers.pop('alt-svc', None)
            flow.response.headers.pop('set-cookie', None)
            text = extract_json_text(content) + '\n' + header_text(flow.response.headers)
            if len(text) > 50_000:
                raise ValueError('Response inspection budget exceeded')
            actor = Actor(user_id=self.user_id, tenant=self.tenant, session_id=flow.client_conn.id, authenticated=True)
            result = await self.gateway.process_output(SecurityEvent(actor=actor, output_text=text,
                source=Source(SourceKind.MODEL_OUTPUT, origin='tls-custom-json')))
            if result.decision != Decision.ALLOW:
                self._deny(flow)
                return
            flow.response.headers['cache-control'] = 'no-store'
            flow.response.headers.pop('alt-svc', None)
            flow.response.headers.pop('set-cookie', None)
        except Exception:
            self._deny(flow, 502)
        finally:
            self._finish(flow)

    def error(self, flow):
        self._finish(flow)

    def tcp_start(self, flow):
        self.tracker.block(self.tenant, flow.client_conn.id)
        flow.kill()

    def udp_start(self, flow):
        flow.kill()

    def websocket_start(self, flow):
        flow.kill()
