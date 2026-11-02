"""Read-only service and provider diagnostics without generating model traffic."""
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from firewall.util.json import strict_json_loads

from .client import NoRedirect, TraceClient
from .local import config_directory
from .policy import load_policy


def provider_probe(url, token_file=None):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment
            or parsed.scheme == 'http' and parsed.hostname not in ('localhost', '127.0.0.1', '::1')):
        return {'state': 'invalid_url', 'models': []}
    headers = {}
    if token_file and Path(token_file).is_file():
        token = Path(token_file).read_text().strip()
        if not token.isascii() or not 1 <= len(token) <= 4096 or any(c.isspace() for c in token):
            return {'state': 'invalid_credentials', 'models': []}
        headers['Authorization'] = 'Bearer ' + token
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url.rstrip('/') + '/models', headers=headers)
    try:
        with opener.open(request, timeout=3) as response:
            payload = response.read(262145)
    except urllib.error.HTTPError as exc:
        code = exc.code
        exc.close()
        return {'state': 'authentication_required' if code in (401, 403) else 'models_endpoint_unavailable',
                'http_status': code, 'models': []}
    except (OSError, urllib.error.URLError):
        return {'state': 'unreachable', 'models': []}
    try:
        if len(payload) > 262144:
            raise ValueError('Oversized provider response')
        data = strict_json_loads(payload)
        if not isinstance(data, dict) or not isinstance(data.get('data'), list):
            raise ValueError('Unsupported models response')
        models = [item['id'] for item in data['data'] if isinstance(item, dict)
                  and isinstance(item.get('id'), str) and 0 < len(item['id']) <= 256][:64]
        return {'state': 'ready' if models else 'no_models', 'models': models}
    except (ValueError, UnicodeError, RecursionError):
        return {'state': 'invalid_models_response', 'models': []}


def diagnose(directory, saved, *, url=None, token_file=None, ca_file=None):
    try:
        installed = version('leakybucket-firewall')
    except PackageNotFoundError:
        installed = 'source checkout'
    report = {'version': installed, 'service': {'state': 'not_initialized'}, 'policy': {}, 'next_steps': []}
    service_url = url or saved.get('url') or 'http://127.0.0.1:8080'
    token_file = token_file or saved.get('token_file') or directory / 'service-token'
    if Path(token_file).is_file():
        try:
            status = TraceClient(service_url, token_file, ca_file).get('/api/status')
            report['service'] = {'state': 'ready' if status.get('ready') is True else 'degraded',
                                 'url': service_url, **status}
        except (ValueError, OSError):
            report['service'] = {'state': 'unreachable', 'url': service_url}
    if report['service']['state'] in ('not_initialized', 'unreachable'):
        report['next_steps'].append('Start the service: leakybucket start')
    if report['service']['state'] == 'degraded':
        report['next_steps'].append('Inspect readiness, audit health and capacity; restart an older service after updating it.')
    policy_path = Path(os.environ.get('LB_POLICY_PATH') or saved.get('policy_path') or config_directory() / 'policy.yaml')
    try:
        policy = load_policy(policy_path)
        report['policy'] = {'state': 'valid', 'path': str(policy_path), 'custom_rules': len(policy.rules)}
    except (ValueError, OSError):
        report['policy'] = {'state': 'invalid_or_missing', 'path': str(policy_path)}
        report['next_steps'].append('Validate the policy: leakybucket policy validate')
    provider_url = report['service'].get('upstream_url') or os.environ.get('LB_UPSTREAM_URL') or saved.get('upstream_url') or 'http://127.0.0.1:11434/v1'
    trusted_provider = os.environ.get('LB_UPSTREAM_URL') or saved.get('upstream_url') or 'http://127.0.0.1:11434/v1'
    provider_token = (os.environ.get('LB_UPSTREAM_TOKEN_FILE') or directory / 'upstream-token') if provider_url.rstrip('/') == trusted_provider.rstrip('/') else None
    report['provider'] = {'url': provider_url, **provider_probe(provider_url, provider_token)}
    if report['provider']['state'] == 'unreachable':
        report['next_steps'].append('Start your model provider, or stop LeakyBucket and restart it with --upstream-url URL.')
    elif report['provider']['state'] == 'authentication_required':
        report['next_steps'].append('Provision the provider key in the upstream-token file, then restart LeakyBucket.')
    elif report['provider']['state'] == 'no_models':
        report['next_steps'].append('Load a model in your provider before sending chat requests.')
    elif report['provider']['state'] != 'ready':
        report['next_steps'].append('Check the provider URL, credentials and OpenAI-compatible /models endpoint.')
    report['ready'] = report['service']['state'] == 'ready' and report['policy']['state'] == 'valid' and report['provider']['state'] == 'ready'
    return report
