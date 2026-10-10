"""Shared local-only evaluation transport and provenance utilities."""
from __future__ import annotations

import hashlib
from functools import lru_cache
import json
from pathlib import Path
import time
import urllib.parse
import urllib.request

from firewall.ml.semantic import LocalSemanticClassifier, _NoRedirect


class CachedLocalClassifier:
    """Bounded campaign-local cache of exact text plus source-location labels.

    Classification contexts are stateless. Faults are not cached. Operational
    measurements deliberately use the uncached adapter instead.
    """
    def __init__(self, endpoint, model, timeout=180):
        self.backend = LocalSemanticClassifier(endpoint, model, timeout=timeout)
        self.version = model

    def predict(self, text):
        return self.predict_for_carrier(text, 'input')

    @lru_cache(maxsize=256)
    def predict_for_carrier(self, text, location):
        return self.backend.predict_for_carrier(text, location)


def runtime_hash() -> str:
    digest = hashlib.sha256()
    root = Path(__file__).resolve().parent.parent
    paths = sorted((root / 'firewall').rglob('*.py'))
    if not paths:
        raise ValueError('Firewall sources missing; cannot pin evaluated runtime')
    for path in paths:
        digest.update(str(path.relative_to(root)).encode() + path.read_bytes())
    return digest.hexdigest()


def local_endpoint(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if (parsed.scheme != 'http' or parsed.hostname not in {'127.0.0.1', 'localhost', '::1'}
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('Evaluation requires a local HTTP endpoint')
    return value.rstrip('/')


def completion(endpoint, model, messages, *, max_tokens=96, seed=7, schema=None):
    payload = dict(model=model, messages=messages, max_tokens=max_tokens,
                   temperature=0, seed=seed)
    if schema is not None:
        payload['response_format'] = {'type': 'json_schema', 'json_schema': {
            'name': 'evaluation_response', 'strict': True, 'schema': schema}}
    request = urllib.request.Request(local_endpoint(endpoint) + '/v1/chat/completions',
                                    json.dumps(payload).encode(), {'Content-Type': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    started = time.perf_counter()
    with opener.open(request, timeout=240) as response:
        raw = response.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError('Model response exceeds evaluation bounds')
    result = json.loads(raw)
    choice = result['choices'][0]
    return dict(text=choice['message']['content'], finish_reason=choice.get('finish_reason'),
                usage=result.get('usage', {}), seconds=time.perf_counter() - started)


def save_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)
