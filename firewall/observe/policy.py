"""Validated, bounded YAML policies with atomic reloads."""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Policy:
    digest: str
    rules: tuple
    prices: dict
    latency_ms: float | None
    cost_usd: float | None

    def evaluate(self, body):
        messages = body.get('messages', [])
        if not isinstance(messages, list):
            return []
        text = '\n'.join(m.get('content', '') for m in messages
                         if isinstance(m, dict) and isinstance(m.get('content'), str))
        matched = []
        for rule in self.rules:
            if rule.get('model') not in (None, body.get('model')):
                continue
            if rule.get('input_contains', '').casefold() not in text.casefold():
                continue
            matched.append({'name': rule['name'], 'action': rule['action']})
        return matched

    def cost(self, model, prompt, completion):
        price = self.prices.get(model)
        if price is None or prompt is None or completion is None:
            return None
        return (prompt * price[0] + completion * price[1]) / 1_000_000


def _number(value):
    if type(value) not in (float, int) or not 0 <= value <= 1_000_000 or not math.isfinite(value):
        raise ValueError('Thresholds and prices must be finite numbers between 0 and 1000000')
    return float(value)


def load_policy(path):
    import yaml
    raw = Path(path).read_bytes()
    if len(raw) > 65536:
        raise ValueError('Policy exceeds 64 KiB')

    class Loader(yaml.SafeLoader):
        def construct_mapping(self, node, deep=False):
            result = {}
            for key, value in node.value:
                name = self.construct_object(key, deep=deep)
                if not isinstance(name, str) or name in result:
                    raise ValueError('Policy keys must be unique strings')
                result[name] = self.construct_object(value, deep=deep)
            return result

    try:
        tokens = list(yaml.scan(raw))
        if len(tokens) > 8192 or any(isinstance(t, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)) for t in tokens):
            raise ValueError('YAML aliases, anchors and oversized policies are unsupported')
        data = yaml.load(raw, Loader=Loader)
    except (yaml.YAMLError, RecursionError, UnicodeError) as exc:
        raise ValueError('Invalid policy YAML') from exc
    if not isinstance(data, dict) or set(data) - {'version', 'rules', 'pricing', 'alerts'} or type(data.get('version')) is not int or data['version'] != 1:
        raise ValueError('Policy requires version: 1 and supported fields')
    rules = data.get('rules', [])
    if not isinstance(rules, list) or len(rules) > 128:
        raise ValueError('Policy supports up to 128 rules')
    names = set()
    for rule in rules:
        if (not isinstance(rule, dict) or set(rule) - {'name', 'model', 'input_contains', 'action'}
                or rule.get('action') not in ('block', 'warn')
                or not isinstance(rule.get('name'), str) or not 1 <= len(rule['name']) <= 128
                or rule['name'] in names
                or not any(k in rule for k in ('model', 'input_contains'))):
            raise ValueError('Invalid or duplicate rule')
        names.add(rule['name'])
        for key in ('model', 'input_contains'):
            if key in rule and (not isinstance(rule[key], str) or not 1 <= len(rule[key]) <= 1024):
                raise ValueError('Rule match must be a nonempty bounded string')
    prices = data.get('pricing', {})
    if not isinstance(prices, dict) or len(prices) > 256:
        raise ValueError('Invalid model pricing')
    parsed_prices = {}
    for model, price in prices.items():
        if (not 1 <= len(model) <= 256 or not isinstance(price, dict)
                or set(price) != {'input_per_million', 'output_per_million'}):
            raise ValueError('Pricing requires input_per_million and output_per_million')
        parsed_prices[model] = (_number(price['input_per_million']), _number(price['output_per_million']))
    alerts = data.get('alerts', {})
    if not isinstance(alerts, dict) or set(alerts) - {'latency_ms', 'cost_usd'}:
        raise ValueError('Invalid alert thresholds')
    return Policy(hashlib.sha256(raw).hexdigest(), tuple(rules), parsed_prices,
                  _number(alerts['latency_ms']) if 'latency_ms' in alerts else None,
                  _number(alerts['cost_usd']) if 'cost_usd' in alerts else None)
