"""Bounded extraction for custom JSON AI protocols."""
import math

from firewall.util.json import strict_json_loads


def extract_json_text(content: bytes, max_bytes=262_144, max_chars=50_000):
    if not isinstance(content, bytes) or not 0 < len(content) <= max_bytes:
        raise ValueError('Missing or oversized JSON body')
    value = strict_json_loads(content.decode('utf-8'))
    if not isinstance(value, (dict, list)):
        raise ValueError('AI payload must be a JSON object or array')
    stack = [(value, 0)]
    strings = []
    nodes = chars = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > 4096 or depth > 24:
            raise ValueError('JSON structure exceeds inspection bounds')
        if isinstance(item, str):
            chars += len(item) + 1
            if chars > max_chars:
                raise ValueError('JSON text exceeds inspection bounds')
            strings.append(item)
        elif isinstance(item, dict):
            if len(item) * 2 + len(stack) + nodes > 8192:
                raise ValueError('JSON structure exceeds inspection bounds')
            parts = [part for pair in item.items() for part in pair]
            stack.extend((part, depth + 1) for part in reversed(parts))
        elif isinstance(item, list):
            if len(item) + len(stack) + nodes > 8192:
                raise ValueError('JSON structure exceeds inspection bounds')
            stack.extend((part, depth + 1) for part in reversed(item))
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError('JSON number exceeds finite inspection bounds')
        if len(stack) + nodes > 8192:
            raise ValueError('JSON structure exceeds inspection bounds')
    if not strings:
        raise ValueError('No inspectable JSON strings')
    return '\n'.join(strings)
