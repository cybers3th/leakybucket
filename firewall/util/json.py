"""Strict JSON decoding for security-sensitive wire formats."""
import json


def strict_json_loads(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError('Non-finite JSON number')
    return json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)
