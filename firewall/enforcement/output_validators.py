"""Output-shape / schema validation.

Deliberately dependency-free — supports a subset of JSON Schema sufficient
for structured LLM output enforcement: type, properties, required, enum,
minLength, maxLength, minimum, maximum, pattern, items, additionalProperties.
"""
from __future__ import annotations

import json
import re
from typing import Any


class SchemaError(ValueError):
    pass


def validate_json_schema(instance: Any, schema: dict, path: str = "$") -> list[str]:
    """Return a list of error messages. Empty list = valid."""
    errors: list[str] = []
    if "$ref" in schema:
        return errors  # refs not supported in this minimal impl
    t = schema.get("type")
    if t:
        if not _type_matches(instance, t):
            errors.append(f"{path}: expected type {t}, got {type(instance).__name__}")
            return errors
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: value {instance!r} not in enum {schema['enum']}")
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{path}: string shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{path}: string longer than maxLength {schema['maxLength']}")
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            errors.append(f"{path}: string does not match pattern {schema['pattern']}")
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: {instance} < minimum {schema['minimum']}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: {instance} > maximum {schema['maximum']}")
    if isinstance(instance, list) and "items" in schema:
        for i, item in enumerate(instance):
            errors += validate_json_schema(item, schema["items"], f"{path}[{i}]")
    if isinstance(instance, dict):
        required = schema.get("required", [])
        for k in required:
            if k not in instance:
                errors.append(f"{path}: missing required '{k}'")
        props = schema.get("properties", {})
        for k, v in instance.items():
            if k in props:
                errors += validate_json_schema(v, props[k], f"{path}.{k}")
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: additional property '{k}' not allowed")
    return errors


def _type_matches(instance: Any, t: str) -> bool:
    return {
        "string":  isinstance(instance, str),
        "integer": isinstance(instance, int) and not isinstance(instance, bool),
        "number":  isinstance(instance, (int, float)) and not isinstance(instance, bool),
        "boolean": isinstance(instance, bool),
        "array":   isinstance(instance, list),
        "object":  isinstance(instance, dict),
        "null":    instance is None,
    }.get(t, False)


def try_parse_json(text: str) -> tuple[Any, str | None]:
    try:
        return json.loads(text), None
    except Exception as e:
        return None, str(e)
