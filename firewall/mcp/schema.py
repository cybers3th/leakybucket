"""Validate approved tool schemas without retrieving remote references."""
from functools import lru_cache
import json


@lru_cache(maxsize=256)
def _validator(canonical_schema):
    from jsonschema import Draft202012Validator
    from referencing import Registry
    schema = json.loads(canonical_schema)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=Registry())


def validate_arguments(schema, arguments):
    """Fail closed on invalid arguments, schema errors, and missing dependencies.

    Pinned schemas are administrator-reviewed configuration. No schema or
    validation error content is returned, since it can contain credentials.
    """
    try:
        canonical = json.dumps(schema, sort_keys=True, allow_nan=False)
        _validator(canonical).validate(arguments)
    except ImportError:
        return False, "Schema validation dependency missing; install the package"
    except Exception:
        return False, "Arguments do not satisfy the approved tool schema"
    return True, ""
