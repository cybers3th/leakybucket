"""Scoped bearer credentials for service-to-service proxy deployments."""
from dataclasses import replace
import hashlib
import hmac

from firewall.core.events import Actor


def verified_actor(actor):
    return (isinstance(actor, Actor) and actor.authenticated is True
            and all(isinstance(value, str) and 1 <= len(value) <= 256
                    for value in (actor.user_id, actor.tenant, actor.session_id))
            and isinstance(actor.roles, list) and len(actor.roles) <= 64
            and all(isinstance(role, str) and 1 <= len(role) <= 128 for role in actor.roles))


class StaticTokenAuthenticator:
    """Bind administrator-provisioned tokens to server-controlled identities.

    Supply tokens from a secret manager, rotate them externally, and terminate
    TLS before this resolver. This adapter does not implement OAuth delegation.
    """
    def __init__(self, identities: dict[str, Actor]):
        if not identities:
            raise ValueError('At least one service credential is required')
        self._identities = []
        for token, actor in identities.items():
            if (not isinstance(token, str) or len(token) < 32 or len(token) > 4096
                    or any(c.isspace() for c in token) or not token.isascii()):
                raise ValueError('Service credentials must contain 32–4096 non-space ASCII characters')
            if not verified_actor(actor):
                raise ValueError('Provision authenticated identities with tenant and session IDs')
            self._identities.append((hashlib.sha256(token.encode()).digest(),
                                     replace(actor, roles=list(actor.roles), metadata={})))

    def __call__(self, request) -> Actor:
        value = request.headers.get('Authorization', '')
        if len(value) > 4103:
            raise PermissionError('Invalid credential')
        scheme, separator, token = value.partition(' ')
        if not separator or scheme.lower() != 'bearer' or not token or not token.isascii():
            raise PermissionError('Bearer credential required')
        digest = hashlib.sha256(token.encode()).digest()
        selected = None
        for expected, identity in self._identities:
            if hmac.compare_digest(digest, expected):
                selected = identity
        if selected is None:
            raise PermissionError('Invalid credential')
        return replace(selected, roles=list(selected.roles), metadata={})
