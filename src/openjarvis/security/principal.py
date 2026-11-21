"""Host-issued principal credentials for isolated execution tests.

This module deliberately provides a local test authority, not a production
identity provider. Callers must verify a credential before obtaining a
``TrustedPrincipal``; a caller supplied principal string is never sufficient.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PrincipalCredential:
    principal_id: str
    token_id: str
    issued_at: int
    expires_at: int
    signature: str


@dataclass(frozen=True, slots=True)
class TrustedPrincipal:
    principal_id: str
    token_id: str
    issued_at: int
    expires_at: int
    source: str
    _proof: object


def _payload(credential: PrincipalCredential) -> bytes:
    return json.dumps(
        {
            "principal_id": credential.principal_id,
            "token_id": credential.token_id,
            "issued_at": credential.issued_at,
            "expires_at": credential.expires_at,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class TestPrincipalAuthority:
    """Issue and revoke signed principals for local synthetic tests only."""

    __test__ = False

    source = "test-principal-authority"

    def __init__(self, secret: bytes, *, ttl: int = 300) -> None:
        if not isinstance(secret, bytes) or not secret or ttl <= 0:
            raise ValueError("principal authority configuration is invalid")
        self._secret = bytes(secret)
        self._ttl = int(ttl)
        self._proof = object()
        self._revoked: set[str] = set()
        self._issued: dict[str, tuple[str, int, int]] = {}

    def issue(self, principal_id: str) -> PrincipalCredential:
        if not isinstance(principal_id, str) or not principal_id.strip():
            raise ValueError("principal identity is required")
        now = int(time.time())
        credential = PrincipalCredential(
            principal_id.strip(),
            secrets.token_urlsafe(18),
            now,
            now + self._ttl,
            "",
        )
        self._issued[credential.token_id] = (
            credential.principal_id,
            credential.issued_at,
            credential.expires_at,
        )
        signature = hmac.new(
            self._secret, _payload(credential), hashlib.sha256
        ).hexdigest()
        return PrincipalCredential(
            credential.principal_id,
            credential.token_id,
            credential.issued_at,
            credential.expires_at,
            signature,
        )

    def verify(self, credential: PrincipalCredential) -> TrustedPrincipal:
        if not isinstance(credential, PrincipalCredential):
            raise PermissionError("principal credential required")
        if credential.token_id in self._revoked:
            raise PermissionError("principal revoked")
        if (
            type(credential.issued_at) is not int
            or type(credential.expires_at) is not int
        ):
            raise PermissionError("principal credential invalid")
        now = int(time.time())
        if now < credential.issued_at or now >= credential.expires_at:
            raise PermissionError("principal credential expired")
        expected = hmac.new(
            self._secret, _payload(credential), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, credential.signature):
            raise PermissionError("principal credential invalid")
        return TrustedPrincipal(
            credential.principal_id,
            credential.token_id,
            credential.issued_at,
            credential.expires_at,
            self.source,
            self._proof,
        )

    def accepts(self, principal: TrustedPrincipal) -> bool:
        if not self.owns(principal):
            return False
        now = int(time.time())
        if (
            principal.token_id in self._revoked
            or now < principal.issued_at
            or now >= principal.expires_at
        ):
            return False
        return True

    def owns(self, principal: TrustedPrincipal) -> bool:
        """Return whether this authority issued the binding, even if revoked."""
        return (
            isinstance(principal, TrustedPrincipal)
            and principal._proof is self._proof
            and principal.source == self.source
            and self._issued.get(principal.token_id)
            == (principal.principal_id, principal.issued_at, principal.expires_at)
        )

    def revoke(self, principal: TrustedPrincipal) -> None:
        if not self.owns(principal):
            raise PermissionError("principal is not owned by this authority")
        self._revoked.add(principal.token_id)


__all__ = ["PrincipalCredential", "TestPrincipalAuthority", "TrustedPrincipal"]
