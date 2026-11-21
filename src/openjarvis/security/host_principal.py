"""Principal credentials minted and revoked by the Windows Host bootstrap."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock

from openjarvis.security.principal import TrustedPrincipal


@dataclass(frozen=True, slots=True)
class HostPrincipalCredential:
    principal_id: str
    token_id: str
    session_id: str
    issued_at: int
    expires_at: int
    signature: str


def _payload(credential: HostPrincipalCredential) -> bytes:
    return json.dumps(
        {
            "principal_id": credential.principal_id,
            "token_id": credential.token_id,
            "session_id": credential.session_id,
            "issued_at": credential.issued_at,
            "expires_at": credential.expires_at,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class HostPrincipalAuthority:
    """Authenticate Host-delivered credentials after OS-bound pipe delivery."""

    source = "windows-host-bootstrap"

    def __init__(
        self,
        secret: bytes,
        *,
        ttl: int = 3600,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            not isinstance(secret, bytes)
            or len(secret) < 32
            or type(ttl) is not int
            or ttl <= 0
            or not callable(clock)
        ):
            raise ValueError("host principal configuration is invalid")
        self._secret = bytes(secret)
        self._ttl = ttl
        self._clock = clock
        self._proof = object()
        self._verified: dict[str, tuple[str, str, int, int]] = {}
        self._revoked: set[str] = set()
        self._lock = Lock()

    def issue(
        self, principal_id: str, session_id: str, *, ttl: int | None = None
    ) -> HostPrincipalCredential:
        if (
            not isinstance(principal_id, str)
            or not principal_id.strip()
            or not isinstance(session_id, str)
            or not session_id.strip()
        ):
            raise ValueError("host principal and session are required")
        lifetime = self._ttl if ttl is None else ttl
        if type(lifetime) is not int or lifetime <= 0 or lifetime > self._ttl:
            raise ValueError("host principal lifetime is invalid")
        now = int(self._clock())
        unsigned = HostPrincipalCredential(
            principal_id.strip(),
            secrets.token_urlsafe(18),
            session_id.strip(),
            now,
            now + lifetime,
            "",
        )
        signature = hmac.new(
            self._secret,
            b"atlas-host-principal-v1\0" + _payload(unsigned),
            hashlib.sha256,
        ).hexdigest()
        return HostPrincipalCredential(
            unsigned.principal_id,
            unsigned.token_id,
            unsigned.session_id,
            unsigned.issued_at,
            unsigned.expires_at,
            signature,
        )

    def verify(self, credential: HostPrincipalCredential) -> TrustedPrincipal:
        if not isinstance(credential, HostPrincipalCredential):
            raise PermissionError("host principal credential required")
        if (
            not isinstance(credential.principal_id, str)
            or not credential.principal_id
            or len(credential.principal_id) > 256
            or not isinstance(credential.token_id, str)
            or not credential.token_id
            or len(credential.token_id) > 256
            or not isinstance(credential.session_id, str)
            or not credential.session_id
            or len(credential.session_id) > 256
            or type(credential.issued_at) is not int
            or type(credential.expires_at) is not int
            or credential.expires_at <= credential.issued_at
            or credential.expires_at - credential.issued_at > self._ttl
            or not isinstance(credential.signature, str)
            or len(credential.signature) != 64
        ):
            raise PermissionError("host principal credential invalid")
        now = int(self._clock())
        if now < credential.issued_at or now >= credential.expires_at:
            raise PermissionError("host principal credential expired")
        expected = hmac.new(
            self._secret,
            b"atlas-host-principal-v1\0" + _payload(credential),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, credential.signature):
            raise PermissionError("host principal credential invalid")
        with self._lock:
            if credential.token_id in self._revoked:
                raise PermissionError("host principal credential revoked")
            self._verified[credential.token_id] = (
                credential.principal_id,
                credential.session_id,
                credential.issued_at,
                credential.expires_at,
            )
        return TrustedPrincipal(
            credential.principal_id,
            credential.token_id,
            credential.issued_at,
            credential.expires_at,
            self.source,
            self._proof,
        )

    def accepts(
        self, principal: TrustedPrincipal, *, session_id: str | None = None
    ) -> bool:
        if (
            not isinstance(principal, TrustedPrincipal)
            or principal._proof is not self._proof
            or principal.source != self.source
        ):
            return False
        with self._lock:
            binding = self._verified.get(principal.token_id)
            revoked = principal.token_id in self._revoked
        if (
            binding is None
            or revoked
            or binding[0] != principal.principal_id
            or binding[2] != principal.issued_at
            or binding[3] != principal.expires_at
            or principal.expires_at <= int(self._clock())
            or (session_id is not None and binding[1] != session_id)
        ):
            return False
        return True

    def session_id(self, principal: TrustedPrincipal) -> str:
        if not self.accepts(principal):
            raise PermissionError("host principal binding invalid")
        return self._verified[principal.token_id][1]

    def revoke(self, principal: TrustedPrincipal) -> None:
        if not self.accepts(principal):
            raise PermissionError("host principal binding invalid")
        with self._lock:
            self._revoked.add(principal.token_id)


__all__ = ["HostPrincipalAuthority", "HostPrincipalCredential"]
