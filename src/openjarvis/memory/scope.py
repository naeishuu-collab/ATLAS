"""Deterministic ownership checks for model-facing memory."""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, List

SCHEMA_VERSION = 1

SCOPE_USER = "USER"
SCOPE_AGENT = "AGENT"
SCOPE_TASK = "TASK"
SCOPE_SESSION = "SESSION"
SCOPE_GLOBAL = "GLOBAL"
SCOPES = frozenset(
    {SCOPE_USER, SCOPE_AGENT, SCOPE_TASK, SCOPE_SESSION, SCOPE_GLOBAL}
)

PROVENANCE_USER_EXPLICIT = "USER_EXPLICIT"
PROVENANCE_USER_CORRECTION = "USER_CORRECTION"
PROVENANCE_TOOL_OBSERVATION = "TOOL_OBSERVATION"
PROVENANCE_TASK_RESULT = "TASK_RESULT"
PROVENANCE_SYSTEM_OBSERVATION = "SYSTEM_OBSERVATION"
PROVENANCE_MODEL_INFERENCE = "MODEL_INFERENCE"
PROVENANCE_IMPORTED = "IMPORTED"
PROVENANCES = frozenset(
    {
        PROVENANCE_USER_EXPLICIT,
        PROVENANCE_USER_CORRECTION,
        PROVENANCE_TOOL_OBSERVATION,
        PROVENANCE_TASK_RESULT,
        PROVENANCE_SYSTEM_OBSERVATION,
        PROVENANCE_MODEL_INFERENCE,
        PROVENANCE_IMPORTED,
    }
)

PRIVACY_PRIVATE = "PRIVATE"
PRIVACY_RESTRICTED = "RESTRICTED"
PRIVACY_NORMAL = "NORMAL"
PRIVACY_SHARED = "SHARED"
PRIVACIES = frozenset(
    {PRIVACY_PRIVATE, PRIVACY_RESTRICTED, PRIVACY_NORMAL, PRIVACY_SHARED}
)


@dataclass(frozen=True, slots=True)
class MemoryAuthorization:
    """Identity available to one memory read/write operation."""

    user_id: str | None = None
    agent_id: str | None = None
    task_id: str | None = None
    session_id: str | None = None
    allow_global: bool = False

    def has(self, name: str) -> bool:
        return bool(getattr(self, name, None))


def _text(value: Any) -> str:
    return str(value or "").strip()


def _same_optional_owner(
    metadata: Mapping[str, Any], auth: MemoryAuthorization
) -> bool:
    """Reject a row carrying a more specific owner than the caller proves."""
    for key in ("owner_user_id", "agent_id", "task_id", "session_id"):
        stored = _text(metadata.get(key))
        if not stored:
            continue
        caller_key = "user_id" if key == "owner_user_id" else key
        caller = _text(getattr(auth, caller_key, None))
        if not caller or caller != stored:
            return False
    return True


def authorized_metadata(
    metadata: Mapping[str, Any] | None,
    authorization: MemoryAuthorization | None,
    *,
    now: float | None = None,
) -> bool:
    """Return whether *metadata* is safe for this caller to use.

    Missing or legacy ownership metadata is deliberately rejected whenever an
    authorization is supplied. Callers without an authorization must use the
    legacy compatibility paths explicitly; this function never treats them as
    shared.
    """
    if authorization is None or not isinstance(metadata, Mapping):
        return False
    try:
        if int(metadata.get("schema_version", 0)) != SCHEMA_VERSION:
            return False
    except (TypeError, ValueError):
        return False

    scope = _text(metadata.get("scope")).upper()
    if scope not in SCOPES or bool(metadata.get("deleted", False)):
        return False
    provenance = _text(metadata.get("provenance")).upper()
    if provenance not in PROVENANCES:
        return False
    try:
        confidence = float(metadata.get("confidence"))
    except (TypeError, ValueError):
        return False
    if not 0.0 <= confidence <= 1.0:
        return False
    privacy = _text(metadata.get("privacy")).upper()
    if privacy not in PRIVACIES:
        return False
    expiry = metadata.get("expires_at")
    if expiry not in (None, ""):
        try:
            if float(expiry) <= (time.time() if now is None else now):
                return False
        except (TypeError, ValueError):
            return False

    if scope == SCOPE_USER:
        if not authorization.has("user_id") or _text(
            metadata.get("owner_user_id")
        ) != authorization.user_id:
            return False
    elif scope == SCOPE_AGENT:
        if not authorization.has("agent_id") or _text(
            metadata.get("agent_id")
        ) != authorization.agent_id:
            return False
    elif scope == SCOPE_TASK:
        if not authorization.has("task_id") or _text(
            metadata.get("task_id")
        ) != authorization.task_id:
            return False
    elif scope == SCOPE_SESSION:
        if not authorization.has("session_id") or _text(
            metadata.get("session_id")
        ) != authorization.session_id:
            return False
    elif not (
        authorization.allow_global
        and privacy == PRIVACY_SHARED
        and metadata.get("shared") is True
    ):
        return False

    return _same_optional_owner(metadata, authorization)


def build_metadata(
    authorization: MemoryAuthorization,
    *,
    scope: str = SCOPE_AGENT,
    provenance: str = PROVENANCE_MODEL_INFERENCE,
    confidence: float = 0.0,
    privacy: str = PRIVACY_PRIVATE,
    expires_at: float | None = None,
    now: float | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create validated ownership metadata for a new memory row."""
    scope = _text(scope).upper()
    provenance = _text(provenance).upper()
    privacy = _text(privacy).upper()
    if scope not in SCOPES:
        raise ValueError(f"unknown memory scope: {scope!r}")
    if provenance not in PROVENANCES:
        raise ValueError(f"unknown memory provenance: {provenance!r}")
    try:
        confidence = float(confidence)
    except (TypeError, ValueError) as exc:
        raise ValueError("memory confidence must be numeric") from exc
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("memory confidence must be between 0 and 1")
    if privacy not in PRIVACIES:
        raise ValueError(f"unknown memory privacy: {privacy!r}")
    required = {
        SCOPE_USER: "user_id",
        SCOPE_AGENT: "agent_id",
        SCOPE_TASK: "task_id",
        SCOPE_SESSION: "session_id",
    }.get(scope)
    if required and not authorization.has(required):
        raise ValueError(f"{scope} memory requires {required}")
    if scope == SCOPE_GLOBAL and not (
        authorization.allow_global and privacy == PRIVACY_SHARED
    ):
        raise ValueError("GLOBAL memory requires explicit shared authorization")

    timestamp = time.time() if now is None else float(now)
    metadata: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "owner_user_id": authorization.user_id,
        "agent_id": authorization.agent_id if scope == SCOPE_AGENT else None,
        "task_id": authorization.task_id if scope == SCOPE_TASK else None,
        "session_id": authorization.session_id if scope == SCOPE_SESSION else None,
        "scope": scope,
        "provenance": provenance,
        "confidence": confidence,
        "privacy": privacy,
        "created_at": timestamp,
        "updated_at": timestamp,
        "expires_at": expires_at,
        "deleted": False,
        "shared": scope == SCOPE_GLOBAL,
    }
    if extra:
        # Callers may add provenance references and trust tags, but may not
        # override the ownership or lifecycle fields above.
        for key, value in extra.items():
            if key not in metadata:
                metadata[key] = value
    ownership_metadata = dict(metadata)
    ownership_metadata["expires_at"] = None
    if not authorized_metadata(ownership_metadata, authorization, now=timestamp):
        raise ValueError("memory metadata failed ownership validation")
    return metadata


def retrieve_authorized(
    backend: Any,
    query: str,
    *,
    top_k: int,
    authorization: MemoryAuthorization | None,
) -> List[Any]:
    """Retrieve only authorized rows, fetching the full index first.

    A bounded top-k fetch cannot prove that an unauthorized exact match did not
    crowd out an authorized weaker match. Backends without a count contract
    therefore fail closed for scoped reads.
    """
    if authorization is None or top_k <= 0:
        return []
    count = getattr(backend, "count", None)
    if not callable(count):
        return []
    try:
        fetch_k = max(top_k, int(count()))
        results = backend.retrieve(query, top_k=fetch_k)
    except Exception:
        return []
    allowed = [
        result
        for result in results
        if authorized_metadata(getattr(result, "metadata", None), authorization)
    ]
    return allowed[:top_k]


class ScopedMemoryBackend:
    """Ownership-enforcing view over an existing backend."""

    def __init__(
        self,
        backend: Any,
        authorization: MemoryAuthorization | None,
        *,
        scope: str = SCOPE_AGENT,
        provenance: str = PROVENANCE_TOOL_OBSERVATION,
        privacy: str = PRIVACY_PRIVATE,
    ) -> None:
        self._backend = backend
        self._authorization = authorization
        self._scope = scope
        self._provenance = provenance
        self._privacy = privacy
        self.backend_id = f"scoped:{getattr(backend, 'backend_id', 'memory')}"

    def store(
        self,
        content: str,
        source: str = "",
        *,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        if self._authorization is None:
            raise PermissionError("memory ownership identity is required")
        supplied = dict(metadata or {})
        generated = build_metadata(
            self._authorization,
            scope=self._scope,
            provenance=str(supplied.pop("provenance", self._provenance)),
            confidence=float(supplied.pop("confidence", 1.0)),
            privacy=str(supplied.pop("privacy", self._privacy)),
            expires_at=supplied.pop("expires_at", None),
            extra=supplied,
        )
        return self._backend.store(content, source=source, metadata=generated)

    def retrieve(
        self,
        query: str,
        *,
        top_k: int = 5,
        **kwargs: Any,
    ) -> List[Any]:
        del kwargs
        return retrieve_authorized(
            self._backend,
            query,
            top_k=top_k,
            authorization=self._authorization,
        )

    def delete(self, doc_id: str) -> bool:
        # A backend-specific lookup is required before a scoped delete. Do not
        # turn an opaque id into a cross-owner deletion primitive.
        return False

    def clear(self) -> None:
        raise PermissionError("scoped memory cannot clear the shared backend")

    def count(self) -> int:
        # A scoped count is intentionally unavailable without a backend-native
        # metadata count; exposing the shared total would leak other owners.
        return 0


__all__ = [
    "MemoryAuthorization",
    "ScopedMemoryBackend",
    "SCHEMA_VERSION",
    "SCOPE_USER",
    "SCOPE_AGENT",
    "SCOPE_TASK",
    "SCOPE_SESSION",
    "SCOPE_GLOBAL",
    "PROVENANCE_USER_EXPLICIT",
    "PROVENANCE_USER_CORRECTION",
    "PROVENANCE_TOOL_OBSERVATION",
    "PROVENANCE_TASK_RESULT",
    "PROVENANCE_SYSTEM_OBSERVATION",
    "PROVENANCE_MODEL_INFERENCE",
    "PROVENANCE_IMPORTED",
    "PRIVACY_PRIVATE",
    "PRIVACY_RESTRICTED",
    "PRIVACY_NORMAL",
    "PRIVACY_SHARED",
    "authorized_metadata",
    "build_metadata",
    "retrieve_authorized",
]
