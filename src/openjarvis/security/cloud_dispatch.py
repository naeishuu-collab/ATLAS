"""Cloud dispatch privacy contract — fail-closed host authorization.

Design decisions (see docs/astra-cloud-egress-authorization.md plan):
- Untrusted callers build :class:`CloudDispatchRequest`; only
  :class:`CloudDispatchAuthorizer` can mint the sealed
  :class:`AuthorizedPayload`.
- Unknown classification is denied; PRIVATE is local-only (no cloud
  :class:`AuthorizedPayload` is ever issued for a cloud provider).
- Provider allowlist uses exact ``(engine, provider, model)`` matches.
- Empty/disabled/failing scanners deny instead of passing content through.
- The final redacted payload is digest-bound; any post-authorization
  mutation is rejected at send time (``CLOUD_PAYLOAD_CHANGED``).
- Audit records never contain raw prompts.

No network I/O here. No live cloud calls. No changes to
``HostLLMBroker``/``RequestLedger``/``ExecutionJournal``.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Failure codes (stable contract — routers and tests match on these)
# ---------------------------------------------------------------------------

PRIVACY_CLASSIFICATION_REQUIRED = "PRIVACY_CLASSIFICATION_REQUIRED"
PRIVACY_ROUTE_UNAVAILABLE = "PRIVACY_ROUTE_UNAVAILABLE"
CLOUD_PROVIDER_NOT_ALLOWED = "CLOUD_PROVIDER_NOT_ALLOWED"
PRIVACY_SCANNER_UNAVAILABLE = "PRIVACY_SCANNER_UNAVAILABLE"
CLOUD_PAYLOAD_CHANGED = "CLOUD_PAYLOAD_CHANGED"
BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
GRANT_EXPIRED = "GRANT_EXPIRED"
ENDPOINT_NOT_ALLOWED = "ENDPOINT_NOT_ALLOWED"
SESSION_MISMATCH = "SESSION_MISMATCH"
NONCE_REPLAY = "NONCE_REPLAY"

#: Cloud egress for these codes must never be retried blindly; a fresh
#: authorization is required.
NON_RETRYABLE_CODES = frozenset(
    {
        PRIVACY_CLASSIFICATION_REQUIRED,
        PRIVACY_ROUTE_UNAVAILABLE,
        CLOUD_PROVIDER_NOT_ALLOWED,
        PRIVACY_SCANNER_UNAVAILABLE,
        CLOUD_PAYLOAD_CHANGED,
        BUDGET_EXCEEDED,
        GRANT_EXPIRED,
        ENDPOINT_NOT_ALLOWED,
        SESSION_MISMATCH,
        NONCE_REPLAY,
    }
)


class PrivacyClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    PRIVATE = "PRIVATE"


class PrivacyDenied(RuntimeError):
    """Raised when cloud dispatch authorization fails (fail-closed)."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


# ---------------------------------------------------------------------------
# Value types (all frozen — the dispatch contract is immutable)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProviderIdentity:
    """Exact identity of one cloud-capable destination.

    ``endpoint`` binds the network destination (base URL / host) so a
    provider SDK cannot silently retarget the authorized payload.
    """

    engine: str
    provider: str
    model: str
    is_cloud: bool = True
    endpoint: str = ""

    def key(self) -> Tuple[str, str, str]:
        return (self.engine, self.provider, self.model)


@dataclass(frozen=True, slots=True)
class ExplicitGrant:
    agent_id: str
    capability: str
    resource: str = "llm"
    expires_at: Optional[float] = None  # epoch seconds; None = no expiry

    def expired(self, now: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return False
        return (time.time() if now is None else now) >= self.expires_at


@dataclass(frozen=True, slots=True)
class BudgetReservation:
    est_prompt_tokens: int = 0
    max_tokens: int = 1024
    ctx_limit: int = 16384
    per_request_usd: Optional[float] = None
    session_left_usd: Optional[float] = None
    reservation_id: str = ""


@dataclass(frozen=True, slots=True)
class DispatchIdentity:
    dispatch_id: str
    provider_key: Tuple[str, str, str]


PayloadDigest = str


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def compute_payload_digest(
    provider: ProviderIdentity, redacted_messages: Sequence[Dict[str, Any]]
) -> PayloadDigest:
    canonical = _canonical_json(
        {
            "engine": provider.engine,
            "provider": provider.provider,
            "model": provider.model,
            "endpoint": provider.endpoint,
            "messages": list(redacted_messages),
        }
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CloudDispatchRequest:
    classification: Optional[PrivacyClassification]
    provider: ProviderIdentity
    messages: Tuple[Dict[str, str], ...]
    grant: ExplicitGrant
    budget: BudgetReservation = field(default_factory=BudgetReservation)
    # Optional session/nonce binding. When set, the enforcement point must
    # present the same values; enforcement points additionally reject nonce
    # reuse within their scope (replay protection).
    session_id: str = ""
    nonce: str = ""


@dataclass(frozen=True, slots=True)
class AuthorizedPayload:
    """Sealed authorization. Only the authorizer can mint this."""

    dispatch_id: str
    provider: ProviderIdentity
    redacted_messages: Tuple[Dict[str, str], ...]
    digest: PayloadDigest
    grant: ExplicitGrant
    budget_id: str
    session_id: str = ""
    nonce: str = ""

    @property
    def identity(self) -> DispatchIdentity:
        return DispatchIdentity(
            dispatch_id=self.dispatch_id, provider_key=self.provider.key()
        )


# ---------------------------------------------------------------------------
# Authorizer
# ---------------------------------------------------------------------------


def _check_explicit_grant(policy: Any, grant: ExplicitGrant) -> bool:
    """Mirror HostLLMBroker's fail-closed grant check (no open-by-default)."""
    if policy is None:
        return False
    list_agents = getattr(policy, "list_agents", None)
    list_grants = getattr(policy, "list_grants", None)
    check = getattr(policy, "check", None)
    if not callable(list_agents) or not callable(list_grants) or not callable(check):
        return False
    try:
        import fnmatch

        agents = list(list_agents())
        grant_agent = grant.agent_id if grant.agent_id in agents else "_default"
        grants = list_grants(grant_agent)
        granted = any(
            fnmatch.fnmatchcase(grant.capability, str(getattr(g, "capability", "")))
            for g in grants
        )
        return bool(granted) and bool(
            check(grant.agent_id, grant.capability, grant.resource)
        )
    except Exception:
        return False


class CloudDispatchAuthorizer:
    """Fail-closed host authorization for cloud LLM egress.

    Parameters
    ----------
    allowlist:
        Exact set of permitted ``(engine, provider, model)`` keys.
    scanners:
        Non-empty list of scanner-likes exposing ``scan(text)`` (with
        ``.findings``) and ``redact(text)``. Empty/disabled/failing
        scanners deny every request.
    capability_policy:
        Object exposing ``list_agents/list_grants/check``; ``None``
        denies every request.
    """

    def __init__(
        self,
        *,
        allowlist: Iterable[Tuple[str, str, str]],
        scanners: Optional[Sequence[Any]] = None,
        capability_policy: Any = None,
        allowed_endpoints: Optional[Iterable[str]] = None,
    ) -> None:
        self._allowlist = frozenset(tuple(k) for k in allowlist)
        self._scanners: Tuple[Any, ...] = tuple(scanners) if scanners else ()
        self._policy = capability_policy
        self._allowed_endpoints = (
            frozenset(allowed_endpoints) if allowed_endpoints is not None else None
        )

    @property
    def allowlist(self) -> frozenset:
        return self._allowlist

    # -- main entry ------------------------------------------------------
    def authorize(self, request: CloudDispatchRequest) -> AuthorizedPayload:
        # 1. Classification is required (no inference, no default).
        if request.classification is None or not isinstance(
            request.classification, PrivacyClassification
        ):
            raise PrivacyDenied(
                PRIVACY_CLASSIFICATION_REQUIRED,
                "privacy classification is required for cloud dispatch",
            )
        # 2. PRIVATE is local-only — never mint a cloud authorization.
        if request.classification == PrivacyClassification.PRIVATE:
            if request.provider.is_cloud:
                raise PrivacyDenied(
                    PRIVACY_ROUTE_UNAVAILABLE,
                    "PRIVATE data is local-only; cloud dispatch denied",
                )
            # Local-only destinations are out of scope for cloud auth.
            raise PrivacyDenied(
                PRIVACY_ROUTE_UNAVAILABLE,
                "local-only destination does not need cloud authorization",
            )
        # 3. Exact allowlist match (no prefix/glob fallback).
        if request.provider.key() not in self._allowlist:
            raise PrivacyDenied(
                CLOUD_PROVIDER_NOT_ALLOWED,
                f"destination not allowlisted: {request.provider.key()!r}",
            )
        # 3b. Endpoint binding (model + endpoint are both authorized).
        if request.provider.is_cloud and self._allowed_endpoints is not None:
            if not request.provider.endpoint or (
                request.provider.endpoint not in self._allowed_endpoints
            ):
                raise PrivacyDenied(
                    ENDPOINT_NOT_ALLOWED,
                    "cloud endpoint is not in the allowed endpoint set",
                )
        # 4. Scanners must be present and usable (fail-closed).
        if not self._scanners:
            raise PrivacyDenied(
                PRIVACY_SCANNER_UNAVAILABLE,
                "no privacy scanners configured; failing closed",
            )
        # 5. Budget enforcement.
        budget = request.budget
        total = budget.est_prompt_tokens + budget.max_tokens
        if total > budget.ctx_limit:
            raise PrivacyDenied(
                BUDGET_EXCEEDED,
                f"token budget exceeded: {total} > ctx_limit {budget.ctx_limit}",
            )
        if (
            budget.per_request_usd is not None
            and budget.session_left_usd is not None
            and budget.per_request_usd > budget.session_left_usd
        ):
            raise PrivacyDenied(
                BUDGET_EXCEEDED,
                "cost budget exceeded for this dispatch",
            )
        # 6. Explicit grant (host-side, no LLM delegation).
        if request.grant.expired():
            raise PrivacyDenied(
                GRANT_EXPIRED,
                "capability grant has expired; re-authorize",
            )
        if not _check_explicit_grant(self._policy, request.grant):
            raise PrivacyDenied(
                CLOUD_PROVIDER_NOT_ALLOWED,
                "explicit capability grant required for cloud dispatch",
            )
        # 7. Redact + rescan the final payload.
        try:
            redacted = self._redact_messages(request.messages)
            self._assert_clean(redacted)
        except PrivacyDenied:
            raise
        except Exception as exc:
            raise PrivacyDenied(
                PRIVACY_SCANNER_UNAVAILABLE,
                f"scanner failure; failing closed ({type(exc).__name__})",
            ) from exc
        digest = compute_payload_digest(request.provider, redacted)
        return AuthorizedPayload(
            dispatch_id=f"cdisp_{uuid.uuid4().hex[:16]}",
            provider=request.provider,
            redacted_messages=tuple(redacted),
            digest=digest,
            grant=request.grant,
            budget_id=budget.reservation_id,
            session_id=request.session_id,
            nonce=request.nonce,
        )

    # -- send-time verification (TOCTOU prevention) -----------------------
    def verify_for_send(
        self,
        authorized: AuthorizedPayload,
        final_messages: Sequence[Dict[str, Any]],
        *,
        endpoint: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], ...]:
        """Recompute the digest over the exact bytes about to leave.

        Raises ``CLOUD_PAYLOAD_CHANGED`` on any drift (including key order
        independent content changes, provider swaps, or message edits).
        Also re-runs scanners over the final payload so a redact-then-
        reintroduce race is caught here, not just at authorize time.
        When the authorization binds an endpoint, the adapter must present
        the same endpoint it is actually sending to.
        """
        if not isinstance(authorized, AuthorizedPayload):
            raise PrivacyDenied(
                CLOUD_PAYLOAD_CHANGED, "unrecognized authorization object"
            )
        if authorized.provider.key() not in self._allowlist:
            raise PrivacyDenied(
                CLOUD_PROVIDER_NOT_ALLOWED,
                "destination no longer allowlisted at send time",
            )
        if authorized.provider.endpoint and endpoint != authorized.provider.endpoint:
            raise PrivacyDenied(
                CLOUD_PAYLOAD_CHANGED,
                "send-time endpoint differs from the authorized endpoint",
            )
        if self._allowed_endpoints is not None and authorized.provider.is_cloud:
            if endpoint not in self._allowed_endpoints:
                raise PrivacyDenied(
                    ENDPOINT_NOT_ALLOWED,
                    "send-time endpoint is not in the allowed endpoint set",
                )
        if not self._scanners:
            raise PrivacyDenied(
                PRIVACY_SCANNER_UNAVAILABLE,
                "scanners unavailable at send time; failing closed",
            )
        final = [dict(m) for m in final_messages]
        try:
            self._assert_clean(
                [
                    {
                        "role": str(m.get("role", "")),
                        "content": str(m.get("content", "")),
                    }
                    for m in final
                ]
            )
        except PrivacyDenied:
            raise
        except Exception as exc:
            raise PrivacyDenied(
                PRIVACY_SCANNER_UNAVAILABLE,
                f"send-time scanner failure ({type(exc).__name__})",
            ) from exc
        expected = compute_payload_digest(authorized.provider, final)
        if expected != authorized.digest:
            raise PrivacyDenied(
                CLOUD_PAYLOAD_CHANGED,
                "final payload differs from the authorized payload",
            )
        return tuple(final)

    # -- provider-SDK wire verification ---------------------------------
    @staticmethod
    def extract_semantic_messages(wire: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract (role, content) pairs from a provider wire payload.

        Covers the shapes our engines/SDKs emit: OpenAI-style
        ``{"messages": [...]}`` (string or content-part lists), Anthropic
        ``{"messages": [...]}``, and Google ``{"contents": [{"parts":
        [{"text": ...}]}]}``. Unknown shapes raise ``CLOUD_PAYLOAD_CHANGED``
        instead of being silently accepted.
        """
        if "messages" in wire and isinstance(wire["messages"], list):
            raw = wire["messages"]
        elif "contents" in wire and isinstance(wire["contents"], list):
            raw = wire["contents"]
        else:
            raise PrivacyDenied(
                CLOUD_PAYLOAD_CHANGED, "unrecognized wire payload shape"
            )
        out: List[Dict[str, str]] = []
        for m in raw:
            if not isinstance(m, dict):
                raise PrivacyDenied(
                    CLOUD_PAYLOAD_CHANGED, "unrecognized wire message shape"
                )
            role = str(m.get("role", "user"))
            if role == "model":
                role = "assistant"
            content = m.get("content", m.get("parts", ""))
            if isinstance(content, list):
                texts = []
                for part in content:
                    if isinstance(part, dict):
                        if "text" in part:
                            texts.append(str(part["text"]))
                        elif part.get("type") in ("text", "input_text"):
                            texts.append(str(part.get("text", "")))
                content = "".join(texts)
            out.append({"role": role, "content": str(content)})
        return out

    def verify_wire_payload(
        self,
        authorized: AuthorizedPayload,
        wire: Dict[str, Any],
        *,
        endpoint: Optional[str] = None,
    ) -> Tuple[Dict[str, str], ...]:
        """Verify a provider-SDK wire payload against the authorization.

        Proves the bytes the SDK is about to send carry exactly the
        authorized semantic content (role/content pairs), bound to the
        authorized endpoint. SDK envelope differences (field names,
        generation configs) are tolerated; content drift is not.
        """
        semantic = self.extract_semantic_messages(wire)
        return tuple(
            dict(m)
            for m in self.verify_for_send(
                authorized, semantic, endpoint=endpoint
            )
        )

    # -- audit -----------------------------------------------------------
    @staticmethod
    def audit_record(
        authorized: AuthorizedPayload,
        *,
        decision: str = "ALLOW",
        code: Optional[str] = None,
        usage: Optional[Dict[str, int]] = None,
        cost_usd: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Audit entry with digests only — never raw prompts."""
        return {
            "dispatch_id": authorized.dispatch_id,
            "engine": authorized.provider.engine,
            "provider": authorized.provider.provider,
            "model": authorized.provider.model,
            "decision": decision,
            "code": code,
            "digest": authorized.digest,
            "message_count": len(authorized.redacted_messages),
            "usage": dict(usage or {}),
            "cost_usd": cost_usd,
        }

    # -- internals --------------------------------------------------------
    def _redact_messages(
        self, messages: Sequence[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        redacted: List[Dict[str, str]] = []
        for m in messages:
            role = str(m.get("role", "user"))
            content = str(m.get("content", ""))
            out = content
            for scanner in self._scanners:
                scan = getattr(scanner, "scan", None)
                redact = getattr(scanner, "redact", None)
                if not callable(scan) or not callable(redact):
                    raise PrivacyDenied(
                        PRIVACY_SCANNER_UNAVAILABLE,
                        "scanner missing scan/redact interface",
                    )
                result = scan(out)
                if getattr(result, "findings", None):
                    out = redact(out)
            redacted.append({"role": role, "content": out})
        return redacted

    def _assert_clean(self, messages: Sequence[Dict[str, Any]]) -> None:
        for m in messages:
            content = str(m.get("content", ""))
            for scanner in self._scanners:
                result = scanner.scan(content)
                if getattr(result, "findings", None):
                    raise PrivacyDenied(
                        CLOUD_PROVIDER_NOT_ALLOWED,
                        "sensitive content remains after redaction; "
                        "dispatch denied",
                    )


__all__ = [
    "BUDGET_EXCEEDED",
    "ENDPOINT_NOT_ALLOWED",
    "GRANT_EXPIRED",
    "NONCE_REPLAY",
    "AuthorizedPayload",
    "BudgetReservation",
    "CLOUD_PAYLOAD_CHANGED",
    "CLOUD_PROVIDER_NOT_ALLOWED",
    "CloudDispatchAuthorizer",
    "CloudDispatchRequest",
    "DispatchIdentity",
    "ExplicitGrant",
    "NON_RETRYABLE_CODES",
    "PRIVACY_CLASSIFICATION_REQUIRED",
    "PRIVACY_ROUTE_UNAVAILABLE",
    "PRIVACY_SCANNER_UNAVAILABLE",
    "PrivacyClassification",
    "PrivacyDenied",
    "ProviderIdentity",
    "SESSION_MISMATCH",
    "compute_payload_digest",
]
