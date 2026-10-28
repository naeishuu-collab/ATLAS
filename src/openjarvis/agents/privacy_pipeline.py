"""Host-owned privacy pipeline: minimize -> redact -> authorize -> fake.

Pure functions over plain data (no tools, no network, no logging of
secrets). Regexes mask known shapes; they never certify completeness —
unredactable values (credential-bearing URLs) refuse transmission
instead. The only delivery target is :class:`FakeProviderSink`.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from openjarvis.agents.host_routing import (
    HostEgressPolicy,
    ModelCardRegistry,
    authorize_egress,
)

PAYLOAD_OVERSIZED = "PAYLOAD_OVERSIZED"
UNSUPPORTED_TYPE = "UNSUPPORTED_TYPE"
CREDENTIAL_URL_REJECTED = "CREDENTIAL_URL_REJECTED"
INVALID_ALLOWLIST = "INVALID_ALLOWLIST"

_REDACTED = "[REDACTED]"

_SENSITIVE_KEYS = frozenset({
    "authorization", "api_key", "apikey", "api-key", "password", "passwd",
    "secret", "secrets", "token", "access_token", "refresh_token",
    "client_secret", "private_key", "session_token",
})

_BEARER_RE = re.compile(r"Bearer\s+([A-Za-z0-9\-._~+/=]+)")
# Best-effort assignment shapes: api_key=..., "password": "...", etc.
# Never a completeness claim: allowlists and refusal do the real work.
_SECRET_ASSIGN_RE = re.compile(
    r"([\"']?(?:api[_-]?key|password|passwd|secret|token)[\"']?"
    r"\s*[:=]\s*[\"']?)([^\"'\s,}]+)")
_URL_USERINFO_RE = re.compile(r"https?://[^/\s]*:[^/\s]*@")


class PipelineError(ValueError):
    """Pipeline refusal with a machine-readable code."""

    def __init__(self, code: str, reason: str = "") -> None:
        super().__init__(f"{code}: {reason}" if reason else code)
        self.code = code
        self.reason = reason


def credential_url_rejected(url: Any) -> bool:
    """True when a string carries userinfo in an http(s) URL."""
    return isinstance(url, str) and _URL_USERINFO_RE.search(url) is not None


def _check_scalar(value: Any) -> None:
    if value is None or isinstance(value, (bool, int, float, str)):
        return
    raise PipelineError(UNSUPPORTED_TYPE,
                        f"unsupported value {type(value).__name__}")


def minimize_context(raw: Dict[str, Any], *, allow: tuple,
                     purpose: str, max_items: int,
                     max_bytes: int) -> Tuple[Dict[str, Any], List[str]]:
    """Project ``raw`` onto allowlisted dotted paths.

    Only listed paths survive (unknown fields, raw observations, and
    secret-bearing metadata drop unless explicitly listed); output keys
    are sorted for determinism; the input is never mutated. Oversize or
    unsupported values raise instead of truncating silently.
    """
    if not isinstance(raw, dict):
        raise PipelineError(UNSUPPORTED_TYPE, "context must be an object")
    if not isinstance(purpose, str) or not purpose.strip():
        raise PipelineError("MINIMIZER_REQUIRED", "purpose is required")
    paths: Dict[str, tuple] = {}
    for entry in allow:
        parts = tuple(str(entry).split("."))
        paths.setdefault(parts[0], []).append(parts[1:])
    out: Dict[str, Any] = {}
    dropped: List[str] = []
    for key in sorted(raw):
        subs = paths.get(key, [])
        if not subs:
            dropped.append(key)
            continue
        value = raw[key]
        if any(s == () for s in subs):
            _check_scalar(value) if not isinstance(value, (list, dict)) \
                else _check_collection(value)
            out[key] = copy.deepcopy(value)
        elif isinstance(value, dict):
            nested, _ = minimize_context(
                value, allow=tuple(".".join(s) for s in subs),
                purpose=purpose, max_items=max_items, max_bytes=max_bytes)
            if nested:
                out[key] = nested
            else:
                dropped.append(key)
        else:
            dropped.append(key)
    if len(out) > max_items:
        raise PipelineError("MINIMIZER_REQUIRED", "too many items")
    blob = json.dumps(out, sort_keys=True, default=str)
    if len(blob.encode("utf-8")) > max_bytes:
        raise PipelineError(PAYLOAD_OVERSIZED, f"{len(blob)} bytes")
    return out, dropped


def _check_collection(value: Any) -> None:
    if isinstance(value, dict):
        for item in value.values():
            _check_scalar(item) if not isinstance(item, (list, dict)) \
                else _check_collection(item)
    elif isinstance(value, list):
        for item in value:
            _check_scalar(item) if not isinstance(item, (list, dict)) \
                else _check_collection(item)
    else:
        _check_scalar(value)


def redact_credentials(obj: Any) -> Tuple[Any, int]:
    """Mask known credential shapes in a deep copy.

    Sensitive key names mask whole values; bearer tokens mask in free
    text; credential-bearing URLs raise (the destination cannot be made
    safe by rewriting). Returns (sanitized, redaction_count).
    """
    count = 0

    def walk(node: Any) -> Any:
        nonlocal count
        if isinstance(node, dict):
            clean: Dict[str, Any] = {}
            for key, value in node.items():
                if (isinstance(key, str)
                        and key.lower() in _SENSITIVE_KEYS):
                    clean[key] = _REDACTED
                    count += 1
                else:
                    clean[key] = walk(value)
            return clean
        if isinstance(node, list):
            return [walk(item) for item in node]
        if isinstance(node, str):
            if credential_url_rejected(node):
                raise PipelineError(CREDENTIAL_URL_REJECTED, "userinfo URL")
            masked, n1 = _BEARER_RE.subn(f"Bearer {_REDACTED}", node)
            masked, n2 = _SECRET_ASSIGN_RE.subn(rf"\1{_REDACTED}", masked)
            count += n1 + n2
            return masked
        return node

    return walk(copy.deepcopy(obj)), count


@dataclass(frozen=True)
class MinimizerEvidence:
    """Whether host-verified minimization happened before egress."""

    verified: bool = True

@dataclass(frozen=True)
class SanitizedPayload:
    payload: Dict[str, Any]
    dropped: List[str] = field(default_factory=list)
    redactions: int = 0
    decision: Any = None


_WIRE_FIELDS = frozenset({"model", "messages", "stream", "options",
                          "tools"})
_KNOWN_WIRE_ENGINES = frozenset({"ollama"})


def seal_wire_envelope(engine_id: str, envelope: Dict[str, Any],
                       decision: Any) -> AuthorizedPayload:
    """Seal a complete wire envelope for one engine.

    Only the documented host-authorized fields seal; provider-specific
    extras and unknown engines refuse (the adapter owner's schema owns
    anything beyond this set). Adapter-mechanical fields added later by
    the real transport (e.g. think/keep_alive) are outside the seal and
    must be subset-checked at conformance time, never assumed.
    """
    if engine_id not in _KNOWN_WIRE_ENGINES:
        raise PipelineError("MODEL_BINDING_UNVERIFIED",
                            f"unknown wire schema {engine_id!r}")
    if not isinstance(envelope, dict):
        raise PipelineError(UNSUPPORTED_TYPE, "envelope must be an object")
    unknown = set(envelope) - _WIRE_FIELDS
    if unknown:
        raise PipelineError("UNKNOWN_FIELD", f"refused {sorted(unknown)}")
    if not isinstance(envelope.get("stream", False), bool):
        raise PipelineError(UNSUPPORTED_TYPE, "stream must be boolean")
    if "options" in envelope and not isinstance(envelope["options"], dict):
        raise PipelineError(UNSUPPORTED_TYPE, "options must be an object")
    if "tools" in envelope and not isinstance(envelope["tools"], list):
        raise PipelineError(UNSUPPORTED_TYPE, "tools must be a list")
    return seal_authorized_envelope(envelope, decision)


def fingerprint_payload(payload: Dict[str, Any]) -> str:
    """Canonical SHA-256 over the exact bytes that will be sent."""
    import hashlib

    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuthorizedPayload:
    """Immutable binding of authorized bytes to their egress decision."""

    fingerprint: str
    decision_code: str
    model: str


def seal_authorized_envelope(payload: Dict[str, Any],
                             decision: Any) -> AuthorizedPayload:
    """Seal sanitized bytes after egress approval. Only allowed
    decisions seal; anything else raises instead of sealing."""
    if decision is None or not getattr(decision, "allowed", False):
        raise PipelineError("EGRESS_DENIED", "cannot seal a refusal")
    return AuthorizedPayload(
        fingerprint=fingerprint_payload(payload),
        decision_code=str(getattr(decision, "code", "")),
        model=str(payload.get("model", "")),
    )


def verify_authorized_envelope(sealed: AuthorizedPayload,
                               payload: Dict[str, Any]) -> None:
    """Prove the bytes about to be sent equal the authorized bytes."""
    if fingerprint_payload(payload) != sealed.fingerprint:
        raise PipelineError("PAYLOAD_TAMPERED",
                            "bytes differ from authorized payload")


@dataclass
class FakeProviderSink:
    """Test-only delivery target. Records sanitized payloads only."""

    received: List[Dict[str, Any]] = field(default_factory=list)

    def deliver(self, payload: Dict[str, Any], decision: Any) -> None:
        self.received.append({"payload": payload, "code": decision.code})


_ADAPTABLE_FIELDS = frozenset(
    {"role", "content", "name", "tool_calls", "tool_call_id"})
_KNOWN_ROLES = frozenset({"system", "user", "assistant", "tool"})


def _role_value(role: Any) -> str:
    value = getattr(role, "value", role)
    if not isinstance(value, str) or value not in _KNOWN_ROLES:
        raise PipelineError(UNSUPPORTED_TYPE,
                            f"unknown role {value!r}")
    return value


def _capped_text(value: Any, max_chars: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise PipelineError(UNSUPPORTED_TYPE,
                            f"unsupported text {type(value).__name__}")
    return value[:max_chars]


def adapt_provider_messages(messages: Any, *,
                            allow_fields: tuple = (
                                "role", "content", "tool_calls"),
                            max_messages: int = 64,
                            max_chars: int = 8000,
                            max_total_bytes: int = 65536,
                            allow_images: bool = False
                            ) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Convert ``Message`` objects to the crossing wire shape.

    Mirrors the real boundary (``messages_to_dicts``): role/content,
    tool calls, and images cross; ``metadata`` never does. Images drop
    unless explicitly allowed; unknown roles, non-text content, and
    dangerous allowlists raise. Per-message text truncates at an
    explicit host bound; an oversized total refuses instead.
    """
    unknown = set(allow_fields) - _ADAPTABLE_FIELDS - {"images", "metadata"}
    if unknown or "metadata" in allow_fields:
        raise PipelineError(INVALID_ALLOWLIST,
                            f"refused fields {sorted(unknown)}")
    if "images" in allow_fields and not allow_images:
        raise PipelineError(INVALID_ALLOWLIST, "images need allow_images")
    if not isinstance(messages, (list, tuple)):
        raise PipelineError(UNSUPPORTED_TYPE, "messages must be a sequence")
    if len(messages) > max_messages:
        raise PipelineError("MINIMIZER_REQUIRED", "too many messages")
    adapted: List[Dict[str, Any]] = []
    dropped: List[str] = []
    for idx, msg in enumerate(messages):
        role = _role_value(getattr(msg, "role", None))
        item: Dict[str, Any] = {}
        if "role" in allow_fields:
            item["role"] = role
        if "content" in allow_fields:
            item["content"] = _capped_text(
                getattr(msg, "content", ""), max_chars)
        if "name" in allow_fields and getattr(msg, "name", None):
            item["name"] = _capped_text(msg.name, max_chars)
        calls = getattr(msg, "tool_calls", None)
        if "tool_calls" in allow_fields and calls:
            item["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {
                     "name": tc.name,
                     "arguments": _capped_text(tc.arguments, max_chars)}}
                for tc in calls
            ]
        if "tool_call_id" in allow_fields and getattr(
                msg, "tool_call_id", None):
            item["tool_call_id"] = msg.tool_call_id
        seen_dropped_image = False
        for pos, image in enumerate(getattr(msg, "images", None) or []):
            if allow_images and isinstance(image, str):
                item.setdefault("images", []).append(image)
            elif not seen_dropped_image:
                dropped.append(f"images[{idx}]")
                seen_dropped_image = True
        adapted.append(item)
    blob = json.dumps(adapted, sort_keys=True, default=str)
    if len(blob.encode("utf-8")) > max_total_bytes:
        raise PipelineError(PAYLOAD_OVERSIZED, f"{len(blob)} bytes")
    return adapted, dropped


def build_provider_envelope(model: str,
                            messages: List[Dict[str, Any]]
                            ) -> Dict[str, Any]:
    """Build the host-owned provider envelope (model + messages only)."""
    if not isinstance(model, str) or not model.strip():
        raise PipelineError(UNSUPPORTED_TYPE, "model must be nonempty")
    if not isinstance(messages, list):
        raise PipelineError(UNSUPPORTED_TYPE, "messages must be a list")
    return {"model": model, "messages": messages}


def deliver_to_fake(envelope: Dict[str, Any], *,
                    registry: ModelCardRegistry, policy: HostEgressPolicy,
                    privacy: Any, provider: str, engine: str, model: str,
                    allow: tuple, purpose: str, sink: FakeProviderSink,
                    evidence: MinimizerEvidence = MinimizerEvidence(),
                    max_items: int = 64,
                    max_bytes: int = 65536) -> SanitizedPayload:
    """Minimize an adapted envelope -> redact -> authorize -> fake-deliver.

    Any refusal raises before the sink sees anything. Redaction success
    alone never authorizes: the egress gate decides.
    """
    minimized, dropped = minimize_context(
        envelope, allow=allow, purpose=purpose,
        max_items=max_items, max_bytes=max_bytes)
    clean, redactions = redact_credentials(minimized)
    decision = authorize_egress(
        registry=registry, policy=policy, privacy=privacy,
        provider=provider, engine=engine, model=model,
        has_minimizer=bool(evidence.verified),
        contains_credentials=False, available=True)
    if not decision.allowed:
        raise PipelineError(decision.code, decision.reason)
    sink.deliver(clean, decision)
    return SanitizedPayload(payload=clean, dropped=dropped,
                            redactions=redactions, decision=decision)


def sanitize_for_egress(raw: Dict[str, Any], *, registry: ModelCardRegistry,
                        policy: HostEgressPolicy, privacy: Any,
                        provider: str, engine: str, model: str,
                        allow: tuple, purpose: str, sink: FakeProviderSink,
                        evidence: MinimizerEvidence = MinimizerEvidence(),
                        max_items: int = 64,
                        max_bytes: int = 65536) -> SanitizedPayload:
    """Minimize -> redact -> authorize -> fake-deliver, in that order.

    Any refusal raises :class:`PipelineError` before the sink sees
    anything; the sink therefore only ever receives sanitized payloads.
    Redaction success alone never authorizes: the egress gate decides.
    """
    minimized, dropped = minimize_context(
        raw, allow=allow, purpose=purpose,
        max_items=max_items, max_bytes=max_bytes)
    clean, redactions = redact_credentials(minimized)
    decision = authorize_egress(
        registry=registry, policy=policy, privacy=privacy,
        provider=provider, engine=engine, model=model,
        has_minimizer=bool(evidence.verified),
        contains_credentials=False, available=True)
    if not decision.allowed:
        raise PipelineError(decision.code, decision.reason)
    sink.deliver(clean, decision)
    return SanitizedPayload(payload=clean, dropped=dropped,
                            redactions=redactions, decision=decision)


__all__ = [
    "CREDENTIAL_URL_REJECTED",
    "INVALID_ALLOWLIST",
    "PAYLOAD_OVERSIZED",
    "UNSUPPORTED_TYPE",
    "FakeProviderSink",
    "MinimizerEvidence",
    "PipelineError",
    "SanitizedPayload",
    "AuthorizedPayload",
    "adapt_provider_messages",
    "build_provider_envelope",
    "credential_url_rejected",
    "deliver_to_fake",
    "fingerprint_payload",
    "minimize_context",
    "redact_credentials",
    "sanitize_for_egress",
    "seal_authorized_envelope",
    "seal_wire_envelope",
    "verify_authorized_envelope",
]
