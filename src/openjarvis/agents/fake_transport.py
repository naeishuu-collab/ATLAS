"""Fake Transport with provider-equivalent contracts (zero network).

Mirrors the real boundary: envelope validation, option allowlisting,
timeout/cancel semantics, retry-without-escalation, and authorized-only
fallback. Scripted responses only; failures are injected per call, never
read from any connection. Responses are untrusted data (never verified).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Tuple

EGRESS_DENIED = "EGRESS_DENIED"
UNKNOWN_FIELD = "UNKNOWN_FIELD"
TRANSPORT_TIMEOUT = "TRANSPORT_TIMEOUT"
TRANSPORT_UNAVAILABLE = "TRANSPORT_UNAVAILABLE"
TRANSPORT_CANCELLED = "TRANSPORT_CANCELLED"
STREAM_INTERRUPTED = "STREAM_INTERRUPTED"
RETRY_EXHAUSTED = "RETRY_EXHAUSTED"
FALLBACK_MISMATCH = "FALLBACK_MISMATCH"

_RETRYABLE = frozenset({TRANSPORT_TIMEOUT, TRANSPORT_UNAVAILABLE})
_ENVELOPE_FIELDS = frozenset({"model", "messages", "stream", "options",
                               "tools"})
_ALLOWED_OPTIONS = frozenset({"temperature", "max_tokens", "stream"})


class TransportError(ValueError):
    """Fake-transport refusal with a machine-readable code."""

    def __init__(self, code: str, reason: str = "") -> None:
        super().__init__(f"{code}: {reason}" if reason else code)
        self.code = code
        self.reason = reason


@dataclass
class FakeTransport:
    """Scripted, network-free stand-in for a provider transport."""

    calls: List[Dict[str, Any]] = field(default_factory=list)
    attempts: int = 0

    def _check(self, payload: Dict[str, Any], decision: Any,
               options: Dict[str, Any] | None) -> None:
        if decision is None or not getattr(decision, "allowed", False):
            raise TransportError(EGRESS_DENIED, "no egress approval")
        if not isinstance(payload, dict):
            raise TransportError(UNKNOWN_FIELD, "envelope must be an object")
        unknown = set(payload) - _ENVELOPE_FIELDS
        if unknown:
            raise TransportError(UNKNOWN_FIELD, f"refused {sorted(unknown)}")
        if ("stream" in payload
                and not isinstance(payload["stream"], bool)):
            raise TransportError(UNKNOWN_FIELD, "stream must be boolean")
        if ("options" in payload
                and not isinstance(payload["options"], dict)):
            raise TransportError(UNKNOWN_FIELD, "options must be an object")
        if "tools" in payload and not isinstance(payload["tools"], list):
            raise TransportError(UNKNOWN_FIELD, "tools must be a list")
        unknown_opts = set(options or {}) - _ALLOWED_OPTIONS
        if unknown_opts:
            raise TransportError(UNKNOWN_FIELD,
                                 f"refused options {sorted(unknown_opts)}")

    def _verify_seal(self, payload: Dict[str, Any], authorized: Any) -> None:
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        if digest != authorized.fingerprint:
            raise TransportError("PAYLOAD_TAMPERED",
                                 "bytes differ from seal")

    def _response(self, payload: Dict[str, Any], content: str,
                  tool_calls: Any, usage: Dict[str, int] | None) -> Dict:
        response: Dict[str, Any] = {
            "content": content,
            "usage": usage or {"prompt_tokens": 10, "completion_tokens": 5,
                               "total_tokens": 15},
            "model": payload.get("model", ""),
            "finish_reason": "tool_calls" if tool_calls else "stop",
        }
        if tool_calls:
            response["tool_calls"] = list(tool_calls)
        return response

    def complete(self, payload: Dict[str, Any], decision: Any, *,
                 options: Dict[str, Any] | None = None,
                 timeout_s: float = 30.0, latency_s: float = 0.0,
                 fail: str = "none", cancelled: bool = False,
                 authorized: Any = None,
                 content: str = "",
                 tool_calls: Any = None,
                 usage: Dict[str, int] | None = None) -> Dict[str, Any]:
        """One scripted completion. Records only successful dispatches.

        When ``authorized`` (an AuthorizedPayload seal) is supplied, the
        exact bytes are fingerprint-checked against the seal before
        anything is recorded; tampering refuses with PAYLOAD_TAMPERED.
        """
        if cancelled:
            raise TransportError(TRANSPORT_CANCELLED, "cancelled")
        self._check(payload, decision, options)
        if authorized is not None:
            self._verify_seal(payload, authorized)
        if latency_s > timeout_s:
            raise TransportError(TRANSPORT_TIMEOUT,
                                 f"{latency_s}s > {timeout_s}s")
        if fail == "timeout":
            raise TransportError(TRANSPORT_TIMEOUT, "injected")
        if fail == "unavailable":
            raise TransportError(TRANSPORT_UNAVAILABLE, "injected")
        self.calls.append({"payload": payload,
                           "options": dict(options or {})})
        return self._response(payload, content, tool_calls, usage)

    def stream(self, payload: Dict[str, Any], decision: Any, *,
               chunks: Tuple[str, ...] = (),
               interrupt_at: int | None = None,
               cancelled: bool = False,
               authorized: Any = None,
               options: Dict[str, Any] | None = None,
               timeout_s: float = 30.0,
               latency_s: float = 0.0,
               fail: str = "none") -> Iterator[str]:
        """Scripted chunk stream. Interruption raises; partial text is
        never presented as a complete response. A seal, when supplied,
        is verified before the first chunk (streaming starts authorized
        or not at all)."""
        if cancelled:
            raise TransportError(TRANSPORT_CANCELLED, "cancelled")
        self._check(payload, decision, options)
        if authorized is not None:
            self._verify_seal(payload, authorized)
        if latency_s > timeout_s:
            raise TransportError(TRANSPORT_TIMEOUT, "setup exceeded")
        if fail == "unavailable":
            raise TransportError(TRANSPORT_UNAVAILABLE, "injected")
        self.calls.append({"payload": payload, "stream": True})
        for idx, chunk in enumerate(chunks):
            if interrupt_at is not None and idx >= interrupt_at:
                raise TransportError(STREAM_INTERRUPTED,
                                     f"interrupted at chunk {idx}")
            yield chunk

    def complete_with_retry(self, payload: Dict[str, Any], decision: Any, *,
                            retries: int = 0,
                            fail_modes: Tuple[str, ...] = (),
                            **kwargs: Any) -> Dict[str, Any]:
        """Retry transient failures only. Denials and validation errors
        propagate on the first attempt and are never retried. When every
        permitted attempt fails transiently, RETRY_EXHAUSTED replaces
        the last error (unless no retry was permitted, which re-raises
        the original). ``attempts`` counts this call's tries."""
        self.attempts = 0
        last: TransportError | None = None
        for attempt in range(1 + retries):
            self.attempts += 1
            mode = (fail_modes[attempt]
                    if attempt < len(fail_modes) else "none")
            try:
                return self.complete(payload, decision, fail=mode, **kwargs)
            except TransportError as exc:
                if exc.code not in _RETRYABLE:
                    raise
                last = exc
        if retries > 0 and last is not None:
            raise TransportError(RETRY_EXHAUSTED,
                                 f"after {self.attempts} attempts")
        assert last is not None
        raise last

    def complete_with_fallback(self, primary: Dict[str, Any],
                               primary_decision: Any,
                               fallback: Dict[str, Any],
                               fallback_decision: Any, *,
                               fail_modes: Tuple[str, ...] = ("unavailable",),
                               primary_authorized: Any = None,
                               fallback_authorized: Any = None,
                               **kwargs: Any) -> Dict[str, Any]:
        """Fall back only on transient primary failure, and only to a
        separately authorized envelope. Anything else propagates. When
        the primary ran sealed, the fallback must carry its own seal."""
        try:
            return self.complete_with_retry(
                primary, primary_decision, retries=0,
                fail_modes=fail_modes, authorized=primary_authorized,
                **kwargs)
        except TransportError as exc:
            if exc.code not in _RETRYABLE:
                raise
        if (fallback_decision is None
                or not getattr(fallback_decision, "allowed", False)):
            raise TransportError(FALLBACK_MISMATCH,
                                 "fallback lacks egress approval")
        if primary_authorized is not None and fallback_authorized is None:
            raise TransportError(FALLBACK_MISMATCH,
                                 "fallback not sealed")
        return self.complete(fallback, fallback_decision,
                             authorized=fallback_authorized, **kwargs)


__all__ = [
    "EGRESS_DENIED",
    "FALLBACK_MISMATCH",
    "RETRY_EXHAUSTED",
    "STREAM_INTERRUPTED",
    "TRANSPORT_CANCELLED",
    "TRANSPORT_TIMEOUT",
    "TRANSPORT_UNAVAILABLE",
    "UNKNOWN_FIELD",
    "FakeTransport",
    "TransportError",
]
