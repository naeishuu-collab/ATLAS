"""Provider egress dispatch contract: authorized payload == dispatched bytes.

Wraps seal_wire_envelope + verify_authorized_envelope + FakeTransport so
that only authorized, sealed payloads reach the fake transport, with
re-authorization on retry/fallback and seal verification at stream start.
"""

from __future__ import annotations

from typing import Any, Dict, Iterator, Tuple

from openjarvis.agents.fake_transport import (
    EGRESS_DENIED,
    FALLBACK_MISMATCH,
    FakeTransport,
    TransportError,
)
from openjarvis.agents.host_routing import (
    EgressDecision,
)
from openjarvis.agents.privacy_pipeline import (
    AuthorizedPayload,
    PipelineError,
    verify_authorized_envelope,
)


class DispatchContract:
    """Host-owned dispatch contract for provider egress.

    No dispatch happens without an authorized, sealed payload. Retry and
    fallback each require their own seal. Streaming verifies the seal
    before the first chunk.
    """

    def __init__(self, transport: FakeTransport) -> None:
        self.transport = transport

    def dispatch(self, payload: Dict[str, Any], decision: EgressDecision,
                 *, authorized: AuthorizedPayload | None = None,
                 **kwargs: Any) -> Dict[str, Any]:
        """Dispatch one sealed payload. Denial/tampering refuses."""
        if authorized is None:
            raise TransportError(EGRESS_DENIED,
                                 "sealed authorization is required")
        if authorized is not None:
            try:
                verify_authorized_envelope(authorized, payload)
            except PipelineError as exc:
                raise TransportError(exc.code, exc.reason) from exc
        if decision is None or not decision.allowed:
            raise TransportError(EGRESS_DENIED, "no egress approval")
        return self.transport.complete(
            payload, decision, authorized=authorized, **kwargs)

    def dispatch_with_retry(self, payload: Dict[str, Any],
                            decision: EgressDecision, *, retries: int = 0,
                            fail_modes: Tuple[str, ...] = (),
                            authorized: AuthorizedPayload | None = None,
                            **kwargs: Any) -> Dict[str, Any]:
        """Retry transient failures with the same seal."""
        if authorized is None:
            raise TransportError(EGRESS_DENIED,
                                 "sealed authorization is required")
        return self.transport.complete_with_retry(
            payload, decision, retries=retries,
            fail_modes=fail_modes, authorized=authorized, **kwargs)

    def dispatch_with_fallback(self, primary: Dict[str, Any],
                               primary_decision: EgressDecision,
                               fallback: Dict[str, Any],
                               fallback_decision: EgressDecision, *,
                               fail_modes: Tuple[str, ...] = ("unavailable",),
                               primary_authorized: AuthorizedPayload | None = None,
                               fallback_authorized: AuthorizedPayload | None = None,
                               **kwargs: Any) -> Dict[str, Any]:
        """Fallback on transient primary failure, only to a separately
        authorized envelope."""
        if primary_authorized is None:
            raise TransportError(EGRESS_DENIED,
                                 "primary seal is required")
        if fallback_authorized is None:
            raise TransportError(FALLBACK_MISMATCH,
                                 "fallback seal is required")
        return self.transport.complete_with_fallback(
            primary, primary_decision, fallback, fallback_decision,
            fail_modes=fail_modes,
            primary_authorized=primary_authorized,
            fallback_authorized=fallback_authorized, **kwargs)

    def stream_with_authorization(self, payload: Dict[str, Any],
                                  decision: EgressDecision, *,
                                  chunks: Tuple[str, ...] = (),
                                  interrupt_at: int | None = None,
                                  authorized: AuthorizedPayload | None = None,
                                  **kwargs: Any) -> Iterator[str]:
        """Stream only after seal verification at start."""
        if authorized is None:
            raise TransportError(EGRESS_DENIED,
                                 "sealed authorization is required")
        if authorized is not None:
            try:
                verify_authorized_envelope(authorized, payload)
            except PipelineError as exc:
                raise TransportError(exc.code, exc.reason) from exc
        if decision is None or not decision.allowed:
            raise TransportError(EGRESS_DENIED, "no egress approval")
        return self.transport.stream(
            payload, decision, chunks=chunks,
            interrupt_at=interrupt_at, authorized=authorized, **kwargs)


__all__ = [
    "DispatchContract",
]
