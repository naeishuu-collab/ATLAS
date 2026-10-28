"""Cloud dispatch ledger — integrity and retry semantics.

Separate from RLM ``RequestLedger`` (which owns exactly-once LLM RPC for
the isolated worker). This ledger owns general cloud-LLM dispatch:
- one ``dispatch_id`` → at most one dispatch (no blind retry);
- ``UNKNOWN_OUTCOME`` is sticky quarantine (no automatic provider
  switch, no same-id retry);
- provider or payload changes require a *new* authorization;
- audit entries carry digests, never raw prompts.

``RequestLedger`` and ``ExecutionJournal`` transitions are untouched.

Thread-safety: all state transitions hold an internal lock so concurrent
duplicate dispatches are denied atomically.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from openjarvis.security.cloud_dispatch import (
    CLOUD_PAYLOAD_CHANGED,
    AuthorizedPayload,
    PrivacyDenied,
)

STATE_NOT_STARTED = "NOT_STARTED"
STATE_DISPATCHED = "DISPATCHED"
STATE_EXECUTED = "EXECUTED"
STATE_FAILED = "FAILED"
STATE_CANCELLED = "CANCELLED"
STATE_UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"

_TERMINAL = frozenset(
    {STATE_EXECUTED, STATE_FAILED, STATE_CANCELLED, STATE_UNKNOWN_OUTCOME}
)

# Machine-readable failure codes for deterministic-vs-unknown classification.
CODE_PROVIDER_TIMEOUT = "PROVIDER_TIMEOUT"
CODE_CONNECTION_FAILURE = "CONNECTION_FAILURE"
CODE_CANCELLED = "CANCELLED"
CODE_PARTIAL_RESPONSE = "PARTIAL_RESPONSE"
CODE_STREAM_INTERRUPTED = "STREAM_INTERRUPTED"


@dataclass
class DispatchEntry:
    dispatch_id: str
    provider_key: Tuple[str, str, str]
    digest: str
    streaming: bool = False
    state: str = STATE_NOT_STARTED
    failure_code: Optional[str] = None
    # Envelope-only resends under the same authorization (e.g. a rejected
    # tools request retried without tools). Bounded to one; any further
    # resend needs a fresh authorization (new dispatch id).
    attempts: int = 0


@dataclass
class ReconcileEvidence:
    """Trusted control-plane evidence for UNKNOWN_OUTCOME review."""

    worker_stopped: bool
    observation: str = ""

    def valid(self) -> bool:
        return self.worker_stopped and bool(self.observation.strip())


class CloudDispatchLedger:
    """Tracks cloud dispatch integrity per sealed authorization."""

    def __init__(self) -> None:
        self._entries: Dict[str, DispatchEntry] = {}
        self._lock = threading.Lock()

    def begin(
        self, authorized: AuthorizedPayload, *, streaming: bool = False
    ) -> DispatchEntry:
        with self._lock:
            existing = self._entries.get(authorized.dispatch_id)
            if existing is not None:
                # Same sealed object presented twice: blind retry is denied.
                # A genuinely new attempt needs a fresh authorization (new id).
                raise PrivacyDenied(
                    CLOUD_PAYLOAD_CHANGED,
                    f"dispatch {authorized.dispatch_id} already begun; "
                    "re-authorize instead of retrying",
                )
            entry = DispatchEntry(
                dispatch_id=authorized.dispatch_id,
                provider_key=authorized.provider.key(),
                digest=authorized.digest,
                streaming=streaming,
            )
            self._entries[authorized.dispatch_id] = entry
            return entry

    def mark_dispatched(self, entry: DispatchEntry) -> None:
        with self._lock:
            if entry.state != STATE_NOT_STARTED:
                raise PrivacyDenied(
                    CLOUD_PAYLOAD_CHANGED,
                    "dispatch is not in NOT_STARTED; refusing re-dispatch",
                )
            entry.state = STATE_DISPATCHED

    def check_send(
        self, entry: DispatchEntry, authorized: AuthorizedPayload
    ) -> None:
        """Binding check at the egress instant (destination + payload)."""
        if entry.state != STATE_DISPATCHED:
            raise PrivacyDenied(
                CLOUD_PAYLOAD_CHANGED,
                "send requires a DISPATCHED entry (TOCTOU guard)",
            )
        if authorized.provider.key() != entry.provider_key:
            raise PrivacyDenied(
                CLOUD_PAYLOAD_CHANGED,
                "provider changed after authorization; re-authorize",
            )
        if authorized.digest != entry.digest:
            raise PrivacyDenied(
                CLOUD_PAYLOAD_CHANGED,
                "payload changed after authorization; re-authorize",
            )

    def finish(
        self, entry: DispatchEntry, state: str, *, code: Optional[str] = None
    ) -> None:
        with self._lock:
            if state not in _TERMINAL:
                raise PrivacyDenied(
                    CLOUD_PAYLOAD_CHANGED, f"invalid terminal state {state!r}"
                )
            if entry.state != STATE_DISPATCHED:
                raise PrivacyDenied(
                    CLOUD_PAYLOAD_CHANGED,
                    "only a DISPATCHED entry can reach a terminal state",
                )
            entry.state = state
            entry.failure_code = code

    def mark_unknown(
        self, entry: DispatchEntry, *, code: str = "UNKNOWN_OUTCOME"
    ) -> None:
        self.finish(entry, STATE_UNKNOWN_OUTCOME, code=code)

    def cancel(self, entry: DispatchEntry) -> None:
        """Cancel a dispatch.

        Pre-send cancellation (never dispatched) is deterministic:
        ``CANCELLED``. Cancellation at/after the send instant cannot prove
        the provider did nothing, so it quarantines as ``UNKNOWN_OUTCOME``.
        """
        with self._lock:
            if entry.state == STATE_NOT_STARTED:
                entry.state = STATE_CANCELLED
                entry.failure_code = CODE_CANCELLED
                return
            if entry.state != STATE_DISPATCHED:
                raise PrivacyDenied(
                    CLOUD_PAYLOAD_CHANGED,
                    "only NOT_STARTED or DISPATCHED entries can be cancelled",
                )
        self.finish(entry, STATE_UNKNOWN_OUTCOME, code=CODE_CANCELLED)

    def note_partial_response(self, entry: DispatchEntry) -> None:
        """A truncated/partial provider response is uncertain by definition."""
        if entry.state != STATE_DISPATCHED:
            raise PrivacyDenied(
                CLOUD_PAYLOAD_CHANGED,
                "partial response requires a DISPATCHED entry",
            )
        self.finish(entry, STATE_UNKNOWN_OUTCOME, code=CODE_PARTIAL_RESPONSE)

    def note_stream_interrupted(self, entry: DispatchEntry) -> None:
        """A broken stream cannot prove what the provider processed."""
        if entry.state != STATE_DISPATCHED:
            raise PrivacyDenied(
                CLOUD_PAYLOAD_CHANGED,
                "stream interruption requires a DISPATCHED entry",
            )
        self.finish(entry, STATE_UNKNOWN_OUTCOME, code=CODE_STREAM_INTERRUPTED)

    def fail_before_send(self, entry: DispatchEntry, *, code: str) -> None:
        """Deterministic pre-send failure (timeout connecting, DNS, refused).

        Distinguished from UNKNOWN_OUTCOME: nothing left the boundary, so
        a *fresh* authorization (new dispatch id) may retry. Same-id retry
        stays denied.
        """
        with self._lock:
            if entry.state != STATE_NOT_STARTED:
                raise PrivacyDenied(
                    CLOUD_PAYLOAD_CHANGED,
                    "pre-send failure requires a NOT_STARTED entry",
                )
            entry.state = STATE_FAILED
            entry.failure_code = code

    def request_retry(self, dispatch_id: str) -> None:
        """Blind retry (same id) is always denied — including UNKNOWN_OUTCOME."""
        entry = self._entries.get(dispatch_id)
        if entry is None:
            raise PrivacyDenied(
                CLOUD_PAYLOAD_CHANGED, "unknown dispatch id; re-authorize"
            )
        raise PrivacyDenied(
            entry.failure_code or CLOUD_PAYLOAD_CHANGED,
            f"dispatch {dispatch_id} is {entry.state}; "
            "automatic retry denied, quarantine holds",
        )

    def reconcile_unknown(
        self, dispatch_id: str, evidence: ReconcileEvidence
    ) -> DispatchEntry:
        """Trusted review of a quarantined dispatch.

        Never re-sends. Returns the quarantined entry for inspection and
        requires a *new* authorization for any follow-up dispatch.
        """
        entry = self._entries.get(dispatch_id)
        if entry is None or entry.state != STATE_UNKNOWN_OUTCOME:
            raise PrivacyDenied(
                CLOUD_PAYLOAD_CHANGED,
                "only UNKNOWN_OUTCOME entries can be reconciled",
            )
        if not evidence.valid():
            raise PrivacyDenied(
                CLOUD_PAYLOAD_CHANGED,
                "reconciliation requires worker-stopped proof + observation",
            )
        return entry

    def audit(self, dispatch_id: str) -> Dict[str, object]:
        entry = self._entries[dispatch_id]
        return {
            "dispatch_id": entry.dispatch_id,
            "provider": list(entry.provider_key),
            "digest": entry.digest,
            "streaming": entry.streaming,
            "state": entry.state,
            "failure_code": entry.failure_code,
        }


__all__ = [
    "CODE_CANCELLED",
    "CODE_CONNECTION_FAILURE",
    "CODE_PARTIAL_RESPONSE",
    "CODE_PROVIDER_TIMEOUT",
    "CODE_STREAM_INTERRUPTED",
    "STATE_CANCELLED",
    "STATE_DISPATCHED",
    "STATE_EXECUTED",
    "STATE_FAILED",
    "STATE_NOT_STARTED",
    "STATE_UNKNOWN_OUTCOME",
    "CloudDispatchLedger",
    "DispatchEntry",
    "ReconcileEvidence",
]
