"""Dispatch integrity tests — fake authorizations only, no network."""

from __future__ import annotations

import pytest

from openjarvis.security.cloud_dispatch import (
    AuthorizedPayload,
    ExplicitGrant,
    PrivacyDenied,
    ProviderIdentity,
)
from openjarvis.security.dispatch_ledger import (
    STATE_DISPATCHED,
    STATE_EXECUTED,
    STATE_UNKNOWN_OUTCOME,
    CloudDispatchLedger,
    ReconcileEvidence,
)


def _auth(dispatch_id: str = "cdisp_aaa", model: str = "m1") -> AuthorizedPayload:
    return AuthorizedPayload(
        dispatch_id=dispatch_id,
        provider=ProviderIdentity(engine="fake-cloud", provider="groq", model=model),
        redacted_messages=({"role": "user", "content": "hi"},),
        digest="digest-1",
        grant=ExplicitGrant(agent_id="a", capability="llm:cloud"),
        budget_id="b1",
    )


class TestLifecycle:
    def test_begin_dispatch_finish(self) -> None:
        ledger = CloudDispatchLedger()
        entry = ledger.begin(_auth())
        assert entry.state == "NOT_STARTED"
        ledger.mark_dispatched(entry)
        assert entry.state == STATE_DISPATCHED
        ledger.check_send(entry, _auth())
        ledger.finish(entry, STATE_EXECUTED)
        assert entry.state == STATE_EXECUTED

    def test_begin_twice_denied_no_blind_retry(self) -> None:
        ledger = CloudDispatchLedger()
        ledger.begin(_auth())
        with pytest.raises(PrivacyDenied):
            ledger.begin(_auth())
        with pytest.raises(PrivacyDenied):
            ledger.request_retry("cdisp_aaa")

    def test_finish_requires_dispatched(self) -> None:
        ledger = CloudDispatchLedger()
        entry = ledger.begin(_auth())
        with pytest.raises(PrivacyDenied):
            ledger.finish(entry, STATE_EXECUTED)

    def test_terminal_once(self) -> None:
        ledger = CloudDispatchLedger()
        entry = ledger.begin(_auth())
        ledger.mark_dispatched(entry)
        ledger.finish(entry, STATE_EXECUTED)
        with pytest.raises(PrivacyDenied):
            ledger.finish(entry, STATE_EXECUTED)


class TestUnknownOutcomeQuarantine:
    def test_unknown_sticky_no_auto_retry_or_switch(self) -> None:
        ledger = CloudDispatchLedger()
        entry = ledger.begin(_auth())
        ledger.mark_dispatched(entry)
        ledger.mark_unknown(entry)
        assert entry.state == STATE_UNKNOWN_OUTCOME
        with pytest.raises(PrivacyDenied):
            ledger.request_retry("cdisp_aaa")
        # Provider switch on the same id is not a thing: new auth, new id.
        with pytest.raises(PrivacyDenied):
            ledger.begin(_auth())  # same id reuse denied

    def test_reconcile_needs_evidence(self) -> None:
        ledger = CloudDispatchLedger()
        entry = ledger.begin(_auth())
        ledger.mark_dispatched(entry)
        ledger.mark_unknown(entry)
        with pytest.raises(PrivacyDenied):
            ledger.reconcile_unknown(
                "cdisp_aaa", ReconcileEvidence(worker_stopped=False, observation="x")
            )
        with pytest.raises(PrivacyDenied):
            ledger.reconcile_unknown(
                "cdisp_aaa", ReconcileEvidence(worker_stopped=True, observation="")
            )
        found = ledger.reconcile_unknown(
            "cdisp_aaa",
            ReconcileEvidence(worker_stopped=True, observation="provider timeout"),
        )
        assert found is entry  # review only — never re-sends


class TestReauthorization:
    def test_provider_change_requires_reauth(self) -> None:
        ledger = CloudDispatchLedger()
        entry = ledger.begin(_auth())
        ledger.mark_dispatched(entry)
        with pytest.raises(PrivacyDenied):
            ledger.check_send(entry, _auth(model="other-model"))

    def test_streaming_uses_same_ledger(self) -> None:
        ledger = CloudDispatchLedger()
        entry = ledger.begin(_auth(), streaming=True)
        ledger.mark_dispatched(entry)
        ledger.check_send(entry, _auth())
        ledger.finish(entry, STATE_EXECUTED)
        record = ledger.audit("cdisp_aaa")
        assert record["streaming"] is True
        assert record["state"] == STATE_EXECUTED
        assert "hi" not in str(record)
