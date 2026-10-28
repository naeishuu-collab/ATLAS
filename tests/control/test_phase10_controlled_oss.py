"""Phase 10 controlled MCP execution proof with an offline fake transport."""

from __future__ import annotations

from openjarvis.control.oss_adapter import (
    ActionProposal,
    AdapterMode,
    CandidateDispatchError,
    ControlSurface,
    DispatchResult,
    ObservationSnapshot,
    SafeEngineAdapter,
    make_authorized_action,
)
from openjarvis.core.execution import ExecutionState, MutationIntent

KEY = b"phase10-controlled-oss-key"
IDENTITY = {"process_id": 77, "runtime_id": [4, 2], "role": "button"}


class FakeMcpTransport:
    """Untrusted MCP-shaped transport; it has no network implementation."""

    def __init__(self, proposal: ActionProposal, failure=None) -> None:
        self.proposal = proposal
        self.failure = failure
        self.propose_calls = 0
        self.dispatch_calls = 0
        self.close_calls = 0
        self.egress_attempts = 0

    def propose(self, observation):
        self.propose_calls += 1
        return self.proposal

    def dispatch(self, authorized):
        self.dispatch_calls += 1
        if self.failure is not None:
            raise self.failure
        return DispatchResult(True, {"verified_value": "fixture"})

    def close(self) -> None:
        self.close_calls += 1


def browser_snapshot(*, privacy: str = "PUBLIC", observation_id: str = "obs-10"):
    return ObservationSnapshot(
        ControlSurface.BROWSER,
        observation_id,
        ({"target_id": "target-10", "identity": IDENTITY},),
        privacy=privacy,
    )


def browser_proposal(**changes) -> ActionProposal:
    values = {
        "action_id": "action-10",
        "observation_id": "obs-10",
        "target_id": "target-10",
        "target_identity": IDENTITY,
        "action": "browser_click",
        "arguments": {"button": "primary"},
    }
    values.update(changes)
    return ActionProposal(**values)


def authorized(
    proposal: ActionProposal, *, session_id: str = "session-10", nonce="nonce-10"
):
    return make_authorized_action(
        proposal,
        MutationIntent("exec-10", "step-10", "intent-10"),
        session_id=session_id,
        nonce=nonce,
        key=KEY,
    )


def test_mcp_catalog_is_proposal_only_until_host_authorizes_dispatch():
    candidate = FakeMcpTransport(browser_proposal())
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.BROWSER,
        mode=AdapterMode.PROPOSAL_ONLY,
        session_id="session-10",
        seal_key=KEY,
    )

    proposed = adapter.propose(browser_snapshot())
    assert proposed.state is ExecutionState.EXECUTED
    blocked = adapter.execute(
        proposed.proposal,
        browser_snapshot(),
        authorized=authorized(proposed.proposal),
        verify=lambda *_: True,
    )
    assert blocked.failure == "OSS_EXECUTION_DISABLED"
    assert candidate.dispatch_calls == 0
    candidate.close()
    assert candidate.close_calls == 1


def test_private_observation_denies_before_candidate_transport():
    candidate = FakeMcpTransport(browser_proposal())
    adapter = SafeEngineAdapter(
        candidate, surface=ControlSurface.BROWSER, mode=AdapterMode.PROPOSAL_ONLY
    )

    result = adapter.propose(browser_snapshot(privacy="PRIVATE"))
    assert result.failure == "PRIVACY_DENIED"
    assert candidate.propose_calls == 0
    assert candidate.egress_attempts == 0


def test_cross_session_and_authorized_argument_mismatch_stop_dispatch():
    candidate = FakeMcpTransport(browser_proposal())
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.BROWSER,
        mode=AdapterMode.ENFORCE,
        session_id="session-10",
        seal_key=KEY,
    )
    action = browser_proposal()

    wrong_session = adapter.execute(
        action,
        browser_snapshot(),
        authorized=authorized(action, session_id="wrong-session"),
        verify=lambda *_: True,
    )
    assert wrong_session.failure == "SESSION_MISMATCH"

    wrong_arguments = browser_proposal(arguments={"button": "secondary"})
    argument_mismatch = adapter.execute(
        action,
        browser_snapshot(),
        authorized=authorized(wrong_arguments, nonce="nonce-11"),
        verify=lambda *_: True,
    )
    assert argument_mismatch.failure == "AUTHORIZATION_MISMATCH"
    assert candidate.dispatch_calls == 0


def test_unknown_outcome_quarantines_nonce_and_does_not_retry():
    candidate = FakeMcpTransport(
        browser_proposal(), failure=CandidateDispatchError("timeout", dispatched=None)
    )
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.BROWSER,
        mode=AdapterMode.ENFORCE,
        session_id="session-10",
        seal_key=KEY,
    )
    action = browser_proposal()
    auth = authorized(action)

    result = adapter.execute(
        action, browser_snapshot(), authorized=auth, verify=lambda *_: True
    )
    assert result.state is ExecutionState.UNKNOWN_OUTCOME
    assert adapter.journal[action.action_id] == "UNKNOWN"
    assert (
        adapter.execute(
            action, browser_snapshot(), authorized=auth, verify=lambda *_: True
        ).failure
        == "NONCE_REPLAY"
    )
    assert candidate.dispatch_calls == 1


def test_untrusted_mcp_code_tool_is_denied_before_any_dispatch():
    candidate = FakeMcpTransport(browser_proposal(action="browser_run_code_unsafe"))
    adapter = SafeEngineAdapter(
        candidate, surface=ControlSurface.BROWSER, mode=AdapterMode.PROPOSAL_ONLY
    )

    result = adapter.propose(browser_snapshot())
    assert result.failure == "ACTION_NOT_ALLOWLISTED"
    assert candidate.dispatch_calls == 0
    assert candidate.egress_attempts == 0
