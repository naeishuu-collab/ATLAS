"""Offline safety proof for Browser/App OSS proposal adapters."""

from __future__ import annotations

from dataclasses import replace

import pytest

from openjarvis.control.oss_adapter import (
    ActionProposal,
    AdapterMode,
    CandidateDispatchError,
    ControlSurface,
    DispatchResult,
    ObservationSnapshot,
    SafeEngineAdapter,
    make_authorized_action,
    mode_from_env,
)
from openjarvis.core.execution import ExecutionState, MutationIntent

KEY = b"phase8-test-seal-key"
IDENTITY = {"process_id": 41, "runtime_id": [1, 2], "role": "button"}


def snapshot(*, privacy="PUBLIC", screenshot=False, targets=None):
    return ObservationSnapshot(
        ControlSurface.WINDOWS_APP,
        "obs-1",
        tuple(targets or ({"target_id": "target-1", "identity": IDENTITY},)),
        privacy=privacy,
        has_screenshot=screenshot,
        process_id=41,
    )


class Candidate:
    def __init__(self, proposal=None, dispatch=None):
        self.proposal = proposal
        self.dispatch_result = dispatch or DispatchResult(True, {"value": "ok"})
        self.propose_calls = 0
        self.dispatch_calls = 0

    def propose(self, observation):
        self.propose_calls += 1
        return self.proposal

    def dispatch(self, authorized):
        self.dispatch_calls += 1
        if isinstance(self.dispatch_result, Exception):
            raise self.dispatch_result
        return self.dispatch_result


def proposal(**changes):
    values = {
        "action_id": "action-1",
        "observation_id": "obs-1",
        "target_id": "target-1",
        "target_identity": IDENTITY,
        "action": "click",
        "arguments": {"button": "primary"},
    }
    values.update(changes)
    return ActionProposal(**values)


def intent():
    return MutationIntent("exec-1", "step-1", "intent-1")


def authorized(action):
    return make_authorized_action(
        action,
        intent(),
        session_id="session-1",
        nonce="nonce-1",
        key=KEY,
    )


def test_default_mode_is_legacy_and_does_not_call_candidate(monkeypatch):
    monkeypatch.delenv("ASTRA_CONTROL_ENGINE", raising=False)
    candidate = Candidate(proposal())
    adapter = SafeEngineAdapter(candidate, surface=ControlSurface.BROWSER)
    result = adapter.propose(
        ObservationSnapshot(
            ControlSurface.BROWSER,
            "obs-1",
            ({"target_id": "target-1", "identity": IDENTITY},),
            privacy="PUBLIC",
        )
    )
    assert result.failure == "LEGACY_ENGINE_ACTIVE"
    assert candidate.propose_calls == 0
    assert mode_from_env() is AdapterMode.LEGACY


def test_observation_and_seal_payloads_are_immutable():
    source_identity = dict(IDENTITY)
    action = proposal(target_identity=source_identity)
    observed = snapshot(
        targets=({"target_id": "target-1", "identity": source_identity},)
    )
    source_identity["role"] = "mutated-source"
    assert action.target_identity["role"] == "button"
    assert observed.targets[0]["identity"]["role"] == "button"
    with pytest.raises(TypeError):
        action.arguments["button"] = "secondary"
    with pytest.raises(TypeError):
        observed.targets[0]["identity"]["role"] = "link"


def test_proposal_only_never_dispatches_and_preserves_exact_target():
    candidate = Candidate(proposal())
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.WINDOWS_APP,
        mode=AdapterMode.PROPOSAL_ONLY,
        session_id="session-1",
        seal_key=KEY,
    )
    result = adapter.propose(snapshot())
    assert result.state is ExecutionState.EXECUTED
    assert result.proposal == proposal()
    blocked = adapter.execute(
        result.proposal,
        snapshot(),
        authorized=authorized(result.proposal),
        verify=lambda *_: True,
    )
    assert blocked.state is ExecutionState.NOT_STARTED
    assert blocked.failure == "OSS_EXECUTION_DISABLED"
    assert candidate.dispatch_calls == 0


@pytest.mark.parametrize(
    ("snap", "expected"),
    [
        (snapshot(privacy="PRIVATE"), "PRIVACY_DENIED"),
        (snapshot(screenshot=True), "PRIVACY_DENIED"),
        (
            snapshot(
                targets=(
                    {"target_id": "target-1", "identity": IDENTITY},
                    {"target_id": "target-1", "identity": IDENTITY},
                )
            ),
            "AMBIGUOUS_TARGET",
        ),
    ],
)
def test_privacy_and_ambiguous_target_fail_before_candidate_transport(snap, expected):
    candidate = Candidate(proposal())
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.WINDOWS_APP,
        mode=AdapterMode.PROPOSAL_ONLY,
    )
    result = adapter.propose(snap)
    assert result.failure == expected
    assert candidate.propose_calls == 0 if expected == "PRIVACY_DENIED" else True


def test_wrong_surface_stale_and_cross_process_are_refused():
    candidate = Candidate(proposal())
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.BROWSER,
        mode=AdapterMode.PROPOSAL_ONLY,
    )
    assert adapter.propose(snapshot()).failure == "SURFACE_MISMATCH"

    candidate = Candidate(proposal(observation_id="old"))
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.WINDOWS_APP,
        mode=AdapterMode.PROPOSAL_ONLY,
    )
    assert adapter.propose(snapshot()).failure == "STALE_TARGET"

    candidate = Candidate(proposal(target_identity={**IDENTITY, "process_id": 99}))
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.WINDOWS_APP,
        mode=AdapterMode.PROPOSAL_ONLY,
    )
    assert adapter.propose(snapshot()).failure == "TARGET_IDENTITY_MISMATCH"

    cross_process = snapshot(
        targets=({"target_id": "target-1", "identity": {**IDENTITY, "process_id": 99}},)
    )
    candidate = Candidate(proposal(target_identity={**IDENTITY, "process_id": 99}))
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.WINDOWS_APP,
        mode=AdapterMode.PROPOSAL_ONLY,
    )
    assert adapter.propose(cross_process).failure == "CROSS_PROCESS"


def test_unsafe_browser_tool_is_denied_before_dispatch():
    candidate = Candidate(proposal(action="browser_run_code_unsafe"))
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.BROWSER,
        mode=AdapterMode.PROPOSAL_ONLY,
    )
    browser_snapshot = ObservationSnapshot(
        ControlSurface.BROWSER,
        "obs-1",
        ({"target_id": "target-1", "identity": IDENTITY},),
        privacy="PUBLIC",
    )
    result = adapter.propose(browser_snapshot)
    assert result.failure == "ACTION_NOT_ALLOWLISTED"
    assert candidate.dispatch_calls == 0


def test_authorization_seal_session_nonce_and_exact_arguments_are_required():
    candidate = Candidate(proposal())
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.WINDOWS_APP,
        mode=AdapterMode.ENFORCE,
        session_id="session-1",
        seal_key=KEY,
    )
    action = proposal()
    missing = adapter.execute(
        action, snapshot(), authorized=None, verify=lambda *_: True
    )
    assert missing.failure == "AUTHORIZATION_REQUIRED"
    bad = replace(authorized(action), seal="0" * 64)
    assert (
        adapter.execute(
            action, snapshot(), authorized=bad, verify=lambda *_: True
        ).failure
        == "SEAL_MISMATCH"
    )
    other = make_authorized_action(
        proposal(arguments={"button": "secondary"}),
        intent(),
        session_id="session-1",
        nonce="nonce-2",
        key=KEY,
    )
    assert (
        adapter.execute(
            action, snapshot(), authorized=other, verify=lambda *_: True
        ).failure
        == "AUTHORIZATION_MISMATCH"
    )
    wrong_session = make_authorized_action(
        action,
        intent(),
        session_id="other",
        nonce="nonce-3",
        key=KEY,
    )
    assert (
        adapter.execute(
            action, snapshot(), authorized=wrong_session, verify=lambda *_: True
        ).failure
        == "SESSION_MISMATCH"
    )


def test_non_mutating_proposal_cannot_enter_dispatch_lane():
    candidate = Candidate(proposal(mutation=False))
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.WINDOWS_APP,
        mode=AdapterMode.ENFORCE,
        session_id="session-1",
        seal_key=KEY,
    )
    action = proposal(mutation=False)
    result = adapter.execute(
        action,
        snapshot(),
        authorized=authorized(action),
        verify=lambda *_: True,
    )
    assert result.failure == "MUTATION_ACTION_REQUIRED"
    assert candidate.dispatch_calls == 0


def test_verified_action_is_exactly_once_and_nonce_replay_is_denied():
    candidate = Candidate(proposal())
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.WINDOWS_APP,
        mode=AdapterMode.ENFORCE,
        session_id="session-1",
        seal_key=KEY,
    )
    action = proposal()
    auth = authorized(action)
    result = adapter.execute(
        action, snapshot(), authorized=auth, verify=lambda *_: True
    )
    assert result.state is ExecutionState.VERIFIED
    assert candidate.dispatch_calls == 1
    duplicate = adapter.execute(
        action, snapshot(), authorized=auth, verify=lambda *_: True
    )
    assert duplicate.failure == "NONCE_REPLAY"
    assert candidate.dispatch_calls == 1
    assert adapter.journal == {"action-1": "COMPLETED"}


def test_timeout_after_boundary_and_verification_failure_quarantine_without_retry():
    for failure in (
        CandidateDispatchError("lost", dispatched=True),
        CandidateDispatchError("timeout", dispatched=None),
    ):
        candidate = Candidate(proposal(), dispatch=failure)
        adapter = SafeEngineAdapter(
            candidate,
            surface=ControlSurface.WINDOWS_APP,
            mode=AdapterMode.ENFORCE,
            session_id="session-1",
            seal_key=KEY,
        )
        action = proposal()
        result = adapter.execute(
            action,
            snapshot(),
            authorized=authorized(action),
            verify=lambda *_: True,
        )
        assert result.state is ExecutionState.UNKNOWN_OUTCOME
        assert adapter.journal[action.action_id] == "UNKNOWN"
        assert (
            adapter.execute(
                action,
                snapshot(),
                authorized=authorized(action),
                verify=lambda *_: True,
            ).failure
            == "NONCE_REPLAY"
        )
        assert candidate.dispatch_calls == 1

    candidate = Candidate(proposal())
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.WINDOWS_APP,
        mode=AdapterMode.ENFORCE,
        session_id="session-1",
        seal_key=KEY,
    )
    action = proposal()
    result = adapter.execute(
        action,
        snapshot(),
        authorized=authorized(action),
        verify=lambda *_: False,
    )
    assert result.state is ExecutionState.UNKNOWN_OUTCOME
    assert result.failure == "VERIFICATION_FAILED"
    assert candidate.dispatch_calls == 1
