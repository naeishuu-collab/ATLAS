"""Phase 34/35 host-owned browser dispatch and negative tests."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from openjarvis.control.browser_dispatch import (
    BrowserActionClass,
    BrowserDispatchFacade,
)
from openjarvis.control.browser_use_schema import extract_browser_use_action_schema
from openjarvis.control.oss_adapter import (
    AdapterMode,
    CandidateDispatchError,
    ControlSurface,
    DispatchResult,
    ObservationSnapshot,
    SafeEngineAdapter,
    make_authorized_action,
)
from openjarvis.core.execution import ExecutionState, MutationIntent

_KEY = b"phase34-test-only-host-key"
_EVIDENCE = (
    Path(__file__).resolve().parents[2]
    / ".astra-artifacts"
    / "phase30-32-20261025"
    / "browser-use-action-schema.json"
)


class _FakeExecutor:
    def __init__(self, failure=None):
        self.calls = 0
        self.failure = failure

    def propose(self, _observation):
        return None

    def dispatch(self, _authorized):
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return DispatchResult(True, {"calls": self.calls})


def _schema():
    evidence = json.loads(_EVIDENCE.read_text(encoding="utf-8"))
    rows = {
        item["sdk_action"]: {"schema": item["sdk_schema"]}
        for item in evidence["actions"]
    }
    return extract_browser_use_action_schema(rows, version=evidence["version"])


def _snapshot(
    *,
    observation_id="obs1",
    privacy="PUBLIC",
    process_id=None,
    identity_overrides=None,
    targets=None,
):
    identity = {
        "session_id": "s1",
        "tab_id": "tab1",
        "page_id": "page1",
        "frame_id": "frame1",
        "window_id": "window1",
        "origin": "https://fixture.invalid",
        "dom_revision": "r1",
        "element_index": 3,
    }
    identity.update(identity_overrides or {})
    if targets is None:
        targets = ({"target_id": "element-3", "identity": identity},)
    return ObservationSnapshot(
        ControlSurface.BROWSER,
        observation_id,
        tuple(targets),
        privacy=privacy,
        process_id=process_id,
    )


def _facade(failure=None):
    executor = _FakeExecutor(failure)
    host = SafeEngineAdapter(
        executor,
        surface=ControlSurface.BROWSER,
        mode=AdapterMode.ENFORCE,
        session_id="s1",
        seal_key=_KEY,
    )
    return BrowserDispatchFacade(_schema(), host=host, session_id="s1"), executor


def _auth(facade, action, snapshot, action_id="a1", nonce="n1"):
    proposal = facade.propose(action, snapshot, action_id=action_id)
    return make_authorized_action(
        proposal,
        MutationIntent("execution", "step", "intent"),
        session_id="s1",
        nonce=nonce,
        key=_KEY,
    )


def _assert_denied(result, executor, failure, *, calls=0, dispatched=False):
    assert result.adapter_result.failure == failure
    assert result.evidence.verified is False
    assert result.evidence.retryable is False
    assert result.evidence.dispatched is dispatched
    assert executor.calls == calls


def test_matrix_covers_real_sdk_schema_and_denies_direct_dispatch():
    facade, _ = _facade()
    matrix = {row["sdk_action"]: row for row in facade.action_matrix()}
    assert len(matrix) == 24
    assert matrix["screenshot"]["action_class"] == "FILESYSTEM_MUTATION"
    assert matrix["search"]["action_class"] == "NETWORK"
    assert matrix["click"]["direct_sdk_dispatch"] == "DENIED"
    assert (
        facade.classify_action("child_process")
        is BrowserActionClass.UNSUPPORTED
    )


def test_facade_rejects_raw_sdk_and_unenforced_hosts():
    with pytest.raises(TypeError, match="DISPATCH_HOST_REQUIRED"):
        BrowserDispatchFacade(_schema(), host=object(), session_id="s1")

    shadow = SafeEngineAdapter(
        _FakeExecutor(),
        surface=ControlSurface.BROWSER,
        mode=AdapterMode.SHADOW,
        session_id="s1",
        seal_key=_KEY,
    )
    with pytest.raises(ValueError, match="DISPATCH_ENFORCE_REQUIRED"):
        BrowserDispatchFacade(_schema(), host=shadow, session_id="s1")

    wrong_surface = SafeEngineAdapter(
        _FakeExecutor(),
        surface=ControlSurface.WINDOWS_APP,
        mode=AdapterMode.ENFORCE,
        session_id="s1",
        seal_key=_KEY,
    )
    with pytest.raises(ValueError, match="DISPATCH_SURFACE_MISMATCH"):
        BrowserDispatchFacade(_schema(), host=wrong_surface, session_id="s1")


def test_valid_real_schema_path_is_exactly_once_and_structured():
    facade, executor = _facade()
    snapshot = _snapshot()
    action = {"click": {"index": 3}}
    auth = _auth(facade, action, snapshot)
    result = facade.dispatch(
        action,
        snapshot,
        action_id="a1",
        authorized=auth,
        verify=lambda *_: True,
    )
    assert result.adapter_result.state is ExecutionState.VERIFIED
    assert result.evidence.to_dict()["verified"] is True
    assert result.to_dict()["proposal"]["action"] == "browser_sdk_click"
    assert executor.calls == 1


def test_unauthorized_action_is_not_dispatched():
    facade, executor = _facade()
    result = facade.dispatch(
        {"click": {"index": 3}},
        _snapshot(),
        action_id="unauthorized",
        authorized=None,
        verify=lambda *_: True,
    )
    _assert_denied(result, executor, "AUTHORIZATION_REQUIRED")


@pytest.mark.parametrize(
    "action,reason",
    [
        ({"click": {"index": 99}}, "STALE_TARGET"),
        ({"close": {"tab_id": "tab2"}}, "STALE_TARGET"),
        ({"navigate": {"url": "https://other.invalid/"}}, "CROSS_ORIGIN"),
        ({"search": {"query": "secret"}}, "NAVIGATION_TARGET_UNVERIFIED"),
        ({"click": {"index": 3}, "wait": {}}, "MULTI_ACTION"),
        ({"shell": {"command": "dir"}}, "UNSUPPORTED_ACTION"),
    ],
)
def test_invalid_target_or_bypass_is_denied_without_mutation(action, reason):
    facade, executor = _facade()
    result = facade.dispatch(
        action,
        _snapshot(),
        action_id="invalid",
        authorized=None,
        verify=lambda *_: True,
    )
    _assert_denied(result, executor, reason)


def test_wrong_process_is_denied_without_dispatch():
    facade, executor = _facade()
    snapshot = _snapshot(process_id=42, identity_overrides={"process_id": 99})
    action = {"click": {"index": 3}}
    auth = _auth(facade, action, snapshot)
    result = facade.dispatch(
        action,
        snapshot,
        action_id="wrong-process",
        authorized=auth,
        verify=lambda *_: True,
    )
    _assert_denied(result, executor, "CROSS_PROCESS")


@pytest.mark.parametrize(
    "identity_overrides,reason",
    [
        ({"window_id": "window2"}, "TARGET_IDENTITY_MISMATCH"),
        ({"page_id": "page2"}, "TARGET_IDENTITY_MISMATCH"),
    ],
)
def test_wrong_window_or_page_is_denied_without_dispatch(
    identity_overrides, reason
):
    facade, executor = _facade()
    original = _snapshot()
    action = {"click": {"index": 3}}
    auth = _auth(facade, action, original, action_id="wrong-identity")
    current = _snapshot(identity_overrides=identity_overrides)
    result = facade.dispatch_proposal(
        facade.propose(action, original, action_id="wrong-identity"),
        current,
        authorized=auth,
        verify=lambda *_: True,
    )
    _assert_denied(result, executor, reason)


def test_stale_observation_and_ambiguous_target_are_denied():
    facade, executor = _facade()
    action = {"click": {"index": 3}}
    auth = _auth(facade, action, _snapshot(), action_id="stale")
    stale = facade.dispatch_proposal(
        facade.propose(action, _snapshot(), action_id="stale"),
        _snapshot(observation_id="obs2"),
        authorized=auth,
        verify=lambda *_: True,
    )
    _assert_denied(stale, executor, "STALE_TARGET")

    identity = _snapshot().targets[0]["identity"]
    ambiguous_snapshot = _snapshot(
        targets=(
            {"target_id": "element-a", "identity": identity},
            {"target_id": "element-b", "identity": identity},
        )
    )
    ambiguous = facade.dispatch(
        action,
        ambiguous_snapshot,
        action_id="ambiguous",
        authorized=None,
        verify=lambda *_: True,
    )
    _assert_denied(ambiguous, executor, "AMBIGUOUS_TARGET")


def test_session_and_privacy_boundaries_are_denied():
    facade, executor = _facade()
    wrong_session = _snapshot(
        identity_overrides={"session_id": "other"},
    )
    session_result = facade.dispatch(
        {"click": {"index": 3}},
        wrong_session,
        action_id="session",
        authorized=None,
        verify=lambda *_: True,
    )
    _assert_denied(session_result, executor, "SESSION_MISMATCH")

    private_result = facade.dispatch(
        {"click": {"index": 3}},
        _snapshot(privacy="PRIVATE"),
        action_id="privacy",
        authorized=None,
        verify=lambda *_: True,
    )
    _assert_denied(private_result, executor, "PRIVACY_DENIED")


def test_file_write_and_screenshot_require_authorization():
    facade, executor = _facade()
    for action, action_id in (
        (
            {"write_file": {"file_name": "out.txt", "content": "secret"}},
            "write-file",
        ),
        ({"screenshot": {"file_name": "out.png"}}, "screenshot"),
    ):
        result = facade.dispatch(
            action,
            _snapshot(),
            action_id=action_id,
            authorized=None,
            verify=lambda *_: True,
        )
        _assert_denied(result, executor, "AUTHORIZATION_REQUIRED")
    assert executor.calls == 0


def test_read_only_action_never_enters_mutation_dispatch():
    facade, executor = _facade()
    result = facade.dispatch(
        {"wait": {"seconds": 1}},
        _snapshot(),
        action_id="wait",
        authorized=None,
        verify=lambda *_: True,
    )
    _assert_denied(result, executor, "READ_ONLY_NOT_DISPATCHABLE")


def test_nonce_replay_and_duplicate_mutation_are_denied():
    facade, executor = _facade()
    snapshot = _snapshot()
    action = {"click": {"index": 3}}
    auth = _auth(facade, action, snapshot, action_id="once")
    first = facade.dispatch(
        action,
        snapshot,
        action_id="once",
        authorized=auth,
        verify=lambda *_: True,
    )
    replay = facade.dispatch(
        action,
        snapshot,
        action_id="once",
        authorized=auth,
        verify=lambda *_: True,
    )
    new_auth = _auth(facade, action, snapshot, action_id="once", nonce="n2")
    duplicate = facade.dispatch(
        action,
        snapshot,
        action_id="once",
        authorized=new_auth,
        verify=lambda *_: True,
    )
    assert first.adapter_result.state is ExecutionState.VERIFIED
    _assert_denied(replay, executor, "NONCE_REPLAY", calls=1)
    _assert_denied(duplicate, executor, "DUPLICATE_ACTION", calls=1)


def test_payload_tampering_is_denied_without_dispatch():
    facade, executor = _facade()
    snapshot = _snapshot()
    action = {"click": {"index": 3}}
    auth = _auth(facade, action, snapshot, action_id="tampered")
    tampered = replace(
        auth,
        proposal=replace(auth.proposal, arguments={"index": 99}),
    )
    result = facade.dispatch(
        action,
        snapshot,
        action_id="tampered",
        authorized=tampered,
        verify=lambda *_: True,
    )
    _assert_denied(result, executor, "AUTHORIZATION_MISMATCH")


def test_internal_retry_is_not_authorized_or_repeated():
    facade, executor = _facade(
        CandidateDispatchError("candidate retry", dispatched=False)
    )
    snapshot = _snapshot()
    action = {"click": {"index": 3}}
    auth = _auth(facade, action, snapshot, action_id="retry")
    result = facade.dispatch(
        action,
        snapshot,
        action_id="retry",
        authorized=auth,
        verify=lambda *_: True,
    )
    _assert_denied(result, executor, "CANDIDATE_REJECTED", calls=1)
    replay = facade.dispatch(
        action,
        snapshot,
        action_id="retry",
        authorized=auth,
        verify=lambda *_: True,
    )
    _assert_denied(replay, executor, "NONCE_REPLAY", calls=1)


@pytest.mark.parametrize("failure", [TimeoutError(), RuntimeError()])
def test_timeout_and_unknown_outcome_are_not_retried(failure):
    facade, executor = _facade(failure)
    snapshot = _snapshot()
    action = {"click": {"index": 3}}
    auth = _auth(facade, action, snapshot, action_id="unknown")
    result = facade.dispatch(
        action,
        snapshot,
        action_id="unknown",
        authorized=auth,
        verify=lambda *_: True,
    )
    _assert_denied(
        result,
        executor,
        "UNKNOWN_OUTCOME",
        calls=1,
        dispatched=True,
    )
    assert result.adapter_result.state is ExecutionState.UNKNOWN_OUTCOME


def test_verification_failure_is_not_success_or_retryable():
    facade, executor = _facade()
    snapshot = _snapshot()
    action = {"click": {"index": 3}}
    auth = _auth(facade, action, snapshot, action_id="verify")
    result = facade.dispatch(
        action,
        snapshot,
        action_id="verify",
        authorized=auth,
        verify=lambda *_: False,
    )
    _assert_denied(
        result,
        executor,
        "VERIFICATION_FAILED",
        calls=1,
        dispatched=True,
    )
    assert result.adapter_result.state is ExecutionState.UNKNOWN_OUTCOME
