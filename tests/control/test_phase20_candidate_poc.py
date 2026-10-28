"""Offline candidate contract and host-owned Fake execution; no SDK or GUI."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from openjarvis.control.candidate_poc import (
    BrowserUseProposalAdapter,
    UfoProposalAdapter,
)
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
from tests.agents.test_goal_completion_e2e import (
    _agent,
    _call,
    _completed,
    _Counter,
    _executor,
    _plan,
    _planner_of,
    _ready,
    _run,
    _VerifiedNotesTool,
)
from tests.control.phase20_guard import deny_side_effect

KEY = b"phase20-test-only-host-key"


@pytest.mark.parametrize("event,args", [
    ("subprocess.Popen", ("not-executed",)),
    ("_winapi.CreateProcess", ("not-executed",)),
    ("socket.connect", (None, ("203.0.113.1", 443))),
    ("socket.getaddrinfo", ("example.invalid", 443)),
])
def test_test_lane_denies_side_effects_without_executing_them(event, args):
    with pytest.raises(PermissionError, match="PHASE20_"):
        deny_side_effect(event, args)


def test_test_lane_allows_loopback_only():
    deny_side_effect("socket.connect", (None, ("127.0.0.1", 1)))
    deny_side_effect("socket.connect", (None, ("::1", 1)))


def case(surface="browser", **identity_changes):
    identity = (
        dict(session_id="s1", tab_id="t1", page_id="p1", frame_id="f1",
             origin="https://fixture.invalid", dom_revision="rev1")
        if surface == "browser"
        else dict(session_id="s1", process_id=41, process_created=123,
                  hwnd=500, foreground_hwnd=500, window_cookie="cookie1",
                  runtime_id=[1, 2])
    )
    identity.update(identity_changes)
    snapshot = ObservationSnapshot(
        ControlSurface(surface), "obs1",
        ({"target_id": "target1", "identity": identity},),
        privacy="PUBLIC", process_id=41 if surface == "windows_app" else None,
    )
    data = dict(
        action_id="action1", observation_id="obs1", target_id="target1",
        target_identity=identity,
        action="browser_click" if surface == "browser" else "click",
        arguments={},
    )
    cls = BrowserUseProposalAdapter if surface == "browser" else UfoProposalAdapter
    return cls, snapshot, data


@pytest.mark.parametrize("surface", ["browser", "windows_app"])
def test_default_off_and_enforce_forbidden(surface, monkeypatch):
    cls, snapshot, data = case(surface)
    monkeypatch.delenv("ASTRA_CONTROL_ENGINE", raising=False)
    adapter = cls("not even parsed", session_id="s1")
    assert adapter.propose(snapshot).failure == "LEGACY_ENGINE_ACTIVE"
    with pytest.raises(ValueError, match="proposal/shadow only"):
        cls(json.dumps(data), session_id="s1", mode=AdapterMode.ENFORCE)


@pytest.mark.parametrize("surface", ["browser", "windows_app"])
@pytest.mark.parametrize("mode", [AdapterMode.PROPOSAL_ONLY, AdapterMode.SHADOW])
def test_public_proposal_preserves_identity_and_cannot_dispatch(surface, mode):
    cls, snapshot, data = case(surface)
    adapter = cls(json.dumps(data), session_id="s1", mode=mode)
    result = adapter.propose(snapshot)
    assert result.proposal.payload() == {**data, "mutation": True}
    blocked = adapter.execute(
        result.proposal, snapshot, authorized=None, verify=None,
    )
    assert blocked.failure == "OSS_EXECUTION_DISABLED"
    assert not blocked.dispatched and not blocked.verified
    with pytest.raises(CandidateDispatchError, match="PROPOSAL_ONLY_ENGINE"):
        adapter.engine.dispatch(None)


@pytest.mark.parametrize("surface", ["browser", "windows_app"])
@pytest.mark.parametrize("field", ["session_id", "observation_id", "target_id"])
def test_stale_wrong_session_and_wrong_target(surface, field):
    cls, snapshot, data = case(surface)
    if field == "session_id":
        snapshot = replace(snapshot, targets=(
            {"target_id": "target1", "identity": {
                **data["target_identity"], "session_id": "wrong",
            }},
        ))
        data["target_identity"] = dict(snapshot.targets[0]["identity"])
    else:
        data[field] = "wrong"
    adapter = cls(json.dumps(data), session_id="s1", mode=AdapterMode.SHADOW)
    result = adapter.propose(snapshot)
    assert result.state is ExecutionState.NOT_STARTED
    assert result.failure in {"SESSION_MISMATCH", "STALE_TARGET"}
    assert result.proposal is None


@pytest.mark.parametrize("field", [
    "tab_id", "page_id", "frame_id", "origin", "dom_revision",
])
def test_browser_wrong_tab_page_frame_origin_and_stale_dom(field):
    cls, snapshot, data = case()
    data["target_identity"] = {**data["target_identity"], field: "wrong"}
    result = cls(json.dumps(data), session_id="s1", mode="shadow").propose(snapshot)
    assert result.failure == "TARGET_IDENTITY_MISMATCH"


@pytest.mark.parametrize("field", [
    "process_id", "process_created", "hwnd", "window_cookie", "runtime_id",
])
def test_app_cross_process_hwnd_reuse_and_stale_element(field):
    cls, snapshot, data = case("windows_app")
    data["target_identity"] = {**data["target_identity"], field: "wrong"}
    result = cls(json.dumps(data), session_id="s1", mode="shadow").propose(snapshot)
    assert result.failure == "TARGET_IDENTITY_MISMATCH"


@pytest.mark.parametrize("changes,expected", [
    ({"foreground_hwnd": 999}, "WRONG_FOREGROUND"),
    ({"process_id": 42}, "CROSS_PROCESS"),
    ({"process_created": None}, "TARGET_IDENTITY_INCOMPLETE"),
])
def test_app_current_observation_must_match_host_identity(changes, expected):
    cls, snapshot, data = case("windows_app", **changes)
    result = cls(json.dumps(data), session_id="s1", mode="shadow").propose(snapshot)
    assert result.failure == expected


@pytest.mark.parametrize("surface", ["browser", "windows_app"])
def test_privacy_and_ambiguity_denied(surface):
    cls, snapshot, data = case(surface)
    adapter = cls(json.dumps(data), session_id="s1", mode="shadow")
    assert adapter.propose(replace(snapshot, privacy="PRIVATE")).failure == (
        "PRIVACY_DENIED"
    )
    assert adapter.propose(replace(snapshot, has_screenshot=True)).failure == (
        "PRIVACY_DENIED"
    )
    assert adapter.propose(replace(snapshot, targets=snapshot.targets * 2)).failure == (
        "AMBIGUOUS_TARGET"
    )


@pytest.mark.parametrize("change", [
    {"action": "browser_navigate", "arguments": {"url": "https://other.invalid"}},
    {"arguments": {"fallback_selector": "body"}},
    {"arguments": {"retry": True}},
    {"mutation": False},
    {"action": "browser_type", "arguments": {"value": "\u0000"}},
    {"action": "browser_type", "arguments": {"value": "x" * 4097}},
])
def test_cross_origin_navigation_retry_and_unsafe_fallback_denied(change):
    cls, snapshot, data = case()
    data.update(change)
    result = cls(json.dumps(data), session_id="s1", mode="shadow").propose(snapshot)
    assert result.state is ExecutionState.NOT_STARTED
    assert result.proposal is None


@pytest.mark.parametrize("transcript", ["[]", "{", '{"actions": []}'])
def test_untrusted_envelope_is_rejected(transcript):
    cls, snapshot, _ = case()
    result = cls(transcript, session_id="s1", mode="shadow").propose(snapshot)
    assert result.failure == "CANDIDATE_ERROR"


@pytest.mark.parametrize("surface", ["browser", "windows_app"])
def test_bounded_text_proposal_and_missing_identity(surface):
    cls, snapshot, data = case(surface)
    data.update(
        action="browser_type" if surface == "browser" else "type_into",
        arguments={"value": "fixture text"},
    )
    adapter = cls(json.dumps(data), session_id="s1", mode="shadow")
    assert adapter.propose(snapshot).proposal.arguments["value"] == "fixture text"
    identity = dict(data["target_identity"])
    identity.pop("session_id")
    data["target_identity"] = identity
    incomplete = replace(snapshot, targets=(
        {"target_id": "target1", "identity": identity},
    ))
    assert cls(json.dumps(data), session_id="s1", mode="shadow").propose(
        incomplete,
    ).failure == "TARGET_IDENTITY_INCOMPLETE"
    with pytest.raises(ValueError, match="bounded JSON"):
        cls("x" * 16385, session_id="s1", mode="shadow")


class HostFixture:
    def __init__(self, failure=None):
        self.calls = 0
        self.counter = 0
        self.failure = failure

    def dispatch(self, _authorized):
        self.calls += 1
        self.counter += 1
        if self.failure:
            raise self.failure
        return DispatchResult(True, {"counter": self.counter})


@pytest.mark.parametrize("surface", ["browser", "windows_app"])
def test_host_authorizes_proposal_then_independently_verifies_once(surface):
    cls, snapshot, data = case(surface)
    proposal = cls(json.dumps(data), session_id="s1", mode="shadow").propose(
        snapshot,
    ).proposal
    fixture = HostFixture()
    host = SafeEngineAdapter(
        fixture, surface=ControlSurface(surface), mode="enforce",
        session_id="s1", seal_key=KEY,
    )
    def verify(*_):
        return fixture.counter == 1
    assert host.execute(
        proposal, snapshot, authorized=None, verify=verify,
    ).failure == "AUTHORIZATION_REQUIRED"
    assert fixture.calls == 0
    intent = MutationIntent("execution1", "step1", "intent1")
    auth = make_authorized_action(
        proposal, intent, session_id="s1", nonce="nonce1", key=KEY,
    )
    for bad, failure in [
        (replace(auth, seal="0" * 64), "SEAL_MISMATCH"),
        (replace(auth, session_id="other"), "SESSION_MISMATCH"),
        (replace(auth, intent=MutationIntent("other", "step1", "intent1")),
         "SEAL_MISMATCH"),
        (replace(auth, proposal=replace(proposal, arguments={"value": "tamper"})),
         "AUTHORIZATION_MISMATCH"),
    ]:
        assert host.execute(
            proposal, snapshot, authorized=bad, verify=verify,
        ).failure == failure
    assert fixture.calls == 0
    assert host.execute(
        proposal, snapshot, authorized=auth, verify=verify,
    ).state is ExecutionState.VERIFIED
    assert host.execute(
        proposal, snapshot, authorized=auth, verify=verify,
    ).failure == "NONCE_REPLAY"
    new_auth = make_authorized_action(
        proposal, intent, session_id="s1", nonce="nonce2", key=KEY,
    )
    assert host.execute(
        proposal, snapshot, authorized=new_auth, verify=verify,
    ).failure == "DUPLICATE_ACTION"
    assert fixture.calls == fixture.counter == 1


@pytest.mark.parametrize("surface", ["browser", "windows_app"])
@pytest.mark.parametrize("failure,verified", [
    (TimeoutError(), True), (RuntimeError(), True), (None, False),
])
def test_partial_execution_timeout_and_false_success_never_retry(
    surface, failure, verified,
):
    cls, snapshot, data = case(surface)
    proposal = cls(json.dumps(data), session_id="s1", mode="shadow").propose(
        snapshot,
    ).proposal
    fixture = HostFixture(failure)
    host = SafeEngineAdapter(
        fixture, surface=ControlSurface(surface), mode="enforce",
        session_id="s1", seal_key=KEY,
    )
    auth = make_authorized_action(
        proposal, MutationIntent("e", "s", "i"),
        session_id="s1", nonce="n", key=KEY,
    )
    result = host.execute(
        proposal, snapshot, authorized=auth, verify=lambda *_: verified,
    )
    assert result.state is ExecutionState.UNKNOWN_OUTCOME
    assert host.journal == {"action1": "UNKNOWN"}
    assert host.execute(
        proposal, snapshot, authorized=auth, verify=lambda *_: True,
    ).failure == "NONCE_REPLAY"
    assert fixture.calls == 1


@pytest.mark.parametrize("surface", ["browser", "windows_app"])
@pytest.mark.parametrize("stale", [False, True])
def test_candidate_proposal_in_production_agent_goal(tmp_path, surface, stale):
    from openjarvis.agents.manager import AgentManager
    from openjarvis.agents.proposals import PlanProposal, PlanStepProposal
    from openjarvis.core.registry import ToolRegistry
    from openjarvis.core.types import ToolResult
    class CandidateFixtureTool(_VerifiedNotesTool):
        tool_id = "phase20_candidate_fixture"

        def execute(self, **params):
            cls, snapshot, data = case(surface)
            data.update(
                action="browser_type" if surface == "browser" else "type_into",
                arguments={"value": params["value"]},
                observation_id="stale" if stale else "obs1",
            )
            result = cls(json.dumps(data), session_id="s1", mode="shadow").propose(
                snapshot,
            )
            if result.proposal is None:
                return ToolResult(
                    self.tool_id, result.failure, success=False,
                    execution_state=ExecutionState.NOT_STARTED,
                )
            return super().execute(value=result.proposal.arguments["value"])

    _Counter.reset()
    manager = AgentManager(str(tmp_path / "candidate-agent.db"))
    try:
        agent = _agent(manager, CandidateFixtureTool.tool_id)
        ToolRegistry.register_value(CandidateFixtureTool.tool_id, CandidateFixtureTool)
        _ready(manager, agent["id"])
        plan = PlanProposal("candidate-plan", steps=(PlanStepProposal(
            local_index="type", kind="MUTATING",
            tool_name=CandidateFixtureTool.tool_id, arguments={"value": "ATLAS"},
        ),))
        minted = _executor(manager).plan_goal(
            agent["id"], _planner_of(plan), "type into owned Fake target",
            supported_tools={CandidateFixtureTool.tool_id},
        )
        _run(manager, agent["id"], [
            _call(CandidateFixtureTool.tool_id, "call1", value="ATLAS"),
            {"content": "Done only after independent verification."},
        ])
        completed = _completed(_plan(manager, agent["id"]))
        if stale:
            assert not completed and _Counter.dispatches == 0
        else:
            assert completed == {minted["local_to_planner_node"]["type"]}
            assert _Counter.store == {"note": "ATLAS"}
            assert _Counter.dispatches == 1
        assert manager.execution_journal.pending(agent["id"]) == []
    finally:
        manager.close()
