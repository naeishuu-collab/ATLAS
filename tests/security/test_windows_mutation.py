"""Real Windows mutation/verification against explicitly test-owned processes."""

import json
import os

import pytest

from openjarvis.windows.actions import WindowsActionSession
from openjarvis.windows.identity import IdentityError
from openjarvis.windows.observer import WindowsObserver
from tests.security.windows_mutation_fixture import FixtureProcess

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Win32 fixture")


@pytest.fixture
def application(request):
    from tests.security.windows_mutation_fixture import FixtureProcess

    guardian = FixtureProcess.guardian
    if guardian is not None and request.node.name.startswith(
        (
            "test_correct_observed_click",
            "test_type_into_independently",
            "test_type_into_value",
            "test_typing_requires",
            "test_typing_late",
            "test_receiver_closes",
            "test_real_agent",
            "test_lost_acknowledgement",
        )
    ):
        guardian.before_dispatch = None
        guardian.lose_ack = False
        guardian.rpc("reset")
        yield guardian
        return
    with FixtureProcess() as app:
        yield app


@pytest.fixture
def session(application):
    if FixtureProcess.prewarmed_observer is not None:
        yield WindowsActionSession(FixtureProcess.prewarmed_observer, application)
        return
    with WindowsObserver(timeout=15) as observer:
        yield WindowsActionSession(observer, application)


def target(session, app, cid="201"):
    observation = session.observe(app.hwnd)
    identity = session.resolve(observation["observation_id"], automation_id=cid)
    return observation, identity


def test_correct_observed_click_mutates_once_and_verifies_ui_state(
    application, session
):
    application.focus()
    observation, identity = target(session, application)
    result = session.act("click", observation["observation_id"], identity)
    assert result["outcome"] == "VERIFIED", json.dumps(result, indent=2)
    assert result["dispatch"] == "DISPATCHED"
    assert result["verification"] == "VERIFIED"
    assert result["evidence"]["counter_before"] == 0
    assert result["evidence"]["counter_after"] == 1
    assert result["evidence"]["post_observation_id"] != observation["observation_id"]
    state = application.state()  # separate RPC, not action acknowledgement
    assert state["count"] == len(state["events"]) == 1
    event = state["events"][0]
    assert event["pid"] == observation["window"]["process"]["pid"]
    assert event["window_hwnd"] == application.hwnd
    assert event["control_id"] == "201"
    assert event["control_hwnd"] == result["identity"]["control"]["hwnd"]
    replay = session.act("click", observation["observation_id"], identity)
    assert replay["outcome"] == "NOT_STARTED"
    assert replay["dispatch"] == "NOT_DISPATCHED"
    assert application.state()["count"] == 1


def rejected(result, failures):
    assert result["outcome"] == "NOT_STARTED", json.dumps(result, indent=2)
    assert result["failure"] in failures, result
    assert result["dispatch"] == "NOT_DISPATCHED"
    assert result["verification"] == "NOT_VERIFIED"
    assert result["retryable"] is False


@pytest.mark.parametrize("value", ["fixture value", "Unicode: 日本語 α 🚀"])
def test_type_into_independently_reads_intended_edit_once(application, session, value):
    application.focus(101)
    observation, identity = target(session, application, "101")
    result = session.act(
        "type_into", observation["observation_id"], identity, value=value
    )
    assert result["outcome"] == "VERIFIED", json.dumps(result, indent=2)
    assert result["dispatch"] == "DISPATCHED"
    assert result["evidence"]["value_length"] == len(value)
    assert value not in json.dumps(result)
    state = application.state()
    assert state["text"] == value
    assert state["count"] == len(state["events"]) == 1
    assert state["events"][0]["pid"] == application.pid
    assert state["events"][0]["control_id"] == "101"
    assert state["events"][0]["control_hwnd"] == result["identity"]["control"]["hwnd"]
    rejected(
        session.act("type_into", observation["observation_id"], identity, value=value),
        {"STALE_TARGET"},
    )
    assert application.state()["count"] == 1


@pytest.mark.parametrize("mode", ["password", "readonly"])
def test_type_into_value_capability_rejects_before_dispatch(application, session, mode):
    application.focus(101)
    application.rpc("edit_mode", {mode: True})
    observation, identity = target(session, application, "101")
    observed = next(c for c in observation["controls"] if c["target_id"] == identity)
    if mode == "password":
        assert observed["value_verifiable"] is False
    else:
        # Read-only edits remain readable, so the owner-thread receiver must
        # reject the physical setter after the live style check.
        assert observed["value_verifiable"] is True
    result = session.act(
        "type_into", observation["observation_id"], identity, value="must not enter"
    )
    rejected(result, {"UNSUPPORTED_CONTROL"})
    state = application.state()
    assert state["count"] == len(state["events"]) == 0
    assert state["text"] == ""


def test_typing_late_readonly_change_rejected_on_owner_thread(application, session):
    application.focus(101)
    observation, identity = target(session, application, "101")

    def change_capability():
        application.rpc("edit_mode", {"readonly": True})

    application.before_dispatch = change_capability
    result = session.act(
        "type_into", observation["observation_id"], identity, value="must not enter"
    )
    rejected(result, {"UNSUPPORTED_CONTROL"})
    state = application.state()
    assert state["count"] == len(state["events"]) == 0
    assert state["text"] == ""


@pytest.mark.parametrize("action,cid", [("click", "201"), ("type_into", "101")])
def test_wrong_foreground_a_and_b_receive_zero_mutations(
    application, session, action, cid
):
    application.focus(int(cid))
    observation, identity = target(session, application, cid)
    with FixtureProcess() as other:
        other.focus(int(cid))
        assert other.state()["foreground"] == other.hwnd
        result = session.act(
            action, observation["observation_id"], identity, value="must not enter"
        )
        rejected(result, {"WRONG_FOREGROUND"})
        assert application.state()["count"] == other.state()["count"] == 0
        assert application.state()["text"] == other.state()["text"] == ""
        assert other.state()["foreground"] == other.hwnd


def test_cross_process_same_semantics_never_retargets(application, session):
    observation, identity = target(session, application)
    with FixtureProcess() as other, WindowsObserver(timeout=15) as other_observer:
        alternate = other_observer.observe(other.hwnd)
        alternative = other_observer.select(
            alternate["observation_id"], automation_id="201"
        )
        assert alternative != identity
        assert (
            alternate["window"]["process"]["pid"]
            != observation["window"]["process"]["pid"]
        )
        # B has the same Name/type. A's captured target ceases to exist.
        application.rpc("replace")
        result = session.act("click", observation["observation_id"], identity)
        rejected(result, {"STALE_TARGET", "IDENTITY_MISMATCH"})
        assert application.state()["count"] == other.state()["count"] == 0


def test_duplicate_semantic_controls_are_ambiguous_and_never_dispatch(
    application, session
):
    observation = session.observe(application.hwnd)
    duplicates = [c for c in observation["controls"] if c["name"] == "Duplicate"]
    assert len(duplicates) == 2
    with pytest.raises(IdentityError, match="2 matches"):
        session.resolve(
            observation["observation_id"], name="Duplicate", control_type=50000
        )
    result = session.act(
        "click", observation["observation_id"], duplicates[0]["target_id"]
    )
    rejected(result, {"STALE_TARGET"})
    assert application.state()["count"] == 0


def test_replaced_control_invalidates_old_target(application, session):
    observation, identity = target(session, application)
    old = application.snapshot()["controls"]["201"]
    replacement = application.rpc("replace")["snapshot"]["controls"]["201"]
    assert replacement["cookie"] != old["cookie"]
    result = session.act("click", observation["observation_id"], identity)
    rejected(result, {"STALE_TARGET", "IDENTITY_MISMATCH"})
    assert application.state()["count"] == 0


def test_window_recreation_requires_fresh_authorization(application, session):
    observation, identity = target(session, application)
    old = application.snapshot()
    recreated = application.rpc("recreate")
    application.hwnd = recreated["snapshot"]["hwnd"]
    assert recreated["snapshot"]["pid"] == old["pid"]
    assert recreated["snapshot"]["window_cookie"] != old["window_cookie"]
    rejected(
        session.act("click", observation["observation_id"], identity),
        {"STALE_TARGET", "IDENTITY_MISMATCH"},
    )
    assert application.state()["count"] == 0


def test_process_restart_cannot_inherit_old_authorization(application, session):
    observation, identity = target(session, application)
    before = application.state()
    assert before["count"] == 0
    application.close()
    with FixtureProcess() as restarted:
        snapshot = restarted.snapshot()
        assert snapshot["created_filetime"] != before["snapshot"]["created_filetime"]
        result = session.act("click", observation["observation_id"], identity)
        rejected(result, {"STALE_TARGET", "IDENTITY_MISMATCH"})
        assert restarted.state()["count"] == 0
        assert not application.process.is_alive()


def test_bounded_hwnd_reuse_probe_preserves_old_target_rejection(application, session):
    from pathlib import Path

    observation, identity = target(session, application)
    old = application.snapshot()["controls"]["201"]
    reused = False
    handles = []
    for _ in range(64):
        current = application.rpc("replace")["snapshot"]["controls"]["201"]
        handles.append(current["hwnd"])
        assert current["cookie"] != old["cookie"]
        reused = reused or current["hwnd"] == old["hwnd"]
    result = session.act("click", observation["observation_id"], identity)
    rejected(result, {"STALE_TARGET", "IDENTITY_MISMATCH"})
    assert application.state()["count"] == 0
    evidence = {
        "status": "REPRODUCED" if reused else "NOT REPRODUCED",
        "replacements": 64,
        "old_hwnd": old["hwnd"],
        "replacement_hwnds": handles,
        "physical_clicks": 0,
        "old_authorization_failure": result["failure"],
    }
    output = Path(".astra-tools/mutation-hwnd-reuse.json")
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")


def test_typing_requires_exact_control_focus(application, session):
    application.focus(201)
    observation, identity = target(session, application, "101")
    result = session.act(
        "type_into", observation["observation_id"], identity, value="forbidden"
    )
    rejected(result, {"FOCUS_FAILURE"})
    assert result["preconditions"] == "REJECTED_AT_RECEIVER"
    assert application.state()["count"] == 0
    assert application.state()["text"] == ""


@pytest.mark.parametrize("race", ["replace", "recreate", "foreground"])
def test_receiver_closes_revalidation_to_dispatch_identity_gap(
    application, session, race
):
    # Click needs root foreground, not Button focus. Keep focus on a surviving
    # control when replacing the target, isolating identity from focus lifetime.
    application.focus(101 if race == "replace" else 201)
    observation, identity = target(session, application)
    with FixtureProcess() as other:

        def change():
            if race == "foreground":
                other.focus()
            else:
                new = application.rpc(race)
                application.hwnd = new["snapshot"]["hwnd"]

        application.before_dispatch = change
        result = session.act("click", observation["observation_id"], identity)
        rejected(result, {"STALE_TARGET", "WRONG_FOREGROUND", "IDENTITY_MISMATCH"})
        assert result["preconditions"] == "REJECTED_AT_RECEIVER"
        assert application.state()["count"] == other.state()["count"] == 0


def test_real_agent_tool_and_trace_receive_native_verified_result(
    application, session, tmp_path
):
    from unittest.mock import MagicMock

    from openjarvis.agents.native_react import NativeReActAgent
    from openjarvis.core.events import EventBus
    from openjarvis.core.types import StepType
    from openjarvis.tools.execution_journal import ExecutionJournal
    from openjarvis.tools.windows import WindowsActionTool, WindowsObserveTool
    from openjarvis.traces.collector import TraceCollector

    application.focus()
    engine = MagicMock(engine_id="scripted-fixture")
    turn = 0

    def generate(messages, **kwargs):
        nonlocal turn
        turn += 1
        if turn == 1:
            data = {
                "action": "windows_observe",
                "action_input": {
                    "hwnd": application.hwnd,
                    "hints": {"automation_id": "201"},
                },
            }
        elif turn == 2:
            observed = json.loads(messages[-1].content.removeprefix("Observation: "))
            data = {
                "action": "windows_action",
                "action_input": {
                    "action": "click",
                    "observation_id": observed["observation"]["observation_id"],
                    "target_id": observed["target_id"],
                },
            }
        else:
            actual = json.loads(messages[-1].content.removeprefix("Observation: "))
            assert actual["outcome"] == actual["verification"] == "VERIFIED"
            assert actual["dispatch"] == "DISPATCHED"
            data = {"final_answer": "Owned fixture verified"}
        return {
            "content": json.dumps(data),
            "usage": {},
            "model": "scripted-fixture",
            "finish_reason": "stop",
        }

    engine.generate.side_effect = generate
    bus = EventBus(record_history=True)
    agent = NativeReActAgent(
        engine,
        "scripted-fixture",
        tools=[WindowsObserveTool(session), WindowsActionTool(session)],
        bus=bus,
        interactive=True,
        confirm_callback=lambda *_: True,
    )
    journal = ExecutionJournal(tmp_path / "agent-journal.db")
    try:
        agent._executor.bind_execution_journal(journal, "native-fixture-agent")
        collector = TraceCollector(agent, bus=bus)
        result = collector.run("Observe and click the owned fixture once")
        assert result.tool_results[-1].success
        assert result.tool_results[-1].metadata["execution"]["state"] == "VERIFIED"
        assert application.state()["count"] == len(application.state()["events"]) == 1
        steps = [
            s for s in collector.last_trace.steps if s.step_type == StepType.TOOL_CALL
        ]
        assert len(steps) == 2
        assert steps[-1].metadata["windows"]["evidence"]["counter_after"] == 1
        assert journal.pending("native-fixture-agent") == []
    finally:
        journal.close()


def test_lost_acknowledgement_quarantines_replay_across_executor_restart(
    application, session, tmp_path
):
    from openjarvis.core.types import ToolCall
    from openjarvis.tools._stubs import ToolExecutor
    from openjarvis.tools.execution_journal import ExecutionJournal
    from openjarvis.tools.windows import WindowsActionTool, WindowsObserveTool

    application.focus()
    observation, identity = target(session, application)
    application.lose_ack = True
    arguments = json.dumps(
        {
            "action": "click",
            "observation_id": observation["observation_id"],
            "target_id": identity,
        }
    )
    path = tmp_path / "journal.db"
    journal = ExecutionJournal(path)
    try:
        executor = ToolExecutor(
            [WindowsActionTool(session)],
            interactive=True,
            confirm_callback=lambda *_: True,
            execution_journal=journal,
            execution_scope="owned-fixture",
        )
        result = executor.execute(ToolCall("one", "windows_action", arguments))
        assert result.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
        assert result.metadata["windows"]["dispatch"] == "POSSIBLE"
        assert application.state()["count"] == 1
    finally:
        journal.close()
    reopened = ExecutionJournal(path)
    try:
        restarted_executor = ToolExecutor(
            [WindowsActionTool(session), WindowsObserveTool(session)],
            interactive=True,
            confirm_callback=lambda *_: True,
            execution_journal=reopened,
            execution_scope="owned-fixture",
        )
        again = restarted_executor.execute(
            ToolCall("new-id", "windows_action", arguments)
        )
        assert again.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
        assert application.state()["count"] == 1
        # Fresh valid target IDs must not release durable uncertainty. Make the
        # receiver willing to acknowledge so a quarantine bypass would cause a
        # real second click and fail the independent counter assertion.
        application.lose_ack = False
        observed = restarted_executor.execute(
            ToolCall(
                "fresh-observation",
                "windows_observe",
                json.dumps(
                    {"hwnd": application.hwnd, "hints": {"automation_id": "201"}}
                ),
            )
        )
        assert observed.success
        fresh = observed.metadata["windows"]
        assert fresh["observation"]["observation_id"] != observation["observation_id"]
        assert fresh["target_id"] != identity
        blocked = restarted_executor.execute(
            ToolCall(
                "fresh-action",
                "windows_action",
                json.dumps(
                    {
                        "action": "click",
                        "observation_id": fresh["observation"]["observation_id"],
                        "target_id": fresh["target_id"],
                    }
                ),
            )
        )
        assert blocked.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
        assert blocked.metadata["execution"]["retryable"] is False
        assert len(reopened.pending("owned-fixture")) == 1
        assert application.state()["count"] == len(application.state()["events"]) == 1
    finally:
        reopened.close()


@pytest.mark.parametrize("ambiguous", [False, True])
def test_real_agent_fresh_observation_after_stale_rejection(
    application, session, tmp_path, ambiguous
):
    from unittest.mock import MagicMock

    from openjarvis.agents.native_react import NativeReActAgent
    from openjarvis.core.events import EventBus
    from openjarvis.core.types import StepType
    from openjarvis.tools.execution_journal import ExecutionJournal
    from openjarvis.tools.windows import WindowsActionTool, WindowsObserveTool
    from openjarvis.traces.collector import TraceCollector

    application.focus(101)  # the replaced Button must not own fixture focus
    engine = MagicMock(engine_id="scripted-safe-replan")
    engine._publishes_events = False
    old = {}
    turn = 0

    def generate(messages, **kwargs):
        nonlocal turn, old
        turn += 1
        if turn == 1:
            data = {
                "action": "windows_observe",
                "action_input": {
                    "hwnd": application.hwnd,
                    "hints": {"automation_id": "201"},
                },
            }
        elif turn == 2:
            old = json.loads(messages[-1].content.removeprefix("Observation: "))
            application.rpc("replace")
            assert application.state()["foreground"] == application.hwnd
            data = {
                "action": "windows_action",
                "action_input": {
                    "action": "click",
                    "observation_id": old["observation"]["observation_id"],
                    "target_id": old["target_id"],
                },
            }
        elif turn == 3:
            failed = json.loads(messages[-1].content.removeprefix("Observation: "))
            rejected(failed, {"STALE_TARGET", "IDENTITY_MISMATCH"})
            assert application.state()["count"] == 0
            data = {
                "action": "windows_observe",
                "action_input": {
                    "hwnd": application.hwnd,
                    "hints": (
                        {"name": "Duplicate", "control_type": 50000}
                        if ambiguous
                        else {"automation_id": "201"}
                    ),
                },
            }
        elif turn == 4:
            fresh = json.loads(messages[-1].content.removeprefix("Observation: "))
            if ambiguous:
                assert fresh["failure"] == "AMBIGUOUS_TARGET"
                assert fresh["dispatch"] == "NOT_DISPATCHED"
                assert application.state()["count"] == 0
                data = {"final_answer": "Fresh observation is ambiguous; no action"}
            else:
                assert (
                    fresh["observation"]["observation_id"]
                    != old["observation"]["observation_id"]
                )
                assert fresh["target_id"] != old["target_id"]
                before = old["observation"]["receiver_identity"]["controls"]["201"]
                after = fresh["observation"]["receiver_identity"]["controls"]["201"]
                assert before["cookie"] != after["cookie"]
                data = {
                    "action": "windows_action",
                    "action_input": {
                        "action": "click",
                        "observation_id": fresh["observation"]["observation_id"],
                        "target_id": fresh["target_id"],
                    },
                }
        else:
            verified = json.loads(messages[-1].content.removeprefix("Observation: "))
            assert verified["outcome"] == verified["verification"] == "VERIFIED"
            assert verified["evidence"]["counter_before"] == 0
            assert verified["evidence"]["counter_after"] == 1
            data = {"final_answer": "Fresh target independently verified"}
        return {
            "content": json.dumps(data),
            "usage": {},
            "model": "scripted-safe-replan",
            "finish_reason": "stop",
        }

    engine.generate.side_effect = generate
    prompts = []
    bus = EventBus()
    agent = NativeReActAgent(
        engine,
        "scripted-safe-replan",
        max_turns=6,
        tools=[WindowsObserveTool(session), WindowsActionTool(session)],
        bus=bus,
        interactive=True,
        confirm_callback=lambda p: prompts.append(p) or True,
    )
    journal = ExecutionJournal(tmp_path / "replan.db")
    try:
        agent._executor.bind_execution_journal(journal, "owned-safe-replan")
        collector = TraceCollector(agent, bus=bus)
        result = collector.run(
            "Re-observe after a safe stale rejection; authorize a fresh target"
        )
        assert len(result.tool_results) == (3 if ambiguous else 4)
        assert result.tool_results[1].metadata["execution"]["state"] == "NOT_STARTED"
        assert result.tool_results[-1].success is (not ambiguous)
        state = application.state()
        assert state["count"] == len(state["events"]) == (0 if ambiguous else 1)
        assert len(prompts) == (1 if ambiguous else 2)
        assert journal.pending("owned-safe-replan") == []
        steps = [
            s for s in collector.last_trace.steps if s.step_type == StepType.TOOL_CALL
        ]
        assert len(steps) == len(result.tool_results)
        if not ambiguous:
            assert (
                steps[1].metadata["windows"]["target_id"]
                != steps[3].metadata["windows"]["target_id"]
            )
            assert (
                steps[1].metadata["execution"]["call_id"]
                != steps[3].metadata["execution"]["call_id"]
            )
            assert (
                state["events"][0]["control_cookie"]
                == steps[3].metadata["windows"]["identity"]["receiver"][
                    "control_cookie"
                ]
            )
            assert steps[3].metadata["windows"]["evidence"]["counter_after"] == 1
    finally:
        journal.close()


def test_real_agent_typing_omits_raw_trace_payloads(application, session, tmp_path):
    from dataclasses import asdict
    from unittest.mock import MagicMock

    from openjarvis.agents.native_react import NativeReActAgent
    from openjarvis.core.events import EventBus, EventType
    from openjarvis.tools.windows import WindowsActionTool, WindowsObserveTool
    from openjarvis.traces.collector import TraceCollector
    from openjarvis.traces.store import TraceStore

    application.focus(101)
    canary = "phase14-owned-native-canary-e390"
    engine = MagicMock(engine_id="scripted-native-privacy")
    engine._publishes_events = False
    turn = 0

    def generate(messages, **kwargs):
        nonlocal turn
        turn += 1
        if turn == 1:
            data = {
                "action": "windows_observe",
                "action_input": {
                    "hwnd": application.hwnd,
                    "hints": {"automation_id": "101"},
                },
            }
        elif turn == 2:
            observed = json.loads(messages[-1].content.removeprefix("Observation: "))
            data = {
                "action": "windows_action",
                "action_input": {
                    "action": "type_into",
                    "value": canary,
                    "observation_id": observed["observation"]["observation_id"],
                    "target_id": observed["target_id"],
                },
            }
        else:
            actual = json.loads(messages[-1].content.removeprefix("Observation: "))
            assert actual["outcome"] == actual["verification"] == "VERIFIED"
            data = {"final_answer": f"Typed {canary}"}
        return {
            "content": json.dumps(data),
            "usage": {},
            "model": "scripted-native-privacy",
            "finish_reason": "stop",
        }

    engine.generate.side_effect = generate
    prompts = []
    bus = EventBus(record_history=True)
    agent = NativeReActAgent(
        engine,
        "scripted-native-privacy",
        tools=[WindowsObserveTool(session), WindowsActionTool(session)],
        bus=bus,
        interactive=True,
        confirm_callback=lambda p: prompts.append(p) or True,
    )
    store = TraceStore(tmp_path / "native-trace.db")
    try:
        collector = TraceCollector(agent, bus=bus, store=store)
        result = collector.run(f"Type {canary} once into the owned fixture")
        assert result.tool_results[-1].success
        state = application.state()
        assert state["text"] == canary
        assert state["count"] == len(state["events"]) == 1
        assert state["events"][0]["control_id"] == "101"
        assert canary in prompts[0] and canary in result.content
        trace = collector.last_trace
        assert canary not in json.dumps(asdict(trace))
        assert canary not in "\n".join(store._conn.iterdump())
        complete = [e for e in bus.history if e.event_type == EventType.TRACE_COMPLETE]
        assert len(complete) == 1 and complete[0].data["trace"] is trace
        assert result.tool_results[-1].metadata["windows"]["evidence"][
            "value_length"
        ] == len(canary)
    finally:
        store.close()
