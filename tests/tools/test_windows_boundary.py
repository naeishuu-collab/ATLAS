"""Real Python executor/agent boundary, with simulated Windows action endpoints."""

import json
from unittest.mock import MagicMock

import pytest

from openjarvis.agents.native_react import NativeReActAgent
from openjarvis.core.events import EventBus, EventType
from openjarvis.core.registry import ToolRegistry
from openjarvis.core.types import StepType, ToolCall
from openjarvis.tools import _stubs
from openjarvis.tools._stubs import ToolExecutor
from openjarvis.tools.execution_journal import ExecutionJournal
from openjarvis.tools.windows import WindowsActionTool, WindowsObserveTool
from openjarvis.traces.collector import TraceCollector
from openjarvis.windows.actions import WindowsActionSession
from tests.security.test_windows_action_contract import Observer, Receiver


def response(content):
    return {
        "content": json.dumps(content),
        "usage": {},
        "model": "fixture-model",
        "finish_reason": "stop",
    }


@pytest.mark.parametrize(
    "fault,state,failure",
    [
        ("none", "VERIFIED", "NONE"),
        ("foreground", "NOT_STARTED", "WRONG_FOREGROUND"),
        ("ack", "UNKNOWN_OUTCOME", "UNKNOWN_OUTCOME"),
    ],
)
def test_observe_action_agent_and_trace_preserve_structured_outcomes(
    tmp_path, fault, state, failure
):
    observer = Observer()
    receiver = Receiver(observer)
    session = WindowsActionSession(observer, receiver)
    engine = MagicMock(engine_id="fixture-model")
    turn = 0

    def generate(messages, **kwargs):
        nonlocal turn
        turn += 1
        if turn == 1:
            return response(
                {
                    "action": "windows_observe",
                    "action_input": {"hwnd": 100, "hints": {"automation_id": "201"}},
                }
            )
        if turn == 2:
            data = json.loads(messages[-1].content.removeprefix("Observation: "))
            if fault == "foreground":
                observer.backend.front = 999
            if fault == "ack":
                receiver.lost_ack = True
            return response(
                {
                    "action": "windows_action",
                    "action_input": {
                        "action": "click",
                        "observation_id": data["observation"]["observation_id"],
                        "target_id": data["target_id"],
                    },
                }
            )
        data = json.loads(messages[-1].content.removeprefix("Observation: "))
        assert data["outcome"] == state
        assert data["failure"] == failure
        assert data["retryable"] is False
        return response({"final_answer": "fixture result recorded"})

    engine.generate.side_effect = generate
    bus = EventBus(record_history=True)
    agent = NativeReActAgent(
        engine,
        "fixture-model",
        tools=[WindowsObserveTool(session), WindowsActionTool(session)],
        bus=bus,
        interactive=True,
        confirm_callback=lambda *_: True,
    )
    journal = ExecutionJournal(tmp_path / "journal.db")
    try:
        agent._executor.bind_execution_journal(journal, "fixture-boundary")
        collector = TraceCollector(agent, bus=bus)
        result = collector.run("Act once in the owned fixture")
        action = result.tool_results[-1]
        assert action.success is (state == "VERIFIED")
        assert action.metadata["execution"]["state"] == state
        assert action.metadata["windows"]["failure"] == failure
        steps = [
            step
            for step in collector.last_trace.steps
            if step.step_type == StepType.TOOL_CALL
        ]
        assert len(steps) == 2
        assert (
            steps[-1].metadata["windows"]["observation_id"]
            == steps[0].metadata["windows"]["observation"]["observation_id"]
        )
        assert steps[-1].metadata["windows"]["outcome"] == state
        assert steps[-1].metadata["execution"]["call_id"]
        assert receiver.calls == (0 if fault == "foreground" else 1)
        assert bool(journal.pending("fixture-boundary")) is (state == "UNKNOWN_OUTCOME")
    finally:
        journal.close()


def test_default_registry_tools_are_unbound_and_cannot_mutate():
    # The repository's autouse fixture clears registries after module imports.
    import importlib

    import openjarvis.tools.windows as module

    importlib.reload(module)
    assert ToolRegistry.get("windows_action") is module.WindowsActionTool
    result = WindowsActionTool().execute("click", "old", "target")
    assert not result.success
    assert result.metadata["windows"]["failure"] == "UNBOUND_APPLICATION"
    assert result.execution_state.value == "NOT_STARTED"


def test_confirmation_remains_required_before_windows_dispatch():
    session = MagicMock()
    result = ToolExecutor([WindowsActionTool(session)]).execute(
        ToolCall(
            "one",
            "windows_action",
            '{"action":"click","observation_id":"o","target_id":"t"}',
        )
    )
    assert not result.success
    session.act.assert_not_called()


def test_typing_value_is_reviewable_but_redacted_from_tool_trace_arguments():
    secret = "fixture-secret-canary"
    session = MagicMock()
    session.act.return_value = {
        "outcome": "VERIFIED",
        "verification": "VERIFIED",
        "dispatch": "DISPATCHED",
        "failure": "NONE",
        "retryable": False,
    }
    prompts = []
    bus = EventBus(record_history=True)
    collector = TraceCollector(MagicMock(), bus=bus)
    handlers = collector._subscribe()
    try:
        executor = ToolExecutor(
            [WindowsActionTool(session)],
            bus=bus,
            interactive=True,
            confirm_callback=lambda prompt: prompts.append(prompt) or True,
        )
        result = executor.execute(
            ToolCall(
                "one",
                "windows_action",
                json.dumps(
                    {
                        "action": "type_into",
                        "observation_id": "o",
                        "target_id": "t",
                        "value": secret,
                    }
                ),
            )
        )
        assert result.success
        assert secret in prompts[0]  # concrete approval must show the actual value
        assert session.act.call_args.kwargs["value"] == secret
        assert result.metadata["arguments"]["value"] == "[REDACTED]"
        assert secret not in repr(collector._current_steps)
        assert secret not in repr(
            [
                e.data
                for e in bus.history
                if e.event_type in (EventType.TOOL_CALL_START, EventType.TOOL_CALL_END)
            ]
        )
    finally:
        collector._unsubscribe(handlers)


def test_capacity_is_retryable_before_dispatch_and_visible_to_agent(monkeypatch):
    session = MagicMock()
    runner = MagicMock()
    runner.submit.return_value = None
    monkeypatch.setattr(_stubs, "_TOOL_RUNNER", runner)
    executor = ToolExecutor(
        [WindowsActionTool(session)], interactive=True, confirm_callback=lambda *_: True
    )
    result = executor.execute(
        ToolCall(
            "one",
            "windows_action",
            '{"action":"click","observation_id":"o","target_id":"t"}',
        )
    )
    assert result.metadata["execution"]["state"] == "NOT_STARTED"
    assert result.metadata["execution"]["failure"] == "CAPACITY"
    assert result.metadata["execution"]["retryable"] is True
    session.act.assert_not_called()


def test_windows_capabilities_require_explicit_observation_and_mutation_grants():
    from openjarvis.security.capabilities import CapabilityPolicy

    policy = CapabilityPolicy(default_deny=True)
    session = MagicMock()
    executor = ToolExecutor(
        [WindowsActionTool(session), WindowsObserveTool(session)],
        capability_policy=policy,
        agent_id="fixture-agent",
        interactive=True,
        confirm_callback=lambda *_: True,
    )
    observation = executor.execute(
        ToolCall("observe", "windows_observe", '{"hwnd":100}')
    )
    assert not observation.success
    session.observe.assert_not_called()
    policy.grant("fixture-agent", "desktop:observe")
    result = executor.execute(
        ToolCall(
            "mutate",
            "windows_action",
            '{"action":"click","observation_id":"o","target_id":"t"}',
        )
    )
    assert not result.success
    session.act.assert_not_called()
    policy.grant("fixture-agent", "desktop:mutate")
    session.act.return_value = {
        "outcome": "VERIFIED",
        "dispatch": "DISPATCHED",
        "verification": "VERIFIED",
        "failure": "NONE",
        "retryable": False,
    }
    assert executor.execute(
        ToolCall(
            "allowed",
            "windows_action",
            '{"action":"click","observation_id":"o","target_id":"t"}',
        )
    ).success
    session.act.assert_called_once()
