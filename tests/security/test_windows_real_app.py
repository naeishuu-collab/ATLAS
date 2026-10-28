"""Production-bound receiver tests against a disposable non-cooperative app."""

import json
import os
import time

import pytest

from openjarvis.windows.actions import WindowsActionSession
from openjarvis.windows.identity import IdentityError
from openjarvis.windows.observer import WindowsObserver
from openjarvis.windows.receiver import NativeBoundWin32Receiver
from tests.security.real_app_fixture import RealAppProcess

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Win32 real app")


def _bounded_diagnostic_value(value, *, limit: int = 4096):
    """Keep failure diagnostics JSON-safe and scoped to test-owned data."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, dict):
        return {
            str(key): _bounded_diagnostic_value(item, limit=limit)
            for key, item in list(value.items())[:64]
        }
    if isinstance(value, (list, tuple)):
        return [_bounded_diagnostic_value(item, limit=limit) for item in value[:64]]
    return str(value)[:limit]


def _spark_failure_diagnostic(
    result,
    bus,
    app,
    journal,
    scope: str,
    *,
    wall_time_seconds: float,
    error: BaseException | None = None,
) -> dict:
    """Collect existing Agent/tool/event state without changing execution."""
    from openjarvis.core.events import EventType

    model_turns = []
    tool_events = []
    turn = 0
    for event in bus.history:
        if event.event_type == EventType.INFERENCE_END:
            turn += 1
            data = event.data
            calls = data.get("tool_calls") or []
            model_turns.append(
                {
                    "turn": turn,
                    "response_type": "native_tool_call" if calls else "text",
                    "content": _bounded_diagnostic_value(data.get("content", "")),
                    "tool_calls": _bounded_diagnostic_value(calls),
                    "finish_reason": data.get("finish_reason"),
                    "usage": _bounded_diagnostic_value(data.get("usage", {})),
                }
            )
        elif event.event_type == EventType.TOOL_CALL_START:
            tool_events.append(
                {
                    "turn": turn,
                    "phase": "start",
                    "tool": event.data.get("tool"),
                    "call_id": event.data.get("call_id"),
                    "arguments": _bounded_diagnostic_value(
                        event.data.get("arguments", {})
                    ),
                }
            )
        elif event.event_type == EventType.TOOL_CALL_END:
            tool_events.append(
                {
                    "turn": turn,
                    "phase": "end",
                    "tool": event.data.get("tool"),
                    "call_id": event.data.get("call_id"),
                    "success": event.data.get("success"),
                    "result": _bounded_diagnostic_value(event.data.get("result", "")),
                    "metadata": _bounded_diagnostic_value(
                        event.data.get("metadata", {})
                    ),
                }
            )

    result_metadata = getattr(result, "metadata", {}) or {}
    tool_results = []
    for item in getattr(result, "tool_results", []) if result is not None else []:
        execution = item.metadata.get("execution", {}) or {}
        windows = item.metadata.get("windows", {}) or {}
        tool_results.append(
            {
                "tool": item.tool_name,
                "call_id": execution.get("call_id"),
                "arguments": _bounded_diagnostic_value(
                    item.metadata.get("arguments", {})
                ),
                "content": _bounded_diagnostic_value(item.content),
                "success": item.success,
                "execution": _bounded_diagnostic_value(execution),
                "mutation_state": execution.get("state"),
                "dispatch": windows.get("dispatch"),
                "outcome": windows.get("outcome"),
                "verification": windows.get("verification"),
                "retryable": windows.get("retryable", execution.get("retryable")),
                "windows": _bounded_diagnostic_value(windows),
            }
        )

    try:
        state = app.state()
        helper_state = {
            key: state[key]
            for key in (
                "text",
                "dispatch_count",
                "wrong_target_dispatch_count",
                "replay_count",
                "hwnd",
                "control_hwnd",
            )
            if key in state
        }
    except Exception as exc:
        helper_state = {"error": f"{type(exc).__name__}: {exc}"[:1000]}

    try:
        journal_pending = _bounded_diagnostic_value(journal.pending(scope))
    except Exception as exc:
        journal_pending = {"error": f"{type(exc).__name__}: {exc}"[:1000]}

    max_turns_exceeded = bool(result_metadata.get("max_turns_exceeded"))
    terminal_reason = result_metadata.get("terminal_reason")
    if terminal_reason is None and max_turns_exceeded:
        terminal_reason = "MAX_TURNS_EXCEEDED"

    return {
        "schema_version": 1,
        "wall_time_seconds": wall_time_seconds,
        "model_turns": model_turns,
        "tool_events": tool_events,
        "tool_results": tool_results,
        "agent_result": (
            {
                "content": _bounded_diagnostic_value(result.content),
                "turns": result.turns,
                "max_turns_exceeded": max_turns_exceeded,
                "terminal_reason": terminal_reason,
                "response_parse_error": result_metadata.get("response_parse_error"),
                "messages": _bounded_diagnostic_value(
                    result_metadata.get("messages", [])
                ),
            }
            if result is not None
            else None
        ),
        "helper_state": helper_state,
        "journal_pending": journal_pending,
        "error": (
            {"type": type(error).__name__, "message": str(error)[:2000]}
            if error is not None
            else None
        ),
    }


def _session(app):
    observer = WindowsObserver(timeout=15)
    receiver = NativeBoundWin32Receiver(
        hwnd=app.hwnd,
        control_hwnd=app.control_hwnd,
        executable=app.executable,
        window_class=app.window_class,
    )
    return observer, receiver, WindowsActionSession(observer, receiver)


def _target(session, app):
    observation = session.observe(app.hwnd)
    target_id = session.resolve(
        observation["observation_id"],
        control_type=50004,
        class_name="Edit",
    )
    return observation, target_id


def test_real_app_type_into_is_one_dispatch_with_independent_readback():
    with RealAppProcess() as app:
        observer, receiver, session = _session(app)
        try:
            app.focus()
            observation, target_id = _target(session, app)
            result = session.act(
                "type_into",
                observation["observation_id"],
                target_id,
                value="ASTRA_REAL_APP_CANARY",
            )
            assert result["outcome"] == "VERIFIED", json.dumps(result, indent=2)
            assert result["dispatch"] == "DISPATCHED"
            assert result["verification"] == "VERIFIED"
            state = app.state()
            assert state["text"] == "ASTRA_REAL_APP_CANARY"
            assert state["dispatch_count"] == 1
        finally:
            receiver.close()
            observer.close()


def test_wrong_foreground_rejects_before_physical_dispatch():
    with RealAppProcess() as app, RealAppProcess() as other:
        observer, receiver, session = _session(app)
        try:
            app.focus()
            observation, target_id = _target(session, app)
            other.focus()
            result = session.act(
                "type_into",
                observation["observation_id"],
                target_id,
                value="must-not-enter",
            )
            assert result["outcome"] == "NOT_STARTED", result
            assert result["failure"] == "WRONG_FOREGROUND"
            assert result["dispatch"] == "NOT_DISPATCHED"
            assert app.state()["dispatch_count"] == 0
            assert other.state()["dispatch_count"] == 0
        finally:
            receiver.close()
            observer.close()


def test_replaced_control_rejects_stale_target_without_dispatch():
    with RealAppProcess() as app:
        observer, receiver, session = _session(app)
        try:
            app.focus()
            observation, target_id = _target(session, app)
            old_control = app.control_hwnd
            app.rpc("replace")
            assert app.state()["control_hwnd"] != old_control
            result = session.act(
                "type_into",
                observation["observation_id"],
                target_id,
                value="stale-control",
            )
            assert result["outcome"] == "NOT_STARTED", result
            assert result["failure"] in {"STALE_TARGET", "IDENTITY_MISMATCH"}
            assert result["dispatch"] == "NOT_DISPATCHED"
            assert app.state()["dispatch_count"] == 0
        finally:
            receiver.close()
            observer.close()


def test_recreated_window_rejects_old_authorization_without_dispatch():
    with RealAppProcess() as app:
        observer, receiver, session = _session(app)
        try:
            app.focus()
            observation, target_id = _target(session, app)
            old_window = app.hwnd
            state = app.rpc("recreate")
            app.hwnd = state["hwnd"]
            app.control_hwnd = state["control_hwnd"]
            assert app.hwnd != old_window
            result = session.act(
                "type_into",
                observation["observation_id"],
                target_id,
                value="stale-window",
            )
            assert result["outcome"] == "NOT_STARTED", result
            assert result["failure"] in {"STALE_TARGET", "IDENTITY_MISMATCH"}
            assert result["dispatch"] == "NOT_DISPATCHED"
            assert app.state()["dispatch_count"] == 0
        finally:
            receiver.close()
            observer.close()


def test_ambiguous_edit_resolution_fails_closed():
    with RealAppProcess() as app:
        observer, receiver, session = _session(app)
        try:
            app.focus()
            app.rpc("duplicate")
            observation = session.observe(app.hwnd)
            with pytest.raises(IdentityError, match="2 matches"):
                session.resolve(
                    observation["observation_id"],
                    control_type=50004,
                    class_name="Edit",
                )
            assert app.state()["dispatch_count"] == 0
        finally:
            receiver.close()
            observer.close()


def test_process_restart_rejects_old_authorization_without_dispatch():
    app = RealAppProcess()
    observer, receiver, session = _session(app)
    try:
        app.focus()
        observation, target_id = _target(session, app)
        app.close()
        with RealAppProcess() as restarted:
            result = session.act(
                "type_into",
                observation["observation_id"],
                target_id,
                value="old-process",
            )
            assert result["outcome"] == "NOT_STARTED", result
            assert result["failure"] in {"STALE_TARGET", "IDENTITY_MISMATCH"}
            assert result["dispatch"] == "NOT_DISPATCHED"
            assert restarted.state()["dispatch_count"] == 0
    finally:
        receiver.close()
        observer.close()


def test_acknowledgement_loss_is_unknown_and_never_replayed():
    with RealAppProcess() as app:
        observer, receiver, session = _session(app)
        try:
            app.focus()
            observation, target_id = _target(session, app)
            dispatch = receiver.dispatch

            def lose_ack(request):
                acknowledgement = dispatch(request)
                assert acknowledgement["dispatched"] is True
                raise OSError("controlled acknowledgement loss")

            receiver.dispatch = lose_ack
            result = session.act(
                "type_into",
                observation["observation_id"],
                target_id,
                value="unknown-outcome",
            )
            assert result["outcome"] == "UNKNOWN_OUTCOME", result
            assert result["failure"] == "UNKNOWN_OUTCOME"
            assert app.state()["dispatch_count"] == 1
            replay = session.act(
                "type_into",
                observation["observation_id"],
                target_id,
                value="unknown-outcome",
            )
            assert replay["outcome"] == "NOT_STARTED", replay
            assert app.state()["dispatch_count"] == 1
        finally:
            receiver.close()
            observer.close()


def test_scripted_managed_agent_uses_real_app_receiver_once(tmp_path):
    from unittest.mock import MagicMock

    from openjarvis.agents.native_react import NativeReActAgent
    from openjarvis.core.events import EventBus
    from openjarvis.core.types import StepType
    from openjarvis.tools.execution_journal import ExecutionJournal
    from openjarvis.tools.windows import WindowsActionTool, WindowsObserveTool
    from openjarvis.traces.collector import TraceCollector

    with RealAppProcess() as app:
        observer, receiver, session = _session(app)
        journal = ExecutionJournal(tmp_path / "real-app-agent.db")
        try:
            app.focus()
            engine = MagicMock(engine_id="scripted-real-app")
            turn = 0

            def generate(messages, **kwargs):
                nonlocal turn
                turn += 1
                if turn == 1:
                    data = {
                        "action": "windows_observe",
                        "action_input": {
                            "hwnd": app.hwnd,
                            "hints": {"control_type": 50004, "class_name": "Edit"},
                        },
                    }
                elif turn == 2:
                    observed = json.loads(
                        messages[-1].content.removeprefix("Observation: ")
                    )
                    data = {
                        "action": "windows_action",
                        "action_input": {
                            "action": "type_into",
                            "observation_id": observed["observation"]["observation_id"],
                            "target_id": observed["target_id"],
                            "value": "ASTRA_SCRIPTED_AGENT_CANARY",
                        },
                    }
                else:
                    actual = json.loads(
                        messages[-1].content.removeprefix("Observation: ")
                    )
                    assert actual["outcome"] == actual["verification"] == "VERIFIED"
                    assert actual["dispatch"] == "DISPATCHED"
                    data = {"final_answer": "Real app mutation verified"}
                return {
                    "content": json.dumps(data),
                    "usage": {},
                    "model": "scripted-real-app",
                    "finish_reason": "stop",
                }

            engine.generate.side_effect = generate
            bus = EventBus(record_history=True)
            agent = NativeReActAgent(
                engine,
                "scripted-real-app",
                tools=[WindowsObserveTool(session), WindowsActionTool(session)],
                bus=bus,
                interactive=True,
                confirm_callback=lambda *_: True,
            )
            agent._executor.bind_execution_journal(journal, "real-app-agent")
            collector = TraceCollector(agent, bus=bus)
            result = collector.run("Type the supplied canary into the owned editor")
            assert result.tool_results[-1].success
            assert result.tool_results[-1].metadata["execution"]["state"] == "VERIFIED"
            assert app.state()["text"] == "ASTRA_SCRIPTED_AGENT_CANARY"
            assert app.state()["dispatch_count"] == 1
            steps = [
                step
                for step in collector.last_trace.steps
                if step.step_type == StepType.TOOL_CALL
            ]
            assert len(steps) == 2
            assert journal.pending("real-app-agent") == []
        finally:
            journal.close()
            receiver.close()
            observer.close()


def test_scripted_managed_agent_multi_step_reauthorizes_each_mutation(tmp_path):
    from unittest.mock import MagicMock

    from openjarvis.agents.native_react import NativeReActAgent
    from openjarvis.core.events import EventBus
    from openjarvis.core.types import StepType
    from openjarvis.tools.execution_journal import ExecutionJournal
    from openjarvis.tools.windows import WindowsActionTool, WindowsObserveTool
    from openjarvis.traces.collector import TraceCollector

    with RealAppProcess() as app:
        observer, receiver, session = _session(app)
        journal = ExecutionJournal(tmp_path / "real-app-agent-multistep.db")
        try:
            app.focus()
            engine = MagicMock(engine_id="scripted-real-app-multistep")
            turn = 0
            observations = []
            actions = []

            def generate(messages, **kwargs):
                nonlocal turn
                turn += 1
                if turn == 1:
                    data = {
                        "action": "windows_observe",
                        "action_input": {
                            "hwnd": app.hwnd,
                            "hints": {"control_type": 50004, "class_name": "Edit"},
                        },
                    }
                elif turn == 2:
                    observed = json.loads(
                        messages[-1].content.removeprefix("Observation: ")
                    )
                    observations.append(observed)
                    data = {
                        "action": "windows_action",
                        "action_input": {
                            "action": "type_into",
                            "observation_id": observed["observation"][
                                "observation_id"
                            ],
                            "target_id": observed["target_id"],
                            "value": "ASTRA_SCRIPTED_AGENT_CANARY_A",
                        },
                    }
                elif turn == 3:
                    action_result = json.loads(
                        messages[-1].content.removeprefix("Observation: ")
                    )
                    actions.append(action_result)
                    assert action_result["outcome"] == "VERIFIED"
                    assert action_result["dispatch"] == "DISPATCHED"
                    data = {
                        "action": "windows_observe",
                        "action_input": {
                            "hwnd": app.hwnd,
                            "hints": {"control_type": 50004, "class_name": "Edit"},
                        },
                    }
                elif turn == 4:
                    observed = json.loads(
                        messages[-1].content.removeprefix("Observation: ")
                    )
                    observations.append(observed)
                    assert observations[0]["observation"][
                        "observation_id"
                    ] != observed["observation"]["observation_id"]
                    data = {
                        "action": "windows_action",
                        "action_input": {
                            "action": "type_into",
                            "observation_id": observed["observation"][
                                "observation_id"
                            ],
                            "target_id": observed["target_id"],
                            "value": "ASTRA_SCRIPTED_AGENT_CANARY_B",
                        },
                    }
                elif turn == 5:
                    action_result = json.loads(
                        messages[-1].content.removeprefix("Observation: ")
                    )
                    actions.append(action_result)
                    assert action_result["outcome"] == "VERIFIED"
                    assert action_result["dispatch"] == "DISPATCHED"
                    data = {"final_answer": "Two real app mutations verified"}
                else:
                    raise AssertionError(f"unexpected scripted turn {turn}")
                return {
                    "content": json.dumps(data),
                    "usage": {},
                    "model": "scripted-real-app-multistep",
                    "finish_reason": "stop",
                }

            engine.generate.side_effect = generate
            bus = EventBus(record_history=True)
            agent = NativeReActAgent(
                engine,
                "scripted-real-app-multistep",
                tools=[WindowsObserveTool(session), WindowsActionTool(session)],
                bus=bus,
                interactive=True,
                confirm_callback=lambda *_: True,
            )
            agent._executor.bind_execution_journal(
                journal, "real-app-agent-multistep"
            )
            collector = TraceCollector(agent, bus=bus)
            result = collector.run(
                "Type canary A, observe again, then type canary B into the owned editor"
            )
            assert result.content == "Two real app mutations verified"
            assert [item.execution_state.value for item in result.tool_results] == [
                "EXECUTED",
                "VERIFIED",
                "EXECUTED",
                "VERIFIED",
            ]
            assert len(actions) == 2
            assert all(
                item["evidence"].get("post_observation_id") for item in actions
            )
            assert app.state()["text"] == "ASTRA_SCRIPTED_AGENT_CANARY_B"
            assert app.state()["dispatch_count"] == 2
            steps = [
                step
                for step in collector.last_trace.steps
                if step.step_type == StepType.TOOL_CALL
            ]
            assert len(steps) == 4
            assert journal.pending("real-app-agent-multistep") == []
        finally:
            journal.close()
            receiver.close()
            observer.close()


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("ASTRA_RUN_SPARK_REAL_APP") != "1",
    reason="Explicit live Spark real-app run required",
)
def test_spark_managed_agent_real_app_uses_safety_boundary(tmp_path):
    from openjarvis.agents.native_react import NativeReActAgent
    from openjarvis.core.events import EventBus
    from openjarvis.engine.ollama import OllamaEngine
    from openjarvis.tools.execution_journal import ExecutionJournal
    from openjarvis.tools.windows import WindowsActionTool, WindowsObserveTool

    model = "SparkLLM/Spark-X2.5-4B:latest"
    with RealAppProcess() as app:
        observer, receiver, session = _session(app)
        journal = ExecutionJournal(tmp_path / "spark-real-app-agent.db")
        try:
            app.focus()
            engine = OllamaEngine(timeout=180)
            agent = NativeReActAgent(
                engine,
                model,
                tools=[WindowsObserveTool(session), WindowsActionTool(session)],
                bus=EventBus(record_history=True),
                max_turns=4,
                max_tokens=256,
                temperature=0.0,
                interactive=True,
                confirm_callback=lambda *_: True,
            )
            agent._executor.bind_execution_journal(journal, "spark-real-app-agent")
            result = None
            started = time.perf_counter()
            try:
                result = agent.run(
                    "Use windows_observe on the supplied test window with "
                    "control_type 50004 and class_name Edit. Then use the returned "
                    "target exactly once with windows_action type_into and value "
                    "ASTRA_SPARK_REAL_APP_CANARY. Finish only after the verified "
                    "result; do not use any other tool. Window HWND is "
                    f"{app.hwnd}."
                )
                assert app.state()["text"] == "ASTRA_SPARK_REAL_APP_CANARY"
                assert app.state()["dispatch_count"] == 1
                assert any(
                    tool.metadata.get("execution", {}).get("state") == "VERIFIED"
                    for tool in result.tool_results
                )
            except Exception as exc:
                diagnostic = _spark_failure_diagnostic(
                    result,
                    agent._bus,
                    app,
                    journal,
                    "spark-real-app-agent",
                    wall_time_seconds=time.perf_counter() - started,
                    error=exc,
                )
                raise AssertionError(
                    "Spark Real App structured diagnostic:\n"
                    + json.dumps(diagnostic, ensure_ascii=False, indent=2, default=str)
                ) from exc
        finally:
            journal.close()
            receiver.close()
            observer.close()
