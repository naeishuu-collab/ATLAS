"""Production managed-agent cancellation, deadline, and restart boundaries."""

from __future__ import annotations

import sqlite3
import threading
import time

import pytest

from openjarvis.agents.errors import RetryableError
from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.orchestrator import OrchestratorAgent
from openjarvis.core.events import EventBus
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import AgentRegistry, ToolRegistry
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec
from openjarvis.tools.execution_journal import ExecutionJournal
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem


def _register(tool: type[BaseTool]) -> None:
    if not AgentRegistry.contains("orchestrator"):
        AgentRegistry.register_value("orchestrator", OrchestratorAgent)
    if not ToolRegistry.contains(tool.tool_id):
        ToolRegistry.register_value(tool.tool_id, tool)


def _new_agent(
    manager: AgentManager,
    name: str,
    *,
    tool: type[BaseTool] | None = None,
    overall_timeout_seconds: float | None = None,
) -> dict:
    if not AgentRegistry.contains("orchestrator"):
        AgentRegistry.register_value("orchestrator", OrchestratorAgent)
    config = {
        "model": "fake-model",
        "instruction": "Continue safely from the checkpoint.",
        "tools": [tool.tool_id] if tool else [],
    }
    if overall_timeout_seconds is not None:
        config["overall_timeout_seconds"] = overall_timeout_seconds
    return manager.create_agent(name, agent_type="orchestrator", config=config)


def _execute(manager: AgentManager, agent_id: str, engine: FakeEngine) -> None:
    executor = AgentExecutor(manager, EventBus(), system=FakeSystem(engine))
    executor.execute_tick(agent_id)


def _tool_call(tool_name: str, call_id: str = "mutation-call") -> dict:
    return {"tool_calls": [{"id": call_id, "name": tool_name, "arguments": "{}"}]}


class _BlockingMutation(BaseTool):
    tool_id = "cancel_blocking_verified"
    calls = 0
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    result_state = ExecutionState.VERIFIED

    @property
    def spec(self):
        return ToolSpec(
            self.tool_id,
            "blocking cancellation fixture mutation",
            effect=ToolEffect.MUTATING,
            timeout_seconds=3,
        )

    def execute(self, **params):
        type(self).calls += 1
        type(self).started.set()
        try:
            assert type(self).release.wait(4)
            return ToolResult(
                self.tool_id,
                "mutation-result",
                execution_state=type(self).result_state,
            )
        finally:
            type(self).finished.set()


class _TimeoutMutation(BaseTool):
    tool_id = "cancel_timeout_mutation"
    calls = 0
    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    @property
    def spec(self):
        return ToolSpec(
            self.tool_id,
            "blocking timeout fixture mutation",
            effect=ToolEffect.MUTATING,
            timeout_seconds=0.04,
        )

    def execute(self, **params):
        type(self).calls += 1
        type(self).started.set()
        try:
            assert type(self).release.wait(4)
            return ToolResult(self.tool_id, "late result")
        finally:
            type(self).finished.set()


class _BlockingEngine(FakeEngine):
    def __init__(self, responses: list[dict]):
        super().__init__(responses)
        self.started = threading.Event()
        self.release = threading.Event()

    def generate(self, messages, *, model, **kwargs):
        self.started.set()
        assert self.release.wait(4)
        return super().generate(messages, model=model, **kwargs)


def _reset_blocking_tool(tool: type[_BlockingMutation]) -> None:
    tool.calls = 0
    tool.started = threading.Event()
    tool.release = threading.Event()
    tool.finished = threading.Event()
    tool.result_state = ExecutionState.VERIFIED


def _run_thread(manager: AgentManager, agent_id: str, engine: FakeEngine):
    errors: list[BaseException] = []

    def run():
        try:
            _execute(manager, agent_id, engine)
        except BaseException as exc:  # surfaced in the test thread
            errors.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, errors


def test_cancel_before_dispatch_gate_records_not_started(tmp_path):
    journal = ExecutionJournal(tmp_path / "cancel-gate.db")
    _reset_blocking_tool(_BlockingMutation)
    tool = _BlockingMutation()
    executor = ToolExecutor(
        [tool], execution_journal=journal, execution_scope="agent-a"
    )

    def checkpoint(state, _result):
        if state == "PREPARED":
            journal.request_cancellation("agent-a", reason="user")

    try:
        result = executor.execute(
            ToolCall("before-cancel", tool.tool_id, "{}"),
            checkpoint_callback=checkpoint,
        )
        assert result.metadata["execution"]["state"] == "NOT_STARTED"
        assert result.metadata["cancelled"] is True
        assert tool.calls == 0
        assert journal.pending("agent-a") == []
        assert (
            journal.reconciliation("agent-a", tool.tool_id, "before-cancel")[
                "resolution"
            ]
            == "NOT_EXECUTED"
        )
    finally:
        journal.close()


def test_dispatch_gate_wins_race_without_interrupting_mutation(tmp_path):
    journal = ExecutionJournal(tmp_path / "dispatch-wins.db")
    _reset_blocking_tool(_BlockingMutation)
    _BlockingMutation.release.set()
    tool = _BlockingMutation()
    executor = ToolExecutor(
        [tool], execution_journal=journal, execution_scope="agent-a"
    )

    def checkpoint(state, _result):
        if state == "EXECUTING":
            # This callback runs after the atomic gate committed but before
            # the worker is submitted. The accepted operation must complete.
            journal.request_cancellation("agent-a", reason="user")

    try:
        result = executor.execute(
            ToolCall("gate-won", tool.tool_id, "{}"),
            checkpoint_callback=checkpoint,
        )
        assert result.success
        assert result.metadata["execution"]["state"] == "VERIFIED"
        assert tool.calls == 1
        assert journal.cancellation_state("agent-a")["state"] == "REQUESTED"
        assert journal.pending("agent-a") == []
    finally:
        journal.close()


def test_cancel_racing_terminal_checkpoint_prevents_idle_completion(
    tmp_path, monkeypatch
):
    manager = AgentManager(str(tmp_path / "cancel-terminal-race.db"))
    agent = _new_agent(manager, "cancel-terminal-race")
    engine = FakeEngine([{"content": "finished"}])
    complete = manager.complete_tick_if_not_cancelled

    def cancel_after_checkpoint(agent_id):
        manager.request_cancellation(agent_id, reason="user")
        return complete(agent_id)

    monkeypatch.setattr(
        manager, "complete_tick_if_not_cancelled", cancel_after_checkpoint
    )
    try:
        _execute(manager, agent["id"], engine)
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint["conversation_state"]["lifecycle"] == "CANCELLED"
        assert checkpoint["tool_state"]["cancellation"]["state"] == "TERMINALIZED"
        assert manager.get_agent(agent["id"])["status"] == "paused"
        assert engine.call_count == 1
    finally:
        manager.close()


def test_cancel_during_verified_mutation_is_cooperative_and_per_agent(tmp_path):
    _register(_BlockingMutation)
    _reset_blocking_tool(_BlockingMutation)
    manager = AgentManager(str(tmp_path / "cancel-isolation.db"))
    first = _new_agent(manager, "cancelled", tool=_BlockingMutation)
    second = _new_agent(manager, "unrelated")
    first_engine = FakeEngine(
        [_tool_call(_BlockingMutation.tool_id), {"content": "done"}]
    )
    second_engine = FakeEngine([{"content": "unaffected"}])
    thread, errors = _run_thread(manager, first["id"], first_engine)
    try:
        assert _BlockingMutation.started.wait(2)
        cancellation = manager.request_cancellation(first["id"], reason="user")
        assert cancellation["state"] == "REQUESTED"
        assert thread.is_alive()  # the in-flight physical operation was not killed

        _execute(manager, second["id"], second_engine)
        assert second_engine.call_count == 1
        assert manager.get_agent(second["id"])["status"] == "idle"

        _BlockingMutation.release.set()
        thread.join(3)
        assert not thread.is_alive()
        assert errors == []
        assert _BlockingMutation.calls == 1
        assert manager.get_agent(first["id"])["status"] == "paused"
        checkpoint = manager.get_latest_checkpoint(first["id"])
        assert checkpoint["conversation_state"]["lifecycle"] == "CANCELLED"
        assert checkpoint["tool_state"]["cancellation"]["state"] == "TERMINALIZED"
        assert manager.execution_journal.pending(first["id"]) == []
    finally:
        _BlockingMutation.release.set()
        thread.join(2)
        manager.close()

    restarted = AgentManager(
        str(tmp_path / "cancel-isolation.db"), clear_stale_running=True
    )
    no_resume_engine = FakeEngine([{"content": "must not resume"}])
    try:
        _execute(restarted, first["id"], no_resume_engine)
        assert no_resume_engine.call_count == 0
        assert _BlockingMutation.calls == 1
        assert restarted.get_agent(first["id"])["status"] == "paused"
    finally:
        restarted.close()


def test_archive_during_mutation_waits_for_safe_boundary_and_stays_terminal(tmp_path):
    _register(_BlockingMutation)
    _reset_blocking_tool(_BlockingMutation)
    db_path = str(tmp_path / "archive-running.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, "archive-running", tool=_BlockingMutation)
    engine = FakeEngine(
        [_tool_call(_BlockingMutation.tool_id), {"content": "must not continue"}]
    )
    thread, errors = _run_thread(manager, agent["id"], engine)
    try:
        assert _BlockingMutation.started.wait(2)

        cancellation = manager.delete_agent(agent["id"])

        assert cancellation["reason"] == "archive"
        assert manager.get_agent(agent["id"])["status"] == "running"
        assert thread.is_alive()
        _BlockingMutation.release.set()
        thread.join(3)

        assert not thread.is_alive()
        assert errors == []
        assert _BlockingMutation.calls == 1
        assert engine.call_count == 1
        assert manager.get_agent(agent["id"])["status"] == "archived"
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint["conversation_state"]["lifecycle"] == "CANCELLED"
        assert checkpoint["tool_state"]["cancellation"]["reason"] == "archive"
        assert checkpoint["tool_state"]["cancellation"]["state"] == "TERMINALIZED"
        assert manager.execution_journal.pending(agent["id"]) == []
        with pytest.raises(ValueError, match="archived"):
            manager.resume_agent(agent["id"])
    finally:
        _BlockingMutation.release.set()
        thread.join(2)
        manager.close()


def test_cancel_before_mutation_verification_requires_reconciliation(tmp_path):
    _register(_BlockingMutation)
    _reset_blocking_tool(_BlockingMutation)
    _BlockingMutation.result_state = ExecutionState.EXECUTED
    manager = AgentManager(str(tmp_path / "cancel-unverified.db"))
    agent = _new_agent(manager, "unverified-cancel", tool=_BlockingMutation)
    engine = FakeEngine([_tool_call(_BlockingMutation.tool_id)])
    thread, errors = _run_thread(manager, agent["id"], engine)
    try:
        assert _BlockingMutation.started.wait(2)
        manager.request_cancellation(agent["id"], reason="user")
        _BlockingMutation.release.set()
        thread.join(3)
        assert not thread.is_alive()
        assert errors == []
        assert _BlockingMutation.calls == 1
        assert manager.get_agent(agent["id"])["status"] == "needs_attention"
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint["conversation_state"]["lifecycle"] == "RECOVERY_REQUIRED"
        assert checkpoint["tool_state"]["recovery"]["required"] is True
        assert manager.execution_journal.pending(agent["id"])[0]["state"] == "EXECUTED"
    finally:
        _BlockingMutation.release.set()
        thread.join(2)
        manager.close()

    restarted = AgentManager(
        str(tmp_path / "cancel-unverified.db"), clear_stale_running=True
    )
    restarted.recover_agent(agent["id"])
    no_replay_engine = FakeEngine([{"content": "must reconcile first"}])
    try:
        _execute(restarted, agent["id"], no_replay_engine)
        assert no_replay_engine.call_count == 0
        assert _BlockingMutation.calls == 1
        assert (
            restarted.execution_journal.pending(agent["id"])[0]["state"] == "EXECUTED"
        )
    finally:
        restarted.close()


def test_overall_deadline_before_mutation_is_checkpointed_across_restart(tmp_path):
    _register(_BlockingMutation)
    _reset_blocking_tool(_BlockingMutation)
    manager = AgentManager(str(tmp_path / "deadline-before.db"))
    agent = _new_agent(
        manager,
        "deadline-before",
        tool=_BlockingMutation,
        overall_timeout_seconds=1.0,
    )
    engine = _BlockingEngine([_tool_call(_BlockingMutation.tool_id)])
    thread, errors = _run_thread(manager, agent["id"], engine)
    try:
        assert engine.started.wait(2)
        deadline = time.monotonic() + 2
        while (
            manager.cancellation_state(agent["id"]) is None
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert manager.cancellation_state(agent["id"])["reason"] == "deadline"
        engine.release.set()
        thread.join(3)
        assert not thread.is_alive()
        assert errors == []
        assert _BlockingMutation.calls == 0
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint["conversation_state"]["lifecycle"] == "TIMED_OUT"
        assert checkpoint["conversation_state"]["deadline_at"] > 0
        assert checkpoint["tool_state"]["cancellation"]["timeout_kind"] == (
            "overall_task_deadline"
        )
        assert manager.get_agent(agent["id"])["status"] == "paused"
    finally:
        engine.release.set()
        thread.join(2)
        manager.close()

    restarted = AgentManager(
        str(tmp_path / "deadline-before.db"), clear_stale_running=True
    )
    no_resume_engine = FakeEngine([_tool_call(_BlockingMutation.tool_id)])
    try:
        _execute(restarted, agent["id"], no_resume_engine)
        assert no_resume_engine.call_count == 0
        assert _BlockingMutation.calls == 0
    finally:
        restarted.close()


def test_overall_deadline_during_mutation_waits_for_verified_boundary(tmp_path):
    _register(_BlockingMutation)
    _reset_blocking_tool(_BlockingMutation)
    manager = AgentManager(str(tmp_path / "deadline-during.db"))
    agent = _new_agent(
        manager,
        "deadline-during",
        tool=_BlockingMutation,
        overall_timeout_seconds=1.0,
    )
    engine = FakeEngine([_tool_call(_BlockingMutation.tool_id)])
    thread, errors = _run_thread(manager, agent["id"], engine)
    try:
        assert _BlockingMutation.started.wait(2)
        deadline = time.monotonic() + 2
        while (
            manager.cancellation_state(agent["id"]) is None
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert thread.is_alive()
        assert _BlockingMutation.finished.is_set() is False
        _BlockingMutation.release.set()
        thread.join(3)
        assert not thread.is_alive()
        assert errors == []
        assert _BlockingMutation.calls == 1
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint["conversation_state"]["lifecycle"] == "TIMED_OUT"
        assert checkpoint["tool_state"]["active_step"]["execution_state"] == "VERIFIED"
    finally:
        _BlockingMutation.release.set()
        thread.join(2)
        manager.close()


def test_tool_timeout_after_possible_mutation_is_unknown_and_survives_restart(tmp_path):
    _register(_TimeoutMutation)
    _TimeoutMutation.calls = 0
    _TimeoutMutation.started = threading.Event()
    _TimeoutMutation.release = threading.Event()
    _TimeoutMutation.finished = threading.Event()
    manager = AgentManager(str(tmp_path / "timeout-mutation.db"))
    agent = _new_agent(manager, "timeout-mutation", tool=_TimeoutMutation)
    engine = FakeEngine([_tool_call(_TimeoutMutation.tool_id)])
    try:
        _execute(manager, agent["id"], engine)
        assert _TimeoutMutation.started.is_set()
        assert not _TimeoutMutation.finished.is_set()
        assert _TimeoutMutation.calls == 1
        assert manager.get_agent(agent["id"])["status"] == "needs_attention"
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint["tool_state"]["active_step"]["execution_state"] == (
            "UNKNOWN_OUTCOME"
        )
        assert checkpoint["tool_state"]["active_step"]["timeout"]["kind"] == (
            "physical_mutation"
        )
        assert manager.execution_journal.pending(agent["id"])[0]["state"] == (
            "UNKNOWN_OUTCOME"
        )
    finally:
        _TimeoutMutation.release.set()
        assert _TimeoutMutation.finished.wait(2)
        manager.close()

    restarted = AgentManager(
        str(tmp_path / "timeout-mutation.db"), clear_stale_running=True
    )
    restarted.recover_agent(agent["id"])
    no_replay_engine = FakeEngine([{"content": "must reconcile first"}])
    try:
        _execute(restarted, agent["id"], no_replay_engine)
        assert no_replay_engine.call_count == 0
        assert _TimeoutMutation.calls == 1
        assert restarted.execution_journal.pending(agent["id"])[0]["state"] == (
            "UNKNOWN_OUTCOME"
        )
    finally:
        restarted.close()


def test_cancel_during_unknown_timeout_preserves_reconciliation_on_restart(
    tmp_path,
):
    _register(_TimeoutMutation)
    _TimeoutMutation.calls = 0
    _TimeoutMutation.started = threading.Event()
    _TimeoutMutation.release = threading.Event()
    _TimeoutMutation.finished = threading.Event()
    db_path = str(tmp_path / "cancel-unknown-timeout.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, "cancel-unknown-timeout", tool=_TimeoutMutation)
    engine = FakeEngine([_tool_call(_TimeoutMutation.tool_id)])
    thread, errors = _run_thread(manager, agent["id"], engine)
    try:
        assert _TimeoutMutation.started.wait(2)
        cancellation = manager.request_cancellation(agent["id"], reason="user")
        assert cancellation["state"] == "REQUESTED"
        thread.join(2)
        assert not thread.is_alive()
        assert errors == []
        assert _TimeoutMutation.calls == 1
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint["conversation_state"]["lifecycle"] == "RECOVERY_REQUIRED"
        assert checkpoint["tool_state"]["cancellation"]["state"] == "REQUESTED"
        assert checkpoint["tool_state"]["active_step"]["execution_state"] == (
            "UNKNOWN_OUTCOME"
        )
        assert manager.execution_journal.pending(agent["id"])[0]["state"] == (
            "UNKNOWN_OUTCOME"
        )
    finally:
        _TimeoutMutation.release.set()
        assert _TimeoutMutation.finished.wait(2)
        manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    restarted.recover_agent(agent["id"])
    no_replay_engine = FakeEngine([{"content": "must reconcile first"}])
    try:
        _execute(restarted, agent["id"], no_replay_engine)
        assert no_replay_engine.call_count == 0
        assert _TimeoutMutation.calls == 1
        assert restarted.execution_journal.pending(agent["id"])[0]["state"] == (
            "UNKNOWN_OUTCOME"
        )
    finally:
        restarted.close()


def test_corrupt_checkpoint_with_cancellation_fails_closed(tmp_path):
    _register(_BlockingMutation)
    _reset_blocking_tool(_BlockingMutation)
    db_path = str(tmp_path / "corrupt-cancel.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, "corrupt-cancel", tool=_BlockingMutation)
    manager.start_tick(agent["id"])
    tick_id = "corrupt-cancel-tick"
    manager.save_checkpoint(
        agent["id"],
        tick_id,
        {
            "schema_version": 1,
            "tick_id": tick_id,
            "lifecycle": "RUNNING",
            "resumable": True,
            "messages": [{"role": "user", "content": "continue"}],
        },
        {
            "schema_version": 1,
            "active_step": {"state": "NOT_STARTED"},
            "completed_steps": [],
            "retry_count": 0,
            "retry_history": [],
        },
    )
    manager.request_cancellation(agent["id"], reason="user")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE agent_checkpoints SET tool_state='{' WHERE agent_id=?",
            (agent["id"],),
        )
    manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    no_resume_engine = FakeEngine([_tool_call(_BlockingMutation.tool_id)])
    try:
        _execute(restarted, agent["id"], no_resume_engine)
        assert no_resume_engine.call_count == 0
        assert _BlockingMutation.calls == 0
        assert restarted.get_agent(agent["id"])["status"] == "needs_attention"
        assert restarted.cancellation_state(agent["id"])["state"] == "REQUESTED"
    finally:
        restarted.close()


def test_cancel_during_retry_backoff_preserves_persistent_budget(tmp_path, monkeypatch):
    manager = AgentManager(str(tmp_path / "retry-cancel.db"))
    agent = _new_agent(manager, "retry-cancel")
    engine = FakeEngine(
        [{"raise": RetryableError("temporary timeout")}, {"content": "done"}]
    )
    monkeypatch.setattr("openjarvis.agents.executor.retry_delay", lambda _attempt: 2)
    thread, errors = _run_thread(manager, agent["id"], engine)
    try:
        deadline = time.monotonic() + 2
        checkpoint = None
        while time.monotonic() < deadline:
            checkpoint = manager.get_latest_checkpoint(agent["id"])
            history = (
                checkpoint["tool_state"].get("retry_history", []) if checkpoint else []
            )
            if history and history[-1].get("state") == "FAILED":
                break
            time.sleep(0.01)
        assert checkpoint is not None
        assert checkpoint["tool_state"]["retry_count"] == 1
        manager.request_cancellation(agent["id"], reason="user")
        thread.join(3)
        assert not thread.is_alive()
        assert errors == []
        final = manager.get_latest_checkpoint(agent["id"])
        assert engine.call_count == 1, (final["tool_state"], errors)
        assert final["tool_state"]["retry_count"] == 1
        assert final["tool_state"]["retry_history"][-1]["state"] == "FAILED"
        assert (
            final["tool_state"]["retry_history"][-1]["cancelled_before_retry"] is True
        )
        assert final["tool_state"]["cancellation"]["state"] == "TERMINALIZED"
    finally:
        thread.join(2)
        manager.close()


def test_explicit_resume_clears_cancel_and_preserves_completed_steps(tmp_path):
    manager = AgentManager(str(tmp_path / "resume-after-cancel.db"))
    agent = _new_agent(manager, "resume-after-cancel")
    manager.start_tick(agent["id"])
    runtime = {
        "agent_id": agent["id"],
        "tick_id": "cancelled-empty",
        "resumable": False,
        "tool_state": {
            "active_step": {"state": "NOT_STARTED"},
            "completed_steps": [],
            "retry_count": 0,
            "retry_history": [],
        },
    }
    executor = AgentExecutor(manager, EventBus(), system=FakeSystem(FakeEngine([])))
    executor._persist_tick_state(
        runtime, [], runtime["tool_state"], lifecycle="CANCELLED"
    )
    manager.execution_journal.request_cancellation(agent["id"], reason="user")
    manager.execution_journal.advance_cancellation(agent["id"], "TERMINALIZED")
    manager.update_agent(agent["id"], status="paused")

    try:
        manager.resume_agent(agent["id"])
        resumed = manager.get_latest_checkpoint(agent["id"])
        assert resumed["conversation_state"]["lifecycle"] == "RUNNING"
        assert resumed["conversation_state"]["resume_authorized"] is True
        assert manager.cancellation_state(agent["id"]) is None
    finally:
        manager.close()
