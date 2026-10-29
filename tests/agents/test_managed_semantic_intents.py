"""Managed AgentExecutor semantic exactly-once tests (non-physical)."""

from __future__ import annotations

import json

import pytest

from openjarvis.agents.executor import AgentExecutor, _ManagedMutationController
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.orchestrator import OrchestratorAgent
from openjarvis.core.events import EventBus, EventType
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import AgentRegistry, ToolRegistry
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec
from openjarvis.tools.execution_journal import ExecutionJournal
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem


class _ManagedMutationTool(BaseTool):
    tool_id = "managed_semantic_mutation"
    calls = 0
    unknown = False

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id,
            "test-only managed mutation",
            parameters={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            effect=ToolEffect.MUTATING,
        )

    def execute(self, **params):
        type(self).calls += 1
        if type(self).unknown:
            raise RuntimeError("response lost after simulated dispatch")
        return ToolResult(
            self.tool_id,
            json.dumps({"verified": True}),
            execution_state=ExecutionState.VERIFIED,
        )


def _register() -> None:
    AgentRegistry.register_value("orchestrator", OrchestratorAgent)
    ToolRegistry.register_value(_ManagedMutationTool.tool_id, _ManagedMutationTool)


def _agent(manager: AgentManager) -> dict:
    _register()
    return manager.create_agent(
        "managed-semantic-test",
        agent_type="orchestrator",
        config={
            "model": "fake-model",
            "instruction": "Execute the controlled test step.",
            "tools": [_ManagedMutationTool.tool_id],
        },
    )


def _call(call_id: str, arguments: str = "{}") -> dict:
    return {
        "tool_calls": [
            {
                "id": call_id,
                "name": _ManagedMutationTool.tool_id,
                "arguments": arguments,
            }
        ]
    }


def _run(manager: AgentManager, agent_id: str, responses: list[dict]):
    engine = FakeEngine(responses)
    bus = EventBus(record_history=True)
    AgentExecutor(manager, bus, system=FakeSystem(engine)).execute_tick(agent_id)
    return engine, bus


def _restart(manager: AgentManager, agent_id: str, db_path: str) -> AgentManager:
    checkpoint = manager.get_latest_checkpoint(agent_id)
    assert checkpoint is not None
    conversation = dict(checkpoint["conversation_state"])
    conversation["lifecycle"] = "RUNNING"
    manager.save_checkpoint(
        agent_id,
        checkpoint["tick_id"],
        conversation,
        checkpoint["tool_state"],
    )
    manager.start_tick(agent_id)
    manager.close()
    return AgentManager(db_path, clear_stale_running=True)


def test_c1_no_authorization_exists_before_controller_creates_intent(tmp_path):
    journal = ExecutionJournal(tmp_path / "c1.db")
    runtime = {"tool_state": {"execution_id": "execution-c1"}}
    controller = _ManagedMutationController(journal, "c1", runtime)
    try:
        assert controller.snapshot() is None
        assert not journal.semantic_step_exists("c1", "execution-c1", "step-1")
    finally:
        journal.close()


def test_c2_prepared_checkpoint_observes_same_authorized_intent(tmp_path):
    _ManagedMutationTool.calls = 0
    journal = ExecutionJournal(tmp_path / "c2.db")
    tool = _ManagedMutationTool()
    runtime = {"tool_state": {"execution_id": "execution-c2"}}
    controller = _ManagedMutationController(journal, "c2", runtime)
    call = ToolCall("c2-call", tool.tool_id, "{}")
    intent = controller.context_for(call)
    executor = ToolExecutor(
        [tool], execution_journal=journal, execution_scope="c2",
        require_mutation_intent=True,
    )
    observed: dict[str, str] = {}

    def checkpoint(state, _result):
        if state == "PREPARED":
            observed["status"] = journal.semantic_intent("c2", intent)["status"]

    try:
        result = executor.execute(
            call, checkpoint_callback=checkpoint, mutation_context=intent
        )
        assert observed["status"] == "PREPARED"
        assert result.success
        assert tool.calls == 1
        assert journal.semantic_intent("c2", intent)["status"] == "VERIFIED"
    finally:
        journal.close()


def test_m1_managed_duplicate_after_verified_is_not_dispatched(tmp_path):
    _ManagedMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "m1.db"))
    agent = _agent(manager)
    try:
        _, bus = _run(
            manager,
            agent["id"],
            [_call("call-a"), _call("call-b"), {"content": "done"}],
        )
        starts = [e for e in bus.history if e.event_type == EventType.TOOL_CALL_START]
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert _ManagedMutationTool.calls == 1
        assert len(starts) == 1
        assert checkpoint["tool_state"]["semantic_step"]["status"] == "VERIFIED"
        assert checkpoint["tool_state"]["completed_steps"][-1][
            "mutation_intent_id"
        ]
    finally:
        manager.close()


def test_m2_controller_authorized_next_step_dispatches(tmp_path):
    _ManagedMutationTool.calls = 0
    path = str(tmp_path / "m2.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _run(manager, agent["id"], [_call("step-1-call"), {"content": "first"}])
    AgentExecutor(
        manager, EventBus(), system=FakeSystem(FakeEngine([]))
    ).advance_plan_step(agent["id"], step_id="step-2")
    try:
        _run(manager, agent["id"], [_call("step-2-call"), {"content": "second"}])
        assert _ManagedMutationTool.calls == 2
        completed = manager.get_latest_checkpoint(agent["id"])["tool_state"][
            "completed_steps"
        ]
        semantic_steps = [step for step in completed if "step_id" in step]
        assert len(semantic_steps) >= 2
        assert "step-2" in {step["step_id"] for step in semantic_steps}
    finally:
        manager.close()


def test_m3_identical_action_across_controller_steps_is_allowed(tmp_path):
    _ManagedMutationTool.calls = 0
    path = str(tmp_path / "m3.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _run(manager, agent["id"], [_call("same-a"), {"content": "first"}])
    AgentExecutor(
        manager, EventBus(), system=FakeSystem(FakeEngine([]))
    ).advance_plan_step(agent["id"], step_id="same-action-step-2")
    try:
        _run(manager, agent["id"], [_call("same-b"), {"content": "second"}])
        assert _ManagedMutationTool.calls == 2
    finally:
        manager.close()


def test_controller_rejects_reused_step_id(tmp_path):
    _ManagedMutationTool.calls = 0
    path = str(tmp_path / "reused-step.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [_call("first"), {"content": "done"}])
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        step_id = checkpoint["tool_state"]["semantic_step"]["step_id"]
        with pytest.raises(ValueError, match="already used"):
            AgentExecutor(
                manager, EventBus(), system=FakeSystem(FakeEngine([]))
            ).advance_plan_step(agent["id"], step_id=step_id)
    finally:
        manager.close()


def test_m4_restart_after_verified_blocks_fresh_call_id(tmp_path):
    _ManagedMutationTool.calls = 0
    path = str(tmp_path / "m4.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _run(manager, agent["id"], [_call("before-restart"), {"content": "done"}])
    restarted = _restart(manager, agent["id"], path)
    try:
        engine, _ = _run(
            restarted,
            agent["id"],
            [_call("fresh-after-restart"), {"content": "continued"}],
        )
        assert _ManagedMutationTool.calls == 1
        assert engine.call_count == 2
    finally:
        restarted.close()


def test_m5_unknown_outcome_restart_does_not_dispatch(tmp_path):
    _ManagedMutationTool.calls = 0
    _ManagedMutationTool.unknown = True
    path = str(tmp_path / "m5.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _run(manager, agent["id"], [_call("unknown")])
    manager.start_tick(agent["id"])
    manager.close()
    restarted = AgentManager(path, clear_stale_running=True)
    _ManagedMutationTool.unknown = False
    try:
        engine, _ = _run(restarted, agent["id"], [{"content": "must not run"}])
        assert _ManagedMutationTool.calls == 1
        assert engine.call_count == 0
        assert restarted.execution_journal.pending(agent["id"])[0]["state"] == (
            "UNKNOWN_OUTCOME"
        )
    finally:
        restarted.close()


def test_m6_new_provider_call_id_reuses_managed_intent(tmp_path):
    _ManagedMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "m6.db"))
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [_call("provider-a"), _call("provider-b")])
        assert _ManagedMutationTool.calls == 1
    finally:
        manager.close()


def test_m7_checkpoint_compaction_preserves_semantic_reference(tmp_path):
    _ManagedMutationTool.calls = 0
    path = str(tmp_path / "m7.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _run(manager, agent["id"], [_call("compact-call"), {"content": "done"}])
    checkpoint = manager.get_latest_checkpoint(agent["id"])
    assert checkpoint["tool_state"]["semantic_step"]["status"] == "VERIFIED"
    checkpoint["conversation_state"]["messages"] = checkpoint[
        "conversation_state"
    ]["messages"][-1:]
    manager.save_checkpoint(
        agent["id"],
        checkpoint["tick_id"],
        {**checkpoint["conversation_state"], "lifecycle": "RUNNING"},
        checkpoint["tool_state"],
    )
    manager.start_tick(agent["id"])
    manager.close()
    restarted = AgentManager(path, clear_stale_running=True)
    try:
        _run(restarted, agent["id"], [{"content": "continued"}])
        assert _ManagedMutationTool.calls == 1
    finally:
        restarted.close()


def test_m8_persistent_retry_does_not_replay_verified_step(tmp_path):
    _ManagedMutationTool.calls = 0
    path = str(tmp_path / "m8.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    try:
        engine = FakeEngine(
            [
                _call("retry-call"),
                {"raise": RuntimeError("transient model timeout")},
                {"content": "completed"},
            ]
        )
        executor = AgentExecutor(manager, EventBus(), system=FakeSystem(engine))
        # Runtime error classification is retryable in the managed loop only
        # when the exception carries the existing retry marker.
        from openjarvis.agents.errors import RetryableError

        engine._responses[1] = {"raise": RetryableError("transient model error")}
        executor.execute_tick(agent["id"])
        assert _ManagedMutationTool.calls == 1
    finally:
        manager.close()


def test_m9_not_executed_allows_explicit_new_controller_step(tmp_path):
    _ManagedMutationTool.calls = 0
    journal = ExecutionJournal(tmp_path / "m9.db")
    tool = _ManagedMutationTool()
    runtime = {
        "tool_state": {
            "execution_id": "execution-m9",
            "active_step": {"state": "NOT_STARTED"},
        }
    }
    controller = _ManagedMutationController(journal, "m9", runtime)
    try:
        intent = controller.context_for(ToolCall("old", tool.tool_id, "{}"))
        executor = ToolExecutor(
            [tool],
            execution_journal=journal,
            execution_scope="m9",
            require_mutation_intent=True,
        )

        def fail_before_dispatch(state, _result):
            if state == "PREPARED":
                raise OSError("checkpoint unavailable")

        failed = executor.execute(
            ToolCall("old", tool.tool_id, "{}"),
            checkpoint_callback=fail_before_dispatch,
            mutation_context=intent,
        )
        controller.record_result(ToolCall("old", tool.tool_id, "{}"), failed)
        assert tool.calls == 0
        controller.advance_step("m9-new-step")
        new_intent = controller.context_for()
        assert new_intent.step_id == "m9-new-step"
        assert executor.execute(
            ToolCall("new", tool.tool_id, "{}"), mutation_context=new_intent
        ).success
        assert tool.calls == 1
    finally:
        journal.close()


def test_m10_verified_step_cannot_be_replanned_by_model_call(tmp_path):
    _ManagedMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "m10.db"))
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [_call("verified"), _call("model-replan")])
        assert _ManagedMutationTool.calls == 1
        semantic = manager.get_latest_checkpoint(agent["id"])["tool_state"][
            "semantic_step"
        ]
        assert semantic["status"] == "VERIFIED"
    finally:
        manager.close()


def test_m11_max_turn_failure_keeps_verified_intent_closed(tmp_path):
    _ManagedMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "m11.db"))
    agent = _agent(manager)
    try:
        responses = [_call(f"loop-{index}") for index in range(12)]
        _run(manager, agent["id"], responses)
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert _ManagedMutationTool.calls == 1
        assert checkpoint["tool_state"]["semantic_step"]["status"] == "VERIFIED"
    finally:
        manager.close()


def test_m12_checkpoint_journal_mismatch_fails_closed(tmp_path):
    _ManagedMutationTool.calls = 0
    path = str(tmp_path / "m12.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _run(manager, agent["id"], [_call("mismatch-source"), {"content": "done"}])
    checkpoint = manager.get_latest_checkpoint(agent["id"])
    semantic = dict(checkpoint["tool_state"]["semantic_step"])
    semantic["mutation_intent_id"] = "not-in-journal"
    state = {**checkpoint["tool_state"], "semantic_step": semantic}
    conversation = {**checkpoint["conversation_state"], "lifecycle": "RUNNING"}
    manager.save_checkpoint(agent["id"], checkpoint["tick_id"], conversation, state)
    manager.start_tick(agent["id"])
    manager.close()
    restarted = AgentManager(path, clear_stale_running=True)
    try:
        engine, _ = _run(restarted, agent["id"], [{"content": "must not run"}])
        assert engine.call_count == 0
        assert _ManagedMutationTool.calls == 1
        assert restarted.get_agent(agent["id"])["status"] == "needs_attention"
    finally:
        restarted.close()
