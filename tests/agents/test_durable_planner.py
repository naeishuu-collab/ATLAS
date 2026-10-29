"""Durable planner/controller foundation tests (non-physical)."""

from __future__ import annotations

import copy
import json

import pytest

from openjarvis.agents.executor import AgentExecutor, _ManagedMutationController
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.orchestrator import OrchestratorAgent
from openjarvis.agents.plan import DurablePlan
from openjarvis.core.events import EventBus
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import AgentRegistry, ToolRegistry
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec
from openjarvis.tools.execution_journal import ExecutionJournal
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem


class _PlanMutationTool(BaseTool):
    tool_id = "durable_plan_mutation"
    calls = 0
    unknown = False

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id,
            "test-only mutation",
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
    ToolRegistry.register_value(_PlanMutationTool.tool_id, _PlanMutationTool)


def _agent(manager: AgentManager) -> dict:
    _register()
    return manager.create_agent(
        "durable-plan-test",
        agent_type="orchestrator",
        config={
            "model": "fake-model",
            "instruction": "Execute the controlled test step.",
            "tools": [_PlanMutationTool.tool_id],
        },
    )


def _call(call_id: str, arguments: str = "{}") -> dict:
    return {
        "tool_calls": [
            {
                "id": call_id,
                "name": _PlanMutationTool.tool_id,
                "arguments": arguments,
            }
        ]
    }


def _run(manager: AgentManager, agent_id: str, responses: list[dict]):
    engine = FakeEngine(responses)
    AgentExecutor(manager, EventBus(), system=FakeSystem(engine)).execute_tick(agent_id)
    return engine


def _restart(manager: AgentManager, agent_id: str, db_path: str) -> AgentManager:
    checkpoint = manager.get_latest_checkpoint(agent_id)
    assert checkpoint is not None
    conversation = {**checkpoint["conversation_state"], "lifecycle": "RUNNING"}
    manager.save_checkpoint(
        agent_id,
        checkpoint["tick_id"],
        conversation,
        checkpoint["tool_state"],
    )
    manager.start_tick(agent_id)
    manager.close()
    return AgentManager(db_path, clear_stale_running=True)


def _controller(path, scope="plan-test", execution_id="execution-plan"):
    journal = ExecutionJournal(path)
    runtime = {"tool_state": {"execution_id": execution_id}}
    return journal, runtime, _ManagedMutationController(journal, scope, runtime)


def test_d1_durable_plan_creation_and_reload(tmp_path):
    path = str(tmp_path / "d1.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [{"content": "initialize"}])
        executor = AgentExecutor(manager, EventBus(), system=FakeSystem(FakeEngine([])))
        node = executor.create_plan_node(agent["id"], planner_node_id="s1")
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        plan = DurablePlan.from_dict(checkpoint["tool_state"]["durable_plan"])
        assert node["plan_id"] == plan.plan_id
        assert node["execution_id"] == plan.execution_id
        assert plan.node("s1").status == "PLANNED"
        manager.close()
        reopened = AgentManager(path)
        try:
            restored = DurablePlan.from_dict(
                reopened.get_latest_checkpoint(agent["id"])["tool_state"][
                    "durable_plan"
                ]
            )
            assert (restored.execution_id, restored.plan_id) == (
                plan.execution_id,
                plan.plan_id,
            )
            assert restored.node("s1").planner_node_id == "s1"
        finally:
            reopened.close()
    except Exception:
        manager.close()
        raise


def test_d2_model_identity_fields_do_not_replace_controller_ids(tmp_path):
    _PlanMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "d2.db"))
    agent = _agent(manager)
    try:
        _run(
            manager,
            agent["id"],
            [
                _call(
                    "model-call",
                    json.dumps(
                        {
                            "plan_id": "fake-plan",
                            "planner_node_id": "fake-node",
                            "step_id": "fake-step",
                            "mutation_intent_id": "fake-intent",
                        }
                    ),
                ),
                {"content": "done"},
            ],
        )
        state = manager.get_latest_checkpoint(agent["id"])["tool_state"]
        plan = state["durable_plan"]
        assert plan["plan_id"] != "fake-plan"
        assert plan["nodes"] == []
        assert "semantic_step" not in state
        assert _PlanMutationTool.calls == 0
    finally:
        manager.close()


def test_d3_activation_binds_exactly_one_intent(tmp_path):
    journal, runtime, controller = _controller(tmp_path / "d3.db")
    try:
        controller.create_plan_node(planner_node_id="s1")
        controller.advance_step("s1")
        intent = controller.context_for()
        node = controller.plan.node("s1")
        assert node.status == "ACTIVE"
        assert node.mutation_intent_id == intent.mutation_intent_id
        assert journal.semantic_intent("plan-test", intent)["status"] == "AUTHORIZED"
    finally:
        journal.close()


def test_d4_duplicate_proposals_reuse_one_intent(tmp_path):
    _PlanMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "d4.db"))
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [_call("a"), _call("b"), {"content": "done"}])
        state = manager.get_latest_checkpoint(agent["id"])["tool_state"]
        plan = state["durable_plan"]
        assert _PlanMutationTool.calls == 1
        assert len(plan["nodes"]) == 1
        assert plan["nodes"][0]["status"] == "COMPLETED"
        assert state["semantic_step"]["step_id"] == plan["nodes"][0]["planner_node_id"]
    finally:
        manager.close()


def test_d5_d6_verified_node_is_durable_and_cannot_reopen(tmp_path):
    _PlanMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "d5.db"))
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [_call("first"), _call("duplicate")])
        state = manager.get_latest_checkpoint(agent["id"])["tool_state"]
        assert state["durable_plan"]["nodes"][0]["status"] == "COMPLETED"
        assert _PlanMutationTool.calls == 1
    finally:
        manager.close()


def test_d7_d8_controller_step_two_allows_identical_action(tmp_path):
    _PlanMutationTool.calls = 0
    path = str(tmp_path / "d7.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [_call("s1"), {"content": "first"}])
        advanced = AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).advance_plan_step(agent["id"], step_id="s2")
        _run(manager, agent["id"], [_call("s2"), {"content": "second"}])
        plan = DurablePlan.from_dict(
            manager.get_latest_checkpoint(agent["id"])["tool_state"]["durable_plan"]
        )
        assert advanced["planner_node_id"] == "s2"
        assert _PlanMutationTool.calls == 2
        assert {node.status for node in plan.nodes.values()} == {"COMPLETED"}
        assert len({node.mutation_intent_id for node in plan.nodes.values()}) == 2
    finally:
        manager.close()


def test_d9_restart_after_verified_restores_closed_node(tmp_path):
    _PlanMutationTool.calls = 0
    path = str(tmp_path / "d9.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _run(manager, agent["id"], [_call("before-restart"), {"content": "done"}])
    restarted = _restart(manager, agent["id"], path)
    try:
        _run(restarted, agent["id"], [_call("fresh"), {"content": "continued"}])
        state = restarted.get_latest_checkpoint(agent["id"])["tool_state"]
        assert _PlanMutationTool.calls == 1
        assert state["durable_plan"]["nodes"][0]["status"] == "COMPLETED"
    finally:
        restarted.close()


def test_d10_d11_unknown_outcome_quarantines_plan_across_restart(tmp_path):
    _PlanMutationTool.calls = 0
    _PlanMutationTool.unknown = True
    path = str(tmp_path / "d10.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [_call("unknown")])
        state = manager.get_latest_checkpoint(agent["id"])["tool_state"]
        assert state["durable_plan"]["nodes"][0]["status"] == (
            "RECONCILIATION_REQUIRED"
        )
        with pytest.raises(ValueError, match="reconciliation"):
            AgentExecutor(
                manager, EventBus(), system=FakeSystem(FakeEngine([]))
            ).advance_plan_step(agent["id"], step_id="replacement")
        manager.start_tick(agent["id"])
        manager.close()
        restarted = AgentManager(path, clear_stale_running=True)
        try:
            _PlanMutationTool.unknown = False
            _run(restarted, agent["id"], [{"content": "must not run"}])
            restored = restarted.get_latest_checkpoint(agent["id"])["tool_state"]
            assert _PlanMutationTool.calls == 1
            assert restored["durable_plan"]["nodes"][0]["status"] == (
                "RECONCILIATION_REQUIRED"
            )
        finally:
            restarted.close()
    finally:
        _PlanMutationTool.unknown = False
        if getattr(manager, "_conn", None) is not None:
            try:
                manager.close()
            except Exception:
                pass


def test_d12_not_executed_allows_controller_replan(tmp_path):
    _PlanMutationTool.calls = 0
    journal, runtime, controller = _controller(tmp_path / "d12.db")
    tool = _PlanMutationTool()
    executor = ToolExecutor(
        [tool],
        execution_journal=journal,
        execution_scope="plan-test",
        require_mutation_intent=True,
    )
    try:
        controller.advance_step("s1")
        intent = controller.context_for()

        def fail_checkpoint(state, _result):
            if state == "PREPARED":
                raise OSError("checkpoint unavailable")

        result = executor.execute(
            ToolCall("old", tool.tool_id, "{}"),
            checkpoint_callback=fail_checkpoint,
            mutation_context=intent,
        )
        controller.record_result(ToolCall("old", tool.tool_id, "{}"), result)
        controller.advance_step("s2")
        new_intent = controller.context_for()
        assert controller.plan.node("s1").status == "FAILED"
        assert new_intent.step_id == "s2"
        assert executor.execute(
            ToolCall("new", tool.tool_id, "{}"), mutation_context=new_intent
        ).success
        assert tool.calls == 1
    finally:
        journal.close()


def test_d13_checkpoint_plan_mismatch_fails_closed(tmp_path):
    _PlanMutationTool.calls = 0
    path = str(tmp_path / "d13.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _run(manager, agent["id"], [_call("source"), {"content": "done"}])
    checkpoint = manager.get_latest_checkpoint(agent["id"])
    state = copy.deepcopy(checkpoint["tool_state"])
    state["durable_plan"]["execution_id"] = "wrong-execution"
    manager.save_checkpoint(
        agent["id"],
        checkpoint["tick_id"],
        {**checkpoint["conversation_state"], "lifecycle": "RUNNING"},
        state,
    )
    restarted = _restart(manager, agent["id"], path)
    try:
        _run(restarted, agent["id"], [{"content": "must not run"}])
        assert restarted.get_agent(agent["id"])["status"] == "needs_attention"
        assert _PlanMutationTool.calls == 1
    finally:
        restarted.close()


def test_d14_planner_semantic_journal_mismatch_fails_closed(tmp_path):
    _PlanMutationTool.calls = 0
    path = str(tmp_path / "d14.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _run(manager, agent["id"], [_call("source"), {"content": "done"}])
    checkpoint = manager.get_latest_checkpoint(agent["id"])
    state = copy.deepcopy(checkpoint["tool_state"])
    state["durable_plan"]["nodes"][0]["mutation_intent_id"] = "wrong-intent"
    manager.save_checkpoint(
        agent["id"],
        checkpoint["tick_id"],
        {**checkpoint["conversation_state"], "lifecycle": "RUNNING"},
        state,
    )
    restarted = _restart(manager, agent["id"], path)
    try:
        _run(restarted, agent["id"], [{"content": "must not run"}])
        assert restarted.get_agent(agent["id"])["status"] == "needs_attention"
        assert _PlanMutationTool.calls == 1
    finally:
        restarted.close()


def test_d15_context_compaction_preserves_plan_identity(tmp_path):
    _PlanMutationTool.calls = 0
    path = str(tmp_path / "d15.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _run(manager, agent["id"], [_call("compact"), {"content": "done"}])
    checkpoint = manager.get_latest_checkpoint(agent["id"])
    plan = copy.deepcopy(checkpoint["tool_state"]["durable_plan"])
    manager.save_checkpoint(
        agent["id"],
        checkpoint["tick_id"],
        {
            **checkpoint["conversation_state"],
            "lifecycle": "RUNNING",
            "messages": checkpoint["conversation_state"]["messages"][-1:],
        },
        checkpoint["tool_state"],
    )
    restarted = _restart(manager, agent["id"], path)
    try:
        _run(restarted, agent["id"], [{"content": "continued"}])
        restored = restarted.get_latest_checkpoint(agent["id"])["tool_state"]
        assert restored["durable_plan"] == plan
        assert _PlanMutationTool.calls == 1
    finally:
        restarted.close()


def test_d16_cancellation_keeps_plan_dispatch_closed(tmp_path):
    _PlanMutationTool.calls = 0
    journal, runtime, controller = _controller(tmp_path / "d16.db")
    tool = _PlanMutationTool()
    executor = ToolExecutor(
        [tool],
        execution_journal=journal,
        execution_scope="plan-test",
        require_mutation_intent=True,
    )
    try:
        controller.advance_step("cancel-step")
        intent = controller.context_for()
        journal.request_cancellation("plan-test")
        result = executor.execute(
            ToolCall("cancel", tool.tool_id, "{}"), mutation_context=intent
        )
        assert result.metadata["execution"]["state"] == "NOT_STARTED"
        assert tool.calls == 0
    finally:
        journal.close()


def test_d17_deadline_keeps_plan_dispatch_closed(tmp_path):
    _PlanMutationTool.calls = 0
    journal, runtime, controller = _controller(tmp_path / "d17.db")
    tool = _PlanMutationTool()
    executor = ToolExecutor(
        [tool],
        execution_journal=journal,
        execution_scope="plan-test",
        require_mutation_intent=True,
    )
    try:
        controller.advance_step("deadline-step")
        intent = controller.context_for()
        journal.request_cancellation(
            "plan-test", reason="deadline", timeout_kind="tool"
        )
        result = executor.execute(
            ToolCall("deadline", tool.tool_id, "{}"), mutation_context=intent
        )
        assert result.metadata["execution"]["state"] == "NOT_STARTED"
        assert tool.calls == 0
    finally:
        journal.close()


def test_d18_read_only_node_needs_no_mutation_intent(tmp_path):
    plan = DurablePlan.create("read-only-execution")
    plan.add_node(planner_node_id="observe", kind="READ_ONLY")
    plan.activate("observe")
    plan.complete_read_only("observe")
    restored = DurablePlan.from_dict(plan.to_dict())
    assert restored.node("observe").status == "COMPLETED"
    assert restored.node("observe").mutation_intent_id is None


def test_dc1_dc2_plan_and_authorized_intent_restore(tmp_path):
    journal, runtime, controller = _controller(tmp_path / "dc12.db")
    try:
        controller.create_plan_node(planner_node_id="s1")
        before = DurablePlan.from_dict(controller.plan_snapshot())
        assert before.node("s1").status == "PLANNED"
        controller.advance_step("s1")
        intent = controller.context_for()
        reloaded = _ManagedMutationController(
            journal, "plan-test", {"tool_state": copy.deepcopy(runtime["tool_state"])}
        )
        assert reloaded.plan.node("s1").status == "ACTIVE"
        assert reloaded.context_for().mutation_intent_id == intent.mutation_intent_id
    finally:
        journal.close()


def test_dc3_unknown_dispatch_boundary_is_reconciliation_required(tmp_path):
    _PlanMutationTool.calls = 0
    _PlanMutationTool.unknown = True
    journal, runtime, controller = _controller(tmp_path / "dc3.db")
    tool = _PlanMutationTool()
    executor = ToolExecutor(
        [tool],
        execution_journal=journal,
        execution_scope="plan-test",
        require_mutation_intent=True,
    )
    try:
        controller.advance_step("s1")
        intent = controller.context_for()
        result = executor.execute(
            ToolCall("unknown", tool.tool_id, "{}"), mutation_context=intent
        )
        controller.record_result(ToolCall("unknown", tool.tool_id, "{}"), result)
        assert result.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
        assert controller.plan.node("s1").status == "RECONCILIATION_REQUIRED"
        assert tool.calls == 1
    finally:
        _PlanMutationTool.unknown = False
        journal.close()


def test_dc4_journal_verified_wins_before_plan_completion_checkpoint(tmp_path):
    journal, runtime, controller = _controller(tmp_path / "dc4.db")
    tool = _PlanMutationTool()
    executor = ToolExecutor(
        [tool],
        execution_journal=journal,
        execution_scope="plan-test",
        require_mutation_intent=True,
    )
    try:
        controller.advance_step("s1")
        intent = controller.context_for()
        stale = copy.deepcopy(runtime["tool_state"])
        stale["semantic_step"]["status"] = "PREPARED"
        result = executor.execute(
            ToolCall("verified", tool.tool_id, "{}"), mutation_context=intent
        )
        assert result.success
        restored = _ManagedMutationController(
            journal, "plan-test", {"tool_state": stale}
        )
        assert restored.plan.node("s1").status == "COMPLETED"
        assert restored.plan_snapshot()["status"] == "COMPLETED"
    finally:
        journal.close()


def test_dc5_completed_node_restores_normally(tmp_path):
    journal, runtime, controller = _controller(tmp_path / "dc5.db")
    tool = _PlanMutationTool()
    executor = ToolExecutor(
        [tool],
        execution_journal=journal,
        execution_scope="plan-test",
        require_mutation_intent=True,
    )
    try:
        controller.advance_step("s1")
        intent = controller.context_for()
        result = executor.execute(
            ToolCall("verified", tool.tool_id, "{}"), mutation_context=intent
        )
        controller.record_result(ToolCall("verified", tool.tool_id, "{}"), result)
        restored = _ManagedMutationController(
            journal, "plan-test", {"tool_state": copy.deepcopy(runtime["tool_state"])}
        )
        assert restored.plan.node("s1").status == "COMPLETED"
    finally:
        journal.close()
