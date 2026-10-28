"""Agent safe-E2E advancement (offline, mock-only, tmp sqlite).

Proves the Goal -> Plan -> Execute -> Observe -> Verify -> Replan chain
with the existing managed-execution pieces (no new runtime): two-step
goal verification, UNKNOWN-outcome re-mutation ban, cross-scope intent
rejection, capability fail-closed, model-capability safe defer, step
result isolation, journal/checkpoint consistency. Tool failure -> replan,
timeout/cancel, and restart-resume are covered by test_replan_revisions,
test_executor_resume, and cancellation tests; they are not duplicated.
"""

from __future__ import annotations

import json

import pytest

from openjarvis.agents.capability_router import (
    MODEL_CAPABILITY_UNAVAILABLE,
    CapabilityRouter,
    ModelCapability,
    ModelCard,
    ProviderSnapshot,
    RouteRequest,
    RouterFailure,
)
from openjarvis.agents.executor import AgentExecutor, _ManagedMutationController
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.proposals import ToolExecutionProposal
from openjarvis.core.events import EventBus
from openjarvis.core.execution import ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.security.cloud_dispatch import PrivacyClassification
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem
from tests.agents.test_plan_proposal_materialization import (
    _agent,
    _call,
    _materialize,
    _plan,
    _PlanProposalMutationTool,
    _ready,
    _run,
)

TOOL = _PlanProposalMutationTool.tool_id


@pytest.fixture(autouse=True)
def _reset_fake_tool():
    _PlanProposalMutationTool.calls = 0
    _PlanProposalMutationTool.unknown = False
    yield
    _PlanProposalMutationTool.calls = 0
    _PlanProposalMutationTool.unknown = False


def _controller(manager: AgentManager, agent_id: str):
    checkpoint = manager.get_latest_checkpoint(agent_id)
    assert checkpoint is not None
    runtime = {"tool_state": dict(checkpoint["tool_state"])}
    return _ManagedMutationController(
        manager.execution_journal, agent_id, runtime)


def test_e2e_two_step_goal_verifies_end_to_end(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "e2e.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        mat = _materialize(manager, agent["id"])
        _run(manager, agent["id"], [_call("s1"), {"content": "s1 done"}])
        AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).advance_materialized_plan_node(
            agent["id"],
            planner_node_id=mat["local_to_planner_node"]["s2"],
        )
        _run(manager, agent["id"], [_call("s2"), {"content": "s2 done"}])
        plan = _plan(manager, agent["id"])
        by_node = {n["planner_node_id"]: n["status"] for n in plan["nodes"]}
        assert by_node[mat["local_to_planner_node"]["s1"]] == "COMPLETED"
        assert by_node[mat["local_to_planner_node"]["s2"]] == "COMPLETED"
        assert _PlanProposalMutationTool.calls == 2
        assert manager.execution_journal.pending(agent["id"]) == []
    finally:
        manager.close()


def test_e2e_unknown_outcome_blocks_remutation(tmp_path) -> None:
    _PlanProposalMutationTool.unknown = True
    manager = AgentManager(str(tmp_path / "e2e-unknown.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        _materialize(manager, agent["id"])
        _run(manager, agent["id"], [_call("s1"), {"content": "s1 lost"}])
        assert _PlanProposalMutationTool.calls == 1
        # Journal holds the step unresolved: controller refuses any
        # replacement mutation and the plan cannot advance.
        controller = _controller(manager, agent["id"])
        call = ToolCall("s1-retry", TOOL, json.dumps({"value": "ok"}))
        decision = controller.authorize_proposal(
            ToolExecutionProposal.from_tool_call(call), effect="MUTATING")
        assert decision.allowed is False
        assert decision.code == "RECONCILIATION_REQUIRED"
        with pytest.raises(ValueError, match="[Rr]econciliation"):
            AgentExecutor(
                manager, EventBus(), system=FakeSystem(FakeEngine([]))
            ).advance_plan_step(agent["id"], step_id="s2")
        # A fresh executor with the same intent is also refused: the tool
        # is never dispatched a second time.
        intent = controller.context_for()
        second = ToolExecutor(
            [_PlanProposalMutationTool()],
            execution_journal=manager.execution_journal,
            execution_scope=agent["id"],
            require_mutation_intent=True,
        ).execute(call, mutation_context=intent)
        assert second.success is False
        assert _PlanProposalMutationTool.calls == 1
    finally:
        manager.close()


def test_e2e_cross_scope_intent_is_rejected(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "e2e-scope.db"))
    try:
        agent_a = _agent(manager)
        agent_b = manager.create_agent(
            "phase3d-plan-scope-b",
            agent_type="orchestrator",
            config={
                "model": "fake-model",
                "instruction": "Execute the controlled test step.",
                "tools": [TOOL],
            },
        )
        controller_a = _ManagedMutationController(
            manager.execution_journal, agent_a["id"],
            {"tool_state": {"execution_id": "exec-scope-a"}},
        )
        intent_a = controller_a.context_for()
        result = ToolExecutor(
            [_PlanProposalMutationTool()],
            execution_journal=manager.execution_journal,
            execution_scope=agent_b["id"],
            require_mutation_intent=True,
        ).execute(
            ToolCall("x-call", TOOL, json.dumps({"value": "ok"})),
            mutation_context=intent_a,
        )
        assert result.success is False
        assert _PlanProposalMutationTool.calls == 0
        assert not manager.execution_journal.semantic_step_exists(
            agent_b["id"], "exec-scope-a", intent_a.step_id)
    finally:
        manager.close()


class _GatedTool(BaseTool):
    tool_id = "e2e_gated_mutation"
    calls = 0

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id, "test-only gated mutation",
            effect=ToolEffect.MUTATING,
            required_capabilities=["network:fetch"],
        )

    def execute(self, **params):
        type(self).calls += 1
        return ToolResult(self.tool_id, "ok")


def test_e2e_capability_shortfall_denies_before_dispatch(tmp_path) -> None:
    _GatedTool.calls = 0
    journal_manager = AgentManager(str(tmp_path / "e2e-cap.db"))
    try:
        agent = _agent(journal_manager)
        policy = CapabilityPolicy(default_deny=True)
        result = ToolExecutor(
            [_GatedTool()],
            execution_journal=journal_manager.execution_journal,
            execution_scope=agent["id"],
            capability_policy=policy,
        ).execute(ToolCall("g1", _GatedTool.tool_id, "{}"))
        assert result.success is False
        assert _GatedTool.calls == 0
    finally:
        journal_manager.close()


def _local_card() -> ModelCard:
    return ModelCard(
        engine="local", provider="local", model="tiny-4b",
        capabilities=frozenset({ModelCapability.TEXT}),
        ctx_limit=4096, cost_per_1k=0.0, latency_p50_ms=50.0,
        is_cloud=False, tier=0,
    )


def test_e2e_model_capability_shortfall_defers_safely(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "e2e-defer.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        outcome = CapabilityRouter([_local_card()]).propose(
            RouteRequest(
                difficulty="hard",
                need=frozenset({ModelCapability.NATIVE_TOOLS}),
                privacy=PrivacyClassification.PRIVATE,
                est_prompt_tokens=100,
            ),
            ProviderSnapshot(available={_local_card().key(): True}),
        )
        assert isinstance(outcome, RouterFailure)
        assert outcome.code == MODEL_CAPABILITY_UNAVAILABLE
        # Safe defer: no intent authorized, no tool dispatched, the
        # checkpointed run stays intact for a later retry/escalation.
        assert manager.execution_journal.pending(agent["id"]) == []
        assert _PlanProposalMutationTool.calls == 0
        assert manager.get_latest_checkpoint(agent["id"]) is not None
    finally:
        manager.close()


def test_e2e_step_results_stay_isolated(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "e2e-isolation.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        mat = _materialize(manager, agent["id"])
        _run(manager, agent["id"],
             [_call("s1", value="one"), {"content": "s1 done"}])
        first = manager.get_latest_checkpoint(agent["id"])
        AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).advance_materialized_plan_node(
            agent["id"],
            planner_node_id=mat["local_to_planner_node"]["s2"],
        )
        _run(manager, agent["id"],
             [_call("s2", value="two"), {"content": "s2 done"}])
        second = manager.get_latest_checkpoint(agent["id"])
        completed = second["tool_state"]["completed_steps"]
        by_step = {s["step_id"]: s for s in completed if "step_id" in s}
        s1_id = mat["local_to_planner_node"]["s1"]
        s2_id = mat["local_to_planner_node"]["s2"]
        assert set(by_step) >= {s1_id, s2_id}
        assert (by_step[s1_id]["mutation_intent_id"]
                != by_step[s2_id]["mutation_intent_id"])
        assert first["tool_state"]["execution_id"] == (
            second["tool_state"]["execution_id"])
    finally:
        manager.close()
