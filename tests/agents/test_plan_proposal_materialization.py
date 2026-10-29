"""Phase 3D-A trusted plan materialization tests (non-physical)."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from openjarvis.agents.executor import AgentExecutor, _ManagedMutationController
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.orchestrator import OrchestratorAgent
from openjarvis.agents.proposals import (
    PlanProposal,
    PlanProposalError,
    PlanStepProposal,
)
from openjarvis.core.events import EventBus
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import AgentRegistry, ToolRegistry
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem


class _PlanProposalMutationTool(BaseTool):
    tool_id = "phase3d_plan_proposal_mutation"
    calls = 0
    unknown = False
    artifact_output: str | None = None

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id,
            "test-only mutation",
            parameters={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
                "additionalProperties": False,
            },
            effect=ToolEffect.MUTATING,
        )

    def execute(self, **params):
        type(self).calls += 1
        if type(self).unknown:
            raise RuntimeError("response lost after simulated dispatch")
        metadata = {}
        if type(self).artifact_output and params.get("value") == "three":
            content = b"verified final artifact"
            path = Path(type(self).artifact_output)
            path.write_bytes(content)
            metadata["artifacts"] = [
                {
                    "type": "file",
                    "path": str(path.resolve()),
                    "size_bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            ]
        return ToolResult(
            self.tool_id,
            json.dumps({"value": params.get("value", "ok")}),
            execution_state=ExecutionState.VERIFIED,
            metadata=metadata,
        )


def _register() -> None:
    AgentRegistry.register_value("orchestrator", OrchestratorAgent)
    ToolRegistry.register_value(
        _PlanProposalMutationTool.tool_id, _PlanProposalMutationTool
    )


def _agent(manager: AgentManager) -> dict:
    _register()
    return manager.create_agent(
        "phase3d-plan-proposal-test",
        agent_type="orchestrator",
        config={
            "model": "fake-model",
            "instruction": "Execute the controlled test step.",
            "tools": [_PlanProposalMutationTool.tool_id],
        },
    )


def _call(call_id: str, value: str = "one") -> dict:
    return {
        "tool_calls": [
            {
                "id": call_id,
                "name": _PlanProposalMutationTool.tool_id,
                "arguments": json.dumps({"value": value}),
            }
        ]
    }


def _run(manager: AgentManager, agent_id: str, responses: list[dict]):
    engine = FakeEngine(responses)
    AgentExecutor(manager, EventBus(), system=FakeSystem(engine)).execute_tick(agent_id)
    return engine


def _ready(manager: AgentManager, agent_id: str) -> None:
    _run(manager, agent_id, [{"content": "ready"}])


def _plan(manager: AgentManager, agent_id: str) -> dict:
    checkpoint = manager.get_latest_checkpoint(agent_id)
    assert checkpoint is not None
    return checkpoint["tool_state"]["durable_plan"]


def _node(plan: dict, planner_node_id: str) -> dict:
    return next(
        node for node in plan["nodes"] if node["planner_node_id"] == planner_node_id
    )


def _proposal(*, identical: bool = False) -> PlanProposal:
    value = "same" if identical else "one"
    return PlanProposal(
        proposal_id="model-plan",
        steps=(
            PlanStepProposal(
                local_index="s1",
                kind="MUTATING",
                tool_name=_PlanProposalMutationTool.tool_id,
                arguments={"value": value},
            ),
            PlanStepProposal(
                local_index="s2",
                kind="MUTATING",
                tool_name=_PlanProposalMutationTool.tool_id,
                arguments={"value": value if identical else "two"},
                dependencies=("s1",),
            ),
        ),
    )


def _materialize(manager: AgentManager, agent_id: str, proposal=None) -> dict:
    return AgentExecutor(
        manager, EventBus(), system=FakeSystem(FakeEngine([]))
    ).materialize_plan_proposal(
        agent_id,
        proposal or _proposal(),
        supported_tools={_PlanProposalMutationTool.tool_id},
    )


def _restart(manager: AgentManager, agent_id: str, db_path: str) -> AgentManager:
    checkpoint = manager.get_latest_checkpoint(agent_id)
    assert checkpoint is not None
    manager.save_checkpoint(
        agent_id,
        checkpoint["tick_id"],
        {**checkpoint["conversation_state"], "lifecycle": "RUNNING"},
        checkpoint["tool_state"],
    )
    manager.start_tick(agent_id)
    manager.close()
    return AgentManager(db_path, clear_stale_running=True)


def test_p3d_a1_a8_materializes_trusted_plan_and_only_activates_s1(tmp_path):
    manager = AgentManager(str(tmp_path / "materialize.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result = _materialize(manager, agent["id"])
        plan = _plan(manager, agent["id"])
        nodes = plan["nodes"]
        assert len(nodes) == 2
        assert result["active_node_id"] == result["local_to_planner_node"]["s1"]
        s1 = _node(plan, result["local_to_planner_node"]["s1"])
        s2 = _node(plan, result["local_to_planner_node"]["s2"])
        assert s1["status"] == "ACTIVE"
        assert s2["status"] == "PLANNED"
        assert s2["dependencies"] == [result["local_to_planner_node"]["s1"]]
        assert all(node["mutation_intent_id"] is None for node in nodes)
    finally:
        manager.close()


def test_goal_planning_auto_advances_only_the_unique_verified_successor(tmp_path):
    _PlanProposalMutationTool.calls = 0
    artifact_path = tmp_path / "goal-artifact.txt"
    _PlanProposalMutationTool.artifact_output = str(artifact_path)
    manager = AgentManager(str(tmp_path / "automatic-progression.db"))
    agent = _agent(manager)
    try:
        manager.update_agent(
            agent["id"], config={**agent["config"], "goal_planning": {"enabled": True}}
        )
        _ready(manager, agent["id"])
        proposal = _proposal()
        proposal = PlanProposal(
            proposal_id=proposal.proposal_id,
            steps=(
                *proposal.steps,
                PlanStepProposal(
                    "s3",
                    "MUTATING",
                    _PlanProposalMutationTool.tool_id,
                    arguments={"value": "three"},
                    dependencies=("s2",),
                ),
            ),
        )
        materialized = _materialize(manager, agent["id"], proposal)
        _run(
            manager,
            agent["id"],
            [
                _call("auto-s1", "one"),
                _call("auto-s2", "two"),
                _call("auto-s3", "three"),
                {"content": "done"},
            ],
        )
        assert _PlanProposalMutationTool.calls == 3
        final_plan = _plan(manager, agent["id"])
        assert len(final_plan["nodes"]) == 3
        assert all(node["status"] == "COMPLETED" for node in final_plan["nodes"])
        assert final_plan["active_node_id"] is None
        assert materialized["plan_id"] == final_plan["plan_id"]
        acceptance = AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).verify_goal_acceptance(agent["id"])
        assert acceptance["status"] == "VERIFIED"
        assert (
            acceptance["evidence"][0]["actual_sha256"]
            == hashlib.sha256(b"verified final artifact").hexdigest()
        )
    finally:
        _PlanProposalMutationTool.artifact_output = None
        manager.close()


def test_invalid_tool_arguments_fail_before_dispatch(tmp_path):
    _PlanProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "invalid-tool-arguments.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        engine = _run(
            manager,
            agent["id"],
            [
                {
                    "tool_calls": [
                        {
                            "id": "wrong-type",
                            "name": _PlanProposalMutationTool.tool_id,
                            "arguments": json.dumps({"value": 1}),
                        }
                    ]
                }
            ],
        )
        assert _PlanProposalMutationTool.calls == 0
        assert manager.execution_journal.pending(agent["id"]) == []
        assert _plan(manager, agent["id"])["nodes"] == []
        assert any(
            "TOOL_ARGUMENT_TYPE" in message.content
            for message in engine.last_messages or []
            if message.role.value == "tool"
        )
    finally:
        manager.close()


def test_p3d_a2_controller_generates_plan_and_node_ids(tmp_path):
    manager = AgentManager(str(tmp_path / "ids.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result = _materialize(manager, agent["id"])
        assert result["plan_id"] != "model-plan"
        assert all(
            node_id != local
            for local, node_id in result["local_to_planner_node"].items()
        )
        assert all(
            node_id.startswith("node-")
            for node_id in result["local_to_planner_node"].values()
        )
    finally:
        manager.close()


@pytest.mark.parametrize(
    "payload",
    [
        {"plan_id": "fake", "steps": []},
        {
            "steps": [
                {
                    "local_index": "s1",
                    "kind": "MUTATING",
                    "tool_name": _PlanProposalMutationTool.tool_id,
                    "arguments": {"mutation_intent_id": "fake"},
                }
            ]
        },
        {
            "steps": [
                {
                    "local_index": "s1",
                    "kind": "MUTATING",
                    "tool_name": _PlanProposalMutationTool.tool_id,
                    "arguments": '{"revision_id": "fake"}',
                }
            ]
        },
    ],
)
def test_p3d_a3_authority_injection_rejected_without_nodes(tmp_path, payload):
    manager = AgentManager(str(tmp_path / "authority.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        with pytest.raises(PlanProposalError, match="PLAN_PROPOSAL_REJECTED"):
            proposal = PlanProposal.from_dict(payload)
            _materialize(manager, agent["id"], proposal)
        assert _plan(manager, agent["id"])["nodes"] == []
        assert manager.execution_journal.pending(agent["id"]) == []
    finally:
        manager.close()


def test_p3d_a4_dependency_translation(tmp_path):
    manager = AgentManager(str(tmp_path / "deps.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result = _materialize(manager, agent["id"])
        plan = _plan(manager, agent["id"])
        s1 = result["local_to_planner_node"]["s1"]
        s2 = result["local_to_planner_node"]["s2"]
        assert _node(plan, s2)["dependencies"] == [s1]
    finally:
        manager.close()


def test_p3d_a5_unsupported_tool_has_no_partial_plan(tmp_path):
    manager = AgentManager(str(tmp_path / "unsupported-tool.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        proposal = PlanProposal(
            "unsupported",
            (PlanStepProposal("s1", "MUTATING", "not-registered"),),
        )
        with pytest.raises(PlanProposalError, match="unsupported tools"):
            _materialize(manager, agent["id"], proposal)
        assert _plan(manager, agent["id"])["nodes"] == []
    finally:
        manager.close()


def test_p3d_a7_ambiguous_frontier_fails_closed(tmp_path):
    manager = AgentManager(str(tmp_path / "ambiguous-frontier.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        proposal = PlanProposal(
            "ambiguous",
            (
                PlanStepProposal(
                    "s1",
                    "MUTATING",
                    _PlanProposalMutationTool.tool_id,
                    arguments={"value": "one"},
                ),
                PlanStepProposal(
                    "s2",
                    "MUTATING",
                    _PlanProposalMutationTool.tool_id,
                    arguments={"value": "two"},
                ),
            ),
        )
        with pytest.raises(PlanProposalError, match="AMBIGUOUS_PLAN_FRONTIER"):
            _materialize(manager, agent["id"], proposal)
        assert _plan(manager, agent["id"])["nodes"] == []
    finally:
        manager.close()


@pytest.mark.parametrize(
    "steps, message",
    [
        (
            (
                PlanStepProposal("s1", "MUTATING", _PlanProposalMutationTool.tool_id),
                PlanStepProposal(
                    "s2",
                    "MUTATING",
                    _PlanProposalMutationTool.tool_id,
                    dependencies=("missing",),
                ),
            ),
            "unknown dependencies",
        ),
        (
            (
                PlanStepProposal(
                    "s1",
                    "MUTATING",
                    _PlanProposalMutationTool.tool_id,
                    dependencies=("s2",),
                ),
                PlanStepProposal(
                    "s2",
                    "MUTATING",
                    _PlanProposalMutationTool.tool_id,
                    dependencies=("s1",),
                ),
            ),
            "cyclic dependencies",
        ),
    ],
)
def test_p3d_a5_a6_invalid_graph_has_no_partial_plan(tmp_path, steps, message):
    manager = AgentManager(str(tmp_path / "invalid-graph.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        proposal = PlanProposal("invalid", steps)
        with pytest.raises(PlanProposalError, match=message):
            _materialize(manager, agent["id"], proposal)
        assert _plan(manager, agent["id"])["nodes"] == []
    finally:
        manager.close()


def test_p3d_a9_a10_verified_step_is_closed_to_model_duplicate(tmp_path):
    _PlanProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "verified.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result = _materialize(manager, agent["id"])
        _run(
            manager,
            agent["id"],
            [
                _call("s1-call", "one"),
                _call("fresh-call", "one"),
                {"content": "done"},
            ],
        )
        assert _PlanProposalMutationTool.calls == 1
        plan = _plan(manager, agent["id"])
        assert (
            _node(plan, result["local_to_planner_node"]["s1"])["status"] == "COMPLETED"
        )
        assert _node(plan, result["local_to_planner_node"]["s2"])["status"] == "PLANNED"
        assert (
            result["local_to_planner_node"]["s1"]
            != result["local_to_planner_node"]["s2"]
        )
    finally:
        manager.close()


def test_p3d_a11_a12_trusted_s2_activation_allows_second_action(tmp_path):
    _PlanProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "s2.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result = _materialize(manager, agent["id"])
        _run(manager, agent["id"], [_call("s1-call", "one"), {"content": "done"}])
        executor = AgentExecutor(manager, EventBus(), system=FakeSystem(FakeEngine([])))
        executor.advance_materialized_plan_node(
            agent["id"], planner_node_id=result["local_to_planner_node"]["s2"]
        )
        _run(manager, agent["id"], [_call("s2-call", "two"), {"content": "done"}])
        plan = _plan(manager, agent["id"])
        assert _PlanProposalMutationTool.calls == 2
        assert {node["status"] for node in plan["nodes"]} == {"COMPLETED"}
        assert len({node["mutation_intent_id"] for node in plan["nodes"]}) == 2
    finally:
        manager.close()


def test_p3d_a13_identical_actions_on_distinct_nodes_are_allowed(tmp_path):
    _PlanProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "identical.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result = _materialize(manager, agent["id"], _proposal(identical=True))
        _run(manager, agent["id"], [_call("s1-call", "same"), {"content": "done"}])
        AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).advance_materialized_plan_node(
            agent["id"], planner_node_id=result["local_to_planner_node"]["s2"]
        )
        _run(manager, agent["id"], [_call("s2-call", "same"), {"content": "done"}])
        assert _PlanProposalMutationTool.calls == 2
    finally:
        manager.close()


@pytest.mark.parametrize("kind", ["provider-call", "fresh-observation"])
def test_p3d_a14_a15_new_model_metadata_cannot_activate_s2(tmp_path, kind):
    _PlanProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / f"metadata-{kind}.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        _materialize(manager, agent["id"])
        _run(
            manager,
            agent["id"],
            [_call("s1-call"), _call(kind), {"content": "done"}],
        )
        plan = _plan(manager, agent["id"])
        assert _PlanProposalMutationTool.calls == 1
        assert sum(node["status"] == "ACTIVE" for node in plan["nodes"]) == 0
    finally:
        manager.close()


def test_p3d_a16_unknown_outcome_blocks_s2(tmp_path):
    _PlanProposalMutationTool.calls = 0
    _PlanProposalMutationTool.unknown = True
    manager = AgentManager(str(tmp_path / "unknown.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result = _materialize(manager, agent["id"])
        _run(manager, agent["id"], [_call("unknown")])
        with pytest.raises(ValueError, match="reconciliation"):
            AgentExecutor(
                manager, EventBus(), system=FakeSystem(FakeEngine([]))
            ).advance_materialized_plan_node(
                agent["id"], planner_node_id=result["local_to_planner_node"]["s2"]
            )
        plan = _plan(manager, agent["id"])
        assert _PlanProposalMutationTool.calls == 1
        assert (
            _node(plan, result["local_to_planner_node"]["s1"])["status"]
            == "RECONCILIATION_REQUIRED"
        )
        assert (
            _node(plan, result["local_to_planner_node"]["s2"])["mutation_intent_id"]
            is None
        )
    finally:
        _PlanProposalMutationTool.unknown = False
        manager.close()


def test_p3d_a17_restart_after_verified_preserves_s1_and_allows_trusted_s2(tmp_path):
    _PlanProposalMutationTool.calls = 0
    path = str(tmp_path / "restart.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _ready(manager, agent["id"])
    result = _materialize(manager, agent["id"])
    _run(manager, agent["id"], [_call("s1-call"), {"content": "done"}])
    restarted = _restart(manager, agent["id"], path)
    try:
        plan = _plan(restarted, agent["id"])
        assert (
            _node(plan, result["local_to_planner_node"]["s1"])["status"] == "COMPLETED"
        )
        _run(
            restarted, agent["id"], [_call("fresh-after-restart"), {"content": "done"}]
        )
        assert _PlanProposalMutationTool.calls == 1
        AgentExecutor(
            restarted, EventBus(), system=FakeSystem(FakeEngine([]))
        ).advance_materialized_plan_node(
            agent["id"], planner_node_id=result["local_to_planner_node"]["s2"]
        )
    finally:
        restarted.close()


def test_p3d_a18_compaction_preserves_plan_authority(tmp_path):
    _PlanProposalMutationTool.calls = 0
    path = str(tmp_path / "compaction.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _ready(manager, agent["id"])
    result = _materialize(manager, agent["id"])
    _run(manager, agent["id"], [_call("s1-call"), {"content": "done"}])
    checkpoint = manager.get_latest_checkpoint(agent["id"])
    assert checkpoint is not None
    manager.save_checkpoint(
        agent["id"],
        checkpoint["tick_id"],
        {**checkpoint["conversation_state"], "lifecycle": "RUNNING", "messages": []},
        checkpoint["tool_state"],
    )
    restarted = _restart(manager, agent["id"], path)
    try:
        _run(restarted, agent["id"], [_call("after-compaction"), {"content": "done"}])
        assert _PlanProposalMutationTool.calls == 1
        plan = _plan(restarted, agent["id"])
        assert (
            _node(plan, result["local_to_planner_node"]["s1"])["status"] == "COMPLETED"
        )
    finally:
        restarted.close()


@pytest.mark.parametrize("reason", ["user", "deadline"])
def test_p3d_a19_terminal_lifecycle_blocks_s2(tmp_path, reason):
    manager = AgentManager(str(tmp_path / f"terminal-{reason}.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result = _materialize(manager, agent["id"])
        _run(manager, agent["id"], [_call("s1-call"), {"content": "done"}])
        manager.start_tick(agent["id"])
        manager.request_cancellation(agent["id"], reason=reason)
        with pytest.raises(ValueError, match="Cancelled"):
            AgentExecutor(
                manager, EventBus(), system=FakeSystem(FakeEngine([]))
            ).advance_materialized_plan_node(
                agent["id"], planner_node_id=result["local_to_planner_node"]["s2"]
            )
    finally:
        manager.close()


def test_p3d_a20_checkpoint_plan_journal_mismatch_fails_closed(tmp_path):
    _PlanProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "mismatch.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result = _materialize(manager, agent["id"])
        _run(manager, agent["id"], [_call("s1-call"), {"content": "done"}])
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint is not None
        tool_state = copy.deepcopy(checkpoint["tool_state"])
        for node in tool_state["durable_plan"]["nodes"]:
            if node["planner_node_id"] == result["local_to_planner_node"]["s1"]:
                node["mutation_intent_id"] = "fake-intent"
                break
        manager.save_checkpoint(
            agent["id"],
            checkpoint["tick_id"],
            checkpoint["conversation_state"],
            tool_state,
        )
        with pytest.raises(ValueError):
            AgentExecutor(
                manager, EventBus(), system=FakeSystem(FakeEngine([]))
            ).advance_materialized_plan_node(
                agent["id"], planner_node_id=result["local_to_planner_node"]["s2"]
            )
        assert _PlanProposalMutationTool.calls == 1
    finally:
        manager.close()


def test_p3d_ac1_crash_before_materialization_has_no_partial_authority(tmp_path):
    from openjarvis.tools.execution_journal import ExecutionJournal

    journal = ExecutionJournal(tmp_path / "ac1.db")
    try:
        runtime = {"tool_state": {"execution_id": "ac1-execution"}}
        controller = _ManagedMutationController(journal, "ac1", runtime)
        controller.materialize_plan(
            _proposal(), supported_tools={_PlanProposalMutationTool.tool_id}
        )
        restarted = _ManagedMutationController(
            journal, "ac1", {"tool_state": {"execution_id": "ac1-execution"}}
        )
        assert restarted.plan.nodes == {}
        assert journal.pending("ac1") == []
    finally:
        journal.close()


def test_p3d_ac2_crash_before_s1_restores_same_plan(tmp_path):
    path = str(tmp_path / "ac2.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _ready(manager, agent["id"])
    result = _materialize(manager, agent["id"])
    restarted = _restart(manager, agent["id"], path)
    try:
        plan = _plan(restarted, agent["id"])
        assert plan["plan_id"] == result["plan_id"]
        assert {node["planner_node_id"] for node in plan["nodes"]} == set(
            result["local_to_planner_node"].values()
        )
    finally:
        restarted.close()


def test_p3d_ac3_crash_after_verified_does_not_replay_s1(tmp_path):
    _PlanProposalMutationTool.calls = 0
    path = str(tmp_path / "ac3.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _ready(manager, agent["id"])
    _materialize(manager, agent["id"])
    _run(manager, agent["id"], [_call("s1-call"), {"content": "done"}])
    restarted = _restart(manager, agent["id"], path)
    try:
        _run(
            restarted,
            agent["id"],
            [_call("duplicate-after-crash"), {"content": "done"}],
        )
        assert _PlanProposalMutationTool.calls == 1
    finally:
        restarted.close()


def test_p3d_ac4_crash_after_s2_activation_reuses_s2_intent(tmp_path):
    _PlanProposalMutationTool.calls = 0
    path = str(tmp_path / "ac4.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _ready(manager, agent["id"])
    result = _materialize(manager, agent["id"])
    _run(manager, agent["id"], [_call("s1-call"), {"content": "done"}])
    AgentExecutor(
        manager, EventBus(), system=FakeSystem(FakeEngine([]))
    ).advance_materialized_plan_node(
        agent["id"], planner_node_id=result["local_to_planner_node"]["s2"]
    )
    restarted = _restart(manager, agent["id"], path)
    try:
        _run(restarted, agent["id"], [_call("s2-call", "two"), {"content": "done"}])
        assert _PlanProposalMutationTool.calls == 2
        plan = _plan(restarted, agent["id"])
        assert plan["nodes"][1]["status"] == "COMPLETED"
    finally:
        restarted.close()


def test_p3d_ac5_unknown_outcome_survives_restart_and_blocks_s2(tmp_path):
    _PlanProposalMutationTool.calls = 0
    _PlanProposalMutationTool.unknown = True
    path = str(tmp_path / "ac5.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _ready(manager, agent["id"])
    result = _materialize(manager, agent["id"])
    _run(manager, agent["id"], [_call("unknown")])
    restarted = _restart(manager, agent["id"], path)
    try:
        with pytest.raises(ValueError):
            AgentExecutor(
                restarted, EventBus(), system=FakeSystem(FakeEngine([]))
            ).advance_materialized_plan_node(
                agent["id"], planner_node_id=result["local_to_planner_node"]["s2"]
            )
        assert _PlanProposalMutationTool.calls == 1
    finally:
        _PlanProposalMutationTool.unknown = False
        restarted.close()
