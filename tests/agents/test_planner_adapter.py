"""Phase 3D-B planner adapter tests (non-physical)."""

from __future__ import annotations

import json

import pytest

from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.planner import (
    PlannerAdapter,
    PlannerParseError,
    ReplannerAdapter,
)
from openjarvis.core.events import EventBus
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem
from tests.agents.test_plan_proposal_materialization import (
    _agent,
    _call,
    _node,
    _plan,
    _PlanProposalMutationTool,
    _ready,
    _restart,
    _run,
)
from tests.agents.test_replan_revisions import _setup_not_executed


def _payload(*, authority: dict | None = None) -> str:
    body = {
        "proposal_id": "model-proposal",
        "steps": [
            {
                "local_index": "s1",
                "kind": "MUTATING",
                "tool_name": _PlanProposalMutationTool.tool_id,
                "arguments": {"value": "one"},
            },
            {
                "local_index": "s2",
                "kind": "MUTATING",
                "tool_name": _PlanProposalMutationTool.tool_id,
                "arguments": {"value": "two"},
                "dependencies": ["s1"],
            },
        ],
    }
    if authority:
        body.update(authority)
    return json.dumps(body)


def _planner(content: str, *, source: str = "model_planner") -> PlannerAdapter:
    return PlannerAdapter(
        FakeEngine([{"content": content}]), model="fake-model", source=source
    )


def _replanner(content: str, *, source: str = "model_replanner") -> ReplannerAdapter:
    return ReplannerAdapter(
        FakeEngine([{"content": content}]), model="fake-model", source=source
    )


def _materialize_with_planner(manager: AgentManager, agent_id: str, planner=None):
    planner = planner or _planner(_payload())
    result = AgentExecutor(
        manager, EventBus(), system=FakeSystem(FakeEngine([]))
    ).plan_goal(
        agent_id,
        planner,
        "complete the controlled task",
        supported_tools={_PlanProposalMutationTool.tool_id},
    )
    return result, planner


def test_p3d_b1_b4_goal_adapter_materializes_controller_ids(tmp_path):
    manager = AgentManager(str(tmp_path / "initial.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result, planner = _materialize_with_planner(manager, agent["id"])
        assert planner.call_count == 1
        assert result["plan_id"] != "model-proposal"
        assert result["active_node_id"].startswith("node-")
        assert all(
            node["planner_node_id"].startswith("node-")
            for node in result["plan"]["nodes"]
        )
        assert all(
            node["mutation_intent_id"] is None for node in result["plan"]["nodes"]
        )
    finally:
        manager.close()


def test_p3d_b5_malformed_output_fails_closed(tmp_path):
    manager = AgentManager(str(tmp_path / "malformed.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        planner = _planner('{"steps": []} trailing')
        with pytest.raises(PlannerParseError, match="PLAN_PROPOSAL_PARSE_FAILED"):
            _materialize_with_planner(manager, agent["id"], planner)
        assert _plan(manager, agent["id"])["nodes"] == []
        assert manager.execution_journal.pending(agent["id"]) == []
    finally:
        manager.close()


@pytest.mark.parametrize(
    "authority",
    [
        {"plan_id": "fake-plan"},
        {"revision": 99},
        {
            "steps": [
                {
                    "local_index": "s1",
                    "kind": "MUTATING",
                    "tool_name": "x",
                    "arguments": {"mutation_intent_id": "fake"},
                }
            ]
        },
    ],
)
def test_p3d_b6_authority_injection_fails_closed(tmp_path, authority):
    manager = AgentManager(str(tmp_path / "authority.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        with pytest.raises(PlannerParseError, match="PLAN_PROPOSAL_PARSE_FAILED"):
            _materialize_with_planner(
                manager, agent["id"], _planner(_payload(authority=authority))
            )
        assert _plan(manager, agent["id"])["nodes"] == []
    finally:
        manager.close()


def test_p3d_b7_b8_multi_step_plan_has_one_frontier_and_no_i2(tmp_path):
    manager = AgentManager(str(tmp_path / "frontier.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result, _ = _materialize_with_planner(manager, agent["id"])
        nodes = result["plan"]["nodes"]
        assert sum(node["status"] == "ACTIVE" for node in nodes) == 1
        assert sum(node["mutation_intent_id"] is not None for node in nodes) == 0
        s2 = next(
            node
            for node in nodes
            if node["planner_node_id"] != result["active_node_id"]
        )
        assert s2["status"] == "PLANNED"
    finally:
        manager.close()


def test_p3d_b9_b10_b11_trusted_progression_needs_no_planner_call(tmp_path):
    _PlanProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "progress.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result, planner = _materialize_with_planner(manager, agent["id"])
        _run(manager, agent["id"], [_call("s1"), {"content": "done"}])
        s2 = next(
            node["planner_node_id"]
            for node in result["plan"]["nodes"]
            if node["planner_node_id"] != result["active_node_id"]
        )
        AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).advance_materialized_plan_node(agent["id"], planner_node_id=s2)
        _run(manager, agent["id"], [_call("s2", "two"), {"content": "done"}])
        assert planner.call_count == 1
        assert _PlanProposalMutationTool.calls == 2
    finally:
        manager.close()


def test_p3d_b10_b11_fresh_call_and_observation_cannot_create_authority(tmp_path):
    manager = AgentManager(str(tmp_path / "fresh-identities.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        _, initial = _materialize_with_planner(manager, agent["id"])
        fresh = _planner(_payload())
        reused = AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).plan_goal(
            agent["id"],
            fresh,
            "same goal after provider-call-2 and observation-2",
            context={"provider_call_id": "call-2", "observation_id": "obs-2"},
            supported_tools={_PlanProposalMutationTool.tool_id},
        )
        assert initial.call_count == 1
        assert fresh.call_count == 0
        assert reused["reused"] is True
    finally:
        manager.close()


def test_p3d_b12_b13_restart_reuses_plan_and_does_not_replay(tmp_path):
    _PlanProposalMutationTool.calls = 0
    path = str(tmp_path / "restart.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _ready(manager, agent["id"])
    result, planner = _materialize_with_planner(manager, agent["id"])
    _run(manager, agent["id"], [_call("s1"), {"content": "done"}])
    restarted = _restart(manager, agent["id"], path)
    try:
        reused = AgentExecutor(
            restarted, EventBus(), system=FakeSystem(FakeEngine([]))
        ).plan_goal(
            agent["id"],
            planner,
            "replan me",
            supported_tools={_PlanProposalMutationTool.tool_id},
        )
        assert reused["reused"] is True
        assert planner.call_count == 1
        assert _PlanProposalMutationTool.calls == 1
        assert (
            _node(_plan(restarted, agent["id"]), result["active_node_id"])["status"]
            == "COMPLETED"
        )
    finally:
        restarted.close()


def test_p3d_b14_final_answer_failure_does_not_replan(tmp_path):
    path = str(tmp_path / "final-failure.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _ready(manager, agent["id"])
    result, planner = _materialize_with_planner(manager, agent["id"])
    _run(manager, agent["id"], [_call("s1"), {"content": "done"}])
    restarted = _restart(manager, agent["id"], path)
    try:
        reused = AgentExecutor(
            restarted, EventBus(), system=FakeSystem(FakeEngine([]))
        ).plan_goal(
            agent["id"],
            planner,
            "final prose retry",
            supported_tools={_PlanProposalMutationTool.tool_id},
        )
        assert reused["plan_id"] == result["plan_id"]
        assert planner.call_count == 1
    finally:
        restarted.close()


@pytest.mark.parametrize("reason", ["user", "deadline"])
def test_p3d_b15_b16_terminal_lifecycle_blocks_planning(tmp_path, reason):
    manager = AgentManager(str(tmp_path / f"terminal-{reason}.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        manager.start_tick(agent["id"])
        manager.request_cancellation(agent["id"], reason=reason)
        with pytest.raises(ValueError, match="Cancelled"):
            _materialize_with_planner(manager, agent["id"])
    finally:
        manager.close()


def test_p3d_b17_unknown_outcome_blocks_without_replan_call(tmp_path):
    _PlanProposalMutationTool.calls = 0
    _PlanProposalMutationTool.unknown = True
    manager = AgentManager(str(tmp_path / "unknown.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        _materialize_with_planner(manager, agent["id"])
        _run(manager, agent["id"], [_call("unknown")])
        planner = _planner(_payload())
        with pytest.raises(ValueError, match="reconciliation"):
            AgentExecutor(
                manager, EventBus(), system=FakeSystem(FakeEngine([]))
            ).plan_goal(
                agent["id"],
                planner,
                "replace uncertain step",
                supported_tools={_PlanProposalMutationTool.tool_id},
            )
        assert planner.call_count == 0
        assert _PlanProposalMutationTool.calls == 1
    finally:
        _PlanProposalMutationTool.unknown = False
        manager.close()


def test_p3d_b18_model_replan_adapter_appends_controller_revision(tmp_path):
    manager, agent, original = _setup_not_executed(tmp_path, "adapter")
    replanner = _replanner(_payload())
    try:
        result = AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).replan_goal(
            agent["id"],
            replanner,
            "replace the failed suffix",
            supported_tools={_PlanProposalMutationTool.tool_id},
        )
        assert replanner.call_count == 1
        assert result["revision_id"] != original["plan"]["revision_id"]
        assert result["parent_revision_id"] == original["plan"]["revision_id"]
        assert result["plan"]["revisions"][-1]["reason"] == "REPLAN"
        assert all(
            node["planner_node_id"].startswith("node-")
            for node in result["plan"]["nodes"]
        )
    finally:
        manager.close()


def test_p3d_b19_completed_history_is_retained(tmp_path):
    manager = AgentManager(str(tmp_path / "history.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result, _ = _materialize_with_planner(manager, agent["id"])
        _run(manager, agent["id"], [_call("s1"), {"content": "done"}])
        plan = _plan(manager, agent["id"])
        assert _node(plan, result["active_node_id"])["status"] == "COMPLETED"
    finally:
        manager.close()


def test_p3d_b20_checkpoint_plan_journal_inconsistency_fails_closed(tmp_path):
    manager = AgentManager(str(tmp_path / "mismatch.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result, _ = _materialize_with_planner(manager, agent["id"])
        _run(manager, agent["id"], [_call("s1"), {"content": "done"}])
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint is not None
        tool_state = dict(checkpoint["tool_state"])
        tool_state["durable_plan"] = dict(tool_state["durable_plan"])
        tool_state["durable_plan"]["plan_id"] = "wrong-plan"
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
                agent["id"],
                planner_node_id=next(
                    node["planner_node_id"]
                    for node in result["plan"]["nodes"]
                    if node["planner_node_id"] != result["active_node_id"]
                ),
            )
    finally:
        manager.close()


def test_p3d_bc1_bc2_invalid_response_has_no_authority(tmp_path):
    manager = AgentManager(str(tmp_path / "crash-before.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        for content in ("not-json", _payload(authority={"execution_id": "fake"})):
            with pytest.raises(PlannerParseError, match="PLAN_PROPOSAL_PARSE_FAILED"):
                _materialize_with_planner(manager, agent["id"], _planner(content))
        assert _plan(manager, agent["id"])["nodes"] == []
    finally:
        manager.close()


def test_p3d_bc3_existing_plan_restores_without_planner_call(tmp_path):
    manager = AgentManager(str(tmp_path / "restore.db"))
    agent = _agent(manager)
    try:
        _ready(manager, agent["id"])
        result, planner = _materialize_with_planner(manager, agent["id"])
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint is not None
        restored = AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).plan_goal(
            agent["id"],
            planner,
            "same goal",
            supported_tools={_PlanProposalMutationTool.tool_id},
        )
        assert restored["plan_id"] == result["plan_id"]
        assert planner.call_count == 1
    finally:
        manager.close()


def test_p3d_bc4_verified_restart_does_not_replay(tmp_path):
    _PlanProposalMutationTool.calls = 0
    path = str(tmp_path / "verified-crash.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _ready(manager, agent["id"])
    _materialize_with_planner(manager, agent["id"])
    _run(manager, agent["id"], [_call("s1"), {"content": "done"}])
    restarted = _restart(manager, agent["id"], path)
    try:
        _run(restarted, agent["id"], [{"content": "final answer"}])
        assert _PlanProposalMutationTool.calls == 1
    finally:
        restarted.close()


def test_p3d_bc5_unknown_outcome_restart_blocks_planning(tmp_path):
    _PlanProposalMutationTool.calls = 0
    _PlanProposalMutationTool.unknown = True
    path = str(tmp_path / "unknown-crash.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _ready(manager, agent["id"])
    _materialize_with_planner(manager, agent["id"])
    _run(manager, agent["id"], [_call("unknown")])
    restarted = _restart(manager, agent["id"], path)
    try:
        with pytest.raises(ValueError, match="reconciliation"):
            _materialize_with_planner(restarted, agent["id"])
        assert _PlanProposalMutationTool.calls == 1
    finally:
        _PlanProposalMutationTool.unknown = False
        restarted.close()


def test_p3d_bc6_model_replan_requires_not_executed_before_contact(tmp_path):
    manager = AgentManager(str(tmp_path / "not-eligible.db"))
    agent = _agent(manager)
    replanner = _replanner(_payload())
    try:
        _ready(manager, agent["id"])
        _materialize_with_planner(manager, agent["id"])
        with pytest.raises(ValueError, match="NOT_EXECUTED"):
            AgentExecutor(
                manager, EventBus(), system=FakeSystem(FakeEngine([]))
            ).replan_goal(
                agent["id"],
                replanner,
                "must not contact the model",
                supported_tools={_PlanProposalMutationTool.tool_id},
            )
        assert replanner.call_count == 0
    finally:
        manager.close()
