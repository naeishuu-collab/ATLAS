"""Phase 3D-C append-only replan revision tests (non-physical)."""

from __future__ import annotations

import copy
import json

import pytest

from openjarvis.agents.executor import AgentExecutor, _ManagedMutationController
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.proposals import (
    PlanProposalError,
    PlanStepProposal,
    ReplanProposal,
)
from openjarvis.core.events import EventBus
from openjarvis.core.types import ToolCall
from openjarvis.tools._stubs import ToolExecutor
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem
from tests.agents.test_plan_proposal_materialization import (
    _agent,
    _call,
    _materialize,
    _node,
    _PlanProposalMutationTool,
    _ready,
    _restart,
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


def _plan(manager: AgentManager, agent_id: str) -> dict:
    checkpoint = manager.get_latest_checkpoint(agent_id)
    assert checkpoint is not None
    return checkpoint["tool_state"]["durable_plan"]


def _test_agent(manager: AgentManager) -> dict:
    """Reuse the shared test tool without duplicate registry registration."""
    try:
        return _agent(manager)
    except ValueError as exc:
        if "already has an entry" not in str(exc):
            raise
        return manager.create_agent(
            "phase3d-replan-test",
            agent_type="orchestrator",
            config={
                "model": "fake-model",
                "instruction": "Execute the controlled test step.",
                "tools": [TOOL],
            },
        )


def _setup_not_executed(tmp_path, name: str = "replan"):
    manager = AgentManager(str(tmp_path / f"{name}.db"))
    agent = _test_agent(manager)
    _ready(manager, agent["id"])
    materialized = _materialize(manager, agent["id"])
    _run(manager, agent["id"], [_call("s1"), {"content": "done"}])
    AgentExecutor(
        manager, EventBus(), system=FakeSystem(FakeEngine([]))
    ).advance_materialized_plan_node(
        agent["id"], planner_node_id=materialized["local_to_planner_node"]["s2"]
    )
    checkpoint = manager.get_latest_checkpoint(agent["id"])
    assert checkpoint is not None
    runtime = {"tool_state": copy.deepcopy(checkpoint["tool_state"])}
    controller = _ManagedMutationController(
        manager.execution_journal, agent["id"], runtime
    )
    intent = controller.context_for()
    tool = _PlanProposalMutationTool()
    executor = ToolExecutor(
        [tool],
        execution_journal=manager.execution_journal,
        execution_scope=agent["id"],
        require_mutation_intent=True,
    )
    call = ToolCall("not-executed", TOOL, json.dumps({"value": "old"}))

    def fail_checkpoint(state, _result):
        if state == "PREPARED":
            raise OSError("checkpoint unavailable")

    result = executor.execute(
        call,
        checkpoint_callback=fail_checkpoint,
        mutation_context=intent,
    )
    controller.record_result(call, result)
    manager.save_checkpoint(
        agent["id"],
        checkpoint["tick_id"],
        {**checkpoint["conversation_state"], "lifecycle": "RUNNING"},
        runtime["tool_state"],
    )
    manager.recover_agent(agent["id"])
    assert manager.execution_journal.semantic_intent(
        agent["id"], intent
    )["status"] == "NOT_EXECUTED"
    assert any(
        node["status"] == "FAILED" for node in _plan(manager, agent["id"])["nodes"]
    )
    assert _plan(manager, agent["id"])["nodes"]
    return manager, agent, materialized


def _replan(value: str = "replacement") -> ReplanProposal:
    return ReplanProposal(
        proposal_id="replan-model-1",
        source="fake-replanner",
        model_turn=4,
        steps=(
            PlanStepProposal(
                local_index="replacement",
                kind="MUTATING",
                tool_name=TOOL,
                arguments={"value": value},
            ),
        ),
    )


def _accept(manager, agent_id, proposal=None):
    return AgentExecutor(
        manager, EventBus(), system=FakeSystem(FakeEngine([]))
    ).accept_replan_proposal(
        agent_id,
        proposal or _replan(),
        supported_tools={TOOL},
    )


def test_c1_c2_initial_revision_is_controller_owned(tmp_path):
    manager = AgentManager(str(tmp_path / "initial.db"))
    agent = _test_agent(manager)
    try:
        _ready(manager, agent["id"])
        result = _materialize(manager, agent["id"])
        plan = _plan(manager, agent["id"])
        assert plan["revision_id"] != "model-plan"
        assert plan["parent_revision_id"] is None
        assert plan["revisions"][-1]["reason"] == "INITIAL_PLAN"
        assert result["plan_id"] == plan["plan_id"]
    finally:
        manager.close()


@pytest.mark.parametrize(
    "payload",
    [
        {"revision_id": "fake", "steps": []},
        {"plan_id": "fake", "steps": []},
        {
            "parent_revision_id": "fake",
            "steps": [
                {
                    "local_index": "s1",
                    "kind": "MUTATING",
                    "tool_name": TOOL,
                }
            ],
        },
    ],
)
def test_c3_replan_authority_fields_are_rejected(tmp_path, payload):
    with pytest.raises(PlanProposalError, match="PLAN_PROPOSAL_REJECTED"):
        ReplanProposal.from_dict(payload)


def test_c4_c7_c13_c14_accepts_only_proven_not_executed_and_new_intent(
    tmp_path,
):
    manager, agent, materialized = _setup_not_executed(tmp_path)
    try:
        old_plan = _plan(manager, agent["id"])
        old_s1 = materialized["local_to_planner_node"]["s1"]
        old_s2 = materialized["local_to_planner_node"]["s2"]
        accepted = _accept(manager, agent["id"])
        plan = accepted["plan"]
        old = _node(plan, old_s2)
        completed = _node(plan, old_s1)
        replacement = next(
            node
            for node in plan["nodes"]
            if node["planner_node_id"] not in {old_s1, old_s2}
        )
        assert accepted["parent_revision_id"] == old_plan["revision_id"]
        assert accepted["revision_id"] != old_plan["revision_id"]
        assert len(plan["revisions"]) == 2
        assert plan["revisions"][0]["revision_id"] == old_plan["revision_id"]
        assert _node(plan, old_s1)["status"] == "COMPLETED"
        assert completed["mutation_intent_id"]
        assert old["status"] == "SUPERSEDED"
        assert old["superseded_by"] == replacement["planner_node_id"]
        assert replacement["status"] == "PLANNED"
        assert replacement["mutation_intent_id"] is None
        assert _node(plan, old_s2)["planner_node_id"] == old_s2
        _run(
            manager,
            agent["id"],
            [_call("replacement-call", "replacement"), {"content": "done"}],
        )
        assert _PlanProposalMutationTool.calls == 2
        final = _plan(manager, agent["id"])
        assert _node(final, replacement["planner_node_id"])["status"] == "COMPLETED"
        assert _node(final, replacement["planner_node_id"])["mutation_intent_id"]
    finally:
        manager.close()


def test_c5_c6_c18_completed_and_unknown_states_block_replan(tmp_path):
    manager = AgentManager(str(tmp_path / "blocked.db"))
    agent = _test_agent(manager)
    try:
        _ready(manager, agent["id"])
        _materialize(manager, agent["id"])
        _run(manager, agent["id"], [_call("s1"), {"content": "done"}])
        with pytest.raises(ValueError, match="only NOT_EXECUTED"):
            _accept(manager, agent["id"])
        assert len(_plan(manager, agent["id"])["revisions"]) == 1
    finally:
        manager.close()

    manager = AgentManager(str(tmp_path / "unknown.db"))
    agent = _test_agent(manager)
    try:
        _PlanProposalMutationTool.calls = 0
        _ready(manager, agent["id"])
        _materialize(manager, agent["id"])
        _PlanProposalMutationTool.unknown = True
        _run(manager, agent["id"], [_call("unknown")])
        with pytest.raises(ValueError, match="REPLAN_BLOCKED_RECONCILIATION_REQUIRED"):
            _accept(manager, agent["id"])
        plan = _plan(manager, agent["id"])
        assert len(plan["revisions"]) == 1
        assert _PlanProposalMutationTool.calls == 1
    finally:
        _PlanProposalMutationTool.unknown = False
        manager.close()


def test_c8_c9_c10_c11_append_only_history_and_fresh_identity(tmp_path):
    manager, agent, materialized = _setup_not_executed(tmp_path)
    try:
        before = _plan(manager, agent["id"])
        accepted = _accept(manager, agent["id"])
        after = accepted["plan"]
        old_id = materialized["local_to_planner_node"]["s2"]
        assert after["revisions"][0]["nodes"]
        assert any(
            node["planner_node_id"] == old_id
            and node["status"] == "FAILED"
            for node in after["revisions"][0]["nodes"]
        )
        assert _node(after, old_id)["status"] == "SUPERSEDED"
        assert old_id not in {
            node["planner_node_id"]
            for node in after["revisions"][1]["nodes"]
            if node["planner_node_id"] != old_id
        }
        assert after["revisions"][1]["parent_revision_id"] == before["revision_id"]
    finally:
        manager.close()


def test_c12_c15_normal_advancement_does_not_create_revision_or_early_intent(tmp_path):
    manager = AgentManager(str(tmp_path / "advance.db"))
    agent = _test_agent(manager)
    try:
        _ready(manager, agent["id"])
        materialized = _materialize(manager, agent["id"])
        initial = _plan(manager, agent["id"])
        assert all(node["mutation_intent_id"] is None for node in initial["nodes"])
        _run(manager, agent["id"], [_call("s1"), {"content": "done"}])
        AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).advance_materialized_plan_node(
            agent["id"], planner_node_id=materialized["local_to_planner_node"]["s2"]
        )
        advanced = _plan(manager, agent["id"])
        assert len(advanced["revisions"]) == 1
        assert _node(advanced, materialized["local_to_planner_node"]["s2"])[
            "mutation_intent_id"
        ] is None
    finally:
        manager.close()


def test_c14_identical_future_action_gets_a_fresh_intent(tmp_path):
    manager, agent, _ = _setup_not_executed(tmp_path, "identical-future")
    try:
        accepted = _accept(manager, agent["id"], _replan("ok"))
        replacement = next(
            node
            for node in accepted["plan"]["nodes"]
            if node["status"] == "PLANNED"
        )
        _run(manager, agent["id"], [_call("same-action", "ok"), {"content": "done"}])
        final = _plan(manager, agent["id"])
        assert _PlanProposalMutationTool.calls == 2
        assert _node(final, replacement["planner_node_id"])["status"] == "COMPLETED"
    finally:
        manager.close()


def test_c16_c17_rb7_restart_and_compaction_preserve_lineage(tmp_path):
    path = str(tmp_path / "restart.db")
    manager, agent, _ = _setup_not_executed(tmp_path, "restart")
    accepted = _accept(manager, agent["id"])
    expected = accepted["plan"]
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
        restored = _plan(restarted, agent["id"])
        assert restored["revision_id"] == expected["revision_id"]
        assert restored["parent_revision_id"] == expected["parent_revision_id"]
        assert restored["revisions"] == expected["revisions"]
        _run(restarted, agent["id"], [{"content": "no replay"}])
        assert _PlanProposalMutationTool.calls == 1
    finally:
        restarted.close()


@pytest.mark.parametrize("reason", ["user", "deadline"])
def test_c18_terminal_lifecycle_blocks_revision(tmp_path, reason):
    manager, agent, _ = _setup_not_executed(tmp_path, reason)
    try:
        manager.start_tick(agent["id"])
        manager.request_cancellation(agent["id"], reason=reason)
        with pytest.raises(ValueError, match="cannot accept a replan"):
            _accept(manager, agent["id"])
        assert len(_plan(manager, agent["id"])["revisions"]) == 1
    finally:
        manager.close()


def test_c19_revision_checkpoint_mismatch_fails_closed(tmp_path):
    manager, agent, _ = _setup_not_executed(tmp_path)
    try:
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint is not None
        state = copy.deepcopy(checkpoint["tool_state"])
        state["revision_id"] = "wrong-revision"
        manager.save_checkpoint(
            agent["id"], checkpoint["tick_id"], checkpoint["conversation_state"], state
        )
        with pytest.raises(ValueError, match="revision"):
            _accept(manager, agent["id"])
        assert len(_plan(manager, agent["id"])["revisions"]) == 1
    finally:
        manager.close()


def test_c19_latest_revision_node_mismatch_fails_closed(tmp_path):
    manager, agent, _ = _setup_not_executed(tmp_path, "revision-node-mismatch")
    try:
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint is not None
        state = copy.deepcopy(checkpoint["tool_state"])
        state["durable_plan"]["revisions"][-1]["nodes"][0][
            "planner_node_id"
        ] = "wrong-node"
        manager.save_checkpoint(
            agent["id"], checkpoint["tick_id"], checkpoint["conversation_state"], state
        )
        with pytest.raises(ValueError, match="latest revision"):
            _accept(manager, agent["id"])
    finally:
        manager.close()


def test_c20_malformed_replan_fails_closed(tmp_path):
    with pytest.raises(PlanProposalError):
        ReplanProposal.from_dict(
            {
                "proposal_id": "bad",
                "steps": [
                    {
                        "local_index": "s1",
                        "kind": "MUTATING",
                        "tool_name": TOOL,
                        "arguments": '{"revision_id":"fake"} trailing',
                    }
                ],
            }
        )

    with pytest.raises(PlanProposalError, match="REPLAN_PROPOSAL_PARSE_FAILED"):
        ReplanProposal.from_dict(
            {
                "proposal_id": "duplicate-key",
                "steps": [
                    {
                        "local_index": "s1",
                        "kind": "MUTATING",
                        "tool_name": TOOL,
                        "arguments": '{"value":1,"value":2}',
                    }
                ],
            }
        )


def test_cc1_cc2_failed_save_leaves_r0_authoritative(tmp_path, monkeypatch):
    manager, agent, _ = _setup_not_executed(tmp_path)
    try:
        before = _plan(manager, agent["id"])
        original = manager.save_checkpoint

        def fail_save(*args, **kwargs):
            raise OSError("synthetic revision commit failure")

        monkeypatch.setattr(manager, "save_checkpoint", fail_save)
        with pytest.raises(OSError, match="revision commit"):
            _accept(manager, agent["id"])
        monkeypatch.setattr(manager, "save_checkpoint", original)
        after = _plan(manager, agent["id"])
        assert after["revision_id"] == before["revision_id"]
        assert len(after["revisions"]) == 1
    finally:
        manager.close()


def test_cc3_cc4_restart_after_accept_and_activation_keeps_one_identity(tmp_path):
    path = str(tmp_path / "activation.db")
    manager, agent, _ = _setup_not_executed(tmp_path, "activation")
    accepted = _accept(manager, agent["id"])
    replacement = next(
        node
        for node in accepted["plan"]["nodes"]
        if node["status"] == "PLANNED"
    )
    restarted = _restart(manager, agent["id"], path)
    try:
        after = _plan(restarted, agent["id"])
        active = _node(after, replacement["planner_node_id"])
        assert active["status"] == "PLANNED"
        _run(
            restarted,
            agent["id"],
            [_call("replacement", "replacement"), {"content": "done"}],
        )
        restored = _plan(restarted, agent["id"])
        assert _node(restored, replacement["planner_node_id"])["status"] == "COMPLETED"
    finally:
        restarted.close()


def test_cc5_replacement_verified_is_not_replayed_after_restart(tmp_path):
    path = str(tmp_path / "replacement-verified.db")
    manager, agent, _ = _setup_not_executed(tmp_path, "replacement-verified")
    accepted = _accept(manager, agent["id"])
    replacement = next(
        node for node in accepted["plan"]["nodes"] if node["status"] == "PLANNED"
    )
    _run(
        manager,
        agent["id"],
        [_call("replacement", "replacement"), {"content": "done"}],
    )
    assert _PlanProposalMutationTool.calls == 2
    restarted = _restart(manager, agent["id"], path)
    try:
        _run(restarted, agent["id"], [_call("duplicate"), {"content": "done"}])
        assert _PlanProposalMutationTool.calls == 2
        assert _node(_plan(restarted, agent["id"]), replacement["planner_node_id"])[
            "status"
        ] == "COMPLETED"
    finally:
        restarted.close()


def test_cc6_unknown_outcome_remains_quarantined(tmp_path):
    manager = AgentManager(str(tmp_path / "cc6.db"))
    agent = _test_agent(manager)
    try:
        _ready(manager, agent["id"])
        _materialize(manager, agent["id"])
        _PlanProposalMutationTool.unknown = True
        _run(manager, agent["id"], [_call("unknown")])
        manager.start_tick(agent["id"])
        manager.close()
        restarted = AgentManager(str(tmp_path / "cc6.db"), clear_stale_running=True)
        try:
            with pytest.raises(
                ValueError, match="REPLAN_BLOCKED_RECONCILIATION_REQUIRED"
            ):
                _accept(restarted, agent["id"])
            assert len(_plan(restarted, agent["id"])["revisions"]) == 1
        finally:
            restarted.close()
    finally:
        _PlanProposalMutationTool.unknown = False
        if getattr(manager, "_conn", None) is not None:
            try:
                manager.close()
            except Exception:
                pass


def test_rb1_rb2_rb3_rb4_rb5_rb8_replan_result_is_controller_owned(tmp_path):
    manager, agent, materialized = _setup_not_executed(tmp_path, "rb")
    try:
        original = _plan(manager, agent["id"])
        accepted = _accept(manager, agent["id"])
        new_nodes = [
            node
            for node in accepted["plan"]["nodes"]
            if node["planner_node_id"]
            not in {
                materialized["local_to_planner_node"]["s1"],
                materialized["local_to_planner_node"]["s2"],
            }
        ]
        assert accepted["revision_id"] not in {"fake", original["revision_id"]}
        assert accepted["parent_revision_id"] == original["revision_id"]
        assert new_nodes and new_nodes[0]["planner_node_id"].startswith("node-")
        assert accepted["plan"]["revisions"][0]["nodes"]
        with pytest.raises(ValueError, match="NOT_EXECUTED"):
            _accept(manager, agent["id"], _replan("again"))
    finally:
        manager.close()
