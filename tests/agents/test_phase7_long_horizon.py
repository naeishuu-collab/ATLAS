"""Phase 7 offline long-horizon durability and safe-replan proof."""

from __future__ import annotations

from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.orchestrator import OrchestratorAgent
from openjarvis.agents.proposals import (
    PlanProposal,
    PlanStepProposal,
    ReplanProposal,
)
from openjarvis.core.events import EventBus
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import AgentRegistry, ToolRegistry
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem


class _LongHorizonMutation(BaseTool):
    tool_id = "phase7_long_horizon_mutation"
    calls: list[str] = []

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id,
            "test-owned verified long-horizon mutation",
            effect=ToolEffect.MUTATING,
        )

    def execute(self, **params):
        value = str(params.get("value", ""))
        type(self).calls.append(value)
        return ToolResult(
            self.tool_id,
            f"verified {value}",
            execution_state=ExecutionState.VERIFIED,
            metadata={"verification": "independent test-store read-back"},
        )


def _agent(manager: AgentManager) -> dict:
    if not AgentRegistry.contains("orchestrator"):
        AgentRegistry.register_value("orchestrator", OrchestratorAgent)
    if not ToolRegistry.contains(_LongHorizonMutation.tool_id):
        ToolRegistry.register_value(_LongHorizonMutation.tool_id, _LongHorizonMutation)
    return manager.create_agent(
        "phase7-long-horizon",
        agent_type="orchestrator",
        config={
            "model": "fake-model",
            "instruction": "Complete the ten controlled steps.",
            "tools": [_LongHorizonMutation.tool_id],
            "mcp_tools": False,
        },
    )


def _executor(manager: AgentManager, engine: FakeEngine | None = None) -> AgentExecutor:
    return AgentExecutor(
        manager,
        EventBus(),
        system=FakeSystem(engine or FakeEngine([])),
    )


def _tick(manager: AgentManager, agent_id: str, responses: list[dict]) -> FakeEngine:
    engine = FakeEngine(responses)
    _executor(manager, engine).execute_tick(agent_id)
    return engine


def _call(value: str, call_id: str) -> dict:
    import json

    return {
        "tool_calls": [
            {
                "id": call_id,
                "name": _LongHorizonMutation.tool_id,
                "arguments": json.dumps({"value": value}),
            }
        ]
    }


def _plan(manager: AgentManager, agent_id: str) -> dict:
    checkpoint = manager.get_latest_checkpoint(agent_id)
    assert checkpoint is not None
    return checkpoint["tool_state"]["durable_plan"]


def _restart(manager: AgentManager, agent_id: str, path: str) -> AgentManager:
    checkpoint = manager.get_latest_checkpoint(agent_id)
    assert checkpoint is not None
    manager.save_checkpoint(
        agent_id,
        checkpoint["tick_id"],
        {
            **checkpoint["conversation_state"],
            "lifecycle": "RUNNING",
            "resumable": True,
            "resume_authorized": True,
        },
        checkpoint["tool_state"],
    )
    manager.start_tick(agent_id)
    manager.close()
    return AgentManager(path, clear_stale_running=True)


def _arm_pre_dispatch_checkpoint_failure(manager, monkeypatch) -> None:
    original = manager.save_checkpoint
    armed = True

    def fail_once(*args, **kwargs):
        nonlocal armed
        tool_state = args[3] if len(args) > 3 else kwargs.get("tool_state", {})
        if armed and isinstance(tool_state, dict):
            active = tool_state.get("active_step") or {}
            if active.get("state") == "EXECUTING":
                armed = False
                raise OSError("synthetic checkpoint corruption before dispatch")
        return original(*args, **kwargs)

    monkeypatch.setattr(manager, "save_checkpoint", fail_once)


def test_ten_step_goal_restarts_and_replans_without_duplicate_mutations(
    tmp_path, monkeypatch
):
    _LongHorizonMutation.calls = []
    path = str(tmp_path / "phase7-long-horizon.db")
    manager = AgentManager(path)
    agent_id = None
    try:
        agent = _agent(manager)
        agent_id = agent["id"]
        _tick(manager, agent_id, [{"content": "ready"}])
        first = PlanProposal(
            proposal_id="phase7-long-initial",
            steps=(
                PlanStepProposal(
                    local_index="s1",
                    kind="MUTATING",
                    tool_name=_LongHorizonMutation.tool_id,
                    arguments={"value": "out-1"},
                ),
            ),
        )
        minted = _executor(manager).materialize_plan_proposal(
            agent_id,
            first,
            supported_tools={_LongHorizonMutation.tool_id},
        )
        active_id = minted["local_to_planner_node"]["s1"]
        replanned = []

        for index in range(1, 11):
            if index > 1:
                _executor(manager).advance_plan_step(
                    agent_id, step_id=f"s{index}"
                )
                active_id = f"s{index}"

            if index in {3, 7}:
                _arm_pre_dispatch_checkpoint_failure(manager, monkeypatch)
                _tick(
                    manager,
                    agent_id,
                    [
                        _call(f"attempt-{index}", f"attempt-{index}"),
                        {"content": "Stop after the pre-dispatch checkpoint failure."},
                    ],
                )
                failed = _plan(manager, agent_id)
                assert any(
                    node["planner_node_id"] == active_id
                    and node["status"] == "FAILED"
                    for node in failed["nodes"]
                )
                assert manager.execution_journal.pending(agent_id) == []
                manager = _restart(manager, agent_id, path)

                replacement = ReplanProposal(
                    proposal_id=f"phase7-replan-{index}",
                    steps=(
                        PlanStepProposal(
                            local_index=f"replacement-{index}",
                            kind="MUTATING",
                            tool_name=_LongHorizonMutation.tool_id,
                            arguments={"value": f"out-{index}"},
                        ),
                    ),
                )
                replanned.append(
                    _executor(manager).replan_goal(
                        agent_id,
                        type(
                            "Replanner",
                            (),
                            {
                                "propose": (
                                    lambda _self, _goal, _context=None: replacement
                                )
                            },
                        )(),
                        "Complete the ten controlled steps",
                        supported_tools={_LongHorizonMutation.tool_id},
                    )
                )

            _tick(
                manager,
                agent_id,
                [
                    _call(f"out-{index}", f"success-{index}"),
                    {"content": f"step {index} verified"},
                ],
            )
            checkpoint = manager.get_latest_checkpoint(agent_id)
            assert checkpoint is not None
            assert manager.execution_journal.pending(agent_id) == []

            if index in {4, 8}:
                manager = _restart(manager, agent_id, path)

        final = _plan(manager, agent_id)
        completed_values = [
            value for value in _LongHorizonMutation.calls if value.startswith("out-")
        ]
        assert len(completed_values) == 10
        assert len(set(completed_values)) == 10
        assert len(replanned) == 2
        assert final["revisions"][-1]["reason"] == "REPLAN"
        assert all(
            node["status"] in {"COMPLETED", "SUPERSEDED"}
            for node in final["nodes"]
        )
        assert sum(node["status"] == "COMPLETED" for node in final["nodes"]) == 10
        assert manager.execution_journal.pending(agent_id) == []
    finally:
        if agent_id is not None:
            try:
                manager.close()
            except Exception:
                pass
