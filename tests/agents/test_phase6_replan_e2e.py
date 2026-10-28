"""Phase 6 model-driven planning and replan through the managed tick path."""

from __future__ import annotations

import json

from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.orchestrator import OrchestratorAgent  # noqa: F401
from openjarvis.core.events import EventBus
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import AgentRegistry, ToolRegistry
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem


class _Phase6GoalTool(BaseTool):
    tool_id = "phase6_goal_tool"
    calls: list[str] = []

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id,
            "test-only verified goal mutation",
            parameters={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
            },
            effect=ToolEffect.MUTATING,
        )

    def execute(self, **params):
        value = str(params.get("value", ""))
        type(self).calls.append(value)
        if value == "blocked-first":
            return ToolResult(
                self.tool_id,
                "TARGET_NOT_FOUND: retained target is unavailable",
                success=False,
                execution_state=ExecutionState.NOT_STARTED,
                metadata={"error_code": "TARGET_NOT_FOUND"},
            )
        return ToolResult(
            self.tool_id,
            f"verified {value}",
            execution_state=ExecutionState.VERIFIED,
            metadata={"verification": "independent fake read-back"},
        )


def _register_tool() -> None:
    if not AgentRegistry.contains("orchestrator"):
        AgentRegistry.register_value("orchestrator", OrchestratorAgent)
    if not ToolRegistry.contains(_Phase6GoalTool.tool_id):
        ToolRegistry.register_value(_Phase6GoalTool.tool_id, _Phase6GoalTool)


def _plan(value: str, *, proposal_id: str) -> str:
    return json.dumps(
        {
            "proposal_id": proposal_id,
            "steps": [
                {
                    "local_index": "only",
                    "kind": "MUTATING",
                    "tool_name": _Phase6GoalTool.tool_id,
                    "arguments": {"value": value},
                }
            ],
        }
    )


def _tool_response(value: str, call_id: str) -> dict:
    return {
        "tool_calls": [
            {
                "id": call_id,
                "name": _Phase6GoalTool.tool_id,
                "arguments": json.dumps({"value": value}),
            }
        ]
    }


def _agent(manager: AgentManager) -> dict:
    _register_tool()
    return manager.create_agent(
        "phase6-managed-goal",
        agent_type="orchestrator",
        config={
            "model": "fake-model",
            "instruction": "Complete the controlled goal.",
            "tools": [_Phase6GoalTool.tool_id],
            "goal_planning": {
                "max_replans": 1,
                "planner_max_tokens": 128,
            },
        },
    )


def _restart_for_next_tick(manager: AgentManager, agent_id: str) -> None:
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
    manager.recover_agent(agent_id)


def test_managed_goal_planning_uses_production_executor_and_completes(tmp_path):
    _Phase6GoalTool.calls = []
    engine = FakeEngine(
        [
            {"content": _plan("final", proposal_id="initial")},
            _tool_response("final", "call-final"),
            {"content": "Goal complete."},
        ]
    )
    manager = AgentManager(str(tmp_path / "initial.db"))
    try:
        agent = _agent(manager)
        AgentExecutor(
            manager, EventBus(), system=FakeSystem(engine)
        ).execute_tick(agent["id"])
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint is not None
        plan = checkpoint["tool_state"]["durable_plan"]
        assert plan["revisions"][-1]["reason"] == "INITIAL_PLAN"
        assert [node["status"] for node in plan["nodes"]] == ["COMPLETED"]
        assert _Phase6GoalTool.calls == ["final"]
        assert engine.call_count == 3
        assert manager.execution_journal.pending(agent["id"]) == []
    finally:
        manager.close()


def test_managed_model_replan_reaches_completion_after_not_executed(
    tmp_path, monkeypatch
):
    _Phase6GoalTool.calls = []
    engine = FakeEngine(
        [
            {"content": _plan("blocked-first", proposal_id="initial")},
            _tool_response("blocked-first", "call-blocked"),
            {"content": "The retained target failed; stop this tick."},
            {"content": _plan("replacement", proposal_id="replan")},
            _tool_response("replacement", "call-replacement"),
            {"content": "Goal complete after the safe replan."},
        ]
    )
    manager = AgentManager(str(tmp_path / "replan.db"))
    try:
        agent = _agent(manager)
        original_save_checkpoint = manager.save_checkpoint
        failed_prepared_checkpoint = True

        def fail_before_dispatch(*args, **kwargs):
            nonlocal failed_prepared_checkpoint
            tool_state = args[3] if len(args) > 3 else kwargs.get("tool_state", {})
            active = tool_state.get("active_step", {})
            if failed_prepared_checkpoint and active.get("state") == "EXECUTING":
                failed_prepared_checkpoint = False
                raise OSError("synthetic checkpoint failure before dispatch")
            return original_save_checkpoint(*args, **kwargs)

        monkeypatch.setattr(manager, "save_checkpoint", fail_before_dispatch)
        executor = AgentExecutor(
            manager, EventBus(), system=FakeSystem(engine)
        )
        executor.execute_tick(agent["id"])
        failed = manager.get_latest_checkpoint(agent["id"])
        assert failed is not None
        assert failed["tool_state"]["durable_plan"]["nodes"][0]["status"] == (
            "FAILED"
        )
        assert manager.execution_journal.pending(agent["id"]) == []

        _restart_for_next_tick(manager, agent["id"])
        executor.execute_tick(agent["id"])

        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint is not None
        state = checkpoint["tool_state"]
        plan = state["durable_plan"]
        assert state["replan_count"] == 1
        assert plan["revisions"][-1]["reason"] == "REPLAN"
        assert any(node["status"] == "SUPERSEDED" for node in plan["nodes"])
        assert any(node["status"] == "COMPLETED" for node in plan["nodes"])
        assert _Phase6GoalTool.calls == ["replacement"]
        assert engine.call_count == 6
        assert manager.execution_journal.pending(agent["id"]) == []
    finally:
        manager.close()


def test_managed_goal_planning_rejects_untrusted_tool_without_dispatch(tmp_path):
    _Phase6GoalTool.calls = []
    engine = FakeEngine(
        [
            {
                "content": json.dumps(
                    {
                        "proposal_id": "hostile",
                        "steps": [
                            {
                                "local_index": "bad",
                                "kind": "MUTATING",
                                "tool_name": "not_configured",
                            }
                        ],
                    }
                )
            }
        ]
    )
    manager = AgentManager(str(tmp_path / "reject.db"))
    try:
        agent = _agent(manager)
        AgentExecutor(
            manager, EventBus(), system=FakeSystem(engine)
        ).execute_tick(agent["id"])
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint is not None
        assert "durable_plan" not in checkpoint["tool_state"]
        assert _Phase6GoalTool.calls == []
        assert engine.call_count == 1
    finally:
        manager.close()
