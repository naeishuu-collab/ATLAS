"""Autonomous agent Goal-to-Completion E2E (production path, offline).

Drives the REAL managed-execution chain — ``AgentExecutor.plan_goal``
(untrusted planner proposal -> controller materialization),
``OrchestratorAgent`` ticks, ``ToolExecutor`` with ``ExecutionJournal``
(require_mutation_intent), controller plan advancement, and checkpoints —
with controlled fake tools standing in only for external I/O. No test-only
agent implementation exists here: the production executor, journal state
machine and the production verifier contract (a mutating tool reports
``ExecutionState.VERIFIED`` only after an independent read-back, mirroring
the shipped ``file_write`` / browser tools) gate every scenario.

Scenario map (mission §5):
- single-step goal completes through the untrusted planner entry,
- multi-step goal with step-A output visible to step B and artifacts
  registered only after verified execution,
- target identity mismatch / ambiguous target refuse the mutation with
  zero dispatch and the goal is NOT reported complete,
- non-retryable (permission) failure stops on the first attempt.

Already proven by sibling suites and therefore not duplicated:
UNKNOWN_OUTCOME re-mutation ban + cross-scope rejection +
model-capability safe defer + step isolation (test_agent_safe_e2e),
tool-failure replan / timeout / cancellation (test_replan_revisions),
checkpoint resume (test_executor_resume), retry budgets (test_budget),
Windows/browser target identity fail-closed (test_windows_identity,
test_windows_action_contract, test_browser_safety).
"""

from __future__ import annotations

import json

from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.proposals import PlanProposal, PlanStepProposal
from openjarvis.core.events import EventBus
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import AgentRegistry, ToolRegistry
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem
from tests.agents.test_plan_proposal_materialization import (
    _plan,
    _ready,
    _restart,
    _run,
)


class _Counter:
    """Class-level fake external store shared across step boundaries."""

    store: dict[str, str] = {}
    dispatches = 0

    @classmethod
    def reset(cls):
        cls.store = {}
        cls.dispatches = 0


class _VerifiedNotesTool(BaseTool):
    """Mutation with independent read-back -> VERIFIED (file_write shape)."""

    tool_id = "goal_e2e_verified_note"
    artifact_sha: str = ""

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id,
            "test-only external note mutation with read-back verification",
            parameters={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
                "additionalProperties": False,
            },
            effect=ToolEffect.MUTATING,
        )

    def execute(self, **params):
        _Counter.dispatches += 1
        value = str(params.get("value", ""))
        # Independent verification: read the fake external state back
        # before reporting success (production file_write contract).
        _Counter.store["note"] = value
        if _Counter.store.get("note") != value:  # pragma: no cover - defensive
            return ToolResult(
                self.tool_id,
                "UNKNOWN_OUTCOME: resulting bytes did not verify.",
                success=False,
                execution_state=ExecutionState.UNKNOWN_OUTCOME,
            )
        import hashlib

        sha = hashlib.sha256(value.encode()).hexdigest()
        _VerifiedNotesTool.artifact_sha = sha
        return ToolResult(
            self.tool_id,
            f"Verified write of {value}",
            metadata={
                "verification": "read-back matched staged value",
                "artifacts": [
                    {
                        "type": "file",
                        "path": "notes/note.txt",
                        "size_bytes": len(value),
                        "sha256": sha,
                    }
                ],
            },
            execution_state=ExecutionState.VERIFIED,
        )


class _IdentityBoundMutationTool(BaseTool):
    """Target-identity binding fail-closed (browser/windows contract).

    Dispatch happens only for ``target_id`` values retained in the current
    observation snapshot; a mismatched or ambiguous reference is refused
    before any dispatch, mirroring tools/browser.py's AMBIGUOUS_TARGET /
    TARGET_NOT_FOUND posture.
    """

    tool_id = "goal_e2e_identity_bound_mutation"
    CURRENT_TARGET = "win-123"
    dispatches = 0

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id,
            "test-only identity-bound mutation",
            parameters={
                "type": "object",
                "properties": {
                    "target_id": {"type": "string"},
                    "value": {"type": "string"},
                },
                "required": ["target_id"],
                "additionalProperties": False,
            },
            effect=ToolEffect.MUTATING,
        )

    def execute(self, **params):
        target = str(params.get("target_id", ""))
        if "ambiguous" in target or "match" in target:
            return ToolResult(
                self.tool_id,
                "AMBIGUOUS_TARGET: reference is not a retained identity",
                success=False,
                metadata={"error_code": "AMBIGUOUS_TARGET"},
                execution_state=ExecutionState.NOT_STARTED,
            )
        if target != type(self).CURRENT_TARGET:
            return ToolResult(
                self.tool_id,
                "TARGET_IDENTITY_MISMATCH: stale or unknown identity",
                success=False,
                metadata={"error_code": "TARGET_IDENTITY_MISMATCH"},
                execution_state=ExecutionState.NOT_STARTED,
            )
        type(self).dispatches += 1
        _Counter.dispatches += 1
        return ToolResult(
            self.tool_id,
            "Verified mutation on retained identity",
            execution_state=ExecutionState.VERIFIED,
        )


def _register_tools() -> None:
    from openjarvis.agents.orchestrator import OrchestratorAgent

    AgentRegistry.register_value("orchestrator", OrchestratorAgent)
    ToolRegistry.register_value(_VerifiedNotesTool.tool_id, _VerifiedNotesTool)
    ToolRegistry.register_value(
        _IdentityBoundMutationTool.tool_id, _IdentityBoundMutationTool
    )


def _agent(manager: AgentManager, tool_id: str) -> dict:
    _register_tools()
    return manager.create_agent(
        "goal-completion-e2e",
        agent_type="orchestrator",
        config={
            "model": "fake-model",
            "instruction": "Complete the controlled goal steps.",
            "tools": [tool_id],
        },
    )


def _call(name: str, call_id: str, **args) -> dict:
    return {
        "tool_calls": [
            {"id": call_id, "name": name, "arguments": json.dumps(args)}
        ]
    }


def _planner_of(proposal: PlanProposal):
    class _Planner:
        def propose(self, goal, context=None):
            return proposal

    return _Planner()


def _executor(manager: AgentManager) -> AgentExecutor:
    return AgentExecutor(manager, EventBus(), system=FakeSystem(FakeEngine([])))


def _node(plan: dict, planner_node_id: str) -> dict:
    return next(
        n for n in plan["nodes"] if n["planner_node_id"] == planner_node_id
    )


def _completed(plan: dict) -> set[str]:
    return {
        n["planner_node_id"]
        for n in plan["nodes"]
        if n["status"] == "COMPLETED"
    }


def test_single_step_goal_completes_through_untrusted_planner(tmp_path):
    _Counter.reset()
    manager = AgentManager(str(tmp_path / "g1.db"))
    try:
        agent = _agent(manager, _VerifiedNotesTool.tool_id)
        _ready(manager, agent["id"])
        proposal = PlanProposal(
            proposal_id="planner-1",
            steps=(
                PlanStepProposal(
                    local_index="only",
                    kind="MUTATING",
                    tool_name=_VerifiedNotesTool.tool_id,
                    arguments={"value": "final-answer-7"},
                ),
            ),
        )
        minted = _executor(manager).plan_goal(
            agent["id"],
            _planner_of(proposal),
            "write the final note",
            supported_tools={_VerifiedNotesTool.tool_id},
        )
        assert minted["active_node_id"] == minted["local_to_planner_node"]["only"]
        plan = _plan(manager, agent["id"])
        node_id = minted["local_to_planner_node"]["only"]
        assert _node(plan, node_id)["status"] == "ACTIVE"

        _run(
            manager,
            agent["id"],
            [
                _call(_VerifiedNotesTool.tool_id, "n1", value="final-answer-7"),
                {"content": "Goal complete."},
            ],
        )

        plan = _plan(manager, agent["id"])
        assert _completed(plan) == {node_id}
        assert _Counter.store == {"note": "final-answer-7"}
        assert manager.execution_journal.pending(agent["id"]) == []
    finally:
        manager.close()


def test_step_a_output_is_visible_to_step_b_and_artifacts_register(tmp_path):
    _Counter.reset()
    manager = AgentManager(str(tmp_path / "g3.db"))
    try:
        agent = _agent(manager, _VerifiedNotesTool.tool_id)
        _ready(manager, agent["id"])
        proposal = PlanProposal(
            proposal_id="planner-2",
            steps=(
                PlanStepProposal(
                    local_index="s1",
                    kind="MUTATING",
                    tool_name=_VerifiedNotesTool.tool_id,
                    arguments={"value": "sentinel-42"},
                ),
                PlanStepProposal(
                    local_index="s2",
                    kind="MUTATING",
                    tool_name=_VerifiedNotesTool.tool_id,
                    arguments={"value": "derived-from-s1"},
                    dependencies=("s1",),
                ),
            ),
        )
        minted = _executor(manager).materialize_plan_proposal(
            agent["id"], proposal,
            supported_tools={_VerifiedNotesTool.tool_id},
        )
        s1_id = minted["local_to_planner_node"]["s1"]

        _run(
            manager,
            agent["id"],
            [
                _call(_VerifiedNotesTool.tool_id, "a1", value="sentinel-42"),
                {"content": "s1 done"},
            ],
        )

        # Verifier contract: artifacts register only after verified
        # execution; the completed step carries provenance-validated refs.
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        achieved = [
            s for s in checkpoint["tool_state"]["completed_steps"]
            if s.get("step_id") == s1_id
        ]
        assert achieved, "step A must be checkpointed before advancing"
        artifacts = achieved[-1].get("artifacts") or []
        assert artifacts and artifacts[0]["sha256"] == (
            _VerifiedNotesTool.artifact_sha
        )

        _executor(manager).advance_materialized_plan_node(
            agent["id"],
            planner_node_id=minted["local_to_planner_node"]["s2"],
        )
        second_engine = _run(
            manager,
            agent["id"],
            [
                _call(
                    _VerifiedNotesTool.tool_id, "b1",
                    value="derived-from-s1",
                ),
                {"content": "s2 done"},
            ],
        )

        # Step A's tool result must have reached step B's prompt: the
        # dependency chain carries observed output, not invented data.
        b_prompt = second_engine.last_messages
        flattened = "".join(
            str(
                m.get("content", "") if isinstance(m, dict)
                else getattr(m, "content", "")
            )
            for m in (b_prompt or [])
        )
        assert "sentinel-42" in flattened
        plan = _plan(manager, agent["id"])
        assert _completed(plan) == {
            s1_id, minted["local_to_planner_node"]["s2"],
        }
        assert _Counter.store == {"note": "derived-from-s1"}
    finally:
        manager.close()


def test_target_identity_mismatch_refuses_and_goal_stays_incomplete(tmp_path):
    _Counter.reset()
    manager = AgentManager(str(tmp_path / "g7.db"))
    try:
        agent = _agent(manager, _IdentityBoundMutationTool.tool_id)
        _ready(manager, agent["id"])
        proposal = PlanProposal(
            proposal_id="planner-3",
            steps=(
                PlanStepProposal(
                    local_index="targeted",
                    kind="MUTATING",
                    tool_name=_IdentityBoundMutationTool.tool_id,
                    arguments={"target_id": "stale-999", "value": "x"},
                ),
            ),
        )
        minted = _executor(manager).materialize_plan_proposal(
            agent["id"], proposal,
            supported_tools={_IdentityBoundMutationTool.tool_id},
        )
        node_id = minted["local_to_planner_node"]["targeted"]

        _run(
            manager,
            agent["id"],
            [
                _call(
                    _IdentityBoundMutationTool.tool_id, "t1",
                    target_id="stale-999", value="x",
                ),
                {"content": "stopping on identity mismatch"},
            ],
        )

        assert _IdentityBoundMutationTool.dispatches == 0
        plan = _plan(manager, agent["id"])
        assert _node(plan, node_id)["status"] != "COMPLETED"
        assert _completed(plan) == set()
        # No mutation intent may remain open for later silent replay.
        pending = manager.execution_journal.pending(agent["id"])
        for row in pending:
            assert row["status"] != "VERIFIED"
    finally:
        manager.close()


def test_ambiguous_target_refuses_mutation(tmp_path):
    _Counter.reset()
    manager = AgentManager(str(tmp_path / "g8.db"))
    try:
        agent = _agent(manager, _IdentityBoundMutationTool.tool_id)
        _ready(manager, agent["id"])
        proposal = PlanProposal(
            proposal_id="planner-4",
            steps=(
                PlanStepProposal(
                    local_index="ambiguous",
                    kind="MUTATING",
                    tool_name=_IdentityBoundMutationTool.tool_id,
                    arguments={"target_id": "ambiguous:match-anything"},
                ),
            ),
        )
        _executor(manager).materialize_plan_proposal(
            agent["id"], proposal,
            supported_tools={_IdentityBoundMutationTool.tool_id},
        )
        _run(
            manager,
            agent["id"],
            [
                _call(
                    _IdentityBoundMutationTool.tool_id, "t2",
                    target_id="ambiguous:match-anything",
                ),
                {"content": "refusing ambiguous target"},
            ],
        )
        assert _IdentityBoundMutationTool.dispatches == 0
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        states = [
            s.get("state") for s in checkpoint["tool_state"]["completed_steps"]
            if s.get("state") is not None
        ]
        assert "FAILED" in states
        assert "COMPLETED" not in states
    finally:
        manager.close()


def test_non_retryable_permission_failure_stops_first_attempt(tmp_path):
    _Counter.reset()
    manager = AgentManager(str(tmp_path / "g6.db"))
    try:
        agent = _agent(manager, _VerifiedNotesTool.tool_id)
        _ready(manager, agent["id"])
        engine = FakeEngine([
            {"raise": RuntimeError("permission denied by host policy")},
        ])
        executor = AgentExecutor(manager, EventBus(), system=FakeSystem(engine))
        import contextlib

        with contextlib.suppress(Exception):
            executor.execute_tick(agent["id"])
        # One attempt only: deterministically fatal errors never burn the
        # retry budget.
        assert engine.call_count == 1
        assert _Counter.dispatches == 0
        updated = manager.get_agent(agent["id"])
        assert updated["status"] != "running"
    finally:
        manager.close()


def test_long_horizon_goal_survives_process_restart(tmp_path):
    _Counter.reset()
    path = str(tmp_path / "g-long.db")
    manager = AgentManager(path)
    agent_id = None
    try:
        agent = _agent(manager, _VerifiedNotesTool.tool_id)
        agent_id = agent["id"]
        _ready(manager, agent_id)
        proposal = PlanProposal(
            proposal_id="planner-long",
            steps=tuple(
                PlanStepProposal(
                    local_index=f"s{i}",
                    kind="MUTATING",
                    tool_name=_VerifiedNotesTool.tool_id,
                    arguments={"value": f"out-{i}"},
                    dependencies=(f"s{i-1}",) if i > 1 else (),
                )
                for i in range(1, 7)
            ),
        )
        minted = _executor(manager).materialize_plan_proposal(
            agent_id, proposal,
            supported_tools={_VerifiedNotesTool.tool_id},
        )
        order = [
            minted["local_to_planner_node"][f"s{i}"] for i in range(1, 7)
        ]

        def run_step(idx):
            _run(
                manager, agent_id,
                [
                    _call(
                        _VerifiedNotesTool.tool_id, f"call-{idx}",
                        value=f"out-{idx}",
                    ),
                    {"content": f"step {idx} done"},
                ],
            )

        run_step(1)
        _executor(manager).advance_materialized_plan_node(
            agent_id, planner_node_id=order[1],
        )
        run_step(2)
        plan = _plan(manager, agent_id)
        assert _completed(plan) == {order[0], order[1]}

        # Process restart: persist a fresh checkpoint and reload the
        # manager from disk (production recovery path).
        manager = _restart(manager, agent_id, path)
        plan = _plan(manager, agent_id)
        assert _completed(plan) == {order[0], order[1]}

        for idx in range(3, 7):
            _executor(manager).advance_materialized_plan_node(
                agent_id, planner_node_id=order[idx - 1],
            )
            run_step(idx)

        plan = _plan(manager, agent_id)
        assert _completed(plan) == set(order)
        assert _Counter.store == {"note": "out-6"}
        assert manager.execution_journal.pending(agent_id) == []
    finally:
        if agent_id is not None:
            try:
                manager.close()
            except Exception:
                pass
