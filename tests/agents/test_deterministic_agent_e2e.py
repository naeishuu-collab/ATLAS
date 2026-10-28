"""Non-physical Agent E2E readiness lane.

This is test-only scaffolding.  It uses the production OrchestratorAgent for
routing, but every action backend, observation, journal, artifact registry and
replanner is in memory.  It cannot start a process, access a network, or call
an external model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from openjarvis.agents.orchestrator import OrchestratorAgent
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec


@dataclass(frozen=True)
class _Plan:
    target: str
    action: str
    executor: str = "in-memory"
    scenario: str = "success"


@dataclass
class _Effects:
    process_creation_count: int = 0
    network_send_count: int = 0
    physical_mutation_count: int = 0
    in_memory_dispatch_count: int = 0


@dataclass
class _LaneState:
    journal: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    observations: dict[str, str] = field(default_factory=dict)
    effects: _Effects = field(default_factory=_Effects)


class _FakePlanner:
    """Controller-owned plan source; no model output is used as authority."""

    def __init__(self, plan: _Plan) -> None:
        self.plan = plan

    def propose(self) -> _Plan:
        return self.plan


class _FakeReplanner:
    def __init__(self, replacement: _Plan) -> None:
        self.replacement = replacement
        self.calls = 0

    def propose_after_bounded_failure(self, result: ToolResult) -> _Plan | None:
        self.calls += 1
        if self.calls == 1 and result.metadata.get("execution", {}).get(
            "state"
        ) == ExecutionState.NOT_STARTED.value:
            return self.replacement
        return None


class _InMemoryAction(BaseTool):
    tool_id = "fake_action"

    def __init__(self, state: _LaneState, plan: _Plan) -> None:
        self._state = state
        self._plan = plan

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.tool_id,
            description="Deterministic in-memory action; never touches the OS.",
            effect=ToolEffect.MUTATING,
            parameters={
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "action": {"type": "string"},
                },
                "required": ["target", "action"],
            },
        )

    def execute(self, *, target: str, action: str) -> ToolResult:
        self._state.effects.in_memory_dispatch_count += 1
        scenario = self._plan.scenario
        if scenario == "unknown":
            execution_state = ExecutionState.UNKNOWN_OUTCOME
            success = False
        elif scenario == "failure":
            execution_state = ExecutionState.NOT_STARTED
            success = False
        elif scenario == "executed_without_observation":
            execution_state = ExecutionState.EXECUTED
            success = True
        else:
            self._state.observations[target] = action
            execution_state = ExecutionState.VERIFIED
            success = True

        self._state.journal.append(
            {
                "target": target,
                "action": action,
                "state": execution_state.value,
                "success": success,
            }
        )
        return ToolResult(
            tool_name=self.tool_id,
            content=f"{execution_state.value}:{target}:{action}",
            success=success,
            execution_state=execution_state,
        )


class _FakeEngine:
    engine_id = "deterministic-fake"

    def __init__(self, *, target: str, action: str, duplicate: bool = False) -> None:
        self._target = target
        self._action = action
        self._duplicate = duplicate
        self._turn = 0

    def generate(self, _messages, **_kwargs):
        if self._turn == 0 or self._duplicate and self._turn == 1:
            response = {
                "content": "",
                "tool_calls": [
                    {
                        "id": f"fake-call-{self._turn}",
                        "name": "fake_action",
                        "arguments": (
                            f'{{"target":"{self._target}",'
                            f'"action":"{self._action}"}}'
                        ),
                    }
                ],
                "usage": {},
                "model": self.engine_id,
                "finish_reason": "tool_calls",
            }
        else:
            response = {
                "content": "controller result",
                "usage": {},
                "model": self.engine_id,
                "finish_reason": "stop",
            }
        self._turn += 1
        return response


def _run(plan: _Plan, state: _LaneState, *, target: str | None = None, duplicate=False):
    """Run one controller plan through the real OrchestratorAgent."""
    tool = _InMemoryAction(state, plan)
    planned_target = plan.target

    def host_gate(name: str, args: dict[str, Any]) -> bool:
        if plan.executor != "in-memory" or name != tool.tool_id:
            return False
        if args.get("target") != planned_target or args.get("action") != plan.action:
            return False
        return not any(
            row["target"] == planned_target
            and row["action"] == plan.action
            and row["state"] in {"VERIFIED", "UNKNOWN_OUTCOME"}
            for row in state.journal
        )

    engine = _FakeEngine(
        target=target or plan.target,
        action=plan.action,
        duplicate=duplicate,
    )
    agent = OrchestratorAgent(
        engine,
        "deterministic-fake",
        tools=[tool],
        max_turns=4,
        parallel_tools=False,
        before_tool_call=host_gate,
    )
    result = agent.run("execute the controller-owned plan")
    return result, state


def _accept_verified(state: _LaneState, plan: _Plan) -> bool:
    """Independent observation gate; model text is never used as proof."""
    verified = (
        bool(state.journal)
        and state.journal[-1]["state"] == ExecutionState.VERIFIED.value
        and state.observations.get(plan.target) == plan.action
    )
    if verified:
        artifact = f"artifact:{plan.target}:{plan.action}"
        state.artifacts.append(artifact)
    return verified


def test_authorized_fake_action_and_target_identity_are_verified_independently():
    state = _LaneState()
    plan = _FakePlanner(_Plan("target-a", "set-value")).propose()
    result, _ = _run(plan, state)

    assert result.tool_results[0].success is True
    assert _accept_verified(state, plan)
    assert state.artifacts == ["artifact:target-a:set-value"]
    assert state.effects.in_memory_dispatch_count == 1
    assert state.effects.process_creation_count == 0
    assert state.effects.network_send_count == 0
    assert state.effects.physical_mutation_count == 0


def test_model_target_mismatch_is_denied_before_fake_dispatch():
    state = _LaneState()
    plan = _Plan("target-a", "set-value")
    result, _ = _run(plan, state, target="target-b")

    assert result.tool_results[0].success is False
    assert state.journal == []
    assert state.effects.in_memory_dispatch_count == 0
    assert state.artifacts == []


def test_successful_tool_claim_without_observation_is_not_success():
    state = _LaneState()
    plan = _Plan("target-a", "set-value", scenario="executed_without_observation")
    result, _ = _run(plan, state)

    assert result.tool_results[0].success is True
    assert not _accept_verified(state, plan)
    assert state.artifacts == []
    assert state.observations == {}


def test_bounded_replan_uses_a_fresh_controller_plan_after_not_started_failure():
    state = _LaneState()
    first = _Plan("target-a", "set-value", scenario="failure")
    result, _ = _run(first, state)
    replanner = _FakeReplanner(_Plan("target-b", "set-value"))

    replacement = replanner.propose_after_bounded_failure(result.tool_results[0])
    assert replacement is not None
    result2, _ = _run(replacement, state)

    assert result.tool_results[0].success is False
    assert result2.tool_results[0].success is True
    assert _accept_verified(state, replacement)
    assert replanner.calls == 1
    assert state.effects.in_memory_dispatch_count == 2


def test_unknown_outcome_is_quarantined_without_replan_or_retry():
    state = _LaneState()
    plan = _Plan("target-a", "set-value", scenario="unknown")
    result, _ = _run(plan, state)

    assert result.tool_results[0].success is False
    assert state.journal[-1]["state"] == ExecutionState.UNKNOWN_OUTCOME.value
    assert _FakeReplanner(_Plan("target-b", "set-value")).propose_after_bounded_failure(
        result.tool_results[0]
    ) is None
    assert state.effects.in_memory_dispatch_count == 1
    assert state.artifacts == []


def test_duplicate_mutation_is_denied_by_controller_journal():
    state = _LaneState()
    plan = _Plan("target-a", "set-value")
    result, _ = _run(plan, state, duplicate=True)

    assert result.tool_results[0].success is True
    assert len(result.tool_results) == 2
    assert result.tool_results[1].success is False
    assert len(state.journal) == 1
    assert state.effects.in_memory_dispatch_count == 1


def test_alternate_executor_is_denied_without_fallback():
    state = _LaneState()
    plan = _Plan("target-a", "set-value", executor="shell")
    result, _ = _run(plan, state)

    assert result.tool_results[0].success is False
    assert state.journal == []
    assert state.effects.in_memory_dispatch_count == 0
    assert state.artifacts == []


def test_structured_result_and_journal_artifact_consistency():
    state = _LaneState()
    plan = _Plan("target-a", "set-value")
    result, _ = _run(plan, state)

    assert result.content == "controller result"
    assert result.tool_results[0].metadata["execution"]["state"] == "VERIFIED"
    assert _accept_verified(state, plan)
    assert len(state.journal) == len(state.artifacts) == 1
    assert state.journal[0]["target"] in state.artifacts[0]

