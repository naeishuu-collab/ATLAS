"""Phase 3C managed proposal boundary tests (non-physical)."""

from __future__ import annotations

import copy
import json

import pytest

from openjarvis.agents.executor import AgentExecutor, _ManagedMutationController
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.orchestrator import OrchestratorAgent
from openjarvis.agents.proposals import ToolExecutionProposal
from openjarvis.core.events import EventBus, EventType
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import AgentRegistry, ToolRegistry
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec
from openjarvis.tools.execution_journal import ExecutionJournal
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem


class _ProposalMutationTool(BaseTool):
    tool_id = "proposal_boundary_mutation"
    calls = 0
    unknown = False

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id,
            "test-only managed mutation",
            parameters={
                "type": "object",
                "properties": {"value": {"type": "string"}},
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
            json.dumps({"value": params.get("value", "ok")}),
            execution_state=ExecutionState.VERIFIED,
        )


class _ProposalReadTool(BaseTool):
    tool_id = "proposal_boundary_read"
    calls = 0

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id,
            "test-only read",
            parameters={
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            effect=ToolEffect.READ_ONLY,
        )

    def execute(self, **_params):
        type(self).calls += 1
        return ToolResult(self.tool_id, "read-ok")


def _register() -> None:
    AgentRegistry.register_value("orchestrator", OrchestratorAgent)
    ToolRegistry.register_value(_ProposalMutationTool.tool_id, _ProposalMutationTool)
    ToolRegistry.register_value(_ProposalReadTool.tool_id, _ProposalReadTool)


def _agent(manager: AgentManager) -> dict:
    _register()
    return manager.create_agent(
        "proposal-boundary-test",
        agent_type="orchestrator",
        config={
            "model": "fake-model",
            "instruction": "Execute the controlled test step.",
            "tools": [_ProposalMutationTool.tool_id, _ProposalReadTool.tool_id],
        },
    )


def _call(call_id: str, name: str = _ProposalMutationTool.tool_id, **args) -> dict:
    return {
        "tool_calls": [
            {
                "id": call_id,
                "name": name,
                "arguments": json.dumps(args),
            }
        ]
    }


def _run(manager: AgentManager, agent_id: str, responses: list[dict]):
    engine = FakeEngine(responses)
    bus = EventBus(record_history=True)
    AgentExecutor(manager, bus, system=FakeSystem(engine)).execute_tick(agent_id)
    return engine, bus


def _tool_text(engine: FakeEngine) -> list[str]:
    return [
        str(message.content)
        for message in engine.last_messages or []
        if getattr(message.role, "value", message.role) == "tool"
    ]


def _state(manager: AgentManager, agent_id: str) -> dict:
    checkpoint = manager.get_latest_checkpoint(agent_id)
    assert checkpoint is not None
    return checkpoint["tool_state"]


def test_pb1_read_only_proposal_needs_no_intent(tmp_path):
    _ProposalMutationTool.calls = 0
    _ProposalReadTool.calls = 0
    manager = AgentManager(str(tmp_path / "pb1.db"))
    agent = _agent(manager)
    try:
        _run(
            manager,
            agent["id"],
            [_call("read-1", _ProposalReadTool.tool_id), {"content": "done"}],
        )
        state = _state(manager, agent["id"])
        assert _ProposalReadTool.calls == 1
        assert _ProposalMutationTool.calls == 0
        assert "semantic_step" not in state
        assert state["durable_plan"]["nodes"] == []
    finally:
        manager.close()


def test_pb2_first_mutating_proposal_materializes_s1_i1(tmp_path):
    _ProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "pb2.db"))
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [_call("mutate-1", value="A"), {"content": "done"}])
        state = _state(manager, agent["id"])
        assert _ProposalMutationTool.calls == 1
        assert state["durable_plan"]["nodes"][0]["status"] == "COMPLETED"
        assert state["semantic_step"]["status"] == "VERIFIED"
    finally:
        manager.close()


def test_pb3_model_trusted_id_injection_is_rejected(tmp_path):
    _ProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "pb3.db"))
    agent = _agent(manager)
    try:
        engine, _ = _run(
            manager,
            agent["id"],
            [
                _call(
                    "inject-1",
                    execution_id="fake-execution",
                    plan_id="fake-plan",
                    planner_node_id="fake-node",
                    step_id="fake-step",
                    mutation_intent_id="fake-intent",
                    journal_token="fake-token",
                ),
                {"content": "done"},
            ],
        )
        state = _state(manager, agent["id"])
        assert _ProposalMutationTool.calls == 0
        assert state["durable_plan"]["nodes"] == []
        assert any("PROPOSAL_REJECTED" in text for text in _tool_text(engine))
    finally:
        manager.close()


def test_pb4_duplicate_after_verified_is_blocked_before_executor(tmp_path):
    _ProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "pb4.db"))
    agent = _agent(manager)
    try:
        engine, bus = _run(
            manager,
            agent["id"],
            [_call("first"), _call("fresh-provider"), {"content": "done"}],
        )
        starts = [e for e in bus.history if e.event_type == EventType.TOOL_CALL_START]
        assert _ProposalMutationTool.calls == 1
        assert len(starts) == 1
        assert any("PLAN_ADVANCEMENT_REQUIRED" in text for text in _tool_text(engine))
    finally:
        manager.close()


def test_pb5_fresh_observation_cannot_reopen_completed_step(tmp_path):
    _ProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "pb5.db"))
    agent = _agent(manager)
    try:
        engine, _ = _run(
            manager,
            agent["id"],
            [_call("first", value="A"), _call("fresh-observation", value="B")],
        )
        assert _ProposalMutationTool.calls == 1
        assert any("PLAN_ADVANCEMENT_REQUIRED" in text for text in _tool_text(engine))
    finally:
        manager.close()


def test_pb6_different_mutation_without_advancement_is_blocked(tmp_path):
    _ProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "pb6.db"))
    agent = _agent(manager)
    try:
        engine, _ = _run(
            manager,
            agent["id"],
            [_call("first", value="A"), _call("different", value="B")],
        )
        assert _ProposalMutationTool.calls == 1
        assert any("PLAN_ADVANCEMENT_REQUIRED" in text for text in _tool_text(engine))
    finally:
        manager.close()


def test_pb7_pb8_trusted_advance_allows_identical_s2(tmp_path):
    _ProposalMutationTool.calls = 0
    path = str(tmp_path / "pb78.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [_call("s1", value="same"), {"content": "done"}])
        AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).advance_plan_step(agent["id"], step_id="s2")
        _run(manager, agent["id"], [_call("s2", value="same"), {"content": "done"}])
        plan = _state(manager, agent["id"])["durable_plan"]
        assert _ProposalMutationTool.calls == 2
        assert {node["status"] for node in plan["nodes"]} == {"COMPLETED"}
        assert len({node["mutation_intent_id"] for node in plan["nodes"]}) == 2
    finally:
        manager.close()


def test_pb9_unknown_outcome_blocks_new_proposal(tmp_path):
    _ProposalMutationTool.calls = 0
    _ProposalMutationTool.unknown = True
    manager = AgentManager(str(tmp_path / "pb9.db"))
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [_call("unknown")])
        state = _state(manager, agent["id"])
        controller = _ManagedMutationController(
            manager.execution_journal,
            agent["id"],
            {"tool_state": copy.deepcopy(state)},
        )
        decision = controller.authorize_proposal(
            ToolExecutionProposal.from_tool_call(
                ToolCall("replacement", _ProposalMutationTool.tool_id, "{}")
            ),
            effect="MUTATING",
        )
        assert not decision.allowed
        assert decision.code == "RECONCILIATION_REQUIRED"
        assert _ProposalMutationTool.calls == 1
    finally:
        _ProposalMutationTool.unknown = False
        manager.close()


def test_pb10_unknown_outcome_blocks_explicit_advance(tmp_path):
    _ProposalMutationTool.calls = 0
    _ProposalMutationTool.unknown = True
    manager = AgentManager(str(tmp_path / "pb10.db"))
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [_call("unknown")])
        with pytest.raises(ValueError, match="reconciliation"):
            AgentExecutor(
                manager, EventBus(), system=FakeSystem(FakeEngine([]))
            ).advance_plan_step(agent["id"], step_id="replacement")
    finally:
        _ProposalMutationTool.unknown = False
        manager.close()


def test_pb11_not_executed_does_not_auto_create_s2(tmp_path):
    _ProposalMutationTool.calls = 0
    journal = ExecutionJournal(tmp_path / "pb11.db")
    runtime = {"tool_state": {"execution_id": "pb11-execution"}}
    controller = _ManagedMutationController(journal, "pb11", runtime)
    try:
        intent = controller.context_for()
        tool = _ProposalMutationTool()
        executor = ToolExecutor(
            [tool],
            execution_journal=journal,
            execution_scope="pb11",
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
        decision = controller.authorize_proposal(
            ToolExecutionProposal.from_tool_call(
                ToolCall("model-retry", tool.tool_id, "{}")
            ),
            effect="MUTATING",
        )
        assert not decision.allowed
        assert decision.code == "PLAN_ADVANCEMENT_REQUIRED"
        assert tool.calls == 0
    finally:
        journal.close()


def test_pb12_not_executed_then_trusted_advance_allows_new_step(tmp_path):
    _ProposalMutationTool.calls = 0
    journal = ExecutionJournal(tmp_path / "pb12.db")
    runtime = {"tool_state": {"execution_id": "pb12-execution"}}
    controller = _ManagedMutationController(journal, "pb12", runtime)
    try:
        intent = controller.context_for()
        tool = _ProposalMutationTool()
        executor = ToolExecutor(
            [tool],
            execution_journal=journal,
            execution_scope="pb12",
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
        controller.advance_step("s2")
        new_intent = controller.context_for()
        result = executor.execute(
            ToolCall("new", tool.tool_id, "{}"), mutation_context=new_intent
        )
        assert result.success
        assert tool.calls == 1
    finally:
        journal.close()


def test_pb13_pb14_restart_then_trusted_s2(tmp_path):
    _ProposalMutationTool.calls = 0
    path = str(tmp_path / "pb1314.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _run(manager, agent["id"], [_call("s1"), {"content": "done"}])
    checkpoint = manager.get_latest_checkpoint(agent["id"])
    assert checkpoint is not None
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
        _run(restarted, agent["id"], [_call("fresh-after-restart")])
        assert _ProposalMutationTool.calls == 1
        AgentExecutor(
            restarted, EventBus(), system=FakeSystem(FakeEngine([]))
        ).advance_plan_step(agent["id"], step_id="s2")
        _run(restarted, agent["id"], [_call("s2-after-restart")])
        assert _ProposalMutationTool.calls == 2
    finally:
        restarted.close()


def test_pb15_context_compaction_keeps_completed_mutation_closed(tmp_path):
    _ProposalMutationTool.calls = 0
    path = str(tmp_path / "pb15.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _run(manager, agent["id"], [_call("first"), {"content": "done"}])
    checkpoint = manager.get_latest_checkpoint(agent["id"])
    assert checkpoint is not None
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
    manager.start_tick(agent["id"])
    manager.close()
    restarted = AgentManager(path, clear_stale_running=True)
    try:
        _run(restarted, agent["id"], [_call("after-compaction")])
        assert _ProposalMutationTool.calls == 1
    finally:
        restarted.close()


def test_pb16_final_answer_failure_keeps_intent_closed(tmp_path):
    _ProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "pb16.db"))
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [_call(f"loop-{i}") for i in range(12)])
        state = _state(manager, agent["id"])
        assert _ProposalMutationTool.calls == 1
        assert state["semantic_step"]["status"] == "VERIFIED"
    finally:
        manager.close()


def test_pb17_cancellation_blocks_proposal_before_dispatch(tmp_path):
    _ProposalMutationTool.calls = 0
    journal = ExecutionJournal(tmp_path / "pb17.db")
    runtime = {"tool_state": {"execution_id": "pb17-execution"}}
    controller = _ManagedMutationController(journal, "pb17", runtime)
    try:
        journal.request_cancellation("pb17")
        decision = controller.authorize_proposal(
            ToolExecutionProposal.from_tool_call(
                ToolCall("cancelled", _ProposalMutationTool.tool_id, "{}")
            ),
            effect="MUTATING",
        )
        assert decision.allowed
        executor = ToolExecutor(
            [_ProposalMutationTool()],
            execution_journal=journal,
            execution_scope="pb17",
            require_mutation_intent=True,
        )
        result = executor.execute(
            ToolCall("cancelled", _ProposalMutationTool.tool_id, "{}"),
            mutation_context=decision.mutation_context,
        )
        assert result.metadata["execution"]["state"] == "NOT_STARTED"
        assert _ProposalMutationTool.calls == 0
    finally:
        journal.close()


def test_pb18_read_after_verified_mutation_remains_allowed(tmp_path):
    _ProposalMutationTool.calls = 0
    _ProposalReadTool.calls = 0
    manager = AgentManager(str(tmp_path / "pb18.db"))
    agent = _agent(manager)
    try:
        _run(
            manager,
            agent["id"],
            [
                _call("mutate", value="A"),
                _call("read-after", _ProposalReadTool.tool_id),
                {"content": "done"},
            ],
        )
        assert _ProposalMutationTool.calls == 1
        assert _ProposalReadTool.calls == 1
    finally:
        manager.close()


def test_historical_spark_duplicate_sequence_is_blocked(tmp_path):
    _ProposalMutationTool.calls = 0
    _ProposalReadTool.calls = 0
    manager = AgentManager(str(tmp_path / "historical.db"))
    agent = _agent(manager)
    try:
        engine, bus = _run(
            manager,
            agent["id"],
            [
                _call("observe-1", _ProposalReadTool.tool_id),
                _call("type-1", value="CANARY"),
                _call("observe-2", _ProposalReadTool.tool_id),
                _call("type-2", value="CANARY"),
                {"content": "done"},
            ],
        )
        starts = [e for e in bus.history if e.event_type == EventType.TOOL_CALL_START]
        assert _ProposalMutationTool.calls == 1
        assert _ProposalReadTool.calls == 2
        assert len(starts) == 3
        assert any("PLAN_ADVANCEMENT_REQUIRED" in text for text in _tool_text(engine))
    finally:
        manager.close()


def test_pbc1_no_materialization_means_no_authority(tmp_path):
    journal = ExecutionJournal(tmp_path / "pbc1.db")
    runtime = {"tool_state": {"execution_id": "pbc1-execution"}}
    controller = _ManagedMutationController(journal, "pbc1", runtime)
    try:
        assert controller.plan.nodes == {}
        assert controller.snapshot() is None
        assert (
            journal.semantic_step_exists("pbc1", "pbc1-execution", "missing")
            is False
        )
    finally:
        journal.close()


def test_pbc2_intent_before_dispatch_is_prepared_safely(tmp_path):
    journal = ExecutionJournal(tmp_path / "pbc2.db")
    runtime = {"tool_state": {"execution_id": "pbc2-execution"}}
    controller = _ManagedMutationController(journal, "pbc2", runtime)
    try:
        decision = controller.authorize_proposal(
            ToolExecutionProposal.from_tool_call(
                ToolCall("prepared", _ProposalMutationTool.tool_id, "{}")
            ),
            effect="MUTATING",
        )
        assert decision.allowed
        assert journal.semantic_intent("pbc2", decision.mutation_context)["status"] == (
            "AUTHORIZED"
        )
    finally:
        journal.close()


def test_pbc3_dispatch_boundary_becomes_unknown_outcome(tmp_path):
    _ProposalMutationTool.calls = 0
    _ProposalMutationTool.unknown = True
    journal = ExecutionJournal(tmp_path / "pbc3.db")
    runtime = {"tool_state": {"execution_id": "pbc3-execution"}}
    controller = _ManagedMutationController(journal, "pbc3", runtime)
    tool = _ProposalMutationTool()
    executor = ToolExecutor(
        [tool],
        execution_journal=journal,
        execution_scope="pbc3",
        require_mutation_intent=True,
    )
    try:
        intent = controller.context_for()
        result = executor.execute(
            ToolCall("unknown", tool.tool_id, "{}"), mutation_context=intent
        )
        controller.record_result(ToolCall("unknown", tool.tool_id, "{}"), result)
        assert result.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
        assert controller.plan.node(intent.step_id).status == (
            "RECONCILIATION_REQUIRED"
        )
        assert tool.calls == 1
    finally:
        _ProposalMutationTool.unknown = False
        journal.close()


def test_pbc4_verified_before_later_turn_cannot_reopen(tmp_path):
    _ProposalMutationTool.calls = 0
    manager = AgentManager(str(tmp_path / "pbc4.db"))
    agent = _agent(manager)
    try:
        _run(manager, agent["id"], [_call("verified"), _call("later")])
        assert _ProposalMutationTool.calls == 1
    finally:
        manager.close()


def test_pbc5_trusted_s2_authority_restores_once(tmp_path):
    _ProposalMutationTool.calls = 0
    path = str(tmp_path / "pbc5.db")
    manager = AgentManager(path)
    agent = _agent(manager)
    _run(manager, agent["id"], [_call("s1")])
    AgentExecutor(
        manager, EventBus(), system=FakeSystem(FakeEngine([]))
    ).advance_plan_step(agent["id"], step_id="s2")
    try:
        _run(manager, agent["id"], [_call("s2")])
        assert _ProposalMutationTool.calls == 2
    finally:
        manager.close()


def test_parallel_path_cannot_dispatch_mutation_without_intent(tmp_path):
    """Parallel Orchestrator dispatch fails closed without MutationIntent.

    Nonphysical: the parallel branch (``_exec_tool``) never consults the
    proposal boundary or the mutation-context resolver, so even with
    pre-authorized intent material present in context, mutating tools must
    not execute there. The sequential branch with equivalent authorization
    must still execute exactly once (control case).
    """
    from openjarvis.agents._stubs import AgentContext
    from openjarvis.agents.proposals import ProposalDecision
    from openjarvis.core.execution import MutationIntent

    scope = "parallel-authority-audit"
    journal = ExecutionJournal(tmp_path / "parallel_audit.db")
    try:
        seq_intent = MutationIntent(
            execution_id="exec-parallel-audit",
            step_id="s1",
            mutation_intent_id="intent-seq",
        )
        par_intent = MutationIntent(
            execution_id="exec-parallel-audit",
            step_id="s2",
            mutation_intent_id="intent-par",
        )
        journal.authorize_intent(scope, seq_intent)
        journal.authorize_intent(scope, par_intent)

        def _context(intent):
            return AgentContext(
                metadata={
                    "managed_proposal_boundary": (
                        lambda proposal, effect: ProposalDecision(
                            allowed=True, mutation_context=intent
                        )
                    ),
                    "managed_mutation_context": lambda call: intent,
                }
            )

        def _agent(responses):
            engine = FakeEngine(responses)
            agent = OrchestratorAgent(
                engine, "fixture-model", tools=[_ProposalMutationTool()]
            )
            agent._executor.bind_execution_journal(
                journal, scope, require_mutation_intent=True
            )
            return agent

        # A. Sequential control: one call + valid proposal + intent executes once.
        _ProposalMutationTool.calls = 0
        seq_agent = _agent([_call("seq-1"), {"content": "done"}])
        seq_result = seq_agent.run("controlled step", context=_context(seq_intent))
        assert _ProposalMutationTool.calls == 1
        assert seq_result.tool_results[0].success is True

        # B/C/D. Parallel: two calls in one turn. Authorization material is
        # present in context, but the parallel branch never consults it, so
        # both calls must fail closed with no tool dispatch (E).
        _ProposalMutationTool.calls = 0
        par_agent = _agent(
            [
                {
                    "tool_calls": [
                        {
                            "id": "par-1",
                            "name": _ProposalMutationTool.tool_id,
                            "arguments": "{}",
                        },
                        {
                            "id": "par-2",
                            "name": _ProposalMutationTool.tool_id,
                            "arguments": "{}",
                        },
                    ]
                },
                {"content": "done"},
            ]
        )
        par_result = par_agent.run("controlled step", context=_context(par_intent))
        assert _ProposalMutationTool.calls == 0
        assert len(par_result.tool_results) == 2
        for tool_result in par_result.tool_results:
            assert tool_result.success is False
            assert tool_result.metadata["execution"]["state"] == "NOT_STARTED"
            assert (
                tool_result.metadata["semantic"]["failure"]
                == "MISSING_TRUSTED_INTENT"
            )
        assert not journal.pending(scope)
        assert journal.semantic_intent(scope, par_intent)["status"] == "AUTHORIZED"
    finally:
        journal.close()


def test_parallel_read_only_calls_execute_without_intent():
    """Two READ_ONLY calls in one turn complete via the parallel branch.

    Nonphysical: pins that the parallel path preserves existing read
    availability and result ordering while requiring no MutationIntent.
    """
    _ProposalReadTool.calls = 0
    responses = [
        {
            "tool_calls": [
                {
                    "id": "r-1",
                    "name": _ProposalReadTool.tool_id,
                    "arguments": "{}",
                },
                {
                    "id": "r-2",
                    "name": _ProposalReadTool.tool_id,
                    "arguments": "{}",
                },
            ]
        },
        {"content": "done"},
    ]
    for parallel in (True, False):
        _ProposalReadTool.calls = 0
        engine = FakeEngine([dict(response) for response in responses])
        agent = OrchestratorAgent(
            engine,
            "fixture-model",
            tools=[_ProposalReadTool()],
            parallel_tools=parallel,
        )
        assert agent._parallel_tools is parallel
        result = agent.run("read both")
        assert _ProposalReadTool.calls == 2
        assert [tool_result.success for tool_result in result.tool_results] == [
            True,
            True,
        ]
        assert [tool_result.content for tool_result in result.tool_results] == [
            "read-ok",
            "read-ok",
        ]
