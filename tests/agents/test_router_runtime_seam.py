"""Capability Router x Agent Runtime seam (offline, mock-only).

Proves the responsibility split: the router only selects (or refuses);
Host Safety Authority (plan_goal + managed controller) owns execution.
Items 8 (malicious proposal) and 9 (UNKNOWN redispatch) are covered by
test_p3d_a3 and test_agent_safe_e2e; they are not duplicated here.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from openjarvis.agents.capability_router import (
    ALL_PROVIDERS_UNAVAILABLE,
    MODEL_CAPABILITY_UNAVAILABLE,
    CapabilityRouter,
    ModelCapability,
    ModelCard,
    ProviderSnapshot,
    RouteDecision,
    RouteRequest,
    RouterFailure,
    RouterGateError,
)
from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.planner import PlannerAdapter
from openjarvis.core.events import EventBus
from openjarvis.security.cloud_dispatch import PrivacyClassification
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem
from tests.agents.test_plan_proposal_materialization import (
    _agent,
    _plan,
    _PlanProposalMutationTool,
    _ready,
)

TOOL = _PlanProposalMutationTool.tool_id
T = ModelCapability.TEXT
J = ModelCapability.STRUCTURED_JSON
N = ModelCapability.NATIVE_TOOLS


def _cards():
    return [
        ModelCard(
            engine="local", provider="local", model="tiny-4b",
            capabilities=frozenset({T}), ctx_limit=4096,
            cost_per_1k=0.0, latency_p50_ms=50.0,
            is_cloud=False, tier=0,
        ),
        ModelCard(
            engine="cloud", provider="cloud", model="prose-70b",
            capabilities=frozenset({T, J, N}), ctx_limit=128000,
            cost_per_1k=1.0, latency_p50_ms=800.0,
            is_cloud=True, structured_reliability=0.9, tier=2,
        ),
    ]


def _snap(**over):
    args = {"available": {c.key(): True for c in _cards()}}
    args.update(over)
    return ProviderSnapshot(**args)


def _req(**over):
    args = {
        "difficulty": "standard",
        "need": frozenset({T}),
        "privacy": PrivacyClassification.PUBLIC,
        "est_prompt_tokens": 100,
    }
    args.update(over)
    return RouteRequest(**args)


def _plan_json():
    return json.dumps({"steps": [
        {"local_index": "s1", "kind": "MUTATING", "tool_name": TOOL,
         "arguments": {"value": "one"}},
    ]})


def _goal(manager, agent_id, engine, gate, **kw):
    planner = PlannerAdapter(engine, model="tiny-4b")
    return AgentExecutor(
        manager, EventBus(), system=FakeSystem(FakeEngine([]))
    ).plan_goal(agent_id, planner, "do the thing",
                supported_tools={TOOL}, model_gate=gate, **kw)


def test_router_selected_model_plans_through_host_verification(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "seam.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        router = CapabilityRouter(_cards())
        outcome = router.propose(_req(), _snap())
        assert isinstance(outcome, RouteDecision)
        engine = FakeEngine([{"content": _plan_json()}])
        out = _goal(manager, agent["id"], engine,
                    router.gate(_req(), _snap()))
        assert out.get("reused", False) is False
        assert engine.call_count == 1
        plan = _plan(manager, agent["id"])
        assert len(plan["nodes"]) == 1
        assert plan["nodes"][0]["mutation_intent_id"] is None
        assert manager.execution_journal.pending(agent["id"]) == []
    finally:
        manager.close()


def test_router_capability_shortfall_defers_before_model_contact(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "seam-defer.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        before = manager.get_latest_checkpoint(agent["id"])["tool_state"]
        router = CapabilityRouter(_cards())
        req = _req(difficulty="hard",
                   need=frozenset({T, J, N, ModelCapability.LONG_CONTEXT}))
        gate = router.gate(req, _snap())
        engine = FakeEngine([{"content": _plan_json()}])
        with pytest.raises(RouterGateError) as exc:
            _goal(manager, agent["id"], engine, gate)
        assert exc.value.code == MODEL_CAPABILITY_UNAVAILABLE
        assert engine.call_count == 0
        after = manager.get_latest_checkpoint(agent["id"])["tool_state"]
        assert after == before
    finally:
        manager.close()


def test_router_provider_outage_defers_with_distinct_code(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "seam-outage.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        router = CapabilityRouter(_cards())
        gate = router.gate(_req(), _snap(available={}))
        engine = FakeEngine([{"content": _plan_json()}])
        with pytest.raises(RouterGateError) as exc:
            _goal(manager, agent["id"], engine, gate)
        assert exc.value.code == ALL_PROVIDERS_UNAVAILABLE
        assert engine.call_count == 0
    finally:
        manager.close()


def test_contract_checks_run_before_model_gate(tmp_path) -> None:
    import time

    manager = AgentManager(str(tmp_path / "seam-order.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        manager.save_checkpoint(
            agent["id"], checkpoint["tick_id"],
            {**checkpoint["conversation_state"],
             "deadline_at": time.time() - 1},
            checkpoint["tool_state"],
        )
        calls: list = []
        engine = FakeEngine([{"content": _plan_json()}])
        with pytest.raises(ValueError, match="Deadline"):
            _goal(manager, agent["id"], engine, lambda: calls.append(1))
        assert calls == [] and engine.call_count == 0
    finally:
        manager.close()


def test_router_keeps_private_tasks_on_local_models() -> None:
    outcome = CapabilityRouter(_cards()).propose(
        _req(privacy=PrivacyClassification.PRIVATE), _snap())
    assert isinstance(outcome, RouteDecision)
    assert outcome.engine == "local"


def test_router_refuses_unapproved_frontier_escalation() -> None:
    cards = [c for c in _cards() if c.tier < 2] + [
        ModelCard(
            engine="cloud", provider="cloud", model="frontier-x",
            capabilities=frozenset({T, J, N, ModelCapability.LONG_CONTEXT}),
            ctx_limit=1000000, cost_per_1k=10.0, latency_p50_ms=2000.0,
            is_cloud=True, tier=4,
        ),
    ]
    outcome = CapabilityRouter(cards).propose(
        _req(need=frozenset({ModelCapability.LONG_CONTEXT})),
        ProviderSnapshot(available={c.key(): True for c in cards}),
    )
    assert isinstance(outcome, RouterFailure)
    assert outcome.code == MODEL_CAPABILITY_UNAVAILABLE


def test_router_reselection_preserves_task_identity(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "seam-reselect.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        router = CapabilityRouter(_cards())
        engine = FakeEngine([{"content": _plan_json()}])
        first = _goal(manager, agent["id"], engine,
                      router.gate(_req(), _snap()))
        # Providers vanish mid-task: the persisted plan is reused without
        # model contact, so the outage gate is vacuous and the persisted
        # execution identity is untouched for a later retry/escalation.
        second = _goal(manager, agent["id"], engine,
                       router.gate(_req(), _snap(available={})))
        assert second["reused"] is True
        plan = _plan(manager, agent["id"])
        assert plan["execution_id"] == first["execution_id"]
        assert engine.call_count == 1
    finally:
        manager.close()


def test_router_cannot_mint_capability_grants() -> None:
    import openjarvis.agents.capability_router as router_mod

    tree = ast.parse(Path(router_mod.__file__).read_text(encoding="utf-8"))
    src = ast.dump(tree)
    assert "grant" not in src.lower()
    assert "CapabilityPolicy" not in src
    assert "ToolExecutor" not in src
