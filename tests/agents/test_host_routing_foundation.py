"""Host routing foundation proofs (offline, mock-only, tmp sqlite).

Covers the 20-item contract for the host-owned tier/multi-provider base:
registry, snapshot, binding, privacy, managed integration, tick compat,
flags, shadow mode, isolation. No real providers, no prod tick changes.
"""

from __future__ import annotations

import json

import pytest

from openjarvis.agents.capability_router import (
    MODEL_CAPABILITY_UNAVAILABLE,
    ModelCapability,
)
from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.host_routing import (
    BINDING_MISMATCH,
    MODEL_BINDING_UNVERIFIED,
    PRIVACY_UNKNOWN,
    SNAPSHOT_STALE,
    UNKNOWN_CAPABILITY,
    ModelCardRegistry,
    RoutingError,
    bind_decision,
    build_snapshot,
    classify_privacy,
    escalation_state,
    gate_or_none,
)
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


def _host_cards():
    return [
        {"engine": "local", "provider": "local", "model": "tiny-4b",
         "capabilities": ["TEXT"], "ctx_limit": 4096,
         "cost_per_1k": 0.0, "latency_p50_ms": 50.0,
         "is_cloud": False, "tier": 0},
        {"engine": "cloud", "provider": "cloud", "model": "prose-70b",
         "capabilities": ["TEXT", "STRUCTURED_JSON", "NATIVE_TOOLS"],
         "ctx_limit": 128000, "cost_per_1k": 1.0, "latency_p50_ms": 800.0,
         "is_cloud": True, "structured_reliability": 0.9, "tier": 2},
    ]


def _req(**over):
    from openjarvis.agents.capability_router import RouteRequest

    args = {"difficulty": "standard", "need": frozenset({T}),
            "privacy": PrivacyClassification.PUBLIC,
            "est_prompt_tokens": 100}
    args.update(over)
    return RouteRequest(**args)


def _plan_json():
    return json.dumps({"steps": [
        {"local_index": "s1", "kind": "MUTATING", "tool_name": TOOL,
         "arguments": {"value": "one"}}]})


def test_registry_selects_local_model() -> None:
    reg = ModelCardRegistry.from_host_config(_host_cards())
    outcome = reg.router().propose(
        _req(), build_snapshot(
            {("local", "local", "tiny-4b"): True,
             ("cloud", "cloud", "prose-70b"): True},
            version=1, issued_at=1000.0).snapshot)
    assert outcome.model == "tiny-4b"


def test_registry_rejects_unknown_capability() -> None:
    bad = _host_cards()
    bad[0]["capabilities"] = ["MIND_READING"]
    with pytest.raises(RoutingError) as exc:
        ModelCardRegistry.from_host_config(bad)
    assert exc.value.code == UNKNOWN_CAPABILITY


def test_registry_update_is_host_only() -> None:
    reg = ModelCardRegistry.from_host_config(_host_cards())
    with pytest.raises((AttributeError, TypeError)):
        reg.cards = ()


def test_snapshot_unknown_state_is_unavailable() -> None:
    env = build_snapshot({}, version=1, issued_at=1000.0)
    reg = ModelCardRegistry.from_host_config(_host_cards())
    outcome = reg.router().propose(_req(), env.snapshot)
    assert outcome.code == "ALL_PROVIDERS_UNAVAILABLE"


def test_snapshot_explicit_false_is_unavailable() -> None:
    env = build_snapshot(
        {("local", "local", "tiny-4b"): False,
         ("cloud", "cloud", "prose-70b"): False},
        version=1, issued_at=1000.0)
    outcome = ModelCardRegistry.from_host_config(
        _host_cards()).router().propose(_req(), env.snapshot)
    assert outcome.code == "ALL_PROVIDERS_UNAVAILABLE"


def test_stale_snapshot_fails_closed() -> None:
    env = build_snapshot(
        {("local", "local", "tiny-4b"): True}, version=1, issued_at=1000.0)
    assert env.fresh(max_age_s=60.0, now=1059.0) is True
    assert env.fresh(max_age_s=60.0, now=1061.0) is False
    with pytest.raises(RoutingError) as exc:
        env.require_fresh(max_age_s=60.0, now=9999.0)
    assert exc.value.code == SNAPSHOT_STALE


def test_binding_match_verifies() -> None:
    reg = ModelCardRegistry.from_host_config(_host_cards())
    env = build_snapshot(
        {("local", "local", "tiny-4b"): True}, version=1, issued_at=1.0)
    decision = reg.router().propose(_req(), env.snapshot)
    bind_decision(decision, reg.cards, planner_model="tiny-4b",
                  host_engine="local")


def test_binding_model_mismatch_defers() -> None:
    reg = ModelCardRegistry.from_host_config(_host_cards())
    env = build_snapshot(
        {("local", "local", "tiny-4b"): True}, version=1, issued_at=1.0)
    decision = reg.router().propose(_req(), env.snapshot)
    with pytest.raises(RoutingError) as exc:
        bind_decision(decision, reg.cards, planner_model="other",
                      host_engine="local")
    assert exc.value.code == BINDING_MISMATCH


def test_binding_engine_mismatch_defers() -> None:
    reg = ModelCardRegistry.from_host_config(_host_cards())
    env = build_snapshot(
        {("local", "local", "tiny-4b"): True}, version=1, issued_at=1.0)
    decision = reg.router().propose(_req(), env.snapshot)
    with pytest.raises(RoutingError) as exc:
        bind_decision(decision, reg.cards, planner_model="tiny-4b",
                      host_engine="cloud")
    assert exc.value.code == BINDING_MISMATCH


def test_binding_ambiguous_provider_is_unverified() -> None:
    cards = _host_cards() + [dict(_host_cards()[1], provider="cloud-2")]
    reg = ModelCardRegistry.from_host_config(cards)
    env = build_snapshot(
        {("cloud", "cloud", "prose-70b"): True,
         ("cloud", "cloud-2", "prose-70b"): True},
        version=1, issued_at=1.0)
    decision = reg.router().propose(_req(), env.snapshot)
    with pytest.raises(RoutingError) as exc:
        bind_decision(decision, reg.cards, planner_model=decision.model,
                      host_engine=decision.engine)
    assert exc.value.code == MODEL_BINDING_UNVERIFIED


def test_private_task_stays_local() -> None:
    reg = ModelCardRegistry.from_host_config(_host_cards())
    env = build_snapshot(
        {("local", "local", "tiny-4b"): True,
         ("cloud", "cloud", "prose-70b"): True},
        version=1, issued_at=1.0)
    outcome = reg.router().propose(
        _req(privacy=PrivacyClassification.PRIVATE), env.snapshot)
    assert outcome.engine == "local"


def test_unknown_privacy_fails_closed() -> None:
    with pytest.raises(RoutingError) as exc:
        classify_privacy("ULTRA_SECRET")
    assert exc.value.code == PRIVACY_UNKNOWN
    with pytest.raises(RoutingError):
        classify_privacy("")
    assert classify_privacy("private") == PrivacyClassification.PRIVATE


def test_capability_shortfall_defers_with_zero_planner_calls(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "hr.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        reg = ModelCardRegistry.from_host_config(_host_cards())
        env = build_snapshot(
            {("local", "local", "tiny-4b"): True}, version=1, issued_at=1.0)
        req = _req(need=frozenset({ModelCapability.NATIVE_TOOLS}))
        engine = FakeEngine([{"content": _plan_json()}])
        with pytest.raises(RoutingError) as exc:
            AgentExecutor(
                manager, EventBus(), system=FakeSystem(FakeEngine([]))
            ).plan_goal(
                agent["id"], PlannerAdapter(engine, model="tiny-4b"),
                "goal", supported_tools={TOOL},
                model_gate=reg.gate(req, env, max_age_s=60.0, now=1.0))
        assert exc.value.code == MODEL_CAPABILITY_UNAVAILABLE
        assert engine.call_count == 0
        assert manager.execution_journal.pending(agent["id"]) == []
    finally:
        manager.close()


def test_managed_success_plans_and_validates_proposal(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "hr-ok.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        reg = ModelCardRegistry.from_host_config(_host_cards())
        env = build_snapshot(
            {("local", "local", "tiny-4b"): True,
             ("cloud", "cloud", "prose-70b"): True},
            version=1, issued_at=1.0)
        req = _req()
        engine = FakeEngine([{"content": _plan_json()}])
        out = AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).plan_goal(
            agent["id"], PlannerAdapter(engine, model="tiny-4b"),
            "goal", supported_tools={TOOL},
            model_gate=reg.gate(req, env, max_age_s=60.0, now=1.0))
        assert out.get("reused", False) is False
        assert engine.call_count == 1
        assert len(_plan(manager, agent["id"])["nodes"]) == 1
    finally:
        manager.close()


def test_flag_off_keeps_legacy_behavior(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "hr-flag.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        reg = ModelCardRegistry.from_host_config(_host_cards())
        env = build_snapshot({}, version=1, issued_at=1.0)
        engine = FakeEngine([{"content": _plan_json()}])
        AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).plan_goal(
            agent["id"], PlannerAdapter(engine, model="tiny-4b"),
            "goal", supported_tools={TOOL},
            model_gate=gate_or_none(reg, _req(), env, enforce=False,
                                    max_age_s=60.0, now=1.0))
        assert engine.call_count == 1
        assert len(_plan(manager, agent["id"])["nodes"]) == 1
    finally:
        manager.close()


def test_shadow_mode_causes_zero_mutation(tmp_path) -> None:
    from openjarvis.agents.host_routing import shadow_evaluate

    manager = AgentManager(str(tmp_path / "hr-shadow.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        reg = ModelCardRegistry.from_host_config(_host_cards())
        env = build_snapshot(
            {("local", "local", "tiny-4b"): True}, version=1, issued_at=1.0)
        before = manager.get_latest_checkpoint(agent["id"])["tool_state"]
        outcome = shadow_evaluate(reg, _req(), env)
        assert outcome.model == "tiny-4b"
        after = manager.get_latest_checkpoint(agent["id"])["tool_state"]
        assert after == before
        assert manager.execution_journal.pending(agent["id"]) == []
        assert _PlanProposalMutationTool.calls == 0
    finally:
        manager.close()


def test_escalation_states() -> None:
    assert escalation_state("MODEL_CAPABILITY_UNAVAILABLE") == (
        "MODEL_CAPABILITY_UNAVAILABLE")
    assert escalation_state("ALL_PROVIDERS_UNAVAILABLE") == (
        "PROVIDER_UNAVAILABLE")
    assert escalation_state("PRIVACY_ROUTE_UNAVAILABLE") == "PRIVACY_BLOCKED"
    assert escalation_state("LOCAL_ACCEPTED") == "LOCAL_ACCEPTED"
