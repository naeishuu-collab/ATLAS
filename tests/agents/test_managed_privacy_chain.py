"""Managed privacy-first routing chain (offline, mock-only, tmp sqlite).

Executable chain spec: privacy label -> registry/snapshot -> router ->
binding -> planner -> proposal -> authority -> plan. Defer variants
prove zero planner contact; identity/UNKNOWN items are covered by
test_agent_safe_e2e and not duplicated here.
"""

from __future__ import annotations

import json

import pytest

from openjarvis.agents.capability_router import (
    ModelCapability,
    RouteRequest,
    RouterFailure,
)
from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.host_routing import (
    ModelCardRegistry,
    RoutingError,
    bind_decision,
    build_snapshot,
    privacy_from_agent,
)
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.planner import PlannerAdapter
from openjarvis.core.events import EventBus
from openjarvis.security.cloud_dispatch import PrivacyClassification
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem
from tests.agents.test_plan_proposal_materialization import (
    _PlanProposalMutationTool,
    _ready,
    _register,
)

TOOL = _PlanProposalMutationTool.tool_id
T = ModelCapability.TEXT
N = ModelCapability.NATIVE_TOOLS


def _cards():
    return [
        {"engine": "fake", "provider": "local", "model": "tiny-4b",
         "capabilities": ["TEXT"], "ctx_limit": 4096,
         "cost_per_1k": 0.0, "latency_p50_ms": 50.0,
         "is_cloud": False, "tier": 0},
        {"engine": "fake", "provider": "cloud", "model": "prose-70b",
         "capabilities": ["TEXT", "STRUCTURED_JSON", "NATIVE_TOOLS"],
         "ctx_limit": 128000, "cost_per_1k": 1.0, "latency_p50_ms": 800.0,
         "is_cloud": True, "structured_reliability": 0.9, "tier": 2},
    ]


def _labeled(manager: AgentManager, privacy: str | None):
    _register()
    config = {"model": "fake-model", "instruction": "Do it.",
              "tools": [TOOL]}
    if privacy is not None:
        config["privacy"] = privacy
    return manager.create_agent("privacy-chain-test",
                                agent_type="orchestrator", config=config)


def _plan_json():
    return json.dumps({"steps": [
        {"local_index": "s1", "kind": "MUTATING", "tool_name": TOOL,
         "arguments": {"value": "one"}}]})


def _chain(manager, agent, *, need, status, now=1000.0):
    """Run the full host chain; return (engine, outcome-or-error)."""
    reg = ModelCardRegistry.from_host_config(_cards())
    env = build_snapshot(status, version=1, issued_at=1000.0)
    privacy = privacy_from_agent(agent)
    req = RouteRequest(difficulty="standard", need=frozenset(need),
                       privacy=privacy, est_prompt_tokens=100)
    decision = reg.router().propose(req, env.snapshot)
    engine = FakeEngine([{"content": _plan_json()}])
    try:
        if isinstance(decision, RouterFailure):
            # Managed seam refusal: same code the gate enforces, zero
            # planner contact.
            raise RoutingError(decision.code, decision.reason)
        planner = PlannerAdapter(engine, model=decision.model)
        bind_decision(decision, reg.cards, planner_model=planner.model,
                      host_engine="fake")
        out = AgentExecutor(
            manager, EventBus(), system=FakeSystem(FakeEngine([]))
        ).plan_goal(agent["id"], planner, "goal",
                    supported_tools={TOOL},
                    model_gate=reg.gate(req, env, max_age_s=600.0, now=now))
    except RoutingError as exc:
        return engine, exc
    return engine, out


def _status(*triples):
    return {t: True for t in triples}


_LOCAL = ("fake", "local", "tiny-4b")
_CLOUD = ("fake", "cloud", "prose-70b")


def test_chain_public_local_plans(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "pc.db"))
    try:
        agent = _labeled(manager, "PUBLIC")
        _ready(manager, agent["id"])
        engine, out = _chain(manager, agent, need={T},
                             status=_status(_LOCAL, _CLOUD))
        assert engine.call_count == 1
        assert len(out["plan"]["nodes"]) == 1
        assert manager.execution_journal.pending(agent["id"]) == []
    finally:
        manager.close()


def test_chain_private_stays_local(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "pc-priv.db"))
    try:
        agent = _labeled(manager, "PRIVATE")
        assert privacy_from_agent(agent) == PrivacyClassification.PRIVATE
        _ready(manager, agent["id"])
        engine, out = _chain(manager, agent, need={T},
                             status=_status(_LOCAL, _CLOUD))
        assert engine.call_count == 1
        assert len(out["plan"]["nodes"]) == 1
    finally:
        manager.close()


def test_chain_private_cloud_only_defers(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "pc-privout.db"))
    try:
        agent = _labeled(manager, "PRIVATE")
        _ready(manager, agent["id"])
        engine, err = _chain(manager, agent, need={T},
                             status=_status(_CLOUD))
        assert isinstance(err, RoutingError)
        assert err.code == "PRIVACY_ROUTE_UNAVAILABLE"
        assert engine.call_count == 0
        assert manager.execution_journal.pending(agent["id"]) == []
    finally:
        manager.close()


def test_chain_unlabeled_agent_defers(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "pc-unlabeled.db"))
    try:
        agent = _labeled(manager, None)
        _ready(manager, agent["id"])
        with pytest.raises(RoutingError) as exc:
            _chain(manager, agent, need={T}, status=_status(_LOCAL))
        assert exc.value.code == "PRIVACY_UNKNOWN"
    finally:
        manager.close()


def test_chain_outage_defers(tmp_path) -> None:
    manager = AgentManager(str(tmp_path / "pc-outage.db"))
    try:
        agent = _labeled(manager, "PUBLIC")
        _ready(manager, agent["id"])
        engine, err = _chain(manager, agent, need={T}, status={})
        assert isinstance(err, RoutingError)
        assert err.code == "ALL_PROVIDERS_UNAVAILABLE"
        assert engine.call_count == 0
    finally:
        manager.close()


def test_chain_internal_may_select_cloud(tmp_path) -> None:
    """INTERNAL is cloud-eligible by design (only PRIVATE is local-only);
    the router still gates capability and the host still verifies."""
    manager = AgentManager(str(tmp_path / "pc-internal.db"))
    try:
        agent = _labeled(manager, "INTERNAL")
        _ready(manager, agent["id"])
        engine, out = _chain(manager, agent, need={N},
                             status=_status(_LOCAL, _CLOUD))
        assert engine.call_count == 1
        assert len(out["plan"]["nodes"]) == 1
    finally:
        manager.close()
