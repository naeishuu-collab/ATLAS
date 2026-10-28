"""Tick supply + shadow integration proofs (offline, mock-only).

Proves the host-owned supply bundle for production ticks and shadow
evaluation without touching the live tick path (which stays BLOCKED).
Items 16-18 (tick compat, UNKNOWN, exactly-once) are covered by
test_production_tick_routing / test_agent_safe_e2e; not duplicated.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from openjarvis.agents.host_routing import (
    BINDING_MISMATCH,
    ENFORCE_BLOCKED,
    MODEL_BINDING_UNVERIFIED,
    PRIVACY_UNKNOWN,
    REGISTRY_EMPTY,
    SNAPSHOT_STALE,
    ModelCardRegistry,
    RoutingError,
    assemble_tick_supply,
    build_snapshot,
    require_enforce,
    shadow_tick_evaluate,
    snapshot_from_engine,
)
from openjarvis.security.cloud_dispatch import PrivacyClassification


def _cards():
    return [
        {"engine": "fake", "provider": "local", "model": "tiny-4b",
         "capabilities": ["TEXT"], "ctx_limit": 4096,
         "cost_per_1k": 0.0, "latency_p50_ms": 50.0,
         "is_cloud": False, "tier": 0},
    ]


def _agent(model="tiny-4b"):
    return {"id": "agent-1", "config": {"model": model}}


def _system():
    class _FakeTickEngine:
        engine_id = "fake"

    return SimpleNamespace(engine=_FakeTickEngine(), model="system-default")


def _reg():
    return ModelCardRegistry.from_host_config(_cards())


def _env(**over):
    args = {"status": {("fake", "local", "tiny-4b"): True},
            "version": 1, "issued_at": 1000.0}
    args.update(over)
    return build_snapshot(**args)


def _supply(**over):
    args = {"agent": _agent(), "system": _system(), "registry": _reg(),
            "privacy": "PUBLIC", "snapshot_env": _env(),
            "max_age_s": 600.0, "now": 1000.0}
    args.update(over)
    return assemble_tick_supply(**args)


def test_host_supply_normal() -> None:
    supply = _supply()
    assert supply.agent_id == "agent-1"
    assert supply.model == "tiny-4b"
    assert supply.engine == "fake"
    assert supply.privacy == PrivacyClassification.PUBLIC


def test_missing_registry_rejects() -> None:
    reg = ModelCardRegistry.from_host_config([])
    with pytest.raises(RoutingError) as exc:
        _supply_with_registry(reg)
    assert exc.value.code == REGISTRY_EMPTY


def _supply_with_registry(reg):
    return _supply(registry=reg)


def test_stale_snapshot_rejects() -> None:
    with pytest.raises(RoutingError) as exc:
        _supply(now=99999.0)
    assert exc.value.code == SNAPSHOT_STALE


def test_unknown_privacy_rejects() -> None:
    with pytest.raises(RoutingError) as exc:
        _supply(privacy="ULTRA_SECRET")
    assert exc.value.code == PRIVACY_UNKNOWN


def test_model_binding_mismatch_rejects() -> None:
    from openjarvis.agents.host_routing import bind_tick_supply

    supply = _supply()
    reg = ModelCardRegistry.from_host_config(_cards())
    with pytest.raises(RoutingError) as exc:
        bind_tick_supply(supply, reg, planner_model="other-model",
                         max_age_s=600.0, now=1000.0)
    assert exc.value.code == BINDING_MISMATCH


def test_ambiguous_provider_is_unverified() -> None:
    from openjarvis.agents.host_routing import bind_tick_supply

    cards = _cards() + [dict(_cards()[0], provider="local-2")]
    reg = ModelCardRegistry.from_host_config(cards)
    supply = _supply()
    with pytest.raises(RoutingError) as exc:
        bind_tick_supply(supply, reg, planner_model="tiny-4b",
                         max_age_s=600.0, now=1000.0)
    assert exc.value.code == MODEL_BINDING_UNVERIFIED


def test_shadow_keeps_existing_model() -> None:
    from openjarvis.agents.executor import _resolve_tick_model

    agent, system = _agent(), _system()
    before = _resolve_tick_model(agent["config"], system)
    reg = ModelCardRegistry.from_host_config(_cards())
    record = shadow_tick_evaluate(_supply(), reg)
    after = _resolve_tick_model(agent["config"], system)
    assert before == after == "tiny-4b"
    assert record["dispatched"] is False
    assert record["mutations"] == 0


def test_shadow_records_router_failure_without_raising() -> None:
    reg = ModelCardRegistry.from_host_config(_cards())
    supply = _supply()
    record = shadow_tick_evaluate(supply, reg, need=("NATIVE_TOOLS",))
    assert record["dispatched"] is False
    assert record["mutations"] == 0
    assert "MODEL_CAPABILITY_UNAVAILABLE" in record["outcome"]


def test_shadow_sends_no_private_data() -> None:
    import ast
    from pathlib import Path

    import openjarvis.agents.host_routing as hr

    src = ast.dump(ast.parse(Path(hr.__file__).read_text(encoding="utf-8")))
    assert "requests" not in src
    assert "httpx" not in src
    assert "urllib" not in src


def test_enforce_missing_preconditions_blocked() -> None:
    reg = ModelCardRegistry.from_host_config([])
    with pytest.raises(RoutingError) as exc:
        require_enforce(agent=_agent(), system=_system(), registry=reg,
                        privacy="PUBLIC", snapshot_env=_env(),
                        max_age_s=600.0, now=1000.0)
    assert exc.value.code == ENFORCE_BLOCKED


def test_agent_identity_isolation() -> None:
    reg = ModelCardRegistry.from_host_config(_cards())
    a = _supply()
    b = _supply()
    b = assemble_tick_supply(
        agent={"id": "agent-2", "config": {"model": "tiny-4b"}},
        system=_system(), registry=_reg(), privacy="PUBLIC",
        snapshot_env=_env(), max_age_s=600.0, now=1000.0)
    assert a.agent_id != b.agent_id
    ra = shadow_tick_evaluate(a, reg)
    rb = shadow_tick_evaluate(b, reg)
    assert ra["agent_id"] == "agent-1"
    assert rb["agent_id"] == "agent-2"


def test_snapshot_isolation_across_registry_rebuild() -> None:
    env = _env()
    reg1 = ModelCardRegistry.from_host_config(_cards())
    reg2 = ModelCardRegistry.from_host_config([])
    assert shadow_tick_evaluate(_supply(), reg1)["outcome"] != (
        shadow_tick_evaluate(_supply(), reg2)["outcome"])
    assert env.snapshot.available == {
        ("fake", "local", "tiny-4b"): True}


def test_snapshot_from_engine_listing() -> None:
    class _Eng:
        def list_models(self):
            return ["tiny-4b", "other"]

    reg = ModelCardRegistry.from_host_config(_cards())
    env = snapshot_from_engine(_Eng(), reg, version=3, issued_at=50.0)
    assert env.snapshot.available == {("fake", "local", "tiny-4b"): True}
    assert env.version == 3
