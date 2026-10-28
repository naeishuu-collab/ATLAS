"""ShadowObserver independent regression (offline, mock-only).

Proves the read-only tick observer: observes model/engine/privacy/outcome
without changing the legacy tick, never dispatches, never mutates, never
sends to cloud, and never stops the tick on observation failure.
"""

from __future__ import annotations

from types import SimpleNamespace

from openjarvis.agents.host_routing import (
    ModelCardRegistry,
    build_snapshot,
)
from openjarvis.agents.shadow_observer import (
    SHADOW_OBSERVER_ENABLED,
    ShadowObservation,
    ShadowObserver,
)

ISSUED_AT = 1000.0


def _cards():
    return [
        {"engine": "fake", "provider": "local", "model": "tiny-4b",
         "capabilities": ["TEXT"], "ctx_limit": 4096,
         "cost_per_1k": 0.0, "latency_p50_ms": 50.0,
         "is_cloud": False, "tier": 0},
    ]


def _reg():
    return ModelCardRegistry.from_host_config(_cards())


def _env(**over):
    args = {"status": {("fake", "local", "tiny-4b"): True},
            "version": 1, "issued_at": ISSUED_AT}
    args.update(over)
    return build_snapshot(**args)


def _agent(agent_id="agent-1", model="tiny-4b", privacy="PUBLIC"):
    return {"id": agent_id, "config": {"model": model, "privacy": privacy}}


def _system():
    class _Sys:
        engine = SimpleNamespace(engine_id="fake")
        model = "system-default"

    return _Sys()


def _result():
    return SimpleNamespace(content="ok", tool_results=[], turns=1,
                           metadata={"total_tokens": 15})


def test_shadow_observer_defaults_off() -> None:
    """Default posture is OFF: no observation, no behavior change."""
    obs = ShadowObserver()
    assert obs.enabled is False
    assert SHADOW_OBSERVER_ENABLED is False


def test_shadow_observes_read_only_without_side_effects() -> None:
    obs = ShadowObserver(enabled=True)
    agent = _agent()
    system = _system()
    result = _result()
    rec = obs.observe(agent=agent, system=system, model="tiny-4b",
                      engine="fake", provider=None, privacy="PUBLIC",
                      result=result, registry=_reg(),
                      snapshot_env=_env(), now=ISSUED_AT)
    assert isinstance(rec, ShadowObservation)
    assert rec.agent_id == "agent-1"
    assert rec.model == "tiny-4b"
    assert rec.engine == "fake"
    assert rec.dispatched is False
    assert rec.mutations == 0
    assert rec.refused is False
    # Observation recorded but no dispatch/mutation occurred.
    assert len(obs.observations) == 1


def test_shadow_unknown_privacy_fails_closed_no_dispatch() -> None:
    obs = ShadowObserver(enabled=True)
    agent = _agent(privacy="ULTRA_SECRET")
    rec = obs.observe(agent=agent, system=_system(), model="tiny-4b",
                      engine="fake", provider=None, privacy="ULTRA_SECRET",
                      result=_result(), registry=_reg(),
                      snapshot_env=_env(), now=ISSUED_AT)
    assert rec.outcome == "PRIVACY_UNKNOWN"
    assert rec.dispatched is False
    assert rec.mutations == 0


def test_shadow_stale_snapshot_fails_closed() -> None:
    obs = ShadowObserver(enabled=True)
    agent = _agent()
    rec = obs.observe(agent=agent, system=_system(), model="tiny-4b",
                      engine="fake", provider=None, privacy="PUBLIC",
                      result=_result(), registry=_reg(),
                      snapshot_env=_env(), now=99999.0)
    assert rec.outcome == "SNAPSHOT_STALE"
    assert rec.dispatched is False


def test_shadow_observer_disabled_records_disabled_outcome() -> None:
    obs = ShadowObserver(enabled=False)
    rec = obs.observe(agent=_agent(), system=_system(), model="tiny-4b",
                      engine="fake", provider=None, privacy="PUBLIC",
                      result=_result(), registry=_reg(),
                      snapshot_env=_env(), now=ISSUED_AT)
    assert rec.outcome == "observer_disabled"
    assert rec.dispatched is False


def test_shadow_observer_never_stops_tick_on_failure() -> None:
    """Observation failure is swallowed: legacy tick continues."""
    obs = ShadowObserver(enabled=True)
    agent = _agent()
    # Missing registry (empty cards) -> REGISTRY_EMPTY, swallowed.
    rec = obs.observe(agent=agent, system=_system(), model="tiny-4b",
                      engine="fake", provider=None, privacy="PUBLIC",
                      result=_result(),
                      registry=ModelCardRegistry.from_host_config([]),
                      snapshot_env=_env(), now=ISSUED_AT)
    assert rec.outcome == "REGISTRY_EMPTY"
    assert rec.dispatched is False
    assert rec.refused is True
    # The observer itself still functions for a subsequent valid call.
    rec2 = obs.observe(agent=agent, system=_system(), model="tiny-4b",
                       engine="fake", provider=None, privacy="PUBLIC",
                       result=_result(), registry=_reg(),
                       snapshot_env=_env(), now=ISSUED_AT)
    assert rec2.outcome == "tiny-4b"


def test_shadow_run_status_and_secret_safe_failure_record() -> None:
    obs = ShadowObserver(enabled=True)
    rec = obs.observe(
        agent=_agent(), system=_system(), model="tiny-4b", engine="fake",
        provider=None, privacy="PUBLIC", result=None,
        error=RuntimeError("SECRET_SHOULD_NOT_BE_STORED"),
        registry=_reg(), snapshot_env=_env(), now=ISSUED_AT)
    assert rec.run_status == "FAILED"
    assert "SECRET_SHOULD_NOT_BE_STORED" not in rec.reason
    assert rec.reason == "RuntimeError"


def test_shadow_missing_host_supply_is_explicit() -> None:
    obs = ShadowObserver(enabled=True)
    rec = obs.observe(
        agent=_agent(), system=_system(), model="tiny-4b", engine="fake",
        provider=None, privacy="PUBLIC", result=_result(),
        registry=None, snapshot_env=None, now=ISSUED_AT)
    assert rec.outcome == "HOST_SUPPLY_UNAVAILABLE"
    assert rec.refused is True
