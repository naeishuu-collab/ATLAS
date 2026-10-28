"""observe_tick: the exact call the production tick diff will make.

Proves the read-only observation seam a shared `executor.py` hook needs:
no supply = no observation (legacy parity), a supply = one read-only
record, and every failure mode stays inside the observation.
"""

from __future__ import annotations

from types import SimpleNamespace

from openjarvis.agents.host_supply_factory import (
    MODE_SHADOW_ONLY,
    HostConfig,
    build_host_supply,
    observe_tick,
)
from tests.agents.test_host_supply_factory import (
    CLOUD_KEY,
    NOW,
    _cards,
)

LOCAL_KEY = ("ollama", "local", "tiny-4b")


def _agent(agent_id="agent-1", model="tiny-4b", privacy="PUBLIC"):
    return {"id": agent_id, "config": {"model": model, "privacy": privacy}}


def _system():
    class _Sys:
        engine = SimpleNamespace(engine_id="ollama")
        model = "tiny-4b"

    return _Sys()


def _bundle(**over):
    args = dict(
        mode=MODE_SHADOW_ONLY,
        model_registry=tuple(_cards()),
        snapshot_status={LOCAL_KEY: True, CLOUD_KEY: True},
        snapshot_version=1,
        snapshot_issued_at=NOW,
        snapshot_max_age_s=600.0,
        shadow_enabled=True,
        privacy_policy={"agent-1": "PUBLIC"},
    )
    args.update(over)
    return build_host_supply(HostConfig(**args), now=NOW)


def _observe(bundle, **over):
    kwargs = dict(agent=_agent(), system=_system(), model="tiny-4b",
                  engine="ollama", result=SimpleNamespace(
                      content="ok", metadata={}), now=NOW)
    kwargs.update(over)
    return observe_tick(bundle, **kwargs)


def test_absent_supply_observes_nothing() -> None:
    assert _observe(None) is None


def test_supply_produces_one_read_only_record() -> None:
    bundle = _bundle()
    record = _observe(bundle)
    assert record.agent_id == "agent-1"
    assert record.outcome == "tiny-4b"
    assert record.run_status == "SUCCEEDED"
    assert record.dispatched is False
    assert record.mutations == 0
    assert len(bundle.shadow_observer.observations) == 1


def test_failed_ticks_are_observed_without_text_leakage() -> None:
    bundle = _bundle()
    record = _observe(bundle, result=None,
                      error=RuntimeError("prompt text must not be recorded"))
    assert record.run_status == "FAILED"
    assert "prompt text" not in record.reason
    assert record.reason == "RuntimeError"


def test_stale_at_observation_time_is_recorded_not_raised() -> None:
    bundle = _bundle()
    # The build-time freshness check passed; the snapshot expires later.
    record = _observe(bundle, now=NOW + 10_000.0)
    assert record.refused is True
    assert record.outcome == "SNAPSHOT_STALE"
    assert record.dispatched is False


def test_stale_at_build_time_is_refused_before_any_observation() -> None:
    from openjarvis.agents.host_supply_factory import HostSupplyError

    try:
        _bundle(snapshot_issued_at=NOW - 10_000.0, snapshot_max_age_s=1.0)
    except HostSupplyError as exc:
        assert exc.code == "SNAPSHOT_STALE"
    else:  # pragma: no cover - fail closed is the contract
        raise AssertionError("stale snapshot must not build")


def test_unmapped_privacy_is_observed_as_unknown() -> None:
    bundle = _bundle(privacy_policy={"other": "PUBLIC"})
    record = _observe(bundle, agent={"id": "agent-1", "config": {}})
    assert record.refused is True
    assert record.outcome == "PRIVACY_UNKNOWN"


def test_disabled_observer_records_nothing_dispatched() -> None:
    bundle = _bundle(shadow_enabled=False)
    record = _observe(bundle)
    assert record.outcome == "observer_disabled"
    assert record.dispatched is False


def test_observe_tick_never_raises_on_hostile_inputs() -> None:
    bundle = _bundle()
    for over in ({"agent": None}, {"system": object()},
                 {"model": None, "engine": None}, {"result": object()},
                 {"agent": "not-a-dict"}, {"error": KeyboardInterrupt()}):
        assert observe_tick(bundle, **_base(over)) is not None


def _base(over):
    kwargs = dict(agent=_agent(), system=_system(), model="tiny-4b",
                  engine="ollama", result=SimpleNamespace(content="ok",
                                                           metadata={}),
                  now=NOW)
    kwargs.update(over)
    return kwargs
