"""HostSupply independent regression (offline, mock-only).

Proves host-owned supply validation: missing registry, stale snapshot,
unknown privacy, and unresolvable model all fail closed before dispatch.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from openjarvis.agents.host_routing import (
    PRIVACY_UNKNOWN,
    REGISTRY_EMPTY,
    SNAPSHOT_STALE,
    ModelCardRegistry,
    RoutingError,
    build_snapshot,
)
from openjarvis.agents.host_supply import HostSupply

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


def test_host_supply_builds_from_host_owned_sources() -> None:
    supply = HostSupply.build(
        agent=_agent(), system=_system(), registry=_reg(),
        privacy="PUBLIC", snapshot_env=_env(),
        max_age_s=600.0, now=ISSUED_AT)
    assert supply.agent_id == "agent-1"
    assert supply.model == "tiny-4b"
    assert supply.engine == "fake"
    assert supply.privacy.value == "PUBLIC"


def test_missing_registry_rejected() -> None:
    with pytest.raises(RoutingError) as exc:
        HostSupply.build(agent=_agent(), system=_system(),
                         registry=ModelCardRegistry.from_host_config([]),
                         privacy="PUBLIC", snapshot_env=_env(),
                         max_age_s=600.0, now=ISSUED_AT)
    assert exc.value.code == REGISTRY_EMPTY


def test_stale_snapshot_rejected() -> None:
    with pytest.raises(RoutingError) as exc:
        HostSupply.build(agent=_agent(), system=_system(), registry=_reg(),
                         privacy="PUBLIC", snapshot_env=_env(),
                         max_age_s=600.0, now=99999.0)
    assert exc.value.code == SNAPSHOT_STALE


def test_unknown_privacy_rejected() -> None:
    with pytest.raises(RoutingError) as exc:
        HostSupply.build(agent=_agent(), system=_system(), registry=_reg(),
                         privacy="ULTRA_SECRET", snapshot_env=_env(),
                         max_age_s=600.0, now=ISSUED_AT)
    assert exc.value.code == PRIVACY_UNKNOWN


def test_bind_re_verifies_at_dispatch() -> None:
    supply = HostSupply.build(agent=_agent(), system=_system(),
                              registry=_reg(), privacy="PUBLIC",
                              snapshot_env=_env(), max_age_s=600.0,
                              now=ISSUED_AT)
    # Re-binding with the same model/engine succeeds.
    supply.bind(registry=_reg(), planner_model="tiny-4b",
                max_age_s=600.0, now=ISSUED_AT)
    # Model mismatch -> BINDING_MISMATCH fail closed.
    with pytest.raises(RoutingError) as exc:
        supply.bind(registry=_reg(), planner_model="other-model",
                    max_age_s=600.0, now=ISSUED_AT)
    assert exc.value.code == "BINDING_MISMATCH"
