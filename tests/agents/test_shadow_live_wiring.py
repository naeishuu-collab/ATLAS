"""Mock-host shadow integration (offline, mock-only).

Connection spec: the mock host runs the legacy tick first and observes
with the shadow router after. The tick never sees the router; the
router never touches the tick. Live prod wiring is BLOCKED (pinned
below); CLI/server entries are covered by static pins in
test_production_tick_routing plus execute_tick tests, not duplicated.
"""

from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import patch

import pytest

from openjarvis.agents.host_routing import (
    ModelCardRegistry,
    assemble_tick_supply,
    build_snapshot,
    shadow_tick_evaluate,
)
from tests.agents.scenario_harness import ScenarioHarness

ISSUED_AT = 1000.0


def _cards():
    return [
        {"engine": "FakeEngine", "provider": "local", "model": "fake-model",
         "capabilities": ["TEXT"], "ctx_limit": 4096,
         "cost_per_1k": 0.0, "latency_p50_ms": 50.0,
         "is_cloud": False, "tier": 0},
    ]


def _reg():
    return ModelCardRegistry.from_host_config(_cards())


def _env(**over):
    args = {"status": {("FakeEngine", "local", "fake-model"): True},
            "version": 1, "issued_at": ISSUED_AT}
    args.update(over)
    return build_snapshot(**args)


def _mock_host_tick(h: ScenarioHarness, agent_id: str, registry,
                    privacy: str, env, *, now: float = ISSUED_AT):
    """Mock-host connection spec: legacy tick, then shadow observe."""
    h.executor.execute_tick(agent_id)
    agent = h.manager.get_agent(agent_id)
    supply = assemble_tick_supply(
        agent=agent, system=h.system, registry=registry, privacy=privacy,
        snapshot_env=env, max_age_s=600.0, now=now)
    return agent, shadow_tick_evaluate(supply, registry)


def test_mock_host_tick_observes_legacy_run(scenario_harness) -> None:
    h = scenario_harness
    h.engine._responses = [{"content": "Tick done."}]
    agent = h.manager.create_agent(
        name="shadow-manual",
        config={"schedule_type": "manual", "instruction": "Do it."})
    ran, record = _mock_host_tick(h, agent["id"], _reg(), "PUBLIC", _env())
    assert ran["total_runs"] == 1
    assert record["outcome"] == "fake-model"
    assert record["dispatched"] is False
    assert record["mutations"] == 0


def test_scheduler_entry_reaches_tick_and_shadow(scenario_harness) -> None:
    h = scenario_harness
    h.engine._responses = [{"content": "Interval done."}]
    agent = h.manager.create_agent(
        name="shadow-interval",
        config={"schedule_type": "interval", "schedule_value": 60,
                "instruction": "Check."})
    with patch("openjarvis.agents.scheduler.time") as mock_time:
        mock_time.time.return_value = 1_000_000.0
        h.scheduler.register_agent(agent["id"])
    with patch("openjarvis.agents.scheduler.time") as mock_time:
        mock_time.time.return_value = 1_000_061.0
        h.scheduler._check_due_agents()
    assert h.manager.get_agent(agent["id"])["total_runs"] == 1
    _, record = _observe_only(h, agent["id"])
    assert record["outcome"] == "fake-model"


def _observe_only(h: ScenarioHarness, agent_id: str):
    agent = h.manager.get_agent(agent_id)
    supply = assemble_tick_supply(
        agent=agent, system=h.system, registry=_reg(), privacy="PUBLIC",
        snapshot_env=_env(), max_age_s=600.0, now=ISSUED_AT)
    return agent, shadow_tick_evaluate(supply, _reg())


def test_shadow_off_on_parity(scenario_harness) -> None:
    h = scenario_harness
    h.engine._responses = [{"content": "Same."}, {"content": "Same."}]
    bare = h.manager.create_agent(
        name="bare", config={"schedule_type": "manual"})
    h.executor.execute_tick(bare["id"])
    shadowed = h.manager.create_agent(
        name="shadowed", config={"schedule_type": "manual"})
    ran, record = _mock_host_tick(
        h, shadowed["id"], _reg(), "PUBLIC", _env())
    assert h.manager.get_agent(bare["id"])["total_runs"] == 1
    assert ran["total_runs"] == 1
    assert h.engine.call_count == 2
    assert record["outcome"] == "fake-model"


@pytest.mark.parametrize("privacy,now,code", [
    ("ULTRA_SECRET", ISSUED_AT, "PRIVACY_UNKNOWN"),
    ("PUBLIC", 99999.0, "SNAPSHOT_STALE"),
])
def test_shadow_failure_modes_leave_tick_intact(
        scenario_harness, privacy, now, code) -> None:
    h = scenario_harness
    h.engine._responses = [{"content": "Tick done."}]
    agent = h.manager.create_agent(
        name=f"shadow-fail-{code}", config={"schedule_type": "manual"})
    h.executor.execute_tick(agent["id"])
    assert h.manager.get_agent(agent["id"])["total_runs"] == 1
    got = h.manager.get_agent(agent["id"])
    try:
        supply = assemble_tick_supply(
            agent=got, system=h.system, registry=_reg(), privacy=privacy,
            snapshot_env=_env(), max_age_s=600.0, now=now)
        record = shadow_tick_evaluate(supply, _reg())
    except Exception as exc:  # supply-time refusal is also shadow-safe
        record = {"outcome": getattr(exc, "code", type(exc).__name__),
                  "dispatched": False, "mutations": 0}
    assert record["outcome"] == code
    assert record["dispatched"] is False
    assert h.manager.get_agent(agent["id"])["total_runs"] == 1


def test_no_secrets_in_logs(scenario_harness, caplog) -> None:
    import logging

    h = scenario_harness
    h.engine._responses = [{"content": "Tick done."}]
    agent = h.manager.create_agent(
        name="shadow-logged",
        config={"schedule_type": "manual",
                "instruction": "SECRET_MARKER_SHADOW_XYZ"})
    with caplog.at_level(logging.DEBUG):
        _mock_host_tick(h, agent["id"], _reg(), "PUBLIC", _env())
    assert "SECRET_MARKER_SHADOW_XYZ" not in caplog.text


def test_live_shadow_wiring_absent_from_prod_tick() -> None:
    """BLOCKED pin: no live shadow call exists in the production tick
    path. Wiring it requires owner approval + host supply, and must
    update this pin with reachability proof."""
    import openjarvis.agents.executor as executor_mod

    tree = ast.parse(Path(executor_mod.__file__).read_text(encoding="utf-8"))
    assert "shadow_tick_evaluate" not in ast.dump(tree)
    assert "assemble_tick_supply" not in ast.dump(tree)
