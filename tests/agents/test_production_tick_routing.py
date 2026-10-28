"""Production tick routing decision proofs (offline, mock-only).

Characterizes the real CLI/Scheduler/Server -> execute_tick model flow
and pins the router-integration decision: CapabilityRouter stays out of
the production tick path (no cards/snapshot/privacy plumbing exists
there) and applies to managed planning only. Dynamic tick execution
itself is covered by test_agent_lifecycle_scenarios / test_executor.
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from openjarvis.agents.executor import (
    _AGENT_TICK_DEFAULT_MODEL,
    _available_tick_models,
    _resolve_tick_model,
)


class _ListingEngine:
    def __init__(self, models=None, boom=False):
        self._models = models
        self._boom = boom

    def list_models(self):
        if self._boom:
            raise RuntimeError("discovery down")
        return self._models


def test_tick_model_prefers_agent_config() -> None:
    system = SimpleNamespace(model="system-default")
    assert _resolve_tick_model({"model": "config-model"}, system) == (
        "config-model")


def test_tick_model_falls_back_to_system_then_default() -> None:
    assert _resolve_tick_model(
        {}, SimpleNamespace(model="system-default")) == "system-default"
    assert _resolve_tick_model({}, SimpleNamespace(model="")) == (
        _AGENT_TICK_DEFAULT_MODEL)
    assert _resolve_tick_model({}, None) == _AGENT_TICK_DEFAULT_MODEL


def test_available_models_keep_resolved_first() -> None:
    engine = _ListingEngine(models=["other", "resolved"])
    assert _available_tick_models(engine, "resolved") == (
        ["resolved", "other"])


def test_available_models_fall_back_to_singleton() -> None:
    assert _available_tick_models(
        _ListingEngine(models=[]), "resolved") == ["resolved"]
    assert _available_tick_models(
        _ListingEngine(boom=True), "resolved") == ["resolved"]
    assert _available_tick_models(_ListingEngine(boom=True), "") == []


def _prod_src(*names: str) -> dict:
    import openjarvis

    root = Path(openjarvis.__file__).parent
    return {n: (root / n).read_text(encoding="utf-8") for n in names}


def test_production_entries_reach_execute_tick() -> None:
    src = _prod_src("cli/agent_cmd.py", "agents/scheduler.py",
                    "server/agent_manager_routes.py")
    assert "execute_tick(agent_id)" in src["cli/agent_cmd.py"]
    assert "self._executor.execute_tick(agent_id)" in (
        src["agents/scheduler.py"])
    assert "execute_tick(agent_id" in src["server/agent_manager_routes.py"]


def test_tick_path_has_no_router_or_privacy_plumbing() -> None:
    """Decision D pin: no CapabilityRouter, no privacy classification in
    the production tick modules. Adding either must update the router
    integration decision, not slip in silently."""
    src = _prod_src("agents/executor.py", "agents/scheduler.py",
                    "cli/agent_cmd.py")
    for name, text in src.items():
        assert "CapabilityRouter" not in text, name
        assert "PrivacyClassification" not in text, name


def test_tick_router_seam_fails_open_by_design() -> None:
    """The existing router_policy seam documents silent fallback. This
    pin records the current behavior (compat freeze); changing it to
    fail-closed needs the seam owner's approval, not a drive-by edit."""
    import openjarvis.agents.executor as executor_mod

    text = Path(executor_mod.__file__).read_text(encoding="utf-8")
    tree = ast.parse(text)
    assert "router_policy" in ast.dump(tree)
    assert "Fall back to configured model" in text
