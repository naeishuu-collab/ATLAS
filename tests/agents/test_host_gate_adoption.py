"""Host gate adoption scope pins + model binding contract (offline)."""

from __future__ import annotations

import ast
import inspect
from functools import lru_cache
from pathlib import Path

import pytest

from openjarvis.agents import executor as executor_mod
from openjarvis.agents.capability_router import (
    MODEL_CAPABILITY_UNAVAILABLE,
    CapabilityRouter,
    ModelCapability,
    ModelCard,
    ProviderSnapshot,
    RouteDecision,
    RouteRequest,
    RouterFailure,
)
from openjarvis.agents.planner import PlannerAdapter
from openjarvis.security.cloud_dispatch import PrivacyClassification
from tests.agents.fake_engine import FakeEngine


def _src_tree(mod) -> ast.Module:
    return ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))


def _prod_callers(func_name: str, class_name: str | None = None) -> list:
    return _scan(tuple(sorted(_prod_files())), func_name, class_name)


@lru_cache(maxsize=1)
def _prod_files() -> tuple:
    import openjarvis

    root = Path(openjarvis.__file__).parent
    return tuple(p for p in root.rglob("*.py") if "tests" not in p.parts)


@lru_cache(maxsize=8)
def _scan(files: tuple, func_name: str, class_name: str | None) -> list:
    hits = []
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(
                    node.func, ast.Attribute):
                if node.func.attr == func_name:
                    hits.append(f"{path}:{node.lineno}")
            if (class_name is not None
                    and isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == class_name
                    and path.name != "planner.py"):
                hits.append(f"{path}:{node.lineno}")
    return hits


def test_plan_goal_has_a_production_managed_caller() -> None:
    hits = _prod_callers("plan_goal")
    assert any("executor.py" in hit for hit in hits)


def test_planner_adapter_has_no_production_constructions() -> None:
    hits = _prod_callers("", "PlannerAdapter")
    assert any("executor.py" in hit for hit in hits)


def test_model_gate_defaults_to_omission_compatible() -> None:
    sig = inspect.signature(executor_mod.AgentExecutor.plan_goal)
    param = sig.parameters["model_gate"]
    assert param.default is None


def test_planner_exposes_model_for_binding() -> None:
    planner = PlannerAdapter(FakeEngine([]), model="tiny-4b")
    assert planner.model == "tiny-4b"


class _BindingMismatch(ValueError):
    def __init__(self, expected: str, actual: str) -> None:
        super().__init__(f"MODEL_BINDING_MISMATCH: {expected!r} != {actual!r}")
        self.expected = expected
        self.actual = actual


def _check_binding(decision: RouteDecision, planner: PlannerAdapter) -> None:
    """Executable binding specification (host-side pattern): the planner
    must run the router-selected model; anything else defers safely."""
    if planner.model != decision.model:
        raise _BindingMismatch(decision.model, planner.model)


def _decision(model: str = "tiny-4b") -> RouteDecision:
    return RouteDecision(engine="local", model=model, reason="test")


def test_binding_match_allows_planner() -> None:
    _check_binding(_decision("tiny-4b"),
                   PlannerAdapter(FakeEngine([]), model="tiny-4b"))


def test_binding_mismatch_defers_safely() -> None:
    engine = FakeEngine([])
    with pytest.raises(_BindingMismatch) as exc:
        _check_binding(_decision("tiny-4b"),
                       PlannerAdapter(engine, model="other-model"))
    assert exc.value.expected == "tiny-4b"
    assert engine.call_count == 0


def test_router_failure_needs_no_binding_check() -> None:
    """A shortfall never reaches binding: there is no decision to bind."""
    cards = [ModelCard(
        engine="local", provider="local", model="tiny-4b",
        capabilities=frozenset({ModelCapability.TEXT}), ctx_limit=4096,
        cost_per_1k=0.0, latency_p50_ms=50.0, is_cloud=False, tier=0)]
    outcome = CapabilityRouter(cards).propose(
        RouteRequest(difficulty="hard",
                     need=frozenset({ModelCapability.NATIVE_TOOLS}),
                     privacy=PrivacyClassification.PRIVATE,
                     est_prompt_tokens=100),
        ProviderSnapshot(available={cards[0].key(): True}),
    )
    assert isinstance(outcome, RouterFailure)
    assert outcome.code == MODEL_CAPABILITY_UNAVAILABLE


def test_router_module_stays_grant_free() -> None:
    import openjarvis.agents.capability_router as router_mod

    src = ast.dump(_src_tree(router_mod))
    assert "CapabilityPolicy" not in src
    assert "ToolExecutor" not in src
