"""Tests for the heuristic model router (canonical location)."""

from __future__ import annotations

from openjarvis.core.registry import ModelRegistry
from openjarvis.core.types import ModelSpec
from openjarvis.learning._stubs import RoutingContext
from openjarvis.learning.routing.router import (
    HeuristicRouter,
    TieredRouter,
    build_routing_context,
)


def _register_models() -> None:
    """Register a small set of models for testing."""
    ModelRegistry.register_value(
        "small",
        ModelSpec(
            model_id="small",
            name="Small",
            parameter_count_b=3.0,
            context_length=4096,
        ),
    )
    ModelRegistry.register_value(
        "large",
        ModelSpec(
            model_id="large",
            name="Large",
            parameter_count_b=70.0,
            context_length=131072,
        ),
    )
    ModelRegistry.register_value(
        "coder",
        ModelSpec(
            model_id="coder",
            name="DeepSeek Coder",
            parameter_count_b=16.0,
            context_length=131072,
        ),
    )


class TestBuildRoutingContext:
    def test_code_detection(self) -> None:
        ctx = build_routing_context("def hello():\n    pass")
        assert ctx.has_code is True
        assert ctx.has_math is False

    def test_math_detection(self) -> None:
        ctx = build_routing_context("solve the integral of x^2")
        assert ctx.has_math is True
        assert ctx.has_code is False

    def test_length(self) -> None:
        ctx = build_routing_context("Hi")
        assert ctx.query_length == 2

    def test_urgency_default(self) -> None:
        ctx = build_routing_context("test")
        assert ctx.urgency == 0.5

    def test_runtime_metadata_survives_context_build(self) -> None:
        ctx = build_routing_context(
            "test",
            metadata={"failure_history": 2, "uncertainty": 0.9},
        )
        assert ctx.metadata["failure_history"] == 2
        assert ctx.metadata["uncertainty"] == 0.9


class TestHeuristicRouter:
    def test_short_query_prefers_small(self) -> None:
        _register_models()
        router = HeuristicRouter(
            available_models=["small", "large", "coder"],
        )
        ctx = RoutingContext(query="Hi", query_length=2)
        assert router.select_model(ctx) == "small"

    def test_code_prefers_coder(self) -> None:
        _register_models()
        router = HeuristicRouter(
            available_models=["small", "large", "coder"],
        )
        ctx = RoutingContext(
            query="def foo():",
            query_length=10,
            has_code=True,
        )
        assert router.select_model(ctx) == "coder"

    def test_math_prefers_large(self) -> None:
        _register_models()
        router = HeuristicRouter(
            available_models=["small", "large", "coder"],
        )
        ctx = build_routing_context("solve the integral of x^2 dx")
        assert ctx.has_math is True
        assert ctx.complexity_score > 0.20
        assert router.select_model(ctx) == "large"

    def test_unknown_local_model_does_not_beat_known_local_model(self) -> None:
        _register_models()
        ModelRegistry.register_value(
            "unknown-local",
            ModelSpec(
                model_id="unknown-local",
                name="Unknown local model",
                parameter_count_b=0.0,
                context_length=4096,
                supported_engines=("ollama",),
            ),
        )
        router = HeuristicRouter(available_models=["small", "unknown-local"])
        ctx = RoutingContext(
            query="solve this carefully",
            query_length=20,
            has_math=True,
            complexity_score=0.4,
        )

        assert router.select_model(ctx) == "small"

    def test_low_complexity_math_prefers_small(self) -> None:
        """Regression test: a trivial math query ("calculate 2+2") must not
        escalate to the largest model just because it contains a math
        keyword — the low-complexity rule takes priority over the math rule.
        """
        _register_models()
        router = HeuristicRouter(
            available_models=["small", "large", "coder"],
        )
        ctx = build_routing_context("calculate 2+2")
        assert ctx.has_math is True
        assert ctx.complexity_score == 0.20
        assert router.select_model(ctx) == "small"

    def test_high_complexity_prefers_large(self) -> None:
        _register_models()
        router = HeuristicRouter(
            available_models=["small", "large", "coder"],
        )
        ctx = RoutingContext(query="x" * 501, query_length=501, complexity_score=0.7)
        assert router.select_model(ctx) == "large"

    def test_high_urgency_overrides_to_small(self) -> None:
        _register_models()
        router = HeuristicRouter(
            available_models=["small", "large", "coder"],
        )
        ctx = RoutingContext(
            query="x" * 501,
            query_length=501,
            urgency=0.9,
        )
        assert router.select_model(ctx) == "small"

    def test_fallback_chain(self) -> None:
        _register_models()
        router = HeuristicRouter(
            available_models=["small", "large"],
            default_model="large",
            fallback_model="small",
        )
        # Medium complexity, no code/math, no reasoning → falls to default
        ctx = RoutingContext(
            query="Tell me about cats",
            query_length=60,
            complexity_score=0.35,
        )
        assert router.select_model(ctx) == "large"

    def test_no_available_models(self) -> None:
        router = HeuristicRouter(
            available_models=[],
            default_model="fallback-model",
        )
        ctx = RoutingContext(query="test", query_length=4)
        assert router.select_model(ctx) == "fallback-model"

    def test_reasoning_keywords_prefer_large(self) -> None:
        _register_models()
        router = HeuristicRouter(available_models=["small", "large"])
        query = (
            "Please explain step by step how the process"
            " of photosynthesis works in plants"
        )
        ctx = build_routing_context(query)
        assert router.select_model(ctx) == "large"

    def test_code_without_coder_falls_to_large(self) -> None:
        _register_models()
        router = HeuristicRouter(
            available_models=["small", "large"],
        )
        ctx = RoutingContext(
            query="def foo():",
            query_length=10,
            has_code=True,
        )
        assert router.select_model(ctx) == "large"


class TestTieredRouter:
    def setup_method(self) -> None:
        specs = (
            ("local-model", 1.0, ("ollama",)),
            ("luna-model", 8.0, ("ollama",)),
            ("terra-model", 0.0, ("cloud",)),
            ("sol-model", 0.0, ("cloud",)),
        )
        for model_id, parameter_count, engines in specs:
            if not ModelRegistry.contains(model_id):
                ModelRegistry.register_value(
                    model_id,
                    ModelSpec(
                        model_id=model_id,
                        name=model_id,
                        parameter_count_b=parameter_count,
                        context_length=4096,
                        supported_engines=engines,
                    ),
                )

    def _router(self) -> TieredRouter:
        return TieredRouter(
            available_models=[
                "local-model",
                "luna-model",
                "terra-model",
                "sol-model",
            ],
            default_model="luna-model",
            fallback_model="terra-model",
            tier_models={
                "local": "local-model",
                "luna": "luna-model",
                "terra": "terra-model",
                "sol": "sol-model",
            },
        )

    def test_escalates_through_configured_tiers(self) -> None:
        router = self._router()
        assert router.select_model(
            RoutingContext(complexity_score=0.1)
        ) == "local-model"
        assert router.select_model(
            RoutingContext(complexity_score=0.35)
        ) == "luna-model"
        assert router.select_model(
            RoutingContext(has_reasoning=True, complexity_score=0.6)
        ) == "terra-model"
        assert router.select_model(RoutingContext(complexity_score=0.9)) == "sol-model"

    def test_failure_history_escalates_without_model_name_assumptions(self) -> None:
        router = self._router()
        context = RoutingContext(
            complexity_score=0.3,
            metadata={"failure_history": 2},
        )
        assert router.select_model(context) == "sol-model"

    def test_unavailable_tier_falls_back_to_available_capability(self) -> None:
        router = TieredRouter(
            available_models=["local-model", "luna-model"],
            default_model="luna-model",
            tier_models={"terra": "missing", "sol": "missing"},
        )
        assert router.select_model(RoutingContext(complexity_score=0.9)) == "luna-model"
