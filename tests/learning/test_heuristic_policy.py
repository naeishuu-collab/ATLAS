"""Tests for heuristic policy registration."""

from __future__ import annotations

from openjarvis.core.registry import RouterPolicyRegistry
from openjarvis.learning.routing.heuristic_policy import ensure_registered
from openjarvis.learning.routing.router import HeuristicRouter, TieredRouter


class TestHeuristicPolicy:
    def test_registered_as_heuristic(self) -> None:
        ensure_registered()
        assert RouterPolicyRegistry.contains("heuristic")
        assert RouterPolicyRegistry.contains("tiered")

    def test_value_is_heuristic_router(self) -> None:
        ensure_registered()
        assert RouterPolicyRegistry.get("heuristic") is HeuristicRouter
        assert RouterPolicyRegistry.get("tiered") is TieredRouter

    def test_can_instantiate(self) -> None:
        ensure_registered()
        cls = RouterPolicyRegistry.get("heuristic")
        router = cls(available_models=["model-a"])
        assert router.available_models == ["model-a"]
