"""Capability router tests — proposals only, no dispatch power."""

from __future__ import annotations

from openjarvis.agents.capability_router import (
    ALL_PROVIDERS_UNAVAILABLE,
    MODEL_CAPABILITY_UNAVAILABLE,
    CapabilityRouter,
    ModelCapability,
    ModelCard,
    ProviderSnapshot,
    RouteDecision,
    RouteRequest,
    RouterFailure,
)
from openjarvis.security.cloud_dispatch import PrivacyClassification

T = ModelCapability.TEXT
J = ModelCapability.STRUCTURED_JSON
N = ModelCapability.NATIVE_TOOLS
L = ModelCapability.LONG_CONTEXT


def _cards():
    return [
        ModelCard(
            engine="ollama", provider="local", model="qwen3.5:2b",
            capabilities=frozenset({T}), ctx_limit=8192,
            cost_per_1k=0.0, latency_p50_ms=400.0, is_cloud=False,
        ),
        ModelCard(
            engine="litellm", provider="groq", model="llama-3.3-70b",
            capabilities=frozenset({T, J, N}), ctx_limit=32768,
            cost_per_1k=0.05, latency_p50_ms=800.0,
            structured_reliability=0.9,
        ),
        ModelCard(
            engine="cloud", provider="gemini", model="gemini-2.5-flash",
            capabilities=frozenset({T, J, L}), ctx_limit=131072,
            cost_per_1k=0.02, latency_p50_ms=1200.0,
            structured_reliability=0.7,
        ),
    ]


def _snap(**kw):
    base = {
        "available": {
            ("ollama", "local", "qwen3.5:2b"): True,
            ("litellm", "groq", "llama-3.3-70b"): True,
            ("cloud", "gemini", "gemini-2.5-flash"): True,
        }
    }
    base.update(kw)
    return ProviderSnapshot(**base)


def _req(**kw):
    base = {
        "difficulty": "standard",
        "need": frozenset({T}),
        "privacy": PrivacyClassification.INTERNAL,
        "est_prompt_tokens": 100,
    }
    base.update(kw)
    return RouteRequest(**base)


class TestSelection:
    def test_cheapest_capable_wins(self) -> None:
        d = CapabilityRouter(_cards()).propose(_req(), _snap())
        assert isinstance(d, RouteDecision)
        assert (d.engine, d.model) == ("ollama", "qwen3.5:2b")

    def test_structured_prefers_reliability(self) -> None:
        d = CapabilityRouter(_cards()).propose(_req(need=frozenset({T, J})), _snap())
        assert isinstance(d, RouteDecision)
        assert d.model == "llama-3.3-70b"

    def test_private_local_only(self) -> None:
        d = CapabilityRouter(_cards()).propose(
            _req(privacy=PrivacyClassification.PRIVATE), _snap()
        )
        assert isinstance(d, RouteDecision)
        assert d.engine == "ollama"

    def test_private_no_local_unavailable(self) -> None:
        snap = _snap(
            available={
                ("ollama", "local", "qwen3.5:2b"): False,
                ("litellm", "groq", "llama-3.3-70b"): True,
                ("cloud", "gemini", "gemini-2.5-flash"): True,
            }
        )
        r = CapabilityRouter(_cards()).propose(
            _req(privacy=PrivacyClassification.PRIVATE), snap
        )
        assert isinstance(r, RouterFailure)
        assert r.code == "PRIVACY_ROUTE_UNAVAILABLE"

    def test_capability_shortfall_explicit(self) -> None:
        r = CapabilityRouter(_cards()).propose(
            _req(need=frozenset({N, L})), _snap()
        )
        assert isinstance(r, RouterFailure)
        assert r.code == MODEL_CAPABILITY_UNAVAILABLE

    def test_context_overflow_explicit(self) -> None:
        r = CapabilityRouter(_cards()).propose(
            _req(est_prompt_tokens=200000), _snap()
        )
        assert isinstance(r, RouterFailure)
        assert r.code == MODEL_CAPABILITY_UNAVAILABLE

    def test_all_down(self) -> None:
        r = CapabilityRouter(_cards()).propose(_req(), _snap(available={}))
        assert isinstance(r, RouterFailure)
        assert r.code == ALL_PROVIDERS_UNAVAILABLE

    def test_quota_and_health(self) -> None:
        snap = _snap(quota_left={"groq": 0.0, "gemini": 0.0, "local": 10.0})
        d = CapabilityRouter(_cards()).propose(_req(), snap)
        assert isinstance(d, RouteDecision)
        assert d.engine == "ollama"
        snap2 = _snap(quota_left={"groq": 0.0, "gemini": 0.0, "local": 0.0})
        r = CapabilityRouter(_cards()).propose(_req(), snap2)
        assert isinstance(r, RouterFailure)

    def test_latency_routing_and_escalation(self) -> None:
        d = CapabilityRouter(_cards()).propose(
            _req(latency_budget_ms=500), _snap()
        )
        assert isinstance(d, RouteDecision)
        assert d.engine == "ollama"
        d2 = CapabilityRouter(_cards()).propose(_req(difficulty="critical"), _snap())
        assert isinstance(d2, RouteDecision)
        assert isinstance(d2.escalated, bool)

    def test_router_has_no_dispatch_power(self) -> None:
        router = CapabilityRouter(_cards())
        assert not hasattr(router, "generate")
        assert not hasattr(router, "dispatch")
        assert not hasattr(router, "send")
