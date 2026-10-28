"""Multi-provider routing offline E2E.

Two layers, offline only:

* :class:`~openjarvis.engine.multi.MultiEngine` — model-name routing
  across engines with the E7 gate (``ASTRA_MULTI_EGRESS`` ON + a sealed
  host authorization required for EVERY routed call). Cloud routing is
  proven over ``httpx.MockTransport`` (no network); a local fake owns the
  local lane.
* :class:`~openjarvis.agents.capability_router.CapabilityRouter` —
  privacy/cost/quota-aware selection over capability-tier cards with
  safe defer (RouterFailure codes, no dispatch) when nothing fits.

The cloud engine is constructed EXACTLY as the serve lane wires
(factory bundle authority; see tests/engine/test_cloud_wiring_e2e.py).
No real credential, no socket, no OS mutation.
"""

from __future__ import annotations

import httpx
import pytest

import tests.engine.test_cloud_wiring_e2e as cw
from openjarvis.agents.capability_router import (
    ALL_PROVIDERS_UNAVAILABLE,
    BUDGET_EXCEEDED,
    MODEL_CAPABILITY_UNAVAILABLE,
    PRIVACY_ROUTE_UNAVAILABLE,
    QUOTA_EXHAUSTED,
    CapabilityRouter,
    ModelCapability,
    ModelCard,
    ProviderSnapshot,
    RouteRequest,
    RouterFailure,
    RouterGateError,
)
from openjarvis.core.types import Message, Role
from openjarvis.engine.multi import MultiEngine
from openjarvis.security.cloud_dispatch import PrivacyClassification, PrivacyDenied

MODEL = "gpt-4o"
EP = "https://api.openai.com/v1"
CHAT_JSON = {
    "id": "c-multi", "object": "chat.completion", "created": 1,
    "model": MODEL,
    "choices": [{"index": 0,
                 "message": {"role": "assistant", "content": "cloud reply"},
                 "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4},
}


class _LocalEngine:
    engine_id = "ollama"

    def __init__(self):
        self.calls = 0

    def list_models(self):
        return ["spark-4b"]

    def health(self):
        return True

    def generate(self, messages, *, model, **kw):
        self.calls += 1
        return {"content": "local reply", "model": model}


LOCAL_CARD = ModelCard(
    engine="ollama", provider="local", model="spark-4b",
    capabilities=frozenset({ModelCapability.TEXT}),
    ctx_limit=4096, cost_per_1k=0.0, latency_p50_ms=50.0,
    is_cloud=False, tier=0)
FAST_CLOUD_CARD = ModelCard(
    engine="cloud", provider="openai", model=MODEL,
    capabilities=frozenset({ModelCapability.TEXT}),
    ctx_limit=8192, cost_per_1k=0.0006, latency_p50_ms=900.0,
    is_cloud=True, tier=1)
LONG_CARD = ModelCard(
    engine="cloud", provider="gemini", model="synth-long",
    capabilities=frozenset({ModelCapability.TEXT,
                            ModelCapability.LONG_CONTEXT}),
    ctx_limit=65536, cost_per_1k=0.003, latency_p50_ms=1200.0,
    is_cloud=True, tier=2)
FRONTIER_CARD = ModelCard(
    engine="cloud", provider="openai", model="synth-frontier",
    capabilities=frozenset({ModelCapability.TEXT}),
    ctx_limit=16384, cost_per_1k=0.01, latency_p50_ms=1500.0,
    is_cloud=True, tier=4)


def _wired(monkeypatch):
    """(multi, local, cloud, captured, bundle) — serve-lane cloud authority."""
    openai = pytest.importorskip("openai")
    bundle = cw._bundle()
    monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
    captured: list = []
    from openjarvis.engine.cloud import CloudEngine

    cloud = CloudEngine(
        authorizer=bundle.cloud_authorizer,
        dispatch_ledger=bundle.dispatch_ledger,
        session_id=bundle.session_id,
    )
    cloud._openai_client = openai.OpenAI(
        api_key="sk-multi-e2e-fake",
        http_client=httpx.Client(transport=httpx.MockTransport(
            lambda req: captured.append(req)
            or httpx.Response(200, json=CHAT_JSON))),
        max_retries=0,
    )
    local = _LocalEngine()
    multi = MultiEngine([("ollama", local), ("cloud", cloud)])
    return multi, local, cloud, captured, bundle


def _ledger_states(engine):
    return [e.state for e in engine._dispatch_ledger._entries.values()]


# ---------------------------------------------------------------------------
# MultiEngine routing (E7 gate, MockTransport cloud)
# ---------------------------------------------------------------------------


class TestMultiEngineRouting:
    def test_multi_flag_off_blocks_every_routed_call(self, monkeypatch):
        multi, local, cloud, captured, _ = _wired(monkeypatch)
        monkeypatch.delenv("ASTRA_MULTI_EGRESS", raising=False)
        with pytest.raises(PrivacyDenied) as excinfo:
            multi.generate(_msgs(), model="spark-4b")
        assert excinfo.value.code == "FLAG_OFF"
        assert local.calls == 0 and captured == []

    def test_unsealed_route_is_denied_local_lane_untouched(self, monkeypatch):
        multi, local, cloud, captured, _ = _wired(monkeypatch)
        monkeypatch.setenv("ASTRA_MULTI_EGRESS", "on")
        with pytest.raises(PrivacyDenied) as excinfo:
            multi.generate(_msgs(), model="spark-4b")
        assert excinfo.value.code == "NO_GRANT"
        assert local.calls == 0 and captured == []

    def test_cloud_route_with_seal_sends_exactly_once(self, monkeypatch):
        multi, local, cloud, captured, bundle = _wired(monkeypatch)
        monkeypatch.setenv("ASTRA_MULTI_EGRESS", "on")
        out = multi.generate(_msgs(), model=MODEL,
                             cloud_dispatch=cw._seal(bundle))
        assert out["content"] == "cloud reply"
        assert local.calls == 0
        assert len(captured) == 1 and str(captured[0].url).startswith(EP)
        assert _ledger_states(cloud) == ["EXECUTED"]

    def test_cloud_route_denied_when_cloud_flag_off(self, monkeypatch):
        # Multi armed but the cloud egress choke default-denies: the
        # two gates are independent layers of the same host boundary.
        multi, local, cloud, captured, bundle = _wired(monkeypatch)
        monkeypatch.setenv("ASTRA_MULTI_EGRESS", "on")
        monkeypatch.delenv("ASTRA_CLOUD_EGRESS", raising=False)
        with pytest.raises(PrivacyDenied) as excinfo:
            multi.generate(_msgs(), model=MODEL,
                           cloud_dispatch=cw._seal(bundle))
        assert excinfo.value.code == "FLAG_OFF"
        assert captured == []

    def test_unauthorized_fallback_reuse_is_denied(self, monkeypatch):
        # A cloud seal used on the LOCAL model (or vice versa) mismatches
        # the resolved engine: authority cannot be reused across routes.
        multi, local, cloud, captured, bundle = _wired(monkeypatch)
        monkeypatch.setenv("ASTRA_MULTI_EGRESS", "on")
        with pytest.raises(PrivacyDenied) as excinfo:
            multi.generate(_msgs(), model="spark-4b",
                           cloud_dispatch=cw._seal(bundle))
        assert excinfo.value.code == "CLOUD_PROVIDER_NOT_ALLOWED"
        assert local.calls == 0 and captured == []


def _msgs(content="hello"):
    return [Message(role=Role.USER, content=content)]


# ---------------------------------------------------------------------------
# CapabilityRouter: privacy/cost/quota-aware selection + safe defer
# ---------------------------------------------------------------------------


def _req(**over) -> RouteRequest:
    base = dict(
        difficulty="standard",
        need=frozenset({ModelCapability.TEXT}),
        privacy=PrivacyClassification.INTERNAL,
        est_prompt_tokens=512,
        max_tokens=256,
    )
    base.update(over)
    return RouteRequest(**base)


def _snap(**over) -> ProviderSnapshot:
    available = {FRONTIER_CARD.key(): False}
    for c in (LOCAL_CARD, FAST_CLOUD_CARD, LONG_CARD):
        available[c.key()] = True
    base = dict(available=available)
    base.update(over)
    return ProviderSnapshot(**base)


class TestCapabilityRouter:
    def test_internal_prefers_local_by_cost_with_fallback(self):
        decision = CapabilityRouter(
            [LOCAL_CARD, FAST_CLOUD_CARD, LONG_CARD]).propose(_req(), _snap())
        assert not isinstance(decision, RouterFailure)
        assert (decision.engine, decision.model) == ("ollama", "spark-4b")
        assert decision.fallback                      # chain exists

    def test_private_is_local_only(self):
        decision = CapabilityRouter(
            [LOCAL_CARD, FAST_CLOUD_CARD]).propose(
            _req(privacy=PrivacyClassification.PRIVATE), _snap())
        assert decision.model == "spark-4b"
        # No local model available -> safe defer, never a cloud route.
        failure = CapabilityRouter([FAST_CLOUD_CARD]).propose(
            _req(privacy=PrivacyClassification.PRIVATE), _snap())
        assert isinstance(failure, RouterFailure)
        assert failure.code == PRIVACY_ROUTE_UNAVAILABLE

    def test_capability_shortfall_never_downgrades(self):
        req = _req(need=frozenset({ModelCapability.NATIVE_TOOLS}))
        failure = CapabilityRouter(
            [LOCAL_CARD, FAST_CLOUD_CARD]).propose(req, _snap())
        assert isinstance(failure, RouterFailure)
        assert failure.code == MODEL_CAPABILITY_UNAVAILABLE

    def test_all_providers_unavailable_safe_defer(self):
        snap = _snap(available={k: False for k in _snap().available})
        failure = CapabilityRouter(
            [LOCAL_CARD, FAST_CLOUD_CARD, LONG_CARD]).propose(
            _req(privacy=PrivacyClassification.PUBLIC), snap)
        assert isinstance(failure, RouterFailure)
        assert failure.code == ALL_PROVIDERS_UNAVAILABLE

    def test_quota_exhausted_defers(self):
        # Both cloud-capable providers report zero quota; local has no such
        # capability (text only, fine) — so drop local from this pool.
        snap = _snap(quota_left={"openai": 0.0, "gemini": 0.0})
        failure = CapabilityRouter(
            [FAST_CLOUD_CARD, LONG_CARD]).propose(
            _req(privacy=PrivacyClassification.PUBLIC), snap)
        assert isinstance(failure, RouterFailure)
        assert failure.code == QUOTA_EXHAUSTED

    def test_budget_exhausted_defers(self):
        failure = CapabilityRouter(
            [FAST_CLOUD_CARD, LONG_CARD]).propose(
            _req(cost_budget_usd=0.00001,
                 privacy=PrivacyClassification.PUBLIC), _snap())
        assert isinstance(failure, RouterFailure)
        assert failure.code == BUDGET_EXCEEDED

    def test_frontier_tier_gated_without_optin(self):
        decision = CapabilityRouter(
            [FAST_CLOUD_CARD, FRONTIER_CARD]).propose(
            _req(privacy=PrivacyClassification.PUBLIC), _snap())
        assert decision.model == MODEL                # frontier never selected

    def test_planning_gate_raises_before_any_contact(self):
        router = CapabilityRouter([FAST_CLOUD_CARD])
        gate = router.gate(
            _req(privacy=PrivacyClassification.PRIVATE),
            _snap(available={FAST_CLOUD_CARD.key(): False}))
        with pytest.raises(RouterGateError):
            gate()
        ok = router.gate(_req(privacy=PrivacyClassification.PUBLIC),
                         _snap(available={FAST_CLOUD_CARD.key(): True}))
        assert ok() is None                           # open gate is a no-op

    def test_hard_difficulty_escalates_to_higher_tier(self):
        decision = CapabilityRouter(
            [LOCAL_CARD, FAST_CLOUD_CARD, LONG_CARD]).propose(
            _req(difficulty="hard"), _snap())
        assert not isinstance(decision, RouterFailure)
        assert decision.escalated is True
        assert decision.model == "synth-long"
