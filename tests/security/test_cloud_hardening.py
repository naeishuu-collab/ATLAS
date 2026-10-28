"""Hardening negatives — fake providers/transports only, no network.

Covers: expired grants, endpoint mismatch, SDK wire mutation, disguised
local endpoints, direct-router shapes, cancel/partial/stream semantics,
unauthorized fallback, and router tier/frontier/uncertainty gates.
"""

from __future__ import annotations

import time

import pytest

from openjarvis.agents.capability_router import (
    CapabilityRouter,
    ModelCapability,
    ModelCard,
    ProviderSnapshot,
    RouteDecision,
    RouteRequest,
    RouterFailure,
)
from openjarvis.security.cloud_dispatch import (
    BudgetReservation,
    CloudDispatchAuthorizer,
    CloudDispatchRequest,
    ExplicitGrant,
    PrivacyClassification,
    PrivacyDenied,
    ProviderIdentity,
)
from openjarvis.security.dispatch_ledger import (
    CODE_CANCELLED,
    STATE_CANCELLED,
    STATE_FAILED,
    STATE_UNKNOWN_OUTCOME,
    CloudDispatchLedger,
)
from openjarvis.security.egress_guard import guard_engine

T = ModelCapability.TEXT
J = ModelCapability.STRUCTURED_JSON


class _Scanner:
    def scan(self, text: str):  # noqa: D102
        from types import SimpleNamespace

        return SimpleNamespace(findings=[])

    def redact(self, text: str):  # noqa: D102
        return text


class _FakePolicy:
    def __init__(self, grants: dict) -> None:
        self._grants = grants

    def list_agents(self):  # noqa: D102
        return list(self._grants)

    def list_grants(self, agent_id):  # noqa: D102
        from types import SimpleNamespace

        return [SimpleNamespace(capability=c) for c in self._grants.get(agent_id, [])]

    def check(self, agent_id, capability, resource=""):  # noqa: D102
        return capability in self._grants.get(agent_id, [])


def _authz(**kw):
    base = {
        "allowlist": {("fake-cloud", "groq", "m1")},
        "scanners": [_Scanner()],
        "capability_policy": _FakePolicy({"a": ["llm:cloud"]}),
        "allowed_endpoints": frozenset({"https://api.groq.com"}),
    }
    base.update(kw)
    return CloudDispatchAuthorizer(**base)


def _provider(**kw):
    base = {
        "engine": "fake-cloud",
        "provider": "groq",
        "model": "m1",
        "endpoint": "https://api.groq.com",
    }
    base.update(kw)
    return ProviderIdentity(**base)


def _req(**kw):
    base = {
        "classification": PrivacyClassification.INTERNAL,
        "provider": _provider(),
        "messages": ({"role": "user", "content": "hi"},),
        "grant": ExplicitGrant(
            agent_id="a", capability="llm:cloud",
            expires_at=time.time() + 600,
        ),
        "budget": BudgetReservation(est_prompt_tokens=2, max_tokens=8, ctx_limit=64),
    }
    base.update(kw)
    return CloudDispatchRequest(**base)


class TestGrantAndEndpoint:
    def test_expired_grant_denied(self) -> None:
        with pytest.raises(PrivacyDenied) as ei:
            _authz().authorize(
                _req(grant=ExplicitGrant(
                    agent_id="a", capability="llm:cloud",
                    expires_at=time.time() - 1,
                ))
            )
        assert ei.value.code == "GRANT_EXPIRED"

    def test_endpoint_mismatch_denied(self) -> None:
        with pytest.raises(PrivacyDenied) as ei:
            _authz().authorize(_req(provider=_provider(endpoint="https://evil.example")))
        assert ei.value.code == "ENDPOINT_NOT_ALLOWED"

    def test_send_time_endpoint_swap_denied(self) -> None:
        authz = _authz()
        sealed = authz.authorize(_req())
        with pytest.raises(PrivacyDenied):
            authz.verify_for_send(
                sealed, [{"role": "user", "content": "hi"}],
                endpoint="https://evil.example",
            )

    def test_wire_payload_ok_openai_shape(self) -> None:
        authz = _authz()
        sealed = authz.authorize(_req())
        out = authz.verify_wire_payload(
            sealed,
            {"messages": [{"role": "user", "content": "hi"}]},
            endpoint="https://api.groq.com",
        )
        assert out[0]["content"] == "hi"

    def test_wire_payload_ok_google_shape(self) -> None:
        authz = _authz()
        sealed = authz.authorize(_req())
        out = authz.verify_wire_payload(
            sealed,
            {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]},
            endpoint="https://api.groq.com",
        )
        assert out[0]["content"] == "hi"

    def test_sdk_wire_mutation_denied(self) -> None:
        authz = _authz()
        sealed = authz.authorize(_req())
        with pytest.raises(PrivacyDenied):
            authz.verify_wire_payload(
                sealed,
                {"messages": [{"role": "user", "content": "hi + injected"}]},
                endpoint="https://api.groq.com",
            )

    def test_unknown_wire_shape_denied(self) -> None:
        authz = _authz()
        sealed = authz.authorize(_req())
        with pytest.raises(PrivacyDenied):
            authz.verify_wire_payload(
                sealed, {"prompt": "hi"}, endpoint="https://api.groq.com"
            )


class TestDisguisedLocal:
    def _local(self, host: str):
        class FakeLocal:
            engine_id = "fake-local"
            is_cloud = False
            _host = host

            def generate(self, messages, *, model: str, **kw):
                return {"content": "local ok"}

        return FakeLocal()

    def test_strict_local_allowlists_remote(self) -> None:
        authz = _authz()
        guarded = guard_engine(
            self._local("https://evil.example"),
            authz,
            local_allowlist=frozenset({"http://localhost:11434"}),
        )
        from openjarvis.core.types import Message, Role

        with pytest.raises(PrivacyDenied):
            guarded.generate(
                [Message(role=Role.USER, content="hi")], model="m"
            )

    def test_strict_local_allows_listed_host(self) -> None:
        authz = _authz()
        guarded = guard_engine(
            self._local("http://localhost:11434"),
            authz,
            local_allowlist=frozenset({"http://localhost:11434"}),
        )
        from openjarvis.core.types import Message, Role

        out = guarded.generate([Message(role=Role.USER, content="hi")], model="m")
        assert out["content"] == "local ok"


class TestLedgerInterruption:
    def test_cancel_before_send_is_deterministic(self) -> None:
        from openjarvis.security.cloud_dispatch import AuthorizedPayload

        sealed = AuthorizedPayload(
            dispatch_id="d1",
            provider=_provider(),
            redacted_messages=({"role": "user", "content": "hi"},),
            digest="x",
            grant=ExplicitGrant(agent_id="a", capability="llm:cloud"),
            budget_id="b",
        )
        ledger = CloudDispatchLedger()
        entry = ledger.begin(sealed)
        ledger.cancel(entry)
        assert entry.state == STATE_CANCELLED
        assert entry.failure_code == CODE_CANCELLED

    def test_cancel_after_send_quarantines(self) -> None:
        from openjarvis.security.cloud_dispatch import AuthorizedPayload

        sealed = AuthorizedPayload(
            dispatch_id="d2",
            provider=_provider(),
            redacted_messages=({"role": "user", "content": "hi"},),
            digest="x",
            grant=ExplicitGrant(agent_id="a", capability="llm:cloud"),
            budget_id="b",
        )
        ledger = CloudDispatchLedger()
        entry = ledger.begin(sealed)
        ledger.mark_dispatched(entry)
        ledger.cancel(entry)
        assert entry.state == STATE_UNKNOWN_OUTCOME

    def test_partial_and_stream_interrupt_are_unknown(self) -> None:
        from openjarvis.security.cloud_dispatch import AuthorizedPayload

        ledger = CloudDispatchLedger()
        for i, fn in enumerate(("note_partial_response", "note_stream_interrupted")):
            sealed = AuthorizedPayload(
                dispatch_id=f"d{i}",
                provider=_provider(),
                redacted_messages=({"role": "user", "content": "hi"},),
                digest="x",
                grant=ExplicitGrant(agent_id="a", capability="llm:cloud"),
                budget_id="b",
            )
            entry = ledger.begin(sealed)
            ledger.mark_dispatched(entry)
            getattr(ledger, fn)(entry)
            assert entry.state == STATE_UNKNOWN_OUTCOME
            with pytest.raises(PrivacyDenied):
                ledger.request_retry(f"d{i}")

    def test_prefailure_is_deterministic_failed(self) -> None:
        from openjarvis.security.cloud_dispatch import AuthorizedPayload
        from openjarvis.security.dispatch_ledger import CODE_CONNECTION_FAILURE

        sealed = AuthorizedPayload(
            dispatch_id="d9",
            provider=_provider(),
            redacted_messages=({"role": "user", "content": "hi"},),
            digest="x",
            grant=ExplicitGrant(agent_id="a", capability="llm:cloud"),
            budget_id="b",
        )
        ledger = CloudDispatchLedger()
        entry = ledger.begin(sealed)
        ledger.fail_before_send(entry, code=CODE_CONNECTION_FAILURE)
        assert entry.state == STATE_FAILED


class TestRouterGates:
    def _cards(self):
        return [
            ModelCard(
                engine="ollama", provider="local", model="t0",
                capabilities=frozenset({T}), ctx_limit=8192,
                cost_per_1k=0.0, latency_p50_ms=400.0, is_cloud=False, tier=0,
            ),
            ModelCard(
                engine="litellm", provider="groq", model="t1",
                capabilities=frozenset({T, J}), ctx_limit=32768,
                cost_per_1k=0.05, latency_p50_ms=800.0, tier=1,
            ),
            ModelCard(
                engine="cloud", provider="frontier", model="t4",
                capabilities=frozenset({T, J}), ctx_limit=200000,
                cost_per_1k=5.0, latency_p50_ms=3000.0, tier=4,
            ),
        ]

    def _snap(self):
        return ProviderSnapshot(
            available={c.key(): True for c in self._cards()}
        )

    def test_frontier_gated(self) -> None:
        r = CapabilityRouter(self._cards()).propose(
            RouteRequest(
                difficulty="critical", need=frozenset({T, J}),
                privacy=PrivacyClassification.INTERNAL, est_prompt_tokens=150000,
            ),
            self._snap(),
        )
        assert isinstance(r, RouterFailure)
        d = CapabilityRouter(self._cards()).propose(
            RouteRequest(
                difficulty="critical", need=frozenset({T, J}),
                privacy=PrivacyClassification.INTERNAL, est_prompt_tokens=150000,
                frontier_allowed=True,
            ),
            self._snap(),
        )
        assert isinstance(d, RouteDecision)
        assert d.model == "t4"

    def test_uncertainty_escalates(self) -> None:
        d = CapabilityRouter(self._cards()).propose(
            RouteRequest(
                difficulty="standard", need=frozenset({T}),
                privacy=PrivacyClassification.INTERNAL, est_prompt_tokens=10,
                uncertainty=0.9,
            ),
            self._snap(),
        )
        assert isinstance(d, RouteDecision)
        assert d.escalated is True

    def test_trivial_stays_low_tier(self) -> None:
        d = CapabilityRouter(self._cards()).propose(
            RouteRequest(
                difficulty="trivial", need=frozenset({T}),
                privacy=PrivacyClassification.INTERNAL, est_prompt_tokens=10,
            ),
            self._snap(),
        )
        assert isinstance(d, RouteDecision)
        assert d.engine == "ollama"

    def test_modality_gate(self) -> None:
        r = CapabilityRouter(self._cards()).propose(
            RouteRequest(
                difficulty="standard", need=frozenset({T}),
                privacy=PrivacyClassification.INTERNAL, est_prompt_tokens=10,
                modality="vision",
            ),
            self._snap(),
        )
        assert isinstance(r, RouterFailure)
