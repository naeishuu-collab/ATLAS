"""PoC: authorized chain authorizer -> ledger -> guard -> fake transport.

Proves only sealed payloads reach the (fake) transport, and that raw
engines without the guard send freely — i.e. the guard IS the boundary,
and unwired production paths remain unprotected by construction.
Fake transport only. No network, no keys.
"""

from __future__ import annotations

import time
from collections.abc import Sequence

import pytest

from openjarvis.core.types import Message, Role
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
    STATE_EXECUTED,
    CloudDispatchLedger,
)
from openjarvis.security.egress_guard import guard_engine


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


class FakeTransportEngine:
    """Stands in for any cloud engine's socket/SDK send point."""

    engine_id = "fake-cloud"
    is_cloud = True

    def __init__(self) -> None:
        self.sent: list = []

    def generate(self, messages: Sequence[Message], *, model: str, **kw):
        self.sent.append(
            {
                "model": model,
                "content": [m.content for m in messages],
            }
        )
        return {
            "content": "fake reply",
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            "model": model,
        }

    def list_models(self):  # noqa: D102
        return ["m1"]


def _stack():
    authz = CloudDispatchAuthorizer(
        allowlist={("fake-cloud", "groq", "m1")},
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"a": ["llm:cloud"]}),
    )
    transport = FakeTransportEngine()
    guarded = guard_engine(transport, authz)
    ledger = CloudDispatchLedger()
    return authz, guarded, ledger, transport


def _sealed(authz, **kw):
    base = {
        "classification": PrivacyClassification.INTERNAL,
        "provider": ProviderIdentity(engine="fake-cloud", provider="groq", model="m1"),
        "messages": ({"role": "user", "content": "poc hello"},),
        "grant": ExplicitGrant(
            agent_id="a", capability="llm:cloud", expires_at=time.time() + 600
        ),
        "budget": BudgetReservation(est_prompt_tokens=2, max_tokens=8, ctx_limit=64),
    }
    base.update(kw)
    return authz.authorize(CloudDispatchRequest(**base))


def _msgs():
    return [Message(role=Role.USER, content="poc hello")]


class TestAuthorizedChain:
    def test_only_sealed_payload_reaches_transport(self) -> None:
        authz, guarded, ledger, transport = _stack()
        sealed = _sealed(authz)
        entry = ledger.begin(sealed)
        ledger.mark_dispatched(entry)
        out = guarded.generate(_msgs(), model="m1", cloud_dispatch=sealed)
        ledger.check_send(entry, sealed)
        ledger.finish(entry, STATE_EXECUTED)
        assert out["content"] == "fake reply"
        assert len(transport.sent) == 1
        assert transport.sent[0]["content"] == ["poc hello"]
        assert entry.state == STATE_EXECUTED

    def test_unsealed_call_never_touches_transport(self) -> None:
        _, guarded, _, transport = _stack()
        with pytest.raises(PrivacyDenied):
            guarded.generate(_msgs(), model="m1")
        assert transport.sent == []

    def test_mutated_call_never_touches_transport(self) -> None:
        authz, guarded, _, transport = _stack()
        sealed = _sealed(authz)
        bad = [Message(role=Role.USER, content="poc hello + injected")]
        with pytest.raises(PrivacyDenied):
            guarded.generate(bad, model="m1", cloud_dispatch=sealed)
        assert transport.sent == []

    def test_raw_engine_without_guard_sends_freely(self) -> None:
        """Demonstrates the boundary location: no guard => no protection.

        This is the current state of all 13 production paths.
        """
        transport = FakeTransportEngine()
        out = transport.generate(_msgs(), model="m1")
        assert out["content"] == "fake reply"
        assert len(transport.sent) == 1

    def test_private_never_reaches_transport(self) -> None:
        authz, guarded, _, transport = _stack()
        with pytest.raises(PrivacyDenied):
            _sealed(authz, classification=PrivacyClassification.PRIVATE)
        assert transport.sent == []

    def test_unknown_never_reaches_transport(self) -> None:
        authz, _, _, transport = _stack()
        with pytest.raises(PrivacyDenied):
            _sealed(authz, classification=None)
        assert transport.sent == []
