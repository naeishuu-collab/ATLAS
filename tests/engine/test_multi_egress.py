"""E7: MultiEngine routing gate — fake engines only, no network."""

from __future__ import annotations

import pytest

from openjarvis.core.types import Message, Role
from openjarvis.engine.multi import MultiEngine
from openjarvis.security.cloud_dispatch import (
    AuthorizedPayload,
    ExplicitGrant,
    PrivacyDenied,
    ProviderIdentity,
)


class _FakeInner:
    def __init__(self, tag: str, models: list) -> None:
        self.tag = tag
        self._models = models
        self.calls = 0

    def generate(self, messages, *, model: str, **kw):
        self.calls += 1
        assert "cloud_dispatch" in kw, "sealed auth must be forwarded"
        return {"content": f"{self.tag}:{model}"}

    def list_models(self):  # noqa: D102
        return list(self._models)


def _Sealed(engine: str, model: str) -> AuthorizedPayload:
    return AuthorizedPayload(
        dispatch_id=f"d-{engine}-{model}",
        provider=ProviderIdentity(engine=engine, provider=engine, model=model),
        redacted_messages=({"role": "user", "content": "hi"},),
        digest="digest",
        grant=ExplicitGrant(agent_id="a", capability="llm:cloud"),
        budget_id="b",
    )


def _multi():
    return MultiEngine(
        [("a", _FakeInner("A", ["m-a"])), ("b", _FakeInner("B", ["m-b"]))]
    )


def _msgs():
    return [Message(role=Role.USER, content="hi")]


class TestRoutingGate:
    def test_flag_off_deny(self, monkeypatch) -> None:
        monkeypatch.delenv("ASTRA_MULTI_EGRESS", raising=False)
        multi = _multi()
        with pytest.raises(PrivacyDenied):
            multi.generate(_msgs(), model="m-a", cloud_dispatch=_Sealed("a", "m-a"))

    def test_no_grant_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_MULTI_EGRESS", "on")
        multi = _multi()
        with pytest.raises(PrivacyDenied):
            multi.generate(_msgs(), model="m-a")

    def test_misroute_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_MULTI_EGRESS", "on")
        multi = _multi()
        # Sealed names engine "b" but model routes to "a".
        with pytest.raises(PrivacyDenied):
            multi.generate(_msgs(), model="m-a", cloud_dispatch=_Sealed("b", "m-a"))
        with pytest.raises(PrivacyDenied):
            multi.generate(_msgs(), model="m-a", cloud_dispatch=_Sealed("a", "m-b"))
        assert multi._engines[0][1].calls == 0
        assert multi._engines[1][1].calls == 0

    def test_correct_route_forwards_sealed(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_MULTI_EGRESS", "on")
        multi = _multi()
        out = multi.generate(_msgs(), model="m-b", cloud_dispatch=_Sealed("b", "m-b"))
        assert out["content"] == "B:m-b"
        assert multi._engines[1][1].calls == 1
        assert multi._engines[0][1].calls == 0

    def test_unknown_model_still_errors(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_MULTI_EGRESS", "on")
        multi = _multi()
        with pytest.raises((PrivacyDenied, ValueError)):
            multi.generate(_msgs(), model="nope", cloud_dispatch=_Sealed("a", "nope"))
