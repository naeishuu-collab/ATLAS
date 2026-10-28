"""Mock-network boundary PoC — httpx interception, zero real network.

An ``HttpxTransportEngine`` PoC posts OpenAI-shaped wire payloads through
an INJECTED httpx transport only (no default client exists). Tests assert
on captured wire bytes: exact endpoint, redacted body, per-provider keys,
redirect refusal, and zero requests on any denial.
"""

from __future__ import annotations

import json
import time
from collections.abc import Sequence
from typing import Any

import httpx
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
    STATE_UNKNOWN_OUTCOME,
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


class HttpxTransportEngine:
    """PoC cloud engine: wire bytes leave ONLY via injected transport."""

    engine_id = "poc-httpx-cloud"
    is_cloud = True

    def __init__(
        self, *, transport: httpx.BaseTransport, endpoint: str, api_key: str
    ) -> None:
        self._client = httpx.Client(
            transport=transport, follow_redirects=False, trust_env=False,
            timeout=10.0,
        )
        self._endpoint = endpoint
        self._api_key = api_key

    def generate(self, messages: Sequence[Message], *, model: str, **kw: Any):
        from openjarvis.security.cloud_dispatch import PrivacyDenied as _Denied

        presented = kw.pop("dispatch_endpoint", None)
        if presented != self._endpoint:
            raise _Denied(
                "CLOUD_PAYLOAD_CHANGED",
                "send-site endpoint differs from the presented destination",
            )
        # Provider-SDK-shaped wire payload (OpenAI chat completions).
        wire = {
            "model": model,
            "messages": [
                {
                    "role": m.role.value if hasattr(m.role, "value") else str(m.role),
                    "content": m.content,
                }
                for m in messages
            ],
        }
        resp = self._client.post(
            f"{self._endpoint}/chat/completions",
            json=wire,
            headers={"Authorization": f"Bearer {self._api_key}"},
        )
        if resp.status_code in (307, 308, 301, 302):
            raise _Redirected(resp.headers.get("location", ""))
        resp.raise_for_status()
        data = resp.json()
        return {"content": data["choices"][0]["message"]["content"], "model": model}

    def list_models(self):  # noqa: D102
        return ["m1"]


class _Redirected(RuntimeError):
    pass


def _stack(requests: list, handler, *, endpoint="https://api.poc.test"):
    authz = CloudDispatchAuthorizer(
        allowlist={("poc-httpx-cloud", "poc", "m1")},
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"a": ["llm:cloud"]}),
        allowed_endpoints=frozenset({endpoint}),
    )
    engine = HttpxTransportEngine(
        transport=httpx.MockTransport(handler),
        endpoint=endpoint,
        api_key="FAKE-KEY-poc",
    )
    return authz, guard_engine(engine, authz), CloudDispatchLedger()


def _sealed(authz, endpoint="https://api.poc.test", **kw):
    base = {
        "classification": PrivacyClassification.INTERNAL,
        "provider": ProviderIdentity(
            engine="poc-httpx-cloud", provider="poc", model="m1",
            endpoint=endpoint,
        ),
        "messages": ({"role": "user", "content": "hello poc"},),
        "grant": ExplicitGrant(
            agent_id="a", capability="llm:cloud", expires_at=time.time() + 600
        ),
        "budget": BudgetReservation(est_prompt_tokens=2, max_tokens=8, ctx_limit=64),
    }
    base.update(kw)
    return authz.authorize(CloudDispatchRequest(**base))


def _msgs():
    return [Message(role=Role.USER, content="hello poc")]


def _ok_handler(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content.decode())
    assert body["messages"] == [{"role": "user", "content": "hello poc"}]
    assert request.headers["Authorization"] == "Bearer FAKE-KEY-poc"
    return httpx.Response(
        200,
        json={"choices": [{"message": {"content": "poc reply"}}]},
    )


class TestMockNetworkBoundary:
    def test_exact_wire_bytes(self) -> None:
        seen: list = []
        authz, guarded, ledger = _stack(
            seen,
            lambda req: (seen.append(req), _ok_handler(req))[1],
        )
        sealed = _sealed(authz)
        entry = ledger.begin(sealed)
        ledger.mark_dispatched(entry)
        out = guarded.generate(
            _msgs(), model="m1", cloud_dispatch=sealed,
            endpoint="https://api.poc.test",
        )
        ledger.check_send(entry, sealed)
        ledger.finish(entry, STATE_EXECUTED)
        assert out["content"] == "poc reply"
        assert len(seen) == 1
        assert str(seen[0].url) == "https://api.poc.test/chat/completions"
        assert entry.state == STATE_EXECUTED

    def test_denied_means_zero_requests(self) -> None:
        seen: list = []
        authz, guarded, _ = _stack(seen, lambda req: _ok_handler(req))
        with pytest.raises(PrivacyDenied):
            guarded.generate(_msgs(), model="m1")
        assert seen == []

    def test_redirect_never_followed(self) -> None:
        seen: list = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return httpx.Response(307, headers={"location": "https://evil.test/x"})

        authz, guarded, ledger = _stack(seen, handler)
        sealed = _sealed(authz)
        entry = ledger.begin(sealed)
        ledger.mark_dispatched(entry)
        with pytest.raises(_Redirected):
            guarded.generate(
                _msgs(), model="m1", cloud_dispatch=sealed,
                endpoint="https://api.poc.test",
            )
        # Evil host untouched; ambiguity quarantines (bytes left boundary).
        assert [str(r.url) for r in seen] == [
            "https://api.poc.test/chat/completions"
        ]
        ledger.mark_unknown(entry)
        assert entry.state == STATE_UNKNOWN_OUTCOME

    def test_no_implicit_real_transport(self) -> None:
        with pytest.raises(TypeError):
            HttpxTransportEngine(endpoint="https://x.test", api_key="k")  # type: ignore[call-arg]

    def test_no_bypass_switch_on_guard(self) -> None:
        import inspect

        params = inspect.signature(guard_engine).parameters
        assert "enabled" not in params
        assert "disabled" not in params
        assert "enforce" not in params

    def test_key_isolation_across_providers(self) -> None:
        seen: list = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return httpx.Response(
                200, json={"choices": [{"message": {"content": "ok"}}]}
            )

        authz = CloudDispatchAuthorizer(
            allowlist={
                ("poc-httpx-cloud", "pocA", "m1"),
                ("poc-httpx-cloud", "pocB", "m1"),
            },
            scanners=[_Scanner()],
            capability_policy=_FakePolicy({"a": ["llm:cloud"]}),
        )
        eng_a = HttpxTransportEngine(
            transport=httpx.MockTransport(handler),
            endpoint="https://a.test",
            api_key="FAKE-KEY-A",
        )
        eng_b = HttpxTransportEngine(
            transport=httpx.MockTransport(handler),
            endpoint="https://b.test",
            api_key="FAKE-KEY-B",
        )
        g_a, g_b = guard_engine(eng_a, authz), guard_engine(eng_b, authz)

        def seal(provider: str, endpoint: str):
            return authz.authorize(
                CloudDispatchRequest(
                    classification=PrivacyClassification.INTERNAL,
                    provider=ProviderIdentity(
                        engine="poc-httpx-cloud", provider=provider, model="m1",
                        endpoint=endpoint,
                    ),
                    messages=({"role": "user", "content": "hi"},),
                    grant=ExplicitGrant(agent_id="a", capability="llm:cloud"),
                    budget=BudgetReservation(
                        est_prompt_tokens=1, max_tokens=4, ctx_limit=64
                    ),
                )
            )

        g_a.generate(
            [Message(role=Role.USER, content="hi")], model="m1",
            cloud_dispatch=seal("pocA", "https://a.test"),
            endpoint="https://a.test",
        )
        g_b.generate(
            [Message(role=Role.USER, content="hi")], model="m1",
            cloud_dispatch=seal("pocB", "https://b.test"),
            endpoint="https://b.test",
        )
        by_host = {str(r.url.host): r.headers["Authorization"] for r in seen}
        assert by_host == {"a.test": "Bearer FAKE-KEY-A", "b.test": "Bearer FAKE-KEY-B"}
