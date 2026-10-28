"""Network-denial proof: enforced paths complete with sockets blocked."""

from __future__ import annotations

import asyncio
import time

import httpx
import pytest

from openjarvis.core.types import Message, Role
from openjarvis.security.cloud_dispatch import (
    BudgetReservation,
    CloudDispatchAuthorizer,
    CloudDispatchRequest,
    ExplicitGrant,
    PrivacyClassification,
    ProviderIdentity,
)
from openjarvis.security.dispatch_ledger import CloudDispatchLedger
from tests.security._network_deny import deny_network


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


def _authz(allowlist, endpoints):
    return CloudDispatchAuthorizer(
        allowlist=allowlist,
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"host": ["llm:cloud"]}),
        allowed_endpoints=frozenset(endpoints),
    )


def _sealed(authz, engine, provider, model, endpoint):
    import uuid

    return authz.authorize(
        CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(
                engine=engine, provider=provider, model=model,
                endpoint=endpoint,
            ),
            messages=({"role": "user", "content": "hello"},),
            grant=ExplicitGrant(
                agent_id="host", capability="llm:cloud",
                expires_at=time.time() + 600,
            ),
            budget=BudgetReservation(
                est_prompt_tokens=2, max_tokens=8, ctx_limit=64
            ),
            session_id="sess-1",
            nonce=f"n-{uuid.uuid4().hex}",
        )
    )


def _msgs():
    return [Message(role=Role.USER, content="hello")]


def _ok_chat(model):
    return {
        "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        "model": model,
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }


class TestNoRealNetwork:
    def test_nim_offline(self, monkeypatch) -> None:
        deny_network(monkeypatch)
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        from openjarvis.engine.nim import NIMEngine

        host = "https://nim.test"
        authz = _authz({("nim", "nim", "m")}, {host})
        eng = NIMEngine(
            host=host, authorizer=authz,
            dispatch_ledger=CloudDispatchLedger(), session_id="sess-1",
        )
        eng._client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(200, json=_ok_chat("m"))
            ),
            base_url=host,
        )
        out = eng.generate(
            _msgs(), model="m", cloud_dispatch=_sealed(authz, "nim", "nim", "m", host)
        )
        assert out["content"] == "ok"

    def test_compat_offline(self, monkeypatch) -> None:
        deny_network(monkeypatch)
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
        from openjarvis.engine.openai_compat_engines import LlamaCppEngine

        host = "http://testhost:8080"
        authz = _authz({("llamacpp", "llamacpp", "m")}, {host})
        eng = LlamaCppEngine(
            host=host, authorizer=authz,
            dispatch_ledger=CloudDispatchLedger(), session_id="sess-1",
        )
        eng._client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(200, json=_ok_chat("m"))
            ),
            base_url=host,
        )
        out = eng.generate(
            _msgs(), model="m", cloud_dispatch=_sealed(
                authz, "llamacpp", "llamacpp", "m", host
            )
        )
        assert out["content"] == "ok"

    def test_router_offline(self, monkeypatch) -> None:
        deny_network(monkeypatch)
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        import openjarvis.server.cloud_router as router

        sse = (
            'data: {"choices": [{"delta": {"content": "hi"}}]}\n\n'
            "data: [DONE]\n\n"
        ).encode()
        real_async = httpx.AsyncClient
        monkeypatch.setattr(
            router.httpx, "AsyncClient",
            lambda **kw: real_async(
                transport=httpx.MockTransport(
                    lambda req: httpx.Response(200, content=sse)
                )
            ),
        )
        authz = _authz(
            {("cloud-router", "openai", "gpt-4o")},
            {"https://api.openai.com/v1"},
        )

        async def go():
            return [
                t
                async for t in router.stream_cloud(
                    "gpt-4o", _msgs(),
                    cloud_dispatch=_sealed(
                        authz, "cloud-router", "openai", "gpt-4o",
                        "https://api.openai.com/v1",
                    ),
                    authorizer=authz, dispatch_ledger=CloudDispatchLedger(),
                    session_id="sess-1",
                )
            ]

        assert asyncio.run(go()) == ["hi"]

    def test_denial_fires_on_real_attempt(self, monkeypatch) -> None:
        deny_network(monkeypatch)
        import socket

        with pytest.raises(AssertionError, match="network-denial harness"):
            socket.create_connection(("example.com", 443), timeout=1)
        with pytest.raises(AssertionError, match="network-denial harness"):
            socket.socket().connect(("93.184.216.34", 443))
        with pytest.raises(AssertionError, match="network-denial harness"):
            socket.getaddrinfo("example.com", 443)
        import urllib.request

        with pytest.raises(AssertionError, match="network-denial harness"):
            urllib.request.urlopen("http://example.com/")
