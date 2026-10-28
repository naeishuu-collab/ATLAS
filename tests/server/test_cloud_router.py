"""Regression tests for OpenRouter model ID normalization."""

from __future__ import annotations

import time
import uuid

import pytest

from openjarvis.core.types import Message
from openjarvis.security.cloud_dispatch import (
    BudgetReservation,
    CloudDispatchAuthorizer,
    CloudDispatchRequest,
    ExplicitGrant,
    PrivacyClassification,
    PrivacyDenied,
    ProviderIdentity,
)
from openjarvis.security.dispatch_ledger import CloudDispatchLedger
from openjarvis.server import cloud_router


class _Scanner:
    def scan(self, text: str):
        from types import SimpleNamespace

        return SimpleNamespace(findings=[])

    def redact(self, text: str):
        return text


class _Policy:
    def list_agents(self):
        return ["host"]

    def list_grants(self, agent_id):
        from types import SimpleNamespace

        return [SimpleNamespace(capability="llm:cloud")] if agent_id == "host" else []

    def check(self, agent_id, capability, resource=""):
        return agent_id == "host" and capability == "llm:cloud"


def _sealed_router_dispatch(model: str, messages: list[Message]):
    endpoint = "https://openrouter.ai/api/v1"
    authz = CloudDispatchAuthorizer(
        allowlist={("cloud-router", "openrouter", model)},
        scanners=[_Scanner()],
        capability_policy=_Policy(),
        allowed_endpoints={endpoint},
    )
    return authz, authz.authorize(
        CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(
                engine="cloud-router",
                provider="openrouter",
                model=model,
                endpoint=endpoint,
            ),
            messages=tuple(
                {"role": "user", "content": message.content}
                for message in messages
            ),
            grant=ExplicitGrant(
                agent_id="host",
                capability="llm:cloud",
                expires_at=time.time() + 600,
            ),
            budget=BudgetReservation(
                est_prompt_tokens=2,
                max_tokens=8,
                ctx_limit=64,
            ),
            session_id="sess-normalize",
            nonce=f"normalize-{uuid.uuid4().hex}",
        )
    )


def test_get_provider_detects_bare_openrouter_id():
    assert cloud_router.get_provider("anthropic/claude-haiku-4.5") == "openrouter"


def test_get_provider_detects_litellm_prefixed_openrouter_id():
    model = "openrouter/anthropic/claude-haiku-4.5"
    assert cloud_router.get_provider(model) == "openrouter"


@pytest.mark.parametrize(
    "requested_model,expected_forwarded_model",
    [
        ("anthropic/claude-haiku-4.5", "anthropic/claude-haiku-4.5"),
        ("openrouter/anthropic/claude-haiku-4.5", "anthropic/claude-haiku-4.5"),
        ("openrouter/auto", "openrouter/auto"),
        (
            "openrouter/nvidia/nemotron-3.5-super-vl:free",
            "nvidia/nemotron-3.5-super-vl:free",
        ),
    ],
)
@pytest.mark.asyncio
async def test_stream_cloud_normalizes_openrouter_model_before_forwarding(
    monkeypatch, requested_model, expected_forwarded_model
):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
    captured: dict[str, str] = {}
    messages = [Message(role="user", content="hi")]
    authz, sealed = _sealed_router_dispatch(requested_model, messages)

    async def fake_stream_openai(model, messages, temperature, max_tokens, **kwargs):
        captured["model"] = model
        yield "ok"

    monkeypatch.setattr(cloud_router, "_stream_openai", fake_stream_openai)

    tokens = [
        token
        async for token in cloud_router.stream_cloud(
            requested_model,
            messages,
            cloud_dispatch=sealed,
            authorizer=authz,
            dispatch_ledger=CloudDispatchLedger(),
            session_id="sess-normalize",
        )
    ]

    assert tokens == ["ok"]
    assert captured["model"] == expected_forwarded_model


@pytest.mark.asyncio
async def test_stream_cloud_rejects_unapproved_screenshot_before_transport(
    monkeypatch,
):
    monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
    messages = [Message(role="user", content="inspect", images=["aGVsbG8="])]
    model = "openrouter/nvidia/nemotron-3.5-super-vl:free"
    authz, sealed = _sealed_router_dispatch(model, messages)
    called = False

    async def fake_stream_openai(*args, **kwargs):
        nonlocal called
        called = True
        yield "unexpected"

    monkeypatch.setattr(cloud_router, "_stream_openai", fake_stream_openai)
    with pytest.raises(PrivacyDenied, match="screenshot"):
        [
            token
            async for token in cloud_router.stream_cloud(
                model,
                messages,
                cloud_dispatch=sealed,
                authorizer=authz,
                dispatch_ledger=CloudDispatchLedger(),
                session_id="sess-normalize",
            )
        ]
    assert called is False
