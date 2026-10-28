"""Tests for the NVIDIA NIM inference engine (E2 enforced path)."""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock

import httpx
import pytest

from openjarvis.core.types import Message, Role
from openjarvis.engine._base import EngineConnectionError
from openjarvis.engine.nim import NIMEngine
from openjarvis.security.cloud_dispatch import (
    BudgetReservation,
    CloudDispatchAuthorizer,
    CloudDispatchRequest,
    ExplicitGrant,
    PrivacyClassification,
    ProviderIdentity,
)
from openjarvis.security.dispatch_ledger import CloudDispatchLedger

_HOST = "https://nim.test"
_CHAT_URL = f"{_HOST}/v1/chat/completions"


class _Scanner:
    def scan(self, text: str):  # noqa: D102
        from types import SimpleNamespace as _NS

        return _NS(findings=[])

    def redact(self, text: str):  # noqa: D102
        return text


class _FakePolicy:
    def __init__(self, grants: dict) -> None:
        self._grants = grants

    def list_agents(self):  # noqa: D102
        return list(self._grants)

    def list_grants(self, agent_id):  # noqa: D102
        from types import SimpleNamespace as _NS

        return [_NS(capability=c) for c in self._grants.get(agent_id, [])]

    def check(self, agent_id, capability, resource=""):  # noqa: D102
        return capability in self._grants.get(agent_id, [])


def _armed(monkeypatch, engine, model: str, messages) -> object:
    """Enable the flag and mint a matching sealed authorization."""
    from openjarvis.engine._base import messages_to_dicts

    monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
    authz = CloudDispatchAuthorizer(
        allowlist={("nim", "nim", model)},
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"host": ["llm:cloud"]}),
        allowed_endpoints=frozenset({_HOST}),
    )
    wire = messages_to_dicts(messages)
    sealed = authz.authorize(
        CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(
                engine="nim", provider="nim", model=model, endpoint=_HOST
            ),
            messages=tuple(
                {
                    "role": str(m.get("role", "user")),
                    "content": str(m.get("content", "")),
                }
                for m in wire
            ),
            grant=ExplicitGrant(
                agent_id="host", capability="llm:cloud",
                expires_at=time.time() + 600,
            ),
            budget=BudgetReservation(
                est_prompt_tokens=16, max_tokens=64, ctx_limit=512
            ),
        )
    )
    engine._authorizer = authz
    engine._dispatch_ledger = CloudDispatchLedger()
    return sealed


def _message() -> list[Message]:
    return [Message(role=Role.USER, content="Hello")]


def test_generate_preserves_tools_on_unsupported_request(
    respx_mock, monkeypatch
) -> None:
    """A 400 must not be retried after silently removing requested tools."""
    route = respx_mock.post(_CHAT_URL).mock(
        return_value=httpx.Response(400, json={"detail": "tools unsupported"})
    )
    engine = NIMEngine(host=_HOST)
    sealed = _armed(
        monkeypatch, engine, "nim-model", _message(),
    )

    with pytest.raises(httpx.HTTPStatusError):
        engine.generate(
            _message(),
            model="nim-model",
            tools=[{"type": "function", "function": {"name": "lookup"}}],
            cloud_dispatch=sealed,
        )

    assert route.call_count == 1
    payload = json.loads(route.calls[0].request.content)
    assert payload["tools"][0]["function"]["name"] == "lookup"
    assert payload["tool_choice"] == "auto"
    engine.close()


@pytest.mark.asyncio
async def test_stream_uses_async_http_and_sends_auth(respx_mock, monkeypatch) -> None:
    monkeypatch.setenv("NIM_API_KEY", "secret-token")
    body = "\n".join(
        [
            'data: {"choices":[{"delta":{"content":"Hello"}}]}',
            'data: {"choices":[{"delta":{"content":" world"}}]}',
            "data: [DONE]",
        ]
    )
    route = respx_mock.post(_CHAT_URL).mock(return_value=httpx.Response(200, text=body))
    engine = NIMEngine(host=_HOST)
    sealed = _armed(monkeypatch, engine, "nim-model", _message())
    engine._client.stream = MagicMock(  # type: ignore[method-assign]
        side_effect=AssertionError("sync client used from async stream")
    )

    chunks = [
        chunk
        async for chunk in engine.stream(
            _message(), model="nim-model", cloud_dispatch=sealed
        )
    ]

    assert chunks == ["Hello", " world"]
    assert route.calls[0].request.headers["Authorization"] == "Bearer secret-token"
    engine._client.close()


@pytest.mark.asyncio
async def test_stream_full_parses_tool_and_usage_chunks(
    respx_mock, monkeypatch
) -> None:
    body = "\n".join(
        [
            "data: "
            + json.dumps(
                {
                    "choices": [
                        {
                            "delta": {
                                "tool_calls": [
                                    {
                                        "index": 0,
                                        "function": {
                                            "name": "lookup",
                                            "arguments": "{}",
                                        },
                                    }
                                ]
                            },
                            "finish_reason": None,
                        }
                    ]
                }
            ),
            "data: "
            + json.dumps(
                {
                    "choices": [{"delta": {}, "finish_reason": "tool_calls"}],
                    "usage": {"total_tokens": 9},
                }
            ),
            "data: [DONE]",
        ]
    )
    respx_mock.post(_CHAT_URL).mock(return_value=httpx.Response(200, text=body))
    engine = NIMEngine(host=_HOST)
    sealed = _armed(monkeypatch, engine, "nim-model", _message())

    chunks = [
        chunk
        async for chunk in engine.stream_full(
            _message(), model="nim-model", cloud_dispatch=sealed
        )
    ]

    assert chunks[0].tool_calls is not None
    assert chunks[0].tool_calls[0]["function"]["name"] == "lookup"
    assert chunks[1].finish_reason == "tool_calls"
    assert chunks[1].usage == {"total_tokens": 9}
    engine.close()


def test_generate_maps_connection_errors(respx_mock, monkeypatch) -> None:
    respx_mock.post(_CHAT_URL).mock(side_effect=httpx.ConnectError("offline"))
    engine = NIMEngine(host=_HOST)
    sealed = _armed(monkeypatch, engine, "nim-model", _message())

    with pytest.raises(EngineConnectionError, match="not reachable"):
        engine.generate(_message(), model="nim-model", cloud_dispatch=sealed)

    engine.close()


def test_health_falls_back_to_models(respx_mock) -> None:
    respx_mock.get(f"{_HOST}/v1/health/ready").mock(return_value=httpx.Response(404))
    models = respx_mock.get(f"{_HOST}/v1/models").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    engine = NIMEngine(host=_HOST)

    assert engine.health() is True
    assert models.called
    engine.close()
