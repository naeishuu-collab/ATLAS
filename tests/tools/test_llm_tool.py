"""Tests for the LLM tool (E1 enforced path: flag + sealed auth required)."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

from openjarvis.security.cloud_dispatch import (
    BudgetReservation,
    CloudDispatchAuthorizer,
    CloudDispatchRequest,
    ExplicitGrant,
    PrivacyClassification,
    ProviderIdentity,
)
from openjarvis.security.dispatch_ledger import CloudDispatchLedger
from openjarvis.tools.llm_tool import LLMTool


def _make_mock_engine(content: str = "response") -> MagicMock:
    engine = MagicMock()
    engine.is_cloud = True
    engine.generate.return_value = {
        "content": content,
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }
    return engine


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


def _authorizer():
    return CloudDispatchAuthorizer(
        allowlist={("mock", "poc", "test-model")},
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"host": ["llm:cloud"]}),
    )


def _sealed(authz, messages, model="test-model"):
    return authz.authorize(
        CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(engine="mock", provider="poc", model=model),
            messages=tuple(messages),
            grant=ExplicitGrant(
                agent_id="host", capability="llm:cloud",
                expires_at=time.time() + 600,
            ),
            budget=BudgetReservation(
                est_prompt_tokens=4, max_tokens=16, ctx_limit=128
            ),
        )
    )


def _auth_tool(engine, authz, model="test-model"):
    return LLMTool(
        engine,
        model=model,
        provider="poc",
        authorizer=authz,
        dispatch_ledger=CloudDispatchLedger(),
    )


class TestLLMTool:
    def test_spec(self):
        tool = LLMTool()
        assert tool.spec.name == "llm"
        assert tool.spec.category == "inference"

    def test_no_engine(self):
        tool = LLMTool()
        result = tool.execute(prompt="hello")
        assert result.success is False
        assert "No inference engine" in result.content

    def test_no_model(self):
        tool = LLMTool(engine=_make_mock_engine(), model="")
        result = tool.execute(prompt="hello")
        assert result.success is False
        assert "No model" in result.content

    def test_no_prompt(self):
        tool = LLMTool(engine=_make_mock_engine(), model="test-model")
        result = tool.execute(prompt="")
        assert result.success is False

    def test_successful_generation(self, monkeypatch):
        monkeypatch.setenv("ASTRA_LLM_TOOL_EGRESS", "on")
        engine = _make_mock_engine("The answer is 42.")
        authz = _authorizer()
        tool = _auth_tool(engine, authz)
        sealed = _sealed(
            authz, ({"role": "user", "content": "What is the answer?"},)
        )
        result = tool.execute(
            prompt="What is the answer?", cloud_dispatch=sealed
        )
        assert result.success is True
        assert result.content == "The answer is 42."
        assert result.usage["total_tokens"] == 15
        assert engine.generate.call_count == 1

    def test_with_system_message(self, monkeypatch):
        monkeypatch.setenv("ASTRA_LLM_TOOL_EGRESS", "on")
        engine = _make_mock_engine()
        authz = _authorizer()
        tool = _auth_tool(engine, authz)
        sealed = _sealed(
            authz,
            (
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "hello"},
            ),
        )
        tool.execute(
            prompt="hello", system="You are helpful.", cloud_dispatch=sealed
        )
        call_args = engine.generate.call_args
        messages = call_args[0][0]
        assert len(messages) == 2
        assert messages[0].role.value == "system"
        assert messages[1].role.value == "user"

    def test_engine_error(self, monkeypatch):
        monkeypatch.setenv("ASTRA_LLM_TOOL_EGRESS", "on")
        engine = MagicMock()
        engine.is_cloud = True
        engine.generate.side_effect = RuntimeError("connection failed")
        authz = _authorizer()
        tool = _auth_tool(engine, authz)
        sealed = _sealed(authz, ({"role": "user", "content": "hello"},))
        result = tool.execute(prompt="hello", cloud_dispatch=sealed)
        assert result.success is False
        assert "UNKNOWN_OUTCOME" in result.content

    def test_unsealed_call_denied_by_default(self):
        engine = _make_mock_engine()
        tool = LLMTool(engine=engine, model="test-model")
        result = tool.execute(prompt="hello")
        assert result.success is False
        assert "EGRESS_DENIED" in result.content
        engine.generate.assert_not_called()
