"""Offline Groq (via LiteLLM) qualification — no network, no credentials.

Proves adapter behaviour across success and failure statuses BEFORE any
real cloud request: single-send invariant, UNKNOWN_OUTCOME quarantine,
no fallback, sealed-grant binding. Groq model string follows LiteLLM's
``provider/model`` convention.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from unittest import mock

import pytest

from openjarvis.core.types import Message, Role
from openjarvis.engine.litellm import LiteLLMEngine
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

MODEL = "groq/llama-3.3-70b"
MSGS = [Message(role=Role.USER, content="synthetic canary prompt")]


class _Scanner:
    def scan(self, text: str):  # noqa: D102
        return SimpleNamespace(findings=[])

    def redact(self, text: str):  # noqa: D102
        return text


class _FakePolicy:
    def __init__(self, grants: dict) -> None:
        self._grants = grants

    def list_agents(self):  # noqa: D102
        return list(self._grants)

    def list_grants(self, agent_id):  # noqa: D102
        return [SimpleNamespace(capability=c) for c in self._grants.get(agent_id, [])]

    def check(self, agent_id, capability, resource=""):  # noqa: D102
        return capability in self._grants.get(agent_id, [])


def _arm(engine, monkeypatch) -> object:
    monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")
    authz = CloudDispatchAuthorizer(
        allowlist={("litellm", "groq", MODEL)},
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"host": ["llm:cloud"]}),
    )
    sealed = authz.authorize(
        CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(
                engine="litellm", provider="groq", model=MODEL,
                endpoint=(engine._api_base or "")),
            messages=({"role": "user", "content": "synthetic canary prompt"},),
            grant=ExplicitGrant(agent_id="host", capability="llm:cloud",
                                expires_at=time.time() + 600),
            budget=BudgetReservation(est_prompt_tokens=16, max_tokens=64,
                                     ctx_limit=512),
        )
    )
    engine._authorizer = authz
    engine._dispatch_ledger = CloudDispatchLedger()
    return sealed


def _ok_resp():
    return SimpleNamespace(
        choices=[SimpleNamespace(
            message=SimpleNamespace(content='{"decision": "defer"}',
                                    tool_calls=None),
            finish_reason="stop")],
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=5,
                              total_tokens=15),
        model=MODEL)


class _Coded(Exception):
    def __init__(self, status_code: int, msg: str = "provider error") -> None:
        super().__init__(msg)
        self.status_code = status_code


class TestGroqOfflineQualification:
    def test_success_single_send(self, monkeypatch) -> None:
        fake = mock.MagicMock()
        fake.completion.return_value = _ok_resp()
        fake.completion_cost.return_value = 0.0
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            engine = LiteLLMEngine()
            sealed = _arm(engine, monkeypatch)
            out = engine.generate(MSGS, model=MODEL, cloud_dispatch=sealed)
        assert out["content"] == '{"decision": "defer"}'
        assert fake.completion.call_count == 1  # external sends: 1 logical
        assert fake.completion.call_args.kwargs["max_retries"] == 0
        assert fake.completion.call_args.kwargs["model"] == MODEL
        entry = engine._dispatch_ledger._entries[sealed.dispatch_id]
        assert entry.state == "EXECUTED"

    @pytest.mark.parametrize("status", [400, 401, 403, 429, 500])
    def test_error_statuses_quarantine_no_retry(self, monkeypatch, status: int) -> None:
        fake = mock.MagicMock()
        fake.completion.side_effect = _Coded(status)
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            engine = LiteLLMEngine()
            sealed = _arm(engine, monkeypatch)
            with pytest.raises(Exception):
                engine.generate(MSGS, model=MODEL, cloud_dispatch=sealed)
        assert fake.completion.call_count == 1  # no second attempt
        assert fake.completion.call_args.kwargs["max_retries"] == 0
        assert engine._dispatch_ledger._entries[
            sealed.dispatch_id].state == "UNKNOWN_OUTCOME"  # quarantined, no fallback

    def test_connect_failure_quarantines(self, monkeypatch) -> None:
        fake = mock.MagicMock()
        fake.completion.side_effect = ConnectionError("refused")
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            engine = LiteLLMEngine()
            sealed = _arm(engine, monkeypatch)
            with pytest.raises(Exception):
                engine.generate(MSGS, model=MODEL, cloud_dispatch=sealed)
        assert fake.completion.call_count == 1
        entry = engine._dispatch_ledger._entries[sealed.dispatch_id]
        assert entry.state == "UNKNOWN_OUTCOME"

    def test_timeout_quarantines(self, monkeypatch) -> None:
        fake = mock.MagicMock()
        fake.completion.side_effect = TimeoutError("timed out")
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            engine = LiteLLMEngine()
            sealed = _arm(engine, monkeypatch)
            with pytest.raises(Exception):
                engine.generate(MSGS, model=MODEL, cloud_dispatch=sealed)
        assert fake.completion.call_count == 1
        entry = engine._dispatch_ledger._entries[sealed.dispatch_id]
        assert entry.state == "UNKNOWN_OUTCOME"

    def test_no_grant_no_send(self, monkeypatch) -> None:
        fake = mock.MagicMock()
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            engine = LiteLLMEngine()
            monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")
            engine._authorizer = CloudDispatchAuthorizer(
                allowlist=set(), scanners=[_Scanner()],
                capability_policy=_FakePolicy({}))
            with pytest.raises(PrivacyDenied):
                engine.generate(MSGS, model=MODEL)
        assert fake.completion.call_count == 0  # external sends: 0

    def test_model_swap_denied(self, monkeypatch) -> None:
        fake = mock.MagicMock()
        fake.completion.return_value = _ok_resp()
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            engine = LiteLLMEngine()
            sealed = _arm(engine, monkeypatch)
            with pytest.raises(PrivacyDenied):
                engine.generate(MSGS, model="groq/other-model",
                                cloud_dispatch=sealed)
        assert fake.completion.call_count == 0
