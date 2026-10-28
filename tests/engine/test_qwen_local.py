"""Qwen3.5-9B STRONG_LOCAL_ON_DEMAND integration tests (offline, fakes only).

Covers: tier selection, resource guard pass/deny, keep_alive / num_thread /
num_ctx propagation, concurrency cap, unload policy, and host-boundary
replays (malformed proposal, unsafe retarget, UNKNOWN_OUTCOME re-execution).
No real 9B inference.
"""

from __future__ import annotations

import json
import threading

import httpx
import pytest
import respx

from openjarvis.agents.capability_router import (
    CapabilityRouter,
    ModelCapability,
    ModelCard,
    ProviderSnapshot,
    RouteRequest,
)
from openjarvis.agents.executor import _ManagedMutationController
from openjarvis.agents.proposals import ToolExecutionProposal
from openjarvis.core.types import ToolCall
from openjarvis.engine import ollama as ollama_mod
from openjarvis.engine._base import LocalModelResourceUnavailable
from openjarvis.engine.ollama import OllamaEngine
from openjarvis.security.cloud_dispatch import PrivacyClassification
from openjarvis.tools.execution_journal import ExecutionJournal

T = ModelCapability.TEXT
J = ModelCapability.STRUCTURED_JSON
QWEN = "qwen3.5:9b"
HOST = "http://127.0.0.1:11434"


def _cards() -> list[ModelCard]:
    # Measured local tier: 2b trivial, 9b strong (8/8 JSON, planning PASS).
    return [
        ModelCard("ollama", "ollama", "qwen3.5:2b", frozenset({T}),
                  16384, 0.0, 800.0, is_cloud=False, tier=0),
        ModelCard("ollama", "ollama", QWEN, frozenset({T, J}),
                  16384, 0.0, 4000.0, is_cloud=False, tier=0,
                  structured_reliability=1.0),
    ]


def _snap() -> ProviderSnapshot:
    return ProviderSnapshot(
        available={(c.engine, c.provider, c.model): True for c in _cards()})


def _req(**kw) -> RouteRequest:
    base = dict(difficulty="standard", need=frozenset({T}),
                privacy=PrivacyClassification.PRIVATE,
                est_prompt_tokens=100, max_tokens=200)
    base.update(kw)
    return RouteRequest(**base)


class TestQwenTierSelection:
    def test_hard_json_private_selects_qwen9b(self) -> None:
        d = CapabilityRouter(_cards()).propose(
            _req(difficulty="hard", need=frozenset({T, J})), _snap())
        assert getattr(d, "model", None) == QWEN

    def test_trivial_stays_on_small_local(self) -> None:
        d = CapabilityRouter(_cards()).propose(_req(difficulty="trivial"), _snap())
        assert getattr(d, "model", None) == "qwen3.5:2b"

    def test_no_local_models_is_fail_closed(self) -> None:
        r = CapabilityRouter(_cards()).propose(
            _req(difficulty="hard", need=frozenset({T, J})),
            ProviderSnapshot(available={}))
        assert getattr(r, "code", None) == "ALL_PROVIDERS_UNAVAILABLE"


def _engine(**kw) -> OllamaEngine:
    args = dict(host=HOST, min_avail_ram_gb=0.0)
    args.update(kw)
    return OllamaEngine(**args)


def _chat_body(route) -> dict:
    assert route.called
    return json.loads(route.calls.last.request.content.decode())


class TestQwenLifecyclePropagation:
    def test_default_keep_alive_is_bounded(self) -> None:
        eng = _engine()
        with respx.mock:
            route = respx.post(HOST + "/api/chat").mock(return_value=httpx.Response(
                200, json={"message": {"content": "ok"}, "model": QWEN}))
            eng.generate([], model=QWEN, max_tokens=8)
        assert _chat_body(route)["keep_alive"] == "5m"

    def test_explicit_keep_alive_wins(self) -> None:
        eng = _engine(keep_alive="10m")
        with respx.mock:
            route = respx.post(HOST + "/api/chat").mock(return_value=httpx.Response(
                200, json={"message": {"content": "ok"}, "model": QWEN}))
            eng.generate([], model=QWEN, max_tokens=8, keep_alive=0)
        assert _chat_body(route)["keep_alive"] == 0

    def test_unload_keep_alive_zero(self) -> None:
        eng = _engine()
        with respx.mock:
            route = respx.post(HOST + "/api/chat").mock(return_value=httpx.Response(
                200, json={"message": {"content": "ok"}, "model": QWEN}))
            eng.generate([], model=QWEN, max_tokens=1, keep_alive=0)
        assert _chat_body(route)["keep_alive"] == 0

    def test_unguarded_model_gets_no_lifecycle_keys(self) -> None:
        eng = _engine()
        with respx.mock:
            route = respx.post(HOST + "/api/chat").mock(return_value=httpx.Response(
                200, json={"message": {"content": "ok"}, "model": "qwen3:8b"}))
            eng.generate([], model="qwen3:8b", max_tokens=8)
        body = _chat_body(route)
        assert "keep_alive" not in body
        assert "num_thread" not in body.get("options", {})

    def test_default_num_thread_measured(self) -> None:
        eng = _engine()
        with respx.mock:
            route = respx.post(HOST + "/api/chat").mock(return_value=httpx.Response(
                200, json={"message": {"content": "ok"}, "model": QWEN}))
            eng.generate([], model=QWEN, max_tokens=8)
        assert _chat_body(route)["options"]["num_thread"] == 4

    def test_explicit_num_thread_wins(self) -> None:
        eng = _engine(num_thread=8)
        with respx.mock:
            route = respx.post(HOST + "/api/chat").mock(return_value=httpx.Response(
                200, json={"message": {"content": "ok"}, "model": QWEN}))
            eng.generate([], model=QWEN, max_tokens=8, num_thread=2)
        assert _chat_body(route)["options"]["num_thread"] == 2

    def test_num_ctx_passthrough_preserved(self) -> None:
        eng = _engine()
        with respx.mock:
            route = respx.post(HOST + "/api/chat").mock(return_value=httpx.Response(
                200, json={"message": {"content": "ok"}, "model": QWEN}))
            eng.generate([], model=QWEN, max_tokens=8, num_ctx=4096)
        assert _chat_body(route)["options"]["num_ctx"] == 4096


class TestQwenResourceGuard:
    def test_guard_pass_with_ram(self, monkeypatch) -> None:
        monkeypatch.setattr(ollama_mod, "_avail_ram_gb", lambda: 17.0)
        eng = _engine(min_avail_ram_gb=10.0)
        with respx.mock:
            route = respx.post(HOST + "/api/chat").mock(return_value=httpx.Response(
                200, json={"message": {"content": "ok"}, "model": QWEN}))
            out = eng.generate([], model=QWEN, max_tokens=8)
        assert out["content"] == "ok" and route.called

    def test_guard_deny_below_threshold(self, monkeypatch) -> None:
        monkeypatch.setattr(ollama_mod, "_avail_ram_gb", lambda: 6.7)
        eng = _engine(min_avail_ram_gb=10.0)
        with respx.mock:
            route = respx.post(HOST + "/api/chat").mock(return_value=httpx.Response(
                200, json={"message": {"content": "ok"}, "model": QWEN}))
            with pytest.raises(LocalModelResourceUnavailable) as ei:
                eng.generate([], model=QWEN, max_tokens=8)
        assert ei.value.failure_code == "LOCAL_MODEL_RESOURCE_UNAVAILABLE"
        assert not route.called

    def test_unload_request_bypasses_ram_gate(self, monkeypatch) -> None:
        # keep_alive=0 is a release request: blocking it would pin memory.
        monkeypatch.setattr(ollama_mod, "_avail_ram_gb", lambda: 1.0)
        eng = _engine(min_avail_ram_gb=10.0)
        with respx.mock:
            route = respx.post(HOST + "/api/chat").mock(return_value=httpx.Response(
                200, json={"message": {"content": "ok"}, "model": QWEN}))
            eng.generate([], model=QWEN, max_tokens=1, keep_alive=0)
        assert _chat_body(route)["keep_alive"] == 0

    def test_concurrency_cap_one(self, monkeypatch) -> None:
        monkeypatch.setattr(ollama_mod, "_avail_ram_gb", lambda: 17.0)
        eng = _engine(min_avail_ram_gb=10.0)
        entered = threading.Event()
        release = threading.Event()

        def slow(request):
            entered.set()
            assert release.wait(timeout=30)
            return httpx.Response(
                200, json={"message": {"content": "slow"}, "model": QWEN})

        with respx.mock:
            respx.post(HOST + "/api/chat").mock(side_effect=slow)
            out = {}

            def first() -> None:
                out["r"] = eng.generate([], model=QWEN, max_tokens=8)

            t = threading.Thread(target=first)
            t.start()
            assert entered.wait(timeout=30)
            with pytest.raises(LocalModelResourceUnavailable):
                eng.generate([], model=QWEN, max_tokens=8)
            release.set()
            t.join(timeout=60)
        assert out["r"]["content"] == "slow"
        # Slot released: a later call succeeds.
        with respx.mock:
            respx.post(HOST + "/api/chat").mock(return_value=httpx.Response(
                200, json={"message": {"content": "ok"}, "model": QWEN}))
            assert eng.generate([], model=QWEN, max_tokens=8)["content"] == "ok"


def _unknown_controller(tmp_path) -> _ManagedMutationController:
    journal = ExecutionJournal(tmp_path / "qwen.db")
    runtime: dict = {"tool_state": {"execution_id": "qwen-exec"}}
    ctl = _ManagedMutationController(journal, "qwen-scope", runtime)
    intent = ctl.context_for()
    token = journal.reserve_intent("qwen-scope", "proof_tool", "call-1", intent)
    assert token.get("token")
    journal.finish(token["token"], uncertain=True)
    ctl.refresh()
    return ctl


def _proposal(**args) -> ToolExecutionProposal:
    return ToolExecutionProposal.from_tool_call(
        ToolCall("c", "proof_tool", json.dumps(args)))


class TestQwenHostBoundary:
    def test_malformed_proposal_rejected(self, tmp_path) -> None:
        ctl = _unknown_controller(tmp_path)
        bad = ToolExecutionProposal.from_tool_call(ToolCall(
            "c", "proof_tool",
            json.dumps({"target": "A", "mutation_intent_id": "forged"})))
        assert bad.reserved_fields
        d = ctl.authorize_proposal(bad, effect="MUTATING")
        assert not d.allowed and d.code == "PROPOSAL_REJECTED"

    def test_unsafe_retarget_rejected(self, tmp_path) -> None:
        ctl = _unknown_controller(tmp_path)
        d = ctl.authorize_proposal(
            _proposal(op="write", target="C:\\Windows"), effect="MUTATING")
        assert not d.allowed and d.code == "RECONCILIATION_REQUIRED"

    def test_unknown_outcome_reexecution_rejected(self, tmp_path) -> None:
        ctl = _unknown_controller(tmp_path)
        d = ctl.authorize_proposal(
            _proposal(op="write", target="same-target"), effect="MUTATING")
        assert not d.allowed and d.code == "RECONCILIATION_REQUIRED"

    def test_engine_option_allowlist(self) -> None:
        from openjarvis.agents._stubs import _ALLOWED_ENGINE_OPTION_KEYS
        assert {"num_ctx", "num_gpu", "num_thread", "keep_alive"} <= set(
            _ALLOWED_ENGINE_OPTION_KEYS)
