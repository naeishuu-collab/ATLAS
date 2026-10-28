"""Egress integration tests — every cloud path through the guard.

Fake engines/transports only. Covers: CloudEngine/LiteLLM/NIM/
openai-compat/direct-router analogues (fake cloud engines), MultiEngine
fallback analogue, sync+streaming/async, RLM-legacy/Planner/LLMTool/
CLI-style direct generate call shapes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Any, Dict, List

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
from openjarvis.security.egress_guard import guard_engine


class FakeCloudEngine:
    """Analogue of CloudEngine/LiteLLM/NIM/openai-compat/direct-router."""

    engine_id = "fake-cloud"
    is_cloud = True

    def __init__(self, tag: str = "cloud") -> None:
        self.tag = tag
        self.calls: List[Dict[str, Any]] = []

    def generate(self, messages: Sequence[Message], *, model: str, **kw: Any):
        self.calls.append({"model": model, "n": len(list(messages))})
        return {
            "content": f"[{self.tag}:{model}] ok",
            "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
            "model": model,
            "finish_reason": "stop",
        }

    async def stream(
        self, messages: Sequence[Message], *, model: str, **kw: Any
    ) -> AsyncIterator[str]:
        self.calls.append({"model": model, "stream": True})
        yield f"[{self.tag}:{model}] "
        yield "ok"

    async def stream_full(
        self, messages: Sequence[Message], *, model: str, **kw: Any
    ) -> AsyncIterator[Dict[str, Any]]:
        self.calls.append({"model": model, "stream_full": True})
        yield {"content": f"[{self.tag}:{model}] ok", "finish_reason": "stop"}

    def list_models(self):  # noqa: D102
        return ["llama-3.3-70b"]


class FakeLocalEngine(FakeCloudEngine):
    engine_id = "fake-local"
    is_cloud = False


class _FakePolicy:
    def __init__(self, grants: dict) -> None:
        self._grants = grants

    def list_agents(self):  # noqa: D102
        return list(self._grants)

    def list_grants(self, agent_id):  # noqa: D102
        from types import SimpleNamespace

        return [SimpleNamespace(capability=c) for c in self._grants.get(agent_id, [])]

    def check(self, agent_id, capability, resource=""):  # noqa: D102
        return capability in self._grants.get(
            agent_id, self._grants.get("_default", [])
        )


class _Scanner:
    def scan(self, text: str):  # noqa: D102
        from types import SimpleNamespace

        return SimpleNamespace(findings=[])

    def redact(self, text: str):  # noqa: D102
        return text


def _authorizer(models: set):
    return CloudDispatchAuthorizer(
        allowlist={("fake-cloud", "groq", m) for m in models},
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"agent-1": ["llm:cloud"]}),
    )


def _sealed(authz, model: str, text: str = "hello"):
    req = CloudDispatchRequest(
        classification=PrivacyClassification.INTERNAL,
        provider=ProviderIdentity(
            engine="fake-cloud", provider="groq", model=model
        ),
        messages=({"role": "user", "content": text},),
        grant=ExplicitGrant(agent_id="agent-1", capability="llm:cloud"),
        budget=BudgetReservation(est_prompt_tokens=5, max_tokens=50, ctx_limit=4096),
    )
    return authz.authorize(req)


def _msgs(text: str = "hello"):
    return [Message(role=Role.USER, content=text)]


@pytest.mark.parametrize(
    "tag", ["cloud", "litellm", "nim", "openai-compat", "direct-router"]
)
def test_cloud_paths_require_auth(tag: str) -> None:
    authz = _authorizer({"llama-3.3-70b"})
    guarded = guard_engine(FakeCloudEngine(tag), authz)
    # Without sealed auth: every analogue denies.
    with pytest.raises(PrivacyDenied):
        guarded.generate(_msgs(), model="llama-3.3-70b")
    assert guarded.inner.calls == []
    # With sealed auth: allowed exactly once per call.
    sealed = _sealed(authz, "llama-3.3-70b")
    out = guarded.generate(_msgs(), model="llama-3.3-70b", cloud_dispatch=sealed)
    assert out["content"] == f"[{tag}:llama-3.3-70b] ok"
    assert len(guarded.audit_log) == 1
    assert "hello" not in str(guarded.audit_log)


def test_multifallback_to_cloud_requires_auth() -> None:
    """MultiEngine-style fallback: local miss -> cloud needs its own auth."""

    class FakeMulti:
        engine_id = "fake-multi"
        is_cloud = False

        def __init__(self, cloud) -> None:
            self._cloud = cloud

        def generate(self, messages, *, model: str, **kw):
            # Fallback analogue: delegate cloud-looking models.
            if model.startswith("groq/"):
                return self._cloud.generate(
                    messages, model=model.removeprefix("groq/"), **kw
                )
            raise ValueError("local model missing")

        def list_models(self):  # noqa: D102
            return []

    authz = _authorizer({"llama-3.3-70b"})
    cloud = guard_engine(FakeCloudEngine("fallback-cloud"), authz)
    multi = FakeMulti(cloud)
    with pytest.raises(PrivacyDenied):
        multi.generate(_msgs(), model="groq/llama-3.3-70b")
    sealed = _sealed(authz, "llama-3.3-70b")
    out = multi.generate(_msgs(), model="groq/llama-3.3-70b", cloud_dispatch=sealed)
    assert "ok" in out["content"]


def test_streaming_and_async_same_boundary() -> None:
    import asyncio

    authz = _authorizer({"llama-3.3-70b"})
    guarded = guard_engine(FakeCloudEngine("s"), authz)

    async def _denied():
        async for _ in guarded.stream(_msgs(), model="llama-3.3-70b"):
            pass

    with pytest.raises(PrivacyDenied):
        asyncio.run(_denied())
    sealed = _sealed(authz, "llama-3.3-70b")

    async def collect():
        tokens = []
        async for t in guarded.stream(
            _msgs(), model="llama-3.3-70b", cloud_dispatch=sealed
        ):
            tokens.append(t)
        return tokens

    tokens = asyncio.run(collect())
    assert "".join(tokens).endswith("ok")

    async def collect_full():
        out = []
        async for c in guarded.stream_full(
            _msgs(), model="llama-3.3-70b", cloud_dispatch=sealed
        ):
            out.append(c)
        return out

    # Fresh sealed payload per dispatch (no blind reuse across dispatches
    # is enforced by the dispatch ledger in Phase 3; here reuse is visible
    # in audit).
    chunks = asyncio.run(collect_full())
    assert chunks[0]["content"].endswith("ok")


def test_caller_shapes_rlm_planner_tool_cli() -> None:
    """RLM-legacy/Planner/LLMTool/CLI shapes all funnel via the guard."""
    authz = _authorizer({"llama-3.3-70b"})
    guarded = guard_engine(FakeCloudEngine("c"), authz)
    sealed = _sealed(authz, "llama-3.3-70b")

    # RLM-legacy shape: single prompt string -> generate.
    out_legacy = guarded.generate(
        _msgs("legacy"),
        model="llama-3.3-70b",
        cloud_dispatch=_sealed(authz, "llama-3.3-70b", text="legacy"),
    )
    assert out_legacy["content"].endswith("ok")
    # Planner shape: system+user with response_format kw passes through.
    planner_msgs = [
        Message(role=Role.SYSTEM, content="plan"),
        Message(role=Role.USER, content="hello"),
    ]
    req = CloudDispatchRequest(
        classification=PrivacyClassification.INTERNAL,
        provider=ProviderIdentity(
            engine="fake-cloud", provider="groq", model="llama-3.3-70b"
        ),
        messages=(
            {"role": "system", "content": "plan"},
            {"role": "user", "content": "hello"},
        ),
        grant=ExplicitGrant(agent_id="agent-1", capability="llm:cloud"),
        budget=BudgetReservation(
            est_prompt_tokens=8, max_tokens=50, ctx_limit=4096
        ),
    )
    sealed_plan = authz.authorize(req)
    out = guarded.generate(
        planner_msgs, model="llama-3.3-70b", cloud_dispatch=sealed_plan
    )
    assert out["finish_reason"] == "stop"
    # LLMTool/CLI shape tested via `sealed` passthrough.
    out_cli = guarded.generate(
        _msgs(), model="llama-3.3-70b", cloud_dispatch=sealed
    )
    assert out_cli["content"].endswith("ok")


def test_local_only_passthrough() -> None:
    authz = _authorizer({"llama-3.3-70b"})
    guarded = guard_engine(FakeLocalEngine("local"), authz)
    out = guarded.generate(_msgs(), model="any-local-model")
    assert out["content"].endswith("ok")
    assert guarded.audit_log == []


def test_mutated_payload_denied_at_egress() -> None:
    authz = _authorizer({"llama-3.3-70b"})
    guarded = guard_engine(FakeCloudEngine("c"), authz)
    sealed = _sealed(authz, "llama-3.3-70b", text="hello")
    with pytest.raises(PrivacyDenied):
        guarded.generate(
            _msgs("hello tampered"),
            model="llama-3.3-70b",
            cloud_dispatch=sealed,
        )
    assert guarded.inner.calls == []


def test_dry_run_decides_without_dispatch() -> None:
    authz = _authorizer({"llama-3.3-70b"})
    engine = FakeCloudEngine("c")
    guarded = guard_engine(engine, authz)
    sealed = _sealed(authz, "llama-3.3-70b")
    decision = guarded.dry_run(_msgs(), model="llama-3.3-70b", cloud_dispatch=sealed)
    assert decision["decision"] == "ALLOW"
    assert decision["digest"] == sealed.digest
    assert engine.calls == []
    denied = guarded.dry_run(_msgs(), model="llama-3.3-70b")
    assert denied["decision"] == "DENY"
    assert engine.calls == []
    local = guard_engine(FakeLocalEngine("l"), authz)
    assert local.dry_run(_msgs(), model="m")["decision"] == "PASS_LOCAL"
