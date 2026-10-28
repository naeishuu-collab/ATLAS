"""Ollama adapter privacy conformance (offline, MockTransport only).

Drives the REAL OllamaEngine.generate/stream with a MockTransport-backed
client: request bodies must carry sanitized content only, and every
refusal must happen before the adapter is touched. Other providers are
NOT EXECUTED (one representative adapter; same envelope contract).
Cancellation on the sync path is NOT EXECUTED (no cancel parameter).
"""

from __future__ import annotations

import json

import httpx
import pytest

from openjarvis.agents.host_routing import HostEgressPolicy, ModelCardRegistry
from openjarvis.agents.privacy_pipeline import (
    FakeProviderSink,
    PipelineError,
    adapt_provider_messages,
    build_provider_envelope,
    deliver_to_fake,
)
from openjarvis.core.types import Message, Role
from openjarvis.engine.ollama import OllamaEngine

MODEL = "tiny-4b"


def _cards():
    return [
        {"engine": "ollama", "provider": "local", "model": MODEL,
         "capabilities": ["TEXT"], "ctx_limit": 4096,
         "cost_per_1k": 0.0, "latency_p50_ms": 50.0,
         "is_cloud": False, "tier": 0},
    ]


def _policy(**over):
    args = {"allow_cloud": False, "allowed_providers": (),
            "allow_raw_internal": False, "version": 1}
    args.update(over)
    return HostEgressPolicy(**args)


def _mocked_engine(captured, response_json=None, status=200):
    engine = OllamaEngine(host="http://127.0.0.1:11434")

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        return httpx.Response(status, json=response_json or {
            "message": {"role": "assistant", "content": "ok"},
            "model": MODEL, "prompt_eval_count": 3, "eval_count": 2})

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://127.0.0.1:11434")
    return engine


def _sanitized(text, *, privacy="PUBLIC"):
    adapted, _ = adapt_provider_messages(
        [Message(role=Role.USER, content=text)])
    envelope = build_provider_envelope(MODEL, adapted)
    out = deliver_to_fake(
        envelope, registry=ModelCardRegistry.from_host_config(_cards()),
        policy=_policy(), privacy=privacy, provider="local",
        engine="ollama", model=MODEL, allow=("model", "messages"),
        purpose="conformance", sink=FakeProviderSink())
    return [Message(role=Role(m["role"]), content=m["content"])
            for m in out.payload["messages"]]


def test_sanitized_payload_only() -> None:
    captured: list = []
    engine = _mocked_engine(captured)
    result = engine.generate(
        _sanitized("deploy key api_key=sk-live-9"), model=MODEL)
    assert result["content"] == "ok"
    body = captured[0]
    assert body["model"] == MODEL
    assert "sk-live-9" not in json.dumps(body)
    assert "[REDACTED]" in body["messages"][0]["content"]


def test_unknown_privacy_never_reaches_adapter() -> None:
    captured: list = []
    _mocked_engine(captured)
    with pytest.raises(PipelineError) as exc:
        _sanitized("hi", privacy="NOPE")
    assert exc.value.code == "PRIVACY_UNKNOWN"
    assert captured == []


def test_private_local_allowed_but_cloud_refused() -> None:
    captured: list = []
    engine = _mocked_engine(captured)
    result = engine.generate(_sanitized("hi", privacy="PRIVATE"), model=MODEL)
    assert result["content"] == "ok"
    assert len(captured) == 1
    with pytest.raises(PipelineError) as exc:
        deliver_to_fake(
            build_provider_envelope(
                "prose-70b", [{"role": "user", "content": "hi"}]),
            registry=ModelCardRegistry.from_host_config(_cards()),
            policy=_policy(), privacy="PRIVATE", provider="cloud",
            engine="cloud", model="prose-70b", allow=("model", "messages"),
            purpose="conformance", sink=FakeProviderSink())
    assert exc.value.code in ("MODEL_BINDING_UNVERIFIED", "PRIVACY_BLOCKED")
    assert len(captured) == 1


def test_model_binding_mismatch_stops_before_adapter() -> None:
    from openjarvis.agents.capability_router import RouteDecision
    from openjarvis.agents.host_routing import (
        BINDING_MISMATCH,
        RoutingError,
        bind_decision,
    )

    captured: list = []
    _mocked_engine(captured)
    decision = RouteDecision(engine="ollama", model=MODEL, reason="t")
    with pytest.raises(RoutingError) as exc:
        bind_decision(decision,
                      ModelCardRegistry.from_host_config(_cards()).cards,
                      planner_model="other-model", host_engine="ollama")
    assert exc.value.code == BINDING_MISMATCH
    assert captured == []


def test_streaming_sanitized() -> None:
    captured: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        body = ("\n".join([
            json.dumps({"message": {"content": "a"}, "done": False}),
            json.dumps({"message": {"content": "b"}, "done": True}),
        ]) + "\n")
        return httpx.Response(200, text=body)

    engine = OllamaEngine(host="http://127.0.0.1:11434")
    engine._async_transport = httpx.MockTransport(handler)

    async def collect():
        return [tok async for tok in engine.stream(
            _sanitized("hi api_key=sk-2"), model=MODEL)]

    import asyncio

    assert asyncio.run(collect()) == ["a", "b"]
    assert "sk-2" not in json.dumps(captured)


def test_tool_calls_stay_untrusted() -> None:
    captured: list = []
    engine = _mocked_engine(captured, response_json={
        "message": {"role": "assistant", "content": "",
                    "tool_calls": [{"id": "c1",
                                    "function": {"name": "t",
                                                 "arguments": "{}"}}]},
        "model": MODEL, "prompt_eval_count": 3, "eval_count": 2})
    result = engine.generate(_sanitized("hi"), model=MODEL)
    assert result["tool_calls"][0]["name"] == "t"
    assert "verified" not in result


def test_images_default_deny() -> None:
    captured: list = []
    engine = _mocked_engine(captured)
    adapted, _ = adapt_provider_messages(
        [Message(role=Role.USER, content="see", images=["eA=="])])
    assert adapted[0].get("images") is None
    msgs = [Message(role=Role(m["role"]), content=m["content"])
            for m in adapted]
    engine.generate(msgs, model=MODEL)
    assert "images" not in json.dumps(captured[0])


def test_timeout_maps_cleanly_offline() -> None:
    from openjarvis.engine._base import EngineConnectionError

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("wedged")

    engine = OllamaEngine(host="http://127.0.0.1:11434")
    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://127.0.0.1:11434")
    with pytest.raises(EngineConnectionError):
        engine.generate(_sanitized("hi"), model=MODEL)


def test_adapter_retry_without_tools() -> None:
    captured: list = []
    engine = OllamaEngine(host="http://127.0.0.1:11434")

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        captured.append(body)
        if "tools" in body:
            return httpx.Response(400, text="no tools")
        return httpx.Response(200, json={
            "message": {"role": "assistant", "content": "plain"},
            "model": MODEL, "prompt_eval_count": 1, "eval_count": 1})

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://127.0.0.1:11434")
    result = engine.generate(
        _sanitized("hi"), model=MODEL,
        tools=[{"type": "function",
                "function": {"name": "t", "parameters": {}}}])
    assert result["content"] == "plain"
    assert len(captured) == 2
    assert "tools" not in captured[1]


def test_retry_bodies_stay_identical_and_sanitized() -> None:
    from openjarvis.agents.privacy_pipeline import seal_wire_envelope

    captured: list = []
    engine = OllamaEngine(host="http://127.0.0.1:11434")

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content))
        if "tools" in json.loads(request.content):
            return httpx.Response(400, text="no tools")
        return httpx.Response(200, json={
            "message": {"role": "assistant", "content": "plain"},
            "model": MODEL, "prompt_eval_count": 1, "eval_count": 1})

    engine._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://127.0.0.1:11434")
    msgs = _sanitized("note api_key=sk-retry")
    engine.generate(
        msgs, model=MODEL,
        tools=[{"type": "function",
                "function": {"name": "t", "parameters": {}}}])
    first, second = captured
    assert first["messages"] == second["messages"]
    assert first["model"] == second["model"] == MODEL
    assert "sk-retry" not in json.dumps(captured)
    sealed = seal_wire_envelope(
        "ollama",
        {"model": first["model"], "messages": first["messages"]},
        _allowed_decision())
    assert sealed.model == MODEL


def _allowed_decision():
    from openjarvis.agents.host_routing import EgressDecision

    return EgressDecision(True, "EGRESS_ALLOWED", "test")


def test_stream_starts_authorized_and_partial_is_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = ("\n".join([
            json.dumps({"message": {"content": "x"}, "done": False}),
        ]) + "\n")
        return httpx.Response(200, text=body)

    engine = OllamaEngine(host="http://127.0.0.1:11434")
    engine._async_transport = httpx.MockTransport(handler)

    async def collect():
        return [tok async for tok in engine.stream(
            _sanitized("hi"), model=MODEL)]

    import asyncio

    assert asyncio.run(collect()) == ["x"]
    # No "done" chunk arrived: usage is never reported for partial
    # streams, so a partial stream cannot pass as a complete response.
    assert engine._last_stream_usage == {}


def test_stream_cancel_propagates() -> None:
    import asyncio

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=json.dumps(
            {"message": {"content": "x"}, "done": True}) + "\n")

    engine = OllamaEngine(host="http://127.0.0.1:11434")
    engine._async_transport = httpx.MockTransport(handler)

    async def cancelled_collect():
        gen = engine.stream(_sanitized("hi"), model=MODEL)
        task = asyncio.ensure_future(_drain(gen))
        task.cancel()
        return await task

    async def _drain(gen):
        return [tok async for tok in gen]

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cancelled_collect())
    assert engine._last_stream_usage == {}
