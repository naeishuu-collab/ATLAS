"""Unified routing pipeline through Fake Transport (offline, zero network).

Chain: registry -> snapshot -> router -> binding -> adapt -> minimize ->
redact -> egress -> fake transport -> fake response (untrusted). Items
20-21 (UNKNOWN/exactly-once) are covered by managed E2E; not duplicated.
"""

from __future__ import annotations

import pytest

from openjarvis.agents.fake_transport import (
    EGRESS_DENIED,
    FALLBACK_MISMATCH,
    RETRY_EXHAUSTED,
    STREAM_INTERRUPTED,
    TRANSPORT_CANCELLED,
    TRANSPORT_TIMEOUT,
    TRANSPORT_UNAVAILABLE,
    UNKNOWN_FIELD,
    FakeTransport,
    TransportError,
)
from openjarvis.agents.host_routing import HostEgressPolicy, ModelCardRegistry
from openjarvis.agents.privacy_pipeline import (
    FakeProviderSink,
    adapt_provider_messages,
    build_provider_envelope,
    deliver_to_fake,
)
from openjarvis.core.types import Message, Role


def _cards():
    return [
        {"engine": "fake", "provider": "local", "model": "tiny-4b",
         "capabilities": ["TEXT"], "ctx_limit": 4096,
         "cost_per_1k": 0.0, "latency_p50_ms": 50.0,
         "is_cloud": False, "tier": 0},
        {"engine": "fake", "provider": "cloud", "model": "prose-70b",
         "capabilities": ["TEXT", "STRUCTURED_JSON", "NATIVE_TOOLS"],
         "ctx_limit": 128000, "cost_per_1k": 1.0, "latency_p50_ms": 800.0,
         "is_cloud": True, "structured_reliability": 0.9, "tier": 2},
    ]


def _policy(**over):
    args = {"allow_cloud": True, "allowed_providers": ("cloud",),
            "allow_raw_internal": False, "version": 1}
    args.update(over)
    return HostEgressPolicy(**args)


def _chain(messages, *, privacy="PUBLIC", provider="cloud",
           model="prose-70b", need_text=True, transport_kwargs=None,
           sink=None, **adapt_kw):
    """Full unified chain returning (response, transport, sink)."""
    sink = sink if sink is not None else FakeProviderSink()
    adapted, _ = adapt_provider_messages(messages, **adapt_kw)
    envelope = build_provider_envelope(model, adapted)
    out = deliver_to_fake(
        envelope, registry=ModelCardRegistry.from_host_config(_cards()),
        policy=_policy(), privacy=privacy, provider=provider,
        engine="fake", model=model, allow=("model", "messages"),
        purpose="unified", sink=sink)
    transport = FakeTransport()
    response = transport.complete(
        out.payload, out.decision, **(transport_kwargs or {}))
    return response, transport, sink


def _user(text):
    return Message(role=Role.USER, content=text)


def test_local_provider_normal() -> None:
    response, transport, _ = _chain(
        [_user("hi")], privacy="PUBLIC", provider="local",
        model="tiny-4b", transport_kwargs={"content": "local hi"})
    assert response["content"] == "local hi"
    assert len(transport.calls) == 1


def test_cloud_provider_normal_fake() -> None:
    response, _, sink = _chain(
        [_user("hi")], transport_kwargs={"content": "cloud hi"})
    assert response["content"] == "cloud hi"
    assert sink.received[0]["code"] == "EGRESS_ALLOWED"


def test_private_cloud_rejected() -> None:
    from openjarvis.agents.privacy_pipeline import PipelineError

    with pytest.raises(PipelineError) as exc:
        _chain([_user("hi")], privacy="PRIVATE")
    assert exc.value.code == "PRIVACY_BLOCKED"


def test_internal_sanitized_cloud() -> None:
    response, _, sink = _chain(
        [_user("query, api_key=sk-1")], privacy="INTERNAL",
        transport_kwargs={"content": "answer"})
    assert response["content"] == "answer"
    assert "sk-1" not in repr(sink.received)


def test_unknown_privacy_rejected() -> None:
    from openjarvis.agents.privacy_pipeline import PipelineError

    with pytest.raises(PipelineError) as exc:
        _chain([_user("hi")], privacy="NOPE")
    assert exc.value.code == "PRIVACY_UNKNOWN"


def test_binding_mismatches_rejected() -> None:
    from openjarvis.agents.capability_router import RouteDecision
    from openjarvis.agents.host_routing import (
        BINDING_MISMATCH,
        MODEL_BINDING_UNVERIFIED,
        RoutingError,
        bind_decision,
    )

    reg = ModelCardRegistry.from_host_config(_cards())
    good = RouteDecision(engine="fake", model="tiny-4b", reason="t")
    with pytest.raises(RoutingError) as exc:
        bind_decision(good, reg.cards, planner_model="other",
                      host_engine="fake")
    assert exc.value.code == BINDING_MISMATCH
    with pytest.raises(RoutingError) as exc:
        bind_decision(good, reg.cards, planner_model="tiny-4b",
                      host_engine="other")
    assert exc.value.code == BINDING_MISMATCH
    dup = ModelCardRegistry.from_host_config(
        _cards() + [dict(_cards()[0], provider="local-2")])
    with pytest.raises(RoutingError) as exc:
        bind_decision(good, dup.cards, planner_model="tiny-4b",
                      host_engine="fake")
    assert exc.value.code == MODEL_BINDING_UNVERIFIED


def test_secret_redaction_end_to_end() -> None:
    _, _, sink = _chain([_user("password=hunter2")])
    assert "hunter2" not in repr(sink.received)


def test_raw_observation_excluded() -> None:
    from openjarvis.agents.privacy_pipeline import minimize_context

    out, dropped = minimize_context(
        {"query": "q", "observation": "RAW", "tool_results": ["r"]},
        allow=("query",), purpose="t", max_items=8, max_bytes=2048)
    assert out == {"query": "q"}
    assert set(dropped) >= {"observation", "tool_results"}


def test_streaming_payload_safety() -> None:
    transport = FakeTransport()
    adapted, _ = adapt_provider_messages([_user("hi")])
    envelope = build_provider_envelope("tiny-4b", adapted)
    chunks = list(transport.stream(
        envelope, _decision(), chunks=("a", "b", "c")))
    assert "".join(chunks) == "abc"
    with pytest.raises(TransportError) as exc:
        list(transport.stream(
            envelope, _decision(), chunks=("a", "b"), interrupt_at=1))
    assert exc.value.code == STREAM_INTERRUPTED


def _decision():
    from openjarvis.agents.host_routing import EgressDecision

    return EgressDecision(True, "EGRESS_ALLOWED", "test")


def test_tool_call_stays_untrusted() -> None:
    response, _, _ = _chain(
        [_user("hi")],
        transport_kwargs={"content": "",
                          "tool_calls": [{"id": "c1", "name": "t",
                                          "arguments": "{}"}]})
    assert response["tool_calls"][0]["name"] == "t"
    assert response.get("verified", False) is False


def test_images_default_deny() -> None:
    adapted, dropped = adapt_provider_messages(
        [Message(role=Role.USER, content="see", images=["eA=="])])
    assert "images" not in adapted[0]
    assert dropped == ["images[0]"]


def test_provider_options_validated() -> None:
    transport = FakeTransport()
    adapted, _ = adapt_provider_messages([_user("hi")])
    envelope = build_provider_envelope("tiny-4b", adapted)
    out = transport.complete(envelope, _decision(),
                             options={"temperature": 0.0})
    assert out["content"] == ""
    with pytest.raises(TransportError) as exc:
        transport.complete(envelope, _decision(),
                           options={"__import__": True})
    assert exc.value.code == UNKNOWN_FIELD


def test_timeout() -> None:
    transport = FakeTransport()
    adapted, _ = adapt_provider_messages([_user("hi")])
    envelope = build_provider_envelope("tiny-4b", adapted)
    with pytest.raises(TransportError) as exc:
        transport.complete(envelope, _decision(), timeout_s=1.0,
                           latency_s=5.0, content="late")
    assert exc.value.code == TRANSPORT_TIMEOUT
    assert transport.calls == []


def test_cancellation() -> None:
    transport = FakeTransport()
    adapted, _ = adapt_provider_messages([_user("hi")])
    envelope = build_provider_envelope("tiny-4b", adapted)
    with pytest.raises(TransportError) as exc:
        transport.complete(envelope, _decision(), cancelled=True)
    assert exc.value.code == TRANSPORT_CANCELLED


def test_retry_isolation() -> None:
    transport = FakeTransport()
    adapted, _ = adapt_provider_messages([_user("hi")])
    envelope = build_provider_envelope("tiny-4b", adapted)
    out = transport.complete_with_retry(
        envelope, _decision(), retries=2, content="ok",
        fail_modes=("unavailable", "timeout"))
    assert out["content"] == "ok"
    assert transport.attempts == 3
    with pytest.raises(TransportError) as exc:
        transport.complete_with_retry(
            envelope, _decision(), retries=0, content="ok",
            fail_modes=("unavailable",))
    assert exc.value.code == TRANSPORT_UNAVAILABLE
    with pytest.raises(TransportError) as exc:
        transport.complete_with_retry(
            envelope, _denied(), retries=3, content="ok",
            fail_modes=())
    assert exc.value.code == EGRESS_DENIED
    assert transport.attempts == 1


def _denied():
    from openjarvis.agents.host_routing import EgressDecision

    return EgressDecision(False, "PRIVACY_BLOCKED", "test")


def test_fallback_policy() -> None:
    transport = FakeTransport()
    adapted, _ = adapt_provider_messages([_user("hi")])
    primary = build_provider_envelope("prose-70b", adapted)
    fallback = build_provider_envelope("tiny-4b", adapted)
    out = transport.complete_with_fallback(
        primary, _decision(), fallback, _decision(), content="fb",
        fail_modes=("unavailable",))
    assert out["content"] == "fb"
    with pytest.raises(TransportError) as exc:
        transport.complete_with_fallback(
            primary, _decision(), fallback, _denied(), content="fb",
            fail_modes=("unavailable",))
    assert exc.value.code == FALLBACK_MISMATCH


def test_retry_exhaustion() -> None:
    transport = FakeTransport()
    adapted, _ = adapt_provider_messages([_user("hi")])
    envelope = build_provider_envelope("tiny-4b", adapted)
    with pytest.raises(TransportError) as exc:
        transport.complete_with_retry(
            envelope, _decision(), retries=1, content="ok",
            fail_modes=("unavailable", "unavailable"))
    assert exc.value.code == RETRY_EXHAUSTED


def test_agent_and_snapshot_isolation() -> None:
    r1, _, _ = _chain([_user("one")],
                      transport_kwargs={"content": "r1"})
    r2, _, _ = _chain([_user("two")],
                      transport_kwargs={"content": "r2"})
    assert (r1["content"], r2["content"]) == ("r1", "r2")


def test_no_network_and_no_real_mutation() -> None:
    import ast
    from pathlib import Path

    import openjarvis.agents.fake_transport as ft

    src = ast.dump(ast.parse(Path(ft.__file__).read_text(encoding="utf-8")))
    for banned in ("httpx", "requests", "urllib", "socket", "subprocess",
                   "ToolExecutor"):
        assert banned not in src


def test_sealed_payload_identity() -> None:
    from openjarvis.agents.privacy_pipeline import (
        PipelineError,
        seal_authorized_envelope,
        verify_authorized_envelope,
    )

    transport = FakeTransport()
    adapted, _ = adapt_provider_messages([_user("hi")])
    envelope = build_provider_envelope("tiny-4b", adapted)
    sealed = seal_authorized_envelope(envelope, _decision())
    verify_authorized_envelope(sealed, envelope)
    out = transport.complete(envelope, _decision(), authorized=sealed,
                             content="ok")
    assert out["content"] == "ok"
    tampered = dict(envelope, model="other")
    with pytest.raises(PipelineError):
        verify_authorized_envelope(sealed, tampered)
    with pytest.raises(TransportError) as exc:
        transport.complete(tampered, _decision(), authorized=sealed)
    assert exc.value.code == "PAYLOAD_TAMPERED"
    assert len(transport.calls) == 1


def test_seal_refuses_denial() -> None:
    from openjarvis.agents.privacy_pipeline import (
        PipelineError,
        seal_authorized_envelope,
    )

    with pytest.raises(PipelineError):
        seal_authorized_envelope({"model": "m"}, _denied())


def test_retry_and_fallback_reauthorize() -> None:
    from openjarvis.agents.privacy_pipeline import seal_authorized_envelope

    transport = FakeTransport()
    adapted, _ = adapt_provider_messages([_user("hi")])
    primary = build_provider_envelope("prose-70b", adapted)
    fallback = build_provider_envelope("tiny-4b", adapted)
    pseal = seal_authorized_envelope(primary, _decision())
    fseal = seal_authorized_envelope(fallback, _decision())
    out = transport.complete_with_retry(
        primary, _decision(), retries=1, content="ok",
        fail_modes=("unavailable",), authorized=pseal)
    assert out["content"] == "ok"
    out = transport.complete_with_fallback(
        primary, _decision(), fallback, _decision(), content="fb",
        fail_modes=("unavailable",), primary_authorized=pseal,
        fallback_authorized=fseal)
    assert out["content"] == "fb"
    with pytest.raises(TransportError) as exc:
        transport.complete_with_fallback(
            primary, _decision(), fallback, _decision(), content="fb",
            fail_modes=("unavailable",), primary_authorized=pseal)
    assert exc.value.code == FALLBACK_MISMATCH
