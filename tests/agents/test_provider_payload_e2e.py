"""Provider payload boundary E2E (offline, mock-only, fake provider).

Grounded in the real path (Message -> messages_to_dicts ->
{model,messages,...} -> POST): the adapter mirrors the crossing fields,
and the fake provider enforces the same input contract. No real
transport is touched; CLOUD_EGRESS_BOUND stays non-PASS.
"""

from __future__ import annotations

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


def _msg(role, content, **kw):
    return Message(role=role, content=content, **kw)


def _send(messages, *, privacy="PUBLIC", provider="cloud",
          model="prose-70b", allow=("model", "messages"), sink=None,
          **kw):
    sink = sink if sink is not None else FakeProviderSink()
    adapted, dropped = adapt_provider_messages(messages, **kw)
    envelope = build_provider_envelope(model, adapted)
    out = deliver_to_fake(
        envelope, registry=ModelCardRegistry.from_host_config(_cards()),
        policy=_policy(), privacy=privacy, provider=provider,
        engine="fake", model=model, allow=allow, purpose="e2e", sink=sink)
    return out, dropped, sink


def test_message_secret_never_reaches_fake() -> None:
    out, _, sink = _send([_msg(Role.USER, "my api_key=sk-live-1")])
    assert out.payload["messages"][0]["content"] == (
        "my api_key=[REDACTED]")
    assert "sk-live-1" not in repr(sink.received)


def test_tool_arguments_redacted() -> None:
    from openjarvis.core.types import ToolCall

    msg = _msg(Role.ASSISTANT, "calling",
               tool_calls=[ToolCall(id="c1", name="t",
                                    arguments='{"password": "pw"}')])
    out, _, sink = _send([msg])
    args = out.payload["messages"][0]["tool_calls"][0]["function"]
    assert "pw" not in args["arguments"]
    assert "pw" not in repr(sink.received)


def test_images_dropped_by_default() -> None:
    msg = _msg(Role.USER, "see", images=["aGVsbG8="])
    out, dropped, _ = _send([msg])
    assert "images" not in out.payload["messages"][0]
    assert dropped == ["images[0]"]
    out2, _, _ = _send([msg], allow_images=True)
    assert out2.payload["messages"][0]["images"] == ["aGVsbG8="]


def test_unknown_role_rejected() -> None:
    class _Weird:
        value = "mystery"

    msg = _msg(_Weird(), "hi")
    with pytest.raises(PipelineError):
        adapt_provider_messages([msg])


def test_oversized_total_rejected_with_zero_calls() -> None:
    sink = FakeProviderSink()
    msgs = [_msg(Role.USER, "x" * 5000)]
    with pytest.raises(PipelineError) as exc:
        _send(msgs, sink=sink, max_total_bytes=100)
    assert exc.value.code == "PAYLOAD_OVERSIZED"
    assert sink.received == []


def test_unknown_privacy_stops() -> None:
    sink = FakeProviderSink()
    with pytest.raises(PipelineError) as exc:
        _send([_msg(Role.USER, "hi")], privacy="NOPE", sink=sink)
    assert exc.value.code == "PRIVACY_UNKNOWN"
    assert sink.received == []


def test_provider_mismatch_stops() -> None:
    sink = FakeProviderSink()
    with pytest.raises(PipelineError) as exc:
        _send([_msg(Role.USER, "hi")], provider="evil", sink=sink)
    assert exc.value.code == "MODEL_BINDING_UNVERIFIED"
    assert sink.received == []


def test_dangerous_allowlist_rejected() -> None:
    with pytest.raises(PipelineError) as exc:
        adapt_provider_messages([_msg(Role.USER, "hi")],
                                allow_fields=("role", "metadata"))
    assert exc.value.code == "INVALID_ALLOWLIST"


def test_unallowlisted_envelope_field_dropped() -> None:
    out, dropped, _ = _send([_msg(Role.USER, "hi")],
                            allow=("messages",))
    assert "model" not in out.payload
    assert out.dropped == ["model"]
    assert dropped == []
