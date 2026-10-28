"""Privacy pipeline proofs (offline, mock-only, fake sink).

Proves minimize -> redact -> validate -> authorize -> fake-deliver with
zero real transmission. The live egress path does not exist, so
CLOUD_EGRESS_BOUND stays non-PASS by design.
"""

from __future__ import annotations

import pytest

from openjarvis.agents.host_routing import HostEgressPolicy, ModelCardRegistry
from openjarvis.agents.privacy_pipeline import (
    FakeProviderSink,
    PipelineError,
    credential_url_rejected,
    minimize_context,
    redact_credentials,
    sanitize_for_egress,
)


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


def _raw():
    return {
        "query": "summarize the wiki page",
        "observation": "RAW TOOL OUTPUT WITH SECRET",
        "meta": {"source": "wiki", "api_key": "sk-live-123",
                 "nested": {"password": "hunter2", "keep": "yes"}},
        "headers": {"Authorization": "Bearer abc.def.ghi"},
        "extra_unknown": "drop me",
    }


def test_allowlisted_fields_only() -> None:
    out, dropped = minimize_context(
        _raw(), allow=("query", "meta.source", "meta.nested.keep"),
        purpose="test", max_items=8, max_bytes=2048)
    assert out == {"meta": {"nested": {"keep": "yes"}, "source": "wiki"},
                   "query": "summarize the wiki page"}
    assert "observation" in dropped and "extra_unknown" in dropped


def test_nested_secret_redaction() -> None:
    out, dropped = minimize_context(
        _raw(), allow=("query", "meta", "headers"), purpose="test",
        max_items=8, max_bytes=4096)
    clean, count = redact_credentials(out)
    assert clean["meta"]["api_key"] == "[REDACTED]"
    assert clean["meta"]["nested"]["password"] == "[REDACTED]"
    assert clean["meta"]["nested"]["keep"] == "yes"
    assert count == 3  # api_key, password, Authorization header


def test_authorization_and_bearer_removal() -> None:
    clean, _ = redact_credentials(
        {"headers": {"Authorization": "Bearer abc.def.ghi"},
         "note": "call Bearer xyz-9_8 now"})
    assert clean["headers"]["Authorization"] == "[REDACTED]"
    assert "xyz-9_8" not in clean["note"]


def test_credential_url_rejection() -> None:
    with pytest.raises(PipelineError) as exc:
        redact_credentials({"url": "https://user:s3cret@host/x"})
    assert exc.value.code == "CREDENTIAL_URL_REJECTED"
    assert credential_url_rejected("https://user:s3cret@host/x") is True
    assert credential_url_rejected("https://host/x") is False


def test_unsupported_object_rejection() -> None:
    with pytest.raises(PipelineError):
        minimize_context({"query": "q", "blob": object()},
                         allow=("query", "blob"), purpose="test",
                         max_items=8, max_bytes=2048)


def test_oversized_payload_rejection() -> None:
    with pytest.raises(PipelineError) as exc:
        minimize_context({"query": "x" * 5000}, allow=("query",),
                         purpose="test", max_items=8, max_bytes=100)
    assert exc.value.code == "PAYLOAD_OVERSIZED"


def test_raw_observation_excluded_by_default() -> None:
    out, _ = minimize_context({"query": "q", "observation": "raw",
                               "tool_results": ["r"]},
                              allow=("query",), purpose="test",
                              max_items=8, max_bytes=2048)
    assert out == {"query": "q"}


def test_input_immutability() -> None:
    raw = _raw()
    snapshot = repr(raw)
    minimize_context(raw, allow=("query", "meta"), purpose="test",
                     max_items=8, max_bytes=8192)
    redact_credentials(raw)
    assert repr(raw) == snapshot


def test_private_cloud_rejected() -> None:
    reg = ModelCardRegistry.from_host_config(_cards())
    with pytest.raises(PipelineError) as exc:
        sanitize_for_egress(
            _raw(), registry=reg, policy=_policy(), privacy="PRIVATE",
            provider="cloud", engine="fake", model="prose-70b",
            allow=("query",), purpose="test", sink=FakeProviderSink())
    assert exc.value.code == "PRIVACY_BLOCKED"


def test_internal_without_minimizer_rejected() -> None:
    from openjarvis.agents.privacy_pipeline import MinimizerEvidence

    reg = ModelCardRegistry.from_host_config(_cards())
    with pytest.raises(PipelineError) as exc:
        sanitize_for_egress(
            _raw(), registry=reg, policy=_policy(), privacy="INTERNAL",
            provider="cloud", engine="fake", model="prose-70b",
            allow=(), purpose="test", sink=FakeProviderSink(),
            evidence=MinimizerEvidence(verified=False))
    assert exc.value.code == "MINIMIZER_REQUIRED"


def test_internal_verified_pipeline_accepted() -> None:
    reg = ModelCardRegistry.from_host_config(_cards())
    sink = FakeProviderSink()
    out = sanitize_for_egress(
        _raw(), registry=reg, policy=_policy(), privacy="INTERNAL",
        provider="cloud", engine="fake", model="prose-70b",
        allow=("query", "meta.source"), purpose="test", sink=sink)
    assert out.decision.allowed is True
    assert sink.received[0]["payload"] == {
        "meta": {"source": "wiki"}, "query": "summarize the wiki page"}
    assert "sk-live-123" not in repr(sink.received)


def test_provider_mismatch_rejected() -> None:
    reg = ModelCardRegistry.from_host_config(_cards())
    with pytest.raises(PipelineError) as exc:
        sanitize_for_egress(
            _raw(), registry=reg, policy=_policy(), privacy="PUBLIC",
            provider="evil", engine="fake", model="prose-70b",
            allow=("query",), purpose="test", sink=FakeProviderSink())
    assert exc.value.code == "MODEL_BINDING_UNVERIFIED"


def test_fake_sink_receives_only_sanitized() -> None:
    reg = ModelCardRegistry.from_host_config(_cards())
    sink = FakeProviderSink()
    sanitize_for_egress(
        _raw(), registry=reg, policy=_policy(), privacy="PUBLIC",
        provider="cloud", engine="fake", model="prose-70b",
        allow=("query", "meta"), purpose="test", sink=sink)
    assert len(sink.received) == 1
    blob = repr(sink.received)
    assert "sk-live-123" not in blob and "hunter2" not in blob
    assert "abc.def.ghi" not in blob


def test_no_raw_secret_in_logs(caplog) -> None:
    import logging

    reg = ModelCardRegistry.from_host_config(_cards())
    with caplog.at_level(logging.DEBUG):
        sanitize_for_egress(
            _raw(), registry=reg, policy=_policy(), privacy="PUBLIC",
            provider="cloud", engine="fake", model="prose-70b",
            allow=("query", "meta"), purpose="test",
            sink=FakeProviderSink())
    assert "sk-live-123" not in caplog.text
    assert "hunter2" not in caplog.text


def test_missing_policy_rejected() -> None:
    reg = ModelCardRegistry.from_host_config(_cards())
    with pytest.raises(PipelineError) as exc:
        sanitize_for_egress(
            _raw(), registry=reg, policy=_policy(allow_cloud=False),
            privacy="INTERNAL", provider="cloud", engine="fake",
            model="prose-70b", allow=("query",), purpose="test",
            sink=FakeProviderSink())
    assert exc.value.code == "HOST_POLICY_DENIED"


def test_pipeline_failure_makes_zero_provider_calls() -> None:
    reg = ModelCardRegistry.from_host_config(_cards())
    sink = FakeProviderSink()
    with pytest.raises(PipelineError):
        sanitize_for_egress(
            _raw(), registry=reg, policy=_policy(), privacy="PRIVATE",
            provider="cloud", engine="fake", model="prose-70b",
            allow=("query",), purpose="test", sink=sink)
    assert sink.received == []


def test_agent_and_snapshot_isolation() -> None:
    reg = ModelCardRegistry.from_host_config(_cards())
    s1, s2 = FakeProviderSink(), FakeProviderSink()
    a = dict(_raw(), query="agent one")
    b = dict(_raw(), query="agent two")
    sanitize_for_egress(
        a, registry=reg, policy=_policy(), privacy="PUBLIC",
        provider="cloud", engine="fake", model="prose-70b",
        allow=("query",), purpose="t1", sink=s1)
    sanitize_for_egress(
        b, registry=reg, policy=_policy(), privacy="PUBLIC",
        provider="cloud", engine="fake", model="prose-70b",
        allow=("query",), purpose="t2", sink=s2)
    assert s1.received[0]["payload"] == {"query": "agent one"}
    assert s2.received[0]["payload"] == {"query": "agent two"}
