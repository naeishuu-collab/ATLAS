"""DispatchContract independent regression (offline, mock-only).

Proves the egress dispatch contract: only authorized, sealed payloads reach
the fake transport; retry/fallback each require their own seal; streaming
verifies the seal before the first chunk; tampered payloads are refused.
"""

from __future__ import annotations

import pytest

from openjarvis.agents.dispatch_contract import DispatchContract
from openjarvis.agents.fake_transport import (
    EGRESS_DENIED,
    FALLBACK_MISMATCH,
    FakeTransport,
    TransportError,
)
from openjarvis.agents.host_routing import (
    EgressDecision,
    HostEgressPolicy,
    ModelCardRegistry,
    build_snapshot,
)
from openjarvis.agents.privacy_pipeline import (
    PipelineError,
    seal_wire_envelope,
    verify_authorized_envelope,
)

ISSUED_AT = 1000.0


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


def _reg():
    return ModelCardRegistry.from_host_config(_cards())


def _policy(**over):
    args = {"allow_cloud": True, "allowed_providers": ("cloud",),
            "allow_raw_internal": False, "version": 1}
    args.update(over)
    return HostEgressPolicy(**args)


def _env(**over):
    args = {"status": {("fake", "local", "tiny-4b"): True},
            "version": 1, "issued_at": ISSUED_AT}
    args.update(over)
    return build_snapshot(**args)


def _allowed():
    return EgressDecision(True, "EGRESS_ALLOWED", "test")


def _denied():
    return EgressDecision(False, "PRIVACY_BLOCKED", "test")


def _payload(model="tiny-4b", **over):
    env = {"model": model,
           "messages": [{"role": "user", "content": "hi"}],
           "stream": False,
           "options": {"temperature": 0.0}}
    env.update(over)
    return env


def _seal(env):
    return seal_wire_envelope("ollama", env, _allowed())


def test_sealed_payload_reaches_fake_transport() -> None:
    transport = FakeTransport()
    contract = DispatchContract(transport)
    payload = _payload()
    sealed = _seal(payload)
    verify_authorized_envelope(sealed, payload)
    result = contract.dispatch(payload, _allowed(), authorized=sealed)
    assert result["content"] == ""
    assert len(transport.calls) == 1


def test_seal_refuses_denial() -> None:
    with pytest.raises(PipelineError):
        seal_wire_envelope("ollama", _payload(), _denied())


def test_tampered_payload_refused() -> None:
    transport = FakeTransport()
    contract = DispatchContract(transport)
    payload = _payload()
    sealed = _seal(payload)
    tampered = dict(payload, model="other-model")
    with pytest.raises(TransportError) as exc:
        contract.dispatch(tampered, _allowed(), authorized=sealed)
    assert exc.value.code == "PAYLOAD_TAMPERED"
    assert transport.calls == []


def test_denied_decision_no_dispatch() -> None:
    transport = FakeTransport()
    contract = DispatchContract(transport)
    with pytest.raises(TransportError) as exc:
        contract.dispatch(_payload(), _denied())
    assert exc.value.code == EGRESS_DENIED
    assert transport.calls == []


def test_missing_seal_no_dispatch() -> None:
    transport = FakeTransport()
    contract = DispatchContract(transport)
    with pytest.raises(TransportError) as exc:
        contract.dispatch(_payload(), _allowed())
    assert exc.value.code == EGRESS_DENIED
    assert transport.calls == []


def test_retry_re_authorizes_same_seal() -> None:
    transport = FakeTransport()
    contract = DispatchContract(transport)
    payload = _payload()
    sealed = _seal(payload)
    result = contract.dispatch_with_retry(
        payload, _allowed(), retries=1, content="ok",
        fail_modes=("unavailable",), authorized=sealed)
    assert result["content"] == "ok"
    assert transport.attempts == 2


def test_retry_without_seal_propagates_first_failure() -> None:
    transport = FakeTransport()
    contract = DispatchContract(transport)
    payload = _payload()
    # retries=0 → single attempt; transient failure propagates as-is.
    with pytest.raises(TransportError) as exc:
        contract.dispatch_with_retry(
            payload, _allowed(), retries=0,
            fail_modes=("unavailable",))
    assert exc.value.code == EGRESS_DENIED


def test_fallback_reauthorizes_with_separate_seal() -> None:
    transport = FakeTransport()
    contract = DispatchContract(transport)
    primary = _payload(model="prose-70b")
    fallback = _payload(model="tiny-4b")
    pseal = _seal(primary)
    fseal = _seal(fallback)
    result = contract.dispatch_with_fallback(
        primary, _allowed(), fallback, _allowed(), content="fb",
        fail_modes=("unavailable",), primary_authorized=pseal,
        fallback_authorized=fseal)
    assert result["content"] == "fb"


def test_fallback_without_seal_refused() -> None:
    transport = FakeTransport()
    contract = DispatchContract(transport)
    primary = _payload(model="prose-70b")
    fallback = _payload(model="tiny-4b")
    pseal = _seal(primary)
    with pytest.raises(TransportError) as exc:
        contract.dispatch_with_fallback(
            primary, _allowed(), fallback, _allowed(), content="fb",
            fail_modes=("unavailable",), primary_authorized=pseal)
    assert exc.value.code == FALLBACK_MISMATCH


def test_streaming_verifies_seal_before_first_chunk() -> None:
    transport = FakeTransport()
    contract = DispatchContract(transport)
    payload = _payload()
    sealed = _seal(payload)
    chunks = list(contract.stream_with_authorization(
        payload, _allowed(), chunks=("a", "b"), authorized=sealed))
    assert "".join(chunks) == "ab"
    # Unsealed/denied stream refuses before first chunk.
    with pytest.raises(TransportError) as exc:
        list(contract.stream_with_authorization(
            payload, _denied(), chunks=("a",)))
    assert exc.value.code == EGRESS_DENIED
    assert transport.calls == [] or all(
        c.get("stream") for c in transport.calls
    )
