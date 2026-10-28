"""Egress seal hardening (offline, mock-only, fake sinks).

Covers the complete wire envelope, post-authorization mutation,
retry/fallback/streaming re-authorization, and provider-specific
rejection. Real-adapter items live in test_ollama_privacy_conformance.
"""

from __future__ import annotations

import pytest

from openjarvis.agents.fake_transport import (
    FakeTransport,
    TransportError,
)
from openjarvis.agents.host_routing import EgressDecision
from openjarvis.agents.privacy_pipeline import (
    PipelineError,
    seal_wire_envelope,
    verify_authorized_envelope,
)


def _allowed():
    return EgressDecision(True, "EGRESS_ALLOWED", "test")


def _denied():
    return EgressDecision(False, "PRIVACY_BLOCKED", "test")


def _wire(**over):
    envelope = {"model": "tiny-4b",
                "messages": [{"role": "user", "content": "hi"}],
                "stream": False,
                "options": {"temperature": 0.0},
                "tools": [{"type": "function"}]}
    envelope.update(over)
    return envelope


def test_complete_envelope_seal() -> None:
    sealed = seal_wire_envelope("ollama", _wire(), _allowed())
    verify_authorized_envelope(sealed, _wire())
    assert sealed.model == "tiny-4b"


def test_unknown_wire_field_rejected() -> None:
    with pytest.raises(PipelineError) as exc:
        seal_wire_envelope("ollama", _wire(top_p=1.0), _allowed())
    assert exc.value.code == "UNKNOWN_FIELD"


def test_unknown_engine_schema_rejected() -> None:
    with pytest.raises(PipelineError) as exc:
        seal_wire_envelope("mystery-engine", _wire(), _allowed())
    assert exc.value.code == "MODEL_BINDING_UNVERIFIED"


def test_post_auth_mutation_rejected() -> None:
    sealed = seal_wire_envelope("ollama", _wire(), _allowed())
    transport = FakeTransport()
    with pytest.raises(TransportError) as exc:
        transport.complete(_wire(stream=True), _allowed(),
                           authorized=sealed)
    assert exc.value.code == "PAYLOAD_TAMPERED"
    assert transport.calls == []


def test_seal_refuses_denial() -> None:
    with pytest.raises(PipelineError):
        seal_wire_envelope("ollama", _wire(), _denied())


def test_timeout_retry_reauthorizes() -> None:
    transport = FakeTransport()
    sealed = seal_wire_envelope("ollama", _wire(), _allowed())
    out = transport.complete_with_retry(
        _wire(), _allowed(), retries=1, content="ok",
        fail_modes=("timeout",), authorized=sealed)
    assert out["content"] == "ok"
    assert transport.attempts == 2


def test_model_and_engine_fallback_reauthorize() -> None:
    transport = FakeTransport()
    primary = _wire(model="prose-70b")
    fallback = _wire(model="tiny-4b")
    pseal = seal_wire_envelope("ollama", primary, _allowed())
    fseal = seal_wire_envelope("ollama", fallback, _allowed())
    out = transport.complete_with_fallback(
        primary, _allowed(), fallback, _allowed(), content="fb",
        fail_modes=("unavailable",), primary_authorized=pseal,
        fallback_authorized=fseal)
    assert out["content"] == "fb"
    with pytest.raises(TransportError) as exc:
        transport.complete_with_fallback(
            primary, _allowed(), dict(fallback, model="other"),
            _allowed(), content="fb", fail_modes=("unavailable",),
            primary_authorized=pseal, fallback_authorized=fseal)
    assert exc.value.code == "PAYLOAD_TAMPERED"


def test_streaming_start_requires_authorization() -> None:
    transport = FakeTransport()
    sealed = seal_wire_envelope("ollama", _wire(), _allowed())
    chunks = list(transport.stream(
        _wire(), _allowed(), chunks=("a", "b"), authorized=sealed))
    assert "".join(chunks) == "ab"
    with pytest.raises(TransportError) as exc:
        list(transport.stream(
            _wire(), _denied(), chunks=("a",)))
    assert exc.value.code == "EGRESS_DENIED"


def test_streaming_interruption_is_failure() -> None:
    from openjarvis.agents.fake_transport import STREAM_INTERRUPTED

    transport = FakeTransport()
    seen = []
    with pytest.raises(TransportError) as exc:
        for chunk in transport.stream(
                _wire(), _allowed(), chunks=("a", "b"),
                interrupt_at=1):
            seen.append(chunk)
    assert exc.value.code == STREAM_INTERRUPTED
    assert seen == ["a"]  # partial text is never a complete response


def test_streaming_cancel() -> None:
    from openjarvis.agents.fake_transport import TRANSPORT_CANCELLED

    transport = FakeTransport()
    with pytest.raises(TransportError) as exc:
        list(transport.stream(_wire(), _allowed(), chunks=("a",),
                              cancelled=True))
    assert exc.value.code == TRANSPORT_CANCELLED
    assert transport.calls == []


def test_duplicate_dispatch_belongs_to_managed_layer() -> None:
    """Transports do not dedupe: exactly-once is the managed journal's
    job (see managed E2E). Both sends are recorded here."""
    transport = FakeTransport()
    sealed = seal_wire_envelope("ollama", _wire(), _allowed())
    transport.complete(_wire(), _allowed(), authorized=sealed, content="a")
    transport.complete(_wire(), _allowed(), authorized=sealed, content="a")
    assert len(transport.calls) == 2


def test_no_network_no_os_mutation() -> None:
    import ast
    from pathlib import Path

    import openjarvis.agents.fake_transport as ft
    import openjarvis.agents.privacy_pipeline as pp

    for mod in (ft, pp):
        src = ast.dump(ast.parse(
            Path(mod.__file__).read_text(encoding="utf-8")))
        for banned in ("httpx", "requests", "urllib", "socket",
                       "subprocess", "os.", "open("):
            assert banned not in src, (mod.__name__, banned)
