"""Cloud streaming authority — offline E2E (engine lane + MultiEngine stream).

Proves the ASYNC streaming path enforces the same host boundary as
``generate()``:

    Host Supply -> Authorizer -> Ledger -> Session -> CloudEngine.stream()
    -> SDK transport (openai over httpx.MockTransport)

plus the E7 routing gate for ``MultiEngine.stream()``.

New this round — the ledger is now FAIL-CLOSED: an engine running
host-authorized dispatch (authorizer present) may never self-mint its
ledger; dispatch without a host-issued ledger is denied before any
transport call. The replaced fallback sat inside the authorized chain
(after ``verify_for_send``), so it could only ever create unauthorized
audit authority — there is no non-authorized caller of ``_enforce``.

Streaming-specific outcomes: partial streams are never EXECUTED
(mark_unknown), cancellation quarantines as UNKNOWN_OUTCOME, retries and
fallbacks require a FRESH host nonce (a consumed seal is replay-denied),
and a stream seal can never be reused across routes/providers.

Fake chunk-stream clients drive the enforcement matrix (no SDK needed);
the real openai SDK over ``httpx.MockTransport`` drives the
authorized-stream / partial-stream proofs. No real network, no OS
mutation beyond ``tmp_path``.
"""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

import httpx
import pytest

import tests.engine.test_cloud_wiring_e2e as cw
from openjarvis.core.types import Message, Role
from openjarvis.engine.cloud import CloudEngine
from openjarvis.engine.multi import MultiEngine
from openjarvis.security.cloud_dispatch import (
    BudgetReservation,
    CloudDispatchRequest,
    ExplicitGrant,
    PrivacyClassification,
    PrivacyDenied,
    ProviderIdentity,
)
from openjarvis.security.dispatch_ledger import CloudDispatchLedger
from tests.engine._cloud_auth import arm_engine

SSE = (
    'data: {"id":"cs","object":"chat.completion.chunk","created":1,'
    '"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Hel"}}]}\n\n'
    'data: {"id":"cs","object":"chat.completion.chunk","created":1,'
    '"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"lo"}}]}\n\n'
    "data: [DONE]\n\n"
).encode()


def _ok_sse(_req):
    return httpx.Response(
        200, headers={"content-type": "text/event-stream"}, content=SSE)


def _cut_sse(_req):
    def parts():
        yield b'data: {"choices":[{"index":0,"delta":{"content":"Hel"}}]}\n\n'
        raise httpx.ReadError("stream cut by provider")

    return httpx.Response(
        200, headers={"content-type": "text/event-stream"}, content=parts())


def _flaky_sse():
    """First attempt: transport dies mid-stream; later attempts: clean SSE."""
    state = {"n": 0}

    def _handle(req):
        state["n"] += 1
        return _cut_sse(req) if state["n"] == 1 else _ok_sse(req)

    return _handle


class _FakeOpenAI:
    """Minimal chunk-stream client: create() returns a chunk iterable."""

    def __init__(self, chunks=(), *, error_at=None):
        self._chunks = list(chunks)
        self._error_at = error_at
        self.calls = 0
        self.last_kwargs: dict = {}

    def _create(self, **kw):
        self.calls += 1
        self.last_kwargs = kw
        if self._error_at is not None and self.calls == self._error_at[0]:
            raise self._error_at[1]
        return iter(self._chunks)

    @property
    def chat(self):
        return SimpleNamespace(
            completions=SimpleNamespace(create=self._create))


def _mk_fake_engine(monkeypatch, *, session="", flag=True):
    """Engine-lane engine with a fake chunk client (no SDK)."""
    if flag:
        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
    else:
        monkeypatch.delenv("ASTRA_CLOUD_EGRESS", raising=False)
    engine = CloudEngine()
    arm_engine(engine, session=session)
    return engine


def _mint(engine, model, messages, *, session="",
          classification=PrivacyClassification.INTERNAL,
          endpoint=None, nonce=None):
    """Mint a sealed payload from this engine's own harness authorizer."""
    from openjarvis.engine._base import messages_to_dicts

    authz = engine._authorizer
    provider_name, resolved_ep = engine._resolve_provider(model)
    authz._allowlist = frozenset({("cloud", provider_name, model)})
    wire = messages_to_dicts(messages)
    return authz.authorize(CloudDispatchRequest(
        classification=classification,
        provider=ProviderIdentity(
            engine="cloud", provider=provider_name, model=model,
            is_cloud=True, endpoint=endpoint or resolved_ep),
        messages=tuple(
            {"role": str(m.get("role", "user")), "content": str(m.get("content", ""))}
            for m in wire),
        grant=ExplicitGrant(agent_id="host", capability="llm:cloud"),
        budget=BudgetReservation(
            est_prompt_tokens=64, max_tokens=128, ctx_limit=8192),
        session_id=session,
        nonce=nonce or f"s-{uuid.uuid4().hex}",
    ))


def _states(engine):
    return [e.state for e in engine._dispatch_ledger._entries.values()]


async def _collect(agen):
    out = []
    async for token in agen:
        out.append(token)
    return out


def _drain(agen):
    return asyncio.run(_collect(agen))


def _drain_cancel(agen):
    async def _go():
        out = [await agen.__anext__()]
        await agen.aclose()
        return out
    return asyncio.run(_go())


_CHUNKS = (
    SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="Hel"))]),
    SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="lo"))]),
)


class _LocalEngine:
    engine_id = "ollama"

    def __init__(self):
        self.calls = 0

    def list_models(self):
        return ["spark-4b"]

    def health(self):
        return True

    def generate(self, messages, *, model, **kw):
        self.calls += 1
        return {"content": "local reply", "model": model}


def _wired_multi(monkeypatch, handler):
    """(cloud, multi, local, captured, bundle): serve-lane supply wiring."""
    openai = pytest.importorskip("openai")
    bundle = cw._bundle()
    monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
    monkeypatch.setenv("ASTRA_WIRING_E2E_KEY", "sk-stream-e2e-fake")
    captured: list = []

    cloud = CloudEngine(
        authorizer=bundle.cloud_authorizer,
        dispatch_ledger=bundle.dispatch_ledger,
        session_id=bundle.session_id,
    )
    cloud._openai_client = openai.OpenAI(
        api_key="sk-stream-e2e-fake",
        http_client=httpx.Client(transport=httpx.MockTransport(
            lambda req: captured.append(req) or handler(req))),
        max_retries=0,
    )
    local = _LocalEngine()
    multi = MultiEngine([("ollama", local), ("cloud", cloud)])
    return cloud, multi, local, captured, bundle


# ---------------------------------------------------------------------------
# Engine lane: CloudEngine.stream() host boundary
# ---------------------------------------------------------------------------


class TestEngineStreamAuthorized:
    def test_authorized_stream_sdk_sse_exactly_once(self, monkeypatch):
        bundle = cw._bundle()
        engine, captured = cw._wired_engine(monkeypatch, bundle, _ok_sse)
        out = _drain(engine.stream(cw._msgs("hello"), model=cw.MODEL,
                                   cloud_dispatch=cw._seal(bundle)))
        assert "".join(out) == "Hello"
        assert len(captured) == 1 and str(captured[0].url).startswith(cw.OPENAI_EP)
        assert cw._ledger_states(engine) == ["EXECUTED"]

    def test_authorized_stream_fake_chunks(self, monkeypatch):
        engine = _mk_fake_engine(monkeypatch, session="sess-1")
        engine._openai_client = _FakeOpenAI(_CHUNKS)
        out = _drain(engine.stream([Message(role=Role.USER, content="hi")],
                                   model=cw.MODEL,
                                   cloud_dispatch=_mint(engine, cw.MODEL,
                                                        cw._msgs("hi"),
                                                        session="sess-1")))
        assert out == ["Hel", "lo"]
        assert engine._openai_client.calls == 1
        assert _states(engine) == ["EXECUTED"]


class TestEngineStreamDenies:
    def test_missing_ledger_is_fail_closed(self, monkeypatch):
        engine = _mk_fake_engine(monkeypatch, session="sess-1")
        engine._openai_client = _FakeOpenAI(_CHUNKS)
        engine._dispatch_ledger = None
        sealed = _mint(engine, cw.MODEL, cw._msgs("hi"), session="sess-1")
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(engine.stream(cw._msgs("hi"), model=cw.MODEL,
                                 cloud_dispatch=sealed))
        assert excinfo.value.code == "CLOUD_PROVIDER_NOT_ALLOWED"
        assert "host dispatch ledger not configured" in str(excinfo.value)
        assert engine._openai_client.calls == 0
        # the engine must NOT have self-minted a ledger
        assert getattr(engine, "_dispatch_ledger", None) is None

    def test_missing_authorizer_deny(self, monkeypatch):
        engine = _mk_fake_engine(monkeypatch)
        engine._authorizer = None
        engine._dispatch_ledger = CloudDispatchLedger()
        engine._openai_client = _FakeOpenAI(_CHUNKS)
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(engine.stream(cw._msgs("hello"), model=cw.MODEL,
                                 cloud_dispatch=None))
        assert excinfo.value.code == "NO_GRANT"
        assert engine._openai_client.calls == 0

    def test_cloud_flag_off_deny(self, monkeypatch):
        engine = _mk_fake_engine(monkeypatch, flag=False)
        engine._openai_client = _FakeOpenAI(_CHUNKS)
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(engine.stream(cw._msgs("hello"), model=cw.MODEL))
        assert excinfo.value.code == "FLAG_OFF"
        assert engine._openai_client.calls == 0

    def test_unsealed_stream_deny(self, monkeypatch):
        engine = _mk_fake_engine(monkeypatch)
        engine._openai_client = _FakeOpenAI(_CHUNKS)
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(engine.stream(cw._msgs("hello"), model=cw.MODEL))
        assert excinfo.value.code == "NO_GRANT"
        assert engine._openai_client.calls == 0

    def test_session_mismatch_deny(self, monkeypatch):
        engine = _mk_fake_engine(monkeypatch, session="sess-1")
        engine._openai_client = _FakeOpenAI(_CHUNKS)
        sealed = _mint(engine, cw.MODEL, cw._msgs("hi"), session="sess-1")
        engine._session_id = "other-session"   # split-brain session binding
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(engine.stream(cw._msgs("hi"), model=cw.MODEL,
                                 cloud_dispatch=sealed))
        assert excinfo.value.code == "SESSION_MISMATCH"
        assert engine._openai_client.calls == 0

    def test_provider_mismatch_deny(self, monkeypatch):
        engine = _mk_fake_engine(monkeypatch)
        engine._openai_client = _FakeOpenAI(_CHUNKS)
        sealed = _mint(engine, cw.MODEL, cw._msgs("hi"))
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(engine.stream(cw._msgs("hi"), model="claude-3-5-sonnet-20241022",
                                 cloud_dispatch=sealed))
        assert excinfo.value.code == "CLOUD_PROVIDER_NOT_ALLOWED"
        assert engine._openai_client.calls == 0

    def test_endpoint_binding_deny(self, monkeypatch):
        engine = _mk_fake_engine(monkeypatch)
        engine._openai_client = _FakeOpenAI(_CHUNKS)
        sealed = _mint(engine, cw.MODEL, cw._msgs("hi"),
                       endpoint="https://attacker.example/v1")
        from openjarvis.security.cloud_dispatch import ENDPOINT_NOT_ALLOWED

        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(engine.stream(cw._msgs("hi"), model=cw.MODEL,
                                 cloud_dispatch=sealed))
        assert excinfo.value.code == ENDPOINT_NOT_ALLOWED
        assert engine._openai_client.calls == 0

    def test_tampered_payload_deny(self, monkeypatch):
        engine = _mk_fake_engine(monkeypatch)
        engine._openai_client = _FakeOpenAI(_CHUNKS)
        sealed = _mint(engine, cw.MODEL, cw._msgs("hello"))
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(engine.stream(cw._msgs("injected payload"), model=cw.MODEL,
                                 cloud_dispatch=sealed))
        assert excinfo.value.code in {"CLOUD_PAYLOAD_CHANGED",
                                      "CLOUD_PROVIDER_NOT_ALLOWED"}
        assert engine._openai_client.calls == 0

    def test_nonce_replay_deny(self, monkeypatch):
        engine = _mk_fake_engine(monkeypatch, session="sess-1")
        engine._openai_client = _FakeOpenAI(_CHUNKS)
        sealed = _mint(engine, cw.MODEL, cw._msgs("hi"), session="sess-1")
        assert _drain(engine.stream(cw._msgs("hi"), model=cw.MODEL,
                                    cloud_dispatch=sealed)) == ["Hel", "lo"]
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(engine.stream(cw._msgs("hi"), model=cw.MODEL,
                                 cloud_dispatch=sealed))
        assert excinfo.value.code == "NONCE_REPLAY"
        assert engine._openai_client.calls == 1
        assert _states(engine) == ["EXECUTED"]

    def test_private_and_unknown_privacy_never_mint(self, monkeypatch):
        engine = _mk_fake_engine(monkeypatch)
        engine._openai_client = _FakeOpenAI(_CHUNKS)
        with pytest.raises(PrivacyDenied) as excinfo_private:
            _mint(engine, cw.MODEL, cw._msgs("hi"),
                  classification=PrivacyClassification.PRIVATE)
        assert excinfo_private.value.code == "PRIVACY_ROUTE_UNAVAILABLE"
        with pytest.raises(PrivacyDenied) as excinfo_none:
            _mint(engine, cw.MODEL, cw._msgs("hi"), classification=None)
        assert excinfo_none.value.code == "PRIVACY_CLASSIFICATION_REQUIRED"
        assert engine._openai_client.calls == 0


class TestEngineStreamOutcomes:
    def test_partial_stream_never_executed(self, monkeypatch):
        bundle = cw._bundle()
        engine, captured = cw._wired_engine(monkeypatch, bundle, _cut_sse)
        with pytest.raises(Exception):
            _drain(engine.stream(cw._msgs("hello"), model=cw.MODEL,
                                 cloud_dispatch=cw._seal(bundle)))
        assert len(captured) == 1
        assert cw._ledger_states(engine) == ["UNKNOWN_OUTCOME"]

    def test_cancellation_is_unknown(self, monkeypatch):
        bundle = cw._bundle()
        engine, _captured = cw._wired_engine(monkeypatch, bundle, _ok_sse)
        agen = engine.stream(cw._msgs("hello"), model=cw.MODEL,
                             cloud_dispatch=cw._seal(bundle))
        assert _drain_cancel(agen) == ["Hel"]
        assert cw._ledger_states(engine) == ["UNKNOWN_OUTCOME"]

    def test_retry_needs_fresh_authorization(self, monkeypatch):
        bundle = cw._bundle()
        engine, captured = cw._wired_engine(monkeypatch, bundle, _flaky_sse())
        first = cw._seal(bundle)
        with pytest.raises(Exception):
            _drain(engine.stream(cw._msgs("hello"), model=cw.MODEL,
                                 cloud_dispatch=first))
        assert cw._ledger_states(engine) == ["UNKNOWN_OUTCOME"]
        # same seal again: denied before any new contact
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(engine.stream(cw._msgs("hello"), model=cw.MODEL,
                                 cloud_dispatch=first))
        assert excinfo.value.code in {"NONCE_REPLAY", "CLOUD_PAYLOAD_CHANGED"}
        # fresh host authorization (new nonce) => new attempt EXECUTED
        fresh = cw._seal(bundle)
        out = _drain(engine.stream(cw._msgs("hello"), model=cw.MODEL,
                                   cloud_dispatch=fresh))
        assert out == ["Hel", "lo"]
        assert len(captured) == 2
        assert cw._ledger_states(engine) == ["UNKNOWN_OUTCOME", "EXECUTED"]

    def test_shadow_supply_never_streams(self, monkeypatch):
        # A shadow-only supply mints no cloud authority: streaming through
        # its engine cannot even reach the transport.
        bundle = cw._bundle(mode=cw.MODE_SHADOW_ONLY, cloud_egress_enabled=False)
        assert bundle.cloud_authorizer is None
        engine = _mk_fake_engine(monkeypatch)
        engine._openai_client = _FakeOpenAI(_CHUNKS)
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(engine.stream(cw._msgs("hello"), model=cw.MODEL))
        assert excinfo.value.code == "NO_GRANT"
        assert engine._openai_client.calls == 0


# ---------------------------------------------------------------------------
# MultiEngine.stream(): E7 routing gate over streaming
# ---------------------------------------------------------------------------


class TestMultiStream:
    def test_multi_flag_off_blocks_stream(self, monkeypatch):
        cloud, multi, local, captured, _bundle = _wired_multi(
            monkeypatch, _ok_sse)
        monkeypatch.delenv("ASTRA_MULTI_EGRESS", raising=False)
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(multi.stream(cw._msgs("hello"), model="spark-4b"))
        assert excinfo.value.code == "FLAG_OFF"
        assert local.calls == 0 and captured == []

    def test_multi_stream_no_seal_denied(self, monkeypatch):
        cloud, multi, local, captured, _bundle = _wired_multi(
            monkeypatch, _ok_sse)
        monkeypatch.setenv("ASTRA_MULTI_EGRESS", "on")
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(multi.stream(cw._msgs("hello"), model="spark-4b"))
        assert excinfo.value.code == "NO_GRANT"
        assert local.calls == 0 and captured == []

    def test_multi_stream_authorized_cloud(self, monkeypatch):
        cloud, multi, local, captured, bundle = _wired_multi(
            monkeypatch, _ok_sse)
        monkeypatch.setenv("ASTRA_MULTI_EGRESS", "on")
        out = _drain(multi.stream(cw._msgs("hello"), model=cw.MODEL,
                                  cloud_dispatch=cw._seal(bundle)))
        assert out == ["Hel", "lo"]
        assert local.calls == 0
        assert len(captured) == 1
        assert cw._ledger_states(cloud) == ["EXECUTED"]

    def test_multi_stream_cross_engine_seal_reuse_denied(self, monkeypatch):
        cloud, multi, local, captured, bundle = _wired_multi(
            monkeypatch, _ok_sse)
        monkeypatch.setenv("ASTRA_MULTI_EGRESS", "on")
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(multi.stream(cw._msgs("hello"), model="spark-4b",
                                cloud_dispatch=cw._seal(bundle)))
        assert excinfo.value.code == "CLOUD_PROVIDER_NOT_ALLOWED"
        assert local.calls == 0 and captured == []

    def test_multi_stream_fallback_needs_fresh_seal(self, monkeypatch):
        # After a failed cloud stream, the local fallback cannot ride the
        # consumed cloud authorization; a fresh attempt still needs its own
        # host authorization (none exists for the local fake: denied).
        cloud, multi, local, captured, bundle = _wired_multi(
            monkeypatch, _cut_sse)
        monkeypatch.setenv("ASTRA_MULTI_EGRESS", "on")
        first = cw._seal(bundle)
        with pytest.raises(Exception):
            _drain(multi.stream(cw._msgs("hello"), model=cw.MODEL,
                                cloud_dispatch=first))
        assert cw._ledger_states(cloud) == ["UNKNOWN_OUTCOME"]
        with pytest.raises(PrivacyDenied) as excinfo:
            _drain(multi.stream(cw._msgs("hello"), model="spark-4b",
                                cloud_dispatch=first))
        assert excinfo.value.code == "CLOUD_PROVIDER_NOT_ALLOWED"
        with pytest.raises(PrivacyDenied) as excinfo2:
            _drain(multi.stream(cw._msgs("hello"), model=cw.MODEL,
                                cloud_dispatch=first))
        assert excinfo2.value.code in {"NONCE_REPLAY", "CLOUD_PAYLOAD_CHANGED"}
        assert local.calls == 0
        assert len(captured) == 1
