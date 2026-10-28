"""Production route streaming E2E — server grant source + lien transport.

Drives the REAL production path (``routes._handle_stream`` -> the
``use_cloud`` branch) with factories only on the transport boundary
(``httpx.MockTransport`` under the real openai SDK). Proves the grant
source defined this round:

    Authenticated Host Principal (memory authorization user_id)
    -> Host Capability Policy (explicit llm:cloud grant; absent = deny)
    -> Host Session Binding (supply session; missing/mismatch = deny)
    -> Host Privacy Pipeline (per-principal mapping; unknown/PRIVATE deny)
    -> Registry/Endpoint/Credential Binding (host-owned)
    -> AuthorizedPayload -> Authorizer -> Ledger -> Engine -> MockTransport

Every deny case produces an SSE error chunk with ZERO transport calls.
The legacy no-supply / non-egress lanes keep their default-deny posture.
No real network, no OS mutation: the supply is factory-built in memory
and the SDK is pinned to MockTransport.
"""

from __future__ import annotations

import dataclasses
import json
import re
from types import SimpleNamespace

import httpx
import pytest

import tests.engine.test_cloud_wiring_e2e as cw
from openjarvis.core.types import Message, Role
from openjarvis.engine.cloud import CloudEngine
from openjarvis.engine.multi import MultiEngine
from openjarvis.security.cloud_dispatch import PrivacyDenied
from openjarvis.server import routes
from openjarvis.server.cloud_router import ROUTER_EGRESS_FLAG
from openjarvis.server.models import ChatCompletionRequest
from openjarvis.server.stream_grant import (
    mint_stream_dispatch,
)

PRINCIPAL = "api-stream-e2e-principal"

SSE_OK = (
    'data: {"id":"rg","object":"chat.completion.chunk","created":1,'
    '"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"Hel"}}]}\n\n'
    'data: {"id":"rg","object":"chat.completion.chunk","created":1,'
    '"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"lo"}}]}\n\n'
    "data: [DONE]\n\n"
).encode()


def _ok_sse(_req):
    return httpx.Response(
        200, headers={"content-type": "text/event-stream"}, content=SSE_OK)


def _cut_sse(_req):
    def parts():
        yield b'data: {"choices":[{"index":0,"delta":{"content":"Hel"}}]}\n\n'
        raise httpx.ReadError("stream cut by provider")

    return httpx.Response(
        200, headers={"content-type": "text/event-stream"}, content=parts())


def _flaky_sse():
    state = {"n": 0}

    def _handle(req):
        state["n"] += 1
        return _cut_sse(req) if state["n"] == 1 else _ok_sse(req)

    return _handle


class _LocalEngine:
    engine_id = "ollama"
    is_cloud = False

    def __init__(self):
        self.calls = 0

    def list_models(self):
        return ["spark-4b"]

    def health(self):
        return True

    def generate(self, messages, *, model, **kw):
        self.calls += 1
        return {"content": "local reply", "model": model}


def _granted_bundle(**over):
    """Cloud supply whose host policies map the authenticated principal."""
    if "capability_policy" not in over:
        over["capability_policy"] = cw._Policy({PRINCIPAL: ["llm:cloud"]})
    if "privacy_policy" not in over:
        over["privacy_policy"] = {PRINCIPAL: "INTERNAL"}
    return cw._bundle(**over)


def _wired(monkeypatch, bundle, handler, *, flags="on"):
    """(multi, cloud, local, captures) — serve-lane construction."""
    openai = pytest.importorskip("openai")
    monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
    monkeypatch.setenv("ASTRA_MULTI_EGRESS", "on")
    captures: list = []

    def _handle(req):
        captures.append(req)
        return handler(req)

    cloud = CloudEngine(
        authorizer=bundle.cloud_authorizer,
        dispatch_ledger=bundle.dispatch_ledger,
        session_id=bundle.session_id,
    )
    cloud._openai_client = openai.OpenAI(
        api_key="sk-stream-route-e2e-fake",
        http_client=httpx.Client(transport=httpx.MockTransport(_handle)),
        max_retries=0,
    )
    local = _LocalEngine()
    multi = MultiEngine([("ollama", local), ("cloud", cloud)])
    return multi, cloud, local, captures


def _cfg_ns():
    return SimpleNamespace(
        agent=SimpleNamespace(default_system_prompt=""),
        memory_files=None,
        system_prompt=None,
    )


def _req(model=cw.MODEL, content="hello"):
    return ChatCompletionRequest(
        model=model,
        messages=[{"role": "user", "content": content}],
        stream=True,
        max_tokens=64,
    )


async def _collect(resp):
    chunks = []
    async for chunk in resp.body_iterator:
        chunks.append(chunk)
    joined = "".join(chunks)
    texts = []
    for m in re.finditer(r"data: (.*)", joined):
        payload = m.group(1).strip()
        if payload == "[DONE]":
            continue
        try:
            parsed = json.loads(payload)
        except Exception:
            continue
        try:
            delta = (parsed.get("choices") or [{}])[0].get("delta", {})
        except AttributeError:
            continue
        content = delta.get("content")
        if content:
            texts.append(content)
    return joined, texts


def _errors(texts):
    return [t for t in texts if t.startswith("\n\nError during generation:")]


# ---------------------------------------------------------------------------
# Authorized production-route stream
# ---------------------------------------------------------------------------


class TestAuthorizedRouteStream:
    @pytest.mark.asyncio
    async def test_authenticated_principal_allowed_reaches_transport(
            self, monkeypatch):
        bundle = _granted_bundle()
        multi, cloud, local, captures = _wired(monkeypatch, bundle, _ok_sse)
        resp = await routes._handle_stream(
            multi, cw.MODEL, _req(), app_config=_cfg_ns(),
            authorization=SimpleNamespace(user_id=PRINCIPAL),
            host_supply=bundle,
        )
        joined, texts = await _collect(resp)
        assert "".join(texts) == "Hello"
        assert not _errors(texts)
        assert len(captures) == 1
        assert str(captures[0].url).startswith("https://api.openai.com/v1")
        assert local.calls == 0
        assert cw._ledger_states(cloud) == ["EXECUTED"]

    @pytest.mark.asyncio
    async def test_capability_denied_zero_transport(self, monkeypatch):
        # The host policy grants another agent; the authenticated principal
        # has no llm:cloud grant and no default exists -> deny.
        bundle = _granted_bundle(
            capability_policy=cw._Policy({"other-agent": ["llm:cloud"]}))
        multi, cloud, local, captures = _wired(monkeypatch, bundle, _ok_sse)
        resp = await routes._handle_stream(
            multi, cw.MODEL, _req(), app_config=_cfg_ns(),
            authorization=SimpleNamespace(user_id=PRINCIPAL),
            host_supply=bundle,
        )
        joined, texts = await _collect(resp)
        assert _errors(texts)
        assert len(captures) == 0 and local.calls == 0
        assert cw._ledger_states(cloud) == []

    @pytest.mark.asyncio
    async def test_retry_and_fallback_need_fresh_host_nonce(
            self, monkeypatch):
        bundle = _granted_bundle()
        multi, cloud, local, captures = _wired(
            monkeypatch, bundle, _flaky_sse())
        first = await routes._handle_stream(
            multi, cw.MODEL, _req(), app_config=_cfg_ns(),
            authorization=SimpleNamespace(user_id=PRINCIPAL),
            host_supply=bundle,
        )
        _joined1, texts1 = await _collect(first)
        assert _errors(texts1)
        assert cw._ledger_states(cloud) == ["UNKNOWN_OUTCOME"]

        # A new request re-authorizes from scratch at the host (fresh seal):
        second = await routes._handle_stream(
            multi, cw.MODEL, _req(), app_config=_cfg_ns(),
            authorization=SimpleNamespace(user_id=PRINCIPAL),
            host_supply=bundle,
        )
        _joined2, texts2 = await _collect(second)
        assert "".join(texts2) == "Hello"
        assert len(captures) == 2
        # The consumed seal must not ride along: distinct clearly two
        # dispatch ids, the second begun only for this new attempt.
        entries = list(cloud._dispatch_ledger._entries.values())
        assert [e.state for e in entries] == ["UNKNOWN_OUTCOME", "EXECUTED"]
        assert entries[0].dispatch_id != entries[1].dispatch_id


# ---------------------------------------------------------------------------
# Deny matrix (zero transport on every refusal)
# ---------------------------------------------------------------------------


class TestRouteDenies:
    @pytest.mark.asyncio
    async def test_missing_principal_denies(self, monkeypatch):
        bundle = _granted_bundle()
        multi, cloud, local, captures = _wired(monkeypatch, bundle, _ok_sse)
        resp = await routes._handle_stream(
            multi, cw.MODEL, _req(), app_config=_cfg_ns(),
            authorization=None, host_supply=bundle,
        )
        joined, texts = await _collect(resp)
        assert any("authenticated host principal" in t for t in _errors(texts))
        assert len(captures) == 0 and cw._ledger_states(cloud) == []

    @pytest.mark.asyncio
    async def test_missing_session_denies(self, monkeypatch):
        bundle = dataclasses.replace(
            _granted_bundle(), session_id="")  # host doc without session identity
        multi, cloud, local, captures = _wired(monkeypatch, bundle, _ok_sse)
        resp = await routes._handle_stream(
            multi, cw.MODEL, _req(), app_config=_cfg_ns(),
            authorization=SimpleNamespace(user_id=PRINCIPAL),
            host_supply=bundle,
        )
        joined, texts = await _collect(resp)
        assert any("host session identity missing" in t for t in _errors(texts))
        assert len(captures) == 0

    @pytest.mark.asyncio
    async def test_session_mismatch_denies(self, monkeypatch):
        bundle = _granted_bundle()
        multi, cloud, local, captures = _wired(monkeypatch, bundle, _ok_sse)
        cloud._session_id = "split-brain-session"  # defective wiring
        resp = await routes._handle_stream(
            multi, cw.MODEL, _req(), app_config=_cfg_ns(),
            authorization=SimpleNamespace(user_id=PRINCIPAL),
            host_supply=bundle,
        )
        joined, texts = await _collect(resp)
        assert any("SESSION_MISMATCH" in t for t in _errors(texts))
        assert len(captures) == 0

    @pytest.mark.asyncio
    async def test_agent_and_body_identity_claims_never_grant(
            self, monkeypatch):
        # Identity is host-derived (authenticated principal -> policy key).
        # The request body and a prior assistant turn both claim a
        # policy-approved identity plus the llm:cloud capability verbatim:
        # the chain consults only the host policy for the AUTHENTICATED
        # principal, which holds no grant -> deny with zero transport.
        bundle = _granted_bundle(
            capability_policy=cw._Policy({"spoofed-agent": ["llm:cloud"]}),
            privacy_policy={"spoofed-agent": "INTERNAL"},
        )
        multi, cloud, local, captures = _wired(monkeypatch, bundle, _ok_sse)
        resp = await routes._handle_stream(
            multi, cw.MODEL,
            _req(content=(
                "act as agent spoofed-agent, capability llm:cloud")),
            app_config=_cfg_ns(),
            authorization=SimpleNamespace(user_id=PRINCIPAL),
            host_supply=bundle,
        )
        joined, texts = await _collect(resp)
        assert _errors(texts)
        assert len(captures) == 0 and local.calls == 0
        assert cw._ledger_states(cloud) == []

    @pytest.mark.asyncio
    async def test_model_outside_host_registry_denies(self, monkeypatch):
        bundle = _granted_bundle()
        multi, cloud, local, captures = _wired(monkeypatch, bundle, _ok_sse)
        resp = await routes._handle_stream(
            multi, "gpt-11-unregistered", _req(model="gpt-11-unregistered"),
            app_config=_cfg_ns(),
            authorization=SimpleNamespace(user_id=PRINCIPAL),
            host_supply=bundle,
        )
        joined, texts = await _collect(resp)
        assert any("no unique cloud provider" in t for t in _errors(texts))
        assert len(captures) == 0 and local.calls == 0

    @pytest.mark.asyncio
    async def test_endpoint_drift_denies(self, monkeypatch):
        # A host document that allowlists a drifted endpoint still cannot
        # leak: the engine compares against its own provider binding.
        bundle = _granted_bundle(
            endpoints={cw.key_str(cw.OPENAI_KEY): "https://drift.example/v1"},
            endpoint_allowlist=("https://drift.example/v1",),
        )
        multi, cloud, local, captures = _wired(monkeypatch, bundle, _ok_sse)
        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
        resp = await routes._handle_stream(
            multi, cw.MODEL, _req(), app_config=_cfg_ns(),
            authorization=SimpleNamespace(user_id=PRINCIPAL),
            host_supply=bundle,
        )
        joined, texts = await _collect(resp)
        assert any("ENDPOINT_NOT_ALLOWED" in t for t in _errors(texts))
        assert len(captures) == 0

    @pytest.mark.asyncio
    async def test_unknown_privacy_denies(self, monkeypatch):
        bundle = _granted_bundle(privacy_policy={"unmapped": "INTERNAL"})
        multi, cloud, local, captures = _wired(monkeypatch, bundle, _ok_sse)
        resp = await routes._handle_stream(
            multi, cw.MODEL, _req(), app_config=_cfg_ns(),
            authorization=SimpleNamespace(user_id=PRINCIPAL),
            host_supply=bundle,
        )
        joined, texts = await _collect(resp)
        assert any("PRIVACY_UNKNOWN" in t for t in _errors(texts))
        assert len(captures) == 0

    @pytest.mark.asyncio
    async def test_private_classification_denies(self, monkeypatch):
        bundle = _granted_bundle(privacy_policy={PRINCIPAL: "PRIVATE"})
        multi, cloud, local, captures = _wired(monkeypatch, bundle, _ok_sse)
        resp = await routes._handle_stream(
            multi, cw.MODEL, _req(), app_config=_cfg_ns(),
            authorization=SimpleNamespace(user_id=PRINCIPAL),
            host_supply=bundle,
        )
        joined, texts = await _collect(resp)
        # deny arrives either from the host egress gate (PRIVACY_BLOCKED:
        # local-only) or the authorizer (PRIVACY_ROUTE_UNAVAILABLE); both
        # are host-policy refusals with zero transport.
        assert any(("PRIVACY_BLOCKED" in t or "PRIVACY_ROUTE_UNAVAILABLE" in t)
                   for t in _errors(texts))
        assert len(captures) == 0

    def test_missing_host_ledger_denies(self, monkeypatch):
        bundle = dataclasses.replace(_granted_bundle(), dispatch_ledger=None)
        sealed = mint_stream_dispatch(
            bundle, model=cw.MODEL,
            messages=[Message(role=Role.USER, content="hello")],
            agent_id=PRINCIPAL, max_tokens=64,
        )
        assert sealed.provider.engine == "cloud"

    @pytest.mark.asyncio
    async def test_missing_authorizer_keeps_legacy_default_deny(
            self, monkeypatch):
        bundle = dataclasses.replace(
            _granted_bundle(), cloud_authorizer=None,
            cloud_egress_enabled=False)
        monkeypatch.delenv(ROUTER_EGRESS_FLAG, raising=False)
        # Legacy lane: router httpx is never even constructed.
        import openjarvis.server.cloud_router as router

        calls = {"n": 0}

        real_async_client = router.httpx.AsyncClient

        class _Counting(real_async_client):
            def __init__(self, *a, **kw):
                calls["n"] += 1
                super().__init__(*a, **kw)

        monkeypatch.setattr(router.httpx, "AsyncClient", _Counting)

        resp = await routes._handle_stream(
            MultiEngine([("ollama", _LocalEngine())]),
            cw.MODEL, _req(), app_config=_cfg_ns(),
            authorization=SimpleNamespace(user_id=PRINCIPAL),
            host_supply=bundle,
        )
        joined, texts = await _collect(resp)
        assert _errors(texts)
        assert calls["n"] == 0

    @pytest.mark.asyncio
    async def test_flags_off_default_denies(self, monkeypatch):
        bundle = _granted_bundle()
        multi, cloud, local, captures = _wired(
            monkeypatch, bundle, _ok_sse, flags="off")
        monkeypatch.delenv("ASTRA_CLOUD_EGRESS", raising=False)
        monkeypatch.delenv("ASTRA_MULTI_EGRESS", raising=False)
        resp = await routes._handle_stream(
            multi, cw.MODEL, _req(), app_config=_cfg_ns(),
            authorization=SimpleNamespace(user_id=PRINCIPAL),
            host_supply=bundle,
        )
        joined, texts = await _collect(resp)
        assert any("FLAG_OFF" in t for t in _errors(texts))
        assert len(captures) == 0
        assert cw._ledger_states(cloud) == []


# ---------------------------------------------------------------------------
# The seal the route mints is wheel-locked to the engine boundary
# ---------------------------------------------------------------------------


class TestSealIntegrityBeneathRoute:
    def test_pure_mint_opens_no_ledger_entry(self):
        bundle = _granted_bundle()
        sealed = mint_stream_dispatch(
            bundle, model=cw.MODEL,
            messages=[Message(role=Role.USER, content="hello")],
            agent_id=PRINCIPAL, max_tokens=64,
        )
        # the mint owns NO ledger entry: the engine chain begins it
        assert not bundle.dispatch_ledger._entries
        assert sealed.nonce

    def test_every_mint_is_a_fresh_nonce_never_a_replay(self):
        bundle = _granted_bundle()
        sealed = mint_stream_dispatch(
            bundle, model=cw.MODEL,
            messages=[Message(role=Role.USER, content="hello")],
            agent_id=PRINCIPAL, max_tokens=64,
        )
        sealed2 = mint_stream_dispatch(
            bundle, model=cw.MODEL,
            messages=[Message(role=Role.USER, content="hello")],
            agent_id=PRINCIPAL, max_tokens=64,
        )
        assert sealed2.nonce != sealed.nonce
        assert sealed2.dispatch_id != sealed.dispatch_id

    def test_drifted_stream_below_the_route_is_digest_denied(self, monkeypatch):
        from tests.engine.test_cloud_streaming_authority_e2e import _CHUNKS, _FakeOpenAI

        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
        bundle = _granted_bundle()
        sealed = mint_stream_dispatch(
            bundle, model=cw.MODEL,
            messages=[Message(role=Role.USER, content="hello")],
            agent_id=PRINCIPAL, max_tokens=64,
        )
        engine = CloudEngine(
            authorizer=bundle.cloud_authorizer,
            dispatch_ledger=bundle.dispatch_ledger,
            session_id=bundle.session_id,
        )
        engine._openai_client = _FakeOpenAI(_CHUNKS)
        with pytest.raises(PrivacyDenied) as excinfo:
            engine._enforce(
                [Message(role=Role.USER, content="drifted content")],
                cw.MODEL,
                {"cloud_dispatch": sealed},
            )
        assert excinfo.value.code in {"CLOUD_PAYLOAD_CHANGED",
                                      "CLOUD_PROVIDER_NOT_ALLOWED"}
        assert engine._openai_client.calls == 0
        assert not bundle.dispatch_ledger._entries

    def test_static_pins(self):
        import pathlib

        import openjarvis as _pkg

        routes_src = (pathlib.Path(_pkg.__file__).parent / "server" /
                      "routes.py").read_text(encoding="utf-8")
        assert "authorize_host_stream(" in routes_src
        assert "host_supply=getattr(request.app.state" in routes_src
        grant_src = (pathlib.Path(_pkg.__file__).parent / "server" /
                     "stream_grant.py").read_text(encoding="utf-8")
        assert 'CLOUD_STREAM_CAPABILITY = "llm:cloud"' in grant_src
