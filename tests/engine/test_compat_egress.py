"""E4: OpenAI-compatible family enforcement — MockTransport only."""

from __future__ import annotations

import asyncio
import json
import threading
import time

import httpx
import pytest

from openjarvis.core.types import Message, Role
from openjarvis.engine._base import EngineConnectionError
from openjarvis.engine.openai_compat_engines import LlamaCppEngine
from openjarvis.security.cloud_dispatch import (
    BudgetReservation,
    CloudDispatchAuthorizer,
    CloudDispatchRequest,
    ExplicitGrant,
    PrivacyClassification,
    PrivacyDenied,
    ProviderIdentity,
)
from openjarvis.security.dispatch_ledger import (
    STATE_EXECUTED,
    STATE_FAILED,
    STATE_UNKNOWN_OUTCOME,
    CloudDispatchLedger,
)

HOST = "http://testhost:8080"
MODEL = "qwen3:8b"
SSE = (
    'data: {"choices": [{"delta": {"content": "hi"}}]}\n\n'
    "data: [DONE]\n\n"
).encode()


class _Scanner:
    def scan(self, text: str):  # noqa: D102
        from types import SimpleNamespace

        return SimpleNamespace(findings=[])

    def redact(self, text: str):  # noqa: D102
        return text


class _FakePolicy:
    def __init__(self, grants: dict) -> None:
        self._grants = grants

    def list_agents(self):  # noqa: D102
        return list(self._grants)

    def list_grants(self, agent_id):  # noqa: D102
        from types import SimpleNamespace

        return [SimpleNamespace(capability=c) for c in self._grants.get(agent_id, [])]

    def check(self, agent_id, capability, resource=""):  # noqa: D102
        return capability in self._grants.get(agent_id, [])


def _authz(**kw):
    base = {
        "allowlist": {("llamacpp", "llamacpp", MODEL)},
        "scanners": [_Scanner()],
        "capability_policy": _FakePolicy({"host": ["llm:cloud"]}),
        "allowed_endpoints": frozenset({HOST}),
    }
    base.update(kw)
    return CloudDispatchAuthorizer(**base)


def _sealed(authz, session="sess-1", nonce=None, **kw):
    base = {
        "classification": PrivacyClassification.INTERNAL,
        "provider": ProviderIdentity(
            engine="llamacpp", provider="llamacpp", model=MODEL, endpoint=HOST
        ),
        "messages": ({"role": "user", "content": "hello"},),
        "grant": ExplicitGrant(
            agent_id="host", capability="llm:cloud", expires_at=time.time() + 600
        ),
        "budget": BudgetReservation(est_prompt_tokens=2, max_tokens=8, ctx_limit=64),
        "session_id": session,
        "nonce": nonce or f"n-{time.time_ns()}",
    }
    base.update(kw)
    return authz.authorize(CloudDispatchRequest(**base))


def _ok_body():
    return {
        "choices": [{"message": {"content": "compat reply"}}],
        "model": MODEL,
        "usage": {"prompt_tokens": 2, "completion_tokens": 2},
    }


def _engine(authz, handler, session="sess-1"):
    eng = LlamaCppEngine(
        host=HOST, authorizer=authz,
        dispatch_ledger=CloudDispatchLedger(), session_id=session,
    )
    mock = httpx.MockTransport(handler)
    eng._client = httpx.Client(transport=mock, base_url=HOST)
    eng._async_transport = mock
    return eng


def _msgs():
    return [Message(role=Role.USER, content="hello")]


def _ok(req: httpx.Request) -> httpx.Response:
    assert req.url.path == "/v1/chat/completions"
    return httpx.Response(200, json=_ok_body())


def _run(coro):
    import asyncio as _aio
    import inspect

    async def _drive():
        if inspect.isasyncgen(coro):
            return [t async for t in coro]
        return await coro

    return _aio.run(_drive())


class TestFlagAndGrant:
    @pytest.mark.parametrize("value", [None, "off", "ON", ""])
    def test_flag_states_deny(self, monkeypatch, value) -> None:
        if value is None:
            monkeypatch.delenv("ASTRA_COMPAT_EGRESS", raising=False)
        else:
            monkeypatch.setenv("ASTRA_COMPAT_EGRESS", value)
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok(r))[1])
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert seen == []

    def test_no_grant_expired_private_unknown(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok(r))[1])
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL)
        from openjarvis.security.cloud_dispatch import AuthorizedPayload

        live = _sealed(authz)
        expired = AuthorizedPayload(
            dispatch_id=live.dispatch_id, provider=live.provider,
            redacted_messages=live.redacted_messages, digest=live.digest,
            grant=ExplicitGrant(
                agent_id="host", capability="llm:cloud",
                expires_at=time.time() - 1,
            ),
            budget_id=live.budget_id, session_id=live.session_id,
            nonce=live.nonce,
        )
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=expired)
        with pytest.raises(PrivacyDenied):
            _sealed(authz, classification=PrivacyClassification.PRIVATE)
        with pytest.raises(PrivacyDenied):
            _sealed(authz, classification=None)
        assert seen == []

    def test_binding_mismatch(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok(r))[1])
        other = _authz(allowlist={("llamacpp", "llamacpp", "other")})
        bad = other.authorize(
            CloudDispatchRequest(
                classification=PrivacyClassification.INTERNAL,
                provider=ProviderIdentity(
                    engine="llamacpp", provider="llamacpp", model="other",
                    endpoint=HOST,
                ),
                messages=({"role": "user", "content": "hello"},),
                grant=ExplicitGrant(agent_id="host", capability="llm:cloud"),
                budget=BudgetReservation(
                    est_prompt_tokens=2, max_tokens=8, ctx_limit=64
                ),
                session_id="sess-1",
                nonce="n-bad",
            )
        )
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=bad)
        with pytest.raises(PrivacyDenied):
            eng.generate(
                [Message(role=Role.USER, content="tampered")], model=MODEL,
                cloud_dispatch=_sealed(authz),
            )
        assert seen == []


class TestSessionNonceDuplicate:
    def test_session_nonce_replay_cross(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok(r))[1],
                      session="sess-1")
        with pytest.raises(PrivacyDenied):
            eng.generate(
                _msgs(), model=MODEL, cloud_dispatch=_sealed(authz, session="s9")
            )
        first = _sealed(authz, nonce="r-nonce")
        second = _sealed(authz, nonce="r-nonce")
        assert eng.generate(
            _msgs(), model=MODEL, cloud_dispatch=first
        )["content"] == "compat reply"
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=second)
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=first)
        assert len(seen) == 1

    def test_concurrent_duplicate_single_send(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
        seen: list = []
        lock = threading.Lock()

        def handler(req: httpx.Request) -> httpx.Response:
            with lock:
                seen.append(req)
            return httpx.Response(200, json=_ok_body())

        authz = _authz()
        eng = _engine(authz, handler)
        sealed = _sealed(authz)
        results: list = []

        def worker():
            try:
                eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
                results.append("ok")
            except PrivacyDenied:
                results.append("denied")

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10.0)
        assert results.count("ok") == 1
        assert results.count("denied") == 5
        assert len(seen) == 1


class TestFailureSemantics:
    def test_presend_cancel_no_send(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok(r))[1])
        cancel = threading.Event()
        cancel.set()
        with pytest.raises(PrivacyDenied):
            eng.generate(
                _msgs(), model=MODEL, cloud_dispatch=_sealed(authz),
                cancel_event=cancel,
            )
        assert seen == []

    def test_timeout_unknown_connect_failed(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
        authz = _authz()
        eng_t = _engine(
            authz,
            lambda req: (_ for _ in ()).throw(
                httpx.TimeoutException("slow")
            ),
        )
        with pytest.raises(EngineConnectionError):
            eng_t.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert [
            e.state for e in eng_t._dispatch_ledger._entries.values()
        ] == [STATE_UNKNOWN_OUTCOME]
        eng_c = _engine(
            authz,
            lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused")),
        )
        with pytest.raises(EngineConnectionError):
            eng_c.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert [
            e.state for e in eng_c._dispatch_ledger._entries.values()
        ] == [STATE_FAILED]

    def test_unknown_no_resend(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")

        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("slow")

        authz = _authz()
        eng = _engine(authz, handler)
        sealed = _sealed(authz)
        with pytest.raises(EngineConnectionError):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)

    def test_redirect_and_tools_retry(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
        seen: list = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return httpx.Response(307, headers={"location": "https://evil.test/"})

        authz = _authz()
        eng = _engine(authz, handler)
        with pytest.raises(EngineConnectionError):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert all("evil" not in str(r.url) for r in seen)
        # Legacy 400 tools-strip retry still works under sealed auth.
        calls: list = []

        def retry_handler(req: httpx.Request) -> httpx.Response:
            calls.append(req)
            body = json.loads(req.content.decode())
            if "tools" in body:
                return httpx.Response(400, json={"error": "no tools"})
            return httpx.Response(200, json=_ok_body())

        eng2 = _engine(authz, retry_handler)
        out = eng2.generate(
            _msgs(), model=MODEL, cloud_dispatch=_sealed(authz),
            tools=[{"type": "function"}],
        )
        assert out["content"] == "compat reply"
        assert len(calls) == 2


class TestStreams:
    def test_stream_valid_partial_cancel(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
        authz = _authz()
        eng = _engine(
            authz, lambda req: httpx.Response(200, content=SSE)
        )

        async def go():
            return [
                t
                async for t in eng.stream(
                    _msgs(), model=MODEL, cloud_dispatch=_sealed(authz)
                )
            ]

        assert asyncio_run(go()) == ["hi"]
        states = [e.state for e in eng._dispatch_ledger._entries.values()]
        assert states == [STATE_EXECUTED]

        async def go_partial():
            eng2 = _engine(
                authz,
                lambda req: httpx.Response(
                    200,
                    content=b'data: {"choices": [{"delta": {"content": "x"}}]}\n\n',
                ),
            )
            sealed = _sealed(authz)
            eng2._async_transport = httpx.MockTransport(
                lambda req: httpx.Response(
                    200,
                    content=b'data: {"choices": [{"delta": {"content": "x"}}]}\n\n',
                )
            )
            out = [
                t
                async for t in eng2.stream(
                    _msgs(), model=MODEL, cloud_dispatch=sealed
                )
            ]
            return out, eng2

        tokens, eng2 = asyncio_run(go_partial())
        assert tokens == ["x"]
        assert [
            e.state for e in eng2._dispatch_ledger._entries.values()
        ] == [STATE_UNKNOWN_OUTCOME]

    def test_stream_full_valid(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
        authz = _authz()
        eng = _engine(
            authz, lambda req: httpx.Response(200, content=SSE)
        )

        async def go():
            return [
                c
                async for c in eng.stream_full(
                    _msgs(), model=MODEL, cloud_dispatch=_sealed(authz)
                )
            ]

        chunks = asyncio_run(go())
        assert chunks and chunks[0].content == "hi"


def asyncio_run(coro):
    return asyncio.run(coro)


class TestValidRollback:
    def test_valid_grant_one_send(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok(r))[1])
        ledger = CloudDispatchLedger()
        eng._dispatch_ledger = ledger
        sealed = _sealed(authz)
        out = eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        assert out["content"] == "compat reply"
        assert len(seen) == 1
        assert [e.state for e in ledger._entries.values()] == [STATE_EXECUTED]

    def test_retry_budget_exactly_one_resend(self, monkeypatch) -> None:
        # Persistent 400s: at most 2 sends (initial + 1 envelope retry),
        # then FAILED. No retry loop is possible.
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(
            authz,
            lambda req: (
                seen.append(req),
                httpx.Response(400, json={"error": "no tools"}),
            )[1],
        )
        ledger = CloudDispatchLedger()
        eng._dispatch_ledger = ledger
        from openjarvis.engine._base import EngineConnectionError

        with pytest.raises(EngineConnectionError):
            eng.generate(
                _msgs(), model=MODEL, cloud_dispatch=_sealed(authz),
                tools=[{"type": "function"}],
            )
        assert len(seen) == 2
        entries = list(ledger._entries.values())
        assert len(entries) == 1
        assert entries[0].state == STATE_FAILED
        assert entries[0].attempts == 1

    def test_rollback_off_safe(self, monkeypatch) -> None:
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok(r))[1])
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
        eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "off")
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert len(seen) == 1
