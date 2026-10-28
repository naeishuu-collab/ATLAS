"""E2: NIM path enforcement end-to-end — MockTransport only, no network."""

from __future__ import annotations

import json
import threading
import time

import httpx
import pytest

import openjarvis.engine.nim as nim_module
from openjarvis.core.types import Message, Role
from openjarvis.engine.nim import NIMEngine
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

HOST = "https://nim.test"
MODEL = "meta/llama-3.3-70b-instruct"


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
        "allowlist": {("nim", "nim", MODEL)},
        "scanners": [_Scanner()],
        "capability_policy": _FakePolicy({"host": ["llm:cloud"]}),
        "allowed_endpoints": frozenset({HOST}),
    }
    base.update(kw)
    return CloudDispatchAuthorizer(**base)


def _sealed(authz, session="sess-1", nonce=None, **kw):
    import uuid

    base = {
        "classification": PrivacyClassification.INTERNAL,
        "provider": ProviderIdentity(
            engine="nim", provider="nim", model=MODEL, endpoint=HOST
        ),
        "messages": ({"role": "user", "content": "hello nim"},),
        "grant": ExplicitGrant(
            agent_id="host", capability="llm:cloud", expires_at=time.time() + 600
        ),
        "budget": BudgetReservation(est_prompt_tokens=2, max_tokens=8, ctx_limit=64),
        "session_id": session,
        "nonce": nonce or f"n-{uuid.uuid4().hex}",
    }
    base.update(kw)
    return authz.authorize(CloudDispatchRequest(**base))


def _ok_body():
    return {
        "choices": [
            {"message": {"content": "nim reply"}, "finish_reason": "stop"}
        ],
        "model": MODEL,
        "usage": {"prompt_tokens": 2, "completion_tokens": 2},
    }


def _engine(authz, handler, session="sess-1"):
    eng = NIMEngine(
        host=HOST,
        authorizer=authz,
        dispatch_ledger=CloudDispatchLedger(),
        session_id=session,
    )
    eng._client = httpx.Client(
        transport=httpx.MockTransport(handler), base_url=HOST
    )
    return eng


def _msgs():
    return [Message(role=Role.USER, content="hello nim")]


def _ok_handler(request: httpx.Request) -> httpx.Response:
    # NOTE: MockTransport sees the path only (client holds base_url); host
    # binding is enforced in code by the endpoint check, not observable here.
    assert request.url.path == "/v1/chat/completions"
    body = json.loads(request.content.decode())
    assert body["model"] == MODEL
    assert body["messages"] == [{"role": "user", "content": "hello nim"}]
    return httpx.Response(200, json=_ok_body())


class TestFlagGate:
    @pytest.mark.parametrize("value", [None, "off", "ON", "yes", ""])
    def test_flag_states_deny(self, monkeypatch, value) -> None:
        if value is None:
            monkeypatch.delenv("ASTRA_NIM_EGRESS", raising=False)
        else:
            monkeypatch.setenv("ASTRA_NIM_EGRESS", value)
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok_handler(r))[1])
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert seen == []

    def test_flag_toggle_stays_safe(self, monkeypatch) -> None:
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok_handler(r))[1])
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        out = eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert out["content"] == "nim reply"
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "off")
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert len(seen) == 1


class TestGrantBinding:
    def test_no_grant_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        seen: list = []
        eng = _engine(_authz(), lambda r: (seen.append(r), _ok_handler(r))[1])
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL)
        assert seen == []

    def test_expired_grant_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok_handler(r))[1])
        live = _sealed(authz)
        from openjarvis.security.cloud_dispatch import AuthorizedPayload

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
        assert seen == []

    def test_provider_model_endpoint_mismatch(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _authz()
        seen: list = []
        eng = _engine(authz, lambda r: (seen.append(r), _ok_handler(r))[1])
        bad_model = _sealed(
            CloudDispatchAuthorizer(
                allowlist={("nim", "nim", "other")}, scanners=[_Scanner()],
                capability_policy=_FakePolicy({"host": ["llm:cloud"]}),
            ),
            **{
                "provider": ProviderIdentity(
                    engine="nim", provider="nim", model="other",
                    endpoint=HOST,
                )
            },
        )
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=bad_model)
        bad_ep = _sealed(
            _authz(allowed_endpoints=frozenset({HOST, "https://evil.test"})),
            **{
                "provider": ProviderIdentity(
                    engine="nim", provider="nim", model=MODEL,
                    endpoint="https://evil.test",
                )
            },
        )
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=bad_ep)
        assert seen == []

    def test_digest_mismatch_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok_handler(r))[1])
        with pytest.raises(PrivacyDenied):
            eng.generate(
                [Message(role=Role.USER, content="tampered")], model=MODEL,
                cloud_dispatch=_sealed(authz),
            )
        assert seen == []

    def test_private_unknown_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _authz()
        with pytest.raises(PrivacyDenied):
            _sealed(authz, classification=PrivacyClassification.PRIVATE)
        with pytest.raises(PrivacyDenied):
            _sealed(authz, classification=None)


class TestSessionNonce:
    def test_session_mismatch_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok_handler(r))[1],
                      session="sess-1")
        with pytest.raises(PrivacyDenied):
            eng.generate(
                _msgs(), model=MODEL, cloud_dispatch=_sealed(authz, session="sess-2")
            )
        assert seen == []

    def test_nonce_replay_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok_handler(r))[1])
        first = _sealed(authz, nonce="fixed-nonce-1")
        second = _sealed(authz, nonce="fixed-nonce-1")
        out = eng.generate(_msgs(), model=MODEL, cloud_dispatch=first)
        assert out["content"] == "nim reply"
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=second)
        assert len(seen) == 1

    def test_cross_session_replay_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng_b = _engine(authz, lambda r: (seen.append(r), _ok_handler(r))[1],
                        session="sess-B")
        with pytest.raises(PrivacyDenied):
            eng_b.generate(
                _msgs(), model=MODEL, cloud_dispatch=_sealed(authz, session="sess-A")
            )
        assert seen == []

    def test_duplicate_dispatch_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok_handler(r))[1])
        sealed = _sealed(authz)
        eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        assert len(seen) == 1


class TestFailureSemantics:
    def test_presend_cancel_no_send(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok_handler(r))[1])
        cancel = threading.Event()
        cancel.set()
        with pytest.raises(PrivacyDenied):
            eng.generate(
                _msgs(), model=MODEL, cloud_dispatch=_sealed(authz),
                cancel_event=cancel,
            )
        assert seen == []

    def test_timeout_is_unknown(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        seen: list = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            raise httpx.TimeoutException("too slow")

        from openjarvis.engine._base import EngineConnectionError

        authz = _authz()
        eng = _engine(authz, handler)
        with pytest.raises(EngineConnectionError):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert len(seen) == 1
        states = [e.state for e in eng._dispatch_ledger._entries.values()]
        assert states == [STATE_UNKNOWN_OUTCOME]

    def test_http_error_is_failed_not_unknown(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _authz()
        eng = _engine(authz, lambda req: httpx.Response(500, json={"error": "x"}))
        with pytest.raises(httpx.HTTPStatusError):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        states = [e.state for e in eng._dispatch_ledger._entries.values()]
        assert states == [STATE_FAILED]

    def test_unknown_no_auto_resend(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")

        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("too slow")

        from openjarvis.engine._base import EngineConnectionError

        authz = _authz()
        eng = _engine(authz, handler)
        sealed = _sealed(authz)
        with pytest.raises(EngineConnectionError):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)

    def test_response_verification_failure(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _authz()
        eng = _engine(authz, lambda req: httpx.Response(200, json={"choices": []}))
        out = eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert out["finish_reason"] == "error"
        states = [e.state for e in eng._dispatch_ledger._entries.values()]
        assert states == [STATE_FAILED]

    def test_redirect_never_followed(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        seen: list = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return httpx.Response(307, headers={"location": "https://evil.test/x"})

        authz = _authz()
        eng = _engine(authz, handler)
        with pytest.raises(httpx.HTTPStatusError):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert [str(r.url) for r in seen] == [f"{HOST}/v1/chat/completions"]

    def test_no_proxy_configured(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        created: list = []
        real_async = httpx.AsyncClient

        def factory(**kw):
            created.append(kw)
            return real_async(
                transport=httpx.MockTransport(
                    lambda req: httpx.Response(200, json=_ok_body())
                )
            )

        monkeypatch.setattr(nim_module.httpx, "AsyncClient", factory)
        import asyncio

        sse = (
            'data: {"choices": [{"delta": {"content": "hi"}}]}\n\n'
            "data: [DONE]\n\n"
        )

        def factory(**kw):
            created.append(kw)
            return real_async(
                transport=httpx.MockTransport(
                    lambda req: httpx.Response(200, content=sse.encode())
                ),
                base_url=HOST,
            )

        monkeypatch.setattr(nim_module.httpx, "AsyncClient", factory)

        # Sealed per engine authorizer instance: use one shared stack instead.
        async def go2():
            authz = _authz()
            eng = NIMEngine(
                host=HOST, authorizer=authz,
                dispatch_ledger=CloudDispatchLedger(), session_id="sess-1",
            )
            tokens = []
            async for t in eng.stream(
                _msgs(), model=MODEL, cloud_dispatch=_sealed(authz)
            ):
                tokens.append(t)
            return tokens

        assert asyncio.run(go2()) == ["hi"]
        assert all("proxies" not in kw and "proxy" not in kw for kw in created)


class TestConcurrency:
    def test_concurrent_duplicate_single_send(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
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
            except BaseException as exc:  # never swallow: surface the real error
                results.append(f"error:{type(exc).__name__}:{exc}")

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10.0)
        assert not any(t.is_alive() for t in threads), "worker thread hung"
        assert len(results) == 8, f"lost results: {results!r}"
        assert results.count("ok") == 1, f"{results!r}"
        assert results.count("denied") == 7, f"{results!r}"
        assert len(seen) == 1

    def test_concurrent_session_isolation(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok_handler(r))[1],
                      session="sess-1")
        results: list = []

        def worker(session: str):
            try:
                eng.generate(
                    _msgs(), model=MODEL,
                    cloud_dispatch=_sealed(authz, session=session),
                )
                results.append((session, "ok"))
            except PrivacyDenied:
                results.append((session, "denied"))

        threads = [
            threading.Thread(target=worker, args=(s,))
            for s in ("sess-1", "sess-2", "sess-1", "sess-2")
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10.0)
        # Nonces are unique per seal, but session sess-2 is rejected.
        assert results.count(("sess-2", "denied")) == 2


class TestValidAndRollback:
    def test_valid_grant_exactly_one_send(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok_handler(r))[1])
        sealed = _sealed(authz)
        out = eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        assert out["content"] == "nim reply"
        assert len(seen) == 1
        states = [e.state for e in eng._dispatch_ledger._entries.values()]
        assert states == [STATE_EXECUTED]

    def test_rollback_flag_off_is_safe_nonsending(self, monkeypatch) -> None:
        seen: list = []
        authz = _authz()
        eng = _engine(authz, lambda r: (seen.append(r), _ok_handler(r))[1])
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "off")
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        # No raw fallback: the only transport path requires enforcement.
        assert len(seen) == 1

    def test_raw_engine_bypass_absent(self, monkeypatch) -> None:
        # Without the sealed kwarg every public send entry denies before
        # any transport call (generate/stream/stream_full share _enforce).
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        seen: list = []
        eng = _engine(
            authz=_authz(),
            handler=lambda r: (seen.append(r), _ok_handler(r))[1],
        )
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL)
        assert seen == []


def _sse_stream_engine(monkeypatch, authz, body: bytes, session="sess-1"):
    real_async = httpx.AsyncClient

    def factory(**kw):
        return real_async(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(200, content=body)
            ),
            base_url=HOST,
        )

    monkeypatch.setattr(nim_module.httpx, "AsyncClient", factory)
    return NIMEngine(
        host=HOST, authorizer=authz,
        dispatch_ledger=CloudDispatchLedger(), session_id=session,
    )


def _run(coro):
    import asyncio

    return asyncio.run(coro)


class TestStreamSemantics:
    FULL_SSE = (
        'data: {"choices": [{"delta": {"content": "a"}}]}\n\n'
        'data: {"choices": [{"delta": {}, "finish_reason": "stop"}]}\n\n'
        "data: [DONE]\n\n"
    ).encode()

    PARTIAL_SSE = (
        'data: {"choices": [{"delta": {"content": "a"}}]}\n\n'
    ).encode()

    def test_stream_valid_executed(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _authz()
        eng = _sse_stream_engine(monkeypatch, authz, self.FULL_SSE)

        async def go():
            return [
                t
                async for t in eng.stream(
                    _msgs(), model=MODEL, cloud_dispatch=_sealed(authz)
                )
            ]

        assert _run(go()) == ["a"]
        states = [e.state for e in eng._dispatch_ledger._entries.values()]
        from openjarvis.security.dispatch_ledger import STATE_EXECUTED

        assert states == [STATE_EXECUTED]

    def test_stream_presend_cancel(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _authz()
        eng = _sse_stream_engine(monkeypatch, authz, self.FULL_SSE)
        cancel = threading.Event()
        cancel.set()

        async def go():
            return [
                t
                async for t in eng.stream(
                    _msgs(), model=MODEL, cloud_dispatch=_sealed(authz),
                    cancel_event=cancel,
                )
            ]

        with pytest.raises(PrivacyDenied):
            _run(go())

    def test_partial_stream_is_unknown(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _authz()
        eng = _sse_stream_engine(monkeypatch, authz, self.PARTIAL_SSE)

        async def go():
            return [
                t
                async for t in eng.stream(
                    _msgs(), model=MODEL, cloud_dispatch=_sealed(authz)
                )
            ]

        assert _run(go()) == ["a"]  # partial tokens delivered, not success
        states = [e.state for e in eng._dispatch_ledger._entries.values()]
        assert states == [STATE_UNKNOWN_OUTCOME]

    def test_stream_mid_timeout_is_unknown(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")

        class _Flaky(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                raise httpx.TimeoutException("stall")

        real_async = httpx.AsyncClient
        monkeypatch.setattr(
            nim_module.httpx, "AsyncClient",
            lambda **kw: real_async(transport=_Flaky(), base_url=HOST),
        )
        from openjarvis.engine._base import EngineConnectionError

        authz = _authz()
        eng = NIMEngine(
            host=HOST, authorizer=authz,
            dispatch_ledger=CloudDispatchLedger(), session_id="sess-1",
        )

        async def go():
            return [
                t
                async for t in eng.stream(
                    _msgs(), model=MODEL, cloud_dispatch=_sealed(authz)
                )
            ]

        with pytest.raises(EngineConnectionError):
            _run(go())
        states = [e.state for e in eng._dispatch_ledger._entries.values()]
        assert states == [STATE_UNKNOWN_OUTCOME]

    def test_stream_early_termination_is_unknown(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _authz()
        eng = _sse_stream_engine(monkeypatch, authz, self.FULL_SSE)

        async def go():
            gen = eng.stream(
                _msgs(), model=MODEL, cloud_dispatch=_sealed(authz)
            )
            first = await gen.__anext__()
            await gen.aclose()
            return first

        assert _run(go()) == "a"
        states = [e.state for e in eng._dispatch_ledger._entries.values()]
        assert states == [STATE_UNKNOWN_OUTCOME]

    def test_stream_duplicate_and_resend_denied(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _authz()
        eng = _sse_stream_engine(monkeypatch, authz, self.FULL_SSE)
        sealed = _sealed(authz)

        async def go():
            return [
                t async for t in eng.stream(
                    _msgs(), model=MODEL, cloud_dispatch=sealed
                )
            ]

        assert _run(go()) == ["a"]
        with pytest.raises(PrivacyDenied):
            _run(go())

    def test_stream_cross_session_denied(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _authz()
        eng = _sse_stream_engine(monkeypatch, authz, self.FULL_SSE,
                                 session="sess-1")

        async def go():
            return [
                t
                async for t in eng.stream(
                    _msgs(), model=MODEL,
                    cloud_dispatch=_sealed(authz, session="sess-9"),
                )
            ]

        with pytest.raises(PrivacyDenied):
            _run(go())
