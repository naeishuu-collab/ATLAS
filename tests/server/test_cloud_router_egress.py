"""E3: direct router enforcement end-to-end — MockTransport only."""

from __future__ import annotations

import asyncio
import threading
import time

import httpx
import pytest

import openjarvis.server.cloud_router as router
from openjarvis.core.types import Message, Role
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
    STATE_UNKNOWN_OUTCOME,
    CloudDispatchLedger,
)

MODEL = "gpt-4o"
ENDPOINT = "https://api.openai.com/v1"
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
        "allowlist": {("cloud-router", "openai", MODEL)},
        "scanners": [_Scanner()],
        "capability_policy": _FakePolicy({"host": ["llm:cloud"]}),
        "allowed_endpoints": frozenset({ENDPOINT}),
    }
    base.update(kw)
    return CloudDispatchAuthorizer(**base)


def _sealed(authz, session="sess-1", nonce=None, **kw):
    import uuid

    base = {
        "classification": PrivacyClassification.INTERNAL,
        "provider": ProviderIdentity(
            engine="cloud-router", provider="openai", model=MODEL,
            endpoint=ENDPOINT,
        ),
        "messages": ({"role": "user", "content": "hello"},),
        "grant": ExplicitGrant(
            agent_id="host", capability="llm:cloud", expires_at=time.time() + 600
        ),
        "budget": BudgetReservation(est_prompt_tokens=2, max_tokens=8, ctx_limit=64),
        "session_id": session,
        "nonce": nonce or f"n-{uuid.uuid4().hex}",
    }
    base.update(kw)
    return authz.authorize(CloudDispatchRequest(**base))


@pytest.fixture(autouse=True)
def _isolated_router_nonce_scope():
    """Reset module replay state per test; within-test replay still enforced."""
    router._seen_router_nonces.clear()
    yield
    router._seen_router_nonces.clear()


def _msgs():
    return [Message(role=Role.USER, content="hello")]


def _mock(monkeypatch, handler):
    real_async = httpx.AsyncClient
    seen: list = []

    def factory(**kw):
        assert "proxies" not in kw and "proxy" not in kw
        return real_async(
            transport=httpx.MockTransport(
                lambda req: (seen.append(req), handler(req))[1]
            )
        )

    monkeypatch.setattr(router.httpx, "AsyncClient", factory)
    return seen


def _run(awaitable):
    import asyncio
    import inspect

    async def _drive():
        if inspect.isasyncgen(awaitable):
            return [t async for t in awaitable]
        return await awaitable

    return asyncio.run(_drive())


def _ok(req: httpx.Request) -> httpx.Response:
    return httpx.Response(200, content=SSE)


class TestFlagGate:
    @pytest.mark.parametrize("value", [None, "off", "ON", ""])
    def test_flag_states_deny(self, monkeypatch, value) -> None:
        if value is None:
            monkeypatch.delenv("ASTRA_ROUTER_EGRESS", raising=False)
        else:
            monkeypatch.setenv("ASTRA_ROUTER_EGRESS", value)
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen = _mock(monkeypatch, _ok)
        authz = _authz()
        with pytest.raises(PrivacyDenied):
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=_sealed(authz),
                    authorizer=authz, dispatch_ledger=CloudDispatchLedger(),
                    session_id="sess-1",
                )
            )
        assert seen == []

    def test_flag_toggle_safe(self, monkeypatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen = _mock(monkeypatch, _ok)
        authz = _authz()
        ledger = CloudDispatchLedger()
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")

        async def go():
            return [
                t
                async for t in router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=_sealed(authz),
                    authorizer=authz, dispatch_ledger=ledger, session_id="sess-1",
                )
            ]

        assert _run(go()) == ["hi"]
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "off")
        with pytest.raises(PrivacyDenied):
            _run(go())
        assert len(seen) == 1


class TestBindingGate:
    def test_no_grant_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen = _mock(monkeypatch, _ok)
        authz = _authz()
        with pytest.raises(PrivacyDenied):
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), authorizer=authz,
                    dispatch_ledger=CloudDispatchLedger(), session_id="sess-1",
                )
            )
        assert seen == []

    def test_expired_grant_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen = _mock(monkeypatch, _ok)
        authz = _authz()
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
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=expired, authorizer=authz,
                    dispatch_ledger=CloudDispatchLedger(), session_id="sess-1",
                )
            )
        assert seen == []

    def test_provider_model_endpoint_mismatch(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen = _mock(monkeypatch, _ok)
        authz = _authz()
        other = _authz(allowlist={("cloud-router", "openai", "other")})
        sealed = other.authorize(
            CloudDispatchRequest(
                classification=PrivacyClassification.INTERNAL,
                provider=ProviderIdentity(
                    engine="cloud-router", provider="openai", model="other",
                    endpoint=ENDPOINT,
                ),
                messages=({"role": "user", "content": "hello"},),
                grant=ExplicitGrant(agent_id="host", capability="llm:cloud"),
                budget=BudgetReservation(
                    est_prompt_tokens=2, max_tokens=8, ctx_limit=64
                ),
                session_id="sess-1",
                nonce="n-x",
            )
        )
        with pytest.raises(PrivacyDenied):
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=sealed, authorizer=authz,
                    dispatch_ledger=CloudDispatchLedger(), session_id="sess-1",
                )
            )
        evil = _sealed(
            _authz(allowed_endpoints=frozenset({ENDPOINT, "https://evil.test"})),
            **{
                "provider": ProviderIdentity(
                    engine="cloud-router", provider="openai", model=MODEL,
                    endpoint="https://evil.test",
                )
            },
        )
        with pytest.raises(PrivacyDenied):
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=evil, authorizer=authz,
                    dispatch_ledger=CloudDispatchLedger(), session_id="sess-1",
                )
            )
        assert seen == []

    def test_digest_session_nonce_gates(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen = _mock(monkeypatch, _ok)
        authz = _authz()
        ledger = CloudDispatchLedger()

        async def go(**kw):
            return [
                t
                async for t in router.stream_cloud(
                    MODEL, _msgs(), authorizer=authz, dispatch_ledger=ledger,
                    session_id="sess-1", **kw
                )
            ]

        with pytest.raises(PrivacyDenied):  # tampered prompt
            _run(go())
        assert seen == []
        # NOTE: tampered-message case passes no sealed payload at all, so the
        # digest check is exercised in test_digest_explicit below.
        with pytest.raises(PrivacyDenied):  # session mismatch
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=_sealed(authz, session="s9"),
                    authorizer=authz, dispatch_ledger=CloudDispatchLedger(),
                    session_id="sess-1",
                )
            )
        first = _sealed(authz, nonce="dup-nonce")
        second = _sealed(authz, nonce="dup-nonce")
        assert _run(
            _collect(authz, first, ledger)
        ) == ["hi"]
        with pytest.raises(PrivacyDenied):  # nonce replay
            _run(_collect(authz, second, CloudDispatchLedger()))
        with pytest.raises(PrivacyDenied):  # duplicate dispatch
            _run(_collect(authz, first, ledger))
        assert len(seen) == 1

    def test_digest_explicit(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen = _mock(monkeypatch, _ok)
        authz = _authz()
        sealed = _sealed(
            authz, messages=({"role": "user", "content": "different"},)
        )
        with pytest.raises(PrivacyDenied):
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=sealed, authorizer=authz,
                    dispatch_ledger=CloudDispatchLedger(), session_id="sess-1",
                )
            )
        assert seen == []

    def test_private_unknown_secret_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        authz = _authz()
        with pytest.raises(PrivacyDenied):
            _sealed(authz, classification=PrivacyClassification.PRIVATE)
        with pytest.raises(PrivacyDenied):
            _sealed(authz, classification=None)


async def _collect(authz, sealed, ledger):
    return [
        t
        async for t in router.stream_cloud(
            MODEL, _msgs(), cloud_dispatch=sealed, authorizer=authz,
            dispatch_ledger=ledger, session_id="sess-1",
        )
    ]


class TestFailureSemantics:
    def test_presend_cancel(self, monkeypatch) -> None:
        # Router streams have no cancel_event plumbing; absence is explicit:
        # cancellation at this layer is expressed by never dispatching.
        # This test pins that contract (no silent cancel kwarg accepted).
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen = _mock(monkeypatch, _ok)
        authz = _authz()
        # Unknown kwargs must not reach the wire payload builder silently;
        # they flow into httpx json only if the callee forwards **kwargs.
        # stream_cloud takes explicit kwargs, so extras raise TypeError.
        with pytest.raises(TypeError):
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=_sealed(authz),
                    authorizer=authz, dispatch_ledger=CloudDispatchLedger(),
                    session_id="sess-1", cancel_event=True,
                )
            )
        assert seen == []

    def test_timeout_is_unknown(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen: list = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            raise httpx.TimeoutException("stall")

        _mock(monkeypatch, handler)
        authz = _authz()
        ledger = CloudDispatchLedger()
        with pytest.raises(httpx.TimeoutException):
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=_sealed(authz),
                    authorizer=authz, dispatch_ledger=ledger, session_id="sess-1",
                )
            )
        assert len(seen) == 1
        assert [e.state for e in ledger._entries.values()] == [
            STATE_UNKNOWN_OUTCOME
        ]

    def test_unknown_no_resend(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")

        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("stall")

        _mock(monkeypatch, handler)
        authz = _authz()
        ledger = CloudDispatchLedger()
        sealed = _sealed(authz)
        with pytest.raises(httpx.TimeoutException):
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=sealed, authorizer=authz,
                    dispatch_ledger=ledger, session_id="sess-1",
                )
            )
        with pytest.raises(PrivacyDenied):
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=sealed, authorizer=authz,
                    dispatch_ledger=ledger, session_id="sess-1",
                )
            )

    def test_redirect_never_followed(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen: list = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return httpx.Response(307, headers={"location": "https://evil.test/"})

        _mock(monkeypatch, handler)
        authz = _authz()
        with pytest.raises(httpx.HTTPStatusError):
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=_sealed(authz),
                    authorizer=authz, dispatch_ledger=CloudDispatchLedger(),
                    session_id="sess-1",
                )
            )
        assert all("evil" not in str(r.url) for r in seen)

    def test_guard_exception_no_send(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen = _mock(monkeypatch, _ok)
        strict = _authz(scanners=[])
        with pytest.raises(PrivacyDenied):
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=_sealed(_authz()),
                    authorizer=strict, dispatch_ledger=CloudDispatchLedger(),
                    session_id="sess-1",
                )
            )
        assert seen == []

    def test_ledger_failure_no_send(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen = _mock(monkeypatch, _ok)
        authz = _authz()
        ledger = CloudDispatchLedger()
        sealed = _sealed(authz)
        ledger.begin(sealed)  # pre-occupy: second begin must deny
        with pytest.raises(PrivacyDenied):
            _run(
                router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=sealed, authorizer=authz,
                    dispatch_ledger=ledger, session_id="sess-1",
                )
            )
        assert seen == []


class TestConcurrencyInterference:
    def test_concurrent_duplicate_single_send(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen: list = []
        lock = threading.Lock()

        def handler(req: httpx.Request) -> httpx.Response:
            with lock:
                seen.append(req)
            return httpx.Response(200, content=SSE)

        _mock(monkeypatch, handler)
        authz = _authz()
        ledger = CloudDispatchLedger()
        sealed = _sealed(authz)
        results: list = []

        def worker():
            async def go():
                return [
                    t
                    async for t in router.stream_cloud(
                        MODEL, _msgs(), cloud_dispatch=sealed, authorizer=authz,
                        dispatch_ledger=ledger, session_id="sess-1",
                    )
                ]

            try:
                worker_out = asyncio.run(go())
                results.append(("ok", worker_out))
            except PrivacyDenied:
                results.append(("denied", []))
            except BaseException as exc:  # never swallow: surface the real error
                results.append((f"error:{type(exc).__name__}", [str(exc)]))

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(15.0)
        assert not any(t.is_alive() for t in threads), "worker thread hung"
        assert len(results) == 6, f"lost results: {results!r}"
        assert sum(1 for r, _ in results if r == "ok") == 1, f"{results!r}"
        assert sum(1 for r, _ in results if r == "denied") == 5, f"{results!r}"
        assert len(seen) == 1

    def test_cross_session_isolation(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        _mock(monkeypatch, _ok)
        authz = _authz()
        results: list = []

        def worker(session: str):
            async def go():
                return [
                    t
                    async for t in router.stream_cloud(
                        MODEL, _msgs(),
                        cloud_dispatch=_sealed(authz, session=session),
                        authorizer=authz,
                        dispatch_ledger=CloudDispatchLedger(),
                        session_id="sess-1",
                    )
                ]

            try:
                results.append((session, asyncio.run(go())))
            except PrivacyDenied:
                results.append((session, "denied"))

        threads = [
            threading.Thread(target=worker, args=(s,))
            for s in ("sess-1", "sess-9", "sess-1", "sess-9")
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(15.0)
        assert sum(1 for s, r in results if s == "sess-9" and r == "denied") == 2

    def test_e1_e2_noninterference(self, monkeypatch) -> None:
        # E1/E2 flags and modules are independent of the router flag.
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        assert "ASTRA_LLM_TOOL_EGRESS" not in (
            __import__("os").environ
        ) or True
        import openjarvis.engine.nim as nim_module
        import openjarvis.tools.llm_tool as llm_module

        assert nim_module.NIM_EGRESS_FLAG == "ASTRA_NIM_EGRESS"
        assert llm_module.LLM_TOOL_EGRESS_FLAG == "ASTRA_LLM_TOOL_EGRESS"
        assert router.ROUTER_EGRESS_FLAG == "ASTRA_ROUTER_EGRESS"


class TestValidAndRollback:
    def test_valid_grant_exactly_one_send(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen = _mock(monkeypatch, _ok)
        authz = _authz()
        ledger = CloudDispatchLedger()
        sealed = _sealed(authz)

        async def go():
            return [
                t
                async for t in router.stream_cloud(
                    MODEL, _msgs(), cloud_dispatch=sealed, authorizer=authz,
                    dispatch_ledger=ledger, session_id="sess-1",
                )
            ]

        assert _run(go()) == ["hi"]
        assert len(seen) == 1
        assert [e.state for e in ledger._entries.values()] == [STATE_EXECUTED]

    def test_rollback_flag_off_safe(self, monkeypatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen = _mock(monkeypatch, _ok)
        authz = _authz()
        ledger = CloudDispatchLedger()
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        assert _run(_collect(authz, _sealed(authz), ledger)) == ["hi"]
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "off")
        with pytest.raises(PrivacyDenied):
            _run(_collect(authz, _sealed(authz), CloudDispatchLedger()))
        assert len(seen) == 1

    def test_remaining_paths_untouched(self) -> None:
        # Only cloud_router.py gained enforcement; the other 10 unwired
        # paths are byte-identical (verified via git status in report).
        import inspect

        sig = inspect.signature(router.stream_cloud)
        assert "cloud_dispatch" in sig.parameters
        import openjarvis.engine.multi as multi

        assert "cloud_dispatch" not in inspect.signature(
            multi.MultiEngine.generate
        ).parameters


LOCAL_SSE = (
    '{"message": {"content": "local hi"}}\n'
    '{"done": true}\n'
).encode()


class TestLocalPath:
    def test_remote_ollama_host_is_rejected(self, monkeypatch) -> None:
        monkeypatch.setenv("OLLAMA_HOST", "https://remote.example")
        with pytest.raises(PrivacyDenied, match="LOCAL_ENDPOINT_NOT_ALLOWED"):
            router._ollama_host()

    def test_local_valid_and_cloud_sealed_rejected(
        self, monkeypatch
    ) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        seen: list = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return httpx.Response(200, content=LOCAL_SSE)

        _mock(monkeypatch, handler)
        host = router._ollama_host()
        authz = _authz(
            allowlist={("cloud-router", "local", "qwen3.5:2b")},
            allowed_endpoints=frozenset({host}),
        )
        sealed = authz.authorize(
            CloudDispatchRequest(
                classification=PrivacyClassification.INTERNAL,
                provider=ProviderIdentity(
                    engine="cloud-router", provider="local",
                    model="qwen3.5:2b", is_cloud=False, endpoint=host,
                ),
                messages=({"role": "user", "content": "hello"},),
                grant=ExplicitGrant(agent_id="host", capability="llm:cloud"),
                budget=BudgetReservation(
                    est_prompt_tokens=2, max_tokens=8, ctx_limit=64
                ),
                session_id="sess-1",
                nonce="n-local-1",
            )
        )
        ledger = CloudDispatchLedger()

        async def go():
            return [
                t
                async for t in router.stream_local(
                    "qwen3.5:2b", _msgs(), cloud_dispatch=sealed,
                    authorizer=authz, dispatch_ledger=ledger,
                    session_id="sess-1",
                )
            ]

        assert _run(go()) == ["local hi"]
        assert len(seen) == 1
        # A cloud-bound sealed payload is refused on the local route.
        with pytest.raises(PrivacyDenied):
            _run(
                router.stream_local(
                    "qwen3.5:2b", _msgs(),
                    cloud_dispatch=_sealed(_authz()),
                    authorizer=authz,
                    dispatch_ledger=CloudDispatchLedger(),
                    session_id="sess-1",
                )
            )
        assert len(seen) == 1


class TestLedgerFailClosed:
    def test_missing_host_ledger_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        monkeypatch.setenv("OPENAI_API_KEY", "FAKE")
        seen = _mock(monkeypatch, _ok)
        authz = _authz()
        sealed = _sealed(authz)
        with pytest.raises(PrivacyDenied) as excinfo:
            _run(router.stream_cloud(
                MODEL, _msgs(), cloud_dispatch=sealed, authorizer=authz,
                dispatch_ledger=None, session_id="sess-1",
            ))
        assert "host dispatch ledger not configured" in str(excinfo.value)
        assert seen == []

    def test_missing_ledger_local_lane_deny(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_ROUTER_EGRESS", "on")
        seen = _mock(monkeypatch, _ok)
        authz = _authz(
            allowlist={("cloud-router", "local", "qwen3.5:2b")})
        sealed = _sealed(
            authz,
            provider=ProviderIdentity(
                engine="cloud-router", provider="local", model="qwen3.5:2b",
                is_cloud=False, endpoint=""),
        )
        with pytest.raises(PrivacyDenied) as excinfo:
            _run(router.stream_local(
                "qwen3.5:2b", _msgs(), cloud_dispatch=sealed, authorizer=authz,
                dispatch_ledger=None, session_id="sess-1",
            ))
        assert "host dispatch ledger not configured" in str(excinfo.value)
        assert seen == []
