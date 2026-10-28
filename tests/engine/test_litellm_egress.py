"""E5: LiteLLM enforcement — mocked SDK only, no network.

The litellm SDK owns the final HTTP transport (no seam): these tests
prove pre-SDK enforcement (flag/grant/binding/digest/ledger). The SDK's
internal wire transformation stays NOT PROVEN by construction.
"""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace
from unittest import mock

import pytest

from openjarvis.core.types import Message, Role
from openjarvis.engine.litellm import LiteLLMEngine
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

MODEL = "groq/llama-3.3-70b"


class _Scanner:
    def scan(self, text: str):  # noqa: D102
        from types import SimpleNamespace as _NS

        return _NS(findings=[])

    def redact(self, text: str):  # noqa: D102
        return text


class _FakePolicy:
    def __init__(self, grants: dict) -> None:
        self._grants = grants

    def list_agents(self):  # noqa: D102
        return list(self._grants)

    def list_grants(self, agent_id):  # noqa: D102
        from types import SimpleNamespace as _NS

        return [_NS(capability=c) for c in self._grants.get(agent_id, [])]

    def check(self, agent_id, capability, resource=""):  # noqa: D102
        return capability in self._grants.get(agent_id, [])


def _authz(**kw):
    base = {
        "allowlist": {("litellm", "groq", MODEL)},
        "scanners": [_Scanner()],
        "capability_policy": _FakePolicy({"host": ["llm:cloud"]}),
    }
    base.update(kw)
    return CloudDispatchAuthorizer(**base)


def _sealed(authz, session="sess-1", nonce=None, **kw):
    import uuid

    base = {
        "classification": PrivacyClassification.INTERNAL,
        "provider": ProviderIdentity(
            engine="litellm", provider="groq", model=MODEL
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


def _resp(content="lite reply"):
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=content, tool_calls=None),
                finish_reason="stop",
            )
        ],
        usage=SimpleNamespace(prompt_tokens=2, completion_tokens=2, total_tokens=4),
        model=MODEL,
    )


def _engine(authz, fake_litellm, session="sess-1"):
    eng = LiteLLMEngine(
        authorizer=authz, dispatch_ledger=CloudDispatchLedger(),
        session_id=session,
    )
    return eng, fake_litellm


def _sdk(fake_resp=None, fail_with=None):
    fake = mock.MagicMock()
    if fail_with is not None:
        fake.completion.side_effect = fail_with
    else:
        fake.completion.return_value = fake_resp or _resp()
    fake.completion_cost.return_value = 0.001
    return fake


def _msgs():
    return [Message(role=Role.USER, content="hello")]


class TestFlagGrantBinding:
    @pytest.mark.parametrize("value", [None, "off", "ON", ""])
    def test_flag_states_deny(self, monkeypatch, value) -> None:
        if value is None:
            monkeypatch.delenv("ASTRA_LITELLM_EGRESS", raising=False)
        else:
            monkeypatch.setenv("ASTRA_LITELLM_EGRESS", value)
        fake = _sdk()
        authz = _authz()
        eng, _ = _engine(authz, fake)
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            with pytest.raises(PrivacyDenied):
                eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert fake.completion.call_count == 0

    def test_no_grant_expired_private_unknown(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")
        fake = _sdk()
        authz = _authz()
        eng, _ = _engine(authz, fake)
        with mock.patch.dict("sys.modules", {"litellm": fake}):
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
        assert fake.completion.call_count == 0

    def test_provider_confusion_deny(self, monkeypatch) -> None:
        # "openrouter/groq/..." must not satisfy a groq allowlist entry.
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")
        fake = _sdk()
        authz = _authz()
        eng, _ = _engine(authz, fake)
        other = _authz(allowlist={("litellm", "openrouter", "openrouter/x")})
        sealed = other.authorize(
            CloudDispatchRequest(
                classification=PrivacyClassification.INTERNAL,
                provider=ProviderIdentity(
                    engine="litellm", provider="openrouter", model="openrouter/x"
                ),
                messages=({"role": "user", "content": "hello"},),
                grant=ExplicitGrant(agent_id="host", capability="llm:cloud"),
                budget=BudgetReservation(
                    est_prompt_tokens=2, max_tokens=8, ctx_limit=64
                ),
                session_id="sess-1",
                nonce="n-confusion",
            )
        )
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            with pytest.raises(PrivacyDenied):
                eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        assert fake.completion.call_count == 0

    def test_digest_session_nonce(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")
        fake = _sdk()
        authz = _authz()
        eng, _ = _engine(authz, fake)
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            with pytest.raises(PrivacyDenied):
                eng.generate(
                    [Message(role=Role.USER, content="tampered")], model=MODEL,
                    cloud_dispatch=_sealed(authz),
                )
            with pytest.raises(PrivacyDenied):
                eng.generate(
                    _msgs(), model=MODEL,
                    cloud_dispatch=_sealed(authz, session="other"),
                )
            first = _sealed(authz, nonce="dup-n")
            second = _sealed(authz, nonce="dup-n")
            assert eng.generate(
                _msgs(), model=MODEL, cloud_dispatch=first
            )["content"] == "lite reply"
            with pytest.raises(PrivacyDenied):
                eng.generate(_msgs(), model=MODEL, cloud_dispatch=second)
            with pytest.raises(PrivacyDenied):
                eng.generate(_msgs(), model=MODEL, cloud_dispatch=first)
        assert fake.completion.call_count == 1


class TestFailureSemantics:
    def test_sdk_failure_is_unknown(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")
        fake = _sdk(fail_with=RuntimeError("sdk transport blew up"))
        authz = _authz()
        eng, _ = _engine(authz, fake)
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            with pytest.raises(RuntimeError):
                eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert [
            e.state for e in eng._dispatch_ledger._entries.values()
        ] == [STATE_UNKNOWN_OUTCOME]

    def test_unknown_no_resend(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")
        fake = _sdk(fail_with=RuntimeError("boom"))
        authz = _authz()
        eng, _ = _engine(authz, fake)
        sealed = _sealed(authz)
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            with pytest.raises(RuntimeError):
                eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
            with pytest.raises(PrivacyDenied):
                eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        assert fake.completion.call_count == 1

    def test_concurrent_single_sdk_call(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")
        fake = _sdk()
        authz = _authz()
        eng, _ = _engine(authz, fake)
        sealed = _sealed(authz)
        results: list = []

        def worker():
            try:
                with mock.patch.dict("sys.modules", {"litellm": fake}):
                    eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
                results.append("ok")
            except PrivacyDenied:
                results.append("denied")
            except BaseException as exc:
                results.append(f"error:{type(exc).__name__}")

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10.0)
        assert len(results) == 6, f"{results!r}"
        assert results.count("ok") == 1, f"{results!r}"
        assert results.count("denied") == 5, f"{results!r}"
        assert fake.completion.call_count == 1


class TestStreams:
    def test_stream_valid_partial_cancel(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")

        def chunks(contents):
            async def gen():
                for c in contents:
                    yield SimpleNamespace(
                        choices=[
                            SimpleNamespace(
                                delta=SimpleNamespace(content=c)
                            )
                        ]
                    )

            return gen()

        authz = _authz()
        eng, _ = _engine(authz, None)

        async def go_full():
            fake = mock.MagicMock()
            fake.acompletion = mock.AsyncMock(
                return_value=chunks(["a", "b"])
            )
            with mock.patch.dict("sys.modules", {"litellm": fake}):
                return [
                    t
                    async for t in eng.stream(
                        _msgs(), model=MODEL, cloud_dispatch=_sealed(authz)
                    )
                ]

        assert asyncio.run(go_full()) == ["a", "b"]

        async def go_partial():
            fake = mock.MagicMock()
            fake.acompletion = mock.AsyncMock(return_value=chunks(["x"]))
            with mock.patch.dict("sys.modules", {"litellm": fake}):
                eng2, _ = _engine(authz, None)
                sealed = _sealed(authz)
                out = [
                    t
                    async for t in eng2.stream(
                        _msgs(), model=MODEL, cloud_dispatch=sealed
                    )
                ]
                return out, eng2

        # NOTE: litellm chunk streams carry no completion marker, so a
        # truncated chunk sequence is indistinguishable from a short reply.
        # Partial-stream detection is NOT PROVEN for this SDK path.
        tokens, _ = asyncio.run(go_partial())
        assert tokens == ["x"]


class TestValidRollback:
    def test_valid_grant_one_sdk_call(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")
        fake = _sdk()
        authz = _authz()
        ledger = CloudDispatchLedger()
        eng = LiteLLMEngine(
            authorizer=authz, dispatch_ledger=ledger, session_id="sess-1"
        )
        sealed = _sealed(authz)
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            out = eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        assert out["content"] == "lite reply"
        assert fake.completion.call_count == 1
        assert [e.state for e in ledger._entries.values()] == [STATE_EXECUTED]

    def test_rollback_off_safe(self, monkeypatch) -> None:
        fake = _sdk()
        authz = _authz()
        eng, _ = _engine(authz, fake)
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "off")
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            with pytest.raises(PrivacyDenied):
                eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert fake.completion.call_count == 1


class TestSingleSendPins:
    """P0-7: litellm SDK retry suppression pins (transport-proven).

    Real-SDK evidence (litellm 1.100.1, offline MockTransport): default
    completion() resends up to 3x on 500/connect-error; max_retries=0
    yields exactly 1 send in all scenarios (success/500/connect/timeout).
    These pins ensure the production call path always carries the flag.
    """

    def test_generate_passes_max_retries_zero(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")
        fake = _sdk()
        authz = _authz()
        eng, _ = _engine(authz, fake)
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert fake.completion.call_count == 1
        _, kwargs = fake.completion.call_args
        assert kwargs.get("max_retries") == 0, kwargs

    def test_stream_passes_max_retries_zero(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")

        async def chunks():
            yield SimpleNamespace(
                choices=[SimpleNamespace(
                    delta=SimpleNamespace(content="z"))])

        async def go():
            fake = mock.MagicMock()
            fake.acompletion = mock.AsyncMock(return_value=chunks())
            with mock.patch.dict("sys.modules", {"litellm": fake}):
                authz = _authz()
                eng, _ = _engine(authz, None)
                out = [t async for t in eng.stream(
                    _msgs(), model=MODEL, cloud_dispatch=_sealed(authz))]
                _, kwargs = fake.acompletion.call_args
                return out, kwargs

        out, kwargs = asyncio.run(go())
        assert out == ["z"]
        assert kwargs.get("max_retries") == 0, kwargs

    def test_generate_passes_finite_timeout(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")
        fake = _sdk()
        authz = _authz()
        eng, _ = _engine(authz, fake)
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        _, kwargs = fake.completion.call_args
        timeout = kwargs.get("timeout")
        assert isinstance(timeout, (int, float)) and 0 < timeout < float("inf"), kwargs

    def test_caller_cannot_disable_timeout(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_LITELLM_EGRESS", "on")
        fake = _sdk()
        authz = _authz()
        eng, _ = _engine(authz, fake)
        with mock.patch.dict("sys.modules", {"litellm": fake}):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz),
                         timeout=None)
        _, kwargs = fake.completion.call_args
        timeout = kwargs.get("timeout")
        assert isinstance(timeout, (int, float)) and 0 < timeout < float("inf"), kwargs
