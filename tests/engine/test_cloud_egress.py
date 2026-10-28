"""E6: CloudEngine enforcement — mocked SDK clients only, no network.

The vendor SDKs own the final HTTP transport (no seam): these tests prove
pre-SDK enforcement (flag/grant/binding/digest/ledger/session/nonce).
SDK-internal wire transformation stays NOT PROVEN by construction.
"""

from __future__ import annotations

import threading
import time
from types import SimpleNamespace
from unittest import mock

import pytest

from openjarvis.core.types import Message, Role
from openjarvis.engine.cloud import CloudEngine
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
        "allowlist": {("cloud", "openai", MODEL)},
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
            engine="cloud", provider="openai", model=MODEL, endpoint=ENDPOINT
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


def _resp(content="cloud reply"):
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


def _engine(authz, session="sess-1"):
    eng = CloudEngine.__new__(CloudEngine)
    eng._openai_client = mock.MagicMock()
    eng._openai_client.chat.completions.create.return_value = _resp()
    for attr in (
        "anthropic", "google", "openrouter", "atlascloud", "minimax",
        "deepseek", "codex",
    ):
        setattr(eng, f"_{attr}_client", None)
    eng._thought_sigs = {}
    eng._authorizer = authz
    eng._dispatch_ledger = CloudDispatchLedger()
    eng._session_id = session
    eng._seen_nonces = set()
    import threading as _t

    eng._nonce_lock = _t.Lock()
    return eng


def _msgs():
    return [Message(role=Role.USER, content="hello")]


class TestFlagGrantBinding:
    @pytest.mark.parametrize("value", [None, "off", "ON", ""])
    def test_flag_states_deny(self, monkeypatch, value) -> None:
        if value is None:
            monkeypatch.delenv("ASTRA_CLOUD_EGRESS", raising=False)
        else:
            monkeypatch.setenv("ASTRA_CLOUD_EGRESS", value)
        authz = _authz()
        eng = _engine(authz)
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert eng._openai_client.chat.completions.create.call_count == 0

    def test_no_grant_expired_private_unknown(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
        authz = _authz()
        eng = _engine(authz)
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
        assert eng._openai_client.chat.completions.create.call_count == 0

    def test_provider_routing_and_mismatch(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
        authz = _authz()
        eng = _engine(authz)
        # Unrecognized model names fail closed instead of SDK fall-through.
        with pytest.raises(PrivacyDenied):
            eng.generate(
                _msgs(), model="qwen3.5:0.8b", cloud_dispatch=_sealed(authz)
            )
        # Provider confusion: anthropic key must not satisfy openai binding.
        other = _authz(
            allowlist={("cloud", "anthropic", "claude-x")},
            allowed_endpoints=frozenset({"https://api.anthropic.com"}),
        )
        sealed = other.authorize(
            CloudDispatchRequest(
                classification=PrivacyClassification.INTERNAL,
                provider=ProviderIdentity(
                    engine="cloud", provider="anthropic", model="claude-x",
                    endpoint="https://api.anthropic.com",
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
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        assert eng._openai_client.chat.completions.create.call_count == 0

    def test_digest_session_nonce(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
        authz = _authz()
        eng = _engine(authz)
        with pytest.raises(PrivacyDenied):
            eng.generate(
                [Message(role=Role.USER, content="tampered")], model=MODEL,
                cloud_dispatch=_sealed(authz),
            )
        with pytest.raises(PrivacyDenied):
            eng.generate(
                _msgs(), model=MODEL, cloud_dispatch=_sealed(authz, session="s9")
            )
        first = _sealed(authz, nonce="dup-n")
        second = _sealed(authz, nonce="dup-n")
        assert eng.generate(
            _msgs(), model=MODEL, cloud_dispatch=first
        )["content"] == "cloud reply"
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=second)
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=first)
        assert eng._openai_client.chat.completions.create.call_count == 1


class TestFailureSemantics:
    def test_sdk_failure_is_unknown(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
        authz = _authz()
        eng = _engine(authz)
        eng._openai_client.chat.completions.create.side_effect = RuntimeError("sdk")
        with pytest.raises(RuntimeError):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert [
            e.state for e in eng._dispatch_ledger._entries.values()
        ] == [STATE_UNKNOWN_OUTCOME]

    def test_unknown_no_resend(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
        authz = _authz()
        eng = _engine(authz)
        eng._openai_client.chat.completions.create.side_effect = RuntimeError("sdk")
        sealed = _sealed(authz)
        with pytest.raises(RuntimeError):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        assert eng._openai_client.chat.completions.create.call_count == 1

    def test_temperature_retry_envelope(self, monkeypatch) -> None:
        # The SDK-internal temperature retry keeps messages identical under
        # one dispatch entry (same-dispatch continuation, single logical send).
        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
        calls: list = []
        err = Exception(
            "Error code: 400 - Unsupported value: 'temperature' only default"
        )
        authz = _authz()
        eng = _engine(authz)

        def create(**kw):
            calls.append(kw)
            if "temperature" in kw:
                raise err
            return _resp()

        eng._openai_client.chat.completions.create.side_effect = create
        out = eng.generate(
            _msgs(), model=MODEL, cloud_dispatch=_sealed(authz),
        )
        assert out["content"] == "cloud reply"
        assert len(calls) == 2
        assert [e.state for e in eng._dispatch_ledger._entries.values()] == [
            STATE_EXECUTED
        ]

    def test_concurrent_single_sdk_call(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
        authz = _authz()
        eng = _engine(authz)
        sealed = _sealed(authz)
        results: list = []

        def worker():
            try:
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
        assert eng._openai_client.chat.completions.create.call_count == 1


class TestValidRollback:
    def test_valid_grant_one_sdk_call(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
        authz = _authz()
        ledger = CloudDispatchLedger()
        eng = _engine(authz)
        eng._dispatch_ledger = ledger
        sealed = _sealed(authz)
        out = eng.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        assert out["content"] == "cloud reply"
        assert eng._openai_client.chat.completions.create.call_count == 1
        assert [e.state for e in ledger._entries.values()] == [STATE_EXECUTED]

    def test_rollback_off_safe(self, monkeypatch) -> None:
        authz = _authz()
        eng = _engine(authz)
        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
        eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "off")
        with pytest.raises(PrivacyDenied):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert eng._openai_client.chat.completions.create.call_count == 1
