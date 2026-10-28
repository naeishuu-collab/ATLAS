"""E15: CloudEngine OpenAI-branch final-wire evidence via real SDK client.

Uses the REAL `openai` SDK (v2.x) with an injected httpx MockTransport —
no network. Proves the exact final HTTP request (method/URL/body) the
SDK emits, that exactly one send occurs, and that SDK-internal retry is
disabled (max_retries=0, E15 fix). Anthropic/Google/LiteLLM SDKs are not
installed offline: their wire stays NOT PROVEN.
"""

from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest

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

openai = pytest.importorskip("openai")

# E15 repro lock-in: importing capability_router pulls agents.hybrid,
# whose import-time patch wraps openai Completions.create with an 8-retry
# loop. These tests must pass WITH that global patch installed (the
# production CLI/server condition) — single send asserted below.
import openjarvis.agents.capability_router  # noqa: E402,F401


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


def _authz():
    return CloudDispatchAuthorizer(
        allowlist={("cloud", "openai", MODEL)},
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"host": ["llm:cloud"]}),
        allowed_endpoints=frozenset({ENDPOINT}),
    )


def _sealed(authz, nonce=None):
    import uuid

    return authz.authorize(
        CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(
                engine="cloud", provider="openai", model=MODEL, endpoint=ENDPOINT
            ),
            messages=({"role": "user", "content": "hello"},),
            grant=ExplicitGrant(
                agent_id="host", capability="llm:cloud",
                expires_at=time.time() + 600,
            ),
            budget=BudgetReservation(
                est_prompt_tokens=2, max_tokens=8, ctx_limit=64
            ),
            session_id="sess-1",
            nonce=nonce or f"n-{uuid.uuid4().hex}",
        )
    )


def _chat_json(content="wire reply"):
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1,
        "model": MODEL,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4},
    }


def _wire_engine(monkeypatch, handler, api_key="sk-test-fake",
                 authz_factory=None):
    """CloudEngine with a REAL openai client over MockTransport."""
    from openjarvis.engine.cloud import CloudEngine

    monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
    captured: list = []

    def _handle(req: httpx.Request) -> httpx.Response:
        captured.append(req)
        return handler(req)

    client = openai.OpenAI(
        api_key=api_key,
        http_client=httpx.Client(transport=httpx.MockTransport(_handle)),
        max_retries=0,
    )
    eng = CloudEngine.__new__(CloudEngine)
    eng._openai_client = client
    for attr in (
        "anthropic", "google", "openrouter", "atlascloud", "minimax",
        "deepseek", "codex",
    ):
        setattr(eng, f"_{attr}_client", None)
    eng._thought_sigs = {}
    authz = (authz_factory or _authz)()
    eng._authorizer = authz
    eng._dispatch_ledger = CloudDispatchLedger()
    eng._session_id = "sess-1"
    eng._seen_nonces = set()
    import threading as _t

    eng._nonce_lock = _t.Lock()
    return eng, authz, captured


def _msgs():
    return [Message(role=Role.USER, content="hello")]


NEMOTRON_MODEL = "openrouter/nvidia/nemotron-3.5-super-vl:free"
NEMOTRON_PROVIDER_MODEL = "nvidia/nemotron-3.5-super-vl:free"
NEMOTRON_ENDPOINT = "https://openrouter.ai/api/v1"


def _nemotron_authz():
    return CloudDispatchAuthorizer(
        allowlist={("cloud", "openrouter", NEMOTRON_MODEL)},
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"host": ["llm:cloud"]}),
        allowed_endpoints=frozenset({NEMOTRON_ENDPOINT}),
    )


def _nemotron_sealed(authz):
    import uuid

    return authz.authorize(
        CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(
                engine="cloud", provider="openrouter", model=NEMOTRON_MODEL,
                endpoint=NEMOTRON_ENDPOINT,
            ),
            messages=({"role": "user", "content": "hello"},),
            grant=ExplicitGrant(
                agent_id="host", capability="llm:cloud",
                expires_at=time.time() + 600,
            ),
            budget=BudgetReservation(
                est_prompt_tokens=2, max_tokens=8, ctx_limit=64
            ),
            session_id="sess-nemotron",
            nonce=f"n-{uuid.uuid4().hex}",
        )
    )


def _nemotron_wire_engine(monkeypatch, handler):
    from openjarvis.engine.cloud import CloudEngine

    monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
    captured: list[httpx.Request] = []

    def _handle(req: httpx.Request) -> httpx.Response:
        captured.append(req)
        return handler(req)

    client = openai.OpenAI(
        base_url=NEMOTRON_ENDPOINT,
        api_key="sk-or-test-fake",
        http_client=httpx.Client(transport=httpx.MockTransport(_handle)),
        max_retries=0,
    )
    eng = CloudEngine.__new__(CloudEngine)
    eng._openai_client = None
    eng._openrouter_client = client
    for attr in (
        "anthropic", "google", "atlascloud", "minimax", "deepseek", "codex",
    ):
        setattr(eng, f"_{attr}_client", None)
    eng._thought_sigs = {}
    eng._authorizer = _nemotron_authz()
    eng._dispatch_ledger = CloudDispatchLedger()
    eng._session_id = "sess-nemotron"
    eng._seen_nonces = set()
    import threading as _t

    eng._nonce_lock = _t.Lock()
    return eng, captured


class TestFinalWire:
    def test_exact_request_bytes_single_send(self, monkeypatch) -> None:
        eng, authz, captured = _wire_engine(
            monkeypatch, lambda req: httpx.Response(200, json=_chat_json())
        )
        out = eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        assert out["content"] == "wire reply"
        assert len(captured) == 1
        req = captured[0]
        assert req.method == "POST"
        assert str(req.url) == "https://api.openai.com/v1/chat/completions"
        body = json.loads(req.content)
        assert body["model"] == MODEL
        assert body["messages"] == [{"role": "user", "content": "hello"}]
        assert req.headers["authorization"] == "Bearer sk-test-fake"
        assert [e.state for e in eng._dispatch_ledger._entries.values()] == [
            STATE_EXECUTED
        ]

    def test_sdk_retry_disabled_single_send_on_500(self, monkeypatch) -> None:
        eng, authz, captured = _wire_engine(
            monkeypatch,
            lambda req: httpx.Response(500, json={"error": {"message": "x"}}),
        )
        assert eng._openai_client.max_retries == 0
        with pytest.raises(Exception):
            eng.generate(_msgs(), model=MODEL, cloud_dispatch=_sealed(authz))
        # No invisible SDK resend: exactly one HTTP attempt.
        assert len(captured) == 1
        assert [
            e.state for e in eng._dispatch_ledger._entries.values()
        ] == [STATE_UNKNOWN_OUTCOME]

    def test_wire_mismatch_shape_denied(self, monkeypatch) -> None:
        # Tampered message digest must deny before any HTTP attempt.
        eng, authz, captured = _wire_engine(
            monkeypatch, lambda req: httpx.Response(200, json=_chat_json())
        )
        with pytest.raises(PrivacyDenied):
            eng.generate(
                [Message(role=Role.USER, content="tampered")],
                model=MODEL,
                cloud_dispatch=_sealed(authz),
            )
        assert len(captured) == 0


class TestNemotronOpenRouterWire:
    def test_free_model_exact_id_and_capability_options(self, monkeypatch) -> None:
        eng, captured = _nemotron_wire_engine(
            monkeypatch,
            lambda req: httpx.Response(200, json={
                **_chat_json(),
                "model": NEMOTRON_PROVIDER_MODEL,
            }),
        )
        authz = eng._authorizer
        tools = [{
            "type": "function",
            "function": {"name": "lookup", "parameters": {}},
        }]
        response_format = {"type": "json_object"}
        out = eng.generate(
            _msgs(),
            model=NEMOTRON_MODEL,
            tools=tools,
            response_format=response_format,
            cloud_dispatch=_nemotron_sealed(authz),
        )

        assert out["content"] == "wire reply"
        assert len(captured) == 1
        body = json.loads(captured[0].content)
        assert body["model"] == NEMOTRON_PROVIDER_MODEL
        assert body["tools"] == tools
        assert body["response_format"] == response_format
        assert str(captured[0].url) == (
            "https://openrouter.ai/api/v1/chat/completions"
        )

    def test_free_model_streams_through_mocktransport(self, monkeypatch) -> None:
        sse = (
            'data: {"id":"nm","object":"chat.completion.chunk",'
            '"created":1,"model":"nvidia/nemotron-3.5-super-vl:free",'
            '"choices":[{"index":0,"delta":{"content":"ok"}}]}\n\n'
            "data: [DONE]\n\n"
        ).encode()
        eng, captured = _nemotron_wire_engine(
            monkeypatch,
            lambda req: httpx.Response(
                200, headers={"content-type": "text/event-stream"}, content=sse
            ),
        )
        authz = eng._authorizer

        async def _collect():
            return [
                token
                async for token in eng.stream(
                    _msgs(),
                    model=NEMOTRON_MODEL,
                    cloud_dispatch=_nemotron_sealed(authz),
                )
            ]

        assert asyncio.run(_collect()) == ["ok"]
        assert len(captured) == 1
        assert json.loads(captured[0].content)["model"] == NEMOTRON_PROVIDER_MODEL


CANARY_MODEL = "gpt-4o-mini"
CANARY_PROMPT = "Return exactly the word ASTRA_CANARY."
CANARY_MAX_TOKENS = 16


def _canary_authz():
    return CloudDispatchAuthorizer(
        allowlist={("cloud", "openai", CANARY_MODEL)},
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"host": ["llm:cloud"]}),
        allowed_endpoints=frozenset({ENDPOINT}),
    )


def _canary_sealed(authz, nonce=None):
    import uuid

    return authz.authorize(
        CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(
                engine="cloud", provider="openai", model=CANARY_MODEL,
                endpoint=ENDPOINT,
            ),
            messages=({"role": "user", "content": CANARY_PROMPT},),
            grant=ExplicitGrant(
                agent_id="host", capability="llm:cloud",
                expires_at=time.time() + 600,
            ),
            budget=BudgetReservation(
                est_prompt_tokens=32, max_tokens=CANARY_MAX_TOKENS,
                ctx_limit=4096, per_request_usd=0.01,
                session_left_usd=0.01,
            ),
            # Test-engine session ("sess-1"); production canary binds a
            # fresh per-run session the same way.
            session_id="sess-1",
            nonce=nonce or f"n-{uuid.uuid4().hex}",
        )
    )


def _canary_msgs():
    return [Message(role=Role.USER, content=CANARY_PROMPT)]


class TestCanaryPreflight:
    """P0-8A frozen canary shape (gpt-4o-mini, synthetic prompt).

    Offline preflight of the exact P0-8B identity/binding/single-send
    contract. No network, no real credentials.
    """

    def test_canary_identity_single_send(self, monkeypatch) -> None:
        eng, authz, captured = _wire_engine(
            monkeypatch,
            lambda req: httpx.Response(200, json=_chat_json()),
            authz_factory=_canary_authz,
        )
        out = eng.generate(
            _canary_msgs(), model=CANARY_MODEL, max_tokens=CANARY_MAX_TOKENS,
            cloud_dispatch=_canary_sealed(authz),
        )
        assert out["content"] == "wire reply"
        assert len(captured) == 1
        body = json.loads(captured[0].content)
        assert body["model"] == CANARY_MODEL
        assert body["messages"] == [{"role": "user", "content": CANARY_PROMPT}]
        # openai SDK v2 normalizes max_tokens to max_completion_tokens
        # for current models; either wire form bounds output identically.
        assert body.get("max_tokens", body.get("max_completion_tokens")) == (
            CANARY_MAX_TOKENS)

    def test_canary_wrong_model_denied_zero_sends(
        self, monkeypatch
    ) -> None:
        eng, authz, captured = _wire_engine(
            monkeypatch,
            lambda req: httpx.Response(200, json=_chat_json()),
            authz_factory=_canary_authz,
        )
        with pytest.raises(PrivacyDenied):
            eng.generate(
                _canary_msgs(), model="gpt-4o",
                cloud_dispatch=_canary_sealed(authz),
            )
        assert len(captured) == 0

    def test_sentinel_credential_never_logged(
        self, monkeypatch, caplog
    ) -> None:
        sentinel = "ASTRA_FAKE_SECRET_DO_NOT_LOG"
        eng, authz, captured = _wire_engine(
            monkeypatch,
            lambda req: httpx.Response(
                500, json={"error": {"m": "x"}}),
            authz_factory=_canary_authz,
            api_key=sentinel,
        )
        with caplog.at_level("DEBUG"):
            with pytest.raises(Exception) as exc_info:
                eng.generate(
                    _canary_msgs(), model=CANARY_MODEL,
                    max_tokens=CANARY_MAX_TOKENS,
                    cloud_dispatch=_canary_sealed(authz),
                )
        assert sentinel not in caplog.text
        assert sentinel not in str(exc_info.value)
        # The credential reaches ONLY the wire Authorization header.
        assert captured[0].headers["authorization"] == f"Bearer {sentinel}"
        assert [e.state for e in eng._dispatch_ledger._entries.values()] == [
            STATE_UNKNOWN_OUTCOME
        ]
class TestCanaryTemperatureRetryBoundary:
    """P0-8A.1: temperature-400 retry send-count on the canary path.

    The shared helper retries once without temperature after a
    DEFINITIVE HTTP 400 rejection carrying an unsupported-temperature
    message. A second send therefore proves the first had no effect,
    but the frozen canary contract allows at most one transport send
    across every outcome.
    """

    def _temp_400(self):
        return httpx.Response(400, json={
            "error": {"message": "Unsupported value: 'temperature' "
                                 "does not support 0.7 in this model. "
                                 "Only the default value is supported.",
                      "param": "temperature", "code": "unsupported_value"}})

    def _plain_400(self):
        return httpx.Response(400, json={
            "error": {"message": "Bad request: content filtered.",
                      "param": None, "code": "content_filter"}})

    def test_plain_400_single_send_unknown(self, monkeypatch) -> None:
        eng, authz, captured = _wire_engine(
            monkeypatch, lambda req: self._plain_400(),
            authz_factory=_canary_authz,
        )
        with pytest.raises(Exception):
            eng.generate(
                _canary_msgs(), model=CANARY_MODEL,
                max_tokens=CANARY_MAX_TOKENS,
                cloud_dispatch=_canary_sealed(authz),
            )
        assert len(captured) == 1
        assert [e.state for e in eng._dispatch_ledger._entries.values()] == [
            STATE_UNKNOWN_OUTCOME
        ]

    def test_temperature_400_single_send(self, monkeypatch) -> None:
        eng, authz, captured = _wire_engine(
            monkeypatch, lambda req: self._temp_400(),
            authz_factory=_canary_authz,
        )
        with pytest.raises(Exception):
            eng.generate(
                _canary_msgs(), model=CANARY_MODEL,
                max_tokens=CANARY_MAX_TOKENS,
                cloud_dispatch=_canary_sealed(authz),
                _astra_single_send=True,
            )
        assert len(captured) == 1, (
            f"canary contract: at most one send, got {len(captured)}")
        assert [e.state for e in eng._dispatch_ledger._entries.values()] == [
            STATE_UNKNOWN_OUTCOME
        ]


    def test_temperature_400_legacy_retry_preserved(self, monkeypatch) -> None:
        # Without the explicit single-send flag, the historical
        # temperature-400 fallback (second send after definitive 400
        # rejection) is preserved for existing non-canary paths. The
        # MockTransport answers the retried (temperature-free) call.
        eng, authz, captured = _wire_engine(
            monkeypatch, lambda req: self._temp_400(),
            authz_factory=_canary_authz,
        )
        with pytest.raises(Exception):
            eng.generate(
                _canary_msgs(), model=CANARY_MODEL,
                max_tokens=CANARY_MAX_TOKENS,
                cloud_dispatch=_canary_sealed(authz),
            )
        assert len(captured) == 2

    def test_timeout_single_send_unknown(self, monkeypatch) -> None:
        def _slow(req):
            raise httpx.TimeoutException("too slow")

        eng, authz, captured = _wire_engine(
            monkeypatch, _slow, authz_factory=_canary_authz,
        )
        with pytest.raises(Exception):
            eng.generate(
                _canary_msgs(), model=CANARY_MODEL,
                max_tokens=CANARY_MAX_TOKENS,
                cloud_dispatch=_canary_sealed(authz),
            )
        assert len(captured) == 1
        assert [e.state for e in eng._dispatch_ledger._entries.values()] == [
            STATE_UNKNOWN_OUTCOME
        ]
