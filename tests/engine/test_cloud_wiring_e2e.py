"""Cloud host wiring E2E (offline; MockTransport only — no network).

Proves the wiring chain demanded by the host authority plan:

    Host Config -> Host Supply Factory -> Cloud Authorizer
    -> Dispatch Ledger -> Session Binding -> CloudEngine -> MockTransport

The engine is constructed EXACTLY as the serve lane does:

    CloudEngine(authorizer=supply.cloud_authorizer,
                dispatch_ledger=supply.dispatch_ledger,
                session_id=supply.session_id)

with a real openai SDK client over ``httpx.MockTransport``. Deny matrix
covers flag-off, missing authorizer, missing session, tamper, replay,
model/endpoint binding mismatch, unauthorized retry, retry
re-authorization, PRIVATE cloud, unknown privacy/provider/endpoint, and
missing capability.

Two chains, one ledger rule: the factory ``CloudDispatchPlan`` path begins
and closes its ledger inside ``host_cloud_dispatch`` (covered by the host
supply E2E suites); the engine path authorizes from the same FACTORY authorizer
and the engine itself begins/marks/finishes its entry in ``_enforce``. Each
seal is begun by exactly one chain.

No real credential, no socket, no OS mutation beyond ``tmp_path``.
"""

from __future__ import annotations

import dataclasses
import time
from types import SimpleNamespace

import httpx
import pytest

from openjarvis.agents.host_routing import HostEgressPolicy
from openjarvis.agents.host_supply_factory import (
    ENDPOINT_UNKNOWN,
    MODE_CLOUD,
    MODE_SHADOW_ONLY,
    PRIVACY_UNKNOWN,
    PROVIDER_UNKNOWN,
    HostConfig,
    HostSupplyError,
    build_host_supply,
    host_cloud_dispatch,
    key_str,
)
from openjarvis.core.types import Message, Role

MODEL = "gpt-4o"
ENGINE = "cloud"
PROVIDER = "openai"
OPENAI_KEY = (ENGINE, PROVIDER, MODEL)
OPENAI_EP = "https://api.openai.com/v1"
GROQ_KEY = ("litellm", "groq", "llama-3.3-70b")
SESSION = "astra-wiring-e2e-session"
AGENT = "agent-1"
NOW = time.time()

CHAT_JSON = {
    "id": "chatcmpl-wiring-e2e",
    "object": "chat.completion",
    "created": 1,
    "model": MODEL,
    "choices": [{"index": 0,
                 "message": {"role": "assistant", "content": "wired reply"},
                 "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 2, "completion_tokens": 2, "total_tokens": 4},
}


class _NoFindingsScanner:
    def scan(self, text: str):
        return SimpleNamespace(findings=[])

    def redact(self, text: str):
        return text


class _DummyGrant:
    capability = "llm:cloud"


class _Policy:
    def __init__(self, grants: dict) -> None:
        self._grants = grants

    def list_agents(self):
        return list(self._grants)

    def list_grants(self, agent_id):
        return [_DummyGrant() for _ in self._grants.get(agent_id, [])]

    def check(self, agent_id, capability, resource=""):
        return capability in self._grants.get(agent_id, [])


def _cards():
    return [
        {"engine": ENGINE, "provider": PROVIDER, "model": MODEL,
         "capabilities": ["TEXT"], "ctx_limit": 8192, "cost_per_1k": 0.0006,
         "latency_p50_ms": 900.0, "is_cloud": True},
        {"engine": GROQ_KEY[0], "provider": GROQ_KEY[1],
         "model": GROQ_KEY[2], "capabilities": ["TEXT"], "ctx_limit": 8192,
         "cost_per_1k": 0.0005, "latency_p50_ms": 900.0, "is_cloud": True},
    ]


def _cfg(**over) -> HostConfig:
    args: dict = dict(
        mode=MODE_CLOUD,
        model_registry=tuple(_cards()),
        snapshot_status={OPENAI_KEY: True, GROQ_KEY: True},
        snapshot_version=1,
        snapshot_issued_at=NOW,
        shadow_enabled=True,
        cloud_egress_enabled=True,
        privacy_policy={AGENT: "PUBLIC"},
        egress_policy=HostEgressPolicy(allow_cloud=True,
                                       allowed_providers=(PROVIDER,
                                                          GROQ_KEY[1])),
        provider_allowlist=(OPENAI_KEY, GROQ_KEY),
        endpoints={key_str(OPENAI_KEY): OPENAI_EP},
        endpoint_allowlist=(OPENAI_EP,),
        scanners=(_NoFindingsScanner(),),
        capability_policy=_Policy({AGENT: ["llm:cloud"]}),
        session_identity=SESSION,
        credential_reference="env:ASTRA_WIRING_E2E_KEY",
        credential_available=lambda provider: True,
        minimizer_allow=("model", "messages", "messages.role",
                         "messages.content", "stream"),
        minimizer_purpose="host-cloud-dispatch",
    )
    args.update(over)
    return HostConfig(**args)


def _bundle(**over):
    return build_host_supply(_cfg(**over), now=NOW)


def _plan_chain(bundle, content="hello"):
    """Factory CloudDispatchPlan chain (its own ledger lifecycle)."""
    return host_cloud_dispatch(
        bundle, engine=ENGINE, provider=PROVIDER, model=MODEL,
        messages=[Message(role=Role.USER, content=content)],
        agent_id=AGENT, capability="llm:cloud")


def _seal(bundle, content="hello"):
    """Mint a fresh authorization from the FACTORY-built authorizer.

    Engine-side send path: the engine begins its own ledger entry.
    """
    import uuid as _uuid

    from openjarvis.engine._base import messages_to_dicts
    from openjarvis.security.cloud_dispatch import (
        BudgetReservation,
        CloudDispatchRequest,
        ExplicitGrant,
        PrivacyClassification,
        ProviderIdentity,
    )

    wire = tuple(
        {"role": str(m.get("role", "user")), "content": str(m.get("content", ""))}
        for m in messages_to_dicts([Message(role=Role.USER, content=content)])
    )
    return bundle.cloud_authorizer.authorize(
        CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(
                engine=ENGINE, provider=PROVIDER, model=MODEL,
                is_cloud=True, endpoint=OPENAI_EP),
            messages=wire,
            grant=ExplicitGrant(agent_id=AGENT, capability="llm:cloud"),
            budget=BudgetReservation(
                est_prompt_tokens=256, max_tokens=64, ctx_limit=8192),
            session_id=bundle.session_id,
            nonce=f"w-{_uuid.uuid4().hex}",
        ))


def _msgs(content="hello"):
    return [Message(role=Role.USER, content=content)]


def _wired_engine(monkeypatch, bundle, handler, *, flag="on", authorizer="keep"):
    """CloudEngine constructed EXACTLY as the serve lane wires + MockTransport."""
    openai = pytest.importorskip("openai")
    if flag == "on":
        monkeypatch.setenv("ASTRA_CLOUD_EGRESS", "on")
    else:
        monkeypatch.delenv("ASTRA_CLOUD_EGRESS", raising=False)
    monkeypatch.setenv("ASTRA_WIRING_E2E_KEY", "sk-wiring-e2e-fake")
    captured: list = []

    def _handle(req: httpx.Request) -> httpx.Response:
        captured.append(req)
        return handler(req)

    from openjarvis.engine.cloud import CloudEngine

    engine = CloudEngine(
        authorizer=bundle.cloud_authorizer,    # host-issued, factory-minted
        dispatch_ledger=bundle.dispatch_ledger,
        session_id=bundle.session_id,
    )
    engine._openai_client = openai.OpenAI(
        api_key="sk-wiring-e2e-fake",
        http_client=httpx.Client(transport=httpx.MockTransport(_handle)),
        max_retries=0,
    )
    return engine, captured


def _ledger_states(engine):
    return [e.state for e in engine._dispatch_ledger._entries.values()]


def _wired_engine_check(monkeypatch, bundle):
    """Wired engine whose captured sends must stay zero in deny tests."""
    return _wired_engine(monkeypatch, bundle,
                         lambda req: httpx.Response(200, json=CHAT_JSON))


# ---------------------------------------------------------------------------
# Wiring static pins (construction sites carry host supply authority)
# ---------------------------------------------------------------------------


class TestWiringPins:
    def test_serve_lane_constructs_supply_bound_cloud_engine(self):
        import pathlib

        import openjarvis as _pkg

        src = (pathlib.Path(_pkg.__file__).parent
              / "cli" / "serve.py").read_text(encoding="utf-8")
        assert "cloud_engine = CloudEngine(" in src
        assert "authorizer=(host_supply.cloud_authorizer" in src
        assert "dispatch_ledger=(host_supply.dispatch_ledger" in src
        assert "session_id=(host_supply.session_id" in src
        assert "host_supply = _load_shadow_host_supply(" in src
        assert "host_supply=host_supply," in src  # create_app pass-through

    def test_routes_reload_uses_app_state_supply(self):
        import pathlib

        import openjarvis as _pkg

        src = (pathlib.Path(_pkg.__file__).parent
              / "server" / "routes.py").read_text(encoding="utf-8")
        assert 'getattr(request.app.state, "host_supply", None)' in src
        assert "_supply.cloud_authorizer if _supply else None" in src

    def test_app_state_carries_host_supply(self):
        import pathlib

        import openjarvis as _pkg

        src = (pathlib.Path(_pkg.__file__).parent
              / "server" / "app.py").read_text(encoding="utf-8")
        assert "host_supply: Any = None" in src
        assert "app.state.host_supply = host_supply" in src

    def test_builder_supplies_scanners_to_factory(self):
        import pathlib

        import openjarvis as _pkg

        src = (pathlib.Path(_pkg.__file__).parent
              / "system" / "builder.py").read_text(encoding="utf-8")
        assert "scanners=sec.scanners" in src


# ---------------------------------------------------------------------------
# Factory -> CloudEngine binding over MockTransport (the real chain)
# ---------------------------------------------------------------------------


class TestFactoryToEngineBinding:
    def test_wired_engine_single_send_executed(self, monkeypatch):
        bundle = _bundle()
        engine, captured = _wired_engine(
            monkeypatch, bundle,
            lambda req: httpx.Response(200, json=CHAT_JSON))
        out = engine.generate(_msgs(), model=MODEL,
                              cloud_dispatch=_seal(bundle))
        assert out["content"] == "wired reply"
        assert len(captured) == 1                    # exactly once
        assert str(captured[0].url).startswith(OPENAI_EP)
        assert _ledger_states(engine) == ["EXECUTED"]

    def test_default_deny_survives_the_wiring(self, monkeypatch):
        bundle = _bundle()
        engine, captured = _wired_engine(
            monkeypatch, bundle,
            lambda req: httpx.Response(200, json=CHAT_JSON), flag="off")
        from openjarvis.security.cloud_dispatch import PrivacyDenied

        with pytest.raises(PrivacyDenied) as excinfo:
            engine.generate(_msgs(), model=MODEL, cloud_dispatch=_seal(bundle))
        assert excinfo.value.code == "FLAG_OFF"
        assert captured == []                        # zero sends while OFF


# ---------------------------------------------------------------------------
# Deny matrix through the wired engine
# ---------------------------------------------------------------------------


class TestWiredDenyMatrix:
    def test_missing_authorizer_deny(self, monkeypatch):
        bundle = _bundle()
        sealed = _seal(bundle)
        from openjarvis.security.cloud_dispatch import PrivacyDenied

        engine, captured = _wired_engine_check(monkeypatch, bundle)
        engine._authorizer = None                    # removed post-wiring
        with pytest.raises(PrivacyDenied) as excinfo:
            engine.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        assert excinfo.value.code == "CLOUD_PROVIDER_NOT_ALLOWED"
        assert captured == []

    def test_missing_session_deny(self, monkeypatch):
        bundle = _bundle()
        sealed = _seal(bundle)
        from openjarvis.security.cloud_dispatch import PrivacyDenied

        engine, captured = _wired_engine_check(monkeypatch, bundle)
        engine._session_id = "different-host-session"
        with pytest.raises(PrivacyDenied) as excinfo:
            engine.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        assert excinfo.value.code == "SESSION_MISMATCH"
        assert captured == []

    def test_tampered_payload_deny_zero_sends(self, monkeypatch):
        bundle = _bundle()
        sealed = _seal(bundle, "hello")
        from openjarvis.security.cloud_dispatch import PrivacyDenied

        engine, captured = _wired_engine(
            monkeypatch, bundle,
            lambda req: httpx.Response(200, json=CHAT_JSON))
        with pytest.raises(PrivacyDenied):
            engine.generate(_msgs("tampered"), model=MODEL,
                            cloud_dispatch=sealed)
        assert captured == []

    def test_replay_deny(self, monkeypatch):
        # First send succeeds; reusing the SAME seal is a replay: real
        # retries require NEW authorization.
        bundle = _bundle()
        sealed = _seal(bundle)
        from openjarvis.security.cloud_dispatch import PrivacyDenied

        engine, captured = _wired_engine(
            monkeypatch, bundle,
            lambda req: httpx.Response(200, json=CHAT_JSON))
        out = engine.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        assert out["content"] == "wired reply"
        with pytest.raises(PrivacyDenied) as excinfo:
            engine.generate(_msgs(), model=MODEL, cloud_dispatch=sealed)
        assert excinfo.value.code == "NONCE_REPLAY"
        assert len(captured) == 1

    def test_model_binding_mismatch_deny(self, monkeypatch):
        bundle = _bundle()
        sealed = _seal(bundle)
        from openjarvis.security.cloud_dispatch import PrivacyDenied

        engine, captured = _wired_engine(
            monkeypatch, bundle,
            lambda req: httpx.Response(200, json=CHAT_JSON))
        with pytest.raises(PrivacyDenied) as excinfo:
            engine.generate(_msgs(),
                            model="claude-3-5-sonnet-latest",
                            cloud_dispatch=sealed)
        assert excinfo.value.code == "CLOUD_PROVIDER_NOT_ALLOWED"
        assert captured == []

    def test_endpoint_binding_mismatch_deny(self, monkeypatch):
        bundle = _bundle()
        sealed = _seal(bundle)
        from openjarvis.security.cloud_dispatch import (
            ENDPOINT_NOT_ALLOWED,
            PrivacyDenied,
            ProviderIdentity,
        )

        # Post-mint destination swap: same seal, hostile endpoint.
        tampered = dataclasses.replace(
            sealed,
            provider=ProviderIdentity(
                engine=ENGINE, provider=PROVIDER, model=MODEL,
                is_cloud=True, endpoint="https://attacker.invalid/v1"))
        engine, captured = _wired_engine(
            monkeypatch, bundle,
            lambda req: httpx.Response(200, json=CHAT_JSON))
        with pytest.raises(PrivacyDenied) as excinfo:
            engine.generate(_msgs(), model=MODEL, cloud_dispatch=tampered)
        assert excinfo.value.code == ENDPOINT_NOT_ALLOWED
        assert captured == []

    def test_error_outcome_unknown_then_reauthorize(self, monkeypatch):
        # A 5xx is UNKNOWN_OUTCOME: no invisible resend. A retry MUST mint
        # NEW authorization (fresh nonce); replaying the failed seal denies.
        bundle = _bundle()
        engine, captured = _wired_engine(
            monkeypatch, bundle,
            lambda req: httpx.Response(500, json={"error": {"message": "x"}}))
        from openjarvis.security.cloud_dispatch import PrivacyDenied

        sealed_a = _seal(bundle, "first")
        with pytest.raises(Exception):
            engine.generate(_msgs("first"), model=MODEL,
                            cloud_dispatch=sealed_a)
        assert len(captured) == 1                    # one honest send; the
        # 5xx outcome is UNKNOWN, no invisible resend ever happens.
        assert _ledger_states(engine) == ["UNKNOWN_OUTCOME"]

        # Re-authorize (fresh nonce) on the SAME wired engine, transport OK.
        openai = pytest.importorskip("openai")
        engine._openai_client = openai.OpenAI(
            api_key="sk-wiring-e2e-fake",
            http_client=httpx.Client(transport=httpx.MockTransport(
                lambda req: httpx.Response(200, json=CHAT_JSON))),
            max_retries=0,
        )
        sealed_b = _seal(bundle, "retry")
        out = engine.generate(_msgs("retry"), model=MODEL,
                              cloud_dispatch=sealed_b)
        assert out["content"] == "wired reply"
        assert _ledger_states(engine) == ["UNKNOWN_OUTCOME", "EXECUTED"]

        # Replaying the consumed/failed seal = unauthorized retry.
        with pytest.raises(PrivacyDenied) as excinfo:
            engine.generate(_msgs("first"), model=MODEL,
                            cloud_dispatch=sealed_a)
        assert excinfo.value.code == "NONCE_REPLAY"

    def test_grantless_agent_deny(self):
        # Host policy grants nothing: the LLM itself can never mint authority.
        bundle = _bundle(capability_policy=_Policy({}))
        from openjarvis.security.cloud_dispatch import PrivacyDenied

        with pytest.raises(PrivacyDenied):
            _seal(bundle)


# ---------------------------------------------------------------------------
# Host-chain denies (factory level; zero transport)
# ---------------------------------------------------------------------------


class TestHostChainDenies:
    def test_private_cloud_deny(self):
        bundle = _bundle(privacy_policy={AGENT: "PRIVATE"})
        with pytest.raises((Exception,)) as excinfo:
            _plan_chain(bundle)
        assert not isinstance(excinfo.value, AssertionError)

    def test_unknown_privacy_fails_closed(self):
        # Empty per-agent privacy policy = invalid cloud document.
        with pytest.raises(HostSupplyError) as excinfo:
            _bundle(privacy_policy={})
        assert excinfo.value.code == PRIVACY_UNKNOWN

    def test_unknown_provider_deny(self):
        bundle = _bundle()
        with pytest.raises(HostSupplyError) as excinfo:
            host_cloud_dispatch(
                bundle, engine=ENGINE, provider="anthropic",
                model="claude-3-5-sonnet-latest",
                messages=_msgs("x"), agent_id=AGENT, capability="llm:cloud")
        assert excinfo.value.code == PROVIDER_UNKNOWN

    def test_unknown_endpoint_deny(self):
        bundle = _bundle()   # groq allowlisted but holds NO endpoint binding
        with pytest.raises(HostSupplyError) as excinfo:
            host_cloud_dispatch(
                bundle, engine=GROQ_KEY[0], provider=GROQ_KEY[1],
                model=GROQ_KEY[2],
                messages=_msgs("x"), agent_id=AGENT, capability="llm:cloud")
        assert excinfo.value.code == ENDPOINT_UNKNOWN

    def test_internal_without_transmission_approval_deny(self):
        # INTERNAL + allow_cloud=False: the host policy refusal is raised
        # at the egress decision (matches factory E2E semantics).
        bundle = _bundle(privacy_policy={AGENT: "INTERNAL"},
                         egress_policy=HostEgressPolicy(allow_cloud=False))
        with pytest.raises(Exception) as excinfo:
            _plan_chain(bundle)
        assert "HOST_POLICY_DENIED" in str(excinfo.value) or \
            getattr(excinfo.value, "code", "") in ("HOST_POLICY_DENIED",
                                                   "MINIMIZER_REQUIRED")

    def test_shadow_doc_mints_no_cloud_authorizer(self):
        shadow = build_host_supply(
            _cfg(mode=MODE_SHADOW_ONLY, cloud_egress_enabled=False,
                 shadow_enabled=True,
                 provider_allowlist=(), endpoints={},
                 endpoint_allowlist=(),
                 snapshot_status={OPENAI_KEY: True},
                 credential_reference="", credential_available=None,
                 privacy_policy={"default": "PUBLIC"},
                 egress_policy=HostEgressPolicy(allow_cloud=False)),
            now=NOW)
        assert shadow.cloud_authorizer is None
        assert shadow.session_id == ""

    def test_missing_scanners_fail_closed(self):
        with pytest.raises(HostSupplyError) as excinfo:
            _bundle(scanners=())
        assert excinfo.value.code == "PRIVACY_SCANNER_UNAVAILABLE"
