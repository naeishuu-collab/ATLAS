"""Host supply factory offline E2E (mock-only, no network, no OS change).

Covers the host-supply boundary only. Coverage that already exists
upstream is reused rather than duplicated:

* shadow observation side-effect freedom -> tests/agents/test_shadow_observer.py
* observer failure isolation            -> tests/agents/test_shadow_observer.py
* retry/fallback re-authorization      -> tests/agents/test_dispatch_contract.py
* wire tamper / replay / stream states  -> tests/security/test_cloud_dispatch.py,
                                           tests/security/test_egress_guard.py

Synthetic markers only; no real keys, hosts, or provider calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, List

import pytest

from openjarvis.agents.host_routing import HostEgressPolicy
from openjarvis.agents.host_supply_factory import (
    CLOUD_SUPPLY_INCOMPLETE,
    CREDENTIAL_MISSING,
    ENDPOINT_UNKNOWN,
    HOST_CONFIG_INVALID,
    HOST_CONFIG_MISSING,
    HOST_MODE_INVALID,
    MINIMIZER_REQUIRED,
    MODE_CLOUD,
    MODE_LOCAL_ONLY,
    MODE_SHADOW_ONLY,
    PRIVACY_SCANNER_UNAVAILABLE,
    PRIVACY_UNKNOWN,
    PROVIDER_UNKNOWN,
    SESSION_IDENTITY_MISSING,
    SHADOW_SUPPLY_INCOMPLETE,
    SNAPSHOT_STALE,
    HostConfig,
    HostSupplyError,
    build_host_supply,
    finish_cloud_dispatch,
    host_cloud_dispatch,
    key_str,
    mint_session_identity,
)
from openjarvis.security.cloud_dispatch import (
    CLOUD_PAYLOAD_CHANGED,
    PRIVACY_ROUTE_UNAVAILABLE,
    PrivacyClassification,
    PrivacyDenied,
)
from openjarvis.security.dispatch_ledger import STATE_UNKNOWN_OUTCOME

NOW = 1000.0
SYNTH_KEY = "sk-synth-hostsupply0123456789"
AGENT = "agent-1"
CLOUD_KEY = ("litellm", "groq", "llama-3.3-70b")
ENDPOINT = "https://api.synth-groq.invalid/v1"
LOCAL_KEY = ("ollama", "local", "tiny-4b")


# --- stubs (mirror the authorizer's documented scanner/policy contracts) ---


@dataclass
class _Finding:
    pattern_name: str
    matched_text: str


@dataclass
class _ScanResult:
    findings: List[_Finding] = field(default_factory=list)


class _SynthScanner:
    _PATTERNS = [("synth_key", re.compile(r"sk-synth-[A-Za-z0-9_-]{10,}"))]

    def scan(self, text: str) -> _ScanResult:
        return _ScanResult(findings=[
            _Finding(name, m.group())
            for name, pat in self._PATTERNS for m in pat.finditer(text)])

    def redact(self, text: str) -> str:
        for name, pat in self._PATTERNS:
            text = pat.sub(f"[REDACTED:{name}]", text)
        return text


@dataclass
class _Grant:
    capability: str


class _Policy:
    def __init__(self, grants: dict) -> None:
        self._grants = grants

    def list_agents(self):  # noqa: D102
        return list(self._grants)

    def list_grants(self, agent_id):  # noqa: D102
        return [_Grant(c) for c in self._grants.get(agent_id, [])]

    def check(self, agent_id, capability, resource=""):  # noqa: D102
        return (capability in self._grants.get(agent_id, [])
                or capability in self._grants.get("_default", []))


class _NoScanner:
    pass


# --- host config builders -------------------------------------------------


def _cards() -> list:
    return [
        {"engine": "litellm", "provider": "groq",
         "model": "llama-3.3-70b", "capabilities": ["TEXT"],
         "ctx_limit": 8192, "cost_per_1k": 0.0005, "latency_p50_ms": 900.0,
         "is_cloud": True},
        {"engine": "ollama", "provider": "local", "model": "tiny-4b",
         "capabilities": ["TEXT"], "ctx_limit": 4096, "cost_per_1k": 0.0,
         "latency_p50_ms": 50.0, "is_cloud": False, "tier": 0},
    ]


def _shadow_config(**over) -> HostConfig:
    args: dict[str, Any] = dict(
        mode=MODE_SHADOW_ONLY,
        model_registry=tuple(_cards()),
        snapshot_status={LOCAL_KEY: True},
        snapshot_version=1,
        snapshot_issued_at=NOW,
        shadow_enabled=True,
        privacy_policy={"default": "PUBLIC"},
    )
    args.update(over)
    return HostConfig(**args)


def _cloud_config(**over) -> HostConfig:
    args: dict[str, Any] = dict(
        mode=MODE_CLOUD,
        model_registry=tuple(_cards()),
        snapshot_status={LOCAL_KEY: True, CLOUD_KEY: True},
        snapshot_version=1,
        snapshot_issued_at=NOW,
        shadow_enabled=True,
        cloud_egress_enabled=True,
        privacy_policy={AGENT: "PUBLIC"},
        egress_policy=HostEgressPolicy(allow_cloud=True,
                                       allowed_providers=("groq",)),
        provider_allowlist=(CLOUD_KEY,),
        endpoints={key_str(CLOUD_KEY): ENDPOINT},
        endpoint_allowlist=(ENDPOINT,),
        scanners=(_SynthScanner(),),
        capability_policy=_Policy({AGENT: ["llm:cloud"]}),
        session_identity=mint_session_identity(),
        credential_reference="env:SYNTH_CLOUD_KEY",
        credential_available=lambda provider: True,
        minimizer_allow=("model", "messages", "messages.role",
                         "messages.content", "stream"),
        minimizer_purpose="host-cloud-dispatch",
    )
    args.update(over)
    return HostConfig(**args)


def _messages(content: str = "hello") -> list:
    return [SimpleNamespace(role="user", content=content)]


def _shadow_bundle(**over):
    return build_host_supply(_shadow_config(**over), now=NOW)


def _cloud_bundle(**over):
    return build_host_supply(_cloud_config(**over), now=NOW)


def _agent(agent_id=AGENT, model="tiny-4b", privacy="PUBLIC"):
    return {"id": agent_id, "config": {"model": model, "privacy": privacy}}


def _system():
    class _Sys:
        engine = SimpleNamespace(engine_id="ollama")
        model = "tiny-4b"

    return _Sys()


# --- 1-2. host config missing / invalid -----------------------------------


def test_missing_host_config_is_refused() -> None:
    with pytest.raises(HostSupplyError) as ei:
        build_host_supply(None, now=NOW)  # type: ignore[arg-type]
    assert ei.value.code == HOST_CONFIG_MISSING


def test_invalid_mode_and_flag_postures_are_refused() -> None:
    with pytest.raises(HostSupplyError) as ei:
        build_host_supply(HostConfig(mode="enforce"), now=NOW)
    assert ei.value.code == HOST_MODE_INVALID
    with pytest.raises(HostSupplyError) as ei:
        build_host_supply(HostConfig(mode=MODE_LOCAL_ONLY,
                                     cloud_egress_enabled=True), now=NOW)
    assert ei.value.code == HOST_CONFIG_INVALID
    with pytest.raises(HostSupplyError) as ei:
        build_host_supply(HostConfig(mode=MODE_LOCAL_ONLY,
                                     shadow_enabled=True), now=NOW)
    assert ei.value.code == HOST_CONFIG_INVALID


# --- 3-5. registry / snapshot missing / stale -----------------------------


def test_missing_registry_and_snapshot_fail_closed() -> None:
    with pytest.raises(HostSupplyError) as ei:
        _shadow_bundle(model_registry=())
    assert ei.value.code == SHADOW_SUPPLY_INCOMPLETE
    with pytest.raises(HostSupplyError) as ei:
        _shadow_bundle(snapshot_status={}, snapshot_issued_at=0.0)
    assert ei.value.code == SHADOW_SUPPLY_INCOMPLETE


def test_stale_snapshot_is_refused_at_build() -> None:
    with pytest.raises(HostSupplyError) as ei:
        _shadow_bundle(snapshot_issued_at=NOW - 5000.0)
    assert ei.value.code == SNAPSHOT_STALE


# --- 6-7. shadow default OFF / ON observational-only ----------------------


def test_shadow_defaults_off_and_local_only_is_legacy() -> None:
    bundle = build_host_supply(HostConfig(), now=NOW)
    assert bundle.mode == MODE_LOCAL_ONLY
    assert bundle.shadow_observer.enabled is False
    assert bundle.cloud_authorizer is None
    assert bundle.session_id == ""
    record = bundle.shadow_observer.observe(
        agent=_agent(), system=_system(), model="tiny-4b", engine="ollama",
        provider=None, privacy="PUBLIC", result=None)
    assert record.outcome == "observer_disabled"


def test_shadow_on_observes_without_dispatch_or_mutation() -> None:
    bundle = _shadow_bundle()
    record = bundle.shadow_observer.observe(
        agent=_agent(), system=_system(), model="tiny-4b", engine="ollama",
        provider=None, privacy="PUBLIC",
        result=SimpleNamespace(content="ok", metadata={}),
        registry=bundle.registry, snapshot_env=bundle.snapshot,
        max_age_s=bundle.snapshot.issued_at and 600.0, now=NOW)
    assert record.dispatched is False
    assert record.mutations == 0
    assert record.refused is False
    assert record.outcome == "tiny-4b"


# --- 9. privacy unknown ---------------------------------------------------


def test_unknown_privacy_fails_closed() -> None:
    with pytest.raises(HostSupplyError) as ei:
        _cloud_bundle(privacy_policy={AGENT: "ULTRA_SECRET"})
    assert ei.value.code == PRIVACY_UNKNOWN
    # No per-agent host label and no default: an unmapped agent is
    # UNKNOWN, never downgraded to its own self-declared PUBLIC label.
    bundle = _cloud_bundle(privacy_policy={"other-agent": "PUBLIC"})
    with pytest.raises(HostSupplyError) as ei:
        bundle.privacy_for(AGENT)
    assert ei.value.code == PRIVACY_UNKNOWN
    with pytest.raises(HostSupplyError) as ei:
        _cloud_bundle(privacy_policy={})
    assert ei.value.code == PRIVACY_UNKNOWN


def test_private_cloud_dispatch_is_denied() -> None:
    bundle = _cloud_bundle(privacy_policy={AGENT: "PRIVATE"})
    # Host egress gate refuses before any authorization is attempted.
    with pytest.raises(HostSupplyError) as ei:
        host_cloud_dispatch(bundle, engine="litellm", provider="groq",
                            model="llama-3.3-70b", messages=_messages(),
                            agent_id=AGENT, capability="llm:cloud")
    assert ei.value.code == "PRIVACY_BLOCKED"
    # The authorizer independently refuses the same classification.
    with pytest.raises(PrivacyDenied) as ei:
        bundle.cloud_authorizer.authorize(SimpleNamespace(
            classification=PrivacyClassification.PRIVATE,
            provider=SimpleNamespace(key=lambda: CLOUD_KEY,
                                     is_cloud=True, endpoint=ENDPOINT),
            messages=({"role": "user", "content": "hi"},),
            grant=SimpleNamespace(expired=lambda: False),
            budget=SimpleNamespace(est_prompt_tokens=1, max_tokens=1,
                                   ctx_limit=10, per_request_usd=None,
                                   session_left_usd=None),
            session_id=bundle.session_id, nonce="n"))
    assert ei.value.code == PRIVACY_ROUTE_UNAVAILABLE


# --- 11-16. cloud supply completeness and bindings ------------------------


def test_cloud_dispatch_requires_authorizer() -> None:
    bundle = _shadow_bundle()
    with pytest.raises(HostSupplyError) as ei:
        host_cloud_dispatch(bundle, engine="litellm", provider="groq",
                            model="llama-3.3-70b", messages=_messages(),
                            agent_id=AGENT, capability="llm:cloud")
    assert ei.value.code == CLOUD_SUPPLY_INCOMPLETE
    with pytest.raises(HostSupplyError) as ei:
        bundle.guard_engine(object())
    assert ei.value.code == CLOUD_SUPPLY_INCOMPLETE


def test_missing_session_is_refused() -> None:
    with pytest.raises(HostSupplyError) as ei:
        _cloud_bundle(session_identity="")
    assert ei.value.code == SESSION_IDENTITY_MISSING
    bundle = _cloud_bundle()
    plan = host_cloud_dispatch(bundle, engine="litellm", provider="groq",
                               model="llama-3.3-70b",
                               messages=_messages(), agent_id=AGENT,
                               capability="llm:cloud")
    assert plan.session_id == bundle.session_id
    plan.assert_sendable(bundle)
    drifted = SimpleNamespace(**{**bundle.__dict__,
                                 "session_id": "hsess_other"})
    with pytest.raises(HostSupplyError) as ei:
        plan.assert_sendable(drifted)
    assert ei.value.code == SESSION_IDENTITY_MISSING


def test_missing_ledger_is_not_reachable_and_exactly_once_holds() -> None:
    bundle = _cloud_bundle()
    plan = host_cloud_dispatch(bundle, engine="litellm", provider="groq",
                               model="llama-3.3-70b",
                               messages=_messages(), agent_id=AGENT,
                               capability="llm:cloud")
    assert plan.entry.state == "DISPATCHED"
    with pytest.raises(PrivacyDenied) as ei:
        bundle.dispatch_ledger.begin(plan.sealed)
    assert ei.value.code == CLOUD_PAYLOAD_CHANGED


def test_provider_and_endpoint_binding_mismatches_are_denied() -> None:
    with pytest.raises(HostSupplyError) as ei:
        _cloud_config(provider_allowlist=(("litellm", "groq", "no-such"),))
        _cloud_bundle(provider_allowlist=(("litellm", "groq", "no-such"),))
    assert ei.value.code == PROVIDER_UNKNOWN
    bundle = _cloud_bundle()
    with pytest.raises(HostSupplyError) as ei:
        bundle.endpoint_for("litellm", "groq", "no-such")
    assert ei.value.code == PROVIDER_UNKNOWN
    with pytest.raises(HostSupplyError) as ei:
        _cloud_bundle(endpoints={key_str(CLOUD_KEY): "http://plain.invalid"})
    assert ei.value.code == ENDPOINT_UNKNOWN
    plan = host_cloud_dispatch(bundle, engine="litellm", provider="groq",
                               model="llama-3.3-70b",
                               messages=_messages(), agent_id=AGENT,
                               capability="llm:cloud")
    relaxed = SimpleNamespace(**{**bundle.__dict__,
                                 "endpoint_allowlist": ()})
    with pytest.raises(HostSupplyError) as ei:
        plan.assert_sendable(relaxed)
    assert ei.value.code == ENDPOINT_UNKNOWN


def test_missing_credential_is_denied() -> None:
    with pytest.raises(HostSupplyError) as ei:
        _cloud_bundle(credential_reference="")
    assert ei.value.code == CREDENTIAL_MISSING
    bundle = _cloud_bundle(credential_available=lambda provider: False)
    with pytest.raises(HostSupplyError) as ei:
        host_cloud_dispatch(bundle, engine="litellm", provider="groq",
                            model="llama-3.3-70b", messages=_messages(),
                            agent_id=AGENT, capability="llm:cloud")
    assert ei.value.code == CREDENTIAL_MISSING


def test_scanners_policy_and_minimizer_are_mandatory() -> None:
    with pytest.raises(HostSupplyError) as ei:
        _cloud_bundle(scanners=())
    assert ei.value.code == PRIVACY_SCANNER_UNAVAILABLE
    with pytest.raises(HostSupplyError) as ei:
        _cloud_bundle(scanners=(_NoScanner(),))
    assert ei.value.code == PRIVACY_SCANNER_UNAVAILABLE
    with pytest.raises(HostSupplyError) as ei:
        _cloud_bundle(capability_policy=None)
    assert ei.value.code == CLOUD_SUPPLY_INCOMPLETE
    with pytest.raises(HostSupplyError) as ei:
        _cloud_bundle(minimizer_allow=(), minimizer_purpose="")
    assert ei.value.code == MINIMIZER_REQUIRED


# --- 17-20. tamper, replay, retry, fallback re-authorization ---------------


def test_sanitized_bytes_are_sealed_and_tamper_detected() -> None:
    bundle = _cloud_bundle()
    plan = host_cloud_dispatch(bundle, engine="litellm", provider="groq",
                               model="llama-3.3-70b",
                               messages=_messages(f"token {SYNTH_KEY}"),
                               agent_id=AGENT, capability="llm:cloud")
    assert SYNTH_KEY not in plan.wire_messages[0]["content"]
    assert "[REDACTED" in plan.wire_messages[0]["content"]
    with pytest.raises(PrivacyDenied) as ei:
        bundle.cloud_authorizer.verify_for_send(
            plan.sealed, [{"role": "user", "content": "mutated"}],
            endpoint=plan.endpoint)
    assert ei.value.code == CLOUD_PAYLOAD_CHANGED
    # Unlisted destination cannot borrow the seal.
    with pytest.raises(HostSupplyError) as ei:
        host_cloud_dispatch(bundle, engine="ollama", provider="local",
                            model="tiny-4b", messages=_messages(),
                            agent_id=AGENT, capability="llm:cloud")
    assert ei.value.code == PROVIDER_UNKNOWN


def test_retry_and_fallback_require_fresh_authorization() -> None:
    bundle = _cloud_bundle()
    plan = host_cloud_dispatch(bundle, engine="litellm", provider="groq",
                               model="llama-3.3-70b",
                               messages=_messages(), agent_id=AGENT,
                               capability="llm:cloud")
    with pytest.raises(PrivacyDenied) as ei:
        bundle.dispatch_ledger.request_retry(plan.dispatch_id)
    assert ei.value.code == CLOUD_PAYLOAD_CHANGED
    retry = host_cloud_dispatch(bundle, engine="litellm", provider="groq",
                                model="llama-3.3-70b",
                                messages=_messages(), agent_id=AGENT,
                                capability="llm:cloud")
    assert retry.dispatch_id != plan.dispatch_id


def test_explicit_grant_is_required_for_every_dispatch() -> None:
    bundle = _cloud_bundle(capability_policy=_Policy({AGENT: ["llm:local"]}))
    with pytest.raises(PrivacyDenied) as ei:
        host_cloud_dispatch(bundle, engine="litellm", provider="groq",
                            model="llama-3.3-70b", messages=_messages(),
                            agent_id=AGENT, capability="llm:cloud")
    assert ei.value.code == "CLOUD_PROVIDER_NOT_ALLOWED"


# --- 21-22. stream interruption / UNKNOWN_OUTCOME -------------------------


def test_stream_interruption_quarantines_without_retry() -> None:
    bundle = _cloud_bundle()
    plan = host_cloud_dispatch(bundle, engine="litellm", provider="groq",
                               model="llama-3.3-70b",
                               messages=_messages(), agent_id=AGENT,
                               capability="llm:cloud")
    bundle.dispatch_ledger.note_stream_interrupted(plan.entry)
    assert plan.entry.state == STATE_UNKNOWN_OUTCOME
    with pytest.raises(PrivacyDenied) as ei:
        bundle.dispatch_ledger.request_retry(plan.dispatch_id)
    assert ei.value.code == "STREAM_INTERRUPTED"


def test_unknown_outcome_close_is_terminal_and_visible() -> None:
    bundle = _cloud_bundle()
    plan = host_cloud_dispatch(bundle, engine="litellm", provider="groq",
                               model="llama-3.3-70b",
                               messages=_messages(), agent_id=AGENT,
                               capability="llm:cloud")
    finish_cloud_dispatch(bundle, plan, STATE_UNKNOWN_OUTCOME,
                          code="STREAM_INTERRUPTED")
    audit = bundle.dispatch_ledger.audit(plan.dispatch_id)
    assert audit["state"] == STATE_UNKNOWN_OUTCOME
    assert audit["streaming"] is False


# --- audit secrecy --------------------------------------------------------


def test_audit_snapshot_never_contains_secrets_or_payloads() -> None:
    bundle = _cloud_bundle()
    audit = bundle.audit_snapshot()
    assert audit["session_bound"] is True
    assert audit["credential_reference"] == "env:SYNTH_CLOUD_KEY"
    assert SYNTH_KEY not in str(audit)
    assert "groq/llama" not in str(audit).replace("groq/llama-3.3-70b", "")
