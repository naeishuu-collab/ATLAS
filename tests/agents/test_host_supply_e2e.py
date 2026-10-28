"""Host supply -> provider egress offline E2E (mock transport only).

Runs the whole host chain against the existing fake transport:
host config -> factory -> registry/snapshot -> privacy -> cloud authorizer
-> wire seal -> dispatch contract -> fake transport -> ledger close.

No network, no OS mutation, no provider API. A MockTransport run proves
the host contract, never live production binding.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

from openjarvis.agents.dispatch_contract import DispatchContract
from openjarvis.agents.fake_transport import FakeTransport
from openjarvis.agents.host_routing import HostEgressPolicy
from openjarvis.agents.host_supply_factory import (
    MODE_SHADOW_ONLY,
    HostConfig,
    HostSupplyError,
    build_host_supply,
    finish_cloud_dispatch,
    host_cloud_dispatch,
    key_str,
    plan_wire_dispatch,
)
from openjarvis.security.cloud_dispatch import PrivacyDenied
from tests.agents.test_host_supply_factory import (
    AGENT,
    CLOUD_KEY,
    ENDPOINT,
    NOW,
    SYNTH_KEY,
    _cloud_config,
    _messages,
    _Policy,
)

ENGINE, PROVIDER, MODEL = CLOUD_KEY


def _bundle(**over):
    return build_host_supply(_cloud_config(**over), now=NOW)


# --- cloud E2E ------------------------------------------------------------


def test_host_supply_to_mock_transport_end_to_end() -> None:
    bundle = _bundle()
    plan = host_cloud_dispatch(
        bundle, engine=ENGINE, provider=PROVIDER, model=MODEL,
        messages=_messages(f"hello {SYNTH_KEY}"), agent_id=AGENT,
        capability="llm:cloud")
    plan.assert_sendable(bundle)
    payload, decision, seal = plan_wire_dispatch(bundle, plan)

    transport = FakeTransport()
    response = DispatchContract(transport).dispatch(
        payload, decision, authorized=seal, content="ok")
    assert response["content"] == "ok"
    # Only sanitized bytes crossed the transport.
    assert SYNTH_KEY not in str(transport.calls)
    assert transport.calls[0]["payload"] == payload

    finish_cloud_dispatch(bundle, plan, "EXECUTED")
    audit = bundle.dispatch_ledger.audit(plan.dispatch_id)
    assert audit["state"] == "EXECUTED"
    assert SYNTH_KEY not in str(audit)


def test_tampered_bytes_never_reach_the_transport() -> None:
    bundle = _bundle()
    plan = host_cloud_dispatch(bundle, engine=ENGINE, provider=PROVIDER,
                               model=MODEL, messages=_messages(),
                               agent_id=AGENT, capability="llm:cloud")
    payload, decision, seal = plan_wire_dispatch(bundle, plan)
    payload["messages"][0]["content"] = "sneaky rewrite"
    transport = FakeTransport()
    with pytest.raises(Exception) as ei:
        DispatchContract(transport).dispatch(payload, decision,
                                             authorized=seal)
    assert "PAYLOAD_TAMPERED" in str(ei.value)
    assert transport.calls == []


def test_streaming_starts_authorized_and_interruption_quarantines() -> None:
    from openjarvis.agents.fake_transport import TransportError
    from openjarvis.agents.privacy_pipeline import seal_authorized_envelope

    bundle = _bundle()
    plan = host_cloud_dispatch(bundle, engine=ENGINE, provider=PROVIDER,
                               model=MODEL, messages=_messages(),
                               agent_id=AGENT, capability="llm:cloud")
    payload, decision, seal = plan_wire_dispatch(bundle, plan)
    transport = FakeTransport()
    payload["stream"] = True
    # Seal no longer matches the streaming envelope: refuse to start.
    with pytest.raises(TransportError) as ei:
        list(DispatchContract(transport).stream_with_authorization(
            payload, decision, chunks=("a", "b"), authorized=seal))
    assert ei.value.code == "PAYLOAD_TAMPERED"
    assert transport.calls == []

    stream_seal = seal_authorized_envelope(payload, decision)
    with pytest.raises(TransportError) as ei:
        list(DispatchContract(transport).stream_with_authorization(
            payload, decision, chunks=("a", "b", "c"), interrupt_at=2,
            authorized=stream_seal))
    assert ei.value.code == "STREAM_INTERRUPTED"
    # A partial stream is never a success: the dispatch quarantines.
    bundle.dispatch_ledger.note_stream_interrupted(plan.entry)
    assert plan.entry.state == "UNKNOWN_OUTCOME"
    assert bundle.dispatch_ledger.audit(plan.dispatch_id)["state"] == (
        "UNKNOWN_OUTCOME")


def test_missing_grant_never_reaches_transport() -> None:
    bundle = _bundle(capability_policy=_Policy({AGENT: []}))
    transport = FakeTransport()
    with pytest.raises(PrivacyDenied):
        host_cloud_dispatch(bundle, engine=ENGINE, provider=PROVIDER,
                            model=MODEL, messages=_messages(),
                            agent_id=AGENT, capability="llm:cloud")
    assert transport.calls == []


def test_internal_data_requires_explicit_transmission_approval() -> None:
    bundle = _bundle(
        privacy_policy={AGENT: "INTERNAL"},
        egress_policy=HostEgressPolicy(allow_cloud=False))
    with pytest.raises(HostSupplyError) as ei:
        host_cloud_dispatch(bundle, engine=ENGINE, provider=PROVIDER,
                            model=MODEL, messages=_messages(),
                            agent_id=AGENT, capability="llm:cloud")
    assert ei.value.code == "HOST_POLICY_DENIED"


# --- guarded engine wiring (no send) --------------------------------------


def test_guarded_engine_denies_cloud_without_a_seal() -> None:
    from openjarvis.security.egress_guard import EgressGuardedEngine

    class _CloudEngine:
        engine_id = "litellm"
        is_cloud = True

        def generate(self, messages, *, model, **kwargs):  # pragma: no cover
            raise AssertionError("must never be reached")

    bundle = _bundle()
    guarded = bundle.guard_engine(_CloudEngine())
    assert isinstance(guarded, EgressGuardedEngine)
    with pytest.raises(PrivacyDenied):
        guarded.generate(_messages(), model=MODEL)
    assert guarded.dry_run(_messages(), model=MODEL)["decision"] == "DENY"


# --- shadow E2E (no cloud supply) -----------------------------------------


def test_shadow_only_posture_cannot_authorize_egress() -> None:
    bundle = build_host_supply(
        HostConfig(
            mode=MODE_SHADOW_ONLY,
            model_registry=tuple(_cloud_config().model_registry),
            snapshot_status={CLOUD_KEY: True},
            snapshot_version=1, snapshot_issued_at=NOW,
            shadow_enabled=True,
            privacy_policy={AGENT: "PUBLIC"}),
        now=NOW)
    assert bundle.cloud_authorizer is None
    assert bundle.session_id == ""
    with pytest.raises(HostSupplyError) as ei:
        host_cloud_dispatch(bundle, engine=ENGINE, provider=PROVIDER,
                            model=MODEL, messages=_messages(),
                            agent_id=AGENT, capability="llm:cloud")
    assert ei.value.code == "CLOUD_SUPPLY_INCOMPLETE"


# --- 25/26. no network, no OS mutation ------------------------------------


def test_full_chain_performs_no_network_and_no_os_mutation(
        monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_network(*args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("network access attempted")

    def _no_process(*args, **kwargs):  # pragma: no cover - must not run
        raise AssertionError("process/OS mutation attempted")

    import os
    import subprocess

    monkeypatch.setattr(socket, "socket", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    monkeypatch.setattr(subprocess, "Popen", _no_process)
    monkeypatch.setattr(os, "system", _no_process)

    bundle = _bundle()
    plan = host_cloud_dispatch(bundle, engine=ENGINE, provider=PROVIDER,
                               model=MODEL, messages=_messages("hi"),
                               agent_id=AGENT, capability="llm:cloud")
    payload, decision, seal = plan_wire_dispatch(bundle, plan)
    transport = FakeTransport()
    DispatchContract(transport).dispatch(payload, decision, authorized=seal,
                                        content="ok")
    record = bundle.shadow_observer.observe(
        agent={"id": AGENT, "config": {"model": "tiny-4b",
                                       "privacy": "PUBLIC"}},
        system=SimpleNamespace(engine=SimpleNamespace(engine_id="ollama")),
        model="tiny-4b", engine="ollama", provider=None,
        privacy=bundle.privacy_policy[AGENT], result=None,
        registry=bundle.registry, snapshot_env=bundle.snapshot, now=NOW)
    # Observation stays read-only and dispatch-free even while a cloud
    # plan is open on the same supply.
    assert record.refused is False
    assert record.outcome == "tiny-4b"
    assert record.dispatched is False
    assert record.mutations == 0
    assert transport.calls[0]["payload"] == payload
    assert key_str(CLOUD_KEY) in bundle.audit_snapshot()["allowlist"]
    assert ENDPOINT in bundle.audit_snapshot()["endpoints"]
