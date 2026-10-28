"""Host supply document loading + injection contract (offline).

The document is the operator-supplied supply source: it carries host
values only and can never invent authority objects for itself. Scanners,
capability policy, and the credential probe come from the wiring.
"""

from __future__ import annotations

import json

import pytest

from openjarvis.agents.host_supply_factory import (
    CREDENTIAL_MISSING,
    HOST_CONFIG_INVALID,
    HOST_SUPPLY_PATH_ENV,
    MODE_CLOUD,
    MODE_LOCAL_ONLY,
    HostSupplyError,
    credential_probe,
    load_host_config,
    load_host_supply_from_env,
)
from tests.agents.test_host_supply_factory import (
    AGENT,
    CLOUD_KEY,
    ENDPOINT,
    NOW,
    _Policy,
    _SynthScanner,
    key_str,
)


def _document(**over) -> dict:
    doc = {
        "mode": MODE_CLOUD,
        "model_registry": [
            {"engine": "litellm", "provider": "groq",
             "model": "llama-3.3-70b", "capabilities": ["TEXT"],
             "ctx_limit": 8192, "cost_per_1k": 0.0005,
             "latency_p50_ms": 900.0, "is_cloud": True},
        ],
        "snapshot": {"status": [["litellm", "groq", "llama-3.3-70b", True]],
                     "version": 1, "issued_at": NOW, "max_age_s": 600},
        "shadow_enabled": True,
        "cloud_egress_enabled": True,
        "privacy_policy": {AGENT: "PUBLIC"},
        "egress_policy": {"allow_cloud": True, "allowed_providers": ["groq"]},
        "provider_allowlist": [list(CLOUD_KEY)],
        "endpoints": {key_str(CLOUD_KEY): ENDPOINT},
        "endpoint_allowlist": [ENDPOINT],
        "session_identity": "hsess_from_document",
        "credential_reference": "env:SYNTH_HOST_KEY",
        "minimizer": {"allow": ["model", "messages", "messages.role",
                                "messages.content"],
                      "purpose": "host-cloud-dispatch"},
    }
    doc.update(over)
    return doc


def _write(tmp_path, doc) -> str:
    path = tmp_path / "host-supply.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


# --- 1-2. missing / invalid documents -------------------------------------


def test_missing_document_is_refused(tmp_path) -> None:
    with pytest.raises(HostSupplyError) as ei:
        load_host_config(tmp_path / "absent.json")
    assert ei.value.code == HOST_CONFIG_INVALID
    with pytest.raises(HostSupplyError) as ei:
        load_host_config(tmp_path)  # a directory is not a document
    assert ei.value.code == HOST_CONFIG_INVALID


def test_unknown_and_malformed_keys_are_refused(tmp_path) -> None:
    with pytest.raises(HostSupplyError) as ei:
        load_host_config(_write(tmp_path, _document(cloud_enabel=True)))
    assert ei.value.code == HOST_CONFIG_INVALID
    assert "cloud_enabel" in ei.value.reason
    with pytest.raises(HostSupplyError) as ei:
        load_host_config(_write(tmp_path, _document(snapshot=[1, 2])))
    assert ei.value.code == HOST_CONFIG_INVALID
    with pytest.raises(HostSupplyError) as ei:
        load_host_config(_write(tmp_path, _document(snapshot={
            "status": [["litellm", "groq"]], "version": 1,
            "issued_at": NOW})))
    assert ei.value.code == HOST_CONFIG_INVALID


# --- document -> supply ----------------------------------------------------


def test_document_builds_complete_cloud_supply(tmp_path,
                                              monkeypatch) -> None:
    monkeypatch.setenv("SYNTH_HOST_KEY", "synthetic-value")
    monkeypatch.setenv(HOST_SUPPLY_PATH_ENV,
                       _write(tmp_path, _document()))
    bundle = load_host_supply_from_env(
        scanners=(_SynthScanner(),),
        capability_policy=_Policy({AGENT: ["llm:cloud"]}),
        now=NOW)
    assert bundle is not None
    assert bundle.mode == MODE_CLOUD
    assert bundle.cloud_egress_enabled is True
    assert bundle.shadow_observer.enabled is True
    assert bundle.session_id == "hsess_from_document"
    assert bundle.endpoint_for(*CLOUD_KEY) == ENDPOINT
    bundle.require_credential("groq")
    # The credential value itself never enters the bundle.
    assert "synthetic-value" not in str(bundle.audit_snapshot())


def test_missing_credential_env_fails_closed_at_dispatch(
        tmp_path, monkeypatch) -> None:
    from openjarvis.agents.host_supply_factory import host_cloud_dispatch
    from tests.agents.test_host_supply_factory import _messages

    monkeypatch.delenv("SYNTH_HOST_KEY", raising=False)
    monkeypatch.setenv(HOST_SUPPLY_PATH_ENV, _write(tmp_path, _document()))
    bundle = load_host_supply_from_env(
        scanners=(_SynthScanner(),),
        capability_policy=_Policy({AGENT: ["llm:cloud"]}),
        now=NOW)
    with pytest.raises(HostSupplyError) as ei:
        host_cloud_dispatch(bundle, engine="litellm", provider="groq",
                            model="llama-3.3-70b", messages=_messages(),
                            agent_id=AGENT, capability="llm:cloud")
    assert ei.value.code == CREDENTIAL_MISSING


def test_stale_document_snapshot_is_refused(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SYNTH_HOST_KEY", "synthetic-value")
    monkeypatch.setenv(HOST_SUPPLY_PATH_ENV, _write(tmp_path, _document(
        snapshot={"status": [["litellm", "groq", "llama-3.3-70b", True]],
                  "version": 1, "issued_at": NOW - 10_000, "max_age_s": 600})))
    with pytest.raises(HostSupplyError) as ei:
        load_host_supply_from_env(scanners=(_SynthScanner(),),
                                  capability_policy=_Policy({}), now=NOW)
    assert ei.value.code == "SNAPSHOT_STALE"


def test_document_cannot_enable_cloud_without_injected_authority(
        tmp_path, monkeypatch) -> None:
    """A document alone never yields a usable authorizer."""
    monkeypatch.setenv("SYNTH_HOST_KEY", "synthetic-value")
    monkeypatch.setenv(HOST_SUPPLY_PATH_ENV, _write(tmp_path, _document()))
    with pytest.raises(HostSupplyError) as ei:
        load_host_supply_from_env(scanners=(), capability_policy=None,
                                  now=NOW)
    assert ei.value.code == "PRIVACY_SCANNER_UNAVAILABLE"
    with pytest.raises(HostSupplyError) as ei:
        load_host_supply_from_env(scanners=(_SynthScanner(),),
                                  capability_policy=None, now=NOW)
    assert ei.value.code == "CLOUD_SUPPLY_INCOMPLETE"


# --- legacy parity ---------------------------------------------------------


def test_unset_env_var_keeps_legacy_behavior(monkeypatch) -> None:
    monkeypatch.delenv(HOST_SUPPLY_PATH_ENV, raising=False)
    assert load_host_supply_from_env() is None
    monkeypatch.setenv(HOST_SUPPLY_PATH_ENV, "")
    assert load_host_supply_from_env() is None


def test_local_only_document_cannot_enable_shadow(tmp_path,
                                                 monkeypatch) -> None:
    """Shadowing without the shadow-only posture is a configuration error."""
    monkeypatch.setenv(HOST_SUPPLY_PATH_ENV, _write(tmp_path, _document(
        mode=MODE_LOCAL_ONLY, cloud_egress_enabled=False)))
    with pytest.raises(HostSupplyError) as ei:
        load_host_supply_from_env(now=NOW)
    assert ei.value.code == HOST_CONFIG_INVALID
    monkeypatch.setenv(HOST_SUPPLY_PATH_ENV, _write(tmp_path, _document(
        mode=MODE_LOCAL_ONLY, cloud_egress_enabled=False,
        shadow_enabled=False)))
    bundle = load_host_supply_from_env(now=NOW)
    assert bundle.mode == MODE_LOCAL_ONLY
    assert bundle.cloud_authorizer is None
    assert bundle.shadow_observer.enabled is False
    assert bundle.registry.cards  # cards still load, no egress authority


def test_configured_but_broken_document_does_not_degrade(
        tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(HOST_SUPPLY_PATH_ENV, str(tmp_path / "absent.json"))
    with pytest.raises(HostSupplyError) as ei:
        load_host_supply_from_env(now=NOW)
    assert ei.value.code == HOST_CONFIG_INVALID


# --- credential probe ------------------------------------------------------


def test_credential_probe_rejects_unsupported_schemes() -> None:
    with pytest.raises(HostSupplyError) as ei:
        credential_probe("file:/etc/secret")
    assert ei.value.code == CREDENTIAL_MISSING
    with pytest.raises(HostSupplyError) as ei:
        credential_probe("env:")
    assert ei.value.code == CREDENTIAL_MISSING
    probe = credential_probe("env:SYNTH_ABSENT_VAR_XYZ")
    assert probe("groq") is False


def test_missing_config_object_is_refused() -> None:
    with pytest.raises(HostSupplyError) as ei:
        load_host_config(None)
    assert ei.value.code == HOST_CONFIG_INVALID
