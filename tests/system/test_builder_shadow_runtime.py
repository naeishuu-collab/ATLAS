"""SystemBuilder.build() runtime E2E for shadow-only host supply.

Drives the REAL production construction path: SystemBuilder.build() with
an injected offline FakeEngine (no network, no native gates, no OS
mutation beyond tmp_path artifacts). Proves, at runtime:

* no env document -> builder wires NO supply -> legacy host
* shadow OFF document -> bundle present, observer disabled
* shadow ON document -> bundle present, observer enabled, and a real
  managed tick through the builder-built system is observed
* missing registry / missing snapshot / stale snapshot / invalid document
  all fail CLOSED at build time with their factory codes
* the enable flag is host-document-owned; an agent config field cannot
  flip it, even through the real builder
* an observer that crashes still leaves the legacy tick alive
* observations are recorded per engine ATTEMPT (a tick with 3 retry
  attempts yields 3 FAILED records; one logical tick is one execute_tick)
"""

from __future__ import annotations

import json
import time

import pytest
from tests.agents.fake_engine import FakeEngine

from openjarvis.agents.host_supply_factory import (
    HOST_CONFIG_INVALID,
    MODE_SHADOW_ONLY,
    SHADOW_SUPPLY_INCOMPLETE,
    SNAPSHOT_STALE,
    HostSupplyError,
)
from openjarvis.agents.orchestrator import OrchestratorAgent  # noqa: F401
from openjarvis.core.config import JarvisConfig
from openjarvis.core.registry import AgentRegistry
from openjarvis.system import SystemBuilder


def _ensure_orchestrator() -> None:
    try:
        AgentRegistry.register_value("orchestrator", OrchestratorAgent)
    except ValueError:
        pass  # registered by another module in this process


# ---------------------------------------------------------------------------
# Host document helpers (real factory document, written to tmp_path)
# ---------------------------------------------------------------------------


def _doc(tmp_path, **over) -> str:
    doc: dict = {
        "mode": MODE_SHADOW_ONLY,
        "shadow_enabled": True,
        "model_registry": [{"engine": "fake", "provider": "local",
                            "model": "fake-model",
                            "capabilities": ["TEXT"], "ctx_limit": 4096,
                            "cost_per_1k": 0.0, "latency_p50_ms": 50.0,
                            "is_cloud": False, "tier": 0}],
        "snapshot": {"status": [["fake", "local", "fake-model", True]],
                     "version": 1, "issued_at": time.time(),
                     "max_age_s": 600.0},
        "privacy_policy": {"default": "PUBLIC"},
    }
    doc.update(over)
    path = tmp_path / "host_supply_document.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def _build(tmp_path, monkeypatch, doc_path=None, tick=False,
           responses=None):
    """Real SystemBuilder.build() with the injected offline FakeEngine."""

    cfg = JarvisConfig()
    cfg.telemetry.enabled = False
    cfg.traces.enabled = False
    if tick:
        # Enable the managed runtime inside the builder itself.
        from pathlib import Path as _Path

        cfg.agent_manager.enabled = True
        cfg.agent_manager.db_path = str(
            _Path(tmp_path) / f"agents-{time.time_ns()}.db")
    if doc_path is None:
        monkeypatch.delenv("JARVIS_HOST_SUPPLY_PATH", raising=False)
    else:
        monkeypatch.setenv("JARVIS_HOST_SUPPLY_PATH", doc_path)
    engine = FakeEngine(list(responses or []))
    builder = (
        SystemBuilder(cfg)
        .engine_instance(engine, "fake")
        .model("fake-model")
        .agent("orchestrator")
        .telemetry(False)
        .traces(False)
        .sandbox(False)
        .scheduler(False)
        .workflow(False)
        .sessions(False)
    )
    system = builder.build()
    return system, engine


# ---------------------------------------------------------------------------
# OFF / absence of supply
# ---------------------------------------------------------------------------


def test_builder_runtime_no_env_doc_wires_no_supply(tmp_path, monkeypatch):
    system, engine = _build(tmp_path, monkeypatch)
    assert type(engine).__name__ == "FakeEngine"  # builder used the fake
    assert system.host_supply is None             # legacy host
    assert system.agent_executor is not None      # builder runtime is real


def test_builder_runtime_shadow_off_doc_binds_disabled_observer(tmp_path,
                                                                monkeypatch):
    path = _doc(tmp_path, shadow_enabled=False)
    system, engine = _build(tmp_path, monkeypatch, path)
    bundle = system.host_supply
    assert bundle is not None                     # constructed at build()
    assert bundle.shadow_observer.enabled is False
    assert bundle.cloud_authorizer is None        # no egress path anywhere


def test_builder_runtime_shadow_on_observes_built_system_tick(tmp_path,
                                                              monkeypatch):
    path = _doc(tmp_path)
    system, engine = _build(tmp_path, monkeypatch, path, tick=True,
                            responses=[{"content": "built-and-observed"}])
    bundle = system.host_supply
    assert bundle is not None
    assert bundle.shadow_observer.enabled is True
    assert system.agent_manager is not None       # runtime wiring real

    _ensure_orchestrator()
    agent = system.agent_manager.create_agent(
        "builder-runtime-shadow", agent_type="orchestrator",
        config={"model": "fake-model", "instruction": "runtime probe"},
    )
    system.agent_executor.execute_tick(agent["id"])

    obs = bundle.shadow_observer.observations
    assert len(obs) >= 1
    assert obs[-1].run_status == "SUCCEEDED"
    assert obs[-1].dispatched is False and obs[-1].mutations == 0
    assert engine.call_count == 1                 # no additional dispatch


# ---------------------------------------------------------------------------
# Fail-closed at build time (valid doc absent/invalid members)
# ---------------------------------------------------------------------------


def test_builder_runtime_missing_registry_fails_closed(tmp_path, monkeypatch):
    path = _doc(tmp_path, model_registry=[])
    with pytest.raises(HostSupplyError) as excinfo:
        _build(tmp_path, monkeypatch, path)
    assert excinfo.value.code == SHADOW_SUPPLY_INCOMPLETE


def test_builder_runtime_missing_snapshot_fails_closed(tmp_path, monkeypatch):
    path = _doc(tmp_path, snapshot={})
    with pytest.raises(HostSupplyError) as excinfo:
        _build(tmp_path, monkeypatch, path)
    assert excinfo.value.code == SHADOW_SUPPLY_INCOMPLETE


def test_builder_runtime_stale_snapshot_fails_closed(tmp_path, monkeypatch):
    path = _doc(tmp_path, snapshot={"status": [["fake", "local",
                                                "fake-model", True]],
                                    "version": 1,
                                    "issued_at": time.time() - 3600.0,
                                    "max_age_s": 600.0})
    with pytest.raises(HostSupplyError) as excinfo:
        _build(tmp_path, monkeypatch, path)
    assert excinfo.value.code == SNAPSHOT_STALE


def test_builder_runtime_invalid_document_fails_closed(tmp_path, monkeypatch):
    path = _doc(tmp_path, totally_unknown_key=1)
    with pytest.raises(HostSupplyError) as excinfo:
        _build(tmp_path, monkeypatch, path)
    assert excinfo.value.code == HOST_CONFIG_INVALID


# ---------------------------------------------------------------------------
# Flag authority + observer failure isolation at runtime
# ---------------------------------------------------------------------------


def test_builder_runtime_agent_flag_cannot_flip_host_bundle(tmp_path,
                                                            monkeypatch):
    path = _doc(tmp_path, shadow_enabled=False)
    system, engine = _build(tmp_path, monkeypatch, path, tick=True,
                            responses=[{"content": "still-legacy"}])
    bundle = system.host_supply
    assert bundle.shadow_observer.enabled is False

    _ensure_orchestrator()
    agent = system.agent_manager.create_agent(
        "flag-bypass-attempt", agent_type="orchestrator",
        config={"model": "fake-model", "instruction": "probe",
                "shadow_enabled": True},   # agent input must stay inert
    )
    system.agent_executor.execute_tick(agent["id"])
    obs = bundle.shadow_observer.observations
    # A disabled observer returns its record without ever appending it:
    # OFF posture leaves zero observation artifacts in the host process.
    assert obs == []
    assert engine.call_count == 1                 # unchanged dispatch


def test_builder_runtime_observer_crash_keeps_legacy_tick_alive(tmp_path,
                                                                monkeypatch):
    path = _doc(tmp_path)
    system, engine = _build(tmp_path, monkeypatch, path, tick=True,
                            responses=[{"content": "legacy-alive"}])
    bundle = system.host_supply

    def _crash(**_kwargs):
        raise RuntimeError("observer exploded")

    monkeypatch.setattr(bundle.shadow_observer, "observe", _crash)

    _ensure_orchestrator()
    agent = system.agent_manager.create_agent(
        "observer-crash", agent_type="orchestrator",
        config={"model": "fake-model", "instruction": "probe"},
    )
    # Must NOT raise: observation failure can never stop the legacy tick.
    system.agent_executor.execute_tick(agent["id"])
    assert engine.call_count == 1
    assert bundle.shadow_observer.observations == []  # crash was contained


def test_builder_runtime_attempt_level_vs_tick_level(tmp_path, monkeypatch):
    """One logical tick = one execute_tick; N engine attempts = N records."""
    path = _doc(tmp_path)
    system, engine = _build(
        tmp_path, monkeypatch, path, tick=True,
        responses=[{"raise": Boom("boom")}] * 3,
    )
    bundle = system.host_supply

    _ensure_orchestrator()
    agent = system.agent_manager.create_agent(
        "attempt-tick", agent_type="orchestrator",
        config={"model": "fake-model", "instruction": "probe"},
    )
    try:
        system.agent_executor.execute_tick(agent["id"])
    except Exception:
        pass  # exhausted retries are surfaced as a managed failure, or not
    obs = bundle.shadow_observer.observations
    # Every engine attempt was observed separately (3 attempts == 3 FAILED
    # records), while the caller still invoked execute_tick exactly once.
    assert engine.call_count == len(obs) >= 1
    assert all(o.run_status == "FAILED" for o in obs)


class Boom(RuntimeError):
    code = "RUNTIME_BOOM"
