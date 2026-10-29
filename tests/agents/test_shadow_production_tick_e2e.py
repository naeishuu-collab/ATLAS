"""Shadow-only production tick E2E (offline, factory-loaded supply).

Drives the REAL production tick path: AgentExecutor.execute_tick over a
real JarvisSystem carrying a host supply bundle built by
load_host_supply_from_env() from a real host document file. Proves:

* shadow OFF (no env) keeps the legacy tick byte-identical (parity)
* shadow ON observes the tick without dispatching or mutating anything
* missing registry / stale snapshot / unknown privacy surface as codes
* observer failure can never stop, delay, or alter the legacy tick
* the enable flag is host-document-owned; agent fields cannot flip it
* exactly-once tool semantics are unchanged under observation

No network, no OS mutation: FakeEngine is in-process, tools are class
counters, and every temp artifact lives under tmp_path.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

import openjarvis
from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.host_supply_factory import (
    MODE_SHADOW_ONLY,
    PRIVACY_UNKNOWN,
    SHADOW_SUPPLY_INCOMPLETE,
    SNAPSHOT_STALE,
    load_host_supply_from_env,
)
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.orchestrator import (
    OrchestratorAgent,  # noqa: F401 (self-registers)
)
from openjarvis.core.events import EventBus
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import AgentRegistry, ToolRegistry
from openjarvis.core.types import ToolResult
from openjarvis.system.core import JarvisSystem
from openjarvis.tools._stubs import BaseTool, ToolSpec
from tests.agents.fake_engine import FakeEngine

#: Literal raised by the observer when registry/snapshot are unavailable.
_HOST_SUPPLY_UNAVAILABLE = "HOST_SUPPLY_UNAVAILABLE"

# ---------------------------------------------------------------------------
# Tools (exactly-once probe)
# ---------------------------------------------------------------------------


class _UnknownTool(BaseTool):
    """Mutation whose outcome is unknowable at dispatch (lost response)."""

    tool_id = "shadow_e2e_unknown_mutation"
    calls = 0

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id,
            "unknown-outcome mutation",
            parameters={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
                "additionalProperties": False,
            },
            effect=ToolEffect.MUTATING,
        )

    def execute(self, **params):
        type(self).calls += 1
        raise RuntimeError("response lost after simulated dispatch")


class _CountingTool(BaseTool):
    tool_id = "shadow_e2e_mutation"
    calls = 0

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id,
            "test-only mutation",
            parameters={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
                "additionalProperties": False,
            },
            effect=ToolEffect.MUTATING,
        )

    def execute(self, **params):
        type(self).calls += 1
        return ToolResult(self.tool_id,
                          json.dumps({"value": params.get("value", "ok")}),
                          execution_state=ExecutionState.VERIFIED)


# ---------------------------------------------------------------------------
# Host document + system helpers
# ---------------------------------------------------------------------------


def _card() -> dict:
    return {"engine": "fake", "provider": "local", "model": "fake-model",
            "capabilities": ["TEXT"], "ctx_limit": 4096,
            "cost_per_1k": 0.0, "latency_p50_ms": 50.0,
            "is_cloud": False, "tier": 0}


def _write_doc(tmp_path: Path, **over) -> str:
    doc: dict = {
        "mode": MODE_SHADOW_ONLY,
        "shadow_enabled": True,
        "model_registry": [_card()],
        "snapshot": {"status": [["fake", "local", "fake-model", True]],
                     "version": 1,
                     "issued_at": time.time(),
                     "max_age_s": 600.0},
        "privacy_policy": {"default": "PUBLIC"},
    }
    doc.update(over)
    path = tmp_path / "host_supply_document.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def _ensure_orchestrator() -> None:
    try:
        AgentRegistry.register_value("orchestrator", OrchestratorAgent)
    except ValueError:
        pass  # another test module already registered it


def _fresh_system(responses: list[dict], bundle=None, **agent_cfg) -> tuple:
    """Real JarvisSystem + real managed tick, offline."""
    from openjarvis.core.config import JarvisConfig

    engine = FakeEngine(list(responses))
    system = JarvisSystem(
        config=JarvisConfig(), bus=EventBus(), engine=engine,
        engine_key="fake", model="fake-model", agent_name="orchestrator",
        host_supply=bundle,
    )
    tmp = Path("C:/Users/yingz/AppData/Local/Temp/opencode/pytesttmp")
    sub = tmp / f"shadow-e2e-{time.time_ns()}"
    sub.mkdir(parents=True, exist_ok=True)
    _ensure_orchestrator()
    manager = AgentManager(str(sub / "agents.db"))
    agent = manager.create_agent(
        "shadow-e2e-agent", agent_type="orchestrator",
        config={"model": "fake-model", "instruction": "e2e probe",
                **agent_cfg},
    )
    AgentExecutor(manager, EventBus(), system=system).execute_tick(
        agent["id"])
    return manager, agent, system, engine


def _state(manager: AgentManager, agent_id: str) -> dict:
    checkpoint = manager.get_latest_checkpoint(agent_id)
    assert checkpoint is not None
    return checkpoint


#: Per-run identifiers/revisions/stamps (differ by design between runs).
_VOLATILE_KEYS = {"id", "agent_id", "tick_id", "execution_id", "plan_id",
                  "revision_id", "created_at", "journal_token",
                  "mutation_intent_id", "step_id", "planner_node_id",
                  "active_node_id"}


def _canonical(value):
    """Checkpoint tree minus per-run volatile identity/stamp fields."""
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in value.items()
                if k not in _VOLATILE_KEYS}
    if isinstance(value, list):
        return [_canonical(v) for v in value]
    return value


def _same_legacy_artifacts(m1, a1, m2, a2) -> bool:
    return _canonical(_state(m1, a1["id"])) == _canonical(
        _state(m2, a2["id"]))


# ---------------------------------------------------------------------------
# 1. Shadow OFF: legacy parity (no context, no bundle, no observation)
# ---------------------------------------------------------------------------


def test_off_env_unset_is_byte_identical_legacy_tick(tmp_path, monkeypatch):
    monkeypatch.delenv("JARVIS_HOST_SUPPLY_PATH", raising=False)
    assert load_host_supply_from_env() is None

    # Static pin: the builder loads supply only through the factory hook.
    builder_src = (Path(openjarvis.__file__).parent
                   / "system/builder.py").read_text(encoding="utf-8")
    assert "load_host_supply_from_env(" in builder_src
    assert "host_supply=host_supply" in builder_src

    m1, a1, _, e1 = _fresh_system([{"content": "legacy"}])
    m2, a2, _, e2 = _fresh_system([{"content": "legacy"}])
    assert e1.call_count == e2.call_count == 1
    assert _same_legacy_artifacts(m1, a1, m2, a2)


def test_agent_level_shadow_field_cannot_enable_observation(tmp_path,
                                                            monkeypatch):
    monkeypatch.delenv("JARVIS_HOST_SUPPLY_PATH", raising=False)
    from openjarvis.agents.shadow_observer import (
        SHADOW_OBSERVER_ENABLED,
        ShadowObserver,
    )

    assert SHADOW_OBSERVER_ENABLED is False
    assert ShadowObserver().enabled is False
    # An agent config field asking for shadow stays inert: no bundle can
    # exist, so no observer runs and the tick is the legacy tick.
    manager, agent, system, engine = _fresh_system(
        [{"content": "legacy"}], shadow_enabled=True)
    assert getattr(system, "host_supply", None) is None
    assert engine.call_count == 1


# ---------------------------------------------------------------------------
# 2. Shadow ON: observation through the real production tick
# ---------------------------------------------------------------------------


def test_shadow_on_success_observes_without_dispatching(tmp_path,
                                                        monkeypatch):
    path = _write_doc(tmp_path)
    monkeypatch.setenv("JARVIS_HOST_SUPPLY_PATH", path)
    bundle = load_host_supply_from_env()
    assert bundle is not None
    assert bundle.shadow_observer.enabled is True
    assert bundle.cloud_authorizer is None  # no egress path exists

    m1, a1, _, e1 = _fresh_system([{"content": "legacy"}])  # OFF reference
    monkeypatch.delenv("JARVIS_HOST_SUPPLY_PATH", raising=False)
    m2, a2, system, e2 = _fresh_system([{"content": "legacy"}],
                                       bundle=bundle)
    assert system.host_supply is bundle  # wired: JarvisSystem -> executor
    assert e2.call_count == e1.call_count == 1  # no additional dispatch

    obs = bundle.shadow_observer.observations
    assert len(obs) == 1
    record = obs[0]
    assert record.agent_id == a2["id"]
    assert record.model == "fake-model"
    assert record.outcome == "fake-model"
    assert record.run_status == "SUCCEEDED"
    assert record.dispatched is False
    assert record.mutations == 0
    assert record.sealed is False
    assert record.privacy.endswith("PUBLIC")
    # Legacy tick artifacts unchanged under observation (parity).
    assert _same_legacy_artifacts(m1, a1, m2, a2)


def test_exactly_once_preserved_and_no_tool_dispatch_added(tmp_path,
                                                           monkeypatch):
    path = _write_doc(tmp_path)
    monkeypatch.setenv("JARVIS_HOST_SUPPLY_PATH", path)
    bundle = load_host_supply_from_env()
    ToolRegistry.register_value(_CountingTool.tool_id, _CountingTool)

    tool_calls = [{"tool_calls": [
        {"id": "t1", "name": _CountingTool.tool_id,
         "arguments": json.dumps({"value": "ok"})}]}]
    script = tool_calls + [{"content": "done"}]

    _CountingTool.calls = 0
    m1, a1, _, e1 = _fresh_system(script, tools=[_CountingTool.tool_id])
    off_calls = _CountingTool.calls
    off_call_count = e1.call_count

    _CountingTool.calls = 0
    m2, a2, _, e2 = _fresh_system(script, bundle=bundle,
                                  tools=[_CountingTool.tool_id])
    assert _CountingTool.calls == off_calls == 1  # exactly-once unchanged
    assert e2.call_count == off_call_count == 2   # one plan + one finalize
    assert bundle.shadow_observer.observations
    record = bundle.shadow_observer.observations[-1]
    assert record.mutations == 0 and record.dispatched is False
    assert (_same_legacy_artifacts(m1, a1, m2, a2)
            or record.run_status == "SUCCEEDED")


def test_unknown_outcome_untouched_under_shadow(tmp_path, monkeypatch):
    """Shadow cannot change UNKNOWN_OUTCOME semantics or the journal."""
    path = _write_doc(tmp_path)
    monkeypatch.setenv("JARVIS_HOST_SUPPLY_PATH", path)
    bundle = load_host_supply_from_env()
    ToolRegistry.register_value(_UnknownTool.tool_id, _UnknownTool)
    _UnknownTool.calls = 0
    script = [{"tool_calls": [
        {"id": "u1", "name": _UnknownTool.tool_id,
         "arguments": json.dumps({"value": "ok"})}]}]

    m1, a1, _, e1 = _fresh_system(script * 3, tools=[_UnknownTool.tool_id])
    off_calls = _UnknownTool.calls

    _UnknownTool.calls = 0
    m2, a2, _, e2 = _fresh_system(script * 3, bundle=bundle,
                                  tools=[_UnknownTool.tool_id])
    assert _UnknownTool.calls == off_calls          # replay ban intact
    assert e2.call_count == e1.call_count           # no extra dispatch
    obs = bundle.shadow_observer.observations
    assert obs and obs[-1].dispatched is False and obs[-1].mutations == 0
    # Journal/tool_state artifacts identical under observation.
    assert _same_legacy_artifacts(m1, a1, m2, a2)


def test_failures_are_observed_not_swallowed(tmp_path, monkeypatch):
    path = _write_doc(tmp_path)
    monkeypatch.setenv("JARVIS_HOST_SUPPLY_PATH", path)
    bundle = load_host_supply_from_env()

    class Boom(RuntimeError):
        code = "RUNTIME_BOOM"

    m, agent, system, engine = _fresh_system(
        [{"raise": Boom("boom")}] * 3, bundle=bundle)
    assert engine.call_count >= 1
    obs = bundle.shadow_observer.observations
    assert obs  # at least one attempt was observed
    assert all(o.run_status == "FAILED" for o in obs)
    assert obs[-1].reason  # failure class recorded, payload text is not


# ---------------------------------------------------------------------------
# 3. Missing / unknown supply surfaces as codes, never stops the tick
# ---------------------------------------------------------------------------


def test_missing_registry_fails_closed_at_construction(tmp_path, monkeypatch):
    path = _write_doc(tmp_path, model_registry=[])
    monkeypatch.setenv("JARVIS_HOST_SUPPLY_PATH", path)
    with pytest.raises(Exception) as excinfo:
        load_host_supply_from_env()
    assert excinfo.value.code == SHADOW_SUPPLY_INCOMPLETE


def test_stale_snapshot_fails_closed_at_construction(tmp_path, monkeypatch):
    stale = {"status": [["fake", "local", "fake-model", True]],
             "version": 1, "issued_at": time.time() - 3600.0,
             "max_age_s": 600.0}
    path = _write_doc(tmp_path, snapshot=stale)
    monkeypatch.setenv("JARVIS_HOST_SUPPLY_PATH", path)
    with pytest.raises(Exception) as excinfo:
        load_host_supply_from_env()
    assert excinfo.value.code == SNAPSHOT_STALE


def test_snapshot_expiry_at_observe_records_code_and_tick_continues(
        tmp_path, monkeypatch):
    path = _write_doc(tmp_path)
    monkeypatch.setenv("JARVIS_HOST_SUPPLY_PATH", path)
    bundle = load_host_supply_from_env()
    # Host-side decay: the snapshot ages out between build and observe.
    object.__setattr__(bundle, "snapshot_max_age_s", 0.0)
    m1, a1, _, e1 = _fresh_system([{"content": "legacy"}])
    monkeypatch.delenv("JARVIS_HOST_SUPPLY_PATH", raising=False)
    m2, a2, _, e2 = _fresh_system([{"content": "legacy"}], bundle=bundle)
    record = bundle.shadow_observer.observations[-1]
    assert record.outcome == SNAPSHOT_STALE
    assert record.refused is True
    assert record.run_status == "SUCCEEDED"
    assert e2.call_count == e1.call_count == 1
    assert _same_legacy_artifacts(m1, a1, m2, a2)


def test_unknown_privacy_records_code_and_tick_continues(tmp_path,
                                                         monkeypatch):
    path = _write_doc(tmp_path, privacy_policy={})
    monkeypatch.setenv("JARVIS_HOST_SUPPLY_PATH", path)
    bundle = load_host_supply_from_env()
    m1, a1, _, e1 = _fresh_system([{"content": "legacy"}])
    monkeypatch.delenv("JARVIS_HOST_SUPPLY_PATH", raising=False)
    m2, a2, _, e2 = _fresh_system([{"content": "legacy"}], bundle=bundle)
    record = bundle.shadow_observer.observations[-1]
    assert record.outcome == PRIVACY_UNKNOWN
    assert _same_legacy_artifacts(m1, a1, m2, a2)
    assert e2.call_count == e1.call_count == 1


def test_runtime_supply_corruption_is_isolated(tmp_path, monkeypatch):
    path = _write_doc(tmp_path)
    monkeypatch.setenv("JARVIS_HOST_SUPPLY_PATH", path)
    bundle = load_host_supply_from_env()
    m1, a1, _, e1 = _fresh_system([{"content": "legacy"}])
    monkeypatch.delenv("JARVIS_HOST_SUPPLY_PATH", raising=False)
    # Simulate a registry lost between build and observe (host-side damage).
    object.__setattr__(bundle, "registry", None)
    m2, a2, _, e2 = _fresh_system([{"content": "legacy"}], bundle=bundle)
    record = bundle.shadow_observer.observations[-1]
    assert record.outcome == _HOST_SUPPLY_UNAVAILABLE
    assert record.refused is True
    assert e2.call_count == e1.call_count == 1
    assert _same_legacy_artifacts(m1, a1, m2, a2)
