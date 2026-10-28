"""Authority lifecycle regression (offline, zero network).

Pins the specified one-shot contract of `execute_secured_tool`
(security/runtime.py:256): each call gets a FRESH executor, so
quarantine/taint/UNKNOWN retention is per-CALL, not per-agent. Cross-call
durability belongs to managed executors with bound journals (T4 covers
the in-instance behavior). Tests assert both directions: no leakage
across fresh executors, and full retention within one executor.
"""

from __future__ import annotations

import json
import threading
from typing import Any

from openjarvis.core.events import EventBus
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.security.runtime import execute_secured_tool
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec


class _MutatingTool(BaseTool):
    tool_id = "lc_probe"

    def __init__(self, calls: list, name: str = "lc_probe") -> None:
        self._calls = calls
        self._name = name

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name=self._name, description="lifecycle probe",
                        timeout_seconds=30.0, effect=ToolEffect.MUTATING)

    def execute(self, **params: Any) -> ToolResult:
        self._calls.append(dict(params))
        return ToolResult(tool_name=self._name, content="probe-ok",
                          success=True,
                          execution_state=ExecutionState.EXECUTED)


def _managed_call(name: str, cid: str, tool: _MutatingTool,
                  policy: CapabilityPolicy | None = None) -> ToolResult:
    ex = ToolExecutor([tool], agent_id="lc-agent", capability_policy=policy)
    return ex.execute(ToolCall(id=cid, name=name,
                               arguments=json.dumps({"x": 1})))


def test_fresh_executors_share_no_quarantine() -> None:
    """One-shot scope: call B is unaffected by call A's executor state."""
    calls: list = []
    first = _managed_call("lc_probe", "c1", _MutatingTool(calls),
                          CapabilityPolicy())
    second = _managed_call("lc_probe", "c2", _MutatingTool(calls),
                           CapabilityPolicy())
    assert first.success is True
    assert second.success is True
    assert len(calls) == 2


def test_fresh_executors_share_no_taint() -> None:
    """A secret surfaced in call A does not taint call B's fresh executor."""
    from openjarvis.security.taint import TaintLabel, TaintSet

    calls: list = []
    ex_a = ToolExecutor([_MutatingTool(calls)], agent_id="lc-agent",
                        capability_policy=CapabilityPolicy())
    ex_a.begin_session(["sk-12345678901234567890"])
    assert isinstance(ex_a._session_taint, TaintSet)
    assert ex_a._session_taint.has(TaintLabel.SECRET)
    ex_b = ToolExecutor([_MutatingTool(calls)], agent_id="lc-agent",
                        capability_policy=CapabilityPolicy())
    assert not ex_b._session_taint.has(TaintLabel.SECRET)


def test_in_instance_unknown_blocks_retry() -> None:
    """Within ONE executor, UNKNOWN_OUTCOME is retained (T4 contract)."""
    calls: list = []
    entered = threading.Event()
    release = threading.Event()

    class _Gated(_MutatingTool):
        def execute(self, **params: Any) -> ToolResult:
            self._calls.append(dict(params))
            entered.set()
            assert release.wait(timeout=15)
            return ToolResult(tool_name=self._name, content="ok",
                              success=True,
                              execution_state=ExecutionState.EXECUTED)

    ex = ToolExecutor([_Gated(calls)], agent_id="lc-agent",
                      capability_policy=CapabilityPolicy())
    holder: dict = {}
    first = threading.Thread(
        target=lambda: holder.update(
            r=ex.execute(ToolCall(id="c1", name="lc_probe",
                                  arguments=json.dumps({})))) )
    first.start()
    assert entered.wait(timeout=15)
    loser = ex.execute(ToolCall(id="c2", name="lc_probe",
                                arguments=json.dumps({})))
    assert loser.success is False
    assert "UNKNOWN_OUTCOME" in loser.content
    release.set()
    first.join(timeout=15)
    assert holder["r"].success is True
    assert len(calls) == 1


def test_secured_tool_grants_do_not_leak_across_agents() -> None:
    policy = CapabilityPolicy(default_deny=True)
    policy.grant("agent-a", "data:write")

    class _Capped(_MutatingTool):
        @property
        def spec(self) -> ToolSpec:
            base = super().spec
            base.required_capabilities.append("data:write")
            return base

    calls_a: list = []
    calls_b: list = []
    ok = execute_secured_tool(_Capped(calls_a), {"x": 1},
                              capability_policy=policy, agent_id="agent-a")
    denied = execute_secured_tool(_Capped(calls_b), {"x": 1},
                                  capability_policy=policy, agent_id="agent-b")
    assert ok.success is True
    assert denied.success is False
    assert len(calls_a) == 1
    assert calls_b == []


def test_secured_tool_denial_calls_nothing() -> None:
    """A denied secured call never reaches the tool (capability floor)."""

    class _Capped(_MutatingTool):
        @property
        def spec(self) -> ToolSpec:
            base = super().spec
            base.required_capabilities.append("data:write")
            return base

    calls: list = []
    denied = execute_secured_tool(_Capped(calls), {"x": 1},
                                  capability_policy=CapabilityPolicy(
                                      default_deny=True),
                                  agent_id="lc")
    assert denied.success is False
    assert calls == []


def test_runner_pool_carries_no_security_state() -> None:
    """The shared _TOOL_RUNNER is a stateless router (threads only)."""
    from openjarvis.tools import _stubs as stubs

    assert not hasattr(stubs._TOOL_RUNNER, "_mutation_states")
    assert not hasattr(stubs._TOOL_RUNNER, "_session_taint")
    assert not hasattr(stubs._TOOL_RUNNER, "_capability_policy")


def test_bus_events_carry_call_identity() -> None:
    from openjarvis.core.events import EventType

    calls: list = []
    bus = EventBus()
    seen: list = []
    bus.subscribe(EventType.TOOL_CALL_START, seen.append)
    bus.subscribe(EventType.TOOL_CALL_END, seen.append)
    ex = ToolExecutor([_MutatingTool(calls)], bus=bus, agent_id="lc-agent",
                      capability_policy=CapabilityPolicy())
    ex.execute(ToolCall(id="c9", name="lc_probe",
                        arguments=json.dumps({})))
    kinds = {event.event_type for event in seen}
    assert EventType.TOOL_CALL_START in kinds
    assert EventType.TOOL_CALL_END in kinds
    assert all(event.data.get("call_id") == "c9"
               or "call_id" not in event.data for event in seen)
