"""Unbound-mutation audit regression.

Verifies the UNBOUND_MUTATION SECURITY_ALERT emitted by ToolExecutor
(src/openjarvis/tools/_stubs.py) when a mutating tool is dispatched
without a bound execution journal. Recording uses the real EventBus;
fake tools only append to in-memory lists. No network, no subprocess.
"""

from __future__ import annotations

import json
import threading
from typing import Any

from openjarvis.core.events import EventBus, EventType
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec


class _MutatingTool(BaseTool):
    tool_id = "uma_probe"

    def __init__(self, calls: list, name: str = "uma_probe",
                 delay: float = 0.0) -> None:
        self._calls = calls
        self._name = name
        self._delay = delay

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name=self._name, description="unbound audit probe",
                        timeout_seconds=30.0, effect=ToolEffect.MUTATING)

    def execute(self, **params: Any) -> ToolResult:
        import time

        self._calls.append(dict(params))
        if self._delay:
            time.sleep(self._delay)
        return ToolResult(tool_name=self._name, content="probe-ok",
                          success=True,
                          execution_state=ExecutionState.EXECUTED)


class _ReadonlyTool(_MutatingTool):
    tool_id = "uma_readonly"

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name="uma_readonly", description="readonly control",
                        timeout_seconds=30.0, effect=ToolEffect.READ_ONLY)


class _AlertSink:
    def __init__(self, bus: EventBus) -> None:
        self.events: list = []
        self._lock = threading.Lock()
        bus.subscribe(EventType.SECURITY_ALERT, self._on_alert)

    def _on_alert(self, event: Any) -> None:
        with self._lock:
            self.events.append(event)

    def unbound(self) -> list:
        with self._lock:
            return [e for e in self.events
                    if e.data.get("alert") == "UNBOUND_MUTATION"]


def _call(name: str, cid: str, args: dict | None = None) -> ToolCall:
    return ToolCall(id=cid, name=name,
                    arguments=json.dumps(args or {"x": 1}))


def _flatten(value: Any) -> list:
    if isinstance(value, dict):
        out = []
        for item in value.values():
            out.extend(_flatten(item))
        return out
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            out.extend(_flatten(item))
        return out
    return [value]


def test_unbound_mutation_recorded_with_identity() -> None:
    calls: list = []
    bus = EventBus()
    sink = _AlertSink(bus)
    ex = ToolExecutor([_MutatingTool(calls)], bus=bus, agent_id="uma-agent")
    result = ex.execute(_call("uma_probe", "c1"))
    assert result.success is True
    assert len(calls) == 1
    alerts = sink.unbound()
    assert len(alerts) == 1
    data = alerts[0].data
    assert data["tool"] == "uma_probe"
    assert data["call_id"] == "c1"
    assert data["agent"] == "uma-agent"
    assert data["journal_bound"] is False
    assert data["authority"]["mutation_intent"] is False


def test_bound_mutation_not_recorded() -> None:
    from types import SimpleNamespace

    calls: list = []
    bus = EventBus()
    sink = _AlertSink(bus)
    journal = SimpleNamespace(
        cancellation_state=lambda scope: None,
        reserve=lambda *a: "tok",
        begin_dispatch=lambda tok: True,
        finish=lambda tok, **kw: None,
    )
    ex = ToolExecutor([_MutatingTool(calls)], bus=bus, agent_id="uma-agent",
                      execution_journal=journal, execution_scope="uma")
    assert ex.execute(_call("uma_probe", "c1")).success is True
    assert sink.unbound() == []


def test_readonly_not_recorded() -> None:
    calls: list = []
    bus = EventBus()
    sink = _AlertSink(bus)
    ex = ToolExecutor([_ReadonlyTool(calls)], bus=bus, agent_id="uma-agent")
    assert ex.execute(_call("uma_readonly", "c1")).success is True
    assert sink.unbound() == []


def test_denied_mutation_not_recorded() -> None:
    calls: list = []

    class _CodeTool(_MutatingTool):
        @property
        def spec(self) -> ToolSpec:
            base = super().spec
            base.required_capabilities.append("code:execute")
            return base

    bus = EventBus()
    sink = _AlertSink(bus)
    ex = ToolExecutor([_CodeTool(calls)], bus=bus, agent_id="uma-agent")
    result = ex.execute(_call("uma_probe", "c1"))
    assert result.success is False
    assert sink.unbound() == []
    assert calls == []


def test_concurrent_alerts_separated_per_call() -> None:
    calls: list = []
    bus = EventBus()
    sink = _AlertSink(bus)
    ex = ToolExecutor([_MutatingTool(calls, name="uma_a", delay=0.3),
                       _MutatingTool(calls, name="uma_b", delay=0.3)],
                      bus=bus, agent_id="uma-agent")
    results: dict = {}

    def run(key: str, name: str, cid: str) -> None:
        results[key] = ex.execute(_call(name, cid))

    threads = [threading.Thread(target=run, args=("a", "uma_a", "c1")),
               threading.Thread(target=run, args=("b", "uma_b", "c2"))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
    assert results["a"].success is True
    assert results["b"].success is True
    alerts = sink.unbound()
    assert {(a.data["tool"], a.data["call_id"]) for a in alerts} == {
        ("uma_a", "c1"), ("uma_b", "c2")}


def test_broken_subscriber_does_not_block_dispatch() -> None:
    calls: list = []
    bus = EventBus()

    def _boom(event: Any) -> None:
        raise RuntimeError("observer failure")

    bus.subscribe(EventType.SECURITY_ALERT, _boom)
    sink = _AlertSink(bus)
    ex = ToolExecutor([_MutatingTool(calls)], bus=bus, agent_id="uma-agent")
    assert ex.execute(_call("uma_probe", "c1")).success is True
    assert len(sink.unbound()) == 1


def test_bus_absent_dispatch_unaffected() -> None:
    calls: list = []
    ex = ToolExecutor([_MutatingTool(calls)], agent_id="uma-agent")
    assert ex.execute(_call("uma_probe", "c1")).success is True
    assert len(calls) == 1


def test_alert_carries_no_secrets_or_params() -> None:
    secret = "sk-12345678901234567890-audittest"
    calls: list = []
    bus = EventBus()
    sink = _AlertSink(bus)
    ex = ToolExecutor([_MutatingTool(calls)], bus=bus, agent_id="uma-agent")
    result = ex.execute(_call("uma_probe", "c1",
                              {"note": secret, "password": "hunter2-secret"}))
    assert result.success is True
    alerts = sink.unbound()
    assert len(alerts) == 1
    blob = json.dumps([str(v) for v in _flatten(alerts[0].data)])
    assert secret not in blob
    assert "hunter2" not in blob
    assert "note" not in alerts[0].data


def test_unknown_outcome_contract_preserved() -> None:
    class _Hanging(_MutatingTool):
        @property
        def spec(self) -> ToolSpec:
            base = super().spec
            base.timeout_seconds = 0.3
            return base

        def execute(self, **params: Any) -> ToolResult:
            import time

            self._calls.append(dict(params))
            time.sleep(10)
            raise AssertionError("must time out first")

    calls: list = []
    bus = EventBus()
    sink = _AlertSink(bus)
    ex = ToolExecutor([_Hanging(calls)], bus=bus, agent_id="uma-agent")
    result = ex.execute(_call("uma_probe", "c1"))
    assert result.success is False
    assert "UNKNOWN_OUTCOME" in result.content
    assert result.metadata["execution"]["retryable"] is False
    # Submitted while unbound, so exactly one audit record exists —
    # observability without changing the outcome contract.
    assert len(sink.unbound()) == 1
