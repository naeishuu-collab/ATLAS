"""Direct tool-execution boundary regression.

Maps which `tool.execute` paths bypass ToolExecutor gates, using fake
tools only. No network, no subprocess, no real tools.

Design truth under test: executor dispatch (`executor.execute`) applies
capability/taint/confirm/intent/serialization gates; direct Python calls
(`tool.execute`) apply only the tool's own internal checks. Tests record
actual behavior — a direct call that executes is asserted as executing
(boundary documentation), never disguised as denied.
"""

from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace
from typing import Any

from openjarvis.agents.tool_resolver import _SpecOverrideTool
from openjarvis.core.events import EventBus
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.skills.manager import _NullToolExecutor
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec
from openjarvis.tools.mcp_adapter import MCPToolAdapter


class _MutatingTool(BaseTool):
    tool_id = "dtb_probe"

    def __init__(self, calls: list, name: str = "dtb_probe",
                 caps: list | None = None) -> None:
        self._calls = calls
        self._name = name
        self._caps = list(caps or [])

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name=self._name, description="direct boundary probe",
                        timeout_seconds=30.0,
                        required_capabilities=self._caps,
                        effect=ToolEffect.MUTATING)

    def execute(self, **params: Any) -> ToolResult:
        self._calls.append(dict(params))
        return ToolResult(tool_name=self._name, content="probe-ok",
                          success=True,
                          execution_state=ExecutionState.EXECUTED)


def _call(name: str, cid: str, args: dict | None = None) -> ToolCall:
    return ToolCall(id=cid, name=name,
                    arguments=json.dumps(args or {"x": 1}))


def test_model_args_direct_call_executes_without_gates() -> None:
    """Boundary contrast: identical model-derived args, two paths."""
    model_args = {"target": "model-chosen-value"}
    direct_calls: list = []
    direct_tool = _MutatingTool(direct_calls, caps=["code:execute"])
    # Direct path: no capability, no confirm, no intent — executes.
    assert direct_tool.execute(**model_args).success is True
    assert direct_calls == [model_args]
    # Managed path: same tool, same args — denied without host policy.
    gated_calls: list = []
    ex = ToolExecutor([_MutatingTool(gated_calls, caps=["code:execute"])],
                      agent_id="dtb-agent", interactive=True,
                      confirm_callback=lambda prompt: True)
    result = ex.execute(_call("dtb_probe", "c1", model_args))
    assert result.success is False
    assert gated_calls == []


def test_override_dispatch_uses_advertised_name_with_gates() -> None:
    calls: list = []
    inner = _MutatingTool(calls, caps=["code:execute"])
    override = _SpecOverrideTool(
        inner, {"function": {"name": "harmless", "description": "d",
                             "parameters": {}}})
    ex = ToolExecutor([override], agent_id="dtb-agent", interactive=True,
                      confirm_callback=lambda prompt: True)
    assert "harmless" in ex._tools
    assert ex._tools["harmless"] is override
    result = ex.execute(_call("harmless", "c1"))
    assert result.success is False
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert calls == []


def test_override_delegate_reaches_wrapped_tool() -> None:
    """Sensitivity: the adapter itself performs no gating (by design)."""
    calls: list = []
    inner = _MutatingTool(calls)
    override = _SpecOverrideTool(inner, {"function": {"name": "renamed"}})
    assert override.execute(x=1).success is True
    assert len(calls) == 1


def test_null_executor_denies_skill_without_wiring() -> None:
    ex = _NullToolExecutor()
    result = ex.execute(_call("any_skill_tool", "c1"))
    assert result.success is False
    assert "Unknown tool" in result.content


def test_mcp_external_transport_denied() -> None:
    from openjarvis.tools._stubs import ToolSpec as Spec

    client = SimpleNamespace(_transport=object())  # not InProcessTransport
    spec = Spec(name="remote_tool", description="d")
    result = MCPToolAdapter(client, spec).execute(x=1)
    assert result.success is False
    assert result.execution_state == ExecutionState.NOT_STARTED
    assert result.metadata.get("security_denied") is True


def test_direct_call_ignores_executor_quarantine() -> None:
    """Gap documentation: executor serialization does not bind direct calls.

    While the executor holds an unresolved mutating action, a direct call
    to the same tool instance still runs. Asserted as-is (gap record),
    not as approval.
    """
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

    tool = _Gated(calls)
    ex = ToolExecutor([tool], agent_id="dtb-agent")
    holder: dict = {}

    def run() -> None:
        holder["r"] = ex.execute(_call("dtb_probe", "c1"))

    direct: dict = {}

    def run_direct() -> None:
        direct["r"] = tool.execute(x=2)

    first = threading.Thread(target=run)
    first.start()
    assert entered.wait(timeout=15)
    # Executor path would reject a second dispatch; the direct path runs.
    second = threading.Thread(target=run_direct)
    second.start()
    time.sleep(1.0)  # let the direct call enter the tool past any gate
    release.set()
    second.join(timeout=20)
    assert not second.is_alive(), "direct call must not be serialized"
    assert direct["r"].success is True
    first.join(timeout=15)
    assert holder["r"].success is True
    assert len(calls) == 2


def test_direct_call_skips_unbound_mutation_audit() -> None:
    """Audit scope record: direct calls emit no UNBOUND_MUTATION alert."""
    from openjarvis.core.events import EventType

    calls: list = []
    bus = EventBus()
    seen: list = []
    bus.subscribe(EventType.SECURITY_ALERT, seen.append)
    tool = _MutatingTool(calls)
    ToolExecutor([_MutatingTool([])], bus=bus, agent_id="dtb-agent")
    assert tool.execute(x=1).success is True
    assert seen == []
    assert len(calls) == 1


def test_failing_first_removed_gate_detected() -> None:
    """Sensitivity: stripping the executor lets everything through."""

    class _OpenExecutor(ToolExecutor):
        def execute(self, tool_call: ToolCall, **kw: Any) -> ToolResult:  # type: ignore[override]
            tool = self._tools[tool_call.name]
            return tool.execute(**json.loads(tool_call.arguments or "{}"))

    calls: list = []
    ex = _OpenExecutor([_MutatingTool(calls, caps=["code:execute"])],
                       agent_id="dtb-agent")
    assert ex.execute(_call("dtb_probe", "c1")).success is True
    assert len(calls) == 1  # gates gone → reached; real executor must deny
    gated: list = []
    real = ToolExecutor([_MutatingTool(gated, caps=["code:execute"])],
                        agent_id="dtb-agent")
    assert real.execute(_call("dtb_probe", "c2")).success is False
    assert gated == []
