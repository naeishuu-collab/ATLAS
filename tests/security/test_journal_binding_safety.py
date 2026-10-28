"""Journal binding & mutation safety matrix.

Audits ToolExecutor (src/openjarvis/tools/_stubs.py) across journal
bound/unbound configurations with a recording fake tool. No network, no
subprocess, no real tools.

Key architectural fact under test: the constructor default is
journal=None + require_mutation_intent=False (see agents/_stubs.py:448,
mcp/server.py:78, security/runtime.py:269); journal binding happens only
in managed paths (agents/executor.py:2764, server/agent_manager_routes).
The matrix records actual behavior per configuration — it does not force
every row to deny.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from openjarvis.core.execution import ExecutionState, MutationIntent, ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec


class _RecordingTool(BaseTool):
    tool_id = "jb_probe"

    def __init__(self, calls: list, *,
                 effect: ToolEffect = ToolEffect.MUTATING) -> None:
        self._calls = calls
        self._effect = effect

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name="jb_probe", description="journal binding probe",
                        timeout_seconds=30.0, effect=self._effect)

    def execute(self, **params: Any) -> ToolResult:
        self._calls.append(dict(params))
        return ToolResult(tool_name="jb_probe", content="probe-ok",
                          success=True,
                          execution_state=ExecutionState.EXECUTED)


class _StubJournal:
    """Minimal in-memory journal implementing the executor protocol."""

    def __init__(self, fail_on: str = "") -> None:
        self._fail_on = fail_on
        self.finished: list = []

    def _maybe_fail(self, where: str) -> None:
        if self._fail_on == where:
            raise IOError(f"journal {where} unavailable")

    def cancellation_state(self, scope: str) -> None:
        return None

    def reserve(self, scope: str, name: str, call_id: str) -> str:
        self._maybe_fail("reserve")
        return f"tok-{call_id}"

    def reserve_intent(self, scope: str, name: str, call_id: str,
                       intent: MutationIntent) -> dict:
        self._maybe_fail("reserve_intent")
        return {"token": f"tok-{call_id}", "state": "PREPARED"}

    def begin_dispatch(self, token: str) -> bool:
        self._maybe_fail("begin_dispatch")
        return True

    def mark_not_dispatched(self, token: str, evidence: str = "") -> None:
        return None

    def finish(self, token: str, **kw: Any) -> None:
        self._maybe_fail("finish")
        self.finished.append(token)


def _call(cid: str = "c1") -> ToolCall:
    return ToolCall(id=cid, name="jb_probe",
                    arguments=json.dumps({"x": 1}))


def _intent() -> MutationIntent:
    return MutationIntent(execution_id="e1", step_id="s1",
                          mutation_intent_id="m1")


def test_constructor_default_is_unbound() -> None:
    """Default posture: no journal, intent not required (sensitivity trip)."""
    ex = ToolExecutor([_RecordingTool([])], agent_id="jb")
    assert ex._execution_journal is None
    assert ex._require_mutation_intent is False


def test_managed_bound_intent_executes() -> None:
    """Control: bound journal + valid intent dispatches (managed path)."""
    calls: list = []
    journal = _StubJournal()
    ex = ToolExecutor([_RecordingTool(calls)], agent_id="jb",
                      execution_journal=journal, execution_scope="jb-scope",
                      require_mutation_intent=True)
    result = ex.execute(_call(), mutation_context=_intent())
    assert result.success is True
    assert len(calls) == 1
    assert journal.finished == ["tok-c1"]


def test_bound_intent_required_denies_without_intent() -> None:
    calls: list = []
    ex = ToolExecutor([_RecordingTool(calls)], agent_id="jb",
                      execution_journal=_StubJournal(),
                      execution_scope="jb-scope",
                      require_mutation_intent=True)
    result = ex.execute(_call())
    assert result.success is False
    assert result.metadata["semantic"]["failure"] == "MISSING_TRUSTED_INTENT"
    assert calls == []


def test_unbound_intent_required_denies() -> None:
    calls: list = []
    ex = ToolExecutor([_RecordingTool(calls)], agent_id="jb",
                      require_mutation_intent=True)
    result = ex.execute(_call())
    assert result.success is False
    assert result.metadata["semantic"]["failure"] == "MISSING_TRUSTED_INTENT"
    assert calls == []


def test_unbound_no_intent_executes_on_capability_and_confirm() -> None:
    """Focus row: journal=None + intent not required.

    Actual behavior: executes once capability and confirmation gates pass.
    The test proves both gates were consulted (counting doubles), so this
    configuration is capability+confirm authorized — not ungated.
    """
    calls: list = []
    confirmations: list = []
    policy = CapabilityPolicy(default_deny=True)
    policy.grant("jb", "data:write", pattern="jb_probe")

    class _CountingTool(_RecordingTool):
        @property
        def spec(self) -> ToolSpec:
            base = super().spec
            base.required_capabilities.append("data:write")
            base.requires_confirmation = True
            return base

    tool = _CountingTool(calls)
    ex = ToolExecutor([tool], agent_id="jb", capability_policy=policy,
                      interactive=True,
                      confirm_callback=lambda p: confirmations.append(p) or True)
    result = ex.execute(_call())
    assert result.success is True
    assert len(calls) == 1
    assert len(confirmations) == 1
    # Same configuration without the grant must deny.
    calls2: list = []
    ex2 = ToolExecutor([_CountingTool(calls2)], agent_id="jb",
                       capability_policy=CapabilityPolicy(default_deny=True),
                       interactive=True,
                       confirm_callback=lambda p: True)
    assert ex2.execute(_call()).success is False
    assert calls2 == []


def test_unbound_confirm_refusal_denies() -> None:
    calls: list = []

    class _ConfirmTool(_RecordingTool):
        @property
        def spec(self) -> ToolSpec:
            base = super().spec
            base.requires_confirmation = True
            return base

    ex = ToolExecutor([_ConfirmTool(calls)], agent_id="jb",
                      interactive=True,
                      confirm_callback=lambda p: False)
    result = ex.execute(_call())
    assert result.success is False
    assert calls == []


def test_bound_journal_failure_fails_closed_with_intent() -> None:
    calls: list = []
    ex = ToolExecutor([_RecordingTool(calls)], agent_id="jb",
                      execution_journal=_StubJournal(fail_on="reserve_intent"),
                      execution_scope="jb-scope",
                      require_mutation_intent=True)
    result = ex.execute(_call(), mutation_context=_intent())
    assert result.success is False
    assert result.metadata["semantic"]["failure"] == "SEMANTIC_GATE_FAILURE"
    assert calls == []


def test_unbound_readonly_control_executes() -> None:
    calls: list = []
    ex = ToolExecutor(
        [_RecordingTool(calls, effect=ToolEffect.READ_ONLY)], agent_id="jb")
    result = ex.execute(_call())
    assert result.success is True
    assert len(calls) == 1


def test_mutation_intent_rejects_empty_identity() -> None:
    with pytest.raises(ValueError):
        MutationIntent(execution_id="", step_id="s", mutation_intent_id="m")
    with pytest.raises(ValueError):
        MutationIntent(execution_id="e", step_id="s", mutation_intent_id="  ")


def test_rebind_with_unresolved_action_refused() -> None:
    """bind_execution_journal never discards active quarantine."""
    calls: list = []
    ex = ToolExecutor([_RecordingTool(calls)], agent_id="jb")
    ex._mutation_states["jb_probe"] = SimpleNamespace()  # unresolved marker
    with pytest.raises(RuntimeError):
        ex.bind_execution_journal(_StubJournal(), "other-scope")


def test_failing_first_naive_runner_ignores_gates() -> None:
    """Sensitivity: calling the tool directly bypasses every gate."""
    calls: list = []
    tool = _RecordingTool(calls)
    result = tool.execute(x=1)  # no executor, no capability, no confirm
    assert result.success is True
    assert len(calls) == 1
