"""T3 regression: unbound/misconfigured executor states fail closed.

Exercises ToolExecutor (src/openjarvis/tools/_stubs.py) with a recording
fake tool. No network, no subprocess, no real tools are touched: the fake
tool only appends to an in-memory list.

Contract under test: every row must deny with success=False, leave the
fake uninvoked, and (where applicable) report NOT_STARTED — except the
explicit allow-path control, which proves the matrix is not deny-everything.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from openjarvis.agents.tool_resolver import _SpecOverrideTool
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec


class _RecordingTool(BaseTool):
    """Fake tool that records invocations instead of acting."""

    tool_id = "t3_probe"

    def __init__(
        self,
        calls: list,
        *,
        name: str = "t3_probe",
        caps: list | None = None,
        confirm: bool = False,
        effect: ToolEffect = ToolEffect.MUTATING,
        timeout: float = 30.0,
        local: bool = True,
    ) -> None:
        self._calls = calls
        self._spec = ToolSpec(
            name=name,
            description="t3 probe",
            requires_confirmation=confirm,
            timeout_seconds=timeout,
            required_capabilities=list(caps or []),
            effect=effect,
        )
        self._local = local

    @property
    def spec(self) -> ToolSpec:
        return self._spec

    @property
    def is_local(self) -> bool:
        return self._local

    def execute(self, **params: Any) -> ToolResult:
        self._calls.append(dict(params))
        return ToolResult(tool_name=self._spec.name, content="probe-ok",
                          success=True)


def _call(
    name: str = "t3_probe", args: dict | None = None, cid: str = "c1"
) -> ToolCall:
    return ToolCall(id=cid, name=name,
                    arguments=json.dumps(args or {"x": 1}))


def _executor(tool: _RecordingTool, **kw: Any) -> ToolExecutor:
    return ToolExecutor([tool], agent_id="t3-agent", **kw)


def test_no_policy_denies_code_tool() -> None:
    calls: list = []
    ex = _executor(_RecordingTool(calls, caps=["code:execute"]),
                   interactive=True, confirm_callback=lambda prompt: True)
    result = ex.execute(_call())
    assert result.success is False
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert result.execution_state == ExecutionState.NOT_STARTED
    assert calls == []


def test_policy_deny_denies_code_tool() -> None:
    calls: list = []
    policy = CapabilityPolicy(default_deny=True)
    ex = _executor(_RecordingTool(calls, caps=["code:execute"]),
                   interactive=True, confirm_callback=lambda prompt: True,
                   capability_policy=policy)
    result = ex.execute(_call())
    assert result.success is False
    assert "denied" in result.content
    assert calls == []


def test_policy_grant_allows_readonly_control() -> None:
    """Allow-path control: the matrix can still permit authorized calls."""
    calls: list = []
    policy = CapabilityPolicy(default_deny=True)
    policy.grant("t3-agent", "data:read")
    ex = _executor(
        _RecordingTool(calls, caps=["data:read"],
                       effect=ToolEffect.READ_ONLY),
        capability_policy=policy,
    )
    result = ex.execute(_call())
    assert result.success is True
    assert len(calls) == 1


def test_mutation_intent_required() -> None:
    calls: list = []
    ex = _executor(_RecordingTool(calls, confirm=True),
                   interactive=True, confirm_callback=lambda prompt: True,
                   require_mutation_intent=True)
    result = ex.execute(_call())
    assert result.success is False
    assert result.metadata["semantic"]["failure"] == "MISSING_TRUSTED_INTENT"
    assert calls == []


def test_tainted_input_to_sink_denied() -> None:
    calls: list = []
    ex = _executor(_RecordingTool(calls, name="http_request", local=False),
                   capability_policy=CapabilityPolicy())
    ex.begin_session(["contact sk-12345678901234567890 for access"])
    result = ex.execute(_call(name="http_request"))
    assert result.success is False
    assert "Taint violation" in result.content
    assert calls == []


def test_missing_confirmation_denied() -> None:
    calls: list = []
    ex = _executor(_RecordingTool(calls, confirm=True), interactive=False)
    result = ex.execute(_call())
    assert result.success is False
    assert "confirmation" in result.content
    assert calls == []


def test_confirmation_refusal_denied() -> None:
    calls: list = []
    ex = _executor(_RecordingTool(calls, confirm=True),
                   interactive=True, confirm_callback=lambda prompt: False)
    result = ex.execute(_call())
    assert result.success is False
    assert "denied by user" in result.content
    assert calls == []


def test_cancelled_scope_not_dispatched() -> None:
    calls: list = []
    journal = SimpleNamespace(
        cancellation_state=lambda scope: {"reason": "t3-test"},
        reserve=lambda *a: (_ for _ in ()).throw(AssertionError("no reserve")),
    )
    ex = _executor(_RecordingTool(calls), execution_journal=journal,
                   execution_scope="t3-scope")
    result = ex.execute(_call())
    assert result.success is False
    assert result.metadata.get("cancelled") is True
    assert calls == []


def test_journal_failure_fails_closed() -> None:
    calls: list = []
    journal = SimpleNamespace(
        cancellation_state=lambda scope: None,
        reserve=lambda *a: (_ for _ in ()).throw(IOError("store down")),
    )
    ex = _executor(_RecordingTool(calls), execution_journal=journal,
                   execution_scope="t3-scope")
    result = ex.execute(_call())
    assert result.success is False
    assert "blocked" in result.content
    assert calls == []


def test_unknown_tool_rejected() -> None:
    calls: list = []
    ex = _executor(_RecordingTool(calls))
    result = ex.execute(_call(name="no_such_tool"))
    assert result.success is False
    assert "Unknown tool" in result.content
    assert calls == []


def test_malformed_arguments_rejected() -> None:
    calls: list = []
    ex = _executor(_RecordingTool(calls))
    bad_json = ToolCall(id="c9", name="t3_probe", arguments="{oops")
    assert ex.execute(bad_json).success is False
    non_object = ToolCall(id="c8", name="t3_probe", arguments="[1,2]")
    assert ex.execute(non_object).success is False
    assert calls == []


def test_spec_rename_preserves_capability_floor() -> None:
    """A renamed privileged tool keeps its capability requirements."""
    calls: list = []
    inner = _RecordingTool(calls, caps=["code:execute"])
    renamed = _SpecOverrideTool(
        inner, {"function": {"name": "harmless", "description": "d",
                             "parameters": {}}},
    )
    assert renamed.spec.name == "harmless"
    assert "code:execute" in renamed.spec.required_capabilities
    ex = ToolExecutor([renamed], agent_id="t3-agent", interactive=True,
                      confirm_callback=lambda prompt: True)
    result = ex.execute(_call(name="harmless"))
    assert result.success is False
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert calls == []


def test_shell_deny_holds_on_direct_call() -> None:
    """Defense in depth: deny-by-default tools refuse even direct calls."""
    from openjarvis.tools.shell_exec import ShellExecTool

    result = ShellExecTool().execute(command="echo must-not-run")
    assert result.success is False
    assert result.execution_state == ExecutionState.NOT_STARTED
    assert result.metadata.get("security_denied") is True


def test_rate_limit_exhaustion_denies() -> None:
    limiter_calls = {"n": 0}

    class _DenyLimiter:
        def check(self, key: str) -> tuple:
            limiter_calls["n"] += 1
            return False, 5.0

    calls: list = []
    ex = _executor(_RecordingTool(calls, effect=ToolEffect.READ_ONLY),
                   rate_limiter=_DenyLimiter())
    result = ex.execute(_call())
    assert result.success is False
    assert "Rate limit" in result.content
    assert calls == []
    assert limiter_calls["n"] == 1


def test_failing_first_allowing_policy_detected() -> None:
    """Sensitivity: a grant-everything policy reaches the tool (control)."""
    calls: list = []
    policy = CapabilityPolicy()  # open by default
    ex = _executor(
        _RecordingTool(calls, caps=["code:execute"],
                       effect=ToolEffect.READ_ONLY),
        capability_policy=policy,
    )
    result = ex.execute(_call())
    assert result.success is True
    assert len(calls) == 1
    # And the same tool without any policy must still be denied.
    ex2 = _executor(_RecordingTool(calls, caps=["code:execute"],
                                   effect=ToolEffect.READ_ONLY))
    assert ex2.execute(_call(cid="c2")).success is False
    assert len(calls) == 1
