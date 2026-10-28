"""Web Search authority-boundary regression (mock-only, no network).

Models the `agents/hybrid/_base.py::tavily_search_context` direct-call
pattern with a fake non-local search tool: the same model-derived query
is run through the managed executor path and the direct path, recording
actual behavior on each.

Proven here: the managed path denies without a host capability policy;
the direct path executes on tool-internal checks only. Migration to
`execute_secured_tool` is BLOCKED (see report): without a policy in the
hybrid scaffolding context the managed path denies every search.
"""

from __future__ import annotations

import json
from typing import Any

from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.security.runtime import execute_secured_tool
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec


class _FakeSearchTool(BaseTool):
    """Non-local search stand-in: records instead of touching network."""

    tool_id = "ws_probe"

    def __init__(self, calls: list) -> None:
        self._calls = calls

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name="ws_probe", description="search probe",
                        timeout_seconds=30.0, effect=ToolEffect.MUTATING)

    @property
    def is_local(self) -> bool:
        return False

    def execute(self, **params: Any) -> ToolResult:
        self._calls.append(dict(params))
        return ToolResult(tool_name="ws_probe", content="result-text",
                          success=True,
                          execution_state=ExecutionState.EXECUTED,
                          metadata={"engine": "probe", "credits": 0})


def _call(args: dict, cid: str = "c1") -> ToolCall:
    return ToolCall(id=cid, name="ws_probe", arguments=json.dumps(args))


def test_managed_path_denies_without_policy() -> None:
    calls: list = []
    ex = ToolExecutor([_FakeSearchTool(calls)], agent_id="ws-agent",
                      interactive=True,
                      confirm_callback=lambda prompt: True)
    result = ex.execute(_call({"query": "model-derived query"}))
    assert result.success is False
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert calls == []


def test_managed_path_executes_with_policy() -> None:
    """Control: with a host policy the managed path works (not deny-all)."""
    calls: list = []
    ex = ToolExecutor([_FakeSearchTool(calls)], agent_id="ws-agent",
                      capability_policy=CapabilityPolicy())
    result = ex.execute(_call({"query": "model-derived query"}))
    assert result.success is True
    assert len(calls) == 1


def test_direct_path_executes_without_policy() -> None:
    """Gap record: the _base.py direct-call pattern bypasses the policy."""
    calls: list = []
    result = _FakeSearchTool(calls).execute(query="model-derived query",
                                            max_results=5)
    assert result.success is True
    assert calls == [{"query": "model-derived query", "max_results": 5}]


def test_secured_tool_without_policy_denies_search() -> None:
    """Migration evidence: execute_secured_tool sans policy denies.

    This is why the _base.py migration is BLOCKED — swapping the call
    would turn every hybrid search into a denial until policy plumbing
    exists in the scaffolding context.
    """
    calls: list = []
    result = execute_secured_tool(_FakeSearchTool(calls),
                                  {"query": "q"}, agent_id="ws-agent")
    assert result.success is False
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert calls == []


def test_result_shape_compatible_with_context_builder() -> None:
    """The managed/direct results expose what tavily_search_context reads."""
    calls: list = []
    ex = ToolExecutor([_FakeSearchTool(calls)], agent_id="ws-agent",
                      capability_policy=CapabilityPolicy())
    result = ex.execute(_call({"query": "q"}))
    meta = dict(result.metadata or {})
    assert isinstance(result.content, str)
    assert isinstance(result.success, bool)
    assert "engine" in meta
