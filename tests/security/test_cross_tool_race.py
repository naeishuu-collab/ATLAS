"""T4 regression: cross-tool race & result isolation.

Uses real threads through ToolExecutor (src/openjarvis/tools/_stubs.py)
with recording fake tools. No network, no subprocess, no real tools.

Contract under test:
- Two concurrent dispatches of the same mutating tool: exactly one
  invocation; the loser is rejected with UNKNOWN_OUTCOME (never executed).
- Two concurrent dispatches of different tools: both run, results are
  not mixed (tool_name/call_id binding).
- A timed-out mutating dispatch reports UNKNOWN_OUTCOME (non-retryable)
  and a follow-up retry is rejected until reconciled.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec


class _GatedTool(BaseTool):
    """Fake mutating tool that blocks until released."""

    tool_id = "t4_gated"

    def __init__(self, calls: list, entered: threading.Event,
                 release: threading.Event, marker: str) -> None:
        self._calls = calls
        self._entered = entered
        self._release = release
        self._marker = marker

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name="t4_gated", description="t4 gated",
                        timeout_seconds=30.0, effect=ToolEffect.MUTATING)

    def execute(self, **params: Any) -> ToolResult:
        self._calls.append(dict(params))
        self._entered.set()
        assert self._release.wait(timeout=15), "test harness did not release"
        return ToolResult(tool_name="t4_gated",
                          content=f"gated-{self._marker}", success=True,
                          execution_state=ExecutionState.EXECUTED)


class _EchoTool(BaseTool):
    tool_id = "t4_echo"

    def __init__(self, calls: list, name: str, delay: float = 0.2) -> None:
        self._calls = calls
        self._name = name
        self._delay = delay

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name=self._name, description="t4 echo",
                        timeout_seconds=30.0, effect=ToolEffect.MUTATING)

    def execute(self, **params: Any) -> ToolResult:
        self._calls.append((self._name, dict(params)))
        time.sleep(self._delay)
        return ToolResult(tool_name=self._name,
                          content=f"echo-{self._name}", success=True,
                          execution_state=ExecutionState.EXECUTED)


class _HangingTool(BaseTool):
    tool_id = "t4_hanging"

    def __init__(self, calls: list) -> None:
        self._calls = calls

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name="t4_hanging", description="t4 hanging",
                        timeout_seconds=0.3, effect=ToolEffect.MUTATING)

    def execute(self, **params: Any) -> ToolResult:
        self._calls.append(dict(params))
        time.sleep(10)
        return ToolResult(tool_name="t4_hanging", content="late",
                          success=True,
                          execution_state=ExecutionState.EXECUTED)


def _call(name: str, cid: str) -> ToolCall:
    return ToolCall(id=cid, name=name, arguments=json.dumps({"x": 1}))


def test_same_tool_concurrent_second_rejected() -> None:
    calls: list = []
    entered = threading.Event()
    release = threading.Event()
    ex = ToolExecutor([_GatedTool(calls, entered, release, "A")],
                      agent_id="t4-agent")
    results: dict = {}

    def run(key: str, cid: str) -> None:
        results[key] = ex.execute(_call("t4_gated", cid))

    first = threading.Thread(target=run, args=("first", "c1"))
    first.start()
    assert entered.wait(timeout=15), "first dispatch never reached the tool"
    second = threading.Thread(target=run, args=("second", "c2"))
    second.start()
    second.join(timeout=15)
    assert not second.is_alive(), "rejected dispatch must return promptly"
    release.set()
    first.join(timeout=15)

    assert len(calls) == 1, "same mutating tool must run exactly once"
    assert results["first"].success is True
    loser = results["second"]
    assert loser.success is False
    assert "UNKNOWN_OUTCOME" in loser.content
    # Isolation: the rejection names its own request but points at the
    # unresolved in-flight action, never mixing the two identities.
    assert loser.metadata["request_call_id"] == "c2"
    assert loser.metadata["execution"]["call_id"] == "c1"


def test_distinct_tools_results_not_mixed() -> None:
    calls: list = []
    ex = ToolExecutor([_EchoTool(calls, "t4_alpha"),
                       _EchoTool(calls, "t4_beta")],
                      agent_id="t4-agent")
    results: dict = {}

    def run(key: str, name: str, cid: str) -> None:
        results[key] = ex.execute(_call(name, cid))

    threads = [threading.Thread(target=run, args=("a", "t4_alpha", "c1")),
               threading.Thread(target=run, args=("b", "t4_beta", "c2"))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
    assert results["a"].success is True
    assert results["b"].success is True
    assert results["a"].tool_name == "t4_alpha"
    assert results["b"].tool_name == "t4_beta"
    assert results["a"].content == "echo-t4_alpha"
    assert results["b"].content == "echo-t4_beta"
    assert results["a"].metadata["execution"]["call_id"] == "c1"
    assert results["b"].metadata["execution"]["call_id"] == "c2"
    assert len(calls) == 2


def test_timeout_reports_unknown_outcome_and_blocks_retry() -> None:
    calls: list = []
    ex = ToolExecutor([_HangingTool(calls)], agent_id="t4-agent")
    result = ex.execute(_call("t4_hanging", "c1"))
    assert result.success is False
    assert "UNKNOWN_OUTCOME" in result.content
    assert result.metadata["timeout"]["outcome"] == "UNKNOWN_OUTCOME"
    assert result.metadata["execution"]["retryable"] is False
    retry = ex.execute(_call("t4_hanging", "c2"))
    assert retry.success is False
    assert "UNKNOWN_OUTCOME" in retry.content
    assert len(calls) == 1, "timed-out action must not be re-entered blindly"


def test_failing_first_naive_dispatch_double_runs() -> None:
    """Sensitivity: without executor serialization both dispatches run."""
    calls: list = []
    entered = threading.Event()
    release = threading.Event()
    tool = _GatedTool(calls, entered, release, "naive")

    def run() -> None:
        tool.execute(x=1)

    threads = [threading.Thread(target=run), threading.Thread(target=run)]
    for thread in threads:
        thread.start()
    assert entered.wait(timeout=15)
    release.set()
    for thread in threads:
        thread.join(timeout=15)
    # Proves the T4 serialization assertion (calls == 1) can actually fail:
    assert len(calls) == 2
