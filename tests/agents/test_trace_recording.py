"""Tests for trace recording in AgentExecutor."""

from __future__ import annotations

import json
from unittest.mock import patch

from openjarvis.agents._stubs import AgentResult
from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.manager import AgentManager
from openjarvis.core.events import EventBus, EventType
from openjarvis.traces.store import TraceStore


def test_real_verified_tool_trace_retains_identity_and_frozen_clock_latency(tmp_path):
    from openjarvis.core.types import ToolCall
    from openjarvis.tools._stubs import ToolExecutor
    from openjarvis.tools.file_write import FileWriteTool

    manager = AgentManager(str(tmp_path / "agents.db"))
    store = TraceStore(str(tmp_path / "traces.db"))
    bus = EventBus()
    agent = manager.create_agent("verified trace")
    executor = AgentExecutor(manager, bus, trace_store=store)
    tools = ToolExecutor([FileWriteTool()], bus=bus, agent_id=agent["id"])
    path = tmp_path / "artifact.txt"
    arguments = {"path": str(path), "content": "observed artifact"}

    def invoke(_agent):
        result = tools.execute(
            ToolCall("write-identity", "file_write", json.dumps(arguments))
        )
        assert result.success
        return AgentResult(content="artifact prepared")

    try:
        with (
            patch.object(executor, "_invoke_agent", side_effect=invoke),
            patch("openjarvis.agents.executor.time.time", return_value=100.0),
        ):
            executor.execute_tick(agent["id"])
        trace = store.list_traces(agent=agent["id"])[0]
        step = trace.steps[0]
        assert trace.total_latency_seconds > 0
        assert step.input["args"] == arguments
        assert step.input["call_id"] == "write-identity"
        assert step.duration_seconds > 0
        assert step.metadata["execution"]["state"] == "VERIFIED"
        assert step.output["success"] is True
        assert path.read_bytes() == b"observed artifact"
    finally:
        manager.close()
        store.close()


def test_overlapping_tool_trace_matches_completion_to_call_identity(tmp_path):
    manager = AgentManager(str(tmp_path / "agents.db"))
    store = TraceStore(str(tmp_path / "traces.db"))
    bus = EventBus()
    agent = manager.create_agent("overlap trace")
    executor = AgentExecutor(manager, bus, trace_store=store)

    def invoke(_agent):
        for call_id in ("first", "second"):
            bus.publish(
                EventType.TOOL_CALL_START,
                {
                    "agent": agent["id"],
                    "tool": "same_tool",
                    "call_id": call_id,
                    "arguments": {"target": call_id},
                },
            )
        for call_id in ("first", "second"):
            bus.publish(
                EventType.TOOL_CALL_END,
                {
                    "agent": agent["id"],
                    "tool": "same_tool",
                    "call_id": call_id,
                    "result": f"result for {call_id}",
                    "success": True,
                    "latency": 0.5,
                },
            )
        return AgentResult(content="done")

    try:
        with patch.object(executor, "_invoke_agent", side_effect=invoke):
            executor.execute_tick(agent["id"])
        trace = store.list_traces(agent=agent["id"])[0]
        for step in trace.steps:
            assert step.output["result"] == f"result for {step.input['call_id']}"
    finally:
        manager.close()
        store.close()


def test_executor_records_trace(tmp_path):
    """execute_tick records a trace with steps to TraceStore."""
    mgr = AgentManager(str(tmp_path / "agents.db"))
    trace_store = TraceStore(str(tmp_path / "traces.db"))
    bus = EventBus()
    executor = AgentExecutor(mgr, bus, trace_store=trace_store)

    agent = mgr.create_agent("trace-test")

    def fake_invoke(agent_dict):
        bus.publish(
            EventType.TOOL_CALL_START,
            {
                "agent": agent_dict["id"],
                "tool": "web_search",
                "args": {"query": "test"},
            },
        )
        bus.publish(
            EventType.TOOL_CALL_END,
            {
                "agent": agent_dict["id"],
                "tool": "web_search",
                "result": "search results...",
                "duration": 0.5,
            },
        )
        return AgentResult(content="found it", metadata={"tokens_used": 100})

    with patch.object(executor, "_invoke_agent", side_effect=fake_invoke):
        executor.execute_tick(agent["id"])

    traces = trace_store.list_traces(agent=agent["id"])
    assert len(traces) == 1
    assert traces[0].agent == agent["id"]
    assert traces[0].outcome == "success"
    assert len(traces[0].steps) == 1
    assert traces[0].steps[0].step_type.value == "tool_call"
    assert traces[0].steps[0].input["tool"] == "web_search"
    assert traces[0].total_latency_seconds > 0

    mgr.close()
    trace_store.close()


def test_executor_records_error_trace(tmp_path):
    """execute_tick records an error trace on failure."""
    from openjarvis.agents.errors import FatalError

    mgr = AgentManager(str(tmp_path / "agents.db"))
    trace_store = TraceStore(str(tmp_path / "traces.db"))
    bus = EventBus()
    executor = AgentExecutor(mgr, bus, trace_store=trace_store)

    agent = mgr.create_agent("error-trace")

    with patch.object(
        executor,
        "_invoke_agent",
        side_effect=FatalError("boom"),
    ):
        executor.execute_tick(agent["id"])

    traces = trace_store.list_traces(agent=agent["id"])
    assert len(traces) == 1
    assert traces[0].outcome == "error"

    mgr.close()
    trace_store.close()


def test_executor_no_trace_without_store(tmp_path):
    """Without trace_store, no error is raised."""
    mgr = AgentManager(str(tmp_path / "agents.db"))
    bus = EventBus()
    executor = AgentExecutor(mgr, bus)  # No trace_store

    agent = mgr.create_agent("no-trace")

    def fake_invoke(agent_dict):
        return AgentResult(content="done", metadata={})

    with patch.object(executor, "_invoke_agent", side_effect=fake_invoke):
        executor.execute_tick(agent["id"])

    updated = mgr.get_agent(agent["id"])
    assert updated["status"] == "idle"
    mgr.close()
