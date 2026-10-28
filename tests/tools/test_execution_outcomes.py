"""Fault injection for uncertain tool mutations and executor contracts."""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from openjarvis.core.events import EventBus, EventType
from openjarvis.core.execution import ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.tools import _stubs
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec


class MutationTool(BaseTool):
    tool_id = "mutation"

    def __init__(self, *, raises=False, succeeds=True, effect=ToolEffect.MUTATING):
        self.release = threading.Event()
        self.started = threading.Event()
        self.finished = threading.Event()
        self.calls = 0
        self.raises = raises
        self.succeeds = succeeds
        self.effect = effect

    @property
    def spec(self):
        return ToolSpec(
            name=self.tool_id,
            description="test mutation",
            timeout_seconds=0.05,
            effect=self.effect,
        )

    def execute(self, **params):
        self.calls += 1
        self.started.set()
        try:
            assert self.release.wait(2), "test did not release worker"
            if self.raises:
                raise RuntimeError("mutation happened before transport failed")
            return ToolResult(self.tool_id, "returned", success=self.succeeds)
        finally:
            self.finished.set()


def call(identifier="one", arguments="{}", name="mutation"):
    return ToolCall(identifier, name, arguments)


@pytest.fixture
def runner(monkeypatch):
    value = _stubs._BoundedToolRunner(1, 1)
    monkeypatch.setattr(_stubs, "_TOOL_RUNNER", value)
    yield value
    value.shutdown()


def test_unknown_mutation_cannot_be_retried_with_new_id_or_arguments(runner):
    tool = MutationTool()
    bus = EventBus(record_history=True)
    executor = ToolExecutor([tool], bus=bus)
    try:
        result = executor.execute(call())
        assert tool.started.is_set()
        assert result.metadata["execution"] == {
            "state": "UNKNOWN_OUTCOME",
            "failure": "UNKNOWN_OUTCOME",
            "retryable": False,
            "call_id": "one",
        }
        executor.begin_session(["another conversation"])
        blocked = executor.execute(call("two", '{"new":true}'))
        assert not blocked.success
        assert "reconcile" in blocked.content
        assert tool.calls == 1
        end = [e for e in bus.history if e.event_type == EventType.TOOL_CALL_END]
        assert end[0].data["metadata"]["execution"]["state"] == "UNKNOWN_OUTCOME"
        json.dumps(end[0].data)
    finally:
        tool.release.set()
        assert tool.finished.wait(1)
    # Late success does not automatically authorize a repeat.
    assert not executor.execute(call("three")).success
    assert tool.calls == 1


@pytest.mark.parametrize("raises,succeeds", [(True, True), (False, False)])
def test_error_after_dispatch_is_uncertain_and_blocks_retry(runner, raises, succeeds):
    tool = MutationTool(raises=raises, succeeds=succeeds)
    tool.release.set()
    executor = ToolExecutor([tool])
    result = executor.execute(call())
    assert not result.success
    assert result.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
    assert not executor.execute(call("again")).success
    assert tool.calls == 1


def test_read_only_failure_does_not_quarantine_tool(runner):
    tool = MutationTool(raises=True, effect=ToolEffect.READ_ONLY)
    tool.release.set()
    executor = ToolExecutor([tool])
    for identifier in ("one", "two"):
        result = executor.execute(call(identifier))
        assert result.metadata["execution"]["failure"] == "TOOL_FAILURE"
    assert tool.calls == 2


def test_cancelled_queued_mutation_does_not_execute(runner):
    blocker = threading.Event()
    occupied = threading.Event()

    def occupy():
        occupied.set()
        blocker.wait(2)
        return ToolResult("occupy", "done")

    future = runner.submit(occupy)
    assert occupied.wait(1)
    tool = MutationTool()
    executor = ToolExecutor([tool])
    try:
        result = executor.execute(call())
        assert result.metadata["execution"]["state"] == "NOT_STARTED"
        assert result.metadata["execution"]["retryable"] is True
        assert tool.calls == 0
    finally:
        blocker.set()
        future.result(timeout=1)
    tool.release.set()
    assert executor.execute(call("retry")).success
    assert tool.calls == 1


def test_concurrent_mutation_dispatches_only_once(runner):
    tool = MutationTool()
    executor = ToolExecutor([tool])
    try:
        with ThreadPoolExecutor(2) as callers:
            first = callers.submit(executor.execute, call())
            assert tool.started.wait(1)
            second = callers.submit(executor.execute, call("two"))
            assert not second.result(timeout=1).success
            tool.release.set()
            assert first.result(timeout=1).success
        assert tool.calls == 1
    finally:
        tool.release.set()


def test_success_is_executed_not_implicitly_verified(runner):
    tool = MutationTool()
    tool.release.set()
    result = ToolExecutor([tool]).execute(call())
    assert result.success
    assert result.metadata["execution"]["state"] == "EXECUTED"


def test_duplicate_tool_names_fail_closed():
    with pytest.raises(ValueError, match="Duplicate tool name"):
        ToolExecutor([MutationTool(), MutationTool()])


def test_precondition_failure_did_not_start_mutation():
    tool = MutationTool()
    result = ToolExecutor([tool]).execute(call(arguments="[]"))
    assert not result.success
    assert result.metadata["execution"]["state"] == "NOT_STARTED"
    assert tool.calls == 0


def test_unknown_tools_have_conservative_effect():
    assert ToolSpec("unclassified", "test").effect == ToolEffect.UNKNOWN
