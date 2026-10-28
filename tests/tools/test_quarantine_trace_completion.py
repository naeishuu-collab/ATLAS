"""Actual executor/trace events with simulated mutation endpoints, no GUI E2E."""

import json
from unittest.mock import MagicMock

import pytest

from openjarvis.core.events import EventBus, EventType
from openjarvis.core.types import ToolCall
from openjarvis.tools._stubs import ToolExecutor
from openjarvis.tools.execution_journal import ExecutionJournal
from openjarvis.tools.windows import WindowsActionTool
from openjarvis.traces.collector import TraceCollector


@pytest.mark.parametrize("guard", ["memory", "durable", "journal_unavailable"])
def test_started_quarantine_rejection_completes_trace_without_dispatch(tmp_path, guard):
    endpoint = MagicMock()
    endpoint.act.return_value = {
        "outcome": "UNKNOWN_OUTCOME",
        "dispatch": "POSSIBLE",
        "verification": "NOT_VERIFIED",
        "failure": "UNKNOWN_OUTCOME",
        "retryable": False,
    }
    tool = WindowsActionTool(endpoint)
    bus = EventBus(record_history=True)
    collector = TraceCollector(MagicMock(), bus=bus)
    handlers = collector._subscribe()
    journal = None
    current = []
    lock_available = []

    def check_end_is_outside_mutation_lock(event):
        available = current[0]._mutation_lock.acquire(blocking=False)
        lock_available.append(available)
        if available:
            current[0]._mutation_lock.release()

    bus.subscribe(EventType.TOOL_CALL_END, check_end_is_outside_mutation_lock)

    def executor(active_journal=None):
        instance = ToolExecutor(
            [tool],
            bus=bus,
            interactive=True,
            confirm_callback=lambda *_: True,
            execution_journal=active_journal,
            execution_scope="owned-trace",
        )
        current[:] = [instance]
        return instance

    def call(cid, oid, tid):
        return ToolCall(
            cid,
            "windows_action",
            json.dumps(
                {
                    "action": "type_into",
                    "observation_id": oid,
                    "target_id": tid,
                    "value": "owned-sensitive-canary",
                }
            ),
        )

    try:
        if guard == "journal_unavailable":
            failed_journal = MagicMock()
            failed_journal.reserve.side_effect = OSError("owned journal unavailable")
            active = executor(failed_journal)
        else:
            if guard == "durable":
                journal = ExecutionJournal(tmp_path / "journal.db")
            active = executor(journal)
            first = active.execute(call("original", "observed-1", "target-1"))
            assert first.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
            assert endpoint.act.call_count == 1
            if guard == "durable":
                journal.close()
                journal = ExecutionJournal(tmp_path / "journal.db")
                active = executor(journal)

        blocked = active.execute(
            call("blocked-new", "fresh-observed-2", "fresh-target-2")
        )
        expected_calls = 0 if guard == "journal_unavailable" else 1
        assert endpoint.act.call_count == expected_calls
        assert not blocked.success
        assert blocked.metadata["execution"]["state"] == (
            "NOT_STARTED" if guard == "journal_unavailable" else "UNKNOWN_OUTCOME"
        )
        assert blocked.metadata["execution"]["retryable"] is False
        starts = [e for e in bus.history if e.event_type == EventType.TOOL_CALL_START]
        ends = [e for e in bus.history if e.event_type == EventType.TOOL_CALL_END]
        assert [e.data["call_id"] for e in starts] == [e.data["call_id"] for e in ends]
        assert len(ends) == expected_calls + 1
        assert all(lock_available)
        assert len(collector._current_steps) == len(ends)
        step = collector._current_steps[-1]
        assert step.input["arguments"]["observation_id"] == "fresh-observed-2"
        assert step.input["arguments"]["target_id"] == "fresh-target-2"
        assert step.input["arguments"]["value"] == "[REDACTED]"
        assert step.metadata["request_call_id"] == "blocked-new"
        assert step.metadata["request_dispatch"] == "NOT_DISPATCHED"
        assert step.metadata["execution"] == blocked.metadata["execution"]
        assert step.duration_seconds == blocked.latency_seconds >= 0
        assert "owned-sensitive-canary" not in json.dumps(ends[-1].data)
        if journal is not None:
            assert len(journal.pending("owned-trace")) == 1
    finally:
        collector._unsubscribe(handlers)
        if journal is not None:
            journal.close()
