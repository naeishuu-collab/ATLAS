"""Restart, concurrency and storage-failure tests for mutation quarantine."""

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import pytest

from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec
from openjarvis.tools.execution_journal import ExecutionJournal


class Tool(BaseTool):
    tool_id = "mutate"

    def __init__(self, fails=False):
        self.calls = 0
        self.fails = fails

    @property
    def spec(self):
        return ToolSpec(self.tool_id, "test")

    def execute(self, **params):
        self.calls += 1
        if self.fails:
            raise RuntimeError("response lost after mutation")
        return ToolResult(self.tool_id, "complete")


def execute(journal, tool, *, scope="task-one", identifier="one"):
    return ToolExecutor(
        [tool],
        execution_journal=journal,
        execution_scope=scope,
    ).execute(ToolCall(identifier, tool.tool_id, "{}"))


def test_unknown_outcome_survives_reopen_and_new_call_id(tmp_path):
    path = tmp_path / "journal.db"
    journal = ExecutionJournal(path)
    tool = Tool(fails=True)
    assert not execute(journal, tool).success
    assert journal.pending("task-one")[0]["state"] == "UNKNOWN_OUTCOME"
    journal.close()
    reopened = ExecutionJournal(path)
    try:
        result = execute(reopened, tool, identifier="different-id")
        assert not result.success
        assert result.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
        assert tool.calls == 1
    finally:
        reopened.close()


def test_crash_after_reservation_never_expires_or_replays(tmp_path):
    path = tmp_path / "journal.db"
    journal = ExecutionJournal(path)
    journal.reserve("task-one", "mutate", "crashed")
    journal.close()
    reopened = ExecutionJournal(path)
    try:
        tool = Tool()
        assert not execute(reopened, tool).success
        assert tool.calls == 0
    finally:
        reopened.close()


def test_two_connections_cannot_claim_same_scope_and_tool(tmp_path):
    first = ExecutionJournal(tmp_path / "journal.db")
    second = ExecutionJournal(tmp_path / "journal.db")
    try:
        with ThreadPoolExecutor(2) as pool:
            tokens = list(
                pool.map(
                    lambda j: j.reserve("task", "mutate", "call"),
                    [first, second],
                )
            )
        assert sum(token is not None for token in tokens) == 1
    finally:
        first.close()
        second.close()


@pytest.mark.parametrize("resolution", ["VERIFIED", "NOT_EXECUTED"])
def test_observation_and_stopped_worker_required(tmp_path, resolution):
    journal = ExecutionJournal(tmp_path / "journal.db")
    try:
        token = journal.reserve("task", "mutate", "one")
        with pytest.raises(ValueError, match="stopped worker"):
            journal.reconcile(token, resolution=resolution, evidence="observed")
        with pytest.raises(ValueError, match="evidence"):
            journal.reconcile(
                token, resolution=resolution, evidence="", worker_stopped=True
            )
        assert journal.reserve("task", "mutate", "two") is None
        journal.reconcile(
            token,
            resolution=resolution,
            evidence="state inspected",
            worker_stopped=True,
        )
        assert journal.reserve("task", "mutate", "three") is not None
    finally:
        journal.close()


def test_no_arguments_or_output_persisted(tmp_path):
    path = tmp_path / "journal.db"
    journal = ExecutionJournal(path)
    try:
        executor = ToolExecutor(
            [Tool(fails=True)], execution_journal=journal, execution_scope="task"
        )
        executor.execute(ToolCall("one", "mutate", '{"password":"private-canary"}'))
        rows = journal.pending("task")
        assert "private-canary" not in str(rows)
        assert not {"arguments", "content", "result"} & rows[0].keys()
    finally:
        journal.close()
    assert b"private-canary" not in path.read_bytes()


def test_success_releases_reservation_for_next_action(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    try:
        tool = Tool()
        assert execute(journal, tool).success
        assert execute(journal, tool, identifier="two").success
        assert journal.pending("task-one") == []
        assert tool.calls == 2
    finally:
        journal.close()


def test_storage_failure_blocks_before_dispatch():
    journal = MagicMock()
    journal.reserve.side_effect = OSError("disk unavailable")
    tool = Tool()
    result = execute(journal, tool)
    assert not result.success
    assert tool.calls == 0
    assert result.metadata["execution"]["state"] == "NOT_STARTED"


def test_checkpoint_failure_blocks_before_dispatch_without_unknown_outcome(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    tool = Tool()
    executor = ToolExecutor([tool], execution_journal=journal, execution_scope="task")

    def fail_executing_checkpoint(state, _result):
        if state == "EXECUTING":
            raise OSError("checkpoint unavailable")

    try:
        result = executor.execute(
            ToolCall("one", "mutate", "{}"),
            checkpoint_callback=fail_executing_checkpoint,
        )
        assert not result.success
        assert result.metadata["execution"]["state"] == "NOT_STARTED"
        assert journal.pending("task") == []
        assert tool.calls == 0
        assert execute(journal, tool, scope="task", identifier="retry").success
        assert tool.calls == 1
    finally:
        journal.close()


def test_completion_commit_failure_cannot_authorize_replay():
    journal = MagicMock()
    journal.reserve.return_value = "reservation"
    journal.finish.side_effect = OSError("disk unavailable")
    tool = Tool()
    executor = ToolExecutor([tool], execution_journal=journal, execution_scope="task")
    result = executor.execute(ToolCall("one", "mutate", "{}"))
    assert not result.success
    assert result.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
    assert not executor.execute(ToolCall("two", "mutate", "{}")).success
    assert tool.calls == 1


def test_journal_requires_stable_scope():
    with pytest.raises(ValueError, match="stable execution_scope"):
        ToolExecutor([], execution_journal=MagicMock())
