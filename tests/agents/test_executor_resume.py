"""Production AgentExecutor checkpoint and restart safety tests."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from unittest.mock import patch

import pytest

from openjarvis.agents.errors import RetryableError
from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.orchestrator import OrchestratorAgent
from openjarvis.core.events import EventBus
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import AgentRegistry, ToolRegistry
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec
from openjarvis.tools.file_write import FileWriteTool
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem


class _ResumeReadTool(BaseTool):
    tool_id = "resume_read"
    calls = 0

    @property
    def spec(self):
        return ToolSpec(
            self.tool_id, "read a restart test fixture", effect=ToolEffect.READ_ONLY
        )

    def execute(self, **params):
        type(self).calls += 1
        return ToolResult(
            self.tool_id, "read-result", execution_state=ExecutionState.EXECUTED
        )


class _ResumeMutationTool(BaseTool):
    tool_id = "resume_mutation"
    calls = 0
    uncertain = False

    @property
    def spec(self):
        return ToolSpec(
            self.tool_id, "mutate a restart test fixture", effect=ToolEffect.MUTATING
        )

    def execute(self, **params):
        type(self).calls += 1
        if type(self).uncertain:
            raise RuntimeError("response lost after physical mutation")
        return ToolResult(
            self.tool_id,
            "mutation-verified",
            execution_state=ExecutionState.VERIFIED,
        )


class _WindowsCheckpointTool(BaseTool):
    tool_id = "windows_action"
    calls = 0

    @property
    def spec(self):
        return ToolSpec(
            self.tool_id,
            "fixture action",
            parameters={
                "type": "object",
                "properties": {
                    "action": {"type": "string"},
                    "observation_id": {"type": "string"},
                    "target_id": {"type": "string"},
                },
                "additionalProperties": False,
            },
            effect=ToolEffect.MUTATING,
        )

    def execute(self, action="click", observation_id="", target_id="", **params):
        type(self).calls += 1
        result = {
            "action": action,
            "observation_id": observation_id,
            "target_id": target_id,
            "outcome": "VERIFIED",
            "dispatch": "DISPATCHED",
            "verification": "VERIFIED",
        }
        return ToolResult(
            self.tool_id,
            json.dumps(result),
            execution_state=ExecutionState.VERIFIED,
        )


def _register(tool: type[BaseTool]) -> None:
    AgentRegistry.register_value("orchestrator", OrchestratorAgent)
    ToolRegistry.register_value(tool.tool_id, tool)


def _new_agent(manager: AgentManager, tool: type[BaseTool]) -> dict:
    _register(tool)
    return manager.create_agent(
        "resume-test",
        agent_type="orchestrator",
        config={
            "model": "fake-model",
            "instruction": "Continue safely from the checkpoint.",
            "tools": [tool.tool_id],
        },
    )


def _execute(manager: AgentManager, agent_id: str, engine: FakeEngine) -> None:
    executor = AgentExecutor(manager, EventBus(), system=FakeSystem(engine))
    executor.execute_tick(agent_id)


def _restart_after_checkpoint(manager: AgentManager, agent_id: str) -> str:
    checkpoint = manager.get_latest_checkpoint(agent_id)
    assert checkpoint is not None
    conversation = dict(checkpoint["conversation_state"])
    conversation["lifecycle"] = "RUNNING"
    manager.save_checkpoint(
        agent_id,
        checkpoint["tick_id"],
        conversation,
        checkpoint["tool_state"],
    )
    manager.start_tick(agent_id)
    return manager._db_path


def test_restart_resumes_after_completed_read_without_reexecuting(tmp_path):
    _ResumeReadTool.calls = 0
    db_path = str(tmp_path / "read-resume.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, _ResumeReadTool)
    first_engine = FakeEngine(
        [
            {
                "tool_calls": [
                    {
                        "id": "read-call",
                        "name": _ResumeReadTool.tool_id,
                        "arguments": "{}",
                    }
                ]
            },
            {"content": "read step complete"},
        ]
    )
    _execute(manager, agent["id"], first_engine)
    _restart_after_checkpoint(manager, agent["id"])
    manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    resumed_engine = FakeEngine([{"content": "goal complete"}])
    try:
        _execute(restarted, agent["id"], resumed_engine)
        assert _ResumeReadTool.calls == 1
        assert restarted.get_agent(agent["id"])["total_runs"] == 2
        assert any(
            message.role.value == "tool" and message.content == "read-result"
            for message in resumed_engine.last_messages
        )
        checkpoint = restarted.get_latest_checkpoint(agent["id"])
        assert checkpoint["tool_state"]["recovery_history"][-1]["event"] == "RESUMED"
    finally:
        restarted.close()


def _write_resume_artifact(manager: AgentManager, agent_id: str, path: str) -> None:
    _execute(
        manager,
        agent_id,
        FakeEngine(
            [
                {
                    "tool_calls": [
                        {
                            "id": "artifact-call",
                            "name": "file_write",
                            "arguments": json.dumps(
                                {"path": path, "content": "verified artifact"}
                            ),
                        }
                    ]
                },
                {"content": "artifact task complete"},
            ]
        ),
    )


def test_restart_restores_artifact_and_continues_with_next_tool_step(
    tmp_path, monkeypatch
):
    db_path = str(tmp_path / "artifact-resume.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, FileWriteTool)
    target = (tmp_path / "report.txt").resolve()
    resumed_target = (tmp_path / "summary.txt").resolve()
    content = "verified artifact"
    resumed_content = "written after restart"
    calls = 0
    original_execute = FileWriteTool.execute

    def counted_execute(tool, **params):
        nonlocal calls
        calls += 1
        return original_execute(tool, **params)

    monkeypatch.setattr(FileWriteTool, "execute", counted_execute)
    _write_resume_artifact(manager, agent["id"], str(target))
    assert target.read_text(encoding="utf-8") == content
    checkpoint = manager.get_latest_checkpoint(agent["id"])
    assert checkpoint["tool_state"]["completed_steps"][-1]["artifacts"] == [
        {
            "type": "file",
            "path": str(target),
            "size_bytes": len(content.encode("utf-8")),
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        }
    ]
    _restart_after_checkpoint(manager, agent["id"])
    manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    resumed_engine = FakeEngine(
        [
            {
                "tool_calls": [
                    {
                        "id": "post-restart-call",
                        "name": "file_write",
                        "arguments": json.dumps(
                            {"path": str(resumed_target), "content": resumed_content}
                        ),
                    }
                ]
            },
            {"content": "artifact task complete"},
        ]
    )
    try:
        AgentExecutor(
            restarted,
            EventBus(),
            system=FakeSystem(FakeEngine([])),
        ).advance_plan_step(agent["id"], step_id="post-restart-step")
        _execute(restarted, agent["id"], resumed_engine)
        inventories = [
            message
            for message in resumed_engine.last_messages
            if message.name == "_astra_artifact_inventory"
        ]
        assert len(inventories) == 1
        inventory = json.loads(inventories[0].content.split("\n", 1)[1])
        assert inventory == [
            {
                "tool": "file_write",
                "call_id": "artifact-call",
                "type": "file",
                "path": str(target),
                "size_bytes": len(content.encode("utf-8")),
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            }
        ]
        assert resumed_engine.call_count == 2
        assert calls == 2
        assert target.read_text(encoding="utf-8") == content
        assert resumed_target.read_text(encoding="utf-8") == resumed_content
        resumed_checkpoint = restarted.get_latest_checkpoint(agent["id"])
        assert resumed_checkpoint["conversation_state"]["lifecycle"] == "COMPLETED"
        assert {
            step["call_id"]
            for step in resumed_checkpoint["tool_state"]["completed_steps"]
            if step.get("artifacts")
        } == {"artifact-call", "post-restart-call"}
    finally:
        restarted.close()


def test_corrupt_artifact_checkpoint_fails_closed_without_replay(tmp_path, monkeypatch):
    db_path = str(tmp_path / "corrupt-artifact.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, FileWriteTool)
    target = (tmp_path / "report.txt").resolve()
    calls = 0
    original_execute = FileWriteTool.execute

    def counted_execute(tool, **params):
        nonlocal calls
        calls += 1
        return original_execute(tool, **params)

    monkeypatch.setattr(FileWriteTool, "execute", counted_execute)
    _write_resume_artifact(manager, agent["id"], str(target))
    assert target.read_bytes() == b"verified artifact"
    _restart_after_checkpoint(manager, agent["id"])
    checkpoint = manager.get_latest_checkpoint(agent["id"])
    conversation = dict(checkpoint["conversation_state"])
    conversation["lifecycle"] = "RUNNING"
    tool_state = dict(checkpoint["tool_state"])
    completed = list(tool_state["completed_steps"])
    completed[-1] = {**completed[-1], "artifacts": [{"path": "untrusted"}]}
    tool_state["completed_steps"] = completed
    manager.save_checkpoint(
        agent["id"], checkpoint["tick_id"], conversation, tool_state
    )
    manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    no_resume_engine = FakeEngine([{"content": "must not run"}])
    try:
        _execute(restarted, agent["id"], no_resume_engine)
        assert no_resume_engine.call_count == 0
        assert calls == 1
        assert target.read_bytes() == b"verified artifact"
        assert restarted.get_agent(agent["id"])["status"] == "needs_attention"
        assert (
            restarted.get_latest_checkpoint(agent["id"])["conversation_state"][
                "lifecycle"
            ]
            == "RECOVERY_REQUIRED"
        )
    finally:
        restarted.close()


def test_verified_mutation_is_not_dispatched_again_after_restart(tmp_path):
    _ResumeMutationTool.calls = 0
    _ResumeMutationTool.uncertain = False
    db_path = str(tmp_path / "verified-resume.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, _ResumeMutationTool)
    _execute(
        manager,
        agent["id"],
        FakeEngine(
            [
                {
                    "tool_calls": [
                        {
                            "id": "verified-call",
                            "name": _ResumeMutationTool.tool_id,
                            "arguments": "{}",
                        }
                    ]
                },
                {"content": "mutation verified"},
            ]
        ),
    )
    _restart_after_checkpoint(manager, agent["id"])
    manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    try:
        _execute(restarted, agent["id"], FakeEngine([{"content": "continue"}]))
        assert _ResumeMutationTool.calls == 1
        assert restarted.execution_journal.pending(agent["id"]) == []
    finally:
        restarted.close()


def test_unknown_mutation_restarts_into_recovery_without_replay(tmp_path):
    _ResumeMutationTool.calls = 0
    _ResumeMutationTool.uncertain = True
    db_path = str(tmp_path / "unknown-resume.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, _ResumeMutationTool)
    _execute(
        manager,
        agent["id"],
        FakeEngine(
            [
                {
                    "tool_calls": [
                        {
                            "id": "unknown-call",
                            "name": _ResumeMutationTool.tool_id,
                            "arguments": "{}",
                        }
                    ]
                }
            ]
        ),
    )
    assert manager.get_agent(agent["id"])["status"] == "needs_attention"
    manager.start_tick(agent["id"])
    manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    engine = FakeEngine([{"content": "must not run"}])
    try:
        _execute(restarted, agent["id"], engine)
        assert _ResumeMutationTool.calls == 1
        assert engine.call_count == 0
        assert restarted.execution_journal.pending(agent["id"])[0]["state"] == (
            "UNKNOWN_OUTCOME"
        )
        assert restarted.get_latest_checkpoint(agent["id"])["tool_state"]["recovery"][
            "required"
        ]
        reservation = restarted.execution_journal.pending(agent["id"])[0]
        restarted.execution_journal.reconcile(
            reservation["token"],
            resolution="NOT_EXECUTED",
            evidence="independent state observation: requested state absent",
            worker_stopped=True,
        )
        restarted.recover_agent(agent["id"])
        _execute(restarted, agent["id"], FakeEngine([{"content": "replanned safely"}]))
        assert _ResumeMutationTool.calls == 1
        assert restarted.get_agent(agent["id"])["status"] == "idle"
        events = [
            item["event"]
            for item in restarted.get_latest_checkpoint(agent["id"])["tool_state"][
                "recovery_history"
            ]
        ]
        assert "RECONCILED" in events
    finally:
        restarted.close()
        _ResumeMutationTool.uncertain = False


def test_executing_mutation_interruption_is_not_assumed_unstarted(tmp_path):
    _ResumeMutationTool.calls = 0
    db_path = str(tmp_path / "executing-resume.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, _ResumeMutationTool)
    tick_id = "interrupted-executing"
    manager.save_checkpoint(
        agent["id"],
        tick_id,
        {
            "schema_version": 1,
            "tick_id": tick_id,
            "lifecycle": "RUNNING",
            "resumable": True,
            "messages": [{"role": "user", "content": "continue"}],
        },
        {
            "schema_version": 1,
            "active_step": {
                "call_id": "executing-call",
                "tool": _ResumeMutationTool.tool_id,
                "effect": "MUTATING",
                "state": "EXECUTING",
            },
            "completed_steps": [],
        },
    )
    token = manager.execution_journal.reserve(
        agent["id"], _ResumeMutationTool.tool_id, "executing-call"
    )
    assert token is not None
    assert manager.execution_journal.begin_dispatch(token)
    manager.start_tick(agent["id"])
    manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    engine = FakeEngine([{"content": "must not replay"}])
    try:
        _execute(restarted, agent["id"], engine)
        assert engine.call_count == 0
        assert _ResumeMutationTool.calls == 0
        assert restarted.get_agent(agent["id"])["status"] == "needs_attention"
        assert restarted.execution_journal.pending(agent["id"])[0]["state"] == (
            "EXECUTING"
        )
    finally:
        restarted.close()


def test_prepared_mutation_is_reconciled_as_not_dispatched(tmp_path):
    _ResumeMutationTool.calls = 0
    db_path = str(tmp_path / "prepared-resume.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, _ResumeMutationTool)
    tick_id = "interrupted-prepared"
    manager.save_checkpoint(
        agent["id"],
        tick_id,
        {
            "schema_version": 1,
            "tick_id": tick_id,
            "lifecycle": "RUNNING",
            "resumable": True,
            "messages": [{"role": "user", "content": "continue"}],
        },
        {
            "schema_version": 1,
            "active_step": {
                "call_id": "prepared-call",
                "tool": _ResumeMutationTool.tool_id,
                "effect": "MUTATING",
                "state": "PREPARED",
            },
            "completed_steps": [],
        },
    )
    manager.execution_journal.reserve(
        agent["id"], _ResumeMutationTool.tool_id, "prepared-call"
    )
    manager.start_tick(agent["id"])
    manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    try:
        _execute(restarted, agent["id"], FakeEngine([{"content": "safe continuation"}]))
        record = restarted.execution_journal.reconciliation(
            agent["id"], _ResumeMutationTool.tool_id, "prepared-call"
        )
        assert record["resolution"] == "NOT_EXECUTED"
        assert _ResumeMutationTool.calls == 0
        assert restarted.get_agent(agent["id"])["status"] == "idle"
    finally:
        restarted.close()


def test_verified_checkpoint_reconciles_stranded_journal_reservation(tmp_path):
    _ResumeMutationTool.calls = 0
    db_path = str(tmp_path / "verified-stranded.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, _ResumeMutationTool)
    tick_id = "verified-before-journal-finish"
    call_id = "verified-stranded-call"
    tool = _ResumeMutationTool.tool_id
    manager.save_checkpoint(
        agent["id"],
        tick_id,
        {
            "schema_version": 1,
            "tick_id": tick_id,
            "lifecycle": "RUNNING",
            "resumable": True,
            "messages": [
                {"role": "user", "content": "complete the task"},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{"id": call_id, "name": tool, "arguments": "{}"}],
                },
                {
                    "role": "tool",
                    "content": "verified output",
                    "tool_call_id": call_id,
                    "name": tool,
                },
            ],
        },
        {
            "schema_version": 1,
            "active_step": {
                "call_id": call_id,
                "tool": tool,
                "effect": "MUTATING",
                "state": "VERIFIED",
                "execution_state": "VERIFIED",
            },
            "completed_steps": [
                {
                    "call_id": call_id,
                    "tool": tool,
                    "effect": "MUTATING",
                    "state": "VERIFIED",
                    "execution_state": "VERIFIED",
                }
            ],
        },
    )
    manager.execution_journal.reserve(agent["id"], tool, call_id)
    manager.start_tick(agent["id"])
    manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    try:
        _execute(restarted, agent["id"], FakeEngine([{"content": "continued"}]))
        resolution = restarted.execution_journal.reconciliation(
            agent["id"], tool, call_id
        )
        assert resolution["resolution"] == "VERIFIED"
        assert restarted.execution_journal.pending(agent["id"]) == []
        assert _ResumeMutationTool.calls == 0
    finally:
        restarted.close()


def test_corrupt_checkpoint_fails_closed_before_agent_invocation(tmp_path):
    _ResumeMutationTool.calls = 0
    db_path = str(tmp_path / "corrupt-resume.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, _ResumeMutationTool)
    tick_id = "corrupt"
    manager.save_checkpoint(
        agent["id"],
        tick_id,
        {
            "schema_version": 1,
            "tick_id": tick_id,
            "lifecycle": "RUNNING",
            "resumable": True,
            "messages": [],
        },
        {
            "schema_version": 1,
            "active_step": {"state": "NOT_STARTED"},
            "completed_steps": [],
        },
    )
    manager.start_tick(agent["id"])
    manager.close()
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE agent_checkpoints SET conversation_state='not-json' "
            "WHERE tick_id=?",
            (tick_id,),
        )

    restarted = AgentManager(db_path, clear_stale_running=True)
    engine = FakeEngine([{"content": "must not run"}])
    try:
        _execute(restarted, agent["id"], engine)
        assert engine.call_count == 0
        assert _ResumeMutationTool.calls == 0
        assert restarted.get_agent(agent["id"])["status"] == "needs_attention"
        assert (
            restarted.get_latest_checkpoint(agent["id"])["conversation_state"][
                "lifecycle"
            ]
            == "RECOVERY_REQUIRED"
        )
    finally:
        restarted.close()


def test_stale_windows_target_ids_are_removed_before_restart_resume(tmp_path):
    _WindowsCheckpointTool.calls = 0
    db_path = str(tmp_path / "stale-target-resume.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, _WindowsCheckpointTool)
    _execute(
        manager,
        agent["id"],
        FakeEngine(
            [
                {
                    "tool_calls": [
                        {
                            "id": "windows-call",
                            "name": "windows_action",
                            "arguments": json.dumps(
                                {
                                    "action": "click",
                                    "observation_id": "old-observation-secret",
                                    "target_id": "old-target-secret",
                                }
                            ),
                        }
                    ]
                },
                {"content": "done"},
            ]
        ),
    )
    checkpoint = manager.get_latest_checkpoint(agent["id"])
    assert "old-observation-secret" not in str(checkpoint)
    assert "old-target-secret" not in str(checkpoint)
    _restart_after_checkpoint(manager, agent["id"])
    manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    engine = FakeEngine([{"content": "continue after fresh observation"}])
    try:
        _execute(restarted, agent["id"], engine)
        assert _WindowsCheckpointTool.calls == 1
        assert "old-observation-secret" not in str(engine.last_messages)
        assert "old-target-secret" not in str(engine.last_messages)
    finally:
        restarted.close()


def test_checkpoint_journal_mismatch_blocks_resume(tmp_path):
    _ResumeMutationTool.calls = 0
    db_path = str(tmp_path / "mismatch-resume.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, _ResumeMutationTool)
    tick_id = "mismatch"
    tool = _ResumeMutationTool.tool_id
    manager.save_checkpoint(
        agent["id"],
        tick_id,
        {
            "schema_version": 1,
            "tick_id": tick_id,
            "lifecycle": "RUNNING",
            "resumable": True,
            "messages": [
                {"role": "user", "content": "continue"},
                {
                    "role": "tool",
                    "content": "verified",
                    "tool_call_id": "checkpoint-call",
                    "name": tool,
                },
            ],
        },
        {
            "schema_version": 1,
            "active_step": {
                "call_id": "checkpoint-call",
                "tool": tool,
                "effect": "MUTATING",
                "state": "VERIFIED",
                "execution_state": "VERIFIED",
            },
            "completed_steps": [
                {
                    "call_id": "checkpoint-call",
                    "tool": tool,
                    "effect": "MUTATING",
                    "state": "VERIFIED",
                }
            ],
        },
    )
    manager.execution_journal.reserve(agent["id"], tool, "journal-call")
    manager.start_tick(agent["id"])
    manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    engine = FakeEngine([{"content": "must not continue"}])
    try:
        _execute(restarted, agent["id"], engine)
        assert engine.call_count == 0
        assert _ResumeMutationTool.calls == 0
        assert restarted.get_agent(agent["id"])["status"] == "needs_attention"
        assert restarted.execution_journal.pending(agent["id"])[0]["call_id"] == (
            "journal-call"
        )
    finally:
        restarted.close()


@pytest.mark.parametrize(
    ("retry_count", "expected_calls"),
    [(2, 1), (3, 0)],
)
def test_restart_preserves_bounded_retry_budget(tmp_path, retry_count, expected_calls):
    db_path = str(tmp_path / f"retry-resume-{retry_count}.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, _ResumeReadTool)
    tick_id = "interrupted-retries"
    manager.save_checkpoint(
        agent["id"],
        tick_id,
        {
            "schema_version": 1,
            "tick_id": tick_id,
            "lifecycle": "RUNNING",
            "resumable": True,
            "messages": [{"role": "user", "content": "continue safely"}],
        },
        {
            "schema_version": 1,
            "active_step": {"state": "NOT_STARTED"},
            "completed_steps": [],
            "retry_count": retry_count,
            "retry_history": [
                {
                    "attempt": attempt,
                    "state": (
                        "RUNNING"
                        if attempt == retry_count and retry_count == 3
                        else "FAILED"
                    ),
                    **(
                        {"error_type": "RetryableError", "retryable": True}
                        if attempt < retry_count or retry_count == 2
                        else {}
                    ),
                }
                for attempt in range(1, retry_count + 1)
            ],
        },
    )
    manager.start_tick(agent["id"])
    manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    executor = AgentExecutor(restarted, EventBus(), system=FakeSystem(FakeEngine([])))
    calls = 0

    def retryable_failure(_agent):
        nonlocal calls
        calls += 1
        raise RetryableError("fixture retry")

    try:
        with patch.object(executor, "_invoke_agent", side_effect=retryable_failure):
            with patch("openjarvis.agents.executor.retry_delay", return_value=0):
                executor.execute_tick(agent["id"])
        checkpoint = restarted.get_latest_checkpoint(agent["id"])
        assert calls == expected_calls
        assert checkpoint["tool_state"]["retry_count"] == 3
        assert checkpoint["conversation_state"]["lifecycle"] == "FAILED"
        if expected_calls:
            assert checkpoint["tool_state"]["retry_history"][-1]["state"] == ("FAILED")
        else:
            assert checkpoint["tool_state"]["retry_terminal"] == (
                "ATTEMPT_BUDGET_EXHAUSTED"
            )
    finally:
        restarted.close()


def test_inconsistent_retry_checkpoint_fails_closed(tmp_path):
    _ResumeReadTool.calls = 0
    db_path = str(tmp_path / "retry-corruption.db")
    manager = AgentManager(db_path)
    agent = _new_agent(manager, _ResumeReadTool)
    tick_id = "corrupt-retry-state"
    manager.save_checkpoint(
        agent["id"],
        tick_id,
        {
            "schema_version": 1,
            "tick_id": tick_id,
            "lifecycle": "RUNNING",
            "resumable": True,
            "messages": [{"role": "user", "content": "continue"}],
        },
        {
            "schema_version": 1,
            "active_step": {"state": "NOT_STARTED"},
            "completed_steps": [],
            "retry_count": 2,
            "retry_history": [{"attempt": 1, "state": "FAILED"}],
        },
    )
    manager.start_tick(agent["id"])
    manager.close()

    restarted = AgentManager(db_path, clear_stale_running=True)
    engine = FakeEngine([{"content": "must not run"}])
    try:
        _execute(restarted, agent["id"], engine)
        assert engine.call_count == 0
        assert _ResumeReadTool.calls == 0
        assert restarted.get_agent(agent["id"])["status"] == "needs_attention"
        recovery = restarted.get_latest_checkpoint(agent["id"])
        assert recovery["tool_state"]["recovery"]["required"]
        assert (
            "retry history is invalid" in recovery["tool_state"]["recovery"]["reason"]
        )
    finally:
        restarted.close()


def test_agent_retry_does_not_replay_verified_mutation(tmp_path):
    _ResumeMutationTool.calls = 0
    _ResumeMutationTool.uncertain = False
    manager = AgentManager(str(tmp_path / "retry-after-mutation.db"))
    agent = _new_agent(manager, _ResumeMutationTool)
    engine = FakeEngine(
        [
            {
                "tool_calls": [
                    {
                        "id": "verified-before-retry",
                        "name": _ResumeMutationTool.tool_id,
                        "arguments": "{}",
                    }
                ]
            },
            {"raise": RetryableError("transient model failure")},
            {"content": "goal completed after retry"},
        ]
    )
    executor = AgentExecutor(manager, EventBus(), system=FakeSystem(engine))
    try:
        with patch("openjarvis.agents.executor.retry_delay", return_value=0):
            executor.execute_tick(agent["id"])
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert _ResumeMutationTool.calls == 1
        assert engine.call_count == 3
        assert manager.get_agent(agent["id"])["status"] == "idle"
        # Per-tick attempt budget (docs/astra-run-report.md): the succeeded
        # tick closes its retry window while the verified mutation's tool
        # result stays in the conversation for a resume.
        assert checkpoint["tool_state"]["retry_count"] == 0
        assert checkpoint["tool_state"]["retry_history"] == []
        assert any(
            message["tool_call_id"] == "verified-before-retry"
            for message in checkpoint["conversation_state"]["messages"]
        )
    finally:
        manager.close()
