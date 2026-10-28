"""Non-physical semantic exactly-once tests for controller-owned intents."""

from __future__ import annotations

import json

from openjarvis.core.execution import ExecutionState, MutationIntent, ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec
from openjarvis.tools.execution_journal import ExecutionJournal


class CountingMutation(BaseTool):
    tool_id = "counting_mutation"

    def __init__(self, *, unknown: bool = False) -> None:
        self.calls = 0
        self.unknown = unknown

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            self.tool_id,
            "test-only mutation",
            effect=ToolEffect.MUTATING,
        )

    def execute(self, **params):
        self.calls += 1
        if self.unknown:
            raise RuntimeError("acknowledgement lost")
        return ToolResult(
            self.tool_id,
            json.dumps({"verified": True}),
            execution_state=ExecutionState.VERIFIED,
        )


class ReadOnlyTool(BaseTool):
    tool_id = "read_only"

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(self.tool_id, "test-only read", effect=ToolEffect.READ_ONLY)

    def execute(self, **params):
        return ToolResult(self.tool_id, "read")


def _intent(step: str = "step-1", intent: str = "intent-1") -> MutationIntent:
    return MutationIntent("execution-1", step, intent)


def _executor(journal, tool, scope="semantic-scope"):
    return ToolExecutor(
        [tool],
        execution_journal=journal,
        execution_scope=scope,
        require_mutation_intent=True,
    )


def _authorize(journal, intent, scope="semantic-scope"):
    journal.authorize_intent(scope, intent)


def _call(call_id: str) -> ToolCall:
    return ToolCall(call_id, "counting_mutation", '{"same":true}')


def test_t1_duplicate_proposal_after_verified_is_not_dispatched(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    tool = CountingMutation()
    intent = _intent()
    try:
        _authorize(journal, intent)
        executor = _executor(journal, tool)
        first = executor.execute(_call("call-a"), mutation_context=intent)
        second = executor.execute(_call("call-b"), mutation_context=intent)
        assert first.metadata["execution"]["state"] == "VERIFIED"
        assert second.metadata["execution"]["state"] == "NOT_STARTED"
        assert second.metadata["semantic"]["failure"] == "STEP_ALREADY_VERIFIED"
        assert second.metadata["request_dispatch"] == "NOT_DISPATCHED"
        assert tool.calls == 1
    finally:
        journal.close()


def test_t2_distinct_steps_are_both_authorized(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    tool = CountingMutation()
    first_intent = _intent("step-1", "intent-1")
    second_intent = _intent("step-2", "intent-2")
    try:
        _authorize(journal, first_intent)
        _authorize(journal, second_intent)
        executor = _executor(journal, tool)
        assert executor.execute(_call("call-a"), mutation_context=first_intent).success
        assert executor.execute(_call("call-b"), mutation_context=second_intent).success
        assert tool.calls == 2
    finally:
        journal.close()


def test_t3_identical_arguments_are_allowed_for_distinct_steps(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    tool = CountingMutation()
    first_intent = _intent("step-1", "intent-1")
    second_intent = _intent("step-2", "intent-2")
    try:
        _authorize(journal, first_intent)
        _authorize(journal, second_intent)
        executor = _executor(journal, tool)
        first = executor.execute(_call("same-args-a"), mutation_context=first_intent)
        second = executor.execute(_call("same-args-b"), mutation_context=second_intent)
        assert first.success and second.success
        assert tool.calls == 2
    finally:
        journal.close()


def test_t4_verified_intent_survives_journal_restart(tmp_path):
    path = tmp_path / "journal.db"
    tool = CountingMutation()
    intent = _intent()
    journal = ExecutionJournal(path)
    _authorize(journal, intent)
    assert _executor(journal, tool).execute(
        _call("before-restart"), mutation_context=intent
    ).success
    journal.close()

    reopened = ExecutionJournal(path)
    try:
        result = _executor(reopened, tool).execute(
            _call("after-restart"), mutation_context=intent
        )
        assert not result.success
        assert result.metadata["semantic"]["failure"] == "STEP_ALREADY_VERIFIED"
        assert result.metadata["execution"]["state"] == "NOT_STARTED"
        assert tool.calls == 1
    finally:
        reopened.close()


def test_t5_unknown_outcome_blocks_same_intent(tmp_path):
    path = tmp_path / "journal.db"
    tool = CountingMutation(unknown=True)
    intent = _intent()
    journal = ExecutionJournal(path)
    _authorize(journal, intent)
    first = _executor(journal, tool).execute(
        _call("unknown-a"), mutation_context=intent
    )
    assert first.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
    journal.close()

    reopened = ExecutionJournal(path)
    try:
        second = _executor(reopened, tool).execute(
            _call("unknown-b"), mutation_context=intent
        )
        assert not second.success
        assert second.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
        assert second.metadata["semantic"]["state"] == "UNKNOWN_OUTCOME"
        assert reopened.pending("semantic-scope")
        assert tool.calls == 1
    finally:
        reopened.close()


def test_t6_not_dispatched_intent_requires_new_authorization(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    tool = CountingMutation()
    old_intent = _intent("step-old", "intent-old")
    new_intent = _intent("step-new", "intent-new")
    try:
        _authorize(journal, old_intent)
        executor = _executor(journal, tool)

        def fail_prepared(state, _result):
            if state == "PREPARED":
                raise OSError("checkpoint unavailable")

        old = executor.execute(
            _call("old-call"),
            checkpoint_callback=fail_prepared,
            mutation_context=old_intent,
        )
        assert old.metadata["execution"]["state"] == "NOT_STARTED"
        assert tool.calls == 0
        assert journal.semantic_intent("semantic-scope", old_intent)["status"] == (
            "NOT_EXECUTED"
        )

        _authorize(journal, new_intent)
        fresh = _executor(journal, tool).execute(
            _call("new-call"), mutation_context=new_intent
        )
        assert fresh.success
        assert tool.calls == 1
    finally:
        journal.close()


def test_t7_final_answer_failure_does_not_reopen_verified_intent(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    tool = CountingMutation()
    intent = _intent()
    try:
        _authorize(journal, intent)
        executor = _executor(journal, tool)
        verified = executor.execute(_call("verified"), mutation_context=intent)
        assert verified.metadata["execution"]["state"] == "VERIFIED"
        # A missing final prose answer is outside the mutation gate.  A later
        # provider call still cannot reopen the completed intent.
        later = executor.execute(
            _call("after-final-answer-failure"), mutation_context=intent
        )
        assert not later.success
        assert later.metadata["semantic"]["failure"] == "STEP_ALREADY_VERIFIED"
        assert tool.calls == 1
    finally:
        journal.close()


def test_t8_provider_call_id_instability_does_not_create_new_step(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    tool = CountingMutation()
    intent = _intent()
    try:
        _authorize(journal, intent)
        executor = _executor(journal, tool)
        assert executor.execute(_call("provider-a"), mutation_context=intent).success
        blocked = executor.execute(_call("provider-b"), mutation_context=intent)
        assert blocked.metadata["semantic"]["failure"] == "STEP_ALREADY_VERIFIED"
        assert tool.calls == 1
    finally:
        journal.close()


def test_t9_missing_trusted_intent_blocks_mutation_but_not_read(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    mutation = CountingMutation()
    try:
        executor = _executor(journal, mutation)
        blocked = executor.execute(_call("without-intent"))
        assert not blocked.success
        assert blocked.metadata["execution"]["state"] == "NOT_STARTED"
        assert blocked.metadata["semantic"]["failure"] == "MISSING_TRUSTED_INTENT"
        assert mutation.calls == 0

        reader = ToolExecutor(
            [ReadOnlyTool()],
            execution_journal=journal,
            execution_scope="semantic-scope",
            require_mutation_intent=True,
        )
        assert reader.execute(ToolCall("read", "read_only", "{}")).success
    finally:
        journal.close()


def test_t10_semantic_journal_disagreement_fails_closed(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    tool = CountingMutation()
    intent = _intent()
    scope = "semantic-scope"
    try:
        _authorize(journal, intent, scope)
        reservation = journal.reserve_intent(scope, tool.tool_id, "call-a", intent)
        token = reservation["token"]
        with journal._lock, journal._conn:
            journal._conn.execute(
                "UPDATE semantic_mutation_intents SET status='VERIFIED' "
                "WHERE token=?",
                (token,),
            )
        result = _executor(journal, tool, scope).execute(
            _call("call-b"), mutation_context=intent
        )
        assert not result.success
        assert result.metadata["semantic"]["failure"] == (
            "SEMANTIC_JOURNAL_INCONSISTENCY"
        )
        assert result.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
        assert tool.calls == 0
    finally:
        journal.close()
