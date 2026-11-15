"""Durable batch tests use only an in-process synthetic candidate."""

from dataclasses import replace

from openjarvis.control.authorized_batch import (
    AuthorizedBatchStep,
    execute_authorized_batch,
)
from openjarvis.control.browser_dispatch import BrowserDispatchFacade
from openjarvis.control.browser_use_schema import _POLICIES, BrowserUseActionSpec
from openjarvis.control.oss_adapter import (
    AdapterMode,
    ControlSurface,
    DispatchResult,
    ObservationSnapshot,
    SafeEngineAdapter,
    make_authorized_action,
)
from openjarvis.core.execution import ExecutionState, MutationIntent
from openjarvis.tools.execution_journal import ExecutionJournal

KEY = b"synthetic-batch-key"
IDENTITY = {"session_id": "session", "element_index": 3}
ACTION = {"click": {"index": 3}}
OBSERVATION = ObservationSnapshot(
    ControlSurface.BROWSER,
    "observation",
    ({"target_id": "target", "identity": IDENTITY},),
    privacy="PUBLIC",
)


class Candidate:
    def __init__(self, fail_at=None):
        self.actions = []
        self.fail_at = fail_at

    def dispatch(self, authorized):
        self.actions.append(authorized.proposal.action_id)
        if authorized.proposal.action_id == self.fail_at:
            raise TimeoutError("response lost")
        return DispatchResult(True)


def host(candidate, session_id="session"):
    adapter = SafeEngineAdapter(
        candidate,
        surface=ControlSurface.BROWSER,
        mode=AdapterMode.ENFORCE,
        session_id=session_id,
        seal_key=KEY,
    )
    schema = [
        BrowserUseActionSpec(
            name,
            frozenset({"index", "text"}),
            frozenset({"index"}),
            {"properties": {"index": {}, "text": {}}, "required": ["index"]},
            mutation,
            target,
            (),
            "synthetic",
        )
        for name, (mutation, target) in _POLICIES.items()
    ]
    return BrowserDispatchFacade(schema, host=adapter, session_id=session_id)


def step(number, verify=lambda *_: True):
    proposal = host(Candidate()).propose(ACTION, OBSERVATION, action_id=str(number))
    intent = MutationIntent("execution", f"step-{number}", f"intent-{number}")
    auth = make_authorized_action(
        proposal, intent, session_id="session", nonce=f"nonce-{number}", key=KEY
    )
    return AuthorizedBatchStep(auth, ACTION, lambda: OBSERVATION, verify)


def authorize(journal, steps):
    for item in steps:
        journal.authorize_intent("scope", item.authorization.intent)


def test_preapproved_batch_records_each_verified_step(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    steps = [step(1), step(2)]
    candidate = Candidate()
    try:
        authorize(journal, steps)
        results = execute_authorized_batch(host(candidate), journal, "scope", steps)
        assert [r.state for r in results] == [ExecutionState.VERIFIED] * 2
        assert candidate.actions == ["1", "2"]
        assert journal.pending("scope") == []
        assert all(
            journal.semantic_intent("scope", item.authorization.intent)["status"]
            == "VERIFIED"
            for item in steps
        )
    finally:
        journal.close()


def test_invalid_seal_and_missing_authorization_stop_before_worker(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    candidate = Candidate()
    first, second = step(1), step(2)
    bad = replace(first, authorization=replace(first.authorization, seal="0" * 64))
    try:
        authorize(journal, [first, second])
        result = execute_authorized_batch(
            host(candidate), journal, "scope", [bad, second]
        )
        assert len(result) == 1 and result[0].state is ExecutionState.NOT_STARTED
        assert candidate.actions == []
        missing = step(3)
        result = execute_authorized_batch(host(candidate), journal, "scope", [missing])
        assert result[0].state is ExecutionState.NOT_STARTED
        assert candidate.actions == []
        private = replace(
            first, observe=lambda: replace(OBSERVATION, privacy="PRIVATE")
        )
        denied = execute_authorized_batch(host(candidate), journal, "scope", [private])
        assert denied[0].failure == "OBSERVATION_DENIED"
        assert candidate.actions == []
        altered = replace(second, action={"click": {"index": 4}})
        denied = execute_authorized_batch(host(candidate), journal, "scope", [altered])
        assert denied[0].state is ExecutionState.NOT_STARTED
        assert candidate.actions == []
    finally:
        journal.close()


def test_uncertain_result_stops_and_is_not_replayed_after_restart(tmp_path):
    path = tmp_path / "journal.db"
    journal = ExecutionJournal(path)
    candidate = Candidate(fail_at="1")
    steps = [step(1), step(2)]
    authorize(journal, steps)
    result = execute_authorized_batch(host(candidate), journal, "scope", steps)
    assert len(result) == 1 and result[0].state is ExecutionState.UNKNOWN_OUTCOME
    assert candidate.actions == ["1"]
    journal.close()
    reopened = ExecutionJournal(path)
    try:
        retry = execute_authorized_batch(host(candidate), reopened, "scope", steps)
        assert retry[0].state is ExecutionState.UNKNOWN_OUTCOME
        assert candidate.actions == ["1"]
    finally:
        reopened.close()


def test_crash_after_dispatch_gate_does_not_replay_on_restart(tmp_path):
    path = tmp_path / "crash.db"
    journal = ExecutionJournal(path)
    candidate = Candidate()
    item = step(1)
    authorize(journal, [item])
    claim = journal.reserve_intent(
        "scope", "computer_use_browser", "1", item.authorization.intent
    )
    assert journal.begin_dispatch(claim["token"])
    journal.close()
    reopened = ExecutionJournal(path)
    try:
        result = execute_authorized_batch(host(candidate), reopened, "scope", [item])
        assert result[0].state is ExecutionState.UNKNOWN_OUTCOME
        assert candidate.actions == []
    finally:
        reopened.close()


def test_cancellation_between_steps_prevents_second_dispatch(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    candidate = Candidate()
    first = step(1, verify=lambda *_: bool(journal.request_cancellation("scope")))
    steps = [first, step(2)]
    try:
        authorize(journal, steps)
        result = execute_authorized_batch(host(candidate), journal, "scope", steps)
        assert [r.state for r in result] == [
            ExecutionState.VERIFIED,
            ExecutionState.NOT_STARTED,
        ]
        assert candidate.actions == ["1"]
    finally:
        journal.close()


def test_fresh_observation_rejects_stale_second_target(tmp_path):
    journal = ExecutionJournal(tmp_path / "journal.db")
    candidate = Candidate()
    second = replace(
        step(2), observe=lambda: replace(OBSERVATION, observation_id="new")
    )
    steps = [step(1), second]
    try:
        authorize(journal, steps)
        results = execute_authorized_batch(host(candidate), journal, "scope", steps)
        assert results[0].state is ExecutionState.VERIFIED
        assert results[1].failure == "STALE_TARGET"
        assert candidate.actions == ["1"]
    finally:
        journal.close()
