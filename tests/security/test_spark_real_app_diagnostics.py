"""Non-physical checks for the Spark Real App failure diagnostic."""

from __future__ import annotations

import json
from dataclasses import dataclass

from openjarvis.agents._stubs import AgentResult
from openjarvis.core.events import EventBus, EventType
from openjarvis.core.types import ToolResult
from tests.security.test_windows_real_app import _spark_failure_diagnostic


@dataclass
class _App:
    values: dict

    def state(self):
        return dict(self.values)


@dataclass
class _Journal:
    rows: list[dict]

    def pending(self, scope: str):
        return list(self.rows)


def _bus(*events):
    bus = EventBus(record_history=True)
    for event_type, data in events:
        bus.publish(event_type, data)
    return bus


def _tool_result(
    *,
    call_id: str,
    state: str,
    success: bool,
    dispatch: str,
    outcome: str,
    verification: str,
    retryable: bool,
):
    windows = {
        "observation_id": "obs-diagnostic",
        "target_id": "target-diagnostic",
        "dispatch": dispatch,
        "outcome": outcome,
        "verification": verification,
        "retryable": retryable,
    }
    return ToolResult(
        "windows_action",
        json.dumps(windows),
        success=success,
        metadata={
            "arguments": {
                "action": "type_into",
                "observation_id": "obs-diagnostic",
                "target_id": "target-diagnostic",
            },
            "windows": windows,
            "execution": {
                "state": state,
                "failure": "NONE" if success else outcome,
                "retryable": retryable,
                "call_id": call_id,
            },
        },
    )


def _diagnostic(result, bus, app, journal):
    return _spark_failure_diagnostic(
        result,
        bus,
        app,
        journal,
        "diagnostic-scope",
        wall_time_seconds=0.01,
    )


def test_pre_dispatch_rejection_is_structured_without_physical_dispatch():
    result = AgentResult(
        "blocked",
        [
            _tool_result(
                call_id="reject-1",
                state="NOT_STARTED",
                success=False,
                dispatch="NOT_DISPATCHED",
                outcome="NOT_STARTED",
                verification="NOT_VERIFIED",
                retryable=False,
            )
        ],
        turns=2,
    )
    diagnostic = _diagnostic(
        result,
        _bus(
            (
                EventType.INFERENCE_END,
                {"content": "", "tool_calls": [{"id": "reject-1"}]},
            )
        ),
        _App({"text": "", "dispatch_count": 0}),
        _Journal([]),
    )
    item = diagnostic["tool_results"][0]
    assert item["mutation_state"] == "NOT_STARTED"
    assert item["dispatch"] == "NOT_DISPATCHED"
    assert item["retryable"] is False
    assert diagnostic["helper_state"]["dispatch_count"] == 0


def test_verified_action_then_final_answer_is_ordered_by_model_turn():
    result = AgentResult(
        "complete",
        [
            _tool_result(
                call_id="verified-1",
                state="VERIFIED",
                success=True,
                dispatch="DISPATCHED",
                outcome="VERIFIED",
                verification="VERIFIED",
                retryable=False,
            )
        ],
        turns=3,
        metadata={"messages": [{"role": "assistant", "content": "complete"}]},
    )
    diagnostic = _diagnostic(
        result,
        _bus(
            (EventType.INFERENCE_END, {"content": "", "tool_calls": [{"id": "o"}]}),
            (
                EventType.INFERENCE_END,
                {"content": "", "tool_calls": [{"id": "verified-1"}]},
            ),
            (EventType.INFERENCE_END, {"content": "complete", "tool_calls": []}),
        ),
        _App({"text": "canary", "dispatch_count": 1}),
        _Journal([]),
    )
    assert [item["response_type"] for item in diagnostic["model_turns"]] == [
        "native_tool_call",
        "native_tool_call",
        "text",
    ]
    assert diagnostic["tool_results"][0]["outcome"] == "VERIFIED"
    assert diagnostic["agent_result"]["max_turns_exceeded"] is False


def test_verified_action_on_last_turn_exposes_max_turns():
    result = AgentResult(
        "Maximum turns reached without a final answer.",
        [
            _tool_result(
                call_id="last-1",
                state="VERIFIED",
                success=True,
                dispatch="DISPATCHED",
                outcome="VERIFIED",
                verification="VERIFIED",
                retryable=False,
            )
        ],
        turns=2,
        metadata={"max_turns_exceeded": True, "messages": []},
    )
    diagnostic = _diagnostic(
        result,
        _bus(
            (EventType.INFERENCE_END, {"content": "", "tool_calls": [{"id": "o"}]}),
            (
                EventType.INFERENCE_END,
                {"content": "", "tool_calls": [{"id": "last-1"}]},
            ),
        ),
        _App({"text": "canary", "dispatch_count": 1}),
        _Journal([]),
    )
    assert diagnostic["tool_results"][0]["outcome"] == "VERIFIED"
    assert diagnostic["agent_result"]["terminal_reason"] == "MAX_TURNS_EXCEEDED"
    assert diagnostic["agent_result"]["max_turns_exceeded"] is True
    assert len(diagnostic["model_turns"]) == 2


def test_new_nonretryable_proposal_ids_are_distinguishable():
    results = [
        _tool_result(
            call_id="reject-1",
            state="NOT_STARTED",
            success=False,
            dispatch="NOT_DISPATCHED",
            outcome="NOT_STARTED",
            verification="NOT_VERIFIED",
            retryable=False,
        ),
        _tool_result(
            call_id="reject-2",
            state="NOT_STARTED",
            success=False,
            dispatch="NOT_DISPATCHED",
            outcome="NOT_STARTED",
            verification="NOT_VERIFIED",
            retryable=False,
        ),
    ]
    diagnostic = _diagnostic(
        AgentResult("stopped", results, turns=3),
        _bus(
            (
                EventType.INFERENCE_END,
                {"content": "", "tool_calls": [{"id": "reject-1"}]},
            ),
            (
                EventType.INFERENCE_END,
                {"content": "", "tool_calls": [{"id": "reject-2"}]},
            ),
        ),
        _App({"dispatch_count": 0, "replay_count": 0}),
        _Journal([]),
    )
    assert [item["call_id"] for item in diagnostic["tool_results"]] == [
        "reject-1",
        "reject-2",
    ]
    assert diagnostic["helper_state"]["dispatch_count"] == 0
    assert diagnostic["helper_state"]["replay_count"] == 0


def test_unknown_outcome_keeps_pending_journal_and_replay_evidence():
    result = AgentResult(
        "recovery required",
        [
            _tool_result(
                call_id="unknown-1",
                state="UNKNOWN_OUTCOME",
                success=False,
                dispatch="POSSIBLE",
                outcome="UNKNOWN_OUTCOME",
                verification="NOT_VERIFIED",
                retryable=False,
            )
        ],
        turns=2,
    )
    diagnostic = _diagnostic(
        result,
        _bus(
            (
                EventType.INFERENCE_END,
                {"content": "", "tool_calls": [{"id": "unknown-1"}]},
            )
        ),
        _App({"dispatch_count": 1, "replay_count": 0}),
        _Journal([{"call_id": "unknown-1", "state": "UNKNOWN_OUTCOME"}]),
    )
    assert diagnostic["tool_results"][0]["mutation_state"] == "UNKNOWN_OUTCOME"
    assert diagnostic["journal_pending"] == [
        {"call_id": "unknown-1", "state": "UNKNOWN_OUTCOME"}
    ]
    assert diagnostic["helper_state"]["dispatch_count"] == 1
    assert diagnostic["helper_state"]["replay_count"] == 0
