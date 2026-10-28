"""Trace copies must not retain raw sensitive-tool conversation payloads."""

import json
from dataclasses import asdict
from unittest.mock import MagicMock

import pytest

from openjarvis.agents.native_react import NativeReActAgent
from openjarvis.core.events import EventBus, EventType
from openjarvis.core.types import StepType
from openjarvis.tools.windows import WindowsActionTool
from openjarvis.traces.collector import TraceCollector
from openjarvis.traces.store import TraceStore


@pytest.mark.parametrize("canary", ["owned-canary-7e98", "日本語 α 🚀", "x"])
def test_native_react_trace_omits_sensitive_prose_preserving_live_action(
    tmp_path, canary
):
    session = MagicMock()
    session.act.return_value = {
        "outcome": "VERIFIED",
        "dispatch": "DISPATCHED",
        "verification": "VERIFIED",
        "failure": "NONE",
        "retryable": False,
        "identity": {"window": {"hwnd": 100}, "receiver": {"revision": 0}},
        "evidence": {"value_length": len(canary)},
    }
    engine = MagicMock(engine_id="owned-privacy-fixture")
    engine._publishes_events = False
    turn = 0

    def generate(messages, **kwargs):
        nonlocal turn
        turn += 1
        if turn == 1:
            data = {
                "action": "windows_action",
                "action_input": {
                    "action": "type_into",
                    "observation_id": "observed-1",
                    "target_id": "target-1",
                    "value": canary,
                },
            }
        else:
            assert canary in messages[-2].content
            data = {"final_answer": f"Recorded {canary}"}
        response = {
            "content": json.dumps(data, ensure_ascii=False),
            "model": "owned-fixture",
            "usage": {"total_tokens": 3},
            "finish_reason": "stop",
            "tool_results": [{"content": canary}],
            "content_blocks": [{"text": canary}],
        }
        if turn == 1:
            response["tool_calls"] = [
                {
                    "id": "call_sensitive",
                    "name": "windows_action",
                    "arguments": data["action_input"],
                }
            ]
        else:
            response["tool_calls"] = []
        return response

    engine.generate.side_effect = generate
    prompts = []
    bus = EventBus(record_history=True)
    agent = NativeReActAgent(
        engine,
        "owned-fixture",
        tools=[WindowsActionTool(session)],
        bus=bus,
        interactive=True,
        confirm_callback=lambda p: prompts.append(p) or True,
    )
    store = TraceStore(tmp_path / "trace.db")
    try:
        collector = TraceCollector(agent, bus=bus, store=store)
        result = collector.run(f"Type {canary} into the owned fixture")
        trace = collector.last_trace
        assert session.act.call_count == 1
        assert session.act.call_args.kwargs["value"] == canary
        assert canary in prompts[0] and canary in result.content
        assert canary in json.dumps(result.metadata["messages"], ensure_ascii=False)
        # Check prose payloads individually: a short secret can legitimately occur
        # in unrelated schema keys or identifiers; those must not be corrupted.
        assert trace.query == trace.result == "[REDACTED]"
        assert all(m["content"] == "[REDACTED]" for m in trace.messages)
        generated = [s for s in trace.steps if s.step_type == StepType.GENERATE]
        assert len(generated) == 2
        assert all(s.output["content"] == "[REDACTED]" for s in generated)
        assert all(
            s.output["tool_calls"] == s.output["content_blocks"] == []
            for s in generated
        )
        assert trace.total_tokens == 6
        action = next(s for s in trace.steps if s.step_type == StepType.TOOL_CALL)
        assert action.input["arguments"]["value"] == "[REDACTED]"
        assert action.input["arguments"]["observation_id"] == "observed-1"
        assert action.metadata["windows"]["identity"]["window"]["hwnd"] == 100
        assert action.metadata["execution"]["state"] == "VERIFIED"
        assert action.metadata["execution"]["call_id"]
        assert action.duration_seconds >= 0
        assert trace.metadata["raw_conversation_retained"] is False
        saved = store.get(trace.trace_id)
        assert asdict(saved) == asdict(trace)
        complete = [e for e in bus.history if e.event_type == EventType.TRACE_COMPLETE]
        assert len(complete) == 1 and complete[0].data["trace"] is trace
        if len(canary) > 1:
            assert canary not in json.dumps(asdict(saved), ensure_ascii=False)
            assert canary not in "\n".join(store._conn.iterdump())
        # This change protects TraceCollector/Store/TRACE_COMPLETE copies; raw
        # inference events and the live conversation are explicitly out of scope.
        assert any(
            canary in str(e.data.get("content", ""))
            for e in bus.history
            if e.event_type == EventType.INFERENCE_END
        )
    finally:
        store.close()
