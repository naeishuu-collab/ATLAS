"""Deterministic tests for the host-mediated RLM LLM RPC boundary."""

from __future__ import annotations

import threading
import time
from copy import deepcopy
from typing import Any

import pytest

from openjarvis.agents.rlm import RLMAgent
from openjarvis.agents.rlm_repl import RLMRepl
from openjarvis.agents.rlm_rpc import (
    RPC_MAX_BATCH_ITEMS,
    RPC_MAX_BATCH_PROMPT_CHARS,
    RPC_MAX_FRAME_BYTES,
    RPC_MAX_QUERY_PROMPT_CHARS,
    RPC_MAX_RESPONSE_ITEM_CHARS,
    STATE_EXECUTED,
    STATE_FAILED,
    STATE_NOT_STARTED,
    STATE_UNKNOWN_OUTCOME,
    HostLLMBroker,
    RequestLedger,
    RLMRPCError,
    decode_frame,
    encode_frame,
    validate_request,
)
from openjarvis.agents.rlm_worker import RLMWorker
from openjarvis.security.capabilities import CapabilityPolicy

SESSION = "session-rpc"
NONCE = "nonce-rpc"
AGENT = "rlm-rpc"


def _request(
    request_id: int = 1,
    *,
    operation: str = "llm_query",
    prompt: str = "hello",
    prompts: list[str] | None = None,
    deadline_ms: int = 500,
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "protocol": "rlm-worker-v2",
        "type": "llm_rpc_request",
        "session_id": SESSION,
        "nonce": NONCE,
        "request_id": request_id,
        "parent_request_id": 1,
        "operation": operation,
        "deadline_ms": deadline_ms,
    }
    if operation == "llm_query":
        request["prompt"] = prompt
    else:
        request["prompts"] = prompts if prompts is not None else [prompt]
    return request


def _policy(*capabilities: str) -> CapabilityPolicy:
    policy = CapabilityPolicy(default_deny=True)
    for capability in capabilities:
        policy.grant(AGENT, capability)
    return policy


class _FakeEngine:
    def __init__(self, responses: list[dict[str, Any]] | None = None) -> None:
        self.calls: list[str] = []
        self._responses = list(responses or [])

    def generate(self, messages, **kwargs):
        del kwargs
        self.calls.append(messages[0].content)
        if self._responses:
            return self._responses.pop(0)
        return {"content": f"reply:{messages[0].content}"}


class _BlockingEngine(_FakeEngine):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()

    def generate(self, messages, **kwargs):
        self.started.set()
        self.release.wait(1.0)
        return super().generate(messages, **kwargs)


def test_protocol_accepts_query_batch_and_round_trips_json() -> None:
    query = _request()
    batch = _request(
        2,
        operation="llm_batch",
        prompts=["one", "two"],
    )
    assert validate_request(query, session_id=SESSION, nonce=NONCE) == query
    assert validate_request(batch, session_id=SESSION, nonce=NONCE) == batch
    assert decode_frame(encode_frame(query)) == query


@pytest.mark.parametrize(
    ("field", "value", "error_code"),
    [
        ("protocol", "rlm-worker-v1", "RPC_PROTOCOL_ERROR"),
        ("session_id", "other", "RPC_SESSION_MISMATCH"),
        ("nonce", "other", "RPC_NONCE_MISMATCH"),
        ("extra", True, "RPC_INVALID_SCHEMA"),
    ],
)
def test_protocol_rejects_identity_protocol_and_unknown_fields(
    field: str,
    value: Any,
    error_code: str,
) -> None:
    request = _request()
    if field == "extra":
        request[field] = value
    else:
        request[field] = value
    with pytest.raises(RLMRPCError) as exc_info:
        validate_request(request, session_id=SESSION, nonce=NONCE)
    assert exc_info.value.error_code == error_code


def test_protocol_rejects_unknown_operation_and_malformed_json() -> None:
    request = _request()
    request["operation"] = "tool_call"
    with pytest.raises(RLMRPCError) as exc_info:
        validate_request(request)
    assert exc_info.value.error_code == "RPC_UNKNOWN_OPERATION"
    with pytest.raises(RLMRPCError) as exc_info:
        decode_frame(b"{not-json")
    assert exc_info.value.error_code == "RPC_INVALID_SCHEMA"
    with pytest.raises(RLMRPCError) as exc_info:
        decode_frame(b'{"value":NaN}')
    assert exc_info.value.error_code == "RPC_INVALID_SCHEMA"


def test_protocol_rejects_utf8_batch_and_frame_limits() -> None:
    utf8_prompt = "あ" * (RPC_MAX_QUERY_PROMPT_CHARS // 2 + 1)
    with pytest.raises(RLMRPCError) as exc_info:
        validate_request(_request(prompt=utf8_prompt))
    assert exc_info.value.error_code == "RPC_REQUEST_TOO_LARGE"

    prompts = ["x"] * (RPC_MAX_BATCH_ITEMS + 1)
    with pytest.raises(RLMRPCError) as exc_info:
        validate_request(_request(operation="llm_batch", prompts=prompts))
    assert exc_info.value.error_code == "RPC_INVALID_SCHEMA"

    aggregate = ["x" * (RPC_MAX_BATCH_PROMPT_CHARS // 2)] * 3
    with pytest.raises(RLMRPCError) as exc_info:
        validate_request(_request(operation="llm_batch", prompts=aggregate))
    assert exc_info.value.error_code == "RPC_REQUEST_TOO_LARGE"

    oversized = {"items": ["x" * 64 * 1024] * 5}
    with pytest.raises(RLMRPCError) as exc_info:
        encode_frame(oversized)
    assert exc_info.value.error_code == "RPC_REQUEST_TOO_LARGE"
    with pytest.raises(RLMRPCError):
        decode_frame(b"x" * (RPC_MAX_FRAME_BYTES + 1))


def test_ledger_prevents_duplicate_dispatch_and_preserves_unknown() -> None:
    ledger = RequestLedger(SESSION, NONCE)
    request = _request()
    entry, duplicate = ledger.begin(request)
    assert duplicate is False
    ledger.mark_dispatched(entry)
    pending, duplicate = ledger.begin(request)
    assert duplicate is True
    assert pending is entry
    response = {"state": STATE_UNKNOWN_OUTCOME, "error_code": "RPC_UNKNOWN_OUTCOME"}
    ledger.finish(entry, STATE_UNKNOWN_OUTCOME, response)
    terminal, duplicate = ledger.begin(request)
    assert duplicate is True
    assert terminal.response == response

    changed = deepcopy(request)
    changed["prompt"] = "changed"
    with pytest.raises(RLMRPCError) as exc_info:
        ledger.begin(changed)
    assert exc_info.value.error_code == "RPC_DUPLICATE_REQUEST"


def test_ledger_cancellation_and_invalid_transitions_fail_closed() -> None:
    ledger = RequestLedger(SESSION, NONCE)
    entry, _ = ledger.begin(_request())
    ledger.cancel_before_dispatch(entry)
    assert entry.cancellation_requested is True
    with pytest.raises(RLMRPCError) as exc_info:
        ledger.mark_dispatched(entry)
    assert exc_info.value.error_code == "RPC_INVALID_STATE"

    dispatched, _ = ledger.begin(_request(2))
    ledger.mark_dispatched(dispatched)
    ledger.finish(dispatched, STATE_FAILED, {"error_code": "PROVIDER_FAILURE"})
    with pytest.raises(RLMRPCError) as exc_info:
        ledger.finish(dispatched, STATE_EXECUTED, {})
    assert exc_info.value.error_code == "RPC_INVALID_STATE"


def test_host_broker_query_batch_and_exact_terminal_duplicate() -> None:
    engine = _FakeEngine()
    broker = HostLLMBroker(
        engine,
        model="m",
        temperature=0.0,
        max_tokens=16,
        capability_policy=_policy("llm:query", "llm:batch"),
        agent_id=AGENT,
    )
    broker.bind_session(SESSION, NONCE)
    query = _request()
    response = broker.handle_request(query)
    assert response["state"] == STATE_EXECUTED
    assert response["output"] == "reply:hello"
    assert len(engine.calls) == 1
    duplicate = broker.handle_request(query)
    assert duplicate == response
    assert len(engine.calls) == 1

    batch = _request(2, operation="llm_batch", prompts=["a", "b"])
    batch_response = broker.handle_request(batch)
    assert batch_response["state"] == STATE_EXECUTED
    assert batch_response["outputs"] == ["reply:a", "reply:b"]
    assert engine.calls == ["hello", "a", "b"]


def test_host_broker_authorization_and_pending_duplicate() -> None:
    engine = _FakeEngine()
    broker = HostLLMBroker(
        engine,
        model="m",
        temperature=0.0,
        max_tokens=16,
        capability_policy=CapabilityPolicy(default_deny=True),
        agent_id=AGENT,
    )
    broker.bind_session(SESSION, NONCE)
    response = broker.handle_request(_request())
    assert response["state"] == STATE_NOT_STARTED
    assert response["error_code"] == "RPC_UNAUTHORIZED"
    assert not engine.calls

    broker = HostLLMBroker(
        engine,
        model="m",
        temperature=0.0,
        max_tokens=16,
        capability_policy=_policy("llm:query"),
        agent_id=AGENT,
    )
    broker.bind_session(SESSION, NONCE)
    request = _request()
    entry, _ = broker.ledger.begin(request)
    broker.ledger.mark_dispatched(entry)
    response = broker.handle_request(request)
    assert response["error_code"] == "RPC_DUPLICATE_PENDING"
    assert not engine.calls


@pytest.mark.parametrize(
    ("response", "error_code"),
    [
        ({"content": "provider failed", "tool_calls": None}, "PROVIDER_FAILURE"),
        (
            {"content": "unsafe", "tool_calls": [{"name": "mutate"}]},
            "SUBLM_TOOL_CALL_UNSUPPORTED",
        ),
        (
            {"content": "x" * (RPC_MAX_RESPONSE_ITEM_CHARS + 1)},
            "PROVIDER_RESPONSE_TOO_LARGE",
        ),
    ],
)
def test_host_broker_rejects_provider_failure_tool_calls_and_oversized_output(
    response: dict[str, Any],
    error_code: str,
) -> None:
    if error_code == "PROVIDER_FAILURE":
        class FailingEngine(_FakeEngine):
            def generate(self, messages, **kwargs):
                del messages, kwargs
                raise RuntimeError("provider")

        engine: Any = FailingEngine()
    else:
        engine = _FakeEngine([response])
    broker = HostLLMBroker(
        engine,
        model="m",
        temperature=0.0,
        max_tokens=16,
        capability_policy=_policy("llm:query"),
        agent_id=AGENT,
    )
    broker.bind_session(SESSION, NONCE)
    result = broker.handle_request(_request())
    assert result["state"] == STATE_FAILED
    assert result["error_code"] == error_code
    assert broker.handle_request(_request()) == result
    expected_calls = 0 if error_code == "PROVIDER_FAILURE" else 1
    assert len(engine.calls) == expected_calls


def test_host_broker_cancellation_and_timeout_are_unknown_without_retry() -> None:
    engine = _BlockingEngine()
    broker = HostLLMBroker(
        engine,
        model="m",
        temperature=0.0,
        max_tokens=16,
        capability_policy=_policy("llm:query"),
        agent_id=AGENT,
    )
    broker.bind_session(SESSION, NONCE)
    request = _request(deadline_ms=20)
    response = broker.handle_request(request)
    assert response["state"] == STATE_UNKNOWN_OUTCOME
    assert response["error_code"] == "RPC_UNKNOWN_OUTCOME"
    assert len(engine.calls) == 0
    engine.release.set()
    time.sleep(0.02)
    assert broker.handle_request(request) == response

    cancel = threading.Event()
    cancel.set()
    broker.bind_session(SESSION, "cancel-nonce")
    cancelled_request = _request()
    cancelled_request["nonce"] = "cancel-nonce"
    cancelled = broker.handle_request(cancelled_request, cancel_event=cancel)
    assert cancelled["state"] == STATE_NOT_STARTED
    assert cancelled["error_code"] == "RPC_CANCELLED"


def test_host_broker_partial_batch_failure_has_no_partial_success() -> None:
    engine = _FakeEngine(
        [
            {"content": "first"},
            {"content": "blocked", "tool_calls": [{"name": "mutate"}]},
        ]
    )
    broker = HostLLMBroker(
        engine,
        model="m",
        temperature=0.0,
        max_tokens=16,
        capability_policy=_policy("llm:batch"),
        agent_id=AGENT,
    )
    broker.bind_session(SESSION, NONCE)
    request = _request(4, operation="llm_batch", prompts=["one", "two"])
    response = broker.handle_request(request)
    assert response["state"] == STATE_FAILED
    assert response["error_code"] == "SUBLM_TOOL_CALL_UNSUPPORTED"
    assert response["outputs"] is None
    assert engine.calls == ["one", "two"]
    assert broker.handle_request(request) == response
    assert engine.calls == ["one", "two"]


def test_worker_llm_query_batch_denies_without_approved_sandbox() -> None:
    engine = _FakeEngine()
    broker = HostLLMBroker(
        engine,
        model="m",
        temperature=0.0,
        max_tokens=16,
        capability_policy=_policy("llm:query", "llm:batch"),
        agent_id=AGENT,
    )
    repl = RLMRepl(execution_mode="worker", llm_broker=broker)
    try:
        result = repl.execute_with_outcome("answer = llm_query('one')")
        assert result.success is False
        assert result.error_code == "RLM_SANDBOX_UNAVAILABLE"
        assert engine.calls == []
    finally:
        repl.close()


def test_worker_rejects_sublm_tool_calls_without_sandbox() -> None:
    engine = _FakeEngine(
        [{"content": "unsafe", "tool_calls": [{"name": "write_file"}]}]
    )
    broker = HostLLMBroker(
        engine,
        model="m",
        temperature=0.0,
        max_tokens=16,
        capability_policy=_policy("llm:query"),
        agent_id=AGENT,
    )
    repl = RLMRepl(execution_mode="worker", llm_broker=broker)
    try:
        result = repl.execute_with_outcome("llm_query('no tools')")
        assert result.success is False
        assert result.error_code == "RLM_SANDBOX_UNAVAILABLE"
        assert engine.calls == []
    finally:
        repl.close()


def test_worker_sandbox_denial_quarantines_session_without_retry() -> None:
    engine = _BlockingEngine()
    broker = HostLLMBroker(
        engine,
        model="m",
        temperature=0.0,
        max_tokens=16,
        capability_policy=_policy("llm:query"),
        agent_id=AGENT,
    )
    worker = RLMWorker(execution_timeout=0.05, llm_broker=broker)
    try:
        result = worker.execute_with_outcome("llm_query('timeout')")
        assert result.success is False
        assert result.unknown_outcome is False
        assert result.error_code == "RLM_SANDBOX_UNAVAILABLE"
        assert worker.quarantined is True
        retry = worker.execute_with_outcome("llm_query('retry')")
        assert retry.error_code == "WORKER_QUARANTINED"
        assert engine.calls == []
    finally:
        worker.close()


def test_worker_cancellation_cannot_dispatch_without_sandbox() -> None:
    engine = _BlockingEngine()
    broker = HostLLMBroker(
        engine,
        model="m",
        temperature=0.0,
        max_tokens=16,
        capability_policy=_policy("llm:query"),
        agent_id=AGENT,
    )
    worker = RLMWorker(execution_timeout=1.0, llm_broker=broker)
    try:
        result = worker.execute_with_outcome("llm_query('cancel')")
        assert result.success is False
        assert result.unknown_outcome is False
        assert result.error_code == "RLM_SANDBOX_UNAVAILABLE"
        assert worker.quarantined is True
        assert worker.execute_with_outcome("llm_query('retry')").error_code == (
            "WORKER_QUARANTINED"
        )
        assert engine.calls == []
    finally:
        engine.release.set()
        worker.close()


def test_agent_worker_mode_denies_without_approved_sandbox() -> None:
    from unittest.mock import MagicMock

    engine = MagicMock()
    engine.engine_id = "fake"
    engine.generate.return_value = {
        "content": "```python\nFINAL(llm_query('answer'))\n```",
    }
    policy = _policy("code:execute", "llm:query")
    agent = RLMAgent(
        engine,
        "m",
        execution_mode="worker",
        capability_policy=policy,
        agent_id=AGENT,
    )
    result = agent.run("run worker")
    assert result.metadata["error_code"] == "RLM_SANDBOX_UNAVAILABLE"
    assert engine.generate.call_count == 0

    engine = MagicMock()
    engine.engine_id = "fake"
    engine.generate.return_value = {
        "content": "```python\nFINAL(llm_query('answer'))\n```",
    }
    agent = RLMAgent(
        engine,
        "m",
        execution_mode="worker",
        capability_policy=policy,
        agent_id=AGENT,
    )
    result = agent.run("reject sub tool")
    assert result.metadata["error_code"] == "RLM_SANDBOX_UNAVAILABLE"
    assert engine.generate.call_count == 0
