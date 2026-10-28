"""Host-mediated, non-privileged LLM RPC for the RLM worker.

This module contains only bounded JSON protocol validation and a host-owned
broker.  The broker never exposes its engine, policy, or tool objects to the
worker process.  It is deliberately LLM-only; tool calls are rejected.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any, Dict, Iterable, List, Optional, Tuple

from openjarvis.core.types import Message, Role

RPC_PROTOCOL_VERSION = "rlm-worker-v2"
RPC_MAX_FRAME_BYTES = 256 * 1024
RPC_MAX_QUERY_PROMPT_CHARS = 32 * 1024
RPC_MAX_BATCH_ITEMS = 16
RPC_MAX_BATCH_PROMPT_CHARS = 128 * 1024
RPC_MAX_RESPONSE_ITEM_CHARS = 32 * 1024
RPC_MAX_RESPONSE_AGGREGATE_CHARS = 128 * 1024
RPC_MAX_STRING_CHARS = 64 * 1024
RPC_MAX_COLLECTION_ITEMS = 1024
RPC_MAX_NESTING_DEPTH = 16
RPC_MAX_REQUESTS = 100
RPC_MAX_DEADLINE_MS = 30_000

LLM_QUERY_CAPABILITY = "llm:query"
LLM_BATCH_CAPABILITY = "llm:batch"

STATE_NOT_STARTED = "NOT_STARTED"
STATE_EXECUTED = "EXECUTED"
STATE_FAILED = "FAILED"
STATE_UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"

_COMMON_REQUEST_FIELDS = {
    "protocol",
    "type",
    "session_id",
    "nonce",
    "request_id",
    "parent_request_id",
    "operation",
    "deadline_ms",
}
_QUERY_REQUEST_FIELDS = _COMMON_REQUEST_FIELDS | {"prompt"}
_BATCH_REQUEST_FIELDS = _COMMON_REQUEST_FIELDS | {"prompts"}
_RESPONSE_FIELDS = {
    "protocol",
    "type",
    "session_id",
    "nonce",
    "request_id",
    "parent_request_id",
    "operation",
    "state",
    "success",
    "output",
    "outputs",
    "error_code",
    "usage",
}


class RLMRPCError(RuntimeError):
    """A deterministic protocol, authorization, or broker error."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code


def _error(code: str, message: str) -> RLMRPCError:
    return RLMRPCError(code, message)


def validate_json_value(value: Any, *, depth: int = 0) -> None:
    """Validate the JSON subset before any broker or transport operation."""
    if depth > RPC_MAX_NESTING_DEPTH:
        raise _error("RPC_INVALID_SCHEMA", "JSON nesting limit exceeded")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _error("RPC_INVALID_SCHEMA", "non-finite JSON number")
        return
    if isinstance(value, str):
        if len(value) > RPC_MAX_STRING_CHARS:
            raise _error("RPC_REQUEST_TOO_LARGE", "JSON string limit exceeded")
        return
    if isinstance(value, list):
        if len(value) > RPC_MAX_COLLECTION_ITEMS:
            raise _error("RPC_REQUEST_TOO_LARGE", "JSON collection limit exceeded")
        for item in value:
            validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > RPC_MAX_COLLECTION_ITEMS:
            raise _error("RPC_REQUEST_TOO_LARGE", "JSON object limit exceeded")
        for key, item in value.items():
            if not isinstance(key, str):
                raise _error("RPC_INVALID_SCHEMA", "JSON keys must be strings")
            validate_json_value(key, depth=depth + 1)
            validate_json_value(item, depth=depth + 1)
        return
    raise _error("RPC_INVALID_SCHEMA", "value is not JSON-compatible")


def encode_frame(payload: Dict[str, Any]) -> bytes:
    if not isinstance(payload, dict):
        raise _error("RPC_INVALID_SCHEMA", "frame root must be an object")
    validate_json_value(payload)
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _error("RPC_INVALID_SCHEMA", f"JSON encoding failed: {exc}") from exc
    if len(encoded) > RPC_MAX_FRAME_BYTES:
        raise _error("RPC_REQUEST_TOO_LARGE", "encoded frame limit exceeded")
    return encoded


def decode_frame(frame: bytes) -> Dict[str, Any]:
    if not isinstance(frame, (bytes, bytearray)):
        raise _error("RPC_INVALID_SCHEMA", "frame must be bytes")
    if len(frame) > RPC_MAX_FRAME_BYTES:
        raise _error("RPC_REQUEST_TOO_LARGE", "encoded frame limit exceeded")
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> Dict[str, Any]:
        payload: Dict[str, Any] = {}
        for key, value in pairs:
            if key in payload:
                raise ValueError(f"duplicate JSON key: {key}")
            payload[key] = value
        return payload

    try:
        payload = json.loads(
            bytes(frame).decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise _error("RPC_INVALID_SCHEMA", f"invalid JSON frame: {exc}") from exc
    if not isinstance(payload, dict):
        raise _error("RPC_INVALID_SCHEMA", "frame root must be an object")
    validate_json_value(payload)
    return payload


def _validate_common(
    payload: Dict[str, Any],
    *,
    session_id: Optional[str],
    nonce: Optional[str],
    allowed_fields: set[str],
) -> None:
    unknown = set(payload) - allowed_fields
    if unknown:
        raise _error("RPC_INVALID_SCHEMA", f"unknown fields: {sorted(unknown)}")
    if payload.get("protocol") != RPC_PROTOCOL_VERSION:
        raise _error("RPC_PROTOCOL_ERROR", "protocol version mismatch")
    if payload.get("type") != "llm_rpc_request":
        raise _error("RPC_INVALID_SCHEMA", "invalid RPC request type")
    for key in ("session_id", "nonce"):
        value = payload.get(key)
        if not isinstance(value, str) or not value or len(value) > 128:
            raise _error("RPC_INVALID_SCHEMA", f"invalid {key}")
    if session_id is not None and payload["session_id"] != session_id:
        raise _error("RPC_SESSION_MISMATCH", "session identity mismatch")
    if nonce is not None and payload["nonce"] != nonce:
        raise _error("RPC_NONCE_MISMATCH", "session nonce mismatch")
    request_id = payload.get("request_id")
    parent_request_id = payload.get("parent_request_id")
    deadline_ms = payload.get("deadline_ms")
    if (
        not isinstance(request_id, int)
        or isinstance(request_id, bool)
        or request_id == 0
        or not isinstance(parent_request_id, int)
        or isinstance(parent_request_id, bool)
        or parent_request_id <= 0
        or not isinstance(deadline_ms, int)
        or isinstance(deadline_ms, bool)
        or deadline_ms < 1
        or deadline_ms > RPC_MAX_DEADLINE_MS
    ):
        raise _error("RPC_INVALID_SCHEMA", "invalid request identity or deadline")


def validate_request(
    payload: Dict[str, Any],
    *,
    session_id: Optional[str] = None,
    nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate and return one LLM RPC request."""
    if not isinstance(payload, dict):
        raise _error("RPC_INVALID_SCHEMA", "request must be an object")
    validate_json_value(payload)
    operation = payload.get("operation")
    if operation == "llm_query":
        allowed = _QUERY_REQUEST_FIELDS
    elif operation == "llm_batch":
        allowed = _BATCH_REQUEST_FIELDS
    else:
        raise _error("RPC_UNKNOWN_OPERATION", "unsupported LLM RPC operation")
    _validate_common(
        payload,
        session_id=session_id,
        nonce=nonce,
        allowed_fields=allowed,
    )
    if operation == "llm_query":
        prompt = payload.get("prompt")
        if not isinstance(prompt, str) or not prompt:
            raise _error("RPC_INVALID_SCHEMA", "query prompt must be nonempty text")
        if len(prompt) > RPC_MAX_QUERY_PROMPT_CHARS:
            raise _error("RPC_REQUEST_TOO_LARGE", "query prompt limit exceeded")
        if len(prompt.encode("utf-8")) > RPC_MAX_QUERY_PROMPT_CHARS:
            raise _error("RPC_REQUEST_TOO_LARGE", "encoded prompt limit exceeded")
    else:
        prompts = payload.get("prompts")
        if (
            not isinstance(prompts, list)
            or not prompts
            or len(prompts) > RPC_MAX_BATCH_ITEMS
            or any(not isinstance(prompt, str) or not prompt for prompt in prompts)
        ):
            raise _error("RPC_INVALID_SCHEMA", "invalid batch prompts")
        if any(len(prompt) > RPC_MAX_QUERY_PROMPT_CHARS for prompt in prompts):
            raise _error("RPC_REQUEST_TOO_LARGE", "batch item limit exceeded")
        aggregate = sum(len(prompt) for prompt in prompts)
        encoded_aggregate = sum(len(prompt.encode("utf-8")) for prompt in prompts)
        if (
            aggregate > RPC_MAX_BATCH_PROMPT_CHARS
            or encoded_aggregate > RPC_MAX_BATCH_PROMPT_CHARS
        ):
            raise _error("RPC_REQUEST_TOO_LARGE", "batch aggregate limit exceeded")
    return payload


def validate_response(
    payload: Dict[str, Any],
    request: Dict[str, Any],
    *,
    session_id: str,
    nonce: str,
) -> Dict[str, Any]:
    """Validate a broker response against its request."""
    if not isinstance(payload, dict):
        raise _error("RPC_INVALID_SCHEMA", "response must be an object")
    validate_json_value(payload)
    validate_request(request, session_id=session_id, nonce=nonce)
    unknown = set(payload) - _RESPONSE_FIELDS
    if unknown:
        raise _error(
            "RPC_INVALID_SCHEMA",
            f"unknown response fields: {sorted(unknown)}",
        )
    if payload.get("protocol") != RPC_PROTOCOL_VERSION:
        raise _error("RPC_PROTOCOL_ERROR", "response protocol mismatch")
    if payload.get("type") != "llm_rpc_response":
        raise _error("RPC_INVALID_SCHEMA", "invalid RPC response type")
    if payload.get("session_id") != session_id:
        raise _error("RPC_SESSION_MISMATCH", "response session mismatch")
    if payload.get("nonce") != nonce:
        raise _error("RPC_NONCE_MISMATCH", "response nonce mismatch")
    for key in ("request_id", "parent_request_id"):
        if payload.get(key) != request.get(key):
            raise _error("RPC_INVALID_SCHEMA", f"response {key} mismatch")
    if payload.get("operation") != request.get("operation"):
        raise _error("RPC_INVALID_SCHEMA", "response operation mismatch")
    state = payload.get("state")
    success = payload.get("success")
    error_code = payload.get("error_code")
    if state not in {
        STATE_NOT_STARTED,
        STATE_EXECUTED,
        STATE_FAILED,
        STATE_UNKNOWN_OUTCOME,
    } or not isinstance(success, bool):
        raise _error("RPC_INVALID_SCHEMA", "invalid response state")
    if success != (state == STATE_EXECUTED):
        raise _error("RPC_INVALID_SCHEMA", "response success/state contradiction")
    if state == STATE_EXECUTED:
        if not isinstance(error_code, type(None)):
            raise _error("RPC_INVALID_SCHEMA", "successful response carries an error")
    elif not isinstance(error_code, str) or not error_code:
        raise _error("RPC_INVALID_SCHEMA", "failed response missing error code")

    output = payload.get("output")
    outputs = payload.get("outputs")
    if request["operation"] == "llm_query":
        if state == STATE_EXECUTED:
            if (
                not isinstance(output, str)
                or len(output) > RPC_MAX_RESPONSE_ITEM_CHARS
                or len(output.encode("utf-8")) > RPC_MAX_RESPONSE_ITEM_CHARS
            ):
                raise _error("RPC_INVALID_SCHEMA", "invalid query response")
        elif output is not None or outputs is not None:
            raise _error("RPC_INVALID_SCHEMA", "failed query carries output")
        if outputs is not None:
            raise _error("RPC_INVALID_SCHEMA", "query carries batch output")
    else:
        if state == STATE_EXECUTED:
            prompts = request["prompts"]
            if (
                not isinstance(outputs, list)
                or len(outputs) != len(prompts)
                or any(
                    not isinstance(item, str)
                    or len(item) > RPC_MAX_RESPONSE_ITEM_CHARS
                    or len(item.encode("utf-8")) > RPC_MAX_RESPONSE_ITEM_CHARS
                    for item in outputs
                )
                or sum(len(item) for item in outputs)
                > RPC_MAX_RESPONSE_AGGREGATE_CHARS
                or sum(len(item.encode("utf-8")) for item in outputs)
                > RPC_MAX_RESPONSE_AGGREGATE_CHARS
            ):
                raise _error("RPC_INVALID_SCHEMA", "invalid batch response")
        elif output is not None or outputs is not None:
            raise _error("RPC_INVALID_SCHEMA", "failed batch carries output")

    usage = payload.get("usage")
    if usage is not None:
        if not isinstance(usage, dict) or set(usage) - {
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
        }:
            raise _error("RPC_INVALID_SCHEMA", "invalid usage object")
        for value in usage.values():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise _error("RPC_INVALID_SCHEMA", "invalid usage count")
    return payload


def request_digest(request: Dict[str, Any]) -> str:
    """Return a canonical digest for duplicate-payload detection."""
    return hashlib.sha256(encode_frame(request)).hexdigest()


@dataclass
class LedgerEntry:
    key: Tuple[str, str, int]
    digest: str
    parent_request_id: int
    operation: str
    deadline_ms: int
    state: str = STATE_NOT_STARTED
    dispatched: bool = False
    cancellation_requested: bool = False
    response: Optional[Dict[str, Any]] = None


class RequestLedger:
    """Session-scoped state machine for exactly-once broker dispatch.

    All state transitions hold an internal lock so concurrent duplicate
    dispatches are denied atomically (P0-6: check-then-act race fix).
    The lock is never held across engine/provider invocation.
    """

    def __init__(
        self,
        session_id: str,
        nonce: str,
        *,
        max_requests: int = RPC_MAX_REQUESTS,
    ):
        self.session_id = session_id
        self.nonce = nonce
        self.max_requests = max_requests
        self._entries: Dict[Tuple[str, str, int], LedgerEntry] = {}
        self._lock = threading.Lock()

    @property
    def entries(self) -> Dict[Tuple[str, str, int], LedgerEntry]:
        return dict(self._entries)

    def begin(self, request: Dict[str, Any]) -> Tuple[LedgerEntry, bool]:
        with self._lock:
            validate_request(request, session_id=self.session_id,
                             nonce=self.nonce)
            key = (self.session_id, self.nonce, request["request_id"])
            digest = request_digest(request)
            existing = self._entries.get(key)
            if existing is not None:
                if existing.digest != digest:
                    raise _error("RPC_DUPLICATE_REQUEST",
                                 "duplicate payload changed")
                return existing, True
            if len(self._entries) >= self.max_requests:
                raise _error("RPC_MAX_REQUESTS",
                             "LLM RPC request limit exceeded")
            entry = LedgerEntry(
                key=key,
                digest=digest,
                parent_request_id=request["parent_request_id"],
                operation=request["operation"],
                deadline_ms=request["deadline_ms"],
            )
            self._entries[key] = entry
            return entry, False

    def mark_dispatched(self, entry: LedgerEntry) -> None:
        with self._lock:
            if (
                entry.state != STATE_NOT_STARTED
                or entry.response is not None
                or entry.cancellation_requested
            ):
                raise _error("RPC_INVALID_STATE",
                             "request is not dispatchable")
            entry.state = "DISPATCHED"
            entry.dispatched = True

    def finish(
        self,
        entry: LedgerEntry,
        state: str,
        response: Dict[str, Any],
    ) -> None:
        with self._lock:
            if state not in {
                STATE_EXECUTED,
                STATE_FAILED,
                STATE_UNKNOWN_OUTCOME,
            }:
                raise _error("RPC_INVALID_STATE", "invalid terminal state")
            if entry.state != "DISPATCHED" or entry.response is not None:
                raise _error("RPC_INVALID_STATE",
                             "invalid terminal transition")
            entry.state = state
            entry.response = response

    def cancel_before_dispatch(self, entry: LedgerEntry) -> None:
        with self._lock:
            if entry.state != STATE_NOT_STARTED or entry.response is not None:
                raise _error(
                    "RPC_INVALID_STATE",
                    "request cannot be cancelled before dispatch",
                )
            entry.cancellation_requested = True

    def mark_unknown(self, entry: LedgerEntry, response: Dict[str, Any]) -> None:
        self.finish(entry, STATE_UNKNOWN_OUTCOME, response)


def _explicit_policy_grant(policy: Any, agent_id: str, capability: str) -> bool:
    """Require an actual grant instead of an open-by-default policy result."""
    list_agents = getattr(policy, "list_agents", None)
    list_grants = getattr(policy, "list_grants", None)
    check = getattr(policy, "check", None)
    if not callable(list_agents) or not callable(list_grants) or not callable(check):
        return False
    try:
        agents = list(list_agents())
        grant_agent = agent_id if agent_id in agents else "_default"
        grants: Iterable[Any] = list_grants(grant_agent)
        granted = any(
            fnmatch(capability, str(getattr(grant, "capability", "")))
            for grant in grants
        )
        return granted and bool(check(agent_id, capability, "llm"))
    except Exception:
        return False


class HostLLMBroker:
    """Host-only LLM broker with no ToolExecutor access."""

    def __init__(
        self,
        engine: Any,
        *,
        model: str,
        temperature: float,
        max_tokens: int,
        capability_policy: Any,
        agent_id: str,
        max_requests: int = RPC_MAX_REQUESTS,
    ) -> None:
        self._engine = engine
        self._model = model
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._capability_policy = capability_policy
        self._agent_id = agent_id
        self._ledger = RequestLedger("", "", max_requests=max_requests)
        self._max_requests = max_requests

    def bind_session(self, session_id: str, nonce: str) -> None:
        self._ledger = RequestLedger(session_id, nonce, max_requests=self._max_requests)

    @property
    def ledger(self) -> RequestLedger:
        return self._ledger

    def handle_request(
        self,
        request: Dict[str, Any],
        *,
        absolute_deadline: Optional[float] = None,
        cancel_event: Optional[threading.Event] = None,
    ) -> Dict[str, Any]:
        validate_request(
            request,
            session_id=self._ledger.session_id,
            nonce=self._ledger.nonce,
        )
        entry, duplicate = self._ledger.begin(request)
        if duplicate:
            if entry.response is not None:
                return dict(entry.response)
            return self._response(
                request,
                STATE_NOT_STARTED,
                success=False,
                error_code="RPC_DUPLICATE_PENDING",
            )

        capability = (
            LLM_QUERY_CAPABILITY
            if request["operation"] == "llm_query"
            else LLM_BATCH_CAPABILITY
        )
        if not _explicit_policy_grant(
            self._capability_policy,
            self._agent_id,
            capability,
        ):
            self._ledger.cancel_before_dispatch(entry)
            response = self._response(
                request,
                STATE_NOT_STARTED,
                success=False,
                error_code="RPC_UNAUTHORIZED",
            )
            entry.response = response
            return response

        deadline = time.monotonic() + request["deadline_ms"] / 1000
        if absolute_deadline is not None:
            deadline = min(deadline, absolute_deadline)
        if cancel_event is not None and cancel_event.is_set():
            self._ledger.cancel_before_dispatch(entry)
            response = self._response(
                request,
                STATE_NOT_STARTED,
                success=False,
                error_code="RPC_CANCELLED",
            )
            entry.response = response
            return response
        if time.monotonic() >= deadline:
            self._ledger.cancel_before_dispatch(entry)
            response = self._response(
                request,
                STATE_NOT_STARTED,
                success=False,
                error_code="RPC_DEADLINE_EXCEEDED",
            )
            entry.response = response
            return response

        self._ledger.mark_dispatched(entry)
        if request["operation"] == "llm_query":
            outcome = self._invoke_one(request["prompt"], deadline, cancel_event)
            if outcome[0] == STATE_EXECUTED:
                response = self._response(
                    request,
                    STATE_EXECUTED,
                    success=True,
                    output=outcome[1],
                    usage=outcome[2],
                )
            else:
                response = self._response(
                    request,
                    outcome[0],
                    success=False,
                    error_code=outcome[1],
                )
        else:
            outputs: List[str] = []
            usage: Dict[str, int] = {}
            for prompt in request["prompts"]:
                outcome = self._invoke_one(prompt, deadline, cancel_event)
                if outcome[0] != STATE_EXECUTED:
                    response = self._response(
                        request,
                        outcome[0],
                        success=False,
                        error_code=outcome[1],
                    )
                    break
                outputs.append(outcome[1])
                for key, value in outcome[2].items():
                    usage[key] = usage.get(key, 0) + value
            else:
                response = self._response(
                    request,
                    STATE_EXECUTED,
                    success=True,
                    outputs=outputs,
                    usage=usage or None,
                )

        self._ledger.finish(entry, response["state"], response)
        return response

    def _invoke_one(
        self,
        prompt: str,
        deadline: float,
        cancel_event: Optional[threading.Event],
    ) -> Tuple[str, Any, Dict[str, int]]:
        result_box: List[Any] = []
        done = threading.Event()

        def invoke() -> None:
            try:
                result_box.append((True, self._engine.generate(
                    [Message(role=Role.USER, content=prompt)],
                    model=self._model,
                    temperature=self._temperature,
                    max_tokens=self._max_tokens,
                )))
            except Exception as exc:  # provider failure is known
                result_box.append((False, exc))
            finally:
                done.set()

        threading.Thread(target=invoke, daemon=True).start()
        while not done.is_set():
            if cancel_event is not None and cancel_event.is_set():
                return STATE_UNKNOWN_OUTCOME, "RPC_UNKNOWN_OUTCOME", {}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return STATE_UNKNOWN_OUTCOME, "RPC_UNKNOWN_OUTCOME", {}
            done.wait(min(remaining, 0.02))

        ok, result = result_box[0]
        if not ok:
            return STATE_FAILED, "PROVIDER_FAILURE", {}
        if not isinstance(result, dict) or not isinstance(
            result.get("content", ""), str
        ):
            return STATE_FAILED, "PROVIDER_RESPONSE_INVALID", {}
        if result.get("tool_calls"):
            return STATE_FAILED, "SUBLM_TOOL_CALL_UNSUPPORTED", {}
        output = result.get("content", "")
        if len(output) > RPC_MAX_RESPONSE_ITEM_CHARS:
            return STATE_FAILED, "PROVIDER_RESPONSE_TOO_LARGE", {}
        usage = result.get("usage") or {}
        if not isinstance(usage, dict):
            return STATE_FAILED, "PROVIDER_RESPONSE_INVALID", {}
        clean_usage: Dict[str, int] = {}
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            value = usage.get(key)
            if value is not None:
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    return STATE_FAILED, "PROVIDER_RESPONSE_INVALID", {}
                clean_usage[key] = value
        return STATE_EXECUTED, output, clean_usage

    def _response(
        self,
        request: Dict[str, Any],
        state: str,
        *,
        success: bool,
        error_code: Optional[str] = None,
        output: Optional[str] = None,
        outputs: Optional[List[str]] = None,
        usage: Optional[Dict[str, int]] = None,
    ) -> Dict[str, Any]:
        payload = {
            "protocol": RPC_PROTOCOL_VERSION,
            "type": "llm_rpc_response",
            "session_id": request["session_id"],
            "nonce": request["nonce"],
            "request_id": request["request_id"],
            "parent_request_id": request["parent_request_id"],
            "operation": request["operation"],
            "state": state,
            "success": success,
            "output": output,
            "outputs": outputs,
            "error_code": error_code,
            "usage": usage,
        }
        validate_response(
            payload,
            request,
            session_id=self._ledger.session_id,
            nonce=self._ledger.nonce,
        )
        return payload


__all__ = [
    "HostLLMBroker",
    "LLM_BATCH_CAPABILITY",
    "LLM_QUERY_CAPABILITY",
    "LedgerEntry",
    "RequestLedger",
    "RPC_PROTOCOL_VERSION",
    "RPC_MAX_BATCH_ITEMS",
    "RPC_MAX_BATCH_PROMPT_CHARS",
    "RPC_MAX_FRAME_BYTES",
    "RPC_MAX_QUERY_PROMPT_CHARS",
    "RPC_MAX_RESPONSE_AGGREGATE_CHARS",
    "RPC_MAX_RESPONSE_ITEM_CHARS",
    "RLMRPCError",
    "STATE_EXECUTED",
    "STATE_FAILED",
    "STATE_NOT_STARTED",
    "STATE_UNKNOWN_OUTCOME",
    "decode_frame",
    "encode_frame",
    "request_digest",
    "validate_json_value",
    "validate_request",
    "validate_response",
]
