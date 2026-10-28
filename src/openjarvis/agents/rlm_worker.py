"""Isolated worker foundation for model-generated RLM code.

The worker receives only bounded JSON frames over a ``multiprocessing`` pipe.
It never receives host callbacks, tools, agents, engines, or arbitrary Python
objects.  Python restrictions remain defense in depth; this is not an OS
sandbox.
"""

from __future__ import annotations

import importlib
import io
import json
import math
import threading
import time
import uuid
from contextlib import redirect_stderr, redirect_stdout
from multiprocessing.connection import BufferTooShort
from typing import Any, Callable, Dict, List, Optional

from openjarvis.agents.rlm_repl import (
    _BLOCKED_PATTERNS,
    _SAFE_BUILTINS,
    _SAFE_MODULES,
    RLMExecutionResult,
)
from openjarvis.agents.rlm_rpc import (
    RPC_PROTOCOL_VERSION,
    RLMRPCError,
)
from openjarvis.agents.rlm_rpc import (
    encode_frame as encode_rpc_frame,
)
from openjarvis.agents.rlm_rpc import (
    validate_request as validate_rpc_request,
)
from openjarvis.agents.rlm_rpc import (
    validate_response as validate_rpc_response,
)

PROTOCOL_VERSION = RPC_PROTOCOL_VERSION
MAX_FRAME_BYTES = 256 * 1024
MAX_STRING_CHARS = 64 * 1024
MAX_COLLECTION_ITEMS = 1024
MAX_NESTING_DEPTH = 16
DEFAULT_MAX_REQUESTS = 100
DEFAULT_STARTUP_TIMEOUT = 5.0
DEFAULT_EXECUTION_TIMEOUT = 5.0
DEFAULT_SHUTDOWN_TIMEOUT = 2.0


class RLMWorkerError(RuntimeError):
    """A worker lifecycle or protocol failure with a stable error code."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code


def _protocol_error(message: str) -> RLMWorkerError:
    return RLMWorkerError("WORKER_PROTOCOL_ERROR", message)


class RLMCapabilityUnavailable(RuntimeError):
    """Raised by worker-local helpers that need a future host RPC."""


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    """Validate the bounded JSON value subset used by the worker protocol."""
    if depth > MAX_NESTING_DEPTH:
        raise _protocol_error("JSON nesting limit exceeded")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _protocol_error("non-finite JSON number")
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING_CHARS:
            raise _protocol_error("JSON string limit exceeded")
        return
    if isinstance(value, list):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise _protocol_error("JSON collection limit exceeded")
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise _protocol_error("JSON collection limit exceeded")
        for key, item in value.items():
            if not isinstance(key, str):
                raise _protocol_error("JSON object keys must be strings")
            _validate_json_value(key, depth=depth + 1)
            _validate_json_value(item, depth=depth + 1)
        return
    raise _protocol_error("IPC value is not JSON-compatible")


def _validate_variable_name(name: Any) -> None:
    if (
        not isinstance(name, str)
        or not name
        or len(name) > MAX_STRING_CHARS
        or not name.isidentifier()
        or name.startswith("__")
    ):
        raise _protocol_error("invalid worker variable name")


def _encode_frame(payload: Dict[str, Any]) -> bytes:
    _validate_json_value(payload)
    try:
        frame = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise _protocol_error(f"JSON encoding failed: {exc}") from exc
    if len(frame) > MAX_FRAME_BYTES:
        raise _protocol_error("IPC frame limit exceeded")
    return frame


def _decode_frame(frame: bytes) -> Dict[str, Any]:
    if not isinstance(frame, (bytes, bytearray)):
        raise _protocol_error("IPC frame must be bytes")
    if len(frame) > MAX_FRAME_BYTES:
        raise _protocol_error("IPC frame limit exceeded")
    try:
        payload = json.loads(bytes(frame).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _protocol_error(f"invalid JSON frame: {exc}") from exc
    if not isinstance(payload, dict):
        raise _protocol_error("IPC frame must contain a JSON object")
    _validate_json_value(payload)
    return payload


def _send_frame(connection: Any, payload: Dict[str, Any]) -> None:
    connection.send_bytes(_encode_frame(payload))


def _recv_frame(connection: Any) -> Dict[str, Any]:
    try:
        return _decode_frame(connection.recv_bytes(MAX_FRAME_BYTES))
    except RLMWorkerError:
        raise
    except (BufferTooShort, EOFError, OSError, ValueError) as exc:
        raise _protocol_error(f"IPC receive failed: {exc}") from exc


def _validate_identity(payload: Dict[str, Any], session_id: str, nonce: str) -> None:
    if payload.get("protocol") != PROTOCOL_VERSION:
        raise _protocol_error("protocol version mismatch")
    if payload.get("session_id") != session_id:
        raise _protocol_error("session identity mismatch")
    if payload.get("nonce") != nonce:
        raise _protocol_error("session nonce mismatch")


def _validate_handshake(
    payload: Dict[str, Any],
    session_id: str,
    nonce: str,
    max_requests: Optional[int] = None,
) -> None:
    _validate_identity(payload, session_id, nonce)
    if payload.get("type") != "ready":
        raise _protocol_error("invalid worker handshake type")
    reported_max_requests = payload.get("max_requests")
    if not isinstance(reported_max_requests, int) or isinstance(
        reported_max_requests, bool
    ):
        raise _protocol_error("worker handshake missing max_requests")
    if max_requests is not None and reported_max_requests != max_requests:
        raise _protocol_error("worker handshake max_requests mismatch")


def _validate_result(
    payload: Dict[str, Any],
    session_id: str,
    nonce: str,
    request_id: int,
) -> RLMExecutionResult:
    _validate_identity(payload, session_id, nonce)
    if payload.get("type") != "result":
        raise _protocol_error("invalid worker result type")
    response_request_id = payload.get("request_id")
    if not isinstance(response_request_id, int) or isinstance(
        response_request_id, bool
    ):
        raise _protocol_error("worker result has invalid request_id")
    if response_request_id != request_id:
        raise _protocol_error("worker request ordering mismatch")
    output = payload.get("output")
    success = payload.get("success")
    error_code = payload.get("error_code")
    terminated = payload.get("terminated")
    final_value = payload.get("final_value")
    request_count = payload.get("request_count")
    if not isinstance(output, str) or not isinstance(success, bool):
        raise _protocol_error("worker result has invalid output or success")
    if error_code is not None and not isinstance(error_code, str):
        raise _protocol_error("worker result has invalid error_code")
    if not isinstance(terminated, bool) or not isinstance(request_count, int):
        raise _protocol_error("worker result has invalid state fields")
    if isinstance(request_count, bool):
        raise _protocol_error("worker result has invalid state fields")
    if request_count != request_id:
        raise _protocol_error("worker request count mismatch")
    if success and error_code is not None:
        raise _protocol_error("successful worker result carries an error")
    if not success and error_code is None:
        raise _protocol_error("failed worker result is missing error_code")
    if not terminated and final_value is not None:
        raise _protocol_error("non-terminated result carries final_value")
    unknown_outcome = payload.get("unknown_outcome", False)
    if not isinstance(unknown_outcome, bool):
        raise _protocol_error("worker result has invalid unknown_outcome")
    if success and unknown_outcome:
        raise _protocol_error("successful worker result is unknown")
    if final_value is not None:
        _validate_json_value(final_value)
    if output and len(output) > MAX_STRING_CHARS:
        raise _protocol_error("worker output limit exceeded")
    return RLMExecutionResult(
        output=output,
        success=success,
        error_code=error_code,
        terminated=terminated,
        final_value=final_value,
        unknown_outcome=unknown_outcome,
    )


class _BoundedOutput(io.StringIO):
    def __init__(self, limit: int) -> None:
        super().__init__()
        self._limit = limit
        self.truncated = False

    def write(self, value: str) -> int:
        remaining = self._limit - self.tell()
        if len(value) > remaining:
            self.truncated = True
        super().write(value[: max(0, remaining)])
        return len(value)


def _worker_namespace(
    rpc_call: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
    """Build the persistent namespace inside the worker process only."""
    namespace: Dict[str, Any] = {"__builtins__": _SAFE_BUILTINS}
    for module_name in _SAFE_MODULES:
        try:
            namespace[module_name] = importlib.import_module(module_name)
        except ImportError:
            continue

    namespace["answer"] = {"ready": False, "value": None}
    state: Dict[str, Any] = {"terminated": False, "final_value": None}

    def final(value: Any) -> None:
        state["terminated"] = True
        state["final_value"] = value

    def final_var(name: str) -> None:
        state["terminated"] = True
        state["final_value"] = namespace.get(name)

    namespace["FINAL"] = final
    namespace["FINAL_VAR"] = final_var

    if rpc_call is not None:

        def llm_query(prompt: str) -> str:
            response = rpc_call("llm_query", {"prompt": prompt})
            return response["output"]

        def llm_batch(prompts: list[str]) -> list[str]:
            response = rpc_call("llm_batch", {"prompts": prompts})
            return response["outputs"]

        namespace["llm_query"] = llm_query
        namespace["llm_batch"] = llm_batch

    if rpc_call is None:

        def unavailable_llm_query(*args: Any, **kwargs: Any) -> Any:
            del args, kwargs
            raise RLMCapabilityUnavailable("llm_query: RLM_CAPABILITY_UNAVAILABLE")

        def unavailable_llm_batch(*args: Any, **kwargs: Any) -> Any:
            del args, kwargs
            raise RLMCapabilityUnavailable("llm_batch: RLM_CAPABILITY_UNAVAILABLE")

        namespace["llm_query"] = unavailable_llm_query
        namespace["llm_batch"] = unavailable_llm_batch

    for helper_name in ("tool_call", "file_read", "read_file", "read_file_chunk"):

        def unavailable(*args: Any, _name: str = helper_name, **kwargs: Any) -> Any:
            raise RLMCapabilityUnavailable(
                f"{_name}: RLM_CAPABILITY_UNAVAILABLE"
            )

        namespace[helper_name] = unavailable
    return namespace, state


def _worker_execute(
    namespace: Dict[str, Any],
    state: Dict[str, Any],
    code: str,
    max_output_chars: int,
    rpc_call: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
) -> RLMExecutionResult:
    for pattern in _BLOCKED_PATTERNS:
        if pattern in code:
            return RLMExecutionResult(
                output=f"Error: Blocked: code contains prohibited pattern '{pattern}'",
                success=False,
                error_code="SECURITY_BLOCKED",
            )

    state["terminated"] = False
    state["final_value"] = None
    stdout_buf = _BoundedOutput(max_output_chars)
    stderr_buf = _BoundedOutput(max_output_chars)
    try:
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            exec(code, namespace)  # noqa: S102
    except BaseException as exc:
        if isinstance(exc, RLMRPCError):
            return RLMExecutionResult(
                output=str(exc),
                success=False,
                error_code=exc.error_code,
                unknown_outcome=exc.error_code == "RPC_UNKNOWN_OUTCOME",
            )
        if isinstance(exc, RLMCapabilityUnavailable):
            return RLMExecutionResult(
                output=str(exc),
                success=False,
                error_code="RLM_CAPABILITY_UNAVAILABLE",
            )
        return RLMExecutionResult(
            output=f"{type(exc).__name__}: {exc}",
            success=False,
            error_code=type(exc).__name__,
        )

    output = stdout_buf.getvalue()
    error_output = stderr_buf.getvalue()
    if error_output:
        output += ("\n" if output else "") + error_output
    was_truncated = stdout_buf.truncated or stderr_buf.truncated
    if len(output) > max_output_chars:
        output = output[:max_output_chars]
        was_truncated = True
    if was_truncated:
        marker = "\n... (output truncated)"
        output = output[: max(0, max_output_chars - len(marker))] + marker

    answer = namespace.get("answer")
    if (
        not state["terminated"]
        and isinstance(answer, dict)
        and answer.get("ready") is True
    ):
        state["terminated"] = True
        state["final_value"] = answer.get("value")

    terminated = bool(state["terminated"])
    final_value = state["final_value"] if terminated else None
    if terminated:
        try:
            _validate_json_value(final_value)
        except RLMWorkerError:
            return RLMExecutionResult(
                output="FINAL value is not JSON-compatible",
                success=False,
                error_code="NON_JSON_RESULT",
            )
    return RLMExecutionResult(
        output=output,
        success=True,
        terminated=terminated,
        final_value=final_value,
    )


def _worker_rpc_call(
    connection: Any,
    session_id: str,
    nonce: str,
    parent_request_id: int,
    rpc_id: int,
    operation: str,
    payload: Dict[str, Any],
    deadline: float,
) -> Dict[str, Any]:
    # Reserve a small transport window for the host response before the
    # parent execution deadline expires; otherwise a known provider timeout
    # can be misclassified as a worker transport timeout.
    remaining_ms = int((deadline - time.monotonic()) * 1000) - 5
    if remaining_ms < 1:
        raise RLMRPCError("RPC_DEADLINE_EXCEEDED", "worker RPC deadline expired")
    request = {
        "protocol": RPC_PROTOCOL_VERSION,
        "type": "llm_rpc_request",
        "session_id": session_id,
        "nonce": nonce,
        "request_id": rpc_id,
        "parent_request_id": parent_request_id,
        "operation": operation,
        "deadline_ms": remaining_ms,
        **payload,
    }
    try:
        validate_rpc_request(request, session_id=session_id, nonce=nonce)
        connection.send_bytes(encode_rpc_frame(request))
    except RLMRPCError:
        raise
    except (BrokenPipeError, EOFError, OSError) as exc:
        raise RLMRPCError("RPC_UNKNOWN_OUTCOME", str(exc)) from exc

    response_wait = deadline - time.monotonic()
    if response_wait <= 0 or not connection.poll(response_wait):
        raise RLMRPCError("RPC_UNKNOWN_OUTCOME", "host RPC response timed out")
    try:
        response = _recv_frame(connection)
        validate_rpc_response(
            response,
            request,
            session_id=session_id,
            nonce=nonce,
        )
    except RLMRPCError as exc:
        raise RLMRPCError(exc.error_code, str(exc)) from exc
    if response["state"] != "EXECUTED":
        error_code = response["error_code"]
        if error_code == "RPC_UNAUTHORIZED":
            error_code = "RLM_CAPABILITY_UNAVAILABLE"
        raise RLMRPCError(
            error_code,
            error_code,
        )
    return response


def _worker_entrypoint(
    connection: Any,
    session_id: str,
    nonce: str,
    max_output_chars: int,
    max_requests: int,
    llm_rpc_enabled: bool,
) -> None:
    """Module-level spawn target; only primitive configuration crosses spawn."""
    request_count = 0
    rpc_count = 0
    current_request_id = [0]
    current_deadline = [0.0]

    def rpc_call(operation: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        nonlocal rpc_count
        if current_request_id[0] <= 0 or current_deadline[0] <= 0:
            raise RLMRPCError("RPC_INVALID_STATE", "no active execution request")
        rpc_count += 1
        return _worker_rpc_call(
            connection,
            session_id,
            nonce,
            current_request_id[0],
            -rpc_count,
            operation,
            payload,
            current_deadline[0],
        )

    namespace, state = _worker_namespace(rpc_call if llm_rpc_enabled else None)
    try:
        _send_frame(
            connection,
            {
                "protocol": PROTOCOL_VERSION,
                "type": "ready",
                "session_id": session_id,
                "nonce": nonce,
                "max_requests": max_requests,
            },
        )
        while True:
            try:
                request = _recv_frame(connection)
            except RLMWorkerError as exc:
                try:
                    _send_frame(
                        connection,
                        {
                            "protocol": PROTOCOL_VERSION,
                            "type": "error",
                            "session_id": session_id,
                            "nonce": nonce,
                            "request_id": 0,
                            "error_code": exc.error_code,
                        },
                    )
                except (BrokenPipeError, OSError):
                    pass
                continue

            try:
                _validate_identity(request, session_id, nonce)
                request_type = request.get("type")
                request_id = request.get("request_id")
                if not isinstance(request_id, int) or isinstance(request_id, bool):
                    raise _protocol_error("invalid request_id")
                if request_type == "shutdown":
                    if request_id != 0:
                        raise _protocol_error("invalid shutdown request_id")
                    _send_frame(
                        connection,
                        {
                            "protocol": PROTOCOL_VERSION,
                            "type": "shutdown_ack",
                            "session_id": session_id,
                            "nonce": nonce,
                        },
                    )
                    break
                if request_type == "set_variable":
                    if request_id != 0:
                        raise _protocol_error("invalid set_variable request_id")
                    name = request.get("name")
                    _validate_variable_name(name)
                    value = request.get("value")
                    _validate_json_value(value)
                    namespace[name] = value
                    _send_frame(
                        connection,
                        {
                            "protocol": PROTOCOL_VERSION,
                            "type": "set_ack",
                            "session_id": session_id,
                            "nonce": nonce,
                            "name": name,
                        },
                    )
                    continue
                if request_type != "execute":
                    raise _protocol_error("unsupported worker operation")
                code = request.get("code")
                if not isinstance(code, str):
                    raise _protocol_error("worker code must be a string")
                deadline_ms = request.get("deadline_ms")
                if (
                    not isinstance(deadline_ms, int)
                    or isinstance(deadline_ms, bool)
                    or deadline_ms < 1
                ):
                    raise _protocol_error("invalid execution deadline")
                request_count += 1
                if request_count > max_requests:
                    result = RLMExecutionResult(
                        output="Worker request limit exceeded",
                        success=False,
                        error_code="MAX_REQUESTS_EXCEEDED",
                    )
                else:
                    deadline = time.monotonic() + deadline_ms / 1000
                    current_request_id[0] = request_id
                    current_deadline[0] = deadline
                    result = _worker_execute(
                        namespace,
                        state,
                        code,
                        max_output_chars,
                        rpc_call,
                    )
                    current_request_id[0] = 0
                    current_deadline[0] = 0.0
                _send_frame(
                    connection,
                    {
                        "protocol": PROTOCOL_VERSION,
                        "type": "result",
                        "session_id": session_id,
                        "nonce": nonce,
                        "request_id": request_id,
                        "request_count": request_count,
                        "output": result.output,
                        "success": result.success,
                        "error_code": result.error_code,
                        "terminated": result.terminated,
                        "final_value": result.final_value,
                        "unknown_outcome": result.unknown_outcome,
                    },
                )
            except RLMWorkerError as exc:
                try:
                    _send_frame(
                        connection,
                        {
                            "protocol": PROTOCOL_VERSION,
                            "type": "error",
                            "session_id": session_id,
                            "nonce": nonce,
                            "request_id": request.get("request_id", 0),
                            "error_code": exc.error_code,
                        },
                    )
                except (BrokenPipeError, OSError):
                    break
    except (BrokenPipeError, EOFError, OSError):
        pass
    finally:
        connection.close()


class RLMWorker:
    """Persistent spawn worker with fail-closed lifecycle semantics."""

    def __init__(
        self,
        *,
        llm_broker: Optional[Any] = None,
        session_id: Optional[str] = None,
        nonce: Optional[str] = None,
        max_output_chars: int = 10000,
        max_requests: int = DEFAULT_MAX_REQUESTS,
        startup_timeout: float = DEFAULT_STARTUP_TIMEOUT,
        execution_timeout: float = DEFAULT_EXECUTION_TIMEOUT,
        shutdown_timeout: float = DEFAULT_SHUTDOWN_TIMEOUT,
        sandbox: Optional[Any] = None,
    ) -> None:
        """Create a worker.

        An approved AppContainer sandbox is mandatory. A missing or
        unapproved sandbox is denied before any process can be created.
        """
        if (
            not isinstance(max_output_chars, int)
            or isinstance(max_output_chars, bool)
            or max_output_chars < 1
            or max_output_chars > MAX_STRING_CHARS
        ):
            raise ValueError("max_output_chars is outside the protocol limit")
        if (
            not isinstance(max_requests, int)
            or isinstance(max_requests, bool)
            or max_requests < 1
            or max_requests > MAX_COLLECTION_ITEMS
        ):
            raise ValueError("max_requests is outside the protocol limit")
        if startup_timeout <= 0 or execution_timeout <= 0 or shutdown_timeout <= 0:
            raise ValueError("worker timeouts must be positive")
        if execution_timeout * 1000 > 30_000:
            raise ValueError("worker execution timeout exceeds protocol limit")
        self._session_id = uuid.uuid4().hex if session_id is None else session_id
        self._nonce = uuid.uuid4().hex if nonce is None else nonce
        for name, value in (("session_id", self._session_id), ("nonce", self._nonce)):
            if not isinstance(value, str) or not value or len(value) > 128:
                raise ValueError(f"invalid {name}")
        self._max_output_chars = max_output_chars
        self._max_requests = max_requests
        self._startup_timeout = startup_timeout
        self._execution_timeout = execution_timeout
        self._shutdown_timeout = shutdown_timeout
        self._llm_broker = llm_broker
        self._sandbox = sandbox
        self._sandbox_handles: Any = None
        self._sandbox_cleanup_errors: List[str] = []
        self._approval_audit: Any = None
        self._process: Any = None
        self._connection: Any = None
        self._started = False
        self._closed = False
        self._quarantined = False
        self._request_count = 0
        self._cancel_event = threading.Event()

    @property
    def session_id(self) -> str:
        return self._session_id

    @property
    def nonce(self) -> str:
        return self._nonce

    @property
    def process(self) -> Any:
        return self._process

    @property
    def started(self) -> bool:
        return self._started

    @property
    def quarantined(self) -> bool:
        return self._quarantined

    @property
    def request_count(self) -> int:
        return self._request_count

    def start(self) -> None:
        if self._closed:
            raise RLMWorkerError("WORKER_CLOSED", "worker is closed")
        if self._quarantined:
            raise RLMWorkerError("WORKER_QUARANTINED", "worker is quarantined")
        if self._started:
            return

        if self._sandbox is None:
            self._quarantine()
            raise RLMWorkerError(
                "RLM_SANDBOX_UNAVAILABLE",
                "approved AppContainer sandbox is required",
            )
        self._start_sandboxed()

        if not self._connection.poll(self._startup_timeout):
            still_alive = self._process.is_alive()
            self._quarantine()
            error_code = (
                "WORKER_STARTUP_TIMEOUT"
                if still_alive
                else "WORKER_CRASH"
            )
            raise RLMWorkerError(error_code, "worker handshake did not arrive")
        try:
            _validate_handshake(
                _recv_frame(self._connection),
                self._session_id,
                self._nonce,
                self._max_requests,
            )
        except RLMWorkerError:
            self._quarantine()
            raise
        if self._llm_broker is not None:
            bind_session = getattr(self._llm_broker, "bind_session", None)
            if not callable(bind_session):
                self._quarantine()
                raise RLMWorkerError("RPC_INVALID_STATE", "invalid LLM broker")
            try:
                bind_session(self._session_id, self._nonce)
            except Exception as exc:
                self._quarantine()
                raise RLMWorkerError("RPC_INVALID_STATE", str(exc)) from exc
        self._started = True

    def _start_sandboxed(self) -> None:
        """AppContainer staged-runtime launch (explicit opt-in only).

        Any failure quarantines and raises RLMWorkerError carrying the
        sandbox taxonomy code. There is deliberately no fallback to the
        legacy spawn path.
        """
        from openjarvis.sandbox import worker_launcher as wl

        spec = self._sandbox
        from openjarvis.sandbox.worker_launcher import SandboxSpec

        if not isinstance(spec, SandboxSpec):
            self._quarantine()
            raise RLMWorkerError(
                "SANDBOX_SPEC_INVALID", "sandbox spec is not a SandboxSpec"
            )
        # Verifier integration point: audit any attached approval
        # evidence before denying. The audit result never authorizes
        # native execution; production stays fail-closed below.
        try:
            from openjarvis.sandbox import approval_verifier as av

            self._approval_audit = av.audit_spec_approval(spec)
        except Exception:
            self._approval_audit = None
        # A caller-supplied SandboxSpec is configuration, not host authority.
        # Native provenance and policy approval are unavailable in this
        # checkout, so the launcher remains unreachable until approved.
        self._quarantine()
        raise RLMWorkerError(
            "RLM_SANDBOX_NOT_AUTHORIZED",
            "AppContainer launcher is not approved for production execution",
        )
        try:
            handles = wl.launch_sandboxed_owned(
                spec,
                session_id=self._session_id,
                nonce=self._nonce,
                max_chars=self._max_output_chars,
                max_req=self._max_requests,
                rpc_enabled=self._llm_broker is not None,
                startup_timeout=self._startup_timeout,
            )
        except Exception as exc:
            self._quarantine()
            code = getattr(exc, "code", None)
            if not isinstance(code, str) or not code:
                code = "WORKER_START_FAILED"
            raise RLMWorkerError(code, str(exc)) from exc
        self._process = handles.process
        self._connection = handles.connection
        self._sandbox_handles = handles

    def execute_with_outcome(self, code: str) -> RLMExecutionResult:
        if not isinstance(code, str):
            return RLMExecutionResult(
                output="Worker code must be a string",
                success=False,
                error_code="INVALID_REQUEST",
            )
        if len(code) > MAX_STRING_CHARS:
            return RLMExecutionResult(
                output="Worker code exceeds the protocol limit",
                success=False,
                error_code="REQUEST_TOO_LARGE",
            )
        if self._closed:
            return self._failure("WORKER_CLOSED", "worker is closed")
        if self._quarantined:
            return self._failure("WORKER_QUARANTINED", "worker is quarantined")
        if self._cancel_event.is_set():
            self._cancel_event.clear()
            return self._failure("RPC_CANCELLED", "worker execution cancelled")
        try:
            self.start()
        except RLMWorkerError as exc:
            return self._failure(exc.error_code, str(exc))
        if not self._process.is_alive():
            self._quarantine()
            return self._failure("WORKER_CRASH", "worker exited before execution")
        if self._request_count >= self._max_requests:
            return self._failure(
                "MAX_REQUESTS_EXCEEDED",
                "worker request limit exceeded",
            )

        request_id = self._request_count + 1
        request = {
            "protocol": PROTOCOL_VERSION,
            "type": "execute",
            "session_id": self._session_id,
            "nonce": self._nonce,
            "request_id": request_id,
            "deadline_ms": max(1, int(self._execution_timeout * 1000)),
            "code": code,
        }
        try:
            _send_frame(self._connection, request)
            self._request_count = request_id
        except (BrokenPipeError, EOFError, OSError, RLMWorkerError) as exc:
            self._quarantine()
            return self._failure(
                "WORKER_IPC_ERROR",
                f"worker request failed: {exc}",
                unknown_outcome=True,
            )

        deadline = time.monotonic() + self._execution_timeout
        while True:
            if self._cancel_event.is_set():
                self._quarantine()
                return self._failure(
                    "RPC_UNKNOWN_OUTCOME",
                    "worker execution cancelled after dispatch",
                    unknown_outcome=True,
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._connection.poll(min(remaining, 0.05)):
                if time.monotonic() >= deadline:
                    self._quarantine()
                    return self._failure(
                        "WORKER_TIMEOUT",
                        "worker execution timed out",
                        unknown_outcome=True,
                    )
                continue
            try:
                frame = _recv_frame(self._connection)
                if frame.get("type") == "llm_rpc_request":
                    response = self._handle_llm_rpc(frame, request_id, deadline)
                    _send_frame(self._connection, response)
                    continue
                result = _validate_result(
                    frame,
                    self._session_id,
                    self._nonce,
                    request_id,
                )
                if result.unknown_outcome:
                    self._quarantine()
                return result
            except RLMWorkerError as exc:
                unknown = not self._process.is_alive()
                self._quarantine()
                return self._failure(
                    "WORKER_CRASH" if unknown else exc.error_code,
                    str(exc),
                    unknown_outcome=True,
                )

    def _handle_llm_rpc(
        self,
        request: Dict[str, Any],
        parent_request_id: int,
        deadline: float,
    ) -> Dict[str, Any]:
        if self._llm_broker is None:
            raise _protocol_error("LLM RPC is not configured")
        try:
            validate_rpc_request(
                request,
                session_id=self._session_id,
                nonce=self._nonce,
            )
        except RLMRPCError as exc:
            raise RLMWorkerError(exc.error_code, str(exc)) from exc
        if request["parent_request_id"] != parent_request_id:
            raise _protocol_error("LLM RPC parent request mismatch")
        try:
            return self._llm_broker.handle_request(
                request,
                absolute_deadline=deadline,
                cancel_event=self._cancel_event,
            )
        except RLMRPCError as exc:
            raise RLMWorkerError(exc.error_code, str(exc)) from exc

    def cancel(self) -> None:
        """Request cancellation of the active execution without retrying it."""
        self._cancel_event.set()

    def set_variable(self, name: str, value: Any) -> None:
        """Set one bounded JSON value in the persistent worker namespace."""
        _validate_variable_name(name)
        _validate_json_value(value)
        if self._closed:
            raise RLMWorkerError("WORKER_CLOSED", "worker is closed")
        if self._quarantined:
            raise RLMWorkerError("WORKER_QUARANTINED", "worker is quarantined")
        try:
            self.start()
        except RLMWorkerError:
            raise
        if not self._process.is_alive():
            self._quarantine()
            raise RLMWorkerError("WORKER_CRASH", "worker exited before variable set")

        try:
            _send_frame(
                self._connection,
                {
                    "protocol": PROTOCOL_VERSION,
                    "type": "set_variable",
                    "session_id": self._session_id,
                    "nonce": self._nonce,
                    "request_id": 0,
                    "name": name,
                    "value": value,
                },
            )
            if not self._connection.poll(self._execution_timeout):
                raise RLMWorkerError(
                    "WORKER_TIMEOUT", "worker variable set timed out"
                )
            response = _recv_frame(self._connection)
            _validate_identity(response, self._session_id, self._nonce)
            if response.get("type") != "set_ack" or response.get("name") != name:
                raise _protocol_error("invalid worker variable acknowledgement")
        except (BrokenPipeError, EOFError, OSError, RLMWorkerError) as exc:
            self._quarantine()
            if isinstance(exc, RLMWorkerError):
                raise
            raise RLMWorkerError("WORKER_IPC_ERROR", str(exc)) from exc

    def execute(self, code: str) -> str:
        """Return the text output while preserving the structured API above."""
        return self.execute_with_outcome(code).output

    def close(self) -> None:
        if self._closed:
            return
        try:
            if (
                self._started
                and not self._quarantined
                and self._process is not None
                and self._process.is_alive()
            ):
                try:
                    _send_frame(
                        self._connection,
                        {
                            "protocol": PROTOCOL_VERSION,
                            "type": "shutdown",
                            "session_id": self._session_id,
                            "nonce": self._nonce,
                            "request_id": 0,
                        },
                    )
                    if self._connection.poll(self._shutdown_timeout):
                        response = _recv_frame(self._connection)
                        _validate_identity(response, self._session_id, self._nonce)
                        if response.get("type") != "shutdown_ack":
                            raise _protocol_error("invalid shutdown acknowledgement")
                    else:
                        self._quarantined = True
                except (BrokenPipeError, EOFError, OSError, RLMWorkerError):
                    self._quarantined = True
        finally:
            self._terminate_process()
            if self._connection is not None:
                self._connection.close()
            self._cleanup_sandbox_handles()
            self._closed = True

    def _failure(
        self,
        error_code: str,
        message: str,
        *,
        unknown_outcome: bool = False,
    ) -> RLMExecutionResult:
        return RLMExecutionResult(
            output=message,
            success=False,
            error_code=error_code,
            unknown_outcome=unknown_outcome,
        )

    def _terminate_process(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            if process.is_alive():
                process.terminate()
            process.join(timeout=self._shutdown_timeout)
            if process.is_alive():
                process.kill()
                process.join(timeout=self._shutdown_timeout)
        except (AssertionError, OSError):
            return

    def _quarantine(self) -> None:
        self._quarantined = True
        self._terminate_process()
        if self._connection is not None:
            self._connection.close()
        self._cleanup_sandbox_handles()

    def _cleanup_sandbox_handles(self) -> None:
        """Best-effort sandbox teardown (revoke ACE, delete profile).

        Residue is recorded, never hidden: cleanup errors accumulate on
        _sandbox_cleanup_errors for the caller to inspect.
        """
        handles = self._sandbox_handles
        if handles is None:
            return
        self._sandbox_handles = None
        try:
            errors = handles.close()
        except Exception:
            errors = ["CLEANUP_FAILURE"]
        if errors:
            self._sandbox_cleanup_errors = (
                self._sandbox_cleanup_errors + errors
            )

    def __enter__(self) -> "RLMWorker":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


__all__ = [
    "DEFAULT_EXECUTION_TIMEOUT",
    "DEFAULT_MAX_REQUESTS",
    "DEFAULT_SHUTDOWN_TIMEOUT",
    "DEFAULT_STARTUP_TIMEOUT",
    "MAX_FRAME_BYTES",
    "MAX_STRING_CHARS",
    "PROTOCOL_VERSION",
    "RLMWorker",
    "RLMWorkerError",
]
