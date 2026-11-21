"""Controller-owned process worker for deterministic synthetic task tools."""

from __future__ import annotations

import base64
import math
import os
import queue
import secrets
import site
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from openjarvis.control.sandbox_launcher import SandboxPolicy
from openjarvis.control.task_worker_ipc import TaskWorkerChannel
from openjarvis.control.ufo_worker_rpc import (
    MAX_RPC_BYTES,
    UfoRpcError,
    decode_request,
    encode_ready,
    encode_response,
)
from openjarvis.control.worker_process import (
    WorkerProcess,
    WorkerProcessError,
    safe_worker_environment,
)
from openjarvis.core.types import ToolResult

_WORKER_KIND = "atlas-task-worker"
_SOURCE_ROOT = Path(__file__).resolve().parents[2]
_PROJECT_ROOT = _SOURCE_ROOT.parent


class TaskWorkerExecutionError(RuntimeError):
    def __init__(self, reason: str, *, unknown_outcome: bool = False):
        super().__init__(reason)
        self.unknown_outcome = unknown_outcome


class TaskWorkerSupervisor:
    """Own one task-bound OS process and its authenticated stdio channel."""

    def __init__(
        self,
        binding: Mapping[str, Any],
        *,
        validate_authority: Callable[[], Any],
        startup_timeout: float = 5.0,
    ) -> None:
        if not isinstance(binding, Mapping) or not callable(validate_authority):
            raise ValueError("TASK_WORKER_BINDING_REQUIRED")
        # shortcut: this worker keeps its start-time lease, rotate before longer tasks.
        self.binding = dict(binding)
        self._validate_authority = validate_authority
        self._key = secrets.token_bytes(32)
        self._host_channel: TaskWorkerChannel | None = TaskWorkerChannel(
            self._key, self.binding, role="host"
        )
        executable = sys.executable
        pythonpath = [str(_SOURCE_ROOT)]
        if os.name == "nt" and sys.prefix != sys.base_prefix:
            executable = str(Path(sys.base_prefix) / "python.exe")
            pythonpath.extend(site.getsitepackages())
        self._home = tempfile.TemporaryDirectory(prefix="atlas-task-worker-")
        self._worker = WorkerProcess(
            [executable, "-m", "openjarvis.control.task_worker"],
            worker_kind=_WORKER_KIND,
            session_id=self.binding["supervisor_id"],
            env=safe_worker_environment(pythonpath=pythonpath, home=self._home.name),
            cwd=_PROJECT_ROOT,
            startup_timeout=startup_timeout,
            request_timeout=30.0,
            sandbox=SandboxPolicy(
                worker_kind=_WORKER_KIND,
                run_id=self.binding["worker_id"],
                executable=executable,
                max_processes=1,
                max_runtime=3600.0,
            ),
        )
        self._worker_pid: int | None = None
        self._io_lock = threading.Lock()
        self._authenticated = False
        self._started = False
        self._closed = False
        self._launch_attempted = False
        self._stop_attempted = False
        self._cleanup_unconfirmed = False
        self._cleanup_error: Exception | None = None
        self._home_cleanup_attempted = False
        self._request_thread: threading.Thread | None = None
        self._evidence: dict[str, Any] = {
            "controller_pid": os.getpid(),
            "worker_instance_id": self.binding["worker_id"],
            "supervisor_id": self.binding["supervisor_id"],
            "task_id": self.binding["task_id"],
            "agent_id": self.binding["agent_id"],
            "principal_id": self.binding["principal_id"],
            "attempt": self.binding["attempt"],
            "epoch": self.binding["epoch"],
            "checkpoint_version": self.binding["checkpoint_version"],
            "ipc_authenticated": False,
        }

    @property
    def evidence(self) -> dict[str, Any]:
        return dict(self._evidence)

    @property
    def pid(self) -> int | None:
        return self._worker_pid

    def start(self) -> None:
        if self._started or self._closed or self._cleanup_unconfirmed:
            raise TaskWorkerExecutionError("TASK_WORKER_LIFECYCLE_INVALID")
        try:
            self._launch_attempted = True
            ready = self._worker.start()
            actual_pid = self._worker.lifecycle.launcher_pid
            if not isinstance(actual_pid, int) or ready.get("pid") != actual_pid:
                raise TaskWorkerExecutionError("TASK_WORKER_PID_MISMATCH")
            self._worker_pid = actual_pid
            bootstrap = self._rpc_action(
                {
                    "op": "bootstrap",
                    "key": base64.b64encode(self._key).decode("ascii"),
                    "binding": self.binding,
                },
                timeout=5.0,
                monitor_authority=True,
            )
            first = self._open_reply(bootstrap)
            if (
                first["kind"] != "AUTHENTICATE"
                or first["payload"].get("pid") != actual_pid
                or first["payload"].get("worker_id") != self.binding["worker_id"]
            ):
                raise TaskWorkerExecutionError("TASK_WORKER_AUTH_FAILED")
            host_frame = self._seal(
                "AUTHENTICATE",
                request_id="host-auth-" + uuid.uuid4().hex,
                tool_call_id="host-auth",
                deadline=min(time.time() + 5.0, self.binding["lease_expires_at"]),
                payload={"supervisor_id": self.binding["supervisor_id"]},
            )
            second = self._open_reply(
                self._rpc_frame(host_frame, timeout=5.0, monitor_authority=True)
            )
            if (
                second["kind"] != "AUTHENTICATE"
                or second["payload"].get("pid") != actual_pid
                or second["payload"].get("authenticated") is not True
            ):
                raise TaskWorkerExecutionError("TASK_WORKER_AUTH_FAILED")
            self._authenticated = True
            self._started = True
            self._evidence.update({"worker_pid": actual_pid, "ipc_authenticated": True})
        except Exception as exc:
            self._abort()
            if isinstance(exc, TaskWorkerExecutionError):
                raise
            raise TaskWorkerExecutionError("TASK_WORKER_START_FAILED") from None

    def execute_tool(
        self,
        tool_call: Any,
        params: Mapping[str, Any],
        *,
        timeout: float,
        request_id: str | None = None,
        deadline: float | None = None,
        checkpoint_version: int | None = None,
    ) -> ToolResult:
        with self._io_lock:
            return self._execute_tool(
                tool_call,
                params,
                timeout=timeout,
                request_id=request_id,
                deadline=deadline,
                checkpoint_version=checkpoint_version,
            )

    def _execute_tool(
        self,
        tool_call: Any,
        params: Mapping[str, Any],
        *,
        timeout: float,
        request_id: str | None,
        deadline: float | None,
        checkpoint_version: int | None,
    ) -> ToolResult:
        if not self._authenticated or self._closed:
            raise TaskWorkerExecutionError("TASK_WORKER_NOT_READY")
        if not self._worker.running:
            self._abort()
            raise TaskWorkerExecutionError("TASK_WORKER_NOT_READY")
        if getattr(tool_call, "name", None) != "synthetic_echo":
            raise TaskWorkerExecutionError("TASK_WORKER_TOOL_NOT_ALLOWED")
        if not isinstance(params, Mapping):
            raise TaskWorkerExecutionError("TASK_WORKER_ARGUMENTS_INVALID")
        if (
            type(timeout) not in (int, float)
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise TaskWorkerExecutionError("TASK_WORKER_DEADLINE_INVALID")

        try:
            self._validate_authority()
            request_id = request_id or uuid.uuid4().hex
            deadline = (
                deadline
                if deadline is not None
                else min(time.time() + timeout, self.binding["lease_expires_at"])
            )
            checkpoint_version = (
                self.binding["checkpoint_version"]
                if checkpoint_version is None
                else checkpoint_version
            )
            if type(checkpoint_version) is not int or checkpoint_version < 0:
                raise ValueError("invalid checkpoint version")
            frame = self._seal(
                "EXECUTE_TOOL",
                request_id=request_id,
                tool_call_id=tool_call.id,
                deadline=deadline,
                payload={
                    "tool_name": tool_call.name,
                    "params": dict(params),
                    "checkpoint_version": checkpoint_version,
                },
            )
        except TaskWorkerExecutionError:
            raise
        except Exception:
            self._abort()
            raise TaskWorkerExecutionError("TASK_WORKER_AUTHORITY_REJECTED") from None

        try:
            response = self._rpc_frame(
                frame,
                timeout=float(timeout),
                monitor_authority=True,
                dispatched=True,
            )
            body = self._open_reply(response)
            payload = body["payload"]
            if (
                body["kind"] != "TOOL_RESULT"
                or payload.get("tool_name") != tool_call.name
                or payload.get("execution_pid") != self._worker_pid
                or payload.get("checkpoint_version") != checkpoint_version
                or type(payload.get("success")) is not bool
                or not isinstance(payload.get("content"), str)
            ):
                raise TaskWorkerExecutionError(
                    "TASK_WORKER_RESULT_INVALID", unknown_outcome=True
                )
            self._validate_authority()
            evidence = {
                **self._evidence,
                "tool_name": tool_call.name,
                "tool_execution_pid": payload["execution_pid"],
            }
            self._evidence.update(evidence)
            return ToolResult(
                tool_name=tool_call.name,
                content=payload["content"],
                success=payload["success"],
                metadata={"worker_execution": evidence},
            )
        except TaskWorkerExecutionError as exc:
            self._abort()
            if not exc.unknown_outcome:
                raise TaskWorkerExecutionError(
                    "TASK_WORKER_EXECUTION_UNKNOWN", unknown_outcome=True
                ) from None
            raise
        except Exception:
            self._abort()
            raise TaskWorkerExecutionError(
                "TASK_WORKER_EXECUTION_UNKNOWN", unknown_outcome=True
            ) from None

    def close(self) -> None:
        if self._closed:
            return
        if self._cleanup_unconfirmed:
            raise TaskWorkerExecutionError(
                "TASK_WORKER_CLEANUP_UNCONFIRMED", unknown_outcome=True
            ) from self._cleanup_error
        if not self._started:
            self._abort()
            return
        try:
            frame = self._seal(
                "SHUTDOWN",
                request_id="shutdown-" + uuid.uuid4().hex,
                tool_call_id="shutdown",
                deadline=min(time.time() + 2.0, self.binding["lease_expires_at"]),
                payload={},
            )
            body = self._open_reply(
                self._rpc_frame(frame, timeout=2.0, monitor_authority=False)
            )
            if body["kind"] != "EXIT":
                raise TaskWorkerExecutionError("TASK_WORKER_SHUTDOWN_FAILED")
            lifecycle = self._stop_worker(force=False, timeout=2.0)
            sandbox = lifecycle.sandbox
            self._validate_stop_lifecycle(lifecycle, clean=True)
            self._evidence.update(
                {
                    "job_exit_confirmed": True,
                    "worker_exit_code": lifecycle.exit_code,
                    "worker_forced_termination": False,
                    "process_wait_confirmed": True,
                    "exit_observed_at": sandbox["exit_observed_at"],
                }
            )
            self._cleanup_home_once()
            self._closed = True
            self._authenticated = False
        except TaskWorkerExecutionError:
            if not self._cleanup_unconfirmed:
                self._abort()
            raise
        except Exception:
            if not self._cleanup_unconfirmed:
                self._abort()
            raise TaskWorkerExecutionError("TASK_WORKER_SHUTDOWN_FAILED") from None

    def _stop_worker(self, *, force: bool, timeout: float = 1.0):
        if self._cleanup_unconfirmed:
            raise TaskWorkerExecutionError(
                "TASK_WORKER_CLEANUP_UNCONFIRMED", unknown_outcome=True
            ) from self._cleanup_error
        sandbox_process = self._worker._sandbox_process
        if sandbox_process is not None and sandbox_process.closed:
            return self._worker.lifecycle
        if self._stop_attempted:
            raise TaskWorkerExecutionError(
                "TASK_WORKER_CLEANUP_UNCONFIRMED", unknown_outcome=True
            )
        self._stop_attempted = True
        try:
            lifecycle = self._worker.stop(force=force, timeout=timeout)
        except Exception as exc:
            self._cleanup_error = exc
            self._cleanup_unconfirmed = True
            self._authenticated = False
            raise TaskWorkerExecutionError(
                "TASK_WORKER_CLEANUP_UNCONFIRMED", unknown_outcome=True
            ) from exc
        return lifecycle

    def _validate_stop_lifecycle(self, lifecycle: Any, *, clean: bool) -> None:
        sandbox = lifecycle.sandbox
        expected_pid = self._worker_pid or self._worker.lifecycle.launcher_pid
        valid = (
            lifecycle.cleaned is True
            and type(lifecycle.exit_code) is int
            and expected_pid is not None
            and sandbox.get("pid") == expected_pid
            and sandbox.get("pre_start_containment") is True
            and sandbox.get("process_in_job") is True
            and sandbox.get("job_exit_confirmed") is True
            and sandbox.get("process_wait_confirmed") is True
            and sandbox.get("observed_exit_code") == lifecycle.exit_code
            and type(sandbox.get("exit_observed_at")) in (int, float)
            and math.isfinite(sandbox["exit_observed_at"])
            and sandbox["exit_observed_at"] > 0
            and sandbox.get("closed") is True
            and type(sandbox.get("forced_termination")) is bool
        )
        if clean:
            valid = (
                valid
                and lifecycle.exit_code == 0
                and lifecycle.forced_termination is False
                and sandbox.get("forced_termination") is False
            )
        if not valid:
            error = TaskWorkerExecutionError("TASK_WORKER_EXIT_INVALID")
            self._cleanup_error = error
            self._cleanup_unconfirmed = True
            self._authenticated = False
            raise error

    def _cleanup_home_once(self) -> None:
        if self._home_cleanup_attempted:
            raise TaskWorkerExecutionError(
                "TASK_WORKER_CLEANUP_UNCONFIRMED", unknown_outcome=True
            ) from self._cleanup_error
        self._home_cleanup_attempted = True
        try:
            self._home.cleanup()
        except Exception as exc:
            self._cleanup_error = exc
            self._cleanup_unconfirmed = True
            raise TaskWorkerExecutionError(
                "TASK_WORKER_CLEANUP_UNCONFIRMED", unknown_outcome=True
            ) from exc

    def _rpc_action(
        self,
        action: Mapping[str, Any],
        *,
        timeout: float,
        monitor_authority: bool,
        unknown_outcome_on_authority_failure: bool = False,
    ) -> bytes:
        if monitor_authority:
            self._validate_authority()

        response_queue: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)

        def request_worker() -> None:
            try:
                value = self._worker.request(
                    request_id=uuid.uuid4().hex,
                    nonce=uuid.uuid4().hex,
                    observation_id=self.binding["supervisor_id"],
                    action=action,
                    timeout=timeout,
                )
                response_queue.put((True, value))
            except BaseException as exc:
                response_queue.put((False, exc))

        if self._request_thread is not None:
            raise TaskWorkerExecutionError(
                "TASK_WORKER_REQUEST_ALREADY_ACTIVE", unknown_outcome=True
            )
        request_thread = threading.Thread(target=request_worker, daemon=True)
        self._request_thread = request_thread
        request_thread.start()
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            try:
                succeeded, response = response_queue.get(
                    timeout=min(0.1, max(0.001, remaining))
                )
            except queue.Empty:
                if monitor_authority:
                    try:
                        self._validate_authority()
                    except Exception:
                        raise TaskWorkerExecutionError(
                            "TASK_WORKER_AUTHORITY_REJECTED",
                            unknown_outcome=unknown_outcome_on_authority_failure,
                        ) from None
                if time.monotonic() >= deadline:
                    raise WorkerProcessError(
                        "WORKER_TIMEOUT", pid=self._worker.pid, unknown=True
                    )
                continue
            request_thread.join(timeout=2.0)
            if request_thread.is_alive():
                raise TaskWorkerExecutionError(
                    "TASK_WORKER_REQUEST_THREAD_UNCONFIRMED",
                    unknown_outcome=unknown_outcome_on_authority_failure,
                )
            self._request_thread = None
            if not succeeded:
                raise response
            return self._response_frame(response)

    def _rpc_frame(
        self,
        frame: bytes,
        *,
        timeout: float,
        monitor_authority: bool,
        dispatched: bool = False,
    ) -> bytes:
        try:
            return self._rpc_action(
                {"op": "frame", "frame": base64.b64encode(frame).decode("ascii")},
                timeout=timeout,
                monitor_authority=monitor_authority,
                unknown_outcome_on_authority_failure=dispatched,
            )
        except WorkerProcessError:
            raise TaskWorkerExecutionError(
                "TASK_WORKER_IPC_FAILED", unknown_outcome=dispatched
            ) from None

    def _response_frame(self, response: Mapping[str, Any]) -> bytes:
        proposal = response.get("proposal")
        encoded = proposal.get("frame") if isinstance(proposal, Mapping) else None
        if response.get("status") != "PROPOSAL" or not isinstance(encoded, str):
            raise TaskWorkerExecutionError("TASK_WORKER_IPC_RESPONSE_INVALID")
        try:
            return base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            raise TaskWorkerExecutionError("TASK_WORKER_IPC_RESPONSE_INVALID") from None

    def _open_reply(self, frame: bytes) -> dict[str, Any]:
        if self._host_channel is None:
            raise TaskWorkerExecutionError("TASK_WORKER_CHANNEL_NOT_READY")
        try:
            return self._host_channel.open(frame)
        except Exception:
            raise TaskWorkerExecutionError("TASK_WORKER_AUTH_FAILED") from None

    def _seal(
        self,
        kind: str,
        *,
        request_id: str,
        tool_call_id: str,
        deadline: float,
        payload: Mapping[str, Any],
    ) -> bytes:
        if self._host_channel is None:
            raise TaskWorkerExecutionError("TASK_WORKER_CHANNEL_NOT_READY")
        try:
            return self._host_channel.seal(
                kind,
                message_id=uuid.uuid4().hex,
                request_id=request_id,
                tool_call_id=tool_call_id,
                deadline=deadline,
                cancellation="ACTIVE",
                payload=payload,
            )
        except Exception:
            raise TaskWorkerExecutionError("TASK_WORKER_IPC_REJECTED") from None

    def _abort(self) -> None:
        if self._closed:
            return
        if self._cleanup_unconfirmed:
            raise TaskWorkerExecutionError(
                "TASK_WORKER_CLEANUP_UNCONFIRMED", unknown_outcome=True
            ) from self._cleanup_error
        if not self._launch_attempted:
            try:
                self._cleanup_home_once()
            except Exception:
                raise
            self._authenticated = False
            self._closed = True
            return
        if self._worker._process is None and self._worker._sandbox_process is None:
            error = RuntimeError("worker launch outcome has no ownership evidence")
            self._cleanup_error = error
            self._cleanup_unconfirmed = True
            self._authenticated = False
            raise TaskWorkerExecutionError(
                "TASK_WORKER_CLEANUP_UNCONFIRMED", unknown_outcome=True
            ) from error
        try:
            lifecycle = self._stop_worker(force=True)
            self._validate_stop_lifecycle(lifecycle, clean=False)
            if self._request_thread is not None:
                if self._request_thread is threading.current_thread():
                    raise RuntimeError("worker request cannot join itself")
                self._request_thread.join(timeout=2.0)
                if self._request_thread.is_alive():
                    raise TimeoutError("worker request thread did not stop")
                self._request_thread = None
            self._evidence.update(
                {
                    "job_exit_confirmed": True,
                    "worker_exit_code": lifecycle.exit_code,
                    "worker_forced_termination": bool(lifecycle.forced_termination),
                    "process_wait_confirmed": True,
                    "exit_observed_at": lifecycle.sandbox["exit_observed_at"],
                }
            )
            self._cleanup_home_once()
            self._authenticated = False
            self._closed = True
        except Exception as exc:
            if not self._cleanup_unconfirmed:
                self._cleanup_error = exc
                self._cleanup_unconfirmed = True
            self._authenticated = False
            if isinstance(exc, TaskWorkerExecutionError):
                raise
            raise TaskWorkerExecutionError(
                "TASK_WORKER_CLEANUP_UNCONFIRMED", unknown_outcome=True
            ) from exc


def _write(frame: bytes) -> None:
    sys.stdout.buffer.write(frame + b"\n")
    sys.stdout.buffer.flush()


def _worker_result(body: Mapping[str, Any]) -> dict[str, Any]:
    payload = body["payload"]
    if (
        body["kind"] != "EXECUTE_TOOL"
        or payload.get("tool_name") != "synthetic_echo"
        or not isinstance(payload.get("params"), dict)
        or type(payload.get("checkpoint_version")) is not int
        or payload["checkpoint_version"] < 0
        or set(payload["params"]) != {"value"}
        or not isinstance(payload["params"]["value"], str)
        or len(payload["params"]["value"]) > 8192
    ):
        raise ValueError("tool not allowed")
    result = f"synthetic:{payload['params']['value']}"
    return {
        "tool_name": "synthetic_echo",
        "success": True,
        "content": result,
        "execution_pid": os.getpid(),
        "checkpoint_version": payload["checkpoint_version"],
    }


def _worker_main() -> int:
    _write(
        encode_ready(
            worker_kind=_WORKER_KIND,
            pid=os.getpid(),
            python=sys.version.split()[0],
            capabilities={"task_ipc_version": 1},
        )
    )
    channel = None
    binding: dict[str, Any] | None = None
    for line in iter(sys.stdin.buffer.readline, b""):
        shutdown = False
        if len(line) > MAX_RPC_BYTES + 1:
            return 2
        try:
            request = decode_request(line.rstrip(b"\r\n"))
            action = request["action"]
            if channel is None:
                if (
                    set(action) != {"op", "key", "binding"}
                    or action.get("op") != "bootstrap"
                    or request["session_id"] != action["binding"].get("supervisor_id")
                ):
                    return 2
                key = base64.b64decode(action["key"], validate=True)
                binding = dict(action["binding"])
                channel = TaskWorkerChannel(key, binding, role="worker")
                frame = channel.seal(
                    "AUTHENTICATE",
                    message_id=uuid.uuid4().hex,
                    request_id="worker-auth-" + uuid.uuid4().hex,
                    tool_call_id="worker-auth",
                    deadline=min(time.time() + 5.0, binding["lease_expires_at"]),
                    cancellation="ACTIVE",
                    payload={
                        "worker_id": binding["worker_id"],
                        "pid": os.getpid(),
                    },
                )
            else:
                if (
                    set(action) != {"op", "frame"}
                    or action.get("op") != "frame"
                    or request["session_id"] != binding["supervisor_id"]
                ):
                    return 2
                frame = base64.b64decode(action["frame"], validate=True)
                body = channel.open(frame)
                kind = body["kind"]
                if kind == "AUTHENTICATE":
                    if body["payload"].get("supervisor_id") != binding["supervisor_id"]:
                        return 2
                    reply_kind = "AUTHENTICATE"
                    reply_payload = {
                        "authenticated": True,
                        "pid": os.getpid(),
                        "worker_id": binding["worker_id"],
                    }
                elif kind == "EXECUTE_TOOL":
                    reply_kind = "TOOL_RESULT"
                    reply_payload = _worker_result(body)
                elif kind == "SHUTDOWN":
                    reply_kind = "EXIT"
                    reply_payload = {"pid": os.getpid()}
                    shutdown = True
                else:
                    return 2
                frame = channel.seal(
                    reply_kind,
                    message_id=uuid.uuid4().hex,
                    request_id=body["request_id"],
                    tool_call_id=body["tool_call_id"],
                    deadline=body["deadline"],
                    cancellation="ACTIVE",
                    payload=reply_payload,
                )
            response = encode_response(
                request_id=request["request_id"],
                session_id=request["session_id"],
                nonce=request["nonce"],
                status="PROPOSAL",
                proposal={"frame": base64.b64encode(frame).decode("ascii")},
            )
            _write(response)
            if shutdown:
                return 0
        except (ValueError, TypeError, UfoRpcError, PermissionError):
            return 2
    return 0 if channel is not None else 2


if __name__ == "__main__":
    raise SystemExit(_worker_main())
