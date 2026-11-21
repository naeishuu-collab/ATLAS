"""Host-owned subprocess for a single authenticated synthetic task worker.

The host owns this object's private pipes and must outlive any Controller using
it.  This is not a Controller transport, reconnect protocol, or host authority.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
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
from ctypes import wintypes
from pathlib import Path
from typing import Any, Callable, Mapping

from openjarvis.control.sandbox_launcher import (
    JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
    SandboxLauncher,
    SandboxPolicy,
    _BasicAccountingInformation,
    _windows_kernel32,
)
from openjarvis.control.task_worker import (
    TaskWorkerExecutionError,
    TaskWorkerSupervisor,
)
from openjarvis.control.task_worker_ipc import TaskWorkerChannel
from openjarvis.control.worker_process import safe_worker_environment
from openjarvis.core.types import ToolCall, ToolResult

_SOURCE_ROOT = Path(__file__).resolve().parents[2]
_MAX_LINE = 131072


def _evidence_key(key: bytes) -> bytes:
    return hmac.new(key, b"atlas-supervisor-evidence-key-v1", hashlib.sha256).digest()


def _evidence_mac(key: bytes, record: Mapping[str, Any]) -> str:
    data = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hmac.new(
        key, b"atlas-supervisor-exit-v1\0" + data, hashlib.sha256
    ).hexdigest()


def verify_signed_exit_record(
    envelope: Mapping[str, Any], key: bytes, binding: Mapping[str, Any]
) -> bool:
    try:
        if (
            not isinstance(key, bytes)
            or len(key) < 32
            or set(envelope) != {"record", "mac"}
        ):
            return False
        record, mac = envelope["record"], envelope["mac"]
        if not isinstance(record, dict) or not isinstance(mac, str):
            return False
        evidence = record["evidence"]
        return bool(
            hmac.compare_digest(mac, _evidence_mac(key, record))
            and record["version"] == 1
            and record["sequence"] == 1
            and record["binding"] == dict(binding)
            and type(record["supervisor_pid"]) is int
            and record["supervisor_pid"] > 0
            and type(record["supervisor_creation_time"]) is int
            and record["supervisor_creation_time"] > 0
            and type(record["worker_creation_time"]) is int
            and record["worker_creation_time"] > 0
            and isinstance(record["job_id"], str)
            and len(record["job_id"]) == 32
            and isinstance(evidence, dict)
            and evidence.get("controller_pid") == record["supervisor_pid"]
            and type(evidence.get("worker_pid")) is int
            and evidence["worker_pid"] > 0
            and evidence["worker_pid"] != record["supervisor_pid"]
            and evidence.get("worker_instance_id") == binding["worker_id"]
            and evidence.get("supervisor_id") == binding["supervisor_id"]
            and evidence.get("task_id") == binding["task_id"]
            and evidence.get("agent_id") == binding["agent_id"]
            and evidence.get("principal_id") == binding["principal_id"]
            and evidence.get("attempt") == binding["attempt"]
            and type(evidence.get("epoch")) is int
            and evidence["epoch"] == binding["epoch"]
            and evidence.get("job_exit_confirmed") is True
            and evidence.get("process_wait_confirmed") is True
            and type(evidence.get("worker_exit_code")) is int
            and 0 <= evidence["worker_exit_code"] <= 0xFFFFFFFF
            and type(evidence.get("worker_forced_termination")) is bool
            and (
                evidence["worker_forced_termination"]
                or evidence["worker_exit_code"] == 0
            )
            and type(evidence.get("exit_observed_at")) in (int, float)
            and math.isfinite(evidence["exit_observed_at"])
            and evidence["exit_observed_at"] > 0
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def _read(stream: Any) -> bytes:
    line = stream.readline(_MAX_LINE + 1)
    if not line or len(line) > _MAX_LINE or not line.endswith(b"\n"):
        raise PermissionError("supervisor pipe closed or invalid")
    return base64.b64decode(line.strip(), validate=True)


def _write(stream: Any, frame: bytes) -> None:
    remaining = memoryview(base64.b64encode(frame) + b"\n")
    while remaining:
        written = stream.write(remaining)
        if not isinstance(written, int) or written <= 0:
            raise OSError("supervisor pipe write failed")
        remaining = remaining[written:]
    stream.flush()


def _frame(
    channel: TaskWorkerChannel,
    kind: str,
    request: str,
    call: str,
    deadline: float,
    payload: Mapping[str, Any],
) -> bytes:
    return channel.seal(
        kind,
        message_id=uuid.uuid4().hex,
        request_id=request,
        tool_call_id=call,
        deadline=deadline,
        cancellation="ACTIVE",
        payload=payload,
    )


class HostTaskSupervisorProcess:
    """Own a supervisor process and authorize each worker authority check.

    Only a trusted host may own this object; its private pipe is not a way to
    authenticate a Controller. The host must journal dispatch separately.
    """

    def __init__(
        self, binding: Mapping[str, Any], *, validate_authority: Callable[[], Any]
    ) -> None:
        if not callable(validate_authority):
            raise ValueError("host authority required")
        self.binding = dict(binding)
        self._validate_authority = validate_authority
        self._key = secrets.token_bytes(32)
        self._channel = TaskWorkerChannel(self._key, self.binding, role="host")
        self._home = tempfile.TemporaryDirectory(prefix="atlas-host-supervisor-")
        executable = sys.executable
        pythonpath = [str(_SOURCE_ROOT)]
        if os.name == "nt" and sys.prefix != sys.base_prefix:
            executable = str(Path(sys.base_prefix) / "python.exe")
            pythonpath.extend(site.getsitepackages())
        policy = SandboxPolicy(
            "host-supervisor",
            self.binding["supervisor_id"],
            executable,
            max_processes=256,
            max_runtime=24 * 60 * 60,
        )
        try:
            command = [
                executable,
                "-m",
                "openjarvis.control.host_task_supervisor",
                "--child",
            ]
            self._sandbox_process = SandboxLauncher(policy).launch(
                command,
                cwd=str(_SOURCE_ROOT.parent),
                env=safe_worker_environment(
                    pythonpath=pythonpath, home=self._home.name
                ),
            )
        except Exception:
            self._home.cleanup()
            raise
        self._process = self._sandbox_process.process
        self._lock = threading.Lock()
        self._output: queue.Queue[bytes | None] = queue.Queue()
        self._stderr_tail = bytearray()
        self._closed = False
        self._shutdown_requested = False
        self._started = False
        self._worker_stopped = False
        self._exit_record: dict[str, Any] | None = None
        self._evidence: dict[str, Any] = {}
        self._worker_handle: Any = None
        self._job_handle: Any = None
        self._creation_time: int | None = None
        self._worker_pid: int | None = None
        self._supervisor_creation_time: int | None = None
        self._job_id: str | None = None
        self._handle_lock = threading.Lock()
        self._handle_close_attempted: set[str] = set()
        self._handle_close_unconfirmed: set[str] = set()
        self._stream_close_attempted: set[str] = set()
        self._cleanup_unconfirmed = False
        self._cleanup_error: Exception | None = None
        self._watch_error: Exception | None = None
        self._worker_job_watch: threading.Thread | None = None
        self._reader = threading.Thread(target=self._read_output, daemon=True)
        self._stderr_reader = threading.Thread(target=self._drain_stderr, daemon=True)
        try:
            self._reader.start()
            self._stderr_reader.start()
            bootstrap = json.dumps(
                {
                    "key": base64.b64encode(self._key).decode("ascii"),
                    "binding": self.binding,
                }
            ).encode("utf-8")
            _write(self._process.stdin, bootstrap)
        except Exception:
            self._abort()
            raise TaskWorkerExecutionError("HOST_SUPERVISOR_START_FAILED") from None

    def _read_output(self) -> None:
        try:
            while True:
                self._output.put(_read(self._process.stdout))
        except Exception:
            self._output.put(None)

    def _drain_stderr(self) -> None:
        try:
            while True:
                chunk = self._process.stderr.read(4096)
                if not chunk:
                    break
                self._stderr_tail.extend(chunk)
                if len(self._stderr_tail) > 4096:
                    del self._stderr_tail[:-4096]
        except Exception:
            pass

    @property
    def pid(self) -> int:
        return self._process.pid

    @property
    def evidence(self) -> dict[str, Any]:
        return dict(self._evidence)

    @property
    def exit_record(self) -> dict[str, Any] | None:
        return json.loads(json.dumps(self._exit_record)) if self._exit_record else None

    @property
    def evidence_verification_key(self) -> bytes:
        """Trusted host only; deliver to an authorized verifier confidentially."""
        return _evidence_key(self._key)

    @staticmethod
    def _kernel() -> Any:
        kernel = _windows_kernel32()
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.DuplicateHandle.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        kernel.DuplicateHandle.restype = wintypes.BOOL
        kernel.GetProcessId.argtypes = [wintypes.HANDLE]
        kernel.GetProcessId.restype = wintypes.DWORD
        kernel.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        kernel.GetProcessTimes.restype = wintypes.BOOL
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.GetExitCodeProcess.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel.GetExitCodeProcess.restype = wintypes.BOOL
        return kernel

    def _duplicate_handles(self, payload: Mapping[str, Any]) -> None:
        kernel = self._kernel()
        try:
            for name, field in (
                ("worker_handle", "_worker_handle"),
                ("job_handle", "_job_handle"),
            ):
                value = payload.get(name)
                if type(value) is not int or value <= 0:
                    raise PermissionError("supervisor handle invalid")
                duplicate = wintypes.HANDLE()
                if not kernel.DuplicateHandle(
                    wintypes.HANDLE(int(self._process._handle)),
                    wintypes.HANDLE(value),
                    kernel.GetCurrentProcess(),
                    ctypes.byref(duplicate),
                    0,
                    False,
                    2,
                ):
                    raise PermissionError("supervisor handle duplication failed")
                setattr(self, field, duplicate)
            member = wintypes.BOOL()
            if (
                kernel.GetProcessId(self._worker_handle)
                != payload["evidence"]["worker_pid"]
                or not kernel.IsProcessInJob(
                    self._worker_handle, self._job_handle, ctypes.byref(member)
                )
                or not member.value
            ):
                raise PermissionError("worker job membership not verified")
            self._creation_time = self._process_creation(kernel, self._worker_handle)
            self._worker_pid = payload["evidence"]["worker_pid"]
            self._supervisor_creation_time = self._process_creation(
                kernel, wintypes.HANDLE(int(self._process._handle))
            )
            if (
                payload.get("worker_creation_time") != self._creation_time
                or payload.get("supervisor_creation_time")
                != self._supervisor_creation_time
                or not isinstance(payload.get("job_id"), str)
                or len(payload["job_id"]) != 32
            ):
                raise PermissionError("supervisor process identity mismatch")
            self._job_id = payload["job_id"]
        except Exception:
            raise

    @staticmethod
    def _process_creation(kernel: Any, handle: Any) -> int:
        created, exited, kernel_time, user_time = (
            wintypes.FILETIME() for _ in range(4)
        )
        if not kernel.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel_time),
            ctypes.byref(user_time),
        ):
            raise PermissionError("worker process identity unavailable")
        return (created.dwHighDateTime << 32) | created.dwLowDateTime

    def _os_exit_verified(self, expected_exit_code: int = 0) -> bool:
        if not self._worker_handle or not self._job_handle:
            return False
        kernel = self._kernel()
        accounting, exit_code = _BasicAccountingInformation(), wintypes.DWORD()
        return bool(
            kernel.WaitForSingleObject(self._worker_handle, 0) == 0
            and kernel.GetProcessId(self._worker_handle) == self._worker_pid
            and kernel.GetExitCodeProcess(self._worker_handle, ctypes.byref(exit_code))
            and exit_code.value == expected_exit_code
            and kernel.QueryInformationJobObject(
                self._job_handle,
                JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                ctypes.byref(accounting),
                ctypes.sizeof(accounting),
                None,
            )
            and accounting.active_processes == 0
            and self._process_creation(kernel, self._worker_handle)
            == self._creation_time
        )

    def release_exit_evidence(self) -> None:
        if self._process.poll() is None or not self._sandbox_process.closed:
            raise TaskWorkerExecutionError(
                "HOST_SUPERVISOR_HANDLES_STILL_OWNED", unknown_outcome=True
            )
        with self._handle_lock:
            kernel = self._kernel()
            for field in ("_worker_handle", "_job_handle"):
                handle = getattr(self, field)
                if handle:
                    if field in self._handle_close_attempted:
                        raise TaskWorkerExecutionError(
                            "HOST_SUPERVISOR_HANDLE_CLOSE_UNCONFIRMED",
                            unknown_outcome=True,
                        )
                    self._handle_close_attempted.add(field)
                    try:
                        closed = kernel.CloseHandle(handle)
                    except Exception:
                        self._handle_close_unconfirmed.add(field)
                        raise
                    if not closed:
                        self._handle_close_unconfirmed.add(field)
                        raise OSError(
                            ctypes.get_last_error(),
                            "CloseHandle did not confirm supervisor handle release",
                        )
                    setattr(self, field, None)

    def _watch_supervisor(self) -> None:
        self._process.wait()
        try:
            with self._handle_lock:
                if not self._job_handle:
                    return
                kernel = self._kernel()
                accounting = _BasicAccountingInformation()
                if not kernel.QueryInformationJobObject(
                    self._job_handle,
                    JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                    ctypes.byref(accounting),
                    ctypes.sizeof(accounting),
                    None,
                ):
                    raise OSError(
                        ctypes.get_last_error(),
                        "worker Job accounting query failed",
                    )
                if accounting.active_processes:
                    if not kernel.TerminateJobObject(self._job_handle, 1):
                        raise OSError(
                            ctypes.get_last_error(),
                            "worker Job termination was not confirmed",
                        )
                    deadline = time.monotonic() + 2.0
                    while True:
                        accounting = _BasicAccountingInformation()
                        if not kernel.QueryInformationJobObject(
                            self._job_handle,
                            JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
                            ctypes.byref(accounting),
                            ctypes.sizeof(accounting),
                            None,
                        ):
                            raise OSError(
                                ctypes.get_last_error(),
                                "worker Job drain query failed",
                            )
                        if not accounting.active_processes:
                            return
                        if time.monotonic() >= deadline:
                            raise TimeoutError("worker Job drain was not confirmed")
                        threading.Event().wait(0.01)
        except Exception as exc:
            self._watch_error = exc

    def _exchange(
        self,
        kind: str,
        payload: Mapping[str, Any],
        *,
        timeout: float,
        call: str = "control",
        request: str | None = None,
        deadline: float | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            if (
                self._closed
                or self._cleanup_unconfirmed
                or self._process.poll() is not None
            ):
                raise TaskWorkerExecutionError("HOST_SUPERVISOR_UNAVAILABLE")
            request = request or uuid.uuid4().hex
            deadline = min(
                deadline or time.time() + timeout,
                time.time() + timeout,
                self.binding["lease_expires_at"],
            )
            try:
                _write(
                    self._process.stdin,
                    _frame(self._channel, kind, request, call, deadline, payload),
                )
                while True:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        raise TimeoutError("supervisor deadline expired")
                    raw = self._output.get(timeout=remaining)
                    if raw is None:
                        raise EOFError("supervisor pipe closed")
                    body = self._channel.open(raw)
                    if body["kind"] == "HEARTBEAT":
                        try:
                            self._validate_authority()
                            authorized = True
                        except Exception:
                            authorized = False
                        _write(
                            self._process.stdin,
                            _frame(
                                self._channel,
                                "AUTHENTICATE",
                                body["request_id"],
                                body["tool_call_id"],
                                body["deadline"],
                                {"authorized": authorized},
                            ),
                        )
                        continue
                    if body["request_id"] != request or body["tool_call_id"] != call:
                        raise PermissionError("supervisor response mismatch")
                    if body["kind"] == "EXIT" and body["payload"].get("error"):
                        if (
                            kind != "EXECUTE_TOOL"
                            or body["payload"]["error"] != "unknown"
                        ):
                            raise PermissionError("supervisor rejected request")
                        self._evidence = dict(body["payload"]["evidence"])
                        self._exit_record = body["payload"].get("exit_record")
                        self._worker_stopped = True
                        if not self._verified_stopped_worker():
                            raise PermissionError("worker exit evidence invalid")
                    return body
            except Exception:
                self._abort()
                raise TaskWorkerExecutionError(
                    "HOST_SUPERVISOR_OUTCOME_UNKNOWN"
                    if kind == "EXECUTE_TOOL"
                    else "HOST_SUPERVISOR_REQUEST_FAILED",
                    unknown_outcome=kind == "EXECUTE_TOOL",
                ) from None

    def start(self) -> None:
        if self._started or self._closed or self._cleanup_unconfirmed:
            raise TaskWorkerExecutionError("HOST_SUPERVISOR_LIFECYCLE_INVALID")
        body = self._exchange("START", {}, timeout=10)
        payload = body["payload"]
        sandbox = payload.get("sandbox")
        if (
            body["kind"] != "AUTHENTICATE"
            or payload.get("supervisor_pid") != self.pid
            or not isinstance(sandbox, dict)
            or sandbox.get("pre_start_containment") is not True
            or sandbox.get("process_in_job") is not True
            or sandbox.get("pid") != payload.get("evidence", {}).get("worker_pid")
            or sandbox.get("job_limits", {}).get("active_process_limit") != 1
        ):
            self._abort()
            raise TaskWorkerExecutionError("HOST_SUPERVISOR_IDENTITY_INVALID")
        try:
            self._duplicate_handles(payload)
            self._worker_job_watch = threading.Thread(
                target=self._watch_supervisor, daemon=True
            )
            self._worker_job_watch.start()
        except Exception:
            self._abort()
            raise TaskWorkerExecutionError("HOST_SUPERVISOR_HANDLE_INVALID") from None
        self._evidence = dict(payload["evidence"])
        self._started = True

    def execute_tool(
        self,
        tool_call: ToolCall,
        params: Mapping[str, Any],
        *,
        timeout: float,
        request_id: str,
        deadline: float,
        checkpoint_version: int,
    ) -> ToolResult:
        if (
            not self._started
            or self._worker_stopped
            or tool_call.name != "synthetic_echo"
        ):
            raise TaskWorkerExecutionError("HOST_SUPERVISOR_TOOL_NOT_ALLOWED")
        body = self._exchange(
            "EXECUTE_TOOL",
            {
                "name": tool_call.name,
                "params": dict(params),
                "checkpoint_version": checkpoint_version,
            },
            timeout=timeout,
            call=tool_call.id,
            request=request_id,
            deadline=deadline,
        )
        payload = body["payload"]
        if body["kind"] == "EXIT" and payload.get("error") == "unknown":
            raise TaskWorkerExecutionError(
                "HOST_SUPERVISOR_OUTCOME_UNKNOWN", unknown_outcome=True
            )
        if (
            body["kind"] != "TOOL_RESULT"
            or payload.get("tool_name") != tool_call.name
            or type(payload.get("success")) is not bool
            or not isinstance(payload.get("content"), str)
        ):
            self._abort()
            raise TaskWorkerExecutionError(
                "HOST_SUPERVISOR_RESULT_INVALID", unknown_outcome=True
            )
        self._evidence = dict(payload["evidence"])
        return ToolResult(
            tool_name=tool_call.name,
            content=payload["content"],
            success=payload["success"],
            metadata={"worker_execution": self.evidence},
        )

    def stop_worker(self) -> None:
        """Stop the owned worker while keeping the supervisor process alive."""
        if not self._started or self._worker_stopped:
            raise TaskWorkerExecutionError("HOST_SUPERVISOR_LIFECYCLE_INVALID")
        body = self._exchange("CANCEL", {}, timeout=5)
        if body["kind"] != "EXIT":
            self._abort()
            raise TaskWorkerExecutionError("HOST_SUPERVISOR_EXIT_INVALID")
        self._evidence = dict(body["payload"]["evidence"])
        self._exit_record = body["payload"].get("exit_record")
        self._worker_stopped = True
        if not self._verified_stopped_worker():
            self._abort()
            raise TaskWorkerExecutionError("HOST_SUPERVISOR_EXIT_INVALID")

    def _verified_stopped_worker(self) -> bool:
        try:
            record = self._exit_record["record"]
            return bool(
                verify_signed_exit_record(
                    self._exit_record, self.evidence_verification_key, self.binding
                )
                and record["job_id"] == self._job_id
                and record["worker_creation_time"] == self._creation_time
                and record["supervisor_creation_time"] == self._supervisor_creation_time
                and self._os_exit_verified(record["evidence"]["worker_exit_code"])
                and self._process.poll() is None
            )
        except Exception:
            return False

    def close(self) -> None:
        if self._closed:
            return
        if self._cleanup_unconfirmed:
            raise TaskWorkerExecutionError(
                "HOST_SUPERVISOR_CLEANUP_UNCONFIRMED", unknown_outcome=True
            ) from self._cleanup_error
        self._shutdown_requested = True
        try:
            body = self._exchange("SHUTDOWN", {}, timeout=5)
            if body["kind"] != "EXIT":
                raise TaskWorkerExecutionError("HOST_SUPERVISOR_EXIT_INVALID")
            self._evidence = dict(body["payload"]["evidence"])
            self._close_stream("stdin")
            if self._process.wait(timeout=5) != 0:
                raise TaskWorkerExecutionError("HOST_SUPERVISOR_EXIT_INVALID")
            self._finish_owned_process()
        except Exception as exc:
            if not self._closed and not self._cleanup_unconfirmed:
                self._abort()
            if isinstance(exc, TaskWorkerExecutionError):
                raise
            raise TaskWorkerExecutionError(
                "HOST_SUPERVISOR_EXIT_INVALID", unknown_outcome=True
            ) from exc

    def _close_stream(self, name: str) -> None:
        stream = getattr(self._process, name)
        if stream is None or stream.closed:
            return
        if name in self._stream_close_attempted:
            raise OSError(f"supervisor {name} close is unconfirmed")
        self._stream_close_attempted.add(name)
        stream.close()
        if not stream.closed:
            raise OSError(f"supervisor {name} close is unconfirmed")

    def _finish_owned_process(
        self, *, prior_error: Exception | None = None
    ) -> dict[str, Any]:
        if self._cleanup_unconfirmed:
            raise TaskWorkerExecutionError(
                "HOST_SUPERVISOR_CLEANUP_UNCONFIRMED", unknown_outcome=True
            ) from self._cleanup_error
        try:
            evidence = self._sandbox_process.close()
            if (
                evidence.get("pid") != self._process.pid
                or evidence.get("pre_start_containment") is not True
                or evidence.get("process_in_job") is not True
                or evidence.get("process_wait_confirmed") is not True
                or evidence.get("job_exit_confirmed") is not True
                or evidence.get("closed") is not True
                or type(evidence.get("observed_exit_code")) is not int
                or evidence.get("observed_exit_code") != self._process.returncode
                or self._process.poll() is None
            ):
                raise PermissionError("supervisor Job exit was not confirmed")
            for thread in (
                self._worker_job_watch,
                self._reader,
                self._stderr_reader,
            ):
                if thread is not None:
                    thread.join(timeout=5)
                    if thread.is_alive():
                        raise TimeoutError(
                            "supervisor output or Job watch did not stop"
                        )
            if self._watch_error is not None:
                raise RuntimeError(
                    "worker Job drain was not confirmed"
                ) from self._watch_error
            first_error = prior_error
            for name in ("stdin", "stdout", "stderr"):
                try:
                    self._close_stream(name)
                except Exception as exc:
                    if first_error is None:
                        first_error = exc
            if first_error is not None:
                raise first_error
            self.release_exit_evidence()
            self._home.cleanup()
            self._closed = True
            return evidence
        except Exception as exc:
            self._cleanup_error = exc
            self._cleanup_unconfirmed = True
            raise TaskWorkerExecutionError(
                "HOST_SUPERVISOR_CLEANUP_UNCONFIRMED", unknown_outcome=True
            ) from exc

    def verify_exit_evidence(self, evidence: Mapping[str, Any]) -> bool:
        """Verify evidence received on the owned channel and the supervisor handle."""
        try:
            os_verified = self._os_exit_verified(evidence["worker_exit_code"])
        except Exception:
            os_verified = False
        return (
            (
                (self._closed and self._process.returncode == 0)
                or (self._worker_stopped and self._process.poll() is None)
            )
            and os_verified
            and isinstance(evidence, Mapping)
            and dict(evidence) == self._evidence
            and evidence.get("controller_pid") == self.pid
            and evidence.get("worker_pid") == self._worker_pid
            and evidence.get("supervisor_id") == self.binding["supervisor_id"]
            and evidence.get("worker_instance_id") == self.binding["worker_id"]
            and evidence.get("job_exit_confirmed") is True
            and evidence.get("process_wait_confirmed") is True
            and type(evidence.get("worker_exit_code")) is int
            and type(evidence.get("worker_forced_termination")) is bool
        )

    def _abort(self) -> None:
        if self._closed:
            return
        if self._cleanup_unconfirmed:
            raise TaskWorkerExecutionError(
                "HOST_SUPERVISOR_CLEANUP_UNCONFIRMED", unknown_outcome=True
            ) from self._cleanup_error
        pipe_error = None
        try:
            self._close_stream("stdin")
        except Exception as exc:
            pipe_error = exc
        try:
            self._finish_owned_process(prior_error=pipe_error)
        except Exception as exc:
            if not self._cleanup_unconfirmed:
                self._cleanup_error = exc
                self._cleanup_unconfirmed = True
            if isinstance(exc, TaskWorkerExecutionError):
                raise
            raise TaskWorkerExecutionError(
                "HOST_SUPERVISOR_CLEANUP_UNCONFIRMED", unknown_outcome=True
            ) from exc


def _child() -> int:
    worker: TaskWorkerSupervisor | None = None
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    try:
        config = json.loads(_read(source))
        key = base64.b64decode(config["key"], validate=True)
        binding = config["binding"]
        channel = TaskWorkerChannel(key, binding, role="worker")
        operation: dict[str, Any] = {}

        def validate_authority() -> None:
            request = "authority-" + uuid.uuid4().hex
            deadline = min(operation["deadline"], binding["lease_expires_at"])
            _write(
                sink, _frame(channel, "HEARTBEAT", request, "authority", deadline, {})
            )
            response = channel.open(_read(source))
            if (
                response["kind"] != "AUTHENTICATE"
                or response["request_id"] != request
                or response["tool_call_id"] != "authority"
                or response["payload"] != {"authorized": True}
            ):
                raise PermissionError("host authority denied")

        worker_stopped = False
        exit_record: dict[str, Any] | None = None
        job_id = uuid.uuid4().hex
        worker_creation_time = None
        kernel = HostTaskSupervisorProcess._kernel()
        supervisor_creation_time = HostTaskSupervisorProcess._process_creation(
            kernel, kernel.GetCurrentProcess()
        )

        def sign_exit() -> dict[str, Any]:
            record = {
                "version": 1,
                "sequence": 1,
                "binding": binding,
                "supervisor_pid": os.getpid(),
                "evidence": worker.evidence,
                "job_id": job_id,
                "worker_creation_time": worker_creation_time,
                "supervisor_creation_time": supervisor_creation_time,
            }
            return {"record": record, "mac": _evidence_mac(_evidence_key(key), record)}

        while True:
            operation = channel.open(_read(source))
            kind = operation["kind"]
            if kind == "START" and worker is None:
                worker = TaskWorkerSupervisor(
                    binding, validate_authority=validate_authority
                )
                worker.start()
                sandbox = worker._worker._sandbox_process
                worker_creation_time = HostTaskSupervisorProcess._process_creation(
                    kernel, wintypes.HANDLE(int(sandbox.process._handle))
                )
                reply, payload = (
                    "AUTHENTICATE",
                    {
                        "supervisor_pid": os.getpid(),
                        "evidence": worker.evidence,
                        "sandbox": worker._worker.lifecycle.sandbox,
                        "worker_handle": int(sandbox.process._handle),
                        "job_handle": int(sandbox.job.handle),
                        "job_id": job_id,
                        "worker_creation_time": worker_creation_time,
                        "supervisor_creation_time": supervisor_creation_time,
                    },
                )
            elif kind == "EXECUTE_TOOL" and worker is not None and not worker_stopped:
                data = operation["payload"]
                call = ToolCall(operation["tool_call_id"], data["name"], "{}")
                try:
                    result = worker.execute_tool(
                        call,
                        data["params"],
                        timeout=operation["deadline"] - time.time(),
                        request_id=operation["request_id"],
                        deadline=operation["deadline"],
                        checkpoint_version=data["checkpoint_version"],
                    )
                    reply, payload = (
                        "TOOL_RESULT",
                        {
                            "tool_name": result.tool_name,
                            "content": result.content,
                            "success": result.success,
                            "evidence": worker.evidence,
                        },
                    )
                except TaskWorkerExecutionError as exc:
                    if not exc.unknown_outcome:
                        raise
                    worker_stopped = True
                    exit_record = sign_exit()
                    reply, payload = (
                        "EXIT",
                        {
                            "error": "unknown",
                            "evidence": worker.evidence,
                            "exit_record": exit_record,
                        },
                    )
            elif kind in {"CANCEL", "SHUTDOWN"} and worker is not None:
                if not worker_stopped:
                    worker.close()
                    worker_stopped = True
                    exit_record = sign_exit()
                reply, payload = (
                    "EXIT",
                    {
                        "evidence": worker.evidence,
                        "exit_record": exit_record,
                    },
                )
            else:
                raise PermissionError("supervisor operation rejected")
            _write(
                sink,
                _frame(
                    channel,
                    reply,
                    operation["request_id"],
                    operation["tool_call_id"],
                    operation["deadline"],
                    payload,
                ),
            )
            if kind == "SHUTDOWN":
                return 0
    except Exception:
        if worker is not None:
            worker._abort()
        return 1


if __name__ == "__main__":
    raise SystemExit(_child() if sys.argv[1:] == ["--child"] else 2)
