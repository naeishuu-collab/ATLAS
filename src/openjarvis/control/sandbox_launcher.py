"""Explicit opt-in Windows Job Object launcher for proposal workers.

This is process lifecycle containment, not an AppContainer, token, ACL, or
network sandbox.  Unsupported or failed setup is terminal; callers must not
fall back to an unsandboxed launch.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SandboxLaunchError(RuntimeError):
    """A sandbox launch could not be established fail-closed."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}:{detail}" if detail else reason)


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """Per-run policy; providing this object is the explicit opt-in."""

    worker_kind: str
    run_id: str
    executable: str
    max_processes: int = 1
    max_runtime: float = 30.0

    def __post_init__(self) -> None:
        if not self.worker_kind.strip() or not self.run_id.strip():
            raise ValueError("SANDBOX_IDENTITY_REQUIRED")
        if not self.executable.strip():
            raise ValueError("SANDBOX_EXECUTABLE_REQUIRED")
        if self.max_processes < 1 or self.max_runtime <= 0:
            raise ValueError("SANDBOX_LIMIT_INVALID")


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("per_process_user_time_limit", ctypes.c_int64),
        ("per_job_user_time_limit", ctypes.c_int64),
        ("limit_flags", wintypes.DWORD),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority_class", wintypes.DWORD),
        ("scheduling_class", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_uint64)
        for name in (
            "read_operations",
            "write_operations",
            "other_operations",
            "read_bytes",
            "write_bytes",
            "other_bytes",
        )
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("basic", _BasicLimitInformation),
        ("io", _IoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    ]


class _BasicAccountingInformation(ctypes.Structure):
    _fields_ = [
        ("total_user_time", ctypes.c_int64),
        ("total_kernel_time", ctypes.c_int64),
        ("period_user_time", ctypes.c_int64),
        ("period_kernel_time", ctypes.c_int64),
        ("page_fault_count", wintypes.DWORD),
        ("total_processes", wintypes.DWORD),
        ("active_processes", wintypes.DWORD),
        ("terminated_processes", wintypes.DWORD),
    ]


JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000
CREATE_SUSPENDED = 0x00000004
TH32CS_SNAPTHREAD = 0x00000004
THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_LIMITED_INFORMATION = 0x0800
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
ERROR_NO_MORE_FILES = 18


class _ThreadEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
    ]


def _windows_kernel32():
    if os.name != "nt":
        raise SandboxLaunchError("SANDBOX_UNSUPPORTED_PLATFORM", os.name)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.QueryInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
    ]
    kernel.QueryInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.IsProcessInJob.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.BOOL),
    ]
    kernel.IsProcessInJob.restype = wintypes.BOOL
    kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel.GetProcessId.restype = wintypes.DWORD
    kernel.GetProcessIdOfThread.argtypes = [wintypes.HANDLE]
    kernel.GetProcessIdOfThread.restype = wintypes.DWORD
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
    kernel.Thread32First.restype = wintypes.BOOL
    kernel.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
    kernel.Thread32Next.restype = wintypes.BOOL
    kernel.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenThread.restype = wintypes.HANDLE
    kernel.ResumeThread.argtypes = [wintypes.HANDLE]
    kernel.ResumeThread.restype = wintypes.DWORD
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    return kernel


def _close_windows_handle(kernel, handle, failure: str) -> None:
    if handle and not kernel.CloseHandle(handle):
        raise SandboxLaunchError(failure, str(ctypes.get_last_error()))


def _require_process_live(kernel, process_handle) -> None:
    state = kernel.WaitForSingleObject(process_handle, 0)
    if state == WAIT_TIMEOUT:
        return
    if state == WAIT_OBJECT_0:
        raise SandboxLaunchError("SANDBOX_PROCESS_EXITED_BEFORE_RESUME")
    raise SandboxLaunchError(
        "SANDBOX_PROCESS_STATE_QUERY_FAILED", str(ctypes.get_last_error())
    )


def _resume_primary_thread(process: subprocess.Popen[bytes]) -> None:
    """Resume the sole thread of a still-live, suspended, job-assigned process."""

    kernel = _windows_kernel32()
    process_handle = process._handle
    handle_pid = kernel.GetProcessId(process_handle)
    if not handle_pid or handle_pid != process.pid:
        raise SandboxLaunchError(
            "SANDBOX_PROCESS_HANDLE_INVALID", str(ctypes.get_last_error())
        )
    _require_process_live(kernel, process_handle)

    snapshot = kernel.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    invalid = ctypes.c_void_p(-1).value
    if not snapshot or snapshot == invalid:
        raise SandboxLaunchError(
            "SANDBOX_THREAD_SNAPSHOT_FAILED", str(ctypes.get_last_error())
        )

    thread_handle = None
    primary_error: BaseException | None = None
    try:
        # The live Popen handle pins this process identity while its PID is used.
        entry = _ThreadEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        found = kernel.Thread32First(snapshot, ctypes.byref(entry))
        if not found and ctypes.get_last_error() != ERROR_NO_MORE_FILES:
            raise SandboxLaunchError(
                "SANDBOX_THREAD_ENUMERATION_FAILED", str(ctypes.get_last_error())
            )
        thread_id = None
        while found:
            if entry.th32OwnerProcessID == handle_pid:
                if thread_id is not None:
                    raise SandboxLaunchError("SANDBOX_PRIMARY_THREAD_AMBIGUOUS")
                thread_id = entry.th32ThreadID
            entry.dwSize = ctypes.sizeof(entry)
            found = kernel.Thread32Next(snapshot, ctypes.byref(entry))
            if not found and ctypes.get_last_error() != ERROR_NO_MORE_FILES:
                raise SandboxLaunchError(
                    "SANDBOX_THREAD_ENUMERATION_FAILED", str(ctypes.get_last_error())
                )
        if thread_id is None:
            raise SandboxLaunchError("SANDBOX_PRIMARY_THREAD_NOT_FOUND")

        thread_handle = kernel.OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
            False,
            thread_id,
        )
        if not thread_handle:
            raise SandboxLaunchError(
                "SANDBOX_PRIMARY_THREAD_OPEN_FAILED", str(ctypes.get_last_error())
            )
        thread_pid = kernel.GetProcessIdOfThread(thread_handle)
        if not thread_pid:
            raise SandboxLaunchError(
                "SANDBOX_PRIMARY_THREAD_OWNER_QUERY_FAILED",
                str(ctypes.get_last_error()),
            )
        if thread_pid != handle_pid:
            raise SandboxLaunchError("SANDBOX_PRIMARY_THREAD_OWNER_MISMATCH")
        _require_process_live(kernel, process_handle)

        previous_suspend_count = kernel.ResumeThread(thread_handle)
        if previous_suspend_count == 0xFFFFFFFF:
            raise SandboxLaunchError(
                "SANDBOX_THREAD_RESUME_FAILED", str(ctypes.get_last_error())
            )
        if previous_suspend_count != 1:
            raise SandboxLaunchError(
                "SANDBOX_THREAD_SUSPEND_COUNT_INVALID",
                str(previous_suspend_count),
            )
    except BaseException as exc:
        primary_error = exc

    close_errors = []
    for handle, reason in (
        (thread_handle, "SANDBOX_PRIMARY_THREAD_CLOSE_FAILED"),
        (snapshot, "SANDBOX_THREAD_SNAPSHOT_CLOSE_FAILED"),
    ):
        try:
            _close_windows_handle(kernel, handle, reason)
        except BaseException as exc:
            close_errors.append(exc)

    if primary_error is not None:
        if close_errors:
            detail = "; ".join(str(error) for error in close_errors)
            raise primary_error from SandboxLaunchError(
                "SANDBOX_THREAD_HANDLE_CLOSE_FAILED", detail
            )
        raise primary_error
    if close_errors:
        if len(close_errors) == 1:
            raise close_errors[0]
        raise SandboxLaunchError(
            "SANDBOX_THREAD_HANDLE_CLOSE_FAILED",
            "; ".join(str(error) for error in close_errors),
        )


class _JobObject:
    def __init__(self, policy: SandboxPolicy) -> None:
        self.policy = policy
        self.kernel = _windows_kernel32()
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise SandboxLaunchError(
                "SANDBOX_JOB_CREATE_FAILED", str(ctypes.get_last_error())
            )
        try:
            limits = _ExtendedLimitInformation()
            limits.basic.limit_flags = (
                JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            limits.basic.active_process_limit = policy.max_processes
            if not self.kernel.SetInformationJobObject(
                self.handle,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
            ):
                raise SandboxLaunchError(
                    "SANDBOX_JOB_LIMIT_FAILED", str(ctypes.get_last_error())
                )
            self.limits = {
                "limit_flags": int(limits.basic.limit_flags),
                "active_process_limit": int(limits.basic.active_process_limit),
            }
        except BaseException as exc:
            try:
                self.close()
            except BaseException as close_error:
                raise exc from close_error
            raise

    def assign(self, process: subprocess.Popen[bytes]) -> None:
        handle = getattr(process, "_handle", None)
        if not handle or not self.kernel.AssignProcessToJobObject(
            self.handle, handle
        ):
            raise SandboxLaunchError(
                "SANDBOX_JOB_ASSIGN_FAILED", str(ctypes.get_last_error())
            )

    def contains(self, process: subprocess.Popen[bytes]) -> bool:
        result = wintypes.BOOL()
        if not self.kernel.IsProcessInJob(
            process._handle, self.handle, ctypes.byref(result)
        ):
            raise SandboxLaunchError(
                "SANDBOX_JOB_QUERY_FAILED", str(ctypes.get_last_error())
            )
        return bool(result.value)

    def terminate(self) -> None:
        if self.handle and not self.kernel.TerminateJobObject(self.handle, 1):
            raise SandboxLaunchError(
                "SANDBOX_JOB_TERMINATE_FAILED", str(ctypes.get_last_error())
            )

    def active_processes(self) -> int:
        accounting = _BasicAccountingInformation()
        if not self.handle or not self.kernel.QueryInformationJobObject(
            self.handle,
            JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            ctypes.byref(accounting),
            ctypes.sizeof(accounting),
            None,
        ):
            raise SandboxLaunchError(
                "SANDBOX_JOB_QUERY_FAILED", str(ctypes.get_last_error())
            )
        return int(accounting.active_processes)

    def close(self) -> None:
        if self.handle:
            handle = self.handle
            _close_windows_handle(self.kernel, handle, "SANDBOX_JOB_CLOSE_FAILED")
            self.handle = None


class SandboxedProcess:
    """A Popen process with an owned Job Object and bounded lifetime."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        job: _JobObject,
        policy: SandboxPolicy,
        process_in_job: bool,
        pre_start_containment: bool = False,
    ) -> None:
        self.process = process
        self.job = job
        self.policy = policy
        self.process_in_job = process_in_job
        self.pre_start_containment = pre_start_containment
        self.timed_out = False
        self.forced_termination = False
        self.closed = False
        self.job_exit_confirmed = False
        self.process_wait_confirmed = False
        self.exit_observed_at: float | None = None
        self.observed_exit_code: int | None = None
        self._termination_error: SandboxLaunchError | None = None
        self._first_error: Exception | None = None
        self._job_lock = threading.RLock()
        self._timer = threading.Timer(policy.max_runtime, self._deadline)
        self._timer.daemon = True
        self._timer.start()

    def _deadline(self) -> None:
        try:
            self._terminate_job(deadline=True)
        except Exception as exc:
            if self._first_error is None:
                self._first_error = exc

    def terminate(self) -> None:
        self._terminate_job(deadline=False)

    def _terminate_job(self, *, deadline: bool) -> None:
        with self._job_lock:
            if self.closed:
                return
            try:
                if not self.job.active_processes():
                    return
            except SandboxLaunchError:
                # A failed query provides no proof that the job is empty.
                pass
            if deadline:
                self.timed_out = True
            self.forced_termination = True
            try:
                self.job.terminate()
            except SandboxLaunchError as exc:
                if self._termination_error is None:
                    self._termination_error = exc
                if self._first_error is None:
                    self._first_error = SandboxLaunchError(
                        "SANDBOX_TERMINATE_FAILED", str(exc)
                    )
                try:
                    self.job.close()
                except Exception as close_error:
                    raise exc from close_error
                raise

    def evidence(self) -> dict[str, Any]:
        return {
            "worker_kind": self.policy.worker_kind,
            "run_id": self.policy.run_id,
            "pid": self.process.pid,
            "job_object": True,
            "process_in_job": self.process_in_job,
            "job_limits": dict(self.job.limits),
            "assignment_after_process_start": not self.pre_start_containment,
            "pre_start_containment": self.pre_start_containment,
            "max_runtime": self.policy.max_runtime,
            "close_fds_requested": True,
            "timed_out": self.timed_out,
            "forced_termination": self.forced_termination,
            "closed": self.closed,
            "job_exit_confirmed": self.job_exit_confirmed,
            "process_wait_confirmed": self.process_wait_confirmed,
            "exit_observed_at": self.exit_observed_at,
            "observed_exit_code": self.observed_exit_code,
        }

    def close(self) -> dict[str, Any]:
        self._timer.cancel()
        self._timer.join()
        with self._job_lock:
            if not self.closed:
                poll = getattr(self.process, "poll", None)
                try:
                    process_running = not callable(poll) or poll() is None
                except Exception as exc:
                    process_running = True
                    if self._first_error is None:
                        self._first_error = exc
                if process_running:
                    try:
                        self.terminate()
                    except Exception as exc:
                        if self._first_error is None:
                            self._first_error = exc
                else:
                    # Let Job accounting catch up with an already-exited process
                    # before deciding that a descendant needs forced termination.
                    deadline = time.monotonic() + 0.1
                    active = 1
                    while active:
                        try:
                            active = self.job.active_processes()
                        except Exception as exc:
                            active = 1
                            if self._first_error is None:
                                self._first_error = exc
                            break
                        if not active or time.monotonic() >= deadline:
                            break
                        threading.Event().wait(0.01)
                    if active:
                        try:
                            self.terminate()
                        except Exception as exc:
                            if self._first_error is None:
                                self._first_error = exc
                try:
                    self.observed_exit_code = self.process.wait(timeout=2.0)
                    self.process_wait_confirmed = True
                    self.exit_observed_at = time.time()
                except Exception as exc:
                    if self._first_error is None:
                        self._first_error = exc
                if self.process_wait_confirmed:
                    deadline = time.monotonic() + 2.0
                    while True:
                        try:
                            active = self.job.active_processes()
                        except Exception as exc:
                            if self._first_error is None:
                                self._first_error = exc
                            break
                        if not active:
                            self.job_exit_confirmed = (
                                self.pre_start_containment and self.process_in_job
                            )
                            break
                        if time.monotonic() >= deadline:
                            if self._first_error is None:
                                self._first_error = SandboxLaunchError(
                                    "SANDBOX_JOB_EXIT_UNCONFIRMED"
                                )
                            break
                        threading.Event().wait(0.01)
                try:
                    self.job.close()
                except Exception as exc:
                    if self._first_error is None:
                        self._first_error = exc
                else:
                    self.closed = True
            if self._first_error is not None:
                raise self._first_error from self._termination_error
            return self.evidence()


class SandboxLauncher:
    """Launch only an explicitly approved executable inside a Job Object."""

    def __init__(self, policy: SandboxPolicy) -> None:
        self.policy = policy

    def launch(
        self,
        command: Sequence[str],
        *,
        cwd: str | Path | None,
        env: Mapping[str, str],
    ) -> SandboxedProcess:
        if os.name != "nt":
            raise SandboxLaunchError("SANDBOX_UNSUPPORTED_PLATFORM", os.name)
        if isinstance(command, (str, bytes)) or not command:
            raise SandboxLaunchError("SANDBOX_COMMAND_INVALID")
        if any(not isinstance(part, str) or not part.strip() for part in command):
            raise SandboxLaunchError("SANDBOX_COMMAND_INVALID")
        if _normalized(command[0]) != _normalized(self.policy.executable):
            raise SandboxLaunchError("SANDBOX_EXECUTABLE_NOT_ALLOWLISTED")
        process: subprocess.Popen[bytes] | None = None
        job: _JobObject | None = None
        try:
            job = _JobObject(self.policy)
            creationflags = (
                CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW | CREATE_SUSPENDED
            )
            process = subprocess.Popen(
                list(command),
                cwd=str(cwd) if cwd is not None else None,
                env=dict(env),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                close_fds=True,
                creationflags=creationflags,
            )
            job.assign(process)
            in_job = job.contains(process)
            if not in_job:
                raise SandboxLaunchError("SANDBOX_JOB_MEMBERSHIP_NOT_PROVEN")
            _resume_primary_thread(process)
            return SandboxedProcess(process, job, self.policy, in_job, True)
        except SandboxLaunchError as exc:
            cleanup_error = _cleanup_failed_launch(process, job)
            if cleanup_error is not None:
                raise exc from cleanup_error
            raise
        except (OSError, ValueError) as exc:
            cleanup_error = _cleanup_failed_launch(process, job)
            detail = str(exc)
            if cleanup_error is not None:
                detail = f"{detail}; {cleanup_error}"
            raise SandboxLaunchError("SANDBOX_LAUNCH_FAILED", detail) from exc
        except BaseException as exc:
            cleanup_error = _cleanup_failed_launch(process, job)
            if cleanup_error is not None:
                raise exc from cleanup_error
            raise


def _cleanup_failed_launch(
    process: subprocess.Popen[bytes] | None,
    job: _JobObject | None,
) -> SandboxLaunchError | None:
    errors = []
    if job is not None:
        try:
            job.terminate()
        except Exception as exc:
            errors.append(exc)
    if process is not None:
        try:
            running = process.poll() is None
        except Exception as exc:
            running = True
            errors.append(exc)
        if running:
            try:
                process.kill()
            except Exception as exc:
                errors.append(exc)
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
                process.wait(timeout=2.0)
            except Exception as exc:
                errors.append(exc)
        except Exception as exc:
            errors.append(exc)
    if job is not None:
        try:
            job.close()
        except Exception as exc:
            errors.append(exc)
    if errors:
        return SandboxLaunchError(
            "SANDBOX_LAUNCH_CLEANUP_FAILED",
            "; ".join(str(error) for error in errors),
        )
    return None


def _normalized(value: str) -> str:
    return os.path.normcase(os.path.abspath(value))


def new_run_id(worker_kind: str) -> str:
    if not worker_kind.strip():
        raise ValueError("SANDBOX_IDENTITY_REQUIRED")
    return f"{worker_kind}-{uuid.uuid4().hex}"


__all__ = [
    "SandboxLaunchError",
    "SandboxLauncher",
    "SandboxPolicy",
    "SandboxedProcess",
    "new_run_id",
]
