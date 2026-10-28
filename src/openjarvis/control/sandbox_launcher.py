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


JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_NO_WINDOW = 0x08000000


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
    return kernel


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
        except BaseException:
            self.close()
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

    def close(self) -> None:
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


class SandboxedProcess:
    """A Popen process with an owned Job Object and bounded lifetime."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        job: _JobObject,
        policy: SandboxPolicy,
        process_in_job: bool,
    ) -> None:
        self.process = process
        self.job = job
        self.policy = policy
        self.process_in_job = process_in_job
        self.timed_out = False
        self.forced_termination = False
        self.closed = False
        self._timer = threading.Timer(policy.max_runtime, self._deadline)
        self._timer.daemon = True
        self._timer.start()

    def _deadline(self) -> None:
        if self.process.poll() is None:
            self.timed_out = True
            self.forced_termination = True
            try:
                self.job.terminate()
            except SandboxLaunchError:
                pass

    def terminate(self) -> None:
        if self.process.poll() is None:
            self.forced_termination = True
            self.job.terminate()

    def evidence(self) -> dict[str, Any]:
        return {
            "worker_kind": self.policy.worker_kind,
            "run_id": self.policy.run_id,
            "pid": self.process.pid,
            "job_object": True,
            "process_in_job": self.process_in_job,
            "job_limits": dict(self.job.limits),
            "assignment_after_process_start": True,
            "max_runtime": self.policy.max_runtime,
            "close_fds_requested": True,
            "timed_out": self.timed_out,
            "forced_termination": self.forced_termination,
            "closed": self.closed,
        }

    def close(self) -> dict[str, Any]:
        if self.closed:
            return self.evidence()
        self._timer.cancel()
        if self.process.poll() is None:
            self.terminate()
            self.process.wait(timeout=2.0)
        self.job.close()
        self.closed = True
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
            creationflags = (
                CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
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
            job = _JobObject(self.policy)
            # shortcut: post-start assignment; native CreateProcess is next upgrade.
            job.assign(process)
            in_job = job.contains(process)
            if not in_job:
                raise SandboxLaunchError("SANDBOX_JOB_MEMBERSHIP_NOT_PROVEN")
            return SandboxedProcess(process, job, self.policy, in_job)
        except SandboxLaunchError:
            if job is not None:
                try:
                    job.terminate()
                except SandboxLaunchError:
                    pass
            if process is not None:
                try:
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2.0)
            if job is not None:
                job.close()
            raise
        except (OSError, ValueError) as exc:
            if job is not None:
                try:
                    job.terminate()
                except SandboxLaunchError:
                    pass
                job.close()
            if process is not None:
                try:
                    process.kill()
                    process.wait(timeout=2.0)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            raise SandboxLaunchError("SANDBOX_LAUNCH_FAILED", str(exc)) from exc


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
