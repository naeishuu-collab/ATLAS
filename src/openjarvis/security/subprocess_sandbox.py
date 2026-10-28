"""Environment filtering and owned process cleanup, not an OS security sandbox."""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_owned_jobs: dict[int, tuple[object, subprocess.Popen]] = {}
_jobs_lock = threading.RLock()


class _WindowsJob:
    """Own a kernel job handle; attach the existing process handle, never reopen PID."""

    def __init__(self, proc: subprocess.Popen):
        import ctypes
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("process_time", ctypes.c_longlong),
                ("job_time", ctypes.c_longlong),
                ("flags", wintypes.DWORD),
                ("min_ws", ctypes.c_size_t),
                ("max_ws", ctypes.c_size_t),
                ("active", wintypes.DWORD),
                ("affinity", ctypes.c_size_t),
                ("priority", wintypes.DWORD),
                ("scheduling", wintypes.DWORD),
            ]

        class Counters(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_ulonglong)
                for name in (
                    "read_ops",
                    "write_ops",
                    "other_ops",
                    "read_bytes",
                    "write_bytes",
                    "other_bytes",
                )
            ]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("basic", BasicLimits),
                ("io", Counters),
                ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t),
                ("peak_process", ctypes.c_size_t),
                ("peak_job", ctypes.c_size_t),
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        kernel.CreateJobObjectW.restype = wintypes.HANDLE
        kernel.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        kernel.SetInformationJobObject.restype = wintypes.BOOL
        kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateJobObject.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        self._kernel = kernel
        self._handle = kernel.CreateJobObjectW(None, None)
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            limits = ExtendedLimits()
            limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not kernel.SetInformationJobObject(
                self._handle,
                9,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if not kernel.AssignProcessToJobObject(self._handle, int(proc._handle)):
                raise ctypes.WinError(ctypes.get_last_error())
        except Exception:
            self.close()
            raise

    def terminate(self) -> None:
        import ctypes

        if not self._kernel.TerminateJobObject(self._handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if self._handle:
            self._kernel.CloseHandle(self._handle)
            self._handle = None


# Safe environment variables to pass through
_SAFE_ENV_VARS = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LANG",
        "TERM",
        "SHELL",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "TZ",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "COMSPEC",
    }
)


@dataclass(slots=True)
class SandboxResult:
    """Result of a sandboxed subprocess execution."""

    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    timed_out: bool = False
    killed: bool = False
    started: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False


def build_safe_env(
    passthrough: Optional[List[str]] = None,
    extra: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Build a sanitized environment dict.

    Only copies safe vars from current env, plus any in passthrough list.
    Extra vars are added directly.
    """
    env: Dict[str, str] = {}
    allowed = _SAFE_ENV_VARS | frozenset(passthrough or [])
    for key in allowed:
        val = os.environ.get(key)
        if val is not None:
            env[key] = val
    if extra:
        env.update(extra)
    return env


def kill_process_tree(pid: int) -> None:
    """Kill a process and all its children (best effort)."""
    if os.name == "nt":
        with _jobs_lock:
            owned = _owned_jobs.get(pid)
            if owned is not None:
                owned[0].terminate()
        # Refuse to act on an unowned/recycled PID. No taskkill-by-PID fallback.
        return
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (OSError, ProcessLookupError) as exc:
        logger.debug("Failed to terminate process %d: %s", pid, exc)
    try:
        os.kill(pid, signal.SIGKILL)
    except (OSError, ProcessLookupError) as exc:
        logger.debug("Failed to kill process %d: %s", pid, exc)


def run_sandboxed(
    command: str | List[str],
    *,
    timeout: float = 30.0,
    working_dir: Optional[str] = None,
    env_passthrough: Optional[List[str]] = None,
    env_extra: Optional[Dict[str, str]] = None,
    max_output_bytes: int = 102_400,
) -> SandboxResult:
    """Deny generic subprocess execution until host isolation is approved.

    Features:
    - Clean environment (only safe vars passed through)
    - Timeout enforcement with process tree kill
    - Output truncation
    - New process group for clean cleanup
    """
    # Environment filtering and Job Object cleanup are not an OS sandbox.
    # Keep this direct helper fail-closed so callers cannot bypass tool gates.
    return SandboxResult(
        stderr="SUBPROCESS_SANDBOX_UNAVAILABLE: approved OS sandbox required"
    )

    env = build_safe_env(passthrough=env_passthrough, extra=env_extra)
    if working_dir and not os.path.isdir(working_dir):
        return SandboxResult(stderr="Requested working directory is unavailable")
    if timeout <= 0 or max_output_bytes < 1:
        return SandboxResult(stderr="Timeout and output limit must be positive")
    cwd = working_dir or None

    result = SandboxResult()
    proc = None
    job = None
    try:
        process_options = {}
        if os.name == "nt":
            process_options["creationflags"] = subprocess.CREATE_NO_WINDOW
        else:
            process_options["start_new_session"] = True
        proc = subprocess.Popen(
            command,
            # This API explicitly runs caller-provided shell commands.
            shell=isinstance(command, str),  # nosec B602
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            cwd=cwd,
            **process_options,
        )
        result.started = True
        if os.name == "nt":
            try:
                job = _WindowsJob(proc)
            except Exception:
                proc.kill()
                proc.wait(timeout=5)
                raise
            with _jobs_lock:
                _owned_jobs[proc.pid] = (job, proc)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            result.stdout = stdout[:max_output_bytes] if stdout else ""
            result.stderr = stderr[:max_output_bytes] if stderr else ""
            result.stdout_truncated = len(stdout or "") > max_output_bytes
            result.stderr_truncated = len(stderr or "") > max_output_bytes
            result.returncode = proc.returncode
        except subprocess.TimeoutExpired:
            kill_process_tree(proc.pid)
            proc.communicate(timeout=5)
            result.timed_out = True
            result.killed = True
            result.returncode = -1
            result.stdout = "(timed out)"
            result.stderr = ""
    except OSError as exc:
        result.stderr = f"Execution error: {exc}"
        result.returncode = -1
    finally:
        if job is not None:
            with _jobs_lock:
                _owned_jobs.pop(proc.pid, None)
                job.close()
        if proc is not None:
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    pipe.close()

    return result


__all__ = ["SandboxResult", "build_safe_env", "kill_process_tree", "run_sandboxed"]
