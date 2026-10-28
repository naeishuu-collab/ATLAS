"""Host-owned lifecycle for proposal-only SDK worker processes."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from openjarvis.control.sandbox_launcher import (
    SandboxedProcess,
    SandboxLauncher,
    SandboxLaunchError,
    SandboxPolicy,
)
from openjarvis.control.ufo_worker_rpc import (
    MAX_RPC_BYTES,
    UfoRpcError,
    decode_ready,
    decode_response,
    decode_worker_error,
    encode_request,
)


class WorkerProcessError(RuntimeError):
    """A worker lifecycle or bounded RPC operation failed."""

    def __init__(
        self,
        reason: str,
        *,
        pid: int | None = None,
        retryable: bool = False,
        unknown: bool = False,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.pid = pid
        self.retryable = retryable
        self.unknown = unknown


@dataclass(slots=True)
class WorkerLifecycle:
    worker_kind: str
    pid: int | None = None
    launcher_pid: int | None = None
    python: str = ""
    exit_code: int | None = None
    started: bool = False
    ready: bool = False
    timed_out: bool = False
    forced_termination: bool = False
    cleaned: bool = False
    requests: int = 0
    stderr: str = ""
    capabilities: dict[str, Any] = field(default_factory=dict)
    sandbox: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "worker_kind": self.worker_kind,
            "pid": self.pid,
            "launcher_pid": self.launcher_pid,
            "python": self.python,
            "exit_code": self.exit_code,
            "started": self.started,
            "ready": self.ready,
            "timed_out": self.timed_out,
            "forced_termination": self.forced_termination,
            "cleaned": self.cleaned,
            "requests": self.requests,
            "stderr": self.stderr,
            "capabilities": dict(self.capabilities),
            "sandbox": dict(self.sandbox),
        }


def safe_worker_environment(
    *,
    pythonpath: Sequence[str] = (),
    home: str | Path | None = None,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a small environment without credentials or arbitrary passthrough."""

    allowed = {
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "WINDIR",
    }
    environment = {
        key: value for key, value in os.environ.items() if key in allowed
    }
    environment.update({"PYTHONNOUSERSITE": "1", "PYTHONUTF8": "1"})
    if home is not None:
        home_path = Path(home).resolve()
        environment["HOME"] = str(home_path)
        environment["USERPROFILE"] = str(home_path)
        if len(home_path.parts) >= 2 and home_path.drive:
            environment["HOMEDRIVE"] = home_path.drive
            environment["HOMEPATH"] = str(home_path)[len(home_path.drive) :]
    paths = [str(path) for path in pythonpath if str(path).strip()]
    if paths:
        environment["PYTHONPATH"] = os.pathsep.join(paths)
    if extra:
        for key, value in extra.items():
            if key not in {"PYTHONPATH", "PYTHONNOUSERSITE", "PYTHONUTF8"}:
                raise ValueError("WORKER_ENV_EXTRA_NOT_ALLOWLISTED")
            environment[key] = str(value)
    return environment


class WorkerProcess:
    """Start one bounded proposal worker and own its complete lifecycle."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        worker_kind: str,
        session_id: str,
        env: Mapping[str, str],
        cwd: str | Path | None = None,
        startup_timeout: float = 5.0,
        request_timeout: float = 2.0,
        sandbox: SandboxPolicy | None = None,
    ) -> None:
        if not command or any(not str(part).strip() for part in command):
            raise ValueError("WORKER_COMMAND_REQUIRED")
        if not worker_kind.strip() or not session_id.strip():
            raise ValueError("WORKER_BINDING_REQUIRED")
        if startup_timeout <= 0 or request_timeout <= 0:
            raise ValueError("WORKER_TIMEOUT_INVALID")
        self.command = tuple(str(part) for part in command)
        self.worker_kind = worker_kind
        self.session_id = session_id
        self.env = dict(env)
        self.cwd = str(cwd) if cwd is not None else None
        self.startup_timeout = startup_timeout
        self.request_timeout = request_timeout
        self.sandbox_policy = sandbox
        self.lifecycle = WorkerLifecycle(worker_kind)
        self._process: subprocess.Popen[bytes] | None = None
        self._sandbox_process: SandboxedProcess | None = None
        self._stdout: queue.Queue[bytes | None] = queue.Queue()
        self._stderr_chunks: list[bytes] = []
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None

    @property
    def pid(self) -> int | None:
        return self.lifecycle.pid

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def start(self) -> dict[str, Any]:
        if self._process is not None:
            raise WorkerProcessError("WORKER_ALREADY_STARTED", pid=self.pid)
        if self.sandbox_policy is not None:
            try:
                self._sandbox_process = SandboxLauncher(
                    self.sandbox_policy
                ).launch(self.command, cwd=self.cwd, env=self.env)
            except SandboxLaunchError as exc:
                self.lifecycle.cleaned = True
                raise WorkerProcessError(
                    f"SANDBOX_LAUNCH_FAILED:{exc}", pid=self.pid
                ) from exc
            self._process = self._sandbox_process.process
            self.lifecycle.sandbox = self._sandbox_process.evidence()
        else:
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            self._process = subprocess.Popen(
                self.command,
                cwd=self.cwd,
                env=self.env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                creationflags=creationflags,
                start_new_session=os.name != "nt",
            )
        self.lifecycle.launcher_pid = self._process.pid
        self.lifecycle.pid = self._process.pid
        self.lifecycle.started = True
        self._stdout_thread = threading.Thread(
            target=self._read_stdout,
            name=f"atlas-worker-stdout-{self.pid}",
            daemon=True,
        )
        self._stderr_thread = threading.Thread(
            target=self._read_stderr,
            name=f"atlas-worker-stderr-{self.pid}",
            daemon=True,
        )
        self._stdout_thread.start()
        self._stderr_thread.start()
        raw = self._next_frame(self.startup_timeout)
        try:
            ready = decode_ready(raw, worker_kind=self.worker_kind)
        except UfoRpcError as exc:
            self.stop(force=True)
            raise WorkerProcessError(
                f"WORKER_READY_INVALID:{exc}", pid=self.pid
            ) from exc
        if not isinstance(ready["pid"], int) or ready["pid"] <= 0:
            self.stop(force=True)
            raise WorkerProcessError("WORKER_PID_INVALID", pid=self.pid)
        self.lifecycle.pid = ready["pid"]
        self.lifecycle.python = ready["python"]
        self.lifecycle.capabilities = dict(ready["capabilities"])
        self.lifecycle.ready = True
        return ready

    def request(
        self,
        *,
        request_id: str,
        nonce: str,
        observation_id: str,
        action: Mapping[str, Any],
        timeout: float | None = None,
    ) -> dict[str, Any]:
        raw = encode_request(
            request_id=request_id,
            session_id=self.session_id,
            nonce=nonce,
            observation_id=observation_id,
            action=action,
        )
        return self._request_raw(
            raw,
            request_id=request_id,
            session_id=self.session_id,
            nonce=nonce,
            timeout=timeout,
        )

    def _request_raw(
        self,
        raw: bytes,
        *,
        request_id: str,
        session_id: str,
        nonce: str,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        if not self.running or not self.lifecycle.ready:
            raise WorkerProcessError("WORKER_NOT_READY", pid=self.pid)
        if len(raw) > MAX_RPC_BYTES:
            raise WorkerProcessError("RPC_MESSAGE_TOO_LARGE", pid=self.pid)
        process = self._process
        assert process is not None
        try:
            assert process.stdin is not None
            process.stdin.write(raw + b"\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise WorkerProcessError("WORKER_PIPE_BROKEN", pid=self.pid) from exc
        self.lifecycle.requests += 1
        response = self._next_frame(timeout or self.request_timeout)
        try:
            payload = json.loads(response.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise WorkerProcessError("RPC_JSON_INVALID", pid=self.pid) from exc
        if isinstance(payload, dict) and payload.get("kind") == "atlas_worker_error":
            try:
                error = decode_worker_error(response)
            except UfoRpcError as exc:
                raise WorkerProcessError(
                    f"WORKER_ERROR_INVALID:{exc}", pid=self.pid
                ) from exc
            raise WorkerProcessError(error["error"], pid=self.pid)
        try:
            return decode_response(
                response,
                request_id=request_id,
                session_id=session_id,
                nonce=nonce,
            )
        except UfoRpcError as exc:
            raise WorkerProcessError(str(exc), pid=self.pid) from exc

    def stop(self, *, force: bool = False, timeout: float = 1.0) -> WorkerLifecycle:
        process = self._process
        if process is None:
            self.lifecycle.cleaned = True
            return self.lifecycle
        if force:
            self.lifecycle.forced_termination = True
            self._kill_process_tree(process)
        else:
            try:
                if process.stdin is not None:
                    process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.lifecycle.forced_termination = True
            self._kill_process_tree(process)
            process.wait(timeout=timeout)
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=0.2)
        if self._stdout_thread is not None:
            self._stdout_thread.join(timeout=0.2)
        self.lifecycle.exit_code = process.returncode
        self.lifecycle.stderr = b"".join(self._stderr_chunks).decode(
            "utf-8", errors="replace"
        )[-4096:]
        self.lifecycle.cleaned = process.poll() is not None
        if self._sandbox_process is not None:
            self.lifecycle.sandbox = self._sandbox_process.close()
        return self.lifecycle

    def _kill_process_tree(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        if self._sandbox_process is not None:
            self._sandbox_process.terminate()
            return
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            process.kill()

    def _next_frame(self, timeout: float) -> bytes:
        try:
            frame = self._stdout.get(timeout=timeout)
        except queue.Empty as exc:
            self.lifecycle.timed_out = True
            self.stop(force=True)
            raise WorkerProcessError(
                "WORKER_TIMEOUT",
                pid=self.pid,
                unknown=True,
            ) from exc
        if frame is None:
            if self._sandbox_process is not None and self._sandbox_process.timed_out:
                self.lifecycle.timed_out = True
                raise WorkerProcessError(
                    "WORKER_TIMEOUT", pid=self.pid, unknown=True
                ) from None
            raise WorkerProcessError("WORKER_EXITED", pid=self.pid) from None
        return frame

    def _read_stdout(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            self._stdout.put(None)
            return
        for line in iter(process.stdout.readline, b""):
            self._stdout.put(line.rstrip(b"\r\n"))
        self._stdout.put(None)

    def _read_stderr(self) -> None:
        process = self._process
        if process is None or process.stderr is None:
            return
        for chunk in iter(lambda: process.stderr.read(4096), b""):
            self._stderr_chunks.append(chunk)

    def __enter__(self) -> "WorkerProcess":
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()


__all__ = [
    "WorkerLifecycle",
    "WorkerProcess",
    "WorkerProcessError",
    "safe_worker_environment",
]
