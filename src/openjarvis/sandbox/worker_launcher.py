"""Fail-closed sandboxed RLMWorker launch (AppContainer + staged runtime).

Owns the full lifecycle: stage -> verify -> profile -> RX grant -> verify
-> pipes -> job -> launch -> identity/image proof -> PipeConnection.

Any stage failure raises SandboxError with a taxonomy code; callers must
treat it as terminal (no unsandboxed fallback). No network, no provider
secrets, no provider stack in the worker.
"""

from __future__ import annotations

import os
import struct
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

from openjarvis.sandbox import appcontainer as ac

STAGE_TIMEOUT_S = 600.0

# Child bootstrap: fd-backed Connection speaking the multiprocessing
# length-prefix framing (struct ">I"), then the REAL worker entrypoint.
# poll() uses PeekNamedPipe via ctypes so broker RPC also works.
CHILD_BOOTSTRAP = (
    "import ctypes, os, struct, sys\n"
    "sys.path.insert(0, {worker!r})\n"
    "from ctypes import wintypes\n"
    "from openjarvis.agents import rlm_worker as W\n"
    "def _read_exactly(n):\n"
    " out = bytearray()\n"
    " while len(out) < n:\n"
    "  c = os.read(0, n - len(out))\n"
    "  if not c: raise EOFError('stdin closed')\n"
    "  out += c\n"
    " return bytes(out)\n"
    "def _poll(timeout_s):\n"
    " import time as _t, msvcrt\n"
    " k32 = ctypes.WinDLL('kernel32', use_last_error=True)\n"
    " h = msvcrt.get_osfhandle(0)\n"
    " avail = wintypes.DWORD()\n"
    " end = _t.monotonic() + max(0.0, timeout_s)\n"
    " while True:\n"
    "  ok = k32.PeekNamedPipe(h, None, 0, None, ctypes.byref(avail), None)\n"
    "  if not ok: return False\n"
    "  if avail.value > 0: return True\n"
    "  if _t.monotonic() >= end: return False\n"
    "  _t.sleep(0.005)\n"
    "class FDConn:\n"
    " def send_bytes(self, data):\n"
    "  buf = struct.pack('>I', len(data)) + bytes(data)\n"
    "  mv = memoryview(buf)\n"
    "  while mv:\n"
    "   n = os.write(1, mv); mv = mv[n:]\n"
    " def recv_bytes(self, max_n):\n"
    "  (ln,) = struct.unpack('>I', _read_exactly(4))\n"
    "  if not 0 < ln <= max_n: raise ValueError('bad frame')\n"
    "  return _read_exactly(ln)\n"
    " def poll(self, timeout):\n"
    "  return _poll(timeout)\n"
    " def close(self):\n"
    "  pass\n"
    "W._worker_entrypoint(FDConn(), {session!r}, {nonce!r}, "
    "{max_chars!r}, {max_req!r}, {rpc!r})"
)


@dataclass
class SandboxSpec:
    """Explicit opt-in sandbox configuration (OFF unless provided)."""

    build_parent: Path = Path("C:/Users/yingz/AppData/Local/Temp/opencode")
    startup_timeout_s: float = 60.0
    keep_runtime_dir: bool = False
    # Test/shared runs may stage once and reuse: when set, no build and
    # no runtime-dir removal occur. Production leaves this unset (owned).
    runtime_root: Optional[Path] = None


class PipeConnection:
    """Parent-side Connection over anonymous stdio pipes.

    Speaks the same length-prefix framing as multiprocessing.Connection:
    send_bytes adds ">I" prefix; recv_bytes(max_n) reads one message;
    poll(seconds) peeks. Errors surface as BrokenPipeError/EOFError/
    OSError so RLMWorker fail-closed handling applies unchanged.
    """

    def __init__(self, read_handle: int, write_handle: int) -> None:
        self._read = read_handle
        self._write = write_handle
        self._closed = False

    def send_bytes(self, data: bytes) -> None:
        if self._closed:
            raise BrokenPipeError("pipe connection closed")
        try:
            ac.write_all(self._write, struct.pack(">I", len(data)) + data)
        except ac.SandboxError as exc:
            if exc.code in ("PIPE_EOF", "PIPE_TIMEOUT"):
                raise BrokenPipeError(str(exc)) from exc
            raise OSError(str(exc)) from exc

    def recv_bytes(self, max_n: int) -> bytes:
        if self._closed:
            raise EOFError("pipe connection closed")
        try:
            (ln,) = struct.unpack(
                ">I", ac.read_exact(self._read, 4, timeout_ms=60000))
        except ac.SandboxError as exc:
            if exc.code == "PIPE_EOF":
                raise EOFError(str(exc)) from exc
            raise OSError(str(exc)) from exc
        if not 0 < ln <= max_n:
            raise ValueError(f"bad frame length {ln}")
        try:
            return ac.read_exact(self._read, ln, timeout_ms=60000)
        except ac.SandboxError as exc:
            if exc.code == "PIPE_EOF":
                raise EOFError(str(exc)) from exc
            raise OSError(str(exc)) from exc

    def poll(self, timeout: float = 0) -> bool:
        if self._closed:
            return False
        try:
            return ac.poll_pipe(self._read,
                                timeout_ms=int(max(0.0, timeout) * 1000))
        except ac.SandboxError:
            return False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        ac.close_handle(self._write)
        ac.close_handle(self._read)


class SandboxProcess:
    """Minimal process handle for RLMWorker lifecycle (duck-typed).

    All failures surface as OSError so RLMWorker's existing
    fail-closed handling applies unchanged.
    """

    def __init__(self, child: ac.LaunchedChild) -> None:
        self._child = child

    def _guarded(self, fn, *args):
        try:
            return fn(*args)
        except ac.SandboxError as exc:
            raise OSError(str(exc)) from exc

    def is_alive(self) -> bool:
        return self._guarded(
            lambda: ac.wait_process(self._child.process_handle, 0)
            == "timeout")

    def terminate(self) -> None:
        try:
            ok = ac._kernel32().TerminateProcess(self._child.process_handle,
                                                 1)
        except ac.SandboxError as exc:
            raise OSError(str(exc)) from exc
        if not ok and self.is_alive():
            raise OSError("TerminateProcess failed")

    def kill(self) -> None:
        self.terminate()

    def join(self, timeout: Optional[float] = None) -> None:
        ms = 0xFFFFFFFF if timeout is None else int(timeout * 1000)
        self._guarded(ac.wait_process, self._child.process_handle, ms)


@dataclass
class SandboxedHandles:
    connection: PipeConnection
    process: SandboxProcess
    child: ac.LaunchedChild
    runtime_root: Path
    profile_name: str
    profile_sid: str
    acl_delta: Any = None
    owned_runtime_dir: Optional[Path] = None

    def close(self) -> List[str]:
        """Terminate + revoke + delete. Returns cleanup error codes."""
        errors: List[str] = []
        try:
            self.connection.close()
        except Exception:
            errors.append("CONN_CLOSE")
        try:
            ac.terminate_child(self.child)
        except Exception:
            errors.append("TERMINATE")
        try:
            sid = ac.sid_from_string(self.profile_sid)
            try:
                back = ac.revoke_sid(self.runtime_root, sid)
                if [a for a in back.after if a.sid == self.profile_sid]:
                    errors.append("ACL_REVOKE_VERIFY")
            finally:
                ac.free_sid(sid)
        except Exception:
            errors.append("ACL_REVOKE")
        try:
            if not ac.delete_profile(self.profile_name):
                # Missing profile is acceptable residue-free state.
                pass
        except Exception:
            errors.append("PROFILE_DELETE")
        if self.owned_runtime_dir is not None and not _keep_dir():
            import shutil
            import time as _time

            removed = False
            for _ in range(3):
                shutil.rmtree(self.owned_runtime_dir, ignore_errors=True)
                if not Path(self.owned_runtime_dir).exists():
                    removed = True
                    break
                _time.sleep(0.5)
            if not removed:
                errors.append("RUNTIME_RM")
        return errors


def _keep_dir() -> bool:
    return os.environ.get("ASTRA_SANDBOX_KEEP_RUNTIME", "") == "1"


def launch_sandboxed_owned(spec: SandboxSpec, *, session_id: str,
                           nonce: str, max_chars: int, max_req: int,
                           rpc_enabled: bool,
                           startup_timeout: float) -> SandboxedHandles:
    """Build an owned staged runtime, then launch. Raises SandboxError."""
    from openjarvis.sandbox import staged_runtime as sr

    if sys.platform != "win32":
        raise ac.SandboxError("UNSUPPORTED_PLATFORM", sys.platform)
    if spec.runtime_root is not None:
        shared = Path(spec.runtime_root)
        if not sr.runtime_ready(shared):
            raise ac.SandboxError("MANIFEST_FAILURE", str(shared))
        handles = launch_sandboxed(
            shared, session_id=session_id, nonce=nonce, max_chars=max_chars,
            max_req=max_req, rpc_enabled=rpc_enabled,
            startup_timeout_s=startup_timeout, spec=spec)
        return handles
    parent = Path(spec.build_parent)
    parent.mkdir(parents=True, exist_ok=True)
    build_dir = parent / f".astra-runtime-{uuid.uuid4().hex[:12]}"
    try:
        result = sr.build_runtime(
            build_dir, python_home=Path(sys.base_prefix),
            repo_src=Path(__file__).resolve().parents[2],  # .../src
            source_revision="p05-production",
            python_version=(
                f"{sys.version_info.major}.{sys.version_info.minor}."
                f"{sys.version_info.micro}"),
            architecture="AMD64")
    except ac.SandboxError:
        raise
    except Exception as exc:
        raise ac.SandboxError("STAGE_FAILURE", str(exc)) from exc
    if not result.ready or not sr.runtime_ready(build_dir):
        raise ac.SandboxError("MANIFEST_FAILURE", str(build_dir))
    handles = launch_sandboxed(
        build_dir, session_id=session_id, nonce=nonce, max_chars=max_chars,
        max_req=max_req, rpc_enabled=rpc_enabled,
        startup_timeout_s=startup_timeout, spec=spec)
    handles.owned_runtime_dir = build_dir
    return handles


def launch_sandboxed(runtime_root: Path, *, session_id: str, nonce: str,
                     max_chars: int, max_req: int, rpc_enabled: bool,
                     startup_timeout_s: float,
                     spec: SandboxSpec) -> SandboxedHandles:
    """Full fail-closed launch sequence. Raises SandboxError (terminal)."""
    from openjarvis.sandbox import staged_runtime as sr

    runtime_root = Path(runtime_root)
    if not sr.runtime_ready(runtime_root):
        raise ac.SandboxError("MANIFEST_FAILURE",
                              f"staged tree invalid: {runtime_root}")
    profile_name = ac.random_profile_name()
    try:
        profile_sid, _ = ac.create_profile(profile_name)
    except ac.SandboxError as exc:
        raise ac.SandboxError("PROFILE_FAILURE", str(exc)) from exc
    sid = None
    pipes = None
    child = None
    try:
        sid = ac.sid_from_string(profile_sid)
        try:
            delta = ac.grant_rx(runtime_root, sid)
        except ac.SandboxError as exc:
            raise ac.SandboxError("ACL_PROVISION_FAILURE",
                                  str(exc)) from exc
        problems = ac.verify_rx(delta, profile_sid)
        if problems:
            raise ac.SandboxError("ACL_VERIFY_FAILURE", "; ".join(problems))
        pipes = ac.make_stdio_pipes()
        job = ac.create_kill_job()
        exe = str(runtime_root / "runtime" / "python.exe")
        code = CHILD_BOOTSTRAP.format(
            worker=str(runtime_root / "worker"), session=session_id,
            nonce=nonce, max_chars=max_chars, max_req=max_req,
            rpc=rpc_enabled)
        cmd = '"' + exe + '" -s -B -c "' + code + '"'
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        env = {
            "SystemRoot": sys_root,
            "PATH": str(runtime_root / "runtime") + ";" + os.path.join(
                sys_root, "System32"),
            "LOCALAPPDATA": str(runtime_root),
            "PYTHONHOME": str(runtime_root / "runtime"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
        try:
            child = ac.launch_appcontainer(
                cmd, profile_sid, pipes, cwd=str(runtime_root / "runtime"),
                env_block=ac.build_env_block(env), job=job)
        except ac.SandboxError as exc:
            raise ac.SandboxError("PROCESS_CREATION_FAILURE",
                                  str(exc)) from exc
        child.profile_name = profile_name
        try:
            ident = ac.query_token_identity(child.process_handle)
        except ac.SandboxError as exc:
            raise ac.SandboxError("IDENTITY_FAILURE", str(exc)) from exc
        if not ident.is_appcontainer or \
                ident.appcontainer_sid != profile_sid:
            raise ac.SandboxError(
                "IDENTITY_FAILURE",
                f"isAC={ident.is_appcontainer} "
                f"match={ident.appcontainer_sid == profile_sid}")
        conn = PipeConnection(pipes.parent_stdout_read,
                              pipes.parent_stdin_write)
        # Pipes ownership moves to conn; prevent double-close below.
        pipes = None
        proc = SandboxProcess(child)
        if not proc.is_alive():
            raise ac.SandboxError("WORKER_BOOTSTRAP_FAILURE",
                                  "child exited before handshake")
        if not conn.poll(startup_timeout_s):
            raise ac.SandboxError("WORKER_BOOTSTRAP_FAILURE",
                                  "handshake timeout")
        return SandboxedHandles(connection=conn, process=proc, child=child,
                                runtime_root=runtime_root,
                                profile_name=profile_name,
                                profile_sid=profile_sid, acl_delta=delta)
    except BaseException:
        if pipes is not None:
            for h in (pipes.parent_stdin_write, pipes.parent_stdout_read,
                      pipes.child_stdin_read, pipes.child_stdout_write):
                try:
                    ac.close_handle(h)
                except Exception:
                    pass
        if child is not None:
            try:
                ac.terminate_child(child)
            except Exception:
                pass
        if sid is not None:
            try:
                ac.revoke_sid(runtime_root, sid)
            except Exception:
                pass
            try:
                ac.free_sid(sid)
            except Exception:
                pass
        try:
            ac.delete_profile(profile_name)
        except Exception:
            pass
        raise
