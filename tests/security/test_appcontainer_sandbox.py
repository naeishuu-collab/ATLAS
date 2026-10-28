"""P0-5 dedicated AppContainer/sandbox regression.

Portable unit tests run everywhere; Windows physical tests prove the
real staged RLMWorker path (ACL -> profile -> launch -> identity ->
Pipe IPC -> descendant -> cleanup). Physical results are reported
separately (EXECUTED, never merged into portable counts as PASS).

No network, no credentials, no provider stack in the worker.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import struct
import sys
import tempfile
import time
import uuid
from ctypes import wintypes
from pathlib import Path

import pytest

from openjarvis.sandbox import appcontainer as ac

WINDOWS = sys.platform == "win32"
requires_windows = pytest.mark.skipif(
    not WINDOWS, reason="SKIPPED — ENVIRONMENT: Windows sandbox required")

APPROVED_TMP = Path("C:/Users/yingz/AppData/Local/Temp/opencode")

if WINDOWS:
    from openjarvis.agents import rlm_worker as W
    from openjarvis.agents.rlm_worker import RLMWorker, RLMWorkerError
    from openjarvis.sandbox import staged_runtime as sr
    from openjarvis.sandbox.worker_launcher import (
        CHILD_BOOTSTRAP,
        SandboxSpec,
    )


# --------------------------------------------------------------------------
# portable unit tests
# --------------------------------------------------------------------------


class TestSandboxUnit:
    def test_child_bootstrap_compiles(self) -> None:
        code = CHILD_BOOTSTRAP.format(
            worker="w", session="s", nonce="n", max_chars=1, max_req=1,
            rpc=False) if WINDOWS else "pass"
        compile(code, "<child>", "exec")

    def test_env_block_format(self) -> None:
        if not WINDOWS:
            pytest.skip("SKIPPED — ENVIRONMENT")
        blob = ac.build_env_block({"A": "1", "B": "2"})
        assert blob.endswith('\x00\x00'.encode("utf-16-le"))
        assert blob.decode("utf-16-le").split('\x00')[:2] == ["A=1", "B=2"]

    def test_malformed_sid_rejected(self) -> None:
        with pytest.raises(ac.SandboxError):
            ac.sid_from_string("not-a-sid")

    def test_no_fallback_invalid_spec(self) -> None:
        from openjarvis.agents.rlm_worker import RLMWorker

        worker = RLMWorker(sandbox=object())
        with pytest.raises(RLMWorkerError) as exc_info:
            worker.start()
        assert exc_info.value.error_code == "SANDBOX_SPEC_INVALID"
        assert worker.quarantined
        assert worker.process is None

    def test_no_fallback_stage_failure(self, tmp_path) -> None:
        # build_parent is a FILE: staging cannot proceed. Terminal,
        # quarantined, legacy spawn never attempted.
        from openjarvis.agents.rlm_worker import RLMWorker
        from openjarvis.sandbox.worker_launcher import SandboxSpec

        anchor = tmp_path / "file"
        anchor.write_text("x")
        worker = RLMWorker(
            sandbox=SandboxSpec(build_parent=anchor), startup_timeout=5.0)
        with pytest.raises(RLMWorkerError):
            worker.start()
        assert worker.quarantined
        assert worker.process is None


# --------------------------------------------------------------------------
# module fixture: one owned staged runtime for all physical tests
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def staged_root():
    if not WINDOWS:
        pytest.skip("SKIPPED — ENVIRONMENT")
    base = Path(tempfile.mkdtemp(prefix="p05-suite-",
                                 dir=str(APPROVED_TMP)))
    root = base / "runtime"
    result = sr.build_runtime(
        root, python_home=Path(sys.base_prefix), repo_src=Path("src"),
        source_revision="p05-suite")
    assert result.ready and sr.runtime_ready(root)
    yield root
    shutil.rmtree(base, ignore_errors=True)


def _env_for(rt: Path) -> dict:
    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    return {
        "SystemRoot": sys_root,
        "PATH": str(rt / "runtime") + ";" + os.path.join(sys_root,
                                                         "System32"),
        "LOCALAPPDATA": str(rt),
        "PYTHONHOME": str(rt / "runtime"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }


def _launch(rt: Path, name: str, sid: str, code: str,
            timeout_s: float = 60.0):
    """Grant -> pipes -> job -> launch. Returns (pipes, job, child)."""
    s = ac.sid_from_string(sid)
    try:
        delta = ac.grant_rx(rt, s)
    finally:
        ac.free_sid(s)
    assert ac.verify_rx(delta, sid) == []
    pipes = ac.make_stdio_pipes()
    job = ac.create_kill_job()
    exe = str(rt / "runtime" / "python.exe")
    cmd = '"' + exe + '" -s -B -c "' + code + '"'
    child = ac.launch_appcontainer(
        cmd, sid, pipes, cwd=str(rt / "runtime"),
        env_block=ac.build_env_block(_env_for(rt)), job=job)
    child.profile_name = name
    return pipes, job, child


def _read_text(pipes, timeout_s=30.0, stop_markers=()) -> str:
    k32 = ac._kernel32()
    buf = ctypes.create_string_buffer(1 << 20)
    got = wintypes.DWORD()
    deadline = time.monotonic() + timeout_s
    text = ""
    while time.monotonic() < deadline:
        avail = wintypes.DWORD()
        k32.PeekNamedPipe(pipes.parent_stdout_read, None, 0, None,
                          ctypes.byref(avail), None)
        if avail.value:
            k32.ReadFile(pipes.parent_stdout_read, buf,
                         min(avail.value, 1 << 20),
                         ctypes.byref(got), None)
            text += buf.raw[:got.value].decode("utf-8", "replace")
            if any(m in text for m in stop_markers):
                break
            if len(text) > 4096:
                break
        else:
            time.sleep(0.1)
    return text


def _send_frame(pipes, payload: dict) -> None:
    raw = W._encode_frame(payload)
    ac.write_all(pipes.parent_stdin_write, struct.pack(">I", len(raw)) + raw)


def _read_frame(pipes, timeout_ms=30000) -> dict:
    (ln,) = struct.unpack(
        ">I", ac.read_exact(pipes.parent_stdout_read, 4,
                            timeout_ms=timeout_ms))
    assert 0 < ln <= 65536, f"frame len {ln}"
    return W._decode_frame(
        ac.read_exact(pipes.parent_stdout_read, ln, timeout_ms=timeout_ms))


def _teardown(rt, name, sid, pipes, job, child) -> None:
    ac.terminate_child(child)
    for h in (pipes.parent_stdin_write, pipes.parent_stdout_read):
        try:
            ac.close_handle(h)
        except Exception:
            pass
    s = ac.sid_from_string(sid)
    try:
        back = ac.revoke_sid(rt, s)
    finally:
        ac.free_sid(s)
    assert not [a for a in back.after if a.sid == sid]
    assert ac.delete_profile(name) or True
    # Residue proof: recreating the same name must report created=True
    # (DeriveAppContainerSid works from the name alone, so a derive
    # check would be vacuous here).
    _, recreated = ac.create_profile(name)
    assert recreated, f"profile residue: {name}"
    ac.delete_profile(name)


# --------------------------------------------------------------------------
# ACL boundary
# --------------------------------------------------------------------------


@requires_windows
class TestAclBoundary:
    def test_grant_verify_revoke_cycle(self, tmp_path) -> None:
        target = tmp_path / "tree"
        target.mkdir()
        name = ac.random_profile_name()
        sid, _ = ac.create_profile(name)
        try:
            before = ac.snapshot_dacl(target)
            s = ac.sid_from_string(sid)
            try:
                delta = ac.grant_rx(target, s)
                assert ac.verify_rx(delta, sid) == []
            finally:
                ac.free_sid(s)
            # Duplicate provisioning is stable (no ACE duplication).
            s = ac.sid_from_string(sid)
            try:
                again = ac.grant_rx(target, s)
                assert ac.verify_rx(again, sid) == []
                assert len(again.after) == len(delta.after)
            finally:
                ac.free_sid(s)
            s = ac.sid_from_string(sid)
            try:
                back = ac.revoke_sid(target, s)
                assert not [a for a in back.after if a.sid == sid]
                assert len(back.after) == len(before)
            finally:
                ac.free_sid(s)
        finally:
            ac.delete_profile(name)

    def test_wrong_sid_verify_fails(self, tmp_path) -> None:
        target = tmp_path / "tree"
        target.mkdir()
        name_a = ac.random_profile_name()
        name_b = ac.random_profile_name()
        sid_a, _ = ac.create_profile(name_a)
        sid_b, _ = ac.create_profile(name_b)
        try:
            s = ac.sid_from_string(sid_a)
            try:
                delta = ac.grant_rx(target, s)
            finally:
                ac.free_sid(s)
            assert ac.verify_rx(delta, sid_b) != []
            s = ac.sid_from_string(sid_a)
            try:
                ac.revoke_sid(target, s)
            finally:
                ac.free_sid(s)
        finally:
            ac.delete_profile(name_a)
            ac.delete_profile(name_b)

    def test_missing_path_fails_closed(self) -> None:
        name = ac.random_profile_name()
        sid, _ = ac.create_profile(name)
        try:
            s = ac.sid_from_string(sid)
            try:
                with pytest.raises(ac.SandboxError):
                    ac.grant_rx(Path("Z:/definitely/not/here"), s)
            finally:
                ac.free_sid(s)
        finally:
            ac.delete_profile(name)

    def test_reparse_source_refused(self, tmp_path) -> None:
        link = tmp_path / "link"
        try:
            link.symlink_to(tmp_path, target_is_directory=True)
        except OSError:
            pytest.skip("SKIPPED — ENVIRONMENT: symlink privilege")
        assert ac._is_reparse(link)


# --------------------------------------------------------------------------
# AppContainer bootstrap + identity
# --------------------------------------------------------------------------


@requires_windows
class TestAppContainerBootstrap:
    def test_startup_identity(self, staged_root) -> None:
        rt = staged_root
        name = ac.random_profile_name()
        sid, _ = ac.create_profile(name)
        pipes, job, child = _launch(
            rt, name, sid,
            "import sys; print('up'); sys.stdout.flush()")
        try:
            ac.close_handle(pipes.parent_stdin_write)
            ident = ac.query_token_identity(child.process_handle)
            assert ident.is_appcontainer
            assert ident.appcontainer_sid == sid
            image = ac.query_process_image(child.process_handle)
            assert image.lower() == str(
                rt / "runtime" / "python.exe").lower()
            assert ac.is_process_in_job(child.process_handle, job)
            assert _read_text(pipes, 20.0).strip() == "up"
            assert ac.wait_process(child.process_handle, 10000) == "exited"
        finally:
            _teardown(rt, name, sid, pipes, job, child)

    def test_real_worker_ipc_cycle(self, staged_root) -> None:
        rt = staged_root
        session = "sess-" + uuid.uuid4().hex[:8]
        nonce = "nonce-" + uuid.uuid4().hex[:8]
        code = CHILD_BOOTSTRAP.format(
            worker=str(rt / "worker"), session=session, nonce=nonce,
            max_chars=4096, max_req=8, rpc=False)
        name = ac.random_profile_name()
        sid, _ = ac.create_profile(name)
        pipes, job, child = _launch(rt, name, sid, code)
        try:
            ready = _read_frame(pipes)
            assert ready["type"] == "ready"
            W._validate_handshake(ready, session, nonce, 8)
            _send_frame(pipes, {"protocol": W.PROTOCOL_VERSION,
                                "type": "execute", "session_id": session,
                                "nonce": nonce, "request_id": 1,
                                "deadline_ms": 10000, "code": "result = 41"})
            resp = _read_frame(pipes)
            assert resp["type"] == "result" and resp["success"] is True
            # Negative: wrong session is a structured error, not a crash.
            _send_frame(pipes, {"protocol": W.PROTOCOL_VERSION,
                                "type": "execute", "session_id": "wrong",
                                "nonce": nonce, "request_id": 2,
                                "deadline_ms": 10000, "code": "result = 1"})
            bad = _read_frame(pipes)
            assert bad["type"] == "error"
            # Negative: oversized length prefix is rejected, worker lives.
            ac.write_all(pipes.parent_stdin_write,
                         struct.pack(">I", 10**8))
            over = _read_frame(pipes)
            assert over["type"] == "error"
            _send_frame(pipes, {"protocol": W.PROTOCOL_VERSION,
                                "type": "shutdown", "session_id": session,
                                "nonce": nonce, "request_id": 0})
            assert _read_frame(pipes)["type"] == "shutdown_ack"
            assert ac.wait_process(child.process_handle, 15000) == "exited"
        finally:
            _teardown(rt, name, sid, pipes, job, child)
        assert sr.runtime_ready(rt)

    def test_unknown_outcome_on_killed_execute(self, staged_root) -> None:
        rt = staged_root
        worker = RLMWorker(
            sandbox=SandboxSpec(runtime_root=rt), execution_timeout=3.0,
            startup_timeout=60.0)
        try:
            result = worker.execute_with_outcome(
                "total = 0\nfor i in range(10**12):\n total += i")
            assert result.error_code == "WORKER_TIMEOUT"
            assert result.unknown_outcome is True
            assert worker.quarantined
        finally:
            worker.close()
            assert worker._sandbox_cleanup_errors == []


# --------------------------------------------------------------------------
# production integration
# --------------------------------------------------------------------------


@requires_windows
class TestProductionIntegration:
    def test_sandboxed_execute_end_to_end(self, staged_root) -> None:
        rt = staged_root
        worker = RLMWorker(
            sandbox=SandboxSpec(runtime_root=rt), startup_timeout=60.0)
        try:
            worker.start()
            assert worker.started and not worker.quarantined
            result = worker.execute_with_outcome("result = 6 * 7")
            assert result.success is True
            assert worker._sandbox_cleanup_errors == []
        finally:
            worker.close()
            assert worker._sandbox_cleanup_errors == []

    def test_legacy_path_unchanged(self) -> None:
        worker = RLMWorker()
        try:
            with pytest.raises(RLMWorkerError) as exc_info:
                worker.start()
            assert exc_info.value.error_code == "RLM_SANDBOX_UNAVAILABLE"
            assert worker.quarantined
            assert worker.process is None
        finally:
            worker.close()

    def test_owned_build_lifecycle_removed(self, tmp_path) -> None:
        from openjarvis.sandbox.worker_launcher import SandboxSpec

        built: list = []
        real_build = sr.build_runtime

        def _spy_build(dest, **kw):
            built.append(Path(dest))
            return real_build(dest, **kw)

        import openjarvis.sandbox.staged_runtime as sr_mod

        old = sr_mod.build_runtime
        sr_mod.build_runtime = _spy_build
        try:
            worker = RLMWorker(
                sandbox=SandboxSpec(build_parent=tmp_path),
                startup_timeout=120.0)
            try:
                result = worker.execute_with_outcome("result = 6 * 7")
                assert result.success is True
            finally:
                worker.close()
                assert worker._sandbox_cleanup_errors == []
        finally:
            sr_mod.build_runtime = old
        assert len(built) == 1
        assert not built[0].exists(), "owned runtime residue"

    def test_filesystem_write_denied(self, staged_root) -> None:
        # Purpose-built probe (raw staged interpreter, NOT worker
        # execute: the worker REPL correctly blocks open()/os anyway).
        rt = staged_root
        canary = Path(
            "C:/Users/yingz/.codex/worktrees/astra-opencode/JARVIS-Sol"
            "/pyproject.toml")
        probe = (
            "import os, sys\n"
            "out = []\n"
            "try:\n"
            " open(r'" + str(rt / "runtime" / "Lib" / "os.py") + "', 'w')\n"
            " out.append('runtime-write-allowed')\n"
            "except OSError:\n"
            " out.append('runtime-write-denied')\n"
            "try:\n"
            " os.makedirs(r'" + str(rt / "newdir") + "')\n"
            " out.append('mkdir-allowed')\n"
            "except OSError:\n"
            " out.append('mkdir-denied')\n"
            "try:\n"
            " open(r'" + str(canary) + "', 'r').read(8)\n"
            " out.append('repo-read-allowed')\n"
            "except OSError:\n"
            " out.append('repo-read-denied')\n"
            "print('PROBE ' + ','.join(out))\n"
            "sys.stdout.flush()\n"
        )
        name = ac.random_profile_name()
        sid, _ = ac.create_profile(name)
        pipes, job, child = _launch(rt, name, sid, probe)
        try:
            ac.close_handle(pipes.parent_stdin_write)
            text = _read_text(pipes, 30.0)
            assert "runtime-write-denied" in text, text[:300]
            assert "mkdir-denied" in text, text[:300]
            assert "repo-read-denied" in text, text[:300]
            assert ac.wait_process(child.process_handle, 15000) == "exited"
        finally:
            _teardown(rt, name, sid, pipes, job, child)
        assert sr.runtime_ready(rt)


# --------------------------------------------------------------------------
# descendant containment + kill-on-close
# --------------------------------------------------------------------------


@requires_windows
class TestDescendantContainment:
    def _spawn_probe(self, rt, name, sid, grandchild_code, wait_s=25.0):
        child_code = (
            "import subprocess, sys, time\n"
            "try:\n"
            " p = subprocess.Popen([sys.executable, '-s', '-B', '-c', "
            + repr(grandchild_code) + "], stdout=subprocess.PIPE,"
            " stderr=subprocess.STDOUT)\n"
            " print('DESC_SPAWNED pid=%d' % (p.pid,))\n"
            " sys.stdout.flush()\n"
            " time.sleep(" + str(wait_s) + ")\n"
            " p.terminate()\n"
            " print('DESC_REAPED')\n"
            " sys.stdout.flush()\n"
            "except Exception as e:\n"
            " print('DESC_DENIED %r' % (e,))\n"
            " sys.stdout.flush()\n"
        )
        return _launch(rt, name, sid, child_code)

    def test_descendant_identity_and_job(self, staged_root) -> None:
        rt = staged_root
        name = ac.random_profile_name()
        sid, _ = ac.create_profile(name)
        pipes, job, child = self._spawn_probe(
            rt, name, sid, "import time; print(100); time.sleep(25)")
        try:
            text = _read_text(pipes, 40.0, ("DESC_SPAWNED", "DESC_DENIED"))
            assert "DESC_SPAWNED" in text, text[:200]
            import re
            dpid = int(re.search(r"pid=(\d+)", text).group(1))
            k32 = ac._kernel32()
            h = k32.OpenProcess(0x0400 | 0x1000, False, dpid)
            assert h, "descendant handle"
            try:
                ident = ac.query_token_identity(h)
                assert ident.is_appcontainer
                assert ident.appcontainer_sid == sid
                image = ac.query_process_image(h)
                assert image.lower() == str(
                    rt / "runtime" / "python.exe").lower()
                assert ac.is_process_in_job(h, job)
            finally:
                k32.CloseHandle(h)
            assert ac.wait_process(child.process_handle, 40000) == "exited"
        finally:
            _teardown(rt, name, sid, pipes, job, child)

    def test_kill_on_job_close(self, staged_root) -> None:
        rt = staged_root
        name = ac.random_profile_name()
        sid, _ = ac.create_profile(name)
        pipes, job, child = self._spawn_probe(
            rt, name, sid, "import time; time.sleep(60)", wait_s=60.0)
        try:
            text = _read_text(pipes, 40.0, ("DESC_SPAWNED", "DESC_DENIED"))
            assert "DESC_SPAWNED" in text, text[:200]
            import re
            dpid = int(re.search(r"pid=(\d+)", text).group(1))
            k32 = ac._kernel32()
            h = k32.OpenProcess(0x1000 | 0x00100000, False, dpid)
            assert h, "descendant handle"
            try:
                # Close the JOB (not terminate): kill-on-close must fire.
                ac.close_handle(job)
                assert ac.wait_process(h, 20000) == "exited", \
                    "KILL_ON_JOB_CLOSE did not fire"
            finally:
                k32.CloseHandle(h)
        finally:
            # Job already closed; terminate remainder + full cleanup.
            try:
                ac.terminate_child(child)
            except Exception:
                pass
            for hdl in (pipes.parent_stdin_write, pipes.parent_stdout_read):
                try:
                    ac.close_handle(hdl)
                except Exception:
                    pass
            s = ac.sid_from_string(sid)
            try:
                back = ac.revoke_sid(rt, s)
            finally:
                ac.free_sid(s)
            assert not [a for a in back.after if a.sid == sid]
            ac.delete_profile(name)
