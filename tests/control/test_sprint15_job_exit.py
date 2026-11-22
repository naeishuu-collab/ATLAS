"""Job exit evidence covers owned descendants, not external side effects."""

import sys
from pathlib import Path

import pytest

from openjarvis.control.sandbox_launcher import (
    SandboxedProcess,
    SandboxLauncher,
    SandboxLaunchError,
    SandboxPolicy,
)
from openjarvis.control.worker_process import WorkerProcess, safe_worker_environment


def test_job_exit_waits_for_owned_descendant(tmp_path):
    import _winapi

    executable = Path(sys.base_prefix) / "python.exe"
    assert executable.is_file()
    policy = SandboxPolicy("fixture", "exit-test", str(executable), 2, 30)
    code = (
        "import subprocess,sys\n"
        "child = subprocess.Popen("
        "[sys.executable,'-I','-c','import time; time.sleep(30)'],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,"
        "creationflags=0x08000000)\n"
        "print(child.pid,flush=True)\n"
    )
    worker = SandboxLauncher(policy).launch(
        [str(executable), "-I", "-c", code],
        cwd=tmp_path,
        env=safe_worker_environment(home=tmp_path),
    )
    descendant = None
    try:
        child_pid = int(worker.process.stdout.readline())
        descendant = _winapi.OpenProcess(0x00100000, False, child_pid)
        assert worker.process.wait(timeout=5) == 0
        assert worker.job.active_processes() > 0
    finally:
        try:
            result = worker.close()
        finally:
            if descendant is not None:
                try:
                    assert _winapi.WaitForSingleObject(descendant, 5000) == 0
                finally:
                    _winapi.CloseHandle(descendant)
    assert result["job_exit_confirmed"] is True
    assert result["forced_termination"] is True
    assert result["closed"] is True


def test_job_query_failure_never_confirms_exit():
    class Process:
        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    class Job:
        handle = True
        limits = {}

        def active_processes(self):
            raise SandboxLaunchError("SANDBOX_JOB_QUERY_FAILED")

        def close(self):
            self.handle = None

    policy = SandboxPolicy("fixture", "query-test", "python", 1, 30)
    job = Job()
    worker = SandboxedProcess(Process(), job, policy, True, True)
    with pytest.raises(SandboxLaunchError, match="SANDBOX_JOB_QUERY_FAILED"):
        worker.close()
    assert worker.closed
    assert worker.job_exit_confirmed is False
    assert job.handle is None


def test_single_owned_process_exit_is_confirmed(tmp_path):
    executable = Path(sys.base_prefix) / "python.exe"
    policy = SandboxPolicy("fixture", "single-exit", str(executable), 1, 30)
    worker = SandboxLauncher(policy).launch(
        [str(executable), "-I", "-c", "print('ready', flush=True)"],
        cwd=tmp_path,
        env=safe_worker_environment(home=tmp_path),
    )
    try:
        assert worker.process.stdout.readline().strip() == b"ready"
        assert worker.process.wait(timeout=5) == 0
    finally:
        result = worker.close()
    assert result["job_exit_confirmed"] is True


def test_single_process_waits_for_job_accounting_to_settle():
    class Process:
        pid = 123

        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    class Job:
        limits = {}

        def __init__(self):
            self.counts = iter((1, 0, 0, 0))

        def active_processes(self):
            return next(self.counts, 0)

        def terminate(self):
            raise AssertionError("settling accounting should not force termination")

        def close(self):
            pass

    worker = SandboxedProcess(
        Process(),
        Job(),
        SandboxPolicy("fixture", "settling", "python", 1, 30),
        True,
        True,
    )
    result = worker.close()
    assert result["job_exit_confirmed"] is True
    assert result["forced_termination"] is False


def test_worker_cleanup_failure_is_not_reported_as_cleaned():
    class Process:
        stdin = None
        returncode = 0

        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    class BrokenSandbox:
        def close(self):
            raise SandboxLaunchError("SANDBOX_JOB_QUERY_FAILED")

    worker = WorkerProcess(["python"], worker_kind="stub", session_id="test", env={})
    worker._process = Process()
    worker._sandbox_process = BrokenSandbox()
    with pytest.raises(SandboxLaunchError, match="SANDBOX_JOB_QUERY_FAILED"):
        worker.stop()
    assert worker.lifecycle.cleaned is False
