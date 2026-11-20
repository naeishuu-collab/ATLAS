"""Job exit evidence covers owned descendants, not external side effects."""

import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from openjarvis.control.sandbox_launcher import (
    SandboxedProcess,
    SandboxLauncher,
    SandboxLaunchError,
    SandboxPolicy,
)
from openjarvis.control.worker_process import WorkerProcess, safe_worker_environment


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object required")
@pytest.mark.parametrize("stop", ["deadline", "cancel"])
def test_job_stops_descendant_after_worker_exit(tmp_path, stop):
    import _winapi  # noqa: PLC0415

    executable = Path(sys.base_prefix) / "python.exe"
    runtime = 2 if stop == "deadline" else 30
    policy = SandboxPolicy("fixture", "descendant-stop", str(executable), 4, runtime)
    marker = tmp_path / "effect"
    code = (
        "import subprocess,sys\n"
        "effect = 'from pathlib import Path; import sys,time; "
        "time.sleep(20); Path(sys.argv[1]).touch()'\n"
        "child = subprocess.Popen([sys.executable,'-I','-c',effect,sys.argv[1]],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,"
        "creationflags=0x08000000)\n"
        "print(child.pid,flush=True)\n"
    )
    worker = SandboxLauncher(policy).launch(
        [str(executable), "-I", "-c", code, str(marker)],
        cwd=tmp_path,
        env=safe_worker_environment(home=tmp_path),
    )
    try:
        pid = int(worker.process.stdout.readline())
        descendant = _winapi.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        try:
            assert worker.process.wait(timeout=5) == 0
            assert _winapi.WaitForSingleObject(descendant, 0) == 0x102  # WAIT_TIMEOUT
            assert worker.job.active_processes() > 0
            if stop == "cancel":
                worker.terminate()
            assert _winapi.WaitForSingleObject(descendant, 5000) == 0
            assert worker.timed_out is (stop == "deadline")
            assert worker.forced_termination
            assert not marker.exists()
        finally:
            _winapi.CloseHandle(descendant)
    finally:
        worker.close()


def test_explicit_termination_waits_for_job_close():
    releasing = threading.Event()
    released = threading.Event()
    terminate_started = threading.Event()
    concurrent_query = threading.Event()

    class Process:
        pid = 123

        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    class Job:
        limits = {}

        def active_processes(self):
            if releasing.is_set():
                concurrent_query.set()
            return 0

        def close(self):
            releasing.set()
            assert released.wait(timeout=5)

    policy = SandboxPolicy("fixture", "concurrent-close", "python")
    worker = SandboxedProcess(Process(), Job(), policy, True)

    def terminate():
        terminate_started.set()
        worker.terminate()

    with ThreadPoolExecutor(max_workers=2) as pool:
        closing = pool.submit(worker.close)
        try:
            assert releasing.wait(timeout=5)
            stopping = pool.submit(terminate)
            assert terminate_started.wait(timeout=5)
            assert not concurrent_query.wait(timeout=0.25)
        finally:
            released.set()
        assert closing.result(timeout=5)["closed"]
        stopping.result(timeout=5)
    assert not concurrent_query.is_set()


def test_worker_kills_job_even_after_root_exit():
    class Exited:
        def poll(self):
            return 0

    class JobOwner:
        called = False

        def terminate(self):
            self.called = True

    job = JobOwner()
    worker = object.__new__(WorkerProcess)
    worker._sandbox_process = job
    worker._kill_process_tree(Exited())
    assert job.called


def test_query_failure_terminates_job_and_closes_handle_on_failure():
    class Process:
        pid = 123

        def wait(self, timeout):
            return 0

    class Job:
        limits = {}
        terminated = False
        closed = False

        def active_processes(self):
            raise SandboxLaunchError("QUERY_FAILED")

        def terminate(self):
            self.terminated = True
            raise SandboxLaunchError("TERMINATE_FAILED")

        def close(self):
            self.closed = True

    job = Job()
    policy = SandboxPolicy("fixture", "error", "python")
    worker = SandboxedProcess(Process(), job, policy, True)
    with pytest.raises(SandboxLaunchError, match="TERMINATE_FAILED"):
        worker.close()
    assert job.terminated and job.closed and worker.closed


def test_deadline_failure_is_reported_after_cleanup():
    class Process:
        pid = 123
        waited = False

        def wait(self, timeout):
            self.waited = True
            return 0

    ended = threading.Event()

    class Job:
        limits = {}
        closed = False

        def active_processes(self):
            if self.closed:
                raise SandboxLaunchError("QUERY_CLOSED")
            return 1

        def terminate(self):
            if not self.closed:
                raise SandboxLaunchError("TERMINATE_FAILED")

        def close(self):
            self.closed = True
            ended.set()

    process = Process()
    job = Job()
    policy = SandboxPolicy("fixture", "deadline-error", "python", max_runtime=0.05)
    worker = SandboxedProcess(process, job, policy, True)
    assert ended.wait(timeout=5)
    with pytest.raises(SandboxLaunchError, match="SANDBOX_TERMINATE_FAILED"):
        worker.close()
    assert process.waited and job.closed and worker.closed
    with pytest.raises(SandboxLaunchError, match="SANDBOX_TERMINATE_FAILED"):
        worker.close()


def test_explicit_termination_failure_remains_visible():
    class Process:
        pid = 123

        def wait(self, timeout):
            return 0

    class Job:
        limits = {}
        closed = False

        def active_processes(self):
            if self.closed:
                raise SandboxLaunchError("QUERY_CLOSED")
            return 1

        def terminate(self):
            if not self.closed:
                raise SandboxLaunchError("TERMINATE_FAILED")

        def close(self):
            self.closed = True

    job = Job()
    worker = SandboxedProcess(
        Process(), job, SandboxPolicy("fixture", "explicit-error", "python"), True
    )
    with pytest.raises(SandboxLaunchError, match="TERMINATE_FAILED"):
        worker.terminate()
    for _ in range(2):
        with pytest.raises(SandboxLaunchError, match="SANDBOX_TERMINATE_FAILED"):
            worker.close()
    assert job.closed and worker.closed


def test_worker_force_stop_cleans_up_after_termination_failure():
    class Process:
        returncode = None

        def poll(self):
            return 0

    class JobOwner:
        closed = False

        def terminate(self):
            raise SandboxLaunchError("TERMINATE_FAILED")

        def close(self):
            self.closed = True
            raise SandboxLaunchError("CLEANUP_FAILED")

    worker = WorkerProcess(
        ["python"], worker_kind="fixture", session_id="session", env={}
    )
    owner = JobOwner()
    worker._process = Process()
    worker._sandbox_process = owner
    with pytest.raises(SandboxLaunchError, match="TERMINATE_FAILED") as exc:
        worker.stop(force=True)
    assert "CLEANUP_FAILED" in str(exc.value.__cause__)
    assert owner.closed and not worker.lifecycle.cleaned


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object required")
def test_worker_force_stop_kills_descendant_after_root_exit(tmp_path):
    import _winapi  # noqa: PLC0415

    executable = Path(sys.base_prefix) / "python.exe"
    policy = SandboxPolicy("fixture", "force-stop", str(executable), 4, 30)
    code = (
        "import subprocess,sys\n"
        "child = subprocess.Popen([sys.executable,'-I','-c',"
        "'import time; time.sleep(30)'],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,"
        "creationflags=0x08000000)\n"
        "print(child.pid,flush=True)\n"
    )
    sandbox = SandboxLauncher(policy).launch(
        [str(executable), "-I", "-c", code],
        cwd=tmp_path,
        env=safe_worker_environment(home=tmp_path),
    )
    worker = WorkerProcess(
        [str(executable)], worker_kind="fixture", session_id="s", env={}
    )
    worker._process = sandbox.process
    worker._sandbox_process = sandbox
    try:
        pid = int(sandbox.process.stdout.readline())
        descendant = _winapi.OpenProcess(0x00100000, False, pid)
        try:
            assert sandbox.process.wait(timeout=5) == 0
            assert _winapi.WaitForSingleObject(descendant, 0) == 0x102
            result = worker.stop(force=True)
            assert _winapi.WaitForSingleObject(descendant, 5000) == 0
            assert result.cleaned and result.sandbox["closed"]
        finally:
            _winapi.CloseHandle(descendant)
    finally:
        sandbox.close()


def test_close_wait_failure_is_retained_and_job_is_closed():
    class Process:
        pid = 123

        def wait(self, timeout):
            raise TimeoutError("WAIT_FAILED")

    class Job:
        limits = {}
        closed = False

        def active_processes(self):
            return 0

        def close(self):
            self.closed = True

    job = Job()
    worker = SandboxedProcess(
        Process(), job, SandboxPolicy("fixture", "wait-error", "python"), True
    )
    for _ in range(2):
        with pytest.raises(TimeoutError, match="WAIT_FAILED"):
            worker.close()
    assert job.closed and worker.closed


def test_close_failure_retries_without_forgetting_first_error():
    class Process:
        pid = 123

        def wait(self, timeout):
            return 0

    class Job:
        limits = {}
        attempts = 0

        def active_processes(self):
            return 0

        def close(self):
            self.attempts += 1
            if self.attempts == 1:
                raise OSError("CLOSE_FAILED")

    job = Job()
    worker = SandboxedProcess(
        Process(), job, SandboxPolicy("fixture", "close-error", "python"), True
    )
    with pytest.raises(OSError, match="CLOSE_FAILED"):
        worker.close()
    assert not worker.closed
    with pytest.raises(OSError, match="CLOSE_FAILED"):
        worker.close()
    assert worker.closed and job.attempts == 2


def test_termination_failure_takes_precedence_over_wait_and_close():
    class Process:
        pid = 123

        def wait(self, timeout):
            raise TimeoutError("WAIT_FAILED")

    class Job:
        limits = {}
        close_calls = 0

        def active_processes(self):
            return 1

        def terminate(self):
            raise SandboxLaunchError("TERMINATE_FAILED")

        def close(self):
            self.close_calls += 1
            raise OSError("CLOSE_FAILED")

    job = Job()
    worker = SandboxedProcess(
        Process(), job, SandboxPolicy("fixture", "priority", "python"), True
    )
    for _ in range(2):
        with pytest.raises(SandboxLaunchError, match="SANDBOX_TERMINATE_FAILED"):
            worker.close()
    assert not worker.closed and job.close_calls >= 2


def test_wait_failure_precedes_later_close_failure():
    class Process:
        pid = 123

        def wait(self, timeout):
            raise TimeoutError("WAIT_FIRST")

    class Job:
        limits = {}

        def active_processes(self):
            return 0

        def close(self):
            raise OSError("CLOSE_SECOND")

    worker = SandboxedProcess(
        Process(), Job(), SandboxPolicy("fixture", "priority-wait", "python"), True
    )
    for _ in range(2):
        with pytest.raises(TimeoutError, match="WAIT_FIRST"):
            worker.close()
    assert not worker.closed


def test_worker_stop_wait_failure_still_closes_job_and_timer():
    import subprocess

    class Process:
        pid = 123
        returncode = None

        def poll(self):
            return None

        def wait(self, timeout):
            raise subprocess.TimeoutExpired("fixture", timeout)

    class Job:
        limits = {}
        active = 1
        closed = False

        def active_processes(self):
            return self.active

        def terminate(self):
            self.active = 0

        def close(self):
            self.closed = True

    process = Process()
    job = Job()
    sandbox = SandboxedProcess(
        process,
        job,
        SandboxPolicy("fixture", "stop-wait", "python", max_runtime=30),
        True,
    )
    worker = WorkerProcess(
        ["python"], worker_kind="fixture", session_id="stop-wait", env={}
    )
    worker._process = process
    worker._sandbox_process = sandbox
    with pytest.raises(subprocess.TimeoutExpired):
        worker.stop(force=True)
    assert job.closed and sandbox.closed
    assert not sandbox._timer.is_alive() and not worker.lifecycle.cleaned


def test_worker_stop_poll_failure_still_closes_sandbox():
    class Process:
        returncode = 0

        def wait(self, timeout):
            return 0

        def poll(self):
            raise OSError("POLL_FAILED")

    class Sandbox:
        closed = False

        def terminate(self):
            pass

        def close(self):
            self.closed = True
            return {"closed": True}

    process = Process()
    sandbox = Sandbox()
    worker = WorkerProcess(
        ["python"], worker_kind="fixture", session_id="stop-poll", env={}
    )
    worker._process = process
    worker._sandbox_process = sandbox
    with pytest.raises(OSError, match="POLL_FAILED"):
        worker.stop(force=True)
    assert sandbox.closed and not worker.lifecycle.cleaned
