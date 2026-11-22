"""Exercise the independent host-owned supervisor with real Windows jobs."""

import ctypes
import os
import threading
import time
import uuid
from ctypes import wintypes
from types import SimpleNamespace

import pytest

import openjarvis.control.host_task_supervisor as host_task_supervisor
from openjarvis.agents.manager import AgentManager
from openjarvis.control.host_task_supervisor import (
    HostTaskSupervisorProcess,
    verify_signed_exit_record,
)
from openjarvis.control.task_worker import (
    TaskWorkerExecutionError,
    TaskWorkerSupervisor,
)
from openjarvis.control.worker_process import WorkerProcess
from openjarvis.core.types import ToolCall
from openjarvis.security.principal import TestPrincipalAuthority
from tests.agents.test_sprint15_task_tool_journal import _task


def _setup(tmp_path):
    manager = AgentManager(str(tmp_path / "supervisor.db"))
    authority = TestPrincipalAuthority(b"independent-host-test-authority")
    principal = authority.verify(authority.issue("synthetic-principal"))
    identity, _ = _task(manager, authority, principal)
    task_id, agent_id, _, _, attempt, token, epoch = identity
    live = manager.task_authority_binding(*identity)
    binding = {
        "worker_id": uuid.uuid4().hex,
        "supervisor_id": uuid.uuid4().hex,
        "task_id": task_id,
        "agent_id": agent_id,
        "principal_id": principal.principal_id,
        "attempt": attempt,
        "owner_hash": live["owner_hash"],
        "epoch": epoch,
        "checkpoint_version": 1,
        "lease_expires_at": live["lease_expires_at"],
    }
    return manager, identity, binding


def test_host_supervisor_owns_real_worker_and_validates_live_authority(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    checks = []

    def authorize():
        manager.validate_task_authority(*identity)
        checks.append(True)

    supervisor = HostTaskSupervisorProcess(binding, validate_authority=authorize)
    try:
        supervisor.start()
        evidence = supervisor.evidence
        assert supervisor.pid != os.getpid()
        assert evidence["controller_pid"] == supervisor.pid
        assert evidence["worker_pid"] not in {os.getpid(), supervisor.pid}
        assert evidence["ipc_authenticated"] is True
        call = ToolCall("test-call", "synthetic_echo", "{}")
        result = supervisor.execute_tool(
            call,
            {"value": "host"},
            timeout=15,
            request_id="test-request",
            deadline=time.time() + 15,
            checkpoint_version=1,
        )
        assert result.content == "synthetic:host"
        assert (
            result.metadata["worker_execution"]["tool_execution_pid"]
            == evidence["worker_pid"]
        )
        supervisor.close()
        assert supervisor.verify_exit_evidence(supervisor.evidence)
        assert supervisor.evidence["job_exit_confirmed"] is True
        assert supervisor.evidence["process_wait_confirmed"] is True
        assert supervisor.evidence["worker_exit_code"] == 0
        assert checks
        print(
            {
                "host_pid": os.getpid(),
                "supervisor_pid": supervisor.pid,
                "worker_pid": evidence["worker_pid"],
                "worker_exit": 0,
            }
        )
    finally:
        supervisor._abort()
        manager.close()


def test_host_authority_revocation_fails_closed(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    allow = [True]

    def authorize():
        if not allow[0]:
            raise PermissionError("host authorization revoked")
        manager.validate_task_authority(*identity)

    supervisor = HostTaskSupervisorProcess(binding, validate_authority=authorize)
    try:
        supervisor.start()
        allow[0] = False
        with pytest.raises(TaskWorkerExecutionError) as failure:
            supervisor.execute_tool(
                ToolCall("denied-call", "synthetic_echo", "{}"),
                {"value": "host"},
                timeout=10,
                request_id="denied-request",
                deadline=time.time() + 10,
                checkpoint_version=1,
            )
        assert failure.value.unknown_outcome is True
        assert supervisor._process.poll() is not None
    finally:
        supervisor._abort()
        manager.close()


def test_worker_stop_is_verified_while_supervisor_remains_alive(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    supervisor = HostTaskSupervisorProcess(
        binding, validate_authority=lambda: manager.validate_task_authority(*identity)
    )
    try:
        supervisor.start()
        assert not supervisor.verify_exit_evidence(supervisor.evidence)
        supervisor.stop_worker()
        assert supervisor._process.poll() is None
        assert supervisor.verify_exit_evidence(supervisor.evidence)
        original_creation = supervisor._creation_time
        supervisor._creation_time += 1
        assert not supervisor.verify_exit_evidence(supervisor.evidence)
        supervisor._creation_time = original_creation
        assert verify_signed_exit_record(
            supervisor.exit_record, supervisor.evidence_verification_key, binding
        )
        changed = supervisor.exit_record
        changed["record"]["evidence"]["worker_pid"] += 1
        assert not verify_signed_exit_record(
            changed, supervisor.evidence_verification_key, binding
        )
        forged = {
            **supervisor.evidence,
            "worker_pid": supervisor.evidence["worker_pid"] + 1,
        }
        assert not supervisor.verify_exit_evidence(forged)
        with pytest.raises(TaskWorkerExecutionError):
            supervisor.execute_tool(
                ToolCall("after-stop", "synthetic_echo", "{}"),
                {"value": "host"},
                timeout=5,
                request_id="after-stop",
                deadline=time.time() + 5,
                checkpoint_version=1,
            )
        supervisor.close()
    finally:
        supervisor._abort()
        manager.close()


def test_supervisor_crash_terminates_owned_job_without_exit_attestation(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    supervisor = HostTaskSupervisorProcess(
        binding, validate_authority=lambda: manager.validate_task_authority(*identity)
    )
    try:
        supervisor.start()
        worker_handle = supervisor._worker_handle
        supervisor._process.kill()
        assert supervisor._process.wait(timeout=10) != 0
        assert supervisor._kernel().WaitForSingleObject(worker_handle, 10000) == 0
        assert supervisor.exit_record is None
        assert not supervisor.verify_exit_evidence(supervisor.evidence)
    finally:
        supervisor._abort()
        manager.close()


def test_worker_crash_does_not_create_clean_exit_attestation(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    supervisor = HostTaskSupervisorProcess(
        binding, validate_authority=lambda: manager.validate_task_authority(*identity)
    )
    try:
        supervisor.start()
        kernel = supervisor._kernel()
        kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        kernel.TerminateProcess.restype = wintypes.BOOL
        assert kernel.TerminateProcess(supervisor._worker_handle, 17)
        assert kernel.WaitForSingleObject(supervisor._worker_handle, 10000) == 0
        with pytest.raises(TaskWorkerExecutionError):
            supervisor.stop_worker()
        assert supervisor.exit_record is None
        assert not supervisor.verify_exit_evidence(supervisor.evidence)
    finally:
        supervisor._abort()
        manager.close()


def test_forged_worker_pid_is_rejected_and_real_worker_cleaned(tmp_path, monkeypatch):
    manager, identity, binding = _setup(tmp_path)
    original = WorkerProcess.start

    def forged_ready(self):
        ready = original(self)
        return {**ready, "pid": ready["pid"] + 1}

    monkeypatch.setattr(WorkerProcess, "start", forged_ready)
    supervisor = TaskWorkerSupervisor(
        binding, validate_authority=lambda: manager.validate_task_authority(*identity)
    )
    try:
        with pytest.raises(TaskWorkerExecutionError, match="PID_MISMATCH"):
            supervisor.start()
        assert supervisor._worker.lifecycle.cleaned is True
        assert supervisor._worker.running is False
    finally:
        supervisor._abort()
        manager.close()


def test_supervisor_abort_retains_home_and_handles_when_job_close_is_uncertain(
    monkeypatch,
):
    class FailedSandbox:
        closed = False

        def close(self):
            raise OSError("synthetic Job drain failure")

    class Home:
        def __init__(self):
            self.calls = 0

        def cleanup(self):
            self.calls += 1

    supervisor = object.__new__(HostTaskSupervisorProcess)
    supervisor._closed = False
    supervisor._cleanup_unconfirmed = False
    supervisor._cleanup_error = None
    supervisor._process = SimpleNamespace(
        pid=101,
        returncode=None,
        poll=lambda: None,
        stdin=None,
        stdout=None,
        stderr=None,
    )
    supervisor._sandbox_process = FailedSandbox()
    supervisor._worker_handle = 201
    supervisor._job_handle = 202
    supervisor._handle_lock = threading.Lock()
    supervisor._handle_close_attempted = set()
    supervisor._handle_close_unconfirmed = set()
    supervisor._stream_close_attempted = set()
    supervisor._worker_job_watch = None
    supervisor._reader = None
    supervisor._stderr_reader = None
    supervisor._watch_error = None
    supervisor._home = Home()

    with pytest.raises(TaskWorkerExecutionError, match="CLEANUP_UNCONFIRMED"):
        supervisor._abort()

    assert supervisor._closed is False
    assert supervisor._cleanup_unconfirmed is True
    assert supervisor._worker_handle == 201
    assert supervisor._job_handle == 202
    assert supervisor._home.calls == 0


def test_release_exit_evidence_preserves_handle_on_closehandle_failure(monkeypatch):
    class Kernel:
        attempts = []

        def CloseHandle(self, handle):
            self.attempts.append(handle)
            return False

    kernel = Kernel()
    supervisor = object.__new__(HostTaskSupervisorProcess)
    supervisor._process = SimpleNamespace(poll=lambda: 0)
    supervisor._sandbox_process = SimpleNamespace(closed=True)
    supervisor._handle_lock = threading.Lock()
    supervisor._worker_handle = 201
    supervisor._job_handle = 202
    supervisor._handle_close_attempted = set()
    supervisor._handle_close_unconfirmed = set()
    monkeypatch.setattr(HostTaskSupervisorProcess, "_kernel", lambda _self: kernel)

    with pytest.raises(OSError, match="CloseHandle"):
        supervisor.release_exit_evidence()
    assert supervisor._worker_handle == 201
    assert supervisor._job_handle == 202
    assert supervisor._handle_close_unconfirmed == {"_worker_handle"}
    with pytest.raises(TaskWorkerExecutionError, match="HANDLE_CLOSE_UNCONFIRMED"):
        supervisor.release_exit_evidence()
    assert kernel.attempts == [201]


def test_supervisor_watch_records_failed_job_termination(monkeypatch):
    class Kernel:
        terminate_calls = 0

        def QueryInformationJobObject(self, _handle, _kind, info, _size, _ret):
            query = ctypes.cast(
                info,
                ctypes.POINTER(host_task_supervisor._BasicAccountingInformation),
            ).contents
            query.active_processes = 1
            return True

        def TerminateJobObject(self, _handle, _code):
            self.terminate_calls += 1
            return False

    kernel = Kernel()
    supervisor = object.__new__(HostTaskSupervisorProcess)
    supervisor._process = SimpleNamespace(wait=lambda: 0)
    supervisor._job_handle = 303
    supervisor._handle_lock = threading.Lock()
    supervisor._watch_error = None
    monkeypatch.setattr(HostTaskSupervisorProcess, "_kernel", lambda _self: kernel)

    supervisor._watch_supervisor()

    assert kernel.terminate_calls == 1
    assert isinstance(supervisor._watch_error, OSError)
    assert supervisor._job_handle == 303


def test_task_worker_abort_propagates_stop_failure_and_retains_temp_home():
    calls = []

    class Worker:
        _process = object()
        _sandbox_process = None
        lifecycle = SimpleNamespace(launcher_pid=404)

        def stop(self, **_kwargs):
            calls.append("stop")
            raise OSError("synthetic worker Job drain failure")

    class Home:
        def __init__(self):
            self.calls = 0

        def cleanup(self):
            self.calls += 1

    worker = Worker()
    home = Home()
    supervisor = object.__new__(TaskWorkerSupervisor)
    supervisor._closed = False
    supervisor._cleanup_unconfirmed = False
    supervisor._cleanup_error = None
    supervisor._launch_attempted = True
    supervisor._stop_attempted = False
    supervisor._authenticated = True
    supervisor._worker = worker
    supervisor._home = home

    with pytest.raises(TaskWorkerExecutionError, match="CLEANUP_UNCONFIRMED"):
        supervisor._abort()

    assert supervisor._closed is False
    assert supervisor._cleanup_unconfirmed is True
    assert supervisor._worker is worker
    assert home.calls == 0
    with pytest.raises(TaskWorkerExecutionError, match="CLEANUP_UNCONFIRMED"):
        supervisor._abort()
    assert calls == ["stop"]
