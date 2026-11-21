"""Actual Controller API crash and host-owned supervisor reconnection."""

import base64
import ctypes
import json
import os
import queue
import site
import sqlite3
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from dataclasses import asdict
from pathlib import Path

import pytest

from openjarvis.agents.manager import AgentManager
from openjarvis.control.host_supervisor_broker import (
    HostSupervisorBroker,
    HostSupervisorClient,
)
from openjarvis.control.host_task_supervisor import HostTaskSupervisorProcess
from openjarvis.control.task_worker import TaskWorkerExecutionError
from openjarvis.security.principal import TestPrincipalAuthority


def _wire_grant(grant):
    return {**grant, "key": base64.b64encode(grant["key"]).decode("ascii")}


def _spawn():
    root = Path(__file__).resolve().parents[2]
    executable = Path(sys.base_prefix) / "python.exe"
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(root / "src"), str(root), *site.getsitepackages()]
    )
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    process = subprocess.Popen(
        [str(executable), str(Path(__file__).with_name("host_controller_process.py"))],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    lines = queue.Queue()

    def read():
        for line in process.stdout:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=read, daemon=True).start()
    return process, lines


def _write(process, obj):
    process.stdin.write(json.dumps(obj) + "\n")
    process.stdin.flush()


def _event(process, lines):
    value = lines.get(timeout=35)
    if value is None:
        raise AssertionError(
            f"controller exited: {process.poll()} {process.stderr.read()}"
        )
    return json.loads(value)


@pytest.mark.parametrize(
    "crash_point", ["after_checkpoint", "before_journal_result", "during_tool"]
)
def test_controller_api_crash_supervisor_survives_and_observer_reconnects(
    tmp_path, monkeypatch, crash_point
):
    controller_a, lines_a = _spawn()
    controller_b = None
    broker = None
    host_manager = None
    result_ready = threading.Event()
    release_result = threading.Event()
    if crash_point == "before_journal_result":
        original_execute = HostTaskSupervisorProcess.execute_tool

        def hold_result(self, *args, **kwargs):
            result = original_execute(self, *args, **kwargs)
            result_ready.set()
            if not release_result.wait(20):
                raise TimeoutError("test did not release worker result")
            return result

        monkeypatch.setattr(HostTaskSupervisorProcess, "execute_tool", hold_result)
    elif crash_point == "during_tool":
        original_execute = HostTaskSupervisorProcess.execute_tool

        def suspend_worker(self, *args, **kwargs):
            native = ctypes.WinDLL("ntdll", use_last_error=True)
            native.NtSuspendProcess.argtypes = [wintypes.HANDLE]
            native.NtSuspendProcess.restype = ctypes.c_long
            if native.NtSuspendProcess(self._worker_handle) != 0:
                raise PermissionError("owned worker could not be suspended")
            timer = threading.Timer(0.5, result_ready.set)
            timer.daemon = True
            timer.start()
            return original_execute(self, *args, **kwargs)

        monkeypatch.setattr(HostTaskSupervisorProcess, "execute_tool", suspend_worker)
    authority = TestPrincipalAuthority(b"sprint15-worker-authority")
    credential = authority.issue("principal-synthetic")
    principal = authority.verify(credential)
    try:
        _write(
            controller_a,
            {"mode": "a", "temp": str(tmp_path), "credential": asdict(credential)},
        )
        created = _event(controller_a, lines_a)
        assert created["event"] == "created"
        db = created["db"]
        host_manager = AgentManager(db)

        def authorize(grant, binding):
            return (
                authority.accepts(principal)
                and grant["principal_id"] == principal.principal_id
                and binding["principal_id"] == principal.principal_id
            )

        broker = HostSupervisorBroker(
            authorize,
            host_manager,
            principal,
            authority,
            integrity_key=b"sprint15-worker-checkpoint-integrity-key",
        )
        grant_a = broker.issue(
            role="controller",
            task_id=created["task"],
            agent_id=created["agent"],
            principal_id=principal.principal_id,
            expires_at=time.time() + 60,
            client_pid=controller_a.pid,
        )
        _write(controller_a, {"grant": _wire_grant(grant_a)})
        if crash_point == "after_checkpoint":
            assert _event(controller_a, lines_a)["event"] == "checkpoint-ready"
        else:
            assert result_ready.wait(20)
        supervisor = broker.supervisor
        assert supervisor is not None
        supervisor_pid, worker_pid = supervisor.pid, supervisor.evidence["worker_pid"]
        assert len({controller_a.pid, supervisor_pid, worker_pid}) == 3
        assert broker.tool_dispatch_count == 1
        binding = dict(broker.binding)
        controller_a.kill()
        assert controller_a.wait(timeout=10) != 0
        release_result.set()
        assert broker.disconnected.wait(15)
        assert broker.unknown_outcome is (crash_point == "during_tool")
        assert supervisor._process.poll() is None and supervisor.pid == supervisor_pid
        assert supervisor.verify_exit_evidence(supervisor.evidence)
        if crash_point == "during_tool":
            assert supervisor.evidence["worker_forced_termination"] is True
        else:
            assert supervisor.evidence["worker_exit_code"] == 0
        with pytest.raises(TaskWorkerExecutionError):
            HostSupervisorClient(grant_a, binding, validate_authority=lambda: None)

        forbidden_grant = broker.issue(
            role="controller",
            task_id=created["task"],
            agent_id=created["agent"],
            principal_id=principal.principal_id,
            expires_at=time.time() + 30,
        )
        with pytest.raises(TaskWorkerExecutionError):
            HostSupervisorClient(
                forbidden_grant, binding, validate_authority=lambda: None
            )
        assert broker.tool_dispatch_count == 1

        stale_grant = broker.issue(
            role="observer",
            task_id=created["task"],
            agent_id=created["agent"],
            principal_id=principal.principal_id,
            expires_at=time.time() + 30,
        )
        with pytest.raises(TaskWorkerExecutionError):
            HostSupervisorClient(
                stale_grant, {**binding, "epoch": 2}, validate_authority=lambda: None
            )

        controller_b, lines_b = _spawn()
        grant_b = broker.issue(
            role="observer",
            task_id=created["task"],
            agent_id=created["agent"],
            principal_id=principal.principal_id,
            expires_at=time.time() + 30,
            client_pid=controller_b.pid,
        )
        _write(
            controller_b,
            {
                "mode": "b",
                "credential": asdict(credential),
                "db": db,
                "binding": binding,
                "grant": _wire_grant(grant_b),
                "verification_key": base64.b64encode(
                    supervisor.evidence_verification_key
                ).decode("ascii"),
            },
        )
        observed = _event(controller_b, lines_b)
        assert observed["event"] == "observer"
        assert observed["status"] == 200, observed
        body = observed["body"]
        assert body["task_status"] == "running"
        expected_state = (
            "CHECKPOINTED" if crash_point == "after_checkpoint" else "UNKNOWN_OUTCOME"
        )
        assert body["journal_states"] == [expected_state]
        assert body["checkpoint_version"] >= 1
        record = body["exit_record"]["record"]
        assert record["supervisor_pid"] == supervisor_pid
        assert record["evidence"]["worker_pid"] == worker_pid
        assert record["evidence"]["job_exit_confirmed"] is True
        assert record["binding"] == binding
        assert controller_b.pid != controller_a.pid
        assert controller_b.wait(timeout=10) == 0
        with sqlite3.connect(db, timeout=5) as conn:
            journal = conn.execute(
                "SELECT request_id, result_sha256, state FROM task_tool_journal "
                "WHERE task_id=?",
                (binding["task_id"],),
            ).fetchone()
        assert journal is not None
        print(
            json.dumps(
                {
                    "controller_a_pid": controller_a.pid,
                    "controller_a_exit": controller_a.returncode,
                    "controller_b_pid": controller_b.pid,
                    "controller_b_exit": controller_b.returncode,
                    "supervisor_pid": supervisor_pid,
                    "supervisor_id": binding["supervisor_id"],
                    "worker_pid": worker_pid,
                    "worker_id": binding["worker_id"],
                    "job_id": record["job_id"],
                    "task_id": binding["task_id"],
                    "agent_id": binding["agent_id"],
                    "principal_id": binding["principal_id"],
                    "attempt": binding["attempt"],
                    "epoch": binding["epoch"],
                    "worker_exit_code": record["evidence"]["worker_exit_code"],
                    "worker_creation_time": record["worker_creation_time"],
                    "supervisor_creation_time": record["supervisor_creation_time"],
                    "job_empty_verified": supervisor._os_exit_verified(
                        supervisor.evidence["worker_exit_code"]
                    ),
                    "checkpoint_version": body["checkpoint_version"],
                    "journal_states": body["journal_states"],
                    "task_status": body["task_status"],
                    "journal_request_id": journal[0],
                    "journal_result_sha256": journal[1],
                    "journal_persisted_state": journal[2],
                    "controller_a_session": grant_a["session_id"],
                    "controller_b_session": grant_b["session_id"],
                    "tool_dispatch_count": broker.tool_dispatch_count,
                    "crash_point": crash_point,
                    "old_session_rejected": True,
                    "mismatched_epoch_rejected": True,
                }
            )
        )
    finally:
        release_result.set()
        for process in (controller_a, controller_b):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        if broker is not None:
            broker.close()
        if host_manager is not None:
            host_manager.close()
