"""Host-broker reconnect against a real supervisor and real worker."""

import base64
import ctypes
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from pathlib import Path

import pytest

from openjarvis.agents.manager import AgentManager
from openjarvis.agents.tool_semantics import arguments_sha256
from openjarvis.control.host_supervisor_broker import (
    HostSupervisorBroker,
    HostSupervisorClient,
    _send,
)
from openjarvis.control.host_task_supervisor import _write
from openjarvis.control.task_worker import TaskWorkerExecutionError
from openjarvis.control.task_worker_ipc import TaskWorkerChannel
from openjarvis.control.worker_process import safe_worker_environment
from openjarvis.core.types import ToolCall
from tests.agents.test_sprint15_task_tool_journal import KEY
from tests.control.test_host_task_supervisor import _setup


def test_short_transport_writes_are_completed():
    class PartialWriter:
        def __init__(self):
            self.data = bytearray()

        def write(self, data):
            part = bytes(data[:3])
            self.data.extend(part)
            return len(part)

        def flush(self):
            pass

    stream = PartialWriter()
    _send(stream, {"key": "value"})
    assert json.loads(stream.data) == {"key": "value"}
    stream = PartialWriter()
    _write(stream, b"authenticated-frame")
    assert base64.b64decode(stream.data.strip()) == b"authenticated-frame"


def test_broker_close_retains_supervisor_when_supervisor_drain_fails():
    class FakeSocket:
        def close(self):
            pass

    class FakeThread:
        def join(self, timeout=None):
            pass

        def is_alive(self):
            return False

    class FakeSupervisor:
        _closed = False

        def __init__(self):
            self.close_calls = 0

        def close(self):
            self.close_calls += 1
            raise OSError("synthetic Supervisor Job drain failure")

    supervisor = FakeSupervisor()
    broker = object.__new__(HostSupervisorBroker)
    broker._close_complete = False
    broker._cleanup_unconfirmed = False
    broker._cleanup_error = None
    broker._closed = threading.Event()
    broker._socket = FakeSocket()
    broker._active_conn = None
    broker._lock = threading.Lock()
    broker._thread = FakeThread()
    broker.supervisor = supervisor
    broker.unknown_outcome = False

    with pytest.raises(TaskWorkerExecutionError, match="CLEANUP_UNCONFIRMED"):
        broker.close()

    assert broker.supervisor is supervisor
    assert broker._close_complete is False
    assert broker._cleanup_unconfirmed is True
    assert supervisor.close_calls == 1
    with pytest.raises(TaskWorkerExecutionError, match="CLEANUP_UNCONFIRMED"):
        broker.close()
    assert supervisor.close_calls == 1


def test_broker_detects_disconnect_and_reauthenticates_observer(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    broker = HostSupervisorBroker(
        lambda grant, received: grant["principal_id"] == received["principal_id"],
        manager,
        identity[2],
        identity[3],
        integrity_key=KEY,
    )
    client = None
    observer = None
    try:
        grant = broker.issue(
            role="controller",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=binding["principal_id"],
            expires_at=time.time() + 45,
        )
        client = HostSupervisorClient(
            grant,
            binding,
            validate_authority=lambda: manager.validate_task_authority(*identity),
        )
        client.start()
        deadline = time.time() + 10
        manager.prepare_task_tool_journal(
            *identity,
            worker_id=binding["worker_id"],
            request_id="request-a",
            tool_call_id="call-a",
            tool_name="synthetic_echo",
            arguments_sha256=arguments_sha256({"value": "broker"}),
            deadline=deadline,
            integrity_key=KEY,
        )
        manager.transition_task_tool_journal(
            *identity,
            worker_id=binding["worker_id"],
            request_id="request-a",
            expected="PREPARED",
            state="DISPATCHED",
            integrity_key=KEY,
        )
        result = client.execute_tool(
            ToolCall("call-a", "synthetic_echo", "{}"),
            {"value": "broker"},
            timeout=10,
            request_id="request-a",
            deadline=deadline,
            checkpoint_version=1,
        )
        assert result.content == "synthetic:broker"
        supervisor = broker.supervisor
        supervisor_pid = supervisor.pid
        worker_pid = supervisor.evidence["worker_pid"]
        client.release_exit_evidence()
        assert broker.disconnected.wait(10)
        assert not broker.unknown_outcome
        assert supervisor._process.poll() is None
        assert supervisor.pid == supervisor_pid
        assert supervisor.verify_exit_evidence(supervisor.evidence)
        with pytest.raises(TaskWorkerExecutionError):
            HostSupervisorClient(grant, binding, validate_authority=lambda: None)
        observer_grant = broker.issue(
            role="observer",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=binding["principal_id"],
            expires_at=time.time() + 30,
        )
        observer = HostSupervisorClient(
            observer_grant,
            binding,
            validate_authority=lambda: manager.validate_task_authority(*identity),
        )
        record = observer.read_exit_evidence(supervisor.evidence_verification_key)
        assert record["record"]["supervisor_pid"] == supervisor_pid
        assert record["record"]["evidence"]["worker_pid"] == worker_pid
        with pytest.raises(TaskWorkerExecutionError):
            observer.execute_tool(
                ToolCall("observer-call", "synthetic_echo", "{}"),
                {"value": "denied"},
                timeout=5,
                request_id="observer-request",
                deadline=time.time() + 5,
                checkpoint_version=1,
            )
        assert broker.tool_dispatch_count == 1
        print(
            {
                "supervisor_pid": supervisor_pid,
                "worker_pid": worker_pid,
                "job_id": record["record"]["job_id"],
                "session_rotated": True,
            }
        )
    finally:
        if observer is not None:
            observer.release_exit_evidence()
        if client is not None:
            client.release_exit_evidence()
        broker.close()
        manager.close()


@pytest.mark.parametrize(
    "attack", ["forged_key", "cross_task", "cross_principal", "expired"]
)
def test_broker_rejects_forged_or_mismatched_grants(tmp_path, attack):
    manager, identity, binding = _setup(tmp_path)
    broker = HostSupervisorBroker(
        lambda grant, received: grant["principal_id"] == received["principal_id"],
        manager,
        identity[2],
        identity[3],
        integrity_key=KEY,
    )
    try:
        grant = broker.issue(
            role="controller",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=binding["principal_id"],
            expires_at=time.time() + 30,
        )
        used_binding = dict(binding)
        if attack == "forged_key":
            grant = {**grant, "key": b"x" * 32}
        elif attack == "cross_task":
            used_binding["task_id"] = "wrong-task"
        elif attack == "cross_principal":
            used_binding["principal_id"] = "wrong-principal"
        else:
            broker._grants[grant["session_id"]]["expires_at"] = time.time() - 1
        with pytest.raises(TaskWorkerExecutionError):
            HostSupervisorClient(grant, used_binding, validate_authority=lambda: None)
        assert broker.supervisor is None
        assert broker.tool_dispatch_count == 0
    finally:
        broker.close()
        manager.close()


def test_broker_rejects_nonfinite_session_expiry(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    broker = HostSupervisorBroker(
        lambda *_: True, manager, identity[2], identity[3], integrity_key=KEY
    )
    try:
        with pytest.raises(ValueError):
            broker.issue(
                role="controller",
                task_id=binding["task_id"],
                agent_id=binding["agent_id"],
                principal_id=binding["principal_id"],
                expires_at=float("nan"),
            )
    finally:
        broker.close()
        manager.close()


def test_host_revocation_stops_idle_worker_and_revokes_session(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    allowed = [True]
    broker = HostSupervisorBroker(
        lambda *_: allowed[0],
        manager,
        identity[2],
        identity[3],
        integrity_key=KEY,
    )
    client = None
    try:
        grant = broker.issue(
            role="controller",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=binding["principal_id"],
            expires_at=time.time() + 30,
        )
        client = HostSupervisorClient(grant, binding, validate_authority=lambda: None)
        client.start()
        allowed[0] = False
        assert broker.disconnected.wait(10)
        assert broker.supervisor._process.poll() is None
        assert broker.supervisor.verify_exit_evidence(broker.supervisor.evidence)
        with pytest.raises(TaskWorkerExecutionError):
            client.execute_tool(
                ToolCall("revoked", "synthetic_echo", "{}"),
                {"value": "no"},
                timeout=5,
                request_id="revoked",
                deadline=time.time() + 5,
                checkpoint_version=1,
            )
        assert broker.tool_dispatch_count == 0
    finally:
        if client is not None:
            client.release_exit_evidence()
        broker.close()
        manager.close()


def test_cancellation_during_real_worker_dispatch_is_unknown(tmp_path, monkeypatch):
    manager, identity, binding = _setup(tmp_path)
    manager.start_tick(binding["agent_id"])
    broker = HostSupervisorBroker(
        lambda *_: True, manager, identity[2], identity[3], integrity_key=KEY
    )
    client = None
    thread = None
    claimed = threading.Event()
    original_claim = manager.claim_task_tool_dispatch

    def observe_claim(*args, **kwargs):
        original_claim(*args, **kwargs)
        claimed.set()

    monkeypatch.setattr(manager, "claim_task_tool_dispatch", observe_claim)
    try:
        grant = broker.issue(
            role="controller",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=binding["principal_id"],
            expires_at=time.time() + 30,
        )
        client = HostSupervisorClient(grant, binding, validate_authority=lambda: None)
        client.start()
        supervisor = broker.supervisor
        native = ctypes.WinDLL("ntdll", use_last_error=True)
        native.NtSuspendProcess.argtypes = [wintypes.HANDLE]
        native.NtSuspendProcess.restype = ctypes.c_long
        assert native.NtSuspendProcess(supervisor._worker_handle) == 0
        deadline = time.time() + 15
        manager.prepare_task_tool_journal(
            *identity,
            worker_id=binding["worker_id"],
            request_id="cancel-request",
            tool_call_id="cancel-call",
            tool_name="synthetic_echo",
            arguments_sha256=arguments_sha256({"value": "cancel"}),
            deadline=deadline,
            integrity_key=KEY,
        )
        manager.transition_task_tool_journal(
            *identity,
            worker_id=binding["worker_id"],
            request_id="cancel-request",
            expected="PREPARED",
            state="DISPATCHED",
            integrity_key=KEY,
        )
        failures = []

        def dispatch():
            try:
                client.execute_tool(
                    ToolCall("cancel-call", "synthetic_echo", "{}"),
                    {"value": "cancel"},
                    timeout=15,
                    request_id="cancel-request",
                    deadline=deadline,
                    checkpoint_version=1,
                )
            except Exception as exc:
                failures.append(exc)

        thread = threading.Thread(target=dispatch)
        thread.start()
        assert claimed.wait(10)
        threading.Event().wait(0.3)
        manager.request_cancellation(binding["agent_id"], reason="user")
        thread.join(timeout=15)
        assert not thread.is_alive()
        assert len(failures) == 1
        assert isinstance(failures[0], TaskWorkerExecutionError)
        assert failures[0].unknown_outcome is True
        assert broker.disconnected.wait(10)
        assert broker.tool_dispatch_count == 1
        assert broker.unknown_outcome is True
        rows = manager.read_task_tool_journal(
            identity[0], identity[1], identity[2], identity[3], integrity_key=KEY
        )
        assert rows[0]["recovery_state"] == "UNKNOWN_OUTCOME"
        assert (
            manager._get_task(binding["task_id"], agent_id=binding["agent_id"])[
                "status"
            ]
            != "completed"
        )
    finally:
        if client is not None:
            client.release_exit_evidence()
        if thread is not None:
            thread.join(timeout=10)
        broker.close()
        manager.close()


def test_real_worker_timeout_is_unknown_and_owned_job_stops(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    broker = HostSupervisorBroker(
        lambda *_: True, manager, identity[2], identity[3], integrity_key=KEY
    )
    client = None
    worker_handle = None
    try:
        grant = broker.issue(
            role="controller",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=binding["principal_id"],
            expires_at=time.time() + 30,
        )
        client = HostSupervisorClient(grant, binding, validate_authority=lambda: None)
        client.start()
        supervisor = broker.supervisor
        kernel = supervisor._kernel()
        worker_handle = wintypes.HANDLE()
        assert kernel.DuplicateHandle(
            kernel.GetCurrentProcess(),
            supervisor._worker_handle,
            kernel.GetCurrentProcess(),
            ctypes.byref(worker_handle),
            0,
            False,
            2,
        )
        native = ctypes.WinDLL("ntdll", use_last_error=True)
        native.NtSuspendProcess.argtypes = [wintypes.HANDLE]
        native.NtSuspendProcess.restype = ctypes.c_long
        assert native.NtSuspendProcess(worker_handle) == 0
        deadline = time.time() + 1.5
        manager.prepare_task_tool_journal(
            *identity,
            worker_id=binding["worker_id"],
            request_id="timeout-request",
            tool_call_id="timeout-call",
            tool_name="synthetic_echo",
            arguments_sha256=arguments_sha256({"value": "timeout"}),
            deadline=deadline,
            integrity_key=KEY,
        )
        manager.transition_task_tool_journal(
            *identity,
            worker_id=binding["worker_id"],
            request_id="timeout-request",
            expected="PREPARED",
            state="DISPATCHED",
            integrity_key=KEY,
        )
        with pytest.raises(TaskWorkerExecutionError) as failure:
            client.execute_tool(
                ToolCall("timeout-call", "synthetic_echo", "{}"),
                {"value": "timeout"},
                timeout=1.5,
                request_id="timeout-request",
                deadline=deadline,
                checkpoint_version=1,
            )
        assert failure.value.unknown_outcome is True
        assert kernel.WaitForSingleObject(worker_handle, 10000) == 0
        assert broker.disconnected.wait(10)
        assert broker.tool_dispatch_count == 1
        supervisor_alive = supervisor._process.poll() is None
        if not supervisor_alive:
            assert broker.supervisor_lost.wait(5)
            assert not supervisor.verify_exit_evidence(supervisor.evidence)
        print(
            {
                "timeout_supervisor_alive": supervisor_alive,
                "timeout_worker_os_exit_confirmed": True,
            }
        )
        rows = manager.read_task_tool_journal(
            identity[0], identity[1], identity[2], identity[3], integrity_key=KEY
        )
        assert rows[0]["recovery_state"] == "UNKNOWN_OUTCOME"
        assert (
            manager._get_task(binding["task_id"], agent_id=binding["agent_id"])[
                "status"
            ]
            != "completed"
        )
    finally:
        if worker_handle:
            supervisor._kernel().CloseHandle(worker_handle)
        if client is not None:
            client.release_exit_evidence()
        broker.close()
        manager.close()


def test_broker_rejects_unjournaled_tool_before_worker_dispatch(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    broker = HostSupervisorBroker(
        lambda *_: True,
        manager,
        identity[2],
        identity[3],
        integrity_key=KEY,
    )
    client = None
    try:
        grant = broker.issue(
            role="controller",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=binding["principal_id"],
            expires_at=time.time() + 30,
        )
        client = HostSupervisorClient(grant, binding, validate_authority=lambda: None)
        client.start()
        with pytest.raises(TaskWorkerExecutionError) as failure:
            client.execute_tool(
                ToolCall("unprepared", "synthetic_echo", "{}"),
                {"value": "no"},
                timeout=5,
                request_id="unprepared",
                deadline=time.time() + 5,
                checkpoint_version=1,
            )
        assert failure.value.unknown_outcome is True
        assert broker.disconnected.wait(10)
        assert broker.tool_dispatch_count == 0
    finally:
        if client is not None:
            client.release_exit_evidence()
        broker.close()
        manager.close()


def test_durable_exit_record_reloads_and_rejects_tampering(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    broker = HostSupervisorBroker(
        lambda *_: True, manager, identity[2], identity[3], integrity_key=KEY
    )
    client = None
    reopened = None
    observer = None
    try:
        grant = broker.issue(
            role="controller",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=binding["principal_id"],
            expires_at=time.time() + 30,
        )
        client = HostSupervisorClient(grant, binding, validate_authority=lambda: None)
        client.start()
        client.release_exit_evidence()
        assert broker.disconnected.wait(10)
        supervisor = broker.supervisor
        reopened = AgentManager(manager._db_path)
        record = reopened.read_host_worker_exit(
            identity[2],
            identity[3],
            binding,
            supervisor.evidence_verification_key,
            integrity_key=KEY,
        )
        assert record == supervisor.exit_record
        with pytest.raises(PermissionError, match="already recorded"):
            reopened.record_host_worker_exit(
                identity[2],
                identity[3],
                binding,
                record,
                supervisor.evidence_verification_key,
                integrity_key=KEY,
                verify_os_exit=supervisor.verify_exit_evidence,
            )
        reopened._conn.execute("UPDATE task_worker_exit_evidence SET payload='{}'")
        reopened._conn.commit()
        with pytest.raises(PermissionError):
            reopened.read_host_worker_exit(
                identity[2],
                identity[3],
                binding,
                supervisor.evidence_verification_key,
                integrity_key=KEY,
            )
        observer_grant = broker.issue(
            role="observer",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=binding["principal_id"],
            expires_at=time.time() + 30,
        )
        observer = HostSupervisorClient(
            observer_grant, binding, validate_authority=lambda: None
        )
        with pytest.raises(TaskWorkerExecutionError):
            observer.read_exit_evidence(supervisor.evidence_verification_key)
    finally:
        if observer is not None:
            observer.release_exit_evidence()
        if reopened is not None:
            reopened.close()
        if client is not None:
            client.release_exit_evidence()
        broker.close()
        manager.close()


def test_forged_supervisor_hmac_is_rejected(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    address = listener.getsockname()

    def forge():
        conn, _ = listener.accept()
        with conn, conn.makefile("rwb", buffering=0) as stream:
            outer = json.loads(stream.readline())
            original = json.loads(base64.b64decode(outer["frame"]))["body"]
            fake = TaskWorkerChannel(b"x" * 32, binding, role="worker")
            frame = fake.seal(
                "AUTHENTICATE",
                message_id="forged",
                request_id=original["request_id"],
                tool_call_id=original["tool_call_id"],
                deadline=original["deadline"],
                cancellation="ACTIVE",
                payload={"authenticated": True},
            )
            stream.write(
                json.dumps({"frame": base64.b64encode(frame).decode()}).encode() + b"\n"
            )
        listener.close()

    thread = threading.Thread(target=forge, daemon=True)
    thread.start()
    try:
        with pytest.raises(TaskWorkerExecutionError):
            HostSupervisorClient(
                {"address": address, "session_id": "forged", "key": b"y" * 32},
                binding,
                validate_authority=lambda: manager.validate_task_authority(*identity),
            )
        thread.join(timeout=5)
        assert not thread.is_alive()
    finally:
        listener.close()
        manager.close()


def test_ipc_timeout_after_dispatch_is_unknown(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    address = listener.getsockname()
    key = b"t" * 32

    def unresponsive_host():
        conn, _ = listener.accept()
        with conn, conn.makefile("rwb", buffering=0) as stream:
            outer = json.loads(stream.readline())
            host = TaskWorkerChannel(key, binding, role="worker")
            request = host.open(base64.b64decode(outer["frame"]))
            reply = host.seal(
                "AUTHENTICATE",
                message_id="auth-response",
                request_id=request["request_id"],
                tool_call_id=request["tool_call_id"],
                deadline=request["deadline"],
                cancellation="ACTIVE",
                payload={"authenticated": True},
            )
            stream.write(
                json.dumps({"frame": base64.b64encode(reply).decode()}).encode() + b"\n"
            )
            stream.readline()
            threading.Event().wait(0.5)
        listener.close()

    thread = threading.Thread(target=unresponsive_host, daemon=True)
    thread.start()
    client = None
    try:
        client = HostSupervisorClient(
            {"address": address, "session_id": "timeout", "key": key},
            binding,
            validate_authority=lambda: manager.validate_task_authority(*identity),
        )
        with pytest.raises(TaskWorkerExecutionError) as failure:
            client.execute_tool(
                ToolCall("timeout-call", "synthetic_echo", "{}"),
                {"value": "no"},
                timeout=0.2,
                request_id="timeout-request",
                deadline=time.time() + 0.2,
                checkpoint_version=1,
            )
        assert failure.value.unknown_outcome is True
        thread.join(timeout=5)
        assert not thread.is_alive()
    finally:
        if client is not None:
            client.release_exit_evidence()
        listener.close()
        manager.close()


def test_broker_detects_supervisor_crash_and_refuses_exit_evidence(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    broker = HostSupervisorBroker(
        lambda *_: True,
        manager,
        identity[2],
        identity[3],
        integrity_key=KEY,
    )
    client = None
    observer = None
    worker_handle = None
    try:
        grant = broker.issue(
            role="controller",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=binding["principal_id"],
            expires_at=time.time() + 30,
        )
        client = HostSupervisorClient(
            grant,
            binding,
            validate_authority=lambda: manager.validate_task_authority(*identity),
        )
        client.start()
        supervisor = broker.supervisor
        kernel = supervisor._kernel()
        worker_handle = wintypes.HANDLE()
        assert kernel.DuplicateHandle(
            kernel.GetCurrentProcess(),
            supervisor._worker_handle,
            kernel.GetCurrentProcess(),
            ctypes.byref(worker_handle),
            0,
            False,
            2,
        )
        supervisor._process.kill()
        assert supervisor._process.wait(timeout=10) != 0
        assert broker.supervisor_lost.wait(10)
        assert supervisor._kernel().WaitForSingleObject(worker_handle, 10000) == 0
        assert broker.disconnected.wait(10)
        assert broker.unknown_outcome
        assert supervisor.exit_record is None
        observer_grant = broker.issue(
            role="observer",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=binding["principal_id"],
            expires_at=time.time() + 30,
        )
        observer = HostSupervisorClient(
            observer_grant, binding, validate_authority=lambda: None
        )
        with pytest.raises(TaskWorkerExecutionError):
            observer.read_exit_evidence(supervisor.evidence_verification_key)
    finally:
        if worker_handle:
            supervisor._kernel().CloseHandle(worker_handle)
        if observer is not None:
            observer.release_exit_evidence()
        if client is not None:
            client.release_exit_evidence()
        broker.close()
        manager.close()


def test_broker_rejects_stolen_session_key_from_another_process(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    broker = HostSupervisorBroker(
        lambda *_: True,
        manager,
        identity[2],
        identity[3],
        integrity_key=KEY,
    )
    try:
        grant = broker.issue(
            role="controller",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=binding["principal_id"],
            expires_at=time.time() + 30,
        )
        assert grant["client_identity"]["pid"] == os.getpid()
        grant_wire = {**grant, "key": base64.b64encode(grant["key"]).decode("ascii")}
        code = """import base64,json,sys
from openjarvis.control.host_supervisor_broker import HostSupervisorClient
from openjarvis.control.task_worker import TaskWorkerExecutionError
p=json.load(sys.stdin)
p['grant']['key']=base64.b64decode(p['grant']['key'],validate=True)
try:
 client=HostSupervisorClient(p['grant'],p['binding'],validate_authority=lambda:None)
 client.start()
except TaskWorkerExecutionError:
 print('OS_PEER_REJECTED')
else:
 raise SystemExit('stolen key accepted from another process')
"""
        proc = subprocess.Popen(
            [str(Path(sys.base_prefix) / "python.exe"), "-c", code],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=safe_worker_environment(
                pythonpath=[str(Path(__file__).resolve().parents[2] / "src")],
                home=str(tmp_path),
            ),
            cwd=str(Path(__file__).resolve().parents[2]),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout, stderr = proc.communicate(
            json.dumps({"grant": grant_wire, "binding": binding}), timeout=15
        )
        assert proc.returncode == 0, stderr
        assert "OS_PEER_REJECTED" in stdout
        assert broker.supervisor is None
        assert broker.tool_dispatch_count == 0
        print(
            json.dumps(
                {
                    "host_pid": os.getpid(),
                    "attacker_pid": proc.pid,
                    "expected_pid": grant["client_identity"]["pid"],
                    "expected_created_filetime": grant["client_identity"][
                        "created_filetime"
                    ],
                    "same_user_sid": grant["client_identity"]["user_sid"],
                    "integrity_rid": grant["client_identity"]["integrity_rid"],
                    "stolen_key_rejected": True,
                    "tool_dispatch_count": broker.tool_dispatch_count,
                }
            ),
            flush=True,
        )
    finally:
        broker.close()
        manager.close()


def test_live_old_owner_epoch_change_is_rechecked_at_dispatch(tmp_path, monkeypatch):
    manager, identity, binding = _setup(tmp_path)
    broker = HostSupervisorBroker(
        lambda *_: True,
        manager,
        identity[2],
        identity[3],
        integrity_key=KEY,
    )
    client = None
    try:
        grant = broker.issue(
            role="controller",
            task_id=binding["task_id"],
            agent_id=binding["agent_id"],
            principal_id=binding["principal_id"],
            expires_at=time.time() + 30,
        )
        client = HostSupervisorClient(grant, binding, validate_authority=lambda: None)
        client.start()
        supervisor = broker.supervisor
        assert supervisor is not None and supervisor._process.poll() is None
        assert not supervisor.verify_exit_evidence(supervisor.evidence)
        deadline = time.time() + 20
        request_id = "real-epoch-change"
        call_id = "real-epoch-call"
        params = {"value": "must-not-dispatch"}
        manager.prepare_task_tool_journal(
            *identity,
            worker_id=binding["worker_id"],
            request_id=request_id,
            tool_call_id=call_id,
            tool_name="synthetic_echo",
            arguments_sha256=arguments_sha256(params),
            deadline=deadline,
            integrity_key=KEY,
        )
        manager.transition_task_tool_journal(
            *identity,
            worker_id=binding["worker_id"],
            request_id=request_id,
            expected="PREPARED",
            state="DISPATCHED",
            integrity_key=KEY,
        )
        transitioned = []
        original_claim = manager.claim_task_tool_dispatch

        def change_epoch_before_claim(*args, **kwargs):
            with sqlite3.connect(manager._db_path, timeout=5) as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT owner_hash, epoch FROM agent_task_authority "
                    "WHERE task_id=?",
                    (binding["task_id"],),
                ).fetchone()
                assert row is not None
                next_owner = hashlib.sha256(b"synthetic-next-owner").hexdigest()
                changed = conn.execute(
                    "UPDATE agent_task_authority SET owner_hash=?, epoch=? "
                    "WHERE task_id=? AND agent_id=? AND principal_id=? AND attempt=? "
                    "AND owner_hash=? AND epoch=? AND state='ACTIVE' AND expires_at>?",
                    (
                        next_owner,
                        row[1] + 1,
                        binding["task_id"],
                        binding["agent_id"],
                        binding["principal_id"],
                        binding["attempt"],
                        row[0],
                        row[1],
                        time.time(),
                    ),
                )
                assert changed.rowcount == 1
                conn.commit()
            transitioned.append(
                {
                    "old_epoch": row[1],
                    "new_epoch": row[1] + 1,
                    "new_owner_hash": next_owner,
                }
            )
            return original_claim(*args, **kwargs)

        monkeypatch.setattr(
            manager, "claim_task_tool_dispatch", change_epoch_before_claim
        )
        with pytest.raises(TaskWorkerExecutionError) as failure:
            client.execute_tool(
                ToolCall(call_id, "synthetic_echo", "{}"),
                params,
                timeout=15,
                request_id=request_id,
                deadline=deadline,
                checkpoint_version=binding["checkpoint_version"],
            )
        assert failure.value.unknown_outcome is True
        assert transitioned and transitioned[0]["new_epoch"] == binding["epoch"] + 1
        assert broker.disconnected.wait(10)
        assert broker.tool_dispatch_count == 0
        assert supervisor._process.poll() is None
        assert supervisor.verify_exit_evidence(supervisor.evidence)
        assert (
            manager._conn.execute(
                "SELECT count(*) FROM task_tool_dispatch_claims WHERE task_id=?",
                (binding["task_id"],),
            ).fetchone()[0]
            == 0
        )
        with pytest.raises(PermissionError):
            manager.validate_task_authority(*identity)
        print(
            json.dumps(
                {
                    "controller_pid": os.getpid(),
                    "supervisor_pid": supervisor.pid,
                    "worker_pid": supervisor.evidence["worker_pid"],
                    "old_epoch": transitioned[0]["old_epoch"],
                    "new_epoch": transitioned[0]["new_epoch"],
                    "dispatch_count": broker.tool_dispatch_count,
                    "dispatch_claim_count": 0,
                    "worker_job_empty": supervisor.evidence["job_exit_confirmed"],
                    "stop_evidence_verified": True,
                    "new_epoch_execution": "NOT RUN",
                }
            ),
            flush=True,
        )
    finally:
        if client is not None:
            client.release_exit_evidence()
        broker.close()
        manager.close()
