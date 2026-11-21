"""Real Windows-process checks for the Host-owned bootstrap pipe."""

from __future__ import annotations

import base64
import http.client
import io
import json
import os
import queue
import site
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest
from tests.integration.test_host_supervisor_crash_e2e import (
    _event as _controller_event,
)
from tests.integration.test_host_supervisor_crash_e2e import (
    _spawn as _spawn_controller,
)
from tests.integration.test_host_supervisor_crash_e2e import (
    _write as _write_controller,
)

import openjarvis.control.host_supervisor_bootstrap as host_bootstrap
from openjarvis.control.host_supervisor_bootstrap import (
    HostSupervisorBootstrapClient,
    HostSupervisorBootstrapService,
)
from openjarvis.control.windows_peer import (
    is_process_descendant,
    process_identity,
)


class _BootstrapManager:
    def validate_host_task_binding(self, *_args, **_kwargs):
        raise AssertionError("task grants are outside this bootstrap test")

    def close(self):
        pass


@pytest.mark.skipif(os.name != "nt", reason="Windows Host bootstrap boundary")
@pytest.mark.parametrize("listener_started", [False, True], ids=["startup", "rearm"])
def test_host_bootstrap_listener_failure_closes_owned_resources(
    monkeypatch, listener_started
):
    pipe = rf"\\.\pipe\atlas-s17-cleanup-{uuid.uuid4().hex}"
    manager = _BootstrapManager()
    manager_closed = threading.Event()
    monkeypatch.setattr(manager, "close", manager_closed.set)
    service = HostSupervisorBootstrapService(pipe, manager)
    original_listener = host_bootstrap.NamedPipeServer
    initial_listener_available = listener_started

    def fail_listener_setup(name):
        nonlocal initial_listener_available
        if initial_listener_available:
            initial_listener_available = False
            return original_listener(name)
        raise OSError("fixture cannot create listener")

    monkeypatch.setattr(host_bootstrap, "NamedPipeServer", fail_listener_setup)
    try:
        if listener_started:
            service.start()
            serve_thread = service._thread
            service.register_controller(os.getpid())
            identity = service._service_identity
            HostSupervisorBootstrapClient(
                pipe,
                supervisor_pid=identity["pid"],
                supervisor_created_filetime=identity["created_filetime"],
            ).bootstrap()
            assert service._closed.wait(timeout=5)
            serve_thread.join(timeout=5)
            assert not serve_thread.is_alive()
            assert manager_closed.wait(timeout=5)
        else:
            with pytest.raises(OSError, match="fixture cannot create listener"):
                service.run(io.BytesIO())
        assert manager_closed.is_set()
        service.close()
        assert service._close_complete is True
        assert service._server is None
    finally:
        service.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows Host bootstrap boundary")
def test_host_bootstrap_rejects_ipc_request_replay():
    pipe = rf"\\.\pipe\atlas-s15-replay-{uuid.uuid4().hex}"
    service = HostSupervisorBootstrapService(pipe, _BootstrapManager())
    service.start()
    try:
        service.register_controller(os.getpid())
        identity = service._service_identity
        client = HostSupervisorBootstrapClient(
            pipe,
            supervisor_pid=identity["pid"],
            supervisor_created_filetime=identity["created_filetime"],
        ).bootstrap()
        session = service._sessions[client.session_id]
        body = {
            "operation": "ISSUE_CONTROLLER",
            "session_id": client.session_id,
            "request_id": uuid.uuid4().hex,
            "payload": {},
        }
        request = {
            "body": body,
            "mac": host_bootstrap._mac(
                session.api_key, b"atlas-host-ipc-request-v1", body
            ),
        }
        with pytest.raises(PermissionError, match="Host task binding invalid"):
            service._authenticated_request(service._service_identity, request)
        with pytest.raises(PermissionError, match="Host IPC authentication rejected"):
            service._authenticated_request(service._service_identity, request)
    finally:
        service.close()


def _test_child_env(root: Path, home: Path) -> dict[str, str]:
    env = {
        name: os.environ[name]
        for name in (
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "COMSPEC",
            "USERPROFILE",
            "HOMEDRIVE",
            "HOMEPATH",
        )
        if name in os.environ
    }
    env["PYTHONPATH"] = os.pathsep.join(
        (str(root / "src"), str(root), *site.getsitepackages())
    )
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["OPENJARVIS_HOME"] = str(home)
    return env


def _spawn_product_host(root: Path, pipe: str, home: Path, db_path: Path):
    home.mkdir(parents=True, exist_ok=True)
    config_path = home / "config.toml"
    config_path.write_text(
        f'[agent_manager]\nenabled = true\ndb_path = "{db_path.as_posix()}"\n',
        encoding="utf-8",
    )
    env = _test_child_env(root, home)
    process = subprocess.Popen(
        [
            str(Path(sys.base_prefix) / "python.exe"),
            "-m",
            "openjarvis.cli",
            "host-supervisor",
            "--pipe-name",
            pipe,
        ],
        cwd=root,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    lines = queue.Queue()

    def read_lines():
        for line in process.stdout:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=read_lines, daemon=True).start()
    return process, lines


def _spawn_product_controller(root: Path, home: Path):
    process = subprocess.Popen(
        [
            str(Path(sys.base_prefix) / "python.exe"),
            str(root / "tests" / "integration" / "host_controller_serve_process.py"),
        ],
        cwd=root,
        env=_test_child_env(root, home),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    lines = queue.Queue()

    def read_lines():
        for line in process.stdout:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=read_lines, daemon=True).start()
    return process, lines


def _write_product_controller(process, value: dict) -> None:
    process.stdin.write(json.dumps(value) + "\n")
    process.stdin.flush()


def _product_controller_event(process, lines, event: str, timeout: float = 30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                f"product Controller CLI exited with {process.returncode}"
            )
        try:
            line = lines.get(timeout=min(0.1, max(0.01, deadline - time.monotonic())))
        except queue.Empty:
            continue
        if line is None:
            raise AssertionError(f"product Controller CLI exited with {process.poll()}")
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if value.get("event") == event:
            return value
    raise AssertionError(f"product Controller event timed out: {event}")


def _loopback_json(port: int, method: str, path: str, payload=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"} if body is not None else {}
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
        return response.status, json.loads(data) if data else None
    finally:
        connection.close()


def _wait_product_controller(process, port: int) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(
                f"product Controller CLI exited with {process.returncode}"
            )
        try:
            status, _ = _loopback_json(port, "GET", "/openapi.json")
            if status == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.05)
    raise AssertionError("product Controller API listener timed out")


def _loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _register_controller(host, pid: int) -> None:
    host.stdin.write(
        json.dumps({"operation": "REGISTER_CONTROLLER", "pid": pid}) + "\n"
    )
    host.stdin.flush()


def _stop_product_host(host) -> None:
    if host.poll() is not None:
        return
    host.stdin.write('{"operation":"SHUTDOWN"}\n')
    host.stdin.flush()
    try:
        host.wait(timeout=15)
    except subprocess.TimeoutExpired:
        host.kill()
        host.wait(timeout=5)


def _host_ready(host, lines):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        line = lines.get(timeout=max(0.1, deadline - time.monotonic()))
        if line is None:
            raise AssertionError(f"product Host CLI exited with {host.poll()}")
        if line.startswith("ATLAS_HOST_READY:"):
            fields = line.strip().split(":")
            assert len(fields) == 3, line
            return int(fields[1]), int(fields[2])
    raise AssertionError("product Host CLI readiness timed out")


def _spawn(root: Path, mode: str, pipe: str, pid: int, created: int):
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        (str(root / "src"), str(root), *site.getsitepackages())
    )
    process = subprocess.Popen(
        [
            str(Path(sys.base_prefix) / "python.exe"),
            str(root / "tests" / "integration" / "host_bootstrap_process.py"),
            mode,
            pipe,
            str(pid),
            str(created),
        ],
        cwd=root,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    lines = queue.Queue()

    def read_lines():
        for line in process.stdout:
            lines.put(line)
        lines.put(None)

    threading.Thread(target=read_lines, daemon=True).start()
    return process, lines


def _event(process, lines):
    line = lines.get(timeout=20)
    if line is None:
        raise AssertionError(f"bootstrap child exited with {process.poll()}")
    return json.loads(line)


def _stop(process, *, force=False):
    if process.poll() is not None:
        return
    if force:
        process.kill()
    else:
        process.stdin.write("STOP\n")
        process.stdin.flush()
    process.wait(timeout=10)


@pytest.mark.skipif(os.name != "nt", reason="Windows Host bootstrap boundary")
def test_host_pipe_binds_controller_child_session_and_revokes_stolen_key():
    root = Path(__file__).resolve().parents[2]
    identity = process_identity(os.getpid())
    pipe = rf"\\.\pipe\atlas-s15-bootstrap-{uuid.uuid4().hex}"
    service = HostSupervisorBootstrapService(pipe, _BootstrapManager())
    controller_a = None
    controller_b = None
    stolen_client = None
    candidate = None
    service.start()
    try:
        controller_a, lines_a = _spawn(
            root, "bootstrap", pipe, identity["pid"], identity["created_filetime"]
        )
        controller_a_pid = controller_a.pid
        service.register_controller(controller_a.pid)
        controller_a.stdin.write("BOOTSTRAP\n")
        controller_a.stdin.flush()
        session_a = _event(controller_a, lines_a)
        assert session_a["event"] == "bootstrapped"
        assert session_a["pid"] == controller_a.pid

        candidate = subprocess.Popen(
            [
                str(Path(sys.base_prefix) / "python.exe"),
                "-c",
                "import time; time.sleep(30)",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        with pytest.raises(PermissionError, match="previous Controller process"):
            service.register_controller(candidate.pid)
        _stop(candidate, force=True)
        candidate = None

        api_key = service._sessions[session_a["session_id"]].api_key
        stolen_client, stolen_lines = _spawn(
            root, "stolen-key", pipe, identity["pid"], identity["created_filetime"]
        )
        stolen_client.stdin.write(
            json.dumps(
                {
                    "session_id": session_a["session_id"],
                    "key": base64.b64encode(api_key).decode("ascii"),
                }
            )
            + "\n"
        )
        stolen_client.stdin.flush()
        stolen = _event(stolen_client, stolen_lines)
        assert stolen["event"] == "stolen_key_attempt"
        assert stolen["accepted"] is False
        assert stolen["detail"] == "HOST_IPC_REJECTED"
        assert stolen["pid"] != controller_a.pid
        assert stolen["pid"] != os.getpid()
        stolen_client_pid = stolen["pid"]
        stolen_client.wait(timeout=10)
        stolen_client = None

        _stop(controller_a, force=True)
        controller_a_exit = controller_a.returncode
        assert controller_a_exit != 0
        controller_a = None
        assert not service._closed.is_set()

        controller_b, lines_b = _spawn(
            root, "bootstrap", pipe, identity["pid"], identity["created_filetime"]
        )
        service.register_controller(controller_b.pid)
        controller_b.stdin.write("BOOTSTRAP\n")
        controller_b.stdin.flush()
        session_b = _event(controller_b, lines_b)
        controller_b_pid = controller_b.pid
        assert session_b["event"] == "bootstrapped"
        assert session_b["pid"] == controller_b_pid
        assert session_b["principal_id"] == session_a["principal_id"]
        assert session_b["session_id"] != session_a["session_id"]
        assert not service._sessions[session_a["session_id"]].active
        assert service._sessions[session_b["session_id"]].active
        assert not service._closed.is_set()
        _stop(controller_b)
        controller_b_exit = controller_b.returncode
        assert controller_b_exit == 0
        controller_b = None
        print(
            json.dumps(
                {
                    "named_pipe_server_pid": identity["pid"],
                    "controller_a_pid": controller_a_pid,
                    "controller_a_exit_code": controller_a_exit,
                    "stolen_key_client_pid": stolen_client_pid,
                    "stolen_key_rejected": True,
                    "controller_b_pid": controller_b_pid,
                    "controller_b_exit_code": controller_b_exit,
                    "new_session_issued": True,
                    "old_session_revoked": True,
                    "task_supervisor_started": False,
                }
            )
        )
    finally:
        for child in (stolen_client, candidate, controller_a, controller_b):
            if child is not None:
                _stop(child, force=child is controller_a or child is candidate)
        service.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows Host bootstrap boundary")
def test_host_bootstrap_rejects_same_user_sibling_process():
    root = Path(__file__).resolve().parents[2]
    host_identity = process_identity(os.getpid())
    pipe = rf"\\.\pipe\atlas-s15-sibling-{uuid.uuid4().hex}"
    service = HostSupervisorBootstrapService(pipe, _BootstrapManager())
    launcher = None
    sibling = None
    service.start()
    try:
        launcher, launcher_lines = _spawn(
            root,
            "bootstrap",
            pipe,
            host_identity["pid"],
            host_identity["created_filetime"],
        )
        service.register_controller(launcher.pid)
        launcher.stdin.write("BOOTSTRAP\n")
        launcher.stdin.flush()
        session = _event(launcher, launcher_lines)
        launcher_identity = process_identity(launcher.pid)

        sibling, sibling_lines = _spawn(
            root,
            "bootstrap",
            pipe,
            host_identity["pid"],
            host_identity["created_filetime"],
        )
        sibling_identity = process_identity(sibling.pid)
        assert sibling_identity["user_sid"] == launcher_identity["user_sid"]
        assert sibling_identity["integrity_rid"] == launcher_identity["integrity_rid"]
        assert not is_process_descendant(sibling.pid, launcher_identity)

        sibling.stdin.write("BOOTSTRAP\n")
        sibling.stdin.flush()
        sibling_exit = sibling.wait(timeout=10)
        sibling_error = sibling.stderr.read()
        assert sibling_exit != 0
        assert "Host bootstrap rejected" in sibling_error
        assert len(service._sessions) == 1
        assert service._current_session_id == session["session_id"]
        print(
            json.dumps(
                {
                    "host_pid": host_identity["pid"],
                    "registered_controller_pid": launcher.pid,
                    "same_user_and_integrity_sibling_pid": sibling.pid,
                    "sibling_outside_registered_tree": True,
                    "sibling_rejected": True,
                    "session_count": len(service._sessions),
                }
            )
        )
    finally:
        if sibling is not None:
            _stop(sibling, force=True)
        if launcher is not None:
            _stop(launcher, force=True)
        service.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows Host bootstrap boundary")
def test_host_bootstrap_rejects_forged_supervisor_identity():
    root = Path(__file__).resolve().parents[2]
    pipe = rf"\\.\pipe\atlas-s15-forged-host-{uuid.uuid4().hex}"
    service = HostSupervisorBootstrapService(pipe, _BootstrapManager())
    controllers = []
    service.start()
    try:
        identity = service._service_identity
        cases = (
            (int(identity["pid"]) + 1, int(identity["created_filetime"])),
            (int(identity["pid"]), int(identity["created_filetime"]) + 1),
        )
        for pinned_pid, pinned_created in cases:
            controller, _lines = _spawn(
                root, "bootstrap", pipe, pinned_pid, pinned_created
            )
            controllers.append(controller)
            controller.stdin.write("BOOTSTRAP\n")
            controller.stdin.flush()
            assert controller.wait(timeout=10) != 0
            assert (
                "Windows named-pipe server identity mismatch"
                in controller.stderr.read()
            )
        assert not service._sessions
        print(
            json.dumps(
                {
                    "actual_pipe_server_pid": identity["pid"],
                    "actual_created_filetime": identity["created_filetime"],
                    "pid_mismatch_rejected": True,
                    "creation_time_mismatch_rejected": True,
                    "session_count": 0,
                }
            )
        )
    finally:
        for controller in controllers:
            _stop(controller, force=True)
        service.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows Host bootstrap boundary")
def test_host_bootstrap_serializes_concurrent_controller_authentication():
    root = Path(__file__).resolve().parents[2]
    identity = process_identity(os.getpid())
    pipe = rf"\\.\pipe\atlas-s15-concurrent-auth-{uuid.uuid4().hex}"
    service = HostSupervisorBootstrapService(pipe, _BootstrapManager())
    clients = []
    accepted = []
    rejected = []
    service.start()
    try:
        service.register_controller(identity["pid"])
        clients = [
            _spawn(
                root,
                "bootstrap",
                pipe,
                identity["pid"],
                identity["created_filetime"],
            )
            for _ in range(2)
        ]
        for process, _lines in clients:
            process.stdin.write("BOOTSTRAP\n")
            process.stdin.flush()

        for process, lines in clients:
            line = lines.get(timeout=20)
            if line is None:
                process.wait(timeout=10)
                assert process.returncode != 0
                rejected.append(process.stderr.read())
            else:
                accepted.append(json.loads(line))
        assert len(accepted) == len(rejected) == 1
        assert "Host bootstrap rejected" in rejected[0]
        assert len(service._sessions) == 1
        session = service._sessions[accepted[0]["session_id"]]
        assert session.identity["pid"] == accepted[0]["pid"]
        print(
            json.dumps(
                {
                    "controller_pids": [process.pid for process, _ in clients],
                    "accepted_controller_pid": accepted[0]["pid"],
                    "rejected_count": len(rejected),
                    "session_count": len(service._sessions),
                    "second_live_controller_rejected": True,
                }
            )
        )
    finally:
        for process, _lines in clients:
            _stop(process, force=process.poll() is None)
        service.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows Host bootstrap boundary")
def test_host_bootstrap_stolen_key_inside_host_tree_is_pid_bound():
    root = Path(__file__).resolve().parents[2]
    host_identity = process_identity(os.getpid())
    pipe = rf"\\.\pipe\atlas-s15-stolen-in-tree-{uuid.uuid4().hex}"
    service = HostSupervisorBootstrapService(pipe, _BootstrapManager())
    controller = None
    attacker = None
    service.start()
    try:
        service.register_controller(host_identity["pid"])
        controller, controller_lines = _spawn(
            root,
            "bootstrap",
            pipe,
            host_identity["pid"],
            host_identity["created_filetime"],
        )
        controller.stdin.write("BOOTSTRAP\n")
        controller.stdin.flush()
        session = _event(controller, controller_lines)
        controller_identity = process_identity(controller.pid)
        issued = service._sessions[session["session_id"]]
        assert issued.identity == controller_identity
        assert is_process_descendant(controller.pid, host_identity)

        attacker, attacker_lines = _spawn(
            root,
            "stolen-key",
            pipe,
            host_identity["pid"],
            host_identity["created_filetime"],
        )
        attacker_identity = process_identity(attacker.pid)
        assert attacker.pid != controller.pid
        assert attacker_identity["user_sid"] == controller_identity["user_sid"]
        assert (
            attacker_identity["integrity_rid"] == controller_identity["integrity_rid"]
        )
        assert is_process_descendant(attacker.pid, host_identity)
        assert attacker_identity != issued.identity

        attacker.stdin.write(
            json.dumps(
                {
                    "session_id": session["session_id"],
                    "key": base64.b64encode(issued.api_key).decode("ascii"),
                }
            )
            + "\n"
        )
        attacker.stdin.flush()
        result = _event(attacker, attacker_lines)
        assert result["event"] == "stolen_key_attempt"
        assert result["accepted"] is False
        assert result["detail"] == "HOST_IPC_REJECTED"
        attacker.wait(timeout=10)
        print(
            json.dumps(
                {
                    "registered_host_launcher_pid": host_identity["pid"],
                    "controller_pid": controller.pid,
                    "stolen_key_attacker_pid": attacker.pid,
                    "attacker_inside_authorized_host_tree": True,
                    "same_user_and_integrity": True,
                    "session_owner_pid_mismatch": True,
                    "stolen_key_rejected": True,
                }
            )
        )
    finally:
        if attacker is not None:
            _stop(attacker, force=True)
        if controller is not None:
            _stop(controller, force=True)
        service.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows Host bootstrap boundary")
def test_host_bootstrap_rejects_forged_hmac_from_bound_controller():
    root = Path(__file__).resolve().parents[2]
    host_identity = process_identity(os.getpid())
    pipe = rf"\\.\pipe\atlas-s15-forged-hmac-{uuid.uuid4().hex}"
    service = HostSupervisorBootstrapService(pipe, _BootstrapManager())
    controller = None
    service.start()
    try:
        service.register_controller(host_identity["pid"])
        controller, controller_lines = _spawn(
            root,
            "bootstrap",
            pipe,
            host_identity["pid"],
            host_identity["created_filetime"],
        )
        controller.stdin.write("BOOTSTRAP\n")
        controller.stdin.flush()
        session = _event(controller, controller_lines)
        identity = process_identity(controller.pid)
        issued = service._sessions[session["session_id"]]
        assert issued.identity == identity
        assert identity["pid"] == controller.pid
        assert is_process_descendant(controller.pid, host_identity)

        controller.stdin.write("FORGED_HMAC\n")
        controller.stdin.flush()
        result = _event(controller, controller_lines)
        assert result["event"] == "forged_hmac_attempt"
        assert result["pid"] == controller.pid
        assert result["accepted"] is False
        assert result["detail"] == "HOST_IPC_REJECTED"
        assert not issued.used_requests
        controller.wait(timeout=10)
        print(
            json.dumps(
                {
                    "registered_host_launcher_pid": host_identity["pid"],
                    "bound_controller_pid": controller.pid,
                    "forged_hmac_rejected": True,
                    "request_id_not_consumed": True,
                }
            )
        )
    finally:
        if controller is not None:
            _stop(controller, force=True)
        service.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows Host bootstrap boundary")
def test_host_bootstrap_controller_crash_reauth_and_epoch_fencing(tmp_path):
    root = Path(__file__).resolve().parents[2]
    shared = tmp_path / "shared"
    shared.mkdir()
    db_path = shared / "controller.db"
    host_home = tmp_path / "product-host-home"
    pipe = rf"\\.\pipe\atlas-s15-product-host-{uuid.uuid4().hex}"
    host, host_lines = _spawn_product_host(root, pipe, host_home, db_path)
    host_pid, host_created = _host_ready(host, host_lines)
    assert host_pid == host.pid
    host_identity = process_identity(host_pid)
    assert host_identity["created_filetime"] == host_created
    host_bootstrap = {
        "pipe_name": pipe,
        "supervisor_pid": host_pid,
        "supervisor_created_filetime": host_created,
    }
    controller_a = None
    controller_b = None
    try:
        controller_a, lines_a = _spawn_controller()
        _register_controller(host, controller_a.pid)
        _write_controller(
            controller_a,
            {"mode": "a", "temp": str(shared), "host_bootstrap": host_bootstrap},
        )
        created = _controller_event(controller_a, lines_a)
        assert created["event"] == "created"
        assert created["host_session_id"]
        binding_event = _controller_event(controller_a, lines_a)
        assert binding_event["event"] == "host_binding"
        binding = binding_event["binding"]
        assert binding["task_id"] == created["task"]
        assert binding["epoch"] == 1
        assert _controller_event(controller_a, lines_a)["event"] == "checkpoint-ready"

        controller_a_pid = controller_a.pid
        controller_a.kill()
        controller_a_exit = controller_a.wait(timeout=10)
        controller_a = None
        assert controller_a_exit != 0

        controller_b, lines_b = _spawn_controller()
        _register_controller(host, controller_b.pid)
        _write_controller(
            controller_b,
            {
                "mode": "b",
                "temp": str(shared),
                "host_bootstrap": host_bootstrap,
                "agent": created["agent"],
                "task": created["task"],
                "old_binding": binding,
            },
        )
        observed = _controller_event(controller_b, lines_b)
        assert observed["event"] == "observer"
        assert observed["status"] == 200, observed
        body = observed["body"]
        assert observed["host_session_id"] != created["host_session_id"]
        assert body["task_status"] == "running"
        assert body["journal_states"] == ["CHECKPOINTED"]
        assert body["checkpoint_version"] >= 1
        exit_record = body["exit_record"]["record"]
        assert exit_record["binding"] == binding
        supervisor_pid = exit_record["supervisor_pid"]
        worker_pid = exit_record["evidence"]["worker_pid"]
        assert exit_record["evidence"]["worker_exit_code"] == 0
        assert exit_record["evidence"]["job_exit_confirmed"] is True
        supervisor_identity = process_identity(supervisor_pid)
        assert supervisor_identity["pid"] == supervisor_pid
        assert process_identity(host_pid)["created_filetime"] == host_created
        assert host.poll() is None

        controller_b.stdin.write("FENCE_EPOCH\n")
        controller_b.stdin.flush()
        fence = _controller_event(controller_b, lines_b)
        assert fence["event"] == "epoch_fence"
        assert fence["status"] == 200, fence
        assert fence["body"]["previous_epoch"] == binding["epoch"]
        assert fence["body"]["epoch"] == binding["epoch"] + 1
        assert fence["body"]["state"] == "FENCED"
        assert fence["body"]["journal_states"] == ["CHECKPOINTED"]
        with sqlite3.connect(db_path, timeout=5) as connection:
            authority_state = connection.execute(
                "SELECT epoch,state,owner_hash FROM agent_task_authority "
                "WHERE task_id=?",
                (binding["task_id"],),
            ).fetchone()
            dispatch_count = connection.execute(
                "SELECT COUNT(*) FROM task_tool_dispatch_claims WHERE task_id=?",
                (binding["task_id"],),
            ).fetchone()[0]
        assert authority_state[0:2] == (binding["epoch"] + 1, "FENCED")
        assert authority_state[2] != binding["owner_hash"]
        assert dispatch_count == 1
        controller_b.stdin.write("PROBE_OLD_EPOCH\n")
        controller_b.stdin.flush()
        old_epoch = _controller_event(controller_b, lines_b)
        assert old_epoch == {"event": "old_epoch_rejected", "rejected": True}
        controller_b_pid = controller_b.pid
        assert controller_b.wait(timeout=10) == 0
        controller_b_exit = controller_b.returncode
        controller_b = None
        assert host.poll() is None
        assert (
            process_identity(supervisor_pid)["created_filetime"]
            == supervisor_identity["created_filetime"]
        )
        print(
            json.dumps(
                {
                    "host_bootstrap_server_pid": host_pid,
                    "host_created_filetime": host_created,
                    "controller_a_pid": controller_a_pid,
                    "controller_a_exit_code": controller_a_exit,
                    "supervisor_pid": supervisor_pid,
                    "supervisor_id": binding["supervisor_id"],
                    "worker_pid": worker_pid,
                    "worker_id": binding["worker_id"],
                    "worker_exit_code": exit_record["evidence"]["worker_exit_code"],
                    "job_empty_verified": exit_record["evidence"]["job_exit_confirmed"],
                    "controller_b_pid": controller_b_pid,
                    "controller_b_exit_code": controller_b_exit,
                    "agent_id": binding["agent_id"],
                    "task_id": binding["task_id"],
                    "attempt": binding["attempt"],
                    "epoch_1": binding["epoch"],
                    "epoch_2": binding["epoch"] + 1,
                    "authority_epoch_fence": fence["body"],
                    "old_epoch_rejected_by_sqlite_authority": True,
                    "old_session_rotated": True,
                    "tool_dispatch_count": dispatch_count,
                    "journal_states": body["journal_states"],
                    "checkpoint_version": body["checkpoint_version"],
                    "supervisor_survived_controller_a": True,
                    "product_host_cli_process": True,
                    "new_epoch_execution": "NOT RUN",
                    "tauri_host_launcher": "NOT RUN",
                }
            )
        )
    finally:
        for process in (controller_a, controller_b):
            if process is not None:
                _stop(process, force=True)
        _stop_product_host(host)
    assert host.returncode == 0
    print(json.dumps({"event": "host_shutdown", "exit_code": host.returncode}))


@pytest.mark.skipif(os.name != "nt", reason="Windows Host bootstrap boundary")
def test_host_bootstrap_product_serve_cli_crash_reauth_and_epoch_fencing(tmp_path):
    _exercise_product_serve_recovery(tmp_path, hold_before_checkpoint=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows Host bootstrap boundary")
def test_product_serve_cli_quarantines_unknown_outcome(tmp_path):
    _exercise_product_serve_recovery(tmp_path, hold_before_checkpoint=True)


def _exercise_product_serve_recovery(tmp_path, *, hold_before_checkpoint):
    root = Path(__file__).resolve().parents[2]
    shared = tmp_path / "shared"
    shared.mkdir()
    db_path = shared / "controller.db"
    host_home = tmp_path / "product-serve-home"
    pipe = rf"\\.\pipe\atlas-s15-product-serve-{uuid.uuid4().hex}"
    host, host_lines = _spawn_product_host(root, pipe, host_home, db_path)
    host_pid, host_created = _host_ready(host, host_lines)
    assert host_pid == host.pid
    assert process_identity(host_pid)["created_filetime"] == host_created
    (host_home / "config.toml").write_text(
        '[engine]\ndefault = "synthetic"\n'
        '[speech]\nbackend = "none"\n'
        '[server]\nhost = "127.0.0.1"\nmodel = "fake-model"\n'
        "[telemetry]\nenabled = false\n"
        "[traces]\nenabled = false\n"
        f'[agent_manager]\nenabled = true\ndb_path = "{db_path.as_posix()}"\n',
        encoding="utf-8",
    )
    host_bootstrap = {
        "pipe_name": pipe,
        "supervisor_pid": host_pid,
        "supervisor_created_filetime": host_created,
    }
    controller_a = None
    controller_b = None
    try:
        port_a = _loopback_port()
        controller_a, lines_a = _spawn_product_controller(root, host_home)
        _register_controller(host, controller_a.pid)
        _write_product_controller(
            controller_a,
            {
                "mode": "a",
                "port": port_a,
                "hold_before_checkpoint": hold_before_checkpoint,
                **host_bootstrap,
            },
        )
        session_a = _product_controller_event(controller_a, lines_a, "host_bootstrap")
        _wait_product_controller(controller_a, port_a)
        agent_status, agent = _loopback_json(
            port_a,
            "POST",
            "/v1/managed-agents",
            {
                "name": "sprint15-product-serve",
                "agent_type": "orchestrator",
                "config": {
                    "model": "fake-model",
                    "tools": ["synthetic_echo"],
                    "mcp_tools": False,
                },
            },
        )
        assert agent_status == 200
        task_status, task = _loopback_json(
            port_a,
            "POST",
            f"/v1/managed-agents/{agent['id']}/tasks",
            {
                "description": "product serve CLI supervisor crash",
                "required_tools": ["synthetic_echo"],
            },
        )
        assert task_status == 200

        run_result = {}

        def run_task():
            try:
                run_result["result"] = _loopback_json(
                    port_a,
                    "POST",
                    f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run",
                )
            except Exception as exc:
                run_result["error"] = type(exc).__name__

        run_thread = threading.Thread(target=run_task, daemon=True)
        run_thread.start()
        crash_barrier = (
            "result-before-checkpoint" if hold_before_checkpoint else "checkpoint-ready"
        )
        try:
            _product_controller_event(controller_a, lines_a, crash_barrier, timeout=25)
        except AssertionError:
            raise AssertionError(
                f"product serve task did not reach the crash barrier: {run_result}"
            ) from None
        controller_a_pid = controller_a.pid
        controller_a.kill()
        controller_a_exit = controller_a.wait(timeout=10)
        controller_a = None
        run_thread.join(timeout=5)
        assert controller_a_exit != 0

        port_b = _loopback_port()
        controller_b, lines_b = _spawn_product_controller(root, host_home)
        _register_controller(host, controller_b.pid)
        _write_product_controller(
            controller_b,
            {"mode": "b", "port": port_b, **host_bootstrap},
        )
        session_b = _product_controller_event(controller_b, lines_b, "host_bootstrap")
        assert session_b["principal_id"] == session_a["principal_id"]
        assert session_b["session_fingerprint"] != session_a["session_fingerprint"]
        _wait_product_controller(controller_b, port_b)

        deadline = time.monotonic() + 25
        observed = None
        while time.monotonic() < deadline:
            try:
                status, body = _loopback_json(
                    port_b,
                    "GET",
                    f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}"
                    "/worker-exit-evidence",
                )
                if status == 200:
                    observed = body
                    break
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        assert observed is not None
        assert observed["task_status"] == "running"
        expected_state = "UNKNOWN_OUTCOME" if hold_before_checkpoint else "CHECKPOINTED"
        assert observed["journal_states"] == [expected_state]
        assert observed["checkpoint_version"] >= 1
        exit_record = observed["exit_record"]["record"]
        binding = exit_record["binding"]
        assert binding["epoch"] == 1
        assert binding["principal_id"] == session_b["principal_id"]
        snapshot_query = (
            "SELECT a.principal_id,a.attempt,a.owner_hash,a.epoch,a.expires_at,"
            "a.state,t.checkpoint_id,t.checkpoint_version,j.mac "
            "FROM agent_task_authority a "
            "JOIN agent_tasks t ON t.id=a.task_id "
            "JOIN task_tool_journal_heads j ON j.task_id=a.task_id "
            "WHERE a.task_id=?"
        )
        with sqlite3.connect(db_path, timeout=5) as connection:
            before_fence = connection.execute(snapshot_query, (task["id"],)).fetchone()
        assert before_fence[:4] == (
            binding["principal_id"],
            binding["attempt"],
            binding["owner_hash"],
            binding["epoch"],
        )
        assert before_fence[4] >= binding["lease_expires_at"] > time.time()
        assert before_fence[5] == "ACTIVE"
        assert before_fence[6] and before_fence[7] == observed["checkpoint_version"]
        cross_task_status, _ = _loopback_json(
            port_b,
            "GET",
            f"/v1/managed-agents/{agent['id']}/tasks/{uuid.uuid4().hex}"
            "/worker-exit-evidence",
        )
        assert cross_task_status == 403
        worker_evidence = exit_record["evidence"]
        assert worker_evidence["worker_exit_code"] == 0
        assert worker_evidence["job_exit_confirmed"] is True
        supervisor_pid = exit_record["supervisor_pid"]
        supervisor_identity = process_identity(supervisor_pid)
        assert host.poll() is None
        assert process_identity(host_pid)["created_filetime"] == host_created

        task_url = f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}"
        fence_status, fence = _loopback_json(port_b, "POST", f"{task_url}/epoch-fence")
        if hold_before_checkpoint:
            assert fence_status == 409
            assert fence["detail"] == "task epoch fence unavailable"
            rerun_status, rerun = _loopback_json(port_b, "POST", f"{task_url}/run")
            assert rerun_status == 409
            assert rerun["detail"] == "task state or execution attempt is stale"
            with sqlite3.connect(db_path, timeout=5) as connection:
                after_denials = connection.execute(
                    snapshot_query, (task["id"],)
                ).fetchone()
                claim_count = connection.execute(
                    "SELECT COUNT(*) FROM task_tool_dispatch_claims WHERE task_id=?",
                    (task["id"],),
                ).fetchone()[0]
                fence_count = connection.execute(
                    "SELECT COUNT(*) FROM agent_task_epoch_fences WHERE task_id=?",
                    (task["id"],),
                ).fetchone()[0]
            assert after_denials == before_fence
            assert claim_count == 1
            assert fence_count == 0
            assert host.poll() is None
            assert (
                process_identity(supervisor_pid)["created_filetime"]
                == supervisor_identity["created_filetime"]
            )
            print(
                json.dumps(
                    {
                        "event": "unknown_outcome_quarantine",
                        "host_bootstrap_server_pid": host_pid,
                        "controller_a_pid": controller_a_pid,
                        "controller_b_pid": controller_b.pid,
                        "supervisor_pid": supervisor_pid,
                        "worker_pid": worker_evidence["worker_pid"],
                        "worker_job_empty_verified": True,
                        "session_rotated": True,
                        "journal_states": observed["journal_states"],
                        "checkpoint_version": observed["checkpoint_version"],
                        "epoch": binding["epoch"],
                        "tool_dispatch_count": claim_count,
                        "epoch_fence_count": fence_count,
                        "epoch_fence_http_status": fence_status,
                        "rerun_http_status": rerun_status,
                        "journal_and_checkpoint_unchanged": True,
                    }
                )
            )
            return
        assert fence_status == 200, fence
        assert fence["previous_epoch"] == binding["epoch"]
        assert fence["epoch"] == binding["epoch"] + 1
        assert fence["state"] == "FENCED"
        assert fence["journal_states"] == ["CHECKPOINTED"]
        with sqlite3.connect(db_path, timeout=5) as connection:
            authority_state = connection.execute(
                "SELECT epoch,state,owner_hash FROM agent_task_authority "
                "WHERE task_id=?",
                (task["id"],),
            ).fetchone()
            dispatch_count = connection.execute(
                "SELECT COUNT(*) FROM task_tool_dispatch_claims WHERE task_id=?",
                (task["id"],),
            ).fetchone()[0]
        assert authority_state[0:2] == (binding["epoch"] + 1, "FENCED")
        assert authority_state[2] != binding["owner_hash"]
        assert dispatch_count == 1
        _write_product_controller(
            controller_b,
            {"operation": "PROBE_OLD_EPOCH", "binding": binding},
        )
        old_epoch = _product_controller_event(
            controller_b, lines_b, "old_epoch_rejected"
        )
        assert old_epoch["rejected"] is True
        repeat_fence_status, _ = _loopback_json(
            port_b, "POST", f"{task_url}/epoch-fence"
        )
        assert repeat_fence_status == 403
        rerun_status, rerun = _loopback_json(port_b, "POST", f"{task_url}/run")
        assert rerun_status == 409
        assert rerun["detail"] == "task state or execution attempt is stale"
        with sqlite3.connect(db_path, timeout=5) as connection:
            dispatch_count_after_denials = connection.execute(
                "SELECT COUNT(*) FROM task_tool_dispatch_claims WHERE task_id=?",
                (task["id"],),
            ).fetchone()[0]
            after_denials = connection.execute(snapshot_query, (task["id"],)).fetchone()
        assert dispatch_count_after_denials == dispatch_count
        assert after_denials[:2] == before_fence[:2]
        assert after_denials[2:4] == (authority_state[2], fence["epoch"])
        assert after_denials[4] <= time.time()
        assert after_denials[5] == "FENCED"
        assert after_denials[6:] == before_fence[6:]

        controller_b_pid = controller_b.pid
        controller_b.kill()
        controller_b_exit = controller_b.wait(timeout=10)
        controller_b = None
        assert controller_b_exit != 0
        assert host.poll() is None
        assert (
            process_identity(supervisor_pid)["created_filetime"]
            == supervisor_identity["created_filetime"]
        )
        print(
            json.dumps(
                {
                    "host_bootstrap_server_pid": host_pid,
                    "host_created_filetime": host_created,
                    "controller_a_pid": controller_a_pid,
                    "controller_a_exit_code": controller_a_exit,
                    "supervisor_pid": supervisor_pid,
                    "supervisor_id": binding["supervisor_id"],
                    "worker_pid": worker_evidence["worker_pid"],
                    "worker_id": binding["worker_id"],
                    "worker_exit_code": worker_evidence["worker_exit_code"],
                    "job_empty_verified": worker_evidence["job_exit_confirmed"],
                    "controller_b_pid": controller_b_pid,
                    "controller_b_exit_code": controller_b_exit,
                    "agent_id": agent["id"],
                    "task_id": task["id"],
                    "attempt": binding["attempt"],
                    "epoch_1": binding["epoch"],
                    "epoch_2": fence["epoch"],
                    "authority_state": "FENCED",
                    "journal_states_after_fence": fence["journal_states"],
                    "old_epoch_rejected_by_sqlite_authority": True,
                    "session_rotated": True,
                    "tool_dispatch_count": dispatch_count,
                    "tool_dispatch_count_after_denials": dispatch_count_after_denials,
                    "cross_task_observer_http_status": cross_task_status,
                    "repeated_fence_http_status": repeat_fence_status,
                    "fenced_task_rerun_http_status": rerun_status,
                    "journal_and_checkpoint_unchanged": True,
                    "lease_invalidated_by_fence": True,
                    "principal_and_attempt_preserved": True,
                    "journal_states": observed["journal_states"],
                    "checkpoint_version": observed["checkpoint_version"],
                    "supervisor_survived_controller_a": True,
                    "product_host_cli_process": True,
                    "product_serve_cli_process": True,
                    "real_loopback_http_listener": True,
                    "new_epoch_execution": "NOT RUN",
                    "external_egress": "NOT RUN",
                    "tauri_host_launcher": "NOT RUN",
                }
            )
        )
    finally:
        for process in (controller_a, controller_b):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        _stop_product_host(host)
        assert host.returncode == 0
        print(json.dumps({"event": "host_shutdown", "exit_code": host.returncode}))
