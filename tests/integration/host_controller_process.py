"""Subprocess fixture running the actual Controller API for crash testing."""

import base64
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.integration.test_phase1_sprint15_controller_worker_e2e import _controller

from openjarvis.agents.manager import AgentManager
from openjarvis.control.host_supervisor_broker import HostSupervisorClient
from openjarvis.security.principal import PrincipalCredential, TestPrincipalAuthority
from openjarvis.server import agent_manager_routes


def _input():
    return json.loads(sys.stdin.readline())


def _grant(data):
    return {**data, "key": base64.b64decode(data["key"], validate=True)}


def _host_bootstrap(config):
    values = config.get("host_bootstrap")
    if values is None:
        return None
    from openjarvis.control.host_supervisor_bootstrap import (
        HostSupervisorBootstrapClient,
    )

    return HostSupervisorBootstrapClient(
        values["pipe_name"],
        supervisor_pid=values["supervisor_pid"],
        supervisor_created_filetime=values["supervisor_created_filetime"],
    ).bootstrap()


def controller_a(config):
    monkeypatch = pytest.MonkeyPatch()
    host_bootstrap = _host_bootstrap(config)
    manager, app, agent, engine, *_rest = _controller(
        Path(config["temp"]),
        monkeypatch,
        PrincipalCredential(**config["credential"]) if host_bootstrap is None else None,
        host_bootstrap=host_bootstrap,
    )
    if host_bootstrap is not None:
        factory = app.state.task_worker_supervisor_factory

        def capture_binding(binding, validate_authority):
            print(
                json.dumps({"event": "host_binding", "binding": dict(binding)}),
                flush=True,
            )
            return factory(binding, validate_authority)

        app.state.task_worker_supervisor_factory = capture_binding
    original_generate = engine.generate

    def generate(*args, **kwargs):
        if engine.call_count == 1:
            print(json.dumps({"event": "checkpoint-ready"}), flush=True)
            time.sleep(120)
        return original_generate(*args, **kwargs)

    engine.generate = generate
    with TestClient(app) as client:
        task = client.post(
            f"/v1/managed-agents/{agent['id']}/tasks",
            json={"description": "independent supervisor crash"},
        ).json()
        print(
            json.dumps(
                {
                    "event": "created",
                    "task": task["id"],
                    "agent": agent["id"],
                    "db": manager._db_path,
                    "host_session_id": (
                        host_bootstrap.session_id if host_bootstrap is not None else ""
                    ),
                }
            ),
            flush=True,
        )
        if host_bootstrap is None:
            grant = _grant(_input()["grant"])
            app.state.task_worker_supervisor_factory = (
                lambda binding, validate_authority: HostSupervisorClient(
                    grant, binding, validate_authority=validate_authority
                )
            )
        response = client.post(
            f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
        )
        print(
            json.dumps(
                {"event": "unexpected-completion", "status": response.status_code}
            ),
            flush=True,
        )


def controller_b(config):
    host_bootstrap = _host_bootstrap(config)
    if host_bootstrap is not None:
        monkeypatch = pytest.MonkeyPatch()
        manager, app, *_rest = _controller(
            Path(config["temp"]),
            monkeypatch,
            host_bootstrap=host_bootstrap,
            existing_agent_id=config["agent"],
        )
        try:
            with TestClient(app, raise_server_exceptions=False) as client:
                deadline = time.monotonic() + 20
                response = client.get(
                    f"/v1/managed-agents/{config['agent']}/tasks/{config['task']}"
                    "/worker-exit-evidence"
                )
                while response.status_code != 200 and time.monotonic() < deadline:
                    time.sleep(0.05)
                    response = client.get(
                        f"/v1/managed-agents/{config['agent']}/tasks/{config['task']}"
                        "/worker-exit-evidence"
                    )
                print(
                    json.dumps(
                        {
                            "event": "observer",
                            "status": response.status_code,
                            "body": response.json(),
                            "host_session_id": host_bootstrap.session_id,
                        }
                    ),
                    flush=True,
                )
            command = sys.stdin.readline().strip()
            if command == "FENCE_EPOCH":
                with TestClient(app, raise_server_exceptions=False) as client:
                    response = client.post(
                        f"/v1/managed-agents/{config['agent']}/tasks/{config['task']}"
                        "/epoch-fence"
                    )
                print(
                    json.dumps(
                        {
                            "event": "epoch_fence",
                            "status": response.status_code,
                            "body": response.json(),
                        }
                    ),
                    flush=True,
                )
                command = sys.stdin.readline().strip()
            if command == "PROBE_OLD_EPOCH":
                try:
                    host_bootstrap.issue(
                        config["old_binding"], validate_authority=lambda: None
                    )
                except PermissionError:
                    rejected = True
                else:
                    rejected = False
                print(
                    json.dumps({"event": "old_epoch_rejected", "rejected": rejected}),
                    flush=True,
                )
        finally:
            manager.close()
            monkeypatch.undo()
        return

    manager = AgentManager(config["db"])
    authority = TestPrincipalAuthority(b"sprint15-worker-authority")
    credential = PrincipalCredential(**config["credential"])
    authority.verify(credential)
    authority._issued[credential.token_id] = (
        credential.principal_id,
        credential.issued_at,
        credential.expires_at,
    )
    principal = authority.verify(credential)
    app = FastAPI()
    app.state.testing = True
    app.state.host_principal_authority = authority
    app.state.task_checkpoint_integrity_key = (
        b"sprint15-worker-checkpoint-integrity-key"
    )
    binding = config["binding"]
    grant = _grant(config["grant"])
    key = base64.b64decode(config["verification_key"], validate=True)

    def validate_reader():
        if not authority.accepts(principal):
            raise PermissionError("observer authorization revoked")
        task = manager._get_task(binding["task_id"], agent_id=binding["agent_id"])
        if task is None or task["principal_id"] != principal.principal_id:
            raise PermissionError("observer task mismatch")

    def fetch():
        client = HostSupervisorClient(
            grant, binding, validate_authority=validate_reader
        )
        try:
            return client.read_exit_evidence(key)
        finally:
            client.release_exit_evidence()

    app.state.host_supervisor_observer = {
        "binding": binding,
        "verification_key": key,
        "fetch": fetch,
    }

    @app.middleware("http")
    async def inject_host_context(request, call_next):
        request.state.host_principal_context = SimpleNamespace(principal=principal)
        return await call_next(request)

    for router in agent_manager_routes.create_agent_manager_router(manager):
        app.include_router(router)
    with TestClient(app) as client:
        response = client.get(
            f"/v1/managed-agents/{binding['agent_id']}/tasks/{binding['task_id']}"
            "/worker-exit-evidence"
        )
        print(
            json.dumps(
                {
                    "event": "observer",
                    "status": response.status_code,
                    "body": response.json(),
                }
            ),
            flush=True,
        )
    manager.close()


if __name__ == "__main__":
    config = _input()
    if config["mode"] == "a":
        controller_a(config)
    elif config["mode"] == "b":
        controller_b(config)
    else:
        raise SystemExit(2)
