"""Controller product route using a host-owned worker supervisor."""

import os
import time

from fastapi.testclient import TestClient
from tests.integration.test_phase1_sprint15_controller_worker_e2e import (
    _controller,
    _forbid_thread_fallback,
)

from openjarvis.agents.manager import AgentManager
from openjarvis.control.host_supervisor_broker import (
    HostSupervisorBroker,
    HostSupervisorClient,
)


def _broker(manager, principal, authority, key):
    host_manager = AgentManager(manager._db_path)
    broker = HostSupervisorBroker(
        lambda grant, binding: (
            authority.accepts(principal)
            and grant["principal_id"] == principal.principal_id
        ),
        host_manager,
        principal,
        authority,
        integrity_key=key,
    )
    return broker, host_manager


def test_controller_api_uses_real_host_supervisor(tmp_path, monkeypatch):
    manager, app, agent, _engine, _old, authority, principal, key = _controller(
        tmp_path, monkeypatch
    )
    _forbid_thread_fallback(monkeypatch)
    broker, host_manager = _broker(manager, principal, authority, key)
    try:
        with TestClient(app) as client:
            task = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={"description": "independent supervisor synthetic task"},
            ).json()
            grant = broker.issue(
                role="controller",
                task_id=task["id"],
                agent_id=agent["id"],
                principal_id=principal.principal_id,
                expires_at=time.time() + 30,
            )
            app.state.task_worker_supervisor_factory = (
                lambda binding, validate_authority: HostSupervisorClient(
                    grant, binding, validate_authority=validate_authority
                )
            )
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
            if response.status_code != 200 and broker.supervisor is not None:
                print(
                    {
                        "diagnostic_evidence": broker.supervisor.evidence,
                        "host_verified": broker.supervisor.verify_exit_evidence(
                            broker.supervisor.evidence
                        ),
                        "supervisor_lost": broker.supervisor_lost.is_set(),
                    }
                )
            assert response.status_code == 200, response.text
            body = response.json()
        supervisor = broker.supervisor
        evidence = supervisor.evidence
        assert body["task"]["status"] == "completed"
        assert supervisor.pid != os.getpid()
        assert evidence["controller_pid"] == supervisor.pid
        assert evidence["worker_pid"] not in {os.getpid(), supervisor.pid}
        assert evidence["tool_execution_pid"] == evidence["worker_pid"]
        assert evidence["job_exit_confirmed"] is True
        assert supervisor._process.returncode == 0
        assert broker.tool_dispatch_count == 1
        reopened = AgentManager(manager._db_path)
        try:
            assert (
                reopened._get_task(task["id"], agent_id=agent["id"])["status"]
                == "completed"
            )
            rows = reopened.read_task_tool_journal(
                task["id"], agent["id"], principal, authority, integrity_key=key
            )
            assert [row["state"] for row in rows] == ["CHECKPOINTED"]
            assert (
                reopened._conn.execute(
                    "SELECT count(*) FROM task_tool_dispatch_claims"
                ).fetchone()[0]
                == 1
            )
        finally:
            reopened.close()
        print(
            {
                "controller_pid": os.getpid(),
                "supervisor_pid": supervisor.pid,
                "worker_pid": evidence["worker_pid"],
                "task_id": task["id"],
                "worker_id": evidence["worker_instance_id"],
                "supervisor_id": evidence["supervisor_id"],
                "checkpoint_version": body["checkpoint_version"],
            }
        )
    finally:
        broker.close()
        host_manager.close()
        manager.close()


def test_production_principal_cannot_fall_back_to_task_worker(tmp_path, monkeypatch):
    manager, app, agent, _engine, supervisors, authority, _principal, _key = (
        _controller(tmp_path, monkeypatch)
    )
    _forbid_thread_fallback(monkeypatch)

    class ProductionAuthorityProxy:
        accepts = authority.accepts
        owns = authority.owns

    app.state.host_principal_authority = ProductionAuthorityProxy()
    try:
        with TestClient(app) as client:
            task = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={"description": "production fallback must fail closed"},
            ).json()
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
            assert response.status_code == 409
            assert "host supervisor factory required" in response.text
            assert supervisors == []
            assert (
                manager._get_task(task["id"], agent_id=agent["id"])["status"]
                == "failed"
            )
    finally:
        manager.close()


def test_controller_rejects_unverified_host_exit_evidence(tmp_path, monkeypatch):
    manager, app, agent, _engine, _old, authority, principal, key = _controller(
        tmp_path, monkeypatch
    )
    _forbid_thread_fallback(monkeypatch)
    broker, host_manager = _broker(manager, principal, authority, key)
    monkeypatch.setattr(HostSupervisorClient, "verify_exit_evidence", lambda *_: False)
    try:
        with TestClient(app) as client:
            task = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={"description": "reject unverified supervisor"},
            ).json()
            grant = broker.issue(
                role="controller",
                task_id=task["id"],
                agent_id=agent["id"],
                principal_id=principal.principal_id,
                expires_at=time.time() + 30,
            )
            app.state.task_worker_supervisor_factory = (
                lambda binding, validate_authority: HostSupervisorClient(
                    grant, binding, validate_authority=validate_authority
                )
            )
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
            assert response.status_code == 409
            assert (
                manager._get_task(task["id"], agent_id=agent["id"])["status"]
                == "failed"
            )
    finally:
        broker.close()
        host_manager.close()
        manager.close()
