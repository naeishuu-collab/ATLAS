"""Controller heartbeat renews only the still-authorized task owner."""

import threading
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from openjarvis.agents.manager import AgentManager
from openjarvis.core.execution import ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.security.principal import TestPrincipalAuthority
from openjarvis.server.agent_manager_routes import (
    _TaskHeartbeat,
    create_agent_manager_router,
)
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec
from tests.agents.fake_engine import FakeEngine


def test_heartbeat_renews_without_checkpoints_across_managers(tmp_path, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr("openjarvis.agents.manager.time.time", lambda: clock[0])
    path = str(tmp_path / "task.db")
    manager = AgentManager(path)
    other = None
    heartbeat = None
    try:
        agent = manager.create_agent("worker")
        task = manager.create_task(agent["id"], "work")
        authority = TestPrincipalAuthority(b"synthetic-heartbeat", ttl=10000)
        principal = authority.verify(authority.issue("owner"))
        token = "a" * 32
        task = manager.start_task(
            task["id"], agent["id"], principal.principal_id, None, worker_token=token
        )
        binding = (
            task["id"],
            agent["id"],
            principal,
            authority,
            task["execution_attempt"],
            token,
            1,
        )
        first_renewal = threading.Event()
        later_renewal = threading.Event()
        original = manager.renew_task_authority

        def record_renewal(*args):
            with manager._db_lock:
                original(*args)
                if clock[0] == 1000:
                    first_renewal.set()
                else:
                    later_renewal.set()

        monkeypatch.setattr(manager, "renew_task_authority", record_renewal)
        heartbeat = _TaskHeartbeat(manager, binding, interval=0.01)
        heartbeat.start()
        assert first_renewal.wait(3)
        with manager._db_lock:
            clock[0] += 3500
        assert later_renewal.wait(3)
        other = AgentManager(path)
        row = other._conn.execute(
            "SELECT expires_at FROM agent_task_authority WHERE task_id = ?",
            (task["id"],),
        ).fetchone()
        assert row["expires_at"] == clock[0] + 3600
        other.validate_task_authority(*binding)
        heartbeat.check()
        clock[0] += 3601
        assert heartbeat._failed.wait(3)
        with pytest.raises(PermissionError, match="heartbeat"):
            heartbeat.check()
        with pytest.raises(PermissionError):
            other.renew_task_authority(*binding)
    finally:
        if heartbeat is not None:
            heartbeat.close()
        if other is not None:
            other.close()
        manager.close()


@pytest.mark.parametrize("invalid", ["owner", "epoch", "principal", "revoked"])
def test_heartbeat_failure_denies_stale_owner(tmp_path, invalid):
    manager = AgentManager(str(tmp_path / "task.db"))
    heartbeat = None
    try:
        agent = manager.create_agent("worker")
        task = manager.create_task(agent["id"], "work")
        authority = TestPrincipalAuthority(b"synthetic-heartbeat")
        principal = authority.verify(authority.issue("owner"))
        token = "a" * 32
        task = manager.start_task(
            task["id"], agent["id"], principal.principal_id, None, worker_token=token
        )
        if invalid == "owner":
            token = "b" * 32
        elif invalid == "principal":
            principal = authority.verify(authority.issue("other"))
        elif invalid == "revoked":
            authority.revoke(principal)
        heartbeat = _TaskHeartbeat(
            manager,
            (
                task["id"],
                agent["id"],
                principal,
                authority,
                task["execution_attempt"],
                token,
                2 if invalid == "epoch" else 1,
            ),
            interval=0.01,
        )
        heartbeat.start()
        assert heartbeat._failed.wait(3)
        with pytest.raises(PermissionError, match="heartbeat"):
            heartbeat.check()
    finally:
        if heartbeat is not None:
            heartbeat.close()
        manager.close()


def test_heartbeat_failure_during_mutation_is_unknown(tmp_path):
    manager = AgentManager(str(tmp_path / "task.db"))
    heartbeat = _TaskHeartbeat(manager, (), interval=60)
    try:
        heartbeat.start()

        class Probe(BaseTool):
            @property
            def spec(self):
                return ToolSpec("probe", "test", effect=ToolEffect.MUTATING)

            def execute(self, **_params):
                heartbeat._failed.set()
                return ToolResult(tool_name="probe", content="effect happened")

        executor = ToolExecutor([Probe()])
        executor._task_authority_check = heartbeat.check
        result = executor.execute(ToolCall(id="call-1", name="probe", arguments="{}"))
        assert not result.success
        assert result.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
        heartbeat.close()
        with pytest.raises(PermissionError, match="heartbeat"):
            heartbeat.check()
    finally:
        heartbeat.close()
        manager.close()


def test_heartbeat_stops_cleanly_before_completion():
    heartbeat = _TaskHeartbeat(None, (), interval=60)
    try:
        heartbeat.start()
        heartbeat.finish()
        with pytest.raises(PermissionError, match="heartbeat"):
            heartbeat.check()
    finally:
        heartbeat.close()


def test_controller_fails_closed_when_heartbeat_fails(tmp_path, monkeypatch):
    from openjarvis.server import agent_manager_routes

    manager = AgentManager(str(tmp_path / "task.db"))
    authority = TestPrincipalAuthority(b"synthetic-heartbeat")
    principal = authority.verify(authority.issue("owner"))
    engine = FakeEngine([])
    app = FastAPI()
    app.state.testing = True
    app.state.host_principal_authority = authority
    app.state.task_checkpoint_integrity_key = b"test-checkpoint-key-at-least-32-bytes"
    app.state.engine = engine
    app.state.model = "fake-model"
    host_context = SimpleNamespace(principal=principal, session_id="test-session")

    @app.middleware("http")
    async def inject_host_context(request, call_next):
        request.state.host_principal_context = host_context
        return await call_next(request)

    for router in create_agent_manager_router(manager):
        app.include_router(router)
    monkeypatch.setattr(
        agent_manager_routes,
        "_make_lightweight_system",
        lambda *_args: SimpleNamespace(),
    )
    monkeypatch.setattr(
        _TaskHeartbeat,
        "check",
        lambda _self: (_ for _ in ()).throw(PermissionError("heartbeat failed")),
    )
    try:
        agent = manager.create_agent("worker", agent_type="orchestrator")
        task = manager.create_task(agent["id"], "work")
        with TestClient(app) as client:
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
        assert response.status_code == 409
        assert "heartbeat failed" in response.text
        assert engine.call_count == 0
        assert manager._get_task(task["id"], agent_id=agent["id"])["status"] == "failed"
    finally:
        manager.close()
