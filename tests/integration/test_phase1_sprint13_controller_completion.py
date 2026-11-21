"""Controller task authorization regression."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.agents.fake_engine import FakeEngine

from openjarvis.agents.manager import AgentManager


def test_controller_task_run_requires_host_principal(tmp_path):
    manager = AgentManager(str(tmp_path / "controller.db"))
    try:
        from openjarvis.server.agent_manager_routes import create_agent_manager_router

        app = FastAPI()
        app.state.engine = FakeEngine([])
        app.state.model = "fake-model"
        for router in create_agent_manager_router(manager):
            app.include_router(router)
        agent = manager.create_agent("no-host", agent_type="simple")
        task = manager.create_task(agent["id"], "must remain pending")
        with TestClient(app) as client:
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
        assert response.status_code == 403
        stored = manager._get_task(task["id"], agent_id=agent["id"])
        assert stored["status"] == "pending"
        assert stored["execution_attempt"] is None
    finally:
        manager.close()
