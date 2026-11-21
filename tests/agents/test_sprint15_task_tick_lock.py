"""Task-bound worker locks must not be recovered by time or startup alone."""

import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from openjarvis.agents.manager import AgentManager
from openjarvis.server.agent_manager_routes import create_agent_manager_router


def test_live_task_lock_survives_stale_age_and_another_manager_startup(tmp_path):
    path = str(tmp_path / "agents.db")
    owner = AgentManager(path)
    other = None
    try:
        agent = owner.create_agent("worker", agent_type="simple")
        task = owner.create_task(agent["id"], "do work")
        owner.start_task(task["id"], agent["id"], "principal", None)
        owner.start_tick(agent["id"])
        owner._conn.execute(
            "UPDATE managed_agents SET updated_at = ? WHERE id = ?",
            (time.time() - owner._STALE_TICK_SECONDS - 1, agent["id"]),
        )
        owner._conn.commit()

        other = AgentManager(path, clear_stale_running=True)
        assert other.get_agent(agent["id"])["status"] == "running"
        assert not other.is_restart_candidate(agent["id"])
        with pytest.raises(ValueError, match="already executing"):
            other.start_tick(agent["id"])
        app = FastAPI()
        for router in create_agent_manager_router(other):
            app.include_router(router)
        with TestClient(app) as client:
            response = client.post(f"/v1/managed-agents/{agent['id']}/recover")
        assert response.status_code == 409
        assert "host authority" in response.text
        assert owner.get_agent(agent["id"])["status"] == "running"
    finally:
        if other is not None:
            other.close()
        owner.close()
