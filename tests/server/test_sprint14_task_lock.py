from fastapi import FastAPI
from fastapi.testclient import TestClient

from openjarvis.agents.manager import AgentManager
from openjarvis.server.agent_manager_routes import create_agent_manager_router


def test_claimed_task_cannot_be_updated_or_deleted(tmp_path):
    manager = AgentManager(str(tmp_path / "tasks.db"))
    try:
        agent = manager.create_agent("owner")
        task = manager.create_task(agent["id"], "original")
        started = manager.start_task(task["id"], agent["id"], "principal", None)
        app = FastAPI()
        for router in create_agent_manager_router(manager):
            app.include_router(router)
        with TestClient(app) as client:
            path = f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}"
            assert client.patch(path, json={"status": "pending"}).status_code == 409
            assert client.delete(path).status_code == 409
        assert (
            manager.update_task(
                task["id"], agent_id=agent["id"], unclaimed_only=True, status="pending"
            )
            is None
        )
        assert not manager.delete_task(
            task["id"], agent_id=agent["id"], unclaimed_only=True
        )
        assert manager._get_task(task["id"], agent_id=agent["id"]) == started
    finally:
        manager.close()
