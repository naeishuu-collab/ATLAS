"""Tests for AgentManager.recover_agent() always resetting status."""

import pytest

from openjarvis.agents.manager import AgentManager


@pytest.fixture
def manager(tmp_path):
    db = str(tmp_path / "agents.db")
    return AgentManager(db_path=db)


def test_recover_resets_to_idle_without_checkpoint(manager):
    """recover_agent must reset status to idle even when no checkpoint exists."""
    agent = manager.create_agent(name="test", agent_type="monitor_operative")
    manager.update_agent(agent["id"], status="error")

    result = manager.recover_agent(agent["id"])

    assert result is None
    refreshed = manager.get_agent(agent["id"])
    assert refreshed["status"] == "idle"


def test_recover_resets_to_idle_with_checkpoint(manager):
    """recover_agent returns checkpoint and resets status when checkpoint exists."""
    agent = manager.create_agent(name="test", agent_type="monitor_operative")
    manager.update_agent(agent["id"], status="error")
    manager.save_checkpoint(agent["id"], "tick-1", {"history": []}, {"tools": {}})

    result = manager.recover_agent(agent["id"])

    assert result is not None
    assert result["tick_id"] == "tick-1"
    refreshed = manager.get_agent(agent["id"])
    assert refreshed["status"] == "idle"


def test_restart_recovers_checkpoint_and_preserves_paused_agent(tmp_path):
    db_path = str(tmp_path / "restart.db")
    manager = AgentManager(db_path=db_path)
    try:
        running = manager.create_agent(name="interrupted", agent_type="simple")
        paused = manager.create_agent(name="paused", agent_type="simple")
        manager.start_tick(running["id"])
        task = manager.create_task(running["id"], "finish verified action", "running")
        manager.update_task(
            task["id"], progress={"step": "observe"}, findings=["target identified"]
        )
        manager.save_checkpoint(
            running["id"],
            "tick-interrupted",
            {"messages": [{"role": "user", "content": "continue safely"}]},
            {"windows_action": {"outcome": "NOT_STARTED"}},
        )
        manager.pause_agent(paused["id"])
    finally:
        manager.close()

    restarted = AgentManager(db_path=db_path, clear_stale_running=True)
    try:
        assert restarted.get_agent(running["id"])["status"] == "idle"
        assert restarted.get_agent(paused["id"])["status"] == "paused"
        assert restarted.list_tasks(running["id"])[0] == {
            **task,
            "progress": {"step": "observe"},
            "findings": ["target identified"],
        }
        checkpoint = restarted.get_latest_checkpoint(running["id"])
        assert checkpoint is not None
        assert checkpoint["tick_id"] == "tick-interrupted"
        assert checkpoint["conversation_state"]["messages"][0]["content"] == (
            "continue safely"
        )
        assert checkpoint["tool_state"]["windows_action"]["outcome"] == "NOT_STARTED"
        assert restarted.recover_agent(running["id"]) == checkpoint
    finally:
        restarted.close()
