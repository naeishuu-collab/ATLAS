"""Tests for AgentExecutor single-tick execution."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openjarvis.agents._stubs import AgentResult
from openjarvis.agents.errors import FatalError, RetryableError
from openjarvis.core.events import EventBus, EventType
from openjarvis.core.types import ToolResult


@pytest.fixture
def manager():
    from openjarvis.agents.manager import AgentManager

    with tempfile.TemporaryDirectory() as tmpdir:
        mgr = AgentManager(db_path=str(Path(tmpdir) / "agents.db"))
        yield mgr
        mgr.close()


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def executor(manager, event_bus):
    from openjarvis.agents.executor import AgentExecutor

    mock_system = MagicMock()
    ex = AgentExecutor(manager=manager, event_bus=event_bus)
    ex.set_system(mock_system)
    return ex


class TestExecutorBasic:
    def test_execute_tick_publishes_start_end_events(
        self, executor, manager, event_bus
    ):
        agent = manager.create_agent(name="test", agent_type="monitor_operative")
        events = []
        event_bus.subscribe(EventType.AGENT_TICK_START, lambda e: events.append(e))
        event_bus.subscribe(EventType.AGENT_TICK_END, lambda e: events.append(e))

        rv = AgentResult(content="result text")
        with patch.object(executor, "_invoke_agent", return_value=rv):
            executor.execute_tick(agent["id"])

        assert len(events) == 2
        assert events[0].event_type == EventType.AGENT_TICK_START
        assert events[1].event_type == EventType.AGENT_TICK_END

    def test_execute_tick_updates_run_stats(self, executor, manager):
        agent = manager.create_agent(name="test", agent_type="monitor_operative")

        rv = AgentResult(content="result text")
        with patch.object(executor, "_invoke_agent", return_value=rv):
            executor.execute_tick(agent["id"])

        updated = manager.get_agent(agent["id"])
        assert updated["total_runs"] == 1
        assert updated["status"] == "idle"

    def test_execute_tick_sets_running_then_idle(self, executor, manager):
        agent = manager.create_agent(name="test", agent_type="monitor_operative")
        statuses = []

        original_start = manager.start_tick

        def track_start(aid):
            original_start(aid)
            statuses.append(manager.get_agent(aid)["status"])

        manager.start_tick = track_start

        rv = AgentResult(content="result")
        with patch.object(executor, "_invoke_agent", return_value=rv):
            executor.execute_tick(agent["id"])

        assert statuses == ["running"]
        assert manager.get_agent(agent["id"])["status"] == "idle"

    def test_execute_tick_handles_fatal_error(self, executor, manager, event_bus):
        agent = manager.create_agent(name="test", agent_type="monitor_operative")
        errors = []
        event_bus.subscribe(EventType.AGENT_TICK_ERROR, lambda e: errors.append(e))

        with patch.object(
            executor, "_invoke_agent", side_effect=FatalError("bad config")
        ):
            executor.execute_tick(agent["id"])

        assert manager.get_agent(agent["id"])["status"] == "error"
        assert len(errors) == 1

    def test_execute_tick_retries_retryable_error(self, executor, manager):
        agent = manager.create_agent(name="test", agent_type="monitor_operative")
        call_count = 0

        def flaky_invoke(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RetryableError("rate limit")
            return AgentResult(content="success")

        with patch.object(executor, "_invoke_agent", side_effect=flaky_invoke):
            with patch("openjarvis.agents.executor.retry_delay", return_value=0):
                executor.execute_tick(agent["id"])

        assert call_count == 3
        assert manager.get_agent(agent["id"])["status"] == "idle"
        retry_state = manager.get_latest_checkpoint(agent["id"])["tool_state"]
        # Per-tick attempt budget (docs/astra-run-report.md): the succeeded
        # tick closes its retry window, so the next tick is not strangled
        # by this one's leftover attempts.
        assert retry_state["retry_count"] == 0
        assert retry_state["retry_history"] == []

    def test_execute_tick_gives_up_after_max_retries(self, executor, manager):
        agent = manager.create_agent(name="test", agent_type="monitor_operative")

        with patch.object(
            executor, "_invoke_agent", side_effect=RetryableError("always fails")
        ):
            with patch("openjarvis.agents.executor.retry_delay", return_value=0):
                executor.execute_tick(agent["id"])

        assert manager.get_agent(agent["id"])["status"] == "error"

    def test_retry_checkpoint_failure_blocks_agent_invocation(self, executor, manager):
        agent = manager.create_agent(name="test", agent_type="monitor_operative")
        original_save = manager.save_checkpoint
        save_count = 0
        invoke_count = 0

        def fail_second_checkpoint(*args, **kwargs):
            nonlocal save_count
            save_count += 1
            if save_count == 2:
                raise OSError("checkpoint storage unavailable")
            return original_save(*args, **kwargs)

        def should_not_invoke(*_args, **_kwargs):
            nonlocal invoke_count
            invoke_count += 1
            return AgentResult(content="unexpected")

        manager.save_checkpoint = fail_second_checkpoint
        with patch.object(executor, "_invoke_agent", side_effect=should_not_invoke):
            executor.execute_tick(agent["id"])

        assert invoke_count == 0
        assert manager.get_agent(agent["id"])["status"] == "error"
        assert (
            manager.get_latest_checkpoint(agent["id"])["conversation_state"][
                "lifecycle"
            ]
            == "FAILED"
        )

    def test_execute_tick_concurrency_guard(self, executor, manager):
        agent = manager.create_agent(name="test", agent_type="monitor_operative")
        manager.start_tick(agent["id"])  # Simulate already running

        # Second tick should handle the ValueError from start_tick
        rv = AgentResult(content="result")
        with patch.object(executor, "_invoke_agent", return_value=rv):
            executor.execute_tick(agent["id"])

        # Agent should still be running (first tick owns it)
        assert manager.get_agent(agent["id"])["status"] == "running"


def test_empty_turn_with_tool_result_is_not_retried() -> None:
    from openjarvis.agents.executor import _should_retry_empty_result

    result = AgentResult(
        content="  ",
        tool_results=[ToolResult(tool_name="channel_send", content="sent")],
    )

    assert _should_retry_empty_result(result) is False
    assert _should_retry_empty_result(AgentResult(content="")) is True


def test_finalize_tick_reads_agent_result_metadata(tmp_path):
    """_finalize_tick() accumulates cost/tokens from AgentResult.metadata."""
    from openjarvis.agents.executor import AgentExecutor
    from openjarvis.agents.manager import AgentManager

    mgr = AgentManager(str(tmp_path / "test.db"))
    bus = EventBus()
    executor = AgentExecutor(mgr, bus)

    agent = mgr.create_agent("budget-agent")
    mgr.start_tick(agent["id"])

    result = AgentResult(
        content="done",
        metadata={"tokens_used": 500, "cost": 0.05},
    )
    executor._finalize_tick(agent["id"], result, error=None, duration=1.0)

    updated = mgr.get_agent(agent["id"])
    assert updated["total_tokens"] == 500
    assert updated["total_cost"] == 0.05
    assert updated["stall_retries"] == 0
    mgr.close()


def test_tick_model_prefers_system_default_before_legacy_fallback() -> None:
    from openjarvis.agents.executor import _resolve_tick_model

    system = MagicMock(model="qwen3:8b")

    assert _resolve_tick_model({}, system) == "qwen3:8b"
    assert _resolve_tick_model({"model": "agent-model"}, system) == "agent-model"


def test_managed_router_receives_every_actual_engine_model() -> None:
    from openjarvis.agents.executor import _available_tick_models
    from openjarvis.learning.routing.router import (
        HeuristicRouter,
        build_routing_context,
    )

    engine = MagicMock()
    engine.list_models.return_value = [
        "qwen3:8b",
        "tiny:1b",
        "code-coder:32b",
        "qwen3:8b",
        "",
    ]

    available = _available_tick_models(engine, "qwen3:8b")
    selected = HeuristicRouter(available_models=available).select_model(
        build_routing_context("Write a Python function with tests")
    )

    assert available == ["qwen3:8b", "tiny:1b", "code-coder:32b"]
    assert selected == "code-coder:32b"
    engine.list_models.assert_called_once_with()


def test_managed_router_excludes_unavailable_fallback_model() -> None:
    from openjarvis.agents.executor import _available_tick_models

    engine = MagicMock()
    engine.list_models.return_value = ["tiny:1b", "large:32b"]

    assert _available_tick_models(engine, "missing:legacy") == [
        "tiny:1b",
        "large:32b",
    ]


def test_managed_router_retains_resolved_model_when_discovery_fails() -> None:
    from openjarvis.agents.executor import _available_tick_models

    engine = MagicMock()
    engine.list_models.side_effect = RuntimeError("offline")

    assert _available_tick_models(engine, "remote:model") == ["remote:model"]


def test_managed_tiered_router_uses_system_tier_configuration(
    manager, event_bus, monkeypatch
) -> None:
    from types import SimpleNamespace

    from openjarvis.agents._stubs import AgentResult
    from openjarvis.agents.executor import AgentExecutor
    from openjarvis.core.registry import RouterPolicyRegistry
    from openjarvis.learning import ensure_registered

    ensure_registered()
    selected: list[str] = []

    class FakeEngine:
        def list_models(self):
            return ["local-id", "luna-id", "terra-id", "sol-id"]

    class FakeAgent:
        accepts_tools = False

        def __init__(self, engine, model, **kwargs):
            selected.append(model)

        def run(self, input_text, context=None, **kwargs):
            return AgentResult(content="routed")

    class EmptyToolkit:
        instances = []
        by_name = []
        mcp_clients = []

        def close(self):
            pass

    routing = SimpleNamespace(
        tier_models={
            "local": "local-id",
            "luna": "luna-id",
            "terra": "terra-id",
            "sol": "sol-id",
        }
    )
    system = SimpleNamespace(
        engine=FakeEngine(),
        model="luna-id",
        memory_backend=None,
        config=SimpleNamespace(
            learning=SimpleNamespace(routing=routing),
            intelligence=SimpleNamespace(fallback_model="terra-id"),
            agent=SimpleNamespace(default_system_prompt=""),
            memory_files=None,
            system_prompt=None,
        ),
        capability_policy=None,
        rate_limiter=None,
        session_store=None,
        knowledge_db_path=None,
    )
    executor = AgentExecutor(manager, event_bus)
    executor.set_system(system)
    agent = manager.create_agent(
        "tiered-agent",
        agent_type="fake",
        config={
            "model": "luna-id",
            "router_policy": "tiered",
            "instruction": "solve the integral of x^2",
        },
    )

    monkeypatch.setattr("openjarvis.agents.AgentRegistry.get", lambda _key: FakeAgent)
    monkeypatch.setattr(
        "openjarvis.agents.executor.resolve_agent_tools",
        lambda *args, **kwargs: EmptyToolkit(),
    )
    monkeypatch.setattr(
        "openjarvis.security.runtime.wire_agent_security",
        lambda *args, **kwargs: None,
    )

    result = executor._invoke_agent_impl(agent)

    assert result.content == "routed"
    assert selected == ["terra-id"]
    assert RouterPolicyRegistry.contains("tiered")

    agent["config"]["instruction"] = "say hello"
    agent["_managed_runtime"] = {
        "tool_state": {
            "retry_history": [
                {"state": "FAILED"},
                {"state": "FAILED"},
            ]
        }
    }
    executor._invoke_agent_impl(agent)
    assert selected == ["terra-id", "sol-id"]


def test_new_agent_without_model_keeps_system_default_unpinned(manager) -> None:
    agent = manager.create_agent("inherits-system-model", config={})

    assert "model" not in agent["config"]
