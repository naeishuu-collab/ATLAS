"""Tests for _get_mcp_tools() caching in agent_manager_routes."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("fastapi", reason="fastapi required for server route tests")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeAppState:
    """Minimal app_state substitute with dynamic attributes."""

    pass


def _make_config(*, enabled: bool = True, servers_json: str = "[]") -> MagicMock:
    """Build a mock config with tools.mcp.enabled and tools.mcp.servers."""
    config = MagicMock()
    config.tools.mcp.enabled = enabled
    config.tools.mcp.servers = servers_json
    return config


def _make_tool_spec(name: str, description: str = "") -> MagicMock:
    spec = MagicMock()
    spec.name = name
    spec.description = description
    spec.parameters = {"type": "object", "properties": {}}
    return spec


def _make_adapter(name: str) -> MagicMock:
    adapter = MagicMock()
    adapter.spec = _make_tool_spec(name)
    return adapter


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@patch("openjarvis.core.config.load_config")
def test_configured_external_server_is_denied_before_discovery(
    mock_load_config: MagicMock,
):
    """Config alone cannot authorize external MCP discovery."""
    from openjarvis.server.agent_manager_routes import _get_mcp_tools

    server_cfg = [{"name": "test-server", "url": "http://localhost:9999"}]
    mock_load_config.return_value = _make_config(
        servers_json=json.dumps(server_cfg),
    )

    with (
        patch("openjarvis.mcp.transport.StreamableHTTPTransport") as transport,
        patch("openjarvis.mcp.client.MCPClient") as client,
        patch("openjarvis.tools.mcp_adapter.MCPToolProvider") as provider,
    ):
        app_state = _FakeAppState()
        tools, adapters = _get_mcp_tools(app_state)

    assert tools == []
    assert adapters == {}
    transport.assert_not_called()
    client.assert_not_called()
    provider.assert_not_called()


@patch("openjarvis.core.config.load_config")
def test_external_mcp_file_is_denied_before_discovery(
    mock_load_config: MagicMock, tmp_path: Path
):
    """File-backed config cannot authorize external MCP discovery."""

    from openjarvis.server.agent_manager_routes import _get_mcp_tools

    server_file = tmp_path / "mcp-servers.json"
    server_file.write_text(
        '[{"name": "file-server", "url": "http://localhost:9999"}]',
        encoding="utf-8",
    )
    config = _make_config(servers_json=server_file.name)
    config._config_dir = tmp_path
    mock_load_config.return_value = config
    with (
        patch("openjarvis.mcp.transport.StreamableHTTPTransport") as transport,
        patch("openjarvis.mcp.client.MCPClient") as client,
        patch("openjarvis.tools.mcp_adapter.MCPToolProvider") as provider,
    ):
        tools, adapters = _get_mcp_tools(_FakeAppState())

    assert tools == []
    assert adapters == {}
    transport.assert_not_called()
    client.assert_not_called()
    provider.assert_not_called()


@patch("openjarvis.core.config.load_config")
def test_external_discovery_does_not_create_a_cache(mock_load_config: MagicMock):
    """Denied external discovery cannot populate a tool cache."""
    from openjarvis.server.agent_manager_routes import _get_mcp_tools

    server_cfg = [{"name": "test-server", "url": "http://localhost:9999"}]
    mock_load_config.return_value = _make_config(
        servers_json=json.dumps(server_cfg),
    )

    with (
        patch("openjarvis.mcp.transport.StreamableHTTPTransport") as transport,
        patch("openjarvis.mcp.client.MCPClient") as client,
        patch("openjarvis.tools.mcp_adapter.MCPToolProvider") as provider,
    ):
        app_state = _FakeAppState()
        tools1, adapters1 = _get_mcp_tools(app_state)
        tools2, adapters2 = _get_mcp_tools(app_state)

    assert tools1 == tools2 == []
    assert adapters1 == adapters2 == {}
    transport.assert_not_called()
    client.assert_not_called()
    provider.assert_not_called()


@patch("openjarvis.core.config.load_config")
def test_denied_external_discovery_has_no_retry_path(mock_load_config: MagicMock):
    """A denied external path cannot retry or redispatch discovery."""
    from openjarvis.server.agent_manager_routes import _get_mcp_tools

    server_cfg = [{"name": "failing-server", "url": "http://localhost:9999"}]
    mock_load_config.return_value = _make_config(
        servers_json=json.dumps(server_cfg),
    )

    with patch("openjarvis.mcp.client.MCPClient") as client:
        app_state = _FakeAppState()
        tools1, _ = _get_mcp_tools(app_state)
        tools2, _ = _get_mcp_tools(app_state)

    assert tools1 == tools2 == []
    assert getattr(app_state, "_mcp_tools_cache", None) is None
    client.assert_not_called()


@patch("openjarvis.core.config.load_config")
def test_handles_config_load_failure(mock_load_config: MagicMock):
    """Config load failure returns empty, no crash."""
    from openjarvis.server.agent_manager_routes import _get_mcp_tools

    mock_load_config.side_effect = RuntimeError("config broken")

    app_state = _FakeAppState()
    tools, adapters = _get_mcp_tools(app_state)

    assert tools == []
    assert adapters == {}


@patch("openjarvis.core.config.load_config")
def test_uses_preloaded_full_system_pool(mock_load_config: MagicMock):
    """Server and scheduled paths reuse one unfiltered MCP discovery."""

    from openjarvis.server.agent_manager_routes import _get_mcp_tools

    adapter = _make_adapter("preloaded_tool")
    app_state = _FakeAppState()
    app_state.mcp_tools = [adapter]

    tools, adapters = _get_mcp_tools(app_state)

    mock_load_config.assert_not_called()
    assert tools[0]["function"]["name"] == "preloaded_tool"
    assert adapters == {"preloaded_tool": adapter}


@patch("openjarvis.core.config.load_config")
def test_preloaded_duplicate_names_are_first_wins(mock_load_config: MagicMock):
    """SSE and executor paths choose the same adapter on name collisions."""

    from openjarvis.server.agent_manager_routes import _get_mcp_tools

    first = _make_adapter("duplicate")
    second = _make_adapter("duplicate")
    app_state = _FakeAppState()
    app_state.mcp_tools = [first, second]

    tools, adapters = _get_mcp_tools(app_state)

    mock_load_config.assert_not_called()
    assert len(tools) == 1
    assert adapters == {"duplicate": first}


def test_app_shutdown_stops_scheduler_before_closing_shared_mcp_clients(
    tmp_path,
) -> None:
    """Shutdown quiesces and drains every user of the shared MCP pool."""

    from fastapi.testclient import TestClient

    from openjarvis.agents.manager import AgentManager
    from openjarvis.core.config import JarvisConfig
    from openjarvis.server.agent_manager_routes import _start_managed_worker
    from openjarvis.server.app import create_app

    events: list[str] = []
    release_worker = threading.Event()
    worker_finished = threading.Event()

    class _Scheduler:
        def request_stop(self):
            events.append("scheduler-stop")

        def wait_stopped(self, timeout=10):
            events.append("scheduler-wait")
            return True

    scheduler = _Scheduler()
    mcp_client = MagicMock()
    memory_backend = MagicMock()
    channel_bridge = MagicMock()
    manager = AgentManager(str(tmp_path / "shutdown-agents.db"))
    agent = manager.create_agent("shutdown-agent")
    manager.start_tick(agent["id"])
    request_cancellation = manager.request_cancellation

    def _request_cancellation(*args, **kwargs):
        events.append("cancel-request")
        return request_cancellation(*args, **kwargs)

    manager.request_cancellation = _request_cancellation

    def _close_mcp():
        events.append("mcp")
        release_worker.set()

    mcp_client.close.side_effect = _close_mcp
    memory_backend.close.side_effect = lambda: events.append("memory")
    channel_bridge.disconnect.side_effect = lambda: events.append("channel")
    config = JarvisConfig()
    config.analytics.enabled = False
    config.traces.enabled = False

    app = create_app(
        MagicMock(),
        "test-model",
        config=config,
        channel_bridge=channel_bridge,
        agent_scheduler=scheduler,
        mcp_clients=[mcp_client],
        memory_backend=memory_backend,
        own_memory_backend=True,
        agent_manager=manager,
    )

    def _worker():
        release_worker.wait(timeout=2)
        events.append("worker-finished")
        worker_finished.set()

    _start_managed_worker(app.state, _worker, name="test-managed-worker")

    with TestClient(app):
        pass

    mcp_client.close.assert_called_once_with()
    memory_backend.close.assert_called_once_with()
    channel_bridge.disconnect.assert_called_once_with()
    assert worker_finished.is_set()
    assert app.state.memory_backend is None
    assert app.state._owns_memory_backend is False
    assert app.state._managed_runtime_stopping is True
    assert app.state._managed_workers == set()
    assert manager.cancellation_state(agent["id"])["reason"] == "shutdown"
    assert events.index("cancel-request") < events.index("mcp")
    assert events.index("channel") < events.index("mcp")
    assert events.index("scheduler-stop") < events.index("mcp")
    assert events.index("mcp") < events.index("worker-finished")
    assert events.index("worker-finished") < events.index("memory")
    with pytest.raises(RuntimeError, match="shutting down"):
        _start_managed_worker(app.state, lambda: None, name="too-late-worker")
    manager.end_tick(agent["id"])
    manager.close()


@patch("openjarvis.core.config.load_config")
def test_denied_mcp_does_not_start_a_lazy_discovery_worker(mock_load_config):
    """The host-authority gate denies before initialize or child creation."""

    from openjarvis.server.agent_manager_routes import _get_mcp_tools

    mock_load_config.return_value = _make_config(
        servers_json=json.dumps([{"name": "blocked", "url": "http://localhost:9999"}])
    )
    app_state = _FakeAppState()

    with (
        patch("openjarvis.mcp.transport.StreamableHTTPTransport") as transport,
        patch("openjarvis.mcp.client.MCPClient") as client,
    ):
        tools, adapters = _get_mcp_tools(app_state)

    assert tools == []
    assert adapters == {}
    transport.assert_not_called()
    client.assert_not_called()
    assert getattr(app_state, "_mcp_clients", []) == []


def test_app_shutdown_closes_lazily_created_memory_backend(monkeypatch) -> None:
    """A backend opened by a managed route is owned and closed by the app."""

    from fastapi.testclient import TestClient

    from openjarvis.core.config import JarvisConfig
    from openjarvis.server import agent_manager_routes as routes
    from openjarvis.server.app import create_app

    backend = MagicMock()
    monkeypatch.setattr(routes, "_resolve_memory_backend", lambda config: backend)
    config = JarvisConfig()
    config.analytics.enabled = False
    config.traces.enabled = False
    app = create_app(MagicMock(), "test-model", config=config)

    assert routes._get_or_create_memory_backend(app.state, config) is backend
    assert app.state._owns_memory_backend is True

    with TestClient(app):
        pass

    backend.close.assert_called_once_with()
    assert app.state.memory_backend is None


def test_app_shutdown_keeps_owned_memory_open_for_live_worker(monkeypatch) -> None:
    """A timed-out worker must never resume against a closed backend."""

    from fastapi.testclient import TestClient

    from openjarvis.core.config import JarvisConfig
    from openjarvis.server import app as app_module
    from openjarvis.server.agent_manager_routes import _start_managed_worker

    monkeypatch.setattr(app_module, "_MANAGED_SHUTDOWN_GRACE_SECONDS", 0.01)
    monkeypatch.setattr(app_module, "_MANAGED_SHUTDOWN_DRAIN_SECONDS", 0.01)

    release_worker = threading.Event()
    worker_holds_memory_lock = threading.Event()
    shutdown_finished = threading.Event()
    shutdown_errors: list[BaseException] = []
    backend = MagicMock()
    config = JarvisConfig()
    config.analytics.enabled = False
    config.traces.enabled = False
    app = app_module.create_app(
        MagicMock(),
        "test-model",
        config=config,
        memory_backend=backend,
        own_memory_backend=True,
    )

    def _hold_memory_lock():
        with app.state._memory_backend_lock:
            worker_holds_memory_lock.set()
            release_worker.wait(timeout=2)

    worker = _start_managed_worker(
        app.state,
        _hold_memory_lock,
        name="memory-using-straggler",
    )
    assert worker_holds_memory_lock.wait(timeout=2)

    def _shutdown_app():
        try:
            with TestClient(app):
                pass
        except BaseException as exc:
            shutdown_errors.append(exc)
        finally:
            shutdown_finished.set()

    shutdown_thread = threading.Thread(target=_shutdown_app, daemon=True)
    shutdown_thread.start()

    try:
        assert shutdown_finished.wait(timeout=1)
        assert shutdown_errors == []
        backend.close.assert_not_called()
        assert app.state.memory_backend is backend
        assert app.state._owns_memory_backend is True
    finally:
        release_worker.set()
        worker.join(timeout=2)
        shutdown_thread.join(timeout=2)


def test_app_shutdown_leaves_borrowed_memory_backend_open() -> None:
    """An injected backend remains owned by its caller unless opted in."""

    from fastapi.testclient import TestClient

    from openjarvis.core.config import JarvisConfig
    from openjarvis.server.app import create_app

    backend = MagicMock()
    config = JarvisConfig()
    config.analytics.enabled = False
    config.traces.enabled = False
    app = create_app(
        MagicMock(),
        "test-model",
        config=config,
        memory_backend=backend,
    )

    with TestClient(app):
        pass

    backend.close.assert_not_called()
    assert app.state.memory_backend is backend
