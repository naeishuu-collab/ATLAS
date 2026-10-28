"""Fail-closed tests for SystemBuilder external MCP discovery."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def builder():
    from openjarvis.system import SystemBuilder

    def _minimal_init(self):
        self._mcp_clients = []
        self._mcp_tools = []
        self._tool_names = None

    with patch.object(SystemBuilder, "__init__", _minimal_init):
        instance = SystemBuilder.__new__(SystemBuilder)
        instance.__init__()
        return instance


@pytest.mark.parametrize(
    "cfg",
    [
        {"name": "http", "url": "https://remote.example/mcp"},
        {"name": "stdio", "command": "untrusted-server", "args": ["--serve"]},
        "{not valid json",
    ],
)
def test_external_discovery_denies_before_transport_or_process(builder, cfg, caplog):
    with (
        patch("openjarvis.mcp.transport.StreamableHTTPTransport") as http,
        patch("openjarvis.mcp.transport.StdioTransport") as stdio,
        patch("openjarvis.mcp.client.MCPClient") as client,
        patch("openjarvis.tools.mcp_adapter.MCPToolProvider") as provider,
        caplog.at_level("WARNING"),
    ):
        result = builder._discover_external_mcp(cfg)

    assert result == []
    assert builder._mcp_clients == []
    assert any(
        "host egress/process authority is unavailable" in r.message
        for r in caplog.records
    )
    http.assert_not_called()
    stdio.assert_not_called()
    client.assert_not_called()
    provider.assert_not_called()


def test_resolve_tools_keeps_external_config_inert(builder):
    from openjarvis.core.config import JarvisConfig

    config = JarvisConfig()
    config.tools.mcp.servers = json.dumps(
        [{"name": "configured", "url": "http://localhost:8080/mcp"}]
    )
    with patch("openjarvis.mcp.server.MCPServer") as mcp_server:
        mcp_server.return_value.get_tools.return_value = []
        tools = builder._resolve_tools(
            config,
            engine=MagicMock(),
            model="test-model",
            memory_backend=None,
        )
    assert tools == []
    assert builder._mcp_clients == []


def test_builder_wires_security_context_into_internal_mcp_server():
    from openjarvis.core.config import JarvisConfig
    from openjarvis.system import SystemBuilder

    config = JarvisConfig()
    policy = object()
    limiter = object()
    bus = object()
    builder = SystemBuilder(config)

    with patch("openjarvis.mcp.server.MCPServer") as mcp_server:
        mcp_server.return_value.get_tools.return_value = []
        builder._resolve_tools(
            config,
            engine=MagicMock(),
            model="test-model",
            memory_backend=None,
            bus=bus,
            capability_policy=policy,
            rate_limiter=limiter,
        )

    mcp_server.assert_called_once_with(
        bus=bus,
        capability_policy=policy,
        rate_limiter=limiter,
        agent_id="system:mcp",
    )


def test_global_mcp_disable_prevents_discovery():
    from openjarvis.core.config import JarvisConfig
    from openjarvis.system import SystemBuilder

    config = JarvisConfig()
    config.tools.mcp.enabled = False
    config.tools.mcp.servers = json.dumps(
        [{"name": "disabled", "url": "http://localhost:8080/mcp"}]
    )
    builder = SystemBuilder(config)
    with patch.object(builder, "_discover_external_mcp") as discover:
        builder._resolve_tools(
            config,
            engine=MagicMock(),
            model="test-model",
            memory_backend=None,
        )
    discover.assert_not_called()
    assert builder._mcp_tools == []
