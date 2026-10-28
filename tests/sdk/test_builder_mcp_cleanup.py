"""Regression for the external MCP host-authority gate."""

from unittest.mock import patch

from openjarvis.core.config import JarvisConfig
from openjarvis.system.builder import SystemBuilder


def test_external_discovery_does_not_spawn_or_leak_clients(caplog):
    builder = SystemBuilder(config=JarvisConfig())
    with (
        patch("openjarvis.mcp.client.MCPClient") as client,
        patch("openjarvis.mcp.transport.StreamableHTTPTransport") as http,
        patch("openjarvis.mcp.transport.StdioTransport") as stdio,
        caplog.at_level("WARNING"),
    ):
        result = builder._discover_external_mcp(
            {"name": "blocked", "url": "https://remote.example/mcp"}
        )

    assert result == []
    assert builder._mcp_clients == []
    client.assert_not_called()
    http.assert_not_called()
    stdio.assert_not_called()
    assert any(
        "host egress/process authority is unavailable" in r.message
        for r in caplog.records
    )
