"""Fail-closed tests for external MCP discovery."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


def _make_mcp_cfg(*, enabled=True, servers):
    cfg = MagicMock()
    cfg.enabled = enabled
    cfg.servers = json.dumps(servers) if not isinstance(servers, str) else servers
    return cfg


@pytest.fixture
def _external_stack():
    with (
        patch("openjarvis.mcp.client.MCPClient") as client,
        patch("openjarvis.mcp.transport.StreamableHTTPTransport") as http,
        patch("openjarvis.mcp.transport.StdioTransport") as stdio,
        patch("openjarvis.tools.mcp_adapter.MCPToolProvider") as provider,
    ):
        yield client, http, stdio, provider


def test_disabled_returns_empty_without_transport(_external_stack):
    from openjarvis.mcp.loader import load_mcp_tools_from_config

    tools, clients = load_mcp_tools_from_config(
        _make_mcp_cfg(enabled=False, servers=[{"url": "http://remote"}])
    )
    assert tools == []
    assert clients == []
    for mock in _external_stack:
        mock.assert_not_called()


def test_empty_servers_returns_empty(_external_stack):
    from openjarvis.mcp.loader import load_mcp_tools_from_config

    assert load_mcp_tools_from_config(
        _make_mcp_cfg(enabled=True, servers=[])
    ) == ([], [])


@pytest.mark.parametrize(
    "server",
    [
        {"name": "remote-http", "url": "https://remote.example/mcp", "token": "secret"},
        {"name": "stdio", "command": "untrusted-server", "args": ["--serve"]},
    ],
)
def test_explicit_external_config_denied_before_network_or_process(
    _external_stack, server, caplog
):
    from openjarvis.mcp.loader import load_mcp_tools_from_config

    with caplog.at_level("WARNING"):
        tools, clients = load_mcp_tools_from_config(
            _make_mcp_cfg(enabled=True, servers=[server])
        )
    assert tools == []
    assert clients == []
    assert any(
        "host egress/process authority is unavailable" in r.message
        for r in caplog.records
    )
    for mock in _external_stack:
        mock.assert_not_called()


def test_malformed_config_is_still_denied_without_parsing_or_transport(
    _external_stack, caplog
):
    from openjarvis.mcp.loader import load_mcp_tools_from_config

    cfg = _make_mcp_cfg(enabled=True, servers="{not valid json")
    with caplog.at_level("WARNING"):
        assert load_mcp_tools_from_config(cfg) == ([], [])
    assert any(
        "host egress/process authority is unavailable" in r.message
        for r in caplog.records
    )
    for mock in _external_stack:
        mock.assert_not_called()


def test_allowed_names_cannot_enable_external_discovery(_external_stack):
    from openjarvis.mcp.loader import load_mcp_tools_from_config

    tools, clients = load_mcp_tools_from_config(
        _make_mcp_cfg(enabled=True, servers=[{"url": "http://localhost:9583/mcp"}]),
        allowed_names={"safe-looking-name"},
    )
    assert tools == []
    assert clients == []
    for mock in _external_stack:
        mock.assert_not_called()
