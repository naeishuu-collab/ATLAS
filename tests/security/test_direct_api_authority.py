"""Direct API fail-closed regressions for external/code-capable tools."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from openjarvis.a2a.client import A2AClient
from openjarvis.a2a.tool import A2AAgentTool
from openjarvis.core.types import ToolCall
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.tools._stubs import ToolExecutor
from openjarvis.tools.channel_tools import ChannelSendTool
from openjarvis.tools.templates.loader import ToolTemplate


def _call(tool, params=None):
    return ToolCall(
        id="direct-api-1",
        name=tool.spec.name,
        arguments=json.dumps(params or {}),
    )


def test_direct_shell_template_denies_before_process_creation():
    tool = ToolTemplate(
        {"name": "direct-shell", "action": {"type": "shell", "command": "cmd"}}
    )
    with patch("openjarvis.tools.templates.loader.subprocess.run") as run:
        result = tool.execute()
    assert not result.success
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert run.call_count == 0


def test_direct_channel_send_denies_before_backend_send():
    calls = []

    class Channel:
        def send(self, *args, **kwargs):
            calls.append((args, kwargs))
            return True

    tool = ChannelSendTool(Channel())
    result = tool.execute(channel="target", content="payload")
    assert not result.success
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert calls == []


def test_direct_a2a_tool_denies_before_client_send():
    calls = []

    class Client:
        def send_task(self, value):
            calls.append(value)
            raise AssertionError("network must not start")

    tool = A2AAgentTool(Client(), name="a2a_direct")
    result = tool.execute(input="payload")
    assert not result.success
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert calls == []


def test_a2a_tool_constructor_does_not_discover():
    calls = []

    class Client:
        def discover(self):
            calls.append("discover")
            raise AssertionError("construction must not perform network I/O")

    A2AAgentTool(Client(), name="a2a_side_effect_free")
    assert calls == []


@pytest.mark.parametrize("method", ["discover", "send_task", "get_task", "cancel_task"])
def test_direct_a2a_client_denies_before_http(method):
    client = A2AClient("https://example.invalid")
    with patch("httpx.get") as get, patch("httpx.post") as post:
        with pytest.raises(PermissionError, match="HOST_AUTHORITY_UNAVAILABLE"):
            if method == "discover":
                client.discover()
            else:
                getattr(client, method)("payload")
    assert get.call_count == 0
    assert post.call_count == 0


def test_authorized_a2a_tool_propagates_network_authority():
    client = A2AClient("https://example.invalid")
    response = type(
        "Response",
        (),
        {
            "raise_for_status": lambda self: None,
            "json": lambda self: {
                "result": {"id": "task-1", "state": "completed", "output": "ok"}
            },
        },
    )()
    tool = A2AAgentTool(client, name="a2a_authorized")
    policy = CapabilityPolicy(default_deny=True)
    policy.grant("host", "network:fetch")
    with patch("httpx.post", return_value=response) as post:
        result = ToolExecutor(
            [tool], capability_policy=policy, agent_id="host"
        ).execute(_call(tool, {"input": "payload"}))
    assert result.success
    post.assert_called_once()


def test_authorized_tool_executor_propagates_authority_to_shell():
    tool = ToolTemplate(
        {"name": "authorized-shell", "action": {"type": "shell", "command": "cmd"}}
    )
    policy = CapabilityPolicy(default_deny=True)
    policy.grant("host", "code:execute")
    policy.grant("host", "system:admin")
    with patch(
        "openjarvis.tools.templates.loader.subprocess.run",
        return_value=SimpleNamespace(returncode=0, stdout="ok", stderr=""),
    ) as run:
        result = ToolExecutor(
            [tool], capability_policy=policy, agent_id="host"
        ).execute(_call(tool))
    assert result.success
    run.assert_called_once()
