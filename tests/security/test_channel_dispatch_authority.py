"""Fail-closed Webhook and ChannelBridge dispatch-boundary regressions."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from openjarvis.channels._stubs import BaseChannel, ChannelStatus
from openjarvis.channels.webhook import WebhookChannel
from openjarvis.core.events import EventBus
from openjarvis.core.types import ToolCall
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.security.runtime import (
    issue_channel_dispatch_authority,
    use_channel_dispatch_authority,
)
from openjarvis.server.channel_bridge import ChannelBridge
from openjarvis.server.session_store import SessionStore
from openjarvis.tools._stubs import ToolExecutor
from openjarvis.tools.channel_tools import ChannelSendTool


class _FakeChannel(BaseChannel):
    channel_id = "fake"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def connect(self) -> None:
        pass

    def disconnect(self) -> None:
        pass

    def send(self, channel, content, *, conversation_id="", metadata=None) -> bool:
        self.calls.append((channel, content))
        return True

    def status(self) -> ChannelStatus:
        return ChannelStatus.CONNECTED

    def list_channels(self) -> list[str]:
        return ["fake"]

    def on_message(self, handler) -> None:
        pass


def _authority(resource: str):
    policy = CapabilityPolicy(default_deny=True)
    policy.grant("host", "channel:send", resource)
    value = issue_channel_dispatch_authority(policy, "host", resource)
    assert value is not None
    return value


def _bridge(channel: _FakeChannel, tmp_path):
    return ChannelBridge(
        channels={"fake": channel},
        session_store=SessionStore(db_path=str(tmp_path / "sessions.db")),
        bus=EventBus(record_history=True),
    )


def test_webhook_direct_send_denies_before_http():
    channel = WebhookChannel(url="https://example.invalid/hook", secret="secret")
    with patch("httpx.request") as request:
        assert channel.send("target", "payload") is False
    request.assert_not_called()


def test_webhook_authority_is_destination_bound_and_disables_proxy_redirects():
    channel = WebhookChannel(url="https://example.invalid/hook")
    response = MagicMock(status_code=200)
    with patch("httpx.request", return_value=response) as request:
        with use_channel_dispatch_authority(_authority("target")):
            assert channel.send("other", "payload") is False
            assert channel.send("target", "payload") is True
    assert request.call_count == 1
    assert request.call_args.kwargs["follow_redirects"] is False
    assert request.call_args.kwargs["trust_env"] is False


def test_channel_bridge_direct_send_denies_before_backend(tmp_path):
    channel = _FakeChannel()
    bridge = _bridge(channel, tmp_path)
    assert bridge.send("fake", "payload") is False
    assert channel.calls == []


def test_channel_bridge_authority_cannot_be_retargeted(tmp_path):
    channel = _FakeChannel()
    bridge = _bridge(channel, tmp_path)
    wrong_target_authority = _authority("fake")
    assert bridge.send("other", "payload", authority=wrong_target_authority) is False
    assert channel.calls == []
    valid_authority = _authority("fake")
    assert bridge.send("fake", "payload", authority=valid_authority) is True
    assert channel.calls == [("fake", "payload")]


def test_channel_tool_policy_is_destination_scoped():
    channel = _FakeChannel()
    tool = ChannelSendTool(channel)
    policy = CapabilityPolicy(default_deny=True)
    policy.grant("host", "channel:send", "allowed")

    denied = ToolExecutor([tool], capability_policy=policy, agent_id="host").execute(
        ToolCall(
            id="channel-denied",
            name="channel_send",
            arguments=json.dumps({"channel": "blocked", "content": "payload"}),
        )
    )
    assert denied.success is False
    assert channel.calls == []

    allowed = ToolExecutor([tool], capability_policy=policy, agent_id="host").execute(
        ToolCall(
            id="channel-allowed",
            name="channel_send",
            arguments=json.dumps({"channel": "allowed", "content": "payload"}),
        )
    )
    assert allowed.success is True
    assert channel.calls == [("allowed", "payload")]


def test_channel_authority_context_does_not_leak():
    channel = WebhookChannel(url="https://example.invalid/hook")
    response = MagicMock(status_code=200)
    authority = _authority("target")
    with patch("httpx.request", return_value=response) as request:
        with use_channel_dispatch_authority(authority):
            assert channel.send("target", "payload") is True
        assert channel.send("target", "payload") is False
        try:
            with use_channel_dispatch_authority(authority):
                raise AssertionError("authority reuse must be denied")
        except PermissionError:
            pass
    assert request.call_count == 1
