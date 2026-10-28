"""Regression tests for host authorization before external/code effects."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import patch

from openjarvis.a2a.tool import A2AAgentTool
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.security.capabilities import Capability, CapabilityPolicy
from openjarvis.security.runtime import authorize_secured_operation
from openjarvis.skills.executor import SkillExecutor
from openjarvis.skills.tool_adapter import SkillTool
from openjarvis.skills.types import SkillManifest, SkillStep
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec
from openjarvis.tools.channel_tools import ChannelSendTool
from openjarvis.tools.templates.loader import ToolTemplate


class _ExternalProbe(BaseTool):
    tool_id = "external_probe"
    is_local = False

    def __init__(self) -> None:
        self.calls = 0

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="external_probe",
            description="test external effect",
            required_capabilities=[Capability.NETWORK_FETCH.value],
        )

    def execute(self, **params: object) -> ToolResult:
        self.calls += 1
        return ToolResult(tool_name=self.spec.name, content="sent", success=True)


class _CodeProbe(BaseTool):
    tool_id = "code_probe"

    def __init__(self) -> None:
        self.calls = 0

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="code_probe",
            description="test code effect",
            required_capabilities=[Capability.CODE_EXECUTE.value],
        )

    def execute(self, **params: object) -> ToolResult:
        self.calls += 1
        return ToolResult(tool_name=self.spec.name, content="executed", success=True)


def _call(name: str) -> ToolCall:
    return ToolCall(id=f"{name}-1", name=name, arguments=json.dumps({}))


def test_external_tool_requires_host_policy_before_execute() -> None:
    tool = _ExternalProbe()

    result = ToolExecutor([tool], agent_id="model").execute(_call(tool.spec.name))

    assert not result.success
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert result.metadata["security_denied"] is True
    assert result.execution_state.value == "NOT_STARTED"
    assert tool.calls == 0


def test_code_capability_requires_host_policy_before_execute() -> None:
    tool = _CodeProbe()

    result = ToolExecutor([tool], agent_id="model").execute(_call(tool.spec.name))

    assert not result.success
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert result.metadata["security_denied"] is True
    assert result.execution_state.value == "NOT_STARTED"
    assert tool.calls == 0


def test_channel_send_requires_host_policy_before_backend_send() -> None:
    sent: list[tuple[str, str]] = []

    class _Channel:
        def send(self, target: str, content: str, **kwargs: object) -> bool:
            sent.append((target, content))
            return True

    tool = ChannelSendTool(_Channel())
    result = ToolExecutor([tool], agent_id="model").execute(
        ToolCall(
            id="channel-send-1",
            name="channel_send",
            arguments=json.dumps({"channel": "target", "content": "secret"}),
        )
    )

    assert not result.success
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert sent == []


def test_a2a_tool_requires_host_policy_before_network_send() -> None:
    calls: list[str] = []

    class _Client:
        def send_task(self, input_text: str):
            calls.append(input_text)
            raise AssertionError("A2A network dispatch must not start")

    tool = object.__new__(A2AAgentTool)
    tool._client = _Client()
    tool._name = "a2a_test"
    tool.tool_id = "a2a_test"
    tool._description = "test A2A"

    result = ToolExecutor([tool], agent_id="model").execute(
        ToolCall(
            id="a2a-send-1",
            name="a2a_test",
            arguments=json.dumps({"input": "secret"}),
        )
    )

    assert not result.success
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert calls == []


def test_dynamic_skill_requires_host_policy_before_step_execution() -> None:
    code = _CodeProbe()
    manifest = SkillManifest(
        name="dynamic-code",
        steps=[SkillStep(tool_name=code.spec.name, arguments_template="{}")],
    )
    skill = SkillTool(manifest, SkillExecutor(ToolExecutor([code])))

    result = ToolExecutor([skill], agent_id="model").execute(
        _call(skill.spec.name)
    )

    assert not result.success
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert code.calls == 0


def test_shell_template_requires_host_policy_before_process_creation() -> None:
    tool = ToolTemplate(
        {
            "name": "template-shell",
            "action": {"type": "shell", "command": "python -c pass"},
        }
    )

    result = ToolExecutor([tool], agent_id="model").execute(_call(tool.spec.name))

    assert not result.success
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert result.metadata["security_denied"] is True
    assert result.execution_state.value == "NOT_STARTED"


def test_shell_template_host_grant_preserves_authorized_fake_path() -> None:
    tool = ToolTemplate(
        {
            "name": "template-shell-authorized",
            "action": {"type": "shell", "command": "python -c pass"},
        }
    )
    policy = CapabilityPolicy(default_deny=True)
    policy.grant("trusted-host", "code:execute")
    policy.grant("trusted-host", "system:admin")

    with patch(
        "openjarvis.tools.templates.loader.subprocess.run",
        return_value=SimpleNamespace(returncode=0, stdout="ok", stderr=""),
    ) as run:
        result = ToolExecutor(
            [tool], capability_policy=policy, agent_id="trusted-host"
        ).execute(_call(tool.spec.name))

    assert result.success
    assert result.content == "ok"
    run.assert_called_once()


def test_direct_operation_authorization_denies_without_host_policy() -> None:
    result = authorize_secured_operation(
        "external_operation",
        [Capability.CODE_EXECUTE.value],
        agent_id="model",
    )

    assert not result.success
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert result.metadata["security_denied"] is True


def test_host_grant_preserves_authorized_external_dispatch() -> None:
    tool = _ExternalProbe()
    policy = CapabilityPolicy(default_deny=True)
    policy.grant("trusted-host", Capability.NETWORK_FETCH.value)

    result = ToolExecutor(
        [tool], capability_policy=policy, agent_id="trusted-host"
    ).execute(_call(tool.spec.name))

    assert result.success
    assert tool.calls == 1
