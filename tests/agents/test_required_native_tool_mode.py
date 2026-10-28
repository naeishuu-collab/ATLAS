"""Required native tool-call contract tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from openjarvis.agents.orchestrator import OrchestratorAgent
from openjarvis.core.execution import (
    ModelCapabilityError,
    ToolEffect,
    ToolRequirement,
)
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec


class _EchoTool(BaseTool):
    tool_id = "diagnostic_echo"

    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.tool_id,
            description="Return a diagnostic value without side effects.",
            parameters={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
            },
            effect=ToolEffect.READ_ONLY,
        )

    def execute(self, **params: str) -> ToolResult:
        self.calls.append(params)
        return ToolResult(
            tool_name=self.tool_id,
            content=params.get("value", ""),
            success=True,
        )


def _engine(response: dict) -> MagicMock:
    engine = MagicMock()
    engine.engine_id = "mock"
    engine.generate.return_value = response
    return engine


def _native_response() -> dict:
    return {
        "content": "",
        "tool_calls": [
            {
                "id": "call-probe",
                "name": "diagnostic_echo",
                "arguments": '{"value":"ASTRA_TOOLCALL_PROBE"}',
            }
        ],
        "usage": {},
        "finish_reason": "tool_calls",
    }


def test_r1_optional_plain_content_remains_final_answer():
    tool = _EchoTool()
    engine = _engine({"content": "Done.", "usage": {}, "finish_reason": "stop"})
    result = OrchestratorAgent(engine, "test-model", tools=[tool]).run("hello")

    assert result.content == "Done."
    assert result.tool_results == []
    assert tool.calls == []
    assert engine.generate.call_args.kwargs["tool_requirement"] == (
        ToolRequirement.OPTIONAL
    )


def test_r2_optional_native_tool_call_is_executed():
    tool = _EchoTool()
    engine = _engine(_native_response())
    engine.generate.side_effect = [
        _native_response(),
        {"content": "Done.", "usage": {}, "finish_reason": "stop"},
    ]

    result = OrchestratorAgent(engine, "test-model", tools=[tool]).run("probe")

    assert result.content == "Done."
    assert tool.calls == [{"value": "ASTRA_TOOLCALL_PROBE"}]


def test_r3_required_native_tool_call_remains_valid():
    tool = _EchoTool()
    engine = _engine(_native_response())
    engine.generate.side_effect = [
        _native_response(),
        {"content": "Done.", "usage": {}, "finish_reason": "stop"},
    ]

    result = OrchestratorAgent(
        engine,
        "test-model",
        tools=[tool],
        tool_requirement=ToolRequirement.REQUIRED_NATIVE,
    ).run("probe")

    assert result.content == "Done."
    assert tool.calls == [{"value": "ASTRA_TOOLCALL_PROBE"}]
    assert engine.generate.call_args_list[0].kwargs["tool_requirement"] == (
        ToolRequirement.REQUIRED_NATIVE
    )


@pytest.mark.parametrize(
    "content",
    [
        "Done.",
        'diagnostic_echo(value="ASTRA_TOOLCALL_PROBE")',
        '<action>observe</action><parameter name="hwnd">101</parameter>',
        "",
    ],
    ids=["plain", "pseudo_call", "legacy_xml", "empty"],
)
def test_r4_r7_required_native_rejects_non_native_output(content: str):
    tool = _EchoTool()
    engine = _engine({"content": content, "usage": {}, "finish_reason": "stop"})
    agent = OrchestratorAgent(
        engine,
        "test-model",
        tools=[tool],
        tool_requirement=ToolRequirement.REQUIRED_NATIVE,
    )

    with pytest.raises(ModelCapabilityError) as error:
        agent.run("probe")

    assert error.value.failure_code == "MODEL_CAPABILITY_INSUFFICIENT"
    assert error.value.retryable is False
    assert tool.calls == []
    engine.generate.assert_called_once()


def test_required_native_failure_is_not_unknown_outcome():
    engine = _engine({"content": "Done.", "usage": {}, "finish_reason": "stop"})
    with pytest.raises(ModelCapabilityError) as error:
        OrchestratorAgent(
            engine,
            "test-model",
            tool_requirement=ToolRequirement.REQUIRED_NATIVE,
        ).run("probe")

    assert "UNKNOWN_OUTCOME" not in str(error.value)
