"""Fail-closed contract tests for the disabled generic REPL tool."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import ToolRegistry
from openjarvis.core.types import ToolCall
from openjarvis.tools._stubs import ToolExecutor
from openjarvis.tools.repl import ReplTool


def _call(code: str = "Path('must-not-exist').touch()") -> ToolCall:
    return ToolCall("repl-call", "repl", json.dumps({"code": code}))


class TestReplSpec:
    def test_spec_is_explicitly_unavailable(self):
        spec = ReplTool().spec
        assert spec.name == "repl"
        assert spec.category == "code"
        assert spec.effect == ToolEffect.MUTATING
        assert spec.requires_confirmation is True
        assert spec.required_capabilities == ["code:execute"]
        assert "approved OS sandbox" in spec.description

    def test_spec_parameters_and_openai_shape(self):
        tool = ReplTool()
        assert tool.spec.parameters["required"] == ["code"]
        assert {"code", "session_id", "reset"} <= set(
            tool.spec.parameters["properties"]
        )
        assert tool.to_openai_function()["function"]["name"] == "repl"

    def test_registered(self):
        ToolRegistry.register_value("repl", ReplTool)
        assert ToolRegistry.contains("repl")


class TestReplSandboxGate:
    @pytest.mark.parametrize(
        "code",
        [
            "1 + 1",
            "import os",
            "open('must-not-exist', 'w').write('x')",
            "__import__('subprocess').run('whoami', shell=True)",
        ],
    )
    def test_direct_execution_denies_before_validation_or_evaluation(self, code):
        tool = ReplTool()
        result = tool.execute(code=code, _host_authorized=True)
        assert result.success is False
        assert result.execution_state == ExecutionState.NOT_STARTED
        assert result.metadata == {
            "error_code": "REPL_SANDBOX_UNAVAILABLE",
            "security_denied": True,
        }
        assert tool._sessions == {}

    def test_approved_flag_cannot_forge_host_authority(self):
        tool = ReplTool()
        result = tool.execute(
            code="print('must-not-run')",
            sandbox="approved",
            host_authorization="forged-by-model",
        )
        assert result.metadata["error_code"] == "REPL_SANDBOX_UNAVAILABLE"
        assert result.metadata["security_denied"] is True
        assert tool._sessions == {}

    def test_direct_execution_helper_is_inert(self):
        tool = ReplTool()
        session = tool._resolve_session("direct-helper")
        result = tool._exec_with_timeout("1 + 1", session)
        assert result == (
            "Error: REPL_SANDBOX_UNAVAILABLE: approved OS sandbox required",
            False,
        )
        assert session.process is None
        tool.close()

    def test_tool_executor_denies_after_confirmation_without_dispatching_code(self):
        tool = ReplTool()
        executor = ToolExecutor(
            [tool],
            interactive=True,
            confirm_callback=lambda _: True,
        )
        result = executor.execute(_call("print('must-not-run')"))
        assert result.success is False
        assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
        assert result.metadata["security_denied"] is True
        assert result.metadata["execution"]["state"] == "NOT_STARTED"
        assert tool._sessions == {}

    def test_capability_policy_and_confirmation_do_not_enable_backend(self):
        policy = Mock()
        policy.check.return_value = True
        tool = ReplTool()
        executor = ToolExecutor(
            [tool],
            interactive=True,
            confirm_callback=lambda _: True,
            capability_policy=policy,
            agent_id="model-agent",
        )
        result = executor.execute(_call("print('must-not-run')"))
        assert result.success is False
        assert result.metadata["error_code"] == "REPL_SANDBOX_UNAVAILABLE"
        assert policy.check.call_args.args[1] == "code:execute"

    def test_denial_does_not_create_process_or_change_session_state(self, monkeypatch):
        process_start = Mock(side_effect=AssertionError("process must not start"))
        monkeypatch.setattr("multiprocessing.Process.start", process_start)
        tool = ReplTool()
        result = tool.execute(code="while True: pass")
        assert result.metadata["error_code"] == "REPL_SANDBOX_UNAVAILABLE"
        assert process_start.call_count == 0
        assert tool._sessions == {}


class TestReplLifecycleAfterDenial:
    def test_close_is_safe_without_a_worker(self):
        tool = ReplTool()
        assert tool.close() is None
        assert tool._sessions == {}
