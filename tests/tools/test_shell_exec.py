"""Fail-closed contract tests for host shell execution."""

from __future__ import annotations

import json
from unittest.mock import Mock

from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import ToolRegistry
from openjarvis.core.types import ToolCall
from openjarvis.tools._stubs import ToolExecutor
from openjarvis.tools.shell_exec import ShellExecTool


class TestShellExecGate:
    def test_spec_requires_host_authority(self):
        spec = ShellExecTool().spec
        assert spec.name == ShellExecTool.tool_id == "shell_exec"
        assert spec.required_capabilities == ["code:execute"]
        assert spec.requires_confirmation is True
        assert spec.effect == ToolEffect.MUTATING

    def test_direct_command_denies_before_validation_or_spawn(self):
        result = ShellExecTool().execute(
            command="python -c \"open('must-not-exist','w').write('x')\"",
            _host_authorized=True,
        )
        assert result.success is False
        assert result.execution_state == ExecutionState.NOT_STARTED
        assert result.metadata == {
            "error_code": "SHELL_SANDBOX_UNAVAILABLE",
            "security_denied": True,
        }

    def test_subprocess_backend_is_not_called(self, monkeypatch):
        runner = Mock(side_effect=AssertionError("subprocess must not run"))
        monkeypatch.setattr("openjarvis.tools.shell_exec.run_sandboxed", runner)
        result = ShellExecTool().execute(command="echo must-not-run")
        assert result.metadata["error_code"] == "SHELL_SANDBOX_UNAVAILABLE"
        assert result.metadata["security_denied"] is True
        runner.assert_not_called()

    def test_confirmation_and_capability_cannot_enable_backend(self):
        executor = ToolExecutor(
            [ShellExecTool()],
            interactive=True,
            confirm_callback=lambda _: True,
        )
        result = executor.execute(
            ToolCall("shell", "shell_exec", json.dumps({"command": "echo x"}))
        )
        assert result.success is False
        assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
        assert result.metadata["security_denied"] is True
        assert result.metadata["execution"]["state"] == "NOT_STARTED"

    def test_registered(self):
        ToolRegistry.register_value("shell_exec", ShellExecTool)
        assert ToolRegistry.contains("shell_exec")
