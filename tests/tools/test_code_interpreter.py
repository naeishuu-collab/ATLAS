"""Fail-closed contract tests for the generic code interpreter."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import ToolRegistry
from openjarvis.tools.code_interpreter import CodeInterpreterTool


class TestCodeInterpreterGate:
    def test_spec_declares_security_boundary(self):
        spec = CodeInterpreterTool().spec
        assert spec.name == "code_interpreter"
        assert spec.category == "code"
        assert spec.required_capabilities == ["code:execute"]
        assert spec.requires_confirmation is True
        assert spec.effect == ToolEffect.MUTATING

    @pytest.mark.parametrize(
        "code",
        [
            "print(2 + 2)",
            "import os; os.system('whoami')",
            "open('must-not-exist', 'w').write('x')",
            "eval('2+2')",
            "def f(:\n",
        ],
    )
    def test_denies_before_ast_or_process_execution(self, code):
        tool = CodeInterpreterTool()
        result = tool.execute(code=code, _host_authorized=True)
        assert result.success is False
        assert result.execution_state == ExecutionState.NOT_STARTED
        assert result.metadata == {
            "error_code": "CODE_SANDBOX_UNAVAILABLE",
            "security_denied": True,
        }

    def test_no_subprocess_on_denial(self, monkeypatch):
        run = Mock(side_effect=AssertionError("subprocess must not run"))
        monkeypatch.setattr("subprocess.run", run)
        result = CodeInterpreterTool().execute(code="print('must-not-run')")
        assert result.metadata["error_code"] == "CODE_SANDBOX_UNAVAILABLE"
        run.assert_not_called()

    def test_model_cannot_forge_sandbox_authority(self):
        result = CodeInterpreterTool().execute(
            code="print('must-not-run')",
            sandbox="approved",
            host_authorization="forged",
        )
        assert result.metadata["error_code"] == "CODE_SANDBOX_UNAVAILABLE"

    def test_openai_shape_and_registration(self):
        tool = CodeInterpreterTool()
        assert tool.to_openai_function()["function"]["name"] == "code_interpreter"
        ToolRegistry.register_value("code_interpreter", CodeInterpreterTool)
        assert ToolRegistry.contains("code_interpreter")
