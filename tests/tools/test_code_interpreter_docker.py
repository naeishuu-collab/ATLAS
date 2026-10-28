"""Fail-closed tests for the unapproved Docker code backend."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.tools.code_interpreter_docker import DockerCodeInterpreterTool


class TestDockerCodeInterpreterGate:
    def test_spec_requires_host_authority(self):
        spec = DockerCodeInterpreterTool().spec
        assert spec.name == "code_interpreter_docker"
        assert spec.required_capabilities == ["code:execute"]
        assert spec.requires_confirmation is True
        assert spec.effect == ToolEffect.MUTATING

    @pytest.mark.parametrize("code", ["print(2 + 2)", "open('/tmp/x', 'w')"])
    def test_denies_before_docker_or_code_execution(self, code):
        result = DockerCodeInterpreterTool().execute(code=code)
        assert result.success is False
        assert result.execution_state == ExecutionState.NOT_STARTED
        assert result.metadata["error_code"] == "CODE_SANDBOX_NOT_AUTHORIZED"

    def test_docker_client_is_not_created(self, monkeypatch):
        docker = Mock()
        monkeypatch.setitem(__import__("sys").modules, "docker", docker)
        result = DockerCodeInterpreterTool().execute(code="print('must-not-run')")
        assert result.metadata["error_code"] == "CODE_SANDBOX_NOT_AUTHORIZED"
        docker.from_env.assert_not_called()
