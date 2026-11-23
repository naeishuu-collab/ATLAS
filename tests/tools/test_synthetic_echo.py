import importlib

import pytest

import openjarvis.tools.synthetic_echo as synthetic_echo_module
from openjarvis.core.execution import ToolEffect
from openjarvis.core.registry import ToolRegistry


def test_synthetic_echo_is_registered_with_a_side_effect_free_schema():
    importlib.reload(synthetic_echo_module)
    registered = ToolRegistry.get("synthetic_echo")
    tool = registered()

    assert isinstance(tool, synthetic_echo_module.SyntheticEchoTool)
    assert tool.spec.effect == ToolEffect.READ_ONLY
    assert tool.spec.parameters["required"] == ["value"]
    assert tool.spec.parameters["additionalProperties"] is False


def test_synthetic_echo_cannot_execute_in_the_controller():
    tool = synthetic_echo_module.SyntheticEchoTool()

    with pytest.raises(PermissionError, match="authenticated Host Supervisor task"):
        tool.execute(value="atlas-test")

    assert tool.calls == 1
