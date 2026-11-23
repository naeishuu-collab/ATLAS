"""Side-effect-free tool for Host Supervisor task validation."""

from __future__ import annotations

from typing import Any

from openjarvis.core.execution import ToolEffect
from openjarvis.core.registry import ToolRegistry
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec


@ToolRegistry.register("synthetic_echo")
class SyntheticEchoTool(BaseTool):
    """Describe a synthetic echo that only a Host Supervisor may dispatch."""

    tool_id = "synthetic_echo"

    def __init__(self) -> None:
        self.calls = 0

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.tool_id,
            description=(
                "Return a deterministic synthetic value through the authenticated "
                "Host Supervisor task worker. This tool has no external side effects."
            ),
            parameters={
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
                "additionalProperties": False,
            },
            category="synthetic",
            effect=ToolEffect.READ_ONLY,
        )

    def execute(self, **_params: Any) -> ToolResult:
        self.calls += 1
        raise PermissionError(
            "synthetic_echo requires an authenticated Host Supervisor task"
        )
