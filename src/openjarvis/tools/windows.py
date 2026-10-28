"""Explicitly bound cooperative Windows tools; default instances fail closed."""

from __future__ import annotations

import json

from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import ToolRegistry
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec
from openjarvis.windows.actions import failure_code


@ToolRegistry.register("windows_observe")
class WindowsObserveTool(BaseTool):
    tool_id = "windows_observe"

    def __init__(self, session=None):
        self.session = session

    @property
    def spec(self):
        return ToolSpec(
            self.tool_id,
            "Observe an explicitly bound Windows app receiver; "
            "resolve hints only within this fresh observation. A new observation "
            "does not reconcile or release an UNKNOWN_OUTCOME mutation.",
            parameters={
                "type": "object",
                "properties": {
                    "hwnd": {"type": "integer"},
                    "hints": {"type": "object"},
                },
                "required": ["hwnd"],
                "additionalProperties": False,
            },
            effect=ToolEffect.READ_ONLY,
            category="observation",
            timeout_seconds=30,
        )

    def execute(self, hwnd: int, hints=None):
        try:
            if self.session is None:
                raise RuntimeError("No trusted cooperative Windows session is bound")
            observation = self.session.observe(hwnd)
            target_id = (
                self.session.resolve(observation["observation_id"], **hints)
                if hints
                else None
            )
            data = {"observation": observation, "target_id": target_id}
            return ToolResult(
                self.tool_id,
                json.dumps(data),
                metadata={"windows": data},
                execution_state=ExecutionState.EXECUTED,
            )
        except Exception as error:
            data = {
                "failure": failure_code(error),
                "dispatch": "NOT_DISPATCHED",
                "retryable": False,
            }
            return ToolResult(
                self.tool_id,
                json.dumps(data),
                success=False,
                metadata={"windows": data},
                execution_state=ExecutionState.NOT_STARTED,
            )


@ToolRegistry.register("windows_action")
class WindowsActionTool(BaseTool):
    tool_id = "windows_action"

    def __init__(self, session=None):
        self.session = session

    @property
    def spec(self):
        return ToolSpec(
            self.tool_id,
            "One receiver-authorized Win32 click or exact edit-value replacement "
            "against a prior observation/target. No focus acquisition or retries. "
            "Success requires independent UIA verification. After a proven "
            "NOT_STARTED stale rejection, replan with fresh observation and "
            "explicit new authorization; never reuse the old target. "
            "UNKNOWN_OUTCOME must remain quarantined, even after re-observation.",
            parameters={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["click", "type_into"]},
                    "observation_id": {"type": "string"},
                    "target_id": {"type": "string"},
                    "value": {"type": "string", "maxLength": 4096},
                },
                "required": ["action", "observation_id", "target_id"],
                "additionalProperties": False,
            },
            effect=ToolEffect.MUTATING,
            requires_confirmation=True,
            timeout_seconds=30,
            metadata={"sensitive_parameters": ["value"]},
        )

    def execute(
        self, action: str, observation_id: str, target_id: str, value: str = ""
    ):
        if self.session is None:
            data = {
                "action": action,
                "observation_id": observation_id,
                "target_id": target_id,
                "identity": None,
                "preconditions": "REJECTED",
                "outcome": "NOT_STARTED",
                "failure": "UNBOUND_APPLICATION",
                "dispatch": "NOT_DISPATCHED",
                "verification": "NOT_VERIFIED",
                "retryable": False,
                "evidence": {},
            }
        else:
            data = self.session.act(action, observation_id, target_id, value=value)
        return ToolResult(
            self.tool_id,
            json.dumps(data),
            success=data["outcome"] == "VERIFIED",
            metadata={"windows": data},
            execution_state=ExecutionState(data["outcome"]),
        )
