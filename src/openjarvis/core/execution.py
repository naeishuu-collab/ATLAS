"""Explicit tool execution outcomes; dispatch is not workflow verification."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class ToolEffect(str, Enum):
    READ_ONLY = "READ_ONLY"
    MUTATING = "MUTATING"
    UNKNOWN = "UNKNOWN"


class ToolRequirement(str, Enum):
    OPTIONAL = "OPTIONAL"
    REQUIRED_NATIVE = "REQUIRED_NATIVE"


class ModelCapabilityError(RuntimeError):
    """The selected model failed a controller-required native tool contract."""

    failure_code = "MODEL_CAPABILITY_INSUFFICIENT"
    retryable = False
    escalation_eligible = True


class ExecutionState(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    VERIFIED = "VERIFIED"
    UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"


class FailureKind(str, Enum):
    NONE = "NONE"
    PRECONDITION = "PRECONDITION"
    CAPACITY = "CAPACITY"
    TIMEOUT = "TIMEOUT"
    TOOL_FAILURE = "TOOL_FAILURE"
    UNKNOWN_OUTCOME = "UNKNOWN_OUTCOME"
    SAFETY_FAILURE = "SAFETY_FAILURE"


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    state: ExecutionState
    failure: FailureKind = FailureKind.NONE
    retryable: bool = False
    call_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            key: value.value if isinstance(value, Enum) else value
            for key, value in asdict(self).items()
        }


@dataclass(frozen=True, slots=True)
class MutationIntent:
    """Trusted controller identity for one semantic mutation step.

    Provider call IDs, observations, and target IDs identify individual
    invocations.  They are deliberately not part of this identity.
    """

    execution_id: str
    step_id: str
    mutation_intent_id: str
    arguments_sha256: str | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("execution_id", self.execution_id),
            ("step_id", self.step_id),
            ("mutation_intent_id", self.mutation_intent_id),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"Mutation intent {name} must be nonempty")
        if self.arguments_sha256 is not None and (
            not isinstance(self.arguments_sha256, str)
            or len(self.arguments_sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.arguments_sha256)
        ):
            raise ValueError("Mutation intent arguments hash is invalid")

    def to_dict(self) -> dict[str, str]:
        result = {
            "execution_id": self.execution_id,
            "step_id": self.step_id,
            "mutation_intent_id": self.mutation_intent_id,
        }
        if self.arguments_sha256 is not None:
            result["arguments_sha256"] = self.arguments_sha256
        return result
