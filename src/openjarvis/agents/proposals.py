"""Untrusted model tool proposals for the managed execution boundary."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from openjarvis.core.execution import MutationIntent
from openjarvis.core.types import ToolCall

_RESERVED_AUTHORITY_FIELDS = frozenset(
    {
        "execution_id",
        "plan_id",
        "planner_node_id",
        "step_id",
        "mutation_intent_id",
        "journal_token",
        "revision",
        "revision_id",
        "parent_revision_id",
        "completion_state",
    }
)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


class PlanProposalError(ValueError):
    """A structurally invalid or authority-bearing plan proposal."""


def _reserved_fields(value: Any, found: set[str] | None = None) -> tuple[str, ...]:
    """Find reserved authority keys without repairing the untrusted payload."""
    keys = found if found is not None else set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key in _RESERVED_AUTHORITY_FIELDS:
                keys.add(key)
            _reserved_fields(child, keys)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reserved_fields(child, keys)
    elif isinstance(value, str):
        try:
            decoded = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            decoded = None
        if isinstance(decoded, (dict, list, tuple)):
            _reserved_fields(decoded, keys)
    return tuple(sorted(keys))


@dataclass(frozen=True, slots=True)
class PlanStepProposal:
    """An untrusted proposal-local plan step."""

    local_index: str
    kind: str
    tool_name: str
    arguments: Any = "{}"
    dependencies: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.local_index, str) or not self.local_index.strip():
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: local_index is required")
        if self.kind not in {"READ_ONLY", "MUTATING"}:
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: invalid step kind")
        if not isinstance(self.tool_name, str) or not self.tool_name.strip():
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: tool_name is required")
        if not isinstance(self.dependencies, (list, tuple)):
            raise PlanProposalError(
                "PLAN_PROPOSAL_REJECTED: dependencies must be a list"
            )
        dependencies = tuple(self.dependencies)
        if any(not isinstance(item, str) or not item.strip() for item in dependencies):
            raise PlanProposalError(
                "PLAN_PROPOSAL_REJECTED: invalid dependency reference"
            )
        if len(set(dependencies)) != len(dependencies):
            raise PlanProposalError(
                "PLAN_PROPOSAL_REJECTED: duplicate dependency reference"
            )
        object.__setattr__(self, "dependencies", dependencies)
        reserved = _reserved_fields(self.arguments)
        if reserved:
            fields = ", ".join(reserved)
            raise PlanProposalError(
                "PLAN_PROPOSAL_REJECTED: authority fields in step arguments "
                f"({fields})"
            )

    @classmethod
    def from_dict(cls, raw: Any) -> "PlanStepProposal":
        if not isinstance(raw, dict):
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: step is not an object")
        reserved = _reserved_fields(raw)
        if reserved:
            fields = ", ".join(reserved)
            raise PlanProposalError(
                "PLAN_PROPOSAL_REJECTED: authority fields are not accepted "
                f"({fields})"
            )
        allowed = {"local_index", "kind", "tool_name", "arguments", "dependencies"}
        unknown = set(raw) - allowed
        if unknown:
            raise PlanProposalError(
                "PLAN_PROPOSAL_REJECTED: unsupported step fields "
                f"({', '.join(sorted(unknown))})"
            )
        dependencies = raw.get("dependencies", ())
        if not isinstance(dependencies, (list, tuple)):
            raise PlanProposalError(
                "PLAN_PROPOSAL_REJECTED: dependencies must be a list"
            )
        return cls(
            local_index=raw.get("local_index", ""),
            kind=raw.get("kind", ""),
            tool_name=raw.get("tool_name", ""),
            arguments=raw.get("arguments", "{}"),
            dependencies=tuple(dependencies),
        )


@dataclass(frozen=True, slots=True)
class PlanProposal:
    """An untrusted plan proposal with no durable controller identity."""

    proposal_id: str
    steps: tuple[PlanStepProposal, ...]
    source: str = "model"
    model_turn: int | None = None
    reserved_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.proposal_id, str) or not self.proposal_id.strip():
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: proposal_id is required")
        if not isinstance(self.source, str) or not self.source.strip():
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: source is required")
        if self.model_turn is not None and (
            type(self.model_turn) is not int or self.model_turn < 0
        ):
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: invalid model_turn")
        if not isinstance(self.steps, (list, tuple)):
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: steps must be a list")
        steps = tuple(self.steps)
        if not steps:
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: plan has no steps")
        if any(not isinstance(step, PlanStepProposal) for step in steps):
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: invalid plan step")
        indices = [step.local_index for step in steps]
        if len(set(indices)) != len(indices):
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: duplicate local_index")
        reserved = tuple(sorted(set(self.reserved_fields)))
        if reserved:
            object.__setattr__(self, "reserved_fields", reserved)
        object.__setattr__(self, "steps", steps)

    @classmethod
    def from_dict(cls, raw: Any) -> "PlanProposal":
        if not isinstance(raw, dict):
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: proposal is not an object")
        reserved = _reserved_fields(raw)
        if reserved:
            fields = ", ".join(reserved)
            raise PlanProposalError(
                "PLAN_PROPOSAL_REJECTED: authority fields are not accepted "
                f"({fields})"
            )
        allowed = {"proposal_id", "source", "model_turn", "steps"}
        unknown = set(raw) - allowed
        if unknown:
            raise PlanProposalError(
                "PLAN_PROPOSAL_REJECTED: unsupported proposal fields "
                f"({', '.join(sorted(unknown))})"
            )
        raw_steps = raw.get("steps")
        if not isinstance(raw_steps, list):
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: steps must be a list")
        return cls(
            proposal_id=raw.get("proposal_id") or f"proposal-{uuid.uuid4().hex}",
            source=raw.get("source", "model"),
            model_turn=raw.get("model_turn"),
            steps=tuple(PlanStepProposal.from_dict(step) for step in raw_steps),
        )

    def audit_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "source": self.source,
            "model_turn": self.model_turn,
            "steps": len(self.steps),
        }


@dataclass(frozen=True, slots=True)
class ReplanProposal(PlanProposal):
    """An untrusted future-work proposal for a controller-approved replan."""

    @classmethod
    def from_dict(cls, raw: Any) -> "ReplanProposal":
        if isinstance(raw, dict) and isinstance(raw.get("steps"), list):
            for step in raw["steps"]:
                if isinstance(step, dict) and isinstance(step.get("arguments"), str):
                    try:
                        json.loads(
                            step["arguments"],
                            object_pairs_hook=_reject_duplicate_json_keys,
                        )
                    except (TypeError, ValueError, json.JSONDecodeError) as exc:
                        raise PlanProposalError(
                            "REPLAN_PROPOSAL_PARSE_FAILED: invalid step arguments"
                        ) from exc
        proposal = PlanProposal.from_dict(raw)
        return cls(
            proposal_id=proposal.proposal_id,
            steps=proposal.steps,
            source=proposal.source,
            model_turn=proposal.model_turn,
            reserved_fields=proposal.reserved_fields,
        )


@dataclass(frozen=True, slots=True)
class ToolExecutionProposal:
    """A model proposal; it carries no trusted execution identity."""

    proposal_id: str
    tool_name: str
    arguments: str
    provider_call_id: str
    source: str = "model"
    model_turn: int | None = None
    reserved_fields: tuple[str, ...] = ()

    @classmethod
    def from_tool_call(
        cls,
        call: ToolCall,
        *,
        source: str = "model",
        model_turn: int | None = None,
    ) -> "ToolExecutionProposal":
        arguments = call.arguments or "{}"
        reserved: tuple[str, ...] = ()
        try:
            parsed = json.loads(arguments)
        except (TypeError, json.JSONDecodeError):
            parsed = None
        if isinstance(parsed, dict):
            reserved = tuple(sorted(set(parsed) & _RESERVED_AUTHORITY_FIELDS))
        return cls(
            proposal_id=f"proposal-{uuid.uuid4().hex}",
            tool_name=call.name,
            arguments=arguments,
            provider_call_id=call.id,
            source=source,
            model_turn=model_turn,
            reserved_fields=reserved,
        )

    def audit_dict(self) -> dict[str, Any]:
        """Return safe proposal metadata without copying tool arguments."""
        return {
            "proposal_id": self.proposal_id,
            "tool_name": self.tool_name,
            "provider_call_id": self.provider_call_id,
            "source": self.source,
            "model_turn": self.model_turn,
            "reserved_fields": list(self.reserved_fields),
        }


@dataclass(frozen=True, slots=True)
class ProposalDecision:
    """Controller response to one untrusted proposal."""

    allowed: bool
    mutation_context: MutationIntent | None = None
    code: str = ""
    message: str = ""


__all__ = [
    "PlanProposal",
    "PlanProposalError",
    "PlanStepProposal",
    "ReplanProposal",
    "ProposalDecision",
    "ToolExecutionProposal",
]
