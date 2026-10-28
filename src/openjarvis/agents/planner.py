"""Untrusted model planning adapter for the durable plan controller."""

from __future__ import annotations

import json
from typing import Any

from openjarvis.agents.proposals import (
    PlanProposal,
    PlanProposalError,
    ReplanProposal,
)
from openjarvis.core.types import Message, Role
from openjarvis.engine._stubs import ResponseFormat


class PlannerParseError(PlanProposalError):
    """Planner output could not be parsed as one valid plan proposal."""


_PLAN_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "proposal_id": {"type": "string"},
        "source": {"type": "string"},
        "model_turn": {"type": ["integer", "null"], "minimum": 0},
        "steps": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["local_index", "kind", "tool_name"],
                "properties": {
                    "local_index": {"type": "string", "minLength": 1},
                    "kind": {"enum": ["READ_ONLY", "MUTATING"]},
                    "tool_name": {"type": "string", "minLength": 1},
                    "arguments": {},
                    "dependencies": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
    },
    "required": ["steps"],
}

_SYSTEM_PROMPT = """Return exactly one JSON object describing a proposed execution plan.
The object may contain proposal_id, source, model_turn, and steps. Each step has
local_index, kind (READ_ONLY or MUTATING), tool_name, optional arguments, and
optional dependencies. Do not include controller identity or completion fields.
The response is a proposal only; a controller will validate and materialize it."""

_REPLAN_SYSTEM_PROMPT = """Return exactly one JSON object describing a proposed
replacement execution suffix. The object may contain proposal_id, source,
model_turn, and steps. Each step has local_index, kind (READ_ONLY or MUTATING),
tool_name, optional arguments, and optional dependencies. Do not include
controller identity or completion fields. The response is an untrusted proposal
only; a controller will validate and append one durable replan revision."""


def _strict_json(text: str) -> Any:
    """Parse one standards-compliant JSON value without salvage or repair."""

    def duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant: {value}")

    return json.loads(
        text,
        object_pairs_hook=duplicate_keys,
        parse_constant=reject_constant,
    )


class PlannerAdapter:
    """Ask an inference engine for an untrusted :class:`PlanProposal`.

    This adapter never creates durable identities and never executes tools.
    ``AgentExecutor.plan_goal`` is the controller-owned materialization boundary.
    """

    def __init__(
        self,
        engine: Any,
        *,
        model: str,
        source: str = "model_planner",
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> None:
        self._engine = engine
        self._model = model
        self._source = source
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._calls = 0

    @property
    def call_count(self) -> int:
        return self._calls

    @property
    def model(self) -> str:
        """Host-visible model identity for router binding checks.

        Read-only; the host compares this against the router's
        RouteDecision before planning. Mismatch defers safely.
        """
        return self._model

    def _request_json(
        self,
        goal: str,
        context: Any,
        *,
        system_prompt: str,
        error_prefix: str,
    ) -> Any:
        if not isinstance(goal, str) or not goal.strip():
            raise PlannerParseError(f"{error_prefix}: goal is required")
        if context is None:
            context_text = ""
        elif isinstance(context, str):
            context_text = context
        else:
            try:
                context_text = json.dumps(context, sort_keys=True)
            except (TypeError, ValueError) as exc:
                raise PlannerParseError(
                    f"{error_prefix}: context is not serializable"
                ) from exc

        self._calls += 1
        try:
            response = self._engine.generate(
                [
                    Message(role=Role.SYSTEM, content=system_prompt),
                    Message(
                        role=Role.USER,
                        content=(
                            f"Goal:\n{goal.strip()}\n"
                            + (f"Context:\n{context_text}" if context_text else "")
                        ),
                    ),
                ],
                model=self._model,
                temperature=self._temperature,
                max_tokens=self._max_tokens,
                response_format=ResponseFormat(type="json_schema", schema=_PLAN_SCHEMA),
            )
        except Exception as exc:
            raise PlannerParseError(
                f"{error_prefix}: planner inference failed "
                f"({type(exc).__name__})"
            ) from exc

        content = response.get("content") if isinstance(response, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise PlannerParseError(
                f"{error_prefix}: response is not JSON text"
            )
        try:
            return _strict_json(content)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PlannerParseError(f"{error_prefix}: {exc}") from exc

    def _source_for(self, proposal: PlanProposal) -> PlanProposal:
        # Source and turn are audit metadata only. Durable authority is created
        # later by the managed controller, never from provider output.
        if proposal.source == "model" and self._source != "model":
            return type(proposal)(
                proposal_id=proposal.proposal_id,
                steps=proposal.steps,
                source=self._source,
                model_turn=proposal.model_turn,
                reserved_fields=proposal.reserved_fields,
            )
        return proposal

    def propose(self, goal: str, context: Any = None) -> PlanProposal:
        raw = self._request_json(
            goal,
            context,
            system_prompt=_SYSTEM_PROMPT,
            error_prefix="PLAN_PROPOSAL_PARSE_FAILED",
        )
        try:
            proposal = PlanProposal.from_dict(raw)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PlannerParseError(f"PLAN_PROPOSAL_PARSE_FAILED: {exc}") from exc
        return self._source_for(proposal)


class ReplannerAdapter(PlannerAdapter):
    """Ask inference for an untrusted replacement suffix proposal."""

    def propose(self, goal: str, context: Any = None) -> ReplanProposal:
        raw = self._request_json(
            goal,
            context,
            system_prompt=_REPLAN_SYSTEM_PROMPT,
            error_prefix="REPLAN_PROPOSAL_PARSE_FAILED",
        )
        try:
            proposal = ReplanProposal.from_dict(raw)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PlannerParseError(f"REPLAN_PROPOSAL_PARSE_FAILED: {exc}") from exc
        return self._source_for(proposal)  # type: ignore[return-value]


__all__ = ["PlannerAdapter", "PlannerParseError", "ReplannerAdapter"]
