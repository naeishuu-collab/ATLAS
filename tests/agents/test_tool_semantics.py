from __future__ import annotations

import json

import pytest

from openjarvis.agents.executor import _ManagedMutationController
from openjarvis.agents.plan import DurablePlan
from openjarvis.agents.proposals import (
    PlanProposal,
    PlanStepProposal,
    ToolExecutionProposal,
)
from openjarvis.agents.tool_semantics import (
    ToolSemanticError,
    arguments_sha256,
    validate_tool_arguments,
)
from openjarvis.core.execution import ToolEffect
from openjarvis.tools._stubs import ToolSpec
from openjarvis.tools.execution_journal import ExecutionJournal


def _spec(
    *, effect: ToolEffect = ToolEffect.READ_ONLY, parameters: dict | None = None
) -> ToolSpec:
    return ToolSpec(
        "semantic-test-tool",
        "trusted test tool",
        parameters=parameters
        or {
            "type": "object",
            "properties": {
                "resource": {"type": "string", "pattern": "^asset-[a-z]+$"},
                "mode": {"type": "string", "enum": ["read", "write"]},
                "count": {"type": "integer", "minimum": 1, "maximum": 3},
            },
            "required": ["resource", "mode"],
            "additionalProperties": False,
        },
        required_capabilities=["file:read"],
        metadata={
            "schema_version": 4,
            "resource_identity_fields": ["resource"] if parameters is None else [],
        },
        effect=effect,
    )


def _valid_arguments() -> dict:
    return {"resource": "asset-report", "mode": "read", "count": 2}


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        ({"resource": 4, "mode": "read"}, "TOOL_ARGUMENT_TYPE"),
        ({"resource": "asset-report"}, "TOOL_ARGUMENT_MISSING"),
        ({**_valid_arguments(), "extra": True}, "TOOL_ARGUMENT_UNKNOWN_FIELD"),
        ({**_valid_arguments(), "mode": "delete"}, "TOOL_ARGUMENT_ENUM"),
        ({**_valid_arguments(), "count": 4}, "TOOL_ARGUMENT_RANGE"),
        ({**_valid_arguments(), "resource": "other"}, "TOOL_ARGUMENT_PATTERN"),
    ],
)
def test_trusted_schema_rejects_invalid_arguments(arguments, code):
    with pytest.raises(ToolSemanticError) as error:
        validate_tool_arguments(_spec(), arguments)
    assert error.value.code == code
    assert error.value.as_dict()["path"].startswith("$")


def test_schema_version_effect_resource_and_authorization_are_bound():
    spec = _spec()
    with pytest.raises(ToolSemanticError, match="schema version") as version:
        validate_tool_arguments(spec, _valid_arguments(), expected_schema_version=3)
    assert version.value.code == "TOOL_SCHEMA_VERSION_MISMATCH"

    with pytest.raises(ToolSemanticError) as effect:
        validate_tool_arguments(spec, _valid_arguments(), expected_effect="MUTATING")
    assert effect.value.code == "PLAN_EFFECT_MISMATCH"

    with pytest.raises(ToolSemanticError) as resource:
        validate_tool_arguments(
            spec,
            _valid_arguments(),
            expected_resource_identity={"resource": "asset-other"},
        )
    assert resource.value.code == "TOOL_RESOURCE_MISMATCH"

    with pytest.raises(ToolSemanticError) as denied:
        validate_tool_arguments(
            spec,
            _valid_arguments(),
            authorization_check=lambda _capability, _tool: False,
        )
    assert denied.value.code == "AUTHORIZATION_SCOPE_MISMATCH"


def test_canonical_arguments_are_order_independent_and_reject_duplicate_json_keys():
    assert arguments_sha256({"b": 2, "a": 1}) == arguments_sha256({"a": 1, "b": 2})
    with pytest.raises(ToolSemanticError) as duplicate:
        validate_tool_arguments(
            _spec(), '{"resource":"asset-a","resource":"asset-b","mode":"read"}'
        )
    assert duplicate.value.code == "TOOL_ARGUMENT_INVALID_JSON"


def test_structured_error_does_not_echo_argument_values():
    error = ToolSemanticError(
        "TOOL_ARGUMENT_ENUM",
        "argument does not match trusted enum",
        expected=["allowed"],
        actual="private-value",
    )
    assert error.as_dict() == {
        "code": "TOOL_ARGUMENT_ENUM",
        "path": "$",
        "message": "argument does not match trusted enum",
    }


def test_nested_additional_properties_schema_is_validated():
    spec = _spec(
        parameters={
            "type": "object",
            "properties": {},
            "additionalProperties": {"type": "integer", "maximum": 2},
        }
    )
    validate_tool_arguments(spec, {"first": 2})
    with pytest.raises(ToolSemanticError) as error:
        validate_tool_arguments(spec, {"first": "two"})
    assert error.value.code == "TOOL_ARGUMENT_TYPE"


def test_any_of_and_non_string_mapping_keys_are_checked():
    spec = _spec(
        parameters={
            "type": "object",
            "properties": {
                "document_id": {"type": "string"},
                "resource": {"type": "string"},
            },
            "required": ["document_id", "resource"],
            "anyOf": [
                {"required": ["selector"]},
                {"required": ["target"]},
            ],
            "additionalProperties": True,
        }
    )
    validate_tool_arguments(
        spec, {"document_id": "doc-1", "resource": "x", "target": "button"}
    )
    with pytest.raises(ToolSemanticError) as missing:
        validate_tool_arguments(spec, {"document_id": "doc-1", "resource": "x"})
    assert missing.value.code == "TOOL_ARGUMENT_ANY_OF"
    with pytest.raises(ToolSemanticError) as bad_key:
        validate_tool_arguments(_spec(), {1: "asset-report", "mode": "read"})
    assert bad_key.value.code == "TOOL_ARGUMENT_INVALID_JSON"


def test_resource_identity_fields_are_required():
    with pytest.raises(ToolSemanticError) as missing:
        validate_tool_arguments(_spec(), {"mode": "read"})
    assert missing.value.code == "TOOL_ARGUMENT_MISSING"


def test_controller_fails_closed_on_plan_argument_binding_mismatch(tmp_path):
    journal = ExecutionJournal(tmp_path / "semantic.db")
    try:
        spec = _spec(effect=ToolEffect.MUTATING)
        controller = _ManagedMutationController(
            journal,
            "agent-semantic",
            {"tool_state": {"execution_id": "execution-semantic"}},
            tool_specs={spec.name: spec},
            strict_schema=True,
        )
        controller.materialize_plan(
            PlanProposal(
                proposal_id="trusted-test-plan",
                steps=(
                    PlanStepProposal(
                        "step-1",
                        "MUTATING",
                        spec.name,
                        arguments=_valid_arguments(),
                    ),
                ),
            ),
            supported_tools={spec.name},
        )
        changed = {**_valid_arguments(), "resource": "asset-other"}
        decision = controller.authorize_proposal(
            ToolExecutionProposal(
                "proposal-1",
                spec.name,
                json.dumps(changed),
                "call-1",
            ),
            effect="MUTATING",
        )
        assert not decision.allowed
        assert decision.code == "PLAN_ARGUMENT_MISMATCH"
        assert journal.pending("agent-semantic") == []
    finally:
        journal.close()


def test_durable_plan_rejects_cycles_and_accepts_previous_schema_version():
    plan = DurablePlan.create("execution-plan", "plan-1")
    first = plan.add_node(planner_node_id="first")
    second = plan.add_node(
        planner_node_id="second", dependencies=[first.planner_node_id]
    )
    plan_dict = plan.to_dict()
    plan_dict["nodes"][0]["dependencies"] = ["second"]
    plan_dict["revisions"][-1]["nodes"][0]["dependencies"] = ["second"]
    with pytest.raises(ValueError, match="cycle"):
        DurablePlan.from_dict(plan_dict)

    previous = plan.to_dict()
    previous["schema_version"] = 2
    restored = DurablePlan.from_dict(previous)
    assert restored.nodes[second.planner_node_id].dependencies == [
        first.planner_node_id
    ]
