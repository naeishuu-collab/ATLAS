"""AgentExecutor — runs a single agent tick."""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from typing import TYPE_CHECKING, Any

from openjarvis.agents._stubs import AgentResult
from openjarvis.agents.errors import (
    AgentTickError,
    EscalateError,
    FatalError,
    classify_error,
    retry_delay,
)
from openjarvis.agents.plan import DurablePlan, semantic_status_can_advance
from openjarvis.agents.planner import PlannerAdapter, ReplannerAdapter
from openjarvis.agents.proposals import (
    PlanProposal,
    PlanProposalError,
    ProposalDecision,
    ReplanProposal,
    ToolExecutionProposal,
)
from openjarvis.agents.tool_resolver import resolve_agent_tools
from openjarvis.agents.tool_semantics import (
    ToolSemanticBinding,
    ToolSemanticError,
    arguments_sha256,
    validate_tool_arguments,
)
from openjarvis.agents.verification import GoalVerification, verify_goal_artifacts
from openjarvis.core.artifacts import is_artifact_reference, valid_artifact_references
from openjarvis.core.events import EventBus, EventType
from openjarvis.core.execution import MutationIntent, ToolRequirement
from openjarvis.core.types import Message, Role, ToolCall

if TYPE_CHECKING:
    from openjarvis.agents.manager import AgentManager

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3

# Default model for monitor_operative / long-horizon agent ticks. qwen3:8b
# emits tool_calls but, when given the full MonitorOperative system prompt
# alongside a `think` no-op tool, reliably picks `think` instead of the real
# action tools — producing tickless prose from training-data memory.
# gemma4:31b follows the function-calling protocol with the same prompt and
# actually invokes web_search / memory_retrieve. Explicit ``config["model"]``
# on an agent still wins.
_AGENT_TICK_DEFAULT_MODEL = "gemma4:31b"
_CHECKPOINT_SCHEMA_VERSION = 1
_CHECKPOINT_STEP_STATES = {
    "NOT_STARTED",
    "PREPARED",
    "EXECUTING",
    "EXECUTED",
    "VERIFIED",
    "FAILED",
    "UNKNOWN_OUTCOME",
}
_SEMANTIC_STEP_STATES = {
    "AUTHORIZED",
    "PREPARED",
    "EXECUTING",
    "EXECUTED",
    "VERIFIED",
    "FAILED",
    "UNKNOWN_OUTCOME",
    "NOT_EXECUTED",
}


class _ManagedMutationController:
    """Controller-owned plan and semantic identity for one managed execution."""

    def __init__(
        self,
        journal: Any,
        scope: str,
        runtime: dict[str, Any],
        *,
        tool_specs: dict[str, Any] | None = None,
        authorization_check: Any = None,
        strict_schema: bool = False,
    ) -> None:
        self._journal = journal
        self._scope = scope
        self._runtime = runtime
        self._tool_state = runtime.setdefault("tool_state", {})
        self._tool_specs = dict(tool_specs or {})
        self._authorization_check = authorization_check
        self._strict_schema = bool(strict_schema)
        self._auto_advance = runtime.get("_auto_advance_plan") is True
        execution_id = self._tool_state.get("execution_id")
        if not isinstance(execution_id, str) or not execution_id.strip():
            execution_id = uuid.uuid4().hex
            self._tool_state["execution_id"] = execution_id
        self._execution_id = execution_id
        raw_plan = self._tool_state.get("durable_plan")
        self._plan_persisted = raw_plan is not None
        self._plan = (
            DurablePlan.from_dict(raw_plan)
            if raw_plan is not None
            else DurablePlan.create(execution_id)
        )
        if self._plan.execution_id != self._execution_id:
            raise ValueError("durable plan execution identity disagrees")
        persisted_plan_id = self._tool_state.get("plan_id")
        if raw_plan is not None and (
            not isinstance(persisted_plan_id, str)
            or persisted_plan_id != self._plan.plan_id
        ):
            raise ValueError("checkpoint and durable plan identity disagree")
        persisted_revision_id = self._tool_state.get("revision_id")
        if raw_plan is not None and persisted_revision_id is not None and (
            not isinstance(persisted_revision_id, str)
            or persisted_revision_id != self._plan.revision_id
        ):
            raise ValueError("checkpoint and durable plan revision disagree")
        self._intent: MutationIntent | None = None
        self._status: str | None = None
        self._next_step_id = self._tool_state.get("next_step_id")

        semantic = self._tool_state.get("semantic_step")
        if semantic is not None:
            self._load(semantic)
        elif not self._next_step_id:
            # Legacy checkpoints may only have semantic fields on completed
            # steps. Restore the latest one so a fresh model proposal cannot
            # silently reopen it after restart.
            for step in reversed(self._tool_state.get("completed_steps", [])):
                if not isinstance(step, dict) or step.get("effect") == "READ_ONLY":
                    continue
                if all(
                    isinstance(step.get(key), str) and step[key]
                    for key in ("execution_id", "step_id", "mutation_intent_id")
                ):
                    self._load(
                        {
                            "execution_id": step["execution_id"],
                            "step_id": step["step_id"],
                            "mutation_intent_id": step["mutation_intent_id"],
                            "arguments_sha256": step.get("arguments_sha256"),
                            "status": step.get(
                                "semantic_status",
                                step.get("execution_state", ""),
                            ),
                        }
                    )
                    break

    def _load(self, raw: dict[str, Any]) -> None:
        if not isinstance(raw, dict) or any(
            not isinstance(raw.get(key), str) or not raw[key].strip()
            for key in ("execution_id", "step_id", "mutation_intent_id", "status")
        ):
            raise ValueError("managed semantic step is malformed")
        if raw["execution_id"] != self._execution_id:
            raise ValueError("managed semantic execution identity disagrees")
        if raw["status"] not in _SEMANTIC_STEP_STATES:
            raise ValueError("managed semantic step state is invalid")
        intent = MutationIntent(
            raw["execution_id"],
            raw["step_id"],
            raw["mutation_intent_id"],
            raw.get("arguments_sha256"),
        )
        row = self._journal.semantic_intent(self._scope, intent)
        if row is None:
            raise ValueError("managed semantic step is absent from the journal")
        if not semantic_status_can_advance(raw["status"], row["status"]):
            raise ValueError("managed checkpoint and semantic journal disagree")
        node = self._plan.node(intent.step_id)
        if node is None:
            if self._plan_persisted:
                raise ValueError(
                    "managed semantic step is absent from the durable plan"
                )
            node = self._plan.add_node(planner_node_id=intent.step_id)
            self._plan.activate(intent.step_id)
        if node.kind != "MUTATING":
            raise ValueError("managed semantic step is bound to a read-only node")
        if self._plan.argument_binding_required and (
            intent.arguments_sha256 != node.arguments_sha256
        ):
            raise ValueError("PLAN_ARGUMENT_BINDING_MISMATCH")
        if node.mutation_intent_id not in {None, intent.mutation_intent_id}:
            raise ValueError("planner node mutation intent disagrees")
        if node.status == "PLANNED":
            self._plan.activate(intent.step_id)
        self._plan.bind_intent(intent.step_id, intent.mutation_intent_id)
        self._intent = intent
        self._status = row["status"]
        self._sync_plan_state()
        self._tool_state["semantic_step"] = self.snapshot()

    def _write(self) -> None:
        self._tool_state["durable_plan"] = self._plan.to_dict()
        self._tool_state["plan_id"] = self._plan.plan_id
        self._tool_state["revision_id"] = self._plan.revision_id
        if self._intent is None:
            self._tool_state.pop("semantic_step", None)
        else:
            self._tool_state["semantic_step"] = self.snapshot()
        if self._next_step_id:
            self._tool_state["next_step_id"] = self._next_step_id
        else:
            self._tool_state.pop("next_step_id", None)

    def snapshot(self) -> dict[str, str] | None:
        if self._intent is None or self._status is None:
            return None
        return {
            **self._intent.to_dict(),
            "status": self._status,
        }

    def persist_into(self, tool_state: dict[str, Any]) -> None:
        self._write()
        tool_state["execution_id"] = self._execution_id
        tool_state["durable_plan"] = self._plan.to_dict()
        tool_state["plan_id"] = self._plan.plan_id
        tool_state["revision_id"] = self._plan.revision_id
        if self._intent is None:
            tool_state.pop("semantic_step", None)
        else:
            tool_state["semantic_step"] = self.snapshot()
        if self._next_step_id:
            tool_state["next_step_id"] = self._next_step_id
        else:
            tool_state.pop("next_step_id", None)

    def context_for(self, _call: ToolCall | None = None) -> MutationIntent:
        """Return the current intent; create it only in controller code."""
        if self._intent is None:
            if self._next_step_id:
                step_id = self._next_step_id
                node = self._plan.node(step_id)
                if node is None:
                    self._plan.add_node(planner_node_id=step_id)
                    self._plan.activate(step_id)
                elif node.status == "PLANNED":
                    self._plan.activate(step_id)
                elif node.status != "ACTIVE":
                    raise ValueError("next planner node is not executable")
            elif self._plan.active_node_id:
                step_id = self._plan.active_node_id
                node = self._plan.node(step_id)
                if node is None or node.kind != "MUTATING":
                    raise ValueError("active planner node cannot authorize mutation")
            else:
                if self._plan.nodes:
                    raise ValueError("trusted planner advancement is required")
                node = self._plan.add_node(kind="MUTATING")
                self._plan.activate(node.planner_node_id)
                step_id = node.planner_node_id
            intent = MutationIntent(
                self._execution_id,
                step_id,
                f"intent-{uuid.uuid4().hex}",
                node.arguments_sha256
                if self._plan.argument_binding_required
                else None,
            )
            self._journal.authorize_intent(self._scope, intent)
            self._intent = intent
            self._status = "AUTHORIZED"
            self._next_step_id = None
            self._plan.bind_intent(step_id, intent.mutation_intent_id)
            self._write()
        else:
            row = self._journal.semantic_intent(self._scope, self._intent)
            if row is None:
                raise ValueError("managed semantic step disappeared from the journal")
            self._status = row["status"]
            self._sync_plan_state()
            self._write()
        return self._intent

    def _tool_instance(self, tool_name: str) -> Any:
        instance = self._tool_specs.get(tool_name)
        if instance is not None:
            return instance
        try:
            from openjarvis.core.registry import ToolRegistry

            entry = ToolRegistry.get(tool_name)
            return entry() if isinstance(entry, type) else entry
        except Exception:
            return None

    def _tool_spec(self, tool_name: str) -> Any:
        instance = self._tool_instance(tool_name)
        return getattr(instance, "spec", instance)

    def _tool_capabilities(self, tool_name: str) -> tuple[str, ...]:
        instance = self._tool_instance(tool_name)
        if instance is None or not hasattr(instance, "spec"):
            return ()
        from openjarvis.security.capabilities import canonical_tool_capabilities

        return tuple(canonical_tool_capabilities(instance))

    def _semantic_binding(
        self,
        proposal: ToolExecutionProposal,
        *,
        effect: str,
        expected_schema_version: int | None = None,
        expected_resource_identity: dict[str, Any] | None = None,
    ) -> ToolSemanticBinding:
        spec = self._tool_spec(proposal.tool_name)
        if spec is None:
            if not self._strict_schema:
                return ToolSemanticBinding(
                    tool_name=proposal.tool_name,
                    schema_version=1,
                    effect=effect,
                    arguments_sha256=arguments_sha256(proposal.arguments),
                    resource_identity={},
                )
            raise ToolSemanticError(
                "TOOL_SCHEMA_UNAVAILABLE",
                "trusted tool schema is unavailable",
                actual=proposal.tool_name,
            )
        authorization_check = self._authorization_check
        return validate_tool_arguments(
            spec,
            proposal.arguments,
            expected_effect=effect,
            expected_schema_version=expected_schema_version,
            expected_resource_identity=expected_resource_identity,
            authorization_check=authorization_check,
            required_capabilities=self._tool_capabilities(proposal.tool_name),
        )

    def _plan_step_binding(self, step: Any) -> ToolSemanticBinding:
        spec = self._tool_spec(step.tool_name)
        if spec is None:
            if not self._strict_schema:
                return ToolSemanticBinding(
                    tool_name=step.tool_name,
                    schema_version=1,
                    effect=step.kind,
                    arguments_sha256=arguments_sha256(step.arguments),
                    resource_identity={},
                )
            raise ToolSemanticError(
                "TOOL_SCHEMA_UNAVAILABLE",
                "trusted tool schema is unavailable",
                actual=step.tool_name,
            )
        return validate_tool_arguments(
            spec,
            step.arguments,
            expected_effect=step.kind,
            expected_schema_version=step.schema_version,
            authorization_check=self._authorization_check,
            required_capabilities=self._tool_capabilities(step.tool_name),
        )

    @staticmethod
    def _bind_node(node: Any, binding: ToolSemanticBinding) -> None:
        if node.tool_name is not None and node.tool_name != binding.tool_name:
            raise ToolSemanticError(
                "PLAN_TOOL_MISMATCH",
                "proposed tool does not match the controller-bound plan node",
                expected=node.tool_name,
                actual=binding.tool_name,
            )
        if (
            node.arguments_sha256 is not None
            and node.arguments_sha256 != binding.arguments_sha256
        ):
            raise ToolSemanticError(
                "PLAN_ARGUMENT_MISMATCH",
                "proposed arguments do not match the controller-bound plan node",
            )
        if (
            node.schema_version is not None
            and node.schema_version != binding.schema_version
        ):
            raise ToolSemanticError(
                "PLAN_SCHEMA_VERSION_MISMATCH",
                "proposed schema version does not match the controller-bound plan node",
                expected=node.schema_version,
                actual=binding.schema_version,
            )
        if (
            node.resource_identity is not None
            and node.resource_identity != binding.resource_identity
        ):
            raise ToolSemanticError(
                "PLAN_RESOURCE_MISMATCH",
                "proposed resource does not match the controller-bound plan node",
                expected=node.resource_identity,
                actual=binding.resource_identity,
            )
        node.tool_name = binding.tool_name
        node.arguments_sha256 = binding.arguments_sha256
        node.schema_version = binding.schema_version
        node.resource_identity = dict(binding.resource_identity)

    def authorize_proposal(
        self,
        proposal: ToolExecutionProposal,
        *,
        effect: str,
    ) -> ProposalDecision:
        """Validate an untrusted proposal before a managed tool dispatch."""
        if proposal.reserved_fields:
            fields = ", ".join(proposal.reserved_fields)
            return ProposalDecision(
                allowed=False,
                code="PROPOSAL_REJECTED",
                message=(
                    "PROPOSAL_REJECTED: model-supplied authority fields are not "
                    f"accepted ({fields})."
                ),
            )
        try:
            binding = self._semantic_binding(proposal, effect=effect)
            if self._intent is not None:
                self.refresh()
                if self._status == "VERIFIED":
                    if effect != "READ_ONLY" and not (
                        self._auto_advance and self._advance_verified_step()
                    ):
                        return ProposalDecision(
                            allowed=False,
                            code="PLAN_ADVANCEMENT_REQUIRED",
                            message=(
                                "PLAN_ADVANCEMENT_REQUIRED: the current mutation "
                                "step is already VERIFIED; a trusted controller "
                                "step is required before another proposal."
                            ),
                        )
                if effect != "READ_ONLY" and self._status in {
                    "PREPARED",
                    "EXECUTING",
                    "EXECUTED",
                    "UNKNOWN_OUTCOME",
                }:
                    return ProposalDecision(
                        allowed=False,
                        code="RECONCILIATION_REQUIRED",
                        message=(
                            "RECONCILIATION_REQUIRED: the current mutation outcome "
                            "is unresolved; no replacement mutation is allowed."
                        ),
                    )
                if effect != "READ_ONLY" and self._status in {"FAILED", "NOT_EXECUTED"}:
                    return ProposalDecision(
                        allowed=False,
                        code="PLAN_ADVANCEMENT_REQUIRED",
                        message=(
                            "PLAN_ADVANCEMENT_REQUIRED: the current step did not "
                            "execute; a trusted controller replan is required."
                        ),
                    )
            if (
                self._auto_advance
                and self._plan.nodes
                and self._plan.active_node_id is None
            ):
                self._advance_ready_step()
            planned_node_id = (
                self._intent.step_id
                if self._intent is not None
                else self._next_step_id or self._plan.active_node_id
            )
            planned_node = (
                self._plan.node(planned_node_id)
                if isinstance(planned_node_id, str)
                else None
            )
            if effect == "READ_ONLY":
                if planned_node is not None and planned_node.kind == "READ_ONLY":
                    self._bind_node(planned_node, binding)
                    self._write()
                return ProposalDecision(allowed=True)
            if self._plan.nodes and planned_node is None:
                return ProposalDecision(
                    allowed=False,
                    code="PLAN_ADVANCEMENT_REQUIRED",
                    message=(
                        "PLAN_ADVANCEMENT_REQUIRED: no unique controller-bound "
                        "plan step is executable."
                    ),
                )
            if planned_node is not None:
                if (planned_node.kind == "READ_ONLY") != (effect == "READ_ONLY"):
                    return ProposalDecision(
                        allowed=False,
                        code="PLAN_EFFECT_MISMATCH",
                        message=(
                            "PLAN_EFFECT_MISMATCH: proposed tool effect does not "
                            "match the controller-bound plan node."
                        ),
                    )
                self._bind_node(planned_node, binding)
                self._write()
            elif effect == "MUTATING":
                self._plan.tool_binding_required = True
                self._plan.argument_binding_required = True
                self._plan.schema_binding_required = True
                node = self._plan.add_node(
                    kind="MUTATING",
                    tool_name=binding.tool_name,
                    arguments_sha256=binding.arguments_sha256,
                    schema_version=binding.schema_version,
                    resource_identity=binding.resource_identity,
                )
                self._plan.activate(node.planner_node_id)
                self._write()
            intent = self.context_for()
            return ProposalDecision(allowed=True, mutation_context=intent)
        except ToolSemanticError as exc:
            return ProposalDecision(
                allowed=False,
                code=exc.code,
                message=f"{exc.code}: {exc}",
                details=exc.as_dict(),
            )
        except ValueError as exc:
            return ProposalDecision(
                allowed=False,
                code="PLAN_ADVANCEMENT_REQUIRED",
                message=f"PLAN_ADVANCEMENT_REQUIRED: {exc}",
            )

    def record_result(self, _call: ToolCall, result: Any) -> None:
        """Stage the result state in the checkpoint before continuation."""
        if self._intent is None:
            if result is not None and getattr(result, "success", False):
                step_id = self._next_step_id or self._plan.active_node_id
                node = self._plan.node(step_id) if step_id else None
                if node is not None and node.kind == "READ_ONLY":
                    self._plan.complete_read_only(node.planner_node_id)
                    self._next_step_id = None
                    self._write()
            return
        execution = (getattr(result, "metadata", {}) or {}).get("execution", {})
        # A pre-dispatch failure has no reservation token.  Refresh from the
        # journal so NOT_EXECUTED is checkpointed, while a blocked duplicate
        # remains VERIFIED instead of being overwritten by NOT_STARTED.
        if not execution.get("journal_token"):
            self.refresh()
            return
        state = execution.get("state")
        if state in _SEMANTIC_STEP_STATES:
            self._status = state
            self._sync_plan_state()
            self._write()

    def refresh(self) -> None:
        if self._intent is None:
            return
        row = self._journal.semantic_intent(self._scope, self._intent)
        if row is None:
            raise ValueError("managed semantic step disappeared from the journal")
        self._status = row["status"]
        self._sync_plan_state()
        self._write()

    def sync_from_journal(self) -> None:
        """Refresh a pre-dispatch checkpoint from the journal state."""
        self.refresh()

    @property
    def plan(self) -> DurablePlan:
        """Return the controller-owned plan; callers cannot replace it."""
        return self._plan

    def plan_snapshot(self) -> dict[str, Any]:
        return self._plan.to_dict()

    def _ready_nodes(self) -> list[Any]:
        if self._plan.active_node_id is not None:
            return []
        if any(
            node.status in {"FAILED", "RECONCILIATION_REQUIRED"}
            for node in self._plan.nodes.values()
        ):
            return []
        return sorted(
            (
                node
                for node in self._plan.nodes.values()
                if node.status == "PLANNED"
                and all(
                    self._plan.nodes[dependency].status == "COMPLETED"
                    for dependency in node.dependencies
                )
            ),
            key=lambda node: node.planner_node_id,
        )

    def _advance_ready_step(self) -> bool:
        """Advance only when the controller sees one unambiguous frontier."""
        ready = self._ready_nodes()
        if len(ready) != 1:
            return False
        node = ready[0]
        self._plan.activate(node.planner_node_id)
        self._next_step_id = node.planner_node_id
        self._write()
        return True

    def _advance_verified_step(self) -> bool:
        """Move a verified step to its unique controller-owned successor."""
        ready = self._ready_nodes()
        if len(ready) != 1:
            return False
        node = ready[0]
        self._plan.activate(node.planner_node_id)
        self._intent = None
        self._status = None
        self._next_step_id = node.planner_node_id
        self._write()
        return True

    def create_plan_node(
        self,
        *,
        kind: str = "MUTATING",
        planner_node_id: str | None = None,
        dependencies: list[str] | None = None,
    ) -> dict[str, Any]:
        """Materialize an untrusted proposal as a controller-owned node."""
        node = self._plan.add_node(
            planner_node_id=planner_node_id,
            kind=kind,
            dependencies=dependencies,
        )
        self._write()
        return node.to_dict()

    def _validate_plan_proposal(
        self,
        proposal: PlanProposal,
        supported_tools: set[str] | None,
    ) -> list[str]:
        if not isinstance(proposal, PlanProposal):
            raise PlanProposalError("PLAN_PROPOSAL_REJECTED: invalid proposal type")
        if proposal.reserved_fields:
            fields = ", ".join(proposal.reserved_fields)
            raise PlanProposalError(
                "PLAN_PROPOSAL_REJECTED: authority fields are not accepted "
                f"({fields})"
            )
        if supported_tools is not None:
            supported = set(supported_tools)
            unsupported = sorted(
                {
                    step.tool_name
                    for step in proposal.steps
                    if step.tool_name not in supported
                }
            )
            if unsupported:
                raise PlanProposalError(
                    "PLAN_PROPOSAL_REJECTED: unsupported tools "
                    f"({', '.join(unsupported)})"
                )
        local_indices = {step.local_index for step in proposal.steps}
        for step in proposal.steps:
            unknown = set(step.dependencies) - local_indices
            if unknown:
                raise PlanProposalError(
                    "PLAN_PROPOSAL_REJECTED: unknown dependencies "
                    f"({', '.join(sorted(unknown))})"
                )

        remaining = {
            step.local_index: set(step.dependencies) for step in proposal.steps
        }
        order: list[str] = []
        while remaining:
            ready = sorted(index for index, deps in remaining.items() if not deps)
            if not ready:
                raise PlanProposalError("PLAN_PROPOSAL_REJECTED: cyclic dependencies")
            order.extend(ready)
            for index in ready:
                remaining.pop(index)
            for deps in remaining.values():
                deps.difference_update(ready)
        for step in proposal.steps:
            try:
                self._plan_step_binding(step)
            except ToolSemanticError as exc:
                raise PlanProposalError(f"{exc.code}: {exc}") from exc
        return order

    def materialize_plan(
        self,
        proposal: PlanProposal,
        *,
        supported_tools: set[str] | None = None,
    ) -> dict[str, Any]:
        """Materialize one untrusted proposal using controller-owned IDs."""
        if self._plan.nodes or self._intent is not None:
            raise PlanProposalError(
                "PLAN_PROPOSAL_REJECTED: a durable plan is already materialized"
            )
        order = self._validate_plan_proposal(proposal, supported_tools)

        candidate = DurablePlan.create(self._execution_id, self._plan.plan_id)
        candidate.tool_binding_required = True
        candidate.argument_binding_required = True
        candidate.schema_binding_required = True
        local_to_node = {
            step.local_index: f"node-{uuid.uuid4().hex}" for step in proposal.steps
        }
        steps_by_index = {step.local_index: step for step in proposal.steps}
        for local_index in order:
            step = steps_by_index[local_index]
            dependencies = [
                local_to_node[dependency] for dependency in step.dependencies
            ]
            binding = self._plan_step_binding(step)
            candidate.add_node(
                planner_node_id=local_to_node[step.local_index],
                kind=step.kind,
                dependencies=dependencies,
                tool_name=binding.tool_name,
                arguments_sha256=binding.arguments_sha256,
                schema_version=binding.schema_version,
                resource_identity=binding.resource_identity,
            )

        frontier = [
            node.planner_node_id
            for node in candidate.nodes.values()
            if node.status == "PLANNED"
            and all(
                candidate.nodes[dependency].status == "COMPLETED"
                for dependency in node.dependencies
            )
        ]
        if len(frontier) != 1:
            raise PlanProposalError(
                "AMBIGUOUS_PLAN_FRONTIER: exactly one initial executable "
                "node is required"
            )
        candidate.activate(frontier[0])

        self._plan = candidate
        self._plan_persisted = True
        self._intent = None
        self._status = None
        self._next_step_id = None
        self._write()
        return {
            "proposal_id": proposal.proposal_id,
            "execution_id": self._execution_id,
            "plan_id": candidate.plan_id,
            "revision": candidate.revision,
            "active_node_id": candidate.active_node_id,
            "local_to_planner_node": dict(local_to_node),
            "plan": candidate.to_dict(),
        }

    def accept_replan(
        self,
        proposal: ReplanProposal,
        *,
        supported_tools: set[str] | None = None,
    ) -> dict[str, Any]:
        """Accept one narrow NOT_EXECUTED future-suffix replacement."""
        if not isinstance(proposal, ReplanProposal):
            raise PlanProposalError("REPLAN_PROPOSAL_REJECTED: invalid proposal type")
        if self._journal.pending(self._scope):
            raise ValueError("REPLAN_BLOCKED_RECONCILIATION_REQUIRED")
        if self._intent is None:
            raise ValueError("REPLAN_BLOCKED: no proven NOT_EXECUTED step")
        self.refresh()
        if self._status != "NOT_EXECUTED":
            if self._status in {
                "PREPARED",
                "EXECUTING",
                "EXECUTED",
                "UNKNOWN_OUTCOME",
            }:
                raise ValueError("REPLAN_BLOCKED_RECONCILIATION_REQUIRED")
            raise ValueError("REPLAN_BLOCKED: only NOT_EXECUTED is eligible")
        old = self._plan.node(self._intent.step_id)
        if old is None or old.status != "FAILED":
            raise ValueError("REPLAN_BLOCKED: NOT_EXECUTED node is not terminal")
        if any(
            node is not old and node.status not in {"COMPLETED", "SUPERSEDED"}
            for node in self._plan.nodes.values()
        ):
            raise PlanProposalError(
                "REPLAN_SHAPE_UNSUPPORTED: future suffix is complex"
            )
        order = self._validate_plan_proposal(proposal, supported_tools)
        steps_by_index = {step.local_index: step for step in proposal.steps}
        roots = [
            local_index
            for local_index in order
            if not steps_by_index[local_index].dependencies
        ]
        if len(roots) != 1 or steps_by_index[roots[0]].kind != "MUTATING":
            raise PlanProposalError(
                "REPLAN_SHAPE_UNSUPPORTED: exactly one mutating root is required"
            )

        local_to_node = {
            local_index: f"node-{uuid.uuid4().hex}" for local_index in order
        }
        self._plan.capture_current_revision()
        self._plan.mark_superseded(self._intent.step_id, local_to_node[roots[0]])
        for local_index in order:
            step = steps_by_index[local_index]
            dependencies = [
                local_to_node[dependency] for dependency in step.dependencies
            ]
            if not dependencies and local_index == roots[0]:
                dependencies = list(old.dependencies)
            binding = self._plan_step_binding(step)
            self._plan.add_node(
                planner_node_id=local_to_node[local_index],
                kind=step.kind,
                dependencies=dependencies,
                tool_name=binding.tool_name,
                arguments_sha256=binding.arguments_sha256,
                schema_version=binding.schema_version,
                resource_identity=binding.resource_identity,
            )
        self._plan.tool_binding_required = True
        self._plan.argument_binding_required = True
        self._plan.schema_binding_required = True
        self._plan.append_revision(
            reason="REPLAN", proposal_id=proposal.proposal_id
        )
        self._intent = None
        self._status = None
        self._next_step_id = local_to_node[roots[0]]
        self._write()
        return {
            "proposal_id": proposal.proposal_id,
            "execution_id": self._execution_id,
            "plan_id": self._plan.plan_id,
            "revision": self._plan.revision,
            "revision_id": self._plan.revision_id,
            "parent_revision_id": self._plan.parent_revision_id,
            "local_to_planner_node": local_to_node,
            "plan": self._plan.to_dict(),
        }

    def advance_materialized_step(self, planner_node_id: str) -> None:
        """Activate an existing node after verified controller progression."""
        if not isinstance(planner_node_id, str) or not planner_node_id.strip():
            raise ValueError("A materialized step needs a nonempty controller ID")
        if self._journal.pending(self._scope):
            raise ValueError("managed mutation requires reconciliation first")
        self.refresh()
        if self._intent is None or self._status != "VERIFIED":
            raise ValueError("verified completion is required before advancing")
        current = self._plan.node(self._intent.step_id)
        if current is None or current.status != "COMPLETED":
            raise ValueError("current managed node is not completed")
        if any(
            node.status == "RECONCILIATION_REQUIRED"
            for node in self._plan.nodes.values()
        ):
            raise ValueError("managed mutation requires reconciliation first")
        target = self._plan.node(planner_node_id)
        if target is None or target.status != "PLANNED":
            raise ValueError("materialized planner node is not available")
        if target.kind != "MUTATING":
            raise ValueError("materialized step is not a mutating node")
        self._plan.activate(planner_node_id)
        self._intent = None
        self._status = None
        self._next_step_id = planner_node_id
        self._write()

    def _sync_plan_state(self) -> None:
        if self._intent is None or self._status is None:
            return
        node = self._plan.node(self._intent.step_id)
        if node is None or node.mutation_intent_id != self._intent.mutation_intent_id:
            raise ValueError("planner and semantic intent identities disagree")
        self._plan.sync_semantic_status(self._intent.step_id, self._status)

    def advance_step(self, step_id: str) -> None:
        """Explicitly move to a controller-authorized distinct plan step."""
        if not isinstance(step_id, str) or not step_id.strip():
            raise ValueError("A new managed step needs a nonempty controller ID")
        self.refresh()
        if self._intent is not None:
            if self._status in {
                "PREPARED",
                "EXECUTING",
                "EXECUTED",
                "UNKNOWN_OUTCOME",
            }:
                raise ValueError("managed mutation requires reconciliation first")
        existing = self._plan.node(step_id)
        if existing is not None:
            if existing.status != "PLANNED":
                raise ValueError("managed planner node was already used")
        elif self._journal.semantic_step_exists(
            self._scope, self._execution_id, step_id
        ):
            raise ValueError("managed step ID was already used in this execution")
        else:
            self._plan.add_node(planner_node_id=step_id, kind="MUTATING")
        self._plan.activate(step_id)
        self._intent = None
        self._status = None
        self._next_step_id = step_id
        self._write()


def _checkpoint_messages(messages: list[Message]) -> list[dict[str, Any]]:
    """Serialize a restart transcript, invalidating process-local Windows IDs."""
    stored: list[dict[str, Any]] = []
    for message in messages:
        role = (
            message.role.value if isinstance(message.role, Role) else str(message.role)
        )
        if role == Role.SYSTEM.value:
            continue
        calls = []
        for call in message.tool_calls or []:
            calls.append(
                {
                    "id": call.id,
                    "name": call.name,
                    "arguments": "{}"
                    if call.name.startswith("windows_")
                    else call.arguments,
                }
            )
        content = message.content
        if calls or role == Role.ASSISTANT.value:
            # Model-private scratch text can contain cached target identities.
            content = ""
        elif role in {Role.TOOL.value, Role.USER.value} and (
            message.name or ""
        ).startswith("windows_"):
            safe_result: dict[str, Any] = {
                "restart_recovery": "prior Windows target and observation IDs expired"
            }
            try:
                raw = json.loads(content or "{}")
                if message.name == "windows_action" and isinstance(raw, dict):
                    safe_result.update(
                        {
                            key: raw[key]
                            for key in (
                                "outcome",
                                "failure",
                                "dispatch",
                                "verification",
                            )
                            if key in raw
                        }
                    )
            except (TypeError, ValueError):
                pass
            content = json.dumps(safe_result, sort_keys=True)
        stored.append(
            {
                "role": role,
                "content": content,
                "name": message.name,
                "tool_call_id": message.tool_call_id,
                "tool_calls": calls or None,
            }
        )
    return stored


def _restore_checkpoint_messages(raw_messages: Any) -> list[Message]:
    """Validate checkpointed conversation data and restore safe message types."""
    if not isinstance(raw_messages, list):
        raise ValueError("checkpoint messages must be a list")
    messages: list[Message] = []
    for raw in raw_messages:
        if not isinstance(raw, dict):
            raise ValueError("checkpoint message must be an object")
        role_value = raw.get("role")
        if role_value not in {Role.USER.value, Role.ASSISTANT.value, Role.TOOL.value}:
            raise ValueError("checkpoint message has an unsupported role")
        content = raw.get("content", "")
        if content is not None and not isinstance(content, str):
            raise ValueError("checkpoint message content must be text")
        if raw.get("name") is not None and not isinstance(raw.get("name"), str):
            raise ValueError("checkpoint message name must be text")
        if raw.get("tool_call_id") is not None and not isinstance(
            raw.get("tool_call_id"), str
        ):
            raise ValueError("checkpoint tool_call_id must be text")
        raw_calls = raw.get("tool_calls") or []
        if not isinstance(raw_calls, list):
            raise ValueError("checkpoint tool_calls must be a list")
        calls: list[ToolCall] = []
        for call in raw_calls:
            if not isinstance(call, dict) or not all(
                isinstance(call.get(key), str) for key in ("id", "name", "arguments")
            ):
                raise ValueError("checkpoint tool call is malformed")
            calls.append(ToolCall(call["id"], call["name"], call["arguments"]))
        message = Message(
            role=Role(role_value),
            content=content,
            name=raw.get("name"),
            tool_call_id=raw.get("tool_call_id"),
            tool_calls=calls or None,
        )
        # Re-serialize once to strip stale target identities in legacy/corrupt
        # conversation payloads before they reach the model after restart.
        safe = _checkpoint_messages([message])
        if safe[0] != raw:
            messages.extend(_restore_checkpoint_messages(safe))
        else:
            messages.append(message)
    return messages


def _should_retry_empty_result(result: AgentResult) -> bool:
    """Retry only a genuinely empty turn with no completed tool effects."""

    return not (result.content or "").strip() and not result.tool_results


def _resolve_tick_model(config: dict[str, Any], system: Any) -> str:
    """Resolve a managed tick model without hiding the system default."""

    return (
        config.get("model")
        or (getattr(system, "model", "") if system is not None else "")
        or _AGENT_TICK_DEFAULT_MODEL
    )


def _available_tick_models(engine: Any, resolved_model: str) -> list[str]:
    """Return every model the active engine can actually route to.

    Keep the resolved default first when the engine confirms it is available,
    preserving the existing fallback behavior. Some remote engines cannot list
    models, so retain the resolved model as a last-resort singleton when model
    discovery fails or returns no usable identifiers.
    """

    try:
        listed = engine.list_models()
    except Exception as exc:
        logger.warning("Could not list models for managed-agent routing: %s", exc)
        return [resolved_model] if resolved_model else []

    candidates = [listed] if isinstance(listed, str) else listed or []
    available: list[str] = []
    for candidate in candidates:
        normalized = candidate.strip() if isinstance(candidate, str) else ""
        if normalized and normalized not in available:
            available.append(normalized)

    if not available:
        return [resolved_model] if resolved_model else []
    if resolved_model in available:
        available.remove(resolved_model)
        available.insert(0, resolved_model)
    return available


def _tool_calls_for_storage(result: AgentResult) -> list[dict[str, Any]] | None:
    """Convert executor tool results to the managed-message storage contract."""

    calls: list[dict[str, Any]] = []
    for tool_result in result.tool_results:
        metadata = getattr(tool_result, "metadata", {}) or {}
        arguments = metadata.get("arguments", "")
        if not isinstance(arguments, str):
            try:
                arguments = json.dumps(arguments, sort_keys=True)
            except (TypeError, ValueError):
                arguments = json.dumps(str(arguments))
        calls.append(
            {
                "tool": getattr(tool_result, "tool_name", ""),
                "arguments": arguments,
                "result": getattr(tool_result, "content", "") or "",
                "success": bool(getattr(tool_result, "success", False)),
                # SSE and the frontend persist/display latency in milliseconds.
                "latency": float(getattr(tool_result, "latency_seconds", 0.0) or 0.0)
                * 1000.0,
            }
        )
    return calls or None


def _artifact_inventory(tool_state: dict[str, Any]) -> list[dict[str, Any]]:
    """Bind persisted file references to the tool call that produced them."""
    inventory = []
    for step in tool_state.get("completed_steps", []):
        if not isinstance(step, dict):
            continue
        for artifact in step.get("artifacts", []):
            if is_artifact_reference(artifact):
                inventory.append(
                    {
                        "tool": step.get("tool", ""),
                        "call_id": step.get("call_id", ""),
                        **artifact,
                    }
                )
    return inventory[-64:]


class AgentExecutor:
    """Executes a single tick for a managed agent.

    Constructor receives a JarvisSystem reference for access to engine,
    tools, config, memory backends, and all other primitives.
    """

    def __init__(
        self,
        manager: AgentManager,
        event_bus: EventBus,
        system: Any = None,
        trace_store: Any = None,
    ) -> None:
        self._system = system
        self._manager = manager
        self._bus = event_bus
        self._trace_store = trace_store
        self._toolkit_local = threading.local()

    def set_system(self, system: Any) -> None:
        """Deferred system injection — called after JarvisSystem is constructed."""
        self._system = system

    def _authorization_check_for(self, agent_id: str) -> Any:
        policy = getattr(self._system, "capability_policy", None)
        if policy is None:
            return None

        def check(capability: str, tool_name: str) -> bool:
            allowed = policy.check(agent_id, capability, tool_name)
            if not allowed:
                self._bus.publish(
                    EventType.CAPABILITY_DENIED,
                    {
                        "agent_id": agent_id,
                        "capability": capability,
                        "tool": tool_name,
                    },
                )
            return allowed

        return check

    def plan_goal(
        self,
        agent_id: str,
        planner: Any,
        goal: str,
        *,
        context: Any = None,
        supported_tools: set[str] | None = None,
        model_gate: Any = None,
    ) -> dict[str, Any]:
        """Request one untrusted plan and materialize it through the controller.

        A persisted plan is returned without calling the model again. The
        planner object can propose structure only; it cannot supply trusted
        identities or execute a tool. ``model_gate`` is an optional
        host-owned zero-arg callable (e.g. a capability-router gate)
        invoked after the contract preconditions and before any model
        contact; when it raises, planning stops with no model call and
        no checkpoint mutation.
        """
        if self._manager.cancellation_state(agent_id) is not None:
            raise ValueError("Cancelled managed execution cannot plan")
        if self._manager.execution_journal.pending(agent_id):
            raise ValueError("Mutation reconciliation is required before planning")
        checkpoint = self._manager.get_latest_checkpoint(agent_id)
        if checkpoint is None:
            raise ValueError("A plan needs an existing checkpoint")
        conversation = checkpoint.get("conversation_state") or {}
        deadline_at = conversation.get("deadline_at")
        if isinstance(deadline_at, (int, float)) and deadline_at <= time.time():
            raise ValueError("Deadline has terminated managed planning")
        existing = (checkpoint.get("tool_state") or {}).get("durable_plan")
        if isinstance(existing, dict) and existing.get("nodes"):
            return {
                "execution_id": existing.get("execution_id"),
                "plan_id": existing.get("plan_id"),
                "revision": existing.get("revision"),
                "active_node_id": existing.get("active_node_id"),
                "plan": existing,
                "reused": True,
            }
        if model_gate is not None:
            model_gate()
        proposal = planner.propose(goal, context)
        return self.materialize_plan_proposal(
            agent_id,
            proposal,
            supported_tools=supported_tools,
        )

    def replan_goal(
        self,
        agent_id: str,
        replanner: Any,
        goal: str,
        *,
        context: Any = None,
        supported_tools: set[str] | None = None,
        model_gate: Any = None,
    ) -> dict[str, Any]:
        """Request one model replan only after a proven NOT_EXECUTED outcome."""
        if self._manager.cancellation_state(agent_id) is not None:
            raise ValueError("Cancelled managed execution cannot replan")
        if self._manager.execution_journal.pending(agent_id):
            raise ValueError("REPLAN_BLOCKED_RECONCILIATION_REQUIRED")
        checkpoint = self._manager.get_latest_checkpoint(agent_id)
        if checkpoint is None:
            raise ValueError("A replan needs an existing checkpoint")
        conversation = checkpoint.get("conversation_state") or {}
        deadline_at = conversation.get("deadline_at")
        if isinstance(deadline_at, (int, float)) and deadline_at <= time.time():
            raise ValueError("Deadline has terminated managed replanning")
        runtime = {"tool_state": dict(checkpoint.get("tool_state") or {})}
        controller = _ManagedMutationController(
            self._manager.execution_journal,
            agent_id,
            runtime,
        )
        controller.refresh()
        if controller._intent is None:
            raise ValueError("REPLAN_BLOCKED: no proven NOT_EXECUTED step")
        if controller._status != "NOT_EXECUTED":
            if controller._status in {
                "PREPARED",
                "EXECUTING",
                "EXECUTED",
                "UNKNOWN_OUTCOME",
            }:
                raise ValueError("REPLAN_BLOCKED_RECONCILIATION_REQUIRED")
            raise ValueError("REPLAN_BLOCKED: only NOT_EXECUTED is eligible")
        if model_gate is not None:
            model_gate()
        proposal = replanner.propose(goal, context)
        return self.accept_replan_proposal(
            agent_id,
            proposal,
            supported_tools=supported_tools,
        )

    def create_plan_node(
        self,
        agent_id: str,
        *,
        kind: str = "MUTATING",
        planner_node_id: str | None = None,
        dependencies: list[str] | None = None,
    ) -> dict[str, Any]:
        """Persist one controller-materialized plan node.

        This control-plane API is intentionally separate from model/tool
        messages; callers must already own the managed agent lifecycle.
        """
        if self._manager.cancellation_state(agent_id) is not None:
            raise ValueError("Cancelled managed execution cannot create a plan node")
        if self._manager.execution_journal.pending(agent_id):
            raise ValueError("Mutation reconciliation is required before planning")
        checkpoint = self._manager.get_latest_checkpoint(agent_id)
        if checkpoint is None:
            raise ValueError("A plan node needs an existing checkpoint")
        runtime = {"tool_state": dict(checkpoint.get("tool_state") or {})}
        controller = _ManagedMutationController(
            self._manager.execution_journal,
            agent_id,
            runtime,
        )
        node = controller.create_plan_node(
            kind=kind,
            planner_node_id=planner_node_id,
            dependencies=dependencies,
        )
        conversation = dict(checkpoint["conversation_state"])
        conversation.update(
            {"lifecycle": "RUNNING", "resumable": True, "resume_authorized": True}
        )
        tool_state = dict(runtime["tool_state"])
        self._manager.save_checkpoint(
            agent_id, checkpoint["tick_id"], conversation, tool_state
        )
        self._manager.recover_agent(agent_id)
        return {
            "execution_id": tool_state["execution_id"],
            "plan_id": tool_state["plan_id"],
            **node,
        }

    def materialize_plan_proposal(
        self,
        agent_id: str,
        proposal: PlanProposal,
        *,
        supported_tools: set[str] | None = None,
    ) -> dict[str, Any]:
        """Persist a controller-materialized plan from an untrusted proposal."""
        if self._manager.cancellation_state(agent_id) is not None:
            raise ValueError("Cancelled managed execution cannot materialize a plan")
        if self._manager.execution_journal.pending(agent_id):
            raise ValueError("Mutation reconciliation is required before planning")
        checkpoint = self._manager.get_latest_checkpoint(agent_id)
        if checkpoint is None:
            raise ValueError("A plan needs an existing checkpoint")
        runtime = {"tool_state": dict(checkpoint.get("tool_state") or {})}
        controller = _ManagedMutationController(
            self._manager.execution_journal,
            agent_id,
            runtime,
            authorization_check=self._authorization_check_for(agent_id),
            strict_schema=True,
        )
        materialized = controller.materialize_plan(
            proposal,
            supported_tools=supported_tools,
        )
        conversation = dict(checkpoint["conversation_state"])
        conversation.update(
            {"lifecycle": "RUNNING", "resumable": True, "resume_authorized": True}
        )
        tool_state = dict(runtime["tool_state"])
        self._manager.save_checkpoint(
            agent_id, checkpoint["tick_id"], conversation, tool_state
        )
        self._manager.recover_agent(agent_id)
        return materialized

    def accept_replan_proposal(
        self,
        agent_id: str,
        proposal: ReplanProposal,
        *,
        supported_tools: set[str] | None = None,
    ) -> dict[str, Any]:
        """Persist a controller-approved NOT_EXECUTED future revision."""
        if self._manager.cancellation_state(agent_id) is not None:
            raise ValueError("Cancelled managed execution cannot accept a replan")
        if self._manager.execution_journal.pending(agent_id):
            raise ValueError("REPLAN_BLOCKED_RECONCILIATION_REQUIRED")
        checkpoint = self._manager.get_latest_checkpoint(agent_id)
        if checkpoint is None:
            raise ValueError("A replan needs an existing checkpoint")
        conversation = checkpoint.get("conversation_state") or {}
        deadline_at = conversation.get("deadline_at")
        if isinstance(deadline_at, (int, float)) and deadline_at <= time.time():
            raise ValueError("Deadline has terminated managed replanning")
        runtime = {"tool_state": dict(checkpoint.get("tool_state") or {})}
        controller = _ManagedMutationController(
            self._manager.execution_journal,
            agent_id,
            runtime,
            authorization_check=self._authorization_check_for(agent_id),
            strict_schema=True,
        )
        accepted = controller.accept_replan(
            proposal,
            supported_tools=supported_tools,
        )
        conversation = dict(checkpoint["conversation_state"])
        conversation.update(
            {"lifecycle": "RUNNING", "resumable": True, "resume_authorized": True}
        )
        self._manager.save_checkpoint(
            agent_id,
            checkpoint["tick_id"],
            conversation,
            runtime["tool_state"],
        )
        self._manager.recover_agent(agent_id)
        return accepted

    def advance_materialized_plan_node(
        self, agent_id: str, *, planner_node_id: str
    ) -> dict[str, Any]:
        """Activate an existing plan node after trusted completion evaluation."""
        if self._manager.cancellation_state(agent_id) is not None:
            raise ValueError("Cancelled managed execution cannot advance a step")
        if self._manager.execution_journal.pending(agent_id):
            raise ValueError("Mutation reconciliation is required before advancing")
        checkpoint = self._manager.get_latest_checkpoint(agent_id)
        if checkpoint is None:
            raise ValueError("A managed plan step needs an existing checkpoint")
        runtime = {"tool_state": dict(checkpoint.get("tool_state") or {})}
        controller = _ManagedMutationController(
            self._manager.execution_journal,
            agent_id,
            runtime,
        )
        controller.advance_materialized_step(planner_node_id)
        conversation = dict(checkpoint["conversation_state"])
        conversation.update(
            {"lifecycle": "RUNNING", "resumable": True, "resume_authorized": True}
        )
        tool_state = dict(runtime["tool_state"])
        tool_state["active_step"] = {"state": "NOT_STARTED"}
        self._manager.save_checkpoint(
            agent_id, checkpoint["tick_id"], conversation, tool_state
        )
        self._manager.recover_agent(agent_id)
        return {
            "execution_id": tool_state["execution_id"],
            "plan_id": tool_state["plan_id"],
            "planner_node_id": planner_node_id,
            "plan": tool_state["durable_plan"],
        }

    def advance_plan_step(self, agent_id: str, *, step_id: str | None = None) -> dict:
        """Authorize one distinct managed step after a safe checkpoint boundary.

        This is a controller API. Models and tool arguments cannot call it.
        """
        if step_id is None:
            step_id = f"step-{uuid.uuid4().hex}"
        if self._manager.cancellation_state(agent_id) is not None:
            raise ValueError("Cancelled managed execution cannot advance a step")
        if self._manager.execution_journal.pending(agent_id):
            raise ValueError("Mutation reconciliation is required before advancing")
        checkpoint = self._manager.get_latest_checkpoint(agent_id)
        if checkpoint is None:
            raise ValueError("A managed plan step needs an existing checkpoint")
        runtime = {"tool_state": dict(checkpoint.get("tool_state") or {})}
        controller = _ManagedMutationController(
            self._manager.execution_journal,
            agent_id,
            runtime,
        )
        controller.advance_step(step_id)
        conversation = dict(checkpoint["conversation_state"])
        conversation.update(
            {
                "lifecycle": "RUNNING",
                "resumable": True,
                "resume_authorized": True,
            }
        )
        tool_state = dict(runtime["tool_state"])
        tool_state["active_step"] = {"state": "NOT_STARTED"}
        self._manager.save_checkpoint(
            agent_id, checkpoint["tick_id"], conversation, tool_state
        )
        self._manager.recover_agent(agent_id)
        snapshot = controller.snapshot() or {
            "execution_id": tool_state["execution_id"],
            "step_id": step_id,
            "status": "NOT_STARTED",
        }
        return {
            **snapshot,
            "plan_id": tool_state["plan_id"],
            "planner_node_id": step_id,
        }

    def verify_goal_acceptance(
        self,
        agent_id: str,
        *,
        expected_artifacts: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Verify final artifacts and durable plan completion independently."""
        checkpoint = self._manager.get_latest_checkpoint(agent_id)
        if checkpoint is None:
            result = GoalVerification(
                "VERIFICATION_UNAVAILABLE",
                reason="no checkpoint is available",
            )
            return result.to_dict()
        tool_state = dict(checkpoint.get("tool_state") or {})
        if expected_artifacts is None:
            expected_artifacts = []
            for step in tool_state.get("completed_steps", []):
                if not isinstance(step, dict):
                    continue
                expected_artifacts.extend(
                    item
                    for item in step.get("artifacts", [])
                    if is_artifact_reference(item)
                )
        result = verify_goal_artifacts(expected_artifacts)
        durable_plan = tool_state.get("durable_plan")
        if not isinstance(durable_plan, dict):
            result = GoalVerification(
                "VERIFICATION_UNAVAILABLE",
                evidence=result.evidence,
                reason="durable plan is unavailable",
            )
        else:
            try:
                plan = DurablePlan.from_dict(durable_plan)
            except ValueError:
                result = GoalVerification(
                    "VERIFICATION_UNAVAILABLE",
                    evidence=result.evidence,
                    reason="durable plan is structurally invalid",
                )
            else:
                if plan.execution_id != tool_state.get("execution_id"):
                    result = GoalVerification(
                        "VERIFICATION_UNAVAILABLE",
                        evidence=result.evidence,
                        reason="durable plan execution identity disagrees",
                    )
                elif plan.status != "COMPLETED" and result.status == "VERIFIED":
                    result = GoalVerification(
                        "PARTIAL",
                        evidence=result.evidence,
                        reason=(
                            "artifacts are current but the durable plan is incomplete"
                        ),
                    )
        tool_state["goal_acceptance"] = result.to_dict()
        self._manager.save_checkpoint(
            agent_id,
            checkpoint["tick_id"],
            checkpoint["conversation_state"],
            tool_state,
        )
        return result.to_dict()

    def _set_activity(self, agent_id: str, activity: str) -> None:
        """Update the agent's current_activity for progress visibility."""
        try:
            self._manager.update_agent(agent_id, current_activity=activity)
        except Exception:
            pass  # Non-critical

    def _terminalize_cancellation(
        self,
        agent_id: str,
        runtime: dict[str, Any],
        *,
        result: AgentResult | None = None,
        duration: float = 0.0,
    ) -> None:
        """Checkpoint a cooperative stop after all in-flight work is safe."""
        cancellation = self._manager.cancellation_state(agent_id)
        if cancellation is None:
            return
        self._manager.advance_cancellation(agent_id, "ACKNOWLEDGED")
        cancellation = self._manager.advance_cancellation(
            agent_id, "SAFE_BOUNDARY_REACHED"
        ) or cancellation
        tool_state = dict(runtime.get("tool_state") or {})
        tool_state["cancellation"] = cancellation
        history = list(tool_state.get("retry_history", []))
        if history and history[-1].get("state") == "RUNNING":
            history[-1]["state"] = (
                "TIMED_OUT" if cancellation.get("reason") == "deadline" else "CANCELLED"
            )
            if cancellation.get("timeout_kind"):
                history[-1]["timeout_kind"] = cancellation["timeout_kind"]
            tool_state["retry_history"] = history
        lifecycle = (
            "TIMED_OUT"
            if cancellation.get("reason") in {"deadline", "timeout"}
            else "CANCELLED"
        )
        try:
            self._persist_tick_state(
                runtime,
                runtime.get("resume_messages", []),
                tool_state,
                lifecycle=lifecycle,
                result=result,
            )
            cancellation = self._manager.advance_cancellation(
                agent_id, "TERMINALIZED"
            ) or cancellation
            runtime["tool_state"]["cancellation"] = cancellation
            self._manager.end_tick(agent_id)
            self._manager.update_agent(
                agent_id,
                status=(
                    "archived" if cancellation.get("reason") == "archive" else "paused"
                ),
            )
            self._bus.publish(
                EventType.AGENT_TICK_END,
                {
                    "agent_id": agent_id,
                    "status": lifecycle.lower(),
                    "duration": duration,
                },
            )
        except Exception:
            logger.exception("Could not terminalize cancellation for %s", agent_id)
            self._manager.end_tick(agent_id)
            self._manager.update_agent(agent_id, status="needs_attention")

    def _request_deadline_cancellation(self, agent_id: str) -> None:
        try:
            self._manager.request_cancellation(
                agent_id,
                reason="deadline",
                timeout_kind="overall_task_deadline",
            )
        except ValueError:
            # Completion may have atomically won the race with the timer.
            pass
        except Exception:
            logger.exception("Could not persist deadline cancellation for %s", agent_id)

    def _persist_tick_state(
        self,
        runtime: dict[str, Any],
        messages: list[Message],
        tool_state: dict[str, Any],
        *,
        lifecycle: str = "RUNNING",
        result: AgentResult | None = None,
        error: AgentTickError | None = None,
    ) -> None:
        tick_id = runtime["tick_id"]
        conversation_state = {
            "schema_version": _CHECKPOINT_SCHEMA_VERSION,
            "tick_id": tick_id,
            "lifecycle": lifecycle,
            "resumable": bool(runtime.get("resumable", False)),
            "messages": _checkpoint_messages(messages),
        }
        if runtime.get("deadline_at") is not None:
            conversation_state["deadline_at"] = runtime["deadline_at"]
        cancellation = self._manager.cancellation_state(runtime["agent_id"])
        if cancellation is not None:
            tool_state = {**tool_state, "cancellation": cancellation}
        if result is not None:
            conversation_state["result"] = result.content
        if error is not None:
            conversation_state["failure"] = str(error)[:2000]
        persisted_tool_state = {
            "schema_version": _CHECKPOINT_SCHEMA_VERSION,
            **tool_state,
        }
        saved = self._manager.save_checkpoint(
            runtime["agent_id"], tick_id, conversation_state, persisted_tool_state
        )
        runtime["conversation_state"] = conversation_state
        runtime["tool_state"] = persisted_tool_state
        runtime["checkpoint_id"] = saved["id"]
        runtime["resume_messages"] = _restore_checkpoint_messages(
            conversation_state["messages"]
        )
        runtime["has_progress"] = bool(conversation_state["messages"])

    @staticmethod
    def _validate_checkpoint(
        checkpoint: dict[str, Any], agent_id: str
    ) -> list[Message]:
        conversation = checkpoint.get("conversation_state")
        tool_state = checkpoint.get("tool_state")
        tick_id = checkpoint.get("tick_id")
        if not isinstance(tick_id, str) or not tick_id:
            raise ValueError("checkpoint tick_id is missing")
        if checkpoint.get("agent_id") != agent_id:
            raise ValueError("checkpoint belongs to a different agent")
        if not isinstance(conversation, dict) or not isinstance(tool_state, dict):
            raise ValueError("checkpoint state is malformed")
        if conversation.get("schema_version") != _CHECKPOINT_SCHEMA_VERSION:
            raise ValueError("unsupported checkpoint conversation schema")
        if tool_state.get("schema_version") != _CHECKPOINT_SCHEMA_VERSION:
            raise ValueError("unsupported checkpoint tool schema")
        if conversation.get("tick_id") != tick_id:
            raise ValueError("checkpoint tick identifiers disagree")
        if conversation.get("lifecycle") not in {
            "RUNNING",
            "COMPLETED",
            "FAILED",
            "RECOVERY_REQUIRED",
            "CANCELLED",
            "TIMED_OUT",
        }:
            raise ValueError("checkpoint lifecycle is invalid")
        deadline_at = conversation.get("deadline_at")
        if deadline_at is not None and (
            type(deadline_at) not in {int, float} or deadline_at <= 0
        ):
            raise ValueError("checkpoint overall deadline is invalid")
        active = tool_state.get("active_step")
        completed = tool_state.get("completed_steps")
        if (
            not isinstance(active, dict)
            or active.get("state") not in _CHECKPOINT_STEP_STATES
        ):
            raise ValueError("checkpoint active step is invalid")
        if not isinstance(completed, list) or any(
            not isinstance(step, dict)
            or step.get("state") not in _CHECKPOINT_STEP_STATES
            for step in completed
        ):
            raise ValueError("checkpoint completed steps are invalid")
        for step in [active, *completed]:
            artifacts = step.get("artifacts", [])
            if not valid_artifact_references(artifacts):
                raise ValueError("checkpoint artifact references are invalid")
            if artifacts and not all(
                isinstance(step.get(key), str) and step[key]
                for key in ("tool", "call_id")
            ):
                raise ValueError("checkpoint artifact provenance is invalid")
        if not isinstance(tool_state.get("recovery_history", []), list):
            raise ValueError("checkpoint recovery history is invalid")
        retry_count = tool_state.get("retry_count", 0)
        retry_history = tool_state.get("retry_history", [])
        if type(retry_count) is not int or not 0 <= retry_count <= _MAX_RETRIES:
            raise ValueError("checkpoint retry count is invalid")
        if (
            not isinstance(retry_history, list)
            or len(retry_history) != retry_count
            or any(
                not isinstance(attempt, dict)
                or attempt.get("attempt") != index + 1
                or attempt.get("state")
                not in {
                    "RUNNING",
                    "FAILED",
                    "SUCCEEDED",
                    "RECOVERY_REQUIRED",
                    "CANCELLED",
                    "TIMED_OUT",
                }
                for index, attempt in enumerate(retry_history)
            )
        ):
            raise ValueError("checkpoint retry history is invalid")
        messages = _restore_checkpoint_messages(conversation.get("messages"))
        if active.get("state") in {"EXECUTED", "VERIFIED", "FAILED"}:
            call_id = active.get("call_id")
            if not isinstance(call_id, str) or not any(
                step.get("call_id") == call_id for step in completed
            ):
                raise ValueError("checkpoint active result is missing from its journal")
            if not any(
                message.tool_call_id == call_id
                and (
                    message.role == Role.TOOL
                    or (
                        message.role == Role.USER and message.name == active.get("tool")
                    )
                )
                for message in messages
            ):
                raise ValueError("checkpoint result message is missing")
        return messages

    def _validate_managed_semantics(
        self, checkpoint: dict[str, Any], agent_id: str
    ) -> None:
        """Validate checkpoint semantic references against the authoritative journal."""
        tool_state = checkpoint["tool_state"]
        execution_id = tool_state.get("execution_id")
        semantic = tool_state.get("semantic_step")
        durable_plan = tool_state.get("durable_plan")
        plan = None
        if durable_plan is not None:
            plan = DurablePlan.from_dict(durable_plan)
            if execution_id != plan.execution_id:
                raise ValueError("durable plan execution identity disagrees")
            revision_id = tool_state.get("revision_id")
            if revision_id is not None and revision_id != plan.revision_id:
                raise ValueError("checkpoint and durable plan revision disagrees")
            if plan.active_node_id is not None:
                active_node = plan.node(plan.active_node_id)
                if active_node is None or active_node.status != "ACTIVE":
                    raise ValueError("durable plan active node is invalid")
            for node in plan.nodes.values():
                active_placeholder = (
                    node.planner_node_id == plan.active_node_id
                    and node.status == "ACTIVE"
                    and node.mutation_intent_id is None
                )
                if (
                    plan.tool_binding_required
                    and not node.tool_name
                    and not active_placeholder
                ):
                    raise ValueError("planner node is missing trusted tool binding")
                if (
                    plan.argument_binding_required
                    and not node.arguments_sha256
                    and not active_placeholder
                ):
                    raise ValueError("planner node is missing argument binding")
                if (
                    plan.schema_binding_required
                    and node.schema_version is None
                    and not active_placeholder
                ):
                    raise ValueError("planner node is missing schema binding")
                if node.mutation_intent_id is None:
                    continue
                intent = MutationIntent(
                    plan.execution_id,
                    node.planner_node_id,
                    node.mutation_intent_id,
                    node.arguments_sha256
                    if plan.argument_binding_required
                    else None,
                )
                row = self._manager.execution_journal.semantic_intent(
                    agent_id, intent
                )
                if row is None:
                    raise ValueError("planner node is absent from the semantic journal")
                if node.status == "COMPLETED" and row["status"] != "VERIFIED":
                    raise ValueError("completed planner node disagrees with journal")
        if semantic is not None:
            if not isinstance(execution_id, str) or not execution_id:
                raise ValueError("managed semantic execution identity is missing")
            if not isinstance(semantic, dict):
                raise ValueError("managed semantic step is malformed")
            intent = MutationIntent(
                semantic.get("execution_id", ""),
                semantic.get("step_id", ""),
                semantic.get("mutation_intent_id", ""),
                semantic.get("arguments_sha256"),
            )
            if intent.execution_id != execution_id:
                raise ValueError("managed semantic execution identity disagrees")
            if semantic.get("status") not in _SEMANTIC_STEP_STATES:
                raise ValueError("managed semantic step state is invalid")
            row = self._manager.execution_journal.semantic_intent(
                agent_id, intent
            )
            if row is None or not semantic_status_can_advance(
                semantic["status"], row["status"]
            ):
                raise ValueError("managed checkpoint and semantic journal disagree")
            if plan is not None:
                node = plan.node(intent.step_id)
                if node is None or node.mutation_intent_id != intent.mutation_intent_id:
                    raise ValueError("planner and semantic identities disagree")

        for step in [tool_state.get("active_step"), *tool_state["completed_steps"]]:
            if not isinstance(step, dict):
                continue
            keys = ("execution_id", "step_id", "mutation_intent_id")
            present = [key in step for key in keys]
            if not any(present):
                continue
            if not all(
                isinstance(step.get(key), str) and step[key] for key in keys
            ):
                raise ValueError("managed step identity is incomplete")
            intent = MutationIntent(
                step["execution_id"],
                step["step_id"],
                step["mutation_intent_id"],
                step.get("arguments_sha256"),
            )
            if execution_id is not None and intent.execution_id != execution_id:
                raise ValueError("managed step execution identity disagrees")
            row = self._manager.execution_journal.semantic_intent(agent_id, intent)
            if row is None:
                raise ValueError("managed step is absent from the semantic journal")
            semantic_status = step.get("semantic_status")
            if semantic_status is not None and (
                semantic_status not in _SEMANTIC_STEP_STATES
                or not semantic_status_can_advance(semantic_status, row["status"])
            ):
                raise ValueError("managed step semantic status disagrees with journal")
            if (
                step.get("execution_state") == "VERIFIED"
                and row["status"] != "VERIFIED"
            ):
                raise ValueError("verified managed step disagrees with the journal")

    def _require_recovery(
        self,
        agent_id: str,
        reason: str,
        checkpoint: dict[str, Any] | None = None,
    ) -> None:
        if checkpoint is None:
            try:
                checkpoint = self._manager.get_latest_checkpoint(agent_id)
            except Exception:
                checkpoint = None
        tick_id = (
            checkpoint.get("tick_id")
            if isinstance(checkpoint, dict)
            and isinstance(checkpoint.get("tick_id"), str)
            else uuid.uuid4().hex
        )
        active = {"state": "UNKNOWN_OUTCOME"}
        completed: list[dict[str, Any]] = []
        messages: list[Message] = []
        resumable = False
        old_state = checkpoint.get("tool_state") if checkpoint else None
        old_conversation = checkpoint.get("conversation_state") if checkpoint else None
        if isinstance(old_state, dict):
            if isinstance(old_state.get("active_step"), dict):
                active = dict(old_state["active_step"])
            if isinstance(old_state.get("completed_steps"), list):
                completed = old_state["completed_steps"]
        if isinstance(old_conversation, dict):
            try:
                messages = _restore_checkpoint_messages(
                    old_conversation.get("messages")
                )
                resumable = old_conversation.get("resumable") is True
            except Exception:
                messages = []
                resumable = False
        recovery_conversation = {
            "schema_version": _CHECKPOINT_SCHEMA_VERSION,
            "tick_id": tick_id,
            "lifecycle": "RECOVERY_REQUIRED",
            "resumable": resumable,
            "messages": _checkpoint_messages(messages),
            "failure": reason[:2000],
        }
        if isinstance(old_conversation, dict) and old_conversation.get(
            "deadline_at"
        ) is not None:
            recovery_conversation["deadline_at"] = old_conversation["deadline_at"]
        cancellation = self._manager.cancellation_state(agent_id)
        if cancellation is not None:
            old_state = {
                **(old_state if isinstance(old_state, dict) else {}),
                "cancellation": cancellation,
            }
        try:
            self._manager.save_checkpoint(
                agent_id,
                tick_id,
                recovery_conversation,
                {
                    "schema_version": _CHECKPOINT_SCHEMA_VERSION,
                    "active_step": active,
                    "completed_steps": completed,
                    **{
                        key: old_state[key]
                        for key in (
                            "execution_id",
                            "plan_id",
                            "durable_plan",
                            "semantic_step",
                            "next_step_id",
                            "recovery_history",
                            "retry_count",
                            "retry_history",
                            "retry_terminal",
                            "cancellation",
                        )
                        if isinstance(old_state, dict) and key in old_state
                    },
                    "recovery": {
                        "required": True,
                        "requires_user": True,
                        "reason": reason[:2000],
                        "call_id": active.get("call_id"),
                        "tool": active.get("tool"),
                    },
                },
            )
        except Exception:
            logger.exception("Could not persist recovery state for agent %s", agent_id)
        self._manager.end_tick(agent_id)
        self._manager.update_agent(agent_id, status="needs_attention")
        try:
            self._manager.update_summary_memory(
                agent_id, f"RECOVERY REQUIRED: {reason[:1800]}"
            )
        except Exception:
            logger.exception("Could not update recovery summary for agent %s", agent_id)

    def _resume_runtime(
        self, agent_id: str
    ) -> tuple[dict[str, Any] | None, str | None, bool]:
        """Restore an interrupted tick without inferring dispatch from failure."""
        candidate = self._manager.is_restart_candidate(agent_id)
        try:
            checkpoint = self._manager.get_latest_checkpoint(agent_id)
        except Exception as exc:
            return None, f"checkpoint could not be decoded: {exc}", candidate

        pending = self._manager.execution_journal.pending(agent_id)
        if checkpoint is None:
            if candidate or pending:
                return None, "interrupted agent has no valid checkpoint", candidate
            return None, None, False

        conversation = checkpoint.get("conversation_state")
        if not isinstance(conversation, dict) or "schema_version" not in conversation:
            if candidate or pending:
                return (
                    None,
                    "interrupted agent has a legacy/unstructured checkpoint",
                    candidate,
                )
            return None, None, False
        try:
            messages = self._validate_checkpoint(checkpoint, agent_id)
            if checkpoint["conversation_state"].get("lifecycle") != (
                "RECOVERY_REQUIRED"
            ):
                self._validate_managed_semantics(checkpoint, agent_id)
        except Exception as exc:
            return None, f"checkpoint validation failed: {exc}", candidate

        lifecycle = conversation["lifecycle"]
        explicit_recovery = self._manager.is_recovery_requested(agent_id)
        if lifecycle == "RECOVERY_REQUIRED":
            if not candidate or not explicit_recovery:
                return (
                    None,
                    "checkpoint requires explicit recovery after reconciliation",
                    candidate,
                )
            if conversation.get("resumable") is not True:
                return None, "recovery checkpoint has no restorable conversation", True
            if pending:
                return (
                    None,
                    "mutation quarantine must be reconciled before resume",
                    True,
                )
            tool_state = checkpoint["tool_state"]
            active = dict(tool_state["active_step"])
            call_id, tool_name = active.get("call_id"), active.get("tool")
            if not isinstance(call_id, str) or not isinstance(tool_name, str):
                return None, "recovery checkpoint has no exact action identity", True
            resolution = self._manager.execution_journal.reconciliation(
                agent_id, tool_name, call_id
            )
            if resolution is None:
                return None, "exact action has no trusted reconciliation record", True
            recovery_history = list(tool_state.get("recovery_history", []))
            recovery_history.append(
                {
                    "event": "RECONCILED",
                    "call_id": call_id,
                    "tool": tool_name,
                    "resolution": resolution["resolution"],
                }
            )
            if resolution["resolution"] == "VERIFIED":
                active.update(state="VERIFIED", execution_state="VERIFIED")
                semantic_step = dict(tool_state.get("semantic_step") or {})
                if semantic_step:
                    semantic_step["status"] = "VERIFIED"
                    tool_state["semantic_step"] = semantic_step
                    if tool_state.get("durable_plan") is not None:
                        try:
                            plan = DurablePlan.from_dict(tool_state["durable_plan"])
                            plan.sync_semantic_status(
                                semantic_step["step_id"], "VERIFIED"
                            )
                            tool_state["durable_plan"] = plan.to_dict()
                        except Exception as exc:
                            return (
                                None,
                                f"planner reconciliation state is invalid: {exc}",
                                True,
                            )
                matching = False
                for message in reversed(messages):
                    if message.tool_call_id == call_id:
                        message.content = json.dumps(
                            {
                                "outcome": "VERIFIED",
                                "reconciled": True,
                                "restart_recovery": "target identities expired",
                            },
                            sort_keys=True,
                        )
                        matching = True
                        break
                if not matching:
                    messages.extend(
                        [
                            Message(
                                role=Role.ASSISTANT,
                                content="",
                                tool_calls=[ToolCall(call_id, tool_name, "{}")],
                            ),
                            Message(
                                role=Role.TOOL,
                                content=json.dumps(
                                    {"outcome": "VERIFIED", "reconciled": True}
                                ),
                                tool_call_id=call_id,
                                name=tool_name,
                            ),
                        ]
                    )
                completed = list(tool_state.get("completed_steps", []))
                completed = [
                    step for step in completed if step.get("call_id") != call_id
                ]
                completed.append(dict(active))
                tool_state = {**tool_state, "completed_steps": completed}
            elif resolution["resolution"] == "NOT_EXECUTED":
                messages = [
                    message
                    for message in messages
                    if message.tool_call_id != call_id
                    and not any(
                        call.id == call_id for call in (message.tool_calls or [])
                    )
                ]
                messages.append(
                    Message(
                        role=Role.USER,
                        content=(
                            f"Interrupted step '{tool_name}' was reconciled as "
                            "NOT_EXECUTED. Re-observe targets and create a new "
                            "action authorization before proceeding."
                        ),
                    )
                )
                failed_step = {
                    **active,
                    "state": "FAILED",
                    "execution_state": "NOT_STARTED",
                    "resolution": "NOT_EXECUTED",
                }
                if tool_state.get("semantic_step"):
                    semantic_step = dict(tool_state["semantic_step"])
                    semantic_step["status"] = "NOT_EXECUTED"
                    tool_state["semantic_step"] = semantic_step
                    failed_step["semantic_status"] = "NOT_EXECUTED"
                    if tool_state.get("durable_plan") is not None:
                        try:
                            plan = DurablePlan.from_dict(tool_state["durable_plan"])
                            plan.sync_semantic_status(
                                semantic_step["step_id"], "NOT_EXECUTED"
                            )
                            tool_state["durable_plan"] = plan.to_dict()
                        except Exception as exc:
                            return (
                                None,
                                f"planner reconciliation state is invalid: {exc}",
                                True,
                            )
                completed = list(tool_state.get("completed_steps", []))
                completed = [
                    step for step in completed if step.get("call_id") != call_id
                ]
                completed.append(failed_step)
                tool_state = {**tool_state, "completed_steps": completed}
                active = {"state": "NOT_STARTED"}
            else:
                return None, "reconciliation resolution is invalid", True
            tool_state = {
                **tool_state,
                "active_step": active,
                "recovery_history": recovery_history,
                "recovery": {"required": False, "resolution": resolution["resolution"]},
            }
            conversation = {
                **conversation,
                "lifecycle": "RUNNING",
                "resumable": True,
                "messages": _checkpoint_messages(messages),
            }
            checkpoint = {
                **checkpoint,
                "conversation_state": conversation,
                "tool_state": tool_state,
            }
            messages = _restore_checkpoint_messages(conversation["messages"])
            lifecycle = "RUNNING"
        if pending and not candidate:
            return (
                None,
                "durable mutation reservation exists without restart authority",
                False,
            )
        if lifecycle in {"CANCELLED", "TIMED_OUT"}:
            if pending:
                return (
                    None,
                    "terminal cancellation contradicts pending mutation journal",
                    True,
                )
            return {
                "completed": True,
                "cancelled": True,
                "agent_id": agent_id,
            }, None, candidate
        if not candidate:
            if lifecycle in {"RUNNING", "FAILED"}:
                return (
                    None,
                    "incomplete checkpoint has no confirmed stopped worker",
                    False,
                )
            return None, None, False
        if lifecycle == "COMPLETED":
            if pending:
                return None, "completed tick contradicts pending mutation journal", True
            return {"completed": True, "agent_id": agent_id}, None, True
        if (
            lifecycle == "RUNNING"
            and conversation.get("resume_authorized") is True
            and conversation.get("resumable") is not True
        ):
            if pending:
                return None, "fresh resume has unresolved mutation quarantine", True
            self._manager.clear_restart_candidate(agent_id)
            return None, None, True
        if lifecycle not in {"RUNNING", "FAILED"}:
            return None, "interrupted checkpoint lifecycle is not resumable", True
        if conversation.get("resumable") is not True:
            cancellation = self._manager.cancellation_state(agent_id)
            active = checkpoint["tool_state"]["active_step"]
            effect = active.get("effect")
            safe_unverified = active.get("state") in {
                "NOT_STARTED",
                "FAILED",
            } and (
                active.get("state") == "NOT_STARTED"
                or active.get("execution_state") == "NOT_STARTED"
            )
            prepared_reconciled = False
            if active.get("state") == "PREPARED":
                record = self._manager.execution_journal.reconciliation(
                    agent_id,
                    active.get("tool", ""),
                    active.get("call_id", ""),
                )
                prepared_reconciled = bool(
                    record and record.get("resolution") == "NOT_EXECUTED"
                )
            if cancellation is not None and not pending and (
                safe_unverified
                or prepared_reconciled
                or effect == "READ_ONLY"
                or (
                    active.get("state") == "VERIFIED"
                    and active.get("execution_state") == "VERIFIED"
                )
            ):
                runtime = {
                    "agent_id": agent_id,
                    "tick_id": checkpoint["tick_id"],
                    "resumable": False,
                    "conversation_state": conversation,
                    "tool_state": checkpoint["tool_state"],
                    "checkpoint_id": checkpoint["id"],
                    "resume_messages": messages,
                    "has_progress": bool(messages),
                }
                if conversation.get("deadline_at") is not None:
                    runtime["deadline_at"] = conversation["deadline_at"]
                return runtime, None, True
            return None, "checkpoint has no restorable agent conversation", True

        tool_state = checkpoint["tool_state"]
        active = tool_state["active_step"]
        active_state = active["state"]
        if len(pending) > 1:
            return None, "multiple unresolved mutation reservations", True
        if pending:
            reservation = pending[0]
            if reservation["tool"] != active.get("tool") or reservation[
                "call_id"
            ] != active.get("call_id"):
                return (
                    None,
                    "execution journal and checkpoint identify different actions",
                    True,
                )
            if active_state == "PREPARED":
                if reservation.get("state") != "PREPARED":
                    return (
                        None,
                        "dispatch journal advanced beyond PREPARED "
                        "without a matching checkpoint",
                        True,
                    )
                resolution = "NOT_EXECUTED"
                evidence = "checkpoint PREPARED committed before the dispatch gate"
            elif (
                active_state == "FAILED"
                and active.get("execution_state") == "NOT_STARTED"
            ):
                resolution = "NOT_EXECUTED"
                evidence = "checkpoint records a NOT_STARTED result before dispatch"
            elif (
                active_state == "VERIFIED"
                and active.get("execution_state") == "VERIFIED"
            ):
                resolution = "VERIFIED"
                evidence = (
                    f"verified checkpoint {checkpoint['id']} records "
                    f"completed call {active['call_id']}"
                )
            else:
                return (
                    None,
                    "interrupted mutation is unresolved and cannot be replayed",
                    True,
                )
            try:
                self._manager.execution_journal.reconcile(
                    reservation["token"],
                    resolution=resolution,
                    evidence=evidence,
                    worker_stopped=True,
                )
            except Exception as exc:
                return None, f"execution journal reconciliation failed: {exc}", True
            pending = self._manager.execution_journal.pending(agent_id)
        elif active_state in {"EXECUTING", "UNKNOWN_OUTCOME"}:
            return (
                None,
                "interrupted execution has no reconciliation evidence",
                True,
            )
        elif (
            active_state in {"EXECUTED", "FAILED"}
            and active.get("effect") != "READ_ONLY"
            and active.get("execution_state") != "NOT_STARTED"
        ):
            return None, "mutating step was dispatched but lacks VERIFIED outcome", True

        recovery_history = list(tool_state.get("recovery_history", []))
        recovery_history.append(
            {
                "event": "RESUMED",
                "from_checkpoint": checkpoint["id"],
                "resolved_step_state": active_state,
                "pending_mutations": len(pending),
            }
        )
        runtime = {
            "agent_id": agent_id,
            "tick_id": checkpoint["tick_id"],
            "resumable": True,
            "conversation_state": conversation,
            "tool_state": tool_state,
            "checkpoint_id": checkpoint["id"],
            "resume_messages": messages,
            "has_progress": True,
        }
        if conversation.get("deadline_at") is not None:
            runtime["deadline_at"] = conversation["deadline_at"]
        resumed_tool_state = {
            **tool_state,
            "active_step": {"state": "NOT_STARTED"},
            "recovery_history": recovery_history,
        }
        try:
            self._persist_tick_state(runtime, messages, resumed_tool_state)
        except Exception as exc:
            return None, f"could not persist restored continuation: {exc}", True
        self._manager.clear_restart_candidate(agent_id)
        self._manager.clear_recovery_request(agent_id)
        return runtime, None, True

    def run_ephemeral(
        self,
        agent_type: str,
        system_prompt: str,
        input_text: str,
        tools: list[str] | None = None,
    ) -> Any:
        """Run a one-shot agent turn with no lifecycle tracking."""
        from openjarvis.core.registry import AgentRegistry

        agent_cls = AgentRegistry.get(agent_type)
        engine = (
            getattr(self._system, "engine", None)
            if self._system is not None
            else getattr(self._manager, "_engine", None)
        )
        if not tools:
            agent = agent_cls(
                engine=engine,
                system_prompt=system_prompt,
                bus=self._bus,
            )
            return agent.run(input_text)

        # Session-expiry persistence asks a simple agent to use memory/skill
        # tools. A SimpleAgent cannot call them, so resolve the requested tools
        # and use the standard secured function-calling agent for this
        # ephemeral turn instead of silently ignoring ``tools``.
        import openjarvis.tools  # noqa: F401
        from openjarvis.agents.orchestrator import OrchestratorAgent
        from openjarvis.core.registry import ToolRegistry
        from openjarvis.tools._stubs import BaseTool

        instances = []
        for name in tools:
            if not ToolRegistry.contains(name):
                continue
            registered = ToolRegistry.get(name)
            if isinstance(registered, BaseTool):
                instances.append(registered)
            elif isinstance(registered, type) and issubclass(registered, BaseTool):
                instances.append(registered())

        execution_cls = (
            agent_cls
            if getattr(agent_cls, "accepts_tools", False)
            else OrchestratorAgent
        )
        system = self._system
        agent = execution_cls(
            engine=engine,
            model=getattr(system, "model", "") or _AGENT_TICK_DEFAULT_MODEL,
            system_prompt=system_prompt,
            tools=instances,
            bus=self._bus,
            capability_policy=getattr(system, "capability_policy", None),
            rate_limiter=getattr(system, "rate_limiter", None),
            agent_id=f"ephemeral:{agent_type}",
        )
        return agent.run(input_text)

    def execute_tick(self, agent_id: str, *, lock_already_held: bool = False) -> None:
        """Run one tick for the given agent.

        1. Acquire concurrency guard (start_tick)
        2. Invoke agent with retry logic
        3. Update stats
        4. Release guard (end_tick)

        ``lock_already_held`` is set by callers that took the start_tick()
        lock themselves before spawning the worker (e.g. the HTTP /run route
        guards against concurrent POSTs by acquiring before threading).
        Without this flag, the executor would re-acquire and trip its own
        guard — bailing out with no end_tick(), leaving the agent stuck in
        ``status='running'`` forever.
        """
        if lock_already_held:
            self._set_activity(agent_id, "Preparing tick...")
        else:
            try:
                self._manager.start_tick(agent_id)
                self._set_activity(agent_id, "Preparing tick...")
            except ValueError:
                logger.warning("Agent %s already running, skipping tick", agent_id)
                return

        agent = self._manager.get_agent(agent_id)
        if agent is None:
            logger.error("Agent %s not found", agent_id)
            return

        runtime, recovery_error, _ = self._resume_runtime(agent_id)
        if recovery_error:
            self._require_recovery(agent_id, recovery_error)
            return
        cancellation = self._manager.cancellation_state(agent_id)
        if runtime and runtime.get("completed"):
            if cancellation is not None:
                self._manager.advance_cancellation(agent_id, "ACKNOWLEDGED")
                self._manager.advance_cancellation(agent_id, "SAFE_BOUNDARY_REACHED")
                self._manager.advance_cancellation(agent_id, "TERMINALIZED")
                self._manager.end_tick(agent_id)
                self._manager.update_agent(
                    agent_id,
                    status=(
                        "archived"
                        if cancellation.get("reason") == "archive"
                        else "paused"
                    ),
                )
                return
            self._manager.end_tick(agent_id)
            self._manager.update_agent(
                agent_id, status="paused" if runtime.get("cancelled") else "idle"
            )
            self._manager.clear_restart_candidate(agent_id)
            self._manager.clear_recovery_request(agent_id)
            return
        if cancellation is not None:
            if cancellation.get("state") == "TERMINALIZED":
                self._manager.end_tick(agent_id)
                self._manager.update_agent(
                    agent_id,
                    status=(
                        "archived"
                        if cancellation.get("reason") == "archive"
                        else "paused"
                    ),
                )
                return
            if self._manager.execution_journal.pending(agent_id):
                self._require_recovery(
                    agent_id,
                    "cancellation found an unresolved physical mutation",
                )
                return
            if runtime is None:
                runtime = {
                    "agent_id": agent_id,
                    "tick_id": uuid.uuid4().hex,
                    "resumable": False,
                    "conversation_state": {},
                    "tool_state": {
                        "execution_id": uuid.uuid4().hex,
                        "active_step": {"state": "NOT_STARTED"},
                        "completed_steps": [],
                        "retry_count": 0,
                        "retry_history": [],
                    },
                }
            self._terminalize_cancellation(agent_id, runtime)
            return
        if runtime is None:
            timeout_seconds = agent.get("config", {}).get(
                "overall_timeout_seconds", 0
            )
            deadline_at = None
            if (
                type(timeout_seconds) in {int, float}
                and timeout_seconds > 0
                and timeout_seconds < float("inf")
            ):
                deadline_at = time.time() + timeout_seconds
            runtime = {
                "agent_id": agent_id,
                "tick_id": uuid.uuid4().hex,
                "resumable": False,
                "conversation_state": {},
                "tool_state": {
                    "execution_id": uuid.uuid4().hex,
                    "active_step": {"state": "NOT_STARTED"},
                    "completed_steps": [],
                    "retry_count": 0,
                    "retry_history": [],
                },
            }
            if deadline_at is not None:
                runtime["deadline_at"] = deadline_at
            try:
                self._persist_tick_state(runtime, [], runtime["tool_state"])
            except Exception as exc:
                self._require_recovery(
                    agent_id,
                    f"initial checkpoint persistence failed: {exc}",
                )
                return
        agent["_managed_runtime"] = runtime

        deadline_timer = None
        deadline_at = runtime.get("deadline_at")
        if deadline_at is not None:
            remaining = deadline_at - time.time()
            if remaining <= 0:
                self._request_deadline_cancellation(agent_id)
                cancellation = self._manager.cancellation_state(agent_id)
                if cancellation is not None:
                    self._terminalize_cancellation(agent_id, runtime)
                    return
            else:
                deadline_timer = threading.Timer(
                    remaining, self._request_deadline_cancellation, args=(agent_id,)
                )
                deadline_timer.daemon = True
                deadline_timer.start()

        self._bus.publish(
            EventType.AGENT_TICK_START,
            {
                "agent_id": agent_id,
                "agent_name": agent["name"],
            },
        )

        # Activity tracking: subscribe to tool/inference events
        def _on_activity(event: Any) -> None:
            if event.data.get("agent") == agent_id:
                self._manager.update_agent(agent_id, last_activity_at=time.time())

        self._bus.subscribe(EventType.TOOL_CALL_START, _on_activity)
        self._bus.subscribe(EventType.INFERENCE_START, _on_activity)

        # Trace recording: collect tool call steps
        trace_steps: list[dict[str, Any]] = []

        def _on_tool_start(event: Any) -> None:
            if event.data.get("agent") == agent_id:
                trace_steps.append(
                    {
                        "type": "tool_call",
                        "input": {
                            "tool": event.data.get("tool"),
                            "args": event.data.get("arguments", event.data.get("args")),
                            "call_id": event.data.get("call_id"),
                        },
                        "start_time": event.timestamp,
                    }
                )

        def _on_tool_end(event: Any) -> None:
            if event.data.get("agent") == agent_id and trace_steps:
                for step in reversed(trace_steps):
                    if step["type"] == "tool_call" and "output" not in step:
                        call_id = event.data.get("call_id")
                        if call_id and step["input"].get("call_id") != call_id:
                            continue
                        if not call_id and step["input"].get("tool") != event.data.get(
                            "tool"
                        ):
                            continue
                        step["output"] = {
                            "result": str(event.data.get("result", ""))[:4096],
                            "success": event.data.get("success"),
                        }
                        step["duration"] = event.data.get(
                            "latency", event.data.get("duration", 0)
                        )
                        step["metadata"] = event.data.get("metadata", {})
                        break

        if self._trace_store:
            self._bus.subscribe(EventType.TOOL_CALL_START, _on_tool_start)
            self._bus.subscribe(EventType.TOOL_CALL_END, _on_tool_end)

        tick_start = time.time()
        tick_timer = time.perf_counter()
        result = None
        error_info = None

        try:
            result = self._run_with_retries(agent)
        except AgentTickError as e:
            error_info = e
        finally:
            self._bus.unsubscribe(EventType.TOOL_CALL_START, _on_activity)
            self._bus.unsubscribe(EventType.INFERENCE_START, _on_activity)

            if self._trace_store:
                self._bus.unsubscribe(EventType.TOOL_CALL_START, _on_tool_start)
                self._bus.unsubscribe(EventType.TOOL_CALL_END, _on_tool_end)

            tick_duration = time.perf_counter() - tick_timer
            if result is not None and result.metadata.get("recovery_required"):
                tool_state = dict(runtime.get("tool_state") or {})
                tool_state["recovery"] = {
                    "required": True,
                    "requires_user": True,
                    "reason": result.metadata.get(
                        "recovery_reason", "tool outcome UNKNOWN_OUTCOME"
                    ),
                    "active_step": result.metadata.get("active_step"),
                }
                cancellation = self._manager.cancellation_state(agent_id)
                if cancellation is not None:
                    tool_state["cancellation"] = cancellation
                try:
                    self._persist_tick_state(
                        runtime,
                        runtime.get("resume_messages", []),
                        tool_state,
                        lifecycle="RECOVERY_REQUIRED",
                        result=result,
                    )
                except Exception:
                    logger.exception("Could not persist UNKNOWN_OUTCOME recovery state")
                self._manager.end_tick(agent_id)
                self._manager.update_agent(agent_id, status="needs_attention")
                self._manager.update_summary_memory(
                    agent_id, "RECOVERY REQUIRED: unresolved tool outcome"
                )
                self._bus.publish(
                    EventType.AGENT_TICK_ERROR,
                    {
                        "agent_id": agent_id,
                        "error": tool_state["recovery"]["reason"],
                        "error_type": "unknown_outcome",
                        "duration": tick_duration,
                    },
                )
            elif self._manager.cancellation_state(agent_id) is not None:
                if result is None:
                    result = AgentResult(
                        content="Cancellation reached a safe execution boundary.",
                        metadata={"cancelled": True},
                    )
                self._terminalize_cancellation(
                    agent_id,
                    runtime,
                    result=result,
                    duration=tick_duration,
                )
            else:
                try:
                    self._persist_tick_state(
                        runtime,
                        runtime.get("resume_messages", []),
                        runtime.get("tool_state") or {},
                        lifecycle="FAILED" if error_info else "COMPLETED",
                        result=result,
                        error=error_info,
                    )
                except Exception:
                    self._require_recovery(
                        agent_id,
                        f"terminal checkpoint persistence failed for {agent_id}",
                    )
                else:
                    self._manager.complete_tick_if_not_cancelled(agent_id)
                    cancellation = self._manager.cancellation_state(agent_id)
                    if cancellation is not None:
                        if result is None:
                            result = AgentResult(
                                content=(
                                    "Cancellation reached a safe execution boundary."
                                ),
                                metadata={"cancelled": True},
                            )
                        self._terminalize_cancellation(
                            agent_id,
                            runtime,
                            result=result,
                            duration=tick_duration,
                        )
                    else:
                        # The manager transition above closes the cancellation
                        # race. If another lifecycle operation already changed
                        # status, _finalize_tick preserves that status.
                        self._finalize_tick(agent_id, result, error_info, tick_duration)

            if self._trace_store:
                self._save_trace(
                    agent_id,
                    agent,
                    result,
                    error_info,
                    tick_start,
                    tick_duration,
                    trace_steps,
                )
            if deadline_timer is not None:
                deadline_timer.cancel()

    def _run_with_retries(self, agent: dict) -> AgentResult:
        """Invoke within a checkpointed attempt budget, retrying transient errors."""
        runtime = agent.get("_managed_runtime")
        if not isinstance(runtime, dict):
            raise FatalError("managed agent runtime is missing")
        state = dict(runtime.get("tool_state") or {})
        retry_count = state.get("retry_count", 0)
        history = list(state.get("retry_history", []))

        def persist_retry_state(
            current_state: dict[str, Any], *, result: AgentResult | None = None
        ) -> None:
            try:
                self._persist_tick_state(
                    runtime,
                    runtime.get("resume_messages", []),
                    current_state,
                    result=result,
                )
            except Exception as exc:
                raise FatalError(f"retry checkpoint persistence failed: {exc}") from exc

        def cancelled_result() -> AgentResult:
            cancellation = self._manager.cancellation_state(agent["id"])
            return AgentResult(
                content="Cancellation reached a safe execution boundary.",
                metadata={"cancelled": True, "cancellation": cancellation},
            )

        cancellation = self._manager.cancellation_state(agent["id"])
        if cancellation is not None:
            return cancelled_result()

        if retry_count >= _MAX_RETRIES:
            state["retry_terminal"] = "ATTEMPT_BUDGET_EXHAUSTED"
            persist_retry_state(state)
            raise FatalError("managed agent attempt budget exhausted")

        for attempt in range(retry_count, _MAX_RETRIES):
            history.append({"attempt": attempt + 1, "state": "RUNNING"})
            state.update(retry_count=attempt + 1, retry_history=history)
            persist_retry_state(state)
            try:
                result = self._invoke_agent(agent)
            except Exception as exc:
                state = dict(runtime.get("tool_state") or state)
                history = list(state.get("retry_history", history))
                cancellation = self._manager.cancellation_state(agent["id"])
                if cancellation is not None:
                    terminal_state = (
                        "TIMED_OUT"
                        if cancellation.get("reason") in {"deadline", "timeout"}
                        else "CANCELLED"
                    )
                    history[-1].update(
                        state=terminal_state,
                        error_type=type(exc).__name__,
                        retryable=False,
                    )
                    if cancellation.get("timeout_kind"):
                        history[-1]["timeout_kind"] = cancellation["timeout_kind"]
                    state["retry_history"] = history
                    persist_retry_state(state)
                    return cancelled_result()
                classified = (
                    exc if isinstance(exc, AgentTickError) else classify_error(exc)
                )
                history[-1].update(
                    state="FAILED",
                    error_type=type(classified).__name__,
                    retryable=classified.retryable,
                    error=str(classified)[:1000],
                )
                if isinstance(exc, TimeoutError) or any(
                    marker in str(exc).lower()
                    for marker in ("timeout", "timed out")
                ):
                    history[-1]["timeout_kind"] = "model"
                    history[-1]["timeout_phase"] = "planning"
                state["retry_history"] = history
                persist_retry_state(state)
                if not classified.retryable or attempt == _MAX_RETRIES - 1:
                    if classified is exc:
                        raise
                    raise classified from exc
                delay = retry_delay(attempt)
                logger.info(
                    "Agent %s tick retry %d/%d in %ds: %s",
                    agent["id"],
                    attempt + 1,
                    _MAX_RETRIES,
                    delay,
                    classified,
                )
                wait_until = time.monotonic() + delay
                while time.monotonic() < wait_until:
                    cancellation = self._manager.cancellation_state(agent["id"])
                    if cancellation is not None:
                        history[-1]["cancelled_before_retry"] = True
                        if cancellation.get("timeout_kind"):
                            history[-1]["timeout_kind"] = cancellation[
                                "timeout_kind"
                            ]
                        state["retry_history"] = history
                        persist_retry_state(state)
                        return cancelled_result()
                    time.sleep(min(0.25, max(0.0, wait_until - time.monotonic())))
                continue

            state = dict(runtime.get("tool_state") or state)
            history = list(state.get("retry_history", history))
            cancellation = self._manager.cancellation_state(agent["id"])
            if cancellation is not None and not result.metadata.get(
                "recovery_required"
            ):
                result.metadata["cancelled"] = True
                result.metadata["cancellation"] = cancellation
                history[-1]["state"] = (
                    "TIMED_OUT"
                    if cancellation.get("reason") in {"deadline", "timeout"}
                    else "CANCELLED"
                )
                if cancellation.get("timeout_kind"):
                    history[-1]["timeout_kind"] = cancellation["timeout_kind"]
                state["retry_history"] = history
                persist_retry_state(state, result=result)
                return result
            history[-1]["state"] = (
                "RECOVERY_REQUIRED"
                if result.metadata.get("recovery_required")
                else "SUCCEEDED"
            )
            state["retry_history"] = history
            if not result.metadata.get("recovery_required"):
                # A completed tick opens a fresh attempt window: the budget
                # bounds a retry burst inside one run segment, not the
                # agent's whole multi-step lifetime (long-horizon plans
                # tick once per step).
                state["retry_count"] = 0
                state["retry_history"] = []
            persist_retry_state(state, result=result)
            return result

        raise FatalError("managed agent attempt budget exhausted")

    def _invoke_agent(self, agent: dict) -> AgentResult:
        """Invoke one agent while owning every resource its resolver opens."""

        previous = getattr(self._toolkit_local, "current", None)
        self._toolkit_local.current = None
        try:
            return self._invoke_agent_impl(agent)
        finally:
            current = getattr(self._toolkit_local, "current", None)
            if current is not None:
                current.close()
            self._toolkit_local.current = previous

    def _wire_goal_planning(
        self,
        agent: dict[str, Any],
        config: dict[str, Any],
        engine: Any,
        model: str,
        execution_agent_cls: Any,
        tool_instances: list[Any],
    ) -> None:
        """Opt-in model planning through the managed controller boundary."""
        raw_options = config.get("goal_planning")
        if raw_options in (None, False):
            return
        if raw_options is True:
            options: dict[str, Any] = {}
        elif isinstance(raw_options, dict):
            options = dict(raw_options)
        else:
            raise FatalError("goal_planning must be a boolean or object")
        if execution_agent_cls.__name__ != "OrchestratorAgent":
            raise FatalError(
                "goal_planning requires the managed OrchestratorAgent path"
            )

        goal = options.get("goal", config.get("instruction", ""))
        if not isinstance(goal, str) or not goal.strip():
            raise FatalError("goal_planning requires a non-empty goal")
        planner_model = options.get("model", model)
        if not isinstance(planner_model, str) or not planner_model.strip():
            raise FatalError("goal_planning model must be a non-empty string")
        planner_max_tokens = options.get("planner_max_tokens", 2048)
        if type(planner_max_tokens) is not int or planner_max_tokens <= 0:
            raise FatalError("planner_max_tokens must be a positive integer")
        max_replans = options.get("max_replans", 1)
        if type(max_replans) is not int or max_replans < 0:
            raise FatalError("max_replans must be a non-negative integer")

        model_gate = getattr(self._system, "goal_model_gate", None)
        if model_gate is not None and not callable(model_gate):
            raise FatalError("goal_model_gate must be callable when configured")
        supported_tools = {tool.spec.name for tool in tool_instances}
        runtime = agent.get("_managed_runtime")
        if not isinstance(runtime, dict):
            raise FatalError("goal_planning requires a managed runtime")
        tool_state = dict(runtime.get("tool_state") or {})
        raw_plan = tool_state.get("durable_plan")
        active = raw_plan.get("active_node_id") if isinstance(raw_plan, dict) else None
        active_node = (
            next(
                (
                    node
                    for node in raw_plan.get("nodes", [])
                    if node.get("planner_node_id") == active
                ),
                None,
            )
            if isinstance(raw_plan, dict)
            else None
        )
        if active_node is None and isinstance(raw_plan, dict):
            active_node = next(
                (
                    node
                    for node in reversed(raw_plan.get("nodes", []))
                    if node.get("status") == "FAILED"
                ),
                None,
            )

        try:
            if (
                options.get("replan_on_failure", True)
                and isinstance(active_node, dict)
                and active_node.get("status") == "FAILED"
            ):
                replan_count = tool_state.get("replan_count", 0)
                if type(replan_count) is not int or replan_count < 0:
                    raise FatalError("checkpoint replan_count is invalid")
                if replan_count >= max_replans:
                    raise FatalError("GOAL_REPLAN_BUDGET_EXHAUSTED")
                tool_state["replan_count"] = replan_count + 1
                runtime["tool_state"] = tool_state
                self._persist_tick_state(
                    runtime,
                    runtime.get("resume_messages", []),
                    tool_state,
                )
                self.replan_goal(
                    agent["id"],
                    ReplannerAdapter(
                        engine,
                        model=planner_model,
                        source="managed_model_replanner",
                        max_tokens=planner_max_tokens,
                    ),
                    goal,
                    context={"failed_node": active_node},
                    supported_tools=supported_tools,
                    model_gate=model_gate,
                )
            elif not isinstance(raw_plan, dict) or not raw_plan.get("nodes"):
                self.plan_goal(
                    agent["id"],
                    PlannerAdapter(
                        engine,
                        model=planner_model,
                        source="managed_model_planner",
                        max_tokens=planner_max_tokens,
                    ),
                    goal,
                    supported_tools=supported_tools,
                    model_gate=model_gate,
                )
        except PlanProposalError as exc:
            raise FatalError(f"GOAL_PLANNING_DEFERRED: {exc}") from exc

        checkpoint = self._manager.get_latest_checkpoint(agent["id"])
        if checkpoint is not None:
            runtime["conversation_state"] = checkpoint["conversation_state"]
            runtime["tool_state"] = checkpoint["tool_state"]
            runtime["checkpoint_id"] = checkpoint["id"]
            runtime["resume_messages"] = _restore_checkpoint_messages(
                checkpoint["conversation_state"].get("messages", [])
            )
            runtime["has_progress"] = bool(runtime["resume_messages"])
        agent["_managed_runtime"] = runtime

    def _invoke_agent_impl(self, agent: dict) -> AgentResult:
        """Implementation split out so the wrapper owns resolver lifetime."""
        from openjarvis.agents import AgentRegistry

        agent_type = agent.get("agent_type", "monitor_operative")
        agent_cls = AgentRegistry.get(agent_type)
        if agent_cls is None:
            raise FatalError(f"Unknown agent type: {agent_type}")

        config = agent.get("config", {})
        try:
            tool_requirement = ToolRequirement(
                config.get("tool_requirement", ToolRequirement.OPTIONAL.value)
            )
        except (TypeError, ValueError) as exc:
            raise FatalError(f"Invalid tool requirement: {exc}") from exc
        agent_accepts_tools = bool(getattr(agent_cls, "accepts_tools", False))
        supports_tool_fallback = bool(
            getattr(agent_cls, "supports_managed_tool_fallback", False)
        )

        # Resolve engine + model from JarvisSystem
        engine = self._system.engine if self._system else None
        if engine is None:
            raise FatalError("No engine available in JarvisSystem")
        model = _resolve_tick_model(config, self._system)
        if not model:
            raise FatalError("No model configured for agent")

        logger.info(
            "Agent %s [%s]: using model=%s, engine=%s",
            agent["name"],
            agent["id"],
            model,
            type(engine).__name__,
        )
        self._set_activity(agent["id"], f"Loading model {model}...")

        # Optionally override model via router policy
        router_policy_key = config.get("router_policy")
        if router_policy_key and self._system:
            try:
                from openjarvis.core.registry import RouterPolicyRegistry
                from openjarvis.learning.routing.router import (
                    build_routing_context,
                )

                router_kwargs: dict[str, Any] = {
                    "available_models": _available_tick_models(engine, model),
                }
                if router_policy_key == "tiered":
                    system_config = getattr(self._system, "config", None)
                    routing = getattr(
                        getattr(system_config, "learning", None), "routing", None
                    )
                    router_kwargs.update(
                        default_model=model,
                        fallback_model=config.get(
                            "fallback_model",
                            getattr(
                                getattr(system_config, "intelligence", None),
                                "fallback_model",
                                "",
                            ),
                        ),
                        tier_models=config.get(
                            "tier_models",
                            getattr(routing, "tier_models", {}),
                        ),
                    )
                policy = RouterPolicyRegistry.create(
                    router_policy_key,
                    **router_kwargs,
                )
                instruction = config.get("instruction", "")
                runtime = agent.get("_managed_runtime") or {}
                tool_state = runtime.get("tool_state") or {}
                retry_history = tool_state.get("retry_history") or []
                failure_history = sum(
                    1
                    for item in retry_history
                    if isinstance(item, dict)
                    and item.get("state") in {"FAILED", "RECOVERY_REQUIRED"}
                )
                ctx = build_routing_context(
                    instruction,
                    metadata={"failure_history": failure_history},
                )
                selected = policy.select_model(ctx)
                if selected:
                    model = selected
            except Exception:
                pass  # Fall back to configured model

        mcp_tools: list[Any] = []
        mcp_clients: list[Any] = []
        if (
            config.get("mcp_tools", True) is not False
            and self._system is not None
            and (agent_accepts_tools or supports_tool_fallback)
        ):
            provider = getattr(
                self._system,
                "get_managed_agent_mcp_tools",
                None,
            )
            if callable(provider):
                try:
                    mcp_tools, mcp_clients = provider()
                except Exception as exc:
                    logger.warning("Managed-agent MCP discovery failed: %s", exc)
            else:
                mcp_tools = list(getattr(self._system, "mcp_tools", []) or [])
                mcp_clients = list(getattr(self._system, "_mcp_clients", []) or [])

            if not mcp_tools:
                try:
                    from openjarvis.tools.mcp_adapter import MCPToolAdapter

                    pool = (
                        getattr(
                            getattr(self._system, "tool_executor", None),
                            "_tools",
                            {},
                        )
                        or {}
                    )
                    mcp_tools = [
                        tool
                        for tool in pool.values()
                        if isinstance(tool, MCPToolAdapter)
                    ]
                except Exception:
                    mcp_tools = []

        scoped_memory_backend = getattr(self._system, "memory_backend", None)
        if scoped_memory_backend is not None:
            from openjarvis.memory.scope import (
                MemoryAuthorization,
                ScopedMemoryBackend,
            )

            scoped_memory_backend = ScopedMemoryBackend(
                scoped_memory_backend,
                MemoryAuthorization(agent_id=str(agent["id"])),
            )

        resolved_toolkit = resolve_agent_tools(
            agent,
            engine=engine,
            model=model,
            memory_backend=scoped_memory_backend,
            channel_backend=getattr(self._system, "channel_backend", None),
            mcp_tools=mcp_tools,
            mcp_clients=mcp_clients,
            knowledge_db_path=getattr(self._system, "knowledge_db_path", None),
        )
        self._toolkit_local.current = resolved_toolkit
        tool_instances = resolved_toolkit.instances
        logger.info(
            "Agent %s: resolved %d tools (%s)",
            agent["name"],
            len(tool_instances),
            ", ".join(resolved_toolkit.by_name) or "none",
        )

        execution_agent_cls = agent_cls
        if tool_instances and not agent_accepts_tools and supports_tool_fallback:
            # Managed SSE already runs configured tools through a native
            # function-calling loop regardless of the selected class. Use the
            # same capability for immediate/scheduled ticks instead of
            # silently discarding the resolved toolkit for SimpleAgent and
            # other explicitly compatible non-tool classes.
            from openjarvis.agents.orchestrator import OrchestratorAgent

            execution_agent_cls = OrchestratorAgent
            logger.info(
                "Agent %s: %s does not accept tools; using %s for this "
                "tool-enabled tick",
                agent["name"],
                agent_cls.__name__,
                execution_agent_cls.__name__,
            )

        self._wire_goal_planning(
            agent,
            config,
            engine,
            model,
            execution_agent_cls,
            tool_instances,
        )

        # Construct agent instance
        agent_kwargs: dict[str, Any] = {}
        sys_prompt = config.get("system_prompt")
        if getattr(execution_agent_cls, "accepts_tools", False) and tool_instances:
            agent_kwargs["tools"] = tool_instances
        # Hand the agent our EventBus so its ToolExecutor can publish
        # TOOL_CALL_START/END — without this, ToolExecutor's ``self._bus``
        # is None and every tool call executes silently, which is why
        # traces previously reported "0 steps" even when the model was
        # actively invoking web_search/memory_*/etc.
        if self._bus is not None:
            agent_kwargs["bus"] = self._bus
        # Wire RBAC/rate-limiting from the system's SecurityContext into the
        # agent's own ToolExecutor. Without this, every managed-agent tick
        # went through ToolUsingAgent's default capability_policy=None /
        # rate_limiter=None, so tool calls were never actually gated even
        # when the config had capabilities/rate-limiting enabled.
        if self._system is not None:
            cap_policy = getattr(self._system, "capability_policy", None)
            if cap_policy is not None:
                agent_kwargs["capability_policy"] = cap_policy
            rate_limiter = getattr(self._system, "rate_limiter", None)
            if rate_limiter is not None:
                agent_kwargs["rate_limiter"] = rate_limiter
        agent_kwargs["agent_id"] = agent["id"]
        # Propagate confirmation policy from the AgentExecutor down to the
        # agent's own ToolExecutor. Set by CLI paths like `jarvis agents ask`
        # so non-interactive runs can auto-approve tool execution.
        if getattr(self, "_confirm_callback", None) is not None:
            agent_kwargs["interactive"] = True
            agent_kwargs["confirm_callback"] = self._confirm_callback

        # Wire cross-tick state plumbing into agent classes that accept it.
        # Without this, MonitorOperative/Operative agents have no working
        # session_store or memory_backend and silently no-op their state
        # recall / persistence paths.
        import inspect

        init_sig = inspect.signature(execution_agent_cls.__init__)
        accepts_var_kw = any(
            p.kind == inspect.Parameter.VAR_KEYWORD
            for p in init_sig.parameters.values()
        )

        def _accepts(name: str) -> bool:
            return accepts_var_kw or name in init_sig.parameters

        if tool_requirement == ToolRequirement.REQUIRED_NATIVE and (
            not getattr(execution_agent_cls, "supports_required_native_tools", False)
            or not _accepts("tool_requirement")
        ):
            raise FatalError(
                f"Agent {execution_agent_cls.__name__} cannot enforce required native tools"
            )
        if _accepts("tool_requirement"):
            agent_kwargs["tool_requirement"] = tool_requirement

        # Unsupported kwargs used to trigger the broad TypeError fallback
        # below, which retried with a bare constructor and silently discarded
        # valid prompt/state wiring. Filter by the selected class's signature
        # before construction instead.
        if sys_prompt is not None and _accepts("system_prompt"):
            agent_kwargs["system_prompt"] = sys_prompt
        agent_kwargs = {
            name: value for name, value in agent_kwargs.items() if _accepts(name)
        }

        state_kwargs: dict[str, Any] = {}
        if _accepts("operator_id"):
            state_kwargs["operator_id"] = agent["id"]
        if self._system is not None:
            if _accepts("session_store"):
                state_kwargs["session_store"] = getattr(
                    self._system, "session_store", None
                )
            if _accepts("memory_backend"):
                state_kwargs["memory_backend"] = scoped_memory_backend
            # Wire SOUL.md / MEMORY.md / USER.md persona files into persistent
            # agents, mirroring the one-shot `jarvis ask` path so they no
            # longer apply to CLI calls only (#376).
            cfg = getattr(self._system, "config", None)
            if _accepts("prompt_builder") and (
                cfg is not None or sys_prompt is not None
            ):
                from openjarvis.prompt.builder import SystemPromptBuilder

                state_kwargs["prompt_builder"] = SystemPromptBuilder(
                    agent_template=(
                        sys_prompt
                        if sys_prompt is not None
                        else getattr(
                            getattr(cfg, "agent", None),
                            "default_system_prompt",
                            "",
                        )
                        or ""
                    ),
                    memory_files_config=getattr(cfg, "memory_files", None),
                    system_prompt_config=getattr(cfg, "system_prompt", None),
                )

        try:
            try:
                agent_instance = execution_agent_cls(
                    engine,
                    model,
                    **agent_kwargs,
                    **state_kwargs,
                )
            except TypeError:
                try:
                    agent_instance = execution_agent_cls(
                        engine,
                        model,
                        **agent_kwargs,
                    )
                except TypeError:
                    agent_instance = execution_agent_cls(engine, model)
        except Exception:
            resolved_toolkit.close()
            raise

        if resolved_toolkit.mcp_clients:
            agent_instance._mcp_clients = resolved_toolkit.mcp_clients

        # Re-apply runtime security after constructor fallbacks and inject the
        # managed UUID into both direct-operation agents and ToolExecutors.
        # The trace subscriber also relies on this identity.
        from openjarvis.security.runtime import wire_agent_security

        wire_agent_security(
            agent_instance,
            bus=self._bus,
            capability_policy=getattr(self._system, "capability_policy", None),
            rate_limiter=getattr(self._system, "rate_limiter", None),
            agent_id=agent["id"],
        )

        # Conversation recovery cannot authorize replay of uncertain effects.
        tool_executor = getattr(agent_instance, "_executor", None)
        journal = getattr(self._manager, "execution_journal", None)
        managed_controller = None
        managed_semantic = execution_agent_cls.__name__ == "OrchestratorAgent"
        if tool_executor is not None and journal is not None:
            tool_executor.bind_execution_journal(
                journal,
                agent["id"],
                require_mutation_intent=managed_semantic,
            )
            if managed_semantic:
                try:
                    managed_runtime = agent.get("_managed_runtime") or {}
                    goal_planning = config.get("goal_planning")
                    if goal_planning is True or (
                        isinstance(goal_planning, dict)
                        and goal_planning.get("enabled") is True
                    ):
                        managed_runtime["_auto_advance_plan"] = True
                    trusted_tool_specs = {
                        tool.spec.name: tool for tool in tool_instances
                    }
                    plan_was_missing = "durable_plan" not in (
                        managed_runtime.get("tool_state") or {}
                    )
                    managed_controller = _ManagedMutationController(
                        journal,
                        agent["id"],
                        managed_runtime,
                        tool_specs=trusted_tool_specs,
                        authorization_check=self._authorization_check_for(
                            agent["id"]
                        ),
                        strict_schema=True,
                    )
                    if plan_was_missing:
                        managed_controller.persist_into(managed_runtime["tool_state"])
                        self._persist_tick_state(
                            managed_runtime,
                            managed_runtime.get("resume_messages", []),
                            managed_runtime["tool_state"],
                        )
                except Exception as exc:
                    resolved_toolkit.close()
                    raise FatalError(
                        f"managed semantic checkpoint is invalid: {exc}"
                    ) from exc

        logger.info(
            "Agent %s: tool wiring — %d tools resolved (%s), agent class %s",
            agent["name"],
            len(tool_instances),
            ", ".join(t.spec.name for t in tool_instances) or "none",
            execution_agent_cls.__name__,
        )

        # Build input from instruction + summary_memory + pending messages.
        # NB: we deliberately do NOT inject the full previous response back
        # in as "Previous context" — that caused the model to parrot its
        # own prior output verbatim. Cross-tick continuity now lives in the
        # agent's session_store / memory_backend; here we only surface a
        # short tick-boundary marker so the model knows time has passed.
        import datetime
        import re

        today = datetime.date.today().strftime("%A, %B %d, %Y")
        instruction = config.get("instruction", "")
        memory = (agent.get("summary_memory") or "").strip()
        last_run_at = agent.get("last_run_at")

        tick_note = ""
        if memory:
            first_sentence = re.split(r"(?<=[.!?])\s+", memory, maxsplit=1)[0]
            first_sentence = first_sentence.strip()[:200]
            if last_run_at:
                ts = datetime.datetime.fromtimestamp(last_run_at).strftime(
                    "%Y-%m-%d %H:%M"
                )
                tick_note = f"Last tick at {ts}: {first_sentence}"
            else:
                tick_note = f"Previous tick: {first_sentence}"

        if instruction:
            input_text = f"Current date: {today}\n\nStanding instruction: {instruction}"
            if tick_note:
                input_text += f"\n\n{tick_note}"
        else:
            base = tick_note or "Continue your assigned task."
            input_text = f"Current date: {today}\n\n{base}"
        pending = self._manager.get_pending_messages(agent["id"])
        if pending:
            user_msgs = "\n".join(f"User: {m['content']}" for m in pending)
            input_text = (
                f"New instructions:\n{user_msgs}"
                if agent.get("_managed_runtime", {}).get("has_progress")
                else f"{input_text}\n\nNew instructions:\n{user_msgs}"
            )
            for m in pending:
                self._manager.mark_message_delivered(m["id"])
            logger.info(
                "Agent %s: delivering %d pending message(s)",
                agent["name"],
                len(pending),
            )
            self._set_activity(
                agent["id"],
                f"Delivering {len(pending)} message(s)...",
            )
        else:
            logger.info(
                "Agent %s: no pending messages, running with instruction only",
                agent["name"],
            )
        runtime = agent.get("_managed_runtime", {})
        has_progress = bool(runtime.get("has_progress"))
        if has_progress and not pending:
            input_text = ""

        # Build AgentContext with memory results from FTS5 backend
        from openjarvis.agents._stubs import AgentContext

        agent_ctx = AgentContext()
        agent_ctx.metadata["managed_cancel_requested"] = (
            lambda: self._manager.cancellation_state(agent["id"]) is not None
        )
        artifact_inventory = _artifact_inventory(runtime.get("tool_state") or {})
        agent_ctx.metadata["managed_artifacts"] = artifact_inventory
        if has_progress:
            messages = [
                message
                for message in list(runtime.get("resume_messages") or [])
                if message.name != "_astra_artifact_inventory"
            ]
            agent_ctx.conversation.messages = messages
            if artifact_inventory:
                agent_ctx.conversation.messages.append(
                    Message(
                        role=Role.USER,
                        name="_astra_artifact_inventory",
                        content=(
                            "Previously verified file artifacts, grouped by their "
                            "producing tool call. These paths are references only; "
                            "they do not authorize access or mutation.\n"
                            + json.dumps(artifact_inventory, sort_keys=True)
                        ),
                    )
                )
            agent_ctx.metadata["managed_resume"] = True
        if execution_agent_cls.__name__ == "OrchestratorAgent":

            def _checkpoint(
                messages: list[Message], tool_state: dict[str, Any]
            ) -> None:
                runtime["resumable"] = True
                tool_state = dict(tool_state)
                prior_state = runtime.get("tool_state") or {}
                for key in (
                    "recovery_history",
                    "retry_count",
                    "retry_history",
                    "retry_terminal",
                    "replan_count",
                ):
                    if key not in tool_state and key in prior_state:
                        tool_state[key] = prior_state[key]
                if managed_controller is not None:
                    managed_controller.persist_into(tool_state)
                self._persist_tick_state(runtime, messages, tool_state)

            agent_ctx.metadata["managed_checkpoint"] = _checkpoint
            agent_ctx.metadata["managed_completed_steps"] = list(
                (runtime.get("tool_state") or {}).get("completed_steps", [])
            )
            if managed_controller is not None:
                agent_ctx.metadata["managed_mutation_context"] = (
                    managed_controller.context_for
                )
                agent_ctx.metadata["managed_proposal_boundary"] = (
                    managed_controller.authorize_proposal
                )
                agent_ctx.metadata["managed_plan_snapshot"] = (
                    managed_controller.plan_snapshot
                )
                agent_ctx.metadata["managed_mutation_snapshot"] = (
                    managed_controller.snapshot
                )
                agent_ctx.metadata["managed_mutation_result"] = (
                    managed_controller.record_result
                )
                agent_ctx.metadata["managed_mutation_sync"] = (
                    managed_controller.sync_from_journal
                )
                agent_ctx.metadata["managed_advance_step"] = (
                    managed_controller.advance_step
                )
        memory_results = []

        if (
            not has_progress
            and self._system
            and getattr(self._system, "memory_backend", None)
            and getattr(self._system, "config", None)
            and self._system.config.agent.context_from_memory
        ):
            try:
                from openjarvis.tools.storage.context import (
                    ContextConfig,
                    format_context,
                )

                sys_cfg = self._system.config
                ctx_cfg = ContextConfig(
                    top_k=sys_cfg.memory.context_top_k,
                    min_score=sys_cfg.memory.context_min_score,
                    max_context_tokens=sys_cfg.memory.context_max_tokens,
                )
                # Use pending user messages as query, fall back to instruction
                query = ""
                if pending:
                    query = " ".join(m["content"] for m in pending)
                elif instruction:
                    query = instruction

                if query:
                    results = scoped_memory_backend.retrieve(
                        query,
                        top_k=ctx_cfg.top_k,
                    )
                    memory_results = [
                        r for r in results if r.score >= ctx_cfg.min_score
                    ]
                    if memory_results:
                        # Prepend retrieved context to input for agents
                        # that don't inspect AgentContext.memory_results
                        retrieved = format_context(memory_results)
                        input_text = (
                            f"Retrieved context from knowledge base:\n"
                            f"{retrieved}\n\n{input_text}"
                        )
            except Exception:
                pass  # Don't break agent tick if memory retrieval fails

        agent_ctx.memory_results = memory_results
        self._set_activity(agent["id"], "Generating response...")
        logger.info(
            "Agent %s: calling agent.run() with %d chars input",
            agent["name"],
            len(input_text),
        )
        _t0 = time.perf_counter()
        # Host Supply shadow hook: read-only observation, never a dispatch
        # path. No bundle (host_supply None) -> byte-identical legacy tick.
        _host_supply = getattr(self._system, "host_supply", None)
        _shadow_error: BaseException | None = None
        try:
            result = agent_instance.run(input_text, context=agent_ctx)

            # Retry once if the model returned empty content (common with
            # Qwen3.5 thinking mode consuming all tokens).
            if _should_retry_empty_result(result):
                self._set_activity(
                    agent["id"],
                    "Retrying (empty response)...",
                )
                logger.warning(
                    "Agent %s: empty content, retrying once",
                    agent["name"],
                )
                result = agent_instance.run(input_text, context=agent_ctx)
        except BaseException as exc:
            _shadow_error = exc
            raise
        finally:
            resolved_toolkit.close()
            if _host_supply is not None:
                try:
                    from openjarvis.agents.host_supply_factory import (
                        observe_tick,
                    )

                    observe_tick(
                        _host_supply,
                        agent=agent,
                        system=self._system,
                        model=model,
                        engine=getattr(engine, "engine_id", "") or "",
                        result=(
                            None if _shadow_error is not None else result
                        ),
                        error=_shadow_error,
                    )
                except Exception:  # noqa: BLE001 - shadow never stops the tick
                    logger.debug(
                        "Agent %s: shadow observation skipped", agent["name"]
                    )

        _elapsed = time.perf_counter() - _t0
        logger.info(
            "Agent %s: agent.run() completed in %.1fs, "
            "content_len=%d, turns=%d, tokens=%s",
            agent["name"],
            _elapsed,
            len(result.content or ""),
            result.turns,
            result.metadata.get("total_tokens", "?"),
        )
        return result

    def _build_error_detail(self, error: AgentTickError) -> dict[str, Any]:
        """Build structured error detail for trace metadata."""
        import traceback

        from openjarvis.agents.errors import (
            EscalateError,
            FatalError,
            suggest_action,
        )

        if isinstance(error, EscalateError):
            error_type = "escalate"
        elif isinstance(error, FatalError):
            error_type = "fatal"
        else:
            error_type = "retryable"

        return {
            "error_type": error_type,
            "error_message": str(error)[:2000],
            "failure_code": getattr(error, "failure_code", None),
            "retryable": bool(getattr(error, "retryable", False)),
            "escalation_eligible": bool(
                getattr(error, "escalation_eligible", False)
            ),
            "suggested_action": suggest_action(error),
            "stack_trace_summary": "".join(
                traceback.format_exception(type(error), error, error.__traceback__)[-3:]
            )[:1000]
            if error.__traceback__
            else "",
        }

    def _finalize_tick(
        self,
        agent_id: str,
        result: AgentResult | None,
        error: AgentTickError | None,
        duration: float,
    ) -> None:
        """Update agent state after tick completion or failure."""
        self._set_activity(agent_id, "Finalizing...")
        if error is None:
            # Success
            logger.info(
                "Tick succeeded for agent %s in %.1fs, response_len=%d",
                agent_id,
                duration,
                len(result.content or "") if result else 0,
            )
            self._manager.end_tick(agent_id)
            self._manager.update_agent(agent_id, total_runs_increment=1)

            # Accumulate budget metrics from AgentResult metadata
            if result:
                tokens = (
                    result.metadata.get("total_tokens")
                    or result.metadata.get("tokens_used")
                    or 0
                )
                in_tokens = result.metadata.get("prompt_tokens", 0)
                out_tokens = result.metadata.get(
                    "completion_tokens",
                    0,
                )
                cost = result.metadata.get("cost", 0.0)
                budget_kwargs: dict[str, Any] = {"stall_retries": 0}
                if tokens > 0:
                    budget_kwargs["total_tokens_increment"] = tokens
                if in_tokens > 0:
                    budget_kwargs["input_tokens_increment"] = in_tokens
                if out_tokens > 0:
                    budget_kwargs["output_tokens_increment"] = out_tokens
                if cost > 0:
                    budget_kwargs["total_cost_increment"] = cost
                self._manager.update_agent(agent_id, **budget_kwargs)

                # Store the full response. update_summary_memory enforces the
                # rolling-summary cap (_SUMMARY_MAX) itself, and the chat
                # message keeps the complete report. The old [:2000] slices
                # double-truncated and cut findings off mid-sentence.
                self._manager.update_summary_memory(agent_id, result.content)
                self._manager.store_agent_response(
                    agent_id,
                    result.content,
                    tool_calls=_tool_calls_for_storage(result),
                )

            # Budget enforcement (post-tick check)
            agent_data = self._manager.get_agent(agent_id)
            if agent_data:
                config = agent_data.get("config", {})
                max_cost = config.get("max_cost", 0)
                max_tokens = config.get("max_tokens", 0)
                exceeded = False
                if max_cost > 0 and agent_data["total_cost"] > max_cost:
                    exceeded = True
                if max_tokens > 0 and agent_data["total_tokens"] > max_tokens:
                    exceeded = True
                if exceeded:
                    self._manager.update_agent(agent_id, status="budget_exceeded")
                    self._bus.publish(
                        EventType.AGENT_BUDGET_EXCEEDED,
                        {
                            "agent_id": agent_id,
                            "total_cost": agent_data["total_cost"],
                            "total_tokens": agent_data["total_tokens"],
                            "max_cost": max_cost,
                            "max_tokens": max_tokens,
                        },
                    )
            self._bus.publish(
                EventType.AGENT_TICK_END,
                {
                    "agent_id": agent_id,
                    "duration": duration,
                    "status": "ok",
                },
            )
        elif isinstance(error, EscalateError):
            logger.warning(
                "Tick escalated for agent %s after %.1fs: %s",
                agent_id,
                duration,
                error,
            )
            self._manager.end_tick(agent_id)
            self._manager.update_agent(agent_id, status="needs_attention")
            self._bus.publish(
                EventType.AGENT_TICK_ERROR,
                {
                    "agent_id": agent_id,
                    "error": str(error),
                    "error_type": "escalate",
                    "duration": duration,
                },
            )
        else:
            logger.error(
                "Tick failed for agent %s after %.1fs: %s",
                agent_id,
                duration,
                error,
                exc_info=error,
            )
            self._manager.end_tick(agent_id)
            self._manager.update_agent(agent_id, status="error")
            # Write error detail to summary_memory so frontend can display it
            error_msg = str(error)[:2000]
            self._manager.update_summary_memory(agent_id, f"ERROR: {error_msg}")
            self._bus.publish(
                EventType.AGENT_TICK_ERROR,
                {
                    "agent_id": agent_id,
                    "error": str(error),
                    "error_type": (
                        "fatal"
                        if isinstance(error, FatalError)
                        else "retryable_exhausted"
                    ),
                    "duration": duration,
                },
            )

    def _save_trace(
        self,
        agent_id: str,
        agent: dict,
        result: AgentResult | None,
        error: AgentTickError | None,
        tick_start: float,
        tick_duration: float,
        trace_steps: list[dict[str, Any]],
    ) -> None:
        """Persist an execution trace to the trace store."""
        from openjarvis.core.types import StepType, Trace, TraceStep

        steps = []
        for s in trace_steps:
            steps.append(
                TraceStep(
                    step_type=(
                        StepType.TOOL_CALL
                        if s["type"] == "tool_call"
                        else StepType.GENERATE
                    ),
                    input=s.get("input", {}),
                    output=s.get("output", {}),
                    duration_seconds=s.get("duration", 0),
                    timestamp=s.get("start_time", tick_start),
                    metadata=s.get("metadata", {}),
                )
            )

        metadata: dict[str, Any] = {}
        if error is not None:
            metadata["error_detail"] = self._build_error_detail(error)

        outcome = "success" if error is None else "error"
        trace = Trace(
            agent=agent_id,
            query=agent.get("summary_memory", "")[:200],
            result=result.content[:200] if result else "",
            model=agent.get("config", {}).get("model", ""),
            outcome=outcome,
            steps=steps,
            started_at=tick_start,
            ended_at=tick_start + tick_duration,
            total_latency_seconds=tick_duration,
            metadata=metadata,
        )
        try:
            self._trace_store.save(trace)
        except Exception:
            logger.warning(
                "Failed to save trace for agent %s",
                agent_id,
                exc_info=True,
            )
