"""Small durable plan state used by managed AgentExecutor runs.

The plan snapshot lives in the AgentManager checkpoint.  Physical mutation
state remains authoritative in ExecutionJournal; this module only records the
controller-owned plan/node relationship and validates its shape.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

PLAN_SCHEMA_VERSION = 2
_LEGACY_PLAN_SCHEMA_VERSION = 1
PLAN_NODE_STATES = frozenset(
    {
        "PLANNED",
        "ACTIVE",
        "COMPLETED",
        "FAILED",
        "BLOCKED",
        "RECONCILIATION_REQUIRED",
        "SUPERSEDED",
    }
)
PLAN_STATES = frozenset(
    {"PLANNED", "ACTIVE", "COMPLETED", "FAILED", "BLOCKED", "RECONCILIATION_REQUIRED"}
)
PLAN_NODE_KINDS = frozenset({"READ_ONLY", "MUTATING"})


def semantic_status_can_advance(saved: str, current: str) -> bool:
    """Allow only journal progress over a stale checkpoint snapshot."""
    if saved == current:
        return True
    if saved in {"AUTHORIZED", "PREPARED", "EXECUTING", "EXECUTED"} and current in {
        "VERIFIED",
        "NOT_EXECUTED",
        "FAILED",
        "UNKNOWN_OUTCOME",
    }:
        return True
    return False


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


@dataclass
class DurablePlanNode:
    """Controller-owned executable node."""

    planner_node_id: str
    kind: str = "MUTATING"
    status: str = "PLANNED"
    dependencies: list[str] = field(default_factory=list)
    mutation_intent_id: str | None = None
    superseded_by: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.planner_node_id, str)
            or not self.planner_node_id.strip()
        ):
            raise ValueError("planner_node_id must be nonempty")
        if self.kind not in PLAN_NODE_KINDS:
            raise ValueError("invalid planner node kind")
        if self.status not in PLAN_NODE_STATES:
            raise ValueError("invalid planner node state")
        if not isinstance(self.dependencies, list) or any(
            not isinstance(item, str) or not item.strip() for item in self.dependencies
        ):
            raise ValueError("planner node dependencies are invalid")
        if len(set(self.dependencies)) != len(self.dependencies):
            raise ValueError("planner node dependencies are duplicated")
        if self.mutation_intent_id is not None and (
            not isinstance(self.mutation_intent_id, str)
            or not self.mutation_intent_id.strip()
        ):
            raise ValueError("mutation_intent_id must be nonempty when present")
        if self.kind == "READ_ONLY" and self.mutation_intent_id is not None:
            raise ValueError("read-only planner node cannot own a mutation intent")
        if self.superseded_by is not None and (
            not isinstance(self.superseded_by, str) or not self.superseded_by.strip()
        ):
            raise ValueError("superseded_by must be nonempty when present")
        if self.status == "SUPERSEDED" and self.superseded_by is None:
            raise ValueError("superseded planner node needs a replacement")

    def to_dict(self) -> dict[str, Any]:
        return {
            "planner_node_id": self.planner_node_id,
            "kind": self.kind,
            "status": self.status,
            "dependencies": list(self.dependencies),
            "mutation_intent_id": self.mutation_intent_id,
            "superseded_by": self.superseded_by,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "DurablePlanNode":
        if not isinstance(raw, dict):
            raise ValueError("planner node must be an object")
        return cls(
            planner_node_id=raw.get("planner_node_id", ""),
            kind=raw.get("kind", ""),
            status=raw.get("status", ""),
            dependencies=list(raw.get("dependencies", [])),
            mutation_intent_id=raw.get("mutation_intent_id"),
            superseded_by=raw.get("superseded_by"),
        )


@dataclass(frozen=True)
class PlanRevision:
    """Immutable controller-owned snapshot of one plan revision."""

    revision_id: str
    parent_revision_id: str | None
    revision: int
    reason: str
    proposal_id: str | None
    nodes: tuple[dict[str, Any], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.revision_id, str) or not self.revision_id.strip():
            raise ValueError("revision_id must be nonempty")
        if self.parent_revision_id is not None and (
            not isinstance(self.parent_revision_id, str)
            or not self.parent_revision_id.strip()
        ):
            raise ValueError("parent_revision_id must be nonempty when present")
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("revision number must be nonnegative")
        if self.reason not in {"INITIAL_PLAN", "REPLAN"}:
            raise ValueError("invalid plan revision reason")
        if self.proposal_id is not None and (
            not isinstance(self.proposal_id, str) or not self.proposal_id.strip()
        ):
            raise ValueError("proposal_id must be nonempty when present")
        if not isinstance(self.nodes, tuple) or any(
            not isinstance(node, dict) for node in self.nodes
        ):
            raise ValueError("plan revision nodes are invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "revision_id": self.revision_id,
            "parent_revision_id": self.parent_revision_id,
            "revision": self.revision,
            "reason": self.reason,
            "proposal_id": self.proposal_id,
            "nodes": [dict(node) for node in self.nodes],
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "PlanRevision":
        if not isinstance(raw, dict):
            raise ValueError("plan revision must be an object")
        raw_nodes = raw.get("nodes", [])
        if not isinstance(raw_nodes, list):
            raise ValueError("plan revision nodes must be a list")
        nodes = tuple(DurablePlanNode.from_dict(node).to_dict() for node in raw_nodes)
        if len({node["planner_node_id"] for node in nodes}) != len(nodes):
            raise ValueError("duplicate planner node identity in plan revision")
        return cls(
            revision_id=raw.get("revision_id", ""),
            parent_revision_id=raw.get("parent_revision_id"),
            revision=raw.get("revision", -1),
            reason=raw.get("reason", ""),
            proposal_id=raw.get("proposal_id"),
            nodes=nodes,
        )


@dataclass
class DurablePlan:
    """Durable controller state for one managed execution."""

    execution_id: str
    plan_id: str
    revision: int = 0
    status: str = "PLANNED"
    nodes: dict[str, DurablePlanNode] = field(default_factory=dict)
    active_node_id: str | None = None
    revision_id: str = ""
    parent_revision_id: str | None = None
    revision_reason: str = "INITIAL_PLAN"
    revision_proposal_id: str | None = None
    revisions: list[PlanRevision] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.execution_id, str) or not self.execution_id.strip():
            raise ValueError("execution_id must be nonempty")
        if not isinstance(self.plan_id, str) or not self.plan_id.strip():
            raise ValueError("plan_id must be nonempty")
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("plan revision must be a nonnegative integer")
        if not self.revision_id:
            self.revision_id = _new_id("revision")
        if self.parent_revision_id is not None and (
            not isinstance(self.parent_revision_id, str)
            or not self.parent_revision_id.strip()
        ):
            raise ValueError("parent_revision_id must be nonempty when present")
        if self.revision_reason not in {"INITIAL_PLAN", "REPLAN"}:
            raise ValueError("invalid current plan revision reason")
        if self.revision_proposal_id is not None and (
            not isinstance(self.revision_proposal_id, str)
            or not self.revision_proposal_id.strip()
        ):
            raise ValueError("revision_proposal_id must be nonempty when present")
        if self.status not in PLAN_STATES:
            raise ValueError("invalid plan state")
        if not isinstance(self.nodes, dict):
            raise ValueError("plan nodes must be an object")
        for key, node in self.nodes.items():
            if key != node.planner_node_id:
                raise ValueError("planner node key disagrees with its identity")
            if any(dependency not in self.nodes for dependency in node.dependencies):
                raise ValueError("planner node dependency is missing")
        if self.active_node_id is not None and self.active_node_id not in self.nodes:
            raise ValueError("active planner node is missing")
        if self.active_node_id is not None and (
            self.nodes[self.active_node_id].status
            not in {"ACTIVE", "RECONCILIATION_REQUIRED"}
        ):
            raise ValueError("active planner node is not active")
        if not isinstance(self.revisions, list):
            raise ValueError("plan revisions must be a list")
        if self.revisions:
            seen: set[str] = set()
            previous: str | None = None
            for revision in self.revisions:
                if revision.revision_id in seen:
                    raise ValueError("duplicate plan revision identity")
                if revision.parent_revision_id != previous:
                    raise ValueError("plan revision parent chain is invalid")
                seen.add(revision.revision_id)
                previous = revision.revision_id
            if self.revisions[-1].revision_id != self.revision_id:
                raise ValueError("current plan revision is not the latest revision")
            latest = self.revisions[-1]
            if (
                latest.parent_revision_id != self.parent_revision_id
                or latest.revision != self.revision
                or latest.reason != self.revision_reason
                or latest.proposal_id != self.revision_proposal_id
            ):
                raise ValueError("current plan revision metadata disagrees")
            current_nodes = {
                node_id: node.to_dict() for node_id, node in self.nodes.items()
            }
            revision_nodes = {
                node["planner_node_id"]: node for node in self.revisions[-1].nodes
            }
            if current_nodes != revision_nodes:
                raise ValueError("current plan disagrees with its latest revision")
        else:
            self.revisions.append(self._current_revision())

    @classmethod
    def create(cls, execution_id: str, plan_id: str | None = None) -> "DurablePlan":
        return cls(
            execution_id=execution_id,
            plan_id=plan_id or _new_id("plan"),
        )

    @classmethod
    def from_dict(cls, raw: Any) -> "DurablePlan":
        if not isinstance(raw, dict):
            raise ValueError("durable plan must be an object")
        schema_version = raw.get("schema_version")
        if schema_version not in {PLAN_SCHEMA_VERSION, _LEGACY_PLAN_SCHEMA_VERSION}:
            raise ValueError("unsupported durable plan schema")
        raw_nodes = raw.get("nodes", [])
        if not isinstance(raw_nodes, list):
            raise ValueError("durable plan nodes must be a list")
        nodes: dict[str, DurablePlanNode] = {}
        for item in raw_nodes:
            node = DurablePlanNode.from_dict(item)
            if node.planner_node_id in nodes:
                raise ValueError("duplicate planner node identity")
            nodes[node.planner_node_id] = node
        plan_id = raw.get("plan_id", "")
        revision_id = raw.get("revision_id") or f"revision-{plan_id}-0"
        raw_revisions = raw.get("revisions")
        if raw_revisions is None:
            revisions = [
                PlanRevision(
                    revision_id=revision_id,
                    parent_revision_id=None,
                    revision=raw.get("revision", 0),
                    reason="INITIAL_PLAN",
                    proposal_id=None,
                    nodes=tuple(node.to_dict() for node in nodes.values()),
                )
            ]
        elif isinstance(raw_revisions, list) and raw_revisions:
            revisions = [PlanRevision.from_dict(item) for item in raw_revisions]
        elif isinstance(raw_revisions, list):
            raise ValueError("plan revisions must not be empty")
        else:
            raise ValueError("plan revisions must be a list")
        return cls(
            execution_id=raw.get("execution_id", ""),
            plan_id=plan_id,
            revision=raw.get("revision", -1),
            status=raw.get("status", ""),
            nodes=nodes,
            active_node_id=raw.get("active_node_id"),
            revision_id=revision_id,
            parent_revision_id=raw.get("parent_revision_id"),
            revision_reason=raw.get("revision_reason", "INITIAL_PLAN"),
            revision_proposal_id=raw.get("revision_proposal_id"),
            revisions=revisions,
        )

    def _current_revision(self) -> PlanRevision:
        return PlanRevision(
            revision_id=self.revision_id,
            parent_revision_id=self.parent_revision_id,
            revision=self.revision,
            reason=self.revision_reason,
            proposal_id=self.revision_proposal_id,
            nodes=tuple(
                self.nodes[node_id].to_dict() for node_id in sorted(self.nodes)
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PLAN_SCHEMA_VERSION,
            "execution_id": self.execution_id,
            "plan_id": self.plan_id,
            "revision": self.revision,
            "revision_id": self.revision_id,
            "parent_revision_id": self.parent_revision_id,
            "revision_reason": self.revision_reason,
            "revision_proposal_id": self.revision_proposal_id,
            "status": self.status,
            "active_node_id": self.active_node_id,
            "nodes": [self.nodes[node_id].to_dict() for node_id in sorted(self.nodes)],
            "revisions": [
                *[
                    revision.to_dict()
                    for revision in self.revisions[:-1]
                ],
                self._current_revision().to_dict(),
            ],
        }

    def append_revision(self, *, reason: str, proposal_id: str) -> None:
        """Commit a new controller-owned revision after future-node changes."""
        if reason != "REPLAN":
            raise ValueError("only REPLAN revisions may be appended")
        if not isinstance(proposal_id, str) or not proposal_id.strip():
            raise ValueError("replan proposal ID must be nonempty")
        parent = self.revision_id
        self.revision_id = _new_id("revision")
        self.parent_revision_id = parent
        self.revision_reason = reason
        self.revision_proposal_id = proposal_id
        self.revisions.append(self._current_revision())

    def capture_current_revision(self) -> None:
        """Persist the latest state into the current revision snapshot."""
        if not self.revisions:
            self.revisions.append(self._current_revision())
        else:
            self.revisions[-1] = self._current_revision()

    def mark_superseded(self, planner_node_id: str, replacement_id: str) -> None:
        if not isinstance(replacement_id, str) or not replacement_id.strip():
            raise ValueError("replacement planner node ID must be nonempty")
        node = self.node(planner_node_id)
        if node is None:
            raise ValueError("planner node is missing")
        if replacement_id in self.nodes:
            raise ValueError("replacement planner node ID is already used")
        if node.status == "COMPLETED":
            raise ValueError("completed planner node cannot be superseded")
        if node.status != "FAILED":
            raise ValueError("only proven NOT_EXECUTED nodes can be superseded")
        if node.superseded_by not in {None, replacement_id}:
            raise ValueError("planner node replacement cannot be changed")
        node.status = "SUPERSEDED"
        node.superseded_by = replacement_id

    def node(self, planner_node_id: str) -> DurablePlanNode | None:
        return self.nodes.get(planner_node_id)

    def add_node(
        self,
        *,
        planner_node_id: str | None = None,
        kind: str = "MUTATING",
        dependencies: list[str] | None = None,
    ) -> DurablePlanNode:
        node_id = planner_node_id or _new_id("node")
        if node_id in self.nodes:
            raise ValueError("planner node ID was already used in this plan")
        deps = list(dependencies or [])
        if any(dep not in self.nodes for dep in deps):
            raise ValueError("planner node dependency is missing")
        node = DurablePlanNode(
            planner_node_id=node_id,
            kind=kind,
            dependencies=deps,
        )
        self.nodes[node_id] = node
        self.revision = max(1, self.revision + 1)
        if self.status == "COMPLETED":
            self.status = "PLANNED"
        return node

    def activate(self, planner_node_id: str) -> DurablePlanNode:
        node = self.nodes.get(planner_node_id)
        if node is None:
            raise ValueError("planner node is missing")
        if self.active_node_id not in {None, planner_node_id}:
            raise ValueError("another planner node is already active")
        if node.status != "PLANNED":
            raise ValueError("only a planned node can become active")
        if any(self.nodes[dep].status != "COMPLETED" for dep in node.dependencies):
            raise ValueError("planner node dependencies are incomplete")
        node.status = "ACTIVE"
        self.active_node_id = planner_node_id
        self.status = "ACTIVE"
        return node

    def bind_intent(self, planner_node_id: str, mutation_intent_id: str) -> None:
        node = self.nodes.get(planner_node_id)
        if node is None:
            raise ValueError("mutation intent needs an existing planner node")
        if node.kind != "MUTATING":
            raise ValueError("read-only planner node cannot bind a mutation intent")
        if not isinstance(mutation_intent_id, str) or not mutation_intent_id.strip():
            raise ValueError("mutation intent ID must be nonempty")
        if node.mutation_intent_id not in {None, mutation_intent_id}:
            raise ValueError("planner node mutation intent cannot be replaced")
        if node.mutation_intent_id == mutation_intent_id:
            return
        if node.status != "ACTIVE":
            raise ValueError("mutation intent needs an active planner node")
        node.mutation_intent_id = mutation_intent_id

    def sync_semantic_status(self, planner_node_id: str, semantic_status: str) -> None:
        node = self.nodes.get(planner_node_id)
        if node is None:
            raise ValueError("semantic step has no planner node")
        if node.status == "SUPERSEDED":
            raise ValueError("superseded planner node cannot receive semantic state")
        if semantic_status == "VERIFIED":
            if node.status == "BLOCKED":
                raise ValueError("blocked planner node cannot become completed")
            node.status = "COMPLETED"
            if self.active_node_id == planner_node_id:
                self.active_node_id = None
        elif semantic_status in {
            "PREPARED",
            "EXECUTING",
            "EXECUTED",
            "UNKNOWN_OUTCOME",
        }:
            if node.status == "COMPLETED":
                raise ValueError(
                    "completed planner node disagrees with semantic journal"
                )
            node.status = "RECONCILIATION_REQUIRED"
            self.active_node_id = planner_node_id
        elif semantic_status == "NOT_EXECUTED":
            if node.status == "COMPLETED":
                raise ValueError("completed planner node was marked not executed")
            node.status = "FAILED"
            if self.active_node_id == planner_node_id:
                self.active_node_id = None
        elif semantic_status == "FAILED":
            if node.status == "COMPLETED":
                raise ValueError("completed planner node failed")
            node.status = "FAILED"
            if self.active_node_id == planner_node_id:
                self.active_node_id = None
        elif semantic_status == "AUTHORIZED":
            if node.status == "COMPLETED":
                raise ValueError("completed planner node was re-authorized")
            node.status = "ACTIVE"
            self.active_node_id = planner_node_id
        else:
            raise ValueError("unsupported semantic intent state")
        self._refresh_status()

    def complete_read_only(self, planner_node_id: str) -> None:
        node = self.nodes.get(planner_node_id)
        if node is None or node.kind != "READ_ONLY" or node.status != "ACTIVE":
            raise ValueError("read-only planner node is not active")
        node.status = "COMPLETED"
        self.active_node_id = None
        self._refresh_status()

    def _refresh_status(self) -> None:
        if any(
            node.status == "RECONCILIATION_REQUIRED" for node in self.nodes.values()
        ):
            self.status = "RECONCILIATION_REQUIRED"
        elif self.nodes and all(
            node.status in {"COMPLETED", "SUPERSEDED"}
            for node in self.nodes.values()
        ):
            self.status = "COMPLETED"
        elif self.active_node_id is not None:
            self.status = "ACTIVE"
        else:
            self.status = "PLANNED"


__all__ = [
    "DurablePlan",
    "DurablePlanNode",
    "PlanRevision",
    "PLAN_NODE_KINDS",
    "PLAN_NODE_STATES",
    "PLAN_SCHEMA_VERSION",
    "PLAN_STATES",
    "semantic_status_can_advance",
]
