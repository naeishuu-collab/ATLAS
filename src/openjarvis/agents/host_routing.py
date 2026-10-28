"""Host-owned routing foundation: cards, snapshots, binding, escalation.

Wraps :mod:`openjarvis.agents.capability_router` (a parallel workstream;
imported but never modified here) with host-side construction and
verification. Nothing here dispatches, grants, or mutates: helpers
return data or raise :class:`RoutingError`; the managed runtime
(``plan_goal``/``model_gate``) stays the only execution authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Tuple

from openjarvis.agents.capability_router import (
    CapabilityRouter,
    ModelCapability,
    ModelCard,
    ProviderSnapshot,
    RouteDecision,
    RouteRequest,
    RouterFailure,
)
from openjarvis.security.cloud_dispatch import PrivacyClassification

UNKNOWN_CAPABILITY = "UNKNOWN_CAPABILITY"
SNAPSHOT_STALE = "SNAPSHOT_STALE"
PRIVACY_UNKNOWN = "PRIVACY_UNKNOWN"
BINDING_MISMATCH = "BINDING_MISMATCH"
MODEL_BINDING_UNVERIFIED = "MODEL_BINDING_UNVERIFIED"
PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
PRIVACY_BLOCKED = "PRIVACY_BLOCKED"
LOCAL_ACCEPTED = "LOCAL_ACCEPTED"
ESCALATION_ALLOWED = "ESCALATION_ALLOWED"
HUMAN_CONFIRMATION_REQUIRED = "HUMAN_CONFIRMATION_REQUIRED"
REGISTRY_EMPTY = "REGISTRY_EMPTY"
ENFORCE_BLOCKED = "ENFORCE_BLOCKED"
EGRESS_ALLOWED = "EGRESS_ALLOWED"
HOST_POLICY_DENIED = "HOST_POLICY_DENIED"
MINIMIZER_REQUIRED = "MINIMIZER_REQUIRED"
CREDENTIAL_REDACTION_REQUIRED = "CREDENTIAL_REDACTION_REQUIRED"


class RoutingError(ValueError):
    """Host routing refusal with a machine-readable code."""

    def __init__(self, code: str, reason: str = "") -> None:
        super().__init__(f"{code}: {reason}" if reason else code)
        self.code = code
        self.reason = reason


def _capability(name: Any) -> ModelCapability:
    try:
        return ModelCapability(str(name).strip().upper())
    except ValueError:
        raise RoutingError(UNKNOWN_CAPABILITY, f"unknown capability {name!r}")


def _model_card(raw: Dict[str, Any]) -> ModelCard:
    try:
        return ModelCard(
            engine=str(raw["engine"]),
            provider=str(raw["provider"]),
            model=str(raw["model"]),
            capabilities=frozenset(_capability(c)
                                   for c in raw["capabilities"]),
            ctx_limit=int(raw["ctx_limit"]),
            cost_per_1k=float(raw["cost_per_1k"]),
            latency_p50_ms=float(raw["latency_p50_ms"]),
            is_cloud=bool(raw.get("is_cloud", True)),
            structured_reliability=float(
                raw.get("structured_reliability", 0.5)),
            tier=int(raw.get("tier", 1)),
            modalities=frozenset(raw.get("modalities", ("text",))),
        )
    except KeyError as exc:
        raise RoutingError(UNKNOWN_CAPABILITY, f"missing card field {exc}")


@dataclass(frozen=True)
class ModelCardRegistry:
    """Host-built card set. Cards are fixed at construction; updates mean
    building a new registry from new host config (host-managed op only).
    """

    cards: Tuple[ModelCard, ...] = ()

    @classmethod
    def from_host_config(cls, raw_cards: list) -> "ModelCardRegistry":
        return cls(cards=tuple(_model_card(c) for c in raw_cards))

    def router(self) -> CapabilityRouter:
        return CapabilityRouter(list(self.cards))

    def gate(self, req: RouteRequest, env: "SnapshotEnvelope", *,
             max_age_s: float, now: float) -> Callable[[], None]:
        """Freshness-checked gate for ``plan_goal(model_gate=...)``.

        Raises :class:`RoutingError` (stale snapshot or capability
        shortfall) before any model contact; on success returns the
        router's boundary gate, which re-validates at planning time.
        """
        env.require_fresh(max_age_s=max_age_s, now=now)
        outcome = self.router().propose(req, env.snapshot)
        if isinstance(outcome, RouterFailure):
            raise RoutingError(outcome.code, outcome.reason)
        return self.router().gate(req, env.snapshot)


@dataclass(frozen=True)
class SnapshotEnvelope:
    """Immutable per-decision snapshot with issuance metadata."""

    version: int
    issued_at: float
    snapshot: ProviderSnapshot = field(
        default_factory=lambda: ProviderSnapshot(available={}))

    def fresh(self, *, max_age_s: float, now: float) -> bool:
        return 0 <= now - self.issued_at <= max_age_s

    def require_fresh(self, *, max_age_s: float, now: float) -> None:
        if not self.fresh(max_age_s=max_age_s, now=now):
            raise RoutingError(SNAPSHOT_STALE,
                               f"snapshot v{self.version} expired")


def build_snapshot(status: Dict[Tuple[str, str, str], bool], *,
                   version: int, issued_at: float,
                   quota: Dict[str, float] | None = None
                   ) -> SnapshotEnvelope:
    """Build an envelope from fake-provider status. Only explicit True
    counts as available; unknown or False states stay unavailable."""
    return SnapshotEnvelope(
        version=version,
        issued_at=issued_at,
        snapshot=ProviderSnapshot(
            available={k: bool(v) for k, v in status.items()},
            quota_left=dict(quota or {}),
        ),
    )


def classify_privacy(value: Any) -> PrivacyClassification:
    """Resolve a host-supplied label; unknown/empty fails closed and
    never downgrades to PUBLIC."""
    try:
        return PrivacyClassification(str(value).strip().upper())
    except ValueError:
        raise RoutingError(PRIVACY_UNKNOWN, f"unknown privacy {value!r}")


def privacy_from_agent(agent: Dict[str, Any]) -> PrivacyClassification:
    """Read the host-owned privacy label from an agent's config.

    The managed-agent config is free-form host JSON, so no schema
    migration is needed: hosts set ``config["privacy"]`` and unlabeled
    agents fail closed (never default PUBLIC, never send raw private
    observations to cloud models).
    """
    config = agent.get("config", {}) if isinstance(agent, dict) else {}
    return classify_privacy(config.get("privacy", ""))


def bind_decision(decision: RouteDecision | RouterFailure,
                  cards: Tuple[ModelCard, ...], *,
                  planner_model: str, host_engine: str | None) -> None:
    """Verify the router's choice against the actual planner/engine.

    Model ID alone never implies provider identity: exactly one registry
    card must match (engine, model), otherwise the binding is unverified
    and planning defers. Raises :class:`RoutingError` on any mismatch.
    """
    if isinstance(decision, RouterFailure):
        raise RoutingError(decision.code, decision.reason)
    if not planner_model or planner_model != decision.model:
        raise RoutingError(BINDING_MISMATCH,
                           f"{planner_model!r} != {decision.model!r}")
    if host_engine is not None and host_engine != decision.engine:
        raise RoutingError(BINDING_MISMATCH,
                           f"{host_engine!r} != {decision.engine!r}")
    matches = [c for c in cards
               if c.engine == decision.engine and c.model == decision.model]
    if len(matches) != 1:
        raise RoutingError(MODEL_BINDING_UNVERIFIED,
                           f"{len(matches)} cards for "
                           f"{decision.engine}/{decision.model}")


def gate_or_none(registry: ModelCardRegistry, req: RouteRequest,
                 env: SnapshotEnvelope, *, enforce: bool,
                 max_age_s: float, now: float) -> Callable[[], None] | None:
    """Feature flag: enforced mode returns the routing gate; OFF keeps
    the legacy gateless planning path byte-for-byte."""
    if not enforce:
        return None
    return registry.gate(req, env, max_age_s=max_age_s, now=now)


def shadow_evaluate(registry: ModelCardRegistry, req: RouteRequest,
                    env: SnapshotEnvelope) -> RouteDecision | RouterFailure:
    """Observe routing without side effects: pure propose, no planner,
    no journal, no tools. Mutation count stays zero by construction."""
    return registry.router().propose(req, env.snapshot)


_FAILURE_STATES = {
    "MODEL_CAPABILITY_UNAVAILABLE": "MODEL_CAPABILITY_UNAVAILABLE",
    "ALL_PROVIDERS_UNAVAILABLE": PROVIDER_UNAVAILABLE,
    "QUOTA_EXHAUSTED": PROVIDER_UNAVAILABLE,
    "PRIVACY_ROUTE_UNAVAILABLE": PRIVACY_BLOCKED,
    "BUDGET_EXCEEDED": "BUDGET_EXCEEDED",
}


@dataclass(frozen=True)
class TickSupply:
    """Host-assembled routing inputs for one production tick.

    Every field comes from host-owned sources (agent config, system
    object, host registry/snapshot/privacy label). The tick path
    carries no provider identity, so ``provider`` stays None and
    provider binding relies on registry uniqueness at bind time.
    """

    agent_id: str
    model: str
    engine: str
    provider: str | None
    privacy: PrivacyClassification
    snapshot: SnapshotEnvelope


def _engine_name(system: Any) -> str:
    engine = getattr(system, "engine", None)
    if engine is None:
        return ""
    return (getattr(engine, "engine_id", None)
            or getattr(engine, "name", None)
            or type(engine).__name__)


def assemble_tick_supply(*, agent: Dict[str, Any], system: Any,
                         registry: ModelCardRegistry, privacy: Any,
                         snapshot_env: SnapshotEnvelope,
                         max_age_s: float, now: float) -> TickSupply:
    """Assemble the supply bundle from host-owned sources only.

    Unknown or missing values fail closed: empty registry, stale
    snapshot, unknown privacy, and unresolvable model each raise
    :class:`RoutingError` before anything is evaluated or dispatched.
    """
    from openjarvis.agents.executor import _resolve_tick_model

    if not registry.cards:
        raise RoutingError(REGISTRY_EMPTY, "host registry has no cards")
    snapshot_env.require_fresh(max_age_s=max_age_s, now=now)
    classification = classify_privacy(privacy)
    config = agent.get("config", {}) if isinstance(agent, dict) else {}
    model = _resolve_tick_model(config, system)
    if not model:
        raise RoutingError(MODEL_BINDING_UNVERIFIED, "no tick model")
    agent_id = agent.get("id", "") if isinstance(agent, dict) else ""
    if not agent_id:
        raise RoutingError(MODEL_BINDING_UNVERIFIED, "no agent identity")
    return TickSupply(
        agent_id=str(agent_id),
        model=model,
        engine=_engine_name(system),
        provider=None,
        privacy=classification,
        snapshot=snapshot_env,
    )


def _supply_request(supply: TickSupply,
                    need: tuple = ("TEXT",)) -> RouteRequest:
    return RouteRequest(
        difficulty="standard",
        need=frozenset(_capability(n) for n in need),
        privacy=supply.privacy,
        est_prompt_tokens=0,
    )


def bind_tick_supply(supply: TickSupply, registry: ModelCardRegistry, *,
                     planner_model: str, need: tuple = ("TEXT",),
                     max_age_s: float, now: float) -> None:
    """Bind a tick supply against the registry and planner identity.

    Freshness, capability decision, model/engine match, and provider
    uniqueness are all enforced; any gap raises :class:`RoutingError`
    and the tick must defer without dispatching.
    """
    supply.snapshot.require_fresh(max_age_s=max_age_s, now=now)
    outcome = registry.router().propose(
        _supply_request(supply, need), supply.snapshot.snapshot)
    bind_decision(outcome, registry.cards, planner_model=planner_model,
                  host_engine=supply.engine or None)


def shadow_tick_evaluate(supply: TickSupply, registry: ModelCardRegistry, *,
                         need: tuple = ("TEXT",),
                         max_age_s: float = 600.0,
                         now: float | None = None) -> Dict[str, Any]:
    """Observe routing for one tick without side effects.

    Never raises, never dispatches, never touches tools or the network:
    every refusal is recorded as an outcome code. ``dispatched`` and
    ``mutations`` stay False/0 by construction.
    """
    try:
        supply.snapshot.require_fresh(
            max_age_s=max_age_s,
            now=supply.snapshot.issued_at if now is None else now)
        outcome = registry.router().propose(
            _supply_request(supply, need), supply.snapshot.snapshot)
        rendered = (outcome.model if isinstance(outcome, RouteDecision)
                    else outcome.code)
    except RoutingError as exc:
        rendered = exc.code
    return {"agent_id": supply.agent_id, "outcome": rendered,
            "dispatched": False, "mutations": 0}


def require_enforce(*, agent: Dict[str, Any], system: Any,
                    registry: ModelCardRegistry, privacy: Any,
                    snapshot_env: SnapshotEnvelope,
                    max_age_s: float, now: float) -> Callable[[], None]:
    """Return the enforce gate only when every precondition holds.

    Registry, freshness, privacy, model/engine binding, and the routing
    decision are all verified first; the first gap raises
    ENFORCE_BLOCKED (cause preserved in the reason) instead of a gate.
    Default posture stays OFF: callers that never call this keep the
    legacy gateless path byte-for-byte.
    """
    try:
        supply = assemble_tick_supply(
            agent=agent, system=system, registry=registry, privacy=privacy,
            snapshot_env=snapshot_env, max_age_s=max_age_s, now=now)
        bind_tick_supply(supply, registry, planner_model=supply.model,
                         max_age_s=max_age_s, now=now)
        return registry.gate(_supply_request(supply), supply.snapshot,
                             max_age_s=max_age_s, now=now)
    except RoutingError as exc:
        raise RoutingError(ENFORCE_BLOCKED, f"{exc.code}: {exc.reason}")


def snapshot_from_engine(engine: Any, registry: ModelCardRegistry, *,
                         version: int, issued_at: float) -> SnapshotEnvelope:
    """Build an availability envelope from an engine listing.

    Only models the engine reports are marked available; listing
    failure marks everything unavailable. No provider API is called.
    """
    try:
        listed = engine.list_models()
    except Exception:
        listed = []
    names = {m.strip() for m in listed
             if isinstance(m, str) and m.strip()} if isinstance(
                 listed, list) else set()
    return SnapshotEnvelope(
        version=version,
        issued_at=issued_at,
        snapshot=ProviderSnapshot(
            available={c.key(): True for c in registry.cards
                       if c.model in names},
        ),
    )


def escalation_state(code: str, *, tier: int = 1,
                     human_approved: bool = False,
                     local: bool = False) -> str:
    """Map a routing outcome to one confidence state. Frontier-tier use
    without explicit human approval suspends to HUMAN_CONFIRMATION_REQUIRED;
    silent downgrade is never an outcome (failures pass through as codes).
    """
    if code in _FAILURE_STATES:
        return _FAILURE_STATES[code]
    if tier >= 4 and not human_approved:
        return HUMAN_CONFIRMATION_REQUIRED
    if local or code == LOCAL_ACCEPTED:
        return LOCAL_ACCEPTED
    return ESCALATION_ALLOWED


@dataclass(frozen=True)
class HostEgressPolicy:
    """Explicit host transmission policy for cloud egress.

    PRIVATE ignores this policy (local-only always). INTERNAL cloud
    requires ``allow_cloud`` plus provider allowlisting plus minimized
    payload (or an explicit raw override). This gates routing approval
    only — dispatch still needs the capability policy, which is never
    bypassed.
    """

    allow_cloud: bool = False
    allowed_providers: Tuple[str, ...] = ()
    allow_raw_internal: bool = False
    version: int = 1


@dataclass(frozen=True)
class EgressDecision:
    """Audit evidence for one egress authorization."""

    allowed: bool
    code: str
    reason: str = ""
    privacy: PrivacyClassification | None = None
    destination: Tuple[str, str, str] | None = None


def authorize_egress(*, registry: ModelCardRegistry,
                     policy: HostEgressPolicy, privacy: Any,
                     provider: str, engine: str, model: str,
                     has_minimizer: bool = False,
                     contains_credentials: bool = False,
                     available: bool = True) -> EgressDecision:
    """Authorize one cloud/local payload transmission.

    Privacy contract: PUBLIC is cloud-eligible; INTERNAL needs explicit
    host transmission approval; PRIVATE is local-only; unknown privacy
    never downgrades. Destination must match exactly one registry card;
    credentials to cloud are denied until redacted. No provider is
    contacted; no payload is inspected beyond the caller's flags.
    """
    try:
        classification = classify_privacy(privacy)
    except RoutingError:
        return EgressDecision(False, PRIVACY_UNKNOWN)
    matches = [c for c in registry.cards
               if (c.engine, c.provider, c.model) == (engine, provider,
                                                      model)]
    dest = (engine, provider, model)
    if len(matches) != 1:
        return EgressDecision(False, MODEL_BINDING_UNVERIFIED,
                              f"{len(matches)} cards", classification, dest)
    card = matches[0]
    if not available:
        return EgressDecision(False, PROVIDER_UNAVAILABLE,
                              "not available", classification, dest)
    if card.is_cloud and contains_credentials:
        return EgressDecision(False, CREDENTIAL_REDACTION_REQUIRED,
                              "redact first", classification, dest)
    if not card.is_cloud:
        return EgressDecision(True, EGRESS_ALLOWED, "local",
                              classification, dest)
    if classification == PrivacyClassification.PRIVATE:
        return EgressDecision(False, PRIVACY_BLOCKED, "local-only",
                              classification, dest)
    if classification == PrivacyClassification.INTERNAL:
        if not policy.allow_cloud or provider not in policy.allowed_providers:
            return EgressDecision(False, HOST_POLICY_DENIED,
                                  "no transmission approval",
                                  classification, dest)
        if not has_minimizer and not policy.allow_raw_internal:
            return EgressDecision(False, MINIMIZER_REQUIRED,
                                  "minimize first", classification, dest)
    return EgressDecision(True, EGRESS_ALLOWED, "cloud",
                          classification, dest)


__all__ = [
    "BINDING_MISMATCH",
    "CREDENTIAL_REDACTION_REQUIRED",
    "EGRESS_ALLOWED",
    "ENFORCE_BLOCKED",
    "ESCALATION_ALLOWED",
    "HOST_POLICY_DENIED",
    "HUMAN_CONFIRMATION_REQUIRED",
    "LOCAL_ACCEPTED",
    "MINIMIZER_REQUIRED",
    "MODEL_BINDING_UNVERIFIED",
    "PRIVACY_BLOCKED",
    "PRIVACY_UNKNOWN",
    "PROVIDER_UNAVAILABLE",
    "REGISTRY_EMPTY",
    "SNAPSHOT_STALE",
    "UNKNOWN_CAPABILITY",
    "EgressDecision",
    "HostEgressPolicy",
    "ModelCardRegistry",
    "RoutingError",
    "SnapshotEnvelope",
    "assemble_tick_supply",
    "authorize_egress",
    "bind_decision",
    "bind_tick_supply",
    "build_snapshot",
    "classify_privacy",
    "escalation_state",
    "gate_or_none",
    "privacy_from_agent",
    "require_enforce",
    "shadow_evaluate",
    "shadow_tick_evaluate",
    "snapshot_from_engine",
]
