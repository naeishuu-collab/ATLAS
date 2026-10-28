"""Capability-based model router — untrusted proposals only.

The router never dispatches. It returns a :class:`RouteDecision`
(candidate ``(engine, model)`` + fallbacks) or a :class:`RouterFailure`
with an explicit code. The host (``CloudDispatchAuthorizer`` +
``EgressGuardedEngine``) makes the final dispatch decision; capability
shortfalls surface as ``MODEL_CAPABILITY_UNAVAILABLE`` instead of a
silent downgrade.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, FrozenSet, List, Optional, Tuple

from openjarvis.security.cloud_dispatch import PrivacyClassification

MODEL_CAPABILITY_UNAVAILABLE = "MODEL_CAPABILITY_UNAVAILABLE"
PRIVACY_ROUTE_UNAVAILABLE = "PRIVACY_ROUTE_UNAVAILABLE"
QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
ALL_PROVIDERS_UNAVAILABLE = "ALL_PROVIDERS_UNAVAILABLE"
BUDGET_EXCEEDED = "BUDGET_EXCEEDED"


class ModelCapability(str, Enum):
    TEXT = "TEXT"
    STRUCTURED_JSON = "STRUCTURED_JSON"
    NATIVE_TOOLS = "NATIVE_TOOLS"
    LONG_CONTEXT = "LONG_CONTEXT"


@dataclass(frozen=True, slots=True)
class ModelCard:
    engine: str
    provider: str
    model: str
    capabilities: FrozenSet[ModelCapability]
    ctx_limit: int
    cost_per_1k: float
    latency_p50_ms: float
    is_cloud: bool = True
    structured_reliability: float = 0.5
    # Tier: 0 local / 1 fast cloud / 2 long-context-multimodal /
    # 3 advanced reasoning-coding / 4 frontier (gated).
    tier: int = 1
    modalities: FrozenSet[str] = frozenset({"text"})

    def key(self) -> Tuple[str, str, str]:
        return (self.engine, self.provider, self.model)


@dataclass(frozen=True, slots=True)
class RouteRequest:
    difficulty: str  # trivial | standard | hard | critical
    need: FrozenSet[ModelCapability]
    privacy: PrivacyClassification
    est_prompt_tokens: int
    max_tokens: int = 1024
    cost_budget_usd: Optional[float] = None
    latency_budget_ms: Optional[int] = None
    preferred: Optional[Tuple[str, str]] = None
    uncertainty: float = 0.0  # 0..1 model confidence gap; high forces escalation
    modality: str = "text"
    frontier_allowed: bool = False  # tier-4 models require explicit opt-in


@dataclass(frozen=True, slots=True)
class ProviderSnapshot:
    available: Dict[Tuple[str, str, str], bool]
    quota_left: Dict[str, float] = field(default_factory=dict)
    latency_p50_ms: Dict[Tuple[str, str, str], float] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RouteDecision:
    engine: str
    model: str
    reason: str
    fallback: Tuple[Tuple[str, str], ...] = ()
    escalated: bool = False


@dataclass(frozen=True, slots=True)
class RouterFailure:
    code: str
    reason: str
    retryable: bool = False
    escalation_eligible: bool = True


class RouterGateError(ValueError):
    """A capability shortfall surfaced as a planning-time refusal.

    Hosts pass ``CapabilityRouter.gate(...)`` as ``model_gate`` to
    ``AgentExecutor.plan_goal``; raising here stops planning before any
    model contact, with the checkpoint untouched. The router still owns
    no dispatch, mutation, or authority-minting power.
    """

    def __init__(self, failure: RouterFailure) -> None:
        super().__init__(f"{failure.code}: {failure.reason}")
        self.code = failure.code
        self.reason = failure.reason


_DIFFICULTY_RANK = {"trivial": 0, "standard": 1, "hard": 2, "critical": 3}


class CapabilityRouter:
    """Selects among registered model cards. No dispatch power."""

    def __init__(self, cards: List[ModelCard]) -> None:
        self._cards = list(cards)

    def gate(
        self, req: RouteRequest, snapshot: ProviderSnapshot
    ) -> "Callable[[], None]":
        """Return a ``plan_goal`` model gate for one routing decision.

        The gate re-runs ``propose`` at the planning boundary (model
        availability is time-varying) and raises :class:`RouterGateError`
        on shortfall; on success it is a no-op. It never dispatches,
        mutates, or mints authority of any kind.
        """
        outcome = self.propose(req, snapshot)
        if isinstance(outcome, RouterFailure):
            def _closed() -> None:
                raise RouterGateError(outcome)

            return _closed

        def _open() -> None:
            return None

        return _open

    def propose(
        self, req: RouteRequest, snapshot: ProviderSnapshot
    ) -> RouteDecision | RouterFailure:
        pool = [c for c in self._cards if snapshot.available.get(c.key(), False)]
        if not pool:
            return RouterFailure(
                code=ALL_PROVIDERS_UNAVAILABLE,
                reason="no provider reports available",
                escalation_eligible=False,
            )
        # Privacy: PRIVATE is local-only.
        if req.privacy == PrivacyClassification.PRIVATE:
            pool = [c for c in pool if not c.is_cloud]
            if not pool:
                return RouterFailure(
                    code=PRIVACY_ROUTE_UNAVAILABLE,
                    reason="PRIVATE data has no available local model",
                )
        # Capability filter (hard gate — never silently downgrade).
        capable = [c for c in pool if req.need <= set(c.capabilities)]
        if not capable:
            return RouterFailure(
                code=MODEL_CAPABILITY_UNAVAILABLE,
                reason=(
                    f"no available model satisfies "
                    f"{sorted(n.value for n in req.need)}"
                ),
            )
        # Modality + frontier gates.
        capable = [c for c in capable if req.modality in c.modalities]
        if not capable:
            return RouterFailure(
                code=MODEL_CAPABILITY_UNAVAILABLE,
                reason=f"no available model supports modality {req.modality!r}",
            )
        if not req.frontier_allowed:
            capable = [c for c in capable if c.tier < 4]
            if not capable:
                return RouterFailure(
                    code=MODEL_CAPABILITY_UNAVAILABLE,
                    reason="only frontier-tier models satisfy the request "
                    "and frontier use was not allowed",
                )
        # Token/context budget.
        fitting = [
            c
            for c in capable
            if req.est_prompt_tokens + req.max_tokens <= c.ctx_limit
        ]
        if not fitting:
            return RouterFailure(
                code=MODEL_CAPABILITY_UNAVAILABLE,
                reason="prompt exceeds all capable models' context",
            )
        # Cost budget + quota.
        affordable = [
            c
            for c in fitting
            if req.cost_budget_usd is None
            or c.cost_per_1k * (req.est_prompt_tokens + req.max_tokens) / 1000
            <= req.cost_budget_usd
        ]
        if not affordable:
            return RouterFailure(
                code=BUDGET_EXCEEDED,
                reason="no capable model fits the cost budget",
                escalation_eligible=True,
            )
        blocked = [
            c
            for c in affordable
            if snapshot.quota_left.get(c.provider, float("inf")) <= 0
        ]
        selectable = [c for c in affordable if c not in blocked]
        if not selectable:
            return RouterFailure(
                code=QUOTA_EXHAUSTED, reason="all capable providers report no quota"
            )
        # Latency budget (soft: prefer, drop only if nothing fits and
        # alternatives exist — never fail when a capable model exists but
        # is slow unless caller demands it via difficulty escalation).
        if req.latency_budget_ms is not None:
            fast = [
                c
                for c in selectable
                if snapshot.latency_p50_ms.get(c.key(), c.latency_p50_ms)
                <= req.latency_budget_ms
            ]
            if fast:
                selectable = fast
        # Rank: structured reliability for JSON needs, then cost, then latency.
        def rank(c: ModelCard) -> Tuple[float, float, float]:
            struct = (
                -c.structured_reliability
                if ModelCapability.STRUCTURED_JSON in req.need
                else 0.0
            )
            lat = snapshot.latency_p50_ms.get(c.key(), c.latency_p50_ms)
            return (struct, c.cost_per_1k, lat)

        ordered = sorted(selectable, key=rank)
        # Explicit escalation: hard/critical difficulty or high uncertainty
        # prefers the most capable tier over the cheapest option.
        escalated = False
        if _DIFFICULTY_RANK.get(req.difficulty, 1) >= 2 or req.uncertainty >= 0.7:
            by_power = sorted(
                ordered,
                key=lambda c: (
                    -c.tier,
                    -len(c.capabilities),
                    -c.structured_reliability,
                ),
            )
            if by_power[0] != ordered[0]:
                escalated = True
            ordered = by_power
        elif req.difficulty == "trivial" and len(ordered) > 1:
            # Trivial work stays on the lowest capable tier (usually local).
            ordered = sorted(
                ordered,
                key=lambda c: (
                    c.tier,
                    snapshot.latency_p50_ms.get(c.key(), c.latency_p50_ms),
                ),
            )
        top = ordered[0]
        fallbacks = tuple((c.engine, c.model) for c in ordered[1:3])
        return RouteDecision(
            engine=top.engine,
            model=top.model,
            reason=(
                f"capability_match={[n.value for n in req.need]} "
                f"ctx_ok cost_ok privacy={req.privacy.value}"
                + (" escalated" if escalated else "")
            ),
            fallback=fallbacks,
            escalated=escalated,
        )


__all__ = [
    "ALL_PROVIDERS_UNAVAILABLE",
    "BUDGET_EXCEEDED",
    "CapabilityRouter",
    "MODEL_CAPABILITY_UNAVAILABLE",
    "ModelCapability",
    "ModelCard",
    "PRIVACY_ROUTE_UNAVAILABLE",
    "QUOTA_EXHAUSTED",
    "RouteDecision",
    "RouteRequest",
    "ProviderSnapshot",
    "RouterFailure",
    "RouterGateError",
]
