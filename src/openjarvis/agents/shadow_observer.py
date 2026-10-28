"""ShadowObserver — read-only tick observation for production execute_tick.

Observes a managed-agent tick without changing behavior: no model/provider
selection change, no tool execution change, no journal change, no
UNKNOWN_OUTCOME change, no exactly-once change, no cloud dispatch. On
observation failure the legacy tick is never stopped.

Default posture is OFF: hosts must explicitly enable via feature flag.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List

from openjarvis.agents.host_routing import (
    ModelCardRegistry,
    RoutingError,
    SnapshotEnvelope,
    assemble_tick_supply,
    bind_tick_supply,
    shadow_tick_evaluate,
)

SHADOW_OBSERVER_ENABLED = False  # default OFF; host must opt in


@dataclass(frozen=True)
class ShadowObservation:
    """Read-only record of one observed tick. Never dispatched or mutated."""

    agent_id: str
    model: str
    engine: str
    provider: str | None
    privacy: str
    outcome: str          # selected model / refusal code
    run_status: str = "UNKNOWN"  # SUCCEEDED / FAILED / UNKNOWN
    dispatched: bool = False
    mutations: int = 0
    sealed: bool = False
    refused: bool = False
    reason: str = ""


class ShadowObserver:
    """Host-owned shadow observer for production ticks.

    Wraps assemble_tick_supply + bind_tick_supply + shadow_tick_evaluate so
    the legacy tick path is observed without being altered. All failures
    are recorded as outcome codes; the tick always continues.
    """

    def __init__(self, *, enabled: bool = SHADOW_OBSERVER_ENABLED) -> None:
        self.enabled = enabled
        self.observations: List[ShadowObservation] = []

    def observe(
        self,
        *,
        agent: dict,
        system: Any,
        model: str,
        engine: str,
        provider: str | None,
        result: Any,
        error: BaseException | None = None,
        privacy: Any = "",
        max_age_s: float = 600.0,
        now: float | None = None,
        registry: ModelCardRegistry | None = None,
        snapshot_env: SnapshotEnvelope | None = None,
    ) -> ShadowObservation:
        """Observe one tick. Returns a read-only observation record.

        Never raises: supply/binding failures are captured as outcome codes.
        Never dispatches: dispatched and mutations stay False/0.
        Never mutates the tick: legacy execution is unaffected.
        """
        if not self.enabled:
            return ShadowObservation(
                agent_id=str(agent.get("id", "")),
                model=model,
                engine=engine,
                provider=None,
                privacy=str(privacy),
                outcome="observer_disabled",
                run_status="UNKNOWN",
            )

        agent_id = str(agent.get("id", "") if isinstance(agent, dict) else "")
        run_status = "FAILED" if error is not None else (
            "FAILED"
            if (getattr(result, "metadata", {}) or {}).get("recovery_required")
            else "SUCCEEDED"
            if result is not None
            else "UNKNOWN"
        )
        try:
            if registry is None or snapshot_env is None:
                raise RoutingError("HOST_SUPPLY_UNAVAILABLE",
                                   "host supply is not configured")
            supply = assemble_tick_supply(
                agent=agent, system=system, registry=registry,
                privacy=privacy, snapshot_env=snapshot_env,
                max_age_s=max_age_s, now=now,
            )
            bind_tick_supply(supply, registry, planner_model=supply.model,
                             max_age_s=max_age_s, now=now)
            record = shadow_tick_evaluate(supply, registry,
                                          max_age_s=max_age_s, now=now)
            observation = ShadowObservation(
                agent_id=supply.agent_id,
                model=supply.model,
                engine=supply.engine,
                provider=supply.provider,
                privacy=str(supply.privacy),
                outcome=record["outcome"],
                run_status=run_status,
                dispatched=bool(record.get("dispatched", False)),
                mutations=int(record.get("mutations", 0)),
                reason=(
                    getattr(error, "code", type(error).__name__)
                    if error is not None
                    else ""
                ),
            )
        except Exception as exc:  # noqa: BLE001 - shadow must never stop tick
            observation = ShadowObservation(
                agent_id=agent_id, model=model, engine=engine,
                provider=provider, privacy=str(privacy),
                outcome=getattr(exc, "code", type(exc).__name__),
                run_status=run_status,
                refused=True,
                # Keep exception text/payloads out of the observation record.
                reason=getattr(exc, "code", type(exc).__name__),
            )
        self.observations.append(observation)
        return observation


__all__ = [
    "SHADOW_OBSERVER_ENABLED",
    "ShadowObserver",
    "ShadowObservation",
]
