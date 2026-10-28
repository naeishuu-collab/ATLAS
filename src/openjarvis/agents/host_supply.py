"""Host supply validation for production ticks.

Validates that host-owned privacy/registry/snapshot exist and are fresh
before dispatch. Unknown privacy, stale snapshot, missing registry, and
unresolvable model all fail closed.
"""

from __future__ import annotations

from typing import Any

from openjarvis.agents.host_routing import (
    ModelCardRegistry,
    SnapshotEnvelope,
    assemble_tick_supply,
    bind_tick_supply,
)


class HostSupply:
    """Host-assembled supply bundle validated before dispatch."""

    def __init__(self, supply) -> None:
        self.supply = supply

    @property
    def agent_id(self) -> str:
        return self.supply.agent_id

    @property
    def model(self) -> str:
        return self.supply.model

    @property
    def engine(self) -> str:
        return self.supply.engine

    @property
    def provider(self):
        return self.supply.provider

    @property
    def privacy(self):
        return self.supply.privacy

    @classmethod
    def build(cls, *, agent, system, registry: ModelCardRegistry,
              privacy: Any, snapshot_env: SnapshotEnvelope,
              max_age_s: float, now: float) -> "HostSupply":
        """Build supply from host-owned sources. Fails closed on any gap."""
        supply = assemble_tick_supply(
            agent=agent, system=system, registry=registry,
            privacy=privacy, snapshot_env=snapshot_env,
            max_age_s=max_age_s, now=now,
        )
        return cls(supply)

    def bind(self, *, registry: ModelCardRegistry,
             planner_model: str, need: tuple = ("TEXT",),
             max_age_s: float, now: float) -> None:
        """Re-verify binding at dispatch time. Raises RoutingError on gap."""
        bind_tick_supply(supply=self.supply, registry=registry,
                         planner_model=planner_model, need=need,
                         max_age_s=max_age_s, now=now)


__all__ = [
    "HostSupply",
]
