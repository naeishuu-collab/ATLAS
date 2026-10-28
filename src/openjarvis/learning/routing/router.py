"""Heuristic model router — selects the best model based on query characteristics."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, List, Optional

from openjarvis.core.registry import ModelRegistry
from openjarvis.core.types import RoutingContext
from openjarvis.learning._stubs import QueryAnalyzer, RouterPolicy

logger = logging.getLogger(__name__)


def build_routing_context(
    query: str,
    *,
    urgency: float = 0.5,
    model: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> RoutingContext:
    """Populate a ``RoutingContext`` from a raw query string.

    When *model* is provided, the suggested token budget is adjusted
    for thinking models that need extra headroom.
    """
    from openjarvis.learning.routing.complexity import (
        adjust_tokens_for_model,
        score_complexity,
    )

    result = score_complexity(query)
    tokens = adjust_tokens_for_model(result.suggested_max_tokens, model)

    context_metadata = {
        "complexity_tier": result.tier,
        "signals": result.signals,
    }
    if metadata:
        context_metadata.update(metadata)

    return RoutingContext(
        query=query,
        query_length=len(query),
        has_code=result.signals.get("has_code", False),
        has_math=result.signals.get("has_math", False),
        has_reasoning=result.signals.get("has_reasoning", False),
        urgency=urgency,
        complexity_score=result.score,
        suggested_max_tokens=tokens,
        metadata=context_metadata,
    )


def _model_size(key: str) -> float:
    """Return parameter count for a registered model, or 0 if not found."""
    try:
        spec = ModelRegistry.get(key)
        return spec.parameter_count_b
    except (KeyError, AttributeError) as exc:
        logger.debug("Failed to compute model score: %s", exc)
        return 0.0


def _model_rank(key: str) -> tuple[int, float]:
    """Return the capability rank used when selecting the largest model.

    A positive parameter count is the strongest signal for local models. Cloud
    providers do not publish parameter counts, so their catalog entries use
    ``0.0``; an explicitly cloud-backed model gets a separate higher tier
    instead of being treated as smaller than every known local model. Models
    with unknown non-cloud metadata remain at the lowest tier.
    """
    try:
        spec = ModelRegistry.get(key)
        size = spec.parameter_count_b
        if size > 0:
            return (1, size)
        if "cloud" in spec.supported_engines:
            return (2, 0.0)
    except (KeyError, AttributeError, TypeError) as exc:
        logger.debug("Failed to compute model capability rank: %s", exc)
    return (0, 0.0)


def _find_model_by_tag(available: List[str], tag: str) -> Optional[str]:
    """Find the first available model whose key contains *tag* (case-insensitive)."""
    tag_lower = tag.lower()
    for key in available:
        if tag_lower in key.lower():
            return key
    return None


def _largest_model(available: List[str]) -> Optional[str]:
    """Return the most capable model from the available list."""
    if not available:
        return None
    best = available[0]
    best_rank = _model_rank(best)
    for key in available[1:]:
        rank = _model_rank(key)
        if rank > best_rank:
            best = key
            best_rank = rank
    return best


def _smallest_model(available: List[str]) -> Optional[str]:
    """Return the smallest-parameter model from *available*."""
    if not available:
        return None
    best = available[0]
    best_size = _model_size(best) or float("inf")
    for key in available[1:]:
        size = _model_size(key)
        if 0 < size < best_size:
            best = key
            best_size = size
    return best


class HeuristicRouter(RouterPolicy):
    """Rule-based model router.

    Rules (applied in order):
    1. Code detected → prefer model with "code"/"coder" in name
    2. Low complexity (score <= 0.20) → prefer smaller/faster model
    3. Math detected → prefer larger model
    4. High complexity (score >= 0.55 OR reasoning keywords) → prefer larger model
    5. High urgency (>0.8) → override to smaller model
    6. Default fallback → default_model → fallback_model → first available

    Low complexity is checked before the math check so that simple arithmetic
    ("calculate 2+2") routes to the smallest model instead of always escalating
    on the "math" keyword; math problems above the low-complexity threshold
    still escalate to the larger model.
    """

    def __init__(
        self,
        available_models: List[str] | None = None,
        *,
        default_model: str = "",
        fallback_model: str = "",
    ) -> None:
        self._available = available_models or []
        self._default = default_model
        self._fallback = fallback_model

    @property
    def available_models(self) -> List[str]:
        return list(self._available)

    def select_model(self, context: RoutingContext) -> str:
        available = self._available or list(ModelRegistry.keys())
        if not available:
            return self._default or self._fallback or ""

        # Rule 5: High urgency overrides everything → smallest model
        if context.urgency > 0.8:
            return _smallest_model(available) or available[0]

        # Rule 1: Code detected → prefer model with code/coder in name
        if context.has_code:
            code_model = _find_model_by_tag(available, "code") or _find_model_by_tag(
                available, "coder"
            )
            if code_model:
                return code_model
            # Fall through to larger model for code
            return _largest_model(available) or available[0]

        # Rule 2: Low complexity → prefer smaller model (checked before the math
        # rule so simple arithmetic doesn't escalate to the largest model)
        if context.complexity_score <= 0.20:
            return _smallest_model(available) or available[0]

        # Rule 3: Math detected → prefer larger model
        if context.has_math:
            return _largest_model(available) or available[0]

        # Rule 4: High complexity or reasoning → prefer larger model
        if context.complexity_score >= 0.55 or context.has_reasoning:
            return _largest_model(available) or available[0]

        # Rule 6: Default fallback
        if self._default and self._default in available:
            return self._default
        if self._fallback and self._fallback in available:
            return self._fallback
        return available[0]


class TieredRouter(RouterPolicy):
    """Availability-aware Local → Luna → Terra → Sol router.

    Tier names are configuration labels, not model IDs.  ``tier_models`` may
    map them to provider-specific IDs; unavailable entries are ignored and the
    configured default/fallback or discovered capability order is used.
    """

    def __init__(
        self,
        available_models: List[str] | None = None,
        *,
        default_model: str = "",
        fallback_model: str = "",
        tier_models: Mapping[str, str] | None = None,
    ) -> None:
        self._available = available_models or []
        self._default = default_model
        self._fallback = fallback_model
        self._tiers = {
            str(key).lower(): value.strip()
            for key, value in (tier_models or {}).items()
            if isinstance(key, str) and isinstance(value, str) and value.strip()
        }

    @property
    def available_models(self) -> List[str]:
        return list(self._available)

    def _pick(self, tier: str) -> Optional[str]:
        available = self._available
        configured = self._tiers.get(tier)
        if configured in available:
            return configured
        if tier == "local":
            local = []
            for key in available:
                try:
                    engines = getattr(ModelRegistry.get(key), "supported_engines", ())
                except (KeyError, AttributeError, TypeError):
                    continue
                if engines and "cloud" not in engines:
                    local.append(key)
            return _smallest_model(local) if local else None
        if tier == "luna" and self._default in available:
            return self._default
        if tier == "terra" and self._fallback in available:
            return self._fallback
        if tier == "sol":
            return _largest_model(available)
        return None

    @staticmethod
    def _requested_tier(context: RoutingContext) -> str:
        metadata: dict[str, Any] = context.metadata or {}
        uncertainty = metadata.get("uncertainty", 0.0)
        failure_history = metadata.get("failure_history", 0)
        try:
            uncertainty = float(uncertainty)
        except (TypeError, ValueError):
            uncertainty = 0.0
        try:
            failure_history = int(failure_history)
        except (TypeError, ValueError):
            failure_history = 0

        if (
            context.complexity_score >= 0.8
            or uncertainty >= 0.8
            or failure_history >= 2
        ):
            return "sol"
        if (
            context.complexity_score >= 0.55
            or context.has_code
            or context.has_math
            or context.has_reasoning
        ):
            return "terra"
        if context.complexity_score <= 0.20:
            return "local"
        return "luna"

    def select_model(self, context: RoutingContext) -> str:
        available = self._available or list(ModelRegistry.keys())
        if not available:
            return self._default or self._fallback or ""

        requested = self._requested_tier(context)
        tier_order = ("local", "luna", "terra", "sol")
        start = tier_order.index(requested)
        for tier in tier_order[start:]:
            selected = self._pick(tier)
            if selected:
                return selected
        for tier in reversed(tier_order[:start]):
            selected = self._pick(tier)
            if selected:
                return selected
        return available[0]


class DefaultQueryAnalyzer(QueryAnalyzer):
    """Default query analyzer wrapping the heuristic build_routing_context function."""

    def analyze(self, query: str, **kwargs: object) -> RoutingContext:
        urgency = kwargs.get("urgency", 0.5)
        if not isinstance(urgency, (int, float)):
            urgency = 0.5
        model = kwargs.get("model")
        if not isinstance(model, str):
            model = None
        metadata = kwargs.get("metadata")
        if not isinstance(metadata, Mapping):
            metadata = None
        return build_routing_context(
            query,
            urgency=urgency,
            model=model,
            metadata=metadata,
        )


__all__ = [
    "DefaultQueryAnalyzer",
    "HeuristicRouter",
    "TieredRouter",
    "build_routing_context",
]
