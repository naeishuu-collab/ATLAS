"""Deny-only boundary for direct OSS mutation entry points."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True, slots=True)
class DirectMutationDecision:
    """Structured result for an attempted direct SDK invocation."""

    surface: str
    entrypoint: str
    allowed: bool
    failure: str
    dispatched: bool = False
    verified: bool = False
    retryable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "surface": self.surface,
            "entrypoint": self.entrypoint,
            "allowed": self.allowed,
            "failure": self.failure,
            "dispatched": self.dispatched,
            "verified": self.verified,
            "retryable": self.retryable,
        }


class DirectMutationBoundary:
    """Reject direct OSS calls; only the ATLAS host dispatch path may proceed."""

    def __init__(self, surface: str, entrypoints: Iterable[str]) -> None:
        normalized = getattr(surface, "value", surface)
        if not isinstance(normalized, str) or not normalized.strip():
            raise ValueError("BOUNDARY_SURFACE_REQUIRED")
        entries = frozenset(entrypoints)
        if any(not isinstance(item, str) or not item.strip() for item in entries):
            raise ValueError("BOUNDARY_ENTRYPOINT_INVALID")
        self.surface = normalized
        self._entrypoints = entries

    @property
    def entrypoints(self) -> frozenset[str]:
        return self._entrypoints

    def deny(self, entrypoint: str) -> DirectMutationDecision:
        if not isinstance(entrypoint, str) or not entrypoint.strip():
            failure = "DIRECT_ENTRYPOINT_INVALID"
        elif entrypoint not in self._entrypoints:
            failure = "DIRECT_ENTRYPOINT_UNSUPPORTED"
        else:
            failure = "DIRECT_SDK_DISPATCH_DENIED"
        return DirectMutationDecision(
            surface=self.surface,
            entrypoint=entrypoint if isinstance(entrypoint, str) else "",
            allowed=False,
            failure=failure,
        )

    def invoke(
        self,
        entrypoint: str,
        callback: Callable[..., Any] | None = None,
        *_args: Any,
        **_kwargs: Any,
    ) -> DirectMutationDecision:
        """Return denial without evaluating the supplied callback."""

        del callback
        return self.deny(entrypoint)


__all__ = ["DirectMutationBoundary", "DirectMutationDecision"]
