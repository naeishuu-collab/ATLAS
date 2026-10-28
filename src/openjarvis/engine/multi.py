"""Multi-engine wrapper — routes requests to the right backend by model name."""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator, Sequence
from typing import Any, Dict, List

from openjarvis.core.types import Message
from openjarvis.engine._base import InferenceEngine
from openjarvis.engine._stubs import StreamChunk

logger = logging.getLogger(__name__)

#: E7 feature flag. Only the exact value ``"on"`` arms routing checks.
#: Unset / OFF / invalid deny with zero downstream calls.
MULTI_EGRESS_FLAG = "ASTRA_MULTI_EGRESS"
MULTI_EGRESS_ON = "on"


class MultiEngine(InferenceEngine):
    """Wraps multiple engines and routes by model name.

    Models from each engine are discovered via ``list_models()``.
    When ``generate()`` or ``stream()`` is called, the model name
    is looked up to find which engine owns it.
    """

    engine_id = "multi"

    def __init__(self, engines: list[tuple[str, InferenceEngine]]) -> None:
        self._engines = engines
        self._model_map: Dict[str, InferenceEngine] = {}
        self._model_key_map: Dict[str, str] = {}
        self._refresh_map()

    def _refresh_map(self) -> None:
        self._model_map.clear()
        self._model_key_map.clear()
        for key, engine in self._engines:
            try:
                for model_id in engine.list_models():
                    self._model_map[model_id] = engine
                    self._model_key_map[model_id] = key
            except Exception as exc:
                logger.debug("Failed to list models for %s: %s", key, exc)

    _CLOUD_PREFIXES = ("gpt-", "o1-", "o3-", "o4-", "claude-", "gemini-", "openrouter/")

    def _engine_for(self, model: str) -> InferenceEngine:
        """Find the engine that owns a model, refreshing the map once if needed."""
        engine = self._model_map.get(model)
        if engine is not None:
            return engine
        # Refresh and retry (a new model may have been pulled)
        self._refresh_map()
        engine = self._model_map.get(model)
        if engine is not None:
            return engine
        # If model looks like a cloud model, route to the cloud engine
        # rather than falling back to the local engine (which would 404).
        if any(model.startswith(p) for p in self._CLOUD_PREFIXES):
            for key, eng in self._engines:
                if key == "cloud":
                    logger.info("Routing cloud model %r to cloud engine", model)
                    return eng
        # Non-cloud models: do NOT silently fall back to cloud. A transient
        # vLLM outage during a long agentic run would otherwise route every
        # call to cloud, producing confusing "invalid model ID" errors
        # across all tasks.
        raise ValueError(
            f"Model {model!r} not found in any engine "
            f"(known: {', '.join(sorted(self._model_map.keys())) or '<none>'}). "
            f"Check that the expected backend (e.g. vLLM server) is reachable."
        )

    def generate(
        self,
        messages: Sequence[Message],
        *,
        model: str,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        engine = self._verify_routing(model, kwargs)
        return engine.generate(
            messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )

    async def stream(
        self,
        messages: Sequence[Message],
        *,
        model: str,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        engine = self._verify_routing(model, kwargs)
        async for token in engine.stream(
            messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        ):
            yield token

    async def stream_full(
        self,
        messages: Sequence[Message],
        *,
        model: str,
        **kwargs: Any,
    ) -> AsyncIterator["StreamChunk"]:
        """Delegate stream_full() to the engine that owns the model."""
        engine = self._verify_routing(model, kwargs)
        async for chunk in engine.stream_full(messages, model=model, **kwargs):
            yield chunk

    def list_models(self) -> List[str]:
        self._refresh_map()
        return list(self._model_map.keys())

    def engine_key_for(self, model: str) -> str | None:
        """Return the registry key of the engine advertising *model*."""
        key = self._model_key_map.get(model)
        if key is not None:
            return key
        self._refresh_map()
        return self._model_key_map.get(model)

    def _engine_key_of(self, engine: InferenceEngine) -> str | None:
        for key, eng in self._engines:
            if eng is engine:
                return key
        return None

    def _verify_routing(
        self, model: str, kwargs: Dict[str, Any]
    ) -> InferenceEngine:
        """E7 routing gate. Returns the resolved engine or raises.

        Verifies the sealed authorization names THIS multi's resolved
        engine key and model, defeating silent misrouting/fallback. The
        sealed payload is forwarded untouched: the resolved (wired) engine
        owns ledger begin/finish, so no dispatch is double-counted here.
        """
        from openjarvis.security.cloud_dispatch import (
            AuthorizedPayload,
            PrivacyDenied,
        )

        if os.environ.get(MULTI_EGRESS_FLAG, "") != MULTI_EGRESS_ON:
            raise PrivacyDenied("FLAG_OFF", "multi routing enforcement not enabled")
        sealed = kwargs.get("cloud_dispatch")
        if not isinstance(sealed, AuthorizedPayload):
            raise PrivacyDenied("NO_GRANT", "sealed host authorization required")
        resolved = self._engine_for(model)
        key = self._engine_key_of(resolved)
        if key is None or sealed.provider.engine != key:
            raise PrivacyDenied(
                "CLOUD_PROVIDER_NOT_ALLOWED",
                "authorization names a different engine than routing resolved",
            )
        if sealed.provider.model != model:
            raise PrivacyDenied(
                "CLOUD_PAYLOAD_CHANGED",
                "authorized model differs from routed model",
            )
        return resolved

    def health(self) -> bool:
        return any(engine.health() for _key, engine in self._engines)

    def close(self) -> None:
        for _key, engine in self._engines:
            engine.close()


__all__ = ["MultiEngine"]
