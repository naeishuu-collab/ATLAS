"""LiteLLM inference engine — unified access to 100+ LLM providers."""

from __future__ import annotations

import logging
import math
import os
import threading
from collections.abc import AsyncIterator, Sequence
from typing import Any, Dict, List

from openjarvis.core.registry import EngineRegistry
from openjarvis.core.types import Message
from openjarvis.engine._base import InferenceEngine, messages_to_dicts
from openjarvis.security.cloud_dispatch import PrivacyDenied

logger = logging.getLogger(__name__)

#: E5 feature flag. Only the exact value ``"on"`` arms enforcement.
#: Unset / OFF / invalid deny with zero SDK calls. OFF never restores
#: unguarded sending.
LITELLM_EGRESS_FLAG = "ASTRA_LITELLM_EGRESS"
LITELLM_EGRESS_ON = "on"

#: Finite cloud timeout (seconds). No infinite hang; timeouts quarantine as
#: UNKNOWN_OUTCOME (never silent retry). Configurable via ctor/env.
LITELLM_TIMEOUT_ENV = "ASTRA_LITELLM_TIMEOUT_S"
DEFAULT_LITELLM_TIMEOUT_S = 60.0


def _resolve_timeout(value: Any) -> float:
    """Return a finite positive timeout; fall back to env/default."""
    if isinstance(value, (int, float)) and math.isfinite(value) and value > 0:
        return float(value)
    try:
        env = float(os.environ.get(LITELLM_TIMEOUT_ENV, ""))
        if env == env and 0 < env < float("inf"):
            return env
    except (TypeError, ValueError):
        pass
    return DEFAULT_LITELLM_TIMEOUT_S


@EngineRegistry.register("litellm")
class LiteLLMEngine(InferenceEngine):
    """Inference via LiteLLM — routes to any supported provider.

    LiteLLM normalizes all providers (OpenAI, Anthropic, Google, DeepSeek,
    Groq, Together, Fireworks, OpenRouter, Mistral, Cohere, xAI, Perplexity,
    etc.) to OpenAI-format input/output.  Model selection uses LiteLLM's
    ``provider/model`` convention, e.g. ``anthropic/claude-sonnet-4-20250514``.

    API keys are read from environment variables following each provider's
    convention (OPENAI_API_KEY, ANTHROPIC_API_KEY, GROQ_API_KEY, etc.).
    """

    engine_id = "litellm"
    is_cloud = True

    def __init__(
        self,
        *,
        api_base: str | None = None,
        default_model: str | None = None,
        authorizer: Any = None,
        dispatch_ledger: Any = None,
        session_id: str = "",
        timeout: float | None = None,
    ) -> None:
        self._api_base = api_base
        self._default_model = default_model
        self._timeout = _resolve_timeout(timeout)
        # Host-issued enforcement machinery (E5). Never taken from callers.
        self._authorizer = authorizer
        self._dispatch_ledger = dispatch_ledger
        self._session_id = session_id
        self._seen_nonces: set = set()
        self._nonce_lock = threading.Lock()

    def _enforce(
        self, messages: Sequence[Message], model: str, kwargs: Dict[str, Any]
    ) -> Any:
        """E5 enforcement gate. Returns (entry, ledger, sealed) or raises.

        NOTE (NOT PROVEN): the litellm SDK owns the final HTTP transport;
        there is no injection seam. This gate verifies the authorized
        semantic payload and destination *before* the SDK call, but the
        SDK's internal wire transformation is unverified.
        """
        from openjarvis.security.cloud_dispatch import (
            ENDPOINT_NOT_ALLOWED,
            NONCE_REPLAY,
            SESSION_MISMATCH,
            AuthorizedPayload,
            PrivacyDenied,
        )
        from openjarvis.security.dispatch_ledger import CloudDispatchLedger

        if os.environ.get(LITELLM_EGRESS_FLAG, "") != LITELLM_EGRESS_ON:
            raise PrivacyDenied("FLAG_OFF", "litellm egress enforcement not enabled")
        sealed = kwargs.pop("cloud_dispatch", None)
        cancel_event = kwargs.pop("cancel_event", None)
        if not isinstance(sealed, AuthorizedPayload):
            raise PrivacyDenied("NO_GRANT", "sealed host authorization required")
        if sealed.grant.expired():
            raise PrivacyDenied("GRANT_EXPIRED", "capability grant has expired")
        provider = sealed.provider
        # Exact full-model-string match: "openrouter/x" and "anthropic/x"
        # are distinct allowlist keys, defeating provider confusion.
        if provider.engine != "litellm" or provider.model != model:
            raise PrivacyDenied(
                "CLOUD_PROVIDER_NOT_ALLOWED",
                "authorization is not bound to this litellm model",
            )
        expected_endpoint = (self._api_base or "").rstrip("/")
        if (provider.endpoint or "").rstrip("/") != expected_endpoint:
            raise PrivacyDenied(
                ENDPOINT_NOT_ALLOWED, "authorized endpoint differs"
            )
        if (sealed.session_id or self._session_id) and (
            sealed.session_id != self._session_id
        ):
            raise PrivacyDenied(SESSION_MISMATCH, "session identity mismatch")
        if sealed.nonce:
            with self._nonce_lock:
                if sealed.nonce in self._seen_nonces:
                    raise PrivacyDenied(NONCE_REPLAY, "nonce already dispatched")
                self._seen_nonces.add(sealed.nonce)
        if self._authorizer is None:
            raise PrivacyDenied(
                "CLOUD_PROVIDER_NOT_ALLOWED", "host authorizer not configured"
            )
        semantic = [
            {"role": str(m.get("role", "user")), "content": str(m.get("content", ""))}
            for m in messages_to_dicts(messages)
        ]
        self._authorizer.verify_for_send(
            sealed, semantic, endpoint=provider.endpoint or None
        )
        ledger = self._dispatch_ledger or CloudDispatchLedger()
        try:
            entry = ledger.begin(sealed)
        except Exception as exc:
            raise PrivacyDenied(
                "CLOUD_PAYLOAD_CHANGED", f"duplicate dispatch: {exc}"
            ) from exc
        ledger.mark_dispatched(entry)
        if cancel_event is not None and cancel_event.is_set():
            ledger.cancel(entry)
            raise PrivacyDenied("CANCELLED", "cancelled before send")
        return entry, ledger, sealed

    def generate(
        self,
        messages: Sequence[Message],
        *,
        model: str,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        _entry, _ledger, _sealed = self._enforce(messages, model, kwargs)
        import litellm

        call_kwargs: Dict[str, Any] = {
            "model": model,
            "messages": messages_to_dicts(messages),
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if self._api_base:
            call_kwargs["api_base"] = self._api_base
        # Pass through tools if provided
        if "tools" in kwargs:
            call_kwargs["tools"] = kwargs.pop("tools")
        call_kwargs.update(kwargs)
        # P0-7: single-send is a security invariant, not a caller option.
        # The litellm OpenAI handler defaults to max_retries=2 (up to 3
        # invisible HTTP sends per logical call; transport-proven). Set
        # authoritatively AFTER caller kwargs so no caller can re-arm it.
        call_kwargs["max_retries"] = 0
        # Finite timeout, same invariant: a caller value wins only if it is
        # finite and positive, otherwise the engine default applies. A
        # timeout after dispatch is UNKNOWN_OUTCOME (quarantined below).
        call_kwargs["timeout"] = _resolve_timeout(
            kwargs.pop("timeout", self._timeout)
        )

        try:
            resp = litellm.completion(**call_kwargs)
        except Exception:
            # SDK transport outcome is uncertain (no seam): quarantine.
            try:
                _ledger.mark_unknown(_entry)
            except Exception:
                pass
            raise

        choice = resp.choices[0]
        usage = resp.usage
        prompt_tokens = usage.prompt_tokens if usage else 0
        completion_tokens = usage.completion_tokens if usage else 0

        result: Dict[str, Any] = {
            "content": choice.message.content or "",
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": (usage.total_tokens if usage else 0),
            },
            "model": resp.model,
            "finish_reason": choice.finish_reason or "stop",
        }

        # Extract tool_calls in flat format (id, name, arguments)
        if hasattr(choice.message, "tool_calls") and choice.message.tool_calls:
            result["tool_calls"] = [
                {
                    "id": tc.id,
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                }
                for tc in choice.message.tool_calls
            ]

        # Cost tracking via litellm's built-in cost calculation
        try:
            cost = litellm.completion_cost(completion_response=resp)
            result["cost_usd"] = cost
        except Exception as exc:
            logger.debug("Failed to compute cost for LiteLLM call: %s", exc)
            result["cost_usd"] = 0.0

        try:
            _ledger.check_send(_entry, _sealed)
            _ledger.finish(_entry, "EXECUTED")
        except PrivacyDenied:
            raise
        except Exception:
            try:
                _ledger.mark_unknown(_entry)
            except Exception:
                pass
            raise PrivacyDenied(
                "CLOUD_PAYLOAD_CHANGED", "send verification failed; quarantined"
            )
        if not isinstance(result.get("content"), str):
            try:
                _ledger.mark_unknown(_entry)
            except Exception:
                pass
            raise PrivacyDenied(
                "CLOUD_PAYLOAD_CHANGED", "response verification failed; quarantined"
            )

        return result

    async def stream(
        self,
        messages: Sequence[Message],
        *,
        model: str,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> AsyncIterator[str]:
        import litellm

        _entry, _ledger, _sealed = self._enforce(messages, model, kwargs)
        call_kwargs: Dict[str, Any] = {
            "model": model,
            "messages": messages_to_dicts(messages),
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }
        if self._api_base:
            call_kwargs["api_base"] = self._api_base
        call_kwargs.update(kwargs)
        # P0-7: see generate() — authoritative single-send.
        call_kwargs["max_retries"] = 0
        call_kwargs["timeout"] = _resolve_timeout(
            kwargs.pop("timeout", self._timeout)
        )

        # ``acompletion`` + ``async for``: the sync ``litellm.completion`` used
        # before made a blocking network call (and blocking per-chunk reads)
        # inside this ``async def``, stalling the whole event loop between
        # tokens — the same bug the httpx engines' streaming paths had.
        try:
            resp = await litellm.acompletion(**call_kwargs)
        except Exception:
            try:
                _ledger.mark_unknown(_entry)
            except Exception:
                pass
            raise
        completed = False
        try:
            async for chunk in resp:
                delta = chunk.choices[0].delta if chunk.choices else None
                if delta and delta.content:
                    yield delta.content
            completed = True
            _ledger.check_send(_entry, _sealed)
            _ledger.finish(_entry, "EXECUTED")
        except PrivacyDenied:
            raise
        except GeneratorExit:
            try:
                _ledger.mark_unknown(_entry)
            except Exception:
                pass
            raise
        except Exception:
            try:
                if completed:
                    _ledger.mark_unknown(_entry)
                else:
                    _ledger.note_partial_response(_entry)
            except Exception:
                pass
            raise

    def list_models(self) -> List[str]:
        if self._default_model:
            return [self._default_model]
        return []

    def health(self) -> bool:
        try:
            import litellm  # noqa: F401

            return True
        except ImportError:
            return False


__all__ = ["LiteLLMEngine"]
