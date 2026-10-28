"""Egress guard — adapter-boundary enforcement for cloud LLM dispatch.

Design (adapter-boundary, chosen over caller-by-caller):
- Every cloud-capable ``InferenceEngine`` is wrapped in
  :class:`EgressGuardedEngine`. The wrapper is the single choke point per
  egress: ``generate`` / ``stream`` / ``stream_full`` on a cloud
  destination require a sealed :class:`AuthorizedPayload`; anything else
  is denied fail-closed.
- Local engines pass through untouched (PRIVATE local-only stays local).
- Callers (RLM legacy, Planner/Agent, LLM Tool, CLI/Bench/Serve,
  MultiEngine fallback, Direct Cloud Router) build a
  :class:`CloudDispatchRequest` and mint it via
  :class:`CloudDispatchAuthorizer`. The guard re-verifies the digest at
  send time, so post-authorization mutation and provider swaps are
  rejected even if the caller is compromised.
- No changes to wrapped engines, ``HostLLMBroker``, ``RequestLedger``
  or ``ExecutionJournal``.

Sync ``generate`` and async ``stream``/``stream_full`` enforce the
identical boundary.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Dict, List, Optional

from openjarvis.security.cloud_dispatch import (
    AuthorizedPayload,
    CloudDispatchAuthorizer,
    PrivacyDenied,
)

LOCAL_BYPASS_DENIED = "local engine misclassified as cloud"


class EgressGuardedEngine:
    """Wraps one engine; cloud egress requires sealed authorization."""

    engine_id = "egress-guarded"

    def __init__(
        self,
        inner: Any,
        authorizer: CloudDispatchAuthorizer,
        *,
        engine_name: str = "",
        provider_name: str = "",
        local_allowlist: Optional[frozenset] = None,
    ) -> None:
        self._inner = inner
        self._authorizer = authorizer
        self._engine_name = engine_name or getattr(inner, "engine_id", "unknown")
        self._provider_name = provider_name
        # When set, even local (non-cloud) destinations must present a
        # listed host. Default None preserves passthrough for plain local
        # engines; strict deployments pass their loopback/LAN set to stop
        # a remote endpoint disguised as local.
        self._local_allowlist = (
            frozenset(local_allowlist) if local_allowlist is not None else None
        )
        self.audit_log: List[Dict[str, Any]] = []

    @property
    def is_cloud(self) -> bool:
        return bool(getattr(self._inner, "is_cloud", False))

    @property
    def inner(self) -> Any:
        return self._inner

    # -- sync -----------------------------------------------------------
    def generate(self, messages: Any, *, model: str, **kwargs: Any) -> Dict[str, Any]:
        authorized = kwargs.pop("cloud_dispatch", None)
        endpoint = kwargs.pop("endpoint", None)
        if self.is_cloud:
            payload_dicts = self._message_dicts(messages)
            self._require_authorized(
                authorized, model, payload_dicts, endpoint=endpoint
            )
            if endpoint is not None:
                # Forwarded so the send site can confirm the actual
                # destination. Real engines check this at their POST site;
                # PoC engines assert it in-test.
                kwargs["dispatch_endpoint"] = endpoint
        else:
            self._check_local_destination()
        return self._inner.generate(messages, model=model, **kwargs)

    # -- async ----------------------------------------------------------
    async def stream(
        self, messages: Any, *, model: str, **kwargs: Any
    ) -> AsyncIterator[str]:
        authorized = kwargs.pop("cloud_dispatch", None)
        endpoint = kwargs.pop("endpoint", None)
        if self.is_cloud:
            payload_dicts = self._message_dicts(messages)
            self._require_authorized(
                authorized, model, payload_dicts, endpoint=endpoint
            )
            if endpoint is not None:
                kwargs["dispatch_endpoint"] = endpoint
        else:
            self._check_local_destination()
        async for token in self._inner.stream(messages, model=model, **kwargs):
            yield token

    async def stream_full(
        self, messages: Any, *, model: str, **kwargs: Any
    ) -> AsyncIterator[Any]:
        authorized = kwargs.pop("cloud_dispatch", None)
        endpoint = kwargs.pop("endpoint", None)
        if self.is_cloud:
            payload_dicts = self._message_dicts(messages)
            self._require_authorized(
                authorized, model, payload_dicts, endpoint=endpoint
            )
            if endpoint is not None:
                kwargs["dispatch_endpoint"] = endpoint
        else:
            self._check_local_destination()
        async for chunk in self._inner.stream_full(messages, model=model, **kwargs):
            yield chunk

    def list_models(self) -> List[str]:
        return self._inner.list_models()

    def health(self) -> Any:
        fn = getattr(self._inner, "health", None)
        if callable(fn):
            return fn()
        return {"ok": True}

    # -- internals -------------------------------------------------------
    def dry_run(
        self, messages: Any, *, model: str, **kwargs: Any
    ) -> Dict[str, Any]:
        """Evaluate what enforcement WOULD decide, without dispatching.

        Shadow/rollout observability: returns the ALLOW/DENY decision with
        codes and digest, never calls the inner engine, never transmits.
        A DENY here must never be overridden into a real send.
        """
        authorized = kwargs.pop("cloud_dispatch", None)
        endpoint = kwargs.pop("endpoint", None)
        if not self.is_cloud:
            return {"decision": "PASS_LOCAL", "model": model}
        try:
            payload_dicts = self._message_dicts(messages)
            if not isinstance(authorized, AuthorizedPayload):
                raise PrivacyDenied(
                    "PRIVACY_CLASSIFICATION_REQUIRED",
                    "cloud egress requires sealed authorization",
                )
            if authorized.provider.model != model:
                raise PrivacyDenied(
                    "CLOUD_PAYLOAD_CHANGED",
                    "authorized model differs from dispatch model",
                )
            self._authorizer.verify_for_send(
                authorized, payload_dicts, endpoint=endpoint
            )
        except PrivacyDenied as exc:
            return {
                "decision": "DENY",
                "code": exc.code,
                "model": model,
            }
        return {
            "decision": "ALLOW",
            "model": model,
            "digest": authorized.digest,
            "dispatch_id": authorized.dispatch_id,
        }

    def _check_local_destination(self) -> None:
        if self._local_allowlist is None:
            return
        host = getattr(self._inner, "_host", None) or getattr(
            self._inner, "_default_host", ""
        )
        if str(host).rstrip("/") not in self._local_allowlist:
            raise PrivacyDenied(
                "CLOUD_PROVIDER_NOT_ALLOWED",
                "local destination host is not in the local allowlist; "
                "possible remote endpoint disguised as local",
            )

    def _require_authorized(
        self,
        authorized: Any,
        model: str,
        payload_dicts: List[Dict[str, str]],
        *,
        endpoint: Optional[str] = None,
    ) -> AuthorizedPayload:
        if not isinstance(authorized, AuthorizedPayload):
            raise PrivacyDenied(
                "PRIVACY_CLASSIFICATION_REQUIRED",
                f"cloud egress to {model!r} requires sealed authorization",
            )
        if authorized.provider.model != model:
            raise PrivacyDenied(
                "CLOUD_PAYLOAD_CHANGED",
                "authorized model differs from dispatch model",
            )
        self._authorizer.verify_for_send(
            authorized, payload_dicts, endpoint=endpoint
        )
        self.audit_log.append(
            CloudDispatchAuthorizer.audit_record(authorized, decision="ALLOW")
        )
        return authorized

    @staticmethod
    def _message_dicts(messages: Any) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        for m in messages:
            if isinstance(m, dict):
                out.append(
                    {
                        "role": str(m.get("role", "user")),
                        "content": str(m.get("content", "")),
                    }
                )
            else:
                out.append(
                    {
                        "role": str(getattr(m, "role", "user")),
                        "content": str(getattr(m, "content", "")),
                    }
                )
                # Normalize Enum roles to plain values.
                role = out[-1]["role"]
                if hasattr(m, "role") and hasattr(getattr(m, "role"), "value"):
                    out[-1]["role"] = str(getattr(m.role, "value"))
                _ = role
        return out


def guard_engine(
    inner: Any,
    authorizer: CloudDispatchAuthorizer,
    *,
    engine_name: str = "",
    provider_name: str = "",
    local_allowlist: Optional[frozenset] = None,
) -> EgressGuardedEngine:
    """Wrap *inner* so cloud egress is authorization-gated."""
    if isinstance(inner, EgressGuardedEngine):
        return inner
    return EgressGuardedEngine(
        inner,
        authorizer,
        engine_name=engine_name,
        provider_name=provider_name,
        local_allowlist=local_allowlist,
    )


__all__ = ["EgressGuardedEngine", "LOCAL_BYPASS_DENIED", "guard_engine"]
