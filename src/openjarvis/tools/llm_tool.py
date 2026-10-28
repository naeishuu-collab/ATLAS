"""LLM tool — delegate a sub-query to an inference engine.

E1 enforcement: cloud egress through this tool requires an explicitly
enabled feature flag (``ASTRA_LLM_TOOL_EGRESS=on``) AND a sealed
``AuthorizedPayload`` minted by the host. Every other case fails closed
with zero transport calls and no raw-engine fallback.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from openjarvis.core.registry import ToolRegistry
from openjarvis.core.types import Message, Role, ToolResult
from openjarvis.engine._stubs import InferenceEngine
from openjarvis.tools._stubs import BaseTool, ToolSpec

#: Feature flag. Only the exact value ``"on"`` arms the enforced path.
#: Unset / OFF / invalid all deny. OFF never restores unguarded sending.
LLM_TOOL_EGRESS_FLAG = "ASTRA_LLM_TOOL_EGRESS"
LLM_TOOL_EGRESS_ON = "on"


def _deny(code: str, reason: str) -> ToolResult:
    return ToolResult(
        tool_name="llm",
        content=f"EGRESS_DENIED:{code}: {reason}",
        success=False,
    )


@ToolRegistry.register("llm")
class LLMTool(BaseTool):
    """Delegate a sub-query to an inference engine for generation."""

    tool_id = "llm"

    def __init__(
        self,
        engine: Optional[InferenceEngine] = None,
        *,
        model: str = "",
        provider: str = "",
        endpoint: str = "",
        authorizer: Any = None,
        dispatch_ledger: Any = None,
        session_id: str = "",
    ) -> None:
        self._engine = engine
        self._model = model
        # Expected destination binding. Empty means "must match an equally
        # unbound authorization" (local/test use); cloud use configures both.
        self._provider = provider
        self._endpoint = endpoint
        # Host-issued authorization machinery. Never accepted from call params.
        self._authorizer = authorizer
        self._ledger = dispatch_ledger
        self._session_id = session_id
        self._seen_request_ids: set = set()

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="llm",
            description=(
                "Send a prompt to a language model."
                " Useful for sub-queries or summarization."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "prompt": {
                        "type": "string",
                        "description": "The prompt to send to the language model.",
                    },
                    "system": {
                        "type": "string",
                        "description": "Optional system message to set context.",
                    },
                },
                "required": ["prompt"],
            },
            category="inference",
        )

    def execute(self, **params: Any) -> ToolResult:
        if self._engine is None:
            return ToolResult(
                tool_name="llm",
                content="No inference engine configured.",
                success=False,
            )
        if not self._model:
            return ToolResult(
                tool_name="llm",
                content="No model configured.",
                success=False,
            )
        prompt = params.get("prompt", "")
        if not prompt:
            return ToolResult(
                tool_name="llm",
                content="No prompt provided.",
                success=False,
            )
        messages = []
        system = params.get("system")
        if system:
            messages.append(Message(role=Role.SYSTEM, content=system))
        messages.append(Message(role=Role.USER, content=prompt))
        # -- E1 enforcement boundary (default-DENY, no raw fallback) ----
        return self._execute_guarded(messages, params)

    def _execute_guarded(self, messages: list, params: dict) -> ToolResult:
        from openjarvis.security.cloud_dispatch import (
            AuthorizedPayload,
            PrivacyDenied,
        )
        from openjarvis.security.dispatch_ledger import CloudDispatchLedger
        from openjarvis.security.egress_guard import guard_engine

        if os.environ.get(LLM_TOOL_EGRESS_FLAG, "") != LLM_TOOL_EGRESS_ON:
            return _deny("FLAG_OFF", "egress enforcement is not enabled")
        # Sealed payloads arrive via host wiring: the host caller (never the
        # model) attaches the grant it minted as `cloud_dispatch`. Everything
        # about it is re-verified below (binding, digest, ledger).
        sealed = params.get("cloud_dispatch")
        if not isinstance(sealed, AuthorizedPayload):
            return _deny("NO_GRANT", "sealed host authorization is required")
        if sealed.grant.expired():
            return _deny("GRANT_EXPIRED", "capability grant has expired")
        # Destination binding: tool configuration vs sealed authorization.
        if sealed.provider.model != self._model:
            return _deny("MODEL_MISMATCH", "authorized model differs")
        if self._provider and sealed.provider.provider != self._provider:
            return _deny("PROVIDER_MISMATCH", "authorized provider differs")
        if self._endpoint and sealed.provider.endpoint != self._endpoint:
            return _deny("ENDPOINT_MISMATCH", "authorized endpoint differs")
        if self._authorizer is None:
            return _deny("NO_AUTHORIZER", "host authorizer is not configured")
        # Session binding + exactly-once intent (duplicate request ids deny).
        if self._session_id:
            if params.get("session_id", self._session_id) != self._session_id:
                return _deny("SESSION_MISMATCH", "session identity mismatch")
        request_id = params.get("request_id")
        if request_id is not None:
            if request_id in self._seen_request_ids:
                return _deny("DUPLICATE", "request id already dispatched")
            self._seen_request_ids.add(request_id)
        # Built messages must equal the authorized (minimized) content.
        built = [
            {"role": self._role_of(m), "content": str(m.content)} for m in messages
        ]
        if list(sealed.redacted_messages) != built:
            return _deny("PAYLOAD_MISMATCH", "request differs from authorization")
        ledger = self._ledger or CloudDispatchLedger()
        try:
            entry = ledger.begin(sealed)
        except Exception:
            return _deny("DUPLICATE", "dispatch already begun")
        ledger.mark_dispatched(entry)
        if params.get("cancel"):
            ledger.cancel(entry)
            return _deny("CANCELLED", "cancelled before send")
        guarded = guard_engine(self._engine, self._authorizer)
        try:
            result = guarded.generate(
                messages,
                model=self._model,
                cloud_dispatch=sealed,
                **({"endpoint": self._endpoint} if self._endpoint else {}),
            )
        except PrivacyDenied as exc:
            # Guard refused before any transport call: deterministic failure.
            try:
                ledger.finish(entry, "FAILED", code=exc.code)
            except Exception:
                pass
            return _deny(exc.code, "guard refused dispatch")
        except TimeoutError:
            ledger.mark_unknown(entry)
            return _deny("UNKNOWN_OUTCOME", "provider timeout; quarantined")
        except Exception:
            # Uncertain whether bytes left: quarantine, never blind-retry.
            try:
                ledger.mark_unknown(entry)
            except Exception:
                pass
            return _deny("UNKNOWN_OUTCOME", "uncertain failure; quarantined")
        try:
            ledger.check_send(entry, sealed)
        except Exception:
            # Binding drift after a real send: outcome is uncertain.
            try:
                ledger.mark_unknown(entry)
            except Exception:
                pass
            return _deny("INTEGRITY", "send verification failed; quarantined")
        content = result.get("content", "") if isinstance(result, dict) else None
        if not isinstance(content, str):
            # Provider returned an unverifiable response shape.
            try:
                ledger.mark_unknown(entry)
            except Exception:
                pass
            return _deny("INTEGRITY", "response verification failed; quarantined")
        ledger.finish(entry, "EXECUTED")
        return ToolResult(
            tool_name="llm",
            content=content,
            success=True,
            usage=result.get("usage", {}),
        )

    @staticmethod
    def _role_of(message: Any) -> str:
        role = getattr(message, "role", "user")
        return str(getattr(role, "value", role))


__all__ = ["LLMTool"]
