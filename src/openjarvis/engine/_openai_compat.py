"""Shared base for OpenAI-compatible ``/v1/`` engines."""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import AsyncIterator, Sequence
from typing import Any, Dict, List

import httpx

from openjarvis.core.types import Message
from openjarvis.engine._base import (
    EngineConnectionError,
    EngineContextLengthError,
    InferenceEngine,
    estimate_prompt_tokens,
    messages_to_dicts,
)
from openjarvis.engine._http_async import (
    AsyncHTTPEngineMixin,
)
from openjarvis.engine._stubs import StreamChunk
from openjarvis.intelligence.model_catalog import resolve_model_id_for_engine
from openjarvis.security.cloud_dispatch import PrivacyDenied

logger = logging.getLogger(__name__)

#: E4 feature flag. Only the exact value ``"on"`` arms enforcement.
#: Unset / OFF / invalid deny with zero transport calls. OFF never
#: restores unguarded sending.
COMPAT_EGRESS_FLAG = "ASTRA_COMPAT_EGRESS"
COMPAT_EGRESS_ON = "on"


class _OpenAICompatibleEngine(AsyncHTTPEngineMixin, InferenceEngine):
    """Base for engines that serve the OpenAI ``/v1/chat/completions`` API."""

    # vLLM/SGLang report context-window overflows in 400 bodies; the shared
    # ``_raise_stream_http_error`` types those as ``EngineContextLengthError``.
    _stream_400_signals_context_length = True

    engine_id: str = ""
    _default_host: str = "http://localhost:8000"
    _api_prefix: str = "/v1"

    def __init__(
        self,
        host: str | None = None,
        *,
        api_key: str | None = None,
        timeout: float = 600.0,
        authorizer: Any = None,
        dispatch_ledger: Any = None,
        session_id: str = "",
    ) -> None:
        import os

        # Sanitize the engine id for env-var lookup ("openai-compat" ->
        # "OPENAI_COMPAT_..."); shells cannot set hyphenated variable names.
        env_prefix = self.engine_id.upper().replace("-", "_")
        self._host = (
            host or os.environ.get(f"{env_prefix}_HOST") or self._default_host
        ).rstrip("/")
        # Bearer auth for endpoints started with e.g. ``vllm serve --api-key``.
        # Setting it on the client covers generate/stream/stream_full/
        # list_models/health alike; ``None`` keeps requests header-free.
        self._api_key = api_key or os.environ.get(f"{env_prefix}_API_KEY") or None
        headers = (
            {"Authorization": f"Bearer {self._api_key}"} if self._api_key else None
        )
        # Used by the shared async streaming plumbing (AsyncHTTPEngineMixin) so
        # the bounded request timeout is applied to streaming reads, not just
        # the synchronous methods (a wedged token read fails at ``timeout``
        # rather than hanging the caller for the httpx default).
        self._timeout = timeout
        self._headers = headers
        # Injection seam for tests: an ``httpx.MockTransport`` swapped in here lets
        # the async stream path be exercised with a mocked transport and no real
        # server. ``None`` in production so httpx uses its default networking.
        self._async_transport: httpx.AsyncBaseTransport | None = None
        self._client = httpx.Client(
            base_url=self._host, timeout=timeout, headers=headers
        )
        # Host-issued enforcement machinery (E4). Never taken from callers.
        self._authorizer = authorizer
        self._dispatch_ledger = dispatch_ledger
        self._session_id = session_id
        self._seen_nonces: set = set()
        self._nonce_lock = threading.Lock()

    # -- InferenceEngine interface ------------------------------------------

    def _resolve_model_id(self, model: str) -> str:
        return resolve_model_id_for_engine(model, self.engine_id)

    def _enforce(
        self, messages: Sequence[Message], model: str, kwargs: Dict[str, Any]
    ) -> Any:
        """E4 enforcement gate. Returns (entry, ledger, sealed) or raises."""
        from openjarvis.security.cloud_dispatch import (
            ENDPOINT_NOT_ALLOWED,
            NONCE_REPLAY,
            SESSION_MISMATCH,
            AuthorizedPayload,
            PrivacyDenied,
        )
        from openjarvis.security.dispatch_ledger import CloudDispatchLedger

        if os.environ.get(COMPAT_EGRESS_FLAG, "") != COMPAT_EGRESS_ON:
            raise PrivacyDenied("FLAG_OFF", "compat egress enforcement not enabled")
        sealed = kwargs.pop("cloud_dispatch", None)
        cancel_event = kwargs.pop("cancel_event", None)
        if not isinstance(sealed, AuthorizedPayload):
            raise PrivacyDenied("NO_GRANT", "sealed host authorization required")
        if sealed.grant.expired():
            raise PrivacyDenied("GRANT_EXPIRED", "capability grant has expired")
        provider = sealed.provider
        if (
            provider.engine != self.engine_id
            or provider.provider != self.engine_id
            or provider.model != model
        ):
            raise PrivacyDenied(
                "CLOUD_PROVIDER_NOT_ALLOWED",
                "authorization is not bound to this compat destination",
            )
        if not provider.endpoint or provider.endpoint.rstrip(
            "/"
        ) != self._host.rstrip("/"):
            raise PrivacyDenied(
                ENDPOINT_NOT_ALLOWED, "authorized endpoint differs from engine host"
            )
        if (sealed.session_id or getattr(self, "_session_id", "")) and (
            sealed.session_id != getattr(self, "_session_id", "")
        ):
            raise PrivacyDenied(SESSION_MISMATCH, "session identity mismatch")
        if sealed.nonce:
            lock = getattr(self, "_nonce_lock", None)
            seen = getattr(self, "_seen_nonces", None)
            if lock is None or seen is None:
                raise PrivacyDenied(
                    "CLOUD_PROVIDER_NOT_ALLOWED",
                    "engine enforcement state not initialized",
                )
            with lock:
                if sealed.nonce in seen:
                    raise PrivacyDenied(NONCE_REPLAY, "nonce already dispatched")
                seen.add(sealed.nonce)
        authorizer = getattr(self, "_authorizer", None)
        if authorizer is None:
            raise PrivacyDenied(
                "CLOUD_PROVIDER_NOT_ALLOWED", "host authorizer not configured"
            )
        semantic = [
            {"role": str(m.get("role", "user")), "content": str(m.get("content", ""))}
            for m in messages_to_dicts(messages)
        ]
        authorizer.verify_for_send(
            sealed, semantic, endpoint=provider.endpoint
        )
        ledger = getattr(self, "_dispatch_ledger", None) or CloudDispatchLedger()
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
        from openjarvis.security.dispatch_ledger import (
            CODE_CONNECTION_FAILURE,
        )

        _entry, _ledger, _sealed = self._enforce(messages, model, kwargs)
        payload: Dict[str, Any] = {
            "model": self._resolve_model_id(model),
            "messages": messages_to_dicts(messages),
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
            **kwargs,
        }
        # Default to tool_choice=auto when tools are provided
        if "tools" in payload and "tool_choice" not in payload:
            payload["tool_choice"] = "auto"
        try:
            url = f"{self._api_prefix}/chat/completions"
            resp = self._client.post(url, json=payload)
            if resp.status_code == 400 and "tools" in payload:
                # Envelope-only retry (tools stripped, messages identical):
                # allowed at most once per dispatch, only after the provider
                # explicitly rejected the first attempt, and only with the
                # sealed digest re-verified over the unchanged messages.
                # A rejected attempt had no effect, so this is a continuation
                # of one logical dispatch — not a blind retry. Any further
                # resend needs a fresh authorization.
                if _entry.attempts >= 1:
                    raise PrivacyDenied(
                        "CLOUD_PAYLOAD_CHANGED",
                        "retry budget exhausted; re-authorize",
                    )
                self._authorizer.verify_for_send(
                    _sealed,
                    [
                        {
                            "role": str(m.get("role", "user")),
                            "content": str(m.get("content", "")),
                        }
                        for m in messages_to_dicts(messages)
                    ],
                    endpoint=_sealed.provider.endpoint,
                )
                _entry.attempts += 1
                payload.pop("tools", None)
                payload.pop("tool_choice", None)
                resp = self._client.post(url, json=payload)
            resp.raise_for_status()
        except httpx.ConnectError as exc:
            _ledger.finish(_entry, "FAILED", code=CODE_CONNECTION_FAILURE)
            raise EngineConnectionError(
                f"{self.engine_id} engine not reachable at {self._host}"
            ) from exc
        except httpx.TimeoutException as exc:
            _ledger.mark_unknown(_entry)
            raise EngineConnectionError(
                f"{self.engine_id} engine not reachable at {self._host}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            _ledger.finish(_entry, "FAILED", code="PROVIDER_HTTP_ERROR")
            error_detail = exc.response.text.strip()
            if exc.response.status_code == 404:
                detail_suffix = (
                    f" Response body: {error_detail}" if error_detail else ""
                )
                raise EngineConnectionError(
                    f"{self.engine_id} engine at {self._host} returned 404 for "
                    f"{self._api_prefix}/chat/completions. Make sure this port "
                    "is running an OpenAI-compatible chat server, not another "
                    f"local web service.{detail_suffix}"
                ) from exc
            detail_suffix = f": {error_detail}" if error_detail else ""
            raise EngineConnectionError(
                f"{self.engine_id} engine at {self._host} returned HTTP "
                f"{exc.response.status_code}{detail_suffix}"
            ) from exc
        data = resp.json()
        choices = data.get("choices", [])
        if not choices:
            _ledger.finish(_entry, "FAILED", code="PROVIDER_RESPONSE_INVALID")
            return {
                "content": "",
                "usage": data.get("usage", {}),
                "model": data.get("model", model),
                "finish_reason": "error",
            }
        choice = choices[0]
        usage = data.get("usage", {})
        # Ensure prompt_tokens reflects the full prompt size (including
        # system prompt and all conversation history).
        # OpenAI-compat APIs (vLLM, SGLang) report full counts — KV
        # caching is transparent, so evaluated == full.
        reported_prompt = usage.get("prompt_tokens", 0)
        estimated_prompt = estimate_prompt_tokens(messages)
        prompt_tokens = max(reported_prompt, estimated_prompt)
        completion_tokens = usage.get("completion_tokens", 0)
        result: Dict[str, Any] = {
            "content": choice["message"].get("content") or "",
            "usage": {
                "prompt_tokens": prompt_tokens,
                "prompt_tokens_evaluated": reported_prompt or prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
            "model": data.get("model", model),
            "finish_reason": choice.get("finish_reason", "stop"),
        }
        # Extract tool calls if present
        raw_tool_calls = choice["message"].get("tool_calls", [])
        if raw_tool_calls:
            result["tool_calls"] = [
                {
                    "id": tc.get("id", ""),
                    "name": tc.get("function", {}).get("name", ""),
                    "arguments": tc.get("function", {}).get("arguments", "{}"),
                }
                for tc in raw_tool_calls
            ]
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
        from openjarvis.security.dispatch_ledger import (
            CODE_CONNECTION_FAILURE,
        )

        _entry, _ledger, _sealed = self._enforce(messages, model, kwargs)
        payload: Dict[str, Any] = {
            "model": self._resolve_model_id(model),
            "messages": messages_to_dicts(messages),
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
            **kwargs,
        }
        # Default to tool_choice=auto when tools are provided
        if "tools" in payload and "tool_choice" not in payload:
            payload["tool_choice"] = "auto"
        url = f"{self._api_prefix}/chat/completions"
        stream_complete = False
        try:
            # ASYNC streaming: ``httpx.AsyncClient`` + ``aiter_lines`` never
            # blocks the event loop between tokens (the previous SYNC
            # ``httpx.Client`` + ``iter_lines`` inside this ``async def`` blocked
            # the single uvicorn worker on every inter-token wait, serializing all
            # concurrent chats and letting one wedged read freeze the whole API).
            # The shared client keeps pooled connections across turns.
            client = self._get_async_client()
            async with client.stream("POST", url, json=payload) as resp:
                # ``not is_success`` covers 3xx as well as 4xx/5xx. With
                # ``follow_redirects`` off (the default) an unexpected redirect
                # would otherwise fall through to ``aiter_lines`` and surface as
                # a silent EMPTY stream instead of a clean engine error.
                if not resp.is_success:
                    # Load the (short) error body before touching ``.text``:
                    # a streaming response is otherwise unread.
                    await resp.aread()
                    self._raise_stream_http_error(resp.status_code, resp.text)
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data_str = line[len("data:") :].strip()
                    if data_str == "[DONE]":
                        stream_complete = True
                        break
                    try:
                        chunk = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue
                    delta = chunk.get("choices", [{}])[0].get("delta", {})
                    content = delta.get("content")
                    if content:
                        yield content
            if stream_complete:
                _ledger.finish(_entry, "EXECUTED")
            else:
                _ledger.note_partial_response(_entry)
        except EngineConnectionError:
            # Provider-responded errors from _raise_stream_http_error.
            try:
                _ledger.finish(_entry, "FAILED", code="PROVIDER_HTTP_ERROR")
            except Exception:
                pass
            raise
        except httpx.HTTPStatusError as exc:
            _ledger.finish(_entry, "FAILED", code="PROVIDER_HTTP_ERROR")
            raise EngineConnectionError(
                f"{self.engine_id} engine at {self._host} returned HTTP "
                f"{exc.response.status_code}"
            ) from exc
        except httpx.ConnectError as exc:
            _ledger.finish(_entry, "FAILED", code=CODE_CONNECTION_FAILURE)
            raise EngineConnectionError(
                f"{self.engine_id} engine not reachable at {self._host}"
            ) from exc
        except (
            httpx.TimeoutException,
            httpx.RemoteProtocolError,
            httpx.ReadError,
        ) as exc:
            _ledger.mark_unknown(_entry)
            raise EngineConnectionError(
                f"{self.engine_id} engine not reachable at {self._host}"
            ) from exc
        except GeneratorExit:
            try:
                _ledger.mark_unknown(_entry)
            except Exception:
                pass
            raise

    async def stream_full(
        self,
        messages: Sequence[Message],
        *,
        model: str,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> AsyncIterator["StreamChunk"]:
        """Yield StreamChunks with content, tool_calls, and finish_reason."""
        from openjarvis.security.dispatch_ledger import (
            CODE_CONNECTION_FAILURE,
        )

        _entry, _ledger, _sealed = self._enforce(messages, model, kwargs)
        msg_dicts = messages_to_dicts(messages)
        payload: Dict[str, Any] = {
            "model": self._resolve_model_id(model),
            "messages": msg_dicts,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
            **kwargs,
        }
        if "tools" in payload and "tool_choice" not in payload:
            payload["tool_choice"] = "auto"
        url = f"{self._api_prefix}/chat/completions"
        stream_complete = False
        try:
            # ASYNC streaming (see ``stream``): non-blocking shared client so
            # rich streaming never stalls the event loop and honours ``timeout``.
            client = self._get_async_client()
            async with client.stream("POST", url, json=payload) as resp:
                # ``not is_success`` covers 3xx as well as 4xx/5xx. With
                # ``follow_redirects`` off (the default) an unexpected redirect
                # would otherwise fall through to ``aiter_lines`` and surface as
                # a silent EMPTY stream instead of a clean engine error.
                if not resp.is_success:
                    await resp.aread()
                    self._raise_stream_http_error(resp.status_code, resp.text)
                async for line in resp.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data_str = line[len("data:") :].strip()
                    if data_str == "[DONE]":
                        break
                    try:
                        chunk = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue
                    choice = chunk.get("choices", [{}])[0]
                    delta = choice.get("delta", {})
                    finish = choice.get("finish_reason")
                    content = delta.get("content")
                    tool_calls = delta.get("tool_calls")
                    usage = chunk.get("usage")

                    if content or tool_calls or finish or usage:
                        yield StreamChunk(
                            content=content,
                            tool_calls=tool_calls,
                            finish_reason=finish,
                            usage=usage,
                        )
                    if finish:
                        stream_complete = True
            if stream_complete:
                _ledger.finish(_entry, "EXECUTED")
            else:
                _ledger.note_partial_response(_entry)
        except EngineConnectionError:
            try:
                _ledger.finish(_entry, "FAILED", code="PROVIDER_HTTP_ERROR")
            except Exception:
                pass
            raise
        except httpx.HTTPStatusError:
            _ledger.finish(_entry, "FAILED", code="PROVIDER_HTTP_ERROR")
            raise
        except httpx.ConnectError as exc:
            _ledger.finish(_entry, "FAILED", code=CODE_CONNECTION_FAILURE)
            raise EngineConnectionError(
                f"{self.engine_id} engine not reachable at {self._host}"
            ) from exc
        except (
            httpx.TimeoutException,
            httpx.RemoteProtocolError,
            httpx.ReadError,
        ) as exc:
            _ledger.mark_unknown(_entry)
            raise EngineConnectionError(
                f"{self.engine_id} engine not reachable at {self._host}"
            ) from exc
        except GeneratorExit:
            try:
                _ledger.mark_unknown(_entry)
            except Exception:
                pass
            raise

    def list_models(self) -> List[str]:
        try:
            resp = self._client.get(f"{self._api_prefix}/models")
            resp.raise_for_status()
        except (
            httpx.ConnectError,
            httpx.TimeoutException,
            httpx.HTTPStatusError,
        ) as exc:
            logger.warning(
                "Failed to list models from %s at %s: %s",
                self.engine_id,
                self._host,
                exc,
            )
            return []
        data = resp.json()
        return [m["id"] for m in data.get("data", [])]

    def health(self) -> bool:
        try:
            resp = self._client.get(f"{self._api_prefix}/models", timeout=2.0)
            return resp.status_code == 200
        except Exception as exc:
            logger.debug(
                "%s health check failed at %s: %s",
                self.engine_id,
                self._host,
                exc,
            )
            return False

    def close(self) -> None:
        self._client.close()
        self._close_async_client()


# ``EngineContextLengthError`` moved to ``openjarvis.engine._base``; re-exported
# here for callers/tests that import it from this module.
__all__ = ["_OpenAICompatibleEngine", "EngineContextLengthError"]
