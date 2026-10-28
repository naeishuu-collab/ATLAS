"""NVIDIA NIM inference engine — self-hosted inference microservices."""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import AsyncIterator, Sequence
from typing import Any, Dict, List

import httpx

from openjarvis.core.registry import EngineRegistry
from openjarvis.core.types import Message
from openjarvis.engine._base import (
    EngineConnectionError,
    InferenceEngine,
    estimate_prompt_tokens,
    messages_to_dicts,
)
from openjarvis.engine._stubs import StreamChunk

logger = logging.getLogger(__name__)

#: E2 feature flag. Only the exact value ``"on"`` arms enforcement.
#: Unset / OFF / invalid deny with zero transport calls. OFF never
#: restores unguarded sending.
NIM_EGRESS_FLAG = "ASTRA_NIM_EGRESS"
NIM_EGRESS_ON = "on"


@EngineRegistry.register("nim")
class NIMEngine(InferenceEngine):
    """NVIDIA NIM inference engine.

    Supports local and remote NIM deployments with OpenAI-compatible API.
    Requires NIM_API_KEY for NVIDIA-hosted NIM endpoints, optional for self-hosted.
    """

    engine_id = "nim"
    _default_host = "https://integrate.api.nvidia.com"
    _api_prefix = "/v1"

    def __init__(
        self,
        host: str | None = None,
        *,
        timeout: float = 600.0,
        authorizer: Any = None,
        dispatch_ledger: Any = None,
        session_id: str = "",
    ) -> None:
        env_host = os.environ.get("NIM_HOST")
        self._host = (host or env_host or self._default_host).rstrip("/")

        api_key = os.environ.get("NIM_API_KEY", "")
        self._api_key = api_key if api_key else None

        headers = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        self._timeout = timeout
        self._client = httpx.Client(
            base_url=self._host,
            timeout=timeout,
            headers=headers,
        )
        # Host-issued enforcement machinery (E2). Never taken from callers.
        self._authorizer = authorizer
        self._dispatch_ledger = dispatch_ledger
        self._session_id = session_id
        self._seen_nonces: set = set()
        self._nonce_lock = threading.Lock()

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for requests, including auth if configured."""
        headers = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _enforce(
        self, messages: Sequence[Message], model: str, kwargs: Dict[str, Any]
    ) -> Any:
        """E2 enforcement gate. Returns the ledger entry or raises."""
        from openjarvis.security.cloud_dispatch import (
            ENDPOINT_NOT_ALLOWED,
            NONCE_REPLAY,
            SESSION_MISMATCH,
            AuthorizedPayload,
            PrivacyDenied,
        )
        from openjarvis.security.dispatch_ledger import (
            CODE_CANCELLED,
            CloudDispatchLedger,
        )

        if os.environ.get(NIM_EGRESS_FLAG, "") != NIM_EGRESS_ON:
            raise PrivacyDenied("FLAG_OFF", "nim egress enforcement not enabled")
        sealed = kwargs.pop("cloud_dispatch", None)
        cancel_event = kwargs.pop("cancel_event", None)
        if not isinstance(sealed, AuthorizedPayload):
            raise PrivacyDenied("NO_GRANT", "sealed host authorization required")
        if sealed.grant.expired():
            raise PrivacyDenied("GRANT_EXPIRED", "capability grant has expired")
        provider = sealed.provider
        if (
            provider.engine != "nim"
            or provider.provider != "nim"
            or provider.model != model
        ):
            raise PrivacyDenied(
                "CLOUD_PROVIDER_NOT_ALLOWED",
                "authorization is not bound to this nim destination",
            )
        if not provider.endpoint or provider.endpoint.rstrip(
            "/"
        ) != self._host.rstrip("/"):
            raise PrivacyDenied(
                ENDPOINT_NOT_ALLOWED, "authorized endpoint differs from nim host"
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
        wire_dicts = messages_to_dicts(messages)
        semantic = [
            {"role": str(m.get("role", "user")), "content": str(m.get("content", ""))}
            for m in wire_dicts
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
            raise PrivacyDenied(CODE_CANCELLED, "cancelled before send")
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
            CODE_PROVIDER_TIMEOUT,
        )

        _entry, _ledger, _sealed = self._enforce(messages, model, kwargs)
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages_to_dicts(messages),
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
            **kwargs,
        }
        if "tools" in payload and "tool_choice" not in payload:
            payload["tool_choice"] = "auto"
        try:
            url = f"{self._api_prefix}/chat/completions"
            resp = self._client.post(url, json=payload, headers=self._get_headers())
            resp.raise_for_status()
        except httpx.ConnectError as exc:
            # Nothing left the boundary: deterministic failure.
            _ledger.finish(_entry, "FAILED", code=CODE_CONNECTION_FAILURE)
            raise EngineConnectionError(
                f"NIM engine not reachable at {self._host}"
            ) from exc
        except httpx.TimeoutException as exc:
            # Uncertain whether the provider processed the request.
            _ledger.mark_unknown(_entry, code=CODE_PROVIDER_TIMEOUT)
            raise EngineConnectionError(
                f"NIM engine not reachable at {self._host}"
            ) from exc
        except httpx.HTTPStatusError:
            _ledger.finish(_entry, "FAILED", code="PROVIDER_HTTP_ERROR")
            raise
        except Exception:
            # P0-3: any other post-dispatch surprise (non-httpx transport
            # failure, SDK error) leaves the send outcome uncertain:
            # quarantine UNKNOWN (terminal, never retried), re-raise.
            try:
                _ledger.mark_unknown(_entry)
            except Exception:
                pass
            raise
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
        _ledger.check_send(_entry, _sealed)
        _ledger.finish(_entry, "EXECUTED")
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
            "model": model,
            "messages": messages_to_dicts(messages),
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
            **kwargs,
        }
        if "tools" in payload and "tool_choice" not in payload:
            payload["tool_choice"] = "auto"
        try:
            url = f"{self._api_prefix}/chat/completions"
            async with httpx.AsyncClient(
                base_url=self._host,
                timeout=self._timeout,
                headers=self._get_headers(),
            ) as client:
                async with client.stream("POST", url, json=payload) as resp:
                    resp.raise_for_status()
                    stream_complete = False
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
                        choices = chunk.get("choices", [])
                        if not choices:
                            continue
                        delta = choices[0].get("delta", {})
                        content = delta.get("content")
                        if content:
                            yield content
            if stream_complete:
                _ledger.finish(_entry, "EXECUTED")
            else:
                # Truncated stream: no completion marker from the provider.
                _ledger.note_partial_response(_entry)
        except httpx.HTTPStatusError:
            _ledger.finish(_entry, "FAILED", code="PROVIDER_HTTP_ERROR")
            raise
        except httpx.ConnectError as exc:
            _ledger.finish(_entry, "FAILED", code=CODE_CONNECTION_FAILURE)
            raise EngineConnectionError(
                f"NIM engine not reachable at {self._host}"
            ) from exc
        except httpx.TimeoutException as exc:
            _ledger.mark_unknown(_entry)
            raise EngineConnectionError(
                f"NIM engine not reachable at {self._host}"
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
            "model": model,
            "messages": msg_dicts,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": True,
            **kwargs,
        }
        if "tools" in payload and "tool_choice" not in payload:
            payload["tool_choice"] = "auto"
        try:
            url = f"{self._api_prefix}/chat/completions"
            async with httpx.AsyncClient(
                base_url=self._host,
                timeout=self._timeout,
                headers=self._get_headers(),
            ) as client:
                async with client.stream("POST", url, json=payload) as resp:
                    resp.raise_for_status()
                    stream_complete = False
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
                        choices = chunk.get("choices", [])
                        if not choices:
                            continue
                        choice = choices[0]
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
        except httpx.HTTPStatusError:
            _ledger.finish(_entry, "FAILED", code="PROVIDER_HTTP_ERROR")
            raise
        except httpx.ConnectError as exc:
            _ledger.finish(_entry, "FAILED", code=CODE_CONNECTION_FAILURE)
            raise EngineConnectionError(
                f"NIM engine not reachable at {self._host}"
            ) from exc
        except httpx.TimeoutException as exc:
            _ledger.mark_unknown(_entry)
            raise EngineConnectionError(
                f"NIM engine not reachable at {self._host}"
            ) from exc
        except GeneratorExit:
            try:
                _ledger.mark_unknown(_entry)
            except Exception:
                pass
            raise

    def list_models(self) -> List[str]:
        try:
            resp = self._client.get(
                f"{self._api_prefix}/models",
                headers=self._get_headers(),
            )
            resp.raise_for_status()
        except (
            httpx.ConnectError,
            httpx.TimeoutException,
            httpx.HTTPStatusError,
        ) as exc:
            logger.warning("Failed to list models from NIM at %s: %s", self._host, exc)
            return []
        data = resp.json()
        return [m["id"] for m in data.get("data", [])]

    def health(self) -> bool:
        try:
            resp = self._client.get(
                f"{self._api_prefix}/health/ready",
                timeout=2.0,
                headers=self._get_headers(),
            )
            if resp.status_code == 200:
                return True
        except Exception:
            pass
        try:
            resp = self._client.get(
                f"{self._api_prefix}/models",
                timeout=2.0,
                headers=self._get_headers(),
            )
            return resp.status_code == 200
        except Exception as exc:
            logger.debug("NIM health check failed at %s: %s", self._host, exc)
            return False

    def close(self) -> None:
        self._client.close()

    def __repr__(self) -> str:
        return f"NIMEngine(host={self._host})"
