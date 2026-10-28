"""Ollama inference engine backend."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import threading
from collections.abc import AsyncIterator, Sequence
from typing import Any, Dict, List
from urllib.parse import urlparse, urlunparse

import httpx

from openjarvis.core.execution import ModelCapabilityError, ToolRequirement
from openjarvis.core.registry import EngineRegistry
from openjarvis.core.types import Message
from openjarvis.engine._base import (
    EngineConnectionError,
    InferenceEngine,
    LocalModelResourceUnavailable,
    estimate_prompt_tokens,
    messages_to_dicts,
)
from openjarvis.engine._http_async import (
    STREAM_TRANSPORT_ERRORS,
    AsyncHTTPEngineMixin,
)
from openjarvis.engine._stubs import StreamChunk

logger = logging.getLogger(__name__)

# Qwen3 treats ``/think`` and ``/no_think`` as soft-switch control tokens that
# toggle reasoning mode. Small models (e.g. qwen3:14b) fed a multi-line prompt
# sometimes emit one of these as the sole tool argument, e.g.
# ``{"command": "/no_think"}`` instead of the real command. Ollama parses that
# into a fully-formed tool_call via the model's chat template, so we have to
# drop it on our side before the agent executes garbage.
_QWEN_CONTROL_TOKENS = frozenset({"/think", "/no_think"})


def _is_control_token_only_args(raw_args: Any) -> bool:
    """Return True if tool-call arguments contain nothing but a Qwen3 token.

    ``raw_args`` may be a dict (Ollama's native shape) or a JSON / bare string.
    A call is considered degenerate only when it carries at least one control
    token and no other usable content, so legitimate calls such as
    ``{"command": "date"}`` or ``{"command": "echo /no_think"}`` are kept.
    """
    parsed: Any = raw_args
    if isinstance(raw_args, str):
        try:
            parsed = json.loads(raw_args)
        except (json.JSONDecodeError, TypeError):
            parsed = raw_args

    if isinstance(parsed, str):
        return parsed.strip().lower() in _QWEN_CONTROL_TOKENS

    if not isinstance(parsed, dict) or not parsed:
        return False

    saw_token = False
    for value in parsed.values():
        if not isinstance(value, str):
            return False  # a non-string value is real content
        stripped = value.strip()
        if not stripped:
            continue
        if stripped.lower() in _QWEN_CONTROL_TOKENS:
            saw_token = True
        else:
            return False  # real string content
    return saw_token


def _default_num_ctx() -> int:
    """Default context window (tokens). Override with ``JARVIS_NUM_CTX``.

    Raised above Ollama's 4k default so an image (which costs many tokens)
    plus a real conversation fit. 16k is comfortable for small models on a
    typical consumer GPU.
    """
    try:
        return int(os.environ.get("JARVIS_NUM_CTX", "16384"))
    except ValueError:
        return 16384


def _ollama_request_options(
    *,
    temperature: float,
    max_tokens: int,
    kwargs: Dict[str, Any],
) -> Dict[str, Any]:
    """Build Ollama ``options`` dict from generate/stream kwargs."""
    options: Dict[str, Any] = {
        "temperature": temperature,
        "num_predict": max_tokens,
    }
    if kwargs.get("num_ctx") is not None:
        options["num_ctx"] = int(kwargs["num_ctx"])
    else:
        options["num_ctx"] = _default_num_ctx()
    if kwargs.get("num_gpu") is not None:
        options["num_gpu"] = int(kwargs["num_gpu"])
    if kwargs.get("num_thread") is not None:
        options["num_thread"] = int(kwargs["num_thread"])
    return options


# Models heavy enough to need Astra-side resource/concurrency guarding.
# Narrow on purpose: small local models keep existing behaviour.
_QWEN_STRONG_LOCAL_DEFAULTS = {
    "keep_alive": "5m",  # bounded idle residency; never inherit KEEP_ALIVE=-1
    "num_thread": 4,  # measured: 4 threads sustain ~4.5 tok/s on 9B Q4
    "num_ctx": 4096,  # measured qualification context for Qwen3.5-9B Q4_K_M
}
_QWEN_STRONG_LOCAL_MODELS = ("qwen3.5:9b",)


def _verified_loopback_url(host: str) -> str | None:
    """Return a numeric loopback URL, rejecting ambiguous name resolution."""
    try:
        parsed = urlparse(host)
        if parsed.scheme not in {"http", "https"}:
            return None
        if parsed.username or parsed.password or not parsed.hostname:
            return None
        port = parsed.port
        address = ipaddress.ip_address(parsed.hostname)
        mapped = getattr(address, "ipv4_mapped", None)
        if mapped is not None and mapped.is_loopback:
            address = mapped
        if not address.is_loopback:
            return None
    except ValueError:
        if parsed.hostname.lower() != "localhost":
            return None
        try:
            port = parsed.port
            service_port = port or (443 if parsed.scheme == "https" else 80)
            answers = socket.getaddrinfo(
                parsed.hostname,
                service_port,
                type=socket.SOCK_STREAM,
            )
            addresses = [ipaddress.ip_address(item[4][0]) for item in answers]
        except (OSError, TypeError, ValueError):
            return None
        if not addresses or any(not address.is_loopback for address in addresses):
            return None
        address = addresses[0]

    rendered = f"[{address}]" if address.version == 6 else str(address)
    netloc = rendered if port is None else f"{rendered}:{port}"
    return urlunparse(
        (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, "")
    )


def _is_loopback_host(host: str) -> bool:
    """Accept only loopback URLs whose transport destination is numeric."""
    return _verified_loopback_url(host) is not None


def _avail_ram_gb() -> float:
    """Available system RAM in GiB; an unknown value fails the guard closed."""
    try:
        import ctypes

        if os.name == "nt":

            class _Mem(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            s = _Mem()
            s.dwLength = ctypes.sizeof(_Mem)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(s)):
                return s.ullAvailPhys / float(1024**3)
            return 0.0
        try:
            pages = os.sysconf("SC_AVPHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
            return (pages * page_size) / float(1024**3)
        except (ValueError, OSError, AttributeError):
            return 0.0
    except Exception:
        return 0.0


@EngineRegistry.register("ollama")
class OllamaEngine(AsyncHTTPEngineMixin, InferenceEngine):
    """Ollama backend via its native HTTP API."""

    engine_id = "ollama"

    # Ollama has no context-length overflow signal in its 400 bodies, so the
    # shared ``_raise_stream_http_error`` keeps its default (no
    # ``EngineContextLengthError`` branch, unlike the OpenAI-compat engines).

    _DEFAULT_HOST = "http://127.0.0.1:11434"
    _httpx_trust_env = False

    def __init__(
        self,
        host: str | None = None,
        *,
        timeout: float = 1800.0,
        keep_alive: str | None = None,
        num_thread: int | None = None,
        num_ctx: int | None = None,
        min_avail_ram_gb: float = 10.0,
        max_parallel: int = 1,
        guarded_models: tuple = _QWEN_STRONG_LOCAL_MODELS,
    ) -> None:
        # Priority: explicit host (from config.toml) > OLLAMA_HOST env var > default
        if host is None:
            env_host = os.environ.get("OLLAMA_HOST")
            host = env_host or self._DEFAULT_HOST
        verified_host = _verified_loopback_url(host.rstrip("/"))
        if verified_host is None:
            raise ValueError(
                "OLLAMA_REMOTE_HOST_DENIED: Ollama transport is loopback-only"
            )
        self._host = verified_host
        # Request-level lifecycle: a set value overrides the server default
        # AND the machine's OLLAMA_KEEP_ALIVE env (e.g. -1) for Astra-driven
        # requests only. ``None`` preserves previous behaviour exactly.
        self._keep_alive = keep_alive
        self._num_thread = num_thread
        self._num_ctx = num_ctx
        self._min_avail_ram_gb = min_avail_ram_gb
        self._guarded_models = tuple(guarded_models)
        self._slots = threading.Semaphore(max(1, max_parallel))
        # Used by the shared async streaming plumbing (AsyncHTTPEngineMixin) so a
        # wedged token read is bounded by ``timeout`` instead of hanging the
        # single event loop for the httpx default.
        self._timeout = timeout
        # Injection seam for tests: an ``httpx.MockTransport`` swapped in here drives
        # the async stream path with no real Ollama server. ``None`` in production so
        # httpx uses its default networking.
        self._async_transport: httpx.AsyncBaseTransport | None = None
        self._client = httpx.Client(
            base_url=self._host, timeout=timeout, trust_env=False
        )
        # Last stream usage — captured from Ollama's final chunk
        self._last_stream_usage: Dict[str, int] = {}

    def _is_guarded(self, model: str) -> bool:
        return model in self._guarded_models

    def _apply_model_defaults(
        self, model: str, kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Fill per-request lifecycle defaults for guarded heavy models."""
        if not self._is_guarded(model):
            return kwargs
        merged = dict(kwargs)
        if merged.get("keep_alive") is None:
            keep_alive = _QWEN_STRONG_LOCAL_DEFAULTS["keep_alive"]
            if self._keep_alive is not None:
                keep_alive = self._keep_alive
            merged["keep_alive"] = keep_alive
        if merged.get("num_thread") is None:
            num_thread = _QWEN_STRONG_LOCAL_DEFAULTS["num_thread"]
            if self._num_thread is not None:
                num_thread = self._num_thread
            merged["num_thread"] = num_thread
        if merged.get("num_ctx") is None:
            num_ctx = _QWEN_STRONG_LOCAL_DEFAULTS["num_ctx"]
            if self._num_ctx is not None:
                num_ctx = self._num_ctx
            merged["num_ctx"] = num_ctx
        return merged

    def _check_resources(self, model: str, *, unload_only: bool = False) -> bool:
        """Fail closed when the host cannot safely run a guarded model.

        Returns True when a concurrency slot was acquired (caller must
        release it in a ``finally``); False for unguarded models.
        ``unload_only`` (an explicit ``keep_alive=0`` request) skips the
        RAM gate: blocking the release path would pin memory instead of
        freeing it. The concurrency slot is still enforced.
        """
        if not self._is_guarded(model):
            return False
        if not unload_only and self._min_avail_ram_gb > 0:
            avail = _avail_ram_gb()
            if avail < self._min_avail_ram_gb:
                raise LocalModelResourceUnavailable(
                    f"LOCAL_MODEL_RESOURCE_UNAVAILABLE: {avail:.1f} GiB "
                    f"available < {self._min_avail_ram_gb:.1f} GiB required "
                    f"for {model}; refusing load"
                )
        if not self._slots.acquire(blocking=False):
            raise LocalModelResourceUnavailable(
                f"LOCAL_MODEL_RESOURCE_UNAVAILABLE: {model} is already "
                "running; concurrent heavy inference is capped at 1"
            )
        return True

    def generate(
        self,
        messages: Sequence[Message],
        *,
        model: str,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        msg_dicts = messages_to_dicts(messages)
        # Guarded heavy models (qwen3.5:9b) get bounded idle residency and
        # measured thread defaults; explicit per-call kwargs always win.
        kwargs = self._apply_model_defaults(model, kwargs)
        # An explicit keep_alive=0 is a release request: it must pass the
        # RAM gate (blocking it would pin memory instead of freeing it).
        unload_only = kwargs.get("keep_alive") in (0, "0")
        acquired = self._check_resources(model, unload_only=unload_only)
        try:
            return self._generate_guarded(msg_dicts, messages, model,
                                          temperature, max_tokens, kwargs)
        finally:
            if acquired:
                self._slots.release()

    def _generate_guarded(
        self,
        msg_dicts: List[Dict[str, Any]],
        messages: Sequence[Message],
        model: str,
        temperature: float,
        max_tokens: int,
        kwargs: Dict[str, Any],
    ) -> Dict[str, Any]:
        # Ollama expects tool_call arguments as dicts, not JSON strings
        for md in msg_dicts:
            for tc in md.get("tool_calls", []):
                fn = tc.get("function", {})
                args = fn.get("arguments")
                if isinstance(args, str):
                    try:
                        fn["arguments"] = json.loads(args)
                    except (json.JSONDecodeError, TypeError):
                        pass
        payload: Dict[str, Any] = {
            "model": model,
            "messages": msg_dicts,
            "stream": False,
            "options": _ollama_request_options(
                temperature=temperature,
                max_tokens=max_tokens,
                kwargs=kwargs,
            ),
        }
        # Disable extended thinking by default (Qwen3.5 etc.).
        # When enabled, thinking tokens consume the entire budget and
        # the visible content comes back empty.
        if "think" not in kwargs:
            payload["think"] = False
        elif kwargs["think"] is not None:
            payload["think"] = kwargs["think"]
        # Request-level lifecycle: overrides the server default and the
        # machine OLLAMA_KEEP_ALIVE env for this request only. Absent by
        # default (previous behaviour).
        if kwargs.get("keep_alive") is not None:
            payload["keep_alive"] = kwargs["keep_alive"]
        # Pass tools if provided
        tools = kwargs.get("tools")
        tool_requirement = ToolRequirement(
            kwargs.get("tool_requirement", ToolRequirement.OPTIONAL)
        )
        if tool_requirement == ToolRequirement.REQUIRED_NATIVE and not tools:
            raise ModelCapabilityError(
                "Native tool call required but no tool schema was supplied"
            )
        if tools:
            payload["tools"] = tools

        # Apply structured output / JSON mode
        response_format = kwargs.get("response_format")
        if response_format is not None:
            from openjarvis.engine._stubs import ResponseFormat

            if isinstance(response_format, ResponseFormat):
                payload["format"] = "json"
            elif isinstance(response_format, dict):
                payload["format"] = "json"
        try:
            resp = self._client.post("/api/chat", json=payload)
            if resp.status_code == 400 and tools:
                if tool_requirement == ToolRequirement.REQUIRED_NATIVE:
                    body = resp.text[:500]
                    raise ModelCapabilityError(
                        "Ollama rejected the required native tool request"
                        f" (400): {body}"
                    )
                # Model may not support function calling -- retry without tools
                payload.pop("tools", None)
                resp = self._client.post("/api/chat", json=payload)
            resp.raise_for_status()
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            raise EngineConnectionError(
                f"Ollama not reachable at {self._host}"
            ) from exc
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:500] if exc.response else ""
            raise RuntimeError(
                f"Ollama returned {exc.response.status_code}: {body}"
            ) from exc
        data = resp.json()
        # prompt_eval_count = tokens actually evaluated (KV-cache-aware).
        # estimate_prompt_tokens = full prompt size (for cost comparison).
        # We report both so downstream can use the right one:
        #   prompt_tokens        → full size (what cloud would charge)
        #   prompt_tokens_evaluated → actual compute (with KV cache)
        reported_prompt = data.get("prompt_eval_count", 0)
        estimated_prompt = estimate_prompt_tokens(messages)
        prompt_tokens = max(reported_prompt, estimated_prompt)
        prompt_tokens_evaluated = (
            reported_prompt if reported_prompt > 0 else prompt_tokens
        )
        completion_tokens = data.get("eval_count", 0)
        content = data.get("message", {}).get("content", "")
        result: Dict[str, Any] = {
            "content": content,
            "usage": {
                "prompt_tokens": prompt_tokens,
                "prompt_tokens_evaluated": prompt_tokens_evaluated,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
            "model": data.get("model", model),
            "finish_reason": "stop",
        }
        # Extract timing from Ollama response (nanoseconds → seconds)
        result["ttft"] = data.get("prompt_eval_duration", 0) / 1e9
        result["engine_timing"] = {
            k: data[k]
            for k in (
                "total_duration",
                "load_duration",
                "prompt_eval_duration",
                "eval_duration",
            )
            if k in data
        }
        # Extract tool calls if present
        raw_tool_calls = data.get("message", {}).get("tool_calls", [])
        if raw_tool_calls:
            tool_calls = []
            for i, tc in enumerate(raw_tool_calls):
                fn = tc.get("function", {})
                raw_args = fn.get("arguments", "{}")
                if _is_control_token_only_args(raw_args):
                    logger.warning(
                        "Dropping Qwen3 control-token tool call %s(%r)",
                        fn.get("name", ""),
                        raw_args,
                    )
                    continue
                tool_calls.append(
                    {
                        "id": tc.get("id", f"call_{i}"),
                        "name": fn.get("name", ""),
                        "arguments": (
                            json.dumps(raw_args)
                            if isinstance(raw_args, dict)
                            else raw_args
                        ),
                    }
                )
            if tool_calls:
                result["tool_calls"] = tool_calls
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
        kwargs = self._apply_model_defaults(model, kwargs)
        # An explicit keep_alive=0 is a release request: it must pass the
        # RAM gate (blocking it would pin memory instead of freeing it).
        unload_only = kwargs.get("keep_alive") in (0, "0")
        acquired = self._check_resources(model, unload_only=unload_only)
        try:
            async for text in self._stream_guarded(
                messages, model, temperature, max_tokens, kwargs
            ):
                yield text
        finally:
            if acquired:
                self._slots.release()

    async def _stream_guarded(
        self,
        messages: Sequence[Message],
        model: str,
        temperature: float,
        max_tokens: int,
        kwargs: Dict[str, Any],
    ) -> AsyncIterator[str]:
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages_to_dicts(messages),
            "stream": True,
            "options": _ollama_request_options(
                temperature=temperature,
                max_tokens=max_tokens,
                kwargs=kwargs,
            ),
        }
        # Mirror generate()'s default: disable extended thinking unless the
        # caller opted in. Qwen3/etc. with thinking on can stall the visible
        # stream for 60+ seconds before any tokens reach the client, which
        # frontends interpret as a "Load failed" timeout.
        if "think" not in kwargs:
            payload["think"] = False
        elif kwargs["think"] is not None:
            payload["think"] = kwargs["think"]
        if kwargs.get("keep_alive") is not None:
            payload["keep_alive"] = kwargs["keep_alive"]
        try:
            # ASYNC streaming: ``httpx.AsyncClient`` + ``aiter_lines`` never
            # blocks the event loop between tokens (the previous SYNC
            # ``self._client`` + ``iter_lines`` inside this ``async def`` blocked
            # the single uvicorn worker on every inter-token wait, serializing all
            # concurrent chats and letting one wedged read freeze the whole API).
            # The shared client keeps pooled connections across turns.
            client = self._get_async_client()
            async with client.stream("POST", "/api/chat", json=payload) as resp:
                # ``not is_success`` covers 3xx as well as 4xx/5xx and maps
                # to ``EngineConnectionError`` (matching the OpenAI-compat
                # path) instead of leaking a raw ``httpx.HTTPStatusError``.
                # With redirects off (the default) an unexpected 3xx would
                # otherwise fall through to ``aiter_lines`` and surface as a
                # silent EMPTY stream rather than a clean engine error.
                if not resp.is_success:
                    # Read the (short) error body before touching ``.text``:
                    # a streaming response is otherwise unread.
                    await resp.aread()
                    self._raise_stream_http_error(resp.status_code, resp.text)
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    content = chunk.get("message", {}).get("content", "")
                    if content:
                        yield content
                    if chunk.get("done", False):
                        reported_prompt = chunk.get("prompt_eval_count", 0)
                        est_prompt = estimate_prompt_tokens(messages)
                        full_prompt = max(reported_prompt, est_prompt)
                        evaluated = (
                            reported_prompt if reported_prompt > 0 else full_prompt
                        )
                        comp = chunk.get("eval_count", 0)
                        self._last_stream_usage = {
                            "prompt_tokens": full_prompt,
                            "prompt_tokens_evaluated": evaluated,
                            "completion_tokens": comp,
                            "total_tokens": full_prompt + comp,
                        }
                        break
        except STREAM_TRANSPORT_ERRORS as exc:
            # Transport failures (incl. a mid-stream server disconnect) map to a
            # clean error; the set is kept narrow (see STREAM_TRANSPORT_ERRORS)
            # so cancellation still propagates.
            raise EngineConnectionError(
                f"Ollama not reachable at {self._host}"
            ) from exc

    async def stream_full(
        self,
        messages: Sequence[Message],
        *,
        model: str,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> AsyncIterator[StreamChunk]:
        kwargs = self._apply_model_defaults(model, kwargs)
        # An explicit keep_alive=0 is a release request: it must pass the
        # RAM gate (blocking it would pin memory instead of freeing it).
        unload_only = kwargs.get("keep_alive") in (0, "0")
        acquired = self._check_resources(model, unload_only=unload_only)
        try:
            async for chunk in self._stream_full_guarded(
                messages, model, temperature, max_tokens, kwargs
            ):
                yield chunk
        finally:
            if acquired:
                self._slots.release()

    async def _stream_full_guarded(
        self,
        messages: Sequence[Message],
        model: str,
        temperature: float,
        max_tokens: int,
        kwargs: Dict[str, Any],
    ) -> AsyncIterator[StreamChunk]:
        """Yield ``StreamChunk``s including tool_calls.

        Unlike the default ``stream_full`` in the base class (which wraps
        ``stream()`` and drops tools), this posts to ``/api/chat`` with
        ``tools`` from kwargs and parses tool_calls out of the streamed
        response. Falls back to a tools-less retry on 400 (mirrors
        ``generate()``'s behaviour for models that don't support tools).
        """
        msg_dicts = messages_to_dicts(messages)
        for md in msg_dicts:
            for tc in md.get("tool_calls", []):
                fn = tc.get("function", {})
                args = fn.get("arguments")
                if isinstance(args, str):
                    try:
                        fn["arguments"] = json.loads(args)
                    except (json.JSONDecodeError, TypeError):
                        pass

        payload: Dict[str, Any] = {
            "model": model,
            "messages": msg_dicts,
            "stream": True,
            "options": _ollama_request_options(
                temperature=temperature,
                max_tokens=max_tokens,
                kwargs=kwargs,
            ),
        }
        if "think" not in kwargs:
            payload["think"] = False
        elif kwargs["think"] is not None:
            payload["think"] = kwargs["think"]
        if kwargs.get("keep_alive") is not None:
            payload["keep_alive"] = kwargs["keep_alive"]

        tools = kwargs.get("tools")
        if tools:
            payload["tools"] = tools

        async for chunk in self._run_stream(
            payload, messages, retry_without_tools=bool(tools)
        ):
            yield chunk

    async def _run_stream(
        self,
        payload: Dict[str, Any],
        messages: Sequence[Message],
        *,
        retry_without_tools: bool,
    ) -> AsyncIterator[StreamChunk]:
        """Execute the streaming request and yield parsed StreamChunks."""
        try:
            # ASYNC streaming (see ``stream``): shared ``AsyncClient`` +
            # ``aiter_lines`` so rich streaming never stalls the event loop and
            # honours ``timeout``.
            client = self._get_async_client()
            async with client.stream("POST", "/api/chat", json=payload) as resp:
                if resp.status_code == 400 and retry_without_tools:
                    # Model doesn't support tools — retry without them.
                    # PRESERVED: this specific 400 path must still trigger the
                    # tools-less retry; only OTHER non-2xx responses map to
                    # EngineConnectionError below.
                    payload.pop("tools", None)
                    async for c in self._run_stream(
                        payload, messages, retry_without_tools=False
                    ):
                        yield c
                    return
                # ``not is_success`` covers 3xx as well as 4xx/5xx and maps
                # to ``EngineConnectionError`` (matching the OpenAI-compat
                # path) instead of leaking a raw ``httpx.HTTPStatusError``.
                # With redirects off (the default) an unexpected 3xx would
                # otherwise fall through to ``aiter_lines`` and surface as a
                # silent EMPTY stream rather than a clean engine error.
                if not resp.is_success:
                    await resp.aread()
                    self._raise_stream_http_error(resp.status_code, resp.text)

                finish_reason: str | None = None
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    message = chunk.get("message", {}) or {}
                    content = message.get("content", "")
                    raw_tool_calls = message.get("tool_calls") or []

                    if content:
                        yield StreamChunk(content=content)

                    if raw_tool_calls:
                        # Ollama emits fully-formed tool_calls in a single
                        # chunk (not fragmented). Convert to the
                        # OpenAI-delta fragment shape that agent_manager_routes
                        # expects in _merge_tool_call_fragments.
                        fragments: List[Dict[str, Any]] = []
                        for tc in raw_tool_calls:
                            fn = tc.get("function", {}) or {}
                            raw_args = fn.get("arguments", "{}")
                            if _is_control_token_only_args(raw_args):
                                logger.warning(
                                    "Dropping Qwen3 control-token tool call %s(%r)",
                                    fn.get("name", ""),
                                    raw_args,
                                )
                                continue
                            args_str = (
                                json.dumps(raw_args)
                                if isinstance(raw_args, dict)
                                else str(raw_args)
                            )
                            i = len(fragments)
                            fragments.append(
                                {
                                    "index": i,
                                    "id": tc.get("id", f"call_{i}"),
                                    "type": "function",
                                    "function": {
                                        "name": fn.get("name", ""),
                                        "arguments": args_str,
                                    },
                                }
                            )
                        if fragments:
                            yield StreamChunk(tool_calls=fragments)
                            finish_reason = "tool_calls"

                    if chunk.get("done", False):
                        reported_prompt = chunk.get("prompt_eval_count", 0)
                        est_prompt = estimate_prompt_tokens(messages)
                        full_prompt = max(reported_prompt, est_prompt)
                        evaluated = (
                            reported_prompt if reported_prompt > 0 else full_prompt
                        )
                        comp = chunk.get("eval_count", 0)
                        self._last_stream_usage = {
                            "prompt_tokens": full_prompt,
                            "prompt_tokens_evaluated": evaluated,
                            "completion_tokens": comp,
                            "total_tokens": full_prompt + comp,
                        }
                        if finish_reason is None:
                            finish_reason = chunk.get("done_reason") or "stop"
                        yield StreamChunk(
                            finish_reason=finish_reason,
                            usage=dict(self._last_stream_usage),
                        )
                        break
        except STREAM_TRANSPORT_ERRORS as exc:
            # See ``stream``: transport failures (incl. a mid-stream server
            # disconnect) map to a clean error; the set is kept narrow so
            # cancellation still propagates.
            raise EngineConnectionError(
                f"Ollama not reachable at {self._host}"
            ) from exc

    def list_models(self) -> List[str]:
        try:
            resp = self._client.get("/api/tags")
            resp.raise_for_status()
        except (
            httpx.ConnectError,
            httpx.TimeoutException,
            httpx.HTTPStatusError,
        ) as exc:
            logger.warning(
                "Failed to list models from Ollama at %s: %s",
                self._host,
                exc,
            )
            return []
        data = resp.json()
        return [m["name"] for m in data.get("models", [])]

    def health(self) -> bool:
        try:
            resp = self._client.get("/api/tags", timeout=2.0)
            return resp.status_code == 200
        except Exception as exc:
            logger.debug("Ollama health check failed at %s: %s", self._host, exc)
            return False

    def close(self) -> None:
        self._client.close()
        self._close_async_client()


__all__ = ["OllamaEngine"]
