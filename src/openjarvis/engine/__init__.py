"""Inference Engine primitive — LLM runtime management."""

from __future__ import annotations

import importlib
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Eager surface deliberately kept dependency-free: provider implementations
# (nim/ollama/openai_compat_engines/...) require third-party stacks such as
# httpx and must NOT load on generic package import. Broker-mediated workers
# import this package transitively and must stay zero-provider.
#
# Host code that needs provider engines calls ensure_registered() explicitly
# (additionally enforced at the _discovery entry points). Everything else
# resolves lazily through __getattr__ with identical attribute semantics.

_LAZY_SUBMODULES = frozenset(
    {
        "nim",
        "ollama",
        "openai_compat_engines",
        "cloud",
        "litellm",
        "gemma_cpp",
        "apple_fm",
        "_base",
        "_discovery",
        "_stubs",
        "_http_async",
        "_openai_compat",
        "multi",
    }
)

_LAZY_SYMBOLS = {
    "EngineConnectionError": "_base",
    "EngineContextLengthError": "_base",
    "InferenceEngine": "_base",
    "LocalModelResourceUnavailable": "_base",
    "looks_like_context_length_error": "_base",
    "messages_to_dicts": "_base",
    "discover_engines": "_discovery",
    "discover_models": "_discovery",
    "get_engine": "_discovery",
}


def __getattr__(name: str) -> Any:
    """Lazily resolve provider modules and re-exported engine symbols."""
    if name in _LAZY_SYMBOLS:
        module = importlib.import_module(f".{_LAZY_SYMBOLS[name]}", __name__)
        return getattr(module, name)
    if name in _LAZY_SUBMODULES:
        return importlib.import_module(f".{name}", __name__)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_SYMBOLS) | set(__all__))


def _register_optional_engines() -> None:
    """Register available optional engines and retain import diagnostics."""

    # OSError is caught alongside ImportError for apple_fm: its Swift bindings
    # load at import time and raise OSError, not ImportError, on a host whose
    # macOS or Xcode is too old. Letting that escape would take down every
    # other engine too.
    for optional in ("cloud", "litellm", "gemma_cpp", "apple_fm"):
        try:
            importlib.import_module(f".{optional}", __name__)
        except (ImportError, OSError) as exc:
            logger.debug("Optional engine %r unavailable: %s", optional, exc)


def _rescue_module_keys(module_name: str, key_to_attr: dict) -> None:
    """Re-register expected keys from an already-imported provider module.

    Import side effects (the ``@EngineRegistry.register`` decorators) run
    only on first import. Test harnesses may wipe the registry afterwards
    (see the autouse ``_clean_registries`` fixture); re-registering the
    module's own class objects restores registration without reload, so
    class identity never drifts.
    """
    from openjarvis.core.registry import EngineRegistry

    try:
        module = importlib.import_module(f".{module_name}", __name__)
    except (ImportError, OSError) as exc:
        logger.debug("Built-in engine %r unavailable: %s", module_name, exc)
        return
    for key, attr in key_to_attr.items():
        if EngineRegistry.contains(key):
            continue
        cls = getattr(module, attr, None)
        if cls is None:
            logger.debug(
                "Built-in engine %r has no attribute %r", module_name, attr
            )
            continue
        try:
            EngineRegistry.register_value(key, cls)
        except ValueError:
            pass  # already present (concurrent ensure); nothing to do


def _rescue_openai_compat() -> None:
    """Re-register data-driven OpenAI-compatible engines (no reload)."""
    from openjarvis.core.registry import EngineRegistry

    try:
        module = importlib.import_module(".openai_compat_engines", __name__)
    except (ImportError, OSError) as exc:
        logger.debug("Built-in engines 'openai_compat' unavailable: %s", exc)
        return
    for key, (cls_name, _host, _prefix) in module._ENGINES.items():
        if EngineRegistry.contains(key):
            continue
        cls = getattr(module, cls_name, None)
        if cls is None:
            continue
        try:
            EngineRegistry.register_value(key, cls)
        except ValueError:
            pass


_PROVIDER_CLASS_ATTRS = {
    "nim": {"nim": "NIMEngine"},
    "ollama": {"ollama": "OllamaEngine"},
    "cloud": {"cloud": "CloudEngine"},
    "litellm": {"litellm": "LiteLLMEngine"},
    "gemma_cpp": {"gemma_cpp": "GemmaCppEngine"},
    "apple_fm": {"afm": "AppleFMEngine"},
}


def ensure_registered() -> None:
    """Host-side bootstrap: import built-in providers to trigger registry.

    Idempotent (present keys are skipped; ``register_value`` duplicates
    are tolerated for concurrent callers). Registration is restored even
    if the registry was wiped after import, without module reload, so
    class identity never drifts. Performs no network traffic, reads no
    credentials, executes no provider requests.
    """
    for provider, key_to_attr in _PROVIDER_CLASS_ATTRS.items():
        if provider in ("nim", "ollama"):
            _rescue_module_keys(provider, key_to_attr)
    _rescue_openai_compat()
    _register_optional_engines()
    for provider, key_to_attr in _PROVIDER_CLASS_ATTRS.items():
        if provider not in ("nim", "ollama"):
            _rescue_module_keys(provider, key_to_attr)


__all__ = [
    "EngineConnectionError",
    "EngineContextLengthError",
    "InferenceEngine",
    "LocalModelResourceUnavailable",
    "discover_engines",
    "discover_models",
    "ensure_registered",
    "get_engine",
    "looks_like_context_length_error",
    "messages_to_dicts",
]
