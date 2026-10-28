"""Multi-provider catalog — metadata only, no network, no key reads.

Reuses the existing provider implementations
(``CloudEngine``/``LiteLLMEngine``/``NIMEngine``/``OllamaEngine``).
Key presence never authorizes dispatch: a provider is routable only
when (a) it is in the host allowlist, (b) a sealed authorization exists,
and (c) health reports reachable. This module tracks (c) and the
engine/model wiring; the authorizer enforces (a) and (b).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from openjarvis.agents.capability_router import ModelCapability

T = ModelCapability.TEXT
J = ModelCapability.STRUCTURED_JSON
N = ModelCapability.NATIVE_TOOLS
L = ModelCapability.LONG_CONTEXT

OPENROUTER_NEMOTRON_35_SUPER_VL_FREE = (
    "openrouter/nvidia/nemotron-3.5-super-vl:free"
)


@dataclass(frozen=True, slots=True)
class ProviderEntry:
    name: str  # groq | gemini | cerebras | openrouter | mistral | nim | ollama
    engine: str  # litellm | cloud | nim | ollama
    models: Tuple[str, ...]
    capabilities: frozenset
    ctx_limit: int
    is_cloud: bool = True
    tier: int = 1
    modalities: frozenset = frozenset({"text"})


CATALOG: Tuple[ProviderEntry, ...] = (
    ProviderEntry(
        "groq", "litellm", ("llama-3.3-70b",), frozenset({T, J, N}), 32768,
        tier=1,
    ),
    ProviderEntry(
        "gemini", "cloud", ("gemini-2.5-flash",), frozenset({T, J, L}), 131072,
        tier=2,
    ),
    ProviderEntry(
        "cerebras", "litellm", ("llama-3.3-70b",), frozenset({T, J}), 32768,
        tier=1,
    ),
    ProviderEntry(
        "openrouter", "cloud",
        ("openrouter/auto",), frozenset({T, J}), 65536, tier=1,
    ),
    ProviderEntry(
        "openrouter", "cloud",
        (OPENROUTER_NEMOTRON_35_SUPER_VL_FREE,),
        frozenset({T, J, N, L}), 1_000_000, tier=1,
        modalities=frozenset({"text", "image"}),
    ),
    ProviderEntry(
        "mistral", "litellm", ("mistral-large",), frozenset({T, J, N}), 32768,
        tier=3,
    ),
    ProviderEntry(
        "nim", "nim", ("meta/llama-3.3-70b-instruct",), frozenset({T, J, N}),
        32768, tier=1,
    ),
    ProviderEntry(
        "ollama", "ollama", ("qwen3.5:2b",),
        frozenset({T}), 16384, is_cloud=False, tier=0,
    ),
    # Measured 2026-10-11 (Ollama/Q4_K_M, ctx 4096): 8/8 valid JSON,
    # planning/coding/deferral PASS; ~4.5 tok/s CPU; ~= 6.6 GiB residency.
    ProviderEntry(
        "ollama", "ollama", ("qwen3.5:9b",),
        frozenset({T, J}), 16384, is_cloud=False, tier=0,
    ),
    # Metadata only: routable only when allowlisted + healthy + authorized.
    ProviderEntry(
        "cloudflare", "litellm",
        ("cloudflare/@cf/meta/llama-3.1-8b-instruct",),
        frozenset({T}), 8192, tier=1,
    ),
    ProviderEntry(
        "openai", "cloud", ("gpt-4o-mini",), frozenset({T, J, N}), 128000,
        tier=3,
    ),
)


@dataclass
class ProviderHealth:
    """Liveness per provider. Default unknown→unroutable until probed."""

    reachable: Dict[str, bool] = field(default_factory=dict)

    def mark(self, name: str, ok: bool) -> None:
        self.reachable[name] = ok

    def is_routable(self, entry: ProviderEntry) -> bool:
        return self.reachable.get(entry.name, False)


def allowlist_keys(entries: List[ProviderEntry]) -> List[Tuple[str, str, str]]:
    """Exact allowlist keys for explicitly approved (entry, model) pairs."""
    return [
        (e.engine, e.name, m) for e in entries for m in e.models
    ]


def routable_entries(
    wanted: List[str], health: ProviderHealth
) -> List[ProviderEntry]:
    """Subset of CATALOG that is both wanted and healthy."""
    by_name: Dict[str, List[ProviderEntry]] = {}
    for entry in CATALOG:
        by_name.setdefault(entry.name, []).append(entry)
    out = []
    for name in wanted:
        for entry in by_name.get(name, []):
            if health.is_routable(entry):
                out.append(entry)
    return out


__all__ = [
    "CATALOG",
    "OPENROUTER_NEMOTRON_35_SUPER_VL_FREE",
    "ProviderEntry",
    "ProviderHealth",
    "allowlist_keys",
    "routable_entries",
]
