"""Multi-provider tests — fake health only, no live cloud, no keys."""

from __future__ import annotations

import pytest

from openjarvis.engine.provider_catalog import (
    CATALOG,
    OPENROUTER_NEMOTRON_35_SUPER_VL_FREE,
    ProviderHealth,
    allowlist_keys,
    routable_entries,
)
from openjarvis.security.cloud_dispatch import (
    BudgetReservation,
    CloudDispatchAuthorizer,
    CloudDispatchRequest,
    ExplicitGrant,
    PrivacyClassification,
    PrivacyDenied,
    ProviderIdentity,
)


class _Scanner:
    def scan(self, text: str):  # noqa: D102
        from types import SimpleNamespace

        return SimpleNamespace(findings=[])

    def redact(self, text: str):  # noqa: D102
        return text


class _FakePolicy:
    def __init__(self, grants: dict) -> None:
        self._grants = grants

    def list_agents(self):  # noqa: D102
        return list(self._grants)

    def list_grants(self, agent_id):  # noqa: D102
        from types import SimpleNamespace

        return [SimpleNamespace(capability=c) for c in self._grants.get(agent_id, [])]

    def check(self, agent_id, capability, resource=""):  # noqa: D102
        return capability in self._grants.get(agent_id, [])


def _authz(allow):
    return CloudDispatchAuthorizer(
        allowlist=set(allow),
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"a": ["llm:cloud"]}),
    )


class TestCatalog:
    def test_all_candidates_present(self) -> None:
        names = {e.name for e in CATALOG}
        assert {
            "groq", "gemini", "cerebras", "openrouter", "mistral", "nim",
            "ollama",
        } <= names

    def test_key_presence_is_not_permission(self) -> None:
        """A provider 'having a key' (simulated) grants nothing."""
        authz = _authz(
            allowlist_keys([e for e in CATALOG if e.name == "groq"])
        )
        ok = CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(
                engine="litellm", provider="groq", model="llama-3.3-70b"
            ),
            messages=({"role": "user", "content": "hi"},),
            grant=ExplicitGrant(agent_id="a", capability="llm:cloud"),
            budget=BudgetReservation(
                est_prompt_tokens=5, max_tokens=10, ctx_limit=1000
            ),
        )
        authz.authorize(ok)  # allowlisted -> fine
        evil = CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(
                engine="litellm", provider="cerebras", model="llama-3.3-70b"
            ),
            messages=({"role": "user", "content": "hi"},),
            grant=ExplicitGrant(agent_id="a", capability="llm:cloud"),
            budget=BudgetReservation(
                est_prompt_tokens=5, max_tokens=10, ctx_limit=1000
            ),
        )
        with pytest.raises(PrivacyDenied):
            authz.authorize(evil)

    def test_health_gates_routing(self) -> None:
        health = ProviderHealth()
        assert routable_entries(["groq", "nim"], health) == []
        health.mark("groq", True)
        assert [e.name for e in routable_entries(["groq", "nim"], health)] == ["groq"]
        health.mark("nim", False)
        assert [e.name for e in routable_entries(["groq", "nim"], health)] == ["groq"]

    def test_ollama_is_local_only(self) -> None:
        ollama = next(e for e in CATALOG if e.name == "ollama")
        assert ollama.is_cloud is False

    def test_openrouter_nemotron_free_is_explicitly_capable(self) -> None:
        entry = next(
            e for e in CATALOG
            if OPENROUTER_NEMOTRON_35_SUPER_VL_FREE in e.models
        )
        assert entry.models == (OPENROUTER_NEMOTRON_35_SUPER_VL_FREE,)
        assert entry.ctx_limit == 1_000_000
        assert entry.modalities == frozenset({"text", "image"})
        assert {"TEXT", "STRUCTURED_JSON", "NATIVE_TOOLS", "LONG_CONTEXT"} == {
            capability.value for capability in entry.capabilities
        }
        assert (
            "cloud", "openrouter", OPENROUTER_NEMOTRON_35_SUPER_VL_FREE
        ) in allowlist_keys([entry])
        assert (
            "cloud", "openrouter", "openrouter/nvidia/nemotron-3.5-super-vl"
        ) not in allowlist_keys([entry])

    def test_openrouter_health_keeps_model_scoped_entries(self) -> None:
        health = ProviderHealth()
        health.mark("openrouter", True)
        entries = routable_entries(["openrouter"], health)
        assert [entry.models for entry in entries] == [
            ("openrouter/auto",),
            (OPENROUTER_NEMOTRON_35_SUPER_VL_FREE,),
        ]
