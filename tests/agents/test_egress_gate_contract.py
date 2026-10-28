"""Cloud egress gate contract (offline, mock-only, no providers).

Proves the host-owned egress boundary: privacy tiers, provider identity,
host transmission policy, minimizer/redaction requirements, and audit
evidence. Items 14-15 (managed/tick parity) are covered by existing
chain and tick tests; not duplicated.
"""

from __future__ import annotations

import pytest

from openjarvis.agents.host_routing import (
    CREDENTIAL_REDACTION_REQUIRED,
    EGRESS_ALLOWED,
    HOST_POLICY_DENIED,
    MINIMIZER_REQUIRED,
    MODEL_BINDING_UNVERIFIED,
    PRIVACY_BLOCKED,
    PRIVACY_UNKNOWN,
    PROVIDER_UNAVAILABLE,
    HostEgressPolicy,
    ModelCardRegistry,
    authorize_egress,
)
from openjarvis.security.cloud_dispatch import PrivacyClassification


def _cards():
    return [
        {"engine": "fake", "provider": "local", "model": "tiny-4b",
         "capabilities": ["TEXT"], "ctx_limit": 4096,
         "cost_per_1k": 0.0, "latency_p50_ms": 50.0,
         "is_cloud": False, "tier": 0},
        {"engine": "fake", "provider": "cloud", "model": "prose-70b",
         "capabilities": ["TEXT", "STRUCTURED_JSON", "NATIVE_TOOLS"],
         "ctx_limit": 128000, "cost_per_1k": 1.0, "latency_p50_ms": 800.0,
         "is_cloud": True, "structured_reliability": 0.9, "tier": 2},
    ]


def _reg():
    return ModelCardRegistry.from_host_config(_cards())


def _policy(**over):
    args = {"allow_cloud": True, "allowed_providers": ("cloud",),
            "allow_raw_internal": False, "version": 1}
    args.update(over)
    return HostEgressPolicy(**args)


def _egress(registry=None, **over):
    args = {"registry": registry or _reg(), "policy": _policy(),
            "has_minimizer": True, "contains_credentials": False,
            "available": True}
    args.update(over)
    return authorize_egress(**args)


def test_public_normal() -> None:
    d = _egress(privacy="PUBLIC", provider="cloud", engine="fake",
                model="prose-70b")
    assert d.allowed is True and d.code == EGRESS_ALLOWED
    assert d.privacy == PrivacyClassification.PUBLIC


def test_internal_normal() -> None:
    d = _egress(privacy="INTERNAL", provider="cloud", engine="fake",
                model="prose-70b")
    assert d.allowed is True and d.code == EGRESS_ALLOWED


def test_private_local_only() -> None:
    d = _egress(privacy="PRIVATE", provider="local", engine="fake",
                model="tiny-4b")
    assert d.allowed is True and d.code == EGRESS_ALLOWED


def test_private_cloud_rejected() -> None:
    d = _egress(privacy="PRIVATE", provider="cloud", engine="fake",
                model="prose-70b")
    assert d.allowed is False and d.code == PRIVACY_BLOCKED


@pytest.mark.parametrize("label", ["", "ULTRA_SECRET"])
def test_missing_and_unknown_privacy_rejected(label) -> None:
    d = _egress(privacy=label, provider="cloud", engine="fake",
                model="prose-70b")
    assert d.allowed is False and d.code == PRIVACY_UNKNOWN


@pytest.mark.parametrize("label", [123, ["PUBLIC"], None])
def test_invalid_privacy_type_rejected(label) -> None:
    d = _egress(privacy=label, provider="cloud", engine="fake",
                model="prose-70b")
    assert d.allowed is False and d.code == PRIVACY_UNKNOWN


def test_ambiguous_provider_rejected() -> None:
    cards = _cards() + [dict(_cards()[1], provider="cloud-2")]
    reg = ModelCardRegistry.from_host_config(cards)
    # An explicit triple still matches exactly and is allowed ...
    ok = _egress(registry=reg, privacy="PUBLIC", provider="cloud",
                 engine="fake", model="prose-70b")
    assert ok.allowed is True
    # ... but an unknown provider cannot be resolved by model name.
    d = _egress(registry=reg, privacy="PUBLIC", provider="",
                engine="fake", model="prose-70b")
    assert d.allowed is False and d.code == MODEL_BINDING_UNVERIFIED


def test_provider_engine_mismatch_rejected() -> None:
    d = _egress(privacy="PUBLIC", provider="cloud", engine="other",
                model="prose-70b")
    assert d.allowed is False and d.code == MODEL_BINDING_UNVERIFIED


def test_missing_host_policy_rejected() -> None:
    d = _egress(privacy="INTERNAL", provider="cloud", engine="fake",
                model="prose-70b", policy=_policy(allow_cloud=False))
    assert d.allowed is False and d.code == HOST_POLICY_DENIED
    d2 = _egress(privacy="INTERNAL", provider="cloud", engine="fake",
                 model="prose-70b",
                 policy=_policy(allowed_providers=("other",)))
    assert d2.allowed is False and d2.code == HOST_POLICY_DENIED


def test_missing_minimizer_rejected_for_internal() -> None:
    d = _egress(privacy="INTERNAL", provider="cloud", engine="fake",
                model="prose-70b", has_minimizer=False)
    assert d.allowed is False and d.code == MINIMIZER_REQUIRED
    ok = _egress(privacy="INTERNAL", provider="cloud", engine="fake",
                 model="prose-70b", has_minimizer=False,
                 policy=_policy(allow_raw_internal=True))
    assert ok.allowed is True


def test_credential_presence_rejected() -> None:
    d = _egress(privacy="PUBLIC", provider="cloud", engine="fake",
                model="prose-70b", contains_credentials=True)
    assert d.allowed is False and d.code == CREDENTIAL_REDACTION_REQUIRED


def test_unavailable_provider_defers() -> None:
    d = _egress(privacy="PUBLIC", provider="cloud", engine="fake",
                model="prose-70b", available=False)
    assert d.allowed is False and d.code == PROVIDER_UNAVAILABLE
