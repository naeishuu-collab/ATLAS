"""Negative tests for CloudDispatchAuthorizer — fake provider only.

No live cloud, no real PII. Synthetic secrets only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

import pytest

from openjarvis.security.cloud_dispatch import (
    BUDGET_EXCEEDED,
    CLOUD_PAYLOAD_CHANGED,
    CLOUD_PROVIDER_NOT_ALLOWED,
    AuthorizedPayload,
    BudgetReservation,
    CloudDispatchAuthorizer,
    CloudDispatchRequest,
    ExplicitGrant,
    PrivacyClassification,
    PrivacyDenied,
    ProviderIdentity,
)

SYNTH_OPENAI_KEY = "sk-synth-abc123def456ghi789jkl012mno345pqr678stu"
SYNTH_AWS_KEY = "AKIASYNTHETICEXAMPLE1"


@dataclass
class _Finding:
    pattern_name: str
    matched_text: str


@dataclass
class _ScanResult:
    findings: List[_Finding] = field(default_factory=list)


class _MockSecretScanner:
    _PATTERNS = [
        ("synth_openai_key", re.compile(r"sk-synth-[A-Za-z0-9_-]{20,}")),
        ("synth_aws_key", re.compile(r"AKIASYNTHETIC[A-Z0-9]{8}")),
    ]

    def scan(self, text: str) -> _ScanResult:
        findings = []
        for name, pattern in self._PATTERNS:
            for m in pattern.finditer(text):
                findings.append(_Finding(pattern_name=name, matched_text=m.group()))
        return _ScanResult(findings=findings)

    def redact(self, text: str) -> str:
        for name, pattern in self._PATTERNS:
            text = pattern.sub(f"[REDACTED:{name}]", text)
        return text


class _StubbornScanner(_MockSecretScanner):
    """Finds content but never redacts (rescan must deny)."""

    def redact(self, text: str) -> str:  # noqa: D102
        return text


@dataclass
class _Grant:
    capability: str


class _FakePolicy:
    """Minimal policy exposing list_agents/list_grants/check."""

    def __init__(self, grants: dict) -> None:
        self._grants = grants

    def list_agents(self):  # noqa: D102
        return list(self._grants)

    def list_grants(self, agent_id):  # noqa: D102
        return [_Grant(capability=c) for c in self._grants.get(agent_id, [])]

    def check(self, agent_id, capability, resource=""):  # noqa: D102
        if capability in self._grants.get(agent_id, []):
            return True
        return capability in self._grants.get("_default", [])


def _authorizer(**kw):
    base = {
        "allowlist": {("litellm", "groq", "llama-3.3-70b")},
        "scanners": [_MockSecretScanner()],
        "capability_policy": _FakePolicy({"agent-1": ["llm:cloud"]}),
    }
    base.update(kw)
    return CloudDispatchAuthorizer(**base)


def _req(**kw):
    base = {
        "classification": PrivacyClassification.INTERNAL,
        "provider": ProviderIdentity(
            engine="litellm", provider="groq", model="llama-3.3-70b"
        ),
        "messages": ({"role": "user", "content": "hello"},),
        "grant": ExplicitGrant(agent_id="agent-1", capability="llm:cloud"),
        "budget": BudgetReservation(
            est_prompt_tokens=10, max_tokens=50, ctx_limit=4096
        ),
    }
    base.update(kw)
    return CloudDispatchRequest(**base)


class TestClassificationAndLocalOnly:
    def test_unknown_classification_denied(self) -> None:
        with pytest.raises(PrivacyDenied) as ei:
            _authorizer().authorize(_req(classification=None))
        assert ei.value.code == "PRIVACY_CLASSIFICATION_REQUIRED"

    def test_private_cloud_denied(self) -> None:
        with pytest.raises(PrivacyDenied) as ei:
            _authorizer().authorize(
                _req(classification=PrivacyClassification.PRIVATE)
            )
        assert ei.value.code == "PRIVACY_ROUTE_UNAVAILABLE"

    def test_public_allowed(self) -> None:
        auth = _authorizer().authorize(
            _req(classification=PrivacyClassification.PUBLIC)
        )
        assert isinstance(auth, AuthorizedPayload)


class TestAllowlistAndGrant:
    def test_provider_injection_denied(self) -> None:
        evil = ProviderIdentity(
            engine="litellm", provider="evil", model="exfil-1"
        )
        with pytest.raises(PrivacyDenied) as ei:
            _authorizer().authorize(_req(provider=evil))
        assert ei.value.code == CLOUD_PROVIDER_NOT_ALLOWED

    def test_prefix_not_matched(self) -> None:
        # Exact-match only: a superstring model id must not pass.
        evil = ProviderIdentity(
            engine="litellm", provider="groq", model="llama-3.3-70b-evil"
        )
        with pytest.raises(PrivacyDenied):
            _authorizer().authorize(_req(provider=evil))

    def test_missing_grant_denied(self) -> None:
        auth = _authorizer(capability_policy=_FakePolicy({}))
        with pytest.raises(PrivacyDenied):
            auth.authorize(
                _req(grant=ExplicitGrant(agent_id="nobody", capability="llm:cloud"))
            )

    def test_none_policy_denied(self) -> None:
        auth = _authorizer(capability_policy=None)
        with pytest.raises(PrivacyDenied):
            auth.authorize(_req())


class TestScannerFailClosed:
    def test_no_scanners_denied(self) -> None:
        auth = _authorizer(scanners=[])
        with pytest.raises(PrivacyDenied) as ei:
            auth.authorize(_req())
        assert ei.value.code == "PRIVACY_SCANNER_UNAVAILABLE"

    def test_secret_redacted_then_allowed(self) -> None:
        auth = _authorizer().authorize(
            _req(
                messages=(
                    {"role": "user", "content": f"key {SYNTH_OPENAI_KEY} here"},
                )
            )
        )
        assert SYNTH_OPENAI_KEY not in auth.redacted_messages[0]["content"]

    def test_stubborn_scanner_denied(self) -> None:
        auth = _authorizer(scanners=[_StubbornScanner()])
        with pytest.raises(PrivacyDenied):
            auth.authorize(
                _req(
                    messages=(
                        {"role": "user", "content": f"key {SYNTH_AWS_KEY} here"},
                    )
                )
            )


class TestBudget:
    def test_token_budget_exceeded(self) -> None:
        with pytest.raises(PrivacyDenied) as ei:
            _authorizer().authorize(
                _req(
                    budget=BudgetReservation(
                        est_prompt_tokens=4000, max_tokens=500, ctx_limit=4096
                    )
                )
            )
        assert ei.value.code == BUDGET_EXCEEDED

    def test_cost_budget_exceeded(self) -> None:
        with pytest.raises(PrivacyDenied):
            _authorizer().authorize(
                _req(
                    budget=BudgetReservation(
                        est_prompt_tokens=10,
                        max_tokens=10,
                        ctx_limit=4096,
                        per_request_usd=5.0,
                        session_left_usd=1.0,
                    )
                )
            )


class TestPayloadIntegrity:
    def test_verify_ok(self) -> None:
        authz = _authorizer()
        auth = authz.authorize(_req())
        final = authz.verify_for_send(
            auth, [{"role": "user", "content": "hello"}]
        )
        assert final[0]["content"] == "hello"

    def test_mutation_after_auth_rejected(self) -> None:
        authz = _authorizer()
        auth = authz.authorize(_req())
        with pytest.raises(PrivacyDenied) as ei:
            authz.verify_for_send(
                auth, [{"role": "user", "content": "hello tampered"}]
            )
        assert ei.value.code == CLOUD_PAYLOAD_CHANGED

    def test_provider_swap_rejected(self) -> None:
        authz = _authorizer()
        auth = authz.authorize(_req())
        swapped = AuthorizedPayload(
            dispatch_id=auth.dispatch_id,
            provider=ProviderIdentity(
                engine="litellm", provider="evil", model="exfil-1"
            ),
            redacted_messages=auth.redacted_messages,
            digest=auth.digest,
            grant=auth.grant,
            budget_id=auth.budget_id,
        )
        with pytest.raises(PrivacyDenied):
            authz.verify_for_send(
                swapped, [{"role": "user", "content": "hello"}]
            )

    def test_audit_record_has_no_prompts(self) -> None:
        authz = _authorizer()
        auth = authz.authorize(
            _req(
                messages=(
                    {"role": "user", "content": "sensitive synth content"},
                )
            )
        )
        record = CloudDispatchAuthorizer.audit_record(auth, usage={"total_tokens": 5})
        blob = str(record)
        assert "sensitive synth content" not in blob
        assert record["digest"] == auth.digest
