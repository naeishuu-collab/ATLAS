"""Shared sealed-auth helper for CloudEngine enforcement tests.

Drop-in wrappers (`g`/`s`/`sf`) mirror generate/stream/stream_full and
attach a matching sealed authorization. Per-file autouse flag fixture
(not here) enables ``ASTRA_CLOUD_EGRESS``. Fake scanners/policy only.
"""

from __future__ import annotations

import uuid

from openjarvis.engine._base import messages_to_dicts
from openjarvis.security.cloud_dispatch import (
    BudgetReservation,
    CloudDispatchAuthorizer,
    CloudDispatchRequest,
    ExplicitGrant,
    PrivacyClassification,
    ProviderIdentity,
)
from openjarvis.security.dispatch_ledger import CloudDispatchLedger


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


def arm_engine(engine, session: str = "") -> CloudDispatchAuthorizer:
    """Attach host authorizer + ledger (flag enabled by file fixture)."""
    import threading

    authz = CloudDispatchAuthorizer(
        allowlist=set(),
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"host": ["llm:cloud"]}),
    )
    engine._authorizer = authz
    engine._dispatch_ledger = CloudDispatchLedger()
    engine._session_id = session
    engine._seen_nonces = set()
    engine._nonce_lock = threading.Lock()
    return authz


def seal(engine, model: str, messages, authz=None, session: str = ""):
    """Mint a sealed payload matching this engine/model/messages."""
    authz = authz or engine._authorizer
    resolved = engine._resolve_provider(model)
    if resolved is None:
        raise AssertionError(f"test model does not resolve: {model!r}")
    provider_name, endpoint = resolved
    authz._allowlist = frozenset({("cloud", provider_name, model)})
    wire = messages_to_dicts(messages)
    pairs = tuple(
        {"role": str(m.get("role", "user")), "content": str(m.get("content", ""))}
        for m in wire
    )
    return authz.authorize(
        CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(
                engine="cloud", provider=provider_name, model=model,
                endpoint=endpoint,
            ),
            messages=pairs,
            grant=ExplicitGrant(agent_id="host", capability="llm:cloud"),
            budget=BudgetReservation(
                est_prompt_tokens=256, max_tokens=1024, ctx_limit=8192
            ),
            session_id=session,
            nonce=f"t-{uuid.uuid4().hex}",
        )
    )


def ensure_armed(engine) -> CloudDispatchAuthorizer:
    authz = getattr(engine, "_authorizer", None)
    if authz is None:
        authz = arm_engine(engine)
    return authz


def _sealed_for(engine, model: str, messages, session: str = ""):
    """Mint a sealed payload for an already-armed engine (test helper)."""
    ensure_armed(engine)
    return seal(engine, model, messages, session=session)


def g(engine, messages, model: str, **kw):
    """Drop-in generate(): same convention, sealed auth attached."""
    authz = ensure_armed(engine)
    kw["cloud_dispatch"] = seal(engine, model, messages, authz=authz)
    return engine.generate(messages, model=model, **kw)


async def s(engine, messages, model: str, **kw):
    """Drop-in stream collector: same convention, sealed auth attached."""
    authz = ensure_armed(engine)
    kw["cloud_dispatch"] = seal(engine, model, messages, authz=authz)
    return [t async for t in engine.stream(messages, model=model, **kw)]


async def sf(engine, messages, model: str, **kw):
    """Drop-in stream_full collector."""
    authz = ensure_armed(engine)
    kw["cloud_dispatch"] = seal(engine, model, messages, authz=authz)
    return [c async for c in engine.stream_full(messages, model=model, **kw)]
