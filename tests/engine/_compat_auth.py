"""Shared sealed-auth helper for compat-engine enforcement tests.

Mints a host-side authorization matching exactly what the engine will
verify: (engine_id, engine_id, requested model), engine host endpoint,
and the engine's own wire message dicts. Fake scanners/policy only.
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


def arm_engine(engine, monkeypatch, *, session: str = ""):
    """Attach host authorizer + ledger to an engine; enable the flag."""
    import threading

    monkeypatch.setenv("ASTRA_COMPAT_EGRESS", "on")
    authz = CloudDispatchAuthorizer(
        allowlist={(engine.engine_id, engine.engine_id, "*")},
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"host": ["llm:cloud"]}),
    )
    # NOTE: allowlist is exact-match; expand per model below via seal().
    engine._authorizer = authz
    engine._dispatch_ledger = CloudDispatchLedger()
    engine._session_id = session
    engine._seen_nonces = set()
    engine._nonce_lock = threading.Lock()
    engine._compat_test_authz = authz
    return authz


def seal(engine, model: str, messages, *, session: str = ""):
    """Mint a sealed payload matching this engine/model/messages."""
    authz = engine._compat_test_authz
    authz._allowlist = frozenset(
        {(engine.engine_id, engine.engine_id, model)}
    )
    wire = messages_to_dicts(messages)
    pairs = tuple(
        {"role": str(m.get("role", "user")), "content": str(m.get("content", ""))}
        for m in wire
    )
    return authz.authorize(
        CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(
                engine=engine.engine_id,
                provider=engine.engine_id,
                model=model,
                is_cloud=True,
                endpoint=engine._host,
            ),
            messages=pairs,
            grant=ExplicitGrant(agent_id="host", capability="llm:cloud"),
            budget=BudgetReservation(
                est_prompt_tokens=64, max_tokens=256, ctx_limit=8192
            ),
            session_id=session,
            nonce=f"t-{uuid.uuid4().hex}",
        )
    )


def authed_generate(engine, messages, model: str, **kw):
    """generate() with a matching sealed authorization attached."""
    kw["cloud_dispatch"] = seal(engine, model, messages)
    return engine.generate(messages, model=model, **kw)


async def authed_stream(engine, messages, model: str, **kw):
    """Collect stream() with a matching sealed authorization attached."""
    kw["cloud_dispatch"] = seal(engine, model, messages)
    return [
        token
        async for token in engine.stream(messages, model=model, **kw)
    ]


def g(engine, messages, model: str, **kw):
    """Drop-in generate(): same convention, sealed auth attached."""
    return authed_generate(engine, messages, model, **kw)


async def s(engine, messages, model: str, **kw):
    """Drop-in stream collector: same convention, sealed auth attached."""
    return await authed_stream(engine, messages, model, **kw)


async def sf(engine, messages, model: str, **kw):
    """Drop-in stream_full collector: same convention, sealed auth attached."""
    kw["cloud_dispatch"] = seal(engine, model, messages)
    return [
        chunk
        async for chunk in engine.stream_full(messages, model=model, **kw)
    ]
