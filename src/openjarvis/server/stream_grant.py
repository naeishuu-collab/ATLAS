"""Host-side grant source for the direct chat streaming route.

Derives one cloud dispatch authorization for ``_handle_stream`` from
HOST-OWNED state only — never from the HTTP request body, agent strings,
or LLM output:

    Authenticated Host Principal  (memory authorization user_id)
    -> Host Capability Policy     (supply capability policy: an explicit
                                   ``llm:cloud`` grant for that principal,
                                   or the policy's own default agent —
                                   absent/denied always fails closed)
    -> Host Session Binding       (the supply's session identity)
    -> Host Privacy Pipeline      (per-agent privacy classification plus
                                   minimization/redaction under the host
                                   minimizer allowlist; unmapped subjects
                                   deny in cloud posture)
    -> Provider/Endpoint Binding  (supply registry: one unique cloud card,
                                   https endpoint from the host allowlist)
    -> Credential Availability    (host probe, fail-closed)
    -> CloudDispatchAuthorizer    (sealed AuthorizedPayload, fresh nonce)

This module NEVER opens a ledger entry and NEVER performs a transport
call: the resolved engine's own ``_enforce`` chain begins/marks/finishes
the ledger entry on the supply's ledger (exactly one chain per seal, E2E
proven) and owns the SDK transport. Any refusal raises
``HostSupplyError`` / ``PrivacyDenied`` before any transport, which the
route's SSE wrapper surfaces as an error chunk with zero tokens sent.
"""

from __future__ import annotations

import uuid
from typing import Any, Optional, Sequence

from openjarvis.core.types import Message, Role
from openjarvis.security.cloud_dispatch import (
    CloudDispatchRequest,
    ExplicitGrant,
    PrivacyDenied,
    ProviderIdentity,
)

#: The capability this route demands for cloud dispatch. The host
#: capability policy must declare a matching grant for the authenticated
#: principal (or its configured default agent); the policy, not the
#: request, decides whether dispatch proceeds.
CLOUD_STREAM_CAPABILITY = "llm:cloud"


def mint_stream_dispatch(
    bundle: Any,
    *,
    model: str,
    messages: Sequence[Any],
    agent_id: str,
    max_tokens: int,
) -> Any:
    """Mint one sealed streaming dispatch — no ledger entry, no transport.

    Mirrors the proven ``host_cloud_dispatch`` chain minus the send-time
    ledger begin: the engine ``_enforce`` owns that entry on the supply's
    ledger. Refusals raise before any authorization is returned.
    """
    from openjarvis.agents.host_routing import authorize_egress
    from openjarvis.agents.host_supply_factory import (
        HostSupplyBundle,
        HostSupplyError,
        sanitize_messages,
    )
    from openjarvis.security.cloud_dispatch import BudgetReservation

    if not isinstance(bundle, HostSupplyBundle):
        raise PrivacyDenied("NO_GRANT", "host supply required for cloud stream")
    if bundle.cloud_authorizer is None or not bundle.cloud_egress_enabled:
        raise PrivacyDenied(
            "NO_GRANT", "cloud egress is not enabled on this host supply"
        )
    if not bundle.session_id:
        raise PrivacyDenied(
            "SESSION_MISMATCH", "host session identity missing on supply"
        )
    if not agent_id:
        raise PrivacyDenied(
            "NO_GRANT", "authenticated host principal required"
        )

    envelope, classification = sanitize_messages(
        bundle, messages, model=model, agent_id=agent_id
    )

    keys = {
        k for k in bundle.provider_allowlist if k[0] == "cloud" and k[2] == model
    }
    providers = sorted({k[1] for k in keys})
    if len(providers) != 1:
        raise PrivacyDenied(
            "CLOUD_PROVIDER_NOT_ALLOWED",
            f"no unique cloud provider for model {model!r}",
        )
    provider = providers[0]
    endpoint = bundle.endpoint_for("cloud", provider, model)
    bundle.require_credential(provider)

    decision = authorize_egress(
        registry=bundle.registry,
        policy=bundle.egress_policy,
        privacy=classification.value,
        provider=provider,
        engine="cloud",
        model=model,
        has_minimizer=True,
        contains_credentials=False,
        available=True,
    )
    if not decision.allowed:
        raise HostSupplyError(decision.code, decision.reason)

    wire = tuple(
        {"role": str(m.get("role", "user")), "content": str(m.get("content", ""))}
        for m in envelope.get("messages", [])
    )
    est_prompt_tokens = max(1, sum(len(d["content"]) for d in wire) // 4)
    sealed = bundle.cloud_authorizer.authorize(
        CloudDispatchRequest(
            classification=classification,
            provider=ProviderIdentity(
                engine="cloud", provider=provider, model=model,
                is_cloud=True, endpoint=endpoint,
            ),
            messages=wire,
            grant=ExplicitGrant(
                agent_id=agent_id, capability=CLOUD_STREAM_CAPABILITY
            ),
            budget=BudgetReservation(
                est_prompt_tokens=est_prompt_tokens,
                max_tokens=max(int(max_tokens), 1),
                reservation_id=f"bres_{uuid.uuid4().hex[:12]}",
            ),
            session_id=bundle.session_id,
            nonce=uuid.uuid4().hex,
        )
    )
    return sealed


def authorize_host_stream(
    bundle: Any,
    engine: Any,
    model: str,
    messages: Sequence[Any],
    *,
    authorization: Any,
    temperature: float,
    max_tokens: int,
) -> Optional[Any]:
    """Return an authorized streaming iterator through the supply-bound
    engine, or ``None`` to keep the legacy default-deny router lane.

    Refusals raise ``PrivacyDenied`` / ``HostSupplyError`` with zero
    transport calls; the caller's SSE wrapper surfaces them.
    """
    from openjarvis.agents.host_supply_factory import HostSupplyBundle

    if bundle is None or not isinstance(bundle, HostSupplyBundle):
        return None
    if not bundle.cloud_egress_enabled or bundle.cloud_authorizer is None:
        return None  # legacy lane keeps its own default-deny messages
    principal = getattr(authorization, "user_id", None)
    if not principal:
        raise PrivacyDenied(
            "NO_GRANT", "authenticated host principal required"
        )
    sealed = mint_stream_dispatch(
        bundle,
        model=model,
        messages=messages,
        agent_id=str(principal),
        max_tokens=max_tokens,
    )
    # Stream exactly the authorized bytes (post-scan redaction), so the
    # engine's digest re-verification covers the wire verbatim.
    wire = [
        Message(role=Role(str(m["role"])), content=str(m.get("content", "")))
        for m in sealed.redacted_messages
    ]
    return engine.stream(
        wire,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        cloud_dispatch=sealed,
    )
