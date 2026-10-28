"""Host supply factory — the single host authority for production supply.

Everything a managed tick needs before it may observe or dispatch is
built here from host-owned configuration only: model card registry,
provider snapshot, privacy policy, egress policy, shadow observer, cloud
authorizer, dispatch ledger, session binding, provider/endpoint
allowlists, credential availability, and the minimizer/redaction policy.

Nothing is duplicated: registries come from
:mod:`openjarvis.agents.host_routing`, authorization from
:mod:`openjarvis.security.cloud_dispatch`, integrity from
:mod:`openjarvis.security.dispatch_ledger`, the choke point from
:mod:`openjarvis.security.egress_guard`, and minimization/redaction from
:mod:`openjarvis.agents.privacy_pipeline`.

Trust boundary: model, agent, and tool output are untrusted proposals.
They can request a dispatch but never mint authority — every grant,
privacy label, provider/endpoint allowlist entry, session id, and seal
comes from this module's verified :class:`HostConfig`.

The factory performs no network I/O, no tool dispatch, and no OS
mutation. Missing or mismatched supply raises
:class:`HostSupplyError` with a machine-readable code; no value is ever
guessed or defaulted into existence.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Tuple

from openjarvis.agents.host_routing import (
    HostEgressPolicy,
    ModelCardRegistry,
    RoutingError,
    SnapshotEnvelope,
    authorize_egress,
    build_snapshot,
    classify_privacy,
)
from openjarvis.agents.privacy_pipeline import (
    MinimizerEvidence,
    PipelineError,
    adapt_provider_messages,
    build_provider_envelope,
    minimize_context,
    redact_credentials,
    seal_authorized_envelope,
)
from openjarvis.agents.shadow_observer import ShadowObserver
from openjarvis.security.cloud_dispatch import (
    BudgetReservation,
    CloudDispatchAuthorizer,
    CloudDispatchRequest,
    ExplicitGrant,
    PrivacyClassification,
    PrivacyDenied,
    ProviderIdentity,
)
from openjarvis.security.dispatch_ledger import (
    CloudDispatchLedger,
    DispatchEntry,
)

# ---------------------------------------------------------------------------
# Failure codes (stable contract)
# ---------------------------------------------------------------------------

HOST_CONFIG_MISSING = "HOST_CONFIG_MISSING"
HOST_CONFIG_INVALID = "HOST_CONFIG_INVALID"
HOST_MODE_INVALID = "HOST_MODE_INVALID"
SHADOW_SUPPLY_INCOMPLETE = "SHADOW_SUPPLY_INCOMPLETE"
CLOUD_SUPPLY_INCOMPLETE = "CLOUD_SUPPLY_INCOMPLETE"
PROVIDER_UNKNOWN = "PROVIDER_UNKNOWN"
ENDPOINT_UNKNOWN = "ENDPOINT_UNKNOWN"
CREDENTIAL_MISSING = "CREDENTIAL_MISSING"
SESSION_IDENTITY_MISSING = "SESSION_IDENTITY_MISSING"
PRIVACY_UNKNOWN = "PRIVACY_UNKNOWN"
MINIMIZER_REQUIRED = "MINIMIZER_REQUIRED"
PRIVACY_SCANNER_UNAVAILABLE = "PRIVACY_SCANNER_UNAVAILABLE"
SNAPSHOT_STALE = "SNAPSHOT_STALE"

#: Deployment postures. Only ``MODE_CLOUD`` may ever authorize egress.
MODE_LOCAL_ONLY = "local_only"
MODE_SHADOW_ONLY = "shadow_only"
MODE_CLOUD = "cloud_enabled"
_MODES = frozenset({MODE_LOCAL_ONLY, MODE_SHADOW_ONLY, MODE_CLOUD})

#: Host privacy key used when a destination-scoped label is not configured.
DEFAULT_PRIVACY_KEY = "default"


class HostSupplyError(RuntimeError):
    """Fail-closed host supply refusal with a machine-readable code."""

    def __init__(self, code: str, reason: str = "") -> None:
        super().__init__(f"{code}: {reason}" if reason else code)
        self.code = code
        self.reason = reason


def _require(condition: Any, code: str, reason: str) -> None:
    if not condition:
        raise HostSupplyError(code, reason)


def key_str(key: Iterable[str]) -> str:
    """Canonical ``engine/provider/model`` string for map lookups."""
    return "/".join(str(part) for part in key)


def mint_session_identity() -> str:
    """Mint a host session id. Identity only — never a credential."""
    return f"hsess_{uuid.uuid4().hex}"


# ---------------------------------------------------------------------------
# Host configuration contract
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HostConfig:
    """Validated host configuration. Absent values stay absent.

    Required per posture:

    * ``MODE_LOCAL_ONLY`` — nothing beyond ``mode``.
    * ``MODE_SHADOW_ONLY`` — ``model_registry`` + ``snapshot_status``,
      and ``snapshot_enabled``/``shadow_enabled`` to observe at all.
    * ``MODE_CLOUD`` — everything above plus ``provider_allowlist``,
      ``endpoints`` + ``endpoint_allowlist``, ``privacy_policy``,
      ``scanners``, ``capability_policy``, ``session_identity``,
      ``credential_available``, and ``minimizer_allow``/
      ``minimizer_purpose``.

    ``credential_reference`` names *where* a credential lives; the secret
    itself is never stored here, logged, or observed.
    """

    mode: str = MODE_LOCAL_ONLY

    # -- routing supply ---------------------------------------------------
    model_registry: Tuple[Mapping[str, Any], ...] = ()
    snapshot_status: Mapping[Tuple[str, str, str], bool] = field(
        default_factory=dict)
    snapshot_version: int = 0
    snapshot_issued_at: float = 0.0
    snapshot_max_age_s: float = 600.0

    # -- feature flags (host-owned, default OFF) --------------------------
    shadow_enabled: bool = False
    cloud_egress_enabled: bool = False

    # -- privacy / egress policy -----------------------------------------
    privacy_policy: Mapping[str, str] = field(default_factory=dict)
    egress_policy: HostEgressPolicy = field(default_factory=HostEgressPolicy)

    # -- cloud supply -----------------------------------------------------
    provider_allowlist: Tuple[Tuple[str, str, str], ...] = ()
    endpoints: Mapping[str, str] = field(default_factory=dict)
    endpoint_allowlist: Tuple[str, ...] = ()
    scanners: Tuple[Any, ...] = ()
    capability_policy: Any = None
    session_identity: str = ""
    credential_reference: str = ""
    credential_available: Optional[Callable[[str], bool]] = None

    # -- minimization / redaction policy ----------------------------------
    minimizer_allow: Tuple[str, ...] = ()
    minimizer_purpose: str = ""


# ---------------------------------------------------------------------------
# Built supply
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CloudDispatchPlan:
    """Authorized-but-unsent cloud dispatch: exact bytes plus bindings.

    Produced by :func:`host_cloud_dispatch`. Holding a plan authorizes
    nothing by itself — :meth:`assert_sendable` must pass at the send
    instant, and the ledger entry must be begun first.
    """

    sealed: Any
    wire_messages: Tuple[Dict[str, str], ...]
    endpoint: str
    session_id: str
    dispatch_id: str
    provider_key: Tuple[str, str, str]
    classification: str = ""
    entry: Optional[DispatchEntry] = None

    def assert_sendable(self, bundle: "HostSupplyBundle") -> None:
        """Verify session, endpoint, and provider bindings before sending."""
        if bundle.mode != MODE_CLOUD or not bundle.cloud_egress_enabled:
            raise HostSupplyError(CLOUD_SUPPLY_INCOMPLETE,
                                  "cloud egress is not enabled on this supply")
        if self.sealed.session_id != bundle.session_id:
            raise HostSupplyError(SESSION_IDENTITY_MISSING,
                                  "session binding changed after authorization")
        if self.endpoint not in bundle.endpoint_allowlist:
            raise HostSupplyError(ENDPOINT_UNKNOWN,
                                  "endpoint no longer allowed at send time")
        if self.provider_key not in bundle.provider_allowlist:
            raise HostSupplyError(PROVIDER_UNKNOWN,
                                  "destination no longer allowlisted")


@dataclass(frozen=True)
class HostSupplyBundle:
    """Verified host supply. Every field is host-owned and pre-verified."""

    mode: str
    registry: ModelCardRegistry
    snapshot: SnapshotEnvelope
    snapshot_max_age_s: float
    egress_policy: HostEgressPolicy
    shadow_observer: ShadowObserver
    dispatch_ledger: CloudDispatchLedger
    cloud_authorizer: Optional[CloudDispatchAuthorizer]
    session_id: str
    provider_allowlist: Tuple[Tuple[str, str, str], ...]
    endpoints: Mapping[str, str]
    endpoint_allowlist: Tuple[str, ...]
    privacy_policy: Mapping[str, str]
    minimizer_allow: Tuple[str, ...]
    minimizer_purpose: str
    cloud_egress_enabled: bool
    credential_reference: str
    credential_available: Optional[Callable[[str], bool]] = None
    scanners: Tuple[Any, ...] = ()
    capability_policy: Any = None

    # -- privacy ----------------------------------------------------------
    def privacy_for(self, agent_id: str = "", agent_privacy: Any = "") \
            -> PrivacyClassification:
        """Resolve privacy from host policy; unknown always fails closed.

        The host mapping always wins. In cloud posture it must be
        exhaustive and per-agent: an unmapped agent is UNKNOWN and can
        never be downgraded from its own self-declared label. Only
        non-egress postures may fall back to a host default or the
        agent's own label.
        """
        label = self.privacy_policy.get(agent_id)
        if label is None:
            if self.mode == MODE_CLOUD:
                raise HostSupplyError(PRIVACY_UNKNOWN,
                                      "no host privacy label for this agent")
            label = self.privacy_policy.get(DEFAULT_PRIVACY_KEY,
                                            agent_privacy)
        try:
            return classify_privacy(label)
        except RoutingError as exc:
            raise HostSupplyError(PRIVACY_UNKNOWN, exc.reason) from None

    # -- destination binding ----------------------------------------------
    def endpoint_for(self, engine: str, provider: str, model: str) -> str:
        """Return the host-bound endpoint for exactly one registry card."""
        key = (engine, provider, model)
        if key not in self.provider_allowlist:
            raise HostSupplyError(PROVIDER_UNKNOWN, f"{key!r} not allowlisted")
        if len([c for c in self.registry.cards if c.key() == key]) != 1:
            raise HostSupplyError(PROVIDER_UNKNOWN,
                                  "destination is not uniquely bound")
        endpoint = self.endpoints.get(key_str(key), "")
        if not endpoint or endpoint not in self.endpoint_allowlist:
            raise HostSupplyError(ENDPOINT_UNKNOWN, f"no allowed endpoint {key!r}")
        return endpoint

    def require_credential(self, provider: str) -> None:
        """Fail closed when the host reports no credential for a provider."""
        if not self.credential_reference:
            raise HostSupplyError(CREDENTIAL_MISSING,
                                  "no credential reference configured")
        probe = self.credential_available
        if not callable(probe) or not probe(provider):
            raise HostSupplyError(CREDENTIAL_MISSING,
                                  f"credential unavailable for {provider!r}")

    def guard_engine(self, inner: Any, *, local_allowlist: Optional[
            Iterable[str]] = None) -> Any:
        """Wrap one engine in the existing egress choke point.

        Requires cloud supply; without it there is no authorizer to
        authorize with, so wrapping would only add an unusable object.
        """
        from openjarvis.security.egress_guard import guard_engine

        if self.cloud_authorizer is None:
            raise HostSupplyError(CLOUD_SUPPLY_INCOMPLETE,
                                  "no cloud authorizer on this supply")
        return guard_engine(
            inner, self.cloud_authorizer,
            local_allowlist=(frozenset(local_allowlist)
                             if local_allowlist is not None else None),
        )

    def audit_snapshot(self) -> Dict[str, Any]:
        """Supply audit summary — identities and codes only, no secrets."""
        return {
            "mode": self.mode,
            "shadow_enabled": self.shadow_observer.enabled,
            "cloud_egress_enabled": self.cloud_egress_enabled,
            "cards": len(self.registry.cards),
            "snapshot_version": self.snapshot.version,
            "allowlist": sorted(key_str(k) for k in self.provider_allowlist),
            "endpoints": sorted(self.endpoint_allowlist),
            "session_bound": bool(self.session_id),
            "credential_reference": self.credential_reference,
        }


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def _build_registry(config: HostConfig, *, required: bool) -> ModelCardRegistry:
    if not config.model_registry:
        if required:
            raise HostSupplyError(SHADOW_SUPPLY_INCOMPLETE
                                  if not config.cloud_egress_enabled
                                  else CLOUD_SUPPLY_INCOMPLETE,
                                  "model registry is empty")
        return ModelCardRegistry()
    try:
        return ModelCardRegistry.from_host_config(list(config.model_registry))
    except RoutingError as exc:
        raise HostSupplyError(exc.code, exc.reason) from None


def _build_snapshot(config: HostConfig, *, required: bool,
                    now: float) -> SnapshotEnvelope:
    observing = config.shadow_enabled or config.cloud_egress_enabled
    if not observing:
        return SnapshotEnvelope(version=config.snapshot_version,
                                issued_at=config.snapshot_issued_at)
    if required and (not config.snapshot_status
                     or not config.snapshot_issued_at):
        raise HostSupplyError(SHADOW_SUPPLY_INCOMPLETE
                              if not config.cloud_egress_enabled
                              else CLOUD_SUPPLY_INCOMPLETE,
                              "no provider snapshot supplied")
    envelope = build_snapshot(
        dict(config.snapshot_status), version=config.snapshot_version,
        issued_at=config.snapshot_issued_at)
    try:
        envelope.require_fresh(max_age_s=config.snapshot_max_age_s, now=now)
    except RoutingError as exc:
        raise HostSupplyError(SNAPSHOT_STALE, exc.reason) from None
    return envelope


def _validate_allowlist(config: HostConfig, registry: ModelCardRegistry) -> None:
    _require(config.provider_allowlist, PROVIDER_UNKNOWN,
             "provider allowlist is empty")
    seen = set()
    for entry in config.provider_allowlist:
        _require(isinstance(entry, (tuple, list)) and len(entry) == 3,
                 HOST_CONFIG_INVALID, "allowlist entries must be 3-tuples")
        key = tuple(str(part) for part in entry)
        matches = [c for c in registry.cards if c.key() == key]
        if len(matches) != 1:
            raise HostSupplyError(PROVIDER_UNKNOWN,
                                  f"{key_str(key)!r} matches {len(matches)} cards")
        if key in seen:
            raise HostSupplyError(HOST_CONFIG_INVALID,
                                  f"duplicate allowlist entry {key_str(key)!r}")
        seen.add(key)


def _validate_endpoints(config: HostConfig) -> None:
    _require(config.endpoint_allowlist, ENDPOINT_UNKNOWN,
             "endpoint allowlist is empty")
    _require(config.endpoints, ENDPOINT_UNKNOWN, "no endpoint bindings supplied")
    for name, endpoint in config.endpoints.items():
        if endpoint not in config.endpoint_allowlist:
            raise HostSupplyError(ENDPOINT_UNKNOWN,
                                  f"{name!r} endpoint is not allowlisted")
        if not str(endpoint).startswith("https://"):
            raise HostSupplyError(ENDPOINT_UNKNOWN,
                                  f"{name!r} endpoint is not https")


def _validate_scanners(config: HostConfig) -> None:
    if not config.scanners:
        raise HostSupplyError(PRIVACY_SCANNER_UNAVAILABLE,
                              "no privacy scanners configured")
    for scanner in config.scanners:
        if not callable(getattr(scanner, "scan", None)) or not callable(
                getattr(scanner, "redact", None)):
            raise HostSupplyError(PRIVACY_SCANNER_UNAVAILABLE,
                                  "scanner missing scan/redact interface")


def _validate_capability_policy(config: HostConfig) -> None:
    policy = config.capability_policy
    for attr in ("list_agents", "list_grants", "check"):
        if not callable(getattr(policy, attr, None)):
            raise HostSupplyError(CLOUD_SUPPLY_INCOMPLETE,
                                  f"capability policy missing {attr}()")


def _validate_privacy_policy(config: HostConfig) -> None:
    _require(config.privacy_policy, PRIVACY_UNKNOWN,
             "privacy policy is empty")
    for subject, label in config.privacy_policy.items():
        try:
            classify_privacy(label)
        except RoutingError as exc:
            raise HostSupplyError(PRIVACY_UNKNOWN,
                                  f"{subject!r}: {exc.reason}") from None
    # A default label would silently cover unmapped agents at egress.
    if DEFAULT_PRIVACY_KEY in config.privacy_policy:
        raise HostSupplyError(PRIVACY_UNKNOWN,
                              "cloud privacy policy must be per-agent")


def _validate_minimizer(config: HostConfig) -> None:
    if not config.minimizer_allow or not config.minimizer_purpose.strip():
        raise HostSupplyError(MINIMIZER_REQUIRED,
                              "minimizer allowlist and purpose are required")


def build_host_supply(config: HostConfig, *,
                      now: Optional[float] = None) -> HostSupplyBundle:
    """Build the verified host supply, or raise :class:`HostSupplyError`.

    Posture defaults to ``MODE_LOCAL_ONLY`` with both feature flags OFF, so
    an unconfigured host keeps legacy behavior byte-for-byte. Cloud supply
    is only assembled when the host explicitly enables it and every
    required field is present and consistent.
    """
    _require(isinstance(config, HostConfig), HOST_CONFIG_MISSING,
             "config must be a HostConfig")
    _require(config.mode in _MODES, HOST_MODE_INVALID, f"{config.mode!r}")
    stamp = time.time() if now is None else float(now)
    if config.cloud_egress_enabled and config.mode != MODE_CLOUD:
        raise HostSupplyError(HOST_CONFIG_INVALID,
                              "cloud egress requires MODE_CLOUD")
    if config.shadow_enabled and config.mode == MODE_LOCAL_ONLY:
        raise HostSupplyError(HOST_CONFIG_INVALID,
                              "shadow observation requires MODE_SHADOW_ONLY")

    registry = _build_registry(
        config, required=config.shadow_enabled or config.cloud_egress_enabled)
    snapshot = _build_snapshot(
        config, required=config.shadow_enabled or config.cloud_egress_enabled,
        now=stamp)

    authorizer: Optional[CloudDispatchAuthorizer] = None
    session_id = ""
    if config.cloud_egress_enabled:
        _validate_allowlist(config, registry)
        _validate_endpoints(config)
        _validate_privacy_policy(config)
        _validate_scanners(config)
        _validate_capability_policy(config)
        _validate_minimizer(config)
        if not config.session_identity.strip():
            raise HostSupplyError(SESSION_IDENTITY_MISSING,
                                  "session identity is required for cloud")
        if not config.credential_reference:
            raise HostSupplyError(CREDENTIAL_MISSING,
                                  "credential reference is required for cloud")
        if not callable(config.credential_available):
            raise HostSupplyError(CREDENTIAL_MISSING,
                                  "credential availability probe is required")
        session_id = config.session_identity
        authorizer = CloudDispatchAuthorizer(
            allowlist=config.provider_allowlist,
            scanners=config.scanners,
            capability_policy=config.capability_policy,
            allowed_endpoints=config.endpoint_allowlist,
        )

    return HostSupplyBundle(
        mode=config.mode,
        registry=registry,
        snapshot=snapshot,
        snapshot_max_age_s=config.snapshot_max_age_s,
        egress_policy=config.egress_policy,
        shadow_observer=ShadowObserver(enabled=config.shadow_enabled),
        dispatch_ledger=CloudDispatchLedger(),
        cloud_authorizer=authorizer,
        session_id=session_id,
        provider_allowlist=tuple(tuple(k) for k in config.provider_allowlist),
        endpoints=dict(config.endpoints),
        endpoint_allowlist=tuple(config.endpoint_allowlist),
        privacy_policy=dict(config.privacy_policy),
        minimizer_allow=tuple(config.minimizer_allow),
        minimizer_purpose=config.minimizer_purpose,
        cloud_egress_enabled=config.cloud_egress_enabled,
        credential_reference=config.credential_reference,
        credential_available=config.credential_available,
        scanners=tuple(config.scanners),
        capability_policy=config.capability_policy,
    )


# ---------------------------------------------------------------------------
# Cloud dispatch chain (authorize -> sanitize -> verify -> ledger, no send)
# ---------------------------------------------------------------------------


def sanitize_messages(bundle: HostSupplyBundle, messages: Any, *, model: str,
                      agent_id: str = "", privacy: Any = "",
                      max_messages: int = 64, max_chars: int = 8000,
                      max_total_bytes: int = 65536,
                      max_items: int = 64,
                      max_bytes: int = 65536) -> Tuple[Dict[str, Any], Any]:
    """Minimize + redact one message sequence under host policy.

    Returns ``(envelope, classification)`` where the envelope carries only
    allowlisted, redacted fields. Raises before any authorization when
    minimization or redaction cannot be proven.
    """
    adapted, _ = adapt_provider_messages(
        messages, max_messages=max_messages, max_chars=max_chars,
        max_total_bytes=max_total_bytes)
    try:
        raw = build_provider_envelope(model, adapted)
        envelope, _ = minimize_context(
            raw, allow=bundle.minimizer_allow,
            purpose=bundle.minimizer_purpose, max_items=max_items,
            max_bytes=max_bytes)
    except PipelineError as exc:
        raise HostSupplyError(exc.code, exc.reason) from None
    clean, _ = redact_credentials(envelope)
    return clean, bundle.privacy_for(agent_id, privacy)


def host_cloud_dispatch(bundle: HostSupplyBundle, *, engine: str,
                        provider: str, model: str, messages: Any,
                        agent_id: str, capability: str,
                        privacy: Any = "",
                        max_tokens: int = 1024, est_prompt_tokens: int = 0,
                        per_request_usd: Optional[float] = None,
                        session_left_usd: Optional[float] = None,
                        expires_at: Optional[float] = None,
                        max_messages: int = 64, max_chars: int = 8000,
                        max_total_bytes: int = 65536,
                        max_items: int = 64,
                        max_bytes: int = 65536) -> CloudDispatchPlan:
    """Run the full host chain and return an unsent, sealed plan.

    Sanitize -> bind destination/endpoint/credential -> authorize ->
    verify-for-send -> ledger begin. Nothing is transmitted: the caller
    performs the send after :meth:`CloudDispatchPlan.assert_sendable`.
    Any host-policy refusal raises ``HostSupplyError`` (or propagates
    ``PrivacyDenied`` for authorizer/ledger refusals) before a plan exists.
    """
    if bundle.cloud_authorizer is None or not bundle.cloud_egress_enabled:
        raise HostSupplyError(CLOUD_SUPPLY_INCOMPLETE,
                              "cloud egress is not enabled on this supply")
    envelope, classification = sanitize_messages(
        bundle, messages, model=model, agent_id=agent_id, privacy=privacy,
        max_messages=max_messages, max_chars=max_chars,
        max_total_bytes=max_total_bytes, max_items=max_items,
        max_bytes=max_bytes)
    endpoint = bundle.endpoint_for(engine, provider, model)
    bundle.require_credential(provider)

    decision = authorize_egress(
        registry=bundle.registry, policy=bundle.egress_policy,
        privacy=classification.value, provider=provider, engine=engine,
        model=model, has_minimizer=True, contains_credentials=False,
        available=True)
    if not decision.allowed:
        raise HostSupplyError(decision.code, decision.reason)

    identity = ProviderIdentity(engine=engine, provider=provider, model=model,
                                is_cloud=True, endpoint=endpoint)
    request = CloudDispatchRequest(
        classification=classification,
        provider=identity,
        messages=tuple({"role": str(m.get("role", "user")),
                        "content": str(m.get("content", ""))}
                       for m in envelope.get("messages", [])),
        grant=ExplicitGrant(agent_id=agent_id, capability=capability,
                            expires_at=expires_at),
        budget=BudgetReservation(
            est_prompt_tokens=est_prompt_tokens, max_tokens=max_tokens,
            reservation_id=f"bres_{uuid.uuid4().hex[:12]}"),
        session_id=bundle.session_id,
        nonce=uuid.uuid4().hex,
    )
    sealed = bundle.cloud_authorizer.authorize(request)
    # Send-time verification over the exact bytes that will leave, which
    # are the authorizer's post-scan redaction, never the pre-scan input.
    wire = bundle.cloud_authorizer.verify_wire_payload(
        sealed, {"messages": [dict(m) for m in sealed.redacted_messages]},
        endpoint=endpoint)
    entry = bundle.dispatch_ledger.begin(sealed)
    bundle.dispatch_ledger.mark_dispatched(entry)
    bundle.dispatch_ledger.check_send(entry, sealed)
    return CloudDispatchPlan(
        sealed=sealed,
        wire_messages=tuple(wire),
        endpoint=endpoint,
        session_id=sealed.session_id,
        dispatch_id=sealed.dispatch_id,
        provider_key=identity.key(),
        classification=classification.value,
        entry=entry,
    )


def plan_wire_dispatch(bundle: HostSupplyBundle, plan: CloudDispatchPlan
                       ) -> Tuple[Dict[str, Any], Any, Any]:
    """Exact bytes a sender must transmit, plus the egress decision and
    wire seal for them.

    Callers hand these three to the existing dispatch/transport boundary
    (e.g. :class:`~openjarvis.agents.dispatch_contract.DispatchContract`).
    The payload is rebuilt from the plan rather than from caller state, so
    it cannot drift from the authorized bytes.
    """
    engine, provider, model = plan.provider_key
    decision = authorize_egress(
        registry=bundle.registry, policy=bundle.egress_policy,
        privacy=plan.classification, provider=provider, engine=engine,
        model=model, has_minimizer=True, contains_credentials=False,
        available=True)
    payload = {"model": model,
               "messages": [dict(m) for m in plan.wire_messages]}
    return payload, decision, seal_authorized_envelope(payload, decision)


def finish_cloud_dispatch(bundle: HostSupplyBundle, plan: CloudDispatchPlan,
                          state: str, *, code: Optional[str] = None) -> None:
    """Close a begun dispatch. Unknown outcomes are never auto-retried."""
    if plan.entry is None:
        raise HostSupplyError(CLOUD_SUPPLY_INCOMPLETE, "plan was never begun")
    bundle.dispatch_ledger.finish(plan.entry, state, code=code)


def observe_tick(bundle: Optional[HostSupplyBundle], *, agent: Any,
                 system: Any, model: str, engine: str,
                 provider: Optional[str] = None, result: Any = None,
                 error: Optional[BaseException] = None,
                 now: Optional[float] = None) -> Any:
    """Read-only tick observation for a production tick.

    Returns ``None`` when no host supply is configured, so an unwired host
    keeps legacy behavior byte-for-byte. Never raises: an observation
    failure is recorded as an outcome code by the observer and can never
    stop, delay, or alter the tick.
    """
    if bundle is None:
        return None
    stamp = time.time() if now is None else float(now)
    try:
        config = agent.get("config", {}) if isinstance(agent, dict) else {}
        agent_id = str(agent.get("id", "")) if isinstance(agent, dict) else ""
        # Raw host label only: the observer classifies it and records an
        # outcome code when it is unknown, so a gap stays visible instead
        # of vanishing into an exception here.
        privacy = (bundle.privacy_policy.get(agent_id)
                   or bundle.privacy_policy.get(DEFAULT_PRIVACY_KEY)
                   or config.get("privacy", ""))
        return bundle.shadow_observer.observe(
            agent=agent, system=system, model=model, engine=engine,
            provider=provider, result=result, error=error, privacy=privacy,
            registry=bundle.registry, snapshot_env=bundle.snapshot,
            max_age_s=bundle.snapshot_max_age_s, now=stamp)
    except Exception:  # noqa: BLE001 - observation never stops the tick
        return None


# ---------------------------------------------------------------------------
# Host file loading (the operator-supplied supply source)
# ---------------------------------------------------------------------------

#: Environment variable naming the host supply document.
HOST_SUPPLY_PATH_ENV = "JARVIS_HOST_SUPPLY_PATH"

_FIELDS = frozenset({
    "mode", "model_registry", "snapshot", "shadow_enabled",
    "cloud_egress_enabled", "privacy_policy", "egress_policy",
    "provider_allowlist", "endpoints", "endpoint_allowlist",
    "session_identity", "credential_reference", "minimizer",
})


def credential_probe(reference: str) -> Callable[[str], bool]:
    """Presence probe for an ``env:NAME`` credential reference.

    Returns a boolean only; the credential value is never read into the
    bundle, an observation, an audit record, or a log line.
    """
    if not reference.startswith("env:"):
        raise HostSupplyError(CREDENTIAL_MISSING,
                              "credential reference must use the env: scheme")
    name = reference[len("env:"):].strip()
    if not name:
        raise HostSupplyError(CREDENTIAL_MISSING, "empty credential env name")
    return lambda provider: bool(os.environ.get(name))


def load_host_config(path: Any) -> HostConfig:
    """Load the host supply document. Unknown keys refuse; nothing inferred.

    The document carries only host-authored values. Scanners, capability
    policy, and the credential probe are injected by the wiring (see
    :func:`load_host_supply_from_env`), so a file can never invent
    authority objects for itself.
    """
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError) as exc:
        raise HostSupplyError(HOST_CONFIG_INVALID,
                              f"unreadable host supply document "
                              f"({type(exc).__name__})") from None
    if not isinstance(raw, dict):
        raise HostSupplyError(HOST_CONFIG_INVALID, "document must be an object")
    unknown = set(raw) - _FIELDS
    if unknown:
        raise HostSupplyError(HOST_CONFIG_INVALID,
                              f"unknown keys {sorted(unknown)}")
    snapshot = raw.get("snapshot", {}) or {}
    egress = raw.get("egress_policy", {}) or {}
    minimizer = raw.get("minimizer", {}) or {}
    if not isinstance(snapshot, dict) or not isinstance(egress, dict) \
            or not isinstance(minimizer, dict):
        raise HostSupplyError(HOST_CONFIG_INVALID,
                              "snapshot/egress_policy/minimizer must be objects")
    status: Dict[Tuple[str, str, str], bool] = {}
    for entry in snapshot.get("status", ()) or ():
        if not isinstance(entry, (list, tuple)) or len(entry) != 4:
            raise HostSupplyError(HOST_CONFIG_INVALID,
                                  "snapshot status entries must be 4-lists")
        status[tuple(str(p) for p in entry[:3])] = bool(entry[3])
    return HostConfig(
        mode=str(raw.get("mode", MODE_LOCAL_ONLY)),
        model_registry=tuple(raw.get("model_registry", ()) or ()),
        snapshot_status=status,
        snapshot_version=int(snapshot.get("version", 0) or 0),
        snapshot_issued_at=float(snapshot.get("issued_at", 0.0) or 0.0),
        snapshot_max_age_s=float(snapshot.get("max_age_s", 600.0)),
        shadow_enabled=bool(raw.get("shadow_enabled", False)),
        cloud_egress_enabled=bool(raw.get("cloud_egress_enabled", False)),
        privacy_policy=dict(raw.get("privacy_policy", {}) or {}),
        egress_policy=HostEgressPolicy(
            allow_cloud=bool(egress.get("allow_cloud", False)),
            allowed_providers=tuple(egress.get("allowed_providers", ()) or ()),
            allow_raw_internal=bool(egress.get("allow_raw_internal", False)),
            version=int(egress.get("version", 1) or 1)),
        provider_allowlist=tuple(
            tuple(str(p) for p in entry)
            for entry in (raw.get("provider_allowlist", ()) or ())),
        endpoints=dict(raw.get("endpoints", {}) or {}),
        endpoint_allowlist=tuple(raw.get("endpoint_allowlist", ()) or ()),
        session_identity=str(raw.get("session_identity", "") or ""),
        credential_reference=str(raw.get("credential_reference", "") or ""),
        credential_available=credential_probe(
            str(raw["credential_reference"]))
        if raw.get("credential_reference") else None,
        minimizer_allow=tuple(minimizer.get("allow", ()) or ()),
        minimizer_purpose=str(minimizer.get("purpose", "") or ""),
    )


def load_host_supply_from_env(*, scanners: Iterable[Any] = (),
                             capability_policy: Any = None,
                             now: Optional[float] = None
                             ) -> Optional[HostSupplyBundle]:
    """Build supply from the host document named by the environment.

    Returns ``None`` when no path is configured: an unconfigured host
    keeps legacy behavior byte-for-byte. A configured but unreadable or
    invalid document raises instead of silently degrading, so a
    misconfigured host fails closed instead of running unenforced.
    """
    path = os.environ.get(HOST_SUPPLY_PATH_ENV, "").strip()
    if not path:
        return None
    config = load_host_config(path)
    if config.credential_reference and config.credential_available is None:
        config = replace(config, credential_available=credential_probe(
            config.credential_reference))
    return build_host_supply(
        replace(config, scanners=tuple(scanners),
                capability_policy=capability_policy),
        now=now)


__all__ = [
    "CLOUD_SUPPLY_INCOMPLETE",
    "CREDENTIAL_MISSING",
    "DEFAULT_PRIVACY_KEY",
    "ENDPOINT_UNKNOWN",
    "HOST_CONFIG_INVALID",
    "HOST_CONFIG_MISSING",
    "HOST_SUPPLY_PATH_ENV",
    "HOST_MODE_INVALID",
    "MINIMIZER_REQUIRED",
    "MODE_CLOUD",
    "MODE_LOCAL_ONLY",
    "MODE_SHADOW_ONLY",
    "PRIVACY_SCANNER_UNAVAILABLE",
    "PRIVACY_UNKNOWN",
    "PROVIDER_UNKNOWN",
    "SESSION_IDENTITY_MISSING",
    "SHADOW_SUPPLY_INCOMPLETE",
    "SNAPSHOT_STALE",
    "CloudDispatchPlan",
    "HostConfig",
    "HostSupplyBundle",
    "HostSupplyError",
    "MinimizerEvidence",
    "PrivacyDenied",
    "build_host_supply",
    "credential_probe",
    "finish_cloud_dispatch",
    "host_cloud_dispatch",
    "key_str",
    "load_host_config",
    "load_host_supply_from_env",
    "mint_session_identity",
    "observe_tick",
    "plan_wire_dispatch",
    "sanitize_messages",
]
