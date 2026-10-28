"""Positive approval verifier for the future Native AppContainer lane.

Fail-closed, pure-Python verification only. No OS calls, no process
creation, no signing, no WDAC modification, no network. A positive
result here is TEST-ONLY eligibility and never authorizes real native
execution; see ``production_gate_decision``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, FrozenSet, Mapping, Optional

APPROVAL_SCHEMA_VERSION = 1
SUPPORTED_SCHEMA_VERSIONS = frozenset({1})

# Structured denial codes (stable, auditable).
APPROVAL_MISSING = "APPROVAL_MISSING"
APPROVAL_MALFORMED = "APPROVAL_MALFORMED"
SCHEMA_UNSUPPORTED = "SCHEMA_UNSUPPORTED"
SOURCE_DIGEST_MISSING = "SOURCE_DIGEST_MISSING"
SOURCE_IDENTITY_MISMATCH = "SOURCE_IDENTITY_MISMATCH"
SOURCE_MANIFEST_MISMATCH = "SOURCE_MANIFEST_MISMATCH"
ARTIFACT_HASH_MISMATCH = "ARTIFACT_HASH_MISMATCH"
ARCH_MISMATCH = "ARCH_MISMATCH"
SIGNER_MISMATCH = "SIGNER_MISMATCH"
CERT_EVIDENCE_INVALID = "CERT_EVIDENCE_INVALID"
WDAC_POLICY_MISSING = "WDAC_POLICY_MISSING"
WDAC_POLICY_MISMATCH = "WDAC_POLICY_MISMATCH"
BINDING_UNVERIFIED = "BINDING_UNVERIFIED"
APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
APPROVAL_REVOKED = "APPROVAL_REVOKED"
REVOCATION_STALE = "REVOCATION_STALE"
TRUSTED_ROOTS_MISSING = "TRUSTED_ROOTS_MISSING"
SCOPE_MISMATCH = "SCOPE_MISMATCH"
SPEC_MISMATCH = "SPEC_MISMATCH"
OPERATION_MISMATCH = "OPERATION_MISMATCH"
SINGLE_USE_REUSED = "SINGLE_USE_REUSED"
MODEL_SUPPLIED_FORGERY = "MODEL_SUPPLIED_FORGERY"
BACKEND_MISSING = "BACKEND_MISSING"
VERIFIER_EXCEPTION = "VERIFIER_EXCEPTION"
ARTIFACT_REPLACED_TOCTOU = "ARTIFACT_REPLACED_TOCTOU"
PHYSICAL_ACCEPTANCE_MISSING = "PHYSICAL_ACCEPTANCE_MISSING"
LEGACY_FALLBACK_DENIED = "LEGACY_FALLBACK_DENIED"
PRODUCTION_NOT_APPROVED = "PRODUCTION_NOT_APPROVED"

# Production real-execution switch. Never enabled by evidence alone;
# flipping it requires human approval + OS proof, which do not exist.
PRODUCTION_NATIVE_EXECUTION_AUTHORIZED = False


class NativeGateState(str, Enum):
    """Ordered gate states. Not interchangeable; advance one step."""

    UNAPPROVED = "UNAPPROVED"
    EVIDENCE_VALIDATED = "EVIDENCE_VALIDATED"
    POLICY_VERIFIED = "POLICY_VERIFIED"
    PHYSICAL_ACCEPTANCE_AUTHORIZED = "PHYSICAL_ACCEPTANCE_AUTHORIZED"
    NATIVE_EXECUTION_ELIGIBLE = "NATIVE_EXECUTION_ELIGIBLE"


@dataclass(frozen=True)
class ApprovalEvidence:
    """Typed immutable approval record (host-owned, never model input)."""

    schema_version: int
    origin: str
    approval_id: str
    source_identity: str
    source_manifest_digest: str
    build_provenance: str
    toolchain: str
    artifact_sha256: str
    architecture: str
    signer: str
    cert_evidence: Mapping[str, Any]
    policy_id: str
    binding_evidence: Mapping[str, Any]
    policy_owner: str
    issued_at: float
    expires_at: float
    authorized_scope: Mapping[str, Any]
    authorized_operations: tuple
    sandbox_constraints: Mapping[str, Any]
    physical_acceptance: Mapping[str, Any]
    audit_ref: str


@dataclass(frozen=True)
class ExpectedContext:
    """Host-owned expectations the approval must match exactly."""

    artifact_sha256: str
    architecture: str
    signer: str
    policy_id: str
    source_digest: str
    source_identity: str = ""
    scope: Mapping[str, Any] = field(default_factory=dict)
    operation: str = ""
    trusted_roots: FrozenSet[str] = frozenset()
    revoked_ids: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class VerificationResult:
    """Auditable verifier outcome. eligible=True is test-only."""

    eligible: bool
    state: NativeGateState
    code: str
    details: str
    audit: Mapping[str, Any]


@dataclass(frozen=True)
class ProductionDecision:
    """Machine-enforced production gate. allow=False until approved."""

    allow_real_execution: bool
    reason_code: str
    details: str
    audit: Mapping[str, Any]


class SingleUseTracker:
    """Thread-safe single-use claim set for approval authorizations.

    Process-local only: it bounds in-process replay, not cross-process
    or crash-recovery exactly-once. Distributed single dispatch is
    owned by the Dispatch Ledger; never treat this tracker as that.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._used: set[str] = set()

    def try_claim(self, approval_id: str) -> bool:
        """Claim once; False when already used (replay denied)."""
        with self._lock:
            if approval_id in self._used:
                return False
            self._used.add(approval_id)
            return True


def canonical_bytes(value: Any) -> bytes:
    """Canonical JSON serialization for digest binding."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Digest of a source closure manifest via canonical form."""
    return sha256_hex(canonical_bytes(dict(manifest)))


def _eq_hex(a: Any, b: Any) -> bool:
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    try:
        return hmac.compare_digest(a.lower(), b.lower())
    except Exception:
        return False


def _deny(state: NativeGateState, code: str, details: str,
          approval_id: str = "") -> VerificationResult:
    return VerificationResult(
        eligible=False, state=state, code=code, details=details,
        audit={"approval_id": approval_id, "state": state.value,
               "code": code, "details": details},
    )


def check_sandbox_spec(spec: Mapping[str, Any],
                       constraints: Mapping[str, Any]) -> Optional[str]:
    """Pure SandboxSpec-to-constraint check. None when satisfied.

    Never raises for bad input: any malformed side is SPEC_MISMATCH
    (fail closed). Unknown constraint keys are ignored.
    """
    try:
        if not isinstance(spec, Mapping) or not isinstance(
                constraints, Mapping):
            return SPEC_MISMATCH
        timeout = spec.get("startup_timeout_s")
        keep_dir = spec.get("keep_runtime_dir")
        shared = spec.get("shared_runtime")
        max_timeout = constraints.get("max_startup_timeout_s")
        if max_timeout is not None:
            if (isinstance(max_timeout, bool)
                    or not isinstance(timeout, (int, float))
                    or not isinstance(max_timeout, (int, float))):
                return SPEC_MISMATCH
            if not timeout > 0 or timeout > max_timeout:
                return SPEC_MISMATCH
        if keep_dir is True and constraints.get(
                "allow_keep_runtime_dir") is not True:
            return SPEC_MISMATCH
        if shared is True and constraints.get(
                "allow_shared_runtime") is not True:
            return SPEC_MISMATCH
        return None
    except Exception:
        return SPEC_MISMATCH


def parse_approval(data: Any) -> ApprovalEvidence:
    """Strictly parse raw approval JSON into a typed record."""
    if not isinstance(data, dict):
        raise ValueError("approval record must be an object")
    # A bare approved flag is never sufficient authorization.
    mandatory = ("schema_version", "origin", "approval_id", "source",
                 "artifact", "policy", "validity", "scope",
                 "physical_acceptance", "audit_ref")
    for key in mandatory:
        if key not in data:
            raise ValueError(f"missing field: {key}")
    if not isinstance(data["schema_version"], int) or isinstance(
            data["schema_version"], bool):
        raise ValueError("schema_version must be an integer")
    source = data["source"]
    artifact = data["artifact"]
    policy = data["policy"]
    validity = data["validity"]
    scope = data["scope"]
    physical = data["physical_acceptance"]
    for section in (source, artifact, policy, validity, scope, physical):
        if not isinstance(section, dict):
            raise ValueError("approval section must be an object")
    for key in ("identity", "manifest_digest", "build_provenance",
                "toolchain"):
        if key not in source:
            raise ValueError(f"missing source field: {key}")
    for key in ("sha256", "architecture", "signer", "cert_evidence"):
        if key not in artifact:
            raise ValueError(f"missing artifact field: {key}")
    for key in ("policy_id", "binding_evidence", "policy_owner"):
        if key not in policy:
            raise ValueError(f"missing policy field: {key}")
    for key in ("issued_at", "expires_at"):
        if key not in validity:
            raise ValueError(f"missing validity field: {key}")
    for key in ("scope", "operations", "sandbox_constraints"):
        if key not in scope:
            raise ValueError(f"missing scope field: {key}")
    ops = scope["operations"]
    if not isinstance(ops, list) or not ops or not all(
            isinstance(o, str) for o in ops):
        raise ValueError("operations must be a non-empty string list")
    for section_name, section, keys in (
            ("source", source, ("identity", "build_provenance",
                                "toolchain")),
            ("policy", policy, ("policy_owner",))):
        for key in keys:
            value = section[key]
            if not isinstance(value, str) or not value:
                raise ValueError(f"{section_name} field {key} must be a "
                                 "non-empty string")
    for section_name, section, keys in (
            ("artifact", artifact, ("sha256", "architecture", "signer")),
            ("policy", policy, ("policy_id",))):
        for key in keys:
            if not isinstance(section[key], str):
                raise ValueError(f"{section_name} field {key} must be a "
                                 "string")
    for section_name, section, keys in (
            ("artifact", artifact, ("cert_evidence",)),
            ("policy", policy, ("binding_evidence",)),
            ("scope", scope, ("scope", "sandbox_constraints"))):
        for key in keys:
            if not isinstance(section[key], dict):
                raise ValueError(f"{section_name} field {key} must be an "
                                 "object")
    approval_id = data["approval_id"]
    if not isinstance(approval_id, str) or not approval_id:
        raise ValueError("approval_id must be a non-empty string")
    audit_ref = data["audit_ref"]
    if not isinstance(audit_ref, str) or not audit_ref:
        raise ValueError("audit_ref must be a non-empty string")
    return ApprovalEvidence(
        schema_version=data["schema_version"],
        origin=data["origin"],
        approval_id=approval_id,
        source_identity=source["identity"],
        source_manifest_digest=source["manifest_digest"],
        build_provenance=source["build_provenance"],
        toolchain=source["toolchain"],
        artifact_sha256=artifact["sha256"],
        architecture=artifact["architecture"],
        signer=artifact["signer"],
        cert_evidence=artifact["cert_evidence"],
        policy_id=policy["policy_id"],
        binding_evidence=policy["binding_evidence"],
        policy_owner=policy["policy_owner"],
        issued_at=validity["issued_at"],
        expires_at=validity["expires_at"],
        authorized_scope=scope["scope"],
        authorized_operations=tuple(ops),
        sandbox_constraints=scope["sandbox_constraints"],
        physical_acceptance=physical,
        audit_ref=audit_ref,
    )


def verify_approval(
    raw: Any,
    expected: ExpectedContext,
    backend: Any = None,
    *,
    now: Optional[float] = None,
    tracker: Optional[SingleUseTracker] = None,
    artifact_post_hash: Optional[str] = None,
    allow_legacy_fallback: bool = False,
    spec_snapshot: Optional[Mapping[str, Any]] = None,
    revocation_as_of: Optional[float] = None,
    revocation_max_age_s: float = 86400.0,
) -> VerificationResult:
    """Verify approval evidence. Fail closed on any gap.

    Never raises for evidence problems; unexpected internal
    failures also return a fail-closed VERIFIER_EXCEPTION denial.
    ``spec_snapshot`` is an optional host-supplied SandboxSpec
    snapshot; when present it must satisfy the approval constraints.
    ``revocation_as_of`` timestamps the revocation snapshot; when
    present it must be fresh, otherwise REVOCATION_STALE.
    """
    try:
        return _verify_inner(
            raw, expected, backend, now=now, tracker=tracker,
            artifact_post_hash=artifact_post_hash,
            allow_legacy_fallback=allow_legacy_fallback,
            spec_snapshot=spec_snapshot,
            revocation_as_of=revocation_as_of,
            revocation_max_age_s=revocation_max_age_s,
        )
    except Exception as exc:
        return _deny(NativeGateState.UNAPPROVED, VERIFIER_EXCEPTION,
                     f"verifier exception: {type(exc).__name__}")


def _verify_inner(
    raw: Any,
    expected: ExpectedContext,
    backend: Any,
    *,
    now: Optional[float],
    tracker: Optional[SingleUseTracker],
    artifact_post_hash: Optional[str],
    allow_legacy_fallback: bool,
    spec_snapshot: Optional[Mapping[str, Any]],
    revocation_as_of: Optional[float],
    revocation_max_age_s: float,
) -> VerificationResult:
    if raw is None:
        return _deny(NativeGateState.UNAPPROVED, APPROVAL_MISSING,
                      "no approval record supplied")
    if allow_legacy_fallback:
        return _deny(NativeGateState.UNAPPROVED, LEGACY_FALLBACK_DENIED,
                      "legacy fallback is never an approval")
    try:
        approval = parse_approval(raw)
    except ValueError as exc:
        return _deny(NativeGateState.UNAPPROVED, APPROVAL_MALFORMED,
                      f"malformed approval: {exc}")

    aid = approval.approval_id
    # --- Evidence stage (UNAPPROVED on failure) ---
    if approval.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        return _deny(NativeGateState.UNAPPROVED, SCHEMA_UNSUPPORTED,
                      f"unsupported schema: {approval.schema_version}", aid)
    if approval.origin != "host":
        return _deny(NativeGateState.UNAPPROVED, MODEL_SUPPLIED_FORGERY,
                      "approval origin is not host-owned", aid)
    if (not isinstance(approval.source_manifest_digest, str)
            or not approval.source_manifest_digest):
        return _deny(NativeGateState.UNAPPROVED, SOURCE_DIGEST_MISSING,
                      "source manifest digest missing", aid)
    if expected.source_identity and (
            approval.source_identity != expected.source_identity):
        return _deny(NativeGateState.UNAPPROVED, SOURCE_IDENTITY_MISMATCH,
                      "source identity mismatch", aid)
    if not _eq_hex(approval.source_manifest_digest,
                   expected.source_digest):
        return _deny(NativeGateState.UNAPPROVED,
                      SOURCE_MANIFEST_MISMATCH,
                      "source manifest digest mismatch", aid)
    if not _eq_hex(approval.artifact_sha256, expected.artifact_sha256):
        return _deny(NativeGateState.UNAPPROVED, ARTIFACT_HASH_MISMATCH,
                      "artifact hash mismatch", aid)
    if approval.architecture != expected.architecture:
        return _deny(NativeGateState.UNAPPROVED, ARCH_MISMATCH,
                      "artifact architecture mismatch", aid)
    if approval.signer != expected.signer:
        return _deny(NativeGateState.UNAPPROVED, SIGNER_MISMATCH,
                      "signer mismatch", aid)
    # Self-declared signer metadata is not verification evidence,
    # and an empty trust anchor set authorizes nothing on its own.
    if backend is None:
        return _deny(NativeGateState.EVIDENCE_VALIDATED, BACKEND_MISSING,
                      "no verifier backend available", aid)
    if not expected.trusted_roots:
        return _deny(NativeGateState.EVIDENCE_VALIDATED,
                      TRUSTED_ROOTS_MISSING,
                      "no trusted roots configured", aid)
    try:
        cert_ok = backend.verify_certificate(
            approval.cert_evidence, approval.signer,
            frozenset(expected.trusted_roots))
    except Exception as exc:
        return _deny(NativeGateState.UNAPPROVED, VERIFIER_EXCEPTION,
                      f"certificate backend failure: {exc}", aid)
    if cert_ok is not True:
        return _deny(NativeGateState.UNAPPROVED, CERT_EVIDENCE_INVALID,
                      "certificate evidence not verified", aid)

    # --- Policy stage (EVIDENCE_VALIDATED on failure) ---
    if (not isinstance(approval.policy_id, str)
            or not approval.policy_id):
        return _deny(NativeGateState.EVIDENCE_VALIDATED,
                      WDAC_POLICY_MISSING, "WDAC policy missing", aid)
    if approval.policy_id != expected.policy_id:
        return _deny(NativeGateState.EVIDENCE_VALIDATED,
                      WDAC_POLICY_MISMATCH, "wrong policy identity", aid)
    try:
        bound = backend.verify_binding(
            approval.artifact_sha256, approval.policy_id,
            approval.binding_evidence)
    except Exception as exc:
        return _deny(NativeGateState.UNAPPROVED, VERIFIER_EXCEPTION,
                      f"binding backend failure: {exc}", aid)
    if bound is not True:
        return _deny(NativeGateState.EVIDENCE_VALIDATED,
                      BINDING_UNVERIFIED,
                      "artifact-policy binding unverified", aid)
    try:
        moment = time.time() if now is None else float(now)
    except (TypeError, ValueError):
        return _deny(NativeGateState.UNAPPROVED, VERIFIER_EXCEPTION,
                      "clock failure", aid)
    if isinstance(now, bool) or not math.isfinite(moment):
        return _deny(NativeGateState.UNAPPROVED, VERIFIER_EXCEPTION,
                      "clock failure", aid)
    try:
        issued_raw, expires_raw = approval.issued_at, approval.expires_at
        if isinstance(issued_raw, bool) or isinstance(expires_raw, bool):
            raise ValueError("bool timestamp")
        issued = float(issued_raw)
        expires = float(expires_raw)
    except (TypeError, ValueError):
        return _deny(NativeGateState.EVIDENCE_VALIDATED,
                      APPROVAL_MALFORMED, "validity window malformed", aid)
    if not (math.isfinite(issued) and math.isfinite(expires)):
        return _deny(NativeGateState.EVIDENCE_VALIDATED,
                      APPROVAL_MALFORMED, "validity window malformed", aid)
    # Half-open validity: issued_at <= now < expires_at. At expiry the
    # approval is expired. Wall-clock rollback is a residual risk (see
    # handoff): short validity, fresh revocation, and single-use bound
    # the exposure; production stays denied regardless.
    if not (issued <= moment < expires):
        return _deny(NativeGateState.EVIDENCE_VALIDATED,
                      APPROVAL_EXPIRED, "approval expired or not yet valid",
                      aid)
    if approval.approval_id in set(expected.revoked_ids):
        return _deny(NativeGateState.EVIDENCE_VALIDATED, APPROVAL_REVOKED,
                      "approval revoked", aid)
    freshness_checked = False
    if revocation_as_of is not None:
        try:
            as_of_raw = revocation_as_of
            max_age_raw = revocation_max_age_s
            if (isinstance(as_of_raw, bool)
                    or isinstance(max_age_raw, bool)):
                raise ValueError("bool revocation freshness")
            as_of = float(as_of_raw)
            max_age = float(max_age_raw)
        except (TypeError, ValueError):
            return _deny(NativeGateState.UNAPPROVED, VERIFIER_EXCEPTION,
                          "revocation freshness misconfigured", aid)
        if as_of > moment or moment - as_of > max_age:
            return _deny(NativeGateState.EVIDENCE_VALIDATED,
                          REVOCATION_STALE,
                          "revocation snapshot is stale", aid)
        freshness_checked = True

    # --- Physical stage (POLICY_VERIFIED on failure) ---
    physical = approval.physical_acceptance
    if (not isinstance(physical, dict)
            or physical.get("authorized") is not True
            or not physical.get("audit_ref")):
        return _deny(NativeGateState.POLICY_VERIFIED,
                      PHYSICAL_ACCEPTANCE_MISSING,
                      "physical acceptance authorization missing", aid)

    # --- Binding stage (PHYSICAL_ACCEPTANCE_AUTHORIZED on failure) ---
    if canonical_bytes(dict(approval.authorized_scope)) != canonical_bytes(
            dict(expected.scope)):
        return _deny(NativeGateState.PHYSICAL_ACCEPTANCE_AUTHORIZED,
                      SCOPE_MISMATCH, "SandboxSpec scope mismatch", aid)
    if expected.operation not in set(approval.authorized_operations):
        return _deny(NativeGateState.PHYSICAL_ACCEPTANCE_AUTHORIZED,
                      OPERATION_MISMATCH, "operation not authorized", aid)
    if spec_snapshot is not None:
        mismatch = check_sandbox_spec(
            spec_snapshot, approval.sandbox_constraints)
        if mismatch is not None:
            return _deny(NativeGateState.PHYSICAL_ACCEPTANCE_AUTHORIZED,
                          mismatch, "SandboxSpec violates constraints", aid)
    if artifact_post_hash is not None and not _eq_hex(
            artifact_post_hash, approval.artifact_sha256):
        return _deny(NativeGateState.PHYSICAL_ACCEPTANCE_AUTHORIZED,
                      ARTIFACT_REPLACED_TOCTOU,
                      "artifact changed between verify and use", aid)
    if tracker is not None and not tracker.try_claim(approval.approval_id):
        return _deny(NativeGateState.PHYSICAL_ACCEPTANCE_AUTHORIZED,
                      SINGLE_USE_REUSED,
                      "approval authorization already consumed", aid)

    audit = {"approval_id": aid,
             "state": NativeGateState.NATIVE_EXECUTION_ELIGIBLE.value,
             "code": "OK", "details": "synthetic eligibility only",
             "artifact_sha256": approval.artifact_sha256,
             "policy_id": approval.policy_id,
             "operation": expected.operation,
             "toctou_checked": artifact_post_hash is not None,
             "single_use": tracker is not None,
             "revocation_freshness_checked": freshness_checked}
    return VerificationResult(
        eligible=True, state=NativeGateState.NATIVE_EXECUTION_ELIGIBLE,
        code="OK", details="synthetic eligibility only (test use)",
        audit=audit)


def production_gate_decision(result: VerificationResult
                             ) -> ProductionDecision:
    """Machine-enforced production gate: real execution always denied.

    Even a synthetically eligible result must not enable native
    process creation until human approval + OS proof exist.
    """
    audit = {"verifier_state": result.state.value,
             "verifier_code": result.code,
             "allow_real_execution": False,
             "approval_id": result.audit.get("approval_id", "")}
    return ProductionDecision(
        # Always False: the module constant is the future
        # human-approval switch and must never be flipped by evidence.
        allow_real_execution=False,
        reason_code=PRODUCTION_NOT_APPROVED,
        details="NOT APPROVED: requires human approval and OS proof; "
                "synthetic eligibility never enables native execution",
        audit=audit)


def audit_spec_approval(spec: Any, *, now: Optional[float] = None
                        ) -> VerificationResult:
    """Best-effort audit hook for the RLM denial boundary.

    Never raises, never authorizes, never launches. Returns a
    structured denial (APPROVAL_MISSING when no approval present).
    """
    try:
        raw = getattr(spec, "approval", None)
        if raw is None:
            return _deny(NativeGateState.UNAPPROVED, APPROVAL_MISSING,
                         "no approval attached to spec")
        expected = ExpectedContext(
            artifact_sha256="", architecture="", signer="",
            policy_id="", source_digest="")
        return verify_approval(raw, expected, backend=None, now=now)
    except Exception as exc:
        return _deny(NativeGateState.UNAPPROVED, VERIFIER_EXCEPTION,
                      f"audit failure: {type(exc).__name__}")


__all__ = [
    "APPROVAL_SCHEMA_VERSION",
    "ApprovalEvidence",
    "ExpectedContext",
    "NativeGateState",
    "ProductionDecision",
    "SingleUseTracker",
    "SUPPORTED_SCHEMA_VERSIONS",
    "VerificationResult",
    "audit_spec_approval",
    "canonical_bytes",
    "check_sandbox_spec",
    "manifest_digest",
    "parse_approval",
    "production_gate_decision",
    "sha256_hex",
    "verify_approval",
]
