"""Approval-gate negative + synthetic-positive regressions.

Deterministic and nonphysical: mocks/spies only. No native
launcher, process creation, signing, WDAC, or OS execution.
"""

from __future__ import annotations

import threading
from copy import deepcopy
from unittest.mock import MagicMock, patch

from openjarvis.agents.rlm_worker import RLMWorker
from openjarvis.sandbox import approval_verifier as av
from openjarvis.sandbox.approval_verifier import (
    ExpectedContext,
    NativeGateState,
    SingleUseTracker,
)
from openjarvis.sandbox.worker_launcher import SandboxSpec

NOW = 1_700_000_000.0
ARTIFACT = "ab" * 32
SOURCE_DIGEST = av.manifest_digest({"files": ["launcher.c"]})
SCOPE = {"lane": "rlm", "max_s": 5}
OPERATION = "rlm.execute"


class FakeBackend:
    """Isolated fake verification backend (test-only, never OS)."""

    def __init__(self, cert_ok: bool = True, binding_ok: bool = True,
                 explode: bool = False) -> None:
        self.cert_ok = cert_ok
        self.binding_ok = binding_ok
        self.explode = explode
        self.calls: list[str] = []

    def verify_certificate(self, evidence: object, signer: str,
                           roots: object) -> bool:
        self.calls.append("cert")
        if self.explode:
            raise RuntimeError("backend boom")
        return self.cert_ok and bool(roots)

    def verify_binding(self, digest: str, policy: str,
                       evidence: object) -> bool:
        self.calls.append("binding")
        if self.explode:
            raise RuntimeError("backend boom")
        return self.binding_ok


class FakeLauncher:
    """Isolated fake launcher adapter for synthetic transitions."""

    def __init__(self) -> None:
        self.launches: list[str] = []

    def launch(self, approval_id: str) -> str:
        self.launches.append(approval_id)
        return f"fake-launched:{approval_id}"


def make_valid() -> tuple[dict, ExpectedContext, FakeBackend]:
    raw = {
        "schema_version": 1,
        "origin": "host",
        "approval_id": "APR-001",
        "source": {"identity": "tree:abc", "manifest_digest": SOURCE_DIGEST,
                   "build_provenance": "build-log:1",
                   "toolchain": "rust1.88/msvc19.51/sdk26100"},
        "artifact": {"sha256": ARTIFACT, "architecture": "AMD64",
                     "signer": "CN=Test",
                     "cert_evidence": {"chain_ok": True}},
        "policy": {"policy_id": "POLICY-1",
                   "binding_evidence": {"rule": "hash:allow"},
                   "policy_owner": "owner:test"},
        "validity": {"issued_at": NOW - 3600, "expires_at": NOW + 3600},
        "scope": {"scope": dict(SCOPE), "operations": [OPERATION],
                  "sandbox_constraints": {"max_timeout_s": 60}},
        "physical_acceptance": {"authorized": True,
                                "audit_ref": "AUD-1"},
        "audit_ref": "AUD-1",
    }
    expected = ExpectedContext(
        artifact_sha256=ARTIFACT, architecture="AMD64", signer="CN=Test",
        policy_id="POLICY-1", source_digest=SOURCE_DIGEST,
        scope=dict(SCOPE), operation=OPERATION,
        trusted_roots=frozenset({"ROOT-TEST"}))
    return raw, expected, FakeBackend()


def mutate(raw: dict, path: list[str], value: object) -> dict:
    out = deepcopy(raw)
    node = out
    for key in path[:-1]:
        node = node[key]
    if value is None:
        node.pop(path[-1], None)
    else:
        node[path[-1]] = value
    return out


def _deny_cases() -> list[tuple[str, object, dict, str]]:
    raw, expected, _ = make_valid()
    return [
        ("missing", None, {}, av.APPROVAL_MISSING),
        ("malformed", {"approved": True}, {}, av.APPROVAL_MALFORMED),
        ("schema", mutate(raw, ["schema_version"], 99), {},
         av.SCHEMA_UNSUPPORTED),
        ("source-missing", mutate(raw, ["source", "manifest_digest"], ""),
         {}, av.SOURCE_DIGEST_MISSING),
        ("source-mismatch", mutate(raw, ["source", "manifest_digest"],
                                   "00" * 32), {}, av.SOURCE_MANIFEST_MISMATCH),
        ("artifact-hash", mutate(raw, ["artifact", "sha256"], "00" * 32),
         {}, av.ARTIFACT_HASH_MISMATCH),
        ("arch", mutate(raw, ["artifact", "architecture"], "ARM64"), {},
         av.ARCH_MISMATCH),
        ("signer", mutate(raw, ["artifact", "signer"], "CN=Evil"), {},
         av.SIGNER_MISMATCH),
        ("cert", raw, {"cert_ok": False}, av.CERT_EVIDENCE_INVALID),
        ("wdac-missing", mutate(raw, ["policy", "policy_id"], ""), {},
         av.WDAC_POLICY_MISSING),
        ("wdac-wrong", mutate(raw, ["policy", "policy_id"], "OTHER"), {},
         av.WDAC_POLICY_MISMATCH),
        ("binding", raw, {"binding_ok": False}, av.BINDING_UNVERIFIED),
        ("expired", mutate(raw, ["validity", "expires_at"], NOW - 10), {},
         av.APPROVAL_EXPIRED),
        ("revoked", raw, {"revoked": True}, av.APPROVAL_REVOKED),
        ("scope", raw, {"scope": {"lane": "other", "max_s": 5}},
         av.SCOPE_MISMATCH),
        ("operation", raw, {"operation": "other.op"},
         av.OPERATION_MISMATCH),
        ("forged", mutate(raw, ["origin"], "model"), {},
         av.MODEL_SUPPLIED_FORGERY),
        ("no-backend", raw, {"no_backend": True}, av.BACKEND_MISSING),
        ("exception", raw, {"explode": True}, av.VERIFIER_EXCEPTION),
        ("physical", mutate(
            raw, ["physical_acceptance"], {"authorized": False}), {},
         av.PHYSICAL_ACCEPTANCE_MISSING),
        ("legacy", raw, {"legacy": True}, av.LEGACY_FALLBACK_DENIED),
    ]


def _run(raw: object, opts: dict) -> av.VerificationResult:
    base, expected, _ = make_valid()
    if raw is None or (isinstance(raw, dict) and "schema_version" not in raw
                       and "origin" not in raw and raw != base):
        candidate = raw
    else:
        candidate = raw if raw is not None else None
    backend: FakeBackend | None = FakeBackend(
        cert_ok=opts.get("cert_ok") is not False,
        binding_ok=opts.get("binding_ok") is not False,
        explode=bool(opts.get("explode")))
    if opts.get("cert_ok") is False:
        backend.cert_ok = False
    if opts.get("binding_ok") is False:
        backend.binding_ok = False
    if opts.get("no_backend"):
        backend = None
    exp = expected
    if opts.get("revoked"):
        exp = ExpectedContext(
            artifact_sha256=exp.artifact_sha256,
            architecture=exp.architecture, signer=exp.signer,
            policy_id=exp.policy_id, source_digest=exp.source_digest,
            scope=dict(exp.scope), operation=exp.operation,
            trusted_roots=exp.trusted_roots,
            revoked_ids=frozenset({"APR-001"}))
    if "scope" in opts:
        exp = ExpectedContext(
            artifact_sha256=exp.artifact_sha256,
            architecture=exp.architecture, signer=exp.signer,
            policy_id=exp.policy_id, source_digest=exp.source_digest,
            scope=dict(opts["scope"]), operation=exp.operation,
            trusted_roots=exp.trusted_roots, revoked_ids=exp.revoked_ids)
    if "operation" in opts:
        exp = ExpectedContext(
            artifact_sha256=exp.artifact_sha256,
            architecture=exp.architecture, signer=exp.signer,
            policy_id=exp.policy_id, source_digest=exp.source_digest,
            scope=dict(exp.scope), operation=str(opts["operation"]),
            trusted_roots=exp.trusted_roots, revoked_ids=exp.revoked_ids)
    return av.verify_approval(
        candidate, exp, backend, now=NOW,
        allow_legacy_fallback=bool(opts.get("legacy")))


def test_negative_denials_fail_closed() -> None:
    for name, raw, opts, code in _deny_cases():
        result = _run(raw, opts)
        assert result.eligible is False, name
        assert result.code == code, name
        assert result.state != NativeGateState.NATIVE_EXECUTION_ELIGIBLE, name
        assert "approval_id" in result.audit, name


def test_single_use_reuse_denied() -> None:
    raw, expected, backend = make_valid()
    tracker = SingleUseTracker()
    first = av.verify_approval(raw, expected, backend, now=NOW,
                               tracker=tracker)
    assert first.eligible is True
    second = av.verify_approval(raw, expected, backend, now=NOW,
                                tracker=tracker)
    assert second.eligible is False
    assert second.code == av.SINGLE_USE_REUSED


def test_toctou_artifact_replacement_denied() -> None:
    raw, expected, backend = make_valid()
    result = av.verify_approval(raw, expected, backend, now=NOW,
                                artifact_post_hash="00" * 32)
    assert result.eligible is False
    assert result.code == av.ARTIFACT_REPLACED_TOCTOU


def test_concurrent_verification_race_single_winner() -> None:
    raw, expected, _ = make_valid()
    tracker = SingleUseTracker()
    outcomes: list[bool] = []
    lock = threading.Lock()

    def attempt() -> None:
        res = av.verify_approval(raw, expected, FakeBackend(), now=NOW,
                                 tracker=tracker)
        with lock:
            outcomes.append(res.eligible)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 7


def test_each_denial_never_reaches_native_launcher() -> None:
    cases = _deny_cases()
    # Plus single-use reuse and TOCTOU shapes at the worker boundary.
    raw, _, _ = make_valid()
    with patch("multiprocessing.get_context") as get_context, patch(
            "openjarvis.sandbox.worker_launcher.launch_sandboxed_owned"
    ) as launcher:
        for name, bad, opts, _ in cases:
            _ = (opts, name)
            spec = SandboxSpec()
            spec.approval = bad  # host-side attachment, still untrusted
            worker = RLMWorker(sandbox=spec)
            result = worker.execute_with_outcome("result = 1")
            assert result.success is False
            assert result.error_code == "RLM_SANDBOX_NOT_AUTHORIZED"
            assert worker.process is None
            assert worker.quarantined is True
        # Reused/tampered shapes also denied at the worker gate.
        for extra in (raw, {"approved": True}):
            spec = SandboxSpec()
            spec.approval = extra
            worker = RLMWorker(sandbox=spec)
            result = worker.execute_with_outcome("result = 1")
            assert result.error_code == "RLM_SANDBOX_NOT_AUTHORIZED"
    launcher.assert_not_called()
    get_context.assert_not_called()


def test_verification_before_dispatch_ordering() -> None:
    raw, _, _ = make_valid()
    spec = SandboxSpec()
    spec.approval = raw
    worker = RLMWorker(sandbox=spec)
    with patch(
            "openjarvis.sandbox.approval_verifier.audit_spec_approval",
            wraps=av.audit_spec_approval) as audit, patch(
            "openjarvis.sandbox.worker_launcher.launch_sandboxed_owned"
    ) as launcher:
        result = worker.execute_with_outcome("result = 1")
    assert result.error_code == "RLM_SANDBOX_NOT_AUTHORIZED"
    audit.assert_called_once()
    launcher.assert_not_called()


def test_synthetic_positive_stays_test_only() -> None:
    raw, expected, backend = make_valid()
    result = av.verify_approval(raw, expected, backend, now=NOW)
    assert result.eligible is True
    assert result.state == NativeGateState.NATIVE_EXECUTION_ELIGIBLE
    assert result.audit["approval_id"] == "APR-001"
    assert result.audit["code"] == "OK"
    assert "cert" in backend.calls and "binding" in backend.calls
    decision = av.production_gate_decision(result)
    assert decision.allow_real_execution is False
    assert decision.reason_code == av.PRODUCTION_NOT_APPROVED
    # Fake adapter may record a synthetic transition; the real
    # launcher must never be invoked.
    fake = FakeLauncher()
    with patch("openjarvis.sandbox.worker_launcher.launch_sandboxed_owned"
               ) as launcher:
        if result.eligible:
            fake.launch(str(result.audit["approval_id"]))
        decision2 = av.production_gate_decision(result)
        assert decision2.allow_real_execution is False
    launcher.assert_not_called()
    assert fake.launches == ["APR-001"]


def test_failure_propagates_and_quarantines_without_retry() -> None:
    spec = SandboxSpec()
    spec.approval = {"approved": True}  # insufficient by design
    worker = RLMWorker(sandbox=spec)
    with patch("openjarvis.sandbox.worker_launcher.launch_sandboxed_owned"
               ) as launcher:
        first = worker.execute_with_outcome("result = 1")
        assert first.error_code == "RLM_SANDBOX_NOT_AUTHORIZED"
        assert worker.quarantined is True
        second = worker.execute_with_outcome("result = 1")
        assert second.error_code == "WORKER_QUARANTINED"
        assert second.unknown_outcome is False
    launcher.assert_not_called()


def test_canonical_serialization_is_deterministic() -> None:
    first = av.canonical_bytes({"b": 1, "a": [1, 2]})
    second = av.canonical_bytes({"a": [1, 2], "b": 1})
    assert first == second
    assert av.manifest_digest({"files": ["x"]}) == av.manifest_digest(
        {"files": ["x"]})


def test_wrong_source_identity_denied() -> None:
    raw, expected, backend = make_valid()
    bad = mutate(raw, ["source", "identity"], "tree:evil")
    exp = ExpectedContext(
        artifact_sha256=expected.artifact_sha256,
        architecture=expected.architecture, signer=expected.signer,
        policy_id=expected.policy_id, source_digest=expected.source_digest,
        scope=dict(expected.scope), operation=expected.operation,
        trusted_roots=expected.trusted_roots,
        revoked_ids=expected.revoked_ids,
        source_identity="tree:abc")
    result = av.verify_approval(bad, exp, backend, now=NOW)
    assert result.eligible is False
    assert result.code == av.SOURCE_IDENTITY_MISMATCH


def test_bool_timestamps_rejected_as_malformed() -> None:
    raw, expected, backend = make_valid()
    bad = mutate(raw, ["validity", "issued_at"], True)
    result = av.verify_approval(bad, expected, backend, now=NOW)
    assert result.eligible is False
    assert result.code == av.APPROVAL_MALFORMED


def test_nondict_evidence_rejected_as_malformed() -> None:
    raw, expected, backend = make_valid()
    bad = mutate(raw, ["artifact", "cert_evidence"], ["not-a-dict"])
    result = av.verify_approval(bad, expected, backend, now=NOW)
    assert result.eligible is False
    assert result.code == av.APPROVAL_MALFORMED


def _valid_with_snapshot(snapshot: dict
                          ) -> tuple[object, ExpectedContext, FakeBackend]:
    raw, expected, backend = make_valid()
    raw["scope"]["sandbox_constraints"] = {
        "max_startup_timeout_s": 60, "allow_keep_runtime_dir": False,
        "allow_shared_runtime": False}
    return raw, expected, backend


def test_shared_runtime_disallowed_by_constraints() -> None:
    raw, expected, backend = _valid_with_snapshot({})
    result = av.verify_approval(
        raw, expected, backend, now=NOW,
        spec_snapshot={"startup_timeout_s": 5.0, "keep_runtime_dir": False,
                       "shared_runtime": True})
    assert result.eligible is False
    assert result.code == av.SPEC_MISMATCH


def test_keep_runtime_dir_disallowed_by_constraints() -> None:
    raw, expected, backend = _valid_with_snapshot({})
    result = av.verify_approval(
        raw, expected, backend, now=NOW,
        spec_snapshot={"startup_timeout_s": 5.0, "keep_runtime_dir": True,
                       "shared_runtime": False})
    assert result.eligible is False
    assert result.code == av.SPEC_MISMATCH


def test_startup_timeout_over_max_denied() -> None:
    raw, expected, backend = _valid_with_snapshot({})
    result = av.verify_approval(
        raw, expected, backend, now=NOW,
        spec_snapshot={"startup_timeout_s": 600.0,
                       "keep_runtime_dir": False, "shared_runtime": False})
    assert result.eligible is False
    assert result.code == av.SPEC_MISMATCH


def test_compliant_spec_snapshot_passes() -> None:
    raw, expected, backend = _valid_with_snapshot({})
    result = av.verify_approval(
        raw, expected, backend, now=NOW,
        spec_snapshot={"startup_timeout_s": 5.0,
                       "keep_runtime_dir": False, "shared_runtime": False})
    assert result.eligible is True
    assert result.state == NativeGateState.NATIVE_EXECUTION_ELIGIBLE


def test_success_audit_records_which_checks_ran() -> None:
    raw, expected, backend = make_valid()
    plain = av.verify_approval(raw, expected, FakeBackend(), now=NOW)
    assert plain.audit["toctou_checked"] is False
    assert plain.audit["single_use"] is False
    guarded = av.verify_approval(
        raw, expected, FakeBackend(), now=NOW,
        artifact_post_hash=ARTIFACT, tracker=SingleUseTracker())
    assert guarded.eligible is True
    assert guarded.audit["toctou_checked"] is True
    assert guarded.audit["single_use"] is True


def test_fake_launcher_result_identity_verified() -> None:
    from openjarvis.agents.rlm_worker import _validate_result

    raw, expected, backend = make_valid()
    result = av.verify_approval(raw, expected, backend, now=NOW)
    assert result.eligible is True
    fake = FakeLauncher()
    session, nonce = "sess-1", "nonce-1"
    frame = {"protocol": "rlm-worker-v2", "type": "result", "session_id": session,
             "nonce": nonce, "request_id": 1, "request_count": 1,
             "output": "ok", "success": True, "error_code": None,
             "terminated": True, "final_value": None,
             "unknown_outcome": False}
    fake.launch(str(result.audit["approval_id"]))
    checked = _validate_result(frame, session, nonce, 1)
    assert checked.success is True
    forged = dict(frame, session_id="sess-evil")
    try:
        _validate_result(forged, session, nonce, 1)
    except Exception as exc:
        assert "mismatch" in str(exc) or "identity" in str(exc)
    else:
        raise AssertionError("forged session must be rejected")
    assert fake.launches == ["APR-001"]


def test_cancel_before_execute_dispatches_nothing() -> None:
    broker = MagicMock()
    worker = RLMWorker(llm_broker=broker)
    worker.cancel()
    with patch("multiprocessing.get_context") as get_context, patch(
            "openjarvis.sandbox.worker_launcher.launch_sandboxed_owned"
    ) as launcher:
        result = worker.execute_with_outcome("result = 1")
    assert result.error_code == "RPC_CANCELLED"
    broker.handle_request.assert_not_called()
    launcher.assert_not_called()
    get_context.assert_not_called()


def test_close_after_denial_is_safe_and_spawns_nothing() -> None:
    worker = RLMWorker(sandbox=SandboxSpec())
    with patch("openjarvis.sandbox.worker_launcher.launch_sandboxed_owned"
               ) as launcher:
        denied = worker.execute_with_outcome("result = 1")
        assert denied.error_code == "RLM_SANDBOX_NOT_AUTHORIZED"
        worker.close()  # must not raise, retry, or spawn
        assert worker.process is None
    launcher.assert_not_called()


def test_shared_runtime_missing_dir_denied_without_launch(tmp_path) -> None:
    from openjarvis.sandbox import worker_launcher as wl
    from openjarvis.sandbox.appcontainer import SandboxError

    spec = SandboxSpec(runtime_root=tmp_path / "missing-runtime")
    try:
        wl.launch_sandboxed_owned(
            spec, session_id="s", nonce="n", max_chars=100, max_req=5,
            rpc_enabled=False, startup_timeout=1.0)
    except SandboxError as exc:
        assert exc.code == "MANIFEST_FAILURE"
    else:
        raise AssertionError("missing shared runtime must be denied")


def test_new_denial_shapes_never_reach_launcher() -> None:
    raw, _, _ = make_valid()
    shapes = [
        mutate(raw, ["source", "identity"], "tree:evil"),
        mutate(raw, ["validity", "issued_at"], True),
        mutate(raw, ["artifact", "cert_evidence"], ["not-a-dict"]),
    ]
    with patch("openjarvis.sandbox.worker_launcher.launch_sandboxed_owned"
               ) as launcher:
        for bad in shapes:
            spec = SandboxSpec()
            spec.approval = bad
            worker = RLMWorker(sandbox=spec)
            result = worker.execute_with_outcome("result = 1")
            assert result.error_code == "RLM_SANDBOX_NOT_AUTHORIZED"
            assert worker.quarantined is True
    launcher.assert_not_called()


def test_shared_runtime_delegates_without_real_launch() -> None:
    from openjarvis.sandbox import worker_launcher as wl

    sentinel = object()
    spec = SandboxSpec(runtime_root="C:/fake-root")
    with patch("openjarvis.sandbox.staged_runtime.runtime_ready",
               return_value=True) as ready, patch(
            "openjarvis.sandbox.worker_launcher.launch_sandboxed",
            return_value=sentinel) as launch:
        handles = wl.launch_sandboxed_owned(
            spec, session_id="s", nonce="n", max_chars=100, max_req=5,
            rpc_enabled=False, startup_timeout=1.0)
    assert handles is sentinel
    ready.assert_called_once()
    launch.assert_called_once()
    kwargs = launch.call_args
    assert kwargs.kwargs["session_id"] == "s"
    assert kwargs.kwargs["nonce"] == "n"


class LenientBackend:
    """Backend that trusts anything (proves verifier checks roots)."""

    def verify_certificate(self, evidence: object, signer: str,
                           roots: object) -> bool:
        return True

    def verify_binding(self, digest: str, policy: str,
                       evidence: object) -> bool:
        return True


def test_empty_trusted_roots_denied_despite_lenient_backend() -> None:
    raw, expected, _ = make_valid()
    exp = ExpectedContext(
        artifact_sha256=expected.artifact_sha256,
        architecture=expected.architecture, signer=expected.signer,
        policy_id=expected.policy_id, source_digest=expected.source_digest,
        scope=dict(expected.scope), operation=expected.operation,
        trusted_roots=frozenset(), revoked_ids=expected.revoked_ids)
    result = av.verify_approval(raw, exp, LenientBackend(), now=NOW)
    assert result.eligible is False
    assert result.code == av.TRUSTED_ROOTS_MISSING


def test_revocation_stale_snapshot_denied() -> None:
    raw, expected, backend = make_valid()
    result = av.verify_approval(raw, expected, backend, now=NOW,
                                revocation_as_of=NOW - 90000.0)
    assert result.eligible is False
    assert result.code == av.REVOCATION_STALE


def test_revocation_fresh_snapshot_passes_and_flagged() -> None:
    raw, expected, backend = make_valid()
    result = av.verify_approval(raw, expected, backend, now=NOW,
                                revocation_as_of=NOW - 60.0)
    assert result.eligible is True
    assert result.audit["revocation_freshness_checked"] is True


def test_revocation_absent_flagged_not_checked() -> None:
    raw, expected, backend = make_valid()
    result = av.verify_approval(raw, expected, backend, now=NOW)
    assert result.eligible is True
    assert result.audit["revocation_freshness_checked"] is False


def test_expiry_boundaries_are_exact() -> None:
    raw, expected, backend = make_valid()
    issued = raw["validity"]["issued_at"]
    expires = raw["validity"]["expires_at"]
    # Half-open validity: issued_at <= now < expires_at.
    assert av.verify_approval(
        raw, expected, FakeBackend(), now=issued).eligible is True
    assert av.verify_approval(
        raw, expected, FakeBackend(), now=expires - 1).eligible is True
    before = av.verify_approval(
        raw, expected, FakeBackend(), now=issued - 1)
    assert before.code == av.APPROVAL_EXPIRED
    at_expiry = av.verify_approval(
        raw, expected, FakeBackend(), now=expires)
    assert at_expiry.eligible is False
    assert at_expiry.code == av.APPROVAL_EXPIRED
    after = av.verify_approval(
        raw, expected, FakeBackend(), now=expires + 1)
    assert after.code == av.APPROVAL_EXPIRED


def test_zero_length_and_reversed_intervals_expired() -> None:
    raw, expected, backend = make_valid()
    moment = raw["validity"]["issued_at"] + 10
    zero = mutate(raw, ["validity", "expires_at"],
                  raw["validity"]["issued_at"])
    assert av.verify_approval(
        zero, expected, FakeBackend(),
        now=raw["validity"]["issued_at"]).code == av.APPROVAL_EXPIRED
    reversed_raw = mutate(raw, ["validity", "issued_at"], moment + 100)
    reversed_raw = mutate(reversed_raw, ["validity", "expires_at"], moment)
    assert av.verify_approval(
        reversed_raw, expected, FakeBackend(),
        now=moment).code == av.APPROVAL_EXPIRED


def test_nonfinite_timestamps_rejected() -> None:
    raw, expected, backend = make_valid()
    for key, value in (("issued_at", float("inf")),
                       ("expires_at", float("nan"))):
        bad = mutate(raw, ["validity", key], value)
        result = av.verify_approval(bad, expected, FakeBackend(), now=NOW)
        assert result.eligible is False
        assert result.code == av.APPROVAL_MALFORMED
    broken_clock = av.verify_approval(
        raw, expected, FakeBackend(), now=float("nan"))
    assert broken_clock.eligible is False
    assert broken_clock.code == av.VERIFIER_EXCEPTION


def test_scope_superset_denied_exact_match_required() -> None:
    raw, expected, backend = make_valid()
    raw["scope"]["scope"] = dict(SCOPE, extra="minimization-violation")
    result = av.verify_approval(raw, expected, backend, now=NOW)
    assert result.eligible is False
    assert result.code == av.SCOPE_MISMATCH


def test_verifier_eligible_bundle_never_authorizes_production() -> None:
    raw, expected, backend = make_valid()
    synthetic = av.verify_approval(raw, expected, backend, now=NOW)
    assert synthetic.eligible is True  # synthetic only, never production
    assert av.production_gate_decision(synthetic).allow_real_execution is False
    with patch("openjarvis.sandbox.worker_launcher.launch_sandboxed_owned"
               ) as launcher:
        spec = SandboxSpec()
        spec.approval = raw  # fullest synthetic evidence available
        worker = RLMWorker(sandbox=spec)
        first = worker.execute_with_outcome("result = 1")
        assert first.error_code == "RLM_SANDBOX_NOT_AUTHORIZED"
        assert worker.quarantined is True
        second = worker.execute_with_outcome("result = 1")
        assert second.error_code == "WORKER_QUARANTINED"
        assert second.unknown_outcome is False
    launcher.assert_not_called()
