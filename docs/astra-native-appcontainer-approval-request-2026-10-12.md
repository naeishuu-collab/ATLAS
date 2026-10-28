# JARVIS Astra Native AppContainer Approval Request

> **NOT APPROVED — REVIEW REQUEST ONLY**
>
> This document requests a policy-owner decision. It does not approve, sign,
> execute, or distribute a native artifact and does not change Windows
> Application Control.

## 1. Purpose

Request review of the host-owned native launcher required for a future,
bounded RLM worker AppContainer lane. The launcher would create the restricted
worker, enforce the host-selected token/filesystem/network/IPC boundary, apply
Job Object lifetime control, and return a verified result to the host.

The current Python implementation remains fail-closed. No production native
launcher was executed for this request.

## 2. Requested artifact

| Item | Requested state | Current evidence |
|---|---|---|
| Windows launcher | Immutable, signed native executable approved for one bounded AppContainer launch path | **MISSING**; no approved launcher executable identified |
| Python/Rust extension | `openjarvis_rust` only if required by the approved lane | Existing debug DLL is unsigned and is not approved |
| Execution scope | Host-issued launch only; no model-selectable launcher, token, policy, or fallback | Design/source evidence exists; OS proof **NOT VERIFIED** |

The exact executable filename and final SHA-256 must be supplied by the policy
owner/build authority after the approved build. The present debug artifacts are
evidence for review only, not candidates for execution.

## 3. Source and build provenance

| Evidence | Value | Status |
|---|---|---|
| Repository | `JARVIS-Sol`, branch `opencode/cloud-privacy` | AVAILABLE; working tree is dirty |
| HEAD source identity | `d596e482c50982cc79c707c7d9fb50d051fcaaed` | AVAILABLE; not an immutable clean build tree |
| Native launcher source | `third-party/codex-security-poc/native_appcontainer_launcher.c` | AVAILABLE for review; not production-approved |
| Launcher source SHA-256 | `DA66889D38F5D82B78D5AE0134FA8F96FF2AF44E011242F7A35EDF8EA4861081` | VERIFIED read-only hash; source commit binding still required |
| Rust workspace | `rust/`, `rust/crates/openjarvis-python` | AVAILABLE |
| Rust pin | `rust/rust-toolchain.toml`, channel `1.88`, `rust-version = 1.88` | VERIFIED in source |
| CI build command | `uv run maturin develop --manifest-path rust/crates/openjarvis-python/Cargo.toml` | VERIFIED in workflow source |
| CI Rust installer | `dtolnay/rust-toolchain@stable` | VERIFIED in workflow source; exact resolved toolchain record missing |
| Build flags/dependencies/logs | Exact approved build record | **MISSING** |
| Reproducibility | Independent rebuild with matching bytes | **NOT VERIFIED** |

The current checkout contains parallel/dirty work. A policy-owner build must
bind the artifact to an immutable source tree or recorded commit and preserve
the complete build log, lockfiles, flags, and resolved toolchain.

## 4. Existing artifact observations

These hashes identify existing files only; they are not approvals.

| Artifact | SHA-256 | Signature | Status |
|---|---|---|---|
| `.venv/Scripts/maturin.exe` | `787779FA7F453D3444AC732689AD2BB8F1399B4D4E2AF1AD9E00F84BB6460F07` | `NotSigned` | **NOT VERIFIED / DO NOT EXECUTE FOR THIS LANE** |
| `rust/target/debug/openjarvis_rust.dll` | `832E6629917814A518B0BB9AB1ABCB7FB45A7E0DA64A2655B8ED8004E5849888` | `NotSigned` | **NOT VERIFIED / DO NOT LOAD FOR THIS LANE** |
| Approved launcher `.exe` | Not found | Not available | **MISSING** |

## 5. Requested privileges and isolation contract

The requested artifact must be constrained to:

- AppContainer/restricted token selected by the host; no caller/model override.
- Read/execute access only to an approved staged runtime and explicitly scoped
  temporary data.
- No broad user profile, repository, credential, or private-data access.
- No network capability for the worker; any model/tool operation must use the
  host-mediated RPC contract.
- IPC only over the host-created, identity-bound channel with session ID and
  nonce validation.
- No arbitrary child process creation; child-process policy must be enforced by
  the OS/token/job boundary.
- Job Object ownership, timeout, termination, handle cleanup, and quarantine
  on uncertain result.
- `UNKNOWN_OUTCOME` must not retry, redispatch, fall back, retarget, or mutate.

## 5A. Supply-chain and execution threat model

| Threat | Required control | Acceptance evidence |
|---|---|---|
| Model or caller selects a different launcher/token/policy | Launcher identity and sandbox selection are host-owned and bound to the approved artifact | Host-side authorization record plus OS-enforced identity evidence |
| Compromised or substituted native artifact | Immutable source tree, reproducible build, signed PE, hash/signer-bound App Control rule | Build log, dependency manifest, SHA-256, Authenticode chain, rule ID |
| Worker escapes through filesystem or inherited handles | Restricted token, explicit ACLs, no inherited credentials, scoped staging directory | OS token/ACL/handle inspection and negative access tests |
| Worker reaches network or follows an authorized redirect to another host | Network capability denied and transport/proxy/redirect paths blocked | Negative loopback/non-loopback, proxy, redirect, and DNS tests |
| Worker launches descendants or survives timeout | Job Object with descendant kill-on-close and bounded timeout/termination | Process tree, Job Object membership, termination and cleanup receipt |
| Host loses the result after dispatch | Durable request identity and quarantine on `UNKNOWN_OUTCOME`; no retry or fallback | Ledger transition and replay-attempt denial evidence |

Pattern filtering, AST inspection, prompts, and a Python `SandboxSpec` are not
substitutes for these OS-enforced controls.

## 6. Windows Application Control findings

Existing read-only evidence records Code Integrity enforcement and a policy
identifier `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`. The documented policy name
is `VerifiedAndReputableDesktop`. User-mode enforcement and a production allow
rule for this artifact were not established; earlier policy enumeration also
returned `ACCESS_DENIED`.

Required policy evidence remains:

1. WDAC/App Control policy/rule ID that covers the exact final artifact hash or
   signer.
2. Scope limited to the requested launcher and required dependencies.
3. Policy-owner identity/role, decision timestamp, expiry/renewal, and audit ID.
4. Explicit rollback/revocation procedure.

No policy was changed in preparing this request.

## 7. Expected negative tests before any production approval

The policy-owner test record must show, with an approved immutable artifact:

- missing/invalid/forged `SandboxSpec` is denied before process creation;
- unsigned, wrong-hash, wrong-signer, or unapproved launcher is denied;
- token identity, AppContainer membership, filesystem ACL, IPC identity, and
  child-process restrictions are verified from the OS;
- network attempts, redirect escape, proxy use, and non-loopback routing are
  denied;
- timeout/termination removes the worker and owned resources;
- a crash or uncertain RPC result becomes `UNKNOWN_OUTCOME` and is quarantined;
- no ordinary multiprocessing or legacy in-process fallback occurs;
- no external cloud request is made during the proof lane.

Python mocks and portable fixture tests can prove denial and protocol logic,
but do not prove these OS properties.

### 7A. Physical proof acceptance matrix

| Property | Required result | Evidence source | Current state |
|---|---|---|---|
| Process identity/token restrictions | Worker has only the approved restricted/AppContainer token | OS token inspection | **NOT VERIFIED** |
| Filesystem isolation | Access outside the approved staging scope is denied | OS ACL/access probes | **NOT VERIFIED** |
| IPC boundary | Only the host-created, identity-bound RPC channel is usable | Handle/ACL and protocol evidence | **NOT VERIFIED** |
| Network isolation | Direct, proxy, DNS, redirect, and non-loopback attempts fail | OS/network trace plus negative tests | **NOT VERIFIED** |
| Child-process containment | Descendants cannot escape the Job Object or launch unauthorized children | Process tree and Job Object evidence | **NOT VERIFIED** |
| Timeout/termination | Worker and descendants terminate; handles and staging are cleaned | Termination and cleanup receipt | **NOT VERIFIED** |
| Result integrity | Validated result or `UNKNOWN_OUTCOME` quarantine is recorded | Host ledger and audit record | Portable denial only |

Approval requires every OS row above to be evidenced by the exact immutable,
signed artifact under the approved policy. No row is satisfied by a mock.

## 8. Monitoring and audit

The approval record should retain the artifact hash, signer/certificate chain,
source commit/tree, build log, policy ID, launch request identity, sandbox
identity, timeout/termination result, cleanup result, and final quarantine or
verified-result record. Logs must exclude credentials and private prompt data.

## 9. Revocation and rollback

On failed verification, unexpected child/network/filesystem behavior, signer
change, expired approval, or `UNKNOWN_OUTCOME`: disable the rule or revoke the
artifact through the policy owner, remove the artifact from the staged runtime,
quarantine the session, and retain the audit record. The application must
remain on the existing fail-closed `RLM_SANDBOX_NOT_AUTHORIZED` path.

## 10. Open evidence checklist

| Evidence | State | Owner needed |
|---|---|---|
| Immutable source commit/tree and source manifest | **MISSING** | Build authority |
| Reproducible build command, flags, lockfiles, resolved toolchain | **MISSING** | Build authority |
| Final launcher and dependency SHA-256 manifest | **MISSING** | Build authority |
| Authenticode signature and certificate chain | **MISSING** | Signing authority |
| WDAC/App Control rule ID and scope | **MISSING** | Policy owner |
| Approval owner, expiry, audit record | **MISSING** | Policy owner |
| OS token/filesystem/IPC/network/child proof | **NOT VERIFIED** | Windows isolation verifier |
| Rollback/revocation record | **MISSING** | Policy owner |

## 11. Exact policy-owner decision requested

Approve or reject a narrowly scoped review lane for a **specified, signed,
immutable native launcher package**, after the missing provenance and policy
evidence above is supplied. Approval must state the exact artifact hash/signer,
WDAC/App Control rule, allowed scope, expiry, audit ID, and whether one bounded
non-cloud physical isolation proof may run.

Until that written decision exists, native production execution remains
disabled and classified `PROVENANCE_APPROVAL_REQUIRED`.

## 12. Verifier implementation note (2026-10-12)

An isolated pure approval verifier now exists at
`src/openjarvis/sandbox/approval_verifier.py` with deterministic
negative regressions in `tests/security/test_native_approval_verifier.py`.
It proves denial of invalid/absent approval evidence and keeps the
production launcher unreachable (`RLM_SANDBOX_NOT_AUTHORIZED`).
A synthetic positive result is test-only and does not change this
request: artifact, signature, WDAC binding, and OS proof remain
MISSING/NOT VERIFIED until the owners supply them.
