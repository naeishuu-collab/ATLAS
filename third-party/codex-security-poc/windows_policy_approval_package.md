# JARVIS Astra — Windows Policy Approval Package

Status: **EVIDENCE PACKAGE ONLY — NOT SUBMITTED**  
Generated: 2026-10-09  
Scope: AppContainer proof harness and OpenCode Rust-build policy blocker. No
production integration, policy change, privilege elevation, Native execution,
Rust build, or network transmission was performed.

## 1. Verified baseline

- Worktree: `C:\Users\yingz\.codex\worktrees\astra-continuation\JARVIS-Sol`
- Branch: `codex/astra-continuation`
- HEAD: `d596e482c50982cc79c707c7d9fb50d051fcaaed`
- Native launcher execution: blocked before launcher entry.
- `CreateProcessW` Error 203: unresolved; no new execution was attempted.
- AppContainer OS isolation: not proven.
- OpenCode worktree was read-only.

PoC hashes after the documentation-only preparation change:

| Artifact | SHA-256 | Size |
|---|---|---:|
| `tools/security_poc/astra_appcontainer_proof.py` | `02337F0EE46633FB0BE66D1EE9AF937CFEA38EF80AA3D080C002BE26BFF5F6FA` | 54877 |
| `tools/security_poc/native_appcontainer_launcher.c` | `DA66889D38F5D82B78D5AE0134FA8F96FF2AF44E011242F7A35EDF8EA4861081` | 12412 |

The C change only makes the printed `CONFIG.flags` value use the same
conditioned flag value passed to `CreateProcessW`; it does not change the
creation policy or execution path.

## 2. Common Windows Application Control evidence

The following Code Integrity events use the same policy:

- Policy name: `VerifiedAndReputableDesktop`
- Policy GUID: `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`
- Policy ID: `27555.1000.240208`
- Status: `0xc0e90002`
- Event: Code Integrity 3077; related Smart App Control detail event 3118.

| Target | Immediate loader | Event-time SHA-256 / flat hash | Authenticode |
|---|---|---|---|
| `native_appcontainer_launcher.exe` | Codex `pwsh.exe` | `63E7F49F26E41D61E5AA29EA0A04FB444E1D86204E96ECE428057D19401B2A10` / `911AA2FEC7110D956EDABF0F6A4880F59315D956FACE80BD66D7AAD92F6963AC` | File deleted; direct status unavailable |
| `cargo.exe` | `rustup.exe` | `D80239792336F4C592EE85D9E96970C5520A04EDBD6A27A96EF428164CAE02E8` / `C9B44417DC8228B81923A1068A3C09E32D2793F2CCED2A816789CF433C1F0D46` | `NotSigned` |
| `maturin.exe` | `uv.exe` | `7666BD1E1595CDD73D0235D4222798ECC0DC73BCE9763E2444CACA9F3F1B25B1` / `787779FA7F453D3444AC732689AD2BB8F1399B4D4E2AF1AD9E00F84BB6460F07` | `NotSigned` |

Additional `rustc.exe`, build-script, and DLL load failures show the same
policy GUID. This establishes a common user-mode execution-policy blocker,
not a Rust-specific or AppContainer-specific failure.

Read-only management queries:

- `CiTool.exe -lp -json`: `0x80070005 ACCESS_DENIED`.
- `CodeIntegrityPolicyEnforcementStatus=2`.
- `UsermodeCodeIntegrityPolicyEnforcementStatus=2`.
- AppLocker EXE/DLL log: no matching target event found.
- SmartScreen Debug log: disabled.
- Policy owner: not identifiable with the current standard-user access.

## 3. Error 203 state

### Proven

- Native and ctypes ABI layouts were statically aligned.
- Explicit Unicode environment is used.
- Environment entries are sorted and double-NUL terminated.
- `=C:` drive-current-directory entry is supplied.
- `CREATE_UNICODE_ENVIRONMENT` is used.
- `lpEnvironment` is not NULL.
- `bInheritHandles` is FALSE.
- `SECURITY_CAPABILITIES` has the expected AppContainer SID and zero
  capabilities.
- Prior baseline/no-drive/no-appname/no-cwd runs returned 203.
- The no-suspend attempt was blocked by Application Control before launcher
  execution and therefore did not test `CREATE_SUSPENDED`.

### Not proven

- Whether `CREATE_SUSPENDED` contributes to Error 203.
- Whether the AppContainer attribute and explicit environment have a dynamic
  interaction on this device.
- Whether the target image or directory has an AppContainer-specific launch
  restriction not visible in static ACL inspection.
- Whether the created child token would actually contain the expected SID,
  Low IL, and zero capabilities.

No previously executed differential is repeated in this package.

## 4. Policy-compliant execution options

### Option A — Policy-owner approval of one exact artifact

- Executor: device/security policy owner.
- Required authority: formal App Control policy administration.
- Artifact: exact launcher binary, immutable SHA-256, signature evidence.
- Rule: narrow publisher/file-publisher, file-attribute, or exact hash rule;
  never Allow-All and never Smart App Control disablement.
- Audit: policy version/GUID, approval ticket, artifact hash, signer, and
  event correlation.
- Rollback: policy owner removes the temporary rule or revokes the
  supplemental policy after proof.

### Option B — Approved CI build and execution

- Executor: existing enterprise-managed CI owner.
- Required evidence: source commit, compiler/toolchain version, CI job ID,
  signed artifact, SHA-256, artifact retention, and run log.
- The local unsigned binary must not be substituted for the CI artifact.
- Rollback: revoke the CI permission or remove the temporary policy rule;
  retain the immutable run record.

### Option C — Signed Python/Rust extension artifact

- A signed wheel is insufficient by itself if it contains unsigned `.pyd`,
  DLL, or executable components.
- Every executable component must have verifiable provenance and satisfy the
  active policy.
- No local wheel installation or Rust build is authorized by this package.

### Minimum common requirements

- No administrator elevation by Codex.
- No policy bypass flags or environment inheritance.
- No real-user data access.
- No host credentials or secrets in the worker environment.
- No production worker connection.

## 5. Post-approval verification plan

1. Verify the approved artifact hash, signature, policy rule, and CI/approval
   record before launch.
2. Execute exactly one `no-suspend` differential with explicit Unicode
   environment, zero capabilities, and no inherited handles.
3. Save the immediate `CreateProcessW` return and `GetLastError`; stop on
   policy denial or Error 203.
4. If a child is created, query its process token for AppContainer state, SID,
   Low IL, and capability count.
5. Use a suspended launch for deterministic Job assignment, then verify Job
   membership, breakaway rejection, and kill-on-close behavior.
6. Use only temporary directories for allowed/denied filesystem reads and
   native `CreateFileW` negative tests.
7. Verify named-pipe authorization and unauthorized SID denial.
8. Verify child token inheritance, child Job membership, and no unexpected
   handle inheritance.
9. Verify no-network behavior without sending data to the public network.
10. Verify process, Job, pipe, profile, ACL, and temporary-directory cleanup.

Every failed or ambiguous result is a stop condition. No Restricted Token or
unisolated fallback is permitted.

## 6. STOP conditions

- Application Control blocks the approved artifact.
- Artifact hash or signature differs from the approval record.
- Policy owner or CI provenance cannot be established.
- AppContainer SID, token, integrity, or capability identity mismatches.
- Filesystem, IPC, child, or network negative proof fails.
- Job containment or cleanup fails.
- Any policy bypass, elevation, production connection, or real-user data
  access becomes necessary.

## 7. Prohibited changes

- Do not disable Smart App Control or Code Integrity.
- Do not alter Windows policy, ACLs, accounts, or system security settings.
- Do not use `CREATE_PRESERVE_CODE_AUTHZ_LEVEL` or another policy bypass.
- Do not execute the Native launcher or Rust build from this worktree until
  formal approval evidence exists.
- Do not modify the OpenCode worktree or production RLMWorker.
