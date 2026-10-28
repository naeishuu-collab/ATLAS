# JARVIS Astra Native AppContainer Approval Readiness

> **NOT APPROVED — REVIEW REQUEST ONLY**
>
> This is a read-only approval-readiness package. It does not compile, sign,
> load, execute, or distribute a native artifact and does not change WDAC,
> Smart App Control, Defender, ACLs, or other Windows policy.

Snapshot date: 2026-10-12  
Repository: `C:\Users\yingz\.codex\worktrees\astra-opencode\JARVIS-Sol`  
Branch: `opencode/cloud-privacy`  
HEAD: `d596e482c50982cc79c707c7d9fb50d051fcaaed`

The audit-start worktree contained 221 dirty entries. The final read-only
snapshot contained 225 entries: the two approval-package files below were
added intentionally; all other existing/concurrent changes were preserved.

## 1. Current decision

| Gate | State | Evidence |
|---|---|---|
| Native launcher artifact | **MISSING** | No approved launcher `.exe` exists in the checkout |
| Immutable source provenance | **MISSING** | AppContainer Python/C sources are untracked; Rust build output is ignored |
| Reproducible build | **NOT VERIFIED** | Repository pins Rust 1.88; existing DLL metadata records Rust 1.99.0 |
| Authenticode | **MISSING** | Existing Rust DLL and maturin executable are `NotSigned` |
| WDAC/App Control allow rule | **REQUIRES HUMAN APPROVAL** | Current-user `CiTool` query returned `0x80070005`; no artifact-bound rule verified |
| Physical OS isolation | **NOT VERIFIED** | No native physical lane was run |
| Production native execution | **DISABLED / FAIL CLOSED** | RLM sandbox gate remains denial-first |

Native production execution remains `PROVENANCE_APPROVAL_REQUIRED`.

## 2. Source closure

The complete read-only manifest, including 124 Rust source hashes obtained from
the ignored `openjarvis_rust.d` dependency file, is:

- `docs/astra-native-appcontainer-source-manifest-2026-10-12.md`

Security-relevant source records:

| Path | Role | SHA-256 | Git state |
|---|---|---|---|
| `third-party/codex-security-poc/native_appcontainer_launcher.c` | Independent diagnostic C launcher; not connected to RLM production path | `DA66889D38F5D82B78D5AE0134FA8F96FF2AF44E011242F7A35EDF8EA4861081` | **UNTRACKED** |
| `src/openjarvis/sandbox/appcontainer.py` | ctypes AppContainer/profile/token/job/pipe primitives | `85F2503902FA4A6CA45E2422F7AFE0954CC4E41F0EB8727F4C61CA7721393318` | **UNTRACKED** |
| `src/openjarvis/sandbox/worker_launcher.py` | staged runtime → AppContainer launch → identity/handshake | `CD3FF2A051837D9327D10D78818B94B20A1309CD62B4FAEDA7DADDDB1B5D907F` | **UNTRACKED** |
| `src/openjarvis/sandbox/staged_runtime.py` | closure, credential-name, reparse and manifest checks | `300D7FBE5179CE8EDCC361C1DFE179949B5D1AC8475A8C3CE0F9516DDD88E3A1` | **UNTRACKED** |
| `src/openjarvis/sandbox/mount_security.py` | generic mount allowlist | `6D14C72C17D6B249E2934E65ADC118CB48EACF511ABBD5CB5C8DFEB384CED78F` | tracked/clean |
| `src/openjarvis/_rust_bridge.py` | Python/Rust extension boundary | `C3CA000C074401E6670777FECC7B8930BF890A90BED6B25D2C00671226D50F91` | tracked/clean |
| `rust/crates/openjarvis-python/src/lib.rs` | PyO3 extension binding | `F209DD42E67E3F7B8C9033239CC3F8EC8E2E6E69E897E0BE2CC92C412BE3068F` | tracked/clean |
| `rust/Cargo.toml` | Rust workspace/dependency declarations | `9D02C00B346EFFAA37C0A74693680023A6520C876DEE03016BD056ABB0E52824` | tracked/clean |
| `rust/Cargo.lock` | resolved Rust dependency lock | `69FD237228010090C155FF455E06595A60818483C089ACF8CE09A7A349ADA6A5` | tracked/clean |
| `rust/rust-toolchain.toml` | declared Rust pin | `911CC011D5639DB886F4E83F20A980C10B5D213D3307D3C4BFCB74721E4902B5` | tracked/clean |

Relevant source locations:
- `appcontainer.py:382-398`: RX ACL grant/verification; `:426-460`: profile
  creation/deletion; `:636-735`: Job Object, AppContainer CreateProcess,
  assignment and termination; `:776-816`: token identity proof;
  `:840-860`: wait/termination.
- `worker_launcher.py:239-358`: staging, profile, ACL, pipe, Job, launch,
  identity and handshake sequence. Failures are terminal and do not fall back
  to ordinary multiprocessing.
- `staged_runtime.py:1-22,286-329,490-619,679-731`: explicit closure,
  credential-name/reparse rejection and exact-tree verification. Its own
  header states that OS isolation and launcher integration are out of scope.
- The C diagnostic uses `CreateAppContainerProfile` at line 205,
  Job Object setup at lines 273-279, `CreateProcessW` at 285 and cleanup at
  365. It is untracked and was not executed.

Because the AppContainer implementation and diagnostic C source are untracked,
HEAD alone cannot identify the bytes. The Rust source closure is tracked, but
the existing DLL has no immutable build record binding.

## 3. Build reproducibility preflight

| Requirement | Finding | State |
|---|---|---|
| Rust version declaration | `rust/rust-toolchain.toml` channel `1.88`; workspace `rust-version = "1.88"` | AVAILABLE |
| Active local Rust | `rustc 1.99.0`, `cargo 1.99.0`; `stable-x86_64-pc-windows-msvc` | **MISMATCH** |
| Existing DLL build metadata | `rust/target/.rustc_info.json` records Rust 1.99.0, MSVC target, x86_64 | AVAILABLE but not provenance |
| Cargo lock | `rust/Cargo.lock` present and tracked | AVAILABLE |
| PyO3 crate | `crate-type = ["cdylib"]`, PyO3 workspace version 0.29 | AVAILABLE |
| Python build backend | `maturin>=1.0,<2.0` in the Rust subproject; root dev group `maturin>=1.12.6` | AVAILABLE |
| CI procedure | `uv sync ...`; `uv run maturin develop --manifest-path rust/crates/openjarvis-python/Cargo.toml` | AVAILABLE as procedure only |
| MSVC compiler | `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe`; file version `19.51.36256.0`; SHA-256 `E6D57100C82AE0310C18B16ABFE52BC0DF8FBB272CA6C5FB287D485807CFCE91` | **INSTALLED_AND_DISCOVERED**; not initialized on the current `PATH` |
| MSBuild | `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe`; file version `18.9.1.35102`; SHA-256 `602BE585E4D4A233071EF8730ECEC43522C0DB4AFBF5B93553B7B260C5BFB7FF` | **INSTALLED_AND_DISCOVERED**; not initialized on the current `PATH` |
| Windows SDK | `C:\Program Files (x86)\Windows Kits\10\` version `10.0.26100.0`; `Windows.h` SHA-256 `B337D661D03A4ABEFB7B86A2742CE1AD5D19B57CD8B858BD13E7BBCC1DBEEAAA`; `kernel32.lib` SHA-256 `341C7D56125A03B458E4D5093E4C79B33123CCFDFD610FE236937B8E6F3134BB` | **INSTALLED_AND_DISCOVERED**; not build/provenance proof |
| Exact dependency/toolchain resolution log | absent | **MISSING** |
| Reproducibility byte match | not attempted and not established | **NOT VERIFIED** |
| Build flags, environment, timestamp policy | not recorded for the existing DLL | **MISSING** |
| Target architecture | existing PE is x64 (`0x8664`), PE32+ (`0x20b`) | AVAILABLE for existing DLL |

No Cargo, MSVC, maturin build, package download, or toolchain installation was
performed. The required future procedure is: immutable clean source tree →
recorded Rust 1.88/MSVC/SDK versions → locked dependency resolution →
controlled flags/environment → build log → SHA-256 manifest → independent
byte-match rebuild → Authenticode signing → signature verification → policy
owner rule binding. That procedure has not been executed here.

### 3.1 Read-only tool discovery record

`vswhere.exe` was found at
`C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe`, file
version `3.1.7.39155`. It reports the complete Build Tools instance
`VisualStudio/18.9.2+12120.119` at
`C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools` with
`VC\Auxiliary\Build\vcvars64.bat` and `Common7\Tools\vsdevcmd.bat` present.
The discrepancy between the historical `cl/MSBuild NOT FOUND` result and this
record is PATH/environment initialization, not evidence of absence. Neither
environment initializer, compiler, linker, MSBuild, Cargo, nor maturin was run.

The Windows SDK was discovered at
`C:\Program Files (x86)\Windows Kits\10`; version `10.0.26100.0` is present in
`Include`, `Lib`, and `bin`. `signtool.exe` is present at
`...\bin\10.0.26100.0\x64\signtool.exe`, file version
`4.00 (WinBuild.160101.0800)`, SHA-256
`E7B517A6A2828AF2D1FBA3DA60AE1E322A95141BFAE192622725329630CAA2B3`.
These are installed-tool observations only; they do not establish a controlled
build, signature, or policy approval.

## 4. Existing artifact and Authenticode audit

| Artifact | Size | SHA-256 | PE/signature | State |
|---|---:|---|---|---|
| `rust/target/debug/openjarvis_rust.dll` | 25,596,416 bytes | `832E6629917814A518B0BB9AB1ABCB7FB45A7E0DA64A2655B8ED8004E5849888` | x64 PE32+, subsystem 2; `NotSigned` | **NOT VERIFIED / DO NOT LOAD** |
| `rust/target/debug/openjarvis_rust.pdb` | 163,934,208 bytes | `4BDECA3889A861A4046A8B752FD7EDFDA6C3C2A1AA3652A80923A8B186CCB479` | Authenticode query `UnknownError`; no signer | **NOT VERIFIED** |
| `.venv/Scripts/maturin.exe` | 26,386,944 bytes | `787779FA7F453D3444AC732689AD2BB8F1399B4D4E2AF1AD9E00F84BB6460F07` | `NotSigned`; no signer | **NOT VERIFIED / DO NOT USE FOR APPROVAL** |
| Approved AppContainer launcher | — | — | not found | **MISSING** |

The DLL, PDB and maturin executable are ignored/local artifacts, not tracked
release evidence. No final launcher hash, signer chain, build log or approval
record exists.

## 5. WDAC / App Control preflight

Current read-only observations:
- `Win32_DeviceGuard`: `CodeIntegrityPolicyEnforcementStatus=2`,
  `UsermodeCodeIntegrityPolicyEnforcementStatus=0`,
  `VirtualizationBasedSecurityStatus=2`; security services configured/running
  were reported as `{2,3,4}`.
- `root/Microsoft/Windows/CI` and `root/Microsoft/Windows/AppControl` CIM
  namespaces were unavailable in this user context.
- `CiTool --list-policies` returned `0x80070005` (ACCESS_DENIED).
- Existing project documents record policy GUID
  `{0283ac0f-fff1-49ae-ada1-8a933130cad6}` / name
  `VerifiedAndReputableDesktop`, but this report does not treat that historical
  record as current artifact approval.

Required human/policy evidence:
1. Exact policy/rule ID bound to the final PE hash or approved signer.
2. Rule scope limited to the launcher and required dependencies.
3. Policy Owner identity/role, decision timestamp, audit ID and expiry.
4. Enforcement mode and failure behavior.
5. Revocation, rollback and renewal procedure.
6. Approval that one bounded, non-cloud physical proof lane may run.

No Windows policy was modified.

## 6. Future physical isolation acceptance matrix

These are acceptance requirements only. They were not executed.

| Property | Preconditions | Expected evidence | Failure classification |
|---|---|---|---|
| Restricted token identity | approved signed launcher + policy | OS token query shows only approved identity | DENY / NOT PROVEN |
| AppContainer SID/capabilities | same + host-created profile | SID matches request; no extra capabilities | DENY / NOT PROVEN |
| Filesystem boundary | approved staged tree and ACL snapshot | out-of-scope read/write denied; owned cleanup succeeds | DENY / NOT PROVEN |
| IPC boundary | host-created identity-bound pipe/session nonce | only expected pipe works; forged session rejected | DENY / NOT PROVEN |
| Network denial | network capability absent; proxy disabled | direct, proxy, redirect, DNS/non-loopback attempts fail | DENY / NOT PROVEN |
| Child-process containment | Job Object configured before resume | unauthorized child denied/contained | DENY / NOT PROVEN |
| Job kill-on-close | process in job | descendants terminate on close | DENY / NOT PROVEN |
| Timeout termination | bounded launch and RPC timeout | worker and descendants exit; handles close | DENY / NOT PROVEN |
| Cancellation cleanup | cancellation injected | profile, ACL, pipes and staging removed | DENY / NOT PROVEN |
| Orphan prevention | forced parent/worker failure | no owned process/profile/staging residue | DENY / NOT PROVEN |
| Result integrity | valid/invalid/truncated RPC frames | only verified result accepted | DENY / UNKNOWN_OUTCOME |
| UNKNOWN_OUTCOME | lost/ambiguous dispatch | durable quarantine; no retry/fallback/retarget | SAFETY FAILURE |
| Duplicate dispatch | replay attempt | ledger rejects second mutation | SAFETY FAILURE |
| Audit trail | all tests | artifact/source/policy/OS receipts without secrets | NOT PROVEN |

Every row requires the exact immutable, signed artifact and policy bundle. A mock
or portable Python test cannot satisfy a physical row.

## 7. Recent Host Authority / webhook assurance

Read-only audit of the current implementation found:
- `runtime.py:18-72` uses ContextVars for invocation capabilities/resources;
  `:74-121` mints an opaque destination-bound one-shot channel token and
  resets it in `finally`.
- `ToolExecutor` performs the policy check before the worker wrapper at
  `tools/_stubs.py:414-470,915-923`; `ChannelSendTool` checks the same
  destination-bound resource before backend dispatch.
- `WebhookChannel.send` checks authority at `:79-81`, before URL payload
  construction, httpx import/request, DNS or network activity. It sets
  `follow_redirects=False` and `trust_env=False` at `:102-110`.
- `ChannelBridge.send` checks the target before adapter dispatch and consumes
  explicit authority in a reset context at `server/channel_bridge.py:109-147`.

This proves the current mocked path's pre-effect authorization and target
binding for the tested paths. It does not prove that a malicious in-process
plugin cannot import host internals, nor does the current code establish
post-mint revocation/expiry semantics for an already-issued token.

Webhook SSRF/DNS status:
- scheme/host allowlisting and numeric destination pinning are **NOT PROVEN**;
- DNS/rebinding/TOCTOU resistance is **NOT PROVEN**;
- redirects and environment proxy use are explicitly disabled in the current
  request call;
- the URL is constructor/configuration data in the audited route, not a
  model argument in the tested ChannelSendTool path;
- no DNS resolution or HTTP request was performed in this audit.

Therefore this is not a claim of complete SSRF closure.

## 8. Safe regression evidence

All commands used the project `.venv` and a repo-local isolated
`--basetemp`; no physical/native AppContainer test was run.

| Group | Exact command suffix | Result | Exit | Wall time |
|---|---|---:|---:|---:|
| Channel/authority | `tests/security/test_channel_dispatch_authority.py tests/channels/test_webhook.py tests/server/test_channel_bridge.py tests/server/test_channel_routes.py tests/tools/test_channel_tools.py tests/security/test_direct_api_authority.py tests/cli/test_serve_channel_wiring.py -q` | 94 passed, 41 warnings | 0 | 7.11s |
| Host/common | `tests/tools/test_stubs.py tests/tools/test_execution_outcomes.py tests/tools/test_execution_journal.py tests/security/test_host_authority_boundary.py tests/security/test_capabilities.py tests/cli/test_serve_channel_wiring.py tests/sessions/test_wire_channel_history.py tests/server/test_sendblue_webhook.py -q` | 177 passed, 1 warning | 0 | 9.42s |
| RLM/REPL/code denial | `tests/security/test_rlm_sandbox_gate.py tests/agents/test_rlm.py tests/agents/test_rlm_repl.py tests/agents/test_rlm_rpc.py tests/tools/test_repl.py tests/tools/test_template_loader_security.py tests/tools/test_shell_exec.py -q` | 133 passed | 0 | 5.27s |
| MCP/skills | `tests/mcp/test_loader.py tests/mcp/test_discovery.py tests/tools/test_mcp_adapter.py tests/skills/test_skill_trace_tagging_integration.py -q` | 29 passed | 0 | 3.42s |
| Model/egress/browser | `tests/security/test_egress_guard.py tests/security/test_dispatch_ledger.py tests/security/test_cloud_dispatch.py tests/agents/test_capability_router.py tests/engine/test_ollama_native_boundary.py tests/tools/test_browser_safety.py tests/agents/test_deterministic_agent_e2e.py -q` | 72 passed, 1 skipped | 0 | 7.07s |
| Portable sandbox unit only | five explicit `TestSandboxUnit` node IDs from `test_appcontainer_sandbox.py` | 5 passed | 0 | 3.33s |

The skipped model test is the existing test-level skip; no result is promoted to
physical proof. Counts above are per command and intentionally not summed into a
unique-test total.

## 9. Approval owner decision form

**Policy Owner / Build Authority must supply:**

- [ ] immutable source commit/tree and complete source manifest;
- [ ] pinned Rust 1.88, MSVC and Windows SDK versions;
- [ ] locked dependency resolution and reproducible build log;
- [ ] final PE launcher and dependency SHA-256 manifest;
- [ ] Authenticode signature/certificate-chain verification;
- [ ] WDAC/App Control rule ID, scope and enforcement mode;
- [ ] owner, expiry, audit record, renewal and revocation procedure;
- [ ] OS evidence for token, AppContainer, ACL, IPC, network, Job Object,
      timeout, cleanup and orphan prevention;
- [ ] written permission for one bounded, non-cloud physical acceptance lane.

Decision: **APPROVE / REJECT / RETURN FOR EVIDENCE**  
Artifact hash/signer: ____________________  
Policy/rule ID: ____________________  
Expiry: ____________________  
Audit ID: ____________________  
Policy Owner/date: ____________________

Until this form is completed by the authorized human owner, the native lane stays
disabled and no physical test is permitted.

## 12. Controlled-build specification (procedure only)

The following is the exact handoff procedure for the Build Authority. It is not
an execution record and must be run only on an approved, isolated build host.

1. Export an immutable clean source snapshot from the approved source commit.
   Reject any dirty or untracked source, generated file, local patch, or
   environment-only input. Recompute the complete manifest in
   `astra-native-appcontainer-source-manifest-2026-10-12.md` and record the
   snapshot commit/tree separately.
2. Use Rust `1.88` with `rustfmt` and `clippy`, target
   `x86_64-pc-windows-msvc`, MSVC toolset `14.51.36231`/compiler
   `19.51.36256.0`, and Windows SDK `10.0.26100.0`. The installed machine has
   not verified Rust 1.88; it has only active Rust 1.99.0, so it is not a
   controlled-build host for this package.
3. Enforce `rust/Cargo.lock`, capture `rustc -Vv`, `cargo -V`, the selected
   `cl.exe`/SDK paths and hashes, Python/uv/maturin versions, target triple,
   build flags, relevant environment, timezone, and timestamp policy. Use an
   approved `SOURCE_DATE_EPOCH` or document every remaining nondeterministic
   input.
4. Build the two artifacts independently; a PyO3/maturin DLL build
   must not be confused with the standalone C launcher build:
   - Artifact A (standalone C launcher from
     `third-party/codex-security-poc/native_appcontainer_launcher.c`):
     compile and link directly with the pinned MSVC `cl.exe`/`link.exe`
     and Windows SDK only — no maturin, no PyO3, no Python. The exact
     `cl`/`link` command line, resource/manifest inputs (if any), and
     expected launcher filename are MISSING and must be authored by the
     Build Authority; no command was run in this audit.
   - Artifact B (PyO3 extension `openjarvis_rust.dll`, only if the
     approved lane requires it): resolve dependencies without changing
     the lock (`uv sync --project <approved-project-root>`), then
     `uv run maturin build --manifest-path
     rust/crates/openjarvis-python/Cargo.toml --locked --release
     --target x86_64-pc-windows-msvc`. This command is recorded for
     the Build Authority; it was not run in this audit.
5. Capture the expected PyO3 artifact `openjarvis_rust.dll` and any separately
   approved launcher `.exe`, then record file type, architecture, size and
   SHA-256. The launcher filename and dependency set must be fixed by the
   approved build manifest; no current checkout artifact is accepted as that
   manifest.
6. Repeat the build independently in a separate clean directory with the
   same immutable inputs. A byte-for-byte mismatch is a reproducibility
   failure: stop approval, retain both manifests/logs, and do not sign either
   artifact. Matching bytes are necessary but not sufficient for approval.

## 13. Signing and WDAC/App Control handoff

After the Build Authority releases the immutable artifact, the Policy Owner
must independently record (without relying on this dirty checkout):

- final PE path, architecture and SHA-256;
- `Get-AuthenticodeSignature <artifact>` result and certificate chain;
- `signtool verify /pa /all /v <artifact>` output from the approved SDK;
- signer/certificate identity, validity and revocation evidence;
- WDAC/App Control policy ID, rule ID, hash/signer binding, scope and
  enforcement mode;
- approval owner, decision time, expiry, renewal, audit record and revocation
  procedure;
- the exact failure behavior when the hash, signer, policy, expiry or OS
  isolation evidence does not match.

No signing or `signtool` verification was performed here. The existing DLL is
unsigned and must not be loaded or used as approval evidence.

## 14. Machine-enforced approval-gate finding

The current production gate is a denial gate, not a positive artifact verifier:

- `src/openjarvis/agents/rlm_worker.py:645-790` denies missing/invalid
  `SandboxSpec` before process creation and unconditionally returns
  `RLM_SANDBOX_NOT_AUTHORIZED` while native provenance/policy approval is
  unavailable. The native launcher call is therefore unreachable in this
  checkout.
- `tests/security/test_rlm_sandbox_gate.py` verifies no spawn, no generated
  code, no launcher lookup, no file/RPC effect, and no retry/fallback on the
  denial paths.
- `ApprovalStore` is a generic action-approval/TTL store; it does not verify
  native artifact hash, source binding, Authenticode signer, WDAC rule, expiry,
  or revocation. It must not be represented as native approval.

Therefore **unapproved or missing approval cannot reach the native launcher:
PROVEN**. Positive validation of artifact identity, source binding, signer,
policy identity, expiry and revocation is **NOT IMPLEMENTED / NOT PROVEN**
because no approved positive path is available. A future positive path must add
a host-owned verifier before launcher invocation; that is a separate
Build/Policy Authority change and is not invented in this package.

## 15. Human-action checklist and residual risk

The package is ready for formal review only after the human owner supplies the
missing immutable build record, signed PE, artifact-bound policy, and bounded
physical-test authorization. The exact required decision is:

> Approve or reject one immutable, signed launcher hash and its narrowly scoped
> WDAC/App Control rule, with a stated owner, expiry, audit ID, revocation path,
> and permission for one non-cloud physical acceptance lane.

Until then: native execution remains disabled; physical AppContainer isolation,
network denial, filesystem/IPC boundaries, descendant containment, timeout and
orphan cleanup remain **NOT PROVEN**. The residual risks are unsigned/unbound
artifact provenance, Rust 1.88 absence on the current host, and lack of
current-user policy visibility (`CiTool` returned `ACCESS_DENIED`).

## 16. Final nonphysical verification record

These commands were run from the project `.venv` after the package update. They
use isolated temporary pytest directories and do not start a native worker,
external transport, cloud model, desktop mutation, or physical AppContainer
lane. Counts are per command and are not a unique-test total.

| Command | Result | Exit | Wrapper duration |
|---|---:|---:|---:|
| `.venv\Scripts\python.exe -m pytest tests/security/test_rlm_sandbox_gate.py -q --basetemp <temp>` | 17 passed | 0 | 2.74 s |
| `.venv\Scripts\python.exe -m pytest <five TestSandboxUnit nodes> -q --basetemp <temp>` | 5 passed | 0 | 2.65 s |
| `.venv\Scripts\python.exe -m pytest tests/security/test_host_authority_boundary.py tests/security/test_dispatch_ledger.py tests/security/test_egress_guard.py tests/agents/test_deterministic_agent_e2e.py -q --basetemp <temp>` | 36 passed | 0 | 3.04 s |
| `.venv\Scripts\python.exe -m pytest tests/security/test_direct_api_authority.py tests/security/test_channel_dispatch_authority.py tests/channels/test_webhook.py tests/server/test_channel_bridge.py tests/tools/test_channel_tools.py -q --basetemp <temp>` | 70 passed | 0 | 3.26 s |
| `.venv\Scripts\ruff.exe check <nine relevant production paths>` | all checks passed | 0 | 0.61 s |
| `.venv\Scripts\python.exe -m compileall -q src/openjarvis` | passed | 0 | 1.63 s |
| `.venv\Scripts\python.exe -c <import smoke>` | `IMPORT_SMOKE_OK` | 0 | 3.13 s |
| `git diff --check` | passed; pre-existing LF/CRLF warnings only | 0 | 0.75 s |

The five AppContainer nodes were the pure `TestSandboxUnit` cases
`test_child_bootstrap_compiles`, `test_env_block_format`,
`test_malformed_sid_rejected`, `test_no_fallback_invalid_spec`, and
`test_no_fallback_stage_failure`. No physical test node was selected.

## 10. Rollback and failure behavior

Any signer/hash mismatch, policy expiry, failed OS assertion, unexpected
filesystem/network/child effect, timeout with uncertain result, or
`UNKNOWN_OUTCOME` must disable/quarantine the lane. Revoke the policy rule
through the Policy Owner, remove the staged artifact, retain the audit record,
and preserve the existing `RLM_SANDBOX_NOT_AUTHORIZED` fail-closed path. No
retry, redispatch, provider/model fallback, alternate target or duplicate
mutation is allowed.

## 11. Evidence classification

**PROVEN**
- Current branch/HEAD and read-only artifact/source hashes in this snapshot.
- Existing debug DLL PE header classification and unsigned status.
- Current-user policy inspection limitation (`ACCESS_DENIED`).
- Portable denial and authority/egress regression results listed above.
- No native build, native execution, external network request or policy change
  occurred in this task.

**NOT PROVEN**
- Approved launcher identity, immutable native provenance and reproducible bytes.
- Authenticode signer chain and artifact-bound WDAC/App Control rule.
- Physical token, filesystem, IPC, network, child-process, timeout and orphan
  isolation.
- DNS pinning/rebinding resistance for webhook destinations.
- Post-mint authority expiry/revocation and universal third-party plugin
  isolation.
- Cross-process exactly-once, crash recovery and 24-hour operation.

**HUMAN APPROVAL REQUIRED**
- Build authority release of the immutable signed artifact.
- Windows Policy Owner approval of the exact rule/scope/expiry.
- Authorization to run the future physical acceptance matrix.

## 17. Positive approval verifier addendum (2026-10-12)

**NOT APPROVED — REVIEW REQUEST ONLY.** This addendum changes no
approval decision and enables no native execution.

- Implemented isolated pure verifier:
  `src/openjarvis/sandbox/approval_verifier.py` (no OS, process,
  signing, WDAC, or network calls). Typed immutable records,
  canonical serialization, constant-time digest compare, explicit
  trusted roots, expiry/revocation, single-use tracker, structured
  denial codes, auditable results.
- Gate states (ordered, not interchangeable): `UNAPPROVED →
  EVIDENCE_VALIDATED → POLICY_VERIFIED →
  PHYSICAL_ACCEPTANCE_AUTHORIZED → NATIVE_EXECUTION_ELIGIBLE`.
  A synthetic `NATIVE_EXECUTION_ELIGIBLE` result is test-only and
  never authorizes real execution (`production_gate_decision`
  always denies with `PRODUCTION_NOT_APPROVED`).
- Production integration point: `RLMWorker._start_sandboxed` audits
  any attached approval evidence via `audit_spec_approval`, then
  unconditionally raises `RLM_SANDBOX_NOT_AUTHORIZED`. The native
  launcher call remains unreachable; no env flag, config toggle,
  or mock approval bypasses the production denial.
- Negative regressions: `tests/security/test_native_approval_verifier.py`
  (24 denial shapes + single-use/TOCTOU/race/physical/legacy cases;
  every denial proves the launcher is not invoked).
- TOCTOU: verifier compares an optional post-read artifact hash
  (`ARTIFACT_REPLACED_TOCTOU`); path-based hash alone is documented
  as insufficient. Handle-based identity, Authenticode-to-bytes
  binding, and WDAC enforcement remain `REQUIRES_OS_PROOF`.
- Missing verifier backend is a fail-closed denial
  (`BACKEND_MISSING`), never an allow.

## 18. Closure-cycle findings (2026-10-12)

**NOT APPROVED — REVIEW REQUEST ONLY.** No native execution enabled.

Verifier audit (`approval_verifier.py` vs. the §17 contract) found
and fixed six concrete defects, each with a failing-first regression
in `tests/security/test_native_approval_verifier.py` (now 23 passed):

- `source.identity` was parsed but never bound → added
  `ExpectedContext.source_identity` and `SOURCE_IDENTITY_MISMATCH`
  (enforced only when the host supplies an expectation).
- Non-dict `cert_evidence`/`binding_evidence`/scope blobs flowed to
  the backend instead of failing fast → `parse_approval` now
  requires objects/strings strictly (`APPROVAL_MALFORMED`); dedicated
  MISSING codes (`SOURCE_DIGEST_MISSING`, `WDAC_POLICY_MISSING`)
  are preserved.
- Boolean timestamps coerced via `float()` → rejected as
  `APPROVAL_MALFORMED`.
- `sandbox_constraints` were carried but never enforced → pure
  `check_sandbox_spec` plus optional `spec_snapshot` binding
  (`SPEC_MISMATCH` covers shared-runtime/keep-dir/timeout violations;
  absent snapshot means unverified, never allowed in production).
- Success audit did not record which checks ran → now reports
  `toctou_checked` and `single_use`.
- No new root of trust: trusted roots remain caller-supplied;
  self-declared signer/policy metadata still requires backend proof.

Artifact/TOCTOU: exe selection stays a fixed relative path
(`worker_launcher.py:314`); shared-runtime delegation proven
without real launch (missing dir → `MANIFEST_FAILURE`; mocked ready
→ exact session/nonce delegation). Verify-to-execute handle pinning,
Authenticode-to-bytes binding, and WDAC enforcement remain
`REQUIRES_OS_PROOF`; production stays denied.

Integration readiness: `RLMWorker._start_sandboxed` audits attached
approval evidence, then unconditionally raises
`RLM_SANDBOX_NOT_AUTHORIZED`; the launcher stays unreachable. No env
flag, config toggle, or mock approval bypasses the denial. Safe
isolated coverage added for cancel-before-dispatch (`RPC_CANCELLED`,
no broker/launcher contact), close-after-denial (no spawn/retry),
and fake-launcher result identity (forged session rejected).

Source/build: manifest records `rust/Cargo.lock` (tracked-clean);
C-launcher build inputs beyond the `.c` file (exact `cl`/`link`
command, resource inputs) are MISSING (see §12). Rust 1.88 still
absent (active 1.99.0); no compilation performed.

Approval bundle: source identity AVAILABLE as claim / NOT VERIFIED
as binding; reproducible evidence MISSING; PE hash MISSING; signer
+ chain MISSING; WDAC policy + binding MISSING; owner/expiry/audit/
revocation MISSING; physical acceptance NOT VERIFIED. Human actions:
supply the §12 build record, sign, bind policy, and authorize the
physical lane in writing — until then the lane stays disabled.

## 19. Consolidated Build Authority handoff (2026-10-12)

**NOT APPROVED — REVIEW REQUEST ONLY.**
`READY_FOR_HUMAN_REVIEW = true`; `APPROVED_FOR_EXECUTION = false`.
No native execution is authorized by this package.

### 19.1 Exact C launcher build commands (proposed, NOT executed)

Derived from the single C source
(`third-party/codex-security-poc/native_appcontainer_launcher.c`,
only C file; headers `windows.h/sddl.h/userenv.h` + CRT; pragma libs
`advapi32/userenv`; kernel32 implicit; entry `wmain`; no
`__DATE__/__TIME__`, no `.rc`, no `LoadLibrary`/`system` calls).
Tool paths below were verified to exist; the commands were not run.

Set (conceptually; use the isolated build host, never this checkout):

- `MSVC=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools`
  `\VC\Tools\MSVC\14.51.36231`, `SDK=C:\Program Files (x86)`
  `\Windows Kits\10`, `SDKV=10.0.26100.0`.

Environment initialization: prefer direct absolute tool paths as above
(no global environment mutation, fully logged). `vcvars64.bat`
(`VC\Auxiliary\Build\vcvars64.bat`, present) is the documented
alternative; if used, record its exact path, version output, and the
resulting `INCLUDE`/`LIB`/`PATH`. Either way the build log must
contain the full expanded `cl`/`link` command lines, `cl` banner
version, SDK version, and the final artifact hash — a log without
these is a reproducibility failure.

Compile (static CRT `/MT` so the launcher ships no VC-redist
dependency and WDAC binds a single file):

- `"%MSVC%\bin\Hostx64\x64\cl.exe" /nologo /c /W4 /O2 /MT`
  `/DUNICODE /D_UNICODE /DNDEBUG`
  `/I"%MSVC%\include" /I"%SDK%\Include\%SDKV%\ucrt"`
  `/I"%SDK%\Include\%SDKV%\shared" /I"%SDK%\Include\%SDKV%\um"`
  `/Fo"<build>\native_appcontainer_launcher.obj"`
  `"<src>\native_appcontainer_launcher.c"`

Link (console, deterministic, no elevation manifest required):

- `"%MSVC%\bin\Hostx64\x64\link.exe" /NOLOGO`
  `/OUT:"<build>\astra_native_launcher.exe" /MACHINE:X64`
  `/SUBSYSTEM:CONSOLE /ENTRY:wmainCRTStartup /INCREMENTAL:NO /Brepro`
  `/DYNAMICBASE /NXCOMPAT /RELEASE /OPT:REF /OPT:ICF`
  `/LIBPATH:"%MSVC%\lib\x64"`
  `/LIBPATH:"%SDK%\Lib\%SDKV%\ucrt\x64"`
  `/LIBPATH:"%SDK%\Lib\%SDKV%\um\x64"`
  `"<build>\native_appcontainer_launcher.obj"`
  `advapi32.lib userenv.lib kernel32.lib`

The final filename is fixed by the Policy Owner (the PoC usage text
still prints the old name; cosmetic only). `/WX` is intentionally
absent until a clean `/W4` review exists. No PDB is emitted; if PDBs
are later required for triage, the deterministic path policy needs a
separate human decision. Rebuild byte-match must reuse the identical
absolute source path; matching bytes are necessary but not approval.

Flag compatibility matrix (read-only static validation, 2026-10-12;
no binary was executed — presence means the installed toolchain
recognizes the option name, not that the link succeeds):

| Flag | Evidence | Status |
|---|---|---|
| `/Brepro /DYNAMICBASE /NXCOMPAT /INCREMENTAL /SUBSYSTEM /MACHINE /LIBPATH /NOLOGO /OUT /ENTRY /RELEASE` | token present in installed `link.exe` (ASCII/wide scan) | VERIFIED present |
| `/OPT:REF /OPT:ICF` | `ref`+`icf` present in `link.exe` | VERIFIED present |
| `/MT /W4 /NOLOGO` | token present in installed `cl.exe` | VERIFIED present |
| `/O2 /c /I /Fo /D* /ENTRY:wmainCRTStartup` pairing | short/documented-standard tokens | NOT VERIFIED individually |
| `wmainCRTStartup` static entry | symbol present in `libcmt.lib` | VERIFIED |
| `CreateProcessW / CreateAppContainerProfile / ConvertSidToStringSidW` | names present in `kernel32/userenv/advapi32.lib` (um/x64) | VERIFIED |
| Final PE metadata, `/Brepro` byte determinism, default-entry behavior | requires actual link | NOT VERIFIED |

### 19.2 Environment, source, and reproducibility

- Required: MSVC toolset `14.51.36231` (compiler `19.51.36256.0`),
  Windows SDK `10.0.26100.0`, target `x64`. Rust 1.88 is NOT required
  for Artifact A (C-only); it applies to Artifact B (PyO3) only.
- Immutable snapshot: clean export at an approved commit; reject
  dirty/untracked inputs (this checkout is dirty — HEAD does not
  identify it); rehash the §2 closure plus `rust/Cargo.lock`; record
  `cl/link` paths+hashes, flags, env, and timestamp policy.
- Exact verification steps (Build Authority host): `git archive` the
  approved commit to a clean directory; `certutil -hashfile <file>
  SHA256` per closure file and compare against the manifest (any
  mismatch stops the build); `rustc -Vv`, `cargo -V`, and
  `(Get-Item cl.exe).VersionInfo` recorded into the build log.
- Expected PE metadata: x64 (`0x8664`), PE32+, subsystem console,
  statically linked CRT, `asInvoker` (no elevation manifest).

### 19.3 Hash, signing, WDAC, and approval requirements

- Hash: `certutil -hashfile <artifact> SHA256` (or equivalent) on the
  final PE; record size/arch/hash. Policy Owner countersigns the
  manifest; any byte mismatch stops approval.
- Signing: `signtool sign` by the Signing Authority, then
  `Get-AuthenticodeSignature` + `signtool verify /pa /all /v` with
  full chain, validity, and revocation evidence. Unsigned artifacts
  (including the existing debug DLL) are never approval evidence.
- WDAC: policy/rule ID bound to the exact final hash (preferred) or
  approved signer, scope limited to the launcher, enforcement mode
  stated. Approval record carries owner, approval ID, issued/expiry,
  audit ID, renewal, and revocation procedure. Stale revocation
  snapshots are rejected (`REVOCATION_STALE` pattern); empty trust
  anchors never authorize (`TRUSTED_ROOTS_MISSING` pattern).
- Validity semantics are half-open: `issued_at <= now < expires_at`;
  at the expiry instant the approval is expired. Non-finite
  timestamps are malformed. Wall-clock rollback is a residual risk,
  bounded by short validity, fresh revocation, and single-use — and
  production stays denied regardless.

### 19.4 OS-backed identity design (future implementation)

Path hashes alone do not close TOCTOU. The future launcher must hold
an open read-only handle from verification through `CreateProcessW`
and prove: file ID/volume (`GetFileInformationByHandle`), no reparse
(`FILE_ATTRIBUTE_REPARSE_POINT` refusal), Authenticode bound to the
launched bytes (not the path), WDAC allow verdict for the same
bytes, and token/AppContainer SID from `query_token_identity`.
Until that OS proof exists, production stays denied.
Post-launch image evidence has a designated future wiring point:
`query_process_image` (`appcontainer.py:756`) is implemented but not
called in the launch path; binding its result to the verified hash
before handshake acceptance is REQUIRED_OS_WORK, not done here.

### 19.5 Future production integration contract (not connected)

Authorization is host-issued only after verifier `ELIGIBLE` +
signed-artifact binding + WDAC binding + fresh revocation +
single-use claim + Dispatch Ledger `DISPATCHED` (cross-process
exactly-once is ledger-owned, never tracker-owned). IPC keeps
host-minted session/nonce with `_validate_identity` on every frame.
Timeout/cancellation terminates the Job (`KILL_ON_JOB_CLOSE`,
`ActiveProcessLimit=4` per the C source); `UNKNOWN_OUTCOME`
quarantines without retry/redispatch; crash keeps quarantine and
cleanup errors accumulate. Emergency disable: Policy Owner revokes
the rule, artifact removed from staging, audit retained, lane falls
back to `RLM_SANDBOX_NOT_AUTHORIZED`. The unreachable launcher call
(`rlm_worker.py:795`) must not be connected until every item above
is evidenced and separately authorized.

### 19.6 Physical acceptance matrix (future, NOT executed)

Each row: preconditions → action → OS evidence → Astra result →
cleanup. Full detail in §6/§7A; condensed obligations:

- SID/token: approved artifact+policy → token query shows only the
  approved identity → VERIFIED or DENY → delete profile.
- FS read/write denial: staged tree+ACL snapshot → out-of-scope
  access denied → DENY on violation → revoke ACE, remove staging.
- IPC/nonce: host-created pipe → forged session rejected →
  QUARANTINE → close handles.
- Network/DNS/proxy/redirect: no capability → all attempts fail →
  DENY → no residue.
- Child/job: job pre-resume → escape denied, kill-on-close verified
  → DENY → terminate job, confirm no descendants.
- Timeout/cancel/orphan: bounded timeouts → exit+handles+staging
  removed, no residue → else SAFETY FAILURE.
- Artifact/WDAC: final bytes → hash+signer+policy verdict match →
  else DENY → revoke rule, remove artifact.
- `UNKNOWN_OUTCOME`/duplicate/fallback: lost dispatch, replay,
  legacy attempt → quarantine, ledger rejects second, fallback
  denied → audit retained.
- Audit: every row emits artifact/source/policy/OS receipts without
  secrets → incomplete trail is NOT PROVEN.

### 19.7 Outstanding blockers

Approved `.exe` MISSING; C build command unexecuted; Rust 1.88
absent; signatures/policy MISSING; `CiTool ACCESS_DENIED` for the
current user; all §19.6 rows NOT EXECUTED. The single next milestone
is §Q of the closing report.

## 20. Source snapshot, reproducibility, and approval checklists

**NOT APPROVED — REVIEW REQUEST ONLY.** No snapshot created here;
only the Build Authority on an isolated clean host may bless one. A
locally produced snapshot is procedure validation, never approval.

### 20.1 Dirty/untracked-aware snapshot procedure (corrects `git archive`)

`git archive HEAD` silently drops dirty and untracked inputs, so the
procedure overlays them explicitly (read-only commands; nothing is
staged, committed, or overwritten):

1. `git rev-parse HEAD` → record baseline (this checkout: dirty, so
   HEAD alone identifies nothing).
2. `git archive HEAD <tracked allowlist>` → clean directory.
3. Overlay each approved dirty/untracked file from the explicit
   allowlist (§2 closure + `Cargo.lock` + toolchain files); hash
   each with `certutil -hashfile <file> SHA256` (cross-checked
   2026-10-12: C `DA66889D…`, `appcontainer.py` `85F25039…`,
   `worker_launcher.py` `CD3FF2A0…`, `staged_runtime.py`
   `300D7FBE…`, `Cargo.lock` `69FD2372…` — current-byte match,
   still untracked).
4. Reject anything unlisted: `git status --porcelain` plus a full
   directory listing must contain zero files outside the allowlist,
   else STOP.
5. Write the canonical manifest: sorted `SHA256 + "  " + path +
   "  " + git-state` lines, then HEAD, tool versions, and the
   manifest's own SHA-256.
6. Verify by rehashing from the manifest; any mismatch or extra file
   is a provenance failure — stop signing.
7. Freeze the snapshot directory read-only; further mutation
   requires a new manifest and new approval ID.

### 20.2 Controlled reproducibility evidence template

| # | Evidence | Owner | Status |
|---|---|---|---|
| 1 | Immutable manifest (§20.1) + its SHA-256 | Build Authority | TEMPLATE — NOT EXECUTED |
| 2 | Toolchain identity (`rustc -Vv`, `cargo -V`, `cl` banner+file hash, SDK version) | Build Authority | TEMPLATE |
| 3 | Full `cl`/`link` command lines + build log | Build Authority | TEMPLATE (§19.1) |
| 4 | Env/flags/timestamp policy (`SOURCE_DATE_EPOCH` or nondeterminism list) | Build Authority | TEMPLATE |
| 5 | PE metadata (x64, console, static CRT, asInvoker) | Build Authority | TEMPLATE |
| 6 | Final SHA-256 (`certutil -hashfile`) | Build Authority | TEMPLATE |
| 7 | Independent second build, byte-for-byte match | Build Authority | TEMPLATE |
| 8 | Mismatch/provenance-failure stop record | Build Authority | TEMPLATE |

### 20.3 Signing / WDAC / policy-owner checklist

- [ ] Final PE path, arch, size, SHA-256 (Build Authority).
- [ ] `Get-AuthenticodeSignature` + `signtool verify /pa /all /v`
      outputs with full chain, validity, revocation (Signing Authority).
- [ ] WDAC rule ID bound to exact hash (preferred) or signer, narrow
      scope, enforcement mode (Policy Owner).
- [ ] Approval ID, owner/role, decision time, half-open expiry
      (`issued_at <= now < expires_at`), renewal, audit ID, revocation
      path (Policy Owner).
- [ ] Emergency disable: revoke rule → remove staged artifact →
      quarantine session → retain audit → lane reverts to
      `RLM_SANDBOX_NOT_AUTHORIZED`; no retry/redispatch/fallback.
- [ ] Bounded physical-lane authorization: one non-cloud lane, named
      operator, time window (Policy Owner).

### 20.4 Residual risk register (evidence-based)

- Unsigned/unbound artifact provenance — MITIGATION: none yet;
  OWNER: Build/Policy Owner.
- Rust 1.88 absent on current host — MITIGATION: isolated build host
  required; OWNER: Build Authority.
- `CiTool ACCESS_DENIED` (no current-user policy visibility) —
  MITIGATION: Policy Owner evidence; OWNER: Policy Owner.
- Verify-to-execute handle gap; `query_process_image` unwired —
  MITIGATION: §19.4 OS design + denial; OWNER: Windows verifier.
- Wall-clock rollback — MITIGATION: short validity + fresh
  revocation + single-use; OWNER: accepted residual.
- Process-local single-use ≠ cross-process exactly-once —
  MITIGATION: Dispatch Ledger ownership, documented; OWNER: design.

## 21. Operational physical acceptance plan (authorized personnel only)
NOT EXECUTED. Each scenario requires written Policy Owner lane
authorization plus the signed artifact + bound policy. Timeout
10–60 s per scenario unless stated; any FAIL quarantines the lane
and triggers §20.3 emergency disable; cleanup always removes
profile, ACE, pipes, job, and owned staging.

| # | Scenario | Action | OS evidence → Astra result | Pass / Fail |
|---|---|---|---|---|
| 1 | Restricted token | launch, inspect token | only approved identity → VERIFIED | else DENY |
| 2 | AppContainer SID | compare request vs token SID | exact match, no extra caps | else DENY |
| 3 | FS read denial | out-of-scope read probe | ACCESS_DENIED → DENY | access granted → SAFETY FAILURE |
| 4 | FS write denial | out-of-scope write probe | ACCESS_DENIED → DENY | write succeeds → SAFETY FAILURE |
| 5 | IPC identity | valid handshake | `_validate_identity` accepts → continue | — |
| 6 | Nonce/session binding | forged session frame | rejected → QUARANTINE | accepted → SAFETY FAILURE |
| 7 | Network denial | direct connect attempt | fails → DENY | egress → SAFETY FAILURE |
| 8 | DNS/proxy/redirect | resolving/proxied/redirected fetch | all fail, no env proxy use | any success → SAFETY FAILURE |
| 9 | Child containment | spawn descendant probe | denied or job-contained | escape → SAFETY FAILURE |
| 10 | Job kill-on-close | close job with live child | descendants exit ≤5 s | orphan → SAFETY FAILURE |
| 11 | Timeout termination | exceed launch/RPC timeout | exit + handles closed | hang → SAFETY FAILURE |
| 12 | Cancellation cleanup | cancel mid-flight | profile/ACL/pipes/staging removed | residue → FAIL |
| 13 | Orphan prevention | kill parent/worker forcibly | no owned residue | residue → SAFETY FAILURE |
| 14 | Artifact identity | hash launched bytes | equals approved SHA-256 | mismatch → DENY + revoke |
| 15 | WDAC enforcement | run under approved policy | allow verdict for exact bytes | block/allow-mismatch → DENY |
| 16 | UNKNOWN_OUTCOME | drop result frame | quarantine, no retry | retry/redispatch → SAFETY FAILURE |
| 17 | No duplicate dispatch | replay dispatch | ledger rejects second | second mutation → SAFETY FAILURE |
| 18 | No fallback | request legacy/multiprocessing path | denied before spawn | spawn → SAFETY FAILURE |
| 19 | Audit completeness | collect all receipts | artifact/source/policy/OS, no secrets | gaps → NOT PROVEN |

## 23. Gate B approval request and authorization integration (2026-10-12)

**`GATE_B_AUTHORIZED = FALSE`.** No Build Authority approval exists;
the build script refuses every invocation until the ceremony below
is completed by a human authority. Approving Gate B never authorizes
executing the launcher, loading DLLs, signing, WDAC changes,
physical tests, or production connection.

### 23.1 Approval request (Build Authority decision needed)

1. Source snapshot: `.../Temp/opencode/astra-candidate-snapshot-d596e48`,
   manifest SHA-256 `62A15FEA…F4F624` (§22).
2. Build script: `scripts/astra-native-launcher-build.ps1` at the
   hash recorded in the approval (`scriptHash` binds it; any edit
   invalidates prior approvals). Pester boundary suite:
   `tests/security/test_gateb_build_script.Tests.ps1` (12 passed).
3. Toolchain pins: cl `19.51.36256.0`, link `14.51.36256.0`,
   SDK `10.0.26100.0`, x64, static CRT (`TOOLCHAIN.md`).
4. Command: §19.1 exact `cl`/`link` lines; output
   `astra_native_launcher.exe` into the approved (empty) directory.
5. Scope is build-only; prohibited: execution, signing, policy,
   physical tests, production wiring.
6. Approval validity is half-open with expiry + revocation list +
   single-use claim (`claimDir`); failed builds do not consume the
   claim, successful builds do (controlled replay).
7. Evidence: build log, exit codes, PE metadata, final SHA-256,
   `ARTIFACT.<id>.sha256`, claim file. Any mismatch quarantines the
   output and stops signing.
8. Rollback: delete output dir + claim stays consumed; lane remains
   `RLM_SANDBOX_NOT_AUTHORIZED`.

### 23.2 Authorization integration specification (reviewable)

Superseded by §24: approval records are RS256-signed envelopes, and
the trust anchor is the pinned trust store (absent), not an in-code
issuer list. The §23.1 request items (snapshot/script/toolchain
binding, scope, evidence, rollback) remain valid.

Approval record JSON schema (all fields required):
`schema=1`, `issuer`, `approvalId`, `operation="gate-b-build"`,
`snapshotHash` (=`MANIFEST.sha256` hash), `scriptHash` (=running
script hash), `toolchain{cl,link,sdk}`, `outputDir` (exact canonical
path), half-open `issuedAt/expiresAt`, `revokedIds[]`, `claimDir`,
`auditRef`. The script verifies every field against observed reality
and fails closed (`ISSUER_NOT_TRUSTED`, `SNAPSHOT_MISMATCH`,
`SCRIPT_MISMATCH`, `TOOLCHAIN_MISMATCH`, `OUTPUT_DIR_MISMATCH`,
`APPROVAL_EXPIRED/REVOKED/REUSED`).

Trust ceremony (human authority only, no bypass exists in code):
populate `$TrustedIssuers` in the script with the authority identity,
record the new script hash, and issue the approval record against
that hash. There is no environment variable, switch, or default that
skips this. Until then Gate B is non-executable by construction.

## 22. Candidate snapshot and build package record (2026-10-12)

**NOT APPROVED — REVIEW REQUEST ONLY.** GATE A safe portion executed;
Gates B–F are NOT AUTHORIZED and NOT EXECUTED (no explicit approval
identifying operation, target, environment, and authority was issued;
the `third-party` evidence-package files state NOT SUBMITTED).

- Candidate snapshot (CANDIDATE, not approval):
  `C:\Users\yingz\AppData\Local\Temp\opencode\astra-candidate-snapshot-d596e48`
  (outside repo; destination verified absent before creation). 10
  allowlist files + `MANIFEST.sha256` (self-hash
  `62A15FEA…F4F624`) + `PROVENANCE.md` + `TOOLCHAIN.md`; byte-match
  verified (`BYTES_MATCH=True`); zero unlisted files.
- Ready-to-run build package:
  `scripts/astra-native-launcher-build.ps1` (parse-checked, 0 errors,
  never executed). Requires `-ApprovalEnvelope` (RS256-signed JSON,
  schema §24) + `-SourceDir` + `-OutDir`; pinned trust store
  `build-authority/trust-roots.json` is absent, so every invocation
  currently fails closed with `TRUST_STORE_MISSING` before any side
  effect. Validation helpers are unit-tested via dot-sourcing
  (Pester: boundary 6/6, crypto 16/16). Exit codes: 0 built | 2
  authorization/provenance refusal | 3 toolchain | 4 input | 5 build.

## 24. Cryptographic trust design and human ceremony (2026-10-12)

**NOT APPROVED — REVIEW REQUEST ONLY. `GATE_B_AUTHORIZED = FALSE`.**
No trust roots provisioned; no production keys generated.

### 24.1 Design (implemented, non-executable until ceremony)

- Algorithm: fixed `RS256` (RSA-2048+ PKCS#1 v1.5 + SHA-256 via .NET
  `RSACryptoServiceProvider`, no custom primitives, no negotiation;
  re-asserted at envelope parse AND signature step — a unit test
  proved the second check was missing and it was added).
- Envelope `{schema:1, kid, algorithm, payload, signature}`; payload
  binds protocol version, approval/issuer/key IDs, operation,
  snapshot+script hashes, toolchain pins, output+claim dirs,
  authority, integer `issuedAt/notBefore/expiresAt` (half-open),
  revocation ref, `replayPolicy: "single-use"`, audit ID.
- Canonical form: recursive sorted-key compact JSON; signature covers
  exactly those bytes. Duplicates, unknown fields, non-canonical
  types, bad base64, and oversize (>64 KiB) envelopes are malformed.
- Trust store (pinned
  `build-authority/trust-roots.json`, ABSENT): versioned key records
  `{kid, issuer, modulusB64, exponentB64, validity, revoked}` with
  store freshness (`asOf`/`maxAgeSeconds`); weak keys (<2048-bit),
  unknown/duplicated kids, and revoked keys rejected.
- Replay: atomic `FileMode.CreateNew` claims after successful build
  only (cross-process safe; 4-way race test admits exactly one
  winner); pre-existing/corrupt claims deny replay; crashes leave no
  claim so retry is safe (deterministic bytes); unknown build outcome
  never auto-retries.
- A valid untrusted-key signature never authorizes: issuer must equal
  the trusted key's issuer; caller-supplied keys have no field to
  live in.
- Parser-differential closure (PS 5.1 operators are case-insensitive;
  JSON is not): all structural names, identifiers, algorithms, and
  operations compare case-sensitively (`-cne`/`-ceq`/`-cin`); hashes
  and Windows paths keep value/path semantics. ASCII `\uXXXX`
  escapes are normalized before duplicate detection.
- Manifest hardening: `:`-bearing entries (ADS/drive) rejected;
  case-insensitive manifest collisions rejected (`MANIFEST_COLLISION`);
  hardlinks remain a documented residual (re-hash before use +
  claim-bound artifact hash mitigate; OS handle pinning is
  REQUIRED_OS_WORK).

### 24.2 Human trust ceremony (NOT EXECUTED — responsible authority)

Operator runbook (offline machine unless stated):

0. Identify the Build Authority (name/role) and record responsibility.
1. Generate RSA-2048+ offline; never export the private key; record
   custody (who holds which copy, storage medium, access log).
2. Compute modulus/exponent fingerprints; verify them on a second
   machine via an independent channel before use.
3. Verify snapshot identity (`MANIFEST.sha256` rehash), build script
   hash, and toolchain pins against §22/`TOOLCHAIN.md`.
4. Write `build-authority/trust-roots.json` (storeVersion, asOf,
   keys, empty `revokedApprovals`); countersign its hash in the audit
   record with retention (minimum: approval lifetime + 1 year).
5. Generate the approval envelope; verify the signature offline with
   an independent implementation before release.
6. Revocation/expiry: revoked kids and approval IDs go into the store
   (`revoked: true`, `revokedApprovals`); refresh `asOf`; approvals
   carry half-open validity.
7. Emergency disable = revoke kid + approval IDs, delete staged
   outputs, retain audit; rollback of ceremony = remove trust store
   (Gate B returns to `TRUST_STORE_MISSING` denial).
   Rotation: add new kid, dual-publish during overlap, then revoke
   the old kid and refresh `asOf`.

## 25. Gate-separated operator checklist (2026-10-12)

**NOT APPROVED — REVIEW REQUEST ONLY.** No gate implies any other;
each requires its own explicit authorization record.

| Gate | Authorizes | Requires | Status |
|---|---|---|---|
| Trust ceremony | key/store provisioning only | §24.2 steps 0–7 | NOT EXECUTED |
| B build | one isolated C build | §23 envelope + §22 package | NOT AUTHORIZED |
| C sign | signing the built PE | B artifact + §20.3 | NOT AUTHORIZED |
| D policy | WDAC rule install | C signature + §20.3 | NOT AUTHORIZED |
| E physical | 19-scenario lane (§21) | D policy + §20.3 lane auth | 0/19 NOT EXECUTED |
| F production | launcher wiring | A–E evidence + Policy Owner | DENIED |

Cross-gate evidence rules (machine-checked by
`release_evidence.validate_release_bundle`): identical artifact hash
in B–E, C signature approved, D policy enforcing, E 19/19 with
quarantine, freshness window, synthetic bundles never proof.

## 26. Gate B–F execution assessment (2026-10-12)

Per-gate verdicts from read-only inspection (no gate executed):

| Gate | AUTHORIZED | EXECUTED | VERIFIED | Reason |
|---|---|---|---|---|
| Trust ceremony | NO | NO | NO | No designated authority on record; invoking principal (yingz, FullControl over repo) could rewrite a repo-pinned trust store — store needs off-host or admin-ACL placement with countersignature |
| B build | NO | NO | NO | No ceremony, no envelope; script hash `EF31F8AD…` unchanged; snapshot 10/10 intact |
| C signing | NO | NO | NO | No signing auth/identity/infra; offline validation only |
| D WDAC | NO | NO | NO | `citool -lp` now readable (was ACCESS_DENIED): platform policies present, none applied except MS cross-certs audit; no artifact rule; host is a physical daily-driver laptop (HP OmniBook, no VM/rollback) — enforcement here risks lockout |
| E physical | NO | 0/19 | NO | Same host-isolation blocker; mock harness only |
| F production | NO | NO | NO | Gates B–E evidence absent; `NATIVE_EXECUTION = DENIED` |

Machine: HP OmniBook 7 (physical, not disposable); user
`eishu_jarvis\yingz` holds Administrator. Overall approval covers
assessment/preparation only — it does not satisfy authority, scope,
or safety prerequisites for any gate above.


