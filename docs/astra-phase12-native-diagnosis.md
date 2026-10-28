# Astra Phase 12: Windows native build and private-data permissions

This continues `codex/astra-reliability` from `d63643ce` and the eleven verified
implementation checkpoints. Mark1 was not read or modified. Historical counts
in `astra-run-report.md` remain evidence of those earlier runs.

## Native execution restriction: evidence and resolution

The original failure was **Smart App Control enforcement**, implemented through
Windows Code Integrity. It was not a demonstrated Cargo, SQLite, TEMP or ACL
failure. Code Integrity event 3077, record 99567, at
`2026-10-03T05:26:16.3666481Z` identifies:

- Parent: `C:\Users\yingz\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin\cargo.exe`.
- Rejected child:
  `C:\Users\yingz\.codex\worktrees\d76f\JARVIS-Sol\rust\target\debug\build\libsqlite3-sys-b22951d79b95a653\build-script-build.exe`.
- Policy: `VerifiedAndReputableDesktop`, version `27555.1000.240208`, GUID
  `{0283ac0f-fff1-49ae-ada1-8a933130cad6}`.
- Policy SHA-256:
  `2668895a5b233a80432d00d67251d7b7f52686a3fb13780f4b242c5a1f937a01`.
- Requested/validated signing levels: `2 / 1`; NTSTATUS `0xc0e90002`.
- Flat executable SHA-256:
  `ecb2b4cd4953e69715e450f2a3fbd6d3637905b71279b5fa9110824481503993`.
- Related event 3033, record 99565, and event 3089, record 99568: zero signatures,
  unknown publisher/issuer. Authenticode independently reports `NotSigned`.
- Cargo exited 101; CreateProcess failed with Windows error 4551. The child did
  not start. The log's extensionless path resolves to the existing `.exe`.

The original build command, from the repository root, was:

```powershell
$env:PATH="$env:USERPROFILE/.cargo/bin;$env:PATH"
$env:VIRTUAL_ENV=(Resolve-Path .venv).Path
& ./.venv/Scripts/maturin.exe develop --manifest-path rust/crates/openjarvis-python/Cargo.toml
```

Read-only corroboration:

- `VerifiedAndReputablePolicyState=1`, `SAC_EnforcementReason=1`; kernel/user-mode
  Code Integrity enforcement statuses are both 2. The matching active `.cip`
  file's SHA-256 is identical to the event's policy hash.
- Defender `EnableControlledFolderAccess=0`.
- No matching AppLocker EXE/DLL or MSI/script rejection was returned. The
  `SrpV2` policy registry key is absent. `Get-AppLockerPolicy` is unavailable;
  `CiTool -lp -json` returns access denied, `-2147024891`. This is a visibility
  limitation, not permission to change policy or proof about every other policy.
- The executable and Cargo target directory are owned by this user, with
  inherited user/SYSTEM/Administrators full control and CodexSandboxUsers
  read/execute. The executable has no `Zone.Identifier` stream.
- `CARGO_TARGET_DIR`, `CARGO_HOME`, `RUSTUP_HOME`, `RUSTC`, and `PYO3_PYTHON` were
  unset. No user or repository Cargo config/config.toml exists. Target is the
  default repository `rust/target`, not a temporary executable directory.
- `TEMP=TMP=C:\Users\yingz\AppData\Local\Temp`, with a protected DACL including
  this user's full control. Maturin uses TEMP for wheel staging; the originally
  rejected child lives in `rust/target/debug/build`.
- Workspace rusqlite enables bundled SQLite; inspected registry dependency
  `libsqlite3-sys-0.38.2/build.rs` builds that bundled code. Its first operation
  requires `OUT_DIR`. Failure preceded that operation.

### Smallest safe reproduction attempt

After inspecting that build script, the diagnostic deliberately removed
`OUT_DIR` and launched the **same, unmodified, hashed executable** from global
CPython 3.11. If admitted, it must panic before starting a SQLite build. At
`2026-10-03T12:18:33.933064Z` it **was admitted**, then exited 101 with the expected
missing-OUT_DIR panic at build.rs:70. Parent PID was 40348.

A separate standard-library-only probe source was:

```rust
fn main() { println!("astra-native-probe"); }
```

Exact commands:

```powershell
& "$env:USERPROFILE/.cargo/bin/rustc.exe" .astra-tools/native-diagnostic/hello.rs --edition=2021 -o .astra-tools/native-diagnostic/hello.exe
& ./.astra-tools/native-diagnostic/hello.exe
```

Compile and execution both exited zero. Probe SHA-256 was
`385ca9c1dff6ede39ad9fe00e02dd9b9cffc01fc6a1ae2a02017f3432c47a23f`.
The raw commands, parent, timestamps, errors and hashes are retained locally in
`.astra-tools/native-diagnostic/reproduction.json` and `reproduce.py`.

**The original block is established by historical event/log evidence, but
did not reproduce in this attempt.** No file was renamed/copied to evade policy,
and no alternate trusted path was needed. Smart App Control remained enforced;
its on-disk policy hash remained unchanged. Available logs do not explain the
later admission. A reputation/cache decision change is a plausible inference,
not an established cause. Do not claim that arbitrary generated binaries will
always be trusted or that a persistent compatibility fix was installed.

This changed execution evidence justified one new full build with the original
command. It exited zero after 90 seconds, built all local Rust crates, and
installed `openjarvis-rust-0.1.0` for **CPython 3.11 Windows AMD64**. A subsequent
source-change rebuild took 9.75 seconds and also exited zero. Build logs:
`astra-native-phase12-build.log`, `astra-phase12-native-rebuild.log`.
Both report the pre-existing nom 1.2.4 future-compatibility warning.

### Artifact provenance and supported alternatives

The loaded binary is
`.venv/Lib/site-packages/openjarvis_rust/openjarvis_rust.cp311-win_amd64.pyd`.
Its SHA-256 exactly matches `rust/target/debug/openjarvis_rust.dll`:
`8fb8e5421e8a33a282ae14550fb48b520aa75840bbe4c0d20df8bb6b46abb824`.
Editable distribution metadata identifies this worktree's
`rust/crates/openjarvis-python`. Cargo.lock SHA-256:
`69fd237228010090c155ff455e06595a60818483c089acf8ce09a7a349ada6a5`.
No downloaded substitute native binary was used. Runtime: global CPython 3.11.9;
compiler/toolchain: Rust/Cargo 1.99.0, x86_64-pc-windows-msvc, installed VS Build
Tools. The signed global Python uses `PYTHONPATH=src;.venv/Lib/site-packages`.

No security-policy change was required or made. If admission fails again, stop
and inspect the new event instead of looping builds or weakening policy.
[Microsoft documents trusted CA code signing](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control)
as a supported trust route. A controlled Windows builder can also build this
same source and retain source/compiler/artifact provenance; loading its output
on this host would still need to satisfy this host's trust checks. Neither route
authorizes installing a root certificate or broad path exceptions.
[Microsoft's SAC FAQ](https://support.microsoft.com/en-us/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions)
does not offer individual-app bypasses. Disabling SAC is a broad security change
and remains outside this task's authorization; it was not performed.

## Windows permission invariant and implementation

The five failures were invalid POSIX-mode assertions on Windows, but production
also had a real confidentiality defect: chmod changed Windows read-only
attributes, not the DACL. The intended invariant is **ordinary accounts other
than the process user cannot access private application data**. Administrators
with ownership/backup privileges are outside this confidentiality boundary,
just as root is on Unix.

`security/windows_acl.py` now creates objects with a protected DACL containing
one explicit full-control ACE for the current process token's user SID. Existing
objects must be owned by that user. Ownership, type, reparse status and hard-link
count are checked through the same handle used to set and verify the DACL.
Failures propagate; no chmod or permissive fallback masks them. Existing
ancestors are not recursively secured; newly created ancestors are private.
Only supported owner-only 0600/0700 requests map to this Windows contract.

Directories use non-inheritable ACEs and a MAXIMUM_ALLOWED handle, which
[SetSecurityInfo documents](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo)
as suppressing child ACL propagation. Testing caught and corrected an initial
prototype that emptied inherited child DACLs. Final negative tests prove
existing children remain readable/writable. One damaged, empty, test-owned
directory DACL was restored to current-user access with icacls; no user-data or
system ACL was changed. Historical pytest cleanup warnings remain in earlier
run counts.

Atomic text/JSON writes create the Windows temporary file with that DACL before
opening it for secret bytes. The verified temporary object's protected DACL
travels with atomic replacement. Unix chmod/fchmod behavior remains unchanged.
Existing open handles granted before a DACL repair cannot be revoked by this
helper. Ancestor reparse inspection is a precondition check, not a guarantee
against every hostile cross-process ancestor rename. This is private-data
persistence, not a general filesystem transaction or OS sandbox.

Tests use independent GetNamedSecurityInfo/SDDL reads, checking owner SID,
protected DACL, sole explicit owner ACE and absence of inherited/group grants.
They accept Windows' harmless AI bookkeeping flag without accepting inherited
ACEs. Windows PowerShell 5's Get-Acl module could not load under this host's
controls, so validation reads descriptors directly through Windows APIs.
No policy was changed to make that test helper work.

## Failures exposed by native availability

- BM25 Python wrapper called native `delete` and `clear`, but PyO3 lacked those
  exports. The Rust MemoryBackend methods already implemented them. The binding
  now forwards both with the existing error mapping. No native functionality was
  replaced. Existing deletion/count/retrieval tests exercise the real backend.
- The BM25 UUID-length test assumed Python's 32-character `.hex`; Rust has always
  returned canonical hyphenated UUIDs, as the existing SQLite test documents.
  The test now checks actual UUID-v4 validity and uniqueness. Its obsolete
  rank_bm25 import skip was removed because the production backend is Rust.
- REPL reset failed with a one-second timeout. Measured fresh-worker startups
  were 1.050 and 1.040 seconds, while a warm call took 0.001 seconds. The fixture
  now proves readiness before testing a one-second infinite-loop timeout and
  allows ten seconds for explicit reset/bootstrap. Every termination,
  stream-preservation, unknown-outcome and refusal assertion remains. Production
  timeout/worker behavior was not changed.
- Rust workspace tests report five pre-existing symlink fixture failures,
  Windows error 1314 (privilege not held), from file_policy.rs:102. These tests
  fail before reaching policy assertions. The fixture handles PermissionDenied,
  but this Rust/Windows error is returned differently. No privilege setting was
  changed, assertions weakened, or Rust-dependent tests newly skipped. All other
  Rust targets were run using `--no-fail-fast`.

## Regression evidence

Commands use global `python -m pytest`, the PYTHONPATH above, and `-q` with a
separate JUnit file under `.astra-tools/phase12-*.xml`. Counts overlap; never add
them. Initial failing diagnostic runs remain in local logs. Final suite results:

| Scope / exact test selection | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| `tests/core/test_rust_bridge.py` | 23 | 0 | 0 | 0 |
| `tests/agents/test_native_react.py tests/agents/test_native_openhands.py` | 112 | 0 | 0 | 0 |
| Rust: `cargo test --manifest-path rust/Cargo.toml --workspace --exclude openjarvis-python --no-fail-fast` | 421 | 5 | 0 | 1 |
| Native repair: bridge + `tests/memory/test_bm25.py` | 35 | 0 | 0 | 0 |
| `tests/security` | 563 | 0 | 43 | 11 |
| `tests/security/test_file_permissions.py tests/security/test_file_utils.py tests/security/test_windows_acl.py` (before last two negative tests) | 16 | 0 | 0 | 1 |
| Final `tests/security/test_windows_acl.py` | 10 | 0 | 0 | 1 |
| Final combined file-permission/file-utils/Windows-ACL lane | 18 | 0 | 0 | 0 |
| `tests/memory` | 238 | 0 | 13 | 1 |
| `tests/tools/test_execution_outcomes.py` | 10 | 0 | 0 | 0 |
| `tests/tools/test_execution_journal.py` | 10 | 0 | 0 | 1 |
| `tests/tools/test_browser.py tests/tools/test_browser_axtree.py tests/tools/test_browser_safety.py` (13 real Chromium tests) | 100 | 0 | 0 | 1 |
| Shell/REPL/timeout/subprocess/core-utils lane | 110 | 0 | 2 | 1 |
| `tests/agents`, existing offline marker exclusions | 675 | 0 | 0 | 1 |
| `tests/traces tests/agents/test_trace_recording.py` | 66 | 0 | 0 | 1 |
| Existing broad agent/tool/server/security/core-utils/trace lane, offline markers | 2718 | 0 | 68 | 272 |

The shell/REPL lane selects `tests/tools/test_shell_exec.py tests/tools/test_repl.py
tests/tools/test_tool_timeout.py tests/security/test_subprocess_sandbox.py
tests/core/test_utils.py`. The broad lane selects `tests/agents tests/tools
tests/server tests/security tests/core/test_utils.py tests/traces`, with
`-m 'not live and not cloud and not hub and not modal and not live_external and
not live_channel'`. Warnings include pre-existing deprecations and earlier
fixture cleanup evidence. Skip counts retain existing platform/optional-package
conditions; they do not hide native build failures.

Unrestricted `python -m pytest -q --junitxml=.astra-tools/phase12-full.xml`
completed: **8875 passed / 87 failed / 139 skipped / 297 warnings**, zero
collection/teardown errors, 4877.67 seconds. This is the Phase 12 snapshot before
the observation API/new Phase 13 tests and subsequent timing repair.

All 87 failures have a disjoint classification in
`astra-phase12-failure-audit.json`. A `git archive d63643ce` source snapshot,
using the same dependencies/source-built extension, reran precisely those 87
nodes: **85 failed / 2 passed / 0 skipped / 0 warnings**, 24.18 seconds. The two
non-reproducing failures use unchanged coarse-clock paths and are intermittent.
The selected failures do not exercise the new BM25 bindings. This establishes
baseline evidence, not a claim that every failure is harmless.

The audit distinguishes 38 default-encoding test failures, seven coarse-clock
production failures, 12 missing live dependencies/credentials/models/catalogs,
seven HOME-only fixtures, five Linux sysfs-name fixtures, four production
POSIX-strftime portability defects, two symlink privilege failures, and the
remaining distinct launcher, cleanup, formatting and path defects. Windows npm
launch fails because this production path passes bare `npm` to CreateProcess,
while discovery finds `C:\Program Files\nodejs\npm.CMD`. It does not catch the
resulting OSError. The installer URL failure reproduces separately with Git
2.55.0.windows.5: `git ls-remote file:///C:/...` resolves an invalid `/C:/...`
path and exits 128, while the ordinary Windows local path exits zero. Both
escaped and unescaped file URIs fail. These are existing portability defects
outside the native/identity changes; they were not patched speculatively.

The full run exposed one additional credential POSIX permission assertion.
Tracing save_credential -> secure_write_text proved the actual private DACL is
already applied. That assertion now uses the same independent Windows security
descriptor reader, retaining exact POSIX modes on Unix.

Clock inspection on Python 3.11 measured `time` = GetSystemTimeAsFileTime and
`monotonic` = GetTickCount64, both 0.015625-second resolution; `perf_counter` =
QueryPerformanceCounter, 0.0000001-second resolution. Instrumented generate,
stream, rich stream, throughput benchmark and batch accounting now use the
high-resolution monotonic clock for durations; telemetry timestamps remain
wall-clock times. Deterministic frozen-clock tests verify elapsed/TTFT/ITL and
throughput. The focused repaired timing/credential lane passed **134 / 0 / 0 /
0 warnings** in 4.26 seconds. Other pre-existing full-suite failures remain
visible. No full-suite pass or production readiness is claimed.

The subsequent frozen observation implementation full run (`25d4a906`) completed
with **8937 passed / 80 failed / 139 skipped / 291 warnings**, zero errors,
825.56 seconds. It removed all seven timing failures and the credential ACL
assertion. Its remaining failures and one transient RSS fixture DNS dependency
are independently classified in `astra-phase13-full-audit.json`. The DNS fixture
was then repaired without changing production, and an explicit outage refusal
case added; RSS/router/SSRF focused regression: **79 / 0 / 0 / 1 warning**,
4.29 seconds. Full counts remain the observed full-run counts, not an adjusted
sum of later focused results.
