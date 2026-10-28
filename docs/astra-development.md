# JARVIS Astra engineering record

## Baseline — 2026-10-03 (Asia/Tokyo)

- Workspace: `C:\Users\yingz\.codex\worktrees\d76f\JARVIS-Sol`.
- Foundation: actual OpenJarvis source, commit
  `1a9c8cf70fbc24872ba2327115040d4c7a99a11a` (also tagged
  `openjarvis-baseline`). This run's recovery tag is
  `astra-run-baseline-20261003`; branch is `codex/astra-reliability`.
- Initial Git state: clean, detached HEAD. No Mark1 source was inspected.
- Host: native Windows, Python 3.11.9, uv 0.12.10, Node 24.21.0.
- Packaging: hatch/hatch-vcs, `uv.lock`; supported Python 3.10–3.13.
  The original interpreter had no pytest. An isolated `.venv` is being
  populated using the locked dev/server/browser/memory-bm25 extras.
- Rust extension: NOT EXECUTED. Rust/cargo were absent from PATH and the
  conventional user toolchain location. Several components require this
  extension; absent native dependencies must not be counted as passes.
- Real inference, cloud accounts, voice devices and desktop UI: NOT EXECUTED.
  No user credentials or personal runtime databases were read.

## Architecture traced

`jarvis` (Click) and `Jarvis` (SDK) resolve configuration, engines, model
routing and agents. Agent registries supply simple chat, ReAct, orchestrator,
CodeAct, operative/monitor and research agents. `ToolUsingAgent` constructs
`ToolExecutor`; shared dispatch parses JSON, enforces rate, boundary,
capability, taint and confirmation gates, then submits to a bounded daemon
worker pool. The agent consumes `ToolResult` and continues within a turn
budget. EventBus feeds trace, audit and UI consumers.

Tools include filesystem I/O, shell/code execution, search, browser and
external adapters. Local engines include Ollama and OpenAI-compatible local
servers; cloud and optional SDK engines register conditionally. MultiEngine
and learning/routing policies are existing composition points.

`AgentManager` persists agents/tasks/checkpoints in SQLite. AgentScheduler
runs ticks; operative agents recall memory and save conversations. Sessions,
trace stores and scheduler run logs exist. Conversation checkpoints do not
constitute a durable ledger of physical tool mutations.

FastAPI supplies chat, agents, approvals, channels, HTTP/WebSocket auth and
static serving. The frontend is React/Vite with a Tauri desktop shell.
Windows deployment uses PowerShell and a limited-user scheduled task.
Speech has Whisper/STT and several TTS backends. These are implemented but
not live-verified in this run.

## Capability classification and reuse decisions

| Subsystem | Baseline classification | Decision |
| --- | --- | --- |
| Registries, CLI, configuration | IMPLEMENTED BUT UNVERIFIED | KEEP |
| Local/cloud engine boundaries, routing | IMPLEMENTED BUT UNVERIFIED | KEEP |
| Bounded agent loops and loop guard | PARTIAL (no durable action outcome contract) | EXTEND |
| Tool dispatch, timeouts, events | PARTIAL (running timeout loses outcome uncertainty) | EXTEND |
| Capability, taint, SSRF, confirmation | PARTIAL (native backend availability matters) | KEEP / EXTEND |
| Filesystem and shell | PARTIAL (tool return is not independent verification) | KEEP / EXTEND |
| Browser automation | PARTIAL (first-match fallback and retry after click exception) | REFACTOR |
| Browser session | PARTIAL (shared synchronous Playwright objects cross worker threads) | REFACTOR |
| Windows UI Automation / target identity | NOT IMPLEMENTED in the inspected source | EXTEND later |
| Persistent agents, tasks, scheduler, sessions | PARTIAL (conversation persistence differs from action recovery) | KEEP / EXTEND |
| Memory / retrieval / fact store | IMPLEMENTED BUT UNVERIFIED | KEEP |
| External integrations / MCP | IMPLEMENTED BUT UNVERIFIED | KEEP |
| Voice / desktop / vision | IMPLEMENTED BUT UNVERIFIED | KEEP |
| Research learning and benchmarks | NOT EXECUTED | KEEP |

No major component replacement or removal is justified by the audit.

## Security and reliability findings

1. A timed-out Python worker can continue mutating after `execute` reports
   failure. A new model call can repeat it with a new call ID. Ordinary
   failure is insufficient: uncertain actions require reconciliation.
2. Browser click resolves across CSS/text/fuzzy/role strategies and frames,
   then attempts successive matches after exceptions. Multiple actionable
   controls and post-click timeouts can operate unintended targets twice.
3. Lazy global synchronous Playwright state is accessed from the tool pool;
   Playwright objects belong to their creating thread. Sequential calls on
   different workers need one browser owner thread.
4. Capability policy defaults open when not configured; configured security
   and confirmation gates are valuable and should be retained. No claim of
   complete prompt-injection or credential protection is warranted.
5. Browser AX extraction uses the removed `page.accessibility.snapshot`
   surface. Runtime compatibility must be checked with the installed SDK.
6. `file_write` writes directly and reports success without comparing the
   resulting bytes; atomic overwrite and observation are future hardening.

## Minimum target architecture and phases

Keep OpenJarvis's engine → agent → executor → tool pipeline. Add explicit
effect/outcome/failure metadata to the executor, a conservative mutation
quarantine with a durable SQLite option, and browser identity/verification
contracts on the existing Playwright implementation. Reuse existing buses,
agent manager and security gates instead of adding an orchestration stack.

1. Establish reproducible baseline and recovery checkpoint. Run safe focused
   tests and collect wider-suite limitations before source implementation.
2. Executor contracts: distinguish not-started, executed, verified and
   unknown; block uncertain repeats, retain security gates, test concurrency,
   queue cancellation and failures. Rollback: phase Git checkpoint.
3. Persist mutation quarantine across process restart; provide explicit
   trusted reconciliation and prove no automatic replay after crashes.
4. Browser correctness: one owner thread, unique target resolution, pinned
   DOM handles, no fallback after dispatch, document identity and observable
   form verification. Test duplicates, frames, replacement and late failures.
5. Continue with the next evidenced dependency; native Windows control needs
   process/window lifetime and UIA identity before real mutation is exposed.

Exactly-once external effects cannot be guaranteed by a generic thread
executor. The achievable contract is conservative at-most-once dispatch
while an outcome is uncertain, plus explicit observation/reconciliation.
Never describe that as a universal exactly-once guarantee.

## Verification log

Initial safe baseline (before source changes): browser, tool timeout,
file-write and core-type tests: **111 passed, 1 failed, 8 skipped** (7.10s).
The failure expects a mocked navigation error for `nonexistent.example`,
but the live SSRF guard correctly fails closed at DNS resolution first.
The eight skips are symlink cases: this Windows filesystem does not permit
creating symlinks without additional privileges. Baseline core/config
imports succeeded; defaults are Ollama, simple agent, no selected model.

Locked dependency setup completed: 88 packages; editable OpenJarvis version
`1.0.5.dev62+g1a9c8cf7`. uv's generated pytest launcher was blocked by host
application control (`os error 4551`). The installed Python works when
invoked with `PYTHONPATH=src;.venv/Lib/site-packages` and `python -m pytest`;
no operating-system security settings were modified.

Phase 1 adds conservative tool effects and structured execution outcomes,
unknown-outcome quarantine across new call IDs/conversations, concurrent
mutation exclusion and duplicate-name rejection. Existing security gates
are retained. Fault-injection tests cover late success, exceptions after
mutation, queued cancellation and concurrent calls. The first regression
found Windows's low-resolution `monotonic()` could measure zero latency;
measurement now uses the high-resolution monotonic `perf_counter()`.

Phase 1 focused + dispatch regression: **108 passed** (4.90s). Ruff check
passed; formatting applied. Full-suite collection: **8984 selected of 9021,
37 deselected, 1 collection error** (`openjarvis_rust` missing in BM25).
Full-suite execution is therefore NOT EXECUTED at this checkpoint.

Phase 2 persists reservations before dispatch in the existing managed-agent
SQLite database. New ticks share the agent UUID scope; a crash or unknown
outcome leaves a blocking reservation, with no expiry-based replay. The
journal stores IDs/state/time, not arguments or tool content. Reconciliation
is a trusted Python control-plane API requiring observation evidence and an
explicit stopped-worker assertion; it is not exposed as a model tool.
Ad hoc executors can opt in with `execution_journal` and `execution_scope`.
Agents that bypass ToolExecutor are outside this guarantee.

The first phase 2 regression found **161 passed, 2 failed**. Both failures
were existing checkpoint-order ambiguity when Windows timestamps tie.
Checkpoint selection/retention now breaks timestamp ties by SQLite insertion
rowid. A frozen-clock test proves the latest five checkpoints survive.

Phase 2 dispatch/journal/managed-agent regression: **180 passed** (6.15s).
Additional managed runtime integration: **13 passed** (1.65s), including a
real executor loop with a scripted engine proving a new tick/new call ID
cannot repeat a mutation whose response was lost. Ruff check passed.
Git has no configured author identity; checkpoints use command-local
`Codex <codex@localhost>` identity without changing global Git configuration.

Phase 3 refactors the existing Playwright browser tools around one owning
thread (separate from the bounded tool pool). Mutation schemas require the
latest `document_id`; observations retain actual DOM handles and actions
must match an observed node. Same selectors, same text and replacement DOM
nodes cannot establish identity. Resolution aggregates matches across frames,
refuses ambiguity, and never falls back after a dispatched click throws.
Click/type retain confirmation gates. Field typing independently reads the
resulting input value; dispatch success alone stays EXECUTED, not VERIFIED.
SSRF checks run on every intercepted browser request, including redirects
and subresources; service workers are blocked. DNS resolution and browser
connections remain separate, so this is not a DNS-rebinding guarantee.

Modern Playwright AX extraction now uses `Locator.aria_snapshot`; the legacy
adapter remains for older installations. Real Chromium smoke succeeded.
The first real browser lane: **11 passed, 1 failed**. It exposed that typing
with clear=false inserts at the current caret; append now focuses the pinned
field and sets selection to its end before typing. The combined browser,
executor, journal and core regression is **228 passed** (7.85s), including
**12 real Chromium E2E tests**. Ruff check passed.

Limits: browser tools own one headless session, not a user's authenticated
desktop browser. Observations retain at most 100 actionable controls. Selector
resolution supports explicit ordinals, which describe order within the
observed candidates. Arbitrary workflow completion after a click still needs
application-specific result verification. Direct driver calls that bypass
ToolExecutor do not acquire its mutation quarantine. No Windows application
mutation or external account workflow has been executed.

Phase 4 refactors Python `file_write` to stage beside the resolved target,
flush/fsync, atomically replace, and reread exact bytes before VERIFIED.
The inspected Rust implementation uses `std::fs::write`; its low-level
write is not atomic and its return was discarded by the Python wrapper.
The canonical Python tool now uses standard-library atomic I/O; standalone
native tools were not changed or executed. Atomic append is bounded to 10 MB.
Target identity is rechecked before commit; observed concurrent changes fail
closed. Existing sensitivity/allowed-directory checks remain in place.

Fault injection covers disk/replace errors, response loss after append,
verification mismatch, target replacement and concurrent appends. The first
run had **144 passed, 1 failed, 10 skipped**: Windows path resolution from a
second caller transiently opened the target and blocked replacement. Moving
validation into the same process lock fixed that race. The final file,
executor and journal regression: **145 passed, 10 skipped** (1.22s).
Skips are eight unprivileged symlink cases and two native-read cases.
Ruff check passed. This is not a cross-process compare-and-swap or a guarantee
against malicious directory replacement between validation and commit.

Phase 5 replaces only the unsafe REPL execution transport. Persistent Python
namespaces, imports, functions, classes and the registered tool interface are
retained in one spawned worker process per session. The inspected thread
implementation left an infinite loop running after timeout and redirected
the entire host's stdout/stderr into its private buffer indefinitely. The
first broad regression was interrupted at this hang; it has no complete
pass/fail count and is not a completed regression result.

Workers now exchange bounded JSON bytes, never deserialize user Python objects
into the host, capture output within the worker with a retention limit, and
are terminated and joined on timeout. Such sessions require an explicit
reset. Reset, LRU eviction, explicit close and finalization stop owned workers.
ToolExecutor still quarantines uncertain external effects; resetting Python
state does not reconcile those effects. The old import restrictions remain
defense in depth, **not an OS security sandbox**. Process spawning adds startup
latency; one tool instance serializes its sessions to prevent eviction races.
The original REPL suite: **38 passed** (23.84s). REPL fault/cleanup tests plus
server/dispatch/journal/timeout regression: **114 passed, 1 warning** (45.33s).
The warning is FastAPI's upstream TestClient/httpx deprecation. A concurrent
server test now releases its engine in finally even if its first assertion
fails; assertions were retained. Ruff check passed.

Native integration attempt: official SHA256-verified rustup installed the
minimal Rust MSVC toolchain without changing persistent PATH; cargo/rustc
1.99.0 and installed Visual Studio Build Tools were verified. Maturin/cargo
compiled dependencies, then Windows application control refused the generated
libsqlite3-sys build-script executable (`os error 4551`). The native extension
build **FAILED**. Native Rust tests and Rust-dependent integration remain
**NOT EXECUTED**. No operating-system security policy was changed. This is an
environment boundary requiring an approved way to execute native build output.

Phase 6 extends the same stable agent UUID journal to managed SSE streaming,
Deep Research streams and the existing iMessage/SendBlue research-agent wiring.
Generic SSE end events and persisted tool records now include execution state,
failure, retryability and call ID. This preserves UNKNOWN_OUTCOME in the user
interface's event stream rather than reducing every result to a success flag.
The React presentation of these fields is not yet updated.

All four unconditional confirmation callbacks in this managed-server module
were removed. Confirmation-gated tools fail closed unless a trusted host
`app.state.confirm_callback` is explicitly supplied. A remote chat message,
model call or agent configuration does not set this callback. An approvals
UI is not yet connected to this host callback; autonomous authorized read
operations continue, while sensitive tools refuse without confirmation.

Tests use real SQLite journals instead of fabricated MagicMock reservations.
The first streaming regression had **62 passed, 4 failed, 1 warning**: two
mock-journal tokens were not JSON-serializable, one fake research executor
omitted the new binding method, and one Rust-backed policy could not import.
The next run had **67 passed, 2 failed, 1 warning**: the restart test expected
NOT_STARTED but the established contract reports the prior UNKNOWN_OUTCOME;
the counter and persisted reservation proved the new action never dispatched.
That assertion was corrected to require UNKNOWN_OUTCOME, retryable=false and
the explicit no-replay explanation. The native policy failure remains.

Final managed streaming/route/research regression: **68 passed, 1 deselected,
1 warning** (7.38s). The deselected `policy-denied` case requires the unavailable
Rust extension; it is not a pass. New real-database tests prove response loss
cannot replay after server restart/new call ID, confirmation defaults to
refusal, and an explicit trusted approval allows exactly one dispatch. Real
external messaging/accounts are NOT EXECUTED. CLI entry-point `--help` smoke
succeeded; this does not verify model inference or full assistant startup.

The first completed broad regression (agents, tools, server, security;
live/cloud/hub/modal/external/channel markers excluded) was **2437 passed,
181 failed, 71 skipped, 265 warnings** (151.98s). Most failures require the
missing Rust module. Additional failures exposed POSIX-only subprocess calls,
portable-fixture errors, POSIX permission assertions on Windows, native/Python
loop-guard behavior drift, and the parallel read-only fixture's missing effect.
Full-suite collection at that point: **9025 selected of 9062, 37 deselected,
1 collection error** (missing Rust in BM25). Full-suite execution is NOT EXECUTED.

Phase 7 repairs the existing subprocess helper on Windows: hidden child
processes, kernel job ownership attached to the existing process handle,
timeout tree termination, handle cleanup and refusal of unowned PID kills.
Job setup failure stops the owned parent; no unmanaged fallback is used.
Explicit missing working directories now refuse before launch. POSIX launch
uses start_new_session instead of thread-unsafe preexec_fn. Windows interpreter
discovery prefers the running interpreter after an observed Store alias failure
(exit 9009). No user process was killed; all live process tests launch fixtures.

The first helper/orchestrator regression: **50 passed, 1 failed** (4.42s),
exposing the Store alias. Additional process utility tests: **70 passed,
2 skipped** (12.30s). The final Windows helper, core utilities, orchestrator,
shell and injection-fixture regression: **129 passed, 6 skipped** (12.84s).
Real Windows tests prove descendant termination and refused job setup cleanup.
The six skips are two POSIX-only process cases and four pre-existing shell
backend deficiencies; the next phase addresses those shell deficiencies.
Ruff check passed. Template injection fixtures now execute a portable real
Python echo instead of a POSIX executable absent on Windows; substitution
tests assert successful literal output as well as absence of a marker file.

Limits: this helper filters environment and owns process lifetimes, not OS
access rights. Job assignment follows launch, so it is not an atomic containment
boundary against adversarial early child creation. Output is truncated after
capture, not a host-memory limit. Other subprocess paths do not automatically
gain its job ownership. These are not OS sandbox or universal tree-isolation
guarantees. Standalone native tools remain unchanged and unverified.

Phase 8 connects the registered Python shell tool to this tested process
transport. Inspection of `rust/.../builtin/shell.rs` and its PyO3 wrapper showed
unbounded Command::output(), inherited environment and discarded failure
status. Existing tests explicitly skipped timeout/environment/output checks
and expected exit 42 to be reported as success. Replacing only this unsafe
dispatch path is justified by those concrete failures, as with Python file I/O.
The original registry, schema, confirmation and code:execute gates are retained.
Standalone native shell tools are unchanged and are not claimed safe.

The canonical tool now filters environment, honors timeouts, owns Windows
process cleanup and propagates actual exit codes. Missing command/directory or
undispatched launch failures report NOT_STARTED. A process error after launch
or timeout reports UNKNOWN_OUTCOME; a fresh call cannot replay it through
ToolExecutor. Exit zero stays EXECUTED, not task-level VERIFIED. Output format
is the former Python fallback's STDOUT/STDERR sections; callers relying on the
native format need migration. Output truncation indicators are preserved.

The shell suite now executes real portable processes instead of fabricated
native success strings, and removes the four obsolete skips. It tests timeouts,
filtered/explicitly passed environment, cwd, output/stderr, exit 42, failure
after writing a fixture, refused repeat and confirmation before dispatch.
Focused shell/process/outcome/journal regression: **61 passed** (6.24s).
Ruff check passed. The existing executor's 60s shell deadline can return unknown
while a caller-selected longer subprocess timeout is still running; durable
quarantine prevents replay but this is not general per-call cancellation.

Broad regression after phase 8 (adding core process helpers): **2472 passed,
171 failed, 69 skipped, 265 warnings** (169.86s). The failures include 163 direct
Rust import failures, one wrapped capability initialization failure, five
POSIX permission assertions, one native/Python loop-guard discrepancy, one
UTF-8 source-inspection fixture decoding error, and one zero-duration trace.
The last two are addressed in phase 9; these totals remain the exact observed
result of that run, not a claimed pass after subsequent changes.

Final safety lane after phase 8: **148 passed, 8 skipped** (42.83s), including
12 real Chromium tests, durable SQLite restart/confirmation tests, REPL
termination, real shell/process execution and file-write fault injection.
The eight skips are unprivileged symlink cases; no OS privileges were expanded.

Phase 9 uses perf_counter for agent tick/run elapsed time while preserving
wall-clock timestamps. A frozen-clock real file-write test proves positive
elapsed duration and retention of verified tool metadata. Tool start/end
events now carry call IDs; managed traces match overlapping completions by
identity, use the actual arguments/latency keys and retain execution metadata.
This repairs missing target arguments, lost durations/outcomes and incorrect
pairing of concurrent calls to the same tool in the existing trace path.

The first expanded trace regression was **119 passed, 1 failed, 11 teardown
errors** (4.68s): the POSIX-only HOME fixture and unclosed SQLite fixture were
unsafe on Windows. Fixtures now set Windows USERPROFILE as well as HOME and
close the database before deleting the temporary directory. The capability
inventory source-inspection test now reads repository UTF-8 explicitly instead
of using this host's CP932 default. Test assertions are retained.
Final trace/managed-executor/outcome/journal/dispatch regression: **209 passed**
(4.21s). Ruff check passed. Final full integration remains blocked by native
security dependencies; no claim of production readiness follows from these
focused results.

The explicit capability inventory UTF-8 regression: **1 passed** (0.40s).

Phase 10 repairs the existing Python loop-guard fallback. Inspected native
code uses a seen-hash set and refuses the second identical call irrespective
of its reserved max_identical parameter. The fallback now uses that same
conservative duplicate rule. Previously its reason included a growing count;
warn-before-block used that changing text as a key and could warn forever.
The stable reason now permits one warning and blocks subsequent repeats.
Reset/new observation behavior is preserved and fault-tested without a fake
native verdict. The count option remains reserved/unused by both backends;
native polling-budget semantics still differ and need native parity work.
This is not general replanning or safe replay authorization.

Focused loop/orchestrator/dispatch/outcome/journal regression: **165 passed**
(2.88s). Ruff check passed. A final combined regression also includes the
repaired trace lane; its result is recorded below when complete.

Final combined regression after phase 10, including agents/tools/server/security,
core process utilities and all trace tests: **2540 passed, 168 failed, 69 skipped,
265 warnings** (189.81s). JUnit records 2777 selected tests, zero teardown errors.
Classification from actual JUnit failure bodies: **163 missing-Rust failures**
(including the wrapped policy error) and **5 POSIX mode assertions on Windows**.
The exception-line counts in the prior diagnostic paragraph overlap; they are
not independent failure counts. No remaining failure in this run was attributed
to executor, browser, journal, REPL, file-write, shell or trace changes.
The five permission assertions remain failed: Windows ACL protection has not
been implemented/verified, and POSIX chmod bits do not establish that protection.

Phase 11 repairs an agent integration gap before closing the run: the browser
document ID was present only in ToolResult.metadata, while both orchestrator
and managed SSE feeds give models only ToolResult.content. Navigation, extract
and AX results now prepend a JSON observation-data header containing the actual
document ID and bounded control descriptions/IDs. The page body remains data,
external-source injection handling remains in the executor, and confirmation
and live DOM identity checks still govern mutation. Very long DOM IDs are
omitted rather than truncated into a different selector. Screenshot results
retain their media format; agents obtain action identity from text/AX observation.

A real OrchestratorAgent loop with a scripted engine obtains identity solely
from its tool-message text, selects the observed field, types through the real
executor/Chromium stack and independently checks the field. No real LLM inference
is claimed. Browser/unit/agent/SSE regression: **147 passed** (7.04s), including
**13 real Chromium tests**. Ruff check passed. This is the only functional change
after the final broad run; its related regression was rerun explicitly.

## Stop boundary and continuation

This run stops at the confirmed native integration boundary: Windows
application control refuses the generated native build script (error 4551).
Core security, rate limiting, guardrails and BM25 need the absent extension;
enabling real-user automation without validating those boundaries would create
unacceptable risk. No security policy was weakened, no native pass was inferred,
and no production deployment or external-account mutation was performed.

Next: supply an approved build environment or trusted CPython 3.11 Windows
extension built from this source, then execute native/security/memory/full
regressions. Resolve Windows ACL requirements with real temporary-directory
access tests before user-data workflows. Windows UIA requires process/window
lifetime identity and isolated fixture verification before mutation exposure.
Do not proceed to authenticated accounts, voice/UI polish or autonomous
production use on the strength of the synthetic fixture results alone.

Final repository collection after phase 11: **9036 selected of 9073,
37 deselected, 1 BM25/Rust collection error** (13.49s). Full-suite execution
remains NOT EXECUTED. Ruff check and format check pass for all 40 changed
Python files. Final reporting artifacts are `astra-run-report.md` (all 28
requested report items) and `astra-verification.json` (exact observed counts).
Traces now record action arguments; sensitive-data redaction and Windows ACL
protection for those records are not live-verified and require security work.

## Continuation after checkpoint 11: native/security and Windows observation

The preceding blocked-native/full-suite status is historical. Phase 12 resumed
from `d63643ce`, read the original Cargo failure and Windows event evidence,
isolated the unchanged child executable, and built this source under unchanged
enforced Smart App Control. Exact policy, process paths, error codes, environment,
ACLs, reproduction limits, artifact hashes and supported trust alternatives are
in [astra-phase12-native-diagnosis.md](astra-phase12-native-diagnosis.md).

Windows private-data helpers now create and verify protected owner-only DACLs;
existing object ownership/type/reparse/hardlink checks fail closed. Independent
descriptor tests replace POSIX-bit assumptions on Windows while retaining Unix
mode assertions. The native BM25 binding exports previously missing delete/clear
methods. Native/agent/security/memory/execution/browser/process/trace lanes ran
in the requested sequence. The first unrestricted full run completed, exposing
87 failures, separately classified and audited against baseline source in
[astra-phase12-failure-audit.json](astra-phase12-failure-audit.json). Measured
Windows clock resolution justified the subsequent high-resolution duration
repair; no failed assertions were weakened to obtain green output.

Phase 13 adds a bounded, terminable, observation-only Windows identity library.
Its retained native elements, process lifetimes, HWND/thread/class/generation,
foreground and UIA hierarchy/properties are verified before reporting identity
validity. Synthetic real Windows fixtures caught a provider visibility defect;
native monitor/visibility checks now reject off-desktop controls. All identity
results explicitly deny physical mutation authority. Design, 32 policy cases,
18 Windows cases and remaining atomic-action/provider limitations are described
in [astra-windows-identity.md](astra-windows-identity.md).

Current exact broad/full counts and checkpoint commits are maintained in
[astra-run-report.md](astra-run-report.md) and
[astra-verification.json](astra-verification.json). Prior checkpoints remain
intact; no Mark1 inspection/modification, OS policy relaxation, external account
mutation or production-readiness claim occurred.
