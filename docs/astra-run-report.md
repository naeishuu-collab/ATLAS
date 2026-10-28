# JARVIS Astra — run report, 2026-10-04

**Partial development milestone; not production ready.** Phase 12 built and
verified this source's CPython 3.11 Windows native extension without changing
security policy. Windows private-data DACLs and observation-only process/window/
UIA identity are implemented and tested. The historical eleven-checkpoint report
below remains starting evidence; the continuation section records newer results.
The detailed audit, failures, repairs, commands and limits
are in [astra-development.md](astra-development.md); machine-readable results
are in [astra-verification.json](astra-verification.json). Test lanes overlap;
their pass counts must not be added together.

Phase 12 diagnosis: [astra-phase12-native-diagnosis.md](astra-phase12-native-diagnosis.md).
Full failure audit: [astra-phase12-failure-audit.json](astra-phase12-failure-audit.json).
Windows identity: [astra-windows-identity.md](astra-windows-identity.md).

## Phase 13 safe mutation continuation

The cooperative Win32 fixture mutation gate passed **17 passed, 0 failed,
0 skipped, 0 warnings**. Registered Windows tools default to unbound/fail closed.
Verified click/text replacement uses observation-bound identities, receiver
lifetime cookies, one dispatch and fresh UIA verification. Wrong/stale/ambiguous
identities cause zero action mutations. The full 30-item report and exact
commands are in [astra-phase13-mutation-report.md](astra-phase13-mutation-report.md).

Checkpoint **cec283d8**. **Full suite: EXECUTED** on that checkpoint:
**8970 passed, 90 failed, 139 skipped, 291 warnings**. The [new full audit](astra-phase13-mutation-full-audit.json)
classifies 79 existing failures and 11 fixture foreground-setup failures before
dispatch; the DNS repair passes. This full run's native group is 6 passed/11
failed; the separate 17-test gate remains separate evidence. The harness checked
activation before several minutes of collection; a post-collection check is the
next fixture repair. Older counts below remain historical pre-DNS-repair evidence.
**Real App E2E: NOT EXECUTED.**
No OS security policy changes; prior SAC admission behavior remains unexplained.

## Phase 14 safe recovery and agent trace privacy

Explicit fresh-observation/new-authorization recovery after safe stale rejection
is verified through the scripted native agent path. Fresh ambiguity produces zero
clicks; fresh IDs cannot bypass reopened durable UNKNOWN_OUTCOME quarantine.
Native typing independently verifies one mutation while trace copies omit the
canary. Raw inference events and live messages remain outside that privacy repair.
[Detailed report](astra-phase14-safe-replan.md).

Native agent/recovery lane: **5 passed, 0 failed, 0 skipped, 1 warning**
(15 deselected). Broader focused: **1844/0/23/0**. Final broad:
**2820/0/68/271**, passed/failed/skipped/warnings. Separate unsuccessful native
combined batches and the repaired broad regression remain in the report.
**Full suite: NOT EXECUTED** for Phase 14; `cec283d8` full results above are
separate frozen-source evidence. No real application test or OS policy change.

## Phase 15 quarantine trace completion

Checkpoint `7eb95fea` introduced the Phase 14 continuation. The next audit proved
that post-start quarantine/journal rejection omitted TOOL_CALL_END. The repair
preserves the unresolved outcome and adds the blocked request ID, zero-dispatch
evidence, redacted arguments and latency, with publication outside the mutation
lock. [Detailed report](astra-phase15-quarantine-trace.md).

Focused: **95/0/0/0**. Broad: **2823/0/68/271**,
passed/failed/skipped/warnings. The three new tests failed before the repair.
**Full suite: NOT EXECUTED** for Phase 15. No new physical Windows E2E after this
event-only change; preceding native counts remain separate evidence.

## Phase 16 typing capability

Before `type_into`, the native path now requires a readable bounded ValuePattern
and rejects password controls. The cooperative receiver checks live
`ES_PASSWORD`/`ES_READONLY` style on its owner thread before its one `WM_SETTEXT`.
Fresh independent UIA readback remains required after dispatch. The test-owned
fixture covers normal text, password/readonly rejection, a late readonly change,
focus refusal and the scripted Agent trace path. No user application or OS
security policy was changed. [Detailed report](astra-phase16-typing-capability.md).

Current-worktree revalidation: identity/action contract **49 passed**; selected
typing/negative/Agent fixture lane **8 passed, 15 deselected**; Windows
ACL/identity/observer/mutation/boundary regression **108 passed**. A first
Windows regression had 107 pass and one safe pre-dispatch rejection because
the positive-click fixture changed foreground after observation; the test now
focuses its owned window before fresh observation and resolution.

Unrestricted full repository suite: **EXECUTED**, **8996 passed, 78 failed,
139 skipped, 291 warnings** (790.58s). Compared with the frozen Phase 13 JUnit
audit: 78 failures overlap, 12 old failures are absent, and there are no new
failure node IDs. The full suite remains failing; most remaining cases are
Windows and POSIX portability assumptions or unavailable live dependencies,
credentials, models and catalogs. Real-application E2E: **NOT EXECUTED**.
Production readiness: **NOT READY**.

## Long-horizon recovery substrate audit

`AgentManager` stores managed tasks and tick checkpoints in SQLite. A restart
test now proves task status/progress/findings and checkpoint conversation/tool
state survive reopening the database; server startup resets an interrupted
`running` agent to `idle`, preserves a user-paused agent, and `recover_agent`
returns the latest checkpoint. Command:
`uv run python -m pytest -q tests/agents/test_manager_recover.py tests/agents/test_manager.py tests/integration/test_agent_manager_e2e.py`
completed **47 passed** in 2.25s.

This verifies persistence and the recovery API, not autonomous resume. Source
inspection found `AgentExecutor.execute_tick` does not call
`save_checkpoint` or `get_latest_checkpoint`; managed execution does not yet
write or consume tick checkpoints. Artifact tracking, recovery/replan history,
context compaction and long-running goal resume remain **PARTIAL / NOT
IMPLEMENTED**. The next dependency is to connect structured, provenance-aware
task state to the production tick path while keeping unresolved journal outcomes
blocked across recovery.

## Historical checkpoints 1–11

1. **Original baseline.** Workspace: `C:\Users\yingz\.codex\worktrees\d76f\JARVIS-Sol`.
   Clean detached OpenJarvis `1a9c8cf70fbc24872ba2327115040d4c7a99a11a`, editable
   version `1.0.5.dev62+g1a9c8cf7`; Windows/Python 3.11.9/uv 0.12.10/Node 24.21.0.
   Baseline focused tests: 111 passed, 1 failed, 8 skipped. No Mark1 source was
   inspected, copied or modified. Recovery tag: `astra-run-baseline-20261003`.

2. **Architecture discovered.** Click CLI/SDK/configuration and registries
   compose engines, model routing, bounded agents, ToolExecutor, security gates
   and tools. EventBus feeds traces/UI. AgentManager/scheduler persist SQLite
   tasks and checkpoints. Browser uses synchronous Playwright; frontend is
   React/Vite/Tauri; voice and provider adapters are optional implementations.

3. **Components reused.** Registries, CLI/config, SDK/engine abstraction,
   local/cloud routing, existing agents, event bus, SQLite managers/trace stores,
   capability/taint/SSRF/confirmation boundaries, browser driver and schemas.

4. **Components extended.** Tool effects and outcomes, concurrent mutation
   exclusion, durable reservations/reconciliation, cross-tick/stream bindings,
   browser observations, verification evidence and trace event identity.

5. **Components refactored.** Browser owner-thread dispatch and target
   resolution; file commit/verification; Windows process lifecycle handling;
   shell dispatch; persistent REPL transport; timing and trace matching.

6. **Components replaced/removed.** Unsafe low-level Python file-write/shell
   native dispatch and in-process REPL threads were replaced with tested
   standard-library transports. Unconditional managed-server confirmation
   callbacks were removed. No major subsystem was deleted or replaced.

7. **Current architecture.** OpenJarvis engine → bounded agent → gated
   executor → tool remains. Mutations reserve durable per-agent/per-tool state
   before dispatch. Unknown results stay blocked across new call IDs/restarts.
   Browser mutation requires document and observed DOM identity; supported
   verification reads resulting state. Existing traces record action identity
   and structured outcomes. Trusted reconciliation is a Python control API.

8. **Features implemented.** Eleven checkpoints: outcome taxonomy, restart
   quarantine, browser identity/thread ownership, verified atomic file writes,
   terminable REPL workers, safe managed streams, Windows job cleanup, truthful
   bounded shell execution, outcome-aware traces, bounded loop warnings and
   browser identity visible to agents.

9. **Features verified.** Fault-injected no-replay behavior, real SQLite
   restart persistence, ambiguous/stale/replaced DOM refusal, one dispatched
   click after response loss, resulting field/file reads, concurrent append,
   REPL worker termination, real Windows descendant cleanup, confirmation
   refusal, actual shell exit/environment/timeout behavior and trace identity.

10. **Partial/unverified features.** Real-model goal execution, Windows UIA,
    complete workflow verification/replanning, authenticated browser sessions,
    robust OS sandboxing and full Windows ACL protection remain incomplete.

11. **Exact test results.** Final broad lane before the browser-message repair:
    **2540 passed, 168 failed, 69 skipped, 265 warnings**, 2777 selected tests,
    zero teardown errors, 189.81s. Actual JUnit failure bodies classify 163
    missing-Rust failures and five POSIX permission assertions on Windows.
    The subsequent browser/agent/SSE lane: **147 passed**, 7.04s. Trace lane:
    **209 passed**, 4.21s. Loop lane: **165 passed**, 2.88s. Safety lane:
    **148 passed, 8 skipped**, 42.83s. Final repository collection: 9036 of 9073
    selected, 37 deselected, one BM25/Rust collection error, 13.49s.
    Full-suite execution: **NOT EXECUTED**. Ruff check and format check passed
    for all 40 changed Python files. The browser-message repair was tested
    in its related lane; the entire broad lane was not rerun afterward.

12. **Negative safety tests.** Tests refuse duplicate tool registrations,
    unresolved/concurrent mutations, expired document identities, ambiguous
    controls across frames, replaced nodes, unavailable confirmations,
    failed/uncertain file commits, wrong resulting field values, queued
    capacity/timeout dispatch, dead REPL workers and unmanaged Windows jobs.
    Native capability/guardrail tests remain failed/unavailable, not passes.

13. **Agent status.** Existing agents retained. Scripted engines exercise
    real managed ticks, streams and orchestrator loops. Browser identity reaches
    actual tool messages. Real local/cloud LLM inference is **NOT EXECUTED**.

14. **Windows control status.** Real process utilities/job cleanup verified.
    Native application/window/control UIA targeting is **NOT IMPLEMENTED**.
    No user's application was clicked or typed into; fixtures alone were used.

15. **Browser status.** **13 real Chromium tests** on synthetic documents,
    including an actual agent loop with a scripted engine. Tools use one owning
    thread, pinned observed elements and document IDs. Input values are verified;
    click return alone means dispatch. Authenticated/multi-account workflows
    and real-user desktop browser control are **NOT EXECUTED**.

16. **Recovery/replan status.** Unknown mutations fail closed; no expiry-based
    replay. Trusted reconciliation requires external evidence and a stopped
    worker assertion. General automatic recovery/replanning is partial;
    generic exactly-once external effects are not guaranteed.

17. **Long-horizon status.** Existing tasks/checkpoints/scheduler retained.
    Durable reservations survive manager restart; checkpoint ties use insertion
    order. Hours-long autonomous runs and cancellation across every agent/tool
    path are **NOT EXECUTED**.

18. **Memory status.** Existing memory/fact/retrieval interfaces retained.
    SQLite knowledge fixtures run; Rust-dependent memory/BM25 integration cannot
    validate. Real-user memory provenance/privacy workflows are unverified.

19. **Model routing status.** Existing local-first/multi-engine composition
    retained. Default configuration is Ollama with no selected model. Routing
    quality, live provider fallback, cost and latency benchmarking are unverified.

20. **External integration status.** MCP and channel adapters retained and
    managed research wiring journal-bound. External accounts/messages/payments/
    publishing are **NOT EXECUTED**. No external communication was sent.

21. **Voice status.** Existing speech implementations retained; microphone,
    speaker, latency and voice E2E are **NOT EXECUTED**.

22. **UI status.** Existing frontend/desktop shell retained. SSE now exposes
    execution metadata; React presentation and live desktop startup/build remain
    unverified. No interface polish or deployment was undertaken.

23. **Performance status.** Bounded worker/queue behavior, REPL retention and
    high-resolution monotonic timings were tested. REPL subprocess startup adds
    latency. Production throughput, energy, model cost and endurance benchmarks
    are **NOT EXECUTED**.

24. **Security findings.** Five permission tests remain failed because POSIX
    bits do not prove Windows ACL protection. Traces record arguments; their
    sensitive-data redaction/privacy is not live-verified. Missing native security prevents
    full gate validation. The REPL/process helper is not an OS security sandbox;
    browser request checks are not a DNS-rebinding guarantee. Configuration with
    capability gating disabled remains outside a production security claim.

25. **Known limitations.** Guarantees apply to calls using the wired executor;
    direct/native/bypassing agents need separate review. Journal quarantine is
    per tool and agent scope. Atomic file writes are not cross-process CAS.
    Browser uses one headless session and bounded observations. Windows job
    assignment follows launch; output is truncated after capture. A longer
    shell timeout can outlive the outer executor deadline, with replay blocked.
    Native loop-guard count options are reserved and polling semantics need
    native parity tests. Application-specific completion still needs verifiers.

26. **Production readiness.** **NOT READY.** This is verified foundational
    progress, not a complete autonomous Windows assistant or an assurance of
    universal exactly-once behavior. Security/native/full-suite failures remain.

27. **Exact reason stopped.** Rust/cargo 1.99.0 and Visual Studio Build Tools
    were installed/verified, but Windows application control refused Cargo's
    generated `libsqlite3-sys` build script (`os error 4551`). The native build
    **FAILED**; native Rust tests are **NOT EXECUTED**. No OS security policy
    was changed. The next foundational integration requires an approved build
    environment or a trusted Windows extension; real-user autonomy without
    those security checks would create unacceptable risk.

28. **Next highest-value phase.** Build this source's trusted CPython 3.11
    Windows Rust extension in an approved environment; run native/security/
    memory/full regressions. Implement and verify Windows ACL requirements in
    temporary fixtures. Then add UIA process/window lifetime and control
    identity with independent result verification before exposing mutation.

| Phase | Implementation checkpoint |
| --- | --- |
| 1: execution outcomes | `ba9a6e03` |
| 2: durable quarantine | `a1e211ed` |
| 3: browser identity/owner | `09ac403d` |
| 4: atomic verified writes | `d3cd1bf2` |
| 5: isolated REPL | `d1cf1fed` |
| 6: managed stream safety | `72b99e85` |
| 7: Windows process ownership | `c75ee024` |
| 8: truthful shell dispatch | `cf42abfb` |
| 9: trace identity/timing | `3c7020af` |
| 10: bounded loop warnings | `22cbd129` |
| 11: agent-visible browser identity | `f0af3e99` |

Branch: `codex/astra-reliability`. Checkpoints use command-local
`Codex <codex@localhost>` identity, with no global Git identity changes.
Rollback: inspect/revert individual checkpoints, or compare against the recovery
tag. Dependency installations are local development setup and not Git artifacts.

## Continuation: phases 12–13

Starting evidence was clean `d63643ce` on `codex/astra-reliability`. No project
restart, Mark1 access, model escalation or OS security-policy change occurred.

**Native build diagnosis.** Code Integrity event 3077 ties error 4551 to the
unsigned libsqlite3-sys build-script executable and enforced
VerifiedAndReputableDesktop/Smart App Control policy. ACLs, TEMP, Cargo target
configuration and available AppLocker evidence were examined. The same unchanged
executable subsequently ran in a minimal pre-build reproduction. Policy state
and hash remained unchanged; available evidence does not explain its later
admission. This justified one build using the original configuration, which
succeeded. No persistent machine compatibility fix or universal trust guarantee
is claimed. The loaded CPython 3.11 Windows AMD64 artifact exactly matches this
source build's DLL SHA-256:
`8fb8e5421e8a33a282ae14550fb48b520aa75840bbe4c0d20df8bb6b46abb824`.

**Repairs backed by execution evidence.** Windows private files/directories now
use verified protected owner-only DACLs, applied before writing secret bytes.
POSIX permission behavior remains intact. Five original assertions and one
additional credential assertion now inspect actual Windows descriptors. Native
BM25 delete/clear exports now forward already implemented Rust methods; UUID
tests validate real UUID-v4 semantics. The REPL timeout fixture proves worker
readiness before testing a one-second infinite-loop termination. High-resolution
monotonic timing fixes zero-duration Windows inference/batch/benchmark readings;
wall-clock telemetry timestamps remain unchanged.

**Windows application identity.** A terminable process owns UIA reads on a
windowless MTA thread, retaining process creation/executable, HWND/thread/class/
generation, foreground, RuntimeId, AutomationId, type, framework and hierarchy.
Complete enumeration and retained-element validation fail closed on ambiguity,
replacement, stale identity and mismatches. Actual Win32/UIA tests exposed and
fixed an off-desktop provider visibility inconsistency. Successful validation
always returns `mutation_allowed=false`; this observation library is not a
physical input/invoke tool.

| Checkpoint | Commit |
| --- | --- |
| Windows owner-only DACL creation/readback and permission tests | `138bfbe7` |
| Native BM25 bindings and verified native/REPL test fixtures | `39e2407d` |
| High-resolution monotonic telemetry and credential ACL assertion | `8b3a25a3` |
| Windows process/window/UIA observation identity | `25d4a906` |
| RSS configuration DNS fixture and explicit failure refusal | `3eb4ad9f` |

**Exact regression evidence; overlapping counts must not be added.**

| Lane | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| Native bridge + BM25 after binding rebuild | 35 | 0 | 0 | 0 |
| Native ReAct/OpenHands | 112 | 0 | 0 | 0 |
| Complete Rust workspace except PyO3, `--no-fail-fast` | 421 | 5 | 0 | 1 |
| Final combined Windows ACL/file-permission/file-utils | 18 | 0 | 0 | 0 |
| Memory | 238 | 0 | 13 | 1 |
| Execution outcomes | 10 | 0 | 0 | 0 |
| Durable journal/quarantine | 10 | 0 | 0 | 1 |
| Browser identity (13 real Chromium tests) | 100 | 0 | 0 | 1 |
| Shell/REPL/timeout/subprocess/core-utils | 110 | 0 | 2 | 1 |
| Agents with existing offline marker exclusions | 675 | 0 | 0 | 1 |
| Traces and agent trace recording | 66 | 0 | 0 | 1 |
| Repaired timing/credential lane | 134 | 0 | 0 | 0 |
| Windows identity: 32 policy + 18 real Windows cases | 50 | 0 | 0 | 0 |
| Phase 12 broad regression | 2718 | 0 | 68 | 272 |
| Phase 12 unrestricted full repository | 8875 | 87 | 139 | 297 |
| Audit of those 87 nodes against baseline source | 2 | 85 | 0 | 0 |
| Phase 13 broad regression | 2791 | 0 | 68 | 271 |
| Phase 13 unrestricted full repository, frozen implementation | 8937 | 80 | 139 | 291 |
| Post-full RSS router/connector/SSRF regression | 79 | 0 | 0 | 1 |

Full suite: **EXECUTED**, frozen Phase 13 implementation `25d4a906`, **8937
passed / 80 failed / 139 skipped / 291 warnings**, zero collection/teardown
errors, 825.56 seconds. Exact command: `python -m pytest -q
--junitxml=.astra-tools/phase13-full.xml`, with
`PYTHONPATH=src;.venv/Lib/site-packages`. Results are not adjusted for subsequent
focused test repairs. Full-suite success is not claimed.

The five Rust failures occur before policy assertions because this token cannot
create symlinks (Windows 1314). No privileges were changed and no native tests
were newly skipped. All 87 full-suite failures were classified, with 85
reproduced against baseline source and two intermittent unchanged coarse-clock
paths. Classification distinguishes production portability/timing defects from
incorrect test assumptions and absent live credentials/models/catalogs; details
are in the linked failure audit. Timing and the extra ACL assertion are repaired;
other failures remain visible, not silently waived.

The second full run removed all seven measured-clock failures and the extra
credential ACL assertion. Its 80 failures comprise 79 of the previously audited
baseline failures and one transient DNS failure in an RSS configuration test.
That existing test mocks synchronization but requires live example.com DNS.
It passes in isolation when DNS resolves; baseline source fails with the same
HTTP 400 under a controlled DNS outage. The test now supplies controlled public
DNS answers while retaining production SSRF/public-IP validation, and adds an
explicit outage test proving no persistence/sync/success claim. Production code
was not changed after the full run. The focused 79-test RSS/router/SSRF regression
passes, with one existing deprecation warning. No third unrestricted full run
was performed after this test-only fixture repair. The frozen implementation's
full failure classification is in
[astra-phase13-full-audit.json](astra-phase13-full-audit.json).

**Remaining gate.** Physical Windows mutation is not implemented or authorized
by the observation result. Asynchronous UIA/WinEvent generation invalidation is
not an atomic guarantee across future actions; RuntimeId/HWND reuse cannot be
solved by semantic text. Actual same-number PID/HWND reuse is covered by policy
fixtures, not claimed as a forced live demonstration. Arbitrary providers,
occlusion/hit-testing, app-specific state verification, guarded exactly-once
dispatch and recovery still need evidence before introducing real application
mutation. Production readiness remains **NOT READY**.

## Production long-horizon checkpoint and restart recovery — 2026-10-04

Implementation checkpoint commit: `ee9e66b1`.

**Status: VERIFIED for the managed AgentExecutor/Orchestrator fixture path.**
`AgentExecutor.execute_tick` now initializes, updates, restores, and terminalizes
structured checkpoints. The production Orchestrator calls the checkpoint
boundary around prepared, executing, and completed tool steps. `ToolExecutor`
commits the journal reservation before the executing checkpoint and worker
dispatch, then commits the result checkpoint before releasing a known-complete
reservation. Restart recovery requires a confirmed stopped worker, validates
checkpoint shape and identity, matches pending journal entries to the exact
tool/call ID, and records reconciliation/resume events. Persisted Windows
observation and target IDs are removed from restart conversation state.

PREPARED reservations can be reconciled as NOT_EXECUTED because dispatch has
not begun. EXECUTING, UNKNOWN_OUTCOME, mismatched, corrupt, or unverified
mutating outcomes fail closed and require reconciliation; no automatic replay
is authorized. Explicit recovery requires an exact journal reconciliation
record. A checkpoint persistence failure before dispatch now remains
NOT_STARTED rather than being mislabeled UNKNOWN_OUTCOME.

| Check | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| Focused persistence/journal/manager | 55 | 0 | 0 | 0 |
| Restart/recovery negatives A–G | 9 | 0 | 0 | 0 |
| Agent integration | 77 | 0 | 0 | 0 |
| Windows mutation/identity/observer/boundary regression | 98 | 0 | 0 | 0 |
| Broader agents/integration/journal/server regression | 747 | 0 | 0 | 1 |

The broader warning is the existing Starlette `httpx` deprecation from the
installed FastAPI test client. An earlier Windows regression attempt in this
work period had 81 passed and 17 failures during foreground-activation fixture
setup, before action dispatch; the final rerun passed all 98. The fixture
failure was not reproduced on the final run.

The restart tests use the production SQLite manager, execution journal,
AgentExecutor, Orchestrator, and ToolExecutor with fake model/tool endpoints;
they close and reopen managers over the same database and inject crash states.
Forced OS process-kill recovery, a live model, real Windows application E2E,
and the unrestricted full repository suite were **NOT EXECUTED**. Phase 13/14
status is unchanged; Real App E2E remains **NOT EXECUTED**. Historical full-suite
counts, including 8996/78, are not results of this checkpoint.

## Bounded retry continuity — 2026-10-04

Implementation checkpoint commit: `b0ef0735`.

**Status: VERIFIED for managed AgentExecutor retries across checkpoint restore.**
The three-attempt per-tick budget is committed before each agent invocation.
Structured retry history records RUNNING, FAILED, SUCCEEDED, or
RECOVERY_REQUIRED; restart restores the count and terminalizes when no attempts
remain. Checkpoint validation fails closed when retry count and history disagree.
Retry metadata is preserved as Orchestrator tool checkpoints replace the active
step state. A verified mutation followed by a transient model failure resumes
from its stored tool result and dispatches that mutation once.

| Check | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| Retry/resume and AgentExecutor focused regression | 28 | 0 | 0 | 0 |
| Broader agents/integration/journal/server regression | 752 | 0 | 0 | 1 |

The one broader warning is the existing Starlette `httpx` deprecation. Full
repository tests, live model calls, and Real App E2E remain **NOT EXECUTED**.
Cancellation/timeout requests do not yet have a per-agent durable control path;
they remain a later dependency.

## Per-agent safe cancellation and timeout — 2026-10-05

Implementation checkpoint commits: `2a65e952`, `376b43c4`.

**Status: VERIFIED for the managed AgentExecutor/Orchestrator/ToolExecutor
fixture production path.** Cancellation intent is stored per agent in the
execution journal as REQUESTED, ACKNOWLEDGED, SAFE_BOUNDARY_REACHED, or
TERMINALIZED. The journal serializes PREPARED-to-EXECUTING dispatch
authorization against cancellation, so a request that wins the transaction
prevents dispatch. Once dispatch is authorized, cancellation does not kill the
worker: it waits for the operation/result boundary and preserves uncertain or
unverified mutation state for recovery. VERIFIED mutations remain completed and
are not replayed. Running `/pause` now requests safe cancellation without
releasing the per-agent running lock; server shutdown requests cancellation
before draining workers.

Overall deadlines are persisted as absolute deadlines and restored after
restart. Model, tool, observation, verification, and possible physical
mutation timeouts retain their phase/kind; post-dispatch timeout remains
uncertain and enters journal reconciliation. Cancellation checkpoints prevent
automatic restart, and explicit resume requires cancellation/recovery checks.
Retry counters/history are preserved. Real application calls, including model
calls, are not force-killed to meet a deadline.

| Check | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| Focused persistence/cancellation/retry regression | 113 | 0 | 0 | 0 |
| Agent suite | 702 | 0 | 0 | 0 |
| Server suite | 459 | 0 | 0 | 263 |
| Changed-area agent/server regression | 136 | 0 | 0 | 11 |
| Windows identity/action/observer/boundary regression | 75 | 0 | 0 | 0 |
| Browser safety regression | 13 | 0 | 0 | 0 |
| Full repository suite | 9028 | 78 | 139 | 291 |

The full run used `pytest -q --tb=short` with server, Windows-observation,
browser, and desktop-native extras and finished in 823.22 seconds. None of its
78 failures are in the changed AgentExecutor, manager, orchestrator, journal,
tool executor, server agent-route, or Windows identity/action test paths.
Failures remain in unrelated channel/CLI, connector, deployment/packaging,
engine, eval/install, prompt/recipe/skills, and telemetry suites. The run
included Windows privilege/platform mismatches, unavailable live services or
credentials, and host-specific test assumptions. No full-suite run was made at
starting commit `5a5d0d88`, so a strict before/after failure comparison is not
available.

`ruff check`, Python `compileall`, and `git diff --check` passed for the changed
code. Real Windows application E2E, forced OS-process interruption, and live
model timeout E2E are **NOT EXECUTED**. Phase 13/14 status is unchanged; Real
App E2E remains **NOT EXECUTED**, and production readiness remains **NOT
READY**. The implementation commits are the code checkpoints; this report
records the final test run.

## Terminalization and archive safe boundaries — 2026-10-05

Code checkpoint commit: `aacd4d12`.

**Status: VERIFIED for the managed AgentExecutor/AgentManager fixture path.**
Deleting a running agent now persists an `archive` cancellation request and
keeps its running lock until safe terminalization. An existing user cancellation
is escalated to archive intent. The worker is allowed to finish an in-flight
operation and verification/reconciliation; no forceful interruption was added.
After a safe boundary the agent is archived and cannot be started, paused, or
resumed. If a non-running agent still has a mutation journal reservation,
archive fails closed and the server returns HTTP 409 so recovery remains
visible. CLI output distinguishes a pending archive request from a completed
archive.

| Check | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| Agent/Server/CLI/AgentManager integration regression | 1188 | 0 | 0 | 263 |
| Windows identity/action/observer/boundary + agent routes | 143 | 0 | 0 | 1 |
| Ruff / compileall / diff check | PASSED | — | — | — |

The full repository suite was **NOT RE-EXECUTED** after this follow-up. The
most recent full run, at the preceding cancellation checkpoint, was 9028
passed, 78 failed, 139 skipped, and 291 warnings. Real Windows application
E2E remains **NOT EXECUTED**; Phase 13/14 status is unchanged, and production
readiness remains **NOT READY**.

**Next dependency: artifact continuity.** `file_write` currently returns a
verified path and byte size in generic result metadata; managed checkpoints
retain tool/call identity and conversation text but do not persist a structured
artifact reference. The file path survives textually in the current writer
result, but restart-safe artifact provenance is **PARTIAL**. The next bounded
step is to persist validated structured references from verified tool results,
bound to their tool and call IDs, without inferring paths from model text.

## Artifact continuity across managed restart — 2026-10-05

Code checkpoint commit: `0a214d8e`; integration-test strengthening:
`8fc3387d`.

**Status: VERIFIED for the managed fixture path using the production
`FileWriteTool` and a temporary file.** Only successful `VERIFIED` file-write
results contribute validated, bounded artifact references. References retain
tool/call provenance in completed-step state; restore validates provenance and
exposes them as data, not action authorization. Corrupt references fail closed
before model/tool dispatch. The restart test observes exactly one file-write
dispatch and verifies restored path, size, and SHA-256 against the written file.

| Check | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| FileWriteTool + managed resume focused tests | 39 | 0 | 8 | 0 |
| Agent + file-write + Windows mutation broad run | 813 | 17 | 8 | 0 |
| Windows boundary/identity/action/observer/mutation standalone | 81 | 17 | 0 | 0 |
| Ruff / compileall / diff check | PASSED | — | — | — |

All 17 Windows mutation failures occurred during fixture foreground activation:
`foreground_request_accepted=False`; physical mutation count remained zero.
The OS/foreground validation was not weakened. Real model and real Windows
application E2E remain **NOT EXECUTED**. Full repository suite after the
artifact follow-up: **NOT EXECUTED**. The earlier cancellation checkpoint's
9028 passed / 78 failed / 139 skipped / 291 warnings is a separate historical
run, not a result for these commits. Phase 13/14 and production readiness are
unchanged.

## Long-horizon context compaction and restart E2E — 2026-10-05

Production checkpoint commit: `0aceda7c`; managed restart E2E commit:
`744dff0e`.

**Status: VERIFIED for managed Orchestrator fixtures using the production
AgentExecutor, checkpoint store, and `FileWriteTool`.** Context compaction keeps
the original user goal and removes incomplete assistant tool-call/result pairs
atomically. Both function-calling and structured Orchestrator modes checkpoint
the compacted context before the next inference, retaining the completed-step
journal and setting the active step to `NOT_STARTED`. The restart E2E writes one
verified artifact before restart, restores its provenance, dispatches a new
file-write step after restart, and completes. The original file-write dispatch
count remains one; total expected dispatch count is two.

| Check | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| LoopGuard + Orchestrator focused tests | 55 | 0 | 0 | 0 |
| Managed resume/restart test file, including multi-step continuation | 15 | 0 | 0 | 0 |
| Agent suite regression | 712 | 0 | 0 | 0 |
| Resume/cancellation/journal/file-write regression (before E2E test strengthening) | 71 | 0 | 8 | 0 |
| Ruff / compileall / diff check | PASSED | — | — | — |

The Agent suite ran before the final test-only strengthening of the restart
scenario; the updated restart file was then run separately and passed all 15
tests. The context budget is message-count based and truncates old tool output;
it does not create a semantic summary. Full repository suite after these
follow-ups: **NOT EXECUTED**. Windows mutation regression after this follow-up:
**NOT EXECUTED**; its latest run after artifact continuity was 81 passed / 17
failed, all 17 failing in fixture foreground activation before dispatch with
physical mutation count zero. Real model and Real App E2E remain **NOT
EXECUTED**. Phase 13/14 and production readiness are unchanged.

## Memory integration audit — 2026-10-05

**Status: PARTIAL; no new memory write or injection path added.** The managed
AgentExecutor can retrieve from the configured memory backend for a fresh tick;
it stores that context in the conversation checkpoint and does not re-retrieve
it on resume. The separate automatic `MemoryService` consumes completed chat
exchanges. Its fact records currently carry text, source, creation time, and a
trust tier, but no user/agent/task scope, confidence, privacy class, or expiry.
The fact store supports whole-store clearing and reviewed trust promotion, but
not per-fact correction or deletion. As a result, automatic cross-task memory
cannot yet prove the intended owner or retention boundary.

**Next dependency:** add scope-aware memory identity, lifecycle, and per-fact
correction/deletion before expanding persistent memory recall for managed
agents. This is required to prevent one agent or user from receiving another's
stored facts.

## Scope-aware memory ownership and lifecycle — 2026-10-05

Implementation checkpoint commits: `091c4f0e`, `74e85a9f`.

**Status: VERIFIED for the JSONL fact store, authorized retrieval filter, and
managed/HTTP/CLI/SDK context paths covered by fixtures.** New fact rows carry
`memory_id`, owner IDs, `scope`, `provenance`, `confidence`, `privacy`,
timestamps, expiry, correction links, tombstone state, and `schema_version=1`.
Legacy rows remain `schema_version=0`; they are never interpreted as GLOBAL and
are excluded whenever an authorized read is requested. GLOBAL writes require
explicit shared authorization.

`LocalFactStore` now supports scoped insertion, memory-ID deletion, and
history-preserving correction. Correction tombstones the old row and links the
new `USER_CORRECTION` row with `supersedes`; deletion remains persisted across
restart. Expired, deleted, superseded, malformed, unknown-owner, and unknown
provenance rows fail closed before prompt construction. Scoped backend reads
fetch the complete ranked index when a count contract exists, then apply
ownership/privacy/expiry/provenance filtering before `top_k`; backends without
that proof fail closed. Managed `AgentExecutor`, `QueryOrchestrator`, server
chat, CLI chat/ask, SDK, and memory HTTP routes use scoped views. An HTTP API
key is reduced to a server-side owner identifier; keyless memory search returns
no rows and writes/indexing require an owner identity.

| Check | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| Memory store/context/service/scope tests | 245 | 0 | 13 | 0 |
| Managed AgentExecutor + query orchestrator regression | 24 | 0 | 0 | 0 |
| Agent suite | 713 | 0 | 0 | 0 |
| Server routes/API/managed-memory regression | 83 | 0 | 0 | 117 |
| CLI chat/ask/data-boundary regression | 66 | 0 | 0 | 0 |
| SDK + query regression | 87 | 0 | 0 | 0 |
| Storage backend regression | 22 | 0 | 9 | 0 |
| Changed-area aggregate before checkpoint | 1019 | 0 | 22 | 1 |
| Windows identity/action/observer/mutation regression | 90 | 8 | 0 | 0 |
| Ruff / compileall / diff check | PASSED | — | — | — |

The eight Windows failures were fixture foreground activation/revalidation
failures (`WRONG_FOREGROUND`/fixture setup) before a physical action; the
failure payloads reported physical count zero. No Windows production source was
changed by this milestone. Full repository suite: **NOT EXECUTED**. Real model
and Real App E2E remain **NOT EXECUTED**; Phase 13/14 remain unchanged and
production readiness remains **NOT READY**.

The direct `inject_context` helper retains an explicit legacy compatibility
mode when called without an authorization object, so existing library callers
do not silently change behavior. All production context construction paths now
set authorization or `require_authorization=True`; ownerless legacy data is
therefore not injected by those paths. Generic backend deletion remains
backend-specific and the scoped proxy refuses opaque cross-owner deletes;
individual correction/deletion is verified on the durable fact store.

**Next dependency:** terminalization/lifecycle and artifact continuity are
already checkpointed; the next bounded memory work is production Agent memory
E2E with a real configured backend and explicit user/task identity, followed by
Model Router integration only after that boundary is measured.

## Managed Agent scoped SQLite E2E — 2026-10-05

Test checkpoint commit: `1b3d650b`.

The managed `AgentExecutor` scope fixture was extended to use the production
Rust-backed `SQLiteMemory` implementation. An agent-owned row was stored,
retrieved through the executor's scoped view, the backend object was released,
the manager/backend state was reopened from the same database, and the same
agent identity retrieved the row again. The focused test also keeps the
cross-agent negative assertion: a second managed agent receives zero rows.

| Check | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| Scoped memory + managed Agent + SQLite reopen | 9 | 0 | 0 | 0 |
| Ruff / compileall / diff check | PASSED | — | — | — |

This remains fixture/SQLite E2E rather than a live model or real Windows
application run. Full repository suite, live model E2E, and Real App E2E are
**NOT EXECUTED**. Phase 13/14 and production readiness remain unchanged.

## Automatic memory write ownership — 2026-10-05

**Status: IMPLEMENTED and focused-verified.** The background `MemoryService`
can now receive a default `MemoryAuthorization`; the server derives a stable
owner identifier from its configured API key before constructing the service.
HTTP chat completions and streaming paths propagate the request authorization
into the completed-exchange event, and agent-mode CLI chat publishes its agent
authorization. Unauthenticated legacy callers retain their existing behavior,
while production read paths continue to fail closed for ownerless rows.

| Check | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| Memory service + server routes + CLI chat focused tests | 102 | 0 | 0 | 119 |
| Ruff / compileall / diff check | PASSED | — | — | — |

The server test verifies that the persisted event carries only the derived
owner identifier and never the raw API key. Full repository suite, live model
E2E, and Real App E2E remain **NOT EXECUTED**; Phase 13/14 and production
readiness remain unchanged.

## Availability-aware model routing — 2026-10-05

**Status: IMPLEMENTED and focused-verified; live provider execution remains
unverified.** Added an opt-in `tiered` router with configuration labels
`local`, `luna`, `terra`, and `sol`. Provider-specific model IDs are supplied
through `[learning.routing.tier_models]`; the runtime filters against models
actually advertised by the active engine and ignores unavailable tier entries.
Without explicit IDs it uses the configured default/fallback and registered
capability metadata. Complexity, reasoning/code/math signals, uncertainty, and
repeated failure history drive escalation. No GPT/Luna/Terra/Sol model ID is
hardcoded, and router selection does not provide any safety authorization.

The CLI ask path and managed `AgentExecutor` pass the tier configuration into
the policy. A managed-agent fixture verified a hard query selecting the
configured Terra ID; an unavailable upper tier fell back to the available
configured model.

| Check | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| Router/config/CLI/managed-agent focused regression | 83 | 0 | 0 | 0 |
| Ruff / compileall / diff check | PASSED | — | — | — |

Live provider/model E2E: **NOT EXECUTED**. Full repository suite and Real App
E2E remain **NOT EXECUTED**; Phase 13/14 and production readiness remain
unchanged.

Follow-up regression after the router checkpoint: learning/intelligence/CLI
ask/AgentExecutor **815 passed, 7 skipped, 1 warning**; memory plus restart,
cancellation, and resume paths **276 passed, 13 skipped, 0 failed**. The only
warning is the existing Starlette `httpx` deprecation.

## Live local model smoke — 2026-10-05

The local Ollama endpoint was reachable and advertised six installed models.
The real `granite4:3b` model completed a bounded direct generation with
`READY.` and usage `35 prompt / 3 completion / 38 total` tokens. A separate
managed `AgentExecutor` tick used the same real model through `SimpleAgent`
and the production SQLite `AgentManager`; it completed with checkpoint
lifecycle `COMPLETED`, persisted `LIVE_AGENT_READY`, and left the agent idle.
No physical mutation tools were enabled. This is live local-model evidence,
not a Real Windows application E2E or a cloud-provider E2E. The unrestricted
config loader was not used because this host rejected the configured private
data directory ownership; no ACL or security policy was changed.

The managed router now carries persisted retry failure count into its routing
context. A fixture proved a hard instruction selects the configured Terra ID,
then the same agent with two prior `FAILED` retry entries escalates a simple
instruction to the configured Sol ID. Follow-up learning/intelligence and
AgentExecutor regression: **805 passed, 7 skipped, 1 warning**.

## Full repository regression — 2026-10-05

Current HEAD full run (`uv run pytest -q --tb=short`): **9040 passed, 96
failed, 139 skipped, 293 warnings** in 898.01 seconds. The failed node list is
dominated by existing Windows foreground/symlink/privilege fixtures, POSIX-only
format or filesystem assumptions, missing credentials/live connectors,
deployment/packaging environment checks, and unavailable optional engines.
No changed Memory/Router/AgentExecutor focused node failed in the full run.
The one memory-store multiprocess failure was rerun immediately and passed
(`1 passed`), so it is an intermittent suite-level/environment result rather
than a reproduced regression. Changed-area regression remains the targeted
results recorded above; Windows mutation failures remain pre-dispatch fixture
failures with zero physical mutation evidence. Real Windows application E2E
and cloud/live-provider E2E remain **NOT EXECUTED**.

## Windows foreground and Spark-X2.5 investigation — 2026-10-05

**Track A — fixture/foreground classification.** The requested combined
regression was first run as:

```text
uv run pytest tests/security/test_windows_identity.py \
  tests/security/test_windows_action_contract.py \
  tests/security/test_windows_observer.py tests/security/test_windows_mutation.py \
  tests/tools/test_windows_boundary.py -q --tb=short
```

That run produced **81 passed, 17 failed, 0 skipped, 0 warnings** in 61.31s.
Every failure stopped in the test-owned `FixtureProcess.focus()` assertion at
`tests/security/windows_mutation_fixture.py:402`, before observer authorization
or receiver dispatch. The state had `foreground=0`,
`foreground_request_accepted=False`, and `physical_count=0`; activation messages
and a control focus handle were present. This is foreground establishment or
environment timing, not evidence of a production mutation defect.

The same nodes were then isolated and rerun: identity/action/observer **67
passed**, boundary **8 passed**, mutation **23 passed**. A subsequent combined
rerun produced **98 passed, 0 failed, 0 skipped** in 73.15s. The initial 17
failures are therefore classified **INTERMITTENT / WINDOWS FOREGROUND
ENVIRONMENT**, with production action **NOT EXECUTED** and physical mutation
count **0** for each failure. No Windows production source was changed. The
fixture was not weakened to accept an unverified foreground.

**Track B — local model.** Read-only runtime inspection found Ollama **0.33.3**
and the installed API model list initially had no Spark entry. The official
Ollama identifier is `SparkLLM/Spark-X2.5-4B`; the standard pull completed with
digest verification and manifest write, adding
`SparkLLM/Spark-X2.5-4B:latest` (8.2GB). See the
[official Ollama model page](https://ollama.com/SparkLLM/Spark-X2.5-4B) and
[upstream runtime guidance](https://github.com/XHToken/Spark-X2.5#ollama).

The real Astra `OllamaEngine` adapter then produced:

```text
SparkLLM/Spark-X2.5-4B:latest: FAILED
RuntimeError: unknown model architecture: 'spark2_5'
```

The same invocation with `granite4:3b` returned `READY.` with 35 prompt, 3
completion, and 38 total tokens in 7.56s. Thus Spark installation is
**IMPLEMENTED BUT UNLOADABLE on this runtime**, simple inference is **FAILED**,
and managed Spark Agent execution is **NOT EXECUTED**. The `TieredRouter` can
select the configured Spark ID from Ollama's advertised list, but no Spark ID
was persisted into production configuration because loadability is unverified;
model selection is not a safety authorization.

An official `winget upgrade --id Ollama.Ollama --exact` to 0.35.1 was attempted.
The installer verified its hash but rolled back with exit code 5 because the
existing `ollama app.exe` was in use; the process could not be stopped from
this session (`Access denied`). The installed runtime remains **0.33.3** and
no OS security or ACL policy was changed. This is the current external blocker
for Spark loadability.

**Regression evidence after this investigation:**

| Check | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| Windows combined rerun | 98 | 0 | 0 | 0 |
| Memory/router/intelligence/AgentExecutor regression | 1079 | 0 | 20 | 1 |
| Journal/timeout/resume/cancellation/context focused | 82 | 0 | 0 | 0 |

Full repository suite was **NOT EXECUTED** after this docs/runtime-only
investigation. Real Windows App E2E, Spark managed Agent E2E, cloud-provider
E2E, and Phase 13/14 promotion remain **NOT EXECUTED / NOT READY**.

**Next dependency:** resume only after the Ollama process ownership issue is
resolved through a normal runtime restart/update, then repeat Spark load,
inference, adapter, and managed-Agent checks. Until then `granite4:3b` remains
the only live local model verified in this environment; no Real Windows
physical mutation is connected to Spark.

## Safe Ollama restart inspection — 2026-10-05

The current checkpoint was re-audited read-only before any restart attempt.
Git is clean at `9bf5014b9827ffe7331c361a781d1f7e3f3aa4b4` on
`codex/astra-continuation`. `ollama --version` and `/api/version` both report
**0.33.3**. The executable is
`C:\Users\yingz\AppData\Local\Programs\Ollama\ollama.exe`.

No Ollama Windows service or scheduled task was found. The running user-app
chain is:

```text
ollama app.exe  PID 21112  owner EISHU_JARVIS\\yingz  session 7
  └─ ollama.exe PID 10440  owner EISHU_JARVIS\\yingz  session 7
      127.0.0.1:11434 LISTEN
```

The Start-menu registration points to the same `ollama app.exe`, and neither
process exposes a normal window handle. The existing standard `winget` update
attempt already rolled back with Access Denied while that app executable was
in use; no force termination, ACL change, security-policy change, or process
ownership change was attempted. **SAFE RESTART: BLOCKED** from this session.

The model store remains intact and readable: Spark is
`SparkLLM/Spark-X2.5-4B:latest`, 8,229,920,507 bytes, digest
`2d6194f978ca54fe825eeaf535123d2c0535978f5035762110cfb4b2583b528f`, family
`spark2_5`, BF16, 4.1B. `granite4:3b` remains present with digest
`89962fcc75239ac434cdebceb6b7e0669397f92eaef9c487774b718bc36a3e5f`.
No re-pull was performed. Spark loadability and inference remain **FAILED** on
0.33.3; Granite fallback remains **VERIFIED** from the direct Astra adapter
smoke. Spark adapter and managed-Agent validation are **NOT EXECUTED** after a
compatible runtime because that runtime is unavailable.

The next safe action requires the user to close and relaunch Ollama through its
normal application UI, after which the existing model store can be reused for
version, load, inference, adapter, and managed-Agent checks. No administrator
shell, forced kill, ACL modification, or security weakening is required or
requested.

## Post-GUI-exit process recheck — 2026-10-05

After the user reported a normal GUI exit, the required read-only gate was
rechecked. The old processes had **not** exited: `ollama app.exe` PID 21112 and
`ollama.exe` PID 10440 were still running as `EISHU_JARVIS\\yingz` in session 7.
PID 10440 still owned `127.0.0.1:11434` in `Listen` state. The executable and
API version remained **0.33.3**. Because the old runtime was still present, the
standard update mechanism was deliberately **not retried**. No force kill,
privilege change, ACL change, or security-policy change was performed.

The safe restart gate therefore remains **BLOCKED**. A normal application/tray
exit that actually terminates both processes is required before retrying the
standard update. The existing Spark store must continue to be reused; no
re-pull is justified by this process-state observation.

## Spark runtime recovery and managed Agent smoke — 2026-10-05

The user then exited Ollama through the normal Windows tray/UI. A read-only
gate confirmed `ollama app.exe` and `ollama.exe` were both absent and
`127.0.0.1:11434` was not listening. The standard command

```text
winget upgrade --id Ollama.Ollama --exact --silent \
  --accept-source-agreements --accept-package-agreements
```

completed successfully with a verified installer hash and `Successfully
installed`. The actual client version is **0.35.1**. The existing app was then
started normally as the same user; PID 9084 (`ollama app.exe`) owns PID 19660
(`ollama.exe serve`), and PID 19660 owns the 11434 listener.

The model store was reused without a pull. `/api/tags` and `/api/show` report:

```text
SparkLLM/Spark-X2.5-4B:latest
size 8229920507
digest 2d6194f978ca54fe825eeaf535123d2c0535978f5035762110cfb4b2583b528f
family spark2_5 / 4.1B / BF16
```

Runtime and inference results are separated:

* **SPARK MODEL STORE: VERIFIED** — existing manifest, digest, and metadata
  remained readable after the runtime update; no re-pull occurred.
* **SPARK RUNTIME COMPATIBILITY: VERIFIED** — Ollama 0.35.1 loaded the
  `spark2_5` model. A direct `/api/generate` call returned a non-empty result
  (`prompt_eval_count=24`, `eval_count=8`, wall 23.741s; the deliberately
  short budget truncated that first response).
* **SPARK INFERENCE: VERIFIED** — the real Astra `OllamaEngine` adapter called
  `/api/chat` with `think=false` and returned exactly `READY.` in 15.551s,
  with 24 prompt, 4 completion, and 28 total tokens. Ollama timing reported
  13.3295s model load and 1.6542s prompt evaluation.
* **SPARK ASTRA ADAPTER: VERIFIED** — the result came through
  `openjarvis.engine.ollama.OllamaEngine`, not a raw-only probe.

A production `AgentExecutor.execute_tick` smoke then used a real temporary
SQLite `AgentManager`, the production `AgentExecutor`, the same real
`OllamaEngine`, and a read-only `simple` agent with no tools. Evidence:

```text
database: %TEMP%\\astra_spark_managed_smoke.db
agent status: idle
total_runs: 1
checkpoint lifecycle: COMPLETED
checkpoint result: READY
retry history: attempt 1 SUCCEEDED
tool calls: none
```

This establishes **SPARK MANAGED AGENT: VERIFIED** for the bounded,
non-mutating managed tick. It is live local-model/SQLite evidence, not a Real
Windows application E2E or cloud-provider E2E. The tick's `AgentResult` did not
carry token counters into the managed agent row (`total_tokens=0`), so detailed
managed token accounting remains **IMPLEMENTED BUT UNVERIFIED** for this path.

The post-update Granite fallback probe also returned exactly `READY.` through
the same Astra adapter: `granite4:3b`, 36 prompt, 3 completion, and 39 total
tokens in 9.071s. **GRANITE FALLBACK: VERIFIED.**

## Post-Spark Windows regression — 2026-10-05

The first combined Windows rerun after the runtime update produced **86 passed,
12 failed**. All 12 failures occurred in the test-owned
`FixtureProcess.focus()` setup before dispatch; the failure payloads had
`physical_count=0`. Isolated reruns then produced identity/action/observer
**67 passed**, boundary **8 passed**, and mutation **23 passed**. A final
combined rerun produced **98 passed, 0 failed, 0 skipped** in 75.27s. No
Windows production source changed and no wrong-target mutation was observed.
The 12-failure result remains classified as intermittent Windows foreground
fixture timing, consistent with the existing evidence.

Real App E2E remains **NOT EXECUTED**. The production Windows mutation tool is
explicitly bound to a cooperative `WindowsActionSession` receiver; it has no
verified receiver/dispatch adapter for arbitrary Notepad or another real
application. Introducing unverified WM/UIA mutation for a real app would
weaken the identity and exactly-once boundary, so the next safe dependency is a
separate, test-owned real-app adapter design and proof. The test-owned native
fixture is not being relabeled as Real App E2E.

Focused post-Spark regression:

| Check | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| Managed Agent/Memory/Router/Intelligence | 1079 | 0 | 20 | 1 |
| Journal/timeout/resume/cancellation/context | 82 | 0 | 0 | 0 |
| Ollama adapter/provider unit tests | 35 | 0 | 0 | 0 |
| Windows final combined regression | 98 | 0 | 0 | 0 |

Full repository suite, Real App E2E, and cloud-provider E2E remain **NOT
EXECUTED**. Phase 13/14 are not promoted and production readiness remains
**NOT READY**.

## Full repository regression after Spark recovery — 2026-10-05

Current HEAD full run (`uv run pytest -q --tb=short`) completed in 893.34s:
**9058 passed, 78 failed, 139 skipped, 293 warnings**. The failures are
environment or pre-existing capability boundaries: missing WhatsApp/live
connector credentials, Windows symlink privilege and code-page assumptions,
POSIX-only calendar/telemetry behavior, deployment/packaging fixture inputs,
optional live engines, missing skill/runtime fixtures, and similar external
dependencies. No focused Memory/Router/AgentExecutor, journal/restart, Ollama
adapter, or Windows safety regression failed. Real App E2E and cloud-provider
E2E remain **NOT EXECUTED**.

## Test-owned real Windows receiver — 2026-10-05

`NativeBoundWin32Receiver` was added beside the existing cooperative receiver.
It accepts one caller-supplied process/window/edit binding only; it does not
discover HWNDs, choose a first match, acquire focus, or retarget by text. The
binding records PID, process creation FILETIME, normalized executable path,
root HWND/thread/class, child Edit HWND/class, and per-window/control lifetime
properties. Before dispatch it rechecks all of those identities, foreground,
thread focus, visibility, enabled state, style, and revision. It uses one
bounded `SendMessageTimeoutW(WM_SETTEXT)` call; a timeout is raised after the
dispatch boundary and therefore becomes `UNKNOWN_OUTCOME` in
`WindowsActionSession`. Independent UIA observation/readback remains required
for `VERIFIED`.

The disposable test app in
`tests/security/real_app_fixture.py` is a separate non-cooperative Win32
process with a unique title and a standard Edit control. It uses no user file,
account, network, or existing app window. Its own subclass counts received
`WM_SETTEXT` messages as an independent physical-dispatch witness. The
cooperative fixture was not relabeled.

Initial real-app run before the desktop foreground session became unavailable:

| Check | Result |
| --- | --- |
| Low-level positive: dispatch + independent readback | **PASSED** |
| Wrong foreground | **PASSED**, physical dispatch 0 |
| Replaced control | **PASSED**, physical dispatch 0 |
| Recreated window | **PASSED**, physical dispatch 0 |
| Ambiguous Edit resolution | **PASSED**, physical dispatch 0 |
| Process restart | **PASSED**, physical dispatch 0 |
| Acknowledgement loss / replay | **PASSED**, first physical dispatch 1, replay 0 |
| Scripted managed Agent real app | **PASSED**, canary readback and dispatch 1 |

The later rerun was blocked at setup because `GetForegroundWindow()` returned
0; every attempted test stopped before dispatch. No focus check was weakened.
The live Spark Agent real-app attempt ran for 315.45s and did not reach the
canary mutation (`text == ""`); Spark Agent real-app integration is therefore
**NOT VERIFIED**. It is guarded behind explicit `ASTRA_RUN_SPARK_REAL_APP=1`.

Current changed-area regression:

| Check | Passed | Failed | Skipped | Warnings |
| --- | ---: | ---: | ---: | ---: |
| New real-app receiver + scripted Agent (initial run) | 8 | 0 | 0 | 0 |
| Windows identity/action/observer/mutation/boundary combined | 89 | 17 | 0 | 0 |
| AgentExecutor/resume/cancellation/tools/memory scope | 66 | 0 | 0 | 0 |
| Journal/timeout/context focused | 54 | 0 | 0 | 0 |
| Agents + intelligence + learning + memory + CLI | 2406 | 4 | 22 | 13 |
| Ruff / compileall / diff check | PASSED | — | — | — |

The 17 Windows failures were all cooperative-fixture foreground setup failures
before dispatch with physical mutation count 0. The four broad failures were
existing Windows symlink privilege, CLI code-page/output, and platform scan
assumptions; none exercised the new receiver. Full repository regression after
this change is **NOT EXECUTED**. Real user-app E2E, cloud-provider E2E, Phase
13/14 promotion, and production readiness remain **NOT READY**.

The current HEAD full repository run after this checkpoint completed
**9041 passed, 103 failed, 140 skipped, 293 warnings** in 996.78s. The added
real-app tests failed only at foreground setup after the desktop session began
returning `GetForegroundWindow() == 0`; they did not cross the dispatch
boundary. Remaining failures are the existing connector credential/live
provider, Windows foreground/symlink, POSIX formatting/filesystem,
deployment/packaging, optional engine, and fixture/environment groups. This
result supersedes earlier full-suite counts for the current checkpoint.

## Live tiered-router selection — 2026-10-05

The production `AgentExecutor._invoke_agent_impl` path was run with a real
`OllamaEngine` and its live `list_models()` result. With `router_policy="tiered"`
and a simple instruction, the configured local tier resolved to the available
`SparkLLM/Spark-X2.5-4B:latest`; the probe recorded
`selected=["SparkLLM/Spark-X2.5-4B:latest"]`. The probe agent performed no
inference or physical action, so this proves live tier selection only. Spark
managed real-app execution remains **NOT VERIFIED** after the bounded live
attempt documented above.

## Real-app repeatability and multi-step follow-up — 2026-10-06

The read-only desktop gate was normal at the start of this run: foreground
HWND `921134` belonged to Brave (`C:\Program Files\BraveSoftware\Brave.exe`),
not LockApp, and Ollama continued to own `127.0.0.1:11434`. The direct
`uv run pytest` launcher was then blocked before collection by Windows
application-control error 4551. No policy, ACL, or security setting was
changed. The same tests were run through the already documented
`uv run python -m pytest` path.

The first current dedicated run produced **1 failed, 7 passed, 1 skipped**.
The failure occurred after `dispatch=DISPATCHED`: the result was
`UNKNOWN_OUTCOME` with `IdentityError`, and the physical result was not
replayed. A separate fresh-app diagnostic completed with
`dispatch_count=1`, exact readback, and `VERIFIED`. Three subsequent complete
dedicated runs each produced **8 passed, 1 skipped**. This is a bounded
repeatability signal, not a universal guarantee; the first run remains part of
the evidence.

The isolated scripted single-step Agent passed once and failed once on later
repetition. A five-iteration diagnostic showed two classes of safe failure:
one `WRONG_FOREGROUND` before dispatch (`dispatch_count=0`), and later
post-dispatch `UNKNOWN_OUTCOME` with `dispatch_count=1` where independent
readback saw text such as `aaaaaASTRA_AGENT_PROBE_*` instead of the requested
canary. This is verification failure under interactive input interference,
not a reason to replay. No wrong-target mutation was observed.

A new bounded scripted multi-step test was added:

* observe → type canary A → fresh observe → type canary B;
* each action has a separate observation, journal call, dispatch, and
  independent readback;
* the successful run proved final text B and physical dispatch count `2`.

The same test later encountered `UNKNOWN_OUTCOME` during readback under the
same interactive input conditions. Therefore scripted multi-step capability
is **IMPLEMENTED BUT UNVERIFIED for repeatability**.

The four focused broad-regression failures were rerun and identified exactly:

1. `tests/cli/test_model_convert.py::TestModelConvert::test_convert_gguf_shells_and_quantizes`
   — Windows console/output encoding omitted the expected backend text.
2. `tests/cli/test_model_convert.py::TestModelConvert::test_force_replaces_symlink_without_touching_target`
   — WinError 1314 symlink privilege.
3. `tests/cli/test_model_convert.py::TestModelConvert::test_convert_refuses_empty_directory_symlink_without_force`
   — WinError 1314 symlink privilege.
4. `tests/cli/test_scan.py::TestRunQuick::test_run_quick_returns_subset`
   — platform fixture returned `linux` while the Windows expectation allowed
   only `win32` or `all`.

These four failures are environment/platform/CLI boundaries and do not touch
the real-app receiver. The rerun result was **2406 passed, 4 failed, 22
skipped, 13 warnings** in 151.48s.

## Spark proposal diagnosis — 2026-10-06

Two non-mutating Spark probes used the real
`SparkLLM/Spark-X2.5-4B:latest` model and the production ReAct tool
descriptions. The observation-only probe returned parseable ReAct text with a
valid `windows_observe` proposal in 37.869s (579 prompt, 85 completion, 664
total tokens). With a simulated valid observation, Spark returned parseable
JSON but used action value `"type"` instead of the contract value
`"type_into"` in 29.14s (838/44/882 tokens): **MODEL_INVALID_ACTION**.

A stricter non-mutating prompt produced a `type_into` object but prefixed it
with a second JSON thought object. The production parser correctly rejects the
concatenated response: **MODEL_FORMAT_FAILURE** (40.962s, 876/99/975
tokens). The Windows boundary remains unchanged and no Spark real-app retry
was started. The prior approximately 315-second live attempt therefore
remains **IMPLEMENTED BUT UNVERIFIED**; its failure is now classified as
model action/format contract failure before any safety bypass.

## Spark tool-contract bounded probe — 2026-10-06

The production path audit confirmed that `NativeReActAgent.run()` builds a
text-only ReAct prompt and calls `InferenceEngine.generate()` without passing
the available OpenAI/Ollama function schemas. `build_tool_descriptions()` does
render the Windows enum `click | type_into`, and `ToolExecutor` still performs
the canonical action validation. `OllamaEngine.generate()` can accept a
`tools` payload and extract native tool calls, but that capability is not used
by this ReAct path. `_parse_json_response()` intentionally rejects trailing
JSON or partial recovery, preserving the fail-closed boundary.

The new non-mutating harness is
`scripts/astra_spark_tool_contract.py`. It reuses the production descriptions
and parser, performs no tool dispatch, and never retries a model response.
With the existing ReAct prompt and no added contract instruction, ten first
attempts against `SparkLLM/Spark-X2.5-4B:latest` produced:

| Sample | Valid canonical | Invalid action | Invalid args/tool | Parser reject | Multiple JSON | Timeout/engine | Retries | Physical dispatch |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 0 | 10 (`edit`) | 0 | 0 | 0 | 0 | 0 | 0 |

Latency was 20.023–28.238s (mean 22.972s); each response used 560 prompt,
103 completion, and 663 total tokens. With an explicit single-object contract
and exact `type_into` instruction, a separate ten-sample run produced
`valid_canonical=10`, all other categories zero, at 11.643–21.572s (mean
13.239s), with 653/57/710 tokens. This is a contract-prompt signal, not
evidence that the unmodified Spark Agent can safely mutate a real app. No
alias for `type` was added, no parser salvage was added, and no physical
dispatch occurred.

The bounded probe isolated a safe next step: reuse the existing native tool-call
capability before considering any real-app retry. At that point, Spark real-app
execution had not yet been revalidated; the bounded follow-up below records the
result separately from repeatability.

## Native tool-call integration — 2026-10-06

The same placeholder request was sent directly through the existing Ollama
`tools` payload (still with no receiver and no tool execution). Spark returned
one native `windows_action` call with the exact `type_into` value in 24.717s
(349 prompt, 50 completion, 399 total tokens). This isolates the weakness to
the text ReAct contract rather than Spark's ability to follow the declared
schema.

`NativeReActAgent` now passes its existing tool schemas when tools are present,
handles native calls through the existing `ToolExecutor`, and keeps the text
parser as a fallback when an engine ignores or rejects the optional payload.
The Windows safety boundary is unchanged. A live managed-agent probe used
`WindowsActionTool(None)` deliberately; Spark's canonical call reached the
agent, and the tool returned `UNBOUND_APPLICATION` with
`outcome=NOT_STARTED`, `dispatch=NOT_DISPATCHED`, `retryable=false`. No real
window was opened and no physical mutation occurred.

This proves native call plumbing and fail-closed unbound behavior only. It does
not prove a real-app Spark mutation, independent readback, restart recovery, or
repeatability.

Focused regression after the integration:
`uv run python -m pytest -q tests/agents
tests/tools/test_windows_boundary.py tests/engine/test_ollama.py
tests/engine/test_openai_compat_tools.py --tb=short` — **766 passed** in
109.85s. Ruff, compileall, and `git diff --check` also passed. Windows real-app
physical tests, broader Windows regression, and the full repository suite were
not executed in this checkpoint.

The additional non-mutating execution-safety lane
(`tests/tools/test_execution_outcomes.py`, Windows boundary, executor, and
resume tests) completed **49 passed** in 3.38s. No real-app process was
created by this lane.

## Spark real-app bounded follow-up — 2026-10-06

After the native-call change, the existing real-app suite was run three
consecutive times without the Spark-live flag: each run was **9 passed, 1
skipped** (10.46s, 10.49s, 10.26s). This includes the low-level positive and
negative cases plus the scripted multi-step Agent; no wrong-target dispatch was
observed.

The first post-change Spark live test (`ASTRA_RUN_SPARK_REAL_APP=1`) failed
after 196.81s because the canary remained empty. That test did not expose the
tool result, so its exact terminal phase is not retrospectively knowable. A
separate no-dispatch diagnostic showed Spark issuing canonical observe and
`type_into` proposals with matching foreground/focus, and no physical call.

One controlled instrumented run through the actual receiver then completed the
full physical path in 115.229s:

* `windows_observe` returned a fresh observation and exact Edit target;
* Spark proposed `windows_action` with `action=type_into` and the fresh IDs;
* `WindowsActionSession` returned `preconditions=PASSED`,
  `dispatch=DISPATCHED`, `outcome=VERIFIED`, `verification=VERIFIED`;
* helper state read back `ASTRA_SPARK_REAL_APP_CANARY`,
  `physical_dispatch_count=1`, and the execution journal had no pending rows.

The Agent reached its three-turn bound without a final prose answer after the
verified action. This proves one real Spark mutation through the deterministic
safety boundary (**capability VERIFIED**), but repeatability remains **PARTIAL**:
one official live run failed and one controlled run succeeded. The failure is
not evidence of an alias or identity bypass; response-time/turn variability is
the current bounded hypothesis, and no blind live retry was started.

Post-Spark Windows focused regression (identity, action contract, observer,
mutation, and tools boundary) completed **98 passed** in 59.94s. The initial
nonexistent boundary path was corrected to the actual
`tests/tools/test_windows_boundary.py`; that first command ran no tests and is
not counted as a result.

## Final environment gate — 2026-10-06

At the end of this checkpoint, the foreground was Brave `brave.exe` (a
browser game window), not LockApp; Ollama remained on its existing listener and
no test-runner or temporary diagnostic process remained. The desktop is
available but not an exclusive test surface, so further physical Real App
iterations are deferred until external input cannot contaminate the disposable
helper. No user window, LockApp, ACL, policy, or security setting was changed.

## Real-app foreground recheck — 2026-10-05

After the desktop foreground value became nonzero again, the dedicated suite
was rerun with the existing receiver and no code changes. It produced **8
failed, 1 skipped** in 3.83s. All eight failures occurred in
`RealAppProcess.focus()` before observation-bound dispatch; each payload had
`dispatch_count=0`. The foreground HWND was `199310`, owned by
`C:\Windows\SystemApps\Microsoft.LockApp_cw5n1h2txyewy\LockApp.exe`, so the
test-owned window could not be established as foreground from this session.
No foreground or identity check was weakened and no physical mutation was
attempted. The earlier initial 8-test pass remains valid evidence for the
receiver path; a repeatable current run is blocked by the locked/secure
desktop state. Spark real-app remains **NOT VERIFIED**.
At that earlier recheck, Spark real-app was **NOT VERIFIED**; the later
controlled capability result and official failure are recorded in the dated
Spark follow-up above.

## Native argument normalization and current regression — 2026-10-06

The native ReAct path now normalizes provider-decoded object arguments to a
canonical JSON string before the existing loop guard and `ToolExecutor`.
Unserializable values become the JSON `null` sentinel and therefore fail at the
executor's object boundary; no argument salvage or tool alias was added. A
regression test covers the decoded-object case. The sensitive-trace fixture was
updated to return one complete native call on its first turn and no call on its
final-answer turn, matching the native provider contract while retaining the
redaction assertions.

Post-fix focused regression:
`tests/traces/test_sensitive_tools.py`, `tests/agents`, Windows boundary, and
Ollama/OpenAI-compatible engine tests — **770 passed** in 100.02s.
Ruff, compileall, and `git diff --check` also passed.

Post-fix full repository execution:
**9043 passed / 104 failed / 140 skipped / 293 warnings** in 693.71s. The
remaining failures are environment or unrelated repository areas (Windows
foreground/interactive fixture, platform-specific paths, missing credentials or
live services, deployment/packaging fixtures, and optional runtime resources).
The three pre-fix sensitive-trace failures are absent; no failure in the native
ReAct/trace focused lane remains.

The current shell session cannot safely establish a foreground HWND
(`GetForegroundWindow()` returned `0`); process inventory still shows the
test-session `LockApp` process and no test-owned helper. No physical Real App
rerun was attempted after this fix. Existing evidence remains three consecutive
non-Spark runs at **9 passed / 1 skipped** each, one controlled Spark mutation
with dispatch **1** and exact readback, and one official Spark run with an empty
canary. Spark Real App repeatability is therefore **PARTIAL**, not promoted.

A separate non-mutating Spark diagnostic used the exact real-app prompt with a
fake receiver that always returned `TEST_RECEIVER_BLOCKED` and never touched
Windows. Spark produced the canonical observe/action sequence, then repeated
the action after the non-retryable `NOT_STARTED` result until the four-turn
bound; fake action calls were **2**, physical dispatch was **0**. This confirms
the model can continue after a tool failure, but it does not identify the
official live failure's terminal phase and is not evidence for a physical retry.

## Semantic exactly-once managed integration — 2026-10-06

Phase 2 connected the Phase 1 `MutationIntent` journal to the managed
`AgentExecutor → OrchestratorAgent → ToolExecutor` path. The controller now
creates `execution_id`, `step_id`, and `mutation_intent_id`; provider call IDs,
observations, and target IDs remain invocation data only. A mutating managed
call receives the trusted intent through `AgentContext` metadata, and the
strict ToolExecutor gate rejects a fresh call for a `VERIFIED` or unresolved
intent without dispatch. A new intent requires the controller-only
`AgentExecutor.advance_plan_step()` API. Step IDs are durable and cannot be
reused within one execution.

The checkpoint stores the semantic reference and validates it against the
SQLite semantic journal on resume. Mismatches fail closed. The journal remains
authoritative; pre-dispatch checkpoint callbacks synchronize `PREPARED` and
`EXECUTING`, while a result stages the terminal semantic state before the
execution journal finish. A crash or finish mismatch therefore blocks resume
until reconciliation rather than authorizing replay. Cancellation and deadline
paths retain the existing journal serialization and UNKNOWN_OUTCOME quarantine.

Changed production files:

* `src/openjarvis/agents/executor.py`
* `src/openjarvis/agents/orchestrator.py`
* `src/openjarvis/tools/execution_journal.py`

Changed tests:

* `tests/agents/test_managed_semantic_intents.py`
* `tests/agents/test_executor_resume.py`

Non-physical evidence on this checkpoint:

* managed semantic tests (C1/C2, M1–M12, step-ID reuse): **15 passed**;
* Phase 1 semantic/journal/outcome/timeout tests: **32 passed**;
* executor resume: **15 passed**;
* Orchestrator: **42 passed**;
* cancellation/deadline: **13 passed**;
* NativeReAct: **82 passed**;
* traces, sensitive tools, and Windows boundary: **16 passed**;
* all agent tests: **732 passed**;
* Ruff, compileall, and `git diff --check`: **PASSED**.

The existing cancellation/deadline suite covers managed cancellation and
timeout boundaries (M13/M14); no Windows source was changed. The Windows
mutation fixture was not rerun for this non-physical phase. Physical Spark
Real App: **NOT EXECUTED**. Phase 13/14 remain **NOT PROMOTED** and production
readiness remains **NOT READY**. Raw direct NativeReAct mutation remains the
legacy non-strict compatibility path; managed Orchestrator mutations require
controller context.
