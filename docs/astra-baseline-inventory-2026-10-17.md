# Astra Baseline & Regression Failure Inventory — 2026-10-17

Offline closure artifact. **No production file was modified, no test was
executed, no external service was started.** Everything below is read-only
verification of existing artifacts (git state, junit XMLs, pytest cache,
prior reports) plus line-anchored checks of the current tree.

Worktree of record:
`C:\Users\yingz\.codex\worktrees\astra-opencode\JARVIS-Sol`
(branch `opencode/cloud-privacy`).

---

## 1. Verified baseline (claimed vs observed)

| Claim | Observed | Verdict |
|---|---|---|
| Branch `opencode/cloud-privacy` | ✓ same worktree/branch | VERIFIED |
| HEAD `d596e482` ("integrate host-mediated RLM LLM RPC") | ✓ `git worktree list` | VERIFIED |
| Dirty 294 | ✓ 116 modified + 178 untracked = 294 | VERIFIED |
| Focused: 328 passed / 0 failed | no junit/log written for that run | UNKNOWN |
| New Host Supply Tests: 57 passed | no junit/log; static `def test_` count across the 7 host-supply test files = **75** | UNKNOWN (claim not countable; see 3.2 — last failure snapshot contains 2 host-supply failures) |
| Full: 10,135 passed / 132 failed / 143 skipped | **no junit xml / log for any full run of this branch** (only `.pytest_cache/v/cache/lastfailed` @ 2026-10-17 21:39, which is a failure-ID list without counts) | UNKNOWN |
| Production Construction: PARTIAL | ✓ all nine shared-file diffs UNAPPLIED (factory still untracked), `JarvisSystem` has no `host_supply` field, `SecurityContext` has no `scanners` field, `services`/router untouched | VERIFIED |
| Owner Approval: BLOCKED | ✓ no approval record anywhere (git history excluded as evidence by rule F) | VERIFIED |
| Native Gate B–F: BLOCKED | ✓ `docs/hybrid-residual-risk-decision.md` §4: B NOT AUTHORIZED, C/D NOT AUTHORIZED, E 0/19, F DENIED | VERIFIED |

Contradiction to be resolved by the owner: "Focused 328/0" and "Host Supply
57 passed" both lack artifacts, while the machine state (2) contradicts them.

---

## 2. Host Supply change freeze (Section B)

Freeze set = the Host Supply Factory module + its test files (untracked,
independent, no shared file touched):

| File | Bytes | sha256 (first 16) |
|---|---|---|
| `src/openjarvis/agents/host_supply.py` | 1,947 | `E2CB50728CB4BFBE` |
| `src/openjarvis/agents/host_supply_factory.py` | 36,237 | `BADDA83815BBE6D8` |
| `tests/agents/test_host_supply.py` | 3,501 | `E2510C36C57FA306` |
| `tests/agents/test_host_supply_document.py` | 8,593 | `B33EB7549E015AA0` |
| `tests/agents/test_host_supply_e2e.py` | 9,037 | `BAAFEEFE468FAB65` |
| `tests/agents/test_host_supply_factory.py` | 19,154 | `6BED5F6E29DC51A2` |
| `tests/agents/test_host_supply_observe_tick.py` | 4,315 | `37F8EA38600AD1D7` |
| `tests/agents/test_host_supply_wiring.py` | 5,746 | `11669DEF8CD5F4AD` |
| `tests/agents/test_tick_supply_shadow.py` | 6,434 | `7F7F8257B8E92D9C` |

- Mission said "new 6 files"; observed freeze surface is 2 source + 7 test
  files (9). The extra breadth is reported, not invented away.
- All 75 test functions already in the tree are part of the frozen baseline.
- New duplicate Factory / Router / Gate / Ledger modules: **prohibited**
  (existing untracked companions like `host_routing.py`, `shadow_observer.py`,
  `capability_router.py`, `dispatch_contract.py`, `security/dispatch_ledger.py`,
  `security/egress_guard.py`, `security/pinned_transport.py` are pre-existing
  parallel work and are preserved as-is — they are NOT this task's new code).
- Dirty/untracked/parallel changes: preserved untouched (116 M + 178 ??).
- `factory contract`: `load_host_supply_from_env(scanners=..., capability_policy=...)`
  → `None` when `JARVIS_HOST_SUPPLY_PATH` unset (legacy behavior), raises
  `HostSupplyError` on invalid document; bundle flags default OFF unless the
  document sets `shadow_enabled` / `cloud_egress_enabled` explicitly.

---

## 3. Regression failure inventory (Section A)

Rule applied: classifier only asserts what the artifact shows; `UNKNOWN`
when error type cannot be determined from the artifact. No cluster number
is presented as an individual case.

### 3.1 Claimed run `10,135 / 132 / 143` — NOT REPRODUCIBLE FROM EXISTING LOGS

No junitXML, log, or audit JSON matching those totals exists in any of the
five checked worktrees (checked: astra-opencode, astra-continuation,
astra-autodev, d76f, 0d88) — full-run artifacts found are 3.2/3.3 instead.
Status per test: **UNKNOWN** (132-node list cannot be derived honestly).
This does not falsify the run; it only records that the evidence above is
missing, so the 132-failure baseline cannot be restored from current logs.

### 3.2 Best-available reproducible failure snapshots (artifact-backed)

**(a) Full-regression junitXML 2026-10-04** `.astra-tools/phase16-full.xml`
(in worktree `codex/astra-reliability` HEAD-from `7eb95fea` lineage — i.e. a
*near-ancestor* state of the current branch run; recorded here because it is
the ONLY complete full-suite failure artifact in evidence):

- totals: 9,213 selected / 8,996 passed / **78 failed** / 139 skipped,
  0 errors; native mutation file ran separately (11 failures of 17 there).
- Error-type clusters (counts = individually verified rows):

| # cluster | count | rows | Failure stage | Category | Owner | Status | Confidence |
|---|---|---|---|---|---|---|---|
| C1 `UnicodeDecodeError cp932` (files read without `encoding=`, Windows CP932 locale) | 38 | `tests/deploy/test_deploy_auth` x3, `tests/deployment/test_docker` x15, `tests/deployment/test_docs_leaderboard` x2, `tests/deployment/test_packaging` x8, `tests/deployment/test_release_artifact_validation` x8, `tests/evals/test_skill_benchmark::test_write_report_creates_dated_markdown` x1, (deploy subtotal +1 evals = 38 exactly) | test body read() | TEST_ENV_ENCODING (fixture test code, production unaffected) | owner: tests | OPEN fix = add `encoding='utf-8'` to those test helpers | HIGH |
| C2 live/inference dependencies not present (`gemma.cpp model` weights, no running ollama engine, connector secrets absent) | 12 | `tests/engine/test_gemma_cpp` x4 (model_path missing), `tests/connectors/test_new_connectors_live` x4 (Oura/Strava/Spotify state file missing, GoogleTasks `httpx.LocalProtocolError Bearer ''` short header), `tests/skills/test_integration_live` x4 (`RuntimeError No inference engine available` x2, catalog/tool assertion x2) | test setup / production call requiring local service | TEST_ENV_LIVE | owner: tests+env | OPEN (skip-guard deselected in normal `pytest -m "not live"`) | HIGH |
| C3 fixture HOME-state isolation (bg-state wizard not visible to reader) | 7 | `tests/install/test_bg_state` x5, `test_chat_banner` x1, `test_doctor_bg` x1 | test fixture | TEST_HOME_ONLY_FIXTURE_ON_WINDOWS | owner: tests | OPEN | HIGH |
| C4 POSIX strftime `%`-directives rejected on Windows (`ValueError Invalid format string`) | 4 | `tests/connectors/test_apple_calendar` x4 | **production** `toLocale`/`strftime` call inside `connectors/apple_calendar` | PRODUCTION_PLATFORM | owner: src/ production | OPEN (production code platform bug) | HIGH |
| C5 Linux sysfs `/sys/class/power_supply/...:n:...` colon paths on Windows | 5 | `tests/telemetry/test_energy_rapl` x5 | fixture path | TEST_LINUX_SYSFS | owner: tests | OPEN | HIGH |
| C6 `OSError WinError 1314` symlink privilege on Windows tmp | 2 | `tests/cli/test_model_convert` x2 | fixture symlink | TEST_ENV_PRIVILEGE | owner: tests | OPEN | HIGH |
| C7 `WinError 193` `%1 is not a valid Win32 application` (script exec on Windows) | 2 | `tests/deploy/test_render_blueprint` x2 | fixture subprocess | TEST_ENV_LAUNCH | owner: tests | OPEN | MEDIUM |
| C8 `FileNotFoundError` missing npm/node runner (`whatsapp_baileys` bridge) | 1 | `tests/channels/test_channel_contract[whatsapp_baileys]` | production subprocess launch inside test | PRODUCTION_WINDOWS_NPM_LAUNCH | owner: env | OPEN | HIGH |
| C9 subprocess dependency path (codex runtime clone) | 1 | `tests/install/test_version_history[powershell-file-url]` | fixture | TEST_SUBPROCESS_DEP | owner: tests | OPEN | MEDIUM |
| C10 path-separator string comparison (`\\` vs `/`) | 1 | `tests/prompt/test_persona_scope` | test assertion | TEST_PATH_SYNTAX | owner: tests | OPEN | HIGH |
| C11 TOML backslash escape in prompt fixture | 1 | `tests/recipes/test_compose::test_external_prompt_file` | fixture parse | TEST_TOML_BACKSLASH | owner: tests | OPEN | MEDIUM |
| C12 permission-error tempfile sharing (obsidian vault) | 1 | `tests/connectors/test_live_smoke::test_live_obsidian_full_pipeline` | fixture cleanup | TEST_FIXTURE_CLEANUP | owner: tests | OPEN | MEDIUM |
| C13 platform guard (`'linux'` required in LUKS scan result on win32) | 1 | `tests/cli/test_scan::test_run_quick_returns_subset` | production scan platform matrix | PRODUCTION_PLATFORM (expected-by-design for LUKS) | owner: tests | OPEN (test expectation should match platform) | MEDIUM |
| C14 llamacpp backend command output mismatch (missing/failed tool invocation) | 1 | `tests/cli/test_model_convert::test_convert_gguf_shells_and_quantizes` | fixture | TEST_ENV_BACKEND | owner: tests | UNKNOWN (message truncated in XML) | LOW |

  totals 78; **0 failures in `openjarvis/security`, `server`, engine wiring;
  0 host-supply (module did not exist yet on 2026-10-04).**

**(b) Latest failure snapshot** `.pytest_cache/v/cache/lastfailed`,
mtime 2026-10-17 21:39 (this worktree) — **177 entries** =170 test nodes
+ 7 collection-error stub files (`tests/test_bad_collection_*.py`; a stub
record is pytest's note, not a test failure).

Per-file grouping (170 test nodes + 7 collection stubs; statement basis:
pytest cache, error types UNKNOWN per cache limitation):

| File | Nodes | Likely mechanism (GUESS from phase16 clusters, unverified) |
|---|---|---|
| `tests/agents/test_rlm_repl.py` | 35 | worker/gate seam (rlm security work is dirty) |
| `tests/agents/test_rlm_worker.py` | 12 | same seam |
| `tests/agents/test_rlm.py`, `test_rlm_rpc.py` | 2+1 | same seam |
| `tests/mcp/test_discovery.py`, `test_mcp_tools_cache.py`, `tests/sdk/test_builder_mcp_cleanup.py` | 8+5+1 | MCP loader dirty |
| `tests/server/test_security_factory_wiring.py`, `test_managed_agent_resolved_tools.py` | 1+1 | factory-wiring seam |
| `tests/security/test_appcontainer_sandbox.py`, `test_boundary_guard.py`, `test_taint_propagation.py`, `test_transport_coverage.py`, `test_windows_foreground_fixture_probe.py` | 3+1+4+1+1 | security/dirty seams |
| `tests/engine/test_gemma_cpp.py`, `test_openai_compat_tools.py` | 4+5 | weights/ollama live (C2-type) or engine dirty |
| `tests/deployment/test_docker.py`, `test_docs_leaderboard.py`, `test_packaging.py`, `test_release_artifact_validation.py`, `tests/deploy/test_deploy_auth.py`, `test_render_blueprint.py` | 16+2+8+8+3+2 | CP932 / shell-launch clusters (C1/C7-type) |
| `tests/connectors/…`, `tests/skills/test_integration_live.py` | 4+1+4 | live deps (C2-type) |
| `tests/cli/…`, `tests/install/…`, `tests/prompt/…`, `tests/recipes/…`, `tests/evals/…` | 1+2+1+1+1+5+1+1+1+1+1 | env/fixture clusters (C1,C3,C6,C9,C10,C11-type) |
| `tests/telemetry/test_energy_rapl.py`, `tests/tools/test_weather.py`, `tests/integration/test_integration_extended.py`, `tests/agents/test_openhands.py`, `test_native_openhands.py`, `tests/channels/test_channel_contract.py` | 5+1+1+1+3+1 | platform/live (C5,C12,C8-type) |
| host-supply freeze exceptions | `test_host_supply_document.py` 1, `test_host_supply_observe_tick.py` 1 | **see R2** |
| `tests/test_bad_collection_*.py` | 7 | collection-time stubs, not test failures |

- Only node IDs are stored in the cache — per-suite junit/log is absent, so
  Error Type / Failure Stage are **UNKNOWN** for these rows (per mission
  rule: logs cannot decide → UNKNOWN). Only the file/directory grouping is
  factual.
- The snapshot includes `tests/agents/test_host_supply_document…` and
  `test_host_supply_observe_tick…` failures — proof the newest frozen
  module's tests are NOT all green as of Oct 17.
- Temporal contradiction with the claimed baseline (Focused 328/0 and HS
  tests 57 passed) is unresolved: no artifact distinguishes which run the
  cache reflects; the owner must supply the full-run log to classify 132.

**(c) Corroborating historical artifacts (older phase, kept for root-cause
pattern concordance):** `d76f/.astra-tools/phase13-full.xml` (80 failed),
`phase13-mutation-full.xml` (90 failed incl. 11 native-mutation),
`audit_current_full.py`-generated `current-full-audit-detailed.json`.
The phase13 classification counts live in the same run's
`docs/astra-verification.json` ("phase13_full_suite") in the
`codex/astra-reliability` worktree (`C:\Users\yingz\.codex\worktrees\d76f`).

### 3.3 What is needed to make the 132-baseline complete

Short of a prohibited OS action, the only honest completion path:
owner/automation copies of the missing `.junitxml` + `-short-summary` log
for the claimed full run, applied once by the test owner (not this task).

---

## 4. Nine-diff approval package (Section C — verification of
`docs/host-supply-integration-diffs.md`)

Source of record stays the committed-line doc itself (2 sections x 9 diffs,
104-line diff text). What this file adds is **line-anchor verification
against the current (dirty) tree + conflict-state refresh**:

| # | Diff (file/function) | Current anchor (verified 2026-10-17) | Dirty parallel work? | Current behavior | Required Host Supply behavior | Security impact | Owner/Conflict | Approval | Regression plan | Rollback |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `security/__init__.py` — exposing already-built scanners on `SecurityContext` | `SecurityContext` @16, scanners built @45 inside `setup_security` → no `scanners` field today | **file now CLEAN** (doc's conflict table said dirty — outdated; re-check before merge) | scanners discarded after setup | scanners reach authorizer (Host Supply Factory wiring) | additive/opt-in; default `()` unchanged | owner needed; conflict cleared | UNAPPROVED | focused security suite + `tests/agents/test_host_supply_wiring.py` | revert field |
| 2 | `system/core.py` — add one host-owned optional field `host_supply` | `mcp_tools` @91, `rate_limiter` @92 = last positional field; host_supply absent | push after @92 | no supply concept on JarvisSystem | field carrier for factory bundle; None = legacy byte-identical | additive | owner needed; dirty | UNAPPROVED | focused system+CLI tests | remove field |
| 3 | `system/builder.py` — build supply once, attach (`build()` after `sec = setup_security(...)`) | `sec = setup_security(config, engine, bus)` @186 | dirty | builder unaware of supply | single build point per process, invalid doc ⇒ fail closed | fail-closed on bad document (additive) | owner needed; dirty | UNAPPROVED | `tests/cli/test_serve_single_build.py` | remove attach |
| 4 | `server/app.py` — server's single supply point (`create_app` derived-security block + `app.state.host_supply`) | derived_security @217..224, `app.state.audit_logger` @307 | dirty | route-layer supply absent | one `load_host_supply_from_env` call for server route objects | default-deny preserved (no state ⇒ no shadow/cloud) | owner needed; dirty | UNAPPROVED | server route tests | remove state field |
| 5 | `server/agent_manager_routes.py` — `_LightweightSystem` carries supply through to executor | `_LightweightSystem` @234, `knowledge_db_path`-block @260 | dirty | facade drops supply | getattr passthrough only | additive | owner needed; dirty | UNAPPROVED | facade wiring test | drop attr |
| 6 | `agents/executor.py` — observation-only hook (`_invoke_agent_impl` around `agent_instance.run`) | `_invoke_agent_impl` @2443, `_t0` @3000, run call @3002/@3015, `model_gate` seam @861–895 already present as bypass hook precedent | dirty (model_gate seam) | executor has no shadow observation | `observe_tick(...)` never raises / dispatches / mutates | zero per policy (observation only) | owner needed; dirty | UNAPPROVED | `tests/agents/test_tick_supply_shadow.py`, `test_host_supply_observe_tick.py` | drop hook |
| 7 | `cli/serve.py` — supply + CloudEngine construction authority | `sec = setup_security` @211, `cloud_engine = CloudEngine()` @229 | dirty | **anonymous** `CloudEngine()` (fail-open flags-check-only today) | supply-registered authorizer/ledger/session_ids wired into CloudEngine kwargs | live egress GAIN (cloud-authorizer becomes host-checkable) — biggest security-relevant diff | owner needed; dirty | UNAPPROVED | cli/serve + engine/cloud contract tests | revert CloudEngine kwargs |
| 8 | `server/routes.py` — cloud engine reload path uses same supply | route handler @1266, `CloudEngine()` @1308 | dirty | reload re-creates anonymous engine | same kwargs as (#7) from `app.state.host_supply` | mirrors #7 | owner needed; dirty | UNAPPROVED | server route test | same |
| 9 | `server/routes.py` @1024 (`stream_cloud` imported from `server/cloud_router`) | call site verified | dirty (nothing to change) | **deliberately NO DIFF** (BLOCKED) — anonymous HTTP route has no host-owned grant; minting one from request payload would make caller its own authorizer | owner-only future decision: per-caller grant source OR restrict route to local engines | default-deny today (`FLAG_OFF`/`NO_GRANT`, engine/cloud.py:508-573 verified) | BLOCKED by design | BLOCKED (roll to cloud plan) | existing `FLAG_OFF/NO_GRANT` tests | none |

`engine/cloud.py` / `engine/ollama.py`: marked **frozen** in the package —
although those files are themselves dirty, **no change for them is planned**
as part of the nine-diff (parallel work is preserved, not commandeered).

Owner consent is required per diff; git history alone is **not** approval
(mission rule F).

---

## 5. Shadow-first release plan (Section D, plan only — DRAFT)

Applies only to diffs the owner approves. Order (mirrors mission; each
step is a merge unit where its tests are run in that phase):

1. **Host Config** — no diff touching config (factory reads env path; step is
   a no-op keeper/acceptance gate).
2. **Host Registry/Snapshot** — covered by existing factory file (frozen).
3. **System Builder Supply** — diff #3 (+ #2 field).
4. **Shadow Observer Wiring** — diff #6 (`observe_tick`, observation-only
   hook), facade passthrough #5 to keep executor reachable in-process.
5. **Shadow OFF parity** — with `shadow_enabled` false, verify byte-equal
   prior behavior (focused + smoke).
6. **Shadow ON observational-only** — `observe_tick` records, never
   intervenes; never rises to Model/Tool Dispatch (explicit non-goal).
7. **CLI/Scheduler/Server coverage** — diffs #1/#4/#7 wiring reach CLI
   (`serve`) and server route surfaces.
8. **Focused regression** — run, not by this task (owner-scheduled).
9. **Full regression** — same.

Guarantees: Shadow never produces a Model/Tool Dispatch; `observe_tick`
is fail-open-inside-no-effect (`never raises`), so connectivity failure
doesn't change tick semantics.

## 6. Cloud release plan (Section E, separate from Shadow — DRAFT)

Ten-component sequence (doc-owned status, independent green-light criteria),
all currently default-deny (`FLAG_OFF` / `NO_GRANT` / `UNKNOWN_OUTCOME`
are preserved): Host Authorizer → Dispatch Ledger → Session Binding →
CloudEngine construction (diffs #7/#8 wiring) → Router stream path (#9
needs owner design decision; blocked) → Provider/Endpoint binding →
Default-deny (unconditionally fail-closed until every upstream grants) →
Retry/Fallback → Streaming → UNKNOWN_OUTCOME surface parity.

**No real cloud send** is performed or scheduled by this plan; the delivery
that wires these is gated by owner approval of each component, with
`UNKNOWN_OUTCOME` preserved end-to-end and streaming kept observational in
shadow.

## 7. Owner / conflict status (Section F)

- All nine diffs: **UNAPPROVED**. Three-way distinction maintained —
  APPROVED only on written owner records (none exist); UNAPPROVED for
  #1–#8 now; #9 BLOCKED by design (needs an owner decision on the grant
  source, not just a signature).
- Git history/commits by previous agents are NOT treated as approval.
- No shared production file has been touched by this task (verified: `git
  status --porcelain` before/after unchanged except this doc).

## 8. Risks (summary)

- R1 Missing 132-failure evidence: the claimed baseline is unverifiable
  until the owner supplies the full-run junit/log (3.3).
- R2 Host Supply module has 2 failing tests in the latest snapshot: claim
  "57 passed" unproven; needs one clean owner-side run that writes junit/log.
- R3 `model_gate` seam precedent proves the executor does have at least one
  bypass-like hook mechanism, but diff #6's hook is inherently observational
  with zero effect, so residual risk is qualitative (low), not eliminable.
- R4 #7/#8 are the only diffs granting real egress authority: single-hunk
  security cliff; verify `FLAG_OFF` fail-closed test before both.
- R5 Native Gates B–F still BLOCKED; do not rely on the doc's own closure
  for physical proofs; each gate needs separately-authorized artifacts.

## 9. Rollback

- Any approved diff can be reverted hunk-by-hunk (additive-only design;
  two new renamed optional fields at worst).
- Freeze manifest rollback = the untracked files ARE their own backup; they
  stay untracked in place and nothing was moved or copied.
- For #1 (now clean): can be applied/reverted cleanly without conflicts;
  revert re-hides scanners (read-only impact, wiring disengages).
- No pipeline-parameter changes beyond diff text; no environment mutation.

## 10. Final verdicts

| Verdict | Result | Basis |
|---|---|---|
| HOST_SUPPLY_FACTORY_READY | **PARTIAL** | 75 statically-collected test functions present & frozen, BUT 2 observations of failure in newest snapshot and no green artifact for "57 passed" |
| FULL_REGRESSION_STATUS | **UNKNOWN** | claimed 10,135/132/143 has no artifact; best verified full-run alternative = 3.2(a) 9,213/78/139 on a prior checkpoint |
| FAILURE_INVENTORY_COMPLETE | **PARTIAL** | 78 rows fully classified (a) + 177-row snapshot (b), but the 132-specific per-test rows remain not derivable |
| NINE_DIFF_PACKAGE_READY | **PASS** | doc verified + all 9 line anchors confirmed in current tree |
| OWNER_APPROVAL_OBTAINED | **BLOCKED** | none |
| SHADOW_LIVE_BOUND | **NOT EXECUTED** | wiring is still unapplied by design |
| CLOUD_EGRESS_BOUND | **BLOCKED** | fail-closed verified in code, real egress stays prohibited |
| HOST_AUTHORITY_PRESERVED | **PASS** | default-deny invariants intact (cloud.py:508-573 verified; no prod change) |
| NATIVE_EXECUTION_DENIED | **PASS** | no native gate execution attempted; gates remain BLOCKED |

---

## 2026-10-17 Shadow-only production wiring (implemented, same worktree)

Change set (owner-directed shadow-only scope, no cloud diffs #7/#8/#9, no engine/cloud.py change):

- `src/openjarvis/system/core.py` — `JarvisSystem.host_supply: Optional[Any] = None` (host-only field; agent/LLM/tool/user input can never set it).
- `src/openjarvis/system/builder.py` — after security setup, `load_host_supply_from_env(capability_policy=sec.capability_policy)` built once and attached via `host_supply=host_supply`. Unconfigured host → None → legacy tick byte-identical; invalid host document → raise (fail closed).
- `src/openjarvis/agents/executor.py` — `_invoke_agent_impl` observes EVERY tick through `observe_tick(...)` when `_system.host_supply` exists: success/failure distinguished (`result`/`error`), never raises, never dispatches.
- `tests/agents/test_shadow_production_tick_e2e.py` — NEW, 11 offline tests over the REAL production tick (`AgentExecutor.execute_tick` + real `JarvisSystem`): OFF parity, agent-field flag inert, ON observation success (SUCCEEDED / no dispatch / no mutation / parity), exactly-once + no added tool dispatch, UNKNOWN-outcome artifacts unchanged, failure observed (per-attempt FAILED + reason class), missing registry & stale snapshot fail closed at construction, snapshot expiry & unknown privacy & supply corruption record codes without stopping the tick, no cloud authorizer exists in shadow mode.

Evidence (JUnit XML + logs, this directory): `.astra-artifacts/shadow-20261017/`

- `host-supply-regression.xml` — 62 passed (host supply suites).
- `shadow-production-e2e.xml` — 39 passed (tick+shadow+observer+wiring).
- `focused-regression.xml` — 441 passed (host routing / privacy pipeline / executor / production tick / UNKNOWN_OUTCOME / exactly-once / egress-guard default-deny incl. cloud, litellm, compat, nim, ollama, router, LLM-tool).
- `full-regression.xml` / `full-regression.log` — full offline lane (`-m "not live and not cloud and not docker and not live_channel and not live_external and not modal and not hub and not nvidia and not amd and not apple"`); result recorded in `evidence.json`.
- `pre_*.py` byte-identical pre-change backups + `shadow-wiring.diff` + `evidence.json` (commands, Python 3.11.9, HEAD d596e482, hashes).

Rollback: copy the three `pre_*` backups back over the working files and delete the new test file; HEAD/dirty state otherwise untouched (no reset/stash/clean executed).
