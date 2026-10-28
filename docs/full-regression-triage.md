# Full Repository Regression Triage Log

Working-tree doc. NOTE: reconstructed on 2026-10-18 after an accidental full-file
overwrite during the goal-to-completion mission (untracked file, author-recovered
from session records; prior byte-level text of updates 1-2 is not recoverable
exactly — the archives under .astra-artifacts/ hold the underlying JUnit/hashes).

## Mission line

- shadow-20261017 stage `mission_2026_10_18d_cloud_closure`: server grant source
  wired (stream_grant.py), route-level streaming E2E, rlm worker fail-closed
  migration, SSE/factory/weather fixture alignment. Regression:
  cloud-closure-regression.xml 390/0, cloud-security-worker-lanes.xml 215/0,
  sanity 34, drift check 100.

## Prior state (updates 1-3, summarized)

- Cluster A (12 rlm_worker nodes) migrated to the fail-closed spawn contract +
  module-level child-side protocol semantics (`_worker_namespace` /
  `_worker_execute`); no fake-native, no skips, no assert weakening; native
  launch semantics remain behind Native Gates B-F (BLOCKED).
- Cluster B (SSE taint rehydration) and the weather boundary-guard tests: the
  production SSE executor reads capability policy from app state
  (agent_manager_routes.py:1363); fixtures supply host-issued policies.
- Cluster C (factory sync): runtime-sync/rate-limiter asserts pass unchanged;
  the 2026-10 rewrite moved the REPL gate to the tool boundary
  (RLM_WORKER_REQUIRED, UNKNOWN_OUTCOME); the stale CAPABILITY_DENIED event
  assertion aligned to the current gate.
- Owner decisions still pending from prior sessions: ledger fail-closed contract
  ratification, router-lane grant source, diffs #1-#9, ownership of the
  environmental/parallel failure inventory.

## 2026-10-18 update 4 — full-repository regression (mission: agent goal-to-completion)

First full-repo run in this mission line: 10,507 collected, safe-subset executed
(marker exclusions: cloud/docker/live/live_channel/live_external/modal/nvidia/
amd/apple/macos15/slow), serial. Run 1: 10,127 passed / 185 failed / 126
skipped (18m25s). Triage of the 185:

1. FIXED — cross-test class-identity pollution via the registry-isolation
   helper in tests/cli/test_serve_single_build.py (reloads every
   openjarvis.agents.* module when the agent registry is empty). The reload
   split the class identity of the host supply authority
   (`HostConfig`/`HostEgressPolicy`) — HOST_CONFIG_MISSING on every cloud
   wiring / cloud streaming authority / multi-provider / stream route grant /
   builder shadow runtime / server shadow binding test that binds the class at
   collection time. Fixed by extending the helper's existing identity
   exemption list (the same pattern the owner already used for rlm_rpc /
   capability_router / rlm_worker) with `openjarvis.agents.host_supply_factory`
   and `openjarvis.agents.host_routing`. Reproduction: cli + cloud wiring in
   one process = 17 failed; after fix = 40/40 across cli + builder shadow +
   cloud wiring + server shadow binding.
2. FIXED — tests/security/test_taint_propagation.py fixture alignment: the
   executor precondition requires a host-issued capability policy (the
   production SSE executor already reads it from app state); the fake tools
   now carry one. 7/7 standalone.
3. ENVIRONMENTAL (run-time fix, no code change) — `UnicodeDecodeError cp932`
   across deployment/packaging/release/docs/evals-report tests: Windows
   Japanese locale default-encodes UTF-8 text files. Rerun with PYTHONUTF8=1
   heals them (60/63 in the deployment+deploy group; the remaining 3 are
   platform-specific subprocess/path expectations, see 4).
4. ENVIRONMENTAL UNFIXED (recorded): Windows desktop probes
   (test_windows_mutation 17, test_windows_managed_phase3c 19,
   test_windows_real_app 9 — need an interactive desktop/AppContainer),
   test_energy_rapl 5 (no Intel RAPL here), test_appcontainer_sandbox 3
   (native gate), model_convert WinError 1314 (symlink privilege) + backend
   claim diff, render_blueprint WinError 193 (POSIX-style subprocess lines),
   apple_calendar ValueError format strings (macOS codes), whatsapp channel
   node bridge binary missing, cli chat/scan platform expectations, install
   bg_state model-download status dict (network state reader), sdist path
   separator expectation.
5. PARALLEL-ZONE (not mine): tests/agents/test_native_openhands.py 3
   (TOOL_CALL_START event missing mid-run; tool-prompt direct path and
   expanded-url assertions fail standalone), evals display path coloring.

Post-fix focused evidence (before rerun): agent-goal-ecosystem.xml (167 passed /
2 pre-existing designed-not-implemented replan-adapter skips), goal E2E 5/5,
route grant E2E 18/18 (incl. the new principal/body spoofing test).

## 2026-10-18 update 5 — rerun triage + agent goal-to-completion fixes

Rerun (PYTHONUTF8=1, same marker exclusions, serial): 10,254 passed / 64 failed /
126 skipped / 74 deselected (18m01s). All 64 triaged; 28 of them healed by the
fixes below.

1. FIXED (executor, src): `_run_with_retries` persisted `retry_count` across
   ticks and never reset it on success, so any long-horizon plan died on the
   4th successful tick with FatalError("managed agent attempt budget
   exhausted"). The design contract (docs/astra-run-report.md) states a
   *per-tick* three-attempt budget; a non-recovery success now resets the
   window (`retry_count=0`, `retry_history=[]`) while INTERRUPTED-restart
   persistence keeps its bound. Two owner tests that had cemented the leftover
   count were retargeted (calls/status/message assertions kept). Agent battery
   93/93 (executor/resume/budget/goal/safe-e2e/replan/materialization).
2. FIXED (root cause of cross-suite pollution): tests/cli/test_serve_single_build.py
   `_repopulate_registries()` reloaded EVERY `openjarvis.agents.*` /
   `openjarvis.tools.*` module while a registry was empty. Reloading a
   non-registrant module re-executes its top level against the shared module
   dict: class identities shift and module-level caches reset, breaking every
   test module that bound those classes at collection time. Repro: serve tests
   + phase3c + privacy conformance in one process = 19 failed; the same files
   standalone = 51 passed / 2 passed. Pristine-worktree check (temp checkout
   of d596e482) ran the whole affected set 103 passed / 1 skipped, ruling out
   machine environment. Fix: reload only modules whose source contains
   `Registry.register` (`_contains_registrations` helper); the existing
   explicit identity exemptions (rlm_rpc/capability_router/rlm_worker/
   host_supply_factory/host_routing) stay. After: serve + phase3c + privacy
   combo = 66 passed / 1 skipped.
3. FIXED (host-authority fixture class for the uncommitted gate contract):
   tests/agents/test_native_openhands.py (3) — URL expansion goes through
   `execute_secured_tool(WebSearchTool)` (network:fetch, is_local=False) and
   the code_interpreter path is pinned to code:execute by the canonical
   tool-capability floor; the three affected agents now carry a host-issued
   policy. 32/32.
4. FIXED (same class, CLI/integration fixtures): tests/cli/test_chat_cmd.py (1,
   legacy confirmation test now patches setup_security with a policy granting
   code:execute; 47/47 with ask), tests/cli/test_ask_agent.py (1, discovered
   skills are model-invocable composition so the step executor needs a host
   policy even with guardrails disabled), tests/integration/test_integration_extended.py
   (1, code_interpreter fixture), tests/security/test_builder_skill_identity.py
   (1, builder forwards sec.scanners to the host supply factory; fixture
   namespace extended). All standalone green (3/3, 1/1).
5. FIXED (mock drift vs uncommitted code): tests/cli/test_channel_cmd.py
   `_patch_channel` used a bare MagicMock config; the uncommitted channel_send
   builds `CapabilityPolicy(policy_path=cfg.security.capabilities.policy_path)`
   and a MagicMock path raised FileNotFoundError. Mock config now mirrors the
   default (`cfg.security.capabilities.enabled = False`). 7/7.
6. REMAINING after the fixes (recorded; pre-existing environment/platform
   classes or parallel in-flight work, most already classified in
   docs/astra-phase12/13 audits with baseline reproduction):
   - tests/engine/test_openai_compat_tools.py 5 — dirty parallel zone
     (engine + test + new tests/engine/_compat_auth.py all modified); mock
     localhost vs OllamaEngine._DEFAULT_HOST 127.0.0.1.
   - tests/security/test_appcontainer_sandbox.py 3 — untracked parallel WIP;
     native gate closed (RLM_SANDBOX_NOT_AUTHORIZED is the designed posture).
   - bg_state 5 / chat_banner 1 / doctor_bg 1 — NTFS colon-in-filename fixture
     (TEST_HOME_ONLY_FIXTURE_ON_WINDOWS).
   - apple_calendar 4, energy_rapl 5, model_convert 3, render_blueprint 2,
     deployment packaging 1, evals display 1, persona_scope 1, recipes 1,
     version_history 1, cli scan 1, whatsapp channel bridge 1 — phase12/13
     audit classes (macOS strftime, Linux sysfs, WinError 1314/193,
     cp932/excludes, path separators, node bridge launch).
   - phase3c 17 + ollama privacy conformance 2 — full-run-only order effects,
     root-caused to item 2 and fixed with it.

Focused battery after the fixes: tests/cli + cloud wiring/streaming/multi-
provider + stream route grant + server/builder shadow + phase3c + privacy =
808 passed / 3 failed (model_convert x2 WinError 1314, scan x1 platform
mismatch — both pre-existing environment classes).

## 2026-10-18 update 6 — final full run

Final full run (same exclusions, serial, fresh tree incl. all update-5 fixes):
10,445 tests — **10,265 passed / 54 failed / 0 errors / 126 skipped / 74
deselected (16m18s)**. Goal E2E re-confirmed 6/6 (goal-e2e-confirm.xml).

Healed vs rerun (64 -> 54, and 28 nodes healed): phase3c 17 + privacy
conformance 2 (serve reload root cause), native_openhands 3, channel_cmd 2,
chat_cmd 1, ask_agent 1, integration_extended 1, builder_skill_identity 1.

Residual 54, all classified (evidence.json "final_residual_54"):

1. FOREGROUND-SESSION 18 — test_windows_mutation 17 + foreground probe 1:
   "Test-owned fixture foreground setup failed: count 0". The fixture needs a
   Win32 AllowSetForegroundWindow/SetForegroundWindow grant, which depends on
   live desktop state (another app owning the foreground blocks the handoff).
   Flips across runs: RUN1 fail / RERUN pass / FINAL fail; matches the prior
   audit class TEST_FIXTURE_FOREGROUND_SETUP_AFTER_FULL_COLLECTION (baseline
   FAILED). Not code-dependent; not introduced by this mission (RUN1 predates
   it). tests/security/real_app_fixture.py is parallel-dirty — owner's call
   whether the fixture should skip/retry when the desktop refuses the grant.
2. PARALLEL-DIRTY-WIP 8 — openai_compat_tools 5 (engine + test + new
   tests/engine/_compat_auth.py mid-flight) + appcontainer 3 (untracked WIP,
   native gate closed by design).
3. NTFS-COLON-FIXTURE 7 — bg_state 5 + chat_banner 1 + doctor_bg 1.
4. PLATFORM/ENV 21 — energy_rapl 5, apple_calendar 4, model_convert 3,
   render_blueprint 2, packaging 1, evals display 1, persona_scope 1,
   compose 1, version_history 1, whatsapp bridge 1, cli scan 1.

Zero unclassified failures. Zero failures in the mission lanes (goal E2E /
executor / routes / serve / phase3c / privacy). Evidence and per-file hashes:
.astra-artifacts\shadow-20261018\evidence.json +
post-hashes-agent-goal-final.txt.
