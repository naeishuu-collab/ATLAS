# Phase 13 — cooperative Windows safe mutation, 2026-10-04

**VERIFIED for the narrow cooperative Win32 fixture contract. Not production
ready or arbitrary desktop automation.** Counts below are separate overlapping
test lanes; never add them. The complete report follows the requested 30 items.

1. **Production integrity.** Continued actual Astra/OpenJarvis; no Mark1 source,
   imports or data were inspected or modified. Existing identity, outcome,
   journal, browser, REPL, process, ACL and trace foundations remain intact.
2. **Starting checkpoint.** Clean `f887719e`, `codex/astra-reliability`. Native
   CPython 3.11 AMD64 extension SHA256 remains
   `8fb8e5421e8a33a282ae14550fb48b520aa75840bbe4c0d20df8bb6b46abb824`,
   identical to this checkout's Rust debug DLL; no Rust source changes or rebuild.
3. **Actual Windows execution path.** The pre-change audit is
   [astra-phase13-mutation-path.md](astra-phase13-mutation-path.md).
   Registry → WindowsObserve/WindowsAction → existing ToolExecutor gates/journal
   → WindowsActionSession → terminable UIA owner worker → inherited bounded
   fixture IPC → consenting application's GUI-owner receiver → one native
   control dispatch → new UIA observation → verification → structured ToolResult
   → NativeReAct tool observation / EventBus / TraceCollector.
4. **Identity contract.** PID + creation FILETIME + image path; root HWND,
   thread/class and observed epoch; retained UIA element, RuntimeId, native HWND,
   AutomationId/type/class/framework/hierarchy; application window/control birth
   cookies, native lifetime properties and state revision. Name is a hint only.
   Private deep copies prevent returned observations from rewriting authority.
   No first match, automatic target replacement or observation reuse.
5. **Files changed.** Production: `windows/actions.py`, `receiver.py`,
   `identity.py`, `native.py`, `observer.py`; `tools/windows.py`, `_stubs.py`,
   `__init__.py`; `security/capabilities.py`. Tests: Windows mutation fixture,
   `test_windows_mutation.py`, `test_windows_action_contract.py`,
   `test_windows_boundary.py`, capability enum inventory. Harness:
   `scripts/astra_windows_mutation_e2e.py`. Audit/report/verification documents.
6. **Fixture design.** Test-owned spawned ctypes Win32 process with ordinary
   EDIT/BUTTON/STATIC controls: 101 input, 201 action, 203/204 duplicates, 301
   counter, 302 result. GUI-thread notification records PID/root/control/cookies.
   A separate RPC reads actual state. Setup/reset/replacement/focus/cleanup occur
   outside each measured click/text interval. Message-aware waiting services
   synchronous UIA reads; no large GUI framework or user data.
7. **Positive mutation E2E.** Click dispatches BM_CLICK once; independent UIA
   Counter/Result reads and separate event-route state prove one activation.
   ASCII and Unicode edit replacements each dispatch WM_SETTEXT once and verify
   fresh ValuePattern state plus one GUI change notification. Old authorization
   replay is rejected without another mutation.
8. **Wrong-foreground E2E.** Click and text both executed with separate fixture
   B proven foreground. A/B click/change counts remain zero, texts unchanged,
   B still foreground; structured WRONG_FOREGROUND, non-retryable rejection.
9. **Cross-process E2E.** A's observed control is replaced; separate B exposes
   matching semantics with a different native process identity. Old target fails
   closed; both process action counters remain zero.
10. **Ambiguous-target E2E.** Two same-name/type native controls produce two
    candidates. Resolve rejects ambiguity, invalidates authority and never picks
    the first; no action reaches the fixture.
11. **Stale-target E2E.** T1 destroyed and same-AutomationId T2 created with a
    different birth cookie. Old target rejects; T2 receives zero actions.
12. **Window-recreation E2E.** Same process, new root/control lifetimes. Old
    observation does not authorize the recreated window; zero actions.
13. **Process-restart E2E.** Old process terminated and joined; same executable
    restarted with a different creation lifetime. Old identity rejects; restarted
    process counter remains zero. PID alone is never sufficient.
14. **HWND-reuse status.** **HWND reuse negative E2E: NOT REPRODUCED.** A bounded
    64-replacement native probe recorded different numeric handles, new cookies,
    zero clicks and old-target rejection. Its passing probe is not a fabricated
    pass for actual numeric reuse. Native lifetime properties/cookies and retained
    process/UIA evidence protect beyond HWND equality; no permanent HWND identity.
15. **Focus safety.** Production actions never acquire focus. Foreground is
    required and checked before dispatch and again inside the GUI receiver.
    Typing requires GUI-thread GetFocus to equal the registered edit. Wrong
    control focus rejects with FOCUS_FAILURE and zero changes. Fixture-only
    supported scoped foreground grants never target user apps or ASFW_ANY.
16. **Type safety.** Exact standard-edit value replacement, not global keyboard
    injection. Native lifetime, foreground, enabled/visibility and exact control
    focus are mandatory. ValuePattern is read anew after dispatch; password or
    unsupported verification is refused. NUL/oversized/non-string values reject.
17. **Exactly-once status.** Verified for these cooperative BM_CLICK/WM_SETTEXT
    paths and measured intervals. Authority consumed before transport; GUI owner
    compares identity/revision before one dispatch without an intervening pump.
    This is not a universal exactly-once claim for arbitrary UIA providers.
18. **Unknown-outcome status.** Real click occurred once, then acknowledgement
    loss was injected. Outcome remains UNKNOWN_OUTCOME / POSSIBLE / NOT_VERIFIED.
    Reopened existing durable journal blocks a new call ID, counter still one.
    No competing quarantine, expiration or physical retry was introduced.
19. **Result boundary.** Real native fixture through NativeReAct → ToolExecutor
    → journal → tools → UIA → receiver → agent JSON observation → trace passes.
    Scripted engine, not live LLM inference. Unit boundary tests cover verified
    success, safe identity rejection, unknown outcome, pre-dispatch retryable
    capacity exhaustion, confirmation, unbound defaults and capability denial.
20. **Traceability.** Observation/target/call IDs, native/UIA identity, receiver
    cookies/revision, preconditions, dispatch, verification and post-observation
    evidence remain structured. Typed values are hashed in verification evidence
    and redacted in tool argument events/metadata. Confirmation still displays
    the concrete requested value. Existing full conversation/inference tracing
    is not claimed secret-free; no real secrets were used in these fixtures.
21. **Focused tests.** Final native gate: **17 / 0 / 0 / 0**
    passed/failed/skipped/warnings, 20.94s. Controller + result boundary:
    **23 / 0 / 0 / 0**, 2.08s. Capability/boundary lane:
    **39 / 0 / 0 / 0**, 3.94s (before final metadata-only additions).
22. **Negative tests.** Native gate includes all six required negative
    boundaries, both wrong-foreground actions, exact edit focus and three
    validation-to-dispatch races. The separate earlier identity-negative lane
    was **5 / 0 / 0 / 0**, 6.30s; HWND probe **1 / 0 / 0 / 0**, 2.00s. Overlap.
23. **Regression.** Foundations lane **103 / 0 / 0 / 0**, 39.43s, before final
    metadata additions. Broad agents/tools/server/security/credentials/traces:
    **2817 / 0 / 68 / 271**, 269.68s, before final metadata additions. Native
    mutation file was explicitly excluded from broad and tested separately.
    Historical live/cloud/hub/modal/external/channel marker exclusions retained.
24. **Full-suite status.** **Full suite: EXECUTED** on `cec283d8`:
    **8970 passed / 90 failed / 139 skipped / 291 warnings**, zero errors,
    924.00s. [Failure audit](astra-phase13-mutation-full-audit.json): 79 failures
    match the saved baseline; the repaired DNS fixture passes. Eleven new native
    fixture tests failed in foreground setup before dispatch (actual count zero,
    external foreground HWND 67810, supported activation/grant both denied).
    This run's native group is **6 passed / 11 failed / 0 skipped**. Full
    collection started several minutes after the harness's activation check,
    exceeding the requested 60-second foreground interval. The separate final
    native gate remains **17/0/0/0**; it is not substituted into the full count.
    Older 8937/80/139/291 results remain historical pre-DNS-repair evidence.
25. **Real-application E2E.** **Real App E2E: NOT EXECUTED.** Cooperative fixture
    evidence does not authorize arbitrary user applications; no external app
    adapter/cleanup contract is available.
26. **Security status.** No Defender/SAC/WDAC/AppLocker/execution-policy/ACL
    weakening or broad exclusion. Canonical desktop:observe and desktop:mutate
    floors added; mutation needs both. Observation grant alone cannot dispatch.
    Default tool sessions are unbound and fail closed; confirmation retained.
27. **Known limitations.** Cooperative trusted receivers only; arbitrary,
    elevated/custom/malicious providers and universal external action atomicity
    are unproven. Foreground lifetime changes need explicit fixture setup, not
    production refocusing. Older SAC 4551 rejection/later admission is unexplained.
    Earlier Rust symlink privilege failures and unrelated full failures remain
    historical limitations, not repaired or hidden here.
28. **Production readiness.** **NOT PRODUCTION READY.** This proves a limited
    real Win32 mutation boundary, not broad autonomous desktop workflows.
29. **Checkpoint.** `cec283d884128bf703e37fe5f7b714f26dd528ec` (`cec283d8`).
    Full-suite audit is recorded in the following metadata checkpoint. Rollback: revert the
    Phase 13 commit to restore observation-only registration without changing OS
    policy; `f887719e` remains the pre-mutation checkpoint.
30. **Next highest-value phase.** Safe explicit re-observation/replanning after
    proven NOT_STARTED stale rejection, with fresh target identity and fresh
    authorization. Unknown outcomes must remain blocked even after fresh
    observation. Strengthen agent trace privacy before handling real user values.

## Commands and failed-attempt evidence

Environment for all commands: signed Python 3.11, `PYTHONPATH=src;.venv/Lib/site-packages`.

Final gate:
`python -m scripts.astra_windows_mutation_e2e --activation-timeout 300 tests/security/test_windows_mutation.py -q --junitxml=.astra-tools/mutation-gate-final.xml`.
The harness runs lifecycle-destructive cases last, after foreground-dependent
cases, with the same assertions and no skipped cases. No production focus path.

Broad:
`python -m pytest tests/agents tests/tools tests/server tests/security tests/core/test_utils.py tests/core/test_credentials.py tests/traces --ignore=tests/security/test_windows_mutation.py -m 'not live and not cloud and not hub and not modal and not live_external and not live_channel' -q --junitxml=.astra-tools/mutation-broad-final.xml`.

Unrestricted full suite at `cec283d8`:
`python -m scripts.astra_windows_mutation_e2e --fixture-first --activation-timeout 300 -q --junitxml=.astra-tools/phase13-mutation-full.xml`.
No marker/file exclusions; native mutation tests reordered first, lifecycle
negatives last, all assertions retained. Full collection follows the original
activation check; the next harness revision moves that check after collection.

Early logs are retained in ignored `.astra-tools`: 1-pass/14-fail, 5-pass/10-fail,
9-pass/6-fail and 11-pass/6-fail live batches. Failures rejected foreground changes
or setup focus; the first ASCII typing setup also invalidated captured identity
after a focus transition. Focus is now arranged before typing observation.
Fixture IPC-only polling was corrected to a native message-aware wait, reducing
five identity-negative tests from 42.34s to 6.30s. These repairs change fixture
setup/ordering, never identity assertions or physical dispatch requirements.
Earlier broad **2813 passed, 1 failed, 68 skipped, 271 warnings** exposed missing
canonical Windows capability entries; the production inventory was repaired and
the exact enum assertion expanded for the two new capability labels.
