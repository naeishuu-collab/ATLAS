# Phase 14 — explicit safe replanning and trace privacy

Continued `cec283d8` / full-suite audit checkpoint `4da954d5`. Production mutation
dispatch, native identity and durable journal semantics are unchanged. Mark1 and
Windows security configuration were not touched. This remains a trusted
cooperative Win32 fixture path, not arbitrary desktop automation or live LLM
decision-making.

## Actual path and contract

NativeReActAgent → existing ToolExecutor confirmation/capability/journal gates →
WindowsObserveTool / WindowsActionTool → WindowsActionSession → UIA owner worker
and application GUI-thread receiver. After a **NOT_STARTED** stale rejection,
the scripted agent explicitly requests a new observation and a new action with
different observation/target IDs and a new confirmation. The receiver's control
birth cookie also differs. No action call silently resolves a replacement.

The native positive case replaces T1, proves zero clicks after the old action,
observes T2, explicitly authorizes it, dispatches once and independently verifies
counter 0→1 and the event's process/window/control cookie. The negative recovery
case produces duplicate candidates in the fresh observation, returns
AMBIGUOUS_TARGET and stops with zero clicks.

The existing native lost-acknowledgement test now reopens the durable journal,
obtains fresh valid observation/target IDs and attempts a new call. The journal
still blocks it as UNKNOWN_OUTCOME/non-retryable; the independently read counter
and event list remain exactly one. Fresh observation is not reconciliation.

## Privacy evidence and implementation

A canary reproduction on `cec283d8` proved that tool arguments were redacted but
inference content and `AgentResult.metadata.messages` retained the requested
value. TraceCollector persisted those copies in TraceStore's SQLite rows.

TraceCollector now omits raw query/response/conversation/model payloads when the
agent exposes a tool declaring sensitive parameters. Arbitrary prose and malformed
JSON can repeat values, so this does not depend on parsing a model response to
guess which fragments are secret. Structured tool argument events remain
redacted by the existing executor; action identities/outcomes, call IDs,
verification evidence and timing remain available. The trace records the omission
policy explicitly. Ordinary agents without sensitive tools retain their rich
traces; existing calculator/content/history tests remain unchanged.

Live model messages, actual dispatch values and concrete confirmation prompts
remain intact. **Raw inference EventBus payloads and other telemetry consumers
are not covered by this repair. Structured arbitrary tool metadata is not
claimed secret-free.** No real secrets were used. This is not a universal logging
privacy claim.

Native typing through the real agent/executor/receiver/UIA path proves one edit
notification and the exact independently read value, while TraceStore and
TRACE_COMPLETE contain no fixture canary. Scripted engine only.

## Fixture activation diagnosis

The unrestricted Phase 13 run checked foreground before several minutes of
collection. The harness now checks after collection and offers manual-only
activation, with a unique main-window title. Foreground-dependent tests precede
other fixture lifecycle tests. Agent modules preload before activation; moving
that preload into the collection-finish hook avoids importing pytest plugin
dependencies before assertion rewriting is configured.

Fixture WM_ACTIVATE/WM_ACTIVATEAPP history is bounded to 128 entries, separate
from the physical action counter. This observes activation, never acquires focus.
Click replacement/replanning setup keeps focus on a surviving edit; click's
production contract requires root foreground, not Button focus.

Unsuccessful combined batches are retained, not replaced with successful
focused counts: **11 passed / 9 failed / 0 skipped / 0 warnings** (186.46s),
**8 / 12 / 0 / 0** (19.92s), and **14 / 6 / 0 / 0** (145.04s). Most failures
stopped in foreground setup with count zero; one late-recreation case rejected
before the injected receiver boundary after foreground changed. Recorded
external foreground HWND 852064 belongs to ChatGPT.exe; HWND 67810 was also
observed. No user-app controls were read or mutated. A cause for every foreground
transition is not established; no focus restriction was bypassed.

## Executed evidence

Counts overlap; do not add them. Python 3.11,
`PYTHONPATH=src;.venv/Lib/site-packages`.

| Lane | Passed | Failed | Skipped | Warnings | Seconds |
| --- | ---: | ---: | ---: | ---: | ---: |
| Trace canaries + existing collector + Windows boundary | 25 | 0 | 0 | 0 | 3.08 |
| Agents/tools/traces + action contracts/capabilities/guardrails/identity | 1844 | 0 | 23 | 0 | 146.67 |
| Native agent/recovery/quarantine/privacy | 5 | 0 | 0 | 1 | 119.60 |
| Privacy compatibility repair + streaming boundary | 26 | 0 | 0 | 3 | 4.25 |
| Final broad agents/tools/server/security/credentials/traces | 2820 | 0 | 68 | 271 | 244.62 |

Native lane also had **15 deselected**, not skipped. Its runtime includes genuine
foreground activation waiting; the five test cases took only a few seconds.
The warning was `PytestAssertRewriteWarning` for pre-imported anyio; it is retained
in this result. The later preload-location repair is not relabeled as an executed
zero-warning native result.

Native command:
`python -m scripts.astra_windows_mutation_e2e --manual-activation --activation-timeout 600 tests/security/test_windows_mutation.py -k 'real_agent or lost_acknowledgement' -q --junitxml=.astra-tools/phase14-native-agent.xml`.

The first broad run was **2819 passed / 1 failed / 68 skipped / 271 warnings**,
245.88s. The new optional sensitivity lookup incorrectly assumed every agent
`_tools` entry had a ToolSpec. A server streaming fixture legitimately uses a
marker object. The production lookup now tolerates absent optional metadata;
the original streaming assertion was preserved. Focused repair and final broad
results are above. Native five-case evidence precedes that optional-metadata
repair and preload-hook relocation; neither changes the Windows ToolSpec or
physical dispatch contract. The complete 20-case native file was not rerun after
the final fixture setup repairs; its earlier failures remain recorded above.

Broad command:
`python -m pytest tests/agents tests/tools tests/server tests/security tests/core/test_utils.py tests/core/test_credentials.py tests/traces --ignore=tests/security/test_windows_mutation.py -m 'not live and not cloud and not hub and not modal and not live_external and not live_channel' -q --junitxml=.astra-tools/phase14-broad-final.xml`.
Native mutation file is excluded from broad and separately exercised above.

**Full suite: NOT EXECUTED** for Phase 14. The separate unrestricted
`cec283d8` result remains **8970/90/139/291**, with its own failure audit.
**Real App E2E: NOT EXECUTED. HWND reuse negative E2E: NOT REPRODUCED.**

## Files, checkpoint and next dependency

Production: `traces/collector.py`, Windows tool descriptions. Tests:
`tests/traces/test_sensitive_tools.py`, native mutation tests and fixture
activation diagnostics. Harness: post-collection activation, explicit manual
mode, ordering/preload setup. No new GUI framework, dependencies, mutation API or
quarantine store. Revert the Phase 14 commit to restore Phase 13 behavior; no
machine policy rollback is necessary.

The next observed gap is execution trace completion when an existing quarantine
rejects a new call: ToolExecutor emits TOOL_CALL_START, then returns before
TOOL_CALL_END. The blocked agent result is structured and safety still holds,
but the attempted call disappears from TraceCollector. Reproduce and repair
that event boundary without changing mutation/quarantine behavior. Broader
real-app adapters, automatic focus/recovery, live-model decisions and raw-event
privacy remain unverified and gated. **NOT PRODUCTION READY.**
