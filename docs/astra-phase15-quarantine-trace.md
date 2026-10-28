# Phase 15 — complete traces for safe quarantine rejection

Starting checkpoint `7eb95fea`. This is an execution/observability repair, not an
additional Windows physical action or a competing quarantine mechanism.

## Inspect → reproduce → trace

Actual path: NativeReAct/tool invocation → ToolExecutor.execute → `_execute` →
TOOL_CALL_START → mutation guard / ExecutionJournal.reserve → early ToolResult
return → execute's default outcome adapter. All three guard-return branches
bypassed the shared TOOL_CALL_END block. TraceCollector therefore never created
the attempted call's step, despite structured rejection reaching the executor.

A simulated Windows endpoint through the real executor reproduced:

```text
endpoint calls: 1
blocked state: UNKNOWN_OUTCOME
start IDs: original, blocked-new
end IDs: original
trace steps: 1
```

Three new fault tests reproduced the same defect for in-memory quarantine,
reopened durable quarantine and unavailable journal: **0 passed / 3 failed /
0 skipped / 0 warnings**, 4.22s. They failed on mismatched start/end request IDs.
No GUI or physical mutation evidence is claimed for these simulations.

## Minimal repair and contract

The normal and rejected paths share the existing end-event serializer. A
post-start guard rejection now includes redacted arguments, measured guard
latency, `request_call_id`, and `request_dispatch=NOT_DISPATCHED`. It preserves
the original unresolved outcome and call ID for in-memory quarantine; the new
request fields identify the rejected attempt separately. Zero dispatch of the
new request does not assert that the original mutation never occurred.

Mutation-state lookup/reservation remains atomic under the existing lock. The
new end event is published **after releasing** that lock, because EventBus
subscribers run synchronously. Tests verify the lock is available to the end
subscriber. Existing durable reservations are not released/reconciled, no
expiration/retry/recovery is added, and the receiver is not called for a blocked
request. Confirmation/capability gates and concrete prompts are unchanged.

Files: `src/openjarvis/tools/_stubs.py`,
`tests/tools/test_quarantine_trace_completion.py`, reports/verification metadata.
No Mark1 access, native rebuild, system security/ACL changes or new dependencies.

## Verification

Focused execution journal/outcomes, Windows tool boundary and traces:
**95 passed / 0 failed / 0 skipped / 0 warnings**, 4.69s. The new tests additionally
prove endpoint call count 1 for unresolved original mutations, 0 for journal
unavailability, unchanged durable pending reservation, fresh target IDs in the
trace, value redaction, nonnegative latency, and one matching end per start.

Command:
`python -m pytest tests/tools/test_quarantine_trace_completion.py tests/tools/test_execution_journal.py tests/tools/test_execution_outcomes.py tests/tools/test_windows_boundary.py tests/traces -q --junitxml=.astra-tools/phase15-focused.xml`.

Broad agents/tools/server/security/credentials/traces: **2823 passed / 0 failed /
68 skipped / 271 warnings**, 262.33s. Native mutation file is explicitly excluded
and not relabeled as tested by this lane. Test lanes overlap; do not add counts.

Broad command:
`python -m pytest tests/agents tests/tools tests/server tests/security tests/core/test_utils.py tests/core/test_credentials.py tests/traces --ignore=tests/security/test_windows_mutation.py -m 'not live and not cloud and not hub and not modal and not live_external and not live_channel' -q --junitxml=.astra-tools/phase15-broad.xml`.

The original probe after the repair records end IDs `original, blocked-new`,
two trace steps and the unchanged single simulated endpoint call.

**Full suite: NOT EXECUTED** for Phase 15. **New physical Windows E2E after this
event-only change: NOT EXECUTED.** Phase 14's five native cases remain separate
prior evidence, and Phase 13's full `cec283d8` run remains 8970/90/139/291.
**Real App E2E: NOT EXECUTED. HWND reuse negative E2E: NOT REPRODUCED.**

## Limits and next dependency

This repairs the three reproduced post-start mutation-guard exits, not every
possible executor/agent event failure or concurrent trace correlation. Native
foreground transitions remain incompletely understood; mutation still requires
verified foreground and default Windows tool instances remain unbound. Smart App
Control's historical 4551 rejection/later admission remains unexplained. Raw
inference event privacy, live-model replanning, arbitrary app adapters, focus
acquisition and uncertain-outcome reconciliation remain unverified/gated.

Next useful safety audit: typing verification capability must be established
before dispatch. The current native value getter refuses password controls, but
the controller currently calls it after WM_SETTEXT. Reproduce with benign,
test-owned controls before extending typing; do not infer a safe capability from
class/Name alone. Any late capability change must also reject on the GUI owner
thread. No password/read-only production behavior is newly claimed here.

Rollback: revert the Phase 15 commit; the durable journal and prior physical
mutation boundary are unchanged. **NOT PRODUCTION READY.**
