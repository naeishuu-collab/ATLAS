# Phase 16 — typing verification capability before dispatch

Starting checkpoint: `eeee5848` (Phase 15 quarantine-trace completion). This
phase audited the existing cooperative Win32 `type_into` path before adding any
new desktop action. No JARVIS Mark1 files were inspected or used, and no
Windows security policy or ACL was changed.

## Actual path and contract

The production path is:

```text
NativeReActAgent
  → WindowsObserveTool
  → WindowsActionTool
  → WindowsActionSession.act
  → WindowsObserver.validate
  → IdentitySession / NativeBackend
  → cooperative GuardedWin32Receiver.dispatch on the GUI owner thread
  → one WM_SETTEXT
  → fresh UIA observation and read_value verification
```

`NativeBackend.value_capability` now establishes a bounded independent
readback capability for an Edit control before a type action is authorized. It
rejects password elements, checks the native `ES_PASSWORD` style when a native
HWND is available, and requires a readable ValuePattern value of at most 4096
characters. The capability is retained as `value_verifiable` in the observation
and is checked again during the pre-action validation. A missing or uncertain
capability fails closed as `UNSUPPORTED_CONTROL`; no physical setter is sent.

The receiver performs the final safety check on its own GUI owner thread,
immediately before focus and `WM_SETTEXT`. It reads the live Win32 style and
rejects `ES_PASSWORD` and `ES_READONLY`. The style is deliberately treated as a
live mutation precondition, not as permanent HWND identity, so existing
observation before/after identity comparisons remain stable. A style change
after observation therefore cannot silently become a writable target.

After a successful setter, the existing fresh UIA observation and independent
ValuePattern readback remain mandatory. A readback failure still becomes
`UNKNOWN_OUTCOME`; it never authorizes a blind replay.

## Fixture and tests

The existing test-owned Win32 fixture gained only an owned `edit_mode` setup
command. It can set `ES_PASSWORD` or `ES_READONLY` on control `101` and resets
the style before each measured case. It records independent text and mutation
events; no user application or arbitrary desktop window is used.

Final focused unit/observer/action-contract lane:

```text
75 passed / 0 failed / 0 skipped / 0 warnings, 37.59s
```

Final fixture typing lane:

```text
normal ASCII + Unicode type_into: 2 passed / 0 failed / 0 skipped / 0 warnings
password + readonly + late-readonly capability rejection: 3 passed / 0 failed / 0 skipped / 0 warnings
scripted NativeReAct typing and trace privacy: 1 passed / 0 failed / 0 skipped / 0 warnings
```

The two successful type cases each independently observed the intended fixture
value and one physical mutation event. The three rejection cases independently
read zero mutation events and an empty edit value. The agent case propagated the
verified result through `WindowsObserveTool`, `WindowsActionTool`,
`ToolExecutor`, UIA and the trace store; the canary was absent from persisted
trace copies.

The initial phase execution used the owned fixture harness in manual-only
foreground mode and waited for genuine title-bar activation after collection.
The independent revalidation below used a scoped foreground grant only for the
test-owned process; neither method changed OS security policy.

## Independent revalidation, 2026-10-04

This continuation reran the pending source changes from the active
`codex/astra-reliability` worktree. The identity/action-contract lane completed
**49 passed**. The selected fixture lane completed **8 passed, 15 deselected**
and included successful ASCII/Unicode typing, password/readonly/late-readonly
refusal, focus refusal and scripted Agent trace verification. The complete
Windows ACL/identity/observer/mutation/boundary lane completed **108 passed**
in 75.50s.

The first complete Windows lane had **107 passed, 1 failed**. The failing
positive-click test observed the fixture while it was inactive, then foregrounded
it; the observer detected the resulting generation change and rejected dispatch
with `IDENTITY_MISMATCH`, with zero physical mutations. The fixture now
foregrounds its own test window before taking the fresh observation and
resolving the target. The isolated test and full Windows lane then passed. The
fixture uses a scoped foreground grant for its own process; no user application,
security policy, or ACL was changed.

## Regression and limits

The broad non-mutation lane (the native fixture mutation file remains excluded
and separately exercised) completed:

```text
2825 passed / 0 failed / 68 skipped / 271 warnings, 245.18s
```

The frozen Phase 13 full run remains separate evidence at
`8970 passed / 90 failed / 139 skipped / 291 warnings`; it is not a Phase 16
result. Real-application E2E remains **NOT EXECUTED**. HWND reuse remains
`NOT REPRODUCED` in the existing bounded fixture probe.

The unrestricted suite was subsequently executed from this worktree with
`uv run python -m pytest -q --junitxml=.astra-tools/phase16-full.xml`:

```text
8996 passed / 78 failed / 139 skipped / 291 warnings, 790.58s
```

Comparing JUnit node IDs with the frozen Phase 13 failure audit yields **78
overlapping failures, 12 prior failures absent, and 0 new failure node IDs**.
The 12 absent failures include 11 Windows fixture foreground-setup failures
and one subprocess dependency-path failure. The remaining failures are
environment/portability and missing live dependency, credential, model or
catalog cases already classified in the Phase 13 audit; the full suite remains
failing. Phase 16's focused Windows regression passed.

This capability contract is proven for the owned standard Win32 receiver and
the exercised UIA ValuePattern. It is not a universal guarantee for arbitrary,
custom, elevated or malicious providers, and it does not explain the historical
Smart App Control admission discrepancy. Production readiness remains
**NOT READY**.

## Checkpoint

Checkpoint: `030d8e6b` (`feat(windows): verify typing capability before dispatch`).

Production files: `src/openjarvis/windows/actions.py`, `identity.py`,
`native.py`, `observer.py` and `receiver.py`. Tests:
`tests/security/test_windows_action_contract.py`, `test_windows_identity.py`,
`test_windows_mutation.py` and `windows_mutation_fixture.py`. Reports:
`docs/astra-run-report.md` and this phase report.

Known limits: 78 full-suite failures remain, all matching the frozen Phase 13
failure audit; real-application E2E is not executed; arbitrary/custom UIA
providers and the historical Smart App Control admission discrepancy remain
unverified. Roll back this checkpoint to restore the preceding typing contract;
the prior observation-bound mutation and quarantine boundaries remain intact.

Next dependency: wire structured, provenance-aware task checkpoint creation and
recovery into managed agent ticks, with unresolved execution-journal outcomes
still quarantined.
