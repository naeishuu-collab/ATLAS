# Phase 13: Windows application identity, observation only

The source-built CPython 3.11 native extension and focused security/ACL lanes
passed before this phase. Five Rust symlink fixtures remain blocked by Windows
privilege error 1314; the full repository suite exposes additional existing
platform and live-environment failures. This foundation therefore grants **no
physical mutation authority**. JARVIS Mark1 was not inspected or modified.

## Implementation

`src/openjarvis/windows` is an explicit observation library, not a registered
click/type/invoke tool. Install the optional `windows-observation` extra for
comtypes. `WindowsObserver.observe(hwnd)` requires an explicit positive HWND;
there is no application-name or first-window fallback.

Every complete observation records process PID, creation FILETIME and normalized
executable path; window HWND, native thread, class and lifetime generation;
foreground HWND; and control RuntimeId, native HWND, UIA ProcessId, AutomationId,
control type, class, framework, raw hierarchy, name and preconditions. Executable
path identifies the process image location, not publisher authenticity or an
immutable executable-content hash.

A persistent spawned process owns all UIA elements, process handles, subscriptions
and reads on a windowless COM MTA thread. Microsoft recommends that threading
model and same-thread subscription cleanup. Parent callers serialize requests;
native element pointers never cross IPC. The transport is bounded JSON, with a
two-MiB limit, bounded enumeration/depth/property lengths, startup/request
deadlines and owned-process termination on timeout/crash/error. There is no
automatic target recovery. Only a fresh explicit observation can start again.
[Microsoft UIA threading guidance](https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-threading)

Only the latest complete observation remains retained. Selection examines all
matching hints inside that observation and requires exactly one candidate. Names
are hints; retained native elements and process/window lifetimes establish
identity. Validation checks the pinned process handle is alive, complete native
window identity, foreground by default, retained control properties/hierarchy,
enabled/visibility preconditions, complete re-enumeration, and CompareElements.
Missing, ambiguous, stale, replaced or mismatched identities fail closed.

UIA RuntimeIds are opaque and may be reused over time. They are never accepted
alone. Out-of-context create/destroy WinEvents and UIA structure changes invalidate
a session generation; native process creation time and retained handles prevent
PID-lifetime retargeting. These events are asynchronous. They do **not** constitute
an atomic lifetime guarantee between a validation and a future physical action.
[Microsoft RuntimeId semantics](https://learn.microsoft.com/en-us/windows/win32/api/uiautomationclient/nf-uiautomationclient-iuiautomationelement-getruntimeid),
[WinEvent delivery semantics](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwineventhook)

An actual Win32 provider reported off-desktop buttons as IsOffscreen=false.
The backend therefore also checks native root visibility/minimization, native
enabled state and monitor intersection of both root and UIA bounding rectangles.
This rejects the demonstrated provider inconsistency. It does not prove absence
of occlusion, clipping, overlays or pointer hit-test interference.

Even successful validation always returns `mutation_allowed: false`. No input,
focus, control setters, UIA patterns that mutate, or application injection APIs
are present. Exactly-once mutation, independent resulting-state verification and
safe recovery remain future work, requiring a separate guarded design and tests.

## Verification

Exact command, global Python 3.11 with `PYTHONPATH=src;.venv/Lib/site-packages`:

```powershell
python -m pytest tests/security/test_windows_identity.py tests/security/test_windows_observer.py -q --junitxml=.astra-tools/phase13-identity-final.xml
```

**50 passed / 0 failed / 0 skipped / 0 warnings**, 37.58 seconds.

The 32 policy tests inject wrong foreground/process/executable, PID restart,
HWND/thread/class/generation changes including same-number reuse, duplicate
names/AutomationIds/RuntimeIds, ambiguous controls, stale controls, target
replacement, hierarchy changes, partial enumeration and changes during reads.
They prove refusal policy and that successful identity validation grants no
mutation authority. Display-name changes on the same retained native object
do not silently select another element.

The 18 Windows cases use real Win32 windows, actual UIA/COM, process handles and
foreground reads. They verify properties/hierarchy, duplicate names, wrong
foreground, off-desktop preconditions, same-name child replacement, window
recreation, application process exit/restart, stale observations, enumeration
limits, worker crashes, unresponsive startup/request cleanup, multi-caller
serialization and malformed HWND rejection. Unresponsive-worker tests inject
an owned stalled child, rather than hanging a user application.

Synthetic fixture windows are positioned off desktop, use NOACTIVATE/TOOLWINDOW
and never steal focus or create taskbar entries. Only those test-owned windows
are created/destroyed. No real user application was mutated. Actual same-number
HWND/PID reuse has not been forced on this host; deterministic policy fixtures
cover those cases. Coverage of arbitrary custom, virtualized, cross-process,
elevated or malicious UIA providers is not claimed. Inaccessible or unsupported
observations fail closed.

The final broad/full results are recorded in `astra-run-report.md` and
`astra-verification.json`; counts overlap and must not be summed. This is a
tested observation checkpoint, not production-ready Windows automation.
