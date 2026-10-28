# Windows safe mutation: path audit and contract (2026-10-04)

Starting checkpoint: f887719e, clean codex/astra-reliability. Mark1 is outside
scope and is not inspected, imported or modified. This audit precedes production
changes. Prior full counts are pre-DNS-fixture-repair evidence, not this phase's
full-suite evidence. Smart App Control's later admission remains unexplained.

## Actual starting production path

- tools/__init__.py imports built-ins, whose decorators populate ToolRegistry.
  There is no Windows observation/action registration at the starting checkpoint.
- windows/observer.py provides explicit HWND observation, selection and validation
  over bounded JSON IPC to a terminable multiprocessing spawn worker.
- windows/identity.py binds target UUIDs to the latest complete observation and
  retained UIA elements. Semantic hints must have exactly one match. Validation
  rejects changed process/window lifetimes, foreground, properties/hierarchy and
  retained-element identity. Successful validation denies mutation authority.
- windows/native.py owns UIA on a windowless MTA thread, process handles/creation
  FILETIME/image paths, raw UIA hierarchy and WinEvent/structure subscriptions.
  No mutation, focus acquisition or result verifier exists.
- tools/_stubs.py ToolExecutor parses invocation arguments, checks capabilities,
  taint and confirmation, reserves ExecutionJournal before mutating dispatch,
  uses a bounded tool runner and translates ToolResult.execution_state into
  structured outcomes. Unknown outcomes remain blocked across IDs/restarts.
- agents/native_react.py and native_openhands.py call that Python executor for
  external tools. NativeReact's tool messages propagate outcome warnings; model
  messages carry result content, not arbitrary ToolResult metadata. New Windows
  content must carry bounded JSON safety evidence as well as metadata.
- agents/executor.py binds the manager's durable journal and records tool start/
  end by call ID. traces/collector.py and traces/store.py retain JSON-safe
  result metadata. TOOL_CALL_START currently logs arguments; typing values need
  explicit field redaction at this boundary, not just in a tool's result string.
- No Windows retry mechanism exists. Do not add automatic physical retries or a
  competing mutation quarantine.

## Narrow supported mutation contract

Generic UIA Invoke/Value calls or external HWND messages cannot provide an atomic
application lifetime compare-and-dispatch for arbitrary providers. RuntimeIds
and HWNDs may be reused; asynchronous event invalidation alone is insufficient.
This phase supports only an explicitly bound **trusted cooperative adapter**,
supplied by host code, not discovered or constructed from model input. Default
registered tools remain unbound and fail closed. No arbitrary app injection,
global keyboard/mouse input, semantic fallback or automatic focus is added.

1. Native/UIA observation is cross-checked with the bound application's PID and
   creation identity and authenticated inherited adapter channel.
2. An observation records the application's window/control lifetime cookies and
   state revision in addition to native process/window/UIA identity. Names remain
   hints, never authority. Only complete latest observations can authorize targets.
3. Explicit supported hints resolve exactly one retained target. A mutation uses
   observation_id + target_id, never a fresh semantic search.
4. The observer revalidates native/UIA identity and required foreground. The
   receiver on its own GUI thread checks process creation, window/control cookie,
   HWND, current revision, enabled/visibility and foreground again. For text it
   also checks that its thread's focus equals the intended edit control.
5. No message pumping/retargeting occurs between receiver checks and its single
   synchronous BM_CLICK or WM_SETTEXT to the registered standard child control.
   Cooperative receivers are trusted to uphold that contract. Unsupported apps
   remain gated. This is not a universal claim about UIA providers.
6. The observation authorization is consumed before dispatch. A stale revision
   cannot replay the same physical mutation. Lost acknowledgement/verification
   becomes UNKNOWN_OUTCOME and the existing durable executor journal blocks replay.
7. A fresh native/UIA observation checks the same process/window/control lifetime
   and reads the unchanged identity-bound Counter/Result witnesses (click) or
   ValuePattern value (text). Receiver return alone is never VERIFIED.

The fixture is a small ctypes Win32 application in a test-owned spawned process:
standard EDIT/BUTTON/STATIC children, custom parent WndProc counters, random
window/control cookies, separate read-state instrumentation. The application
supports replacement, recreation and explicit test-only focus arrangement.
Two separate processes have identical names/roles. Native GUI focus setup must
be verified; production action code never switches focus to make a test pass.

The cooperative adapter is a deliberately limited proof surface. Real App E2E
requires a supported receiver with reliable lifecycle/cleanup; arbitrary real
apps are NOT authorized by the fixture proof. No security policy changes are
allowed. HWND reuse must be reported NOT REPRODUCED unless actually observed.

Result fields: action, observation_id, target_id, captured identity, preconditions,
dispatch (NOT_DISPATCHED/DISPATCHED/POSSIBLE), outcome, verification, failure code,
retryable, and bounded evidence. Critical identity failures are NOT_STARTED and
non-retryable. Unknown dispatch is UNKNOWN_OUTCOME and non-retryable. Read-only
fresh observation/replanning is distinct from retrying an old authorization.

Win32 reference: [BM_CLICK sends native button input/notification](https://learn.microsoft.com/en-us/windows/win32/controls/bm-click),
[message timeouts do not prove non-delivery](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagetimeoutw).
