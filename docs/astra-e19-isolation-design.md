# E19 OS Isolation Design & Authorization Package (DESIGN ONLY — nothing executed)

## Trust gate (from E18-G evidence, not rerun)

`NATIVE_APPCONTAINER_STARTUP_IDENTITY_PROVEN` (TRUE/TokenIsAppContainer=1/
SID_MATCH/ CLEANUP PASS; 73 + 650 green). `OS_ISOLATION_NOT_PROVEN`.

## Capability baseline (E18-G configuration, from audited source)

- Profile SID: per-run unique, zero capabilities (`CapabilityCount=0`,
  `Capabilities=NULL`): NO internetClient/network caps, NO filesystem
  caps, NO package/impersonation caps.
- Token integrity: Low (AppContainer invariant). Inherited handles FALSE.
- Job: ACTIVE_PROCESS | DIE_ON_UNHANDLED | KILL_ON_JOB_CLOSE,
  ActiveProcessLimit=4. Child: `cmd /c exit 0` equivalent benign probe.
- Privilege model: minimum already proven. No caps added for tests.

## Threat model

Untrusted-but-benign worker code runs in the zero-cap AppContainer.
Adversary goals: reach Internet, read/write host files, signal host IPC,
escape via descendant. Out of scope: kernel exploits, token theft
requiring privileges the token lacks, social engineering.

## E19-A Filesystem denial (proposed first)

- Fixture (future): host-owned `%TEMP%\astra-e19\<uuid>\marker.txt`
  with synthetic content `E19-SYNTHETIC-MARKER`, default ACLs (no
  package ACE). Control: host read+write succeeds.
- Probe: AppContainer attempts read → expect `ERROR_ACCESS_DENIED (5)`;
  attempts write `marker.out` → expect `5`. Evidence: exact error codes,
  ACL dump pre-run, cleanup (host deletes dir).
- Why first: purely passive, no sockets/processes, smallest blast radius.

## E19-B IPC denial (proposed second)

- Primary mechanism: named event. Host creates
  `Global\AstraE19-<uuid>` (default SD, no package ACE, no data).
  Control: host Set/Wait succeeds.
- Probe: AppContainer `OpenEvent(SYNCHRONIZE)` → expect denial
  (`5` or `ERROR_FILE_NOT_FOUND (2)` — namespace isolation also
  acceptable denial; record which). Cleanup: host closes handle.
- No system objects touched.

## E19-C Network denial (proposed third)

- Host: loopback TCP listener `127.0.0.1:0` (ephemeral, host-only).
- Control: host connects → success.
- Probe: AppContainer `connect(127.0.0.1:port)` → expect `WSAEACCES
  (10013)`. Timeout 5 s. No DNS, no external destination, no cloud.
- LOOPBACK CAVEAT (explicit): AppContainer loopback block is a separate
  isolation-policy mechanism from capability-based Internet denial; a
  loopback denial does NOT prove general Internet denial. Internet denial
  rests on token analysis (zero network caps, enforced by the TCP/IP
  capability check) — static proof, recorded as such. No external probe
  is authorized to close that gap.

## E19-D Descendant containment (proposed last)

- Semantics: AppContainer MAY create children; default inherits the
  AppContainer token. Escape needs token reassignment (privilege the
  token lacks). Job adds independent containment (limit 4, kill-on-close).
- Probe (benign): AppContainer child runs `cmd /d /c exit <code>`;
  launcher-equivalent captures grandchild PID, `TokenIsAppContainer`,
  SID equality vs profile SID, job membership, exit code.
- Invariant: no descendant outside the profile SID + job. Any escape =
  security finding, fail closed.
- Why last: process creation is the most privilege-adjacent operation;
  run only after FS/IPC/net probes characterize the sandbox.

## Controls, classification, evidence

- Every probe: host control (success) + sandbox probe (expected denial).
  Distinguishes unavailable-resource from isolation-denial.
- Classes: `ISOLATION_DENIAL_PROVEN` / `CONTROL_INVALID` /
  `UNEXPECTED_ACCESS` (finding) / `AMBIGUOUS_RESULT` / `PROBE_FAILURE` /
  `CLEANUP_FAILURE`. Unexpected access never reinterpreted as harmless.
- Per-test evidence: binary+source hash, profile SID, token flags,
  observed/expected SID, caps, resource id, control+sandbox results,
  exact Win32/WSA error, PIDs, job id, cleanup. No secrets in logs.

## Harness (design, NOT implemented)

- One small probe binary, modes `fs-read|fs-write|ipc-open|net-connect|
  spawn`, deterministic exit codes (`0` control-ok / `10+N` denial code
  / `20` probe failure / `30` cleanup failure), ≤10 s runtime, stdout
  evidence lines only, no shell/PowerShell dep, no generic exec.
- Must not become an escape tool: fixed operation set, no arbitrary paths
  (fixture dir pinned), no network except the loopback probe.

## Safety Authority relationship

Sandbox = defense-in-depth ONLY. Logical model (Safety Authority, sealed
grants, ledger, UNKNOWN quarantine, egress guard, fail-closed) remains
the primary boundary; a compromised worker must fail BOTH. E19 proves
selected physical properties, never a substitute.

## Acceptance criteria

- E19 proves: 4 selected denial/containment properties (with controls).
- E19 cannot prove: complete sandbox security (finite tests), absence of
  kernel-level bypass, production RLMWorker/integration safety, egress
  safety. Those need separate evidence. 4/4 probes ≠ production-safe.

## Regression plan (future)

After harness: Safety Authority (NOT FOUND — gap recorded), RLM RPC,
hardening, UNKNOWN, ledger, ExecutionJournal (check existence then),
egress denial, wire send-count, identity, cleanup, full 650, ruff,
compile, imports. AppContainer dedicated regression: GAP (none exists).

## Stage order

E19-A FS → E19-B IPC → E19-C net → E19-D descendant (passive→active
risk order). Each stage separately authorized; success never auto-
authorizes the next.
