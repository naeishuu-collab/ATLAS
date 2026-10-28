# E19-D Descendant Containment Design (DESIGN ONLY — nothing built/run)

## Semantics audit (local SDK + audited launcher source)

- Descendant of an AppContainer process inherits the AppContainer token
  by default; assigning another token needs `SeAssignPrimaryTokenPrivilege`
  (absent in zero-cap token). Creation itself is not forbidden.
- Job: members' children join the same job unless breakaway permitted +
  `CREATE_BREAKAWAY_FROM_JOB`. Current flags (launcher.c 83-89):
  `ACTIVE_PROCESS|DIE_ON_UNHANDLED|KILL_ON_JOB_CLOSE`
  (`winnt.h:13701/13714/13716`); `BREAKAWAY_OK`/`SILENT_BREAKAWAY_OK`
  NOT set → breakaway unavailable. No nested-job weakening.
- ActiveProcessLimit=4: job will hold child+grandchild (2) — fits, no
  change needed. Launcher itself stays outside the job.

## Threat model

One benign descendant escaping AppContainer identity and/or Job.
Out: privesc, injection, kernel, network/FS/IPC probing, persistence.

## Benign descendant (future tiny binary, NOT implemented)

`descprobe.exe`: prints `DESC_ALIVE pid=<n>`, waits on a host-signaled
named event (or bounded 8 s sleep), exits 0. No I/O, no network, no
children, no registry. Hash-pinned at build.

## Parent probe (future variant, NOT implemented)

Single-purpose launcher variant: fixed descendant path (self-dir +
`descprobe.exe`, no argv forwarding), one `CreateProcessW` attempt
(same caps/env/job/timeout), then host-side inspection of BOTH handles:
parent + descendant token/SID (`EqualSid` vs profile SID),
`IsProcessInJob` both, PIDs, exit codes. Exactly-once creation.

## Identity evidence (both levels)

Parent: PID/token/SID/job (E18-G pattern). Descendant: PID + PPID link,
exe identity (path+hash), `TokenIsAppContainer`, SID equality,
`IsProcessInJob`. PID alone never sufficient (stale-PID control:
inspect live handles, verify exit code collection order).

## PASS properties

`DESCENDANT_TOKEN_IS_APPCONTAINER=1` + `SID==PROFILE_SID` and
`DESCENDANT_IN_EXPECTED_JOB=TRUE`. Escape either → security finding,
fail closed. Denial of creation = separate property, not containment.

## Kill-on-close recommendation — OPTION B (deferred)

Membership is the principal property; kill demonstration adds
attribution/cleanup races (close-while-observing). Every run already
closes the job handle cleanly; explicit kill proof deferred, not required.

## Classes

`DESCENDANT_CREATION_DENIED` / `DESCENDANT_CONTAINED` /
`DESCENDANT_APPCONTAINER_ESCAPE_OBSERVED` / `DESCENDANT_JOB_ESCAPE_OBSERVED` /
`DESCENDANT_DUAL_ESCAPE_OBSERVED` / `DESCENDANT_IDENTITY_NOT_PROVEN` /
`CONTROL_INVALID` / `PROBE_FAILURE` / `AMBIGUOUS`.

## Observability (C2/C3 lessons)

Unbuffered logging; token/SID/job evidence captured pre-wait where
possible; host-handle inspection primary (never buffered-child-output
only); bounded waits (probe < launcher); select-style observation on
all paths; exit codes deterministic.

## Cleanup contract

Terminate descendant+parent (job kill fail-safe), close all handles,
delete profile, pre/post PID+profile snapshots, flags/policies untouched.

## Regression gaps (still open)

`Safety Authority`: NOT FOUND. `AppContainer dedicated`: NOT FOUND.
Future minimum: token/SID/caps/cleanup positive+negative tests mirroring
each physical stage (proposed files only, not created here).

## Claim boundary

Success yields at most
`DESCENDANT_APPCONTAINER_AND_JOB_CONTAINMENT_PROVEN_FOR_TESTED_CHILD`.
Combined E19 then covers: identity, FS fixture, Event object, descendant,
loopback-timeout observation. Complete sandbox, RLMWorker, egress stay
out of scope. No implementation/execution in E19-D.
