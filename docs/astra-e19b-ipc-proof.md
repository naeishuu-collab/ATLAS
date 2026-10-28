# E19-B Named-Event IPC Proof (one authorized stage)

Binaries: `ipcprobe-event.exe` SHA `BA6DEC2F…880B5` (x64, kernel32-only);
`launcher-ipcstage.exe` SHA `D12468F3…875CD` (x64, 3 DLLs).
Probe constrained to `AstraE19B-<32hex>` session-namespace names;
launcher diff limited to event create/control + probe invocation.

## Semantics (local SDK)

`EVENT_MODIFY_STATE=0x2` (`winnt.h:13921`). Session-namespace object
(no `Global\`): name-resolvable same-session; access via DACL +
mandatory integrity. Default SD (creator-owned, no package ACE).

## Fixture + control

Event `AstraE19B-a1b2…8f90` created by launcher (host), creator handle
held for the run. `HOST_IPC_CONTROL=SUCCESS` (open + SetEvent).

## Stage — ALL CRITERIA MET

`VALIDATION_ACCEPTED`, `OPEN_EVENT_API_REACHED`,
`IPC_RESULT=rc=10 err=5` (ERROR_ACCESS_DENIED).
Identity TRUE/1/SID_MATCH; `CHILD_EXIT_CODE=0`; `EventCleanup=CLOSED`;
`CLEANUP=PASS`. Object existed for the full duration (host handle held).

## Classification

`NAMED_EVENT_MODIFY_DENIAL_PROVEN_FOR_TESTED_OBJECT` (narrow; no
universal IPC claim; not-found vs denied distinguished by design).

## Cleanup

334=334 mappings, 0 processes, event destroyed with last handle close.
