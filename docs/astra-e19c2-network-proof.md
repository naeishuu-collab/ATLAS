# E19-C2 Corrected Network Proof (one authorized run — AMBIGUOUS)

Fix: `listen(backlog=4)` + control `accept()`+drain pre-probe
(source-evident; E19-C root cause PROVEN: backlog=1, no accept).
Probe reused unchanged (`netprobe.exe` SHA `75F6735E…`).
New launcher `launcher-netstage-c2.exe` SHA `4B00F9A5…B1`
(x64, same 4 DLLs, NotSigned) + post-probe select/accept observation.

## Listener health — PROVEN

Bound 127.0.0.1:56413, control SUCCESS, ACCEPTED=yes, DRAINED=yes,
STILL_ACTIVE=yes. Backlog empty at probe start.

## Run — TIMEOUT, identity lines missing (anomaly, fail-closed)

`CreateProcessW_RETURN=TRUE`, then NO token/child/server lines;
`WAIT_RESULT=TIMEOUT` (10 s), job-terminated, `ListenerCleanup=CLOSED`,
`CLEANUP=PASS`, exit 1. No probe output (killed before flush).
Source order verified straight-line (token block lines 404-428 before
job assign 452) — absence unexplained; treated as capture anomaly, NOT
as evidence. Identity: NOT PROVEN this run. Server-accept observation:
NOT OBTAINED (observation block sits on the non-timeout path only —
design gap recorded).

## Interpretation

Hang-in-connect is consistent with silent-drop enforcement, and E19-C's
10061 now reads more likely as backlog-RST artifact — but neither is
attributable: AMBIGUOUS. No denial claimed, no success claimed.

## Cleanup

334=334, 0 processes, listener closed, firewall/exemptions untouched.
