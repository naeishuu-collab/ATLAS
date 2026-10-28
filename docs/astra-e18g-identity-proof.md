# E18-G Startup Identity Proof (one authorized run)

Variant: `launcher-noenv-token.exe` SHA `435BEA33…F64` (temp-only patch
on no-env base: +55-line read-only token block, no flow/scheduling change;
no CREATE_SUSPENDED added). Static: x64, imports unchanged
(kernel32/advapi32/userenv), NotSigned.

## Single run (no-env, inherited environment)

Flags `0x00080404`. Profile SUCCESS, SID present.
`CreateProcessW_RETURN=TRUE`, `GetLastError=0`.
`OpenProcessToken=SUCCESS` (retained handle, race-free by design).
`TokenIsAppContainer=1`.
`TokenAppContainerSid=PRESENT`.
`SID_MATCH=TRUE` (`EqualSid` vs profile SID).
`CHILD_EXIT_CODE=0`, `CHILD_JOB_QUERY=TRUE`, `CLEANUP=PASS`, exit 0.

## Classification

`NATIVE_APPCONTAINER_STARTUP_IDENTITY_PROVEN` — startup identity only.
NOT proven: filesystem/network/IPC/child isolation, RLMWorker, egress.

## Cleanup

334=334 mappings, 0 remnants, 0 launcher processes. No config change.
