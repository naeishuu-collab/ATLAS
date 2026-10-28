# E19-A Filesystem Proof (one authorized stage)

Binaries (temp, static-verified): `fsprobe.exe` SHA `0D04C1C5…EE12`
(x64, kernel32-only); `launcher-fsstage.exe` SHA `9927B749…9228`
(x64, kernel32/advapi32/userenv). No network/IPC/spawn/registry/ACL code.

## Fixture (deleted post-stage)

`%TEMP%\AstraE19A\7d5fdfb8…\fixture.txt`, 32 B synthetic marker,
SHA `D8399267…2751`, default ACLs (user F, no package ACE, unmodified).

## Host controls — PASS

Probe on host: `READ_RESULT=rc=0 err=0`; write control file created +
removed. Fixture usable. Contract self-test: outside path → 13 (correct).

## AppContainer stage — AMBIGUOUS (probe contract, not isolation)

Launcher: TRUE, TokenIsAppContainer=1, SID_MATCH=TRUE (identity proven
this run), `CHILD_EXIT_CODE=13`, CLEANUP PASS. Probe printed
`PROBE_CONTRACT=path-outside-fixture-root` and never attempted file I/O.
Same path passes validation on host → the sandbox's `GetTempPathW` view
differs (temp-path virtualization signal, REPORTED, not isolation proof).
Read/write denial: NOT PROVEN (no file op attempted).

## Classification

`FILESYSTEM_ISOLATION = NOT PROVEN` (ambiguous, Case §13-AMBIGUOUS).
No rerun (one-stage rule). Fix for future: validate literal
`AstraE19A\…fixture.txt` shape instead of TEMP-derived prefix
(design noted, not implemented).

## Cleanup

Fixture dir deleted; 334=334 mappings; 0 processes; no config change.
