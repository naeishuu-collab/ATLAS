# E18 Native Proof (executed, limited authorization)

Binary: `...\e17build\launcher.exe` SHA `620AA19D…D9` (verified pre-run).
Pre-run snapshot: 334 mappings, 0 `AstraNative*`. Post-run: identical.

## Condition A (flags 0x00080404, suspended=TRUE)

`CreateAppContainerProfile=SUCCESS`, `AppContainerSid=present`,
`CreateProcessW_RETURN=FALSE`, `IMMEDIATE_GETLASTERROR=203`,
`CLEANUP=PASS`, exit 1. No child started.

## Condition B (flags 0x00080400, `no-suspend`)

Identical outcome: `CreateProcessW_RETURN=FALSE`, `203`,
`CLEANUP=PASS`, exit 1. No child started.

## Lifecycle / residuals

Per-run unique profile created+deleted both times (334→334, zero
`AstraNative*` remnants). No stray child (7 pre-existing `cmd`
belong to other sessions; launcher not running). No network, no
policy/ACL/token change. Single run per condition, no retry.
