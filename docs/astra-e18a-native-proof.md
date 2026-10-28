# E18-A Native Proof (single authorized run)

Binary: SHA `620AA19D…D9` verified pre-run (audited test-only exe).
Pre-run: 334 mappings, 0 `AstraNative*`, 0 launcher processes.

## no-appname run (lpApplicationName=NULL, quoted absolute cmdline)

Flags `0x00080404` (suspended kept), env full, cwd explicit, caps zero.
`CreateAppContainerProfile=SUCCESS`, `AppContainerSid=present`,
`CreateProcessW_RETURN=FALSE`, `IMMEDIATE_GETLASTERROR=203`,
`CLEANUP=PASS`, exit 1. No child → no token/SID obtainable (fail-closed).

## Cleanup

Post-run: 334 mappings, 0 `AstraNative*`, 0 launcher processes.
No network, no config/ACL/policy change, production flags untouched.
Single run, no retry, no combined variants.
