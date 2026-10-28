# E18-C Native Proof (single authorized run)

Binary: SHA `620AA19D…D9` verified pre-run. Pre-run: 334 mappings, 0 remnants.

## Source differential (audited, isolated)

`no-cwd` sets only `current_directory_is_null=TRUE`
(`native_appcontainer_launcher.c:143-145`); `CreateProcessW` receives
`lpCurrentDirectory=NULL` (line 293). Appname explicit, env full
(with `=C:`), suspended kept, caps zero. No rebuild (preimplemented).

## no-cwd run

Flags `0x00080404`, `current_directory=NULL`.
`CreateAppContainerProfile=SUCCESS`, `AppContainerSid=present`,
`CreateProcessW_RETURN=FALSE`, `IMMEDIATE_GETLASTERROR=203`,
`CLEANUP=PASS`, exit 1. No child → no token obtainable (fail-closed).

## Cleanup

Post-run 334 mappings, 0 `AstraNative*`, 0 launcher processes.
No network/config/flag changes. Single run, no combinations.

## Differential series complete

A (0x80404) / B (0x80400) / C (no-appname) / D (no-drive) / E (no-cwd):
all FALSE/203. Every pre-designed single variable is exhausted with
identical outcome. Remaining: H3 deep read (ACL/CI) and capability/
profile-lifecycle designs (next phase; no binary variant left).
