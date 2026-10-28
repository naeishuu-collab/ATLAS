# E18-B Native Proof (single authorized run)

Binary: SHA `620AA19D…D9` verified pre-run. Pre-run: 334 mappings, 0 remnants.

## Source differential (audited, isolated)

`no-drive` sets only `include_drive_entry=FALSE`
(`native_appcontainer_launcher.c:137-139`); the `=C:` drive entry is
omitted from the Unicode env block. Suspended kept, appname explicit,
cwd explicit, caps zero, single-variant enforced by `argc==2` parsing.

## no-drive run

Flags `0x00080404`, env keys `PATH,PYTHONHOME,PYTHONNOUSERSITE,
SystemRoot,WINDIR` (no `=C:`). `CreateAppContainerProfile=SUCCESS`,
`AppContainerSid=present`, `CreateProcessW_RETURN=FALSE`,
`IMMEDIATE_GETLASTERROR=203`, `CLEANUP=PASS`, exit 1.
No child → no token obtainable (fail-closed).

## 203 mapping (local SDK header, PROVEN)

`winerror.h:1642-1648`: `ERROR_ENVVAR_NOT_FOUND 203L` —
"The system could not find the environment option that was entered."

## Cleanup

Post-run 334 mappings, 0 `AstraNative*`, 0 launcher processes.
No network/config/flag changes. Single run, no combinations.
