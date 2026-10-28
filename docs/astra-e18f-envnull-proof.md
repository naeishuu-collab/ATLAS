# E18-F env-NULL Proof (one authorized build + one authorized run)

## Patch (temp copy only; repo source pristine DA66889D…)

5-line diff on `launcher-noenv.c` (temp): `use_null_environment` flag,
`no-env` argv (incl. USAGE guard), diagnostic print, call-site
`use_null_environment ? NULL : environment`. Child/cmdline/cwd/flags/
caps/SID/timeout/cleanup untouched. Diff inspected pre-build.

## Build (offline, MSVC 19.51.36256 + SDK 10.0.26100.0)

`cl /nologo /O1 /W3 launcher-noenv.c /link /OUT:launcher-noenv.exe
advapi32.lib userenv.lib` — clean. `launcher-noenv.exe` 151552 B,
SHA-256 `85217542…0BF6`. PE x64, imports kernel32/advapi32/userenv
(identical to original), NotSigned. Original `launcher.exe` untouched
(hash re-verified post-run).

## Single no-env run — SUCCESS PATH (identity unverified)

`environment_variant=no-env`, flags `0x00080404`, all else baseline.
`CreateAppContainerProfile=SUCCESS`, `AppContainerSid=present`,
`CreateProcessW_RETURN=TRUE`, `GetLastError=0`, `CHILD_EXIT_CODE=0`,
`CHILD_JOB_QUERY=TRUE`, `CLEANUP=PASS`, exit 0.
No secrets dumped (inherited env never printed).

## Classification

`PROCESS_CREATED / APPCONTAINER_IDENTITY_NOT_PROVEN` — child exited
before any token read; exactly one run authorized so no post-hoc token
check exists. No isolation claim. No E19.

## Cleanup

334=334 mappings, 0 `AstraNative*`, 0 launcher processes, original
binary unchanged, no config/flag changes.
