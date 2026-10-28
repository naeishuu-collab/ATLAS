# E17 Binary Trust (static only, test-only status)

- PE: `MZ`, Machine `8664` (x64). No execution performed.
- DLL surface (byte-level import scan): kernel32/advapi32/userenv only.
  Absent: wininet/urlmon/ws2_32/winhttp/shell32/ole32/credui/netapi32 —
  no network/credential/com libraries. Matches `#pragma comment(lib)`
  (`advapi32`, `userenv`) + kernel32.
- Signature: `NotSigned` — not claimed otherwise; test-only binary.
- Source correspondence: single-file build, no patches, flags above.
- Behavior audit (source): one child (`cmd.exe /c exit 0`), 10 s timeout,
  job `KILL_ON_JOB_CLOSE`, handle cleanup, no network, no privilege change.
- IMPORTANT: on run it calls `CreateAppContainerProfile` with a
  per-run unique name (`AstraNativePoc.<pid>.<tick>`) and deletes it at
  exit (`DeleteAppContainerProfile`). So (a) no pre-existing profile can
  satisfy the gate — execution inherently creates one (self-cleaning);
  (b) future H1 execution needs approval covering create+delete, or a
  Derive-only launcher variant. Test-only; NOT production-trusted.
