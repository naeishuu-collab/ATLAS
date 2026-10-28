# E17 Launcher Build (offline, from audited source)

- Source: `third-party/codex-security-poc/native_appcontainer_launcher.c`
  (SHA-256 pre-build recorded in session; unmodified).
- Command (via `vcvars64.bat`, MSVC 19.51.36256 x64):
  `cl /nologo /O1 /W3 <source> /link /OUT:launcher.exe advapi32.lib userenv.lib`
- Output (NOT in repo; approved temp only):
  `C:\Users\yingz\AppData\Local\Temp\opencode\e17build\launcher.exe`
  151040 bytes, SHA-256 `620AA19D…D9`.
- Warnings/errors: none (single `cl` file echo, clean link).
- Rebuild bit-identity: NOT achieved (PE timestamp; second build
  `99EDAB36…`) — toolchain+flags recorded instead. No such claim made.
- Binary NOT executed (E17 prohibits CreateProcessW experiments).
