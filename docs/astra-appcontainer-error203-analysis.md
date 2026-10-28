# AppContainer Error 203 — Non-invasive Analysis (NOT PROVEN)

Source: `third-party/codex-security-poc/native_appcontainer_launcher.c`
(static read-only). No execution, no profile creation, no policy change.

## Statically verified

- `creation_flags = EXTENDED_STARTUPINFO_PRESENT |
  CREATE_UNICODE_ENVIRONMENT (+ CREATE_SUSPENDED unless no-suspend)`.
- Explicit Unicode environment block via `build_environment_block`
  (`=C:` drive entry optional, PATH/PYTHONHOME/PYTHONNOUSERSITE/
  SystemRoot/WINDIR), sorted + double-NUL per Codex report.
- `STARTUPINFOEXW` + attribute list sized by two-step init;
  `SECURITY_CAPABILITIES` zeroed, AppContainerSid set, Capabilities NULL,
  count 0; `bInheritHandles=FALSE`; immediate `GetLastError` capture
  after `CreateProcessW`.
- Differentials exist for no-drive/no-appname/no-cwd/no-suspend, but the
  `no-suspend` run was blocked by Application Control before launcher
  execution — so CREATE_SUSPENDED was never actually eliminated.

## Ranked hypotheses (unresolved)

1. CREATE_SUSPENDED × AppContainer/Job ordering interaction (untested —
   the one differential that never ran).
2. Explicit environment vs runtime-required entries (host inheritance
   forbidden, so an unknown required entry may be missing).
3. Image/directory ACL or Code Integrity evaluation surfacing as 203.
4. Capabilities/profile-lifecycle/token-generation combination.
5. Diagnostic wrapper vs `GetLastError` boundary artifact.

## Verdict

Root cause NOT PROVEN. OS isolation NOT PROVEN. No further static step
can close this; next step needs the approved native execution only.
