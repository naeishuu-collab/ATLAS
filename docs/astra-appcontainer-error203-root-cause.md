# AppContainer Error 203 — Root-Cause Analysis (static only, NOT PROVEN)

Source: `third-party/codex-security-poc/native_appcontainer_launcher.c`
(read-only). No execution, no profile/token/ACL/policy change.

## Statically verified (supporting a correct call shape)

- Env block: entries `NAME=VALUE\0` via `_snwprintf_s` + final `\0`
  = well-formed double-NUL; `=C:` drive entry expands to
  `=C:=C:\Windows\System32` (correct); sorted; `CREATE_UNICODE_ENVIRONMENT`
  set. Malformed-block hypothesis: LOW confidence.
- `STARTUPINFOEXW` + two-step attribute-list sizing; `SECURITY_CAPABILITIES`
  zeroed, AppContainerSid set, Capabilities NULL/count 0;
  `bInheritHandles=FALSE`; immediate `GetLastError` after `CreateProcessW`
  (no intervening call — diagnostic-wrapper artifact: LOW).
- Job `KILL_ON_JOB_CLOSE`, `ActiveProcessLimit=4`.

## Hypotheses

| # | Hypothesis | Supporting | Contradicting | Repro need | Risk | Confidence |
|---|---|---|---|---|---|---|
| H1 | CREATE_SUSPENDED × AppContainer/Job ordering | no-suspend differential never ran (AppControl blocked it) | none | approved native run with no-suspend | low (test binary) | HIGH (most likely) |
| H2 | AppContainer profile/SID lifecycle (missing/restricted profile) | 203 = env lookup; profile provides env | explicit env given | profile-state inspection | low | MEDIUM |
| H3 | Image/dir ACL or Code Integrity surfacing as 203 | known Windows misattribution pattern | cmd.exe is stock path | ACL/CodeIntegrity read | none (read-only) | MEDIUM |
| H4 | Required runtime env entry missing (host inheritance forbidden) | minimal 5-var block | block is well-formed | native run with extended block | low | LOW-MED |
| H5 | Capability/profile/token-generation combination | zero capabilities is unusual | API accepts it statically | native run | low | LOW |

## Verdict

Cause NOT PROVEN. No safe static fix is clearly justified — no code
changed. Next step needs the approved native execution only (H1 first).

## E16 addendum (native not executed — BLOCKED)

Pre-flight gate failed: no launcher binary exists in either worktree and
no C toolchain (`cl.exe`/`gcc.exe`) is present to build one; Smart App
Control reads OFF so it is not the current blocker. H1 differential is
source-ready (`create_suspended`) but unexecuted. Classification stays
INCONCLUSIVE. See `docs/astra-e16-native-appcontainer-proof.md`.
