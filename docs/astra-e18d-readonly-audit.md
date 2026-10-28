# E18-D H3 Read-Only Deep Audit (no execution, no changes)

## Contract audit (launcher.c, all line refs verified)

- Env block: `NAME=VALUE\0` + final `\0` (29-51, 53-78); `=C:` expands to
  `=C:=<cwd>` (correct); sorted; `CREATE_UNICODE_ENVIRONMENT` set (150).
- Attr list: two-step sizing, count=1, single update (227-268); SID heap
  lives through `CreateProcessW`, freed in cleanup (343-370).
- `STARTUPINFOEXW`: zeroed, `cb=112=sizeof(STARTUPINFOEXW)` (270-271),
  `lpAttributeList` set, `bInheritHandles=FALSE` (290).
- Capabilities: SID set, NULL/0/0, matches SDK `winnt.h:12672-12681`.
- Error capture: `SetLastError(SUCCESS)` → immediate `GetLastError` (284-296).
- Cleanup: job kill, handles, attr list, profile delete, SID free (342-370).
- VERDICT: no confirmed API-contract defect. All 5 runs share one
  untested axis: explicit `lpEnvironment` (NULL-env never tried; needs
  rebuild — NOT done here). `cb`/lifetime/ordering all conform.

## ACL audit (read-only icacls)

- `cmd.exe`: TrustedInstaller F; Users RX; ALL APPLICATION PACKAGES RX.
- `System32`: standard inherited ACEs. Launcher exe/dir: user F via
  inheritance (parent runs medium; no AppContainer read needed).
- No deny ACEs observed on the child path. Effective access under a
  zero-cap token NOT PROVEN by static ACEs (recorded, not claimed).

## CI / AppLocker / WDAC (read-only)

- AppLocker EXE/DLL log: only 8001 (policy applied) + 8043 (uninstall
  registration); zero 8003/8004 denials. No enforcement evidence.
- CI Operational: 3102 inventory (4 policies, Status 0x0), informational.
- `VerifiedAndReputablePolicyState=0` (Smart App Control OFF).
- Classification: no denial evidence; absence != non-involvement.

## 203 attribution

- Failing API: `CreateProcessW` (immediate GetLastError, no wrapper).
- Symbol PROVEN (`winerror.h:1648`, "environment option ... not found").
- Internal cause NOT PROVEN. Leading structural candidate: explicit
  caller env block vs AppContainer target (present in all 5 runs,
  never isolated). Next: env-NULL variant (rebuild required) or
  `DeriveAppContainerSidFromAppContainerName` comparison design.
- No defect filed as confirmed; no code changed (per policy).

## Safety Authority

Untouched: flags OFF=DENY, sealed grants, ledger, UNKNOWN quarantine,
fail-closed. No production/test/binary/config change in E18-D.
