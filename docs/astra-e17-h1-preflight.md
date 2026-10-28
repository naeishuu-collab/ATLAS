# E17 H1 Pre-flight Gate (experiment NOT started in E17)

Binary: `...\e17build\launcher.exe` (SHA `620AA19D…D9`, test-only).

| # | Item | Status | Evidence / Action |
|---|---|---|---|
| 1 | Harmless test binary fixed | PASS | hash-pinned exe in approved temp; child is `cmd /c exit 0` |
| 2 | Exe/args/cwd fixed | PASS | Cond A: no arg; Cond B: `no-suspend`; cwd `C:\Windows\System32` |
| 3 | Profile usable | NOT PROVEN | none pre-exists by design; run creates+deletes own → needs approval update |
| 4 | Capabilities held | PASS (static) | zero-cap `SECURITY_CAPABILITIES`, AppContainerSid set |
| 5 | Env block valid | PASS (static) | double-NUL, `=C:` expansion verified |
| 6 | STARTUPINFOEX/attrs valid | PASS (static) | two-step sizing, immediate GetLastError |
| 7 | No external network | PASS (design) | no network imports (verified in binary) |
| 8 | Timeout set | PASS | 10 s wait + `TerminateJobObject` |
| 9 | Handle cleanup | PASS (static) | CloseHandle/DeleteProcThreadAttributeList/FreeSid paths |
| 10 | Abort on anomaly | PASS (procedure) | single run per condition, no retry/fallback |

H1 spec: Cond A vs Cond B (`no-suspend`), all else fixed; record
return/GetLastError/PID/TID/SID/exit code/timestamps/cleanup.
GATE: item 3 NOT PROVEN → E17 performs NO execution (per §10).
Exactly one approval needed: self-cleaning profile create+delete
(or a Derive-only variant + existing profile).
