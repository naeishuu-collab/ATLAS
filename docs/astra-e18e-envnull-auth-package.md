# E18-E env-NULL Authorization Package (design only — NOT built, NOT run)

## A. Verified baseline

Branch `opencode/cloud-privacy`, HEAD `d596e482`, 89 status entries
(preserved), Win 10.0.26200.0. Trusted exe SHA `620AA19D…D9` confirmed.

## B. Trusted source / binary provenance

Source `third-party/codex-security-poc/native_appcontainer_launcher.c`
(unmodified); binary from E17 (`cl /O1`, MSVC 19.51.36256, SDK
10.0.26100.0) in approved temp only.

## C. CreateProcessW environment analysis

Call site lines 285-295 passes `environment` (explicit Unicode block,
built 196-203, lives on stack through the call). All 5 runs used an
explicit block; NULL (inherit) never tested.

## D. Minimal patch proposal (NOT applied)

```c
// decl (~line 124): BOOL use_null_environment = FALSE;
// argv (~line 146): if (argc == 2 && wcscmp(argv[1], L"no-env") == 0) {
//                       use_null_environment = TRUE;
//                   }
// call site (line 292): use_null_environment ? NULL : environment,
// + CONFIG print: environment_variant "no-env".
```

Nothing else changes (exe, cmdline, cwd, flags incl.
CREATE_UNICODE_ENVIRONMENT, SID, caps, STARTUPINFOEX, timeout, cleanup).

## E. Single-variable validity assessment

API parameter: single (`lpEnvironment` block → NULL). HONEST LIMIT:
with NULL the child INHERITS the parent's full environment, so effective
content changes by inheritance semantics. Interpretation: success
implicates explicit-block shape/content; persistence eliminates the
explicit block as a cause class. Secret note: parent env strings become
visible to a benign exit-0 child only; no exfiltration path (no network,
job-killed, zero-cap). Acceptable for test-only with disclosure.

## F. Offline build plan (NOT executed)

Same `vcvars64` + `cl /nologo /O1 /W3` + `advapi32.lib userenv.lib`;
output `launcher-noenv.exe` in approved temp (NEVER overwrite trusted
exe); record SHA, PE arch, import allowlist (kernel32/advapi32/userenv).

## G. Static verification plan

Hash record, PE Machine=8664, import scan (deny wininet/ws2_32/winhttp),
NotSigned acknowledged, source diff review (3 hunks only).

## H. Single native experiment plan (NOT executed)

Pre-flight (hash/pe/argv/snapshot) → one `launcher-noenv.exe no-env` run
→ capture return/GetLastError/PID/token-if-created/timeout/cleanup →
post snapshots (334-baseline compare, AstraNative* zero) → single-run,
no retry, no combinations.

## I. Safety boundaries

No network/policy/ACL/production/RLMWorker changes. Existing profile
namespace only (self-cleaning). No other variants.

## J. Cleanup / rollback

No files created in E18-E except this package doc. Future binary lives
in temp; delete `launcher-noenv.exe` after the authorized run. Worktree
changes preserved; rollback = remove package doc.

## K. Tests actually executed

Ruff (clean). No other execution (build/launch prohibited this phase).

## L. Tests planned but NOT executed

Full 650-suite + focused set (last green E18-D); build verification;
single `no-env` run — all for the authorized next phase.

## M. Proven / NOT proven

Proven: design isolability (modulo inheritance disclosure). Not proven:
203 cause, isolation, production safety (all unchanged).

## N. Production GO / NO-GO — NO-GO (both).

## O. Next safe step

Approve 3-hunk patch + offline build + ONE `no-env` run per plan H.
