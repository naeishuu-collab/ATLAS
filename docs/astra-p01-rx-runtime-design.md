# P0-1 Least-Privilege RX Runtime Design (DESIGN ONLY)

## Startup path (audited)

`multiprocessing spawn` → `python.exe` → `python311.dll` → stdlib →
`openjarvis.agents.rlm_worker` (+`rlm_repl`, `rlm_rpc`, `core.types`,
`core.execution`, package `__init__s`, `agents._stubs`, `core.registry`).
Top-level third-party imports in closure: ZERO (`tomli` is 3.11-fallback
only; stdlib `tomllib` used). REPL dynamic allowlist is stdlib-only
(json/re/math/…). No site-packages needed worker-side (broker stays host).

## Resource classification

- EXECUTE_REQUIRED: `python.exe` (+`pythonw` NOT required).
- READ_REQUIRED: `python311.dll`, `vcruntime140(_1).dll`, `DLLs/*.pyd`
  (notably `_multiprocessing`), stdlib `Lib/` (full recommended — spawn
  + REPL import dynamically; subset = P2 optimization), first-party
  ~12 files (`agents/{rlm_worker,rlm_repl,rlm_rpc,_stubs,__init__}`,
  `core/{types,execution,registry,__init__}`, root `__init__`).
- WRITE_REQUIRED: NONE — with `PYTHONDONTWRITEBYTECODE=1` (+`-B`):
  no `__pycache__`, no temp files (Pipe is handle-based), no logs,
  no dumps attributable to worker, no state files found.
- NOT_REQUIRED: venv site-packages, repo root, user profile, tests,
  docs, evidence, `.env`/credentials, model files (none local).
- UNKNOWN: none material (closed via import scan + spawn-path review).

## Options

- A (RX into host Python + repo paths): ~5k+ files incl. full repo
  (705 py + docs/tests/evidence/dev files). REJECTED: repo-root exposure,
  ACL drift on dev-owned tree, update fragility.
- B (staged immutable runtime): exe+dlls + full `Lib/` + ~12 first-party
  files; repo/user-profile/credentials excluded; manifest-hashed.
  RECOMMENDED.
- C (frozen exe): breaks dynamic REPL imports, build/debug cost high.
  REJECTED unless B fails.

## Secrets: WORKER_PROVIDER_CREDENTIAL_ACCESS = NONE (broker-mediated)

No credential file in B tree by construction (verify at manifest:
reject `.env`/`*.pem`/`*secret*`/`*token*` names). Parent-env keys must
NOT inherit (E18 lesson) — explicit minimal env (below).

## ACL model (no mutation performed)

- Principal: per-run AppContainer SID (narrowest; NOT ALL_APP_PACKAGES).
- ACE: allow RX files (`GENERIC_READ|GENERIC_EXECUTE`), dirs
  traverse+list+read-attr, `OI|CI` on runtime root only.
- No WRITE/DELETE/DAC/OWNER anywhere in runtime.

## Layout / manifest / TOCTOU

`AstraWorkerRuntime/{manifest.json,runtime/,stdlib/,worker/}` +
optional separate scratch (not required now). Manifest: file→SHA-256,
CPython/repo revisions, unexpected-file rejection;
`RUNTIME_MANIFEST_VALID` gate pre-launch. TOCTOU residual HONEST:
host-mutable dir cannot give cryptographic launch integrity; mitigation
= verify-immediately-pre-launch + admin-owned staging in production
deployments (dev residual accepted, recorded).

## DLL search / env / CWD / scratch

- DLLs: adjacent to exe + System32 only; CWD=runtime root (no writable
  DLLs); no user-profile/PATH entries.
- Env (explicit block, E18-safe): SYSTEMROOT, minimal PATH, PYTHONHOME
  + PYTHONPATH→staged dirs, PYTHONDONTWRITEBYTECODE=1; NO API keys,
  NO repo paths, NO TEMP inheritance (omit or scratch-only).
- CWD: runtime root (immutable). Scratch: none required; if later needed,
  per-session dir, no-exec, verified cleanup.

## Profile/SID + cleanup/rollback + fail-closed

- Per-run unique profile (proven pattern) + grant-at-launch +
  revoke-at-cleanup (ACE tagged by SID); stable profile rejected
  (cross-run contamination).
- Rollback: pre-state ACL dump → add ACE → lifecycle → remove ACE →
  verify restore. Fail-closed: `RUNTIME_READY && MANIFEST_VALID &&
  ACL_VALID && PROFILE_VALID && TOKEN_EXPECTATION_DEFINED` else
  `SANDBOX_FILESYSTEM_SETUP_FAILED`, never repo-root/unsandboxed fallback.

## Descendant/IPC impact

- Spawn re-exec resolves INSIDE staged runtime → E19-D creation-denial
  will not recur for the real worker; makes P1 AC-readable containment
  proof feasible (same location). Anonymous Pipe IPC unaffected by FS
  layout (handle inheritance).

## Surface metrics (approx)

- A: ~4.2k Python files + 705 repo py + dev tree; repo+profile exposed.
- B: ~4.2k runtime-justified files, 0 repo files, 0 writable, 0 secrets.
- C: 1 image + bundle; fragile.

## Decision: OPTION B. P0 plan

1 manifest/builder spec → 2 staging → 3 ACL provision+verify →
4 launcher integration → 5 fail-closed startup → 6 cleanup/rollback →
7 dedicated regression. (All future; nothing implemented here.)
