# P0-4 Staged Runtime Builder (IMPLEMENTED, offline only)

Implementation: `src/openjarvis/sandbox/staged_runtime.py`
(`BUILDER_VERSION=astra-p04.1`). Tests:
`tests/security/test_staged_runtime.py` (29 passed, 1 skipped).

## Layout

`manifest.json` + `runtime/{python.exe,python311.dll,python3.dll,
vcruntime140[.dll,_1.dll],DLLs/,Lib/}` + `worker/openjarvis/...`.
`Lib/test`, `Lib/__pycache__`, any `site-packages` are never staged.
No ACL work: proven claim is only
`STAGED_RUNTIME_CONTENT_INTEGRITY_AT_VERIFICATION_TIME`.

## Manifest (schema_version=1)

`{schema_version, builder_version, entry_module, python_version,
architecture, source_revision, files[{path,size,sha256,role}],
tree_hash}`. Canonical JSON (`sort_keys`, indent 2). No timestamps
(deterministic). No signature: host-trust model (integrity, not
authenticity). READY = `verify_runtime(root).ok` — exact tree equality,
reparse/sensitive/forbidden scans, hash + tree_hash agreement.

## P0-1 deltas (audit-proven, production untouched)

1. **httpx required at import** (P0-1 said third-party=0). Real closure
   is 27 files, not ~12: `agents/__init__` -> `agents._stubs` ->
   `engine._stubs` executes parent `engine/__init__.py`, whose
   unguarded lines 9-11 import `nim`/`ollama`/`openai_compat_engines`
   -> `httpx`. P0-1 scanned file-local imports and missed parent
   `__init__` execution. Empirically proven: `-S` interpreter without
   site-packages fails with `ModuleNotFoundError: httpx`; staged-env
   run reproduces it. Semantically unused by the worker (broker-mediated),
   but import-blocking under current code. Builder fails closed
   (`ThirdPartyBlocked`); no site-packages ever staged.
2. **Import-time `Path.home()`** (P0-1 said user profile not required):
   `core.paths` (via `core.config` <- `agents._stubs`) resolves the user
   home at import. No failure with a normal env; proven by scrubbed-env
   run (`RuntimeError: Could not determine home directory` until a neutral
   HOME/USERPROFILE was supplied). No file is read/written; location is
   still resolved — recorded as coupling, not a live defect.

## Surface metrics (dry-run inventory, real inputs)

927 files / 38,760,786 bytes: CPython 900 (exe+dlls+Lib+DLLs minus
test/pycache/site-packages), worker 27, third-party 0 staged
(httpx x4 required-but-blocked). P0-1 estimated ~4.2k files because it
counted unfiltered `Lib/`; exclusions remove ~3.3k test/cache/vendor files.

## Residual risks (not solved here)

`POST_VERIFICATION_HOST_MUTATION` (TOCTOU after verify), cross-process /
restart durability NOT PROVEN, no manifest signing, reparse detection is
best-effort (`lstat` + `FILE_ATTRIBUTE_REPARSE_POINT` on Windows).
Real-worker `HOST_STAGED_RUNTIME_BOOTSTRAP` = BLOCKED (httpx chain);
bootstrap MECHANICS proven with fixture worker on the real staged
interpreter (repo/venv/user-site absent from `sys.path`, no `__pycache__`
written, tree still verifies afterwards).

## P0-4B addendum (import boundary implemented)

Real closure: 14 files, third-party 0, no provider modules, no
`core.config`/`core.paths` (lazy `engine/__init__.py` with
`ensure_registered()` + `_stubs.py` method-level `load_config`).
Real staged `rlm_worker` bootstrap SUCCEEDS with no site-packages,
no repo root, no credentials, no home vars. Upgraded claims:
`REAL_HOST_STAGED_RLMWORKER_BOOTSTRAP_PROVEN`,
`WORKER_THIRD_PARTY_DEPENDENCIES_ZERO`,
`WORKER_PROVIDER_IMPLEMENTATIONS_ZERO`,
`WORKER_IMPORT_PROFILE_COUPLING_REMOVED` (staged artifact only).
