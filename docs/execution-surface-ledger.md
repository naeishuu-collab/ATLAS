# Execution Surface Ledger — JARVIS Astra (read-only audit, 2026-10-16)

- Branch: `opencode/cloud-privacy` @ `d596e482`, dirty 233 (unmodified by this audit)
- Scope: process/code execution paths reachable from agent, skill, MCP, CLI/daemon, eval harness.
- Rule: unverified items are marked UNKNOWN, never PASS. No production code changed.
- Shared gate (agent-invoked tools): `tools/_stubs.py` ToolExecutor —
  rate-limit → boundary-guard (non-local) → capability-policy (external/code
  require host policy) → taint-sink → confirmation → cancellation →
  mutation-intent/journal → per-tool UNKNOWN_OUTCOME serialization. Verified by
  reading `_stubs.py:367-660`.

## Agent-reachable tools (all pass through ToolExecutor gates above)

| ID | File:Line | Callee | Target | Authority / fail-closed | Evidence | Risk |
|---|---|---|---|---|---|---|
| ES-01 | `tools/shell_exec.py:102` | (deny, dead `run_sandboxed` below) | n/a | Unconditional `SHELL_SANDBOX_UNAVAILABLE`, NOT_STARTED | `test_subprocess_sandbox.py`, `test_host_authority_boundary.py` (mock) | P3: dead code retained |
| ES-02 | `tools/repl.py:60` | (deny; session machinery present) | n/a | Disabled until approved OS sandbox | `tests/tools/test_repl.py` | P3 |
| ES-03 | `tools/code_interpreter.py:157` | (deny; dead AST+`subprocess.run -I -B -S` below) | n/a | Unconditional `CODE_SANDBOX_UNAVAILABLE`, NOT_STARTED | `test_code_interpreter*.py` | P2: dead backend could be re-armed by a one-line edit; no test asserts unreachability |
| ES-04 | `tools/docker_shell_exec.py:99` | live `subprocess.run(docker exec …)` | task container only | Gated by `get_active_container()` + ToolExecutor; outside container → refuse | UNKNOWN (no regression asserting container binding) | P2: strongest live agent shell; container escape not assessed |
| ES-05 | `tools/browser.py:166,266` | live Playwright `chromium.launch` | arbitrary URL | SSRF guard never skipped (`check_ssrf`, pure-Python fallback); ToolExecutor caps/confirm apply | `test_ssrf*.py`, browser tests | P2: SSRF-proven, but no Safety-Authority/MutationIntent at tool level; relies on executor layer |
| ES-06 | `tools/windows.py:42,108` | UI automation grant/observe | window handle | STALE/NOT_STARTED on unproven identity; never resolves by text match | `test_windows_action_contract.py` etc. | P2: VERIFIED for contract tests; physical proof absent (Gate E) |
| ES-07 | `tools/git_tool.py`, `tools/http_request.py`, `tools/web_search.py`, `tools/llm_tool.py` | subprocess / network egress | repo, URLs, providers | Executor caps + boundary redaction + `security/cloud_dispatch.py` fail-closed egress | cloud/egress tests | P2: egress filter proven offline; live-provider behavior unproven |
| ES-08 | `tools/mcp_adapter.py:38` | remote MCP tool call | external server | Non-`InProcessTransport` → `MCP_HOST_AUTHORITY_UNAVAILABLE`, NOT_STARTED | `tests/mcp/*`, `test_direct_api_authority.py` | VERIFIED (fail-closed) |
| ES-09 | `tools/skill_manage.py:57`, `skills/manager.py` | composes existing tools via ToolExecutor | same as composed tools | Inherits executor gates; skills cannot add capabilities | skill tests | P3: workspace `./skills` auto-discovered (`cli/ask.py:447-450`) — provenance of workspace skills is operator-trust |
| ES-10 | `agents/tool_resolver.py:194` | `importlib.import_module` fixed names | `openjarvis.channels/tools/browser*` | Fixed allowlist; failures swallowed (`except: pass`) | n/a | P3: silent swallow could hide missing guard; low risk |

## In-worker / in-process code execution

| ID | File:Line | Callee | Target | Authority / fail-closed | Evidence | Risk |
|---|---|---|---|---|---|---|
| ES-11 | `agents/rlm_worker.py:337` | `exec(code, namespace)` in worker process | restricted namespace (`_SAFE_BUILTINS`, allowlisted modules, blocklist, `tool_call`/file helpers raise `RLMCapabilityUnavailable`) | Worker `start()` requires sandbox (`RLM_SANDBOX_UNAVAILABLE` → quarantine); all failures quarantine; approval gate denies production (`RLM_SANDBOX_NOT_AUTHORIZED`) | `test_rlm_sandbox_gate.py`, `test_native_approval_verifier.py` (48 tests incl. launcher-never-called) | VERIFIED fail-closed; P2 residual: in-process `exec` relies on builtins-restriction, not OS isolation (by design — sandbox is the boundary) |
| ES-12 | `agents/rlm_repl.py:115-131` | `_restricted_import`, blocklist incl. `os.system/os.popen` | module names | Restricted `__import__` + pattern block | repl tests | P2: blocklist layer; bypass resistance not fuzz-proven |
| ES-13 | `agents/rlm_worker.py:261` | `importlib.import_module` of `_SAFE_MODULES` | fixed allowlist | Fixed list, ImportError skipped | unit tests | P3 |

## Operator / direct paths (outside ToolExecutor by design — caller is host operator, not the model)

| ID | File:Line | Callee | Target | Authority / fail-closed | Evidence | Risk |
|---|---|---|---|---|---|---|
| ES-14 | `agents/hybrid/mini_swe_agent.py:215` | (deny `CODE_SANDBOX_UNAVAILABLE`; dead `Popen(bash -lc)` below) | n/a | Model commands never launched | UNKNOWN (no test asserts denial) | P1: live-looking `bash -lc` + `git clone` helpers one edit away from re-arming; **missing regression test** |
| ES-15 | `agents/claude_code.py:149,192`, `agents/opencode.py:232` | `npm install`, `node index.mjs`, SDK subprocess | runner dir / stdin-JSON | `_execution_denied_result()` gate before spawn | adapter tests | P2: gate exists but its denial conditions not mapped in this audit (UNKNOWN details) |
| ES-16 | `sandbox/runner.py:183`, `mining/_docker.py`, `mining/_pearl_subprocess.py` | `subprocess.run(docker …)`, `Popen(gateway)` | containers, miner loop | Operator-invoked; mount validation; timeout→kill | UNKNOWN | P2: operator-trust; container-escape posture unassessed |
| ES-17 | `sandbox/appcontainer.py:721` | `CreateProcessW` in AppContainer | launcher (unbuilt) | Approval verifier denies; launcher unreachable; Gate B script refuses without trust store | Pester 36, `test_appcontainer_sandbox.py` unit subset | VERIFIED fail-closed; physical proof absent |
| ES-18 | `cli/*_cmd.py`, `channels/*_daemon.py`, `core/utils.py:116`, `connectors/*` | `Popen/run` (daemons, open-url, oauth, scans) | host processes | Operator-invoked CLI/daemon context; `cli/ask.py:440,478` auto-confirms (`lambda: True`) in interactive pipeline | UNKNOWN | P2: auto-confirm means the human-in-the-loop is the terminal operator, not a per-action approver — acceptable for CLI but must not be mistaken for per-mutation authorization |
| ES-19 | `evals/scorers/*`, `evals/datasets/*`, `core/config.py:1892` | `exec`, `subprocess`, `eval(fld_type, vars(_cfg_mod))`, `ast.literal_eval` | test harnesses, config type names | Test-only / trusted-input; `literal_eval` safe; config `eval` limited to type namespace (noqa S307) | eval test suites | P3: `eval` on config-declared type names — poisoning requires config write; note, not gap |
| ES-20 | Async/subprocess-exec, `os.spawn/exec*`, `os.popen` | — | — | No occurrences found in `src/openjarvis` (grep) | grep evidence | VERIFIED ABSENT (static) |

## Authority Gap Analysis (10 questions)

1. Safety Authority bypass to spawn a process: **none found** for agent paths — ES-01/02/03/14 deny before spawn; ES-04/05/08 pass executor+gates. Direct operator paths (ES-16/18) never enter the authority domain by design.
2. Agent→shell direct call: **no** — `shell_exec` denies; MiniSWE `_run_bash` denies.
3. Skill/plugin arbitrary code: **no escalation** — skills compose executor-bound tools (`skill_manage.py`); workspace auto-discovery is operator-trust (P3).
4. MCP→host execution: **denied** — external transports refused (ES-08).
5. LLM-generated code unapproved: **denied** — interpreter/REPL/worker all gate before run.
6. MutationIntent bypass: executor enforces intent/journal for mutating tools when bound (`_stubs.py:590-619`); RLM worker serializes via quarantine. Unbound-executor configurations (no journal) rely on capability+confirm only — P2 gap, see below.
7. Dangerous retry after failure/timeout/disconnect: executor serializes per-tool mutations as UNKNOWN_OUTCOME until reconciled (`_stubs.py:620-645`); worker quarantines. **VERIFIED pattern.**
8. UNKNOWN_OUTCOME treated as success: **none found** — all paths surface it as failure/quarantine.
9. Async/parallel TOCTOU (authority vs target swap): per-tool mutation lock exists; cross-tool races and RLM RPC interleavings **UNVERIFIED (P2)**.
10. Privacy bypass to external: boundary-guard redaction + taint-sink + fail-closed cloud dispatch (`cloud_dispatch.py:217-226`). **Proven offline; live-provider exfiltration UNPROVEN (P2).**

## Missing regression tests

- T1: MiniSWE `_run_bash` denial + dead-`Popen` unreachability (ES-14) — NOT FOUND.
- T2: code_interpreter dead-backend unreachability assertion (ES-03) — NOT FOUND.
- T3: unbound-executor (no journal/policy) denial matrix for `code:execute` tools — PARTIAL (`test_host_authority_boundary.py` covers loader; extend to all).
- T4: cross-tool mutation race → UNKNOWN_OUTCOME serialization — NOT FOUND.

## Remediation priority

1. T1 (P1): pin MiniSWE denial — one failing-first test, no prod change.
2. T2 (P2): same pattern for code_interpreter.
3. T3 (P2): executor-without-policy matrix.
4. Trust-bootstrap approval (unchanged, gates everything physical).

## Recommended first fix (NOT implemented in this audit)

Add `tests/security/test_miniswe_deny.py`: call `_run_bash("touch …", tmp_path)` and assert
`security_denied is True`, `exit_code is None`, no file created; assert module source
contains the early-deny return before any `Popen` reference (static guard). Failing-first:
test fails today only if denial is removed — it documents the invariant.
