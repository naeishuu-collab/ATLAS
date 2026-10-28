# Hybrid Residual Risk Decision & Gate B–F Readiness (2026-10-16, offline)

Single deliverable for: legacy migration spec, retriever transport design,
closure checklist, Gate B–F matrix, backlog, rollback plan.
Evidence is file:line pinned; nothing here authorizes any gate.

## 1. Legacy migration specification

Public contract: `tavily_search_context(query, *, authority=None)`
(`agents/hybrid/_base.py:114`). `authority=None` runs the legacy direct
`WebSearchTool.execute` (`:160`) with an observability warning (`:156`).
In-repo callers (6) all pass host-built authority; the residual reach is
out-of-repo embeddings only. Reach is read-only search (SSRF-gated);
no mutation path exists (statically pinned).

| Option | Security | Compat | Cost | Verdict |
|---|---|---|---|---|
| A. Explicit-authority new API | best | breaks unknown embedders | medium | REJECT now |
| B. Host Authority Context on existing API | same as A | additive kwarg, default keeps old | small | ADOPTED (done: `authority` kwarg + `authority_for_search`, `skillorchestra/tools.py:335`) |
| C. Deprecate then deny | best long-term | needs notice window | small later | DEFERRED — release condition below |
| D. Read-only restriction | n/a (already read-only) | — | — | no-op, already true |

Decision: stay on B. C unlocks only when: (1) warning-telemetry shows
zero legacy hits for one release cycle, (2) migration note shipped,
(3) explicit owner approval. Unconditional deny now is BLOCKED (compat).

## 2. Retriever transport security design

Chain: `method_cfg.retriever_url` → `orchestrator.py:240` cfg read →
`run_search(retriever_url=...)` (`:371`) → POST `{url}/retrieve`
(`tools.py:426-430`). LLM controls query/body only, never the URL.
Worker gate (`:403`) precedes POST; denial sends 0 bytes. Pinned gaps
(`test_retriever_transport_defaults_are_explicit_residuals`): redirects
followed (default True), env proxies apply, cert verify default-on.

| Option | Verdict |
|---|---|
| A. Strengthen in place (allow_redirects=False, trust_env=False, URL allowlist, body cap) | IMPLEMENTED 2026-10-16 (`tools.py:355` `_validated_retriever_url`, Session `trust_env=False`, `allow_redirects=False`; plaintext http allowed for loopback only) |
| B. Host-owned Transport Broker | DEFERRED (new layer; only if A proves insufficient) |
| C. Secured-Tool conversion | REJECT (retriever is operator infra, not a model tool; no capability gain) |
| D. Dedicated capability + fixed destination | PARTIAL-ADOPT: `skillorchestra_retriever` op id already distinct (`:400`); destination allowlist folds into A |

Design requirements for A: redirect deny, proxy deny-by-default,
destination validated against operator allowlist, `query[:390]`/topk
caps kept, deny ⇒ HTTP 0, error schema unchanged.

## 3. Hybrid Authority closure checklist

PASS requires ALL: (1) every reachable external-I/O path forces
authority; (2) Policy=None fail-closed; (3) capability + agent-identity
enforced; (4) no direct fallback; (5) taint/quarantine/journal held;
(6) UNKNOWN_OUTCOME preserved; (7) exactly-once on managed executors;
(8) privacy/transport bounded; (9) schema compat; (10) regression green.
Today: (1)–(4),(6),(9),(10) proven for tavily 5/5; (5),(7) hold by
executor contract; retriever transport controls are the open item (§2A).
Scope-out (documented, not PASS-blockers): provider SDK internals,
third-party Modal sandbox, SWE loop (deny-proven unreachable).
Verdict: PARTIAL until §2A lands.

## 4. Gate B–F readiness matrix

Source: readiness doc §§22–26; verified 2026-10-16 (script present,
`build-authority/*` absent, HEAD `d596e482`).

| Gate | Authorizes | State | Missing evidence | Release condition |
|---|---|---|---|---|
| Trust ceremony | key/store only | NOT EXECUTED | designated authority, countersigned store | human ceremony §24.2 |
| B build | one isolated C build | NOT AUTHORIZED | RS256 envelope over snapshot+script+toolchain | envelope + trust store |
| C sign | sign built PE | NOT AUTHORIZED | signing identity/infra | B artifact + §20.3 |
| D policy | WDAC install | NOT AUTHORIZED | artifact rule; host is daily-driver laptop (lockout risk) | C signature + disposable host |
| E physical | 19-scenario lane | 0/19 NOT EXECUTED | isolated host | D policy + lane auth |
| F production | launcher wiring | DENIED | B–E evidence | A–E + Policy Owner |

No gate implies another; each needs its own authorization record.

## 5. Implementation backlog (priority order)

1. Retriever transport hardening (§2A) + regression — small, compat-safe.
2. Legacy deny-flip (§1C) after telemetry + notice — needs owner approval.
3. Re-audit only if (1)/(2) change behavior; otherwise NO further audits.

## 6. Rollback / compatibility plan

- Current state rollback: delete the new pin test; prod untouched
  (warning-only), so behavior is identical with or without this task.
- Future §2A rollback: revert flag args to defaults (redirect/proxy
  behavior returns; deny-path unchanged). Never restore legacy silent
  direct call: keep the warning log line in any rollback.
- Compat rule: no unconditional deny without notice window + telemetry.

---
Offline only: no network/shell/Docker/VM/WDAC/AppContainer executed.
Risk: P2 residuals (legacy embed, retriever redirect/proxy) unchanged
by this task; no new exposure introduced.

## 7. Closure freeze (2026-10-16, no prod change)

Conditional-PASS scope (frozen): in-repo reachable tool paths (tavily
5/5 via host authority: `toolorchestra.py:380`, `skillorchestra/
tools.py:437`, `minions.py:389`, `conductor.py:601`, `advisors.py:310`;
retriever via §2A hardened transport `tools.py:452-464`) — proven by
446-test offline battery. Explicitly OUT of the PASS: out-of-repo legacy
embeddings (DEFERRED, unlock = telemetry + notice + owner approval),
provider SDK internals, third-party Modal sandbox, real-TLS/DNS
pinning (mock-proven only), Gates B–F (all BLOCKED, separate human
authority each). No re-audit of frozen items without behavior change.

Physical-proof environment plan (NOT executed): disposable Windows host
or VM with snapshot/rollback; Administrator held by the operator with
lockout prevention (no enforcement on the daily-driver laptop);
network-isolated lane; evidence capture per gate (artifact hash,
signature, policy state, 19/19 lane); each gate needs its own human
authorization record. WDAC/signing/ceremony/real-network stay
forbidden in this workstream.

Backlog: (1) legacy deny-flip after telemetry + notice; (2) Gate B
envelope issuance on a disposable host; (3) C/D/E/F strictly in order.
Rollback rule: revert hunks only; never restore silent direct calls.
