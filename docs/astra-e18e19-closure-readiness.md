# E18/E19 Closure + Production RLMWorker Readiness (ANALYSIS ONLY)

## Authoritative matrix (no reruns)

- Startup identity: PROVEN (TRUE/1/SID_MATCH/cleanup).
- Filesystem: PROVEN for tested fixture (host ok, API reached, read+write 5).
- Named Event: PROVEN for tested object (control ok, API reached, 5).
- Loopback: NOT PROVEN (10061 ambiguous; C2 anomaly; C3 timeout 10060,
  server FALSE — drop observed, attribution refused; NO C4).
- Internet: NOT TESTED. Descendant containment: NOT TESTED
  (creation denied err=5 for user-ACL image location).
- Complete sandbox / RLMWorker / Egress: NO-GO maintained.

## Mechanism confidence (observed vs proven)

- FS/Event denials: observed 5; proven property = tested-resource
  inaccessibility; mechanism (ACL/package boundary) plausible, attribution
  NOT proven as sole cause (integrity policy also in play).
- Loopback timeout: observed drop; property proven = none beyond the
  observation; mechanism NOT proven.
- Descendant denial: observed 5 at creation; property = no descendant
  creatable from that image location; image-ACL mechanism REPORTED only.
- Startup: observed token/SID match; property = identity; mechanism =
  SECURITY_CAPABILITIES plumbing, directly evidenced.

## Current RLMWorker architecture (read-only audit)

- `agents/rlm_worker.py:RLMWorker`: `multiprocessing spawn` child +
  duplex Pipe; fail-closed quarantine (13 call sites, terminal, no
  retry loops); no restart path (closed/quarantined → raise).
- Broker `rlm_rpc.py:HostLLMBroker`: in-host, threading, no retry loop.
- REPL `rlm_repl.py`: import allowlist + blocked patterns
  (open/subprocess/socket/os.system). Generated code constrained;
  `rlm.py` prompt forbids open/subprocess/urllib.
- Legacy REPL requires explicit `allow_unsafe_legacy_repl` (default off);
  worker-without-policy → authorization-denied result (fail-closed).
  No silent unsandboxed fallback exists TODAY (no sandbox exists yet —
  future integration must preserve this).

## Requirement decisions

- NETWORK: worker makes zero direct network calls (REPL blocks socket;
  llm_query → pipe → host broker → engine). Preferred: broker-mediated,
  worker stays zero-net. E19 network NOT PROVEN → MITIGATED
  architecturally (P1 hardening/P2 debt, NOT P0), conditional on broker
  boundary holding + egress guard unchanged.
- DESCENDANT: production worker SPAWNS (multiprocessing). Subprocess is
  REQUIRED by current design. E19-D denial came from image ACL, not
  policy — an AC-readable image location would likely allow creation,
  making containment UNTESTED. Future AC-readable descendant proof =
  MANDATORY before contained-spawn claims (P1). Alternative (P0-adjacent):
  redesign to spawn-free worker (major surgery, not recommended now).
- FILESYSTEM: spawn re-exec needs RX on python.exe + stdlib + venv +
  repo (`rlm_repl`, `rlm_rpc` imports). Zero-cap token lacks these by
  default → worker will NOT START in sandbox as-is. Least-privilege
  RX grants (or packaged runtime) = P0 design work. Writes: none
  required (no worker file output found) → deny-by-default stands.
- IPC: anonymous duplex Pipe (handle inheritance, no namespace) is
  AppContainer-compatible in principle; broker stays host-side.
  P1 integration proof needed (frame validation over the pipe already
  exists in `rlm_rpc` validate_* — reuse).

## Exactly-once risks (future integration)

No retry in worker/broker today (verified). Risk points: spawn-restart
after crash (currently impossible — closed raises; keep it fail-closed),
broker timeout resend (none today), SDK retry inside engines (E15 fixed
openai branches; broker must not add its own). Single-send authority:
DispatchLedger at engine send point (unchanged); worker/broker layers
must never retry a send — Receive UNKNOWN → quarantine (exists).

## Production sandbox architecture (proposed)

Host Astra: Safety Authority → Grant issuer → Egress Guard → RLM Broker
→ AppContainer Worker (spawn, zero-net, RX-only runtime, pipe IPC,
job-contained, zero caps, no arbitrary descendants). Worker = untrusted
executor, never authority.

## Fail-closed startup + fallback + observability + lifecycle

- Startup: any uncertainty (profile/SID/token/job/caps/RX-grant/IPC) →
  `SANDBOX_STARTUP_FAILED`, no execution, no silent host fallback
  (future enforcement point: worker start path `rlm_worker.py:704`).
- Observability fields: invocation/worker PID/profile SID/token-flags/
  caps-hash/job/broker-session/grant/nonce/dispatch/exit/timeout/
  UNKNOWN/cleanup (partially exists: session/nonce/request_count).
- Lifecycle: create→configure→launch→verify→broker→execute→terminate→
  close→delete→verify (mirrors proven test lifecycle).

## GO gates (all NOT SATISFIED except regressions)

1 AppContainer regression NOT FOUND; 2 Safety Authority regression
NOT FOUND; 3 FS design PARTIAL (RX-grant plan needed); 4 IPC design
PARTIAL; 5 fail-closed startup NOT SATISFIED; 6 no-fallback NOT
SATISFIED (no sandbox yet); 7 lifecycle PARTIAL; 8 exactly-once PARTIAL
(E15 done, integration pending); 9 observability PARTIAL; 10 E2E
NOT TESTED.

## Priorities

- P0 (blockers): RX-grant/packaged-runtime FS design; fail-closed
  startup; no-fallback enforcement; Safety Authority regression;
  AppContainer regression.
- P1 (pre-E2E): AC-readable descendant containment proof; pipe-IPC
  integration proof; observability; lifecycle.
- P2 (debt): loopback/Internet physical denial (mitigated by zero-net
  architecture); kill-on-close demo; full sandbox completeness.
