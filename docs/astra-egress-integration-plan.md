# Astra Cloud Egress Integration Plan (design only — no wiring)

Status: DESIGN. No production egress path is modified or connected by
this document. Integration must not start without explicit approval and
without closing the blockers in §15.

Base: `d596e482` / branch `opencode/cloud-privacy` (OpenCode worktree only).

## 1. Egress inventory (13 paths)

| # | Path | Final send point |
|---|---|---|
| 1 | HostLLMBroker (RLM isolated) | `agents/rlm_rpc.py:620` → bound engine |
| 2 | RLM legacy direct | `agents/rlm.py:486,522,532` → `engine.generate` |
| 3 | Planner / generic agents | `agents/planner.py:116`, `_stubs.py:290`, `research_loop.py:662,849` |
| 4 | LLM Tool | `tools/llm_tool.py:79` |
| 5 | CLI / Bench / Serve | `cli/ask.py:1221`, `chat_cmd.py:510`, `serve.py:198`, `bench/*` |
| 6 | MultiEngine fan-out | `engine/multi.py:81` via `_engine_for:45` |
| 7 | CloudEngine | `engine/cloud.py` `_generate_*` (vendor SDKs) + `httpx.post:619` (codex) |
| 8 | CloudEngine streaming | `engine/cloud.py:1294` → `_stream_*:1334-1764`, `stream_full:1967` |
| 9 | LiteLLMEngine | `engine/litellm.py:65` `litellm.completion` / `acompletion` |
| 10 | NIMEngine | `engine/nim.py:84` POST + `:154,:206` streams |
| 11 | OpenAI-compatible remotes | `engine/_openai_compat.py:104,108` POST (+tools-strip retry) |
| 12 | Direct Cloud Router | `server/cloud_router.py:179,226,278` streams + `stream_local:329` |
| 13 | Server route switch | `server/routes.py:493,852,993,1024` (cloud vs engine branch) |

Current protection on all 13: NONE (new guard unwired).

## 2. Enforcement point per path

Authorization is enforced at the adapter boundary — the last code that
can see the wire payload before the socket/SDK call:

- Paths 7–11: inside each engine's `generate`/`stream`/`stream_full`,
  immediately before `post`/`client.*`/`litellm.*` calls.
- Path 12: inside `_stream_openai/_stream_anthropic/_stream_google`
  (and any non-stream `generate_cloud` equivalent) before `client.stream`.
- Path 13: the `use_cloud` branch delegates to path-12 functions; no
  separate check (single choke point preserved).
- Paths 2–5: wrapped by `EgressGuardedEngine`; direct `engine.generate`
  imports are migrated to the wrapped handle (mechanical, caller-shaped
  tests already exist).
- Path 6: `_engine_for` resolves first; the resolved engine's own
  enforcement applies (no second decision at the multi layer).
- Path 1: UNCHANGED. `HostLLMBroker` keeps its own ledger and grant
  check. General dispatch ledger never double-tracks broker requests.

## 3. Shared egress adapter boundary

`EgressGuardedEngine` (sync `generate`, async `stream`/`stream_full`)
plus equivalent guards inside `cloud_router.py` functions form the
common adapter. Responsibilities:

- accept ONLY sealed `AuthorizedPayload` (`cloud_dispatch` kwarg);
- `verify_for_send` / `verify_wire_payload` at the send instant;
- bind `CloudDispatchLedger.begin → mark_dispatched → check_send →
  finish` around the send;
- emit digest-only audit records.

The adapter never classifies, never redacts, never selects providers —
it verifies.

## 4. Authorizer placement

`CloudDispatchAuthorizer.authorize` runs host-side, before dispatch,
once per logical request. Callers build `CloudDispatchRequest`
(classification, provider+endpoint, messages, grant, budget). Router
output (`RouteDecision`) is an input hint to request construction, never
a substitute for authorization.

## 5. Final wire payload verification

`verify_wire_payload(authorized, wire, endpoint=...)`:

1. `extract_semantic_messages` supports OpenAI `messages`, Anthropic
   `messages`, Google `contents/parts`. Unknown shapes → DENY.
2. Semantic (role, content) pairs are digest-compared to the sealed
   authorization; SDK envelope fields are tolerated, content drift is not.
3. The presented endpoint must equal the bound endpoint; when
   `allowed_endpoints` is configured, membership is re-checked.
4. Scanners re-run over the final content (redact-then-reintroduce race).

Provider routes whose wire shape cannot be proven FAIL CLOSED.

## 6. Identity: provider / model / endpoint

`ProviderIdentity(engine, provider, model, is_cloud, endpoint)`.
Allowlist matches the `(engine, provider, model)` triple exactly;
`allowed_endpoints` binds the network destination independently. Both
are sealed into the payload digest. Local destinations use
`local_allowlist` host sets (§7 of `egress_guard`).

## 7. Sync / async / streaming

Outbound messages are frozen before the first byte. `stream`,
`stream_full`, `stream_cloud`, `stream_local` verify identically to
`generate`. Mid-stream message appends, tool additions, and provider
switches are prohibited; a new dispatch (new id, new authorization) is
required. Interruptions quarantine as UNKNOWN_OUTCOME
(`note_stream_interrupted`).

## 8. Fallback / retry

- Same-id retry is always denied (`CLOUD_PAYLOAD_CHANGED`), including
  after UNKNOWN_OUTCOME.
- Provider-changing fallback (multi cloud-prefix, openrouter→openai
  delegation, tools-strip retry that changes host) requires FRESH
  authorization for the actual destination.
- Pre-send deterministic failures (`fail_before_send`: DNS/refused/
  connect timeout) are FAILED, not UNKNOWN — a new authorization may
  retry; the old id may not.
- Post-send ambiguity (timeout waiting, cancel, partial body, broken
  stream) is UNKNOWN_OUTCOME with quarantine; reconciliation reviews
  evidence and never re-sends.

## 9. Ledger separation

`RequestLedger` (RLM worker LLM RPC exactly-once) and
`CloudDispatchLedger` (general cloud dispatch integrity) are disjoint by
construction: broker-owned requests never enter the dispatch ledger,
guard-owned requests never enter the broker ledger. `ExecutionJournal`
transitions are untouched by both.

## 10. UNKNOWN_OUTCOME

Sticky quarantine. No automatic provider switch, no same-id retry.
`reconcile_unknown` requires worker-stopped proof + observation and
returns the entry for inspection only. Follow-up work needs a new
authorization with a new dispatch id.

## 11. Fake-transport verification plan

- `httpx.MockTransport` seam (already present in `_openai_compat.py:72`)
  replicated per adapter; fake engines asserting payload capture.
- Negative matrix (implemented in `test_cloud_hardening.py`): unknown
  classification, PRIVATE cloud, missing/expired grant, provider/model/
  endpoint mismatch, payload mutation, scanner outage, secret leakage,
  duplicate dispatch, UNKNOWN retry, unauthorized fallback, streaming
  without auth, SDK wire mutation, disguised local, direct-router shape.
- Rule: a test proves enforcement only if it fails with the guard
  removed (boundary-adjacent assertion, not mock-internal success).

## 12. Feature flag / rollout

- `egress_enforcement: off | shadow | enforcing` (default off).
- Shadow records ALLOW/DENY decisions to digest-only audit WITHOUT
  changing send behavior — EXCEPT shadow never transmits data that the
  authorization denied (see §13).
- Rollout per path (12 → 7–11 → 6 → 2–5); path 1 excluded permanently.
- Rollback = flag step-down (enforcing → shadow → off), never a code
  revert under pressure.

## 13. Fail-closed rollback (mandatory corrections)

- DENY in shadow mode MUST NOT transmit the denied bytes. Shadow
  evaluation is restricted to fake providers, synthetic data, or
  requests that independently hold a valid authorization.
- PRIVATE / UNKNOWN-classification / secret-bearing payloads are never
  transmitted in any mode without a sealed ALLOW.
- Flag OFF does not restore "unprotected cloud sending": it restores
  the pre-integration code path only via a safe halt or an
  independently verified safe route — never by silently re-enabling
  raw cloud egress. UNKNOWN_OUTCOME entries are never discarded by a
  flag transition.

## 14. Local endpoint rules (mandatory)

- A remote endpoint is never classified as local. Classification is by
  explicit `local_allowlist` host set, not by `is_cloud` flags alone.
- Strict deployments set `local_allowlist` (loopback/LAN); anything
  else is denied as a possible disguised remote.
- DNS resolution changes, HTTP redirects, proxies, and endpoint
  mutations after authorization invalidate the dispatch
  (`CLOUD_PAYLOAD_CHANGED` / `ENDPOINT_NOT_ALLOWED`); adapters must
  not follow redirects across destinations.

## 15. Production regression & stop conditions

- Regression: full `make test` lane (minus live/cloud/hub markers) +
  Rust suite once the build-policy blocker clears.
- NOT PROVEN carry-overs: 12 RLM RPC tests (Rust), AppContainer
  isolation, all 13 wired paths (unwired by design).
- STOP integration if: live-cloud requirement appears, policy bypass
  is needed, UNKNOWN retry is requested, provider identity mismatch is
  tolerated, unexpected egress observed, or any safety regression fails.
