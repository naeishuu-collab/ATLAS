# RLM Egress Integration Plan (E12/E13 — audit and plan only, NO wiring)

Status: PLAN. Production RLMWorker integration is PROHIBITED until OS
isolation is proven. No code in `agents/rlm*.py`, `tools/_stubs.py`,
or `core/execution.py` was modified for this plan.

## Paths

- E12 legacy: `agents/rlm.py:486 _make_sub_query` / `:522` followup /
  `:532` batch → `self._engine.generate` directly (no ledger, no grant
  check beyond worker policy). Primary bypass candidate.
- E13 broker: `agents/rlm_rpc.py:466 HostLLMBroker` → `RequestLedger`
  exactly-once + `_explicit_policy_grant` + deadline/cancel. MUST NOT be
  altered: `begin/mark_dispatched/finish` transitions, `UNKNOWN_OUTCOME`
  stickiness, and `cancel_before_dispatch` semantics are load-bearing for
  the isolated worker.

## Why no wiring yet

1. AppContainer OS isolation NOT PROVEN — the worker has no OS boundary;
   adding dispatch power (even guarded) widens a live path.
2. `RequestLedger` transitions are frozen by the worker contract; a second
   ledger (CloudDispatchLedger) alongside it risks double-accounting the
   same logical send.
3. `rlm.py` legacy direct calls would need host-issued grants threaded
   through the REPL (`llm_query_fn`), i.e. control-plane surgery.

## Integration order (after isolation proof)

1. Prove AppContainer isolation (Codex) or equivalent OS boundary.
2. Migrate legacy `_make_sub_query` onto `HostLLMBroker` (single choke
   point) — no new ledger, no new grant type.
3. Only then evaluate sealed-payload requirements at the broker edge,
   with `RequestLedger` remaining the sole ledger for worker traffic.

## Stop conditions

Any worker Filesystem/Network grant, unisolated fallback, ledger change,
or File RPC (Phase 2D) stops the work.
