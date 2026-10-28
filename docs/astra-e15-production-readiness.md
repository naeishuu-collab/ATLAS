# E15 Production Readiness (snapshot after hybrid-retry fix)

## Root cause (evidenced, was disguised as order-dependent flake)

`src/openjarvis/agents/hybrid/_openai_retry.py::patch_openai_globally()`
runs at import time (`hybrid/_base.py:65`) and replaces
`openai.Completions.create` class-wide with an 8-retry + throttle
wrapper (`_MAX_RETRIES=8`, env `OPENJARVIS_OPENAI_MAX_RETRIES`).
Importing `openjarvis.agents.capability_router` pulls `agents.hybrid`
and installs it process-wide — including production CLI/server and
any test process. CloudEngine S6 openai-based branches (openai,
openrouter, atlascloud, minimax, deepseek) then emit up to **9 HTTP
POSTs per logical dispatch** (1 ledger entry). `max_retries=0` does
NOT stop it (independent loop above the SDK).

Separation (measured): 1 `_chat_completion_with_temperature_retry`
call → 9 MockTransport arrivals; ledger 1 entry;SDK `max_retries==0`
held. Pre-fix: `assert 9 == 1`. Not test pollution — a production
exactly-once defect exercised by import order.

## Fix (minimal diff, 2 production files)

- `_openai_retry.py::wrapped`: pop `_astra_single_send` (never reaches
  the wire); when set, call `orig` directly — no retry, no throttle.
- `cloud.py::_chat_completion_with_temperature_retry` (single choke
  point, all 11 openai-SDK call sites incl. streams): inject the flag
  ONLY when the wrapper is installed (`_hybrid_patched`); unpatched
  processes keep byte-identical kwargs (raw SDK rejects unknowns).
- Hybrid paradigms unchanged (flag absent → old behavior).

## Repro commands (offline, no network)

- Pre-fix observation: any run where `test_cloud_hardening` (or any
  hybrid importer) precedes `test_cloud_wire_evidence`, e.g.
  `pytest tests/security/test_cloud_hardening.py
  tests/engine/test_cloud_wire_evidence.py` → 9 sends, ~90s backoff.
- Post-fix: same command → 3 passed, ~3s, 1 send on the 500 path.
- Lock-in: `test_cloud_wire_evidence.py` now imports
  `capability_router` at module top, so the patch is always installed
  when these tests run (order-independent repro).

## Measured results

- Before: 500-path 9 sends / 1 ledger entry (exactly-once violated).
- After: 500-path 1 send → `UNKNOWN_OUTCOME`, no resend; 200-path
  exact bytes (POST URL/body/auth) 1 send → `EXECUTED`.
- Full suite: **650 passed, 0 failed** (41 files, unique, 126s —
  no backoff anywhere). Ruff clean. Compile clean.

## Still NOT PROVEN (unchanged)

LiteLLM/Anthropic/Google SDK wires (SDKs absent offline); DNS/proxy/
TLS; C-extension/subprocess transports; AppContainer isolation +
Error-203 cause; Production RLMWorker.

## Gate

Production Egress: NO-GO. Production RLMWorker: NO-GO. (Evidence
improved; safety claims unchanged in scope.)
