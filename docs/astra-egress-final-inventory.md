# Astra Egress Final Inventory (rebuilt from code, HEAD d596e482)

Do NOT treat the old "13 paths" as fixed truth. Independent send points:

## A. Independent real send points (7)

| # | Send point | Transport | Guard |
|---|---|---|---|
| S1 | `tools/llm_tool.py` → engine (E1) | delegated engine | ✅ flag+sealed+ledger |
| S2 | `engine/nim.py` 3× httpx POST (E2) | httpx, seam: replaceable `_client` | ✅ |
| S3 | `server/cloud_router.py` 4× httpx stream (E3) | httpx inline clients | ✅ |
| S4 | `engine/_openai_compat.py` 3× httpx (E4, 9 keys) | httpx + `_async_transport` seam | ✅ |
| S5 | `engine/litellm.py` completion/acompletion (E5) | SDK-internal, NO seam | ✅ entry-only |
| S6 | `engine/cloud.py` 8 SDK branches (E6) | SDK-internal, NO seam | ✅ entry-only |
| S7 | `engine/ollama.py` `/api/chat` | httpx | ❌ unwired (local-first) |

## B. Delegation-only (no socket)

MultiEngine (E7 routing gate ✅), Planner/Agent/CLI/Bench/LLM-callers,
`routes.py` branch (delegates to S3/S5/S6/S7 or engines).

## C. Local-only

Ollama default loopback, llama.cpp/vLLM/LMStudio localhost servers,
`stream_local`, gemma_cpp in-process, Nexa shim.

## D. Prohibited

Legacy RLM direct dispatch, HostLLMBroker/RequestLedger changes,
Phase 2D File RPC, worker Filesystem/Network grants.

## E. Watch list (unverified absence claims)

Exo/Uzu/AppleFM shims, MCP server subprocess transports, channel
bridges (TS), desktop Tauri networking, scheduler webhooks — audited by
name only; a new socket owner here would be a new path.
