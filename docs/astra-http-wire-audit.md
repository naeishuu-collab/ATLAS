# Astra HTTP Wire Audit (offline evidence only)

## Proven (exact bytes asserted via MockTransport/respx)

- S2 NIM: POST `{host}/v1/chat/completions`, OpenAI-shaped JSON body,
  model/messages/temperature asserted per request. Redirect: httpx
  default no-follow; 3xx → FAILED (no silent empty stream).
- S4 compat: POST `{host}{prefix}/chat/completions`; SSE `data:` parse;
  `follow_redirects` off; 400 tools-strip retry is the ONLY second-send
  shape and is attempt-bounded (attempts==1) with digest re-verification.
- S3 router: per-provider URLs asserted; key-in-URL (Google) logged as
  leak surface, excluded from audit logs; local Ollama POST asserted.
- S1 tool: no socket of its own (delegated); kwargs forwarded verbatim
  except popped auth fields; proxy keys asserted absent at the boundary.

## NOT PROVEN (BLOCKED as wire claims)

- S5 LiteLLM: `litellm.completion/acompletion` internals — model string
  → provider resolution, hidden retries/fallbacks, proxy handling,
  final bytes. Entry-level checks only.
- S6 CloudEngine: 8 vendor SDKs — per-SDK wire shapes, temperature-retry
  second call bytes, stream chunk framing, key placement. Entry-level
  checks only. Temperature retry is single-shot by code (no loop).
- DNS resolution, proxy env (`trust_env` is disabled only where we
  construct clients; SDK clients are opaque), TLS behavior, C-extension
  sockets, already-connected descriptors.
- Network-denial harness covers `create_connection`/`getaddrinfo`;
  literal-IP `socket.connect` bypasses it (documented residual).

## Canonicalization rule

Digests cover semantic (role, content) + engine/provider/model/endpoint
as canonical JSON. SDK envelope differences are tolerated ONLY where
the transport is in-repo (S2/S3/S4); SDK paths tolerate nothing beyond
the verified semantic set and mark wire NOT PROVEN.
