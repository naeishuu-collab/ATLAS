# SDK Final Wire Evidence (E15, offline)

## Installed SDK versions (venv, offline `importlib.metadata`)

- `openai` 2.21.0 — `DEFAULT_MAX_RETRIES = 2` (verified at runtime).
- `httpx` 0.28.1, `respx` 0.23.1, `aiohttp` 3.14.3, `requests` 2.32.5.
- NOT installed: `litellm`, `anthropic`, `google.genai` — their SDK
  internals cannot be inspected or executed offline.

## E15 fix: SDK-internal retry disabled (openai-based branches)

`src/openjarvis/engine/cloud.py` — all five `openai.OpenAI(...)`
constructions now pass `max_retries=0` (openai/openrouter/atlascloud/
minimax/deepseek). Root cause: SDK default retries twice on
retryable 5xx/429, invisibly resending under one grant. Anthropic/
Google/Codex branches do not use this SDK surface — out of scope.

## Proven: OpenAI-branch final wire (real SDK, MockTransport)

`tests/engine/test_cloud_wire_evidence.py` (3 tests, PASS) drives the
REAL `openai.OpenAI` client with injected `httpx.MockTransport`:

- Exact bytes: `POST https://api.openai.com/v1/chat/completions`,
  JSON body `model`/`messages` asserted, `Authorization: Bearer`
  asserted, exactly 1 request, ledger `EXECUTED`.
- 500 path: SDK raises with NO resend (1 request), ledger
  `UNKNOWN_OUTCOME` — retry-disabled proven at the wire.
- Digest mismatch denies with 0 requests.

## NOT PROVEN (BLOCKED as wire claims)

- LiteLLM `completion/acompletion`: SDK absent offline; no transport
  seam in `engine/litellm.py`; provider resolution, hidden retries,
  proxy/redirect, final bytes all unverified. Entry-guard only.
- CloudEngine anthropic/google/codex branches: SDKs absent offline;
  entry-guard only. Temperature retry is single-shot by code reading
  (no loop) but its second-call bytes use a MagicMock, not the wire.
- DNS/proxy env/TLS/C-extension sockets/subprocess transports.
