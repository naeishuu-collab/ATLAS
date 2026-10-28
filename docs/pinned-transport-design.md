# Pinned HTTP Transport & Hybrid Authority Design (offline, no prod change)

## 1. Transport audit findings (httpx 0.28.1 + httpcore 1.0.9, pinned)

- `_fetch_url` (`tools/web_search.py:200`): per-hop `check_ssrf` re-validation
  + redirect cap exist. Gap: `check_ssrf` resolves DNS, then `client.get`
  resolves AGAIN — classic check-then-connect TOCTOU.
- `httpx.Client` built without `trust_env=False` → env proxies apply
  implicitly (`_transports/default.py:140` default `trust_env=True`).
- SNI/cert hostname derive from connection ORIGIN, not the dialed address
  (`httpcore/_sync/connection.py:150-152`); pooling is keyed by origin
  (`can_handle_request`, `:167-168`). Therefore pinning the dial address
  inside the network backend preserves SNI, cert verification, Host
  header, auth, and pooling safety with zero TLS changes.
- `httpcore.ConnectionPool(..., network_backend=...)` (`connection_pool.py:60`)
  is the injection point. `httpx.HTTPTransport` does not expose it, so the
  wiring is: `transport = httpx.HTTPTransport(trust_env=False, proxy=None)`,
  then `transport._pool = httpcore.ConnectionPool(...,
  network_backend=ValidatingBackend(...))` — private-API touch, version
  pinned (httpx 0.28.1 / httpcore 1.0.9), hence PROOF-OF-DESIGN ONLY until
  httpx exposes backend injection publicly.

## 2. ValidatingBackend design (PoC in tests/security/test_pinned_transport_poc.py)

`connect_tcp(host, port, ...)`:
1. IP literal → classify via SSRF CIDR set; dial or raise `ConnectError`.
2. Hostname → ONE `getaddrinfo` via injected resolver; for each answer in
   order, classify; dial the first passing IP with
   `socket.create_connection((ip, port))`.
3. None pass → raise `ConnectError("no validated address")` — fail closed,
   retry/timeout semantics preserved (httpcore retries ConnectError).
4. No fallback to unchecked resolution. No userinfo (rejected upstream).
5. Proxy: none unless explicitly allowlisted (`proxy=None`,
   `trust_env=False` at transport build).

TOCTOU collapse: validation and dial consume the SAME resolution result
inside one `connect_tcp` call; rebinding across connections is safe
because every connection re-resolves AND re-validates. Residual: none
within a connection; cross-connection rotation is always validated.

## 3. Hybrid authority design (PoC in test_hybrid_authority_design.py)

- Policy owner: host process (operator config); never the model.
- Injection: `tavily_search_context(query, *, authority: HybridAuthority
  | None = None)` where authority bundles `(policy, bus, agent_id,
  confirm_callback, scope_taint)`. `None` → current direct behavior
  (documented residual, SSRF still applies).
- With authority: dispatch the REAL `WebSearchTool` through a ToolExecutor
  bound to the provided policy (capability floor `is_local=False` ⇒ policy
  mandatory); confirmation per spec (currently not required); session
  taint seeded from scope; result shape unchanged (`ToolResult`).
- No unlimited grants: policy is the host's existing `CapabilityPolicy`;
  missing policy ⇒ `HOST_AUTHORITY_UNAVAILABLE` (fail closed).
- LLM cannot alter the bundle (constructed host-side, never from params).

## 4. Readiness

- PoC proves selection/rejection logic offline. NOT proven: real-TLS
  interop, proxy-allowlist deployments, harness signature migration.
- Prod implementation requires: httpx public backend injection (or pinned
  private-API use with version tests), harness signature changes at 5
  call sites, policy plumbing from operator config. All BLOCKED pending
  those decisions — no prod change in this task.
