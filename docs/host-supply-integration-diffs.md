# Host supply → production integration diffs (approval package)

Status: **DOCUMENTED, NOT APPLIED.** Owner approval is unknown for every
shared file below; each carries pre-existing uncommitted parallel work.

New independent module (already merged, untracked):
`src/openjarvis/agents/host_supply_factory.py`

Contract assumed by every diff:

- `load_host_supply_from_env(scanners=..., capability_policy=...)` returns
  `None` when `JARVIS_HOST_SUPPLY_PATH` is unset (legacy byte-for-byte)
  and raises `HostSupplyError` when a configured document is invalid.
- The bundle's own flags stay default OFF; a document must set
  `shadow_enabled` / `cloud_egress_enabled` explicitly.

---

## 1. `src/openjarvis/security/__init__.py` — expose the scanners it already built

`SecurityContext` currently hides the `scanners` list it constructs at
line 45, so the wiring cannot inject host scanners into the authorizer.

```diff
@@ class SecurityContext
     capability_policy: Any = None
     audit_logger: Any = None
     rate_limiter: Any = None
+    scanners: tuple = ()

@@ def setup_security(...)
     # Scanners + engine wrapping
+    scanners: list[BaseScanner] = []
     try:
-        scanners: list[BaseScanner] = []
         if config.security.secret_scanner:
@@     return SecurityContext(
         engine=engine,
         capability_policy=cap_policy,
         audit_logger=audit,
         rate_limiter=rate_limiter,
+        scanners=tuple(scanners),
     )
```

Default OFF: unchanged — `scanners=()` when security is disabled.

## 2. `src/openjarvis/system/core.py` — one host-owned field

```diff
@@ class JarvisSystem
     # Keep newly added fields after every pre-existing positional field so
     # older positional JarvisSystem(...) calls retain their original meaning.
     mcp_tools: List[BaseTool] = field(default_factory=list)
     rate_limiter: Optional[Any] = None
+    # Host-owned supply bundle. None keeps the legacy tick unchanged.
+    host_supply: Optional[Any] = None
```

## 3. `src/openjarvis/system/builder.py` — build supply once, attach it

```diff
@@ build()  (after `sec = setup_security(config, engine, bus)` / `engine = sec.engine`)
+        from openjarvis.agents.host_supply_factory import (
+            load_host_supply_from_env,
+        )
+
+        host_supply = load_host_supply_from_env(
+            scanners=sec.scanners,
+            capability_policy=sec.capability_policy,
+        )

@@ JarvisSystem(...)
             rate_limiter=sec.rate_limiter,
+            host_supply=host_supply,
```

A configured-but-invalid document raises: the host fails closed instead of
starting unenforced.

## 4. `src/openjarvis/server/app.py` — the server's single supply point

`create_app` already derives every other security primitive here
(lines 217, 305-307).

```diff
@@ create_app(...)
             if audit_logger is None:
                 audit_logger = derived_security.audit_logger
+            scanners = derived_security.scanners
+        else:
+            scanners = ()
+
+    from openjarvis.agents.host_supply_factory import (
+        load_host_supply_from_env,
+    )
+
+    host_supply = load_host_supply_from_env(
+        scanners=scanners, capability_policy=capability_policy
+    )
@@ create_app(...)
     app.state.audit_logger = audit_logger
+    app.state.host_supply = host_supply
```

## 5. `src/openjarvis/server/agent_manager_routes.py` — tick facade carries it

Covers both executor sites (lines 1789 and 2199) because both build the
system through this helper.

```diff
@@ class _LightweightSystem.__init__
         self.mcp_tools: list[Any] = []
         self._mcp_clients: list[Any] = []
         self.knowledge_db_path = None
+        self.host_supply = getattr(runtime, "host_supply", None)
```

## 6. `src/openjarvis/agents/executor.py` — observation-only hook

```diff
@@ _invoke_agent_impl  (agent_instance.run() at line 3002)
         _t0 = time.perf_counter()
+        _supply = getattr(self._system, "host_supply", None)
+        _shadow_error: BaseException | None = None
         try:
             result = agent_instance.run(input_text, context=agent_ctx)
@@
                 result = agent_instance.run(input_text, context=agent_ctx)
+        except BaseException as exc:
+            _shadow_error = exc
+            raise
         finally:
             resolved_toolkit.close()
+            if _supply is not None:
+                from openjarvis.agents.host_supply_factory import observe_tick
+
+                observe_tick(
+                    _supply,
+                    agent=agent,
+                    system=self._system,
+                    model=model,
+                    engine=getattr(engine, "engine_id", "") or "",
+                    result=None if _shadow_error is not None else result,
+                    error=_shadow_error,
+                )
```

No return value, journal, retry, UNKNOWN_OUTCOME, or exactly-once change.
`observe_tick` never raises, never dispatches, never mutates.

## 7. `src/openjarvis/cli/serve.py` — supply + cloud engine authority

```diff
@@ serve()  (after `sec = setup_security(config, engine, bus)`)
+    from openjarvis.agents.host_supply_factory import (
+        load_host_supply_from_env,
+    )
+
+    host_supply = load_host_supply_from_env(
+        scanners=sec.scanners, capability_policy=sec.capability_policy
+    )

@@ serve()  line 229
-            cloud_engine = CloudEngine()
+            cloud_engine = CloudEngine(
+                authorizer=(host_supply.cloud_authorizer
+                            if host_supply else None),
+                dispatch_ledger=(host_supply.dispatch_ledger
+                                 if host_supply else None),
+                session_id=(host_supply.session_id
+                            if host_supply else ""),
+            )

@@ serve()  JarvisSystem(..., line 665)
                 rate_limiter=sec.rate_limiter,
+                host_supply=host_supply,
```

## 8. `src/openjarvis/server/routes.py` — cloud engine reload

```diff
@@ reload_cloud_engine(request)  line 1308
-        cloud = CloudEngine()
+        _supply = getattr(request.app.state, "host_supply", None)
+        cloud = CloudEngine(
+            authorizer=(_supply.cloud_authorizer if _supply else None),
+            dispatch_ledger=(_supply.dispatch_ledger if _supply else None),
+            session_id=(_supply.session_id if _supply else ""),
+        )
```

## 9. `src/openjarvis/server/routes.py` line 1024 `stream_cloud(...)` — NO DIFF

BLOCKED, deliberately. The chat-completion route is an anonymous HTTP
entry point: it has no agent identity and therefore no host-owned grant to
put in `cloud_dispatch`. Minting one from request data would make an
untrusted caller its own authorizer. Current behavior (default-deny via
`FLAG_OFF` / `NO_GRANT`) is correct until the owner decides the grant
source. Unblocking requires either an owner-approved per-caller grant
source or restricting the route to local engines.

---

## Rollback

Each diff is additive and independent; reverting any hunk restores the
previous behavior. No signature is changed except the optional
`SecurityContext.scanners` field and the optional `JarvisSystem.host_supply`
field, both defaulted.

## Approval required

| File | Change | Conflict |
|---|---|---|
| `security/__init__.py` | scanners on context | dirty |
| `system/core.py` | new field | dirty |
| `system/builder.py` | build + attach | dirty |
| `server/app.py` | build + app.state | dirty |
| `server/agent_manager_routes.py` | facade field | dirty |
| `agents/executor.py` | observe hook | dirty (`model_gate` seam) |
| `cli/serve.py` | supply + CloudEngine | dirty |
| `server/routes.py` | CloudEngine reload | dirty |
| `engine/cloud.py` / `engine/ollama.py` | none | frozen |

---

## Implementation addendum (2026-10-17, shadow-only lane)

The Owner directed the SHADOW-ONLY minimal scope for this session; cloud
integration diffs (#7/#8/#9) stay unapplied by explicit instruction.

Applied in the `opencode/cloud-privacy` worktree (HEAD d596e482, on top of
the dirty parallel work; verified non-colliding with all pre-existing dirty
hunks):

| Diff (this doc) | Applied? | Actual form |
|---|---|---|
| #1 scanners on SecurityContext | **NOT APPLIED** — not needed for shadow-only | factory loaded without scanners |
| #2 `system/core.py` host field | **APPLIED** | `host_supply: Optional[Any] = None` (name matches installer contract; forbidden-name tests still pass) |
| #3 `system/builder.py` build+attach | **APPLIED** (restricted) | `load_host_supply_from_env(capability_policy=...)` only, attach via `host_supply=host_supply`; no scanners/capability beyond capability_policy |
| #4 `server/app.py` / #5 routes facade | **NOT APPLIED** | server lane untouched this session |
| #6 `agents/executor.py` observe hook | **APPLIED** | observe_tick in `_invoke_agent_impl` finally on every managed tick, success/failure separated, never raises; those tests unchanged. Note: Applied restricted to shadow (no `model_gate` interaction). |
| #7/#8 cloud engine wiring | **NOT APPLIED** — per §5 directive | — |
| #9 stream_cloud | **NO DIFF** (as before) | default-deny preserved |

Evidence: `.astra-artifacts/shadow-20261017/` (62 + 39 + 441 passed JUnit
XMLs; OFF parity + observational-only + flag-host-owned proven offline;
`evidence.json`). Rollback path unchanged from the section above.

---

## Implementation addendum (2026-10-18, cloud host wiring — offline)

The Owner then directed the offline cloud-host-wiring mission: wire the
EXISTING host supply chain (no new gates, no real cloud sends) into every
production `CloudEngine()` construction point, prove it offline over
`httpx.MockTransport`, and keep both egress flags default-deny. Applied on
the same worktree/HEAD; collision check against the dirty hunks passed
again (dirty 300 -> 303 during the session, parallel work is elsewhere).

| Diff (this doc) | Applied? | Actual form |
|---|---|---|
| #1 scanners on SecurityContext | **APPLIED** | `SecurityContext.scanners: Tuple = ()`; `setup_security` populates from its scanner list; `builder.py` now passes `scanners=sec.scanners` to the factory load (cloud docs fail closed without real host scanners) |
| #2 `system/core.py` host field | APPLIED (prior) | unchanged |
| #3 `system/builder.py` build+attach | APPLIED (restricted -> cloud-capable) | prior capability_policy load + now scanners injection |
| #4 `server/app.py` | **APPLIED (lite)** | `create_app(..., host_supply: Any = None)` + `app.state.host_supply = host_supply` (2 additive lines) |
| #5 routes facade | APPLIED (prior) | unchanged shadow binding |
| #6 executor observe hook | APPLIED (prior) | unchanged |
| #7 `cli/serve.py` cloud authority | **APPLIED** | one hoisted supply load per `serve()`; `CloudEngine(authorizer=supply, dispatch_ledger=supply, session_id=supply)` at the cloud-key site (bundle None -> exact legacy `CloudEngine()` default-deny engine); `host_supply=host_supply` into scheduler JarvisSystem + create_app |
| #8 `server/routes.py` reload | **APPLIED (lite)** | `reload_cloud_engine` reads `request.app.state.host_supply` and constructs the supply-bound engine; missing state keeps the bare default-deny engine |
| #9 stream_cloud | **NO DIFF** | grant-source decision remains Owner-owned; file untouched |

NOT touched by directive/parallel-ownership: `engine/cloud.py` (carries
300+ lines of parallel dirty work — the engine-side missing-ledger
fallback remains an Owner decision), `engine/multi.py` E7 semantics,
`engine/_openai_compat.py`, `tools/_stubs.py` executor policy
precondition (parallel work owns its test updates).

Offline proofs (all `httpx.MockTransport`, no network, no OS mutation):
`tests/engine/test_cloud_wiring_e2e.py` 21/21 — the host chain
`Host Config -> Factory -> Authorizer/Ledger/Session -> CloudEngine
(serve form) -> MockTransport -> ledger EXECUTED` plus the deny matrix
(flag off, missing authorizer, session mismatch, tamper, replay,
model/endpoint binding mismatch, 5xx = UNKNOWN_OUTCOME then fresh-nonce
re-authorization, unauthorized reuse, grantless agent, PRIVATE,
unknown privacy/provider/endpoint, shadow-doc parity, missing scanners).
`tests/engine/test_multi_provider_router_e2e.py` 14/14 — MultiEngine E7
gate +CapabilityRouter privacy/cost/quota-tier selection with safe defer.
Combined regression `server-cloud-wiring-regression.xml`: 585 passed /
2 failed (both parallel-rewrite-zone nodes, change set proven not causal
by isolation). Update: `evidence.json -> mission_2026_10_18_cloud_wiring`.


---

## Implementation addendum (2026-10-18, ledger fail-closed + streaming boundary)

Owner-directed FIRST PRIORITY executed this session:

**Ledger authority (fail-closed).** The engine \_enforce\ chain
(src/openjarvis/engine/cloud.py) and the direct-router chain
(src/openjarvis/server/cloud_router.py \_enforce_router\) both had the
same fallback: a missing host ledger silently produced
\CloudDispatchLedger()\ — a SELF-MINTED audit ledger in the middle of the
host-authorized chain (it runs AFTER \erify_for_send\, before
\ledger.begin\). Since a missing host ledger is a missing exactly-once
guarantee, both sites now raise \PrivacyDenied(CLOUD_PROVIDER_NOT_ALLOWED,
host dispatch ledger not configured)\ before begin and before any
transport call. There is no non-authorized recording role for that
fallback (no caller can reach it without a configured authorizer), so no
role-splitting was needed. Compatibility: the bare legacy CloudEngine()
never reaches the fallback (the authorizer check refuses first), the
whole enforcement test harness supplies a host ledger, and the one suite
that relied on the fallback (openrouter normalization E2E) was migrated
to pass an explicit \CloudDispatchLedger()\.

**Streaming host boundary.** CloudEngine.stream() and MultiEngine.stream()
share the same _enforce / _verify_routing gates as generate(); this
session proves the streaming matrix offline
(tests/engine/test_cloud_streaming_authority_e2e.py, 21 tests: authorized
SSE exactly-once; partial stream = UNKNOWN_OUTCOME; cancellation =
UNKNOWN_OUTCOME; consumed-seal replay deny; retry with fresh nonce =
EXECUTED; cross-engine seal reuse denied by the E7 gate; missing
ledger/authorizer/session deny; PRIVATE + unknown-privacy never minted;
MultiEngine stream flag/seal/binding/fallback gates). The routes
stream_cloud direct lane keeps its own default-deny posture: a sealed
AuthorizedPayload is mandatory there and no per-request grant source
exists yet (owner decision pending), so the HTTP route can never stream
cloud tokens today.

Evidence: evidence.json mission_2026_10_18c_ledger_streaming;
JUnit streaming-ledger-regression.xml (862 tests, 848 passed, 0 errors,
14 parallel-owned failures); hashes post-hashes-ledger-streaming.txt;
rollback copies postL_src_openjarvis_engine_cloud.py and
postL_src_openjarvis_server_cloud_router.py.
