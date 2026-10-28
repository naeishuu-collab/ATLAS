# Astra Deterministic Agent E2E Readiness

> **AGENT_E2E_ENTRY_NOT_AUTHORIZED**
>
> Readiness specification only. This document does not enable production
> Agent E2E, native execution, cloud access, browser network access, or
> desktop mutation.

## Scope

The future lane is a nonphysical orchestration test for the existing Planner,
Orchestrator, Executor, Replanner, Journal, Artifact Registry, and verification
contracts. It must use fake adapters and deterministic data only.

## Fixture graph

```text
FakePlanner proposal
  -> existing Orchestrator
  -> in-memory Executor adapter
  -> deterministic observation adapter
  -> existing verification result
  -> Journal + Artifact Registry
  -> success / verification failure / UNKNOWN_OUTCOME
  -> existing Replanner quarantine/defer path
```

## Required fixture rules

- The planner emits a fixed `UNTRUSTED_PROPOSAL`; it never emits executable
  code, shell text, native launcher data, or real credentials.
- The executor adapter records intent and returns scripted observations. It
  never calls `subprocess`, `multiprocessing`, an RLM worker, a browser with
  external network, or a channel/backend.
- Success requires a deterministic observation and verification receipt.
- Verification failure must not become success.
- `UNKNOWN_OUTCOME` must enter quarantine and the fixture must assert zero
  retry, redispatch, provider/model fallback, retarget, and duplicate mutation.
- The Journal and Artifact Registry use in-memory fakes or isolated temporary
  state with no writes to the repository or user profile.
- The Replanner may produce a safe defer result only; it may not reinterpret a
  sandbox, authority, or quarantine denial as permission to execute.

## Proposed cases

| Case | Expected result | Forbidden effects |
|---|---|---|
| Verified observation | One verified result and one journal completion | No physical effect |
| Observation mismatch | Failure, no success claim | No retry or duplicate mutation |
| Executor denial | Structured denial reaches the Agent boundary | No adapter dispatch |
| `UNKNOWN_OUTCOME` | Quarantine with explicit unresolved state | Retry/redispatch/fallback/retarget all zero |
| Replanner after quarantine | Safe defer or suspend | No alternate executor |
| Artifact registration mismatch | Registration denied | No native or filesystem mutation |

## Coverage matrix

| Required property | Deterministic fixture assertion | Forbidden effect |
|---|---|---|
| Target selection | The proposal contains one fixed target identity; the executor accepts only that identity | No retargeting |
| Authorized fake action | The in-memory executor accepts only a host-issued fake grant | No real process, network, or desktop effect |
| Verification-before-success | Success is emitted only after the observation matches the expected receipt | No unverified success |
| Failure detection | A mismatched observation produces a structured failure | No success claim |
| Safe bounded replan | Replanner may emit one safe defer/replan decision within a fixed budget | No alternate executor |
| `UNKNOWN_OUTCOME` quarantine | Uncertain execution enters quarantine with unresolved state | Retry/redispatch/fallback/retarget are zero |
| Duplicate prevention | Reusing the same mutation identity is rejected after completion or quarantine | Duplicate mutation is zero |
| Alternate-executor denial | A denial cannot be converted into an RLM, shell, native, or cloud execution request | No bypass |
| Structured propagation | Executor, Orchestrator, Journal, and Agent retain the same error/effect state | No state laundering |
| Artifact/journal consistency | Artifact registration and journal completion require matching deterministic IDs | No untracked artifact or completion |

## Acceptance boundary

This lane can prove orchestration semantics, structured error propagation,
verification-before-success, Journal behavior, and quarantine handling. It
cannot prove Windows AppContainer token restrictions, WDAC/App Control
authorization, network isolation, descendant containment, or physical exactly
once behavior. Those require a separately approved immutable native artifact
and a policy-owner-approved physical proof run.

No production Agent code is changed or enabled by this specification.
