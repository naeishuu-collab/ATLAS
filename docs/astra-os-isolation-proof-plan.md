# OS Isolation Proof Plan (fixtures ready, native steps NOT executed)

Each item: preconditions / steps / expected evidence / failure class /
cleanup+rollback / approval.

## P1 Network deny

- Pre: worker in AppContainer, loopback-only. Steps: worker attempts
  outbound TCP; host sniffs. Evidence: SYN absent + `UNKNOWN_OUTCOME`
  ledger entry. Fail: any SYN = ISOLATION_FAIL. Cleanup: kill job
  (KILL_ON_JOB_CLOSE). Approval: native-run approval.
- Offline fixture: `tests/security/_network_deny.py` (Python-level only).

## P2 Filesystem deny

- Pre: AppContainer profile, no capabilities. Steps: worker
  reads/writes outside package dirs. Evidence: ACCESS_DENIED + audit
  log. Fail: successful read/write = ISOLATION_FAIL. Rollback: delete
  profile. Approval: native-run + profile-creation approval.

## P3 IPC / child-process / handle-inheritance deny

- Steps: worker opens host pipe, spawns child, inherits handle.
  Evidence: all denied. Fail: any success = ISOLATION_FAIL.
  Rollback: job close. Approval: native-run approval.

## P4 Token identity / SID / capabilities

- Steps: `GetTokenInformation` in worker, compare AppContainer SID +
  zero capabilities vs host token. Evidence: SID match + lowbox.
  Fail: medium+ integrity or host SID = ISOLATION_FAIL. Read-only.

## P5 Lifecycle: job kill-on-close, worker termination → UNKNOWN

- Steps: kill worker mid-dispatch. Evidence: host ledger entry stuck
  `UNKNOWN_OUTCOME`, never auto-retried, reconciliation evidence-only.
  Covered offline by `test_rlm_rpc` cancellation tests (Fake scope).

## P6 Error-203 rerun matrix (H1 first)

- no-suspend → extended-env → ACL/CodeIntegrity read → profile check.
  Each run records immediate `GetLastError` + config line. Approval:
  native-run approval (Smart App Control path must allow the binary).
