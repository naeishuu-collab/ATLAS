# E19-C Final Report (evidence record)

- Semantics audited pre-execution; loopback/capability distinction recorded.
- Host control SUCCESS (ephemeral loopback listener, live at probe time).
- Stage: identity proven, connect reached, WSAECONNREFUSED (10061).
- Harness flaw identified: backlog=1 + never-accepted control connection
  likely RSTs the probe SYN independent of isolation. No retest (one-stage).
- Classification: NETWORK_ISOLATION_NOT_PROVEN / AMBIGUOUS (all three
  sub-classifications). No denial claimed, no success reinterpreted.
- Cleanup verified. Focused 73 PASS; full 650 PASS / 0 FAIL. Ruff clean.
- Repo: docs only. Gates: NO-GO (both).
- Next: backlog-corrected (accept+close control, backlog ≥4) single re-run,
  separately authorized.
