# E19-C2 Final Report (evidence record)

- Root cause PROVEN from source (backlog=1, no accept); fix: backlog=4 +
  accept/drain + post-probe select/accept observation (48-line diff).
- Listener health PROVEN (bound/control/accepted/drained/active).
- Run: TRUE then WAIT_TIMEOUT; probe output none; parent token/child/
  observation lines absent (unexplained capture anomaly, source order
  verified). Identity NOT PROVEN this run.
- Hang-in-connect consistent with silent drop; E19-C 10061 likely
  backlog-RST. Both unattributable: AMBIGUOUS. No claim either way.
- Design gap: server observation sits off the timeout path.
- Cleanup verified. Focused 72+1-flake (known signature); full 650 PASS.
  Ruff clean. Repo: docs only. Gates: NO-GO (both).
- Next: single run with (a) probe connect timeout + unbuffered logging,
  (b) observation on all paths — separately authorized.
