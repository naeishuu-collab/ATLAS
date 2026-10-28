# E18-G Final Report (evidence record)

- Variant `launcher-noenv-token.exe` SHA `435BEA33…F64`; +55 lines,
  read-only, no scheduling change; static imports unchanged.
- Single run: TRUE/0, TokenIsAppContainer=1, SID PRESENT, SID_MATCH=TRUE,
  exit 0, CLEANUP PASS.
- Classification: NATIVE_APPCONTAINER_STARTUP_IDENTITY_PROVEN
  (startup only; isolation/RLM/egress NOT proven; E19 not executed).
- Cleanup verified. Focused 73 PASS; full 650 PASS / 0 FAIL. Ruff clean.
- Repo: 1 doc (+this report). Rollback: delete docs; temp exes retained
  test-only. Gates: NO-GO (both). Next: E19 denial-test design (not run).
