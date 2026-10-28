# E18-F Final Report (evidence record)

- Patch temp-only (repo pristine); 5-line diff inspected; build clean.
- `launcher-noenv.exe` SHA `85217542…0BF6`, x64, imports identical, NotSigned.
- Single run: TRUE/0/0, CLEANUP=PASS. First real child execution.
- Classification: PROCESS_CREATED / APPCONTAINER_IDENTITY_NOT_PROVEN.
- Cause: explicit-block class SUPPORTED (5×203 explicit vs 1×success
  inherited); internal mechanism NOT PROVEN; H3/H5 standing.
- Cleanup verified. Focused 73 PASS; full 650 PASS / 0 FAIL. Ruff clean.
- Repo changes: 1 doc (+this report). Rollback: delete docs; temp exe
  retained per handling policy (test-only, unexecuted further).
- Gates: NO-GO (both), isolation NOT PROVEN, E19 NOT AUTHORIZED.
- Next: token-capture variant (Derive/read token in-launcher) single run.
