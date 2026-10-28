# E19-B Final Report (evidence record)

- Probe `ipcprobe-event.exe` SHA `BA6DEC2F…880B5`, launcher
  `D12468F3…875CD`. Name-constrained, session-namespace only.
- Host control SUCCESS (creator handle + open/SetEvent).
- Stage: identity proven, `IPC_RESULT=rc=10 err=5`, exit 0, cleanup PASS.
- Classification: NAMED_EVENT_MODIFY_DENIAL_PROVEN_FOR_TESTED_OBJECT.
- Focused 73 PASS; full 650 PASS / 0 FAIL. Ruff clean.
- Repo: docs only. Safety Authority/AppContainer regressions: NOT FOUND.
- Gates: NO-GO (both). Next: E19-C network (authorized separately).
