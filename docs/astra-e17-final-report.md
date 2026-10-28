# E17 Final Report (evidence record)

- Toolchain: MSVC 19.51.36256 + WinSDK 10.0.26100.0 (existing, no downloads).
- Launcher audit: single benign child, 10 s timeout, job kill, cleanup;
  BUT creates its own profile per run (`AstraNativePoc.<pid>.<tick>`) and
  self-deletes — "existing profile" gate unmeetable by design.
- Build: `launcher.exe` (151040 B, SHA `620AA19D…D9`) in approved temp only,
  NOT executed, NOT in repo. Rebuild bit-identity NOT achieved (timestamp).
- Binary trust (static): x64, imports kernel32/advapi32/userenv only, no
  network libs, NotSigned (test-only, no other claim).
- Profile: 334 machine mappings, zero `AstraNativePoc*` remnants, zero
  prohibited ops.
- `astra_appcontainer_proof.py`: compiles; uses ctypes/subprocess →
  NOT EXECUTED (would violate E17 native ban).
- H1: spec + pre-flight complete (9/10 PASS, item 3 NOT PROVEN) —
  NO execution in E17. One approval needed: self-cleaning
  create+delete (or Derive-only variant).
- Regression: 650/650 PASS final (one load-sensitive intermittent in
  `test_worker_unknown_outcome_quarantines_session` — 50 ms deadline,
  green file-alone 3/3 and in final full run; no code/test change made).
  Ruff + compile clean.
- Gates: Production Egress NO-GO, Production RLMWorker NO-GO.
