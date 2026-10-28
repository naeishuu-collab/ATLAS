# E18 Final Report (evidence record)

- H1 differential executed (1 run/condition, no retry): A (0x80404) and
  B (0x80400) both FALSE/203, CLEANUP=PASS. H1 REJECTED.
- Profile lifecycle proven: create+delete per run, 334=334, zero remnants.
- Token evidence: no child → TokenIsAppContainer unobtainable (fail-closed).
- Cause: H2 weakened, H3 leading, H4/H6 standing with pre-designed
  differentials (`no-drive`, `no-appname`) for next phase; no extra runs.
- No production change. Regression 649+1-flake (known 50 ms load flake,
  green alone + in prior full runs; unmodified). Ruff clean.
- Gates: Production Egress NO-GO, Production RLMWorker NO-GO.
