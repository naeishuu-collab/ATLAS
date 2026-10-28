# E18 Error 203 Analysis (empirical)

## H1 CREATE_SUSPENDED — REJECTED

0x80404 (suspended) and 0x80400 (resumed) both return FALSE/203 with
identical env/STARTUPINFOEX/capabilities. Suspended-state interaction
is not the cause.

## Re-ranked hypotheses (H2–H5)

- H2 profile/SID lifecycle: WEAKENED — `CreateAppContainerProfile`
  succeeds and SID converts both times; failure is downstream at
  process creation with attributes attached.
- H3 image/dir ACL or Code Integrity surfacing as 203: LEADING —
  App Control OFF did not clear it; needs read-only ACL/CI policy
  inspection (next phase, no execution).
- H4 missing runtime env entry: STANDING — block well-formed but
  minimal (5 vars + optional `=C:`); `no-drive` differential is
  pre-designed in the binary (next phase, 1 run).
- H5 zero-capability combination: STANDING — no evidence either way.
- New H6 `lpApplicationName`-vs-`lpCommandLine` resolution inside
  AppContainer (`no-appname` differential pre-designed; next phase).

No additional native runs in E18 (authorization covered A/B only).
No production change (cause unconfirmed).
