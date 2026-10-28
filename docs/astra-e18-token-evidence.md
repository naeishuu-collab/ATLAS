# E18 Token Evidence

No child process started in either condition (CreateProcessW FALSE),
so there is no child token/SID to read. Recorded instead:

- Parent (launcher) ran as the invoking user, medium integrity by
  inheritance (no elevation performed, no token manipulation in source).
- `AppContainerSid=present` (profile SID derived + converted, both runs).
- `TokenIsAppContainer` (child): NOT OBTAINABLE — FAIL-closed: no success
  claimed. A successful future run must assert it true with SID match.
- Profile SIDs: per-run unique, deleted; pre/post mapping count 334=334.
