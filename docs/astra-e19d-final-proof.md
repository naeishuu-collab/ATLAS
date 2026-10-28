# E19-D FINAL Descendant Proof (one authorized run)

Binaries: `descendant-probe.exe` SHA `E5B25874…FC8A9` (kernel32-only);
`parentprobe.exe` SHA `6C3A4368…41CC7` (kernel32+advapi32; NULL-SID
guard fixed pre-stage after host-control crash finding);
`launcher-descstage.exe` SHA `31E4F768…90FFF` (3 DLLs).
No breakaway/shell/network/registry/ACL APIs. Job flags unchanged
(no BREAKAWAY_OK/SILENT), limit 4.

## Host controls — SUCCESS

Descendant alone: marker/alive/exit 0. Parent on host: creates child,
token readable (0, expected), no crash after NULL-SID fix, exits 1
(correct non-AppContainer outcome).

## Stage — DESCENDANT_CREATION_DENIED

Parent identity proven (TRUE/1/SID_MATCH, in job).
`DESCENDANT_CREATE_ATTEMPT=1`, `DESC_CREATE=FALSE err=5`
(ACCESS_DENIED). No descendant ever existed: job list empty,
all descendant checks vacuous, parent exit 2. CLEANUP PASS.

## Classification

`DESCENDANT_CREATION_DENIED` — NOT containment proof (§20: denial ≠
containment). Probable mechanism (REPORTED, not proven): image file
`descendant-probe.exe` carries user-only ACEs (no package RX), so the
same filesystem boundary from E19-A2 denies image read/execute —
defense-in-depth consistent, mechanism unattributed. Distinguishing
image-ACL vs creation-policy would need an AC-readable image location:
new variant, NOT authorized here.

## Cleanup

334=334, 0 processes, no config change.
