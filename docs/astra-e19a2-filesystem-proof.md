# E19-A2 Filesystem Re-Proof (one corrected stage)

Binaries: `fsprobe-a2.exe` SHA `A590FA12…E500C` (x64, kernel32-only);
`launcher-fsstage-a2.exe` SHA `9808F648…792EC` (x64, 3 DLLs, child-name
only diff). No network/IPC/spawn/ACL code.

## Root cause (E19-A exit 13)

TEMP-derived prefix validation used the sandbox's `GetTempPathW` view,
which differs from the host's. Fix: TEMP-independent shape check
(`<drive>:\…\AstraE19A\<32hex>\fixture.txt`, rejects relative/UNC/device/
`..`/other names). Self-caught off-by-one (`mark+10`→`+11`) fixed
pre-stage; negatives verified (3×13), host read/write rc=0.

## Fixture (deleted)

`%TEMP%\AstraE19A\5805bd78…\fixture.txt`, 32 B synthetic,
SHA `1A350CB7…8F424`, default ACLs unmodified.

## Host controls — PASS (read rc=0, write rc=0 + artifact removed)

## Stage — ALL ACCEPTANCE CRITERIA MET

`VALIDATION_ACCEPTED`, `FILE_API_REACHED` ×2,
`READ_RESULT=rc=10 err=5`, `WRITE_RESULT=rc=10 err=5`,
identity TRUE/1/SID_MATCH, `CHILD_EXIT_CODE=0`, CLEANUP PASS.

## Classification

`FILESYSTEM_DENIAL_PHYSICAL_PROOF = PROVEN` (tested fixture only).

## Cleanup

No `write-probe.tmp` leaked; fixture dir deleted; 334=334; 0 processes.
