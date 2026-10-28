# E19-C Network Proof (one authorized stage — AMBIGUOUS)

Binaries: `netprobe.exe` SHA `75F6735E…D19DD` (x64, kernel32+ws2_32);
`launcher-netstage.exe` SHA `64C3AA3F…47CFB` (x64, +ws2_32 for
loopback listener/control). No DNS/HTTP/TLS/scan. NotSigned test-only.

## Semantics (pre-execution audit)

- Zero caps: no internetClient/internetClientServer/
  privateNetworkClientServer (construction-evident, unchanged E18-G path).
- Loopback AppContainer block is a SEPARATE mechanism from
  capability-based Internet denial (exemption via CheckNetIsolation).
- LOCAL LOOPBACK PROPERTY: only TCP/IPv4 loopback-connect behavior.
- INTERNET PROPERTY: inferable from cap absence only (static).
- LIMITATION: external Internet intentionally untested.

## Host control — SUCCESS

`ListenerBound=127.0.0.1 port=62356` (ephemeral, loopback-only),
`HOST_LOOPBACK_CONNECT=SUCCESS` on the live listener.

## Stage — AMBIGUOUS (harness artifact suspected)

Identity proven (TRUE/1/SID_MATCH). Probe:
`VALIDATION_ACCEPTED`, `SOCKET_CREATED=yes`,
`CONNECT_API_REACHED`, `NET_RESULT=rc=11 wsa=10061`
(WSAECONNREFUSED), child exit 2, CLEANUP PASS.

Root suspicion (documented, not re-tested): `listen(backlog=1)` +
control connection accepted-never leaves one completed connection
queued; the probe SYN is then RST → 10061 regardless of isolation
enforcement. A capability/loopback block would more typically surface
as WSAEACCES. Cannot distinguish without a corrected run.

## Classification

`NETWORK_ISOLATION_NOT_PROVEN / AMBIGUOUS`. No denial claimed.
`LOOPBACK_CONNECTIVITY=AMBIGUOUS`, `NETWORK_CAPABILITY_TOKEN_STATE=
zero-cap (construction-evident)`, `EXTERNAL_INTERNET_PHYSICAL_DENIAL=
NOT TESTED`. Corrected design for next authorization: backlog ≥4 AND
`accept()`+close the control connection before the probe stage.

## Cleanup

Listener closed (`ListenerCleanup=CLOSED`), 334=334, 0 processes,
firewall/exemptions untouched (never modified), flags OFF.
