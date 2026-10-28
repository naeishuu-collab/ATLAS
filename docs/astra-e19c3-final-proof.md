# E19-C3 Final Loopback Diagnostic (one authorized run)

Binaries: `netprobe-c3.exe` SHA `E4BE1F78…D9759` (bounded 3 s connect,
unbuffered); `launcher-netstage-c3.exe` SHA `4F2858FE…4C7CE`
(unbuffered, timeout fall-through, observation on all paths).

## C2 audit conclusion

D (unbounded blocking connect) + G (observation off timeout path)
confirmed by source; child output loss by kill-before-flush; parent
middle-line absence unexplained (transport/capture possibly) —
mitigated by unbuffered streams + exit-code primary signal.

## Run — full chain observed

Identity TRUE/1/SID_MATCH; zero-cap construction; listener healthy
(50725, control accepted/drained); probe validation/startup/socket/
`CONNECT_STARTED` reached; `CONNECT_TIMEOUT=3000ms`,
`NET_RESULT=rc=110 wsa=10060` (WSAETIMEDOUT); server FALSE;
child exit 3; cleanup PASS.

## Classification

Case C: `TCP_IPV4_LOOPBACK_RESULT = TIMEOUT`,
`LOOPBACK_ISOLATION = NOT PROVEN` (drop-behavior ≠ documented denial).
`EXTERNAL_INTERNET_PHYSICAL_DENIAL = NOT TESTED`. No C4 (final per §15).

## Cleanup

334=334, 0 processes, listener closed, firewall/exemptions untouched.
