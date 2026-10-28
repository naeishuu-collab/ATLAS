# Network Denial Coverage (E15)

Harness: `tests/security/_network_deny.py::deny_network` (opt-in per test).

## Covered (test `test_denial_fires_on_real_attempt` proves each fires)

- `socket.create_connection` (IPv4/IPv6, hostname or literal IP)
- `socket.socket.connect` → non-loopback denied; loopback allowed
  (required by Windows ProactorEventLoop internals — verified failure
  then fix, `test_router_offline` green)
- `socket.getaddrinfo` (DNS)
- `urllib.request.urlopen`, `requests.Session.send`,
  `aiohttp.ClientSession._request`

## Proven under denial (4 tests PASS)

NIM / compat / router enforced paths complete with sockets+D globally
blocked; MockTransport/respx need no sockets.

## Residual / NOT PROVEN

- Already-connected file descriptors, C-extension sockets bypassing
  `socket`, subprocess transports, loopback exfiltration to a local
  proxy. Python-level patching is NOT OS isolation — no such claim.
