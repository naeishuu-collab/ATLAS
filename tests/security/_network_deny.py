"""Offline network-denial harness for egress tests.

Blocks real socket egress at several layers so any test running under
:func:`deny_network` fails loudly if it attempts genuine network I/O.
MockTransport/respx/MagicMock paths need no sockets and keep passing.

LIMITS (do not overclaim): this is a Python-level harness. It cannot
prove OS-level isolation, C-extension sockets that bypass ``socket``,
already-connected file descriptors, subprocess transports, or
exfiltrated-but-mocked transports. Residual routes are documented in
``docs/astra-network-denial-coverage.md``.
"""

from __future__ import annotations


def deny_network(monkeypatch) -> None:
    """Fail real network egress attempts during the test.

    Covers:
    - ``socket.create_connection`` (IPv4/IPv6 TCP, hostname or literal IP)
    - ``socket.socket.connect`` (literal-IP direct connect)
    - ``socket.getaddrinfo`` (DNS resolution)
    - ``urllib.request.urlopen`` / ``requests`` / ``aiohttp`` high-level APIs
    """
    import socket

    def _blocked_egress(*args: object, **kwargs: object) -> object:
        raise AssertionError(
            "network-denial harness: real socket egress attempted "
            f"(args={args!r})"
        )

    def _blocked_resolve(*args: object, **kwargs: object) -> object:
        raise AssertionError(
            "network-denial harness: real DNS resolution attempted "
            f"(args={args!r})"
        )

    monkeypatch.setattr(socket, "create_connection", _blocked_egress)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked_resolve)

    _real_connect = socket.socket.connect

    def _guarded_connect(sock: object, address: object) -> object:
        # asyncio ProactorEventLoop uses loopback connects internally;
        # allow loopback, deny everything else.
        host = address[0] if isinstance(address, tuple) else ""
        if host in ("127.0.0.1", "::1", "localhost"):
            return _real_connect(sock, address)
        raise AssertionError(
            "network-denial harness: real socket egress attempted "
            f"(args={address!r})"
        )

    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)

    try:
        import urllib.request as _urlopen_mod

        monkeypatch.setattr(
            _urlopen_mod, "urlopen", _blocked_resolve,
        )
    except ImportError:
        pass
    try:
        import requests.sessions as _req_sessions

        monkeypatch.setattr(
            _req_sessions.Session, "send", _blocked_egress,
        )
    except ImportError:
        pass
    try:
        import aiohttp.client as _aio_client

        monkeypatch.setattr(
            _aio_client.ClientSession, "_request", _blocked_egress,
        )
    except ImportError:
        pass


__all__ = ["deny_network"]
