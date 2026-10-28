"""Pinned HTTP transport: DNS-validated dialing with origin-preserved TLS.

A `httpcore` network backend that resolves the origin hostname ONCE per
connection, dials only a validated IP, and lets the standard httpcore
connection layer keep SNI, certificate hostname verification, Host
header, auth, pooling, timeouts, and retries untouched.

Version-pinned by design: httpx 0.28.1 + httpcore 1.0.9. Any other
combination raises instead of silently changing behavior. No fallback
to an unpinned transport exists anywhere in this module.

Feature flag: ``OPENJARVIS_PINNED_TRANSPORT=1`` enables. Flag OFF keeps
the historical transport (a documented residual, never a safety PASS).
"""

from __future__ import annotations

import logging
import os
import socket
from typing import Any, Callable, Iterable

logger = logging.getLogger(__name__)

SUPPORTED_HTTPX = "0.28.1"
SUPPORTED_HTTPCORE = "1.0.9"

FLAG_ENV_VAR = "OPENJARVIS_PINNED_TRANSPORT"
_FLAG_ON = frozenset({"1", "true", "yes"})


class PinnedTransportError(Exception):
    """Base error for the pinned transport (always fail-closed)."""


class UnsupportedVersionError(PinnedTransportError):
    """httpx/httpcore versions differ from the pinned, reviewed set."""


def is_enabled() -> bool:
    """Whether the pinned transport flag is switched on."""
    return os.environ.get(FLAG_ENV_VAR, "").strip().lower() in _FLAG_ON


def check_versions() -> None:
    """Raise unless the exact reviewed httpx/httpcore pair is present."""
    import httpcore
    import httpx

    if httpx.__version__ != SUPPORTED_HTTPX:
        raise UnsupportedVersionError(
            f"httpx {httpx.__version__} != pinned {SUPPORTED_HTTPX}"
        )
    if httpcore.__version__ != SUPPORTED_HTTPCORE:
        raise UnsupportedVersionError(
            f"httpcore {httpcore.__version__} != pinned {SUPPORTED_HTTPCORE}"
        )


def _default_resolver(host: str, port: int) -> list[str]:
    """Single getaddrinfo pass; returns candidate IP strings in order."""
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    return [sockaddr[0] for _, _, _, _, sockaddr in infos]


class ValidatingBackend:
    """httpcore NetworkBackend: validate-then-dial, never resolve-twice.

    Validation and dialing consume the SAME resolution result inside one
    `connect_tcp` call, collapsing the DNS check-then-connect TOCTOU.
    TLS SNI, certificate verification, Host header, and pooling all stay
    origin-derived in the httpcore connection layer above.
    """

    def __init__(
        self,
        resolver: Callable[[str, int], list[str]] | None = None,
        dial: Callable[..., Any] | None = None,
    ) -> None:
        from httpcore._backends.sync import SyncBackend

        self._resolver = resolver or _default_resolver
        self._sync = SyncBackend()
        self._dial = dial or self._sync.connect_tcp

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> Any:
        import ipaddress

        from httpcore import ConnectError

        from openjarvis.security.ssrf import _BLOCKED_HOSTS, is_private_ip

        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        candidates = [host] if literal is not None else self._resolver(host, port)
        last_error: Exception | None = None
        for ip in candidates:
            if ip in _BLOCKED_HOSTS or is_private_ip(ip):
                continue
            try:
                return self._dial(
                    ip, port, timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:  # noqa: BLE001 - try next candidate
                last_error = exc
        if last_error is not None:
            raise last_error
        raise ConnectError(f"no validated address for {host!r}")

    def connect_unix_socket(self, *args: Any, **kwargs: Any) -> Any:
        raise PinnedTransportError("unix sockets are not supported")

    def sleep(self, seconds: float) -> None:
        import time

        time.sleep(seconds)


def build_pinned_transport(*, verify: Any = True) -> Any:
    """Build an httpx transport with validated-IP dialing.

    Raises on version mismatch or build failure — callers must fail
    closed and never fall back to an unpinned transport.
    """
    check_versions()
    import httpcore
    import httpx

    ssl_context = httpx.create_ssl_context(verify=verify, trust_env=False)
    pool = httpcore.ConnectionPool(
        ssl_context=ssl_context,
        network_backend=ValidatingBackend(),  # type: ignore[arg-type]
    )
    # httpx 0.28 exposes no backend injection; replacing our own
    # subclass instance's pool keeps request conversion intact. Pinned
    # versions make this exact; check_versions() guards drift.
    transport = httpx.HTTPTransport(verify=verify, trust_env=False)
    transport._pool = pool  # noqa: SLF001 - pinned httpx 0.28.1 layout
    logger.debug("pinned HTTP transport built (httpx %s / httpcore %s)",
                 SUPPORTED_HTTPX, SUPPORTED_HTTPCORE)
    return transport
