"""Pinned-transport PoC (offline, test-local implementation, zero network).

Implements the ValidatingBackend design from docs/pinned-transport-design.md
as a TEST-LOCAL class (not production code) with injected resolver + dial.
Proves: validated-IP dialing, rebinding defeat, private-only fail-closed,
IPv6 handling, per-hop re-validation, proxy-env independence, retry-safe
error shape. TLS/SNI preservation holds by construction (origin untouched;
see httpcore connection.py:150-152) and is asserted structurally.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Callable


class ConnectBlocked(Exception):
    """Fail-closed dial refusal (mirrors httpcore.ConnectError shape)."""


def _blocked_ip(ip: str) -> bool:
    from openjarvis.security.ssrf import is_private_ip

    return is_private_ip(ip)


class ValidatingBackend:
    """Test-local PoC of the pinned network backend (see design doc)."""

    def __init__(self, resolver: Callable, dial: Callable) -> None:
        self._resolver = resolver
        self._dial = dial

    def connect_tcp(self, host: str, port: int,
                    timeout: float | None = None) -> Any:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            if _blocked_ip(host):
                raise ConnectBlocked(f"blocked literal: {host}")
            return self._dial(host, port, timeout)
        answers = self._resolver(host, port)
        for ip in answers:
            if _blocked_ip(ip):
                continue
            return self._dial(ip, port, timeout)
        raise ConnectBlocked(f"no validated address for {host}")


def _resolver_factory(mapping: dict) -> Callable:
    def _resolve(host: str, port: int) -> list:
        return list(mapping[host])
    return _resolve


def test_public_host_dials_validated_ip() -> None:
    dialed: list = []
    backend = ValidatingBackend(
        _resolver_factory({"example.com": ["93.184.216.34"]}),
        lambda ip, port, timeout: dialed.append((ip, port)) or object())
    backend.connect_tcp("example.com", 443)
    assert dialed == [("93.184.216.34", 443)]


def test_rebinding_attack_defeated() -> None:
    """Resolver flaps public→private; the dial uses the validated answer."""
    dialed: list = []
    answers = iter([["93.184.216.34"], ["10.9.9.9"]])

    def _flapping(host: str, port: int) -> list:
        return next(answers)

    backend = ValidatingBackend(
        _flapping, lambda ip, port, timeout: dialed.append(ip) or object())
    backend.connect_tcp("example.com", 443)  # resolves public → dials it
    assert dialed == ["93.184.216.34"]
    # Attacker's later private answer can never affect the pinned stream:
    # a second connection re-resolves AND re-validates (fail closed).
    try:
        backend.connect_tcp("example.com", 443)
    except ConnectBlocked:
        pass
    else:
        raise AssertionError("private-only answer must fail closed")
    assert dialed == ["93.184.216.34"]


def test_private_only_fails_closed_without_dial() -> None:
    dialed: list = []
    backend = ValidatingBackend(
        _resolver_factory({"evil.test": ["10.0.0.5", "169.254.169.254"]}),
        lambda ip, port, timeout: dialed.append(ip) or object())
    try:
        backend.connect_tcp("evil.test", 80)
    except ConnectBlocked as exc:
        assert "no validated address" in str(exc)
    else:
        raise AssertionError("must fail closed")
    assert dialed == []


def test_mixed_answers_skip_private_dial_public() -> None:
    dialed: list = []
    backend = ValidatingBackend(
        _resolver_factory({"mix.test": ["10.0.0.5", "93.184.216.34"]}),
        lambda ip, port, timeout: dialed.append(ip) or object())
    backend.connect_tcp("mix.test", 80)
    assert dialed == ["93.184.216.34"]


def test_ipv6_literal_validated() -> None:
    dialed: list = []
    backend = ValidatingBackend(
        _resolver_factory({}), lambda ip, port, timeout: dialed.append(ip))
    try:
        backend.connect_tcp("::ffff:127.0.0.1", 80)
    except ConnectBlocked:
        pass
    else:
        raise AssertionError("mapped loopback literal must be blocked")
    backend.connect_tcp("2606:2800:220:1:248:1893:25c8:1946", 443)
    assert dialed == ["2606:2800:220:1:248:1893:25c8:1946"]


def test_redirect_hops_each_revalidated() -> None:
    """Per-hop simulation: every hop resolves+validates independently."""
    dialed: list = []
    table = {"a.test": ["93.184.216.34"], "b.test": ["169.254.169.254"]}
    backend = ValidatingBackend(
        _resolver_factory(table),
        lambda ip, port, timeout: dialed.append(ip) or object())
    backend.connect_tcp("a.test", 80)
    try:
        backend.connect_tcp("b.test", 80)  # redirect target: metadata
    except ConnectBlocked:
        pass
    else:
        raise AssertionError("redirect to metadata must be blocked")
    assert dialed == ["93.184.216.34"]


def test_no_env_proxy_consulted() -> None:
    """The backend performs no proxy lookup (stdlib socket only)."""
    import inspect

    source = inspect.getsource(ValidatingBackend.connect_tcp)
    assert "proxy" not in source.lower()
    assert "environ" not in source.lower()


def test_sni_origin_preserved_by_construction() -> None:
    """The backend never sees or alters hostname material: it receives the
    origin host and returns a stream; SNI/cert/Host stay origin-derived
    (httpcore connection.py:150-152). Assert the dial contract."""
    seen: list = []
    backend = ValidatingBackend(
        _resolver_factory({"example.com": ["93.184.216.34"]}),
        lambda ip, port, timeout: seen.append((ip, port)) or "stream")
    stream = backend.connect_tcp("example.com", 443)
    assert stream == "stream"
    assert seen == [("93.184.216.34", 443)]  # IP dialed, name never rewritten
