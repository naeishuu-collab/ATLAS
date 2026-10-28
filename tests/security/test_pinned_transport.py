"""Pinned transport production regression (offline, zero network).

Tests the production module (security/pinned_transport.py) and its
wiring in `WebSearchTool._fetch_url` with injected resolvers/dials and
a stub httpx transport. Real DNS, sockets, and HTTP are never touched.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import httpx
import pytest

import openjarvis.tools.web_search as ws_mod
from openjarvis.security import pinned_transport as pt
from openjarvis.security.pinned_transport import (
    UnsupportedVersionError,
    ValidatingBackend,
    build_pinned_transport,
    check_versions,
    is_enabled,
)


def _resolver(mapping: dict):
    def _resolve(host: str, port: int) -> list:
        return list(mapping[host])
    return _resolve


def _recording_dial(dialed: list):
    def _dial(ip: str, port: int, timeout=None, **kw):
        dialed.append((ip, port))
        return object()
    return _dial


def test_flag_defaults_off_and_parses(monkeypatch) -> None:
    monkeypatch.delenv("OPENJARVIS_PINNED_TRANSPORT", raising=False)
    assert is_enabled() is False
    for value in ("1", "true", "YES", " 1 "):
        monkeypatch.setenv("OPENJARVIS_PINNED_TRANSPORT", value)
        assert is_enabled() is True
    for value in ("0", "false", "no", ""):
        monkeypatch.setenv("OPENJARVIS_PINNED_TRANSPORT", value)
        assert is_enabled() is False


def test_versions_match_pinned_pair() -> None:
    check_versions()  # raises on drift; proves the reviewed pair is live


def test_version_mismatch_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(httpx, "__version__", "0.0.0")
    with pytest.raises(UnsupportedVersionError):
        check_versions()
    with pytest.raises(UnsupportedVersionError):
        build_pinned_transport()


def test_backend_dials_validated_ip() -> None:
    dialed: list = []
    backend = ValidatingBackend(_resolver({"example.com": ["93.184.216.34"]}),
                               _recording_dial(dialed))
    backend.connect_tcp("example.com", 443)
    assert dialed == [("93.184.216.34", 443)]


def test_backend_rebinding_defeated() -> None:
    dialed: list = []
    answers = iter([["93.184.216.34"], ["10.9.9.9"]])
    backend = ValidatingBackend(lambda h, p: next(answers),
                                _recording_dial(dialed))
    backend.connect_tcp("example.com", 443)
    assert dialed == [("93.184.216.34", 443)]
    with pytest.raises(Exception):
        backend.connect_tcp("example.com", 443)
    assert dialed == [("93.184.216.34", 443)]


def test_backend_private_only_fails_closed() -> None:
    dialed: list = []
    backend = ValidatingBackend(
        _resolver({"evil.test": ["10.0.0.5", "169.254.169.254"]}),
        _recording_dial(dialed))
    with pytest.raises(Exception):
        backend.connect_tcp("evil.test", 80)
    assert dialed == []


def test_backend_blocks_metadata_literal_not_in_cidr() -> None:
    """100.100.100.200 is Alibaba metadata but outside blocked CIDRs."""
    dialed: list = []
    backend = ValidatingBackend(_resolver({}), _recording_dial(dialed))
    with pytest.raises(Exception):
        backend.connect_tcp("100.100.100.200", 80)
    assert dialed == []


def test_backend_mixed_answers_and_ipv6() -> None:
    dialed: list = []
    backend = ValidatingBackend(
        _resolver({"mix.test": ["10.0.0.5", "93.184.216.34"]}),
        _recording_dial(dialed))
    backend.connect_tcp("mix.test", 80)
    assert dialed == [("93.184.216.34", 80)]
    with pytest.raises(Exception):
        backend.connect_tcp("::ffff:127.0.0.1", 80)


def test_backend_unix_socket_unsupported() -> None:
    backend = ValidatingBackend(_resolver({}), _recording_dial([]))
    with pytest.raises(Exception):
        backend.connect_unix_socket("/tmp/x")


class _StubTransport(httpx.BaseTransport):
    def __init__(self, seen: list) -> None:
        self._seen = seen

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self._seen.append(str(request.url))
        return httpx.Response(200, text="pinned fetch ok")


def test_wiring_flag_off_uses_default_transport(monkeypatch) -> None:
    monkeypatch.delenv("OPENJARVIS_PINNED_TRANSPORT", raising=False)
    created: list = []

    class _NoNetClient:
        def __init__(self, **kwargs: Any) -> None:
            created.append(kwargs.get("transport"))

        def __enter__(self) -> "_NoNetClient":
            return self

        def __exit__(self, *exc: Any) -> bool:
            return False

        def get(self, url: str) -> None:
            raise RuntimeError("offline-guard: no request may run")

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = _NoNetClient  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    with pytest.raises(RuntimeError, match="offline-guard"):
        ws_mod.WebSearchTool._fetch_url("http://93.184.216.34/")
    assert created == [None]


def test_wiring_flag_on_passes_pinned_transport(monkeypatch) -> None:
    monkeypatch.setenv("OPENJARVIS_PINNED_TRANSPORT", "1")
    sentinel = _StubTransport([])
    monkeypatch.setattr(pt, "build_pinned_transport",
                        lambda **kw: sentinel)
    transport_holder: list = []
    real_client = httpx.Client

    def _recording_client(*args: Any, **kwargs: Any):
        transport_holder.append(kwargs.get("transport"))
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", _recording_client)
    try:
        text = ws_mod.WebSearchTool._fetch_url("http://93.184.216.34/")
    finally:
        monkeypatch.undo()
    assert transport_holder == [sentinel]
    assert "pinned fetch ok" in text


def test_wiring_build_failure_no_fallback(monkeypatch) -> None:
    monkeypatch.setenv("OPENJARVIS_PINNED_TRANSPORT", "1")

    def _boom(**kw: Any) -> None:
        raise UnsupportedVersionError("drift")

    monkeypatch.setattr(pt, "build_pinned_transport", _boom)
    client_created: list = []
    real_client = httpx.Client

    def _recording_client(*args: Any, **kwargs: Any):
        client_created.append(True)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "Client", _recording_client)
    with pytest.raises(UnsupportedVersionError):
        ws_mod.WebSearchTool._fetch_url("http://93.184.216.34/")
    assert client_created == []
