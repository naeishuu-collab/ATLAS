"""Web Search SSRF hardening regression (mock-only, zero network).

Covers ground beyond tests/security/test_ssrf*.py (literals, mapped
forms, metadata hosts, DNS fail-closed): per-hop redirect re-validation
in `WebSearchTool._fetch_url`, the DNS check-then-connect TOCTOU window,
scheme entry constraints, and proxy-routing residuals.

HTTP is fully stubbed (`sys.modules["httpx"]` replacement); DNS is
stubbed (`socket.getaddrinfo` patch on the pure-Python guard).
"""

from __future__ import annotations

import ast
import sys
import types
from pathlib import Path
from typing import Any

import openjarvis.security.ssrf as ssrf_mod
import openjarvis.tools.web_search as ws_mod
from openjarvis.security.ssrf import _check_ssrf_python, check_ssrf
from openjarvis.tools.web_search import WebSearchTool


def _force_python_guard(monkeypatch) -> None:
    """Pin the pure-Python guard inside web_search (deterministic + mock DNS)."""
    monkeypatch.setattr(ws_mod, "check_ssrf", _check_ssrf_python)


class _FakeResponse:
    def __init__(self, status: int = 200, location: str = "",
                 url: str = "", text: str = "hello world") -> None:
        self.status_code = status
        self.headers = {"location": location, "content-type": "text/html"}
        self.url = url
        self._text = text

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise ValueError(f"http {self.status_code}")

    @property
    def text(self) -> str:
        return self._text


class _FakeClient:
    """httpx.Client stand-in serving a scripted hop list, then recording."""

    def __init__(self, script: list, seen: list) -> None:
        self._script = list(script)
        self._seen = seen

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def get(self, url: str) -> _FakeResponse:
        self._seen.append(url)
        if self._script:
            return self._script.pop(0)
        return _FakeResponse()


def _install_fake_httpx(monkeypatch, script: list, seen: list) -> None:
    fake = types.ModuleType("httpx")

    def _client(**kwargs: Any) -> _FakeClient:
        return _FakeClient(script, seen)

    fake.Client = _client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "httpx", fake)


def _public_dns(monkeypatch, ip: str = "93.184.216.34") -> None:
    def _resolve(host: str, *args: Any, **kwargs: Any) -> list:
        return [(2, 1, 6, "", (ip, 0))]

    monkeypatch.setattr(ssrf_mod.socket, "getaddrinfo", _resolve)


def test_redirect_to_private_blocked_per_hop(monkeypatch) -> None:
    seen: list = []
    _install_fake_httpx(monkeypatch, [
        _FakeResponse(status=302, location="http://169.254.169.254/x",
                      url="http://example.com/a"),
    ], seen)
    _public_dns(monkeypatch)
    _force_python_guard(monkeypatch)
    try:
        WebSearchTool._fetch_url("http://example.com/a")
    except ValueError as exc:
        assert "169.254.169.254" in str(exc) or "private" in str(exc)
    else:
        raise AssertionError("redirect to metadata must be blocked")
    assert seen == ["http://example.com/a"]  # evil hop never fetched


def test_benign_redirect_chain_passes_per_hop(monkeypatch) -> None:
    seen: list = []
    _install_fake_httpx(monkeypatch, [
        _FakeResponse(status=301, location="http://example.com/b",
                      url="http://example.com/a"),
        _FakeResponse(status=200, url="http://example.com/b"),
    ], seen)
    _public_dns(monkeypatch)
    _force_python_guard(monkeypatch)
    text = WebSearchTool._fetch_url("http://example.com/a")
    assert "hello world" in text
    assert seen == ["http://example.com/a", "http://example.com/b"]


def test_redirect_loop_capped(monkeypatch) -> None:
    seen: list = []
    script = [_FakeResponse(status=302, location="http://example.com/loop",
                            url="http://example.com/loop")
              for _ in range(30)]
    _install_fake_httpx(monkeypatch, script, seen)
    _public_dns(monkeypatch)
    _force_python_guard(monkeypatch)
    try:
        WebSearchTool._fetch_url("http://example.com/loop")
    except ValueError as exc:
        assert "redirect" in str(exc).lower()
    else:
        raise AssertionError("redirect loop must be capped")


def test_dns_rebinding_window_documents_no_pinning(monkeypatch) -> None:
    """Gap record: guard validates per lookup; nothing pins DNS to connect.

    First lookup resolves public (pass), second resolves private (block).
    A connector using fresh resolution between check and connect could
    observe different answers  Erecorded, not approved.
    """
    answers = iter(["93.184.216.34", "10.9.9.9"])

    def _flapping(host: str, *args: Any, **kwargs: Any) -> list:
        return [(2, 1, 6, "", (next(answers), 0))]

    monkeypatch.setattr(ssrf_mod.socket, "getaddrinfo", _flapping)
    first = _check_ssrf_python("http://example.com/")
    second = _check_ssrf_python("http://example.com/")
    assert first is None
    assert second is not None and "private" in second


def test_file_scheme_blocked_no_hostname() -> None:
    assert check_ssrf("file:///etc/passwd") is not None


def test_userinfo_rejected_on_public_host() -> None:
    """Embedded credentials must not pass either backend (credential leak)."""
    assert check_ssrf("http://user:pass@example.com/") is not None
    assert check_ssrf("https://user@example.com:8443/path?q=1") is not None
    assert "credential" in check_ssrf("http://u:p@example.com/").lower()


def test_userinfo_rejected_python_backend(monkeypatch) -> None:
    _force_python_guard(monkeypatch)
    _public_dns(monkeypatch)
    assert _check_ssrf_python("http://user:pass@example.com/") is not None
    # No-userinfo URLs behave exactly as before.
    assert _check_ssrf_python("http://example.com/") is None


def test_fetch_url_with_userinfo_never_fetched(monkeypatch) -> None:
    seen: list = []
    _install_fake_httpx(monkeypatch, [], seen)
    _public_dns(monkeypatch)
    _force_python_guard(monkeypatch)
    try:
        WebSearchTool._fetch_url("http://user:pass@example.com/secret")
    except ValueError as exc:
        assert "credential" in str(exc).lower()
    else:
        raise AssertionError("userinfo URL must be rejected before fetch")
    assert seen == []


def test_entry_points_constrain_to_http() -> None:
    assert WebSearchTool._is_url("http://example.com/") is True
    assert WebSearchTool._is_url("ftp://example.com/") is False
    assert WebSearchTool._is_url("file:///etc/passwd") is False
    assert WebSearchTool._extract_url("see ftp://example.com/x") is None


def test_no_explicit_proxy_config_residual() -> None:
    """Residual record: fetch Client sets no proxy/trust_env kwargs.

    Routing therefore follows process proxy env  Eread-only finding.
    """
    import openjarvis.tools.web_search as ws_mod

    tree = ast.parse(Path(ws_mod.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "Client"):
            keywords = {kw.arg for kw in node.keywords}
            assert "proxy" not in keywords and "trust_env" not in keywords
