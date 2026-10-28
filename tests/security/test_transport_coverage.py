"""Transport coverage & integration review (offline, zero network).

Records the ACTUAL coverage matrix of the pinned transport across all
WebSearchTool HTTP paths, reviews wiring safety properties, and pins the
hybrid-authority BLOCKED state. No production code is changed here.
"""

from __future__ import annotations

import ast
from urllib.parse import urlparse

import httpx

import openjarvis.tools.web_search as ws_mod


def _tree() -> ast.Module:
    from pathlib import Path

    import openjarvis.tools.web_search as mod

    return ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))


def _method(name: str) -> ast.FunctionDef:
    tree = _tree()
    cls = next(node for node in ast.walk(tree)
               if isinstance(node, ast.ClassDef)
               and node.name == "WebSearchTool")
    return next(node for node in cls.body
                if isinstance(node, ast.FunctionDef) and node.name == name)


def test_api_endpoints_are_fixed_hosts() -> None:
    """You.com/Serply calls go to constant hosts; the model controls only
    query params/body — pinned dialing is correctly NOT applied there."""
    for const in ("YOUCOM_KEYED_SEARCH_URL", "YOUCOM_KEYLESS_SEARCH_URL",
                  "YOUCOM_CONTENTS_URL", "SERPLY_SEARCH_URL"):
        url = getattr(ws_mod, const)
        parsed = urlparse(url)
        assert parsed.scheme == "https"
        assert parsed.username is None
        assert parsed.hostname in ("api.you.com", "api.serply.io")


def test_fetch_url_is_only_model_host_path() -> None:
    """Only _fetch_url takes a model-influenced host; engine SDK calls use
    fixed endpoints. Redirect re-validation lives only in _fetch_url."""
    fetch_src = ast.dump(_method("_fetch_url"))
    assert "check_ssrf" in fetch_src
    assert "location" in fetch_src  # redirect loop
    for name in ("_youcom_search", "_serply_search", "_tavily_search",
                 "_duckduckgo_search"):
        src = ast.dump(_method(name))
        assert "check_ssrf" not in src  # fixed-host/SDK paths need none
    assert "TavilyClient" in ast.dump(_method("_tavily_search"))
    assert "DDGS" in ast.dump(_method("_duckduckgo_search"))


def test_pinned_wiring_flag_gated_in_fetch() -> None:
    src = ast.dump(_method("_fetch_url"))
    assert "_pinned_transport_enabled" in src
    assert "build_pinned_transport" in src
    assert "transport" in src


def test_fetch_sets_no_host_or_sni_overrides() -> None:
    """SNI/cert/Host stay origin-derived: no overrides in fetch plumbing."""
    src = ast.dump(_method("_fetch_url")).lower()
    assert "sni_hostname" not in src
    assert "verify" not in src or "verify=false" not in src.replace(" ", "")
    assert "proxies" not in src


def test_pinned_client_closed_after_fetch(monkeypatch) -> None:
    """Resource cleanup: the (stub) pinned transport is closed by the
    unchanged `with httpx.Client(...)` block."""
    monkeypatch.setenv("OPENJARVIS_PINNED_TRANSPORT", "1")
    closed: list = []

    class _TrackedTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="ok")

        def close(self) -> None:
            closed.append(True)

    import openjarvis.security.pinned_transport as pt_mod

    monkeypatch.setattr(pt_mod, "build_pinned_transport",
                        lambda **kw: _TrackedTransport())
    text = ws_mod.WebSearchTool._fetch_url("http://93.184.216.34/")
    assert "ok" in text
    assert closed == [True]


def test_flag_default_off_residual(monkeypatch) -> None:
    """Flag OFF (default) keeps the historical transport — recorded as a
    residual, never as a safety PASS."""
    monkeypatch.delenv("OPENJARVIS_PINNED_TRANSPORT", raising=False)
    from openjarvis.security.pinned_transport import is_enabled

    assert is_enabled() is False


def _hybrid_callers() -> list:
    import pathlib

    base = pathlib.Path(ws_mod.__file__).parent.parent / "agents" / "hybrid"
    callers = []
    for path in (base / "toolorchestra.py",
                 base / "skillorchestra" / "tools.py",
                 base / "minions.py", base / "conductor.py",
                 base / "advisors.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "tavily_search_context"):
                keywords = {kw.arg for kw in node.keywords}
                callers.append((str(path), keywords))
    return callers


def test_hybrid_callers_authority_state() -> None:
    """Authority migration pin: all 5 harness tavily sites thread host
    authority. skillorchestra/minions pass via helper/thunk kwargs —
    see per-harness wiring tests for behavioral proof.

    Any future wiring change must update this test deliberately."""
    callers = _hybrid_callers()
    assert len(callers) == 5
    by_file = {path.split("hybrid")[-1].replace("\\", "/"): keywords
               for path, keywords in callers}
    assert by_file.get("/toolorchestra.py") == {"authority", "max_results"}
    assert "authority" in by_file.get("/minions.py", set())
    conductor_key = next(k for k in by_file if k.endswith("conductor.py"))
    assert "authority" in by_file[conductor_key]
    skill_key = next(k for k in by_file if k.endswith("tools.py"))
    assert "authority" in by_file[skill_key]
    advisors_key = next(k for k in by_file if k.endswith("advisors.py"))
    assert "authority" in by_file[advisors_key]
