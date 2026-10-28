"""Legacy & retriever migration regression (offline, zero network).

- Legacy `authority=None` path emits an observability warning and preserves
  behavior (compat-safe migration step; denial would break unknown
  out-of-repo embeddings).
- SWE loop entry denies dynamically (no clone/network reached).
- Retriever POST stays operator-URL + worker-gated (static pins).
- Retriever transport hardening (§2A): no redirects, no env proxies,
  TLS verify on, operator-URL validated (mock-proven, zero network).
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

import openjarvis.agents.hybrid.skillorchestra.tools as _tools_mod


def test_legacy_path_warns_and_preserves_behavior(caplog, monkeypatch) -> None:
    from openjarvis.agents.hybrid import _base as base_mod
    from tests.security.test_toolorchestra_authority_wiring import (
        _FakeSearchTool,
    )

    _FakeSearchTool.instances.clear()
    monkeypatch.setattr("openjarvis.tools.web_search.WebSearchTool",
                        _FakeSearchTool)
    with caplog.at_level(logging.WARNING, logger=base_mod.__name__):
        result = base_mod.tavily_search_context("model query")
    assert result["success"] is True
    assert any("legacy direct execution" in message
               for message in caplog.messages)


def test_authority_path_emits_no_legacy_warning(caplog, monkeypatch) -> None:
    from openjarvis.agents.hybrid import _base as base_mod
    from tests.security.test_toolorchestra_authority_wiring import (
        _authority,
        _FakeSearchTool,
        _granting_policy,
    )

    _FakeSearchTool.instances.clear()
    monkeypatch.setattr("openjarvis.tools.web_search.WebSearchTool",
                        _FakeSearchTool)
    with caplog.at_level(logging.WARNING, logger=base_mod.__name__):
        base_mod.tavily_search_context(
            "model query", authority=_authority(_granting_policy()))
    assert not any("legacy direct execution" in message
                   for message in caplog.messages)


def test_swe_loop_entry_denies_dynamically() -> None:
    """Dynamic proof: the loop denies before clone/network/dispatch."""
    from openjarvis.agents.hybrid.mini_swe_agent import run_swe_agent_loop

    result = run_swe_agent_loop({}, backbone="cloud", backbone_model="x")
    assert result["security_denied"] is True
    assert result["error"] == "CODE_SANDBOX_UNAVAILABLE"
    assert result["execution_state"] == "NOT_STARTED"


def test_retriever_post_stays_operator_url_and_gated() -> None:
    """Static pins: POST target derives from the operator param with a fixed
    `/retrieve` suffix; the worker-level gate precedes the tavily/retriever
    branch in run_search."""
    import openjarvis.agents.hybrid.skillorchestra.tools as tools_mod

    tree = ast.parse(Path(tools_mod.__file__).read_text(encoding="utf-8"))
    src = ast.dump(tree)
    assert "/retrieve" in src
    func = next(node for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef)
                and node.name == "run_search")
    body_src = ast.dump(func)
    gate_pos = body_src.find("_authorize_direct_operation")
    post_pos = body_src.find("requests")
    assert 0 <= gate_pos < post_pos
    # The URL expression references only the operator parameter + suffix.
    assert "retriever_url" in src


def test_retriever_hardened_transport_pinned() -> None:
    """Static pin for §2A: run_search uses a Session with trust_env=False,
    allow_redirects=False, a validated URL helper, and no direct
    requests.post call. Any regression to the old transport fails here."""
    import openjarvis.agents.hybrid.skillorchestra.tools as tools_mod

    tree = ast.parse(Path(tools_mod.__file__).read_text(encoding="utf-8"))
    func = next(node for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef)
                and node.name == "run_search")
    body_src = ast.dump(func)
    assert "_validated_retriever_url" in body_src
    assert "trust_env" in body_src
    assert "allow_redirects" in body_src
    direct = [node for node in ast.walk(func)
              if isinstance(node, ast.Call)
              and isinstance(node.func, ast.Attribute)
              and node.func.attr == "post"
              and isinstance(node.func.value, ast.Name)
              and node.func.value.id == "requests"]
    assert direct == []  # only session.post remains; no requests.post


# ---------------------------------------------------------------------------
# §2A retriever transport hardening (failing-first, mock-only, zero network)
# ---------------------------------------------------------------------------


class _RedirectResp:
    status_code = 302
    is_redirect = True
    headers = {"Location": "https://evil.example/"}

    def json(self):
        raise AssertionError("redirect body must never be parsed")


class _DocsResp:
    status_code = 200
    is_redirect = False
    headers = {}

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


_DOCS = [[{"document": {"content": "doc-a"}},
          {"document": {"contents": "doc-b"}}]]


class _RetrieverAgent:
    def __init__(self, authorized=True):
        self._authorized = authorized
        self.operations: list = []

    def _authorize_direct_operation(self, caps, *, operation):
        self.operations.append((list(caps), operation))
        return SimpleNamespace(
            success=self._authorized,
            content="ok" if self._authorized else "denied")


def _spec():
    from openjarvis.agents.hybrid.skillorchestra.pool import ModelSpec

    return ModelSpec("search-1", "m", "anthropic", "cloud")


@pytest.fixture
def retriever_net(monkeypatch):
    """Fake the transport: loud on direct requests.post, fake Session."""
    record: dict = {"posts": [], "sessions": [], "direct_post": False}
    behavior: dict = {}

    class _Session:
        def __init__(self, *args, **kwargs):
            self.trust_env = True
            record["sessions"].append(self)

        def post(self, url, **kwargs):
            record["posts"].append((url, kwargs))
            return behavior["fn"](url, kwargs)

    def _loud_post(*args, **kwargs):
        record["direct_post"] = True
        raise AssertionError("direct requests.post must not be used")

    monkeypatch.setattr(requests, "Session", _Session)
    monkeypatch.setattr(requests, "post", _loud_post)
    monkeypatch.setattr(
        _tools_mod, "call_alias",
        lambda agent, spec, **kw: ("<query>SECRET_MARKER_Q</query>",
                                   1, 2, 0.0))
    return record, behavior


def _run(url, record_behavior, authorized=True):
    record, behavior = record_behavior
    agent = _RetrieverAgent(authorized=authorized)
    out = _tools_mod.run_search(
        agent, _spec(), context_str="ctx", problem="prob",
        retriever_url=url, search_backend="provider")
    return agent, out, record


def test_retriever_redirect_refused_single_shot(retriever_net) -> None:
    record, behavior = retriever_net
    behavior["fn"] = lambda url, kw: _RedirectResp()
    _, out, _ = _run("https://retriever.example", retriever_net)
    assert any("redirect" in c for c in out["search_results_data"])
    assert not any("evil.example" in c for c in out["search_results_data"])
    assert len(record["posts"]) == 1  # no follow-up request
    assert record["posts"][0][1].get("allow_redirects") is False
    assert record["direct_post"] is False


def test_retriever_ignores_proxy_env(retriever_net, monkeypatch) -> None:
    record, behavior = retriever_net
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(var, "http://proxy.example:8080/")
    monkeypatch.setenv("NO_PROXY", "*")
    behavior["fn"] = lambda url, kw: _DocsResp(_DOCS)
    _, out, _ = _run("https://retriever.example", retriever_net)
    assert record["sessions"][0].trust_env is False
    assert "proxies" not in record["posts"][0][1]
    assert "doc-a" in out["search_results_data"]


def test_retriever_tls_verify_maintained(retriever_net) -> None:
    record, behavior = retriever_net
    behavior["fn"] = lambda url, kw: _DocsResp(_DOCS)
    _run("https://retriever.example", retriever_net)
    assert record["posts"][0][1].get("verify", True) is True


def test_retriever_no_verify_false_anywhere() -> None:
    tree = ast.parse(Path(_tools_mod.__file__).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "verify":
            assert not (isinstance(node.value, ast.Constant)
                        and node.value.value is False)


def test_retriever_rejects_bad_scheme(retriever_net) -> None:
    record, behavior = retriever_net
    behavior["fn"] = lambda url, kw: _DocsResp(_DOCS)
    _, out, _ = _run("ftp://retriever.example/x", retriever_net)
    assert any("retriever error" in c for c in out["search_results_data"])
    assert record["posts"] == [] and record["direct_post"] is False


def test_retriever_rejects_userinfo(retriever_net) -> None:
    record, behavior = retriever_net
    behavior["fn"] = lambda url, kw: _DocsResp(_DOCS)
    _, out, _ = _run("https://user:s3cret@retriever.example/",
                      retriever_net)
    assert any("retriever error" in c for c in out["search_results_data"])
    assert not any("s3cret" in c for c in out["search_results_data"])
    assert record["posts"] == [] and record["direct_post"] is False


def test_retriever_rejects_empty_host(retriever_net) -> None:
    record, behavior = retriever_net
    behavior["fn"] = lambda url, kw: _DocsResp(_DOCS)
    _, out, _ = _run("https://", retriever_net)
    assert any("retriever error" in c for c in out["search_results_data"])
    assert record["posts"] == [] and record["direct_post"] is False


def test_retriever_rejects_plain_http_remote(retriever_net) -> None:
    record, behavior = retriever_net
    behavior["fn"] = lambda url, kw: _DocsResp(_DOCS)
    _, out, _ = _run("http://retriever.example/", retriever_net)
    assert any("retriever error" in c for c in out["search_results_data"])
    assert record["posts"] == [] and record["direct_post"] is False


def test_retriever_allows_http_loopback(retriever_net) -> None:
    record, behavior = retriever_net
    behavior["fn"] = lambda url, kw: _DocsResp(_DOCS)
    _, out, _ = _run("http://127.0.0.1:8000", retriever_net)
    assert record["posts"][0][0] == "http://127.0.0.1:8000/retrieve"
    assert "doc-a" in out["search_results_data"]


def test_retriever_https_compat_and_query_cannot_steer_url(
        retriever_net) -> None:
    record, behavior = retriever_net
    behavior["fn"] = lambda url, kw: _DocsResp(_DOCS)
    _, out, _ = _run("https://retriever.example/", retriever_net)
    assert record["posts"][0][0] == "https://retriever.example/retrieve"
    # Model-controlled query (mentions an evil URL) never reaches the URL.
    assert all("evil" not in url for url, _ in record["posts"])
    assert "doc-a" in out["search_results_data"]
    assert "doc-b" in out["search_results_data"]


def test_retriever_denied_sends_zero_http(retriever_net) -> None:
    record, behavior = retriever_net
    behavior["fn"] = lambda url, kw: _DocsResp(_DOCS)
    agent, out, _ = _run("https://retriever.example", retriever_net,
                         authorized=False)
    assert any("search blocked" in c for c in out["search_results_data"])
    assert record["posts"] == []
    assert record["sessions"] == [] and record["direct_post"] is False
    assert agent.operations[0][1] == "skillorchestra_retriever"


def test_retriever_timeout_maps_to_error_schema(retriever_net) -> None:
    record, behavior = retriever_net

    def _boom(url, kw):
        raise requests.exceptions.ConnectTimeout("timed out")

    behavior["fn"] = _boom
    _, out, _ = _run("https://retriever.example", retriever_net)
    assert any("retriever error" in c for c in out["search_results_data"])


def test_retriever_logs_no_body(retriever_net, caplog) -> None:
    import logging

    record, behavior = retriever_net
    behavior["fn"] = lambda url, kw: _DocsResp(_DOCS)
    with caplog.at_level(logging.DEBUG):
        _run("https://retriever.example", retriever_net)
    assert "SECRET_MARKER_Q" not in caplog.text
