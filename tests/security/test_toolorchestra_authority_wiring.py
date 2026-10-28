"""ToolOrchestra first-path authority wiring (offline, zero network).

Contract: `tavily_search_context(query, *, max_results, authority=None)`
routes the WebSearchTool call through `execute_secured_tool` with the
host-built authority bundle when provided; `None` preserves the legacy
direct call for the other (unmigrated) harnesses.

The real WebSearchTool class is replaced with a recording fake, so no
network, subprocess, or provider call can occur.
"""

from __future__ import annotations

from typing import Any

import pytest

from openjarvis.agents.hybrid import _base as base_mod
from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.types import ToolResult
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.tools._stubs import BaseTool, ToolSpec


class _FakeSearchTool(BaseTool):
    tool_id = "ws_fake"
    instances: list = []

    def __init__(self, max_results: int = 5) -> None:
        self.calls: list = []
        type(self).instances.append(self)

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name="ws_fake", description="fake search",
                        timeout_seconds=30.0,
                        required_capabilities=["network:fetch"],
                        effect=ToolEffect.MUTATING)

    @property
    def is_local(self) -> bool:
        return False

    def execute(self, **params: Any):
        self.calls.append(dict(params))
        return ToolResult(tool_name="ws_fake", content="search-text",
                          success=True,
                          execution_state=ExecutionState.EXECUTED,
                          metadata={"engine": "tavily", "credits": 3})


@pytest.fixture()
def fake_search(monkeypatch):
    _FakeSearchTool.instances.clear()
    monkeypatch.setattr("openjarvis.tools.web_search.WebSearchTool",
                        _FakeSearchTool)
    return _FakeSearchTool


def _authority(policy=None, agent_id="hybrid-worker"):
    return {"bus": None, "capability_policy": policy, "rate_limiter": None,
            "agent_id": agent_id}


def _granting_policy(agent_id: str = "hybrid-worker"):
    policy = CapabilityPolicy(default_deny=True)
    policy.grant(agent_id, "network:fetch")
    return policy


def test_authorized_search_succeeds_with_schema(fake_search) -> None:
    result = base_mod.tavily_search_context(
        "model query", max_results=5,
        authority=_authority(_granting_policy()))
    assert result["success"] is True
    assert result["text"] == "search-text"
    assert result["engine"] == "tavily"
    assert result["error"] is None
    assert result["n_searches"] == 1
    assert set(result) == {"text", "success", "engine", "credits",
                           "cost_usd", "n_searches", "error"}


def test_policy_absent_denied_without_tool_call(fake_search) -> None:
    result = base_mod.tavily_search_context(
        "model query", authority=_authority(None))
    assert result["success"] is False
    assert result["error"] is not None
    assert all(instance.calls == [] for instance in _FakeSearchTool.instances)


def test_capability_absent_denied_without_tool_call(fake_search) -> None:
    result = base_mod.tavily_search_context(
        "model query",
        authority=_authority(CapabilityPolicy(default_deny=True)))
    assert result["success"] is False
    assert all(instance.calls == [] for instance in _FakeSearchTool.instances)


def test_wrong_agent_grant_denied(fake_search) -> None:
    result = base_mod.tavily_search_context(
        "model query",
        authority=_authority(_granting_policy("other-agent"),
                             agent_id="hybrid-worker"))
    assert result["success"] is False
    assert all(instance.calls == [] for instance in _FakeSearchTool.instances)


def test_legacy_direct_path_preserved_without_authority(fake_search) -> None:
    result = base_mod.tavily_search_context("model query")
    assert result["success"] is True
    assert sum(len(i.calls) for i in _FakeSearchTool.instances) == 1


def test_tool_exception_maps_to_error_not_success(fake_search,
                                                  monkeypatch) -> None:
    class _Boom(_FakeSearchTool):
        def execute(self, **params: Any):
            raise RuntimeError("backend down")

    monkeypatch.setattr("openjarvis.tools.web_search.WebSearchTool", _Boom)
    result = base_mod.tavily_search_context(
        "model query", authority=_authority(_granting_policy()))
    assert result["success"] is False
    assert result["error"] is not None


class _FakeAdvisorsSelf:
    """Minimal stand-in for AdvisorsAgent wiring surface."""

    def __init__(self, executor=None, authorized=True) -> None:
        self._executor = executor
        self._cfg = {"search_backend": "tavily", "tavily_max_results": 5}
        self._authorized = authorized
        self.cloud_calls: list = []

    def _authorize_direct_operation(self, caps, *, operation):
        from openjarvis.core.types import ToolResult

        return ToolResult(tool_name=operation,
                          content="ok" if self._authorized else "denied",
                          success=self._authorized)

    def _call_cloud(self, *, user, system, max_tokens, temperature):
        self.cloud_calls.append(user)
        return ("advisor-answer", 1, 2)


def _advisors_executor(policy=None):
    from types import SimpleNamespace

    return SimpleNamespace(_bus=None, _capability_policy=policy,
                           _rate_limiter=None, _agent_id="advisors")


def test_advisors_tavily_authorized(fake_search) -> None:
    from openjarvis.agents.hybrid.advisors import AdvisorsAgent

    agent = _FakeAdvisorsSelf(_advisors_executor(_granting_policy("advisors")),
                              authorized=True)
    agent.agent_id = "advisors"
    out = AdvisorsAgent._executor_search(
        agent, user="model query", system="sys", max_tokens=100,
        ws_max_uses=5, max_turns=2)
    assert "advisor-answer" in out[0]
    assert any("search-text" in call for call in agent.cloud_calls)
    assert sum(len(i.calls) for i in _FakeSearchTool.instances) == 1


def test_advisors_tavily_policy_absent_denied(fake_search) -> None:
    from openjarvis.agents.hybrid.advisors import AdvisorsAgent

    agent = _FakeAdvisorsSelf(_advisors_executor(None), authorized=True)
    agent.agent_id = "advisors"
    AdvisorsAgent._executor_search(
        agent, user="model query", system="sys", max_tokens=100,
        ws_max_uses=5, max_turns=2)
    assert all(instance.calls == [] for instance in _FakeSearchTool.instances)


def test_advisors_worker_gate_denial_short_circuits(fake_search) -> None:
    from openjarvis.agents.hybrid.advisors import AdvisorsAgent

    agent = _FakeAdvisorsSelf(
        _advisors_executor(_granting_policy("advisors")), authorized=False)
    agent.agent_id = "advisors"
    out = AdvisorsAgent._executor_search(
        agent, user="model query", system="sys", max_tokens=100,
        ws_max_uses=5, max_turns=2)
    assert "denied" in out[0]
    assert agent.cloud_calls == []
    assert all(instance.calls == [] for instance in _FakeSearchTool.instances)


def _conductor_call(monkeypatch, worker, cfg, authority):
    from openjarvis.agents.hybrid import conductor as conductor_mod

    prompts: list = []

    def _fake_openai(*args, **kwargs):
        prompts.append(kwargs.get("user", ""))
        return ("worker-answer", 1, 2)

    monkeypatch.setattr(conductor_mod.LocalCloudAgent, "_call_openai",
                        staticmethod(_fake_openai))
    out = conductor_mod._call_worker(worker, "model query", cfg,
                                     web_search_tool={"enabled": True},
                                     authority=authority)
    return out, prompts


def _conductor_cfg() -> dict:
    return {"search_backend": "tavily", "tavily_max_results": 5,
            "worker_max_tokens": 100, "worker_temperature": 0.0}


def test_conductor_tavily_authorized(monkeypatch, fake_search) -> None:
    out, prompts = _conductor_call(
        monkeypatch, {"endpoint": "openai", "model": "m"},
        _conductor_cfg(), _authority(_granting_policy()))
    text = out[0]
    assert "worker-answer" in text
    assert any("search-text" in prompt for prompt in prompts)
    assert out[3] is False
    assert sum(len(i.calls) for i in _FakeSearchTool.instances) == 1


def test_conductor_tavily_policy_absent_denied(monkeypatch,
                                               fake_search) -> None:
    text, *_rest = _conductor_call(
        monkeypatch, {"endpoint": "openai", "model": "m"},
        _conductor_cfg(), _authority(None))
    assert "worker-answer" in text  # worker still runs; search grounded nothing
    assert all(instance.calls == [] for instance in _FakeSearchTool.instances)


def test_conductor_tavily_wrong_agent_denied(monkeypatch, fake_search) -> None:
    text, *_rest = _conductor_call(
        monkeypatch, {"endpoint": "openai", "model": "m"},
        _conductor_cfg(),
        _authority(_granting_policy("other-agent"),
                   agent_id="hybrid-worker"))
    assert all(instance.calls == [] for instance in _FakeSearchTool.instances)


def test_conductor_tavily_legacy_direct_preserved(monkeypatch,
                                                  fake_search) -> None:
    from openjarvis.agents.hybrid import conductor as conductor_mod

    prompts: list = []

    def _fake_openai(*args, **kwargs):
        prompts.append(kwargs.get("user", ""))
        return ("worker-answer", 1, 2)

    monkeypatch.setattr(conductor_mod.LocalCloudAgent, "_call_openai",
                        staticmethod(_fake_openai))
    text, *_rest = conductor_mod._call_worker(
        {"endpoint": "openai", "model": "m"}, "model query",
        _conductor_cfg(), web_search_tool={"enabled": True})
    assert any("search-text" in prompt for prompt in prompts)
    assert sum(len(i.calls) for i in _FakeSearchTool.instances) == 1


def test_conductor_secured_passes_authority() -> None:
    """Static pin: _call_worker_secured threads host authority down."""
    import ast
    from pathlib import Path

    import openjarvis.agents.hybrid.conductor as conductor_mod

    tree = ast.parse(Path(conductor_mod.__file__).read_text(encoding="utf-8"))
    cls = next(node for node in ast.walk(tree)
               if isinstance(node, ast.ClassDef)
               and node.name == "ConductorAgent")
    method = next(node for node in cls.body
                  if isinstance(node, ast.FunctionDef)
                  and node.name == "_call_worker_secured")
    src = ast.dump(method)
    assert "authority" in src


def test_minions_prefetch_authorized(fake_search) -> None:
    from openjarvis.agents.hybrid import minions as minions_mod

    result = minions_mod._prefetch_context(
        "model query", "anthropic", "model",
        search_backend="tavily", tavily_max_results=5,
        authority=_authority(_granting_policy()))
    assert result["text"] == "search-text"
    assert result.get("error") in (None, "")
    assert sum(len(i.calls) for i in _FakeSearchTool.instances) == 1


def test_minions_prefetch_policy_absent_denied(fake_search) -> None:
    from openjarvis.agents.hybrid import minions as minions_mod

    result = minions_mod._prefetch_context(
        "model query", "anthropic", "model",
        search_backend="tavily", tavily_max_results=5,
        authority=_authority(None))
    assert result.get("error") is not None
    assert all(instance.calls == [] for instance in _FakeSearchTool.instances)


def test_minions_prefetch_legacy_direct_preserved(fake_search) -> None:
    from openjarvis.agents.hybrid import minions as minions_mod

    result = minions_mod._prefetch_context(
        "model query", "anthropic", "model",
        search_backend="tavily", tavily_max_results=5)
    assert result["text"] == "search-text"


class _FakeExecutor:
    def __init__(self, policy=None, agent_id="skill-agent") -> None:
        self._bus = None
        self._capability_policy = policy
        self._rate_limiter = None
        self._agent_id = agent_id


class _FakeAgent:
    def __init__(self, executor=None) -> None:
        self._executor = executor
        self.agent_id = "skill-agent"


def test_skill_authority_built_from_host_executor() -> None:
    from openjarvis.agents.hybrid.skillorchestra.tools import (
        authority_for_search,
    )

    policy = _granting_policy("skill-agent")
    bundle = authority_for_search(_FakeAgent(_FakeExecutor(policy)))
    assert bundle is not None
    assert bundle["capability_policy"] is policy
    assert bundle["agent_id"] == "skill-agent"
    assert set(bundle) == {"bus", "capability_policy", "rate_limiter",
                           "agent_id"}


def test_skill_authority_absent_without_executor() -> None:
    from openjarvis.agents.hybrid.skillorchestra.tools import (
        authority_for_search,
    )

    assert authority_for_search(_FakeAgent(None)) is None
    assert authority_for_search(object()) is None


def test_skill_wired_search_end_to_end(fake_search) -> None:
    from openjarvis.agents.hybrid.skillorchestra.tools import (
        authority_for_search,
    )

    agent = _FakeAgent(_FakeExecutor(_granting_policy("skill-agent")))
    result = base_mod.tavily_search_context(
        "model query", authority=authority_for_search(agent))
    assert result["success"] is True
    assert result["text"] == "search-text"
    bare = _FakeAgent(_FakeExecutor(None))
    denied = base_mod.tavily_search_context(
        "model query", authority=authority_for_search(bare))
    assert denied["success"] is False
    assert denied["error"] is not None
