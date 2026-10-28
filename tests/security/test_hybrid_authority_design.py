"""Hybrid authority architecture tests (offline, test-local design).

Encodes the HybridAuthority DI design from docs/pinned-transport-design.md
as executable contracts on fakes: policy ownership host-side, no-policy
fail-closed, no unlimited grants, result-shape compatibility, direct-path
detection. No production code is changed or depended on beyond the
existing ToolExecutor/CapabilityPolicy contracts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec


@dataclass(frozen=True)
class HybridAuthority:
    """Test-local shape of the proposed host-built authority bundle."""

    policy: Any
    bus: Any
    agent_id: str
    confirm: Callable[[str], bool] | None = None


class _SearchTool(BaseTool):
    tool_id = "hy_probe"

    def __init__(self, calls: list) -> None:
        self._calls = calls

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(name="hy_probe", description="hybrid probe",
                        timeout_seconds=30.0, effect=ToolEffect.MUTATING)

    @property
    def is_local(self) -> bool:
        return False

    def execute(self, **params: Any) -> ToolResult:
        self._calls.append(dict(params))
        return ToolResult(tool_name="hy_probe", content="search-text",
                          success=True,
                          execution_state=ExecutionState.EXECUTED,
                          metadata={"engine": "probe"})


def _managed_search(query: str, authority: HybridAuthority | None,
                    calls: list) -> ToolResult:
    """Test-local sketch of the migrated search path (design §3)."""
    tool = _SearchTool(calls)
    if authority is None:
        # Current direct behavior (residual): tool-internal checks only.
        return tool.execute(query=query)
    ex = ToolExecutor([tool], bus=authority.bus,
                      capability_policy=authority.policy,
                      agent_id=authority.agent_id, interactive=True,
                      confirm_callback=authority.confirm)
    return ex.execute(ToolCall(id="hy1", name="hy_probe",
                              arguments=json.dumps({"query": query})))


def _host_policy() -> CapabilityPolicy:
    return CapabilityPolicy()  # host-owned, open; scoped per deployment


def test_authority_present_with_policy_succeeds() -> None:
    calls: list = []
    authority = HybridAuthority(policy=_host_policy(), bus=None,
                                agent_id="hybrid-worker")
    result = _managed_search("model query", authority, calls)
    assert result.success is True
    assert result.content == "search-text"
    assert result.metadata["engine"] == "probe"  # shape compatible
    assert len(calls) == 1


def test_authority_missing_policy_fails_closed() -> None:
    calls: list = []
    authority = HybridAuthority(policy=None, bus=None,
                                agent_id="hybrid-worker")
    result = _managed_search("model query", authority, calls)
    assert result.success is False
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert calls == []


def test_no_unlimited_grant_shape() -> None:
    """The design carries a policy object, never a grant-all flag."""
    import dataclasses

    fields = {field.name for field in dataclasses.fields(HybridAuthority)}
    assert "grant_all" not in fields
    assert "allow" not in fields
    assert {"policy", "bus", "agent_id"} <= fields


def test_direct_path_detectable() -> None:
    """Without authority the sketch takes the direct branch (residual)."""
    calls: list = []
    result = _managed_search("model query", None, calls)
    assert result.success is True  # documents current residual, not approval
    assert len(calls) == 1


def test_llm_cannot_supply_authority() -> None:
    """Authority is host-built: model params never construct the bundle."""
    import inspect

    source = inspect.getsource(_managed_search)
    assert "authority" in source
    # The bundle enters as a parameter object, never parsed from query args.
    assert "json.loads" not in source
