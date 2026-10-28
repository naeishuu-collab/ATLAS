"""Direct-operation policy enforcement regression (offline, zero network).

Contract under test: `authorize_secured_operation`
(security/runtime.py:285) requires an explicit host capability policy —
`_OperationGate` is non-local, so the policy-absent exemption for local,
non-code tools never applies. Policy-absent direct operations are DENIED.

History: before the fix, policy=None AUTHORIZED network:fetch direct
operations (fail-open, reproduced offline as success=True/EXECUTED). That
old behavior is recorded here as evidence; the assertions below pin the
fixed deny contract.
"""

from __future__ import annotations

from openjarvis.core.execution import ExecutionState
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.security.runtime import authorize_secured_operation


def test_policy_absent_denies_direct_operation() -> None:
    """Fixed contract (was P1 fail-open): no policy ⇒ DENIED.

    Old behavior (evidence): success=True, content="authorized",
    EXECUTED. The fix (`_OperationGate.is_local = False`) routes
    policy-absent direct operations into HOST_AUTHORITY_UNAVAILABLE.
    """
    result = authorize_secured_operation(
        "toolorchestra_worker",
        ["network:fetch"],
        bus=None,
        capability_policy=None,
        rate_limiter=None,
        agent_id="gap-probe",
    )
    assert result.success is False
    assert "HOST_AUTHORITY_UNAVAILABLE" in result.content
    assert result.metadata.get("security_denied") is True
    assert result.execution_state == ExecutionState.NOT_STARTED


def test_policy_deny_blocks_direct_operation() -> None:
    policy = CapabilityPolicy(default_deny=True)
    result = authorize_secured_operation(
        "toolorchestra_worker",
        ["network:fetch"],
        bus=None,
        capability_policy=policy,
        rate_limiter=None,
        agent_id="gap-probe",
    )
    assert result.success is False
    assert "denied" in result.content


def test_policy_grant_authorizes_direct_operation() -> None:
    """Control: with a host grant the same operation is authorized."""
    policy = CapabilityPolicy(default_deny=True)
    policy.grant("gap-probe", "network:fetch")
    result = authorize_secured_operation(
        "toolorchestra_worker",
        ["network:fetch"],
        bus=None,
        capability_policy=policy,
        rate_limiter=None,
        agent_id="gap-probe",
    )
    assert result.success is True
    assert result.metadata.get("security_denied", False) is False


def test_hybrid_search_gates_resolve_to_same_authorizer() -> None:
    """All harness gates funnel into _authorize_direct_operation.

    Static pin: toolorchestra/minions/conductor/advisors each call it;
    none implements independent capability logic. A fix in
    authorize_secured_operation (or mandatory policy wiring) covers all.
    """
    import ast
    from pathlib import Path

    base = (Path(__file__).parent.parent.parent / "src" / "openjarvis"
            / "agents" / "hybrid")
    gated: dict = {}
    for name in ("toolorchestra.py", "minions.py", "conductor.py",
                 "advisors.py"):
        tree = ast.parse((base / name).read_text(encoding="utf-8"))
        hits = [node for node in ast.walk(tree)
                if isinstance(node, ast.Attribute)
                and node.attr == "_authorize_direct_operation"]
        gated[name] = len(hits)
    assert gated["toolorchestra.py"] >= 3
    for name, count in gated.items():
        assert count >= 1, f"{name} has no direct-operation gate"
