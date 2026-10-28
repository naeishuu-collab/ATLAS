"""T1 regression: MiniSWE unapproved shell execution is always denied.

Fail-closed contract under test (src/openjarvis/agents/hybrid/mini_swe_agent.py):
`_run_bash` and `run_swe_agent_loop` return a denial dict before any
subprocess/network/filesystem effect. No real process is ever launched here:
`subprocess.Popen`/`subprocess.run` are replaced with recording fakes that
raise if touched.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import openjarvis.agents.hybrid.mini_swe_agent as mini_swe
from openjarvis.agents.hybrid.mini_swe_agent import _run_bash, run_swe_agent_loop


@pytest.fixture()
def no_subprocess(monkeypatch):
    """Replace process-spawning primitives with tripwires."""
    calls: list = []

    def _tripwire(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("subprocess must not be reached while denied")

    monkeypatch.setattr(mini_swe.subprocess, "Popen", _tripwire)
    monkeypatch.setattr(mini_swe.subprocess, "run", _tripwire)
    return calls


def test_run_bash_denied_contract(tmp_path: Path, no_subprocess) -> None:
    canary = tmp_path / "must_not_exist.txt"
    result = _run_bash(f"touch {canary}", tmp_path)
    assert result["security_denied"] is True
    assert result["exit_code"] is None
    assert result["execution_state"] == "NOT_STARTED"
    assert result["timed_out"] is False
    assert "CODE_SANDBOX_UNAVAILABLE" in result["stderr"]
    assert no_subprocess == []
    assert not canary.exists()


def test_run_bash_denial_is_not_success(tmp_path: Path, no_subprocess) -> None:
    result = _run_bash("echo pwned", tmp_path)
    assert result.get("success", False) is False
    assert result["security_denied"] is True
    assert no_subprocess == []


def test_run_bash_no_retry_executes(tmp_path: Path, no_subprocess) -> None:
    for _ in range(3):
        result = _run_bash("echo pwned", tmp_path)
        assert result["security_denied"] is True
        assert result["exit_code"] is None
    assert no_subprocess == []


def test_run_swe_agent_loop_denied_at_entry(no_subprocess) -> None:
    result = run_swe_agent_loop({}, backbone="cloud", backbone_model="x")
    assert result["security_denied"] is True
    assert result["error"] == "CODE_SANDBOX_UNAVAILABLE"
    assert result["execution_state"] == "NOT_STARTED"
    assert result["patch"] == ""
    assert no_subprocess == []


def test_deny_result_formats_without_exception(tmp_path: Path, no_subprocess) -> None:
    # Exception-path fail-closed: downstream formatting of the denial must
    # not raise and must not flip the outcome to success.
    result = _run_bash("echo pwned", tmp_path)
    text = mini_swe._format_observation(result)
    assert "exit_code: None" in text
    assert no_subprocess == []


def _early_deny_return(tree: ast.Module, func_name: str) -> ast.Return:
    """Return the unconditional early-deny Return of a function.

    Raises AssertionError when the function lacks a top-level (unnested)
    deny `return` before any Call, i.e. the deny gate was removed, made
    conditional, or preceded by executable effects.
    """
    func = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == func_name
    )
    body = list(func.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]  # docstring
    for index, stmt in enumerate(body):
        if isinstance(stmt, ast.Return):
            value = stmt.value
            assert isinstance(value, ast.Dict), (
                f"{func_name} deny must return a dict"
            )
            keys = [
                k.value for k in value.keys if isinstance(k, ast.Constant)
            ]
            assert "security_denied" in keys, (
                f"{func_name} deny must set security_denied"
            )
            return stmt
        # Only side-effect-free bindings may precede the deny return.
        assert isinstance(stmt, (ast.Assign, ast.AnnAssign)), (
            f"{func_name} has executable statement before deny gate"
        )
        assert not any(isinstance(n, ast.Call) for n in ast.walk(stmt)), (
            f"{func_name} has call before deny gate"
        )
    raise AssertionError(f"{func_name} has no deny return")


def test_static_guard_deny_precedes_subprocess() -> None:
    """AST guard: deny return precedes any subprocess spawn in _run_bash."""
    source = Path(mini_swe.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    deny = _early_deny_return(tree, "_run_bash")
    func = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_run_bash"
    )
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr in ("Popen", "run")
        ):
            # Any spawn inside _run_bash must be textually after the deny,
            # i.e. dead code unreachable without removing the gate.
            # (Other functions, e.g. _clone_repo's operator-driven git
            # clone, are out of scope for this guard.)
            assert node.lineno > deny.lineno, (
                "subprocess spawn reachable before deny gate"
            )
    _early_deny_return(tree, "run_swe_agent_loop")


def test_static_guard_rejects_mutated_source() -> None:
    """Failing-first: the guard catches a deny-gate removal (isolated copy)."""
    source = Path(mini_swe.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    deny = _early_deny_return(tree, "_run_bash")
    func = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_run_bash"
    )
    deny = _early_deny_return(tree, "_run_bash")
    func = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_run_bash"
    )
    func.body.remove(deny)  # isolated AST copy only; production file untouched
    with pytest.raises(AssertionError):
        _early_deny_return(tree, "_run_bash")


def test_behavioral_assertions_catch_allowing_impl(
    tmp_path: Path, no_subprocess
) -> None:
    """Failing-first: the behavioral assertions catch a non-denying impl."""

    def _allowing_impl(command, workdir, **kwargs):
        return {
            "stdout": "pwned",
            "stderr": "",
            "exit_code": 0,
            "timed_out": False,
            "truncated": False,
            "latency_s": 0.0,
            "security_denied": False,
            "execution_state": "EXECUTED",
        }

    result = _allowing_impl("echo pwned", tmp_path)
    with pytest.raises(AssertionError):
        assert result["security_denied"] is True
    with pytest.raises(AssertionError):
        assert result["exit_code"] is None
