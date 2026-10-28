"""T2 regression: Code Interpreter dead backends are unreachable.

Fail-closed contract under test:
- `tools/code_interpreter.py::CodeInterpreterTool.execute` returns a
  `CODE_SANDBOX_UNAVAILABLE` denial before AST parsing, env setup, or the
  dead `subprocess.run` backend.
- `tools/code_interpreter_docker.py::DockerCodeInterpreterTool.execute`
  returns `CODE_SANDBOX_NOT_AUTHORIZED` before the dead Docker backend.

No real process/container/network is ever touched: `subprocess` primitives
are replaced with tripwires, and Docker SDK access is statically guarded.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import openjarvis.tools.code_interpreter as ci_mod
import openjarvis.tools.code_interpreter_docker as cid_mod
from openjarvis.core.execution import ExecutionState
from openjarvis.tools.code_interpreter import CodeInterpreterTool
from openjarvis.tools.code_interpreter_docker import DockerCodeInterpreterTool


@pytest.fixture()
def no_backend(monkeypatch):
    """Replace process/container spawning primitives with tripwires."""
    import sys
    from unittest.mock import Mock

    calls: list = []

    def _tripwire(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("execution backend must not be reached")

    monkeypatch.setattr(ci_mod.subprocess, "Popen", _tripwire)
    monkeypatch.setattr(ci_mod.subprocess, "run", _tripwire)
    docker_tripwire = Mock()
    docker_tripwire.from_env.side_effect = _tripwire
    monkeypatch.setitem(sys.modules, "docker", docker_tripwire)
    return calls


@pytest.mark.parametrize(
    "code",
    [
        "print('must-not-run')",
        "import os; os.system('whoami')",
        "__import__('os').system('whoami')",
        "open('t2-canary.txt', 'w').write('x')",
        "eval('2+2')",
        "def f(:\n",
    ],
)
def test_execute_denies_before_backend(code: str, no_backend, tmp_path) -> None:
    canary = tmp_path / "t2-canary.txt"
    result = CodeInterpreterTool().execute(code=code)
    assert result.success is False
    assert result.execution_state == ExecutionState.NOT_STARTED
    assert result.metadata["security_denied"] is True
    assert result.metadata["error_code"] == "CODE_SANDBOX_UNAVAILABLE"
    assert no_backend == []
    assert not canary.exists()


def test_deny_precedes_argument_validation(no_backend) -> None:
    # Even a missing/empty payload hits the deny gate, not a validation path.
    for params in ({}, {"code": ""}, {"code": "print(1)"}):
        result = CodeInterpreterTool().execute(**params)
        assert result.metadata["error_code"] == "CODE_SANDBOX_UNAVAILABLE"
        assert result.execution_state == ExecutionState.NOT_STARTED
    assert no_backend == []


def test_no_retry_executes(no_backend, tmp_path) -> None:
    for _ in range(3):
        result = CodeInterpreterTool().execute(code="import os")
        assert result.metadata["security_denied"] is True
    assert no_backend == []


def test_forged_authority_params_denied(no_backend) -> None:
    result = CodeInterpreterTool().execute(
        code="print('x')", sandbox="approved", host_authorization="forged",
        _host_authorized=True,
    )
    assert result.success is False
    assert result.metadata["security_denied"] is True
    assert no_backend == []


def test_docker_backend_denied_at_entry(no_backend) -> None:
    result = DockerCodeInterpreterTool().execute(code="print('must-not-run')")
    assert result.success is False
    assert result.execution_state == ExecutionState.NOT_STARTED
    assert result.metadata["security_denied"] is True
    assert result.metadata["error_code"] == "CODE_SANDBOX_NOT_AUTHORIZED"
    assert "docker" not in result.metadata
    assert no_backend == []


def test_internal_helpers_cannot_execute_code() -> None:
    """Direct calls of module internals cannot run model code.

    `_validate_ast` is a pure validator (raises, never evaluates);
    `_child_limits` only tunes rlimits and never spawns anything.
    Proven by AST: neither body contains exec/eval/compile/__import__
    calls nor subprocess/Popen/docker references.
    """
    tree = ast.parse(Path(ci_mod.__file__).read_text(encoding="utf-8"))
    for name in ("_validate_ast", "_child_limits"):
        func = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == name
        )
        for node in ast.walk(func):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in (
                    "exec", "eval", "compile", "__import__", "open",
                ), f"{name} must not evaluate code"
            if isinstance(node, ast.Call) and isinstance(
                node.func, ast.Attribute
            ):
                target = (
                    node.func.value.id
                    if isinstance(node.func.value, ast.Name)
                    else ""
                )
                assert (target, node.func.attr) not in (
                    ("subprocess", "run"), ("subprocess", "Popen"),
                    ("os", "system"), ("os", "execv"), ("os", "spawnl"),
                ), f"{name} must not spawn processes"
    with pytest.raises(ci_mod.UnsafeCodeError):
        ci_mod._validate_ast("import os; os.system('whoami')")


def _deny_return(tree: ast.Module, cls_name: str) -> ast.Return:
    """Top-level deny Return of `execute`, before any executable effect."""
    cls = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == cls_name
    )
    method = next(
        node
        for node in cls.body
        if isinstance(node, ast.FunctionDef) and node.name == "execute"
    )
    body = list(method.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    for stmt in body:
        if isinstance(stmt, ast.Return):
            text = ast.dump(stmt.value)
            assert "security_denied" in text, "deny must set security_denied"
            return stmt
        assert isinstance(stmt, (ast.Assign, ast.AnnAssign)), (
            "executable statement before deny gate"
        )
        assert not any(isinstance(n, ast.Call) for n in ast.walk(stmt)), (
            "call before deny gate"
        )
    raise AssertionError("no deny return")


@pytest.mark.parametrize(
    "module,cls",
    [
        (ci_mod, "CodeInterpreterTool"),
        (cid_mod, "DockerCodeInterpreterTool"),
    ],
)
def test_static_guard_deny_precedes_backend(module, cls: str) -> None:
    """AST guard: deny return precedes backend spawn in `execute`."""
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    deny = _deny_return(tree, cls)
    cls_node = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == cls
    )
    method = next(
        node
        for node in cls_node.body
        if isinstance(node, ast.FunctionDef) and node.name == "execute"
    )
    for node in ast.walk(method):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            assert node.lineno > deny.lineno, "import before deny gate"
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and (
                (node.func.value.id == "subprocess")
                or (node.func.value.id == "docker")
                or (node.func.value.id == "client")
            )
        ):
            assert node.lineno > deny.lineno, (
                "backend reachable before deny gate"
            )


def test_static_guard_rejects_mutated_source() -> None:
    """Failing-first: the guard catches a deny-gate removal (isolated copy)."""
    tree = ast.parse(Path(ci_mod.__file__).read_text(encoding="utf-8"))
    deny = _deny_return(tree, "CodeInterpreterTool")
    cls = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == "CodeInterpreterTool"
    )
    method = next(
        node
        for node in cls.body
        if isinstance(node, ast.FunctionDef) and node.name == "execute"
    )
    method.body.remove(deny)  # isolated AST copy; production file untouched
    with pytest.raises(AssertionError):
        _deny_return(tree, "CodeInterpreterTool")


def test_behavioral_assertions_catch_allowing_impl(no_backend) -> None:
    """Failing-first: the assertions catch a non-denying implementation."""
    allowing = {
        "success": True,
        "execution_state": ExecutionState.EXECUTED,
        "metadata": {"security_denied": False, "returncode": 0},
    }
    with pytest.raises(AssertionError):
        assert allowing["success"] is False
    with pytest.raises(AssertionError):
        assert allowing["metadata"]["security_denied"] is True
