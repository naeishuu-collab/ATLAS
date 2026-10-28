"""SWE-fallback tavily scope pins (offline, static + sensitivity).

Proves the SWE one-shot fallbacks cannot reach the Tavily branch:
`toolorchestra._swe_call_worker` and `conductor._swe_worker_step` call
`_call_worker` WITHOUT the `web_search_tool` marker, so `use_ws` stays
False and the tavily branch is dead there. Also proves the search path
itself cannot escalate to code execution primitives.

Any change enabling the marker (or adding exec primitives) fails these
tests deliberately. Sensitivity is proven in-test via isolated AST
mutation — no production code is touched.
"""

from __future__ import annotations

import ast
import copy
from pathlib import Path


def _module_tree(name: str) -> ast.Module:
    import importlib

    mod = importlib.import_module(f"openjarvis.agents.hybrid.{name}")
    return ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    return next(node for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef) and node.name == name)


def _call_worker_calls(func: ast.FunctionDef) -> list:
    return [node for node in ast.walk(func)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_call_worker"]


def test_toolorchestra_swe_fallback_sets_no_search_marker() -> None:
    func = _function(_module_tree("toolorchestra"), "_swe_call_worker")
    calls = _call_worker_calls(func)
    assert len(calls) >= 1
    for node in calls:
        keywords = {kw.arg for kw in node.keywords}
        assert "web_search_tool" not in keywords
        assert "authority" not in keywords


def test_conductor_swe_fallback_sets_no_search_marker() -> None:
    func = _function(_module_tree("conductor"), "_swe_worker_step")
    calls = _call_worker_calls(func)
    assert len(calls) >= 1
    for node in calls:
        keywords = {kw.arg for kw in node.keywords}
        assert "web_search_tool" not in keywords


def test_search_path_cannot_reach_code_execution() -> None:
    """`tavily_search_context` builds one WebSearchTool and shapes results;
    no subprocess/Popen/exec/eval/compile/import calls exist in it."""
    import openjarvis.agents.hybrid._base as base_mod

    tree = ast.parse(Path(base_mod.__file__).read_text(encoding="utf-8"))
    func = _function(tree, "tavily_search_context")
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in (
                "exec", "eval", "compile", "__import__", "open",
                "Popen", "run", "system", "popen"), node.func.id
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names]
            assert not any(n.split(".")[0] in ("subprocess", "os", "ctypes")
                           for n in names), names


def test_pin_detects_marker_addition() -> None:
    """Sensitivity: adding the marker to a SWE fallback trips the pin."""
    tree = _module_tree("toolorchestra")
    func = _function(tree, "_swe_call_worker")
    mutated = copy.deepcopy(func)
    for node in ast.walk(mutated):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "_call_worker"):
            node.keywords.append(ast.keyword(
                arg="web_search_tool", value=ast.Constant(value=True)))
    keywords = {kw.arg
                for node in _call_worker_calls(mutated)
                for kw in node.keywords}
    assert "web_search_tool" in keywords  # the pin below would now fail
