"""Negative contract tests for the ATLAS default-deny test runner."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "atlas_safe_runner", _ROOT / "scripts" / "atlas_safe_runner.py"
)
assert _SPEC is not None and _SPEC.loader is not None
_RUNNER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_RUNNER)


def test_unknown_profile_is_denied() -> None:
    with pytest.raises(_RUNNER.SafeRunnerError, match="unknown safe profile"):
        _RUNNER.validate_profile_paths("unknown")


def test_explicitly_denied_browser_path_is_not_allowlisted() -> None:
    manifest = _RUNNER.load_manifest()
    manifest["profiles"]["bad"] = {"tests": ["tests/tools/test_browser.py"]}
    original = _RUNNER.load_manifest
    _RUNNER.load_manifest = lambda: manifest
    try:
        with pytest.raises(_RUNNER.SafeRunnerError, match="explicitly denied"):
            _RUNNER.validate_profile_paths("bad")
    finally:
        _RUNNER.load_manifest = original


def test_real_helper_is_always_excluded_from_command() -> None:
    command = _RUNNER.build_command(
        "focused",
        basetemp="C:/Users/yingz/AppData/Local/Temp/atlas-phase16-test",
        junitxml="C:/Users/yingz/AppData/Local/Temp/atlas-phase16-test.xml",
    )
    assert "not real_helper" in command
    assert "--include-real-helper" not in command


def test_unknown_markers_fail_collection() -> None:
    command = _RUNNER.build_command(
        "focused",
        basetemp="C:/Users/yingz/AppData/Local/Temp/atlas-phase16-marker-test",
        junitxml="C:/Users/yingz/AppData/Local/Temp/atlas-phase16-marker-test.xml",
    )
    assert "--strict-markers" in command


def test_junit_duplicate_case_is_rejected(tmp_path: Path) -> None:
    xml = tmp_path / "duplicate.xml"
    xml.write_text(
        "<testsuite><testcase classname='x' name='y'/><testcase "
        "classname='x' name='y'/></testsuite>",
        encoding="utf-8",
    )
    with pytest.raises(_RUNNER.SafeRunnerError, match="duplicate testcase"):
        _RUNNER.validate_junit(xml)


def test_junit_real_helper_case_is_rejected(tmp_path: Path) -> None:
    xml = tmp_path / "unsafe.xml"
    xml.write_text(
        "<testsuite><testcase classname='x' name='test_real_helper_case'/></testsuite>",
        encoding="utf-8",
    )
    with pytest.raises(_RUNNER.SafeRunnerError, match="real_helper"):
        _RUNNER.validate_junit(xml)
