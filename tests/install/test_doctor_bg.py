"""Tests for the doctor 'Background tasks' section."""

from __future__ import annotations

import os
from pathlib import Path

from click.testing import CliRunner

from openjarvis.cli.doctor_cmd import doctor


def _model_marker() -> str:
    return "qwen3.5%3A9b" if os.name == "nt" else "qwen3.5:9b"


def test_doctor_shows_bg_section_when_state_present(tmp_openjarvis_home: Path) -> None:
    (tmp_openjarvis_home / ".state" / "extension-built").write_text("")
    marker = tmp_openjarvis_home / ".state" / "models" / f"{_model_marker()}.ready"
    marker.write_text("")
    runner = CliRunner()
    result = runner.invoke(doctor, [], catch_exceptions=False)
    assert "Background tasks" in result.output
    assert "Rust extension" in result.output
    assert "qwen3.5:9b" in result.output
    assert "ready" in result.output


def test_doctor_exit_code_when_bg_failed(tmp_openjarvis_home: Path) -> None:
    (tmp_openjarvis_home / ".state" / "extension-failed").write_text("oom")
    runner = CliRunner()
    result = runner.invoke(doctor, [], catch_exceptions=False)
    # Doctor should exit non-zero when any bg task is failed.
    assert result.exit_code != 0
    assert "failed" in result.output.lower()


def test_doctor_no_bg_section_when_state_dir_empty(tmp_openjarvis_home: Path) -> None:
    """Empty .state/ — section still appears but reports 'no background tasks'."""
    runner = CliRunner()
    result = runner.invoke(doctor, [], catch_exceptions=False)
    assert "Background tasks" in result.output
