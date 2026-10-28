"""Tests for the chat startup banner."""

from __future__ import annotations

import os
from pathlib import Path

from openjarvis.cli import _bg_state
from openjarvis.cli._chat_banner import render_startup_banner


def _model_marker() -> str:
    return "qwen3.5%3A9b" if os.name == "nt" else "qwen3.5:9b"


def test_banner_empty_when_all_ready(tmp_openjarvis_home: Path) -> None:
    (tmp_openjarvis_home / ".state" / "extension-built").write_text("")
    marker = tmp_openjarvis_home / ".state" / "models" / f"{_model_marker()}.ready"
    marker.write_text("")
    s = _bg_state.get_status()
    banner = render_startup_banner(s)
    assert banner == ""


def test_banner_shows_rust_building(tmp_openjarvis_home: Path) -> None:
    """Pending rust ext (no marker file) is shown as 'building'."""
    s = _bg_state.get_status()  # all pending
    banner = render_startup_banner(s)
    assert "Rust extension" in banner
    assert "building" in banner.lower()


def test_banner_shows_model_downloading(tmp_openjarvis_home: Path) -> None:
    (tmp_openjarvis_home / ".state" / "extension-built").write_text("")
    models_dir = tmp_openjarvis_home / ".state" / "models"
    (models_dir / f"{_model_marker()}.downloading").write_text("")
    s = _bg_state.get_status()
    banner = render_startup_banner(s)
    assert "qwen3.5:9b" in banner
    assert "downloading" in banner.lower()


def test_banner_shows_failed_in_dim_warning(tmp_openjarvis_home: Path) -> None:
    (tmp_openjarvis_home / ".state" / "extension-failed").write_text("error tail")
    s = _bg_state.get_status()
    banner = render_startup_banner(s)
    assert "failed" in banner.lower()
    assert "doctor" in banner.lower()
