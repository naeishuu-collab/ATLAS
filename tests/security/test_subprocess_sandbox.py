"""Fail-closed tests for the generic subprocess helper."""

from __future__ import annotations

import os
from unittest.mock import Mock

from openjarvis.security.subprocess_sandbox import (
    build_safe_env,
    kill_process_tree,
    run_sandboxed,
)


class TestBuildSafeEnv:
    def test_only_safe_vars_included(self):
        safe_keys = {
            "PATH",
            "HOME",
            "USER",
            "LANG",
            "TERM",
            "SHELL",
            "LC_ALL",
            "LC_CTYPE",
            "TMPDIR",
            "TZ",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "COMSPEC",
        }
        assert set(build_safe_env()) <= safe_keys

    def test_passthrough_and_extra_are_explicit(self, monkeypatch):
        monkeypatch.setenv("OPENJARVIS_TEST_VAR", "allowed")
        env = build_safe_env(
            passthrough=["OPENJARVIS_TEST_VAR"],
            extra={"OPENJARVIS_EXTRA": "value"},
        )
        assert env["OPENJARVIS_TEST_VAR"] == "allowed"
        assert env["OPENJARVIS_EXTRA"] == "value"

    def test_unknown_environment_is_excluded(self, monkeypatch):
        monkeypatch.setenv("OPENJARVIS_SECRET", "must-not-pass")
        assert "OPENJARVIS_SECRET" not in build_safe_env()


class TestRunSandboxedGate:
    def test_direct_helper_denies_before_process_creation(self, monkeypatch):
        start = Mock(side_effect=AssertionError("Popen must not run"))
        monkeypatch.setattr(
            "openjarvis.security.subprocess_sandbox.subprocess.Popen", start
        )
        result = run_sandboxed("echo must-not-run")
        assert result.started is False
        assert result.returncode == -1
        assert "SUBPROCESS_SANDBOX_UNAVAILABLE" in result.stderr
        start.assert_not_called()

    def test_denial_is_independent_of_command_shape(self):
        for command in ("echo x", ["python", "-c", "print(1)"]):
            result = run_sandboxed(command)
            assert result.started is False
            assert result.timed_out is False


class TestKillProcessTree:
    def test_no_crash_on_nonexistent_pid(self):
        kill_process_tree(999999999)

    def test_windows_unowned_pid_is_not_killed(self, monkeypatch):
        if os.name != "nt":
            return
        forbidden = Mock(side_effect=AssertionError("unowned PID kill"))
        monkeypatch.setattr(os, "kill", forbidden)
        kill_process_tree(os.getpid())
        forbidden.assert_not_called()
