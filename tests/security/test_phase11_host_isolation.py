"""Phase 11 host-isolation contracts; no real child or network is started."""

from __future__ import annotations

import inspect
from unittest.mock import Mock

from openjarvis.security import subprocess_sandbox as sandbox


def test_unapproved_subprocess_denies_before_creation(monkeypatch):
    popen = Mock(side_effect=AssertionError("Popen must not run"))
    monkeypatch.setattr(sandbox.subprocess, "Popen", popen)

    result = sandbox.run_sandboxed(["python", "-c", "print('fixture')"])

    assert result.started is False
    assert result.returncode == -1
    assert result.stderr.startswith("SUBPROCESS_SANDBOX_UNAVAILABLE")
    popen.assert_not_called()


def test_proxy_and_telemetry_environment_is_not_inherited(monkeypatch):
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "OPENAI_API_KEY",
        "POSTHOG_API_KEY",
        "DO_NOT_TRACK",
    ):
        monkeypatch.setenv(key, "must-not-inherit")

    env = sandbox.build_safe_env()

    assert all(key not in env for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "OPENAI_API_KEY",
        "POSTHOG_API_KEY",
        "DO_NOT_TRACK",
    ))


def test_network_environment_requires_explicit_passthrough(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid")

    env = sandbox.build_safe_env(passthrough=["HTTP_PROXY"])

    assert env["HTTP_PROXY"] == "http://proxy.invalid"


def test_unowned_windows_pid_is_never_killed(monkeypatch):
    if sandbox.os.name != "nt":
        return
    monkeypatch.setattr(sandbox, "_owned_jobs", {})
    kill = Mock(side_effect=AssertionError("unowned PID kill"))
    monkeypatch.setattr(sandbox.os, "kill", kill)

    sandbox.kill_process_tree(987654321)

    kill.assert_not_called()


def test_windows_job_is_cleanup_only_and_uses_owned_process_handle():
    source = inspect.getsource(sandbox._WindowsJob)

    assert "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE" in source
    assert "proc._handle" in source
    assert "OpenProcess" not in source


def test_job_object_claim_is_not_host_egress_proof():
    source = inspect.getsource(sandbox._WindowsJob)

    assert "AssignProcessToJobObject" in source
    assert "CreateJobObjectW" in source
    # A lifecycle job does not itself assert DNS/HTTP/WFP/AppContainer policy.
    assert "WinHTTP" not in source
    assert "Windows Filtering Platform" not in source

