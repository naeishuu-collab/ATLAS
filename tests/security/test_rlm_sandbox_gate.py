"""Fail-closed gates for untrusted RLM execution.

These tests deliberately use denial paths only.  They must never execute
generated code or start a child process.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from openjarvis.agents.rlm import RLMAgent
from openjarvis.agents.rlm_repl import RLMRepl
from openjarvis.agents.rlm_worker import RLMWorker
from openjarvis.sandbox.worker_launcher import SandboxSpec


def _assert_no_process_or_code(result, *, error_code: str, worker) -> None:
    assert result.success is False
    assert result.error_code == error_code
    assert worker.process is None
    assert worker.quarantined is True


def test_worker_without_sandbox_denies_before_spawn_or_exec() -> None:
    with (
        patch("multiprocessing.get_context") as get_context,
        patch("openjarvis.agents.rlm_worker._worker_execute") as execute,
    ):
        worker = RLMWorker()
        result = worker.execute_with_outcome(
            "open('should-not-exist', 'w').write('unsafe')"
        )

    _assert_no_process_or_code(
        result, error_code="RLM_SANDBOX_UNAVAILABLE", worker=worker
    )
    get_context.assert_not_called()
    execute.assert_not_called()


def test_worker_mode_denies_before_process_creation() -> None:
    with patch("multiprocessing.get_context") as get_context:
        repl = RLMRepl(execution_mode="worker")
        result = repl.execute_with_outcome("result = 1")

    assert result.success is False
    assert result.error_code == "RLM_SANDBOX_UNAVAILABLE"
    assert repl._worker.process is None
    get_context.assert_not_called()
    repl.close()


def test_legacy_flag_is_a_denial_not_an_execution_mode() -> None:
    with patch("builtins.exec") as execute:
        repl = RLMRepl(allow_unsafe_legacy=True)
        result = repl.execute_with_outcome("result = 1")

    assert repl.execution_mode == "disabled"
    assert result.success is False
    assert result.error_code == "RLM_LEGACY_DISABLED"
    execute.assert_not_called()


def test_agent_legacy_flag_denies_before_model_generation() -> None:
    engine = MagicMock()
    agent = RLMAgent(
        engine,
        "test-model",
        allow_unsafe_legacy_repl=True,
    )

    result = agent.run("execute generated code")

    assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
    assert result.tool_results[0].metadata["error_code"] == "RLM_LEGACY_DISABLED"
    engine.generate.assert_not_called()


def test_agent_worker_mode_denies_before_model_generation_without_sandbox() -> None:
    engine = MagicMock()
    agent = RLMAgent(
        engine,
        "test-model",
        execution_mode="worker",
        capability_policy=MagicMock(check=MagicMock(return_value=True)),
    )

    result = agent.run("execute generated code")

    assert result.metadata["error_code"] == "RLM_SANDBOX_UNAVAILABLE"
    assert result.tool_results[0].metadata["error_code"] == (
        "RLM_SANDBOX_UNAVAILABLE"
    )
    engine.generate.assert_not_called()


def test_direct_worker_invalid_sandbox_denies_without_spawn() -> None:
    with patch("multiprocessing.get_context") as get_context:
        worker = RLMWorker(sandbox=object())
        result = worker.execute_with_outcome("result = 1")

    _assert_no_process_or_code(
        result, error_code="SANDBOX_SPEC_INVALID", worker=worker
    )
    get_context.assert_not_called()


def test_direct_worker_unapproved_sandbox_never_reaches_launcher() -> None:
    with (
        patch("multiprocessing.get_context") as get_context,
        patch(
            "openjarvis.sandbox.worker_launcher.launch_sandboxed_owned"
        ) as launcher,
    ):
        worker = RLMWorker(sandbox=SandboxSpec())
        result = worker.execute_with_outcome("result = 1")

    _assert_no_process_or_code(
        result, error_code="RLM_SANDBOX_NOT_AUTHORIZED", worker=worker
    )
    get_context.assert_not_called()
    launcher.assert_not_called()


def test_missing_runtime_is_denied_before_native_launcher_lookup(tmp_path) -> None:
    with patch("openjarvis.sandbox.worker_launcher.launch_sandboxed_owned") as launcher:
        worker = RLMWorker(
            sandbox=SandboxSpec(runtime_root=tmp_path / "missing-runtime")
        )
        result = worker.execute_with_outcome("result = 1")

    _assert_no_process_or_code(
        result, error_code="RLM_SANDBOX_NOT_AUTHORIZED", worker=worker
    )
    launcher.assert_not_called()


@pytest.mark.parametrize("mode", ["legacy", "spawn", "unsafe"])
def test_worker_mode_alias_cannot_bypass(mode: str) -> None:
    with pytest.raises(ValueError):
        RLMRepl(execution_mode=mode)


def test_denial_never_mutates_files_or_dispatches_rpc(tmp_path) -> None:
    marker = tmp_path / "must-not-exist.txt"
    broker = MagicMock()
    worker = RLMWorker(llm_broker=broker)
    result = worker.execute_with_outcome(
        f"open({str(marker)!r}, 'w').write('unsafe')\n"
        "llm_query('must not dispatch')"
    )

    _assert_no_process_or_code(
        result, error_code="RLM_SANDBOX_UNAVAILABLE", worker=worker
    )
    assert not marker.exists()
    broker.handle_request.assert_not_called()


def test_quarantine_denial_is_terminal_without_retry_or_fallback() -> None:
    with (
        patch("multiprocessing.get_context") as get_context,
        patch("openjarvis.sandbox.worker_launcher.launch_sandboxed_owned") as launcher,
    ):
        worker = RLMWorker(sandbox=SandboxSpec())
        first = worker.execute_with_outcome("result = 1")
        second = worker.execute_with_outcome("result = 2")

    _assert_no_process_or_code(
        first, error_code="RLM_SANDBOX_NOT_AUTHORIZED", worker=worker
    )
    assert second.error_code == "WORKER_QUARANTINED"
    get_context.assert_not_called()
    launcher.assert_not_called()


@pytest.mark.parametrize("override", ["1", "worker", "legacy", "true"])
def test_environment_overrides_cannot_enable_unsandboxed_worker(
    monkeypatch, override: str
) -> None:
    monkeypatch.setenv("ASTRA_RLM_EXECUTION_MODE", override)
    worker = RLMWorker()
    result = worker.execute_with_outcome("result = 1")

    _assert_no_process_or_code(
        result, error_code="RLM_SANDBOX_UNAVAILABLE", worker=worker
    )
