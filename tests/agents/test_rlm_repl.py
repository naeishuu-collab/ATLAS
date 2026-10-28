"""Regression tests for the RLM REPL fail-closed contract."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from openjarvis.agents.rlm_repl import RLMRepl


class TestRLMReplDisabled:
    @pytest.mark.parametrize(
        "code",
        [
            "value = 42",
            "print('should not run')",
            "open('should-not-exist', 'w')",
            "__import__('subprocess').run(['whoami'])",
        ],
    )
    def test_default_mode_denies_before_code_execution(self, code):
        repl = RLMRepl()

        result = repl.execute_with_outcome(code)

        assert result.success is False
        assert result.error_code == "RLM_WORKER_REQUIRED"
        assert "RLM_WORKER_REQUIRED" in result.output
        assert repl.get_variable("value") is None

    def test_legacy_flag_cannot_enable_in_process_execution(self):
        repl = RLMRepl(allow_unsafe_legacy=True)

        result = repl.execute_with_outcome("value = 42")

        assert result.success is False
        assert result.error_code == "RLM_LEGACY_DISABLED"
        assert repl.get_variable("value") is None

    def test_worker_mode_requires_host_sandbox_before_process_creation(self):
        repl = RLMRepl(execution_mode="worker")
        worker = repl._worker
        worker._start_sandboxed = Mock(
            side_effect=AssertionError("sandbox launcher must not start")
        )

        result = repl.execute_with_outcome("print('unreachable')")

        assert result.success is False
        assert result.error_code in {
            "RLM_SANDBOX_UNAVAILABLE",
            "RLM_SANDBOX_NOT_AUTHORIZED",
        }
        worker._start_sandboxed.assert_not_called()
        assert worker.process is None

    def test_direct_execute_is_structured_denial(self):
        repl = RLMRepl(allow_unsafe_legacy=True)

        output = repl.execute("1 + 1")

        assert "RLM_LEGACY_DISABLED" in output
        assert repl.get_variable("answer") is None

    def test_namespace_access_does_not_execute_code(self):
        repl = RLMRepl()

        repl.set_variable("value", 42)

        assert repl.get_variable("value") == 42
        assert repl.get_variable("json") is None
        assert repl.is_terminated is False

    def test_close_without_worker_is_safe(self):
        RLMRepl().close()


class TestRLMReplBoundaryChecks:
    def test_security_check_is_defense_in_depth_only(self):
        repl = RLMRepl()

        assert repl.security_check("value = 1 + 2") is None
        assert "Blocked" in repl.security_check("os.system('whoami')")

    def test_invalid_mode_is_rejected(self):
        with pytest.raises(ValueError):
            RLMRepl(execution_mode="legacy")

    def test_legacy_and_worker_modes_cannot_be_combined(self):
        with pytest.raises(ValueError):
            RLMRepl(execution_mode="worker", allow_unsafe_legacy=True)

    def test_worker_mode_rejects_host_callbacks(self):
        with pytest.raises(ValueError):
            RLMRepl(execution_mode="worker", llm_query_fn=lambda prompt: prompt)

    def test_worker_close_is_forwarded_without_starting_execution(self):
        repl = RLMRepl(execution_mode="worker")
        repl._worker.close = Mock()

        repl.close()

        repl._worker.close.assert_called_once_with()
