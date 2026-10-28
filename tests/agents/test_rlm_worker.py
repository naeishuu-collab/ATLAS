"""Offline RLM worker contract tests (fail-closed spawn posture).

This checkout's worker is deliberately fail-closed: a spawn without an
approved AppContainer sandbox is denied and quarantined before any process
exists (``RLM_SANDBOX_UNAVAILABLE``), and even a caller-supplied
``SandboxSpec`` stays refused (``RLM_SANDBOX_NOT_AUTHORIZED``) until the
native approval verifier integration lands — Native Gates B-F remain
BLOCKED (not executed here, and no fake sandbox is treated as a native one).

The request/reply protocol semantics are therefore verified against the
module-level child-side functions (``_worker_namespace`` /
``_worker_execute``: the exact code the spawned child runs), while
worker-process lifecycle tests assert the current denial contract. Native
launcher semantics (startup timeout, crash classification, host-call RPC
over a real pipe) remain behind the approval gate.
"""

from __future__ import annotations

import pytest

from openjarvis.agents.rlm_repl import RLMRepl
from openjarvis.agents.rlm_worker import (
    MAX_FRAME_BYTES,
    MAX_STRING_CHARS,
    PROTOCOL_VERSION,
    RLMWorker,
    RLMWorkerError,
    _decode_frame,
    _encode_frame,
    _validate_handshake,
    _worker_execute,
    _worker_namespace,
)
from openjarvis.sandbox.worker_launcher import SandboxSpec


def _ready(session_id: str, nonce: str, **extra):
    return {
        "protocol": PROTOCOL_VERSION,
        "type": "ready",
        "session_id": session_id,
        "nonce": nonce,
        "max_requests": 10,
        **extra,
    }


def test_invalid_nonce_rejected_before_accepting_handshake():
    with pytest.raises(RLMWorkerError) as exc_info:
        _validate_handshake(_ready("s", "wrong"), "s", "expected")
    assert exc_info.value.error_code == "WORKER_PROTOCOL_ERROR"


def test_invalid_protocol_rejected_before_accepting_handshake():
    with pytest.raises(RLMWorkerError) as exc_info:
        _validate_handshake(
            _ready("s", "n", protocol="other-protocol"),
            "s",
            "n",
        )
    assert exc_info.value.error_code == "WORKER_PROTOCOL_ERROR"


def test_invalid_json_and_oversized_frames_are_rejected():
    with pytest.raises(RLMWorkerError):
        _decode_frame(b"not-json")
    with pytest.raises(RLMWorkerError):
        _decode_frame(b"x" * (MAX_FRAME_BYTES + 1))
    with pytest.raises(RLMWorkerError):
        _encode_frame({"code": "x" * (MAX_STRING_CHARS + 1)})


# ---------------------------------------------------------------------------
# Fail-closed spawn gate (offline): every spawn is denied and quarantined.
# ---------------------------------------------------------------------------


def test_spawn_worker_handshake_and_identity():
    # The handshake path is only reachable behind an approved native
    # launcher; until then the worker must deny before any process exists
    # while still carrying its host-issued identity.
    worker = RLMWorker(session_id="session-a", nonce="nonce-a")
    result = worker.execute_with_outcome("1 + 1")
    assert result.success is False
    assert result.error_code == "RLM_SANDBOX_UNAVAILABLE"
    assert result.unknown_outcome is False
    assert worker.quarantined is True
    assert worker.started is False
    assert worker.process is None
    assert worker.session_id == "session-a"
    assert worker.nonce == "nonce-a"


def test_spawn_with_spec_still_refused_until_approved():
    # A caller-supplied sandbox spec is configuration, not host authority:
    # the launcher stays unreachable and the worker quarantines.
    spec = SandboxSpec()
    worker = RLMWorker(sandbox=spec)
    result = worker.execute_with_outcome("1 + 1")
    assert result.success is False
    assert result.error_code == "RLM_SANDBOX_NOT_AUTHORIZED"
    assert worker.quarantined is True
    assert worker.process is None


def test_startup_timeout_quarantines_without_restart():
    # Startup only ever reaches the timeout path behind the native gate;
    # offline the startup gate itself quarantines, and a quarantined
    # worker refuses to restart (no second spawn, no retry).
    worker = RLMWorker(startup_timeout=0.01)

    result = worker.execute_with_outcome("1 + 1")

    assert result.success is False
    assert result.error_code == "RLM_SANDBOX_UNAVAILABLE"
    assert worker.quarantined is True
    assert worker.process is None
    again = worker.execute_with_outcome("1 + 1")
    assert again.error_code == "WORKER_QUARANTINED"


# ---------------------------------------------------------------------------
# Child-side protocol semantics (module-level, spawn-free, offline).
# ---------------------------------------------------------------------------


def test_persistent_namespace_and_approved_import():
    namespace, state = _worker_namespace()
    first = _worker_execute(namespace, state, "value = 41", 10000)
    second = _worker_execute(
        namespace, state, "import json\nprint(json.dumps({'value': value + 1}))", 10000
    )
    assert first.success is True
    assert second.success is True
    assert '{"value": 42}' in second.output


def test_rejected_import_is_a_structured_failure():
    namespace, state = _worker_namespace()
    result = _worker_execute(namespace, state, "import os", 10000)
    assert result.success is False
    assert result.error_code == "ImportError"
    assert result.unknown_outcome is False


def test_worker_output_is_bounded():
    namespace, state = _worker_namespace()
    result = _worker_execute(namespace, state, "print('x' * 1000)", 32)
    assert result.success is True
    assert "output truncated" in result.output
    assert len(result.output) < 128


def test_worker_has_no_host_callback_or_module_injection():
    namespace, state = _worker_namespace()
    result = _worker_execute(
        namespace,
        state,
        "try:\n"
        "    llm_query('host')\n"
        "except RuntimeError as exc:\n"
        "    print(str(exc))\n"
        "try:\n"
        "    os\n"
        "except NameError:\n"
        "    print('os absent')",
        10000,
    )
    assert result.success is True
    assert "RLM_CAPABILITY_UNAVAILABLE" in result.output
    assert "os absent" in result.output


def test_final_and_final_var_cross_only_json_values():
    namespace, state = _worker_namespace()
    final = _worker_execute(namespace, state, "FINAL({'status': 'done'})", 10000)
    assert final.success is True
    assert final.terminated is True
    assert final.final_value == {"status": "done"}

    namespace, state = _worker_namespace()
    result = _worker_execute(
        namespace, state, "answer = {'value': 42}\nFINAL_VAR('answer')", 10000
    )
    assert result.success is True
    assert result.terminated is True
    assert result.final_value == {"value": 42}

    namespace, state = _worker_namespace()
    result = _worker_execute(namespace, state, "FINAL(type)", 10000)
    assert result.success is False
    assert result.error_code == "NON_JSON_RESULT"


# ---------------------------------------------------------------------------
# Lifecycle: the loop/crash/limit semantics live behind the native gate;
# offline the fail-closed denial contract is deterministic and restart-free.
# ---------------------------------------------------------------------------


def test_request_limit_is_fail_closed():
    worker = RLMWorker(max_requests=1)
    result = worker.execute_with_outcome("1 + 1")
    assert result.success is False
    assert result.error_code == "RLM_SANDBOX_UNAVAILABLE"
    assert worker.quarantined is True
    assert worker.request_count == 0


def test_execution_timeout_quarantines_unknown_outcome():
    # The timeout classification runs on a live child; until the native gate
    # opens the startup denial is a KNOWN outcome that still quarantines and
    # refuses a retry.
    worker = RLMWorker(execution_timeout=0.2)
    result = worker.execute_with_outcome("while True: pass")
    assert result.success is False
    assert result.error_code == "RLM_SANDBOX_UNAVAILABLE"
    assert result.unknown_outcome is False
    assert worker.quarantined is True
    assert worker.process is None
    again = worker.execute_with_outcome("print('no retry')")
    assert again.error_code == "WORKER_QUARANTINED"


def test_worker_crash_is_classified_without_restart():
    worker = RLMWorker()
    result = worker.execute_with_outcome("1 + 1")
    assert result.success is False
    assert result.error_code == "RLM_SANDBOX_UNAVAILABLE"
    assert result.unknown_outcome is False
    assert worker.quarantined is True
    assert worker.execute_with_outcome("1 + 1").error_code == (
        "WORKER_QUARANTINED"
    )


def test_normal_shutdown_is_deterministic():
    worker = RLMWorker()
    worker.close()
    with pytest.raises(RLMWorkerError) as exc_info:
        worker.start()
    assert exc_info.value.error_code == "WORKER_CLOSED"
    assert worker.execute_with_outcome("1 + 1").error_code == "WORKER_CLOSED"
    assert worker.process is None


def test_explicit_repl_worker_mode_has_no_legacy_fallback():
    # Explicit worker mode has no in-process fallback: the worker's
    # fail-closed sandbox gate surfaces in the result; no legacy
    # execution path is taken.
    repl = RLMRepl(execution_mode="worker")
    try:
        result = repl.execute_with_outcome("value = 7\nFINAL(value)")
        assert repl.execution_mode == "worker"
        assert result.success is False
        assert result.error_code == "RLM_SANDBOX_UNAVAILABLE"
        assert repl.is_terminated is False
    finally:
        repl.close()


def test_worker_mode_rejects_host_callbacks():
    with pytest.raises(ValueError):
        RLMRepl(execution_mode="worker", llm_query_fn=lambda _: "host")
