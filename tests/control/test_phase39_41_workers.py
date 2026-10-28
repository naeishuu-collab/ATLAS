"""Phase 39-41 real proposal-worker lifecycle and enforcement tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from openjarvis.control import (
    AdapterMode,
    ControlSurface,
    DispatchResult,
    ObservationSnapshot,
    SafeEngineAdapter,
    UfoProposalAdapter,
    WorkerProcess,
    WorkerProcessError,
    encode_request,
    safe_worker_environment,
)
from openjarvis.control.oss_adapter import make_authorized_action
from openjarvis.control.ufo_worker_rpc import (
    MAX_RPC_BYTES,
    decode_worker_error,
)
from openjarvis.core.execution import ExecutionState, MutationIntent

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
UFO_PYTHON = Path(
    r"C:\Users\yingz\.codex\isolated\atlas-phase33-35-20261025\venv-ufo-py310\Scripts\python.exe"
)
UFO_SOURCE = Path(
    r"C:\Users\yingz\.codex\isolated\atlas-phase24-26-20261025\UFO"
)
BROWSER_PYTHON = Path(
    r"C:\Users\yingz\.codex\isolated\atlas-phase24-26-20261025\venv-browser-use\Scripts\python.exe"
)
BROWSER_SOURCE = Path(
    r"C:\Users\yingz\.codex\isolated\atlas-phase24-26-20261025\browser-use"
)
WORKER_HOME = Path(
    r"C:\Users\yingz\.codex\isolated\atlas-phase39-41-20261025\worker-home"
)
KEY = b"phase39-41-test-only-key"


class _FakeExecutor:
    def __init__(self) -> None:
        self.calls = 0

    def dispatch(self, _authorized):
        self.calls += 1
        return DispatchResult(True, {"calls": self.calls})


def _worker(kind: str, python: Path, sdk_source: Path) -> WorkerProcess:
    assert python.is_file(), f"missing approved isolated interpreter: {python}"
    assert sdk_source.is_dir(), f"missing isolated SDK source: {sdk_source}"
    WORKER_HOME.mkdir(parents=True, exist_ok=True)
    session_id = f"phase39-41-{kind}"
    return WorkerProcess(
        [
            str(python),
            "-m",
            "openjarvis.control.proposal_worker",
            "--kind",
            kind,
            "--session-id",
            session_id,
            "--inspect",
        ],
        worker_kind=kind,
        session_id=session_id,
        env=safe_worker_environment(
            pythonpath=(str(SRC), str(sdk_source)),
            home=WORKER_HOME,
        ),
        cwd=sdk_source,
        startup_timeout=8.0,
        request_timeout=2.0,
    )


def _ufo_action(function: str = "type") -> dict:
    return {
        "function": function,
        "arguments": {"params": {"text": "fixture"}},
        "target": {"kind": "control", "name": "fixture", "id": "control-1"},
    }


def _ufo_snapshot() -> ObservationSnapshot:
    identity = {
        "session_id": "phase39-41-ufo",
        "process_id": 41,
        "process_created": 123,
        "hwnd": 500,
        "foreground_hwnd": 500,
        "window_cookie": "window-cookie-1",
        "runtime_id": [1, 2],
    }
    return ObservationSnapshot(
        ControlSurface.WINDOWS_APP,
        "obs-ufo-worker",
        ({"target_id": "control-1", "identity": identity},),
        privacy="PUBLIC",
        process_id=41,
    )


def _raw_request(
    worker: WorkerProcess,
    *,
    request_id: str,
    session_id: str,
    nonce: str,
    function: str,
    action: dict | None = None,
) -> dict:
    raw = encode_request(
        request_id=request_id,
        session_id=session_id,
        nonce=nonce,
        observation_id="obs-worker",
        action=action or {"function": function, "arguments": {}, "target": {}},
    )
    return worker._request_raw(
        raw,
        request_id=request_id,
        session_id=session_id,
        nonce=nonce,
    )


def _pid_running(pid: int | None) -> bool:
    if pid is None:
        return False
    result = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
        check=False,
        capture_output=True,
        text=True,
    )
    return f'"{pid}"' in result.stdout


def test_ufo_real_worker_to_safety_authority_fake_e2e():
    worker = _worker("ufo", UFO_PYTHON, UFO_SOURCE)
    ready = worker.start()
    try:
        assert ready["python"] == "3.10.21"
        assert ready["capabilities"]["sdk_import"] == "PASS"
        response = worker.request(
            request_id="ufo-request-1",
            nonce="ufo-nonce-1",
            observation_id="obs-ufo-worker",
            action=_ufo_action(),
        )
        assert response["status"] == "PROPOSAL"
        denied = worker.request(
            request_id="ufo-direct-1",
            nonce="ufo-direct-nonce",
            observation_id="obs-ufo-worker",
            action={
                "function": "ActionExecutor.execute",
                "arguments": {},
                "target": {},
            },
        )
        assert denied["status"] == "DENIED"
        assert denied["error"] == "DIRECT_SDK_DISPATCH_DENIED"
        executor = _FakeExecutor()
        host = SafeEngineAdapter(
            executor,
            surface=ControlSurface.WINDOWS_APP,
            mode=AdapterMode.ENFORCE,
            session_id="phase39-41-ufo",
            seal_key=KEY,
        )
        adapter = UfoProposalAdapter(session_id="phase39-41-ufo")
        proposal = adapter.propose(
            response["proposal"],
            _ufo_snapshot(),
            action_id="ufo-request-1",
        )
        authorized = make_authorized_action(
            proposal,
            MutationIntent("execution-ufo", "step-ufo", "intent-ufo"),
            session_id="phase39-41-ufo",
            nonce="ufo-nonce-1",
            key=KEY,
        )
        result = host.execute(
            proposal,
            _ufo_snapshot(),
            authorized=authorized,
            verify=lambda _proposal, dispatch: dispatch.dispatched,
        )
        assert result.state is ExecutionState.VERIFIED
        assert executor.calls == 1
    finally:
        lifecycle = worker.stop()
    assert lifecycle.cleaned is True
    assert lifecycle.exit_code == 0
    assert lifecycle.pid > 0


def test_browser_real_worker_imports_and_extracts_schema_without_browser():
    worker = _worker("browser", BROWSER_PYTHON, BROWSER_SOURCE)
    ready = worker.start()
    try:
        capabilities = ready["capabilities"]
        assert capabilities["sdk_import"] == "PASS"
        assert capabilities["schema_count"] == 24
        assert capabilities["agent_run"] == "NOT_CALLED"
        assert capabilities["browser_launch"] == "NOT_CALLED"
        response = worker.request(
            request_id="browser-request-1",
            nonce="browser-nonce-1",
            observation_id="obs-browser-worker",
            action={
                "function": "browser_proposal",
                "arguments": {"params": {"action": {"click": {"index": 3}}}},
                "target": {"kind": "element", "name": "fixture", "id": "element-3"},
            },
        )
        assert response["status"] == "PROPOSAL"
        assert response["proposal"]["arguments"]["params"]["action"] == {
            "click": {"index": 3}
        }
        for index, function in enumerate(
            ("Agent.run", "Tools.click", "subprocess", "network", "filesystem")
        ):
            denied = worker.request(
                request_id=f"browser-direct-{index}",
                nonce=f"browser-direct-nonce-{index}",
                observation_id="obs-browser-worker",
                action={"function": function, "arguments": {}, "target": {}},
            )
            assert denied["status"] == "DENIED"
            assert denied["error"] == "DIRECT_SDK_DISPATCH_DENIED"
    finally:
        lifecycle = worker.stop()
    assert lifecycle.cleaned is True
    assert lifecycle.exit_code == 0


def test_browser_worker_proposal_reaches_facade_and_fake_executor():
    from tests.control.test_phase34_35_dispatch import _auth, _facade, _snapshot

    worker = _worker("browser", BROWSER_PYTHON, BROWSER_SOURCE)
    worker.start()
    try:
        response = worker.request(
            request_id="browser-e2e-1",
            nonce="browser-e2e-nonce",
            observation_id="obs-browser-worker",
            action={
                "function": "browser_proposal",
                "arguments": {"params": {"action": {"click": {"index": 3}}}},
                "target": {"kind": "element", "name": "fixture", "id": "element-3"},
            },
        )
        action = response["proposal"]["arguments"]["params"]["action"]
        facade, executor = _facade()
        snapshot = _snapshot()
        auth = _auth(
            facade,
            action,
            snapshot,
            action_id="browser-e2e-1",
            nonce="browser-e2e-nonce",
        )
        result = facade.dispatch(
            action,
            snapshot,
            action_id="browser-e2e-1",
            authorized=auth,
            verify=lambda *_: True,
        )
        assert result.adapter_result.state is ExecutionState.VERIFIED
        assert executor.calls == 1
    finally:
        lifecycle = worker.stop()
    assert lifecycle.cleaned is True
    assert lifecycle.exit_code == 0


def test_worker_environment_excludes_credentials_and_unrestricted_passthrough():
    environment = safe_worker_environment(
        pythonpath=(str(SRC),),
        extra={"PYTHONUTF8": "1"},
    )
    assert "OPENAI_API_KEY" not in environment
    assert "ANTHROPIC_API_KEY" not in environment
    assert "PYTHONPATH" in environment
    with pytest.raises(ValueError, match="WORKER_ENV_EXTRA_NOT_ALLOWLISTED"):
        safe_worker_environment(extra={"OPENAI_API_KEY": "secret"})


def test_worker_rejects_protocol_schema_and_malformed_frames():
    worker = _worker("stub", Path(sys.executable), ROOT)
    worker.start()
    try:
        version_mismatch = json.dumps(
            {
                "version": 99,
                "kind": "ufo_proposal_request",
                "request_id": "bad-version",
                "session_id": worker.session_id,
                "nonce": "bad-version-nonce",
                "observation_id": "obs",
                "action": {},
            },
            separators=(",", ":"),
        ).encode()
        with pytest.raises(WorkerProcessError, match="RPC_VERSION_UNSUPPORTED"):
            worker._request_raw(
                version_mismatch,
                request_id="bad-version",
                session_id=worker.session_id,
                nonce="bad-version-nonce",
            )
        with pytest.raises(WorkerProcessError, match="RPC_JSON_INVALID"):
            worker._request_raw(
                b"not-json",
                request_id="bad-json",
                session_id=worker.session_id,
                nonce="bad-json-nonce",
            )
        extra = json.loads(
            encode_request(
                request_id="extra",
                session_id=worker.session_id,
                nonce="extra-nonce",
                observation_id="obs",
                action={},
            )
        )
        extra["extra"] = True
        with pytest.raises(WorkerProcessError, match="RPC_REQUEST_KEYS_INVALID"):
            worker._request_raw(
                json.dumps(extra).encode(),
                request_id="extra",
                session_id=worker.session_id,
                nonce="extra-nonce",
            )
    finally:
        lifecycle = worker.stop()
    assert lifecycle.cleaned is True


def test_worker_rejects_replay_duplicate_stale_and_wrong_session():
    worker = _worker("stub", Path(sys.executable), ROOT)
    worker.start()
    try:
        first = _raw_request(
            worker,
            request_id="request-1",
            session_id=worker.session_id,
            nonce="nonce-1",
            function="proposal",
        )
        assert first["status"] == "PROPOSAL"
        duplicate = _raw_request(
            worker,
            request_id="request-1",
            session_id=worker.session_id,
            nonce="nonce-2",
            function="proposal",
        )
        assert duplicate == {
            "version": 1,
            "kind": "ufo_proposal_response",
            "request_id": "request-1",
            "session_id": worker.session_id,
            "nonce": "nonce-2",
            "status": "DENIED",
            "proposal": None,
            "error": "RPC_DUPLICATE_REQUEST",
        }
        replay = _raw_request(
            worker,
            request_id="request-2",
            session_id=worker.session_id,
            nonce="nonce-1",
            function="proposal",
        )
        assert replay["error"] == "RPC_NONCE_REPLAY"
        wrong_session = _raw_request(
            worker,
            request_id="request-3",
            session_id="wrong-session",
            nonce="nonce-3",
            function="proposal",
        )
        assert wrong_session["error"] == "RPC_SESSION_MISMATCH"
        with pytest.raises(WorkerProcessError, match="RPC_REQUEST_ID_MISMATCH"):
            _raw_request(
                worker,
                request_id="request-4",
                session_id=worker.session_id,
                nonce="nonce-4",
                function="__stale__",
            )
    finally:
        lifecycle = worker.stop()
    assert lifecycle.cleaned is True


def test_worker_timeout_is_unknown_outcome_and_forced_cleanup():
    worker = _worker("stub", Path(sys.executable), ROOT)
    worker.start()
    with pytest.raises(WorkerProcessError) as error:
        worker.request(
            request_id="timeout-1",
            nonce="timeout-nonce",
            observation_id="obs",
            action={
                "function": "__sleep__",
                "arguments": {"params": {"seconds": 2}},
                "target": {},
            },
            timeout=0.05,
        )
    assert error.value.reason == "WORKER_TIMEOUT"
    assert error.value.unknown is True
    assert worker.lifecycle.forced_termination is True
    assert worker.lifecycle.cleaned is True
    assert _pid_running(worker.lifecycle.pid) is False
    assert _pid_running(worker.lifecycle.launcher_pid) is False


def test_worker_crash_and_oversized_frame_have_cleanup_evidence():
    worker = _worker("stub", Path(sys.executable), ROOT)
    worker.start()
    with pytest.raises(WorkerProcessError, match="WORKER_EXITED"):
        worker.request(
            request_id="crash-1",
            nonce="crash-nonce",
            observation_id="obs",
            action={"function": "__crash__", "arguments": {}, "target": {}},
        )
    crash_lifecycle = worker.stop()
    assert crash_lifecycle.exit_code == 41
    assert crash_lifecycle.cleaned is True
    assert _pid_running(crash_lifecycle.pid) is False
    assert _pid_running(crash_lifecycle.launcher_pid) is False

    worker = _worker("stub", Path(sys.executable), ROOT)
    worker.start()
    try:
        process = worker._process
        assert process is not None and process.stdin is not None
        process.stdin.write(b"x" * (MAX_RPC_BYTES + 1) + b"\n")
        process.stdin.flush()
        frame = worker._next_frame(2.0)
        assert decode_worker_error(frame)["error"] == "RPC_MESSAGE_TOO_LARGE"
    finally:
        lifecycle = worker.stop()
    assert lifecycle.exit_code == 2
    assert lifecycle.cleaned is True
    assert _pid_running(lifecycle.pid) is False
    assert _pid_running(lifecycle.launcher_pid) is False


def test_worker_version_mismatch_is_fail_closed_and_cleaned():
    worker = WorkerProcess(
        [
            sys.executable,
            "-m",
            "openjarvis.control.proposal_worker",
            "--kind",
            "stub",
            "--session-id",
            "version-session",
            "--protocol-version",
            "99",
        ],
        worker_kind="stub",
        session_id="version-session",
        env=safe_worker_environment(pythonpath=(str(SRC),), home=WORKER_HOME),
        cwd=ROOT,
        startup_timeout=2.0,
    )
    with pytest.raises(
        WorkerProcessError,
        match="WORKER_READY_INVALID:RPC_VERSION_UNSUPPORTED",
    ):
        worker.start()
    assert worker.lifecycle.cleaned is True
