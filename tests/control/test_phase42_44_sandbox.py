"""Phase 42-44 local Job Object PoC and opt-in worker integration."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from openjarvis.control import (
    AdapterMode,
    ControlSurface,
    SafeEngineAdapter,
    SandboxLauncher,
    SandboxLaunchError,
    SandboxPolicy,
    UfoProposalAdapter,
    WorkerProcess,
    WorkerProcessError,
    make_authorized_action,
    new_run_id,
    safe_worker_environment,
)
from openjarvis.core.execution import ExecutionState, MutationIntent

ROOT = Path(__file__).resolve().parents[2]
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
    r"C:\Users\yingz\.codex\isolated\atlas-phase42-44-20261028\worker-home"
)
KEY = b"phase42-44-test-only-key"
requires_windows = pytest.mark.skipif(
    os.name != "nt", reason="Windows Job Object PoC requires Windows"
)


def _policy(kind: str, executable: Path, *, max_runtime: float = 5.0):
    return SandboxPolicy(
        worker_kind=kind,
        run_id=new_run_id(kind),
        executable=str(executable),
        max_processes=2,
        max_runtime=max_runtime,
    )


def _child(policy: SandboxPolicy, code: str):
    return SandboxLauncher(policy).launch(
        [policy.executable, "-I", "-c", code],
        cwd=ROOT,
        env=safe_worker_environment(home=WORKER_HOME),
    )


def _sandbox_worker(
    kind: str, python: Path, source: Path, *, session: str | None = None
) -> WorkerProcess:
    session = session or f"phase42-44-{kind}"
    WORKER_HOME.mkdir(parents=True, exist_ok=True)
    return WorkerProcess(
        [
            str(python),
            "-m",
            "openjarvis.control.proposal_worker",
            "--kind",
            kind,
            "--session-id",
            session,
            "--inspect",
        ],
        worker_kind=kind,
        session_id=session,
        env=safe_worker_environment(
            pythonpath=(str(ROOT / "src"), str(source)),
            home=WORKER_HOME,
        ),
        cwd=source,
        startup_timeout=8.0,
        request_timeout=2.0,
        sandbox=SandboxPolicy(
            worker_kind=kind,
            run_id=new_run_id(kind),
            executable=str(python),
            max_processes=2,
            max_runtime=20.0,
        ),
    )


@requires_windows
def test_job_object_startup_membership_limits_and_cleanup():
    child = _child(
        _policy("fixture", Path(sys.executable)),
        "import time; print('SANDBOX_READY', flush=True); time.sleep(30)",
    )
    try:
        line = child.process.stdout.readline().decode("utf-8").strip()
        assert line == "SANDBOX_READY"
        evidence = child.evidence()
        assert evidence["job_object"] is True
        assert evidence["process_in_job"] is True
        assert evidence["job_limits"]["active_process_limit"] == 2
        assert evidence["job_limits"]["limit_flags"] & 0x2008 == 0x2008
    finally:
        evidence = child.close()
    assert child.process.poll() is not None
    assert evidence["closed"] is True


@requires_windows
def test_job_object_rejects_unauthorized_child_creation():
    child = _child(
        _policy("fixture", Path(sys.executable)),
        "import subprocess,sys\n"
        "try:\n"
        " subprocess.Popen([sys.executable,'-I','-c','print(1)'])\n"
        " print('CHILD_ALLOWED')\n"
        "except OSError as exc:\n"
        " print('CHILD_DENIED', getattr(exc,'winerror',None))\n"
        "sys.stdout.flush()",
    )
    try:
        output, _ = child.process.communicate(timeout=5)
    finally:
        child.close()
    assert b"CHILD_DENIED" in output
    assert b"CHILD_ALLOWED" not in output


@requires_windows
def test_job_object_runtime_timeout_is_terminal():
    child = _child(
        _policy("fixture", Path(sys.executable), max_runtime=0.25),
        "import time; time.sleep(10)",
    )
    try:
        child.process.wait(timeout=3)
    finally:
        evidence = child.close()
    assert child.timed_out is True
    assert child.forced_termination is True
    assert evidence["closed"] is True


@requires_windows
def test_sandbox_launcher_rejects_non_allowlisted_executable_without_fallback():
    policy = _policy("fixture", Path(sys.executable))
    with pytest.raises(SandboxLaunchError, match="EXECUTABLE_NOT_ALLOWLISTED"):
        SandboxLauncher(policy).launch(
            [str(Path(sys.executable).with_name("not-an-approved-python.exe"))],
            cwd=ROOT,
            env=safe_worker_environment(home=WORKER_HOME),
        )


@pytest.mark.parametrize(
    ("kind", "python", "source"),
    [
        ("ufo", UFO_PYTHON, UFO_SOURCE),
        ("browser", BROWSER_PYTHON, BROWSER_SOURCE),
    ],
)
@requires_windows
def test_real_worker_opt_in_job_boundary(kind: str, python: Path, source: Path):
    assert python.is_file()
    assert source.is_dir()
    worker = _sandbox_worker(kind, python, source)
    try:
        ready = worker.start()
        assert ready["kind"] == "atlas_worker_ready"
        assert worker.lifecycle.sandbox["process_in_job"] is True
        action = {
            "function": (
                "type" if kind == "ufo" else "browser_proposal"
            ),
            "arguments": {"params": {"text": "fixture"}},
            "target": {"kind": "fixture", "id": "target-1"},
        }
        response = worker.request(
            request_id=f"{kind}-sandbox-request",
            nonce=f"{kind}-sandbox-nonce",
            observation_id=f"obs-{kind}",
            action=action,
        )
        assert response["status"] == "PROPOSAL"
    finally:
        lifecycle = worker.stop()
    assert lifecycle.cleaned is True
    assert lifecycle.sandbox["closed"] is True


@requires_windows
def test_sandboxed_ufo_worker_reaches_safety_authority_once():
    from tests.control.test_phase39_41_workers import (
        _FakeExecutor,
        _ufo_action,
        _ufo_snapshot,
    )

    worker = _sandbox_worker(
        "ufo", UFO_PYTHON, UFO_SOURCE, session="phase39-41-ufo"
    )
    worker.start()
    try:
        response = worker.request(
            request_id="ufo-sandbox-e2e",
            nonce="ufo-sandbox-e2e-nonce",
            observation_id="obs-ufo-worker",
            action=_ufo_action(),
        )
        proposal = UfoProposalAdapter(session_id=worker.session_id).propose(
            response["proposal"], _ufo_snapshot(), action_id="ufo-sandbox-e2e"
        )
        executor = _FakeExecutor()
        host = SafeEngineAdapter(
            executor,
            surface=ControlSurface.WINDOWS_APP,
            mode=AdapterMode.ENFORCE,
            session_id=worker.session_id,
            seal_key=KEY,
        )
        authorized = make_authorized_action(
            proposal,
            MutationIntent("sandbox-ufo", "step-ufo", "intent-ufo"),
            session_id=worker.session_id,
            nonce="ufo-sandbox-e2e-nonce",
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
    assert lifecycle.sandbox["process_in_job"] is True


@requires_windows
def test_sandboxed_browser_worker_reaches_dispatch_facade_once():
    from tests.control.test_phase34_35_dispatch import _auth, _facade, _snapshot

    worker = _sandbox_worker("browser", BROWSER_PYTHON, BROWSER_SOURCE)
    worker.start()
    try:
        response = worker.request(
            request_id="browser-sandbox-e2e",
            nonce="browser-sandbox-e2e-nonce",
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
        authorized = _auth(
            facade,
            action,
            snapshot,
            action_id="browser-sandbox-e2e",
            nonce="browser-sandbox-e2e-nonce",
        )
        result = facade.dispatch(
            action,
            snapshot,
            action_id="browser-sandbox-e2e",
            authorized=authorized,
            verify=lambda *_: True,
        )
        assert result.adapter_result.state is ExecutionState.VERIFIED
        assert executor.calls == 1
    finally:
        lifecycle = worker.stop()
    assert lifecycle.sandbox["process_in_job"] is True


@requires_windows
def test_worker_sandbox_launch_failure_does_not_fallback():
    worker = WorkerProcess(
        [sys.executable, "-c", "print('must-not-run')"],
        worker_kind="stub",
        session_id="phase42-44-failure",
        env=safe_worker_environment(home=WORKER_HOME),
        cwd=ROOT,
        sandbox=SandboxPolicy(
            worker_kind="stub",
            run_id=new_run_id("stub"),
            executable=str(Path(sys.executable).with_name("not-approved.exe")),
        ),
    )
    with pytest.raises(WorkerProcessError, match="SANDBOX_LAUNCH_FAILED"):
        worker.start()
    assert worker.lifecycle.started is False
    assert worker.lifecycle.cleaned is True
