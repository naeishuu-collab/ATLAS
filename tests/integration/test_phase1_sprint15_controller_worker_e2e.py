from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tests.agents.fake_engine import FakeEngine

import openjarvis.agents.executor as agent_executor_module
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.orchestrator import OrchestratorAgent
from openjarvis.agents.tool_semantics import arguments_sha256
from openjarvis.control.sandbox_launcher import (
    SandboxedProcess,
    SandboxLauncher,
    SandboxLaunchError,
)
from openjarvis.control.task_worker import (
    TaskWorkerExecutionError,
    TaskWorkerSupervisor,
)
from openjarvis.control.worker_process import (
    WorkerProcess,
    WorkerProcessError,
    safe_worker_environment,
)
from openjarvis.core.events import EventBus
from openjarvis.core.execution import ToolEffect
from openjarvis.core.registry import AgentRegistry, ToolRegistry
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.security.principal import TestPrincipalAuthority
from openjarvis.server import agent_manager_routes
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec
from openjarvis.tools.synthetic_echo import SyntheticEchoTool


class ProbeTool(BaseTool):
    def __init__(self, name: str):
        self.tool_id = name
        self.calls = 0

    @property
    def spec(self):
        return ToolSpec(
            name=self.tool_id,
            description="Test-only dispatch probe.",
            parameters={"type": "object", "properties": {}},
            effect=ToolEffect.READ_ONLY,
        )

    def execute(self, **_params) -> ToolResult:
        self.calls += 1
        raise AssertionError("disallowed tool ran in the Controller")


class ConfiguredProbeTool(ProbeTool):
    def __init__(self):
        super().__init__("task_probe")


def _tool_call(name: str, **arguments):
    return {
        "tool_calls": [
            {
                "id": f"call-{name}-{uuid.uuid4().hex}",
                "name": name,
                "arguments": json.dumps(arguments),
            }
        ]
    }


def _controller(
    tmp_path,
    monkeypatch,
    principal_credential=None,
    *,
    host_bootstrap=None,
    existing_agent_id=None,
    engine_responses: list[dict] | None = None,
):
    monkeypatch.setitem(AgentRegistry._entries(), "orchestrator", OrchestratorAgent)
    monkeypatch.setitem(ToolRegistry._entries(), "synthetic_echo", SyntheticEchoTool)
    if host_bootstrap is not None:
        authority = host_bootstrap.authority
        principal = host_bootstrap.principal
        host_context = host_bootstrap.principal_context
        integrity_key = host_bootstrap.integrity_key
    else:
        authority = TestPrincipalAuthority(b"sprint15-worker-authority")
        if principal_credential is None:
            principal = authority.verify(authority.issue("principal-synthetic"))
        else:
            authority.verify(principal_credential)
            authority._issued[principal_credential.token_id] = (
                principal_credential.principal_id,
                principal_credential.issued_at,
                principal_credential.expires_at,
            )
            principal = authority.verify(principal_credential)
        host_context = SimpleNamespace(
            principal=principal, session_id="session-sprint15"
        )
        integrity_key = b"sprint15-worker-checkpoint-integrity-key"
    manager = AgentManager(
        str(tmp_path / "controller.db"),
        clear_stale_running=host_bootstrap is None,
    )
    engine = FakeEngine(
        engine_responses
        if engine_responses is not None
        else [
            _tool_call("synthetic_echo", value="phase15"),
            {"content": "synthetic worker verified"},
        ]
    )
    bus = EventBus()
    system = SimpleNamespace(
        engine=engine,
        model="fake-model",
        config=None,
        memory_backend=None,
        channel_backend=None,
        tool_executor=None,
        capability_policy=CapabilityPolicy(default_deny=True),
        rate_limiter=None,
        _mcp_clients=[],
        session_store=None,
    )
    app = FastAPI()
    app.state.testing = host_bootstrap is None
    app.state.host_principal_authority = authority
    app.state.task_checkpoint_integrity_key = integrity_key
    if host_bootstrap is not None:
        from openjarvis.control.host_supervisor_broker import HostSupervisorClient

        def supervisor_factory(binding, validate_authority):
            grant = host_bootstrap.issue(binding, validate_authority=validate_authority)
            return HostSupervisorClient(
                grant, binding, validate_authority=validate_authority
            )

        app.state.task_worker_supervisor_factory = supervisor_factory
        app.state.host_supervisor_observer = lambda task_id, agent_id, current: (
            host_bootstrap.observer(task_id, agent_id, current, manager)
        )
    app.state.engine = engine
    app.state.model = "fake-model"
    app.state.config = None
    app.state.bus = bus
    app.state.memory_service = None
    supervisors = []
    original_supervisor = agent_manager_routes.TaskWorkerSupervisor

    def capture_supervisor(*args, **kwargs):
        supervisor = original_supervisor(*args, **kwargs)
        supervisors.append(supervisor)
        return supervisor

    monkeypatch.setattr(
        agent_manager_routes, "TaskWorkerSupervisor", capture_supervisor
    )
    monkeypatch.setattr(
        agent_manager_routes,
        "_make_lightweight_system",
        lambda *_args: system,
    )

    @app.middleware("http")
    async def inject_host_context(request, call_next):
        request.state.host_principal_context = host_context
        return await call_next(request)

    for router in agent_manager_routes.create_agent_manager_router(manager):
        app.include_router(router)
    agent = (
        manager.get_agent(existing_agent_id)
        if existing_agent_id is not None
        else manager.create_agent(
            "sprint15-worker",
            agent_type="orchestrator",
            config={
                "model": "fake-model",
                "tools": ["synthetic_echo"],
                "mcp_tools": False,
            },
        )
    )
    return manager, app, agent, engine, supervisors, authority, principal, integrity_key


def _worker_binding():
    return {
        "worker_id": uuid.uuid4().hex,
        "supervisor_id": uuid.uuid4().hex,
        "task_id": "task-synthetic",
        "agent_id": "agent-synthetic",
        "principal_id": "principal-synthetic",
        "attempt": "attempt-synthetic",
        "owner_hash": "a" * 64,
        "epoch": 1,
        "checkpoint_version": 0,
        "lease_expires_at": time.time() + 120,
    }


def _tool_executor(tool, supervisor):
    executor = ToolExecutor([tool])
    executor._task_worker_dispatch = supervisor.execute_tool
    return executor


def _forbid_thread_fallback(monkeypatch):
    from openjarvis.tools import _stubs

    monkeypatch.setattr(
        _stubs._TOOL_RUNNER,
        "submit",
        lambda *_args, **_kwargs: pytest.fail("task worker fell back to thread pool"),
    )


def test_controller_api_executes_in_authenticated_worker_and_completes(
    tmp_path, monkeypatch
):
    monkeypatch.setitem(ToolRegistry._entries(), "task_probe", ConfiguredProbeTool)
    manager, app, agent, engine, supervisors, authority, principal, key = _controller(
        tmp_path, monkeypatch
    )
    manager.update_agent(
        agent["id"],
        config={
            **agent["config"],
            "tools": ["synthetic_echo", "task_probe"],
            "mcp_tools": True,
        },
    )
    original_resolver = agent_executor_module.resolve_agent_tools
    resolved_task_tools = []

    def capture_task_tools(*args, **kwargs):
        resolved = original_resolver(*args, **kwargs)
        resolved_task_tools.append(
            (kwargs.get("allowed_tool_names"), sorted(resolved.by_name))
        )
        return resolved

    monkeypatch.setattr(
        agent_executor_module, "resolve_agent_tools", capture_task_tools
    )
    _forbid_thread_fallback(monkeypatch)
    try:
        with TestClient(app) as client:
            created = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={
                    "description": "Execute one deterministic synthetic operation.",
                    "required_tools": ["synthetic_echo"],
                    "task_profile": "synthetic_echo_test",
                },
            )
            assert created.status_code == 200, created.text
            task = created.json()
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
            assert response.status_code == 200, response.text
            body = response.json()
            assert body["task"]["status"] == "completed"
            assert body["result"] == "synthetic worker verified"
            assert body["checkpoint_version"] >= 2
            assert resolved_task_tools == [
                (frozenset({"synthetic_echo"}), ["synthetic_echo"])
            ]
            assert (
                body["task"]["completion_evidence"]["tools"][0]["tool_name"]
                == "synthetic_echo"
            )
            assert len(body["task"]["completion_evidence"]["tools"]) == 1
            assert len(supervisors) == 1
            evidence = supervisors[0].evidence
            assert evidence["controller_pid"] == os.getpid()
            assert evidence["worker_pid"] != evidence["controller_pid"]
            assert evidence["tool_execution_pid"] == evidence["worker_pid"]
            assert evidence["worker_instance_id"]
            assert evidence["supervisor_id"]
            assert evidence["ipc_authenticated"] is True
            assert evidence["task_id"] == task["id"]
            assert evidence["agent_id"] == agent["id"]
            assert evidence["principal_id"] == principal.principal_id
            assert evidence["attempt"] == body["task"]["execution_attempt"]
            assert evidence["epoch"] == 1
            assert evidence["checkpoint_version"] == 0
            assert base64_key_not_in_command(supervisors[0])
            assert not os.path.exists(supervisors[0]._home.name)
            assert supervisors[0]._worker.lifecycle.sandbox["job_exit_confirmed"]
            worker_evidence = body["task"]["completion_evidence"]["worker"]
            assert worker_evidence["pid"] == evidence["worker_pid"]
            assert worker_evidence["instance_id"] == evidence["worker_instance_id"]
            assert worker_evidence["job_exit_confirmed"] is True
            assert worker_evidence["exit_code"] == 0

            second = AgentManager(str(tmp_path / "controller.db"))
            try:
                reopened = second._get_task(task["id"], agent_id=agent["id"])
                assert reopened["status"] == "completed"
                assert reopened["checkpoint_id"] == body["checkpoint_id"]
                assert reopened["completion_evidence"]["worker"] == worker_evidence
                journal = second.read_task_tool_journal(
                    task["id"], agent["id"], principal, authority, integrity_key=key
                )
                assert len(journal) == 1
                assert journal[0]["state"] == "CHECKPOINTED"
                assert journal[0]["recovery_state"] == "CHECKPOINTED"
                assert journal[0]["request_id"]
                assert (
                    journal[0]["tool_call_id"]
                    == (engine._responses[0]["tool_calls"][0]["id"])
                )
                assert journal[0]["arguments_sha256"] == arguments_sha256(
                    {"value": "phase15"}
                )
                assert journal[0]["principal_id"] == principal.principal_id
                assert journal[0]["checkpoint_version"] < body["checkpoint_version"]
                assert journal[0]["deadline"] > journal[0]["created_at"]
                assert journal[0]["worker_id"] == evidence["worker_instance_id"]
                assert journal[0]["attempt"] == evidence["attempt"]
                assert journal[0]["epoch"] == evidence["epoch"]
                assert (
                    journal[0]["checkpoint_version"]
                    < journal[0]["checkpointed_version"]
                    <= body["checkpoint_version"]
                )
                assert (
                    journal[0]["result_sha256"]
                    == hashlib.sha256(b"synthetic:phase15").hexdigest()
                )
                checkpoint = second.get_bound_task_checkpoint(
                    task["id"],
                    agent["id"],
                    principal,
                    authority,
                    integrity_key=key,
                )
                tool_messages = [
                    message
                    for message in checkpoint["conversation_state"]["messages"]
                    if message.get("role") == "tool"
                ]
                assert [(item["name"], item["content"]) for item in tool_messages] == [
                    ("synthetic_echo", "synthetic:phase15")
                ]
            finally:
                second.close()
            print(
                "SPRINT15_CONTROLLER_WORKER:",
                json.dumps(
                    {
                        **evidence,
                        "checkpoint_version_final": body["checkpoint_version"],
                        "tool_result": tool_messages[0]["content"],
                        "final_task_state": body["task"]["status"],
                    },
                    sort_keys=True,
                ),
            )
            calls = engine.call_count
            duplicate = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
            assert duplicate.status_code == 409
            assert engine.call_count == calls
    finally:
        manager.close()


def test_task_authority_failure_blocks_dispatch_before_tool_execution():
    tool = ProbeTool("synthetic_echo")
    dispatched = []

    def dispatch(tool_call, params, *, timeout):
        dispatched.append((tool_call.name, params, timeout))
        raise AssertionError("revoked task reached isolated worker dispatch")

    executor = _tool_executor(tool, SimpleNamespace(execute_tool=dispatch))

    def revoked():
        raise PermissionError("synthetic task cancellation")

    executor._task_authority_check = revoked
    result = executor.execute(
        ToolCall("call-revoked", "synthetic_echo", json.dumps({"value": "x"}))
    )

    assert result.success is False
    assert result.metadata["execution"]["state"] == "NOT_STARTED"
    assert dispatched == []
    assert tool.calls == 0


def test_other_task_tools_never_fall_back_to_controller_execution():
    tool = ProbeTool("local_probe")
    dispatched = []

    class IsolatedWorker:
        def execute_tool(self, tool_call, params, *, timeout):
            dispatched.append((tool_call.name, params, timeout))
            raise TaskWorkerExecutionError("TASK_WORKER_TOOL_NOT_ALLOWED")

    executor = _tool_executor(tool, IsolatedWorker())
    result = executor.execute(ToolCall("call-local", "local_probe", "{}"))

    assert result.success is False
    assert len(dispatched) == 1
    assert dispatched[0][0] == "local_probe"
    assert tool.calls == 0


def test_multiple_synthetic_calls_are_checkpointed_in_order(tmp_path, monkeypatch):
    manager, app, agent, engine, supervisors, authority, principal, key = _controller(
        tmp_path, monkeypatch
    )
    engine._responses = [
        _tool_call("synthetic_echo", value="first"),
        _tool_call("synthetic_echo", value="second"),
        {"content": "both calls completed"},
    ]
    _forbid_thread_fallback(monkeypatch)
    try:
        with TestClient(app) as client:
            task = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={
                    "description": "run two distinct synthetic calls",
                    "required_tools": ["synthetic_echo"],
                },
            ).json()
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
        assert response.status_code == 200, response.text
        records = manager.read_task_tool_journal(
            task["id"], agent["id"], principal, authority, integrity_key=key
        )
        assert len(records) == 2
        assert [row["state"] for row in records] == ["CHECKPOINTED", "CHECKPOINTED"]
        assert records[0]["checkpointed_version"] < records[1]["checkpoint_version"]
        assert len({row["request_id"] for row in records}) == 2
        assert all(
            row["worker_id"] == supervisors[0].binding["worker_id"] for row in records
        )
    finally:
        manager.close()


def test_new_task_starts_fresh_after_a_completed_task(tmp_path, monkeypatch):
    manager, app, agent, engine, supervisors, *_rest = _controller(
        tmp_path, monkeypatch
    )
    engine._responses = [
        _tool_call("synthetic_echo", value="first"),
        {"content": "first task completed"},
        _tool_call("synthetic_echo", value="second"),
        {"content": "second task completed"},
    ]
    _forbid_thread_fallback(monkeypatch)
    try:
        with TestClient(app) as client:
            task_ids = []
            for value in ("first", "second"):
                created = client.post(
                    f"/v1/managed-agents/{agent['id']}/tasks",
                    json={
                        "description": f"Execute the {value} synthetic operation.",
                        "required_tools": ["synthetic_echo"],
                    },
                )
                assert created.status_code == 200, created.text
                task = created.json()
                task_ids.append(task["id"])
                response = client.post(
                    f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
                )
                assert response.status_code == 200, response.text
                assert response.json()["task"]["status"] == "completed"

            assert task_ids[0] != task_ids[1]
            assert len(supervisors) == 2
            assert (
                supervisors[0].binding["attempt"] != supervisors[1].binding["attempt"]
            )
            assert engine.call_count == 4
    finally:
        manager.close()


def base64_key_not_in_command(supervisor):
    import base64

    encoded_key = base64.b64encode(supervisor._key).decode("ascii")
    return all(encoded_key not in argument for argument in supervisor._worker.command)


def test_controller_worker_start_failure_fails_closed(tmp_path, monkeypatch):
    manager, app, agent, engine, supervisors, *_rest = _controller(
        tmp_path, monkeypatch
    )
    _forbid_thread_fallback(monkeypatch)

    def fail_launch(*_args, **_kwargs):
        raise SandboxLaunchError("SYNTHETIC_START_FAILURE")

    monkeypatch.setattr(SandboxLauncher, "launch", fail_launch)
    try:
        with TestClient(app) as client:
            task = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={
                    "description": "must fail closed",
                    "required_tools": ["synthetic_echo"],
                },
            ).json()
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
        assert response.status_code == 500
        assert engine.call_count == 0
        assert manager._get_task(task["id"], agent_id=agent["id"])["status"] == "failed"
        assert len(supervisors) == 1
        assert supervisors[0].pid is None
    finally:
        manager.close()


def test_controller_worker_authentication_failure_fails_closed(tmp_path, monkeypatch):
    manager, app, agent, engine, supervisors, *_rest = _controller(
        tmp_path, monkeypatch
    )
    _forbid_thread_fallback(monkeypatch)
    original = TaskWorkerSupervisor._rpc_action

    def corrupt_bootstrap(self, action, **kwargs):
        frame = original(self, action, **kwargs)
        if action.get("op") == "bootstrap":
            envelope = json.loads(frame)
            envelope["mac"] = "0" * 64
            return json.dumps(envelope).encode()
        return frame

    monkeypatch.setattr(TaskWorkerSupervisor, "_rpc_action", corrupt_bootstrap)
    try:
        with TestClient(app) as client:
            task = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={"description": "reject forged IPC authentication"},
            ).json()
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
        assert response.status_code == 500
        assert manager._get_task(task["id"], agent_id=agent["id"])["status"] == "failed"
        assert engine.call_count == 0
        assert supervisors[0]._worker.lifecycle.cleaned
        assert supervisors[0]._worker.lifecycle.sandbox["job_exit_confirmed"]
    finally:
        manager.close()


def test_controller_worker_crash_after_dispatch_records_unknown(tmp_path, monkeypatch):
    manager, app, agent, _engine, supervisors, authority, principal, key = _controller(
        tmp_path, monkeypatch
    )
    _forbid_thread_fallback(monkeypatch)
    original = WorkerProcess._next_frame
    killed = []

    def crash_after_dispatch(self, timeout):
        if self.lifecycle.requests >= 3:
            process = self._process
            killed.append(process.pid)
            process.kill()
            process.wait(timeout=5)
            raise WorkerProcessError("WORKER_EXITED", pid=process.pid, unknown=True)
        return original(self, timeout)

    monkeypatch.setattr(WorkerProcess, "_next_frame", crash_after_dispatch)
    try:
        with TestClient(app) as client:
            task = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={"description": "crash owned synthetic worker"},
            ).json()
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
        assert response.status_code in (409, 500)
        assert killed == [supervisors[0].pid]
        assert manager._get_task(task["id"], agent_id=agent["id"])["status"] == "failed"
        second = AgentManager(manager._db_path)
        try:
            records = second.read_task_tool_journal(
                task["id"], agent["id"], principal, authority, integrity_key=key
            )
            assert len(records) == 1
            assert records[0]["state"] == "UNKNOWN_OUTCOME"
            assert records[0]["recovery_state"] == "UNKNOWN_OUTCOME"
        finally:
            second.close()
    finally:
        manager.close()


def test_controller_rejects_second_synthetic_echo_dispatch(tmp_path, monkeypatch):
    manager, app, agent, engine, supervisors, authority, principal, key = _controller(
        tmp_path,
        monkeypatch,
        engine_responses=[
            _tool_call("synthetic_echo", value="first"),
            _tool_call("synthetic_echo", value="second"),
            {"content": "finished"},
        ],
    )
    _forbid_thread_fallback(monkeypatch)
    try:
        with TestClient(app) as client:
            created = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={
                    "description": "Attempt two deterministic synthetic operations.",
                    "required_tools": ["synthetic_echo"],
                    "task_profile": "synthetic_echo_test",
                },
            )
            assert created.status_code == 200, created.text
            task = created.json()
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )

            assert response.status_code == 409
            failed = manager._get_task(task["id"], agent_id=agent["id"])
            assert failed["status"] == "failed"
            assert len(supervisors) == 1
            journal = manager.read_task_tool_journal(
                task["id"], agent["id"], principal, authority, integrity_key=key
            )
            assert len(journal) == 1
            assert journal[0]["tool_name"] == "synthetic_echo"
            assert journal[0]["arguments_sha256"] == arguments_sha256(
                {"value": "first"}
            )
            assert journal[0]["state"] == "CHECKPOINTED"
    finally:
        manager.close()


def test_real_worker_result_replay_is_denied_by_new_manager_process(
    tmp_path, monkeypatch
):
    manager, app, agent, _engine, supervisors, authority, principal, key = _controller(
        tmp_path, monkeypatch
    )
    _forbid_thread_fallback(monkeypatch)
    original_transition = manager.transition_task_tool_journal
    original_execute = TaskWorkerSupervisor.execute_tool
    executions = []
    observed = []

    def execute(self, *args, **kwargs):
        executions.append(kwargs["request_id"])
        return original_execute(self, *args, **kwargs)

    code = """import json,os,sys,time
from openjarvis.agents.manager import AgentManager
from openjarvis.security.principal import TestPrincipalAuthority
p=json.load(sys.stdin)
a=TestPrincipalAuthority(p['authority'].encode())
principal=a.verify(a.issue(p['principal']))
m=AgentManager(p['db'])
identity=(p['task'],p['agent'],principal,a,p['attempt'],p['token'],p['epoch'])
rows=m.read_task_tool_journal(p['task'],p['agent'],principal,a,integrity_key=p['key'].encode())
try:
 m.prepare_task_tool_journal(*identity,worker_id=p['worker_id'],request_id=p['request_id'],
   tool_call_id=p['tool_call_id'],tool_name='synthetic_echo',
   arguments_sha256=p['arguments_sha256'],deadline=time.time()+30,
   integrity_key=p['key'].encode())
 denied=False
except PermissionError as exc:
 denied='already exists' in str(exc)
print(json.dumps({'pid':os.getpid(),'state':rows[0]['state'],'denied':denied}))
m.close()
"""

    def transition(*args, **kwargs):
        original_transition(*args, **kwargs)
        if kwargs.get("state") != "RESULT_RECORDED":
            return
        rows = manager.read_task_tool_journal(
            args[0], args[1], principal, authority, integrity_key=key
        )
        row = rows[0]
        payload = {
            "db": manager._db_path,
            "task": args[0],
            "agent": args[1],
            "attempt": args[4],
            "token": args[5],
            "epoch": args[6],
            "authority": "sprint15-worker-authority",
            "principal": principal.principal_id,
            "key": key.decode(),
            "worker_id": kwargs["worker_id"],
            "request_id": kwargs["request_id"],
            "tool_call_id": row["tool_call_id"],
            "arguments_sha256": row["arguments_sha256"],
        }
        root = Path(__file__).resolve().parents[2]
        child = subprocess.run(
            [sys.executable, "-c", code],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=20,
            cwd=root,
            env=safe_worker_environment(pythonpath=[str(root / "src")], home=tmp_path),
        )
        if child.returncode != 0:
            raise RuntimeError("journal replay reader failed")
        observed.append(json.loads(child.stdout))

    monkeypatch.setattr(TaskWorkerSupervisor, "execute_tool", execute)
    monkeypatch.setattr(manager, "transition_task_tool_journal", transition)
    try:
        with TestClient(app) as client:
            task = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={"description": "verify duplicate after real worker result"},
            ).json()
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
        assert response.status_code == 200, response.text
        assert response.json()["task"]["status"] == "completed"
        assert len(executions) == 1
        assert len(observed) == 1 and observed[0]["denied"] is True
        assert observed[0]["state"] == "RESULT_RECORDED"
        assert observed[0]["pid"] not in (os.getpid(), supervisors[0].pid)
        print(
            "SPRINT15_JOURNAL_REPLAY:",
            json.dumps(
                {
                    "controller_pid": os.getpid(),
                    "worker_pid": supervisors[0].pid,
                    "reader_pid": observed[0]["pid"],
                    "request_id": executions[0],
                    "denied": observed[0]["denied"],
                    "worker_dispatch_count": len(executions),
                },
                sort_keys=True,
            ),
        )
    finally:
        manager.close()


def test_controller_result_recorded_before_failure_is_not_replayed(
    tmp_path, monkeypatch
):
    manager, app, agent, _engine, _supervisors, authority, principal, key = _controller(
        tmp_path, monkeypatch
    )
    _forbid_thread_fallback(monkeypatch)
    original = manager.transition_task_tool_journal

    def fail_after_result(*args, **kwargs):
        original(*args, **kwargs)
        if kwargs.get("state") == "RESULT_RECORDED":
            raise RuntimeError("injected failure after durable result")

    monkeypatch.setattr(manager, "transition_task_tool_journal", fail_after_result)
    try:
        with TestClient(app) as client:
            task = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={"description": "fail after synthetic result record"},
            ).json()
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
        assert response.status_code in (409, 500)
        assert manager._get_task(task["id"], agent_id=agent["id"])["status"] == "failed"
        second = AgentManager(manager._db_path)
        try:
            records = second.read_task_tool_journal(
                task["id"], agent["id"], principal, authority, integrity_key=key
            )
            assert len(records) == 1
            assert records[0]["state"] == "RESULT_RECORDED"
            assert records[0]["checkpointed_version"] is None
        finally:
            second.close()
    finally:
        manager.close()


def test_controller_rejects_tampered_tool_journal(tmp_path, monkeypatch):
    manager, app, agent, _engine, _supervisors, *_rest = _controller(
        tmp_path, monkeypatch
    )
    _forbid_thread_fallback(monkeypatch)
    original = TaskWorkerSupervisor.close

    def close_and_tamper(self):
        original(self)
        with manager._db_lock:
            manager._conn.execute(
                "UPDATE task_tool_journal SET result_sha256=? WHERE task_id=?",
                ("f" * 64, self.binding["task_id"]),
            )
            manager._conn.commit()

    monkeypatch.setattr(TaskWorkerSupervisor, "close", close_and_tamper)
    try:
        with TestClient(app) as client:
            task = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={"description": "reject tampered synthetic journal"},
            ).json()
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
        assert response.status_code == 409
        assert "journal integrity" in response.text
        assert manager._get_task(task["id"], agent_id=agent["id"])["status"] == "failed"
    finally:
        manager.close()


def test_controller_rejects_unconfirmed_job_exit(tmp_path, monkeypatch):
    manager, app, agent, engine, supervisors, *_rest = _controller(
        tmp_path, monkeypatch
    )
    _forbid_thread_fallback(monkeypatch)
    original = SandboxedProcess.close

    def unconfirmed(self):
        evidence = original(self)
        evidence["job_exit_confirmed"] = False
        return evidence

    monkeypatch.setattr(SandboxedProcess, "close", unconfirmed)
    try:
        with TestClient(app) as client:
            task = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={"description": "reject unconfirmed worker exit"},
            ).json()
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
        assert response.status_code == 500
        assert manager._get_task(task["id"], agent_id=agent["id"])["status"] == "failed"
        assert engine.call_count >= 2
        assert supervisors[0]._worker.lifecycle.cleaned
    finally:
        manager.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("task_id", "other-task"),
        ("epoch", 2),
        ("epoch", True),
        ("job_exit_confirmed", False),
        ("process_wait_confirmed", False),
        ("exit_observed_at", None),
    ],
)
def test_controller_rejects_mismatched_worker_exit_evidence(
    tmp_path, monkeypatch, field, value
):
    manager, app, agent, _engine, _supervisors, *_rest = _controller(
        tmp_path, monkeypatch
    )
    _forbid_thread_fallback(monkeypatch)
    original = TaskWorkerSupervisor.evidence.fget
    monkeypatch.setattr(
        TaskWorkerSupervisor,
        "evidence",
        property(lambda self: {**original(self), field: value}),
    )
    try:
        with TestClient(app) as client:
            task = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks",
                json={"description": "reject mismatched worker exit evidence"},
            ).json()
            response = client.post(
                f"/v1/managed-agents/{agent['id']}/tasks/{task['id']}/run"
            )
        assert response.status_code == 409
        assert "worker exit evidence invalid" in response.text
        assert manager._get_task(task["id"], agent_id=agent["id"])["status"] == "failed"
    finally:
        manager.close()


@pytest.mark.parametrize("name", ["browser_navigate", "windows_action", "http_request"])
def test_browser_windows_and_external_tools_are_rejected_without_fallback(
    name, monkeypatch
):
    supervisor = TaskWorkerSupervisor(
        _worker_binding(), validate_authority=lambda: None
    )
    _forbid_thread_fallback(monkeypatch)
    try:
        supervisor.start()
        tool = ProbeTool(name)
        result = _tool_executor(tool, supervisor).execute(
            ToolCall(id=f"call-{name}", name=name, arguments="{}")
        )
        assert result.success is False
        assert result.metadata["execution"]["state"] == "NOT_STARTED"
        assert "TASK_WORKER_TOOL_NOT_ALLOWED" in result.content
        assert tool.calls == 0
    finally:
        supervisor.close()


def test_worker_timeout_is_unknown_and_does_not_fall_back(monkeypatch):
    supervisor = TaskWorkerSupervisor(
        _worker_binding(), validate_authority=lambda: None
    )
    _forbid_thread_fallback(monkeypatch)
    original = WorkerProcess._next_frame

    def timeout_after_tool_request(self, timeout):
        if self.lifecycle.requests >= 3:
            self.stop(force=True)
            raise WorkerProcessError("WORKER_TIMEOUT", pid=self.pid, unknown=True)
        return original(self, timeout)

    try:
        supervisor.start()
        monkeypatch.setattr(WorkerProcess, "_next_frame", timeout_after_tool_request)
        tool = SyntheticEchoTool()
        result = _tool_executor(tool, supervisor).execute(
            ToolCall(
                id="call-timeout",
                name="synthetic_echo",
                arguments=json.dumps({"value": "unknown"}),
            )
        )
        assert result.success is False
        assert result.metadata["execution"]["state"] == "UNKNOWN_OUTCOME", (
            result.content
        )
        assert "UNKNOWN_OUTCOME" in result.content
        assert tool.calls == 0
    finally:
        supervisor.close()


def test_worker_abnormal_exit_is_detected_without_fallback(monkeypatch):
    supervisor = TaskWorkerSupervisor(
        _worker_binding(), validate_authority=lambda: None
    )
    _forbid_thread_fallback(monkeypatch)
    try:
        supervisor.start()
        process = supervisor._worker._process
        process.kill()
        process.wait(timeout=5)
        tool = SyntheticEchoTool()
        result = _tool_executor(tool, supervisor).execute(
            ToolCall(
                id="call-exit",
                name="synthetic_echo",
                arguments=json.dumps({"value": "exit"}),
            )
        )
        assert result.success is False
        assert result.metadata["execution"]["state"] == "NOT_STARTED"
        assert "TASK_WORKER_NOT_READY" in result.content
        assert tool.calls == 0
    finally:
        supervisor.close()


def test_cancellation_during_worker_request_is_unknown_and_fail_closed(monkeypatch):
    cancelled = threading.Event()
    waiting = threading.Event()
    release = threading.Event()

    def validate_authority():
        if cancelled.is_set():
            raise PermissionError("cancelled")

    supervisor = TaskWorkerSupervisor(
        _worker_binding(), validate_authority=validate_authority
    )
    _forbid_thread_fallback(monkeypatch)
    original = WorkerProcess._next_frame
    result_holder = {}

    def pause_request(self, timeout):
        if self.lifecycle.requests >= 3:
            waiting.set()
            if not release.wait(5):
                raise TimeoutError("test did not release worker request")
        return original(self, timeout)

    try:
        supervisor.start()
        monkeypatch.setattr(WorkerProcess, "_next_frame", pause_request)
        tool = SyntheticEchoTool()
        executor = _tool_executor(tool, supervisor)
        thread = threading.Thread(
            target=lambda: result_holder.setdefault(
                "result",
                executor.execute(
                    ToolCall(
                        id="call-cancel",
                        name="synthetic_echo",
                        arguments=json.dumps({"value": "cancel"}),
                    )
                ),
            ),
        )
        thread.start()
        assert waiting.wait(5)
        cancelled.set()
        release.set()
        thread.join(timeout=5)
        assert not thread.is_alive()
        result = result_holder["result"]
        assert result.success is False
        assert result.metadata["execution"]["state"] == "UNKNOWN_OUTCOME", (
            result.content
        )
        assert "UNKNOWN_OUTCOME" in result.content
        assert tool.calls == 0
    finally:
        release.set()
        supervisor.close()
