"""Task IPC framing authenticates a fixed worker binding and rejects replay."""

import base64
import hashlib
import hmac
import json
import site
import sys
import time
from pathlib import Path

import pytest

from openjarvis.control.sandbox_launcher import SandboxLauncher, SandboxPolicy
from openjarvis.control.task_worker_ipc import TaskWorkerChannel
from openjarvis.control.worker_process import safe_worker_environment


def _binding():
    return {
        "worker_id": "worker-a",
        "supervisor_id": "supervisor-a",
        "task_id": "task-a",
        "agent_id": "agent-a",
        "principal_id": "principal-a",
        "attempt": "attempt-a",
        "owner_hash": hashlib.sha256(b"owner-test-token").hexdigest(),
        "epoch": 1,
        "checkpoint_version": 2,
        "lease_expires_at": int(time.time()) + 60,
    }


def _request(channel, *, message_id="message-1", deadline=None):
    return channel.seal(
        "EXECUTE_TOOL",
        message_id=message_id,
        request_id="request-1",
        tool_call_id="call-1",
        deadline=deadline or int(time.time()) + 30,
        cancellation="ACTIVE",
        payload={"tool": "fixture"},
    )


def test_roundtrip_and_replay_rejection():
    key, binding = b"k" * 32, _binding()
    host = TaskWorkerChannel(key, binding, role="host")
    worker = TaskWorkerChannel(key, binding, role="worker")
    frame = _request(host)
    request = worker.open(frame)
    assert request["kind"] == "EXECUTE_TOOL"
    response = worker.seal(
        "TOOL_RESULT",
        message_id="result-1",
        request_id="request-1",
        tool_call_id="call-1",
        deadline=request["deadline"],
        cancellation="ACTIVE",
        payload={"result": "ok"},
    )
    assert host.open(response)["payload"] == {"result": "ok"}
    with pytest.raises(PermissionError):
        worker.open(frame)
    with pytest.raises(PermissionError, match="closed"):
        worker.open(b"closed")


@pytest.mark.parametrize(
    "field", ["task_id", "agent_id", "principal_id", "worker_id", "epoch"]
)
def test_cross_binding_and_stale_epoch_are_rejected(field):
    key, binding = b"k" * 32, _binding()
    host = TaskWorkerChannel(key, binding, role="host")
    other = dict(binding)
    other[field] = 2 if field == "epoch" else "different"
    worker = TaskWorkerChannel(key, other, role="worker")
    with pytest.raises(PermissionError):
        worker.open(_request(host))


def test_forgery_ordering_and_repeated_tool_call_fail_closed():
    key, binding = b"k" * 32, _binding()
    host = TaskWorkerChannel(key, binding, role="host")
    wrong_key_worker = TaskWorkerChannel(b"x" * 32, binding, role="worker")
    frame = _request(host)
    with pytest.raises(PermissionError):
        wrong_key_worker.open(frame)
    modified = json.loads(frame)
    modified["body"]["payload"]["tool"] = "forged"
    worker = TaskWorkerChannel(key, binding, role="worker")
    with pytest.raises(PermissionError):
        worker.open(json.dumps(modified).encode())
    worker = TaskWorkerChannel(key, binding, role="worker")
    worker.open(frame)
    rogue = TaskWorkerChannel(key, binding, role="host")
    rogue._sent = 1
    with pytest.raises(PermissionError):
        worker.open(_request(rogue, message_id="message-2"))
    host = TaskWorkerChannel(key, binding, role="host")
    worker = TaskWorkerChannel(key, binding, role="worker")
    _request(host)
    rogue = TaskWorkerChannel(key, binding, role="host")
    rogue._sent = 1
    with pytest.raises(PermissionError):
        worker.open(_request(rogue, message_id="message-2"))


def test_unsolicited_result_is_not_signed():
    worker = TaskWorkerChannel(b"k" * 32, _binding(), role="worker")
    with pytest.raises(ValueError, match="does not match"):
        worker.seal(
            "TOOL_RESULT",
            message_id="m",
            request_id="r",
            tool_call_id="c",
            deadline=int(time.time()) + 30,
            cancellation="ACTIVE",
            payload={},
        )


def test_fractional_lease_and_deadline_are_preserved():
    binding = _binding()
    binding["lease_expires_at"] = time.time() + 60.5
    host = TaskWorkerChannel(b"k" * 32, binding, role="host")
    worker = TaskWorkerChannel(b"k" * 32, binding, role="worker")
    deadline = time.time() + 30.5
    request = worker.open(_request(host, deadline=deadline))
    assert request["deadline"] == deadline
    assert request["binding"]["lease_expires_at"] == binding["lease_expires_at"]


def test_result_must_match_outstanding_call_and_deadline():
    key, binding = b"k" * 32, _binding()
    host = TaskWorkerChannel(key, binding, role="host")
    worker = TaskWorkerChannel(key, binding, role="worker")
    request = worker.open(_request(host))
    with pytest.raises(ValueError, match="does not match"):
        worker.seal(
            "TOOL_RESULT",
            message_id="m",
            request_id="request-1",
            tool_call_id="other-call",
            deadline=request["deadline"],
            cancellation="ACTIVE",
            payload={},
        )
    with pytest.raises(ValueError, match="does not match"):
        worker.seal(
            "TOOL_RESULT",
            message_id="m",
            request_id="request-1",
            tool_call_id="call-1",
            deadline=request["deadline"] + 1,
            cancellation="ACTIVE",
            payload={},
        )


def test_integer_binding_cannot_be_replaced_by_boolean():
    key, binding = b"k" * 32, _binding()
    host = TaskWorkerChannel(key, binding, role="host")
    worker = TaskWorkerChannel(key, binding, role="worker")
    envelope = json.loads(_request(host))
    envelope["body"]["binding"]["epoch"] = True
    canonical = json.dumps(
        envelope["body"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    envelope["mac"] = hmac.new(
        key, b"atlas-task-ipc-v1\0" + canonical, hashlib.sha256
    ).hexdigest()
    with pytest.raises(PermissionError):
        worker.open(json.dumps(envelope).encode())


def test_expired_cancelled_and_oversize_are_denied():
    host = TaskWorkerChannel(b"k" * 32, _binding(), role="host")
    with pytest.raises(ValueError):
        _request(host, deadline=int(time.time()) - 1)
    with pytest.raises(ValueError):
        host.seal(
            "EXECUTE_TOOL",
            message_id="m",
            request_id="r",
            tool_call_id="c",
            deadline=int(time.time()) + 30,
            cancellation="CANCELLED",
            payload={},
        )
    with pytest.raises(ValueError, match="limit"):
        host.seal(
            "EXECUTE_TOOL",
            message_id="m",
            request_id="r",
            tool_call_id="c",
            deadline=int(time.time()) + 30,
            cancellation="ACTIVE",
            payload={"data": "x" * 65536},
        )


def test_frame_roundtrip_across_owned_job_process(tmp_path):
    executable = Path(sys.base_prefix) / "python.exe"
    assert executable.is_file()
    root = Path(__file__).resolve().parents[2]
    key, binding = b"k" * 32, _binding()
    host = TaskWorkerChannel(key, binding, role="host")
    code = (
        "import base64,json,os,sys,time\n"
        "from openjarvis.control.task_worker_ipc import TaskWorkerChannel\n"
        "init=json.loads(sys.stdin.buffer.readline(65537))\n"
        "worker=TaskWorkerChannel(base64.b64decode(init['key']),init['binding'],role='worker')\n"
        "request=worker.open(sys.stdin.buffer.readline(65537).rstrip(b'\\n'))\n"
        "reply=worker.seal('TOOL_RESULT',message_id='result-1',"
        "request_id=request['request_id'],tool_call_id=request['tool_call_id'],"
        "deadline=request['deadline'],cancellation='ACTIVE',payload={'pid':os.getpid()})\n"
        "sys.stdout.buffer.write(reply+b'\\n');sys.stdout.buffer.flush()\n"
    )
    policy = SandboxPolicy("task-ipc-test", "task-ipc-test", str(executable), 1, 15)
    worker = SandboxLauncher(policy).launch(
        [str(executable), "-c", code],
        cwd=tmp_path,
        env=safe_worker_environment(
            pythonpath=(str(root / "src"), *site.getsitepackages()),
            home=tmp_path,
        ),
    )
    try:
        init = json.dumps({"key": base64.b64encode(key).decode(), "binding": binding})
        worker.process.stdin.write(init.encode() + b"\n" + _request(host) + b"\n")
        worker.process.stdin.flush()
        frame = worker.process.stdout.readline(65537).rstrip(b"\n")
        result = host.open(frame)
        assert result["payload"]["pid"] == worker.process.pid
        assert worker.process.wait(timeout=5) == 0
    finally:
        evidence = worker.close()
    assert evidence["job_exit_confirmed"] is True
