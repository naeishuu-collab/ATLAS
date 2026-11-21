"""Task journal remains fail-closed across SQLite connections and restarts."""

import hashlib
import hmac
import json
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from openjarvis.agents.manager import AgentManager
from openjarvis.control.worker_process import safe_worker_environment
from openjarvis.security.principal import TestPrincipalAuthority

KEY = b"synthetic-task-journal-integrity-key"
TOKEN = "t" * 32


def _task(manager, authority, principal, name="agent"):
    agent = manager.create_agent(name)
    task = manager.create_task(agent["id"], "synthetic journal")
    started = manager.start_task(
        task["id"], agent["id"], principal.principal_id, None, worker_token=TOKEN
    )
    identity = (
        task["id"],
        agent["id"],
        principal,
        authority,
        started["execution_attempt"],
        TOKEN,
        1,
    )
    manager.initialize_task_tool_journal(*identity, integrity_key=KEY)
    checkpoint = manager.save_checkpoint(
        agent["id"],
        "tick",
        {"task_id": task["id"], "messages": []},
        {"execution_id": started["execution_attempt"], "worker_epoch": 1},
    )
    manager.bind_task_checkpoint(
        task["id"],
        agent["id"],
        principal,
        authority,
        checkpoint["id"],
        started["execution_attempt"],
        integrity_key=KEY,
        worker_token=TOKEN,
        worker_epoch=1,
    )
    return identity, checkpoint


def _prepare(manager, identity, *, request="request-1", call="call-1", digest=None):
    return manager.prepare_task_tool_journal(
        *identity,
        worker_id="worker-1",
        request_id=request,
        tool_call_id=call,
        tool_name="synthetic_echo",
        arguments_sha256=digest or "a" * 64,
        deadline=time.time() + 60,
        integrity_key=KEY,
    )


def _transition(manager, identity, expected, state, **kwargs):
    manager.transition_task_tool_journal(
        *identity,
        worker_id="worker-1",
        request_id="request-1",
        expected=expected,
        state=state,
        integrity_key=KEY,
        **kwargs,
    )


def _read(manager, identity):
    return manager.read_task_tool_journal(
        identity[0], identity[1], identity[2], identity[3], integrity_key=KEY
    )


def _record_signed_exit(manager, identity):
    authority_binding = manager.task_authority_binding(*identity)
    task = manager._get_task(identity[0], agent_id=identity[1])
    binding = {
        "worker_id": "worker-1",
        "supervisor_id": "supervisor-1",
        "task_id": identity[0],
        "agent_id": identity[1],
        "principal_id": identity[2].principal_id,
        "attempt": identity[4],
        "owner_hash": authority_binding["owner_hash"],
        "epoch": authority_binding["epoch"],
        "checkpoint_version": task["checkpoint_version"],
        "lease_expires_at": authority_binding["lease_expires_at"],
    }
    evidence = {
        "controller_pid": 1,
        "worker_pid": 2,
        "worker_instance_id": binding["worker_id"],
        "supervisor_id": binding["supervisor_id"],
        "task_id": binding["task_id"],
        "agent_id": binding["agent_id"],
        "principal_id": binding["principal_id"],
        "attempt": binding["attempt"],
        "epoch": binding["epoch"],
        "job_exit_confirmed": True,
        "process_wait_confirmed": True,
        "worker_exit_code": 0,
        "worker_forced_termination": False,
        "exit_observed_at": time.time(),
    }
    record = {
        "version": 1,
        "sequence": 1,
        "binding": binding,
        "supervisor_pid": 1,
        "supervisor_creation_time": 1,
        "worker_creation_time": 2,
        "job_id": "a" * 32,
        "evidence": evidence,
    }
    verification_key = b"synthetic-supervisor-exit-verification-key"
    signed = {
        "record": record,
        "mac": hmac.new(
            verification_key,
            b"atlas-supervisor-exit-v1\0"
            + json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii"),
            hashlib.sha256,
        ).hexdigest(),
    }
    manager.record_host_worker_exit(
        identity[2],
        identity[3],
        binding,
        signed,
        verification_key,
        integrity_key=KEY,
        verify_os_exit=lambda _evidence: True,
    )
    return binding, signed, verification_key


@pytest.fixture
def journal(tmp_path):
    manager = AgentManager(str(tmp_path / "task.db"))
    authority = TestPrincipalAuthority(b"synthetic-journal-authority")
    principal = authority.verify(authority.issue("owner"))
    identity, checkpoint = _task(manager, authority, principal)
    try:
        yield manager, identity, checkpoint
    finally:
        manager.close()


def test_journal_survives_reopen_and_refuses_replay(journal):
    manager, identity, _ = journal
    assert manager._conn.execute("PRAGMA synchronous").fetchone()[0] == 2
    assert _prepare(manager, identity) == 1
    second = AgentManager(manager._db_path)
    try:
        assert _read(second, identity)[0]["state"] == "PREPARED"
        for request, call, digest in (
            ("request-1", "call-1", "a" * 64),
            ("request-1", "other-call", "b" * 64),
            ("other-request", "call-1", "b" * 64),
        ):
            with pytest.raises(PermissionError, match="already exists"):
                _prepare(second, identity, request=request, call=call, digest=digest)
        _transition(second, identity, "PREPARED", "DISPATCHED")
    finally:
        second.close()
    reopened = AgentManager(manager._db_path)
    try:
        row = _read(reopened, identity)[0]
        assert row["state"] == "DISPATCHED"
        assert row["recovery_state"] == "UNKNOWN_OUTCOME"
        result_hash = hashlib.sha256(b"synthetic:result").hexdigest()
        _transition(
            reopened,
            identity,
            "DISPATCHED",
            "RESULT_RECORDED",
            result_sha256=result_hash,
            result_success=True,
        )
        assert _read(manager, identity)[0]["result_sha256"] == result_hash
        with pytest.raises(PermissionError):
            _transition(
                reopened,
                identity,
                "DISPATCHED",
                "RESULT_RECORDED",
                result_sha256=result_hash,
                result_success=True,
            )
    finally:
        reopened.close()


def test_new_process_reloads_dispatched_request_and_rejects_replay(tmp_path):
    db = str(tmp_path / "restart.db")
    first = AgentManager(db)
    authority = TestPrincipalAuthority(b"synthetic-journal-authority")
    principal = authority.verify(authority.issue("owner"))
    identity, _ = _task(first, authority, principal)
    _prepare(first, identity)
    _transition(first, identity, "PREPARED", "DISPATCHED")
    first.close()
    code = """import json,sys,time
from openjarvis.agents.manager import AgentManager
from openjarvis.security.principal import TestPrincipalAuthority
p=json.load(sys.stdin)
a=TestPrincipalAuthority(p['authority'].encode()); principal=a.verify(a.issue('owner'))
m=AgentManager(p['db'])
identity=(p['task'],p['agent'],principal,a,p['attempt'],p['token'],1)
rows=m.read_task_tool_journal(p['task'],p['agent'],principal,a,integrity_key=p['key'].encode())
try:
 m.prepare_task_tool_journal(*identity,worker_id='worker-1',request_id='request-1',tool_call_id='call-1',tool_name='synthetic_echo',arguments_sha256='a'*64,deadline=time.time()+30,integrity_key=p['key'].encode())
 denied=False
except PermissionError:
 denied=True
print(json.dumps({'state':rows[0]['state'],'recovery':rows[0]['recovery_state'],'denied':denied}))
m.close()
"""
    inputs = {
        "db": db,
        "task": identity[0],
        "agent": identity[1],
        "attempt": identity[4],
        "token": TOKEN,
        "key": KEY.decode(),
        "authority": "synthetic-journal-authority",
    }
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "-c", code],
        input=json.dumps(inputs),
        text=True,
        capture_output=True,
        timeout=20,
        cwd=root,
        env=safe_worker_environment(pythonpath=[str(root / "src")], home=tmp_path),
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "state": "DISPATCHED",
        "recovery": "UNKNOWN_OUTCOME",
        "denied": True,
    }


@pytest.mark.parametrize("mutation", ["row", "delete-row", "head", "delete-head"])
def test_journal_tampering_is_rejected(journal, mutation):
    manager, identity, _ = journal
    _prepare(manager, identity)
    if mutation == "row":
        manager._conn.execute(
            "UPDATE task_tool_journal SET arguments_sha256=?", ("b" * 64,)
        )
    elif mutation == "delete-row":
        manager._conn.execute("DELETE FROM task_tool_journal")
    elif mutation == "head":
        manager._conn.execute("UPDATE task_tool_journal_heads SET entry_count=0")
    else:
        manager._conn.execute("DELETE FROM task_tool_journal_heads")
    manager._conn.commit()
    with pytest.raises(PermissionError, match="journal"):
        _read(manager, identity)
    with pytest.raises(PermissionError, match="journal"):
        _prepare(manager, identity, request="request-2", call="call-2")


def test_concurrent_duplicate_has_only_one_reservation(journal):
    first, identity, _ = journal
    second = AgentManager(first._db_path)
    barrier = threading.Barrier(2)

    def reserve(manager):
        barrier.wait(timeout=5)
        try:
            _prepare(manager, identity)
            return True
        except PermissionError:
            return False

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(reserve, (first, second)))
        assert sorted(outcomes) == [False, True]
        assert len(_read(first, identity)) == 1
    finally:
        second.close()


def test_cross_task_call_id_and_forged_authority_are_denied(journal):
    manager, identity, _ = journal
    _prepare(manager, identity)
    other, _ = _task(manager, identity[3], identity[2], "other")
    with pytest.raises(PermissionError, match="already exists"):
        _prepare(manager, other, request="request-2", call="call-1")
    for invalid in (
        (*identity[:5], "wrong" * 8, 1),
        (*identity[:6], 2),
        (*identity[:4], "stale-attempt", *identity[5:]),
        ("wrong-task", *identity[1:]),
        (identity[0], "wrong-agent", *identity[2:]),
        (
            identity[0],
            identity[1],
            identity[3].verify(identity[3].issue("other")),
            *identity[3:],
        ),
    ):
        with pytest.raises(PermissionError):
            _prepare(manager, invalid, request="new-request", call="new-call")


def test_expired_lease_and_tampered_checkpoint_block_dispatch(journal):
    manager, identity, checkpoint = journal
    manager._conn.execute(
        "UPDATE agent_checkpoints SET conversation_state=? WHERE id=?",
        ('{"tampered":true}', checkpoint["id"]),
    )
    manager._conn.commit()
    with pytest.raises(PermissionError, match="integrity"):
        _prepare(manager, identity)
    manager._conn.execute(
        "UPDATE agent_task_authority SET expires_at=? WHERE task_id=?",
        (time.time() - 1, identity[0]),
    )
    manager._conn.commit()
    with pytest.raises(PermissionError, match="expired"):
        _prepare(manager, identity)


def test_checkpoint_advance_blocks_prepared_dispatch(journal):
    manager, identity, _ = journal
    _prepare(manager, identity)
    checkpoint = manager.save_checkpoint(
        identity[1],
        "next",
        {"task_id": identity[0], "messages": []},
        {"execution_id": identity[4], "worker_epoch": 1},
    )
    manager.bind_task_checkpoint(
        identity[0],
        identity[1],
        identity[2],
        identity[3],
        checkpoint["id"],
        identity[4],
        integrity_key=KEY,
        worker_token=TOKEN,
        worker_epoch=1,
        expected_version=1,
    )
    with pytest.raises(PermissionError, match="checkpoint is stale"):
        _transition(manager, identity, "PREPARED", "DISPATCHED")
    assert _read(manager, identity)[0]["state"] == "PREPARED"


def test_revoked_principal_cannot_read_or_dispatch(journal):
    manager, identity, _ = journal
    _prepare(manager, identity)
    identity[3].revoke(identity[2])
    with pytest.raises(PermissionError):
        _transition(manager, identity, "PREPARED", "DISPATCHED")
    with pytest.raises(PermissionError):
        _read(manager, identity)


def test_epoch_fence_revokes_old_dispatch_and_preserves_journal(journal):
    manager, identity, _ = journal
    _prepare(manager, identity)
    _transition(manager, identity, "PREPARED", "DISPATCHED")
    result_hash = hashlib.sha256(b"synthetic:result").hexdigest()
    _transition(
        manager,
        identity,
        "DISPATCHED",
        "RESULT_RECORDED",
        result_sha256=result_hash,
        result_success=True,
    )
    checkpoint = manager.save_checkpoint(
        identity[1],
        "tool-result",
        {
            "task_id": identity[0],
            "messages": [
                {
                    "role": "tool",
                    "name": "synthetic_echo",
                    "tool_call_id": "call-1",
                    "content": "synthetic:result",
                }
            ],
        },
        {
            "execution_id": identity[4],
            "worker_epoch": 1,
            "completed_steps": [
                {
                    "call_id": "call-1",
                    "tool": "synthetic_echo",
                    "state": "EXECUTED",
                    "execution_state": "EXECUTED",
                }
            ],
        },
    )
    manager.bind_task_checkpoint(
        identity[0],
        identity[1],
        identity[2],
        identity[3],
        checkpoint["id"],
        identity[4],
        integrity_key=KEY,
        worker_token=TOKEN,
        worker_epoch=1,
        expected_version=1,
    )
    manager.checkpoint_task_tool_journal(
        *identity,
        worker_id="worker-1",
        request_id="request-1",
        integrity_key=KEY,
    )
    binding, signed, verification_key = _record_signed_exit(manager, identity)

    assert (
        manager.fence_task_authority_after_worker_exit(
            identity[2],
            identity[3],
            binding,
            signed,
            verification_key,
            integrity_key=KEY,
        )
        == 2
    )
    assert _read(manager, identity)[0]["state"] == "CHECKPOINTED"
    with pytest.raises(PermissionError):
        manager.validate_task_authority(
            identity[0],
            identity[1],
            identity[2],
            identity[3],
            identity[4],
            TOKEN,
            1,
        )
    with pytest.raises(PermissionError):
        manager.claim_task_tool_dispatch(
            identity[2],
            identity[3],
            binding,
            {
                "kind": "EXECUTE_TOOL",
                "binding": binding,
                "request_id": "request-1",
                "tool_call_id": "call-1",
                "payload": {"name": "synthetic_echo", "params": {"value": "phase15"}},
            },
            integrity_key=KEY,
        )
    assert (
        manager._conn.execute(
            "SELECT COUNT(*) FROM task_tool_dispatch_claims WHERE task_id=?",
            (identity[0],),
        ).fetchone()[0]
        == 0
    )


def test_epoch_fence_refuses_unknown_outcome(journal):
    manager, identity, _ = journal
    _prepare(manager, identity)
    _transition(manager, identity, "PREPARED", "DISPATCHED")
    _transition(manager, identity, "DISPATCHED", "UNKNOWN_OUTCOME")
    binding, signed, verification_key = _record_signed_exit(manager, identity)

    with pytest.raises(PermissionError, match="journal or checkpoint unresolved"):
        manager.fence_task_authority_after_worker_exit(
            identity[2],
            identity[3],
            binding,
            signed,
            verification_key,
            integrity_key=KEY,
        )
    authority_row = manager._conn.execute(
        "SELECT epoch,state FROM agent_task_authority WHERE task_id=?",
        (identity[0],),
    ).fetchone()
    assert tuple(authority_row) == (1, "ACTIVE")
    assert _read(manager, identity)[0]["recovery_state"] == "UNKNOWN_OUTCOME"


@pytest.mark.parametrize(
    "state", ["PREPARED", "DISPATCHED", "RESULT_RECORDED", "UNKNOWN_OUTCOME"]
)
def test_unresolved_record_blocks_a_new_request(journal, state):
    manager, identity, _ = journal
    _prepare(manager, identity)
    if state != "PREPARED":
        _transition(manager, identity, "PREPARED", "DISPATCHED")
    if state == "RESULT_RECORDED":
        _transition(
            manager,
            identity,
            "DISPATCHED",
            state,
            result_sha256="b" * 64,
            result_success=True,
        )
    elif state == "UNKNOWN_OUTCOME":
        _transition(manager, identity, "DISPATCHED", state)
    with pytest.raises(PermissionError, match="requires reconciliation"):
        _prepare(manager, identity, request="new-request", call="new-call")


def test_result_needs_matching_signed_checkpoint_before_new_dispatch(journal):
    manager, identity, _ = journal
    _prepare(manager, identity)
    _transition(manager, identity, "PREPARED", "DISPATCHED")
    result_hash = hashlib.sha256(b"synthetic:result").hexdigest()
    _transition(
        manager,
        identity,
        "DISPATCHED",
        "RESULT_RECORDED",
        result_sha256=result_hash,
        result_success=True,
    )
    step = {
        "call_id": "call-1",
        "tool": "synthetic_echo",
        "state": "EXECUTED",
        "execution_state": "EXECUTED",
    }
    for version, content in ((2, "wrong"), (3, "synthetic:result")):
        checkpoint = manager.save_checkpoint(
            identity[1],
            f"tick-{version}",
            {
                "task_id": identity[0],
                "messages": [
                    {
                        "role": "tool",
                        "name": "synthetic_echo",
                        "tool_call_id": "call-1",
                        "content": content,
                    }
                ],
            },
            {"execution_id": identity[4], "worker_epoch": 1, "completed_steps": [step]},
        )
        manager.bind_task_checkpoint(
            identity[0],
            identity[1],
            identity[2],
            identity[3],
            checkpoint["id"],
            identity[4],
            integrity_key=KEY,
            worker_token=TOKEN,
            worker_epoch=1,
            expected_version=version - 1,
        )
        if version == 2:
            with pytest.raises(PermissionError, match="checkpoint mismatch"):
                manager.checkpoint_task_tool_journal(
                    *identity,
                    worker_id="worker-1",
                    request_id="request-1",
                    integrity_key=KEY,
                )
        else:
            manager.checkpoint_task_tool_journal(
                *identity,
                worker_id="worker-1",
                request_id="request-1",
                integrity_key=KEY,
            )
    assert _read(manager, identity)[0]["checkpointed_version"] == 3
    assert _prepare(manager, identity, request="new-request", call="new-call") == 3
