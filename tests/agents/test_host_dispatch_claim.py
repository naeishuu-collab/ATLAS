"""Durable host claims prevent unjournaled and repeated execution."""

import base64
import copy
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from openjarvis.agents.manager import AgentManager
from openjarvis.agents.tool_semantics import arguments_sha256
from tests.agents.test_sprint15_task_tool_journal import KEY
from tests.control.test_host_task_supervisor import _setup


def _prepared(manager, identity, binding):
    deadline = time.time() + 60
    params = {"value": "claimed"}
    manager.prepare_task_tool_journal(
        *identity,
        worker_id=binding["worker_id"],
        request_id="claim-request",
        tool_call_id="claim-call",
        tool_name="synthetic_echo",
        arguments_sha256=arguments_sha256(params),
        deadline=deadline,
        integrity_key=KEY,
    )
    manager.transition_task_tool_journal(
        *identity,
        worker_id=binding["worker_id"],
        request_id="claim-request",
        expected="PREPARED",
        state="DISPATCHED",
        integrity_key=KEY,
    )
    return {
        "kind": "EXECUTE_TOOL",
        "binding": dict(binding),
        "request_id": "claim-request",
        "tool_call_id": "claim-call",
        "deadline": deadline,
        "payload": {
            "name": "synthetic_echo",
            "params": params,
            "checkpoint_version": 1,
        },
    }


def _claim(manager, identity, binding, body):
    manager.claim_task_tool_dispatch(
        identity[2], identity[3], binding, body, integrity_key=KEY
    )


def test_claim_survives_connection_restart_and_refuses_duplicate(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    body = _prepared(manager, identity, binding)
    path = manager._db_path
    _claim(manager, identity, binding, body)
    manager.close()
    reopened = AgentManager(path)
    try:
        with pytest.raises(PermissionError, match="already claimed"):
            _claim(reopened, identity, binding, body)
        rows = reopened.read_task_tool_journal(
            identity[0], identity[1], identity[2], identity[3], integrity_key=KEY
        )
        assert rows[0]["recovery_state"] == "UNKNOWN_OUTCOME"
    finally:
        reopened.close()


def test_claim_refuses_duplicate_from_new_os_process(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    body = _prepared(manager, identity, binding)
    path = manager._db_path
    _claim(manager, identity, binding, body)
    manager.close()
    code = """import base64,json,sys
from openjarvis.agents.manager import AgentManager
from openjarvis.security.principal import TestPrincipalAuthority
p=json.load(sys.stdin)
a=TestPrincipalAuthority(base64.b64decode(p["authority_key"]))
principal=a.verify(a.issue("synthetic-principal"))
m=AgentManager(p["db"])
try:
 m.claim_task_tool_dispatch(principal,a,p["binding"],p["body"],integrity_key=base64.b64decode(p["integrity_key"]))
 print("unexpected-dispatch")
except PermissionError:
 print("duplicate-denied")
finally:
 m.close()
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        input=json.dumps(
            {
                "db": path,
                "binding": binding,
                "body": body,
                "authority_key": base64.b64encode(
                    b"independent-host-test-authority"
                ).decode("ascii"),
                "integrity_key": base64.b64encode(KEY).decode("ascii"),
            }
        ),
        text=True,
        capture_output=True,
        timeout=15,
        check=True,
    )
    assert result.stdout.strip() == "duplicate-denied"


@pytest.mark.parametrize(
    "attack", ["arguments", "task", "principal", "attempt", "epoch"]
)
def test_claim_rejects_mismatched_binding_and_arguments(tmp_path, attack):
    manager, identity, binding = _setup(tmp_path)
    try:
        body = _prepared(manager, identity, binding)
        altered = copy.deepcopy(binding)
        if attack == "arguments":
            body["payload"]["params"]["value"] = "different"
        else:
            field = {"task": "task_id", "principal": "principal_id"}.get(attack, attack)
            altered[field] = 2 if field == "epoch" else "different"
            body["binding"] = altered
        with pytest.raises((PermissionError, KeyError)):
            _claim(manager, identity, altered, body)
        assert (
            manager._conn.execute(
                "SELECT count(*) FROM task_tool_dispatch_claims"
            ).fetchone()[0]
            == 0
        )
    finally:
        manager.close()


@pytest.mark.parametrize("tamper", ["delete", "mac", "epoch"])
def test_claim_tampering_is_detected_by_journal_head(tmp_path, tamper):
    manager, identity, binding = _setup(tmp_path)
    try:
        body = _prepared(manager, identity, binding)
        _claim(manager, identity, binding, body)
        if tamper == "delete":
            manager._conn.execute("DELETE FROM task_tool_dispatch_claims")
        elif tamper == "mac":
            manager._conn.execute("UPDATE task_tool_dispatch_claims SET mac='forged'")
        else:
            manager._conn.execute("UPDATE task_tool_dispatch_claims SET epoch=2")
        manager._conn.commit()
        with pytest.raises(PermissionError):
            manager.read_task_tool_journal(
                identity[0], identity[1], identity[2], identity[3], integrity_key=KEY
            )
    finally:
        manager.close()


def test_concurrent_claims_allow_only_one_host_dispatch(tmp_path):
    manager, identity, binding = _setup(tmp_path)
    second = AgentManager(manager._db_path)
    try:
        body = _prepared(manager, identity, binding)

        def attempt(connection):
            try:
                _claim(connection, identity, binding, body)
                return True
            except PermissionError:
                return False

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, (manager, second)))
        assert sorted(results) == [False, True]
    finally:
        second.close()
        manager.close()
