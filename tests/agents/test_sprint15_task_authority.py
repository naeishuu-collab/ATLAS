"""Durable Controller task ownership fails closed across SQLite connections."""

import hashlib
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from openjarvis.agents.manager import AgentManager
from openjarvis.core.execution import ToolEffect
from openjarvis.core.types import ToolCall, ToolResult
from openjarvis.security.principal import TestPrincipalAuthority
from openjarvis.tools._stubs import BaseTool, ToolExecutor, ToolSpec


def test_task_claim_is_exclusive_and_validated_across_managers(tmp_path):
    path = str(tmp_path / "task.db")
    first, second = AgentManager(path), AgentManager(path)
    try:
        agent = first.create_agent("worker", agent_type="simple")
        task = first.create_task(agent["id"], "work")
        authority = TestPrincipalAuthority(b"synthetic-owner-test")
        principal = authority.verify(authority.issue("owner"))
        other = authority.verify(authority.issue("other"))
        barrier = threading.Barrier(2)

        def claim(manager, token):
            barrier.wait(timeout=5)
            try:
                return manager.start_task(
                    task["id"],
                    agent["id"],
                    principal.principal_id,
                    None,
                    worker_token=token,
                )
            except PermissionError:
                return None

        tokens = ["a" * 32, "b" * 32]
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(claim, m, t) for m, t in zip((first, second), tokens)
            ]
            results = [f.result(timeout=10) for f in futures]
        assert sum(result is not None for result in results) == 1
        index = 0 if results[0] else 1
        attempt = results[index]["execution_attempt"]
        args = (
            task["id"],
            agent["id"],
            principal,
            authority,
            attempt,
            tokens[index],
            1,
        )
        second.validate_task_authority(*args)
        second.renew_task_authority(*args)
        for invalid in (
            (*args[:5], tokens[1 - index], 1),
            (*args[:5], tokens[index], 2),
            (task["id"], agent["id"], other, authority, attempt, tokens[index], 1),
            (task["id"], "other-agent", *args[2:]),
            ("other-task", *args[1:]),
            (*args[:4], "stale-attempt", *args[5:]),
        ):
            with pytest.raises(PermissionError):
                second.validate_task_authority(*invalid)
        first._conn.execute(
            "UPDATE agent_task_authority SET expires_at = ? WHERE task_id = ?",
            (time.time() - 1, task["id"]),
        )
        first._conn.commit()
        with pytest.raises(PermissionError):
            second.validate_task_authority(*args)
        with pytest.raises(PermissionError):
            second.renew_task_authority(*args)
        with pytest.raises(PermissionError):
            second.start_task(
                task["id"],
                agent["id"],
                principal.principal_id,
                None,
                worker_token="c" * 32,
            )
    finally:
        first.close()
        second.close()


def test_task_authority_binding_returns_only_live_owner_hash_and_lease(tmp_path):
    manager = AgentManager(str(tmp_path / "binding.db"))
    try:
        agent = manager.create_agent("worker")
        task = manager.create_task(agent["id"], "work")
        authority = TestPrincipalAuthority(b"synthetic-owner-test")
        principal = authority.verify(authority.issue("owner"))
        token = "a" * 32
        started = manager.start_task(
            task["id"],
            agent["id"],
            principal.principal_id,
            None,
            worker_token=token,
        )
        binding = manager.task_authority_binding(
            task["id"],
            agent["id"],
            principal,
            authority,
            started["execution_attempt"],
            token,
            1,
        )
        assert set(binding) == {"owner_hash", "epoch", "lease_expires_at"}
        assert binding["owner_hash"] == hashlib.sha256(token.encode()).hexdigest()
        assert binding["epoch"] == 1
        assert binding["lease_expires_at"] > time.time()
        with pytest.raises(PermissionError):
            manager.task_authority_binding(
                task["id"],
                agent["id"],
                principal,
                authority,
                started["execution_attempt"],
                "b" * 32,
                1,
            )
    finally:
        manager.close()


@pytest.mark.parametrize("expire_during_call", [False, True])
def test_tool_boundary_does_not_accept_expired_authority(tmp_path, expire_during_call):
    manager = AgentManager(str(tmp_path / "task.db"))
    try:
        agent = manager.create_agent("worker")
        task = manager.create_task(agent["id"], "work")
        authority = TestPrincipalAuthority(b"synthetic-owner-test")
        principal = authority.verify(authority.issue("owner"))
        token = "a" * 32
        started = manager.start_task(
            task["id"], agent["id"], principal.principal_id, None, worker_token=token
        )
        calls = []

        def expire():
            with manager._db_lock:
                manager._conn.execute(
                    "UPDATE agent_task_authority SET expires_at = ? WHERE task_id = ?",
                    (time.time() - 1, task["id"]),
                )
                manager._conn.commit()

        class Probe(BaseTool):
            @property
            def spec(self):
                return ToolSpec("probe", "test", effect=ToolEffect.MUTATING)

            def execute(self, **_params):
                calls.append("effect")
                expire()
                return ToolResult(tool_name="probe", content="done")

        executor = ToolExecutor([Probe()])
        executor._task_authority_check = lambda: manager.validate_task_authority(
            task["id"],
            agent["id"],
            principal,
            authority,
            started["execution_attempt"],
            token,
            1,
        )
        if not expire_during_call:
            expire()
        result = executor.execute(ToolCall(id="call-1", name="probe", arguments="{}"))
        assert not result.success
        assert len(calls) == int(expire_during_call)
        if expire_during_call:
            assert result.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
    finally:
        manager.close()


@pytest.mark.parametrize("revocation", ["worker", "principal", "cancellation"])
def test_revocation_and_cancellation_deny_worker(tmp_path, revocation):
    manager = AgentManager(str(tmp_path / "task.db"))
    try:
        agent = manager.create_agent("worker")
        task = manager.create_task(agent["id"], "work")
        authority = TestPrincipalAuthority(b"synthetic-owner-test")
        principal = authority.verify(authority.issue("owner"))
        token = "a" * 32
        task = manager.start_task(
            task["id"], agent["id"], principal.principal_id, None, worker_token=token
        )
        if revocation == "worker":
            manager._conn.execute(
                "UPDATE agent_task_authority SET state = 'REVOKED' WHERE task_id = ?",
                (task["id"],),
            )
            manager._conn.commit()
        elif revocation == "principal":
            authority.revoke(principal)
        else:
            manager.start_tick(agent["id"])
            manager.request_cancellation(agent["id"])
        with pytest.raises(PermissionError):
            manager.validate_task_authority(
                task["id"],
                agent["id"],
                principal,
                authority,
                task["execution_attempt"],
                token,
                1,
            )
    finally:
        manager.close()
