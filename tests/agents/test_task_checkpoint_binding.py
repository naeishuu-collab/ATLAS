from __future__ import annotations

import json

import pytest

from openjarvis.agents.manager import AgentManager
from openjarvis.security.principal import TestPrincipalAuthority


def test_sessionless_synthetic_tool_checkpoint_needs_no_session_leases(tmp_path):
    manager = AgentManager(str(tmp_path / "sessionless.db"))
    try:
        agent = manager.create_agent("owner")
        task = manager.create_task(agent["id"], "synthetic task")
        authority = TestPrincipalAuthority(b"sessionless-checkpoint-authority")
        principal = authority.verify(authority.issue("principal"))
        token = "s" * 32
        started = manager.start_task(
            task["id"],
            agent["id"],
            principal.principal_id,
            None,
            worker_token=token,
        )
        state = {"execution_id": started["execution_attempt"], "worker_epoch": 1}
        checkpoint = manager.save_checkpoint(
            agent["id"],
            "synthetic",
            {
                "task_id": task["id"],
                "messages": [
                    {
                        "role": "tool",
                        "name": "synthetic_echo",
                        "content": "synthetic:ok",
                    }
                ],
            },
            state,
        )
        assert (
            manager.bind_task_checkpoint(
                task["id"],
                agent["id"],
                principal,
                authority,
                checkpoint["id"],
                started["execution_attempt"],
                integrity_key=b"sessionless-checkpoint-integrity-key",
                worker_token=token,
                worker_epoch=1,
            )
            == 1
        )
    finally:
        manager.close()


def test_task_checkpoint_binding_revalidates_identity_and_integrity(tmp_path):
    path = str(tmp_path / "tasks.db")
    manager = AgentManager(path)
    agent = manager.create_agent("owner")
    other_agent = manager.create_agent("other")
    task = manager.create_task(agent["id"], "task")
    other_task = manager.create_task(agent["id"], "other task")
    authority = TestPrincipalAuthority(b"synthetic-authority")
    principal = authority.verify(authority.issue("principal"))
    wrong = authority.verify(authority.issue("wrong"))
    key = b"test-only-integrity-key-32-bytes!"
    checkpoint = manager.save_checkpoint(
        agent["id"],
        "tick",
        {"task_id": task["id"]},
        {
            "execution_id": "attempt-1",
        },
    )
    args = (task["id"], agent["id"], principal, authority)
    with pytest.raises(PermissionError, match="mismatch"):
        manager.bind_task_checkpoint(
            other_task["id"],
            agent["id"],
            principal,
            authority,
            checkpoint["id"],
            "attempt-1",
            integrity_key=key,
        )
    manager.bind_task_checkpoint(
        *args, checkpoint["id"], "attempt-1", integrity_key=key
    )
    with pytest.raises(PermissionError, match="already bound"):
        manager.bind_task_checkpoint(
            *args, checkpoint["id"], "attempt-1", integrity_key=key
        )
    for index in range(7):
        manager.save_checkpoint(agent["id"], f"later-{index}", {}, {})
    manager.close()
    manager = AgentManager(path)
    try:
        restored = manager.get_bound_task_checkpoint(*args, integrity_key=key)
        assert restored["id"] == checkpoint["id"]
        with pytest.raises(PermissionError):
            manager.get_bound_task_checkpoint(
                task["id"], other_agent["id"], principal, authority, integrity_key=key
            )
        with pytest.raises(PermissionError):
            manager.get_bound_task_checkpoint(
                task["id"], agent["id"], wrong, authority, integrity_key=key
            )
        with pytest.raises(PermissionError, match="integrity"):
            manager.get_bound_task_checkpoint(*args, integrity_key=b"x" * 32)
        manager._conn.execute(
            "UPDATE agent_checkpoints SET tool_state = ? WHERE id = ?",
            (json.dumps({"execution_id": "tampered"}), checkpoint["id"]),
        )
        manager._conn.commit()
        with pytest.raises(PermissionError, match="integrity"):
            manager.get_bound_task_checkpoint(*args, integrity_key=key)
        authority.revoke(principal)
        with pytest.raises(PermissionError, match="authority"):
            manager.get_bound_task_checkpoint(*args, integrity_key=key)
    finally:
        manager.close()


def test_legacy_checkpoint_cannot_be_bound(tmp_path):
    manager = AgentManager(str(tmp_path / "legacy.db"))
    try:
        agent = manager.create_agent("owner")
        task = manager.create_task(agent["id"], "task")
        authority = TestPrincipalAuthority(b"synthetic-authority")
        principal = authority.verify(authority.issue("principal"))
        checkpoint = manager.save_checkpoint(agent["id"], "tick", {}, {})
        with pytest.raises(PermissionError, match="binding mismatch"):
            manager.bind_task_checkpoint(
                task["id"],
                agent["id"],
                principal,
                authority,
                checkpoint["id"],
                "attempt",
                integrity_key=b"x" * 32,
            )
    finally:
        manager.close()


def test_checkpoint_chain_rejects_stale_updates_and_predecessor_tampering(tmp_path):
    path = str(tmp_path / "chain.db")
    manager = AgentManager(path)
    agent = manager.create_agent("owner")
    task = manager.create_task(agent["id"], "task")
    authority = TestPrincipalAuthority(b"chain-test-authority")
    principal = authority.verify(authority.issue("principal"))
    key = b"chain-integrity-key-for-test-only"
    args = (task["id"], agent["id"], principal, authority)

    def checkpoint(tick, attempt="attempt-1"):
        return manager.save_checkpoint(
            agent["id"],
            tick,
            {"task_id": task["id"]},
            {
                "execution_id": attempt,
            },
        )

    try:
        first = checkpoint("one")
        assert (
            manager.bind_task_checkpoint(
                *args, first["id"], "attempt-1", integrity_key=key
            )
            == 1
        )
        second = checkpoint("two")
        assert (
            manager.bind_task_checkpoint(
                *args, second["id"], "attempt-1", integrity_key=key, expected_version=1
            )
            == 2
        )
        third = checkpoint("three")
        with pytest.raises(PermissionError, match="stale checkpoint"):
            manager.bind_task_checkpoint(
                *args, third["id"], "attempt-1", integrity_key=key, expected_version=1
            )
        wrong_attempt = checkpoint("wrong", "attempt-2")
        with pytest.raises(PermissionError, match="attempt or identity"):
            manager.bind_task_checkpoint(
                *args,
                wrong_attempt["id"],
                "attempt-2",
                integrity_key=key,
                expected_version=2,
            )
        for index in range(6):
            checkpoint(f"extra-{index}")
        manager.close()
        manager = AgentManager(path)
        restored = manager.get_bound_task_checkpoint(*args, integrity_key=key)
        assert restored["id"] == second["id"]
        assert restored["task_binding_version"] == 2
        manager._conn.execute(
            "UPDATE agent_checkpoints SET tool_state = '{}' WHERE id = ?",
            (first["id"],),
        )
        manager._conn.commit()
        with pytest.raises(PermissionError, match="integrity"):
            manager.get_bound_task_checkpoint(*args, integrity_key=key)
    finally:
        manager.close()


def test_sprint11_binding_can_be_upgraded_without_changing_its_signature(tmp_path):
    manager = AgentManager(str(tmp_path / "legacy-link.db"))
    agent = manager.create_agent("owner")
    task = manager.create_task(agent["id"], "task")
    authority = TestPrincipalAuthority(b"legacy-link-authority")
    principal = authority.verify(authority.issue("principal"))
    key = b"test-only-legacy-key-with-32-bytes"
    args = (task["id"], agent["id"], principal, authority)
    state = {"execution_id": "attempt"}
    try:
        one = manager.save_checkpoint(
            agent["id"], "tick-one", {"task_id": task["id"]}, state
        )
        manager.bind_task_checkpoint(*args, one["id"], "attempt", integrity_key=key)
        manager._conn.execute("DELETE FROM agent_task_checkpoint_history")
        manager._conn.commit()
        assert (
            manager.get_bound_task_checkpoint(*args, integrity_key=key)["id"]
            == one["id"]
        )
        two = manager.save_checkpoint(
            agent["id"], "tick-two", {"task_id": task["id"]}, state
        )
        assert (
            manager.bind_task_checkpoint(
                *args, two["id"], "attempt", integrity_key=key, expected_version=1
            )
            == 2
        )
        assert (
            manager.get_bound_task_checkpoint(*args, integrity_key=key)["id"]
            == two["id"]
        )
    finally:
        manager.close()
