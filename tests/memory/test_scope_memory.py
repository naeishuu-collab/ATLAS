"""Ownership, lifecycle, and ranking tests for scoped memory."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from openjarvis.core.types import Message, Role
from openjarvis.memory.scope import (
    PRIVACY_PRIVATE,
    PROVENANCE_MODEL_INFERENCE,
    SCOPE_AGENT,
    SCOPE_TASK,
    SCOPE_USER,
    MemoryAuthorization,
    ScopedMemoryBackend,
)
from openjarvis.memory.store import LocalFactStore
from openjarvis.tools.storage._stubs import MemoryBackend, RetrievalResult
from openjarvis.tools.storage.context import ContextConfig, inject_context


class _Memory(MemoryBackend):
    backend_id = "test"

    def __init__(self) -> None:
        self.rows: list[RetrievalResult] = []

    def store(self, content: str, *, source: str = "", metadata=None) -> str:
        doc_id = str(len(self.rows))
        self.rows.append(
            RetrievalResult(
                content=content,
                score=float(len(self.rows)),
                source=source,
                metadata=dict(metadata or {}),
            )
        )
        return doc_id

    def retrieve(self, query: str, *, top_k: int = 5, **kwargs: Any):
        del query, kwargs
        return list(reversed(self.rows))[:top_k]

    def delete(self, doc_id: str) -> bool:
        del doc_id
        return False

    def clear(self) -> None:
        self.rows.clear()

    def count(self) -> int:
        return len(self.rows)


def _agent(name: str) -> MemoryAuthorization:
    return MemoryAuthorization(agent_id=name)


def test_cross_user_agent_and_task_reads_fail_closed(tmp_path: Path):
    store = LocalFactStore(tmp_path / "facts.jsonl")
    user_a = MemoryAuthorization(user_id="user-a")
    user_b = MemoryAuthorization(user_id="user-b")
    agent_a = _agent("agent-a")
    agent_b = _agent("agent-b")
    task_a = MemoryAuthorization(task_id="task-a")
    task_b = MemoryAuthorization(task_id="task-b")

    store.add_scoped("private user fact", authorization=user_a, scope=SCOPE_USER)
    store.add_scoped("private agent fact", authorization=agent_a, scope=SCOPE_AGENT)
    store.add_scoped("private task fact", authorization=task_a, scope=SCOPE_TASK)

    assert store.list_authorized(user_b) == []
    assert store.list_authorized(agent_b) == []
    assert store.list_authorized(task_b) == []
    assert [f.text for f in store.list_authorized(user_a)] == ["private user fact"]
    assert [f.text for f in store.list_authorized(agent_a)] == ["private agent fact"]
    assert [f.text for f in store.list_authorized(task_a)] == ["private task fact"]


def test_unknown_owner_is_not_promoted_to_global(tmp_path: Path):
    store = LocalFactStore(tmp_path / "facts.jsonl")
    assert store.add("legacy ownerless fact", trust="auto")
    assert store.list_authorized(MemoryAuthorization(user_id="user-a")) == []


def test_correction_and_deletion_survive_restart(tmp_path: Path):
    path = tmp_path / "facts.jsonl"
    auth = _agent("agent-a")
    store = LocalFactStore(path)
    old_id = store.add_scoped("prefers X", authorization=auth, scope=SCOPE_AGENT)
    assert old_id
    new_id = store.correct(old_id, "prefers Y", authorization=auth)
    assert new_id
    assert [f.text for f in store.list_authorized(auth)] == ["prefers Y"]
    assert store.delete(new_id, authorization=auth)
    assert store.list_authorized(auth) == []

    reopened = LocalFactStore(path)
    assert reopened.list_authorized(auth) == []
    rows = {f.memory_id: f for f in reopened.list()}
    assert rows[old_id].superseded_by == new_id
    assert rows[new_id].deleted is True


def test_expiry_is_filtered_before_and_after_restart(tmp_path: Path):
    path = tmp_path / "facts.jsonl"
    auth = _agent("agent-a")
    store = LocalFactStore(path)
    store.add_scoped(
        "expired",
        authorization=auth,
        scope=SCOPE_AGENT,
        expires_at=time.time() - 1,
    )
    assert store.list_authorized(auth) == []
    assert LocalFactStore(path).list_authorized(auth) == []


def test_model_inference_keeps_provenance(tmp_path: Path):
    auth = _agent("agent-a")
    store = LocalFactStore(tmp_path / "facts.jsonl")
    memory_id = store.add_scoped(
        "inferred fact",
        authorization=auth,
        provenance=PROVENANCE_MODEL_INFERENCE,
        scope=SCOPE_AGENT,
    )
    row = next(f for f in store.list() if f.memory_id == memory_id)
    assert row.provenance == PROVENANCE_MODEL_INFERENCE
    assert row.provenance != "USER_EXPLICIT"


def test_authorized_retrieval_filters_ranking_attack():
    backend = _Memory()
    owner_a = _agent("agent-a")
    owner_b = _agent("agent-b")
    backend.store(
        "authorized weaker match",
        metadata={
            "schema_version": 1,
            "scope": SCOPE_AGENT,
            "agent_id": owner_a.agent_id,
            "provenance": PROVENANCE_MODEL_INFERENCE,
            "confidence": 1.0,
            "privacy": PRIVACY_PRIVATE,
            "deleted": False,
        },
    )
    backend.store(
        "unauthorized exact match",
        metadata={
            "schema_version": 1,
            "scope": SCOPE_AGENT,
            "agent_id": owner_b.agent_id,
            "provenance": PROVENANCE_MODEL_INFERENCE,
            "confidence": 1.0,
            "privacy": PRIVACY_PRIVATE,
            "deleted": False,
        },
    )
    messages = [Message(role=Role.USER, content="match")]
    augmented = inject_context(
        "match",
        messages,
        backend,
        config=ContextConfig(authorization=owner_a, top_k=1),
    )
    assert "authorized weaker match" in augmented[0].content
    assert "unauthorized exact match" not in augmented[0].content


def test_scoped_backend_writes_and_reads_only_its_agent():
    backend = _Memory()
    scoped_a = ScopedMemoryBackend(backend, _agent("agent-a"))
    scoped_b = ScopedMemoryBackend(backend, _agent("agent-b"))
    scoped_a.store("agent A secret")
    assert [r.content for r in scoped_a.retrieve("secret", top_k=5)] == [
        "agent A secret"
    ]
    assert scoped_b.retrieve("secret", top_k=5) == []
