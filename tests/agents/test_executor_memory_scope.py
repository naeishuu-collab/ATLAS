"""Managed-agent memory is scoped by the production executor boundary."""

from __future__ import annotations

import gc

import pytest

from openjarvis.agents._stubs import AgentResult
from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.manager import AgentManager
from openjarvis.core.events import EventBus
from openjarvis.core.registry import AgentRegistry
from openjarvis.memory.scope import MemoryAuthorization, ScopedMemoryBackend
from tests.agents.fake_engine import FakeEngine
from tests.agents.scenario_harness import FakeSystem
from tests.memory.test_scope_memory import _Memory


class _ScopedProbeAgent:
    accepts_tools = False
    seen: dict[str, list[str]] = {}

    def __init__(self, engine, model, *, memory_backend=None, agent_id="", **kwargs):
        del engine, model, kwargs
        self._backend = memory_backend
        self._agent_id = agent_id

    def run(self, input_text, context=None):
        del input_text, context
        type(self).seen[self._agent_id] = [
            result.content for result in self._backend.retrieve("private", top_k=5)
        ]
        return AgentResult(content="done")


def test_managed_executor_injects_scoped_memory_view(tmp_path):
    AgentRegistry.register_value("scoped_probe", _ScopedProbeAgent)
    _ScopedProbeAgent.seen = {}
    raw = _Memory()
    manager = AgentManager(db_path=str(tmp_path / "agents.db"))
    try:
        agent_a = manager.create_agent("A", agent_type="scoped_probe", config={})
        agent_b = manager.create_agent("B", agent_type="scoped_probe", config={})
        ScopedMemoryBackend(
            raw,
            MemoryAuthorization(agent_id=agent_a["id"]),
        ).store("private A memory")
        executor = AgentExecutor(
            manager,
            EventBus(),
            system=FakeSystem(
                engine=FakeEngine([{"content": "unused"}, {"content": "unused"}]),
                memory_backend=raw,
            ),
        )
        executor._invoke_agent(agent_a)
        executor._invoke_agent(agent_b)
        assert _ScopedProbeAgent.seen[agent_a["id"]] == ["private A memory"]
        assert _ScopedProbeAgent.seen[agent_b["id"]] == []
    finally:
        manager.close()


def test_managed_executor_scoped_sqlite_memory_survives_reopen(tmp_path):
    pytest.importorskip("openjarvis._rust_bridge")
    from openjarvis.tools.storage.sqlite import SQLiteMemory

    AgentRegistry.register_value("scoped_sqlite_probe", _ScopedProbeAgent)
    _ScopedProbeAgent.seen = {}
    db_path = tmp_path / "memory.db"
    raw = SQLiteMemory(db_path)
    manager = AgentManager(db_path=str(tmp_path / "agents.db"))
    try:
        agent = manager.create_agent(
            "sqlite-agent",
            agent_type="scoped_sqlite_probe",
            config={},
        )
        auth = MemoryAuthorization(agent_id=agent["id"])
        ScopedMemoryBackend(raw, auth).store("private sqlite memory")
        executor = AgentExecutor(
            manager,
            EventBus(),
            system=FakeSystem(
                engine=FakeEngine([{"content": "unused"}]),
                memory_backend=raw,
            ),
        )
        executor._invoke_agent(agent)
        assert _ScopedProbeAgent.seen[agent["id"]] == ["private sqlite memory"]
        del executor
        del raw
        gc.collect()
        reopened = SQLiteMemory(db_path)
        try:
            assert [
                result.content
                for result in ScopedMemoryBackend(reopened, auth).retrieve(
                    "private",
                    top_k=5,
                )
            ] == ["private sqlite memory"]
        finally:
            del reopened
            gc.collect()
    finally:
        manager.close()
