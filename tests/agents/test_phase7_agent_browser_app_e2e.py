"""Phase 7 managed Agent -> Browser/App integration proof.

The browser is a local, test-owned DOM.  The production managed executor,
planner boundary, journal, target identity checks, and independent browser
read-back remain in the path; the fixture supplies external I/O only.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.orchestrator import OrchestratorAgent
from openjarvis.agents.proposals import PlanProposal, PlanStepProposal
from openjarvis.core.events import EventBus
from openjarvis.core.execution import ExecutionState
from openjarvis.core.registry import AgentRegistry, ToolRegistry
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.tools.browser import (
    BrowserExtractTool,
    BrowserTypeTool,
    _BrowserSession,
)
from tests.agents.fake_engine import FakeEngine


@pytest.fixture
def test_browser(monkeypatch):
    session = _BrowserSession()
    session.run(
        lambda: session.page.set_content(
            "<script>window.inputMutations=0</script>"
            "<input id='name' oninput='window.inputMutations++'>"
        )
    )
    monkeypatch.setattr("openjarvis.tools.browser._session", session)
    yield session
    session.close()
    session._runner.shutdown()


def _agent(manager: AgentManager) -> dict:
    AgentRegistry.register_value("orchestrator", OrchestratorAgent)
    for tool in (BrowserExtractTool, BrowserTypeTool):
        if not ToolRegistry.contains(tool.tool_id):
            ToolRegistry.register_value(tool.tool_id, tool)
    return manager.create_agent(
        "phase7-browser-goal",
        agent_type="orchestrator",
        config={
            "model": "fake-model",
            "instruction": "Observe the owned field and enter the supplied value.",
            "tools": [BrowserExtractTool.tool_id, BrowserTypeTool.tool_id],
            "mcp_tools": False,
        },
    )


def _executor(manager: AgentManager, engine: FakeEngine) -> AgentExecutor:
    policy = CapabilityPolicy(default_deny=True)
    policy.grant("_default", "network:fetch")
    system = SimpleNamespace(
        engine=engine,
        model="fake-model",
        capability_policy=policy,
        memory_backend=None,
        channel_backend=None,
        config=None,
    )
    executor = AgentExecutor(manager, EventBus(), system=system)
    executor._confirm_callback = lambda _prompt: True
    return executor


def _tick(manager: AgentManager, agent_id: str, responses: list[dict]) -> FakeEngine:
    engine = FakeEngine(responses)
    _executor(manager, engine).execute_tick(agent_id)
    return engine


def _ready(manager: AgentManager, agent_id: str) -> None:
    _tick(manager, agent_id, [{"content": "ready"}])


def _call(name: str, call_id: str, **arguments) -> dict:
    return {
        "tool_calls": [
            {
                "id": call_id,
                "name": name,
                "arguments": json.dumps(arguments),
            }
        ]
    }


def _plan() -> PlanProposal:
    return PlanProposal(
        proposal_id="phase7-browser-plan",
        steps=(
            PlanStepProposal(
                local_index="mutate",
                kind="MUTATING",
                tool_name=BrowserTypeTool.tool_id,
                arguments={"selector": "#name", "text": "Astra", "clear": True},
            ),
        ),
    )


def _restart(manager: AgentManager, agent_id: str, path: str) -> AgentManager:
    checkpoint = manager.get_latest_checkpoint(agent_id)
    assert checkpoint is not None
    manager.save_checkpoint(
        agent_id,
        checkpoint["tick_id"],
        {
            **checkpoint["conversation_state"],
            "lifecycle": "RUNNING",
            "resumable": True,
            "resume_authorized": True,
        },
        checkpoint["tool_state"],
    )
    manager.start_tick(agent_id)
    manager.close()
    return AgentManager(path, clear_stale_running=True)


def test_managed_agent_browser_goal_restarts_and_verifies_once(tmp_path, test_browser):
    path = str(tmp_path / "phase7-browser.db")
    manager = AgentManager(path)
    agent_id = None
    try:
        agent = _agent(manager)
        agent_id = agent["id"]
        _ready(manager, agent_id)
        observed = _tick(
            manager,
            agent_id,
            [
                _call(BrowserExtractTool.tool_id, "observe-1", selector="body"),
                {"content": "Observation retained; plan the authorized mutation."},
            ],
        )
        document_id = test_browser.document_id
        flattened = "".join(
            str(getattr(message, "content", message))
            for message in (observed.last_messages or [])
        )
        assert document_id in flattened

        planner = type(
            "Planner",
            (),
            {"propose": lambda _self, _goal, _context=None: _plan()},
        )()
        executor = _executor(manager, FakeEngine([]))
        minted = executor.plan_goal(
            agent_id,
            planner,
            "Observe the owned field and enter Astra",
            supported_tools={BrowserExtractTool.tool_id, BrowserTypeTool.tool_id},
        )
        mutate_id = minted["local_to_planner_node"]["mutate"]

        manager = _restart(manager, agent_id, path)
        action = _tick(
            manager,
            agent_id,
            [
                _call(
                    BrowserTypeTool.tool_id,
                    "mutate-1",
                    document_id=document_id,
                    selector="#name",
                    text="Astra",
                    clear=True,
                ),
                {"content": "Goal complete after independent browser verification."},
            ],
        )
        action_text = "".join(
            str(getattr(message, "content", message))
            for message in (action.last_messages or [])
        )
        assert "Typed text into: #name" in action_text, action_text

        assert (
            test_browser.run(lambda: test_browser.page.input_value("#name"))
            == "Astra"
        )
        assert test_browser.run(
            lambda: test_browser.page.evaluate("window.inputMutations")
        ) == 1
        checkpoint = manager.get_latest_checkpoint(agent_id)
        assert checkpoint is not None
        plan = checkpoint["tool_state"]["durable_plan"]
        assert all(node["status"] == "COMPLETED" for node in plan["nodes"])
        completed = checkpoint["tool_state"]["completed_steps"]
        assert any(
            step.get("step_id") == mutate_id
            and step.get("state") == ExecutionState.VERIFIED.value
            for step in completed
        )
        assert manager.execution_journal.pending(agent_id) == []
    finally:
        if agent_id is not None:
            try:
                manager.close()
            except Exception:
                pass


def test_managed_agent_browser_stale_target_fails_closed_without_dispatch(
    tmp_path, test_browser
):
    observed = BrowserExtractTool().execute(selector="body")
    assert observed.success
    old_document_id = observed.metadata["document_id"]
    test_browser.run(
        lambda: test_browser.page.goto(
            "data:text/html,<script>window.inputMutations=0</script>"
            "<input id='name' oninput='window.inputMutations++'>"
        )
    )

    manager = AgentManager(str(tmp_path / "phase7-stale.db"))
    try:
        agent = _agent(manager)
        _ready(manager, agent["id"])
        proposal = PlanProposal(
            proposal_id="phase7-stale-plan",
            steps=(
                PlanStepProposal(
                    local_index="mutate",
                    kind="MUTATING",
                    tool_name=BrowserTypeTool.tool_id,
                    arguments={"selector": "#name", "text": "blocked"},
                ),
            ),
        )
        _executor(manager, FakeEngine([])).materialize_plan_proposal(
            agent["id"],
            proposal,
            supported_tools={BrowserTypeTool.tool_id},
        )
        _tick(
            manager,
            agent["id"],
            [
                _call(
                    BrowserTypeTool.tool_id,
                    "stale-1",
                    document_id=old_document_id,
                    selector="#name",
                    text="blocked",
                ),
                {"content": "Stop: stale target was rejected."},
            ],
        )
        assert test_browser.run(lambda: test_browser.page.input_value("#name")) == ""
        assert test_browser.run(
            lambda: test_browser.page.evaluate("window.inputMutations")
        ) == 0
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint is not None
        plan = checkpoint["tool_state"]["durable_plan"]
        assert plan["nodes"][0]["status"] != "COMPLETED"
        assert manager.execution_journal.pending(agent["id"]) == []
    finally:
        manager.close()
