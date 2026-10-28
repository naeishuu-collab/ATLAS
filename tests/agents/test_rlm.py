"""Tests for the RLM agent."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from openjarvis.agents._stubs import AgentContext
from openjarvis.agents.rlm import RLMAgent, _RLMReplTool
from openjarvis.agents.rlm_repl import RLMRepl
from openjarvis.core.events import EventBus, EventType
from openjarvis.core.registry import AgentRegistry
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _CalcStub(BaseTool):
    tool_id = "calculator"

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="calculator",
            description="Math calculator.",
            parameters={
                "type": "object",
                "properties": {"expression": {"type": "string"}},
                "required": ["expression"],
            },
        )

    def execute(self, **params) -> ToolResult:
        expr = params.get("expression", "0")
        try:
            val = eval(expr)  # noqa: S307
        except Exception as e:
            return ToolResult(tool_name="calculator", content=str(e), success=False)
        return ToolResult(tool_name="calculator", content=str(val), success=True)


class _FileReadStub(BaseTool):
    tool_id = "file_read"

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="file_read",
            description="Read a file.",
            parameters={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        )

    def execute(self, **params) -> ToolResult:
        path = params.get("path", "")
        max_lines = params.get("max_lines")
        if path == "rust/Cargo.toml":
            content = '[workspace]\nmembers = ["a", "b", "c"]\n'
            if max_lines is not None:
                lines = content.splitlines(keepends=True)
                content = "".join(lines[: int(max_lines)])
            return ToolResult(
                tool_name="file_read",
                content=content,
                success=True,
            )
        if path == "long.txt":
            content = "line1\nline2\nline3\nline4\nline5\n"
            if max_lines is not None:
                lines = content.splitlines(keepends=True)
                content = "".join(lines[: int(max_lines)])
            return ToolResult(
                tool_name="file_read",
                content=content,
                success=True,
            )
        return ToolResult(tool_name="file_read", content="", success=False)


def _make_engine(content: str = "Final answer.") -> MagicMock:
    """Engine that returns plain content (no code block)."""
    engine = MagicMock()
    engine.engine_id = "mock"
    engine.generate.return_value = {
        "content": content,
        "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
        "model": "test-model",
        "finish_reason": "stop",
    }
    return engine


def _make_engine_with_code(
    code: str,
    final_content: str = "Done.",
) -> MagicMock:
    """Engine that returns a python code block, then a final answer."""
    engine = MagicMock()
    engine.engine_id = "mock"
    engine.generate.side_effect = [
        {
            "content": f"```python\n{code}\n```",
            "usage": {"prompt_tokens": 5, "completion_tokens": 10, "total_tokens": 15},
            "model": "test-model",
            "finish_reason": "stop",
        },
        {
            "content": final_content,
            "usage": {"prompt_tokens": 15, "completion_tokens": 5, "total_tokens": 20},
            "model": "test-model",
            "finish_reason": "stop",
        },
    ]
    return engine


def _legacy_agent(engine, model="test-model", **kwargs):
    """Opt existing in-process RLM behavior into explicit legacy mode."""
    kwargs["allow_unsafe_legacy_repl"] = True
    return RLMAgent(engine, model, **kwargs)


def _worker_policy(agent_id="rlm"):
    from openjarvis.security.capabilities import CapabilityPolicy

    policy = CapabilityPolicy(default_deny=True)
    policy.grant(agent_id, "code:execute")
    return policy


def _worker_agent(engine, model="test-model", **kwargs):
    kwargs.setdefault("execution_mode", "worker")
    kwargs.setdefault(
        "capability_policy",
        _worker_policy(kwargs.get("agent_id", "rlm")),
    )
    return RLMAgent(engine, model, **kwargs)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRLMAgentRegistration:
    def test_registered(self):
        # Re-register after conftest clears all registries
        AgentRegistry.register_value("rlm", RLMAgent)
        assert AgentRegistry.contains("rlm")

    def test_agent_id(self):
        engine = _make_engine()
        agent = RLMAgent(engine, "test-model")
        assert agent.agent_id == "rlm"


class TestRLMCodeExtraction:
    def test_extract_python_block(self):
        text = "Here is code:\n```python\nx = 1\n```\nDone."
        code = RLMAgent._extract_code(text)
        assert code == "x = 1"

    def test_extract_bare_block(self):
        text = "Here is code:\n```\nx = 1\n```\nDone."
        code = RLMAgent._extract_code(text)
        assert code == "x = 1"

    def test_no_block(self):
        text = "No code here, just text."
        code = RLMAgent._extract_code(text)
        assert code is None

    def test_python_preferred_over_bare(self):
        text = "```python\nx = 1\n```\n\n```\ny = 2\n```"
        code = RLMAgent._extract_code(text)
        assert code == "x = 1"


class TestRLMStripThink:
    def test_strip_think(self):
        text = "<think>thinking...</think>Answer here."
        result = RLMAgent._strip_think_tags(text)
        assert result == "Answer here."

    def test_no_think_tags(self):
        text = "Just text."
        result = RLMAgent._strip_think_tags(text)
        assert result == "Just text."


class TestRLMDirectAnswer:
    def test_no_code_block_returns_content(self):
        """When model returns no code block, treat content as final answer."""
        engine = _make_engine("The answer is 42.")
        agent = RLMAgent(engine, "test-model")
        result = agent.run("What is the answer?")
        assert result.content == "The answer is 42."
        assert result.turns == 1
        assert result.tool_results == []

    def test_default_mode_rejects_generated_code_without_host_execution(self):
        engine = _make_engine_with_code("marker = 42")
        agent = RLMAgent(engine, "test-model")

        result = agent.run("execute generated code")

        assert result.content == "Done."
        assert len(result.tool_results) == 1
        assert result.tool_results[0].success is False
        assert result.tool_results[0].metadata["error_code"] == "RLM_WORKER_REQUIRED"
        assert engine.generate.call_count == 2

    def test_default_deny_blocks_agent_before_generated_code(self):
        from openjarvis.security.capabilities import CapabilityPolicy

        class _RecordingLimiter:
            def __init__(self):
                self.keys = []

            def check(self, key):
                self.keys.append(key)
                return True, 0.0

        engine = _make_engine_with_code("sentinel = 42")
        limiter = _RecordingLimiter()
        agent = RLMAgent(
            engine,
            "test-model",
            capability_policy=CapabilityPolicy(default_deny=True),
            rate_limiter=limiter,
            agent_id="restricted-rlm",
        )

        result = agent.run("execute generated code")

        assert result.metadata["security_denied"] is True
        assert "code:execute" in result.content
        engine.generate.assert_not_called()
        assert limiter.keys == ["restricted-rlm:agent_run"]


class TestRLMWorkerAgentIntegration:
    def test_worker_mode_requires_explicit_capability_policy(self):
        engine = _make_engine_with_code("FINAL('must not run')")
        agent = RLMAgent(engine, "test-model", execution_mode="worker")

        result = agent.run("execute generated code")

        assert result.metadata["error_code"] == "RLM_WORKER_AUTHORIZATION_REQUIRED"
        assert result.metadata["security_denied"] is True
        engine.generate.assert_not_called()

    def test_worker_mode_denies_without_grant(self):
        from openjarvis.security.capabilities import CapabilityPolicy

        engine = _make_engine_with_code("FINAL('must not run')")
        agent = RLMAgent(
            engine,
            "test-model",
            execution_mode="worker",
            capability_policy=CapabilityPolicy(default_deny=True),
        )

        result = agent.run("execute generated code")

        assert result.metadata["security_denied"] is True
        assert "code:execute" in result.content
        engine.generate.assert_not_called()

    def test_worker_mode_is_explicit_and_ignores_model_override(self):
        engine = _make_engine_with_code("marker = 42")
        agent = RLMAgent(engine, "test-model")

        result = agent.run("execute generated code", execution_mode="worker")

        assert agent.execution_mode == "disabled"
        assert result.tool_results[0].metadata["error_code"] == "RLM_WORKER_REQUIRED"

    def test_worker_mode_denies_with_context_without_sandbox(self):
        engine = _make_engine_with_code("FINAL(context.upper())")
        agent = _worker_agent(engine)

        result = agent.run(
            "execute generated code",
            context=AgentContext(metadata={"context": "worker"}),
        )

        assert result.metadata["error_code"] == "RLM_SANDBOX_UNAVAILABLE"
        assert result.metadata["security_denied"] is True
        assert engine.generate.call_count == 0

    def test_worker_failure_cannot_reach_unsandboxed_execution(self):
        engine = _make_engine_with_code("raise RuntimeError('worker failure')")
        agent = _worker_agent(engine)

        result = agent.run("execute generated code")

        assert result.metadata["error_code"] == "RLM_SANDBOX_UNAVAILABLE"
        assert result.metadata["security_denied"] is True
        assert engine.generate.call_count == 0

    def test_worker_unknown_outcome_cannot_start_without_sandbox(self):
        engine = _make_engine_with_code("print('unreachable')")
        agent = _worker_agent(engine)
        result = agent.run("execute generated code")

        assert result.metadata["error_code"] == "RLM_SANDBOX_UNAVAILABLE"
        assert result.metadata["security_denied"] is True
        assert engine.generate.call_count == 0

    def test_worker_helper_is_unavailable_before_sandbox(self):
        engine = _make_engine_with_code("llm_query('not available')")
        agent = _worker_agent(engine)

        result = agent.run("execute generated code")

        assert result.metadata["error_code"] == "RLM_SANDBOX_UNAVAILABLE"
        assert result.metadata["security_denied"] is True
        assert engine.generate.call_count == 0

    def test_worker_and_legacy_modes_cannot_be_combined(self):
        with pytest.raises(ValueError):
            RLMAgent(
                _make_engine(),
                "test-model",
                execution_mode="worker",
                allow_unsafe_legacy_repl=True,
            )


class TestRLMLegacyExecution:
    @pytest.mark.parametrize(
        "code",
        [
            "FINAL('must not run')",
            "result = 42\nFINAL_VAR('result')",
            "open('must-not-exist', 'w')",
            "llm_query('must not dispatch')",
        ],
    )
    def test_legacy_execution_is_denied_before_model_generation(self, code):
        engine = _make_engine_with_code(code)

        result = _legacy_agent(engine).run("execute generated code")

        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
        assert result.metadata["security_denied"] is True
        assert result.tool_results[0].success is False
        assert engine.generate.call_count == 0


class TestRLMContextInjection:
    def test_context_from_metadata(self):
        engine = _make_engine("The answer is 42.")
        agent = RLMAgent(engine, "test-model")
        ctx = AgentContext(metadata={"context": "Some long document text."})
        result = agent.run("Summarize", context=ctx)
        assert result.content == "The answer is 42."

    def test_context_from_memory_results(self):
        engine = _make_engine("Summary.")
        agent = RLMAgent(engine, "test-model")
        ctx = AgentContext(memory_results=["chunk1", "chunk2"])
        result = agent.run("Summarize", context=ctx)
        assert result.content == "Summary."


class TestRLMSubLMCalls:
    def test_sub_lm_called_from_repl(self):
        engine = _make_engine_with_code("llm_query('must not dispatch')")

        result = _legacy_agent(engine).run("Calculate")

        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
        assert engine.generate.call_count == 0


class TestRLMMultiTurn:
    def test_multi_turn_loop(self):
        engine = _make_engine_with_code("x = 10\nprint(x)")

        result = _legacy_agent(engine).run("Calculate")

        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
        assert engine.generate.call_count == 0

    def test_max_turns_exceeded(self):
        engine = _make_engine_with_code("print('looping')")

        result = _legacy_agent(engine, max_turns=3).run("Loop")

        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
        assert engine.generate.call_count == 0

    def test_max_turns_with_partial_answer(self):
        engine = _make_engine_with_code("answer['value'] = 'partial'")

        result = _legacy_agent(engine, max_turns=2).run("Work")

        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
        assert engine.generate.call_count == 0


class TestRLMEventBus:
    def test_agent_events(self):
        bus = EventBus(record_history=True)
        engine = _make_engine("Direct answer.")
        agent = RLMAgent(engine, "test-model", bus=bus)
        agent.run("Hello")
        event_types = [e.event_type for e in bus.history]
        assert EventType.AGENT_TURN_START in event_types
        assert EventType.AGENT_TURN_END in event_types

    def test_agent_events_with_code(self):
        bus = EventBus(record_history=True)
        engine = _make_engine_with_code("FINAL('done')")
        agent = _legacy_agent(engine, "test-model", bus=bus)

        result = agent.run("Test")

        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
        assert engine.generate.call_count == 0
        event_types = [e.event_type for e in bus.history]
        assert event_types == []


class TestRLMSubLMWithTools:
    def test_sub_lm_tool_resolution(self):
        engine = _make_engine_with_code("llm_query('must not dispatch')")
        agent = _legacy_agent(engine, tools=[_CalcStub()])

        result = agent.run("Calculate")

        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
        assert engine.generate.call_count == 0


class TestRLMDirectToolBridge:
    def test_root_repl_can_use_file_read_tool_directly(self):
        engine = _make_engine_with_code('file_read("rust/Cargo.toml")')
        agent = _legacy_agent(engine, tools=[_FileReadStub()])

        result = agent.run("Read Cargo")
        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
        assert engine.generate.call_count == 0

    def test_root_repl_can_use_bounded_read_helper(self):
        engine = _make_engine_with_code('read_file("long.txt", max_lines=2)')
        agent = _legacy_agent(engine, tools=[_FileReadStub()])

        result = agent.run("Read file head")
        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
        assert engine.generate.call_count == 0

    def test_root_repl_can_use_file_chunk_helper(self):
        engine = _make_engine_with_code('read_file_chunk("long.txt", 2, 4)')
        agent = _legacy_agent(engine, tools=[_FileReadStub()])

        result = agent.run("Read file chunk")
        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
        assert engine.generate.call_count == 0


class TestRLMBlockedCode:
    def test_blocked_code_returns_error(self):
        engine = _make_engine_with_code("os.system('ls')")
        agent = _legacy_agent(engine)

        result = agent.run("Test")
        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
        assert result.tool_results[0].success is False
        assert engine.generate.call_count == 0


class TestRLMToolSectionInjection:
    """Verify that tool descriptions are injected into the RLM system prompt."""

    def test_system_prompt_includes_tool_section(self):
        """Tools provided -> system prompt includes descriptions."""
        engine = _make_engine("Direct answer.")
        agent = RLMAgent(engine, "test-model", tools=[_CalcStub()])
        agent.run("Hello")
        call_args = engine.generate.call_args
        messages = call_args[0][0]
        system_msg = messages[0].content
        assert "## Available Tools" in system_msg
        assert "### calculator" in system_msg
        assert "expression" in system_msg

    def test_system_prompt_no_tool_section_without_tools(self):
        """No tools -> system prompt has no tool section."""
        engine = _make_engine("Direct answer.")
        agent = RLMAgent(engine, "test-model")
        agent.run("Hello")
        call_args = engine.generate.call_args
        messages = call_args[0][0]
        system_msg = messages[0].content
        assert "## Available Tools" not in system_msg


class TestRLMReplResults:
    def test_repl_results_in_tool_results(self):
        engine = _make_engine_with_code("print('hello')")
        agent = _legacy_agent(engine)

        result = agent.run("Test")

        assert len(result.tool_results) == 1
        assert result.tool_results[0].tool_name == "rlm_repl"
        assert result.tool_results[0].success is False
        assert result.tool_results[0].metadata["error_code"] == "RLM_LEGACY_DISABLED"
        assert engine.generate.call_count == 0


class TestRLMReplResultClassification:
    def _tool(self):
        return _RLMReplTool(RLMRepl(allow_unsafe_legacy=True))

    def test_import_failure_is_not_success(self):
        result = self._tool().execute(code="import os")

        assert result.success is False
        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
        assert "RLM_LEGACY_DISABLED" in result.content

    def test_runtime_failure_is_not_success(self):
        result = self._tool().execute(code="1 / 0")

        assert result.success is False
        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"

    def test_error_like_stdout_remains_success(self):
        result = self._tool().execute(code="print('ImportError: harmless text')")

        assert result.success is False
        assert result.metadata["error_code"] == "RLM_LEGACY_DISABLED"
