"""OrchestratorAgent — multi-turn agent with tool-calling loop.

Supports two modes:

- **function_calling** (default): Uses OpenAI-format tool definitions and
  parses ``tool_calls`` from the engine response.
- **structured**: Uses a THOUGHT/TOOL/INPUT/FINAL_ANSWER text format
  (like ReAct) with a canonical system prompt from the orchestrator
  prompt registry.  This is the format used by the SFT/GRPO training
  pipelines, making the Orchestrator a distinctive trainable agent type.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import re
from typing import Any, Callable, List, Optional

from openjarvis.agents._stubs import AgentContext, AgentResult, ToolUsingAgent
from openjarvis.agents.proposals import ProposalDecision, ToolExecutionProposal
from openjarvis.core.artifacts import clean_artifact_references
from openjarvis.core.events import EventBus
from openjarvis.core.execution import (
    ExecutionOutcome,
    ExecutionState,
    FailureKind,
    ModelCapabilityError,
    ToolRequirement,
)
from openjarvis.core.registry import AgentRegistry
from openjarvis.core.types import Message, Role, ToolCall, ToolResult
from openjarvis.engine._stubs import InferenceEngine
from openjarvis.tools._stubs import BaseTool

logger = logging.getLogger(__name__)


@AgentRegistry.register("orchestrator")
class OrchestratorAgent(ToolUsingAgent):
    """Multi-turn agent that routes between tools and the LLM.

    Implements a tool-calling loop:
    1. Send messages with tool definitions to the engine.
    2. If the response contains tool_calls, execute them and loop.
    3. If no tool_calls, return the final answer.
    4. Stop after ``max_turns`` iterations.

    In **structured** mode the agent instead uses a
    ``THOUGHT: / TOOL: / INPUT: / FINAL_ANSWER:`` text protocol
    identical to the format used by the orchestrator SFT/GRPO
    training pipelines.
    """

    agent_id = "orchestrator"
    supports_required_native_tools = True
    _default_temperature = 0.7
    _default_max_tokens = 1024
    _default_max_turns = 10

    def __init__(
        self,
        engine: InferenceEngine,
        model: str,
        *,
        tools: Optional[List[BaseTool]] = None,
        bus: Optional[EventBus] = None,
        max_turns: Optional[int] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        mode: str = "function_calling",
        system_prompt: Optional[str] = None,
        prompt_builder: Optional[Any] = None,
        parallel_tools: bool = True,
        interactive: bool = False,
        confirm_callback=None,
        capability_policy: Optional[Any] = None,
        agent_id: Optional[str] = None,
        rate_limiter: Optional[Any] = None,
        before_tool_call: Optional[Callable[[str, dict[str, Any]], bool]] = None,
        tool_requirement: ToolRequirement = ToolRequirement.OPTIONAL,
    ) -> None:
        super().__init__(
            engine,
            model,
            tools=tools,
            bus=bus,
            max_turns=max_turns,
            temperature=temperature,
            max_tokens=max_tokens,
            interactive=interactive,
            confirm_callback=confirm_callback,
            prompt_builder=prompt_builder,
            capability_policy=capability_policy,
            agent_id=agent_id,
            rate_limiter=rate_limiter,
        )
        self._mode = mode
        self._system_prompt = system_prompt
        self._parallel_tools = parallel_tools
        self._before_tool_call = before_tool_call
        self._tool_requirement = ToolRequirement(tool_requirement)

    def run(
        self,
        input: str,
        context: Optional[AgentContext] = None,
        **kwargs: Any,
    ) -> AgentResult:
        if self._mode == "structured":
            if self._tool_requirement == ToolRequirement.REQUIRED_NATIVE:
                raise ModelCapabilityError(
                    "Required native tool mode is incompatible with structured mode"
                )
            return self._run_structured(input, context, **kwargs)
        return self._run_function_calling(input, context, **kwargs)

    # ------------------------------------------------------------------
    # Governance hook
    # ------------------------------------------------------------------

    @staticmethod
    def _governance_denial(tool_name: str, reason: str) -> ToolResult:
        return ToolResult(
            tool_name=tool_name,
            content=(
                f"[Governance] Tool '{tool_name}' was not approved ({reason}). "
                "Adjust your plan and try a different approach."
            ),
            success=False,
        )

    def _check_tool_allowed(self, tc: ToolCall) -> Optional[ToolResult]:
        """Call before_tool_call hook if set.

        Returns None to allow execution, or a denial ToolResult to inject
        instead of running the tool. Invalid arguments and hook failures deny
        execution so a governance integration cannot fail open.
        """
        if self._before_tool_call is None:
            return None

        try:
            tool_args = json.loads(tc.arguments) if tc.arguments else {}
        except (json.JSONDecodeError, TypeError):
            return self._governance_denial(tc.name, "invalid tool arguments")
        if not isinstance(tool_args, dict):
            return self._governance_denial(tc.name, "tool arguments are not an object")

        try:
            allowed = self._before_tool_call(tc.name, tool_args)
        except Exception:
            logger.exception("before_tool_call hook failed for tool %s", tc.name)
            return self._governance_denial(tc.name, "governance check failed")
        if allowed:
            return None
        return self._governance_denial(tc.name, "policy denied the call")

    @staticmethod
    def _managed_mutation_context(
        context: Optional[AgentContext], call: ToolCall, effect: str
    ) -> Any:
        if effect == "READ_ONLY" or context is None:
            return None
        resolver = context.metadata.get("managed_mutation_context")
        return resolver(call) if callable(resolver) else None

    @staticmethod
    def _managed_proposal_decision(
        context: Optional[AgentContext],
        call: ToolCall,
        effect: str,
        model_turn: int,
    ) -> ProposalDecision | None:
        if context is None:
            return None
        resolver = context.metadata.get("managed_proposal_boundary")
        if not callable(resolver):
            return None
        proposal = ToolExecutionProposal.from_tool_call(
            call, model_turn=model_turn
        )
        return resolver(proposal, effect=effect)

    @staticmethod
    def _proposal_denial(
        call: ToolCall, decision: ProposalDecision | None
    ) -> ToolResult | None:
        if decision is None or decision.allowed:
            return None
        outcome = ExecutionOutcome(
            ExecutionState.NOT_STARTED,
            FailureKind.PRECONDITION,
            call_id=call.id,
        )
        return ToolResult(
            tool_name=call.name,
            content=decision.message or f"{decision.code}: proposal blocked",
            success=False,
            metadata={
                "proposal": {
                    "provider_call_id": call.id,
                    "failure": decision.code,
                },
                "plan": {
                    "failure": decision.code,
                    "mutation_dispatched": False,
                },
                "execution": outcome.to_dict(),
            },
        )

    @staticmethod
    def _managed_step_snapshot(
        context: Optional[AgentContext], call: ToolCall, result: Optional[ToolResult]
    ) -> dict[str, Any] | None:
        if context is None:
            return None
        if result is None:
            synchronizer = context.metadata.get("managed_mutation_sync")
            if callable(synchronizer):
                synchronizer()
        recorder = context.metadata.get("managed_mutation_result")
        if result is not None and callable(recorder):
            recorder(call, result)
        provider = context.metadata.get("managed_mutation_snapshot")
        snapshot = provider() if callable(provider) else None
        return dict(snapshot) if isinstance(snapshot, dict) else None

    # ------------------------------------------------------------------
    # Structured mode (THOUGHT/TOOL/INPUT/FINAL_ANSWER)
    # ------------------------------------------------------------------

    def _run_structured(
        self,
        input: str,
        context: Optional[AgentContext] = None,
        **kwargs: Any,
    ) -> AgentResult:
        self._emit_turn_start(input)

        # Build system prompt
        if self._system_prompt:
            sys_prompt = self._system_prompt
        else:
            from openjarvis.learning.intelligence.orchestrator.prompt_registry import (
                build_system_prompt,
            )

            sys_prompt = build_system_prompt(tools=self._tools)

        messages = self._build_messages(input, context, system_prompt=sys_prompt)
        checkpoint = (
            context.metadata.get("managed_checkpoint") if context is not None else None
        )
        cancel_requested = (
            context.metadata.get("managed_cancel_requested")
            if context is not None
            else None
        )

        def _cancelled() -> bool:
            return bool(cancel_requested()) if callable(cancel_requested) else False

        def _cancel_result(
            call: ToolCall | None = None,
            effect: str = "READ_ONLY",
            result: ToolResult | None = None,
        ) -> AgentResult:
            execution = (result.metadata or {}).get("execution", {}) if result else {}
            if (
                call is not None
                and effect != "READ_ONLY"
                and execution.get("state") == "EXECUTED"
            ):
                return AgentResult(
                    content=(
                        "Cancellation reached a boundary before mutation verification."
                    ),
                    metadata={
                        "recovery_required": True,
                        "recovery_reason": (
                            "cancellation interrupted post-action verification"
                        ),
                        "cancellation_verification_required": True,
                        "active_step": {
                            "tool": call.name,
                            "call_id": call.id,
                            "journal_token": execution.get("journal_token"),
                            "effect": effect,
                            "state": "EXECUTED",
                            "execution_state": "EXECUTED",
                        },
                    },
                )
            return AgentResult(
                content="Cancellation reached a safe execution boundary.",
                metadata={"cancelled": True},
            )
        completed_steps = list(
            context.metadata.get("managed_completed_steps", [])
            if context is not None
            else []
        )
        if context is not None and context.metadata.get("managed_resume"):
            if messages and messages[-1].role == Role.USER and not messages[-1].text:
                messages.pop()
        if callable(checkpoint):
            checkpoint(
                messages,
                {
                    "active_step": {"state": "NOT_STARTED"},
                    "completed_steps": completed_steps,
                },
            )

        def _record_structured_step(
            snapshot: list[Message],
            call: ToolCall,
            state: str,
            result: Optional[ToolResult] = None,
            *,
            effect: str = "UNKNOWN",
        ) -> None:
            if not callable(checkpoint):
                return
            active = {
                "call_id": call.id,
                "tool": call.name,
                "effect": effect,
                "state": state,
            }
            if result is None and effect != "READ_ONLY":
                # Create the controller-owned intent before the first
                # PREPARED checkpoint.  A crash between authorization and
                # dispatch then restores the same identity instead of
                # generating an unrelated intent on resume.
                self._managed_mutation_context(context, call, effect)
            semantic = self._managed_step_snapshot(context, call, result)
            if semantic is not None:
                active.update(
                    {
                        key: semantic[key]
                        for key in ("execution_id", "step_id", "mutation_intent_id")
                    }
                )
                active["semantic_status"] = semantic["status"]
            next_completed = completed_steps
            if result is not None:
                execution = (result.metadata or {}).get("execution", {})
                execution_state = execution.get("state", state)
                active["execution_state"] = execution_state
                if execution.get("journal_token"):
                    active["journal_token"] = execution["journal_token"]
                if result.success and execution_state == "VERIFIED":
                    artifacts = clean_artifact_references(
                        (result.metadata or {}).get("artifacts")
                    )
                    if artifacts:
                        active["artifacts"] = artifacts
                if (result.metadata or {}).get("timeout"):
                    active["timeout"] = result.metadata["timeout"]
                if not result.success and execution_state != "UNKNOWN_OUTCOME":
                    active["state"] = "FAILED"
                next_completed = [*completed_steps, dict(active)]
            checkpoint(
                snapshot,
                {"active_step": active, "completed_steps": next_completed},
            )
            if result is not None:
                completed_steps.append(dict(active))

        all_tool_results: list[ToolResult] = []
        turns = 0

        for _turn in range(self._max_turns):
            turns += 1

            if _cancelled():
                self._emit_turn_end(turns=turns - 1)
                return _cancel_result()

            if self._loop_guard:
                prior_messages = messages
                messages = self._loop_guard.compress_context(messages)
                if messages is not prior_messages and callable(checkpoint):
                    checkpoint(
                        messages,
                        {
                            "active_step": {"state": "NOT_STARTED"},
                            "completed_steps": completed_steps,
                        },
                    )

            result = self._generate(messages)
            if _cancelled():
                self._emit_turn_end(turns=turns)
                return _cancel_result()
            content = result.get("content", "")

            parsed = self._parse_structured_response(content)

            # FINAL_ANSWER -> done
            if parsed["final_answer"]:
                if callable(checkpoint):
                    checkpoint(
                        messages,
                        {
                            "active_step": {"state": "NOT_STARTED"},
                            "completed_steps": completed_steps,
                        },
                    )
                self._emit_turn_end(turns=turns)
                return AgentResult(
                    content=parsed["final_answer"],
                    tool_results=all_tool_results,
                    turns=turns,
                )

            # TOOL -> execute
            if parsed["tool"]:
                base_messages = list(messages)
                messages.append(Message(role=Role.ASSISTANT, content=content))

                tool_call = ToolCall(
                    id=f"orch_{turns}",
                    name=parsed["tool"],
                    arguments=self._normalize_structured_tool_input(
                        parsed["tool"],
                        parsed["input"],
                    ),
                )
                denial = self._check_tool_allowed(tool_call)
                tool = getattr(self._executor, "_tools", {}).get(tool_call.name)
                effect = getattr(getattr(tool, "spec", None), "effect", "UNKNOWN")
                effect = getattr(effect, "value", effect)
                proposal_decision = self._managed_proposal_decision(
                    context, tool_call, str(effect), turns
                )
                proposal_denial = self._proposal_denial(
                    tool_call, proposal_decision
                )
                if denial is None and proposal_denial is not None:
                    denial = proposal_denial
                checkpointed_result = False

                def _on_execution_state(
                    state: str,
                    result: Optional[ToolResult],
                ) -> None:
                    nonlocal checkpointed_result
                    if result is None:
                        _record_structured_step(
                            base_messages,
                            tool_call,
                            state,
                            effect=str(effect),
                        )
                        return
                    observation_text = (
                        f"Observation: {result.content}"
                        if result.success
                        else (
                            f"Observation: Tool '{result.tool_name}' failed: "
                            f"{result.content}"
                        )
                    )
                    snapshot = [
                        *base_messages,
                        messages[-1],
                        Message(
                            role=Role.USER,
                            content=observation_text,
                            name=tool_call.name,
                            tool_call_id=tool_call.id,
                        ),
                    ]
                    _record_structured_step(
                        snapshot,
                        tool_call,
                        state,
                        result,
                        effect=str(effect),
                    )
                    checkpointed_result = True

                if denial is not None:
                    tool_result = denial
                else:
                    _record_structured_step(
                        base_messages,
                        tool_call,
                        "PREPARED",
                        effect=str(effect),
                    )
                    mutation_context = (
                        proposal_decision.mutation_context
                        if proposal_decision is not None
                        else self._managed_mutation_context(
                            context, tool_call, str(effect)
                        )
                    )
                    tool_result = self._executor.execute(
                        tool_call,
                        checkpoint_callback=(
                            _on_execution_state if callable(checkpoint) else None
                        ),
                        mutation_context=mutation_context,
                    )
                if callable(checkpoint) and not checkpointed_result:
                    _on_execution_state(
                        (tool_result.metadata or {})
                        .get("execution", {})
                        .get("state", "NOT_STARTED"),
                        tool_result,
                    )
                all_tool_results.append(tool_result)

                if tool_result.success:
                    observation = f"Observation: {tool_result.content}"
                else:
                    observation = (
                        f"Observation: Tool '{tool_result.tool_name}' failed: "
                        f"{tool_result.content}"
                    )
                messages.append(
                    Message(
                        role=Role.USER,
                        content=observation,
                        name=tool_call.name,
                        tool_call_id=tool_call.id,
                    )
                )
                if (tool_result.metadata or {}).get("execution", {}).get(
                    "state"
                ) == "UNKNOWN_OUTCOME":
                    self._emit_turn_end(turns=turns)
                    return AgentResult(
                        content=(
                            "Execution stopped for recovery: a tool outcome is "
                            "unknown and must be reconciled before continuing."
                        ),
                        tool_results=all_tool_results,
                        turns=turns,
                        metadata={
                            "recovery_required": True,
                            "active_step": {
                                "tool": tool_call.name,
                                "call_id": tool_call.id,
                                "state": "UNKNOWN_OUTCOME",
                            },
                        },
                    )
                if _cancelled() or (tool_result.metadata or {}).get("cancelled"):
                    self._emit_turn_end(turns=turns)
                    return _cancel_result(tool_call, str(effect), tool_result)
                continue

            # Neither -> treat content as final answer
            self._emit_turn_end(turns=turns)
            return AgentResult(
                content=content,
                tool_results=all_tool_results,
                turns=turns,
            )

        # Max turns exceeded
        return self._max_turns_result(all_tool_results, turns)

    def _normalize_structured_tool_input(
        self,
        tool_name: str,
        raw_input: str,
    ) -> str:
        """Map unambiguous structured text input to a string parameter."""
        if not raw_input:
            return "{}"

        try:
            parsed_input = json.loads(raw_input)
        except json.JSONDecodeError:
            invalid_json = True
            string_value = raw_input
        else:
            invalid_json = False
            if isinstance(parsed_input, dict):
                return raw_input
            # INPUT is a text protocol. A non-object JSON value such as 42,
            # true, null, or [1, 2] may still be the intended text for a tool's
            # string parameter. Quoted JSON strings are decoded to remove only
            # their surrounding quotes; other values retain their source text.
            string_value = parsed_input if isinstance(parsed_input, str) else raw_input

        tool_spec = None
        for candidate in reversed(self._tools):
            candidate_spec = candidate.spec
            if candidate_spec.name == tool_name:
                tool_spec = candidate_spec
                break
        if tool_spec is None:
            return raw_input

        parameters = tool_spec.parameters
        parameter_container_type = parameters.get("type")
        if parameter_container_type not in (None, "object"):
            return raw_input

        properties = parameters.get("properties", {})
        required = parameters.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            return raw_input

        if len(required) == 1 and required[0] in properties:
            parameter_name = required[0]
        elif not required and len(properties) == 1:
            parameter_name = next(iter(properties))
        else:
            return raw_input

        parameter_schema = properties[parameter_name]
        if not isinstance(parameter_schema, dict):
            return raw_input
        parameter_type = parameter_schema.get("type")
        accepts_string = parameter_type == "string" or (
            isinstance(parameter_type, list) and "string" in parameter_type
        )
        if not accepts_string:
            return raw_input

        allow_object_text = (
            tool_spec.metadata.get("structured_allow_object_text") is True
        )
        starts_like_object = raw_input.lstrip("\ufeff \t\r\n").startswith("{")
        if invalid_json and starts_like_object and not allow_object_text:
            return raw_input

        return json.dumps({parameter_name: string_value})

    @staticmethod
    def _parse_structured_response(text: str) -> dict:
        """Parse THOUGHT/TOOL/INPUT/FINAL_ANSWER from model output."""
        result = {
            "thought": "",
            "tool": "",
            "input": "",
            "final_answer": "",
        }

        thought_match = re.search(
            r"THOUGHT:\s*(.+?)(?=\nTOOL:|\nFINAL[_ ]?ANSWER:|\Z)",
            text,
            re.DOTALL | re.IGNORECASE,
        )
        if thought_match:
            result["thought"] = thought_match.group(1).strip()

        final_match = re.search(
            r"FINAL[_ ]?ANSWER:\s*(.+)",
            text,
            re.DOTALL | re.IGNORECASE,
        )
        if final_match:
            result["final_answer"] = final_match.group(1).strip()
            return result

        tool_match = re.search(r"TOOL:\s*(.+)", text, re.IGNORECASE)
        if tool_match:
            result["tool"] = tool_match.group(1).strip()

        input_match = re.search(
            r"INPUT:\s*(.+?)(?=\nTHOUGHT:|\nTOOL:|\nFINAL|\Z)",
            text,
            re.DOTALL | re.IGNORECASE,
        )
        if input_match:
            result["input"] = input_match.group(1).strip()

        return result

    # ------------------------------------------------------------------
    # Function-calling mode (original behaviour)
    # ------------------------------------------------------------------

    def _run_function_calling(
        self,
        input: str,
        context: Optional[AgentContext] = None,
        **kwargs: Any,
    ) -> AgentResult:
        self._emit_turn_start(input)

        # Build initial messages
        messages = self._build_messages(
            input,
            context,
            system_prompt=self._system_prompt,
        )
        checkpoint = (
            context.metadata.get("managed_checkpoint") if context is not None else None
        )
        cancel_requested = (
            context.metadata.get("managed_cancel_requested")
            if context is not None
            else None
        )

        def _cancelled() -> bool:
            return bool(cancel_requested()) if callable(cancel_requested) else False

        def _cancel_result(
            call: ToolCall | None = None,
            effect: str = "READ_ONLY",
            result: ToolResult | None = None,
        ) -> AgentResult:
            execution = (result.metadata or {}).get("execution", {}) if result else {}
            if (
                call is not None
                and effect != "READ_ONLY"
                and execution.get("state") == "EXECUTED"
            ):
                return AgentResult(
                    content=(
                        "Cancellation reached a boundary before mutation verification."
                    ),
                    metadata={
                        "recovery_required": True,
                        "recovery_reason": (
                            "cancellation interrupted post-action verification"
                        ),
                        "cancellation_verification_required": True,
                        "active_step": {
                            "tool": call.name,
                            "call_id": call.id,
                            "journal_token": execution.get("journal_token"),
                            "effect": effect,
                            "state": "EXECUTED",
                            "execution_state": "EXECUTED",
                        },
                    },
                )
            return AgentResult(
                content="Cancellation reached a safe execution boundary.",
                metadata={"cancelled": True},
            )
        completed_steps = list(
            context.metadata.get("managed_completed_steps", [])
            if context is not None
            else []
        )
        if context is not None and context.metadata.get("managed_resume"):
            if messages and messages[-1].role == Role.USER and not messages[-1].text:
                messages.pop()
        if callable(checkpoint):
            checkpoint(
                messages,
                {
                    "active_step": {"state": "NOT_STARTED"},
                    "completed_steps": completed_steps,
                },
            )

        def _record_step(
            snapshot: list[Message],
            call: ToolCall,
            state: str,
            result: Optional[ToolResult] = None,
            *,
            effect: str = "UNKNOWN",
        ) -> None:
            if not callable(checkpoint):
                return
            active = {
                "call_id": call.id,
                "tool": call.name,
                "effect": effect,
                "state": state,
            }
            if result is None and effect != "READ_ONLY":
                self._managed_mutation_context(context, call, effect)
            semantic = self._managed_step_snapshot(context, call, result)
            if semantic is not None:
                active.update(
                    {
                        key: semantic[key]
                        for key in ("execution_id", "step_id", "mutation_intent_id")
                    }
                )
                active["semantic_status"] = semantic["status"]
            if result is not None:
                execution = (result.metadata or {}).get("execution", {})
                execution_state = execution.get("state", state)
                active["execution_state"] = execution_state
                if execution.get("journal_token"):
                    active["journal_token"] = execution["journal_token"]
                if result.success and execution_state == "VERIFIED":
                    artifacts = clean_artifact_references(
                        (result.metadata or {}).get("artifacts")
                    )
                    if artifacts:
                        active["artifacts"] = artifacts
                if (result.metadata or {}).get("timeout"):
                    active["timeout"] = result.metadata["timeout"]
                if not result.success and execution_state != "UNKNOWN_OUTCOME":
                    active["state"] = "FAILED"
                next_completed = [*completed_steps, dict(active)]
            else:
                next_completed = completed_steps
            checkpoint(
                snapshot,
                {"active_step": active, "completed_steps": next_completed},
            )
            if result is not None:
                completed_steps.append(dict(active))

        # Get OpenAI-format tool definitions
        openai_tools = self._executor.get_openai_tools() if self._tools else []

        all_tool_results: list[ToolResult] = []
        turns = 0
        total_prompt_tokens = 0
        total_completion_tokens = 0
        native_tool_call_seen = False

        for _turn in range(self._max_turns):
            turns += 1

            if _cancelled():
                self._emit_turn_end(turns=turns - 1)
                return _cancel_result()

            if self._loop_guard:
                prior_messages = messages
                messages = self._loop_guard.compress_context(messages)
                if messages is not prior_messages and callable(checkpoint):
                    checkpoint(
                        messages,
                        {
                            "active_step": {"state": "NOT_STARTED"},
                            "completed_steps": completed_steps,
                        },
                    )

            # Build generate kwargs
            gen_kwargs: dict[str, Any] = {}
            if openai_tools:
                gen_kwargs["tools"] = openai_tools
            gen_kwargs["tool_requirement"] = self._tool_requirement

            result = self._generate(messages, **gen_kwargs)
            if _cancelled():
                self._emit_turn_end(turns=turns)
                return _cancel_result()

            # Accumulate token usage
            usage = result.get("usage", {})
            total_prompt_tokens += usage.get("prompt_tokens", 0)
            total_completion_tokens += usage.get("completion_tokens", 0)

            content = result.get("content", "")
            raw_tool_calls = result.get("tool_calls", [])

            # No tool calls -> check continuation, then final answer
            if not raw_tool_calls:
                if (
                    self._tool_requirement == ToolRequirement.REQUIRED_NATIVE
                    and not native_tool_call_seen
                ):
                    raise ModelCapabilityError(
                        "Required native tool call was not returned by the model"
                    )
                content = self._check_continuation(result, messages)
                content = self._strip_think_tags(content)
                if callable(checkpoint):
                    checkpoint(
                        messages,
                        {
                            "active_step": {"state": "NOT_STARTED"},
                            "completed_steps": completed_steps,
                        },
                    )
                self._emit_turn_end(turns=turns, content_length=len(content))
                return AgentResult(
                    content=content,
                    tool_results=all_tool_results,
                    turns=turns,
                    metadata={
                        "prompt_tokens": total_prompt_tokens,
                        "completion_tokens": total_completion_tokens,
                        "total_tokens": total_prompt_tokens + total_completion_tokens,
                    },
                )

            # Build ToolCall objects from raw dicts
            tool_calls = [
                ToolCall(
                    id=tc.get("id", f"call_{i}"),
                    name=tc.get("name", ""),
                    arguments=tc.get("arguments", "{}"),
                )
                for i, tc in enumerate(raw_tool_calls)
            ]
            native_tool_call_seen = True

            # Append assistant message with tool calls
            messages.append(
                Message(
                    role=Role.ASSISTANT,
                    content=content,
                    tool_calls=tool_calls,
                )
            )

            # Execute each tool (with loop guard check) and append results
            if (
                self._parallel_tools
                and len(tool_calls) > 1
                and not callable(checkpoint)
            ):
                # Governance callbacks often wrap stateful policy engines and
                # are not assumed to be thread-safe. Evaluate them in request
                # order before dispatching the approved tool work in parallel.
                results_map: dict[int, tuple[ToolCall, ToolResult]] = {}
                approved_calls: list[ToolCall] = []
                for tc in tool_calls:
                    denial = self._check_tool_allowed(tc)
                    if denial is None:
                        approved_calls.append(tc)
                    else:
                        results_map[id(tc)] = (tc, denial)

                def _exec_tool(tc: ToolCall) -> tuple:
                    if self._loop_guard:
                        verdict = self._loop_guard.check_call(
                            tc.name,
                            tc.arguments,
                        )
                        if verdict.blocked:
                            return tc, ToolResult(
                                tool_name=tc.name,
                                content=f"Loop guard: {verdict.reason}",
                                success=False,
                            )
                    return tc, self._executor.execute(tc)

                if approved_calls:
                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=len(approved_calls),
                    ) as pool:
                        futures = {
                            pool.submit(_exec_tool, tc): tc for tc in approved_calls
                        }
                        for future in concurrent.futures.as_completed(futures):
                            tc_orig = futures[future]
                            results_map[id(tc_orig)] = future.result()

                # Append results in original order
                for tc in tool_calls:
                    _, tool_result = results_map[id(tc)]
                    all_tool_results.append(tool_result)
                    messages.append(
                        Message(
                            role=Role.TOOL,
                            content=tool_result.content,
                            tool_call_id=tc.id,
                            name=tc.name,
                        )
                    )
            else:
                # Sequential execution
                for tc in tool_calls:
                    if _cancelled():
                        self._emit_turn_end(turns=turns)
                        return _cancel_result()
                    # Governance hook check before execution
                    denial = self._check_tool_allowed(tc)
                    if denial is not None:
                        base_messages = messages[:-1]
                        _record_step(
                            [
                                *base_messages,
                                messages[-1],
                                Message(
                                    role=Role.TOOL,
                                    content=denial.content,
                                    tool_call_id=tc.id,
                                    name=tc.name,
                                ),
                            ],
                            tc,
                            "NOT_STARTED",
                            denial,
                        )
                        all_tool_results.append(denial)
                        messages.append(
                            Message(
                                role=Role.TOOL,
                                content=denial.content,
                                tool_call_id=tc.id,
                                name=tc.name,
                            )
                        )
                        continue

                    # Loop guard check before execution
                    if self._loop_guard:
                        verdict = self._loop_guard.check_call(
                            tc.name,
                            tc.arguments,
                        )
                        if verdict.blocked:
                            tool_result = ToolResult(
                                tool_name=tc.name,
                                content=f"Loop guard: {verdict.reason}",
                                success=False,
                            )
                            _record_step(
                                [
                                    *messages[:-1],
                                    messages[-1],
                                    Message(
                                        role=Role.TOOL,
                                        content=tool_result.content,
                                        tool_call_id=tc.id,
                                        name=tc.name,
                                    ),
                                ],
                                tc,
                                "NOT_STARTED",
                                tool_result,
                            )
                            all_tool_results.append(tool_result)
                            messages.append(
                                Message(
                                    role=Role.TOOL,
                                    content=tool_result.content,
                                    tool_call_id=tc.id,
                                    name=tc.name,
                                )
                            )
                            continue

                    tool = getattr(self._executor, "_tools", {}).get(tc.name)
                    effect = getattr(getattr(tool, "spec", None), "effect", "UNKNOWN")
                    effect = getattr(effect, "value", effect)
                    base_messages = messages[:-1]
                    checkpointed_result = False
                    proposal_decision = self._managed_proposal_decision(
                        context, tc, str(effect), turns
                    )
                    proposal_denial = self._proposal_denial(tc, proposal_decision)

                    if proposal_denial is not None:
                        snapshot = [
                            *base_messages,
                            messages[-1],
                            Message(
                                role=Role.TOOL,
                                content=proposal_denial.content,
                                tool_call_id=tc.id,
                                name=tc.name,
                            ),
                        ]
                        _record_step(
                            snapshot,
                            tc,
                            "NOT_STARTED",
                            proposal_denial,
                            effect=str(effect),
                        )
                        all_tool_results.append(proposal_denial)
                        messages.append(
                            Message(
                                role=Role.TOOL,
                                content=proposal_denial.content,
                                tool_call_id=tc.id,
                                name=tc.name,
                            )
                        )
                        continue

                    def _on_execution_state(
                        state: str,
                        result: Optional[ToolResult],
                        *,
                        call: ToolCall = tc,
                        tool_effect: str = str(effect),
                        base: list[Message] = base_messages,
                        assistant: Message = messages[-1],
                    ) -> None:
                        nonlocal checkpointed_result
                        if result is None:
                            _record_step(base, call, state, effect=tool_effect)
                            return
                        snapshot = [
                            *base,
                            assistant,
                            Message(
                                role=Role.TOOL,
                                content=result.content,
                                tool_call_id=call.id,
                                name=call.name,
                            ),
                        ]
                        _record_step(
                            snapshot,
                            call,
                            state,
                            result,
                            effect=tool_effect,
                        )
                        checkpointed_result = True

                    _record_step(
                        base_messages,
                        tc,
                        "PREPARED",
                        effect=str(effect),
                    )
                    mutation_context = self._managed_mutation_context(
                        context, tc, str(effect)
                    )
                    if proposal_decision is not None:
                        mutation_context = proposal_decision.mutation_context
                    tool_result = self._executor.execute(
                        tc,
                        checkpoint_callback=(
                            _on_execution_state if callable(checkpoint) else None
                        ),
                        mutation_context=mutation_context,
                    )
                    if callable(checkpoint) and not checkpointed_result:
                        _on_execution_state(
                            (tool_result.metadata or {})
                            .get("execution", {})
                            .get("state", "NOT_STARTED"),
                            tool_result,
                        )
                    all_tool_results.append(tool_result)

                    # Append tool response message
                    messages.append(
                        Message(
                            role=Role.TOOL,
                            content=tool_result.content,
                            tool_call_id=tc.id,
                            name=tc.name,
                        )
                    )
                    if (tool_result.metadata or {}).get("execution", {}).get(
                        "state"
                    ) == "UNKNOWN_OUTCOME":
                        self._emit_turn_end(turns=turns)
                        return AgentResult(
                            content=(
                                "Execution stopped for recovery: a tool outcome is "
                                "unknown and must be reconciled before continuing."
                            ),
                            tool_results=all_tool_results,
                            turns=turns,
                            metadata={
                                "recovery_required": True,
                                "active_step": {
                                    "tool": tc.name,
                                    "call_id": tc.id,
                                    "state": "UNKNOWN_OUTCOME",
                                },
                            },
                        )
                    if _cancelled() or (tool_result.metadata or {}).get("cancelled"):
                        self._emit_turn_end(turns=turns)
                        return _cancel_result(tc, str(effect), tool_result)

        # Max turns exceeded
        final_content = self._strip_think_tags(content) if content else ""
        self._emit_turn_end(turns=turns, max_turns_exceeded=True)
        return AgentResult(
            content=final_content or "Maximum turns reached without a final answer.",
            tool_results=all_tool_results,
            turns=turns,
            metadata={
                "max_turns_exceeded": True,
                "prompt_tokens": total_prompt_tokens,
                "completion_tokens": total_completion_tokens,
                "total_tokens": total_prompt_tokens + total_completion_tokens,
            },
        )


__all__ = ["OrchestratorAgent"]
