"""Non-physical managed Phase 3C harness for the Windows tool path."""

from __future__ import annotations

import json
import hashlib
import os
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from openjarvis.agents.executor import AgentExecutor, _ManagedMutationController
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.orchestrator import OrchestratorAgent
from openjarvis.agents.plan import DurablePlanNode
from openjarvis.agents.proposals import ToolExecutionProposal
from openjarvis.core.events import EventBus
from openjarvis.core.execution import MutationIntent, ToolEffect, ToolRequirement
from openjarvis.agents.errors import FatalError
from openjarvis.core.registry import AgentRegistry
from openjarvis.tools import _stubs as tool_stubs
from openjarvis.tools._stubs import ToolExecutor
from openjarvis.tools.windows import WindowsActionTool, WindowsObserveTool
from tests.agents.fake_engine import FakeEngine


class _FakeReceiver:
    def __init__(self) -> None:
        self.dispatch_count = 0
        self.wrong_target_dispatch_count = 0
        self.replay_count = 0
        self.pid = 4242
        self.hwnd = 101
        self.control_hwnd = 202
        self.decoy_control_hwnd = 303
        self.expected_executable = "phase3c-test-helper.exe"
        self.expected_window_class = "Phase3CTestWindow"

    def snapshot(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "hwnd": self.hwnd,
            "controls": {"": {"hwnd": self.control_hwnd}},
        }


class _FakeSession:
    """Deterministic substitute for WindowsActionSession; never touches Windows."""

    def __init__(
        self, *, unknown: bool = False, post_dispatch_text: str | None = None
    ) -> None:
        self.receiver = _FakeReceiver()
        self.unknown = unknown
        self.post_dispatch_text = post_dispatch_text
        self.pid = 4242
        self.hwnd = 101
        self.control_hwnd = 202
        self.observation_count = 0
        self._observations: dict[str, dict[str, Any]] = {}
        self.actions: list[dict[str, Any]] = []
        self.text = ""

    def observe(self, hwnd: int) -> dict[str, Any]:
        self.observation_count += 1
        index = self.observation_count
        observation = {
            "observation_id": f"obs-{index}",
            "window": {
                "hwnd": hwnd,
                "pid": self.pid,
                "executable": "phase3c-test-helper.exe",
                "class_name": "Phase3CTestWindow",
            },
            "controls": [
                {
                    "target_id": f"target-{index}",
                    "identity": {
                        "hwnd": self.control_hwnd,
                        "class_name": "Edit",
                        "control_type": 50004,
                        "framework": "Win32",
                        "automation_id": "7",
                        "control_id": 7,
                        "cookie": "edit-cookie",
                    },
                    "name": "Edit",
                    "value": self.text,
                    "enabled": True,
                    "offscreen": False,
                    "value_verifiable": True,
                }
            ],
        }
        self._observations[observation["observation_id"]] = observation
        return observation

    def resolve(self, observation_id: str, **_hints: Any) -> str:
        return f"target-{observation_id.rsplit('-', 1)[-1]}"

    def read_value(self, observation_id: str, target_id: str) -> str:
        observation = self._observations[observation_id]
        if not any(
            control["target_id"] == target_id for control in observation["controls"]
        ):
            raise AssertionError("fake target identity mismatch")
        return self.text

    def state(self) -> dict[str, Any]:
        observation = self.observe(self.hwnd)
        control = observation["controls"][0]
        return {
            "pid": self.pid,
            "hwnd": self.hwnd,
            "control_hwnd": self.control_hwnd,
            "text": self.read_value(
                observation["observation_id"], control["target_id"]
            ),
            "dispatch_count": self.receiver.dispatch_count,
            "expected_control_dispatch_count": self.receiver.dispatch_count,
            "wrong_target_dispatch_count": self.receiver.wrong_target_dispatch_count,
            "last_dispatch_control_hwnd": (
                self.control_hwnd if self.receiver.dispatch_count else 0
            ),
            "decoy_control_hwnd": self.receiver.decoy_control_hwnd,
            "decoy_text": "",
            "foreground": self.hwnd,
            "focus": self.control_hwnd,
            "enabled": control["enabled"],
            "offscreen": control["offscreen"],
            "value_verifiable": control["value_verifiable"],
        }

    def act(
        self,
        action: str,
        observation_id: str,
        target_id: str,
        *,
        value: str = "",
    ) -> dict[str, Any]:
        self.actions.append(
            {
                "action": action,
                "observation_id": observation_id,
                "target_id": target_id,
                "value": value,
            }
        )
        self.receiver.dispatch_count += 1
        if self.unknown:
            return {
                "action": action,
                "observation_id": observation_id,
                "target_id": target_id,
                "identity": {
                    "window": {
                        "hwnd": self.hwnd,
                        "process": {"pid": self.pid},
                    },
                    "control": {"hwnd": self.control_hwnd},
                },
                "preconditions": "PASSED",
                "outcome": "UNKNOWN_OUTCOME",
                "dispatch": "DISPATCHED",
                "verification": "NOT_VERIFIED",
                "retryable": False,
                "failure": "UNKNOWN_OUTCOME",
                "evidence": {},
            }
        self.text = (
            value if self.post_dispatch_text is None else self.post_dispatch_text
        )
        post_observation = self.observe(self.hwnd)
        actual = self.read_value(
            post_observation["observation_id"],
            post_observation["controls"][0]["target_id"],
        )
        identity = {
            "window": {
                "hwnd": post_observation["window"]["hwnd"],
                "process": {"pid": post_observation["window"]["pid"]},
            },
            "control": dict(post_observation["controls"][0]["identity"]),
        }
        if actual != value:
            return {
                "action": action,
                "observation_id": observation_id,
                "target_id": target_id,
                "identity": identity,
                "preconditions": "PASSED",
                "outcome": "UNKNOWN_OUTCOME",
                "dispatch": "DISPATCHED",
                "verification": "NOT_VERIFIED",
                "retryable": False,
                "failure": "UNKNOWN_OUTCOME",
                "evidence": {},
            }
        return {
            "action": action,
            "observation_id": observation_id,
            "target_id": target_id,
            "identity": identity,
            "preconditions": "PASSED",
            "outcome": "VERIFIED",
            "dispatch": "DISPATCHED",
            "verification": "VERIFIED",
            "retryable": False,
            "failure": "NONE",
            "evidence": {
                "value_sha256": hashlib.sha256(value.encode()).hexdigest(),
                "value_length": len(value),
                "post_observation_id": post_observation["observation_id"],
            },
        }


class _FakeForegroundApp:
    def __init__(
        self,
        session: _FakeSession,
        *,
        pid: int | None = None,
        hwnd: int | None = None,
        control_hwnd: int | None = None,
        executable: str | None = None,
        window_class: str | None = None,
        focus_succeeds: bool = True,
    ) -> None:
        receiver = session.receiver
        self.pid = receiver.pid if pid is None else pid
        self.hwnd = receiver.hwnd if hwnd is None else hwnd
        self.control_hwnd = (
            receiver.control_hwnd if control_hwnd is None else control_hwnd
        )
        self.executable = executable or receiver.expected_executable
        self.window_class = window_class or receiver.expected_window_class
        self.focus_succeeds = focus_succeeds
        self.focus_calls = 0
        self._foreground = 0
        self._focus = 0

    def state(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "hwnd": self.hwnd,
            "control_hwnd": self.control_hwnd,
            "foreground": self._foreground,
            "focus": self._focus,
        }

    def focus(self) -> dict[str, Any]:
        self.focus_calls += 1
        if self.focus_succeeds:
            self._foreground = self.hwnd
            self._focus = self.control_hwnd
        return self.state()


class _LateForegroundFailure(RuntimeError):
    pass


_FOREGROUND_OBSERVATION_TIMEOUT_SECONDS = 1.0


@dataclass
class _LateForegroundHook:
    app: Any
    session: Any
    expected_tool: Any | None = None
    expected_value: str = "ASTRA_PHASE3C_CANARY"
    timeout_seconds: float = _FOREGROUND_OBSERVATION_TIMEOUT_SECONDS
    late_foreground_hook_count: int = 0
    focus_request_count: int = 0
    poll_count: int = 0
    identity_match: bool = False
    helper_identity: dict[str, Any] | None = None
    receiver_identity: dict[str, Any] | None = None
    last_state: dict[str, Any] | None = None
    failure: str | None = None

    @staticmethod
    def _state_evidence(state: Any) -> dict[str, Any]:
        if not isinstance(state, dict):
            return {}
        return {
            key: state.get(key)
            for key in ("pid", "hwnd", "control_hwnd", "foreground", "focus")
            if key in state
        }

    def _fail(self, message: str) -> None:
        raise _LateForegroundFailure(message)

    def _validate_identity(
        self, *, tool_call: Any, tool: Any, mutation_context: Any
    ) -> None:
        if self.expected_tool is not None and tool is not self.expected_tool:
            self._fail("TEST_FIXTURE_IDENTITY_FAILURE: unexpected action tool")
        if not isinstance(tool, WindowsActionTool):
            self._fail("TEST_FIXTURE_IDENTITY_FAILURE: unexpected tool type")
        if getattr(tool, "session", None) is not self.session:
            self._fail("TEST_FIXTURE_IDENTITY_FAILURE: unexpected session")
        if getattr(tool.spec, "effect", None) != ToolEffect.MUTATING:
            self._fail("TEST_FIXTURE_IDENTITY_FAILURE: non-mutating action")
        if not isinstance(mutation_context, MutationIntent):
            self._fail("TEST_FIXTURE_IDENTITY_FAILURE: missing MutationIntent")

        raw_arguments = getattr(tool_call, "arguments", None)
        if raw_arguments is None:
            self._fail(
                "TEST_FIXTURE_IDENTITY_FAILURE: missing tool-call arguments "
                f"({type(tool_call).__name__}, tool={type(tool).__name__})"
            )
        try:
            arguments = json.loads(raw_arguments)
        except (TypeError, json.JSONDecodeError) as error:
            self._fail(f"TEST_FIXTURE_IDENTITY_FAILURE: invalid action arguments: {error}")
        if (
            not isinstance(arguments, dict)
            or arguments.get("action") != "type_into"
            or arguments.get("value") != self.expected_value
        ):
            self._fail("TEST_FIXTURE_IDENTITY_FAILURE: unexpected mutation request")

        receiver = getattr(self.session, "receiver", None)
        if receiver is None:
            self._fail("TEST_FIXTURE_IDENTITY_FAILURE: receiver is missing")
        helper_identity = {
            key: getattr(self.app, key, None)
            for key in ("pid", "hwnd", "control_hwnd")
        }
        receiver_identity = {
            key: getattr(receiver, key, None)
            for key in ("pid", "hwnd", "control_hwnd")
        }
        if any(value is None for value in helper_identity.values()) or any(
            value is None for value in receiver_identity.values()
        ):
            self._fail("TEST_FIXTURE_IDENTITY_FAILURE: incomplete identity")
        if helper_identity != receiver_identity:
            self._fail("TEST_FIXTURE_IDENTITY_FAILURE: PID/HWND mismatch")

        for helper_key, receiver_key in (
            ("executable", "expected_executable"),
            ("window_class", "expected_window_class"),
        ):
            helper_value = getattr(self.app, helper_key, None)
            receiver_value = getattr(receiver, receiver_key, None)
            if helper_value is not None and receiver_value is not None:
                if os.path.normcase(str(helper_value)) != os.path.normcase(
                    str(receiver_value)
                ):
                    self._fail(
                        f"TEST_FIXTURE_IDENTITY_FAILURE: {helper_key} mismatch"
                    )

        helper_state = self.app.state()
        if any(
            helper_state.get(key) != value
            for key, value in helper_identity.items()
        ):
            self._fail("TEST_FIXTURE_IDENTITY_FAILURE: live helper mismatch")
        snapshot = getattr(receiver, "snapshot", None)
        if callable(snapshot):
            bound = snapshot()
            if bound.get("pid") != self.app.pid or bound.get("hwnd") != self.app.hwnd:
                self._fail("TEST_FIXTURE_IDENTITY_FAILURE: stale receiver binding")
            controls = bound.get("controls", {})
            if not any(
                isinstance(control, dict)
                and control.get("hwnd") == self.app.control_hwnd
                for control in controls.values()
            ):
                self._fail("TEST_FIXTURE_IDENTITY_FAILURE: control mismatch")
        self.helper_identity = helper_identity
        self.receiver_identity = receiver_identity
        self.identity_match = True

    def _establish_foreground(self) -> None:
        self.focus_request_count += 1
        try:
            self.app.focus()
        except AssertionError:
            # RealAppProcess.focus() already performs one immediate exact check.
            # Continue observing without issuing another foreground request.
            pass

        deadline = time.monotonic() + self.timeout_seconds
        while True:
            state = self.app.state()
            self.poll_count += 1
            self.last_state = self._state_evidence(state)
            if (
                state.get("foreground") == self.app.hwnd
                and state.get("focus") == self.app.control_hwnd
            ):
                return
            if time.monotonic() >= deadline:
                self._fail(
                    "TEST_FIXTURE_FOREGROUND_FAILURE: exact foreground/focus "
                    f"not observed: {self.last_state}"
                )

    def __call__(self, tool_call: Any, tool: Any, mutation_context: Any) -> None:
        if not isinstance(tool, WindowsActionTool):
            return
        self.late_foreground_hook_count += 1
        try:
            if self.late_foreground_hook_count > 1:
                self._fail(
                    "TEST_FIXTURE_DUPLICATE: late foreground hook is one-shot"
                )
            self._validate_identity(
                tool_call=tool_call,
                tool=tool,
                mutation_context=mutation_context,
            )
            self._establish_foreground()
        except Exception as error:
            self.failure = f"{type(error).__name__}: {error}"
            raise

    def evidence(self) -> dict[str, Any]:
        return {
            "hook_count": self.late_foreground_hook_count,
            "focus_request_count": self.focus_request_count,
            "poll_count": self.poll_count,
            "identity_match": self.identity_match,
            "helper_identity": self.helper_identity,
            "receiver_identity": self.receiver_identity,
            "observed_foreground": (
                self.last_state.get("foreground") if self.last_state else None
            ),
            "observed_focus": self.last_state.get("focus") if self.last_state else None,
            "failure": self.failure,
        }


class _CountingToolRunner:
    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate
        self.action_submit_count = 0

    def submit(self, function: Any, **params: Any):
        tool = getattr(function, "__self__", None)
        if getattr(tool, "tool_id", None) == "windows_action":
            self.action_submit_count += 1
        return self.delegate.submit(function, **params)


@dataclass
class _Capture:
    inference_events: list[dict[str, Any]] = field(default_factory=list)
    execute_tick_calls: int = 0
    orchestrator_runs: int = 0
    proposals: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    tool_results: list[Any] = field(default_factory=list)
    final_result: Any = None
    final_error: Any = None


class _ManagedSparkSystem:
    def __init__(self, engine: FakeEngine, tools: list[Any]) -> None:
        self.engine = engine
        self.model = "fake-model"
        self.config = None
        self.memory_backend = None
        self.channel_backend = None
        self.session_store = None
        self.mcp_tools = tools

    def get_managed_agent_mcp_tools(self):
        return list(self.mcp_tools), []


class _CapturingAgentExecutor(AgentExecutor):
    def __init__(self, *args: Any, capture: _Capture, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._capture = capture

    def execute_tick(self, agent_id: str, **kwargs: Any) -> None:
        self._capture.execute_tick_calls += 1
        return super().execute_tick(agent_id, **kwargs)

    def _finalize_tick(self, agent_id, result, error, duration):
        self._capture.final_result = result
        self._capture.final_error = error
        return super()._finalize_tick(agent_id, result, error, duration)


def _safe_arguments(raw: Any) -> Any:
    """Keep diagnostic arguments structural and redact mutation values."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return "[REDACTED]"
    if isinstance(raw, dict):
        return {
            str(key): (
                "[REDACTED]"
                if str(key).lower() in {"value", "text", "content"}
                else _safe_arguments(value)
            )
            for key, value in raw.items()
        }
    if isinstance(raw, list):
        return [_safe_arguments(value) for value in raw]
    return raw


def _tool_call_diagnostic(call: Any) -> dict[str, Any]:
    function = call.get("function", {}) if isinstance(call, dict) else {}
    return {
        "id": call.get("id") if isinstance(call, dict) else None,
        "name": (
            call.get("name") if isinstance(call, dict) else None
        )
        or function.get("name"),
        "arguments": _safe_arguments(
            (call.get("arguments") if isinstance(call, dict) else None)
            or function.get("arguments", {})
        ),
    }


@contextmanager
def _capture_runtime(
    capture: _Capture,
    *,
    engine: Any | None = None,
    late_foreground: _LateForegroundHook | None = None,
):
    original_authorize = _ManagedMutationController.authorize_proposal
    original_run = OrchestratorAgent.run
    original_execute = ToolExecutor.execute

    def authorize(self, proposal, *, effect):
        decision = original_authorize(self, proposal, effect=effect)
        intent = decision.mutation_context
        node = self.plan.node(intent.step_id) if intent else None
        capture.proposals.append(
            {
                "proposal": proposal,
                "decision": decision,
                "plan_id": self.plan.plan_id,
                "planner_node_id": intent.step_id if intent else None,
                "mutation_intent_id": (intent.mutation_intent_id if intent else None),
                "node": node,
            }
        )
        return decision

    def run(self, *args, **kwargs):
        capture.orchestrator_runs += 1
        return original_run(self, *args, **kwargs)

    def execute(self, tool_call, *args, **kwargs):
        tool = self._tools.get(tool_call.name)
        mutation_context = kwargs.get("mutation_context")
        record = {
            "call": tool_call,
            "tool": tool,
            "mutation_context": mutation_context,
            "mutating": bool(tool and tool.spec.effect == ToolEffect.MUTATING),
        }
        capture.tool_calls.append(record)
        checkpoint_callback = kwargs.get("checkpoint_callback")
        if late_foreground is not None and callable(checkpoint_callback):
            def checkpoint_with_late_foreground(state, result):
                checkpoint_callback(state, result)
                if state == "EXECUTING":
                    late_foreground(
                        tool_call=tool_call,
                        tool=tool,
                        mutation_context=mutation_context,
                    )

            kwargs = {
                **kwargs,
                "checkpoint_callback": checkpoint_with_late_foreground,
            }
        result = original_execute(self, tool_call, *args, **kwargs)
        capture.tool_results.append(result)
        return result

    def generate(*args, **kwargs):
        result = original_generate(*args, **kwargs)
        capture.inference_events.append(
            {
                "turn": len(capture.inference_events) + 1,
                "model": kwargs.get("model"),
                "tool_calls": [
                    _tool_call_diagnostic(call)
                    for call in result.get("tool_calls", [])
                ],
                "finish_reason": result.get("finish_reason"),
            }
        )
        return result

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(_ManagedMutationController, "authorize_proposal", authorize)
        )
        stack.enter_context(patch.object(OrchestratorAgent, "run", run))
        stack.enter_context(patch.object(ToolExecutor, "execute", execute))
        if engine is not None:
            original_generate = engine.generate
            stack.enter_context(patch.object(engine, "generate", side_effect=generate))
        yield


@dataclass
class _Run:
    manager: AgentManager
    agent_id: str
    session: _FakeSession
    engine: FakeEngine
    capture: _Capture
    executor: _CapturingAgentExecutor
    late_foreground: _LateForegroundHook | None = None


def _register() -> None:
    if not AgentRegistry.contains("orchestrator"):
        AgentRegistry.register_value("orchestrator", OrchestratorAgent)


def _call(call_id: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "tool_calls": [
            {"id": call_id, "name": name, "arguments": json.dumps(arguments)}
        ]
    }


def _observe(call_id: str, hwnd: int = 101) -> dict[str, Any]:
    return _call(
        call_id,
        "windows_observe",
        {"hwnd": hwnd, "hints": {"control_type": 50004, "class_name": "Edit"}},
    )


def _action(
    call_id: str,
    observation_id: str = "obs-1",
    target_id: str = "target-1",
    value: str = "ASTRA_PHASE3C_CANARY",
    **extra: Any,
) -> dict[str, Any]:
    return _call(
        call_id,
        "windows_action",
        {
            "action": "type_into",
            "observation_id": observation_id,
            "target_id": target_id,
            "value": value,
            **extra,
        },
    )


def _historical_responses() -> list[dict[str, Any]]:
    return [
        _observe("observe-1"),
        _action("type-1"),
        _observe("observe-2"),
        _action("type-2", "obs-2", "target-2"),
        {"content": "done"},
    ]


def _new_run(
    tmp_path: Path,
    responses: list[dict[str, Any]],
    *,
    session: _FakeSession | None = None,
    db_name: str = "managed.db",
    late_foreground: _LateForegroundHook | None = None,
    tool_requirement: ToolRequirement = ToolRequirement.OPTIONAL,
) -> _Run:
    _register()
    session = session or _FakeSession()
    tools = [WindowsObserveTool(session), WindowsActionTool(session)]
    engine = FakeEngine(responses)
    system = _ManagedSparkSystem(engine, tools)
    manager = AgentManager(str(tmp_path / db_name))
    agent = manager.create_agent(
        "phase3c-managed-harness",
        agent_type="orchestrator",
        config={
            "model": "fake-model",
            "instruction": "Use the supplied disposable test helper.",
            "mcp_tools": True,
            "tool_requirement": tool_requirement.value,
        },
    )
    capture = _Capture()
    executor = _CapturingAgentExecutor(
        manager,
        EventBus(record_history=True),
        system=system,
        capture=capture,
    )
    executor._confirm_callback = lambda *_args: True
    with _capture_runtime(
        capture, engine=engine, late_foreground=late_foreground
    ):
        executor.execute_tick(agent["id"])
    return _Run(
        manager,
        agent["id"],
        session,
        engine,
        capture,
        executor,
        late_foreground,
    )


def _tool_state(run: _Run) -> dict[str, Any]:
    checkpoint = run.manager.get_latest_checkpoint(run.agent_id)
    assert checkpoint is not None
    return checkpoint["tool_state"]


def _mutating_proposals(run: _Run) -> list[dict[str, Any]]:
    return [
        item
        for item in run.capture.proposals
        if item["proposal"].tool_name == "windows_action"
    ]


def _mutating_tool_calls(run: _Run) -> list[dict[str, Any]]:
    return [item for item in run.capture.tool_calls if item["mutating"]]


def _safe_observation(observation: Any) -> dict[str, Any] | None:
    if not isinstance(observation, dict):
        return None
    window = observation.get("window", {})
    controls = observation.get("controls", [])
    return {
        "observation_id": observation.get("observation_id"),
        "window": {
            key: window.get(key)
            for key in ("pid", "hwnd", "executable", "class_name")
            if key in window
        },
        "controls": [
            {
                "target_id": control.get("target_id"),
                "identity": control.get("identity"),
                "enabled": control.get("enabled"),
                "offscreen": control.get("offscreen"),
                "value_verifiable": control.get("value_verifiable"),
            }
            for control in controls
            if isinstance(control, dict)
        ],
    }


def _safe_result(result: Any) -> dict[str, Any]:
    metadata = getattr(result, "metadata", {}) or {}
    execution = metadata.get("execution", {}) or {}
    windows = metadata.get("windows", {}) or {}
    safe_windows = {
        key: windows.get(key)
        for key in (
            "preconditions",
            "dispatch",
            "outcome",
            "verification",
            "retryable",
            "failure",
            "identity",
            "evidence",
        )
        if key in windows
    }
    if "observation" in windows:
        safe_windows["observation"] = _safe_observation(windows["observation"])
    return {
        "tool_name": getattr(result, "tool_name", None),
        "success": bool(getattr(result, "success", False)),
        "execution_state": getattr(
            getattr(result, "execution_state", None), "value", None
        ),
        "execution": {
            key: execution.get(key)
            for key in ("call_id", "state", "failure", "retryable")
            if key in execution
        },
        "windows": safe_windows,
    }


def _safe_proposal(item: dict[str, Any]) -> dict[str, Any]:
    proposal = item["proposal"]
    decision = item["decision"]
    intent = decision.mutation_context
    node = item.get("node")
    return {
        "type": type(proposal).__name__,
        "proposal_id": proposal.proposal_id,
        "tool_name": proposal.tool_name,
        "provider_call_id": proposal.provider_call_id,
        "model_turn": proposal.model_turn,
        "arguments": _safe_arguments(proposal.arguments),
        "reserved_fields": list(proposal.reserved_fields),
        "decision": {
            "allowed": decision.allowed,
            "code": decision.code,
            "message": decision.message,
        },
        "plan_id": item.get("plan_id"),
        "planner_node_id": item.get("planner_node_id"),
        "mutation_intent_id": item.get("mutation_intent_id"),
        "execution_id": getattr(intent, "execution_id", None),
        "mutation_context_type": type(intent).__name__ if intent else None,
        "node_type": type(node).__name__ if node else None,
        "node_status": getattr(node, "status", None),
    }


def _safe_tool_call(item: dict[str, Any], run: _Run) -> dict[str, Any]:
    call = item["call"]
    tool = item.get("tool")
    session = getattr(tool, "session", None)
    return {
        "call_id": getattr(call, "id", None),
        "tool_name": getattr(call, "name", None),
        "mutating": bool(item["mutating"]),
        "tool_type": type(tool).__name__ if tool is not None else None,
        "exact_session_binding": (
            session is run.session
            and getattr(session, "receiver", None) is run.session.receiver
        ),
        "mutation_context_present": item.get("mutation_context") is not None,
    }


def _safe_plan(tool_state: dict[str, Any]) -> dict[str, Any]:
    raw = tool_state.get("durable_plan") or {}
    return {
        "execution_id": raw.get("execution_id"),
        "plan_id": raw.get("plan_id"),
        "revision": raw.get("revision"),
        "revision_id": raw.get("revision_id"),
        "status": raw.get("status"),
        "active_node_id": raw.get("active_node_id"),
        "nodes": [
            {
                key: node.get(key)
                for key in (
                    "planner_node_id",
                    "status",
                    "kind",
                    "mutation_intent_id",
                    "superseded_by",
                )
                if key in node
            }
            for node in raw.get("nodes", [])
        ],
    }


def _managed_evidence(
    run: _Run,
    helper_state: dict[str, Any],
) -> dict[str, Any]:
    checkpoint = run.manager.get_latest_checkpoint(run.agent_id)
    tool_state = (checkpoint or {}).get("tool_state", {}) or {}
    result = run.capture.final_result
    result_metadata = getattr(result, "metadata", {}) or {}
    pending = run.manager.execution_journal.pending(run.agent_id)
    tool_results = [
        _safe_result(item)
        for item in run.capture.tool_results
    ]
    proposals = [_safe_proposal(item) for item in run.capture.proposals]
    result_agent = {
        "content": str(getattr(result, "content", ""))[:512] if result else None,
        "turns": getattr(result, "turns", None),
        "max_turns_exceeded": bool(result_metadata.get("max_turns_exceeded")),
        "terminal_reason": result_metadata.get("terminal_reason")
        or result_metadata.get("terminal_state"),
    }
    return {
        "model": {
            "inference_events": list(run.capture.inference_events),
            "provider_call_ids": [
                item["provider_call_id"]
                for item in proposals
            ],
        },
        "agent": {
            "execute_tick_calls": run.capture.execute_tick_calls,
            "orchestrator_runs": run.capture.orchestrator_runs,
            "result": result_agent,
            "final_error": type(run.capture.final_error).__name__
            if run.capture.final_error
            else None,
        },
        "proposals": proposals,
        "tool_calls": [
            _safe_tool_call(item, run) for item in run.capture.tool_calls
        ],
        "tool_results": tool_results,
        "controller": {
            "authorize_proposal_calls": len(run.capture.proposals),
            "mutating_authorized": sum(
                1
                for item in proposals
                if item["tool_name"] == "windows_action"
                and item["decision"]["allowed"]
            ),
            "semantic_duplicate_count": sum(
                1
                for item in proposals
                if item["tool_name"] == "windows_action"
                and not item["decision"]["allowed"]
                and item["decision"]["code"] == "PLAN_ADVANCEMENT_REQUIRED"
            ),
        },
        "plan": _safe_plan(tool_state),
        "semantic_step": dict(tool_state.get("semantic_step") or {}),
        "journal": {
            "pending": [
                {
                    key: row.get(key)
                    for key in ("state", "call_id", "tool")
                    if key in row
                }
                for row in pending
            ]
        },
        "helper": {
            key: helper_state.get(key)
            for key in (
                "pid",
                "hwnd",
                "control_hwnd",
                "text",
                "dispatch_count",
                "expected_control_dispatch_count",
                "wrong_target_dispatch_count",
                "last_dispatch_control_hwnd",
                "decoy_control_hwnd",
                "decoy_text",
                "foreground",
                "focus",
                "enabled",
                "offscreen",
                "value_verifiable",
            )
            if key in helper_state
        },
        "late_foreground": (
            run.late_foreground.evidence()
            if run.late_foreground is not None
            else None
        ),
    }


def _assert_managed_physical_success(
    evidence: dict[str, Any],
    *,
    expected_text: str,
    expected_model: str | None = None,
    require_late_foreground: bool = False,
) -> None:
    assert evidence["model"]["inference_events"], "live inference was not observed"
    if expected_model is not None:
        assert any(
            event["model"] == expected_model
            for event in evidence["model"]["inference_events"]
        )
    assert evidence["agent"]["execute_tick_calls"] == 1
    assert evidence["agent"]["orchestrator_runs"] >= 1
    assert evidence["controller"]["authorize_proposal_calls"] >= 1
    assert any(
        item["type"] == "ToolExecutionProposal"
        for item in evidence["proposals"]
    )

    mutating_proposals = [
        item for item in evidence["proposals"] if item["tool_name"] == "windows_action"
    ]
    authorized = [item for item in mutating_proposals if item["decision"]["allowed"]]
    assert len(authorized) == 1
    first = authorized[0]
    assert first["plan_id"] and first["planner_node_id"]
    assert first["mutation_intent_id"] and first["execution_id"]
    assert first["mutation_context_type"] == "MutationIntent"
    assert first["node_type"] == "DurablePlanNode"
    assert first["node_status"] == "COMPLETED"

    blocked = mutating_proposals[1:]
    assert all(
        item["decision"]["code"] == "PLAN_ADVANCEMENT_REQUIRED"
        for item in blocked
    )

    mutating_calls = [item for item in evidence["tool_calls"] if item["mutating"]]
    assert len(mutating_calls) == 1
    assert mutating_calls[0]["exact_session_binding"] is True
    assert mutating_calls[0]["mutation_context_present"] is True

    mutating_results = [
        item
        for item in evidence["tool_results"]
        if item["tool_name"] == "windows_action"
    ]
    assert len(mutating_results) == 1
    assert mutating_results[0]["success"] is True
    assert mutating_results[0]["execution_state"] == "VERIFIED"
    windows = mutating_results[0]["windows"]
    assert windows["preconditions"] == "PASSED"
    assert windows["dispatch"] == "DISPATCHED"
    assert windows["outcome"] == "VERIFIED"
    assert windows["verification"] == "VERIFIED"
    assert windows["retryable"] is False
    assert windows["failure"] == "NONE"
    assert windows["evidence"]["value_sha256"] == hashlib.sha256(
        expected_text.encode()
    ).hexdigest()
    assert windows["evidence"]["value_length"] == len(expected_text)
    assert windows["evidence"]["post_observation_id"]

    helper = evidence["helper"]
    identity = windows["identity"]
    assert identity["window"]["process"]["pid"] == helper["pid"]
    assert identity["window"]["hwnd"] == helper["hwnd"]
    assert identity["control"]["hwnd"] == helper["control_hwnd"]
    assert helper["dispatch_count"] == 1
    assert helper["expected_control_dispatch_count"] == 1
    assert helper["wrong_target_dispatch_count"] == 0
    assert helper["last_dispatch_control_hwnd"] == helper["control_hwnd"]
    assert helper["decoy_control_hwnd"] > 0
    assert helper["decoy_control_hwnd"] != helper["control_hwnd"]
    assert identity["control"]["hwnd"] != helper["decoy_control_hwnd"]
    assert helper["decoy_text"] == ""
    assert helper["text"] == expected_text

    late = evidence.get("late_foreground")
    if late is not None:
        assert late["hook_count"] <= 1
    if require_late_foreground:
        assert late is not None
        assert late["hook_count"] == 1
        assert late["focus_request_count"] == 1
        assert late["identity_match"] is True
        assert late["helper_identity"] == {
            "pid": helper["pid"],
            "hwnd": helper["hwnd"],
            "control_hwnd": helper["control_hwnd"],
        }
        assert late["receiver_identity"] == late["helper_identity"]
        assert late["observed_foreground"] == helper["hwnd"]
        assert late["observed_focus"] == helper["control_hwnd"]
        assert late["failure"] is None

    plan = evidence["plan"]
    assert plan["plan_id"]
    assert plan["revision_id"]
    assert plan["status"] == "COMPLETED"
    assert len(plan["nodes"]) == 1
    assert plan["nodes"][0]["status"] == "COMPLETED"
    assert plan["nodes"][0]["mutation_intent_id"] == first["mutation_intent_id"]
    assert evidence["semantic_step"]["status"] == "VERIFIED"
    assert evidence["journal"]["pending"] == []


def _write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True), encoding="utf-8")


def _fake_success_evidence(run: _Run) -> dict[str, Any]:
    return _managed_evidence(run, run.session.state())


def _make_success_run(tmp_path: Path) -> _Run:
    return _new_run(
        tmp_path,
        [_observe("observe-1"), _action("type-1"), {"content": "done"}],
    )


@pytest.fixture
def _success_run(tmp_path):
    run = _make_success_run(tmp_path)
    try:
        yield run
    finally:
        run.manager.close()


def test_d1_successful_managed_fake_mutation_has_complete_trace(_success_run):
    _assert_managed_physical_success(
        _fake_success_evidence(_success_run), expected_text="ASTRA_PHASE3C_CANARY"
    )


@pytest.mark.parametrize(
    "case",
    [
        "zero-dispatch",
        "wrong-target",
        "missing-authorize",
        "missing-intent",
        "missing-verification",
    ],
    ids=["D2", "D4", "D5", "D6", "D7"],
)
def test_d2_d7_invalid_evidence_fails_contract(_success_run, case):
    evidence = _fake_success_evidence(_success_run)
    if case == "zero-dispatch":
        evidence["helper"]["dispatch_count"] = 0
    elif case == "wrong-target":
        evidence["helper"]["wrong_target_dispatch_count"] = 1
    elif case == "missing-authorize":
        evidence["controller"]["authorize_proposal_calls"] = 0
    elif case == "missing-intent":
        evidence["proposals"][1]["mutation_intent_id"] = None
    else:
        evidence["tool_results"][1]["windows"]["verification"] = "NOT_VERIFIED"
    with pytest.raises(AssertionError):
        _assert_managed_physical_success(
            evidence, expected_text="ASTRA_PHASE3C_CANARY"
        )


def test_d3_exactly_one_dispatch_is_explicitly_represented(_success_run):
    evidence = _fake_success_evidence(_success_run)
    assert evidence["helper"]["dispatch_count"] == 1
    assert evidence["tool_results"][1]["windows"]["dispatch"] == "DISPATCHED"


def test_d8_verified_intent_completed_node_and_empty_pending_pass(_success_run):
    evidence = _fake_success_evidence(_success_run)
    assert evidence["semantic_step"]["status"] == "VERIFIED"
    assert evidence["plan"]["nodes"][0]["status"] == "COMPLETED"
    assert evidence["journal"]["pending"] == []


def test_d9_unknown_outcome_cannot_be_reported_as_success(tmp_path):
    session = _FakeSession(unknown=True)
    run = _new_run(
        tmp_path, [_observe("observe-1"), _action("type-1")], session=session
    )
    try:
        evidence = _managed_evidence(run, session.state())
        assert evidence["tool_results"][1]["windows"]["outcome"] == "UNKNOWN_OUTCOME"
        assert evidence["journal"]["pending"]
        with pytest.raises(AssertionError):
            _assert_managed_physical_success(
                evidence, expected_text="ASTRA_PHASE3C_CANARY"
            )
    finally:
        run.manager.close()


def test_d10_duplicate_proposal_stays_blocked_at_one_dispatch(tmp_path):
    run = _new_run(tmp_path, _historical_responses())
    try:
        evidence = _fake_success_evidence(run)
        _assert_managed_physical_success(
            evidence, expected_text="ASTRA_PHASE3C_CANARY"
        )
        blocked = [
            item
            for item in evidence["proposals"]
            if item["tool_name"] == "windows_action" and not item["decision"]["allowed"]
        ]
        assert len(blocked) == 1
        assert blocked[0]["decision"]["code"] == "PLAN_ADVANCEMENT_REQUIRED"
    finally:
        run.manager.close()


def test_d11_diagnostics_exclude_secrets_and_environment_dump(tmp_path):
    run = _make_success_run(tmp_path)
    try:
        serialized = json.dumps(_fake_success_evidence(run), sort_keys=True).lower()
        for forbidden in ("api_key", "authorization", "password", "environment"):
            assert forbidden not in serialized
    finally:
        run.manager.close()


def test_d12_trace_survives_manager_cleanup(tmp_path):
    run = _make_success_run(tmp_path)
    evidence = _fake_success_evidence(run)
    run.manager.close()
    assert evidence["plan"]["plan_id"]
    assert evidence["proposals"][1]["mutation_intent_id"]
    assert evidence["journal"]["pending"] == []


def test_d13_requested_value_must_match_independent_fake_observation(tmp_path):
    session = _FakeSession(post_dispatch_text="DIFFERENT_VALUE")
    run = _new_run(
        tmp_path,
        [_observe("observe-1"), _action("type-1"), {"content": "done"}],
        session=session,
    )
    try:
        evidence = _managed_evidence(run, session.state())
        observed = evidence["helper"]["text"]
        requested = session.actions[0]["value"]
        assert requested == "ASTRA_PHASE3C_CANARY"
        assert observed == "DIFFERENT_VALUE"
        assert requested != observed
        assert evidence["helper"]["dispatch_count"] == 1
        assert evidence["tool_results"][1]["windows"]["dispatch"] == "DISPATCHED"
        assert evidence["tool_results"][1]["windows"]["outcome"] == "UNKNOWN_OUTCOME"
        assert (
            evidence["tool_results"][1]["windows"]["verification"]
            == "NOT_VERIFIED"
        )
        with pytest.raises(AssertionError):
            _assert_managed_physical_success(
                evidence, expected_text="ASTRA_PHASE3C_CANARY"
            )
    finally:
        run.manager.close()


class _FixtureMessageUser:
    def CallWindowProcW(self, *_args):
        return 0


def _fixture_message_probe():
    from tests.security.real_app_fixture import _Application, _WM_SETTEXT

    app = object.__new__(_Application)
    app.user = _FixtureMessageUser()
    app.ready = True
    app.edit_hwnd = 101
    app.duplicate_hwnd = 202
    app.expected_control_dispatch_count = 0
    app.wrong_target_dispatch_count = 0
    app.last_dispatch_control_hwnd = 0
    app._old_edit_procs = {101: 11, 202: 22}
    return app, _WM_SETTEXT


def test_w1_expected_control_message_increments_expected_count_only():
    app, wm_settext = _fixture_message_probe()
    app._edit_proc(app.edit_hwnd, wm_settext, 0, 0)
    assert app.expected_control_dispatch_count == 1
    assert app.wrong_target_dispatch_count == 0
    assert app.last_dispatch_control_hwnd == app.edit_hwnd


def test_w2_decoy_control_message_increments_wrong_count_only():
    app, wm_settext = _fixture_message_probe()
    app._edit_proc(app.duplicate_hwnd, wm_settext, 0, 0)
    assert app.expected_control_dispatch_count == 0
    assert app.wrong_target_dispatch_count == 1
    assert app.last_dispatch_control_hwnd == app.duplicate_hwnd


def test_w3_expected_and_decoy_control_hwnds_are_distinct():
    app, _ = _fixture_message_probe()
    assert app.edit_hwnd != app.duplicate_hwnd


def test_w4_receiver_binding_remains_expected_control_only():
    session = _FakeSession()
    assert session.receiver.control_hwnd == session.control_hwnd
    assert session.receiver.control_hwnd != session.receiver.decoy_control_hwnd
    assert session.receiver.snapshot()["controls"][""]["hwnd"] == session.control_hwnd


def test_w5_helper_observation_is_distinct_from_requested_value(tmp_path):
    session = _FakeSession(post_dispatch_text="HELPER_OBSERVED_VALUE")
    run = _new_run(
        tmp_path,
        [_observe("observe-1"), _action("type-1"), {"content": "done"}],
        session=session,
    )
    try:
        state = session.state()
        assert session.actions[0]["value"] == "ASTRA_PHASE3C_CANARY"
        assert state["text"] == "HELPER_OBSERVED_VALUE"
        assert state["text"] != session.actions[0]["value"]
    finally:
        run.manager.close()


def test_w6_late_foreground_contract_remains_one_shot(tmp_path):
    session = _FakeSession()
    app = _FakeForegroundApp(session)
    hook = _LateForegroundHook(app=app, session=session, timeout_seconds=0.01)
    run = _new_run(
        tmp_path,
        _historical_responses(),
        session=session,
        late_foreground=hook,
    )
    try:
        assert hook.late_foreground_hook_count == 1
        assert hook.focus_request_count == 1
        assert app.focus_calls == 1
        assert session.receiver.dispatch_count == 1
    finally:
        run.manager.close()


def test_f1_late_foreground_hook_allows_exact_identity_once(tmp_path):
    session = _FakeSession()
    app = _FakeForegroundApp(session)
    hook = _LateForegroundHook(
        app=app,
        session=session,
        timeout_seconds=0.01,
    )
    run = _new_run(
        tmp_path,
        [_observe("observe-1"), _action("type-1"), {"content": "done"}],
        session=session,
        late_foreground=hook,
    )
    try:
        assert hook.late_foreground_hook_count == 1
        assert hook.focus_request_count == 1
        assert app.focus_calls == 1
        assert hook.identity_match is True
        assert hook.last_state["foreground"] == app.hwnd
        assert hook.last_state["focus"] == app.control_hwnd
        assert session.receiver.dispatch_count == 1
    finally:
        run.manager.close()


def test_f2_late_foreground_identity_mismatch_blocks_focus_and_worker(
    tmp_path, monkeypatch
):
    session = _FakeSession()
    app = _FakeForegroundApp(session, pid=session.pid + 1)
    hook = _LateForegroundHook(
        app=app,
        session=session,
        timeout_seconds=0.01,
    )
    runner = _CountingToolRunner(tool_stubs._TOOL_RUNNER)
    monkeypatch.setattr(tool_stubs, "_TOOL_RUNNER", runner)
    run = _new_run(
        tmp_path,
        [_observe("observe-1"), _action("type-1"), {"content": "done"}],
        session=session,
        late_foreground=hook,
    )
    try:
        assert hook.late_foreground_hook_count == 1
        assert hook.focus_request_count == 0
        assert app.focus_calls == 0
        assert runner.action_submit_count == 0
        assert session.receiver.dispatch_count == 0
        execution = run.capture.tool_results[1].metadata["execution"]
        assert execution["state"] == "NOT_STARTED"
        assert execution["state"] != "UNKNOWN_OUTCOME"
    finally:
        run.manager.close()


def test_f3_late_foreground_failure_is_fail_closed_before_worker(
    tmp_path, monkeypatch
):
    session = _FakeSession()
    app = _FakeForegroundApp(session, focus_succeeds=False)
    hook = _LateForegroundHook(
        app=app,
        session=session,
        timeout_seconds=0.001,
    )
    runner = _CountingToolRunner(tool_stubs._TOOL_RUNNER)
    monkeypatch.setattr(tool_stubs, "_TOOL_RUNNER", runner)
    run = _new_run(
        tmp_path,
        [_observe("observe-1"), _action("type-1"), {"content": "done"}],
        session=session,
        late_foreground=hook,
    )
    try:
        assert hook.late_foreground_hook_count == 1
        assert hook.focus_request_count == 1
        assert app.focus_calls == 1
        assert hook.poll_count >= 1
        assert runner.action_submit_count == 0
        assert session.receiver.dispatch_count == 0
        execution = run.capture.tool_results[1].metadata["execution"]
        assert execution["state"] == "NOT_STARTED"
        assert execution["state"] != "UNKNOWN_OUTCOME"
    finally:
        run.manager.close()


def test_f4_late_foreground_hook_is_one_shot_across_duplicate_proposals(tmp_path):
    session = _FakeSession()
    app = _FakeForegroundApp(session)
    hook = _LateForegroundHook(
        app=app,
        session=session,
        timeout_seconds=0.01,
    )
    run = _new_run(
        tmp_path,
        _historical_responses(),
        session=session,
        late_foreground=hook,
    )
    try:
        assert hook.late_foreground_hook_count == 1
        assert hook.focus_request_count == 1
        assert app.focus_calls == 1
        assert session.receiver.dispatch_count == 1
        blocked = [
            item
            for item in _mutating_proposals(run)
            if not item["decision"].allowed
        ]
        assert blocked
        assert all(
            item["decision"].code == "PLAN_ADVANCEMENT_REQUIRED"
            for item in blocked
        )
    finally:
        run.manager.close()


def test_f5_late_foreground_failure_is_not_unknown_outcome(tmp_path, monkeypatch):
    session = _FakeSession()
    app = _FakeForegroundApp(session, focus_succeeds=False)
    hook = _LateForegroundHook(
        app=app,
        session=session,
        timeout_seconds=0,
    )
    runner = _CountingToolRunner(tool_stubs._TOOL_RUNNER)
    monkeypatch.setattr(tool_stubs, "_TOOL_RUNNER", runner)
    run = _new_run(
        tmp_path,
        [_observe("observe-1"), _action("type-1"), {"content": "done"}],
        session=session,
        late_foreground=hook,
    )
    try:
        execution = run.capture.tool_results[1].metadata["execution"]
        assert execution["state"] == "NOT_STARTED"
        assert execution["failure"] != "UNKNOWN_OUTCOME"
        assert runner.action_submit_count == 0
        assert session.receiver.dispatch_count == 0
    finally:
        run.manager.close()


def test_r1_managed_fixture_registers_canonical_orchestrator():
    _register()
    assert AgentRegistry.contains("orchestrator")


def test_r2_registry_resolves_exact_orchestrator_class():
    _register()
    assert AgentRegistry.get("orchestrator") is OrchestratorAgent


def test_r3_registered_agent_executor_reaches_orchestrator(tmp_path):
    run = _new_run(tmp_path, [{"content": "done"}])
    try:
        assert run.capture.execute_tick_calls == 1
        assert run.capture.orchestrator_runs == 1
    finally:
        run.manager.close()


def test_r4_missing_orchestrator_fails_closed_without_dispatch(tmp_path):
    AgentRegistry.clear()
    session = _FakeSession()
    engine = FakeEngine([{"content": "done"}])
    manager = AgentManager(str(tmp_path / "missing-orchestrator.db"))
    try:
        agent = manager.create_agent(
            "missing-orchestrator",
            agent_type="orchestrator",
            config={"model": "fake-model", "mcp_tools": True},
        )
        capture = _Capture()
        executor = _CapturingAgentExecutor(
            manager,
            EventBus(record_history=True),
            system=_ManagedSparkSystem(
                engine,
                [WindowsObserveTool(session), WindowsActionTool(session)],
            ),
            capture=capture,
        )
        with pytest.raises(KeyError, match="orchestrator"):
            executor._invoke_agent_impl(agent)
        assert capture.proposals == []
        assert capture.tool_calls == []
        assert session.receiver.dispatch_count == 0
    finally:
        manager.close()
        _register()


def test_r5_registered_path_creates_tool_execution_proposal(tmp_path):
    run = _new_run(tmp_path, [_observe("observe-1"), {"content": "done"}])
    try:
        assert isinstance(run.capture.proposals[0]["proposal"], ToolExecutionProposal)
    finally:
        run.manager.close()


def test_r6_registered_path_reaches_authorize_proposal(tmp_path):
    run = _new_run(
        tmp_path, [_observe("observe-1"), _action("type-1"), {"content": "done"}]
    )
    try:
        assert len(run.capture.proposals) == 2
        assert run.capture.proposals[1]["decision"].allowed
    finally:
        run.manager.close()


def test_r7_registration_does_not_supply_controller_identity(tmp_path):
    run = _make_success_run(tmp_path)
    try:
        item = _mutating_proposals(run)[0]
        assert item["plan_id"] and item["planner_node_id"]
        assert item["mutation_intent_id"]
        assert item["plan_id"] != "fake-plan"
        assert item["planner_node_id"] != "fake-node"
        assert item["mutation_intent_id"] != "fake-intent"
    finally:
        run.manager.close()


def test_r8_registered_path_cannot_bypass_managed_orchestrator(tmp_path):
    run = _new_run(tmp_path, [_observe("observe-1"), {"content": "done"}])
    try:
        assert AgentRegistry.get("orchestrator") is OrchestratorAgent
        assert run.capture.execute_tick_calls == 1
        assert run.capture.orchestrator_runs == 1
    finally:
        run.manager.close()


def test_r9_fixture_construction_performs_zero_dispatch(tmp_path):
    _register()
    session = _FakeSession()
    manager = AgentManager(str(tmp_path / "construction.db"))
    try:
        manager.create_agent(
            "construction-only",
            agent_type="orchestrator",
            config={"model": "fake-model", "mcp_tools": True},
        )
        _CapturingAgentExecutor(
            manager,
            EventBus(record_history=True),
            system=_ManagedSparkSystem(
                FakeEngine([]),
                [WindowsObserveTool(session), WindowsActionTool(session)],
            ),
            capture=_Capture(),
        )
        assert session.receiver.dispatch_count == 0
    finally:
        manager.close()


def test_r10_fake_managed_mutation_satisfies_hardened_trace_contract(tmp_path):
    run = _make_success_run(tmp_path)
    try:
        _assert_managed_physical_success(
            _fake_success_evidence(run), expected_text="ASTRA_PHASE3C_CANARY"
        )
    finally:
        run.manager.close()


def test_mp1_managed_entry_reaches_orchestrator(tmp_path):
    run = _new_run(tmp_path, [{"content": "done"}])
    try:
        assert run.capture.execute_tick_calls == 1
        assert run.capture.orchestrator_runs == 1
    finally:
        run.manager.close()


def test_mp2_model_call_becomes_real_tool_execution_proposal(tmp_path):
    run = _new_run(tmp_path, [_observe("observe-1"), {"content": "done"}])
    try:
        proposal = run.capture.proposals[0]["proposal"]
        assert isinstance(proposal, ToolExecutionProposal)
        assert proposal.tool_name == "windows_observe"
        assert proposal.provider_call_id == "observe-1"
    finally:
        run.manager.close()


def test_mp13_legacy_model_output_fails_required_native_mode(tmp_path):
    legacy = (
        '<action>observe</action>\n'
        '<parameter name="hwnd">101</parameter>\n'
        '<parameter name="control_type">50004</parameter>\n'
        '<parameter name="class_name">Edit</parameter>'
    )
    run = _new_run(
        tmp_path,
        [{"content": legacy}],
        tool_requirement=ToolRequirement.REQUIRED_NATIVE,
    )
    try:
        assert isinstance(run.capture.final_error, FatalError)
        assert run.capture.final_error.failure_code == (
            "MODEL_CAPABILITY_INSUFFICIENT"
        )
        assert run.capture.final_error.retryable is False
        detail = run.executor._build_error_detail(run.capture.final_error)
        assert detail["failure_code"] == "MODEL_CAPABILITY_INSUFFICIENT"
        assert detail["retryable"] is False
        assert detail["escalation_eligible"] is True
        assert run.engine.call_count == 1
        assert run.capture.proposals == []
        assert run.capture.tool_calls == []
        assert run.session.receiver.dispatch_count == 0
        assert run.manager.execution_journal.pending(run.agent_id) == []
        assert "UNKNOWN_OUTCOME" not in str(run.capture.final_error)
    finally:
        run.manager.close()


def test_mp3_first_mutation_reaches_controller_intent_and_node(tmp_path):
    run = _new_run(
        tmp_path, [_observe("observe-1"), _action("type-1"), {"content": "done"}]
    )
    try:
        item = _mutating_proposals(run)[0]
        assert item["decision"].allowed
        assert isinstance(item["mutation_intent_id"], str)
        assert isinstance(item["node"], DurablePlanNode)
        assert item["node"].mutation_intent_id == item["mutation_intent_id"]
    finally:
        run.manager.close()


def test_mp4_model_authority_fields_do_not_become_controller_identity(tmp_path):
    run = _new_run(
        tmp_path,
        [
            _action(
                "inject-1",
                execution_id="fake-execution",
                plan_id="fake-plan",
                planner_node_id="fake-node",
                step_id="fake-step",
                mutation_intent_id="fake-intent",
                journal_token="fake-journal",
            ),
            {"content": "done"},
        ],
    )
    try:
        item = _mutating_proposals(run)[0]
        assert item["decision"].code == "PROPOSAL_REJECTED"
        assert not item["decision"].allowed
        assert run.session.receiver.dispatch_count == 0
        assert _tool_state(run)["durable_plan"]["nodes"] == []
    finally:
        run.manager.close()


def test_mp5_executor_receives_exact_bound_windows_tools(tmp_path):
    run = _new_run(
        tmp_path, [_observe("observe-1"), _action("type-1"), {"content": "done"}]
    )
    try:
        observed = [item["tool"] for item in run.capture.tool_calls]
        assert any(isinstance(tool, WindowsObserveTool) for tool in observed)
        assert any(isinstance(tool, WindowsActionTool) for tool in observed)
        for tool in observed:
            assert tool.session is run.session
            assert tool.session.receiver is run.session.receiver
    finally:
        run.manager.close()


def test_mp6_first_mutation_is_verified_once(tmp_path):
    run = _new_run(
        tmp_path, [_observe("observe-1"), _action("type-1"), {"content": "done"}]
    )
    try:
        assert run.session.receiver.dispatch_count == 1
        assert run.session.text == "ASTRA_PHASE3C_CANARY"
        assert _mutating_tool_calls(run)[0]["mutation_context"] is not None
        assert run.capture.tool_results[-1].success
    finally:
        run.manager.close()


def test_mp7_read_after_verified_mutation_remains_allowed(tmp_path):
    run = _new_run(
        tmp_path,
        [
            _observe("observe-1"),
            _action("type-1"),
            _observe("observe-2"),
            {"content": "done"},
        ],
    )
    try:
        assert run.session.receiver.dispatch_count == 1
        assert run.session.observation_count == 3
        assert sum(not item["mutating"] for item in run.capture.tool_calls) == 2
    finally:
        run.manager.close()


def test_mp8_second_mutation_without_advancement_is_blocked(tmp_path):
    run = _new_run(tmp_path, _historical_responses())
    try:
        second = _mutating_proposals(run)[1]
        assert second["decision"].code == "PLAN_ADVANCEMENT_REQUIRED"
        assert second["decision"].allowed is False
        assert run.session.receiver.dispatch_count == 1
    finally:
        run.manager.close()


def test_mp9_blocked_second_mutation_never_reaches_tool_executor(tmp_path):
    run = _new_run(tmp_path, _historical_responses())
    try:
        assert len(run.capture.tool_calls) == 3
        assert len(_mutating_tool_calls(run)) == 1
        assert len(_mutating_proposals(run)) == 2
        assert run.session.receiver.dispatch_count == 1
    finally:
        run.manager.close()


def test_mp10_verified_intent_has_no_pending_reservation(tmp_path):
    run = _new_run(
        tmp_path, [_observe("observe-1"), _action("type-1"), {"content": "done"}]
    )
    try:
        state = _tool_state(run)
        assert state["semantic_step"]["status"] == "VERIFIED"
        assert run.manager.execution_journal.pending(run.agent_id) == []
    finally:
        run.manager.close()


def test_mp11_checkpoint_has_completed_s1_and_no_automatic_s2(tmp_path):
    run = _new_run(
        tmp_path, [_observe("observe-1"), _action("type-1"), {"content": "done"}]
    )
    try:
        plan = _tool_state(run)["durable_plan"]
        assert len(plan["nodes"]) == 1
        assert plan["nodes"][0]["status"] == "COMPLETED"
        assert plan["nodes"][0]["mutation_intent_id"]
        assert plan["active_node_id"] is None
    finally:
        run.manager.close()


def test_mp12_restart_preserves_completed_step_and_blocks_new_proposal(tmp_path):
    path = str(tmp_path / "restart.db")
    session = _FakeSession()
    first = _new_run(
        tmp_path,
        [_observe("observe-1"), _action("type-1"), {"content": "done"}],
        session=session,
        db_name="restart.db",
    )
    checkpoint = first.manager.get_latest_checkpoint(first.agent_id)
    assert checkpoint is not None
    first.manager.save_checkpoint(
        first.agent_id,
        checkpoint["tick_id"],
        {**checkpoint["conversation_state"], "lifecycle": "RUNNING"},
        checkpoint["tool_state"],
    )
    first.manager.start_tick(first.agent_id)
    agent_id = first.agent_id
    first.manager.close()

    manager = AgentManager(path, clear_stale_running=True)
    try:
        _register()
        engine = FakeEngine([_action("fresh-after-restart"), {"content": "done"}])
        system = _ManagedSparkSystem(
            engine, [WindowsObserveTool(session), WindowsActionTool(session)]
        )
        capture = _Capture()
        executor = _CapturingAgentExecutor(
            manager, EventBus(record_history=True), system=system, capture=capture
        )
        executor._confirm_callback = lambda *_args: True
        with _capture_runtime(capture, engine=engine):
            executor.execute_tick(agent_id)
        assert session.receiver.dispatch_count == 1
        assert (
            _mutating_proposals(
                _Run(manager, agent_id, session, engine, capture, executor)
            )[0]["decision"].code
            == "PLAN_ADVANCEMENT_REQUIRED"
        )
    finally:
        manager.close()


def test_historical_spark_duplicate_sequence_through_managed_harness(tmp_path):
    run = _new_run(tmp_path, _historical_responses())
    try:
        assert len(run.capture.proposals) == 4
        assert sum(not item["mutating"] for item in run.capture.tool_calls) == 2
        assert len(_mutating_proposals(run)) == 2
        assert len(_mutating_tool_calls(run)) == 1
        assert run.session.receiver.dispatch_count == 1
        assert run.session.receiver.wrong_target_dispatch_count == 0
        assert run.session.receiver.replay_count == 0
        assert (
            _mutating_proposals(run)[1]["decision"].code == "PLAN_ADVANCEMENT_REQUIRED"
        )
    finally:
        run.manager.close()


def test_unknown_outcome_quarantines_managed_step(tmp_path):
    session = _FakeSession(unknown=True)
    run = _new_run(
        tmp_path, [_observe("observe-1"), _action("type-1")], session=session
    )
    try:
        state = _tool_state(run)
        assert session.receiver.dispatch_count == 1
        assert state["durable_plan"]["nodes"][0]["status"] == "RECONCILIATION_REQUIRED"
        assert state["recovery"]["required"] is True
        assert run.manager.get_agent(run.agent_id)["status"] == "needs_attention"
        pending = run.manager.execution_journal.pending(run.agent_id)
        assert len(pending) == 1
        assert pending[0]["state"] == "UNKNOWN_OUTCOME"
    finally:
        run.manager.close()


def test_unknown_outcome_restart_does_not_allow_replacement_dispatch(tmp_path):
    path = str(tmp_path / "unknown-restart.db")
    session = _FakeSession(unknown=True)
    first = _new_run(
        tmp_path,
        [_observe("observe-1"), _action("type-1")],
        session=session,
        db_name="unknown-restart.db",
    )
    checkpoint = first.manager.get_latest_checkpoint(first.agent_id)
    assert checkpoint is not None
    first.manager.save_checkpoint(
        first.agent_id,
        checkpoint["tick_id"],
        {**checkpoint["conversation_state"], "lifecycle": "RUNNING"},
        checkpoint["tool_state"],
    )
    first.manager.start_tick(first.agent_id)
    agent_id = first.agent_id
    first.manager.close()

    manager = AgentManager(path, clear_stale_running=True)
    try:
        engine = FakeEngine([_action("replacement-after-unknown")])
        system = _ManagedSparkSystem(
            engine, [WindowsObserveTool(session), WindowsActionTool(session)]
        )
        capture = _Capture()
        executor = _CapturingAgentExecutor(
            manager, EventBus(record_history=True), system=system, capture=capture
        )
        executor._confirm_callback = lambda *_args: True
        with _capture_runtime(capture, engine=engine):
            executor.execute_tick(agent_id)
        assert session.receiver.dispatch_count == 1
        assert capture.proposals == []
        assert (
            _tool_state(_Run(manager, agent_id, session, engine, capture, executor))[
                "recovery"
            ]["required"]
            is True
        )
    finally:
        manager.close()


_PHYSICAL_CANARY = "ASTRA_MANAGED_PHASE3C_CANARY"


@pytest.mark.live
@pytest.mark.skipif(os.name != "nt", reason="Native Win32 real app")
@pytest.mark.skipif(
    os.environ.get("ASTRA_RUN_SPARK_REAL_APP") != "1",
    reason="Explicit live Spark real-app run required",
)
def test_spark_managed_executor_real_app_uses_phase3c_proposal_boundary(tmp_path):
    """Future one-shot physical entry point; never enabled by default."""
    from openjarvis.engine.ollama import OllamaEngine
    from tests.security.real_app_fixture import RealAppProcess
    from tests.security.test_windows_real_app import _session

    model = "SparkLLM/Spark-X2.5-4B:latest"
    with RealAppProcess() as app:
        app.add_duplicate()
        observer, receiver, session = _session(app)
        action_tool = WindowsActionTool(session)
        late_foreground = _LateForegroundHook(
            app=app,
            session=session,
            expected_tool=action_tool,
            expected_value=_PHYSICAL_CANARY,
        )
        _register()
        manager = AgentManager(str(tmp_path / "spark-managed-phase3c.db"))
        try:
            engine = OllamaEngine(timeout=180)
            system = _ManagedSparkSystem(
                engine,
                [WindowsObserveTool(session), action_tool],
            )
            system.model = model
            agent = manager.create_agent(
                "phase3c-spark-real-app",
                agent_type="orchestrator",
                config={
                    "model": model,
                    "instruction": (
                        "Use windows_observe on the supplied test window with "
                        "control_type 50004 and class_name Edit, then type the "
                        f"exact canary {_PHYSICAL_CANARY} exactly once. "
                        f"Window HWND is {app.hwnd}."
                    ),
                    "mcp_tools": True,
                    "tool_requirement": ToolRequirement.REQUIRED_NATIVE.value,
                },
            )
            capture = _Capture()
            executor = _CapturingAgentExecutor(
                manager,
                EventBus(record_history=True),
                system=system,
                capture=capture,
            )
            executor._confirm_callback = lambda *_args: True
            with _capture_runtime(
                capture,
                engine=engine,
                late_foreground=late_foreground,
            ):
                executor.execute_tick(agent["id"])

            state = app.state()
            run = _Run(
                manager,
                agent["id"],
                session,
                engine,
                capture,
                executor,
                late_foreground,
            )
            evidence = _managed_evidence(run, state)
            trace_path = tmp_path / "managed-phase3c-physical-trace.json"
            _write_evidence(trace_path, evidence)
            print(f"managed_phase3c_trace={trace_path}")
            _assert_managed_physical_success(
                evidence,
                expected_text=_PHYSICAL_CANARY,
                expected_model=model,
                require_late_foreground=True,
            )
            assert evidence["controller"]["semantic_duplicate_count"] == 0
        finally:
            manager.close()
            receiver.close()
            observer.close()
