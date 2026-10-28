"""Agent loop guard — detect and prevent degenerate tool-calling loops."""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass
from typing import Optional

from openjarvis.core.events import EventBus, EventType


@dataclass(slots=True)
class LoopGuardConfig:
    """Configuration for the loop guard."""

    enabled: bool = True
    max_identical_calls: int = 3  # Reserved native option; duplicate calls are refused.
    ping_pong_window: int = 6  # detect A-B-A-B cycling
    poll_tool_budget: int = 5  # max calls to same polling tool
    max_context_messages: int = 100  # context overflow threshold
    warn_before_block: bool = True  # warn on first cycle, block on second


@dataclass(slots=True)
class LoopVerdict:
    """Result of a loop guard check."""

    blocked: bool = False
    reason: str = ""
    warned: bool = False


class LoopGuard:
    """Detect and prevent degenerate agent loops.

    Features:
    1. Hash tracking: refuse repeated identical calls, matching the native guard.
    2. Ping-pong detection: Sliding window detects A-B-A-B or A-B-C-A-B-C patterns
    3. Poll-tool awareness: Tools with spec.metadata["polling"] = True
       get relaxed budget
    4. Context overflow recovery with preserved goals and complete tool exchanges
    """

    def __init__(self, config: LoopGuardConfig, *, bus: Optional[EventBus] = None):
        self._config = config
        self._bus = bus
        # Track call hashes and their counts
        self._call_counts: dict[str, int] = {}
        # Track tool name sequence for pattern detection
        self._tool_sequence: deque[str] = deque(maxlen=config.ping_pong_window * 2)
        # Track per-tool call counts (for polling budget)
        self._per_tool_counts: dict[str, int] = {}
        # Track cycle keys that have already been warned (for warn-before-block)
        self._warned_cycles: set[str] = set()

        try:
            from openjarvis._rust_bridge import get_rust_module

            _rust = get_rust_module()
            self._rust_impl = _rust.LoopGuard(
                max_identical=config.max_identical_calls,
                max_ping_pong=(
                    config.ping_pong_window // 2 if config.ping_pong_window > 1 else 2
                ),
                poll_budget=config.poll_tool_budget,
            )
        except Exception:
            self._rust_impl = None

    def check_call(self, tool_name: str, arguments: str) -> LoopVerdict:
        """Check whether a tool call should proceed or be blocked."""
        if self._rust_impl is not None:
            rust_result = self._rust_impl.check(tool_name, arguments)
            # Support both raw Rust return (str | None) and LoopVerdict
            if isinstance(rust_result, LoopVerdict):
                verdict = rust_result
            elif rust_result is not None:
                self._emit_triggered("rust_guard", tool_name)
                verdict = LoopVerdict(blocked=True, reason=rust_result)
            else:
                verdict = LoopVerdict()
        else:
            verdict = self._python_check(tool_name, arguments)

        # Wrap with warn-before-block logic
        if verdict.blocked and self._config.warn_before_block:
            cycle_key = verdict.reason
            if cycle_key not in self._warned_cycles:
                self._warned_cycles.add(cycle_key)
                return LoopVerdict(blocked=False, warned=True, reason=verdict.reason)
        return verdict

    def _python_check(self, tool_name: str, arguments: str) -> LoopVerdict:
        """Pure-Python fallback when Rust backend is not available."""
        # 1. Hash tracking — identical calls
        call_hash = hashlib.sha256(f"{tool_name}:{arguments}".encode()).hexdigest()[:16]
        self._call_counts[call_hash] = self._call_counts.get(call_hash, 0) + 1
        # The native guard refuses the second identical call irrespective of
        # its reserved max_identical option. Keep the fallback conservative too.
        if self._call_counts[call_hash] > 1:
            self._emit_triggered("identical_call", tool_name)
            return LoopVerdict(
                blocked=True,
                reason=(
                    f"Loop detected: identical call to '{tool_name}' "
                    "with same arguments"
                ),
            )

        # 2. Per-tool budget (polling tools)
        self._per_tool_counts[tool_name] = self._per_tool_counts.get(tool_name, 0) + 1
        if self._per_tool_counts[tool_name] > self._config.poll_tool_budget:
            self._emit_triggered("poll_budget", tool_name)
            return LoopVerdict(
                blocked=True,
                reason=(
                    f"Tool '{tool_name}' exceeded poll budget "
                    f"({self._config.poll_tool_budget})."
                ),
            )

        # 3. Ping-pong detection
        self._tool_sequence.append(tool_name)
        if len(self._tool_sequence) >= self._config.ping_pong_window:
            if self._detect_ping_pong():
                self._emit_triggered("ping_pong", tool_name)
                return LoopVerdict(
                    blocked=True,
                    reason="Repetitive tool-calling pattern detected (ping-pong).",
                )

        return LoopVerdict()

    def check_response(self, content: str) -> LoopVerdict:
        """Check whether an agent response indicates a loop. Reserved for future use."""
        return LoopVerdict()

    @staticmethod
    def _is_system(msg: object) -> bool:
        """Check if a message has role == system."""
        return getattr(msg, "role", None) == "system"

    @staticmethod
    def _is_tool(msg: object) -> bool:
        """Check if a message has role == tool."""
        return getattr(msg, "role", None) == "tool"

    def compress_context(self, messages: list) -> list:
        """Trim old context while retaining the task goal and valid tool exchanges.

        Stages:
        1. Summarize old tool results (replace content with "[Tool result truncated]")
        2. Sliding window — keep system, first user goal, and recent messages
        3. Drop incomplete tool-call/result exchanges created by the window
        """
        if len(messages) <= self._config.max_context_messages:
            return messages

        # Stage 1: Truncate old tool result messages
        threshold = len(messages) // 2
        compressed = []
        for i, msg in enumerate(messages):
            if i < threshold and self._is_tool(msg):
                from openjarvis.core.types import Message, Role

                compressed.append(
                    Message(
                        role=Role.TOOL,
                        content="[Tool result truncated]",
                        tool_call_id=getattr(
                            msg,
                            "tool_call_id",
                            None,
                        ),
                        name=getattr(msg, "name", None),
                    )
                )
            else:
                compressed.append(msg)

        if len(compressed) <= self._config.max_context_messages:
            return compressed

        # Stage 2: Sliding window — keep system, the original user goal, + recent
        system_msgs = [m for m in compressed if self._is_system(m)]
        non_system = [m for m in compressed if not self._is_system(m)]
        goal_index = next(
            (
                i
                for i, message in enumerate(non_system)
                if getattr(message, "role", None) == "user"
                and not getattr(message, "name", None)
                and not getattr(message, "tool_call_id", None)
            ),
            None,
        )
        goal = [non_system[goal_index]] if goal_index is not None else []
        recent = [m for i, m in enumerate(non_system) if i != goal_index]
        keep = max(
            0,
            self._config.max_context_messages - len(system_msgs) - len(goal),
        )
        compressed = system_msgs + goal + (recent[-keep:] if keep else [])
        return self._remove_orphaned_tool_messages(compressed)

    @staticmethod
    def _remove_orphaned_tool_messages(messages: list) -> list:
        """Keep assistant tool calls only with their complete result set."""
        tool_results: dict[str, int] = {}
        for index, message in enumerate(messages):
            call_id = getattr(message, "tool_call_id", None)
            if getattr(message, "role", None) == "tool" and isinstance(call_id, str):
                tool_results[call_id] = index

        valid_call_ids: set[str] = set()
        invalid_call_messages: set[int] = set()
        for index, message in enumerate(messages):
            calls = getattr(message, "tool_calls", None)
            if getattr(message, "role", None) != "assistant" or not calls:
                continue
            call_ids = [getattr(call, "id", None) for call in calls]
            if not all(
                isinstance(call_id, str)
                and tool_results.get(call_id, -1) > index
                for call_id in call_ids
            ):
                invalid_call_messages.add(index)
                continue
            valid_call_ids.update(call_ids)

        return [
            message
            for index, message in enumerate(messages)
            if index not in invalid_call_messages
            and not (
                getattr(message, "role", None) == "tool"
                and getattr(message, "tool_call_id", None) not in valid_call_ids
            )
        ]

    def reset(self) -> None:
        """Reset all tracking state — always via Rust backend."""
        self._call_counts.clear()
        self._tool_sequence.clear()
        self._per_tool_counts.clear()
        self._warned_cycles.clear()
        if self._rust_impl is not None:
            self._rust_impl.reset()

    def _detect_ping_pong(self) -> bool:
        """Detect repeating patterns in tool call sequence."""
        seq = list(self._tool_sequence)
        n = len(seq)
        # Check for period-2 pattern (A-B-A-B)
        for period in (2, 3):
            if n >= period * 2:
                tail = seq[-period * 2 :]
                pattern = tail[:period]
                if all(tail[i] == pattern[i % period] for i in range(len(tail))):
                    return True
        return False

    def _emit_triggered(self, reason_type: str, tool_name: str) -> None:
        """Publish a LOOP_GUARD_TRIGGERED event."""
        if self._bus:
            self._bus.publish(
                EventType.LOOP_GUARD_TRIGGERED,
                {"reason_type": reason_type, "tool": tool_name},
            )


__all__ = ["LoopGuard", "LoopGuardConfig", "LoopVerdict"]
