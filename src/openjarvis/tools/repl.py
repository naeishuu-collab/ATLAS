"""Disabled generic Python REPL until an approved OS sandbox is available."""

from __future__ import annotations

import threading
import time
import uuid
import weakref
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import ToolRegistry
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec

# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


@dataclass
class _ReplSession:
    session_id: str
    process: Any = None
    connection: Any = None
    quarantined: bool = False
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    execution_count: int = 0


def _stop_session(session: _ReplSession) -> None:
    process = session.process
    if process is not None and process.pid is not None:
        if process.is_alive():
            process.terminate()
        process.join(timeout=2)
        if process.is_alive():
            process.kill()
            process.join(timeout=2)
        if process.is_alive():
            raise RuntimeError("REPL worker termination could not be confirmed")
    if session.connection is not None:
        session.connection.close()


def _close_sessions(sessions: Dict[str, _ReplSession]) -> None:
    for session in list(sessions.values()):
        _stop_session(session)
    sessions.clear()


# ---------------------------------------------------------------------------
# REPL Tool
# ---------------------------------------------------------------------------


@ToolRegistry.register("repl")
class ReplTool(BaseTool):
    """Disabled Python REPL placeholder until an approved OS sandbox exists.

    Parameters
    ----------
    timeout:
        Maximum execution time in seconds per call.
    max_output:
        Maximum characters of captured output.
    max_sessions:
        Maximum concurrent sessions (LRU eviction).
    """

    tool_id = "repl"

    def __init__(
        self,
        timeout: int = 30,
        max_output: int = 10000,
        max_sessions: int = 16,
    ) -> None:
        if timeout <= 0 or max_output < 1 or max_sessions < 1:
            raise ValueError(
                "REPL timeout, output limit and session limit must be positive"
            )
        self._timeout = timeout
        self._max_output = max_output
        self._max_sessions = max_sessions
        self._sessions: Dict[str, _ReplSession] = {}
        self._lock = threading.Lock()
        self._finalizer = weakref.finalize(self, _close_sessions, self._sessions)

    def close(self) -> None:
        """Stop owned workers; closing is serialized with active executions."""
        with self._lock:
            _close_sessions(self._sessions)

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="repl",
            description=(
                "Python REPL is unavailable until the host provides an "
                "approved OS sandbox."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Python code to execute.",
                    },
                    "session_id": {
                        "type": "string",
                        "description": (
                            "Session ID for state persistence. "
                            "Omit to auto-create a new session."
                        ),
                    },
                    "reset": {
                        "type": "boolean",
                        "description": "Reset the session state before execution.",
                    },
                },
                "required": ["code"],
            },
            category="code",
            required_capabilities=["code:execute"],
            metadata={"structured_allow_object_text": True},
            requires_confirmation=True,
            effect=ToolEffect.MUTATING,
        )

    def execute(self, **params: Any) -> ToolResult:
        # Pattern filters and restricted builtins are not an OS sandbox.  Keep
        # the public and direct-constructor paths inert until host-approved
        # isolation is available; no input is parsed or evaluated here.
        return ToolResult(
            tool_name="repl",
            content=(
                "REPL execution denied: an approved OS sandbox is unavailable."
            ),
            success=False,
            metadata={
                "error_code": "REPL_SANDBOX_UNAVAILABLE",
                "security_denied": True,
            },
            execution_state=ExecutionState.NOT_STARTED,
        )

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    def _resolve_session(
        self,
        session_id: Optional[str],
        reset: bool = False,
    ) -> _ReplSession:
        """Get or create a session, with LRU eviction at max_sessions."""
        if session_id and session_id in self._sessions:
            session = self._sessions[session_id]
            if not reset:
                return session
            _stop_session(session)
            del self._sessions[session_id]

        sid = session_id or str(uuid.uuid4())
        if len(self._sessions) >= self._max_sessions:
            oldest_id = min(self._sessions, key=lambda k: self._sessions[k].last_used)
            _stop_session(self._sessions[oldest_id])
            del self._sessions[oldest_id]

        session = _ReplSession(session_id=sid)
        self._sessions[sid] = session
        return session

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def _exec_with_timeout(
        self,
        code: str,
        session: _ReplSession,
    ) -> tuple[str, bool]:
        """Deny direct helper calls before any process or code execution."""
        del code, session
        return (
            "Error: REPL_SANDBOX_UNAVAILABLE: approved OS sandbox required",
            False,
        )


__all__ = ["ReplTool"]
