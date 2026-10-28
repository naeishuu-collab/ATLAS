"""Sandboxed REPL environment for the RLM agent.

Provides a persistent Python namespace with injected helper functions
(``llm_query``, ``llm_batch``, ``FINAL``, ``FINAL_VAR``) that the RLM
agent's generated code uses to decompose context and make recursive
sub-LM calls.

The builtin and import boundaries below are defense in depth, not an OS
sandbox. Execution is disabled by default; worker mode remains unavailable
until the host provides an approved OS sandbox. In-process legacy execution
is permanently disabled.
"""

from __future__ import annotations

import builtins as _builtins
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Optional

# Safe stdlib modules pre-injected into the REPL namespace
_SAFE_MODULES = [
    "json",
    "re",
    "math",
    "collections",
    "itertools",
    "functools",
    "textwrap",
    "string",
    "copy",
    "datetime",
]
_ALLOWED_IMPORTS = frozenset(_SAFE_MODULES)

# Keep generated code useful for data processing while excluding host-facing
# helpers such as open(), eval(), exec(), globals(), and locals().
_SAFE_BUILTIN_NAMES = (
    "abs",
    "all",
    "any",
    "ascii",
    "bin",
    "bool",
    "bytearray",
    "bytes",
    "callable",
    "chr",
    "complex",
    "dict",
    "divmod",
    "enumerate",
    "filter",
    "float",
    "format",
    "frozenset",
    "hash",
    "hex",
    "int",
    "isinstance",
    "issubclass",
    "iter",
    "len",
    "list",
    "map",
    "max",
    "min",
    "next",
    "oct",
    "ord",
    "pow",
    "print",
    "range",
    "repr",
    "reversed",
    "round",
    "set",
    "slice",
    "sorted",
    "str",
    "sum",
    "tuple",
    "type",
    "zip",
    "BaseException",
    "Exception",
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "EOFError",
    "ImportError",
    "IndexError",
    "KeyError",
    "LookupError",
    "ModuleNotFoundError",
    "NameError",
    "RuntimeError",
    "StopIteration",
    "TypeError",
    "ValueError",
    "ZeroDivisionError",
)


def _restricted_import(
    name: str,
    globals: Optional[Dict[str, Any]] = None,
    locals: Optional[Dict[str, Any]] = None,
    fromlist: tuple[str, ...] = (),
    level: int = 0,
) -> Any:
    """Import only one of the explicitly approved top-level modules."""
    if level != 0 or name not in _ALLOWED_IMPORTS:
        raise ImportError(f"RLM import is not allowed: {name}")
    return _builtins.__import__(name, globals, locals, fromlist, level)


_SAFE_BUILTINS = MappingProxyType(
    {
        name: getattr(_builtins, name) for name in _SAFE_BUILTIN_NAMES
    }
    | {"__import__": _restricted_import}
)

# Patterns blocked for security
_BLOCKED_PATTERNS = [
    "os.system",
    "os.popen",
    "subprocess",
    "shutil.rmtree",
    "__import__",
    "open(",
    "ctypes",
    "socket",
    "http.client",
    "urllib",
]


@dataclass(frozen=True, slots=True)
class RLMExecutionResult:
    """Structured result for one RLM execution attempt."""

    output: str
    success: bool
    error_code: Optional[str] = None
    terminated: bool = False
    final_value: Any = None
    unknown_outcome: bool = False


class RLMRepl:
    """Persistent RLM REPL with disabled and sandboxed-worker modes.

    Parameters
    ----------
    llm_query_fn:
        Callback invoked when REPL code calls ``llm_query(prompt)``.
    llm_batch_fn:
        Callback invoked when REPL code calls ``llm_batch(prompts)``.
    max_output_chars:
        Maximum characters captured from stdout per execution.
    allow_unsafe_legacy:
        Retained for compatibility, but always denied. It never enables
        in-process execution.
    execution_mode:
        ``"worker"`` selects the isolated worker; ``"disabled"`` keeps the
        fail-closed default.
    """

    def __init__(
        self,
        llm_query_fn: Optional[Callable[[str], str]] = None,
        llm_batch_fn: Optional[Callable[[List[str]], List[str]]] = None,
        tool_call_fn: Optional[Callable[[str, Dict[str, Any]], str]] = None,
        tool_arg_names: Optional[Dict[str, Optional[str]]] = None,
        *,
        max_output_chars: int = 10000,
        allow_unsafe_legacy: bool = False,
        execution_mode: str = "disabled",
        llm_broker: Any = None,
    ) -> None:
        if execution_mode not in {"disabled", "worker"}:
            raise ValueError("execution_mode must be 'disabled' or 'worker'")
        if allow_unsafe_legacy and execution_mode == "worker":
            raise ValueError("legacy and worker execution modes are mutually exclusive")
        self._max_output_chars = max_output_chars
        self._legacy_disabled = allow_unsafe_legacy
        self._allow_unsafe_legacy = False
        self._execution_mode = execution_mode
        self._terminated = False
        self._final_value: Any = None
        self._tool_call_fn = tool_call_fn
        self._worker: Any = None

        if self._execution_mode == "worker":
            if any(
                callback is not None
                for callback in (llm_query_fn, llm_batch_fn, tool_call_fn)
            ) or tool_arg_names:
                raise ValueError("worker mode cannot receive host callbacks or tools")
            from openjarvis.agents.rlm_worker import RLMWorker

            self._worker = RLMWorker(
                max_output_chars=max_output_chars,
                llm_broker=llm_broker,
            )

        # Build namespace
        self._namespace: Dict[str, Any] = {}
        self._namespace["__builtins__"] = _SAFE_BUILTINS

    # ------------------------------------------------------------------
    # Termination helpers
    # ------------------------------------------------------------------

    def _final(self, value: Any) -> None:
        """Mark the REPL as terminated with a final answer."""
        self._terminated = True
        self._final_value = value

    def _final_var(self, var_name: str) -> None:
        """Mark the REPL as terminated, using a namespace variable as the answer."""
        value = self._namespace.get(var_name)
        self._terminated = True
        self._final_value = value

    @property
    def is_terminated(self) -> bool:
        """Check if FINAL/FINAL_VAR was called or answer["ready"] is True."""
        if self._terminated:
            return True
        answer = self._namespace.get("answer", {})
        if isinstance(answer, dict) and answer.get("ready"):
            return True
        return False

    @property
    def final_answer(self) -> Any:
        """Return the termination value."""
        if self._terminated:
            return self._final_value
        answer = self._namespace.get("answer", {})
        if isinstance(answer, dict) and answer.get("ready"):
            return answer.get("value")
        return None

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def _tool_call(self, tool_name: str, *args: Any, **kwargs: Any) -> str:
        """Execute an injected OpenJarvis tool from within the REPL.

        Supported forms:
        - ``tool_call("file_read", {"path": "foo.txt"})``
        - ``tool_call("file_read", path="foo.txt")``
        """
        if self._tool_call_fn is None:
            raise RuntimeError("tool_call is not available in this REPL")

        if args:
            if len(args) != 1 or kwargs:
                raise TypeError(
                    "tool_call expects either a single dict argument or keyword args"
                )
            if not isinstance(args[0], dict):
                raise TypeError("tool_call positional argument must be a dict")
            params = dict(args[0])
        else:
            params = dict(kwargs)

        return self._tool_call_fn(tool_name, params)

    def _make_tool_wrapper(
        self,
        tool_name: str,
        primary_arg: Optional[str],
    ) -> Callable[..., str]:
        """Return a Python helper that dispatches to ``tool_call``."""

        def _wrapper(*args: Any, **kwargs: Any) -> str:
            if kwargs:
                params = dict(kwargs)
            elif len(args) == 1 and primary_arg is not None:
                params = {primary_arg: args[0]}
            elif len(args) == 1 and isinstance(args[0], dict):
                params = dict(args[0])
            elif not args:
                params = {}
            else:
                message = (
                    f"{tool_name} expects keyword args or a single "
                    f"{primary_arg!r} argument"
                )
                raise TypeError(message)
            return self._tool_call(tool_name, params)

        _wrapper.__name__ = tool_name
        return _wrapper

    def security_check(self, code: str) -> Optional[str]:
        """Check code for dangerous patterns. Returns error message or None."""
        for pattern in _BLOCKED_PATTERNS:
            if pattern in code:
                return f"Blocked: code contains prohibited pattern '{pattern}'"
        return None

    def execute_with_outcome(self, code: str) -> RLMExecutionResult:
        """Execute *code* and preserve success separately from its output."""
        if self._execution_mode == "worker":
            violation = self.security_check(code)
            if violation is not None:
                return RLMExecutionResult(
                    output=f"Error: {violation}",
                    success=False,
                    error_code="SECURITY_BLOCKED",
                )
            result = self._worker.execute_with_outcome(code)
            if result.terminated:
                self._terminated = True
                self._final_value = result.final_value
            return result

        if self._legacy_disabled:
            return RLMExecutionResult(
                output=(
                    "Error: RLM_LEGACY_DISABLED: in-process RLM execution "
                    "is permanently disabled"
                ),
                success=False,
                error_code="RLM_LEGACY_DISABLED",
            )

        if not self._allow_unsafe_legacy:
            return RLMExecutionResult(
                output=(
                    "Error: RLM_WORKER_REQUIRED: in-process RLM execution is "
                    "disabled; use an approved AppContainer worker."
                ),
                success=False,
                error_code="RLM_WORKER_REQUIRED",
            )

    def execute(self, code: str) -> str:
        """Execute *code* and return the legacy text-only result."""
        return self.execute_with_outcome(code).output

    @property
    def execution_mode(self) -> str:
        """Return the configured non-legacy execution mode."""
        return self._execution_mode

    def close(self) -> None:
        """Close an explicitly configured worker session."""
        if self._worker is not None:
            self._worker.close()

    # ------------------------------------------------------------------
    # Namespace access
    # ------------------------------------------------------------------

    def set_variable(self, name: str, value: Any) -> None:
        """Set a variable in the REPL namespace."""
        if self._execution_mode == "worker":
            self._worker.set_variable(name, value)
        self._namespace[name] = value

    def get_variable(self, name: str) -> Any:
        """Get a variable from the REPL namespace."""
        return self._namespace.get(name)


__all__ = ["RLMExecutionResult", "RLMRepl"]
