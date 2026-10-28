"""File write tool — write content to files with path validation."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import threading
from pathlib import Path
from typing import Any, List, Optional

from openjarvis.core.execution import ExecutionState, ToolEffect
from openjarvis.core.registry import ToolRegistry
from openjarvis.core.types import ToolResult
from openjarvis.tools._stubs import BaseTool, ToolSpec

# Maximum file size to write (10 MB)
_MAX_SIZE_BYTES = 10_485_760
_WRITE_LOCK = threading.RLock()


def _file_identity(path: Path):
    try:
        info = path.stat()
    except FileNotFoundError:
        return None
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _commit_file(path: Path, content: bytes, *, append: bool) -> ToolResult:
    """Stage beside the target, atomically replace, then observe exact bytes."""
    temporary = None
    commit_attempted = False
    with _WRITE_LOCK:
        try:
            original = _file_identity(path)
            mode = stat.S_IMODE(path.stat().st_mode) if original is not None else None
            if append and original is not None:
                if original[2] + len(content) > _MAX_SIZE_BYTES:
                    return ToolResult(
                        "file_write",
                        "Resulting file too large for atomic append.",
                        success=False,
                        execution_state=ExecutionState.NOT_STARTED,
                    )
                content = path.read_bytes() + content
            with tempfile.NamedTemporaryFile(
                dir=path.parent,
                prefix=".astra-write-",
                suffix=".tmp",
                delete=False,
            ) as staged:
                temporary = Path(staged.name)
                staged.write(content)
                staged.flush()
                os.fsync(staged.fileno())
            if mode is not None:
                os.chmod(temporary, mode)
            if _file_identity(path) != original:
                return ToolResult(
                    "file_write",
                    "STALE_TARGET: file changed while preparing write.",
                    success=False,
                    execution_state=ExecutionState.NOT_STARTED,
                )
            commit_attempted = True
            os.replace(temporary, path)
            temporary = None
            if path.read_bytes() != content:
                return ToolResult(
                    "file_write",
                    "UNKNOWN_OUTCOME: resulting bytes did not verify.",
                    success=False,
                    execution_state=ExecutionState.UNKNOWN_OUTCOME,
                )
            return ToolResult(
                "file_write",
                f"Verified write to {path}",
                metadata={
                    "path": str(path),
                    "size_bytes": len(content),
                    "verification": "resulting bytes matched staged bytes",
                    "atomic": True,
                    "artifacts": [
                        {
                            "type": "file",
                            "path": str(path),
                            "size_bytes": len(content),
                            "sha256": hashlib.sha256(content).hexdigest(),
                        }
                    ],
                },
                execution_state=ExecutionState.VERIFIED,
            )
        except OSError as exc:
            return ToolResult(
                "file_write",
                f"Write error: {exc}",
                success=False,
                execution_state=(
                    ExecutionState.UNKNOWN_OUTCOME
                    if commit_attempted
                    else ExecutionState.NOT_STARTED
                ),
            )
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


@ToolRegistry.register("file_write")
class FileWriteTool(BaseTool):
    """Write content to files with optional directory restrictions."""

    tool_id = "file_write"

    def __init__(
        self,
        allowed_dirs: Optional[List[str]] = None,
    ) -> None:
        self._allowed_dirs = [Path(d).resolve() for d in (allowed_dirs or [])]

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="file_write",
            description=("Write content to a file. Supports write and append modes."),
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file to write.",
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to write to the file.",
                    },
                    "mode": {
                        "type": "string",
                        "description": (
                            "Write mode: 'write' (overwrite/create)"
                            " or 'append' (append to existing)."
                            " Default: 'write'."
                        ),
                    },
                    "create_dirs": {
                        "type": "boolean",
                        "description": (
                            "Create parent directories if they"
                            " don't exist. Default: false."
                        ),
                    },
                },
                "required": ["path", "content"],
            },
            category="filesystem",
            required_capabilities=["file:write"],
            effect=ToolEffect.MUTATING,
        )

    def _is_path_allowed(self, path: Path) -> bool:
        """Check if path is within allowed directories."""
        if not self._allowed_dirs:
            return True
        resolved = path.resolve()
        return any(
            resolved == d or resolved.is_relative_to(d) for d in self._allowed_dirs
        )

    def execute(self, **params: Any) -> ToolResult:
        # Windows path resolution also opens the target transiently. Keep
        # validation under the same lock so another in-process resolver does
        # not prevent atomic replacement through a sharing violation.
        with _WRITE_LOCK:
            result = self._execute(**params)
            if not result.success and result.execution_state is None:
                result.execution_state = ExecutionState.NOT_STARTED
            return result

    def _execute(self, **params: Any) -> ToolResult:
        file_path = params.get("path", "")
        if not file_path:
            return ToolResult(
                tool_name="file_write",
                content="No path provided.",
                success=False,
            )

        content = params.get("content")
        if not isinstance(content, str):
            return ToolResult(
                tool_name="file_write",
                content="No content provided or content is not a string.",
                success=False,
            )

        mode = params.get("mode", "write")
        if mode not in ("write", "append"):
            return ToolResult(
                tool_name="file_write",
                content=f"Invalid mode: {mode!r}. Use 'write' or 'append'.",
                success=False,
            )

        create_dirs = params.get("create_dirs", False)

        path = Path(file_path)

        # Block sensitive files (secrets, credentials, keys)
        from openjarvis.security.file_policy import is_sensitive_file

        if is_sensitive_file(path):
            return ToolResult(
                tool_name="file_write",
                content=f"Access denied: {file_path} is a sensitive file.",
                success=False,
            )

        if not self._is_path_allowed(path):
            return ToolResult(
                tool_name="file_write",
                content=f"Access denied: {file_path} is outside allowed directories.",
                success=False,
            )

        # Bind the resolved target once so a later symlink/junction retarget
        # cannot change which path this operation writes.
        path = path.resolve()
        if is_sensitive_file(path) or not self._is_path_allowed(path):
            return ToolResult(
                "file_write", "Resolved path is not permitted.", success=False
            )

        # Check content size before writing
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > _MAX_SIZE_BYTES:
            return ToolResult(
                tool_name="file_write",
                content=(
                    f"Content too large: {len(content_bytes)} bytes"
                    f" (max {_MAX_SIZE_BYTES})."
                ),
                success=False,
            )

        # Create parent directories if requested
        if create_dirs:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                return ToolResult(
                    tool_name="file_write",
                    content=f"Cannot create directories: {exc}",
                    success=False,
                )
        else:
            if not path.parent.exists():
                return ToolResult(
                    tool_name="file_write",
                    content=(
                        f"Parent directory does not exist: {path.parent}."
                        " Set create_dirs=true to create it."
                    ),
                    success=False,
                )

        return _commit_file(path, content_bytes, append=mode == "append")


__all__ = ["FileWriteTool"]
