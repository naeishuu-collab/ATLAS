"""Secure file and directory creation helpers.

All OpenJarvis data files under ``~/.openjarvis/`` should be created
through these helpers to ensure consistent, restrictive permissions.
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any


def secure_mkdir(path: Path, mode: int = 0o700) -> Path:
    """Create a directory with restrictive permissions.

    Creates parent directories as needed, then sets *mode* on the
    target directory (even if it already exists). On Windows 0600/0700 mean
    a protected owner-only DACL, with no recursive rewrite of existing children.
    """
    if os.name == "nt":
        from openjarvis.security.windows_acl import private_path

        _windows_mode(mode)
        # Protect only new ancestors; existing ancestors are not ours to change.
        if not path.parent.exists():
            secure_mkdir(path.parent)
        private_path(path, directory=True)
    else:
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, mode)
    return path


def secure_create(path: Path, mode: int = 0o600) -> Path:
    """Ensure a file exists with restrictive permissions.

    Creates the parent directory with ``0o700`` if needed, touches the
    file if it doesn't exist, and sets *mode* on it.
    """
    if os.name == "nt":
        _windows_mode(mode)
    secure_mkdir(path.parent, mode=0o700)
    if os.name == "nt":
        from openjarvis.security.windows_acl import private_path

        private_path(path, directory=False)
    else:
        if not path.exists():
            path.touch()
        os.chmod(path, mode)
    return path


def secure_write_text(
    path: Path,
    content: str,
    *,
    mode: int = 0o600,
    encoding: str = "utf-8",
) -> Path:
    """Atomically replace *path* with owner-only text content.

    The temporary file is created in the destination directory so
    :func:`os.replace` remains atomic. Permissions are restricted before
    secret bytes are written, then re-applied after replacement for platforms
    whose replace semantics preserve the destination's prior mode.
    """
    if os.name == "nt":
        _windows_mode(mode)
    secure_mkdir(path.parent, mode=0o700)
    if os.name == "nt":
        from openjarvis.security.windows_acl import private_path

        temporary_path = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
        private_path(temporary_path, directory=False, exclusive=True)
        try:
            fd = os.open(temporary_path, os.O_RDWR | os.O_BINARY)
        except Exception:
            temporary_path.unlink(missing_ok=True)
            raise
    else:
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=str(path.parent),
        )
        temporary_path = Path(temporary_name)
    try:
        if os.name != "nt" and hasattr(os, "fchmod"):
            os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding=encoding) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        if os.name != "nt":
            os.chmod(path, mode)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise
    return path


def _windows_mode(mode: int) -> None:
    # These defaults express owner-only data, not Windows read-only attributes.
    # Do not silently reinterpret arbitrary POSIX permission requests.
    if mode not in (0o600, 0o700):
        raise ValueError("Windows private data supports only owner-only 0600/0700")


def secure_write_json(path: Path, payload: Any, *, mode: int = 0o600) -> Path:
    """Atomically persist JSON with restrictive permissions."""
    return secure_write_text(
        path,
        json.dumps(payload, indent=2),
        mode=mode,
        encoding="utf-8",
    )
