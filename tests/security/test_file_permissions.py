"""Tests for secure file creation helpers (Section 4)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from tests.security.private_permissions import assert_private


class TestSecureMkdir:
    """secure_mkdir should create directories with 0o700."""

    def test_creates_directory_with_700(self) -> None:
        from openjarvis.security.file_utils import secure_mkdir

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "secure_dir"
            result = secure_mkdir(target)
            assert result.is_dir()
            assert_private(target, 0o700)

    def test_creates_parent_directories(self) -> None:
        from openjarvis.security.file_utils import secure_mkdir

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "a" / "b" / "c"
            result = secure_mkdir(target)
            assert result.is_dir()

    def test_existing_directory_gets_permission_fix(self) -> None:
        from openjarvis.security.file_utils import secure_mkdir

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "existing"
            target.mkdir(mode=0o755)
            secure_mkdir(target)
            assert_private(target, 0o700)


class TestSecureCreate:
    """secure_create should create files with 0o600."""

    def test_creates_file_with_600(self) -> None:
        from openjarvis.security.file_utils import secure_create

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "secure_file.db"
            result = secure_create(target)
            assert result.exists()
            assert_private(target, 0o600)

    def test_existing_file_gets_permission_fix(self) -> None:
        from openjarvis.security.file_utils import secure_create

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "existing.db"
            target.write_text("data")
            os.chmod(target, 0o644)
            secure_create(target)
            assert_private(target, 0o600)

    def test_creates_parent_directory_with_700(self) -> None:
        from openjarvis.security.file_utils import secure_create

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "sub" / "file.db"
            secure_create(target)
            assert_private(target.parent, 0o700)
