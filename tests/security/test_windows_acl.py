"""Windows private-data negative cases, using real filesystem identities."""

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from openjarvis.security.file_utils import (
    secure_create,
    secure_mkdir,
    secure_write_text,
)
from tests.security.private_permissions import assert_private

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows DACL semantics")


def test_nested_new_directories_are_private(tmp_path: Path) -> None:
    secure_mkdir(tmp_path / "new" / "nested")
    assert_private(tmp_path / "new", 0o700)
    assert_private(tmp_path / "new" / "nested", 0o700)


def test_hard_link_refused_without_changing_alias(tmp_path: Path) -> None:
    original = tmp_path / "original"
    original.write_text("unchanged")
    alias = tmp_path / "alias"
    os.link(original, alias)
    with pytest.raises(OSError, match="multiple hard links"):
        secure_create(alias)
    assert original.read_text() == "unchanged"


def test_directory_cannot_be_secured_as_file(tmp_path: Path) -> None:
    target = tmp_path / "directory"
    target.mkdir()
    with pytest.raises(OSError, match="type/reparse identity mismatch"):
        secure_create(target)


def test_junction_ancestor_refused(tmp_path: Path) -> None:
    import subprocess

    target = tmp_path / "real"
    target.mkdir()
    junction = tmp_path / "junction"
    # cmd builtin works without symlink privileges; all paths are test-owned.
    command = f'cmd.exe /d /c mklink /J "{junction}" "{target}"'
    subprocess.run(command, check=True, capture_output=True, timeout=10)
    try:
        with pytest.raises(OSError, match="reparse point"):
            secure_create(junction / "secret")
        assert not (target / "secret").exists()
    finally:
        junction.rmdir()


def test_atomic_replacement_has_private_dacl_before_secret_write(
    tmp_path: Path,
) -> None:
    target = tmp_path / "secret.json"
    real_fdopen = os.fdopen

    def inspect(fd, *args, **kwargs):
        (temporary,) = tmp_path.glob(".secret.json.*.tmp")
        assert temporary.read_bytes() == b""
        assert_private(temporary, 0o600)
        return real_fdopen(fd, *args, **kwargs)

    with patch("openjarvis.security.file_utils.os.fdopen", side_effect=inspect):
        secure_write_text(target, "secret")
    assert target.read_text() == "secret"
    assert_private(target, 0o600)


def test_acl_error_preserves_old_secret(tmp_path: Path) -> None:
    target = tmp_path / "secret.json"
    secure_write_text(target, "old")
    from openjarvis.security.windows_acl import private_path

    def refuse(path, **kwargs):
        if not kwargs["directory"]:
            raise PermissionError("ACL refused")
        return private_path(path, **kwargs)

    with patch("openjarvis.security.windows_acl.private_path", side_effect=refuse):
        with pytest.raises(PermissionError, match="ACL refused"):
            secure_write_text(target, "new")
    assert target.read_text() == "old"
    assert list(tmp_path.glob(".secret.json.*.tmp")) == []


def test_unsupported_mode_is_not_silently_reinterpreted(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="owner-only"):
        secure_mkdir(tmp_path / "shared", 0o755)
    assert not (tmp_path / "shared").exists()


def test_securing_directory_does_not_rewrite_child_acl(tmp_path: Path) -> None:
    child = tmp_path / "existing"
    child.write_text("data")
    secure_mkdir(tmp_path)
    assert child.read_text() == "data"
    child.write_text("updated")
    assert child.read_text() == "updated"


def test_false_acl_success_is_detected_before_returning(tmp_path: Path) -> None:
    from openjarvis.security.windows_acl import _api, private_path

    target = tmp_path / "existing"
    target.write_text("fixture")
    kernel, security = _api()
    with (
        patch("openjarvis.security.windows_acl._api", return_value=(kernel, security)),
        patch.object(security, "SetSecurityInfo", return_value=0),
        pytest.raises(PermissionError, match="DACL verification failed"),
    ):
        private_path(target, directory=False, create=False)
    assert target.read_text() == "fixture"


def test_foreign_owner_refused_before_dacl_change(tmp_path: Path) -> None:
    from openjarvis.security.windows_acl import _api, private_path

    target = tmp_path / "existing"
    target.write_text("fixture")
    kernel, security = _api()
    with (
        patch("openjarvis.security.windows_acl._api", return_value=(kernel, security)),
        patch.object(security, "EqualSid", return_value=0),
        patch.object(security, "SetSecurityInfo") as apply,
        pytest.raises(PermissionError, match="owned by another user"),
    ):
        private_path(target, directory=False, create=False)
    apply.assert_not_called()
    assert target.read_text() == "fixture"
