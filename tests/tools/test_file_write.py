"""Tests for the file_write tool."""

from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest

from openjarvis.core.types import ToolCall
from openjarvis.tools._stubs import ToolExecutor
from openjarvis.tools.file_write import FileWriteTool


class TestFileWriteTool:
    def test_exact_bytes_verified_through_executor(self, tmp_path):
        target = tmp_path / "exact.txt"
        text = "Japanese 日本語\nnext line\n"
        result = ToolExecutor([FileWriteTool()]).execute(
            ToolCall(
                "write",
                "file_write",
                json.dumps({"path": str(target), "content": text}),
            )
        )
        assert result.success
        assert result.metadata["execution"]["state"] == "VERIFIED"
        assert target.read_bytes() == text.encode("utf-8")
        assert result.metadata["atomic"] is True
        assert result.metadata["artifacts"] == [
            {
                "type": "file",
                "path": str(target.resolve()),
                "size_bytes": len(text.encode("utf-8")),
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            }
        ]

    def test_staging_failure_keeps_original_and_removes_temporary(
        self, tmp_path, monkeypatch
    ):
        target = tmp_path / "target.txt"
        target.write_bytes(b"original")

        def fail_fsync(_):
            raise OSError("fixture disk failure")

        monkeypatch.setattr("openjarvis.tools.file_write.os.fsync", fail_fsync)
        result = FileWriteTool().execute(path=str(target), content="replacement")
        assert not result.success
        assert result.execution_state.value == "NOT_STARTED"
        assert target.read_bytes() == b"original"
        assert list(tmp_path.glob(".astra-write-*")) == []

    def test_replacement_failure_keeps_original(self, tmp_path, monkeypatch):
        target = tmp_path / "target.txt"
        target.write_bytes(b"original")

        def fail_replace(*_):
            raise PermissionError("fixture file locked")

        monkeypatch.setattr("openjarvis.tools.file_write.os.replace", fail_replace)
        result = FileWriteTool().execute(path=str(target), content="replacement")
        assert not result.success
        assert target.read_bytes() == b"original"
        assert list(tmp_path.glob(".astra-write-*")) == []

    def test_lost_completion_after_atomic_append_cannot_append_twice(
        self, tmp_path, monkeypatch
    ):
        target = tmp_path / "target.txt"
        target.write_bytes(b"before")
        original = os.replace

        def replace_then_lose_result(source, destination):
            original(source, destination)
            raise OSError("completion lost")

        monkeypatch.setattr(
            "openjarvis.tools.file_write.os.replace", replace_then_lose_result
        )
        executor = ToolExecutor([FileWriteTool()])
        arguments = json.dumps(
            {"path": str(target), "content": " after", "mode": "append"}
        )
        first = executor.execute(ToolCall("first", "file_write", arguments))
        assert not first.success
        assert first.metadata["execution"]["state"] == "UNKNOWN_OUTCOME"
        assert not executor.execute(ToolCall("second", "file_write", arguments)).success
        assert target.read_bytes() == b"before after"
        assert list(tmp_path.glob(".astra-write-*")) == []

    def test_target_change_before_commit_fails_closed(self, tmp_path, monkeypatch):
        target = tmp_path / "target.txt"
        target.write_bytes(b"original")
        original = os.fsync

        def change_during_staging(fd):
            original(fd)
            target.write_bytes(b"external modification")

        monkeypatch.setattr(
            "openjarvis.tools.file_write.os.fsync", change_during_staging
        )
        result = FileWriteTool().execute(path=str(target), content="replacement")
        assert not result.success
        assert "STALE_TARGET" in result.content
        assert target.read_bytes() == b"external modification"

    def test_observation_mismatch_fails_instead_of_claiming_success(
        self, tmp_path, monkeypatch
    ):
        from pathlib import Path

        target = tmp_path / "target.txt"
        original = Path.read_bytes

        def incorrect_observation(path):
            return b"unexpected" if path == target else original(path)

        monkeypatch.setattr(Path, "read_bytes", incorrect_observation)
        result = FileWriteTool().execute(path=str(target), content="replacement")
        assert not result.success
        assert result.execution_state.value == "UNKNOWN_OUTCOME"

    def test_concurrent_append_does_not_lose_data(self, tmp_path):
        target = tmp_path / "target.txt"
        target.write_bytes(b"start\n")

        def append(index):
            return FileWriteTool().execute(
                path=str(target), content=f"{index}\n", mode="append"
            )

        with ThreadPoolExecutor(4) as callers:
            results = list(callers.map(append, range(12)))
        assert all(result.success for result in results), [
            result.content for result in results if not result.success
        ]
        assert set(target.read_text().splitlines()) == {"start"} | {
            str(i) for i in range(12)
        }

    def test_append_result_size_is_bounded(self, tmp_path, monkeypatch):
        target = tmp_path / "target.txt"
        target.write_bytes(b"original")
        monkeypatch.setattr("openjarvis.tools.file_write._MAX_SIZE_BYTES", 10)
        result = FileWriteTool().execute(
            path=str(target), content="append", mode="append"
        )
        assert not result.success
        assert target.read_bytes() == b"original"

    def test_spec(self):
        tool = FileWriteTool()
        assert tool.spec.name == "file_write"
        assert tool.spec.category == "filesystem"
        assert "file:write" in tool.spec.required_capabilities

    def test_no_path(self):
        tool = FileWriteTool()
        result = tool.execute(path="", content="hello")
        assert result.success is False
        assert "No path" in result.content

    def test_no_content(self):
        tool = FileWriteTool()
        result = tool.execute(path="/tmp/test.txt")
        assert result.success is False
        assert "No content" in result.content

    def test_write_file(self, tmp_path):
        f = tmp_path / "test.txt"
        tool = FileWriteTool()
        result = tool.execute(path=str(f), content="hello world\n")
        assert result.success is True
        assert f.read_text(encoding="utf-8") == "hello world\n"
        assert result.metadata["size_bytes"] > 0
        assert result.metadata["path"] == str(f.resolve())

    def test_append_mode(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("line1\n", encoding="utf-8")
        tool = FileWriteTool()
        result = tool.execute(path=str(f), content="line2\n", mode="append")
        assert result.success is True
        assert f.read_text(encoding="utf-8") == "line1\nline2\n"

    def test_create_dirs(self, tmp_path):
        f = tmp_path / "sub" / "deep" / "test.txt"
        tool = FileWriteTool()
        result = tool.execute(
            path=str(f),
            content="nested",
            create_dirs=True,
        )
        assert result.success is True
        assert f.read_text(encoding="utf-8") == "nested"

    def test_create_dirs_false_missing_parent(self, tmp_path):
        f = tmp_path / "nonexistent" / "test.txt"
        tool = FileWriteTool()
        result = tool.execute(path=str(f), content="data")
        assert result.success is False
        assert "Parent directory does not exist" in result.content

    def test_blocks_env_file(self, tmp_path):
        f = tmp_path / ".env"
        tool = FileWriteTool()
        result = tool.execute(path=str(f), content="SECRET=foo")
        assert result.success is False
        assert "sensitive" in result.content.lower()

    def test_blocks_pem_file(self, tmp_path):
        f = tmp_path / "server.pem"
        tool = FileWriteTool()
        result = tool.execute(
            path=str(f),
            content="-----BEGIN CERTIFICATE-----",
        )
        assert result.success is False
        assert "sensitive" in result.content.lower()

    def test_blocks_credentials_json(self, tmp_path):
        f = tmp_path / "credentials.json"
        tool = FileWriteTool()
        result = tool.execute(path=str(f), content='{"token": "abc"}')
        assert result.success is False
        assert "sensitive" in result.content.lower()

    @pytest.mark.parametrize(
        "alias_name,target_name", [("notes.txt", ".env"), (".env", "notes.txt")]
    )
    @pytest.mark.parametrize("target_exists", [True, False])
    @pytest.mark.parametrize("mode", ["write", "append"])
    def test_blocks_symlink_alias_to_sensitive_file(
        self, tmp_path, alias_name, target_name, target_exists, mode
    ):
        sensitive = tmp_path / target_name
        if target_exists:
            sensitive.write_text("SECRET=foo", encoding="utf-8")
        alias = tmp_path / alias_name
        try:
            alias.symlink_to(sensitive)
        except OSError:
            pytest.skip("filesystem does not permit creating symlinks")

        result = FileWriteTool().execute(
            path=str(alias), content="SECRET=bar", mode=mode
        )

        assert result.success is False
        assert "sensitive" in result.content.lower()
        if target_exists:
            assert sensitive.read_text(encoding="utf-8") == "SECRET=foo"
        else:
            assert not sensitive.exists()

    def test_allowed_dirs_blocks(self, tmp_path):
        f = tmp_path / "test.txt"
        tool = FileWriteTool(allowed_dirs=["/some/other/dir"])
        result = tool.execute(path=str(f), content="data")
        assert result.success is False
        assert "Access denied" in result.content

    def test_allowed_dirs_permits(self, tmp_path):
        f = tmp_path / "ok.txt"
        tool = FileWriteTool(allowed_dirs=[str(tmp_path)])
        result = tool.execute(path=str(f), content="ok data")
        assert result.success is True
        assert f.read_text(encoding="utf-8") == "ok data"

    def test_file_size_limit(self, tmp_path):
        f = tmp_path / "big.txt"
        # 10 MB + 1 byte exceeds the limit
        big_content = "x" * (10_485_761)
        tool = FileWriteTool()
        result = tool.execute(path=str(f), content=big_content)
        assert result.success is False
        assert "too large" in result.content.lower()

    def test_write_creates_new_file(self, tmp_path):
        f = tmp_path / "new_file.txt"
        assert not f.exists()
        tool = FileWriteTool()
        result = tool.execute(path=str(f), content="brand new")
        assert result.success is True
        assert f.exists()
        assert f.read_text(encoding="utf-8") == "brand new"

    def test_overwrite_existing_file(self, tmp_path):
        f = tmp_path / "existing.txt"
        f.write_text("old content", encoding="utf-8")
        tool = FileWriteTool()
        result = tool.execute(path=str(f), content="new content")
        assert result.success is True
        assert f.read_text(encoding="utf-8") == "new content"

    def test_invalid_mode(self, tmp_path):
        f = tmp_path / "test.txt"
        tool = FileWriteTool()
        result = tool.execute(
            path=str(f),
            content="data",
            mode="invalid",
        )
        assert result.success is False
        assert "Invalid mode" in result.content
