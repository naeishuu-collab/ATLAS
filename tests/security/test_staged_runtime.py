"""P0-4 dedicated regression: Option B staged runtime builder/verifier.

Offline only. Real CPython files are COPIED to the approved Temp area
for the bootstrap tests; the repository itself is never modified and no
production code path is touched.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from openjarvis.sandbox import staged_runtime as sr

REPO = Path(__file__).resolve().parents[2]
REPO_SRC = REPO / "src"
REAL_PYTHON_HOME = Path(sys.base_prefix)
APPROVED_TMP = Path("C:/Users/yingz/AppData/Local/Temp/opencode")

EXPECTED_CLOSURE = sorted(
    [
        "openjarvis",
        "openjarvis.agents",
        "openjarvis.agents._stubs",
        "openjarvis.agents.rlm_repl",
        "openjarvis.agents.rlm_rpc",
        "openjarvis.agents.rlm_worker",
        "openjarvis.core",
        "openjarvis.core.events",
        "openjarvis.core.execution",
        "openjarvis.core.registry",
        "openjarvis.core.types",
        "openjarvis.core.utils",
        "openjarvis.engine",
        "openjarvis.engine._stubs",
    ]
)


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_repo(root: Path, extra: dict | None = None) -> Path:
    """Minimal stdlib-only worker repo used as builder input."""
    _write(root / "fxpkg" / "__init__.py", "")
    _write(
        root / "fxpkg" / "worker.py",
        "from fxpkg import helper\nVALUE = helper.VALUE + 1\n",
    )
    _write(root / "fxpkg" / "helper.py", "VALUE = 41\n")
    for rel, text in (extra or {}).items():
        _write(root / rel, text)
    return root


def make_python_home(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name in sr.CPYTHON_TOP_FILES:
        (root / name).write_bytes(b"fake-" + name.encode())
    _write(root / "Lib" / "os.py", "name = 'os'\n")
    _write(root / "Lib" / "test" / "test_os.py", "X = 1\n")
    (root / "Lib" / "__pycache__").mkdir(parents=True, exist_ok=True)
    (root / "Lib" / "__pycache__" / "os.pyc").write_bytes(b"junk")
    (root / "DLLs" / "_socket.pyd").parent.mkdir(parents=True, exist_ok=True)
    (root / "DLLs" / "_socket.pyd").write_bytes(b"fake-pyd")
    return root


@pytest.fixture()
def fx_dirs(tmp_path: Path):
    repo = make_repo(tmp_path / "repo")
    pyhome = make_python_home(tmp_path / "pyhome")
    return repo, pyhome, tmp_path


def _build(repo: Path, pyhome: Path, dest: Path, **kw):
    return sr.build_runtime(
        dest,
        python_home=pyhome,
        repo_src=repo,
        entry="fxpkg.worker",
        source_revision="fixture-rev-1",
        python_version="3.11.9-test",
        architecture="AMD64-test",
        **kw,
    )


# --------------------------------------------------------------------------
# manifest / verifier mechanics on fixtures
# --------------------------------------------------------------------------


class TestManifestDeterminism:
    def test_build_twice_identical_manifest(self, fx_dirs) -> None:
        repo, pyhome, tmp = fx_dirs
        first = _build(repo, pyhome, tmp / "r1")
        second = _build(repo, pyhome, tmp / "r2")
        assert first.ready and second.ready
        assert (
            sr.canonical_manifest_bytes(first.manifest)
            == sr.canonical_manifest_bytes(second.manifest)
        )
        assert first.tree_hash_value == second.tree_hash_value

    def test_verify_ok_and_ready(self, fx_dirs) -> None:
        repo, pyhome, tmp = fx_dirs
        result = _build(repo, pyhome, tmp / "r")
        checked = sr.verify_runtime(result.root)
        assert checked.ok, checked.errors
        assert sr.runtime_ready(result.root)
        assert checked.file_count == result.file_count
        assert checked.total_bytes == result.total_bytes

    def test_stdlib_test_and_pycache_excluded(self, fx_dirs) -> None:
        repo, pyhome, tmp = fx_dirs
        result = _build(repo, pyhome, tmp / "r")
        rels = [str(f["path"]) for f in result.manifest["files"]]
        assert not any("/test/" in r or r.endswith("/test") for r in rels)
        assert not any("__pycache__" in r for r in rels)
        assert not any("site-packages" in r for r in rels)


class TestExactTree:
    def _tamper(self, fx_dirs, mutate) -> tuple:
        repo, pyhome, tmp = fx_dirs
        result = _build(repo, pyhome, tmp / "r")
        mutate(result.root)
        return result

    def test_modified_file_rejected(self, fx_dirs) -> None:
        def mutate(root: Path) -> None:
            target = root / "worker" / "fxpkg" / "helper.py"
            target.write_bytes(target.read_bytes() + b"# evil\n")

        result = self._tamper(fx_dirs, mutate)
        checked = sr.verify_runtime(result.root)
        assert not checked.ok
        assert any("hash mismatch" in e for e in checked.errors)
        assert not sr.runtime_ready(result.root)

    def test_missing_file_rejected(self, fx_dirs) -> None:
        def mutate(root: Path) -> None:
            (root / "worker" / "fxpkg" / "helper.py").unlink()

        result = self._tamper(fx_dirs, mutate)
        checked = sr.verify_runtime(result.root)
        assert not checked.ok
        assert any("missing staged file" in e for e in checked.errors)

    def test_extra_file_rejected(self, fx_dirs) -> None:
        def mutate(root: Path) -> None:
            (root / "worker" / "fxpkg" / "evil.py").write_text("X=1\n")

        result = self._tamper(fx_dirs, mutate)
        checked = sr.verify_runtime(result.root)
        assert not checked.ok
        assert any("unexpected staged file" in e for e in checked.errors)

    def test_extra_pycache_rejected(self, fx_dirs) -> None:
        def mutate(root: Path) -> None:
            cache = root / "worker" / "fxpkg" / "__pycache__"
            cache.mkdir()
            (cache / "helper.pyc").write_bytes(b"junk")

        result = self._tamper(fx_dirs, mutate)
        checked = sr.verify_runtime(result.root)
        assert not checked.ok

    def test_staged_byte_semantics_survive_source_mutation(
        self, fx_dirs
    ) -> None:
        repo, pyhome, tmp = fx_dirs
        result = _build(repo, pyhome, tmp / "r")
        before = sr.canonical_manifest_bytes(result.manifest)
        (repo / "fxpkg" / "helper.py").write_text("VALUE = 9999\n")
        checked = sr.verify_runtime(result.root)
        assert checked.ok, checked.errors
        assert sr.canonical_manifest_bytes(result.manifest) == before


class TestManifestSafety:
    def _manifest_with(self, fx_dirs, path: str) -> Path:
        repo, pyhome, tmp = fx_dirs
        result = _build(repo, pyhome, tmp / "r")
        manifest = dict(result.manifest)
        files = [dict(f) for f in manifest["files"]]
        files[0] = dict(files[0])
        files[0]["path"] = path
        manifest["files"] = files
        (result.root / sr.MANIFEST_NAME).write_bytes(
            sr.canonical_manifest_bytes(manifest)
        )
        return result.root

    def test_traversal_rejected(self, fx_dirs) -> None:
        root = self._manifest_with(fx_dirs, "../evil.py")
        checked = sr.verify_runtime(root)
        assert not checked.ok

    def test_absolute_rejected(self, fx_dirs) -> None:
        root = self._manifest_with(fx_dirs, "/abs/evil.py")
        checked = sr.verify_runtime(root)
        assert not checked.ok

    def test_drive_rejected(self, fx_dirs) -> None:
        root = self._manifest_with(fx_dirs, "C:/evil.py")
        checked = sr.verify_runtime(root)
        assert not checked.ok

    def test_duplicate_normalized_rejected(self, fx_dirs) -> None:
        root = self._manifest_with(fx_dirs, "worker/./fxpkg/helper.py")
        checked = sr.verify_runtime(root)
        assert not checked.ok

    def test_schema_rejects_missing_field(self, fx_dirs) -> None:
        repo, pyhome, tmp = fx_dirs
        result = _build(repo, pyhome, tmp / "r")
        manifest = dict(result.manifest)
        del manifest["tree_hash"]
        (result.root / sr.MANIFEST_NAME).write_bytes(
            sr.canonical_manifest_bytes(manifest)
        )
        assert not sr.verify_runtime(result.root).ok

    def test_schema_rejects_bad_version(self, fx_dirs) -> None:
        repo, pyhome, tmp = fx_dirs
        result = _build(repo, pyhome, tmp / "r")
        manifest = dict(result.manifest)
        manifest["schema_version"] = 999
        (result.root / sr.MANIFEST_NAME).write_bytes(
            sr.canonical_manifest_bytes(manifest)
        )
        checked = sr.verify_runtime(result.root)
        assert not checked.ok

    def test_tree_hash_tamper_detected(self, fx_dirs) -> None:
        repo, pyhome, tmp = fx_dirs
        result = _build(repo, pyhome, tmp / "r")
        manifest = dict(result.manifest)
        manifest["tree_hash"] = "0" * 64
        (result.root / sr.MANIFEST_NAME).write_bytes(
            sr.canonical_manifest_bytes(manifest)
        )
        checked = sr.verify_runtime(result.root)
        assert not checked.ok
        assert any("tree_hash" in e for e in checked.errors)


class TestCredentialAndForbidden:
    def test_worker_token_module_blocked(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        _write(repo / "fxpkg" / "__init__.py", "")
        _write(
            repo / "fxpkg" / "worker.py",
            "from fxpkg import api_token\nV = api_token.TOK\n",
        )
        _write(repo / "fxpkg" / "api_token.py", "TOK = 1\n")
        pyhome = make_python_home(tmp_path / "pyhome")
        with pytest.raises(sr.CredentialBlocked):
            _build(repo, pyhome, tmp_path / "r")

    def test_env_file_in_tree_rejected(self, fx_dirs) -> None:
        repo, pyhome, tmp = fx_dirs
        result = _build(repo, pyhome, tmp / "r")
        (result.root / "worker" / ".env").write_text("K=V\n")
        checked = sr.verify_runtime(result.root)
        assert not checked.ok
        assert any(".env" in e for e in checked.errors)

    def test_pem_file_in_tree_rejected(self, fx_dirs) -> None:
        repo, pyhome, tmp = fx_dirs
        result = _build(repo, pyhome, tmp / "r")
        (result.root / "runtime" / "keycert.pem").write_text("X\n")
        checked = sr.verify_runtime(result.root)
        assert not checked.ok

    def test_stdlib_module_names_not_flagged(self, fx_dirs) -> None:
        # token.py / secrets.py are legitimate modules, not secrets.
        repo, pyhome, tmp = fx_dirs
        result = _build(repo, pyhome, tmp / "r")
        (result.root / "worker" / "fxpkg").mkdir(exist_ok=True)
        assert sr.verify_runtime(result.root).ok


class TestBuildAtomicity:
    def test_failed_build_never_ready_and_cleaned(
        self, fx_dirs, monkeypatch
    ) -> None:
        import openjarvis.sandbox.staged_runtime as mod

        repo, pyhome, tmp = fx_dirs
        real_copy = mod.shutil.copyfile
        calls = {"n": 0}

        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("injected copy failure")
            return real_copy(src, dst)

        monkeypatch.setattr(mod.shutil, "copyfile", flaky)
        with pytest.raises(OSError, match="injected copy failure"):
            _build(repo, pyhome, tmp / "r")
        assert not (tmp / "r").exists()
        leftovers = [
            p for p in tmp.iterdir() if ".build-" in p.name
        ]
        assert leftovers == []

    def test_dest_exists_refused(self, fx_dirs) -> None:
        repo, pyhome, tmp = fx_dirs
        (tmp / "r").mkdir()
        with pytest.raises(sr.StagedRuntimeError):
            _build(repo, pyhome, tmp / "r")

    def test_symlink_source_refused(self, tmp_path: Path) -> None:
        repo = make_repo(tmp_path / "repo")
        target = tmp_path / "real_helper.py"
        target.write_text("VALUE = 1\n")
        link = repo / "fxpkg" / "linked.py"
        try:
            link.symlink_to(target)
        except OSError as exc:
            pytest.skip(f"symlink creation unavailable: {exc}")
        pyhome = make_python_home(tmp_path / "pyhome")
        with pytest.raises(sr.StagedRuntimeError):
            sr.build_runtime(
                tmp_path / "r",
                python_home=pyhome,
                repo_src=repo,
                entry="fxpkg.linked",
                source_revision="fixture-rev-1",
            )


# --------------------------------------------------------------------------
# real closure: P0-1 revalidation + third-party fail-closed
# --------------------------------------------------------------------------


class TestRealClosure:
    def test_closure_pinned_to_14_modules(self) -> None:
        closure = sr.resolve_closure(REPO_SRC, sr.WORKER_ENTRY_DEFAULT)
        assert sorted(closure.modules) == EXPECTED_CLOSURE

    def test_closure_requires_no_third_party(self) -> None:
        # P0-4B: lazy engine boundary + _stubs config delay removed the
        # httpx import blocker (historical negative evidence: P0-4
        # ThirdPartyBlocked on httpx via engine/__init__ eager imports).
        closure = sr.resolve_closure(REPO_SRC, sr.WORKER_ENTRY_DEFAULT)
        assert closure.third_party == {}, closure.third_party

    def test_closure_has_no_provider_or_config(self) -> None:
        closure = sr.resolve_closure(REPO_SRC, sr.WORKER_ENTRY_DEFAULT)
        for module in closure.modules:
            assert "nim" not in module.split(".")
            assert module not in (
                "openjarvis.engine.ollama",
                "openjarvis.engine.openai_compat_engines",
                "openjarvis.engine._openai_compat",
                "openjarvis.engine._http_async",
                "openjarvis.core.config",
                "openjarvis.core.paths",
            )

    def test_real_closure_passes_credential_policy(self) -> None:
        closure = sr.resolve_closure(REPO_SRC, sr.WORKER_ENTRY_DEFAULT)
        for rel in closure.modules.values():
            sr.check_worker_source_path(rel)

    def test_real_inventory_metrics(self) -> None:
        inv = sr.inventory_runtime(
            REAL_PYTHON_HOME, REPO_SRC, sr.WORKER_ENTRY_DEFAULT
        )
        assert inv["closure_file_count"] == 14
        assert inv["worker_file_count"] == 14
        assert inv["third_party"] == {}
        assert inv["cpython_file_count"] >= 800
        assert inv["total_files"] >= 900
        assert inv["total_bytes"] > 30_000_000


# --------------------------------------------------------------------------
# host bootstrap (real staged interpreter, fixture worker only)
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def staged_boot_runtime():
    # P0-4B principal acceptance: the REAL worker closure (14 files),
    # staged with the real CPython runtime. Historical note: P0-4 built
    # only a fixture entry here because the real worker import was
    # blocked by httpx (ThirdPartyBlocked); that negative evidence is
    # preserved in git history and the P0-4 report.
    base = Path(
        tempfile.mkdtemp(prefix="p04-boot-", dir=str(APPROVED_TMP))
    )
    try:
        result = sr.build_runtime(
            base / "runtime",
            python_home=REAL_PYTHON_HOME,
            repo_src=REPO_SRC,
            entry=sr.WORKER_ENTRY_DEFAULT,
            source_revision="p04b-bootstrap",
            python_version="3.11.9",
            architecture="AMD64",
        )
        assert sr.runtime_ready(result.root)
        yield result.root
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _child_env(
    staged: Path, extra_path: str, home: str | None
) -> dict:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    path = (
        str(staged / "runtime")
        + os.pathsep
        + os.path.join(system_root, "System32")
    )
    env = {
        "SystemRoot": system_root,
        "PATH": path,
        "PYTHONHOME": str(staged / "runtime"),
        "PYTHONPATH": extra_path,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    if home is not None:
        env["USERPROFILE"] = home
        env["HOME"] = home
    return env


def _run_staged(
    staged: Path,
    worker_dir: Path,
    code: str,
    *,
    with_home: bool,
) -> subprocess.CompletedProcess:
    workdir = Path(
        tempfile.mkdtemp(prefix="p04-cwd-", dir=str(APPROVED_TMP))
    )
    try:
        return subprocess.run(
            [str(staged / "runtime" / "python.exe"), "-s", "-B", "-c", code],
            env=_child_env(
                staged, str(worker_dir), str(workdir) if with_home else None
            ),
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


class TestHostBootstrap:
    def test_real_rlm_worker_import_no_home_vars(
        self, staged_boot_runtime
    ) -> None:
        # No USERPROFILE/HOME/OPENJARVIS_HOME/XDG in the child env at
        # all: Path.home() would raise if reached. Success proves the
        # import-time profile coupling is removed.
        staged = staged_boot_runtime
        proc = _run_staged(
            staged,
            staged / "worker",
            "import openjarvis.agents.rlm_worker as w; "
            "print('RLM_WORKER_OK:' + w.__name__)",
            with_home=False,
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        assert "RLM_WORKER_OK:openjarvis.agents.rlm_worker" in proc.stdout

    def test_real_worker_has_no_provider_stack(
        self, staged_boot_runtime
    ) -> None:
        staged = staged_boot_runtime
        probe = (
            "import sys; "
            "import openjarvis.agents.rlm_worker; "
            "from openjarvis.core.registry import EngineRegistry; "
            "mods = [m for m in sys.modules "
            "if m == 'httpx' or m.startswith('openjarvis.engine.') "
            "and m not in ('openjarvis.engine', "
            "'openjarvis.engine._stubs')]; "
            "print(mods); "
            "print(sorted(EngineRegistry.keys())); "
            "print('openjarvis.core.config' in sys.modules)"
        )
        proc = _run_staged(
            staged, staged / "worker", probe, with_home=False
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        assert proc.stdout.split() == ["[]", "[]", "False"]

    def test_real_worker_syspath_independence(
        self, staged_boot_runtime
    ) -> None:
        staged = staged_boot_runtime
        proc = _run_staged(
            staged,
            staged / "worker",
            "import json, sys; import openjarvis.agents.rlm_worker; "
            "print(json.dumps(sys.path))",
            with_home=True,
        )
        assert proc.returncode == 0, proc.stderr[-2000:]
        joined = proc.stdout.strip().splitlines()[-1].lower()
        assert "jarvis-sol" not in joined
        assert ".venv" not in joined
        assert "site-packages" not in joined

    def test_no_pycache_written_by_bootstrap(
        self, staged_boot_runtime
    ) -> None:
        staged = staged_boot_runtime
        _run_staged(
            staged,
            staged / "worker",
            "import openjarvis.agents.rlm_worker",
            with_home=True,
        )
        checked = sr.verify_runtime(staged)
        assert checked.ok, checked.errors
