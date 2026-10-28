"""P0-4B import-boundary regression: zero-provider RLMWorker.

Proves the worker import graph carries no provider/network stack, no
third-party requirement, and no user-profile coupling, while host-side
provider registration stays explicit and functional.

Subprocess tests use the dev interpreter (httpx IS installed) to prove
the worker import does not PULL it in. No network, no credentials.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
REPO_SRC = REPO / "src"

PROVIDER_MODULES = (
    "openjarvis.engine.nim",
    "openjarvis.engine.ollama",
    "openjarvis.engine.openai_compat_engines",
    "openjarvis.engine._openai_compat",
    "openjarvis.engine._http_async",
)

PUBLIC_ENGINE_SYMBOLS = (
    "EngineConnectionError",
    "EngineContextLengthError",
    "InferenceEngine",
    "discover_engines",
    "discover_models",
    "get_engine",
    "looks_like_context_length_error",
    "messages_to_dicts",
)


def _run_isolated(code: str) -> subprocess.CompletedProcess:
    workdir = Path(
        tempfile.mkdtemp(
            prefix="p04b-",
            dir="C:/Users/yingz/AppData/Local/Temp/opencode",
        )
    )
    env = {
        "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
        "PATH": os.environ.get("PATH", ""),
        # Neutral home (never the real user profile): optional dev-only
        # import chains may resolve it, but the required worker closure
        # must not need it (proven at closure level + in staged env).
        "USERPROFILE": str(workdir),
        "HOME": str(workdir),
        "PYTHONPATH": str(REPO_SRC),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }
    try:
        return subprocess.run(
            [sys.executable, "-s", "-B", "-c", code],
            env=env,
            cwd=str(workdir),
            capture_output=True,
            text=True,
            timeout=120,
        )
    finally:
        import shutil

        shutil.rmtree(workdir, ignore_errors=True)


class TestWorkerClosureBoundary:
    def test_closure_has_no_provider_modules(self) -> None:
        from openjarvis.sandbox.staged_runtime import resolve_closure

        closure = resolve_closure(REPO_SRC, "openjarvis.agents.rlm_worker")
        present = [m for m in PROVIDER_MODULES if m in closure.modules]
        assert present == [], f"provider modules in worker closure: {present}"

    def test_closure_has_no_third_party(self) -> None:
        from openjarvis.sandbox.staged_runtime import resolve_closure

        closure = resolve_closure(REPO_SRC, "openjarvis.agents.rlm_worker")
        assert closure.third_party == {}, closure.third_party

    def test_closure_has_no_config_or_paths(self) -> None:
        from openjarvis.sandbox.staged_runtime import resolve_closure

        closure = resolve_closure(REPO_SRC, "openjarvis.agents.rlm_worker")
        assert "openjarvis.core.config" not in closure.modules
        assert "openjarvis.core.paths" not in closure.modules


class TestWorkerImportIsolation:
    def test_engine_package_import_pulls_no_httpx(self) -> None:
        proc = _run_isolated(
            "import sys, openjarvis.engine; "
            "print('httpx' in sys.modules); "
            "print('openjarvis.engine.nim' in sys.modules)"
        )
        assert proc.returncode == 0, proc.stderr[-1500:]
        assert proc.stdout.split() == ["False", "False"]

    def test_worker_import_pulls_no_provider_modules(self) -> None:
        # NOTE: httpx absence is proven in the staged runtime (where
        # dev-only optional chains are absent), not here: the dev
        # environment intentionally has every optional module installed,
        # and an optional agent chain pulls connectors/weather.
        mods = ", ".join(f"'{m}'" for m in PROVIDER_MODULES)
        check = (
            "import sys; import openjarvis.agents.rlm_worker as w; "
            f"mods = [{mods}]; "
            "print([m for m in mods if m in sys.modules])"
        )
        proc = _run_isolated(check)
        assert proc.returncode == 0, proc.stderr[-1500:]
        assert proc.stdout.split() == ["[]"]

    def test_worker_import_needs_no_home_required_chain(self) -> None:
        # Staged simulation: optional agent modules are absent there, so
        # block them here (sys.modules None -> ImportError -> skipped by
        # the try/except guards, exactly as in the staged runtime). The
        # required chain must then import without touching Path.home().
        optional = (
            "simple,orchestrator,native_react,native_openhands,react,"
            "openhands,rlm,claude_code,opencode,operative,monitor,"
            "monitor_operative,deep_research,morning_digest,hybrid"
        )
        setup = (
            "import sys\n"
            f"for name in '{optional}'.split(','):\n"
            "    sys.modules['openjarvis.agents.' + name] = None\n"
            "import pathlib, os.path\n"
            "pathlib.Path.home = classmethod(\n"
            "    lambda cls: (_ for _ in ()).throw(\n"
            "        RuntimeError('home must not be resolved')))\n"
            "os.path.expanduser = (\n"
            "    lambda p: (_ for _ in ()).throw(\n"
            "        RuntimeError('expanduser must not be reached')))\n"
            "import openjarvis.agents.rlm_worker\n"
            "print('IMPORT_OK')"
        )
        proc = _run_isolated(setup)
        assert proc.returncode == 0, proc.stderr[-1500:]
        assert "IMPORT_OK" in proc.stdout

    def test_worker_registers_no_providers(self) -> None:
        proc = _run_isolated(
            "import openjarvis.agents.rlm_worker; "
            "from openjarvis.core.registry import EngineRegistry; "
            "print(sorted(EngineRegistry.keys()))"
        )
        assert proc.returncode == 0, proc.stderr[-1500:]
        assert proc.stdout.strip() == "[]"


class TestStubsBehaviorPreserved:
    def test_explicit_args_bypass_config(self, monkeypatch) -> None:
        # Method-level config import must keep working when invoked.
        import openjarvis.agents._stubs as stubs
        import openjarvis.core.config as config_mod

        def _boom():
            raise AssertionError("load_config must not be called")

        monkeypatch.setattr(config_mod, "load_config", _boom)

        class _Agent(stubs.BaseAgent):
            agent_id = "probe"
            _default_temperature = 0.3

            def run(self, *a, **k):
                raise NotImplementedError

        agent = _Agent(None, "probe-model", temperature=0.1, max_tokens=7)
        assert agent._temperature == 0.1
        assert agent._max_tokens == 7


class TestEnsureRegistered:
    def test_builtin_providers_registered(self) -> None:
        httpx = pytest.importorskip("httpx")
        del httpx
        from openjarvis.engine import ensure_registered

        ensure_registered()
        from openjarvis.core.registry import EngineRegistry

        assert EngineRegistry.contains("nim")
        assert EngineRegistry.contains("ollama")

    def test_idempotent(self) -> None:
        httpx = pytest.importorskip("httpx")
        del httpx
        from openjarvis.core.registry import EngineRegistry
        from openjarvis.engine import ensure_registered

        ensure_registered()
        before = sorted(EngineRegistry.keys())
        ensure_registered()
        ensure_registered()
        assert sorted(EngineRegistry.keys()) == before

    def test_public_api_symbols(self) -> None:
        import openjarvis.engine as engine_pkg

        for symbol in PUBLIC_ENGINE_SYMBOLS:
            assert hasattr(engine_pkg, symbol), symbol
        assert "ensure_registered" in engine_pkg.__all__ or hasattr(
            engine_pkg, "ensure_registered"
        )
        from openjarvis.engine import gemma_cpp  # noqa: F401  (submodule)
        assert hasattr(engine_pkg, "importlib")
        assert hasattr(engine_pkg, "_register_optional_engines")

    def test_discovery_enforces_registration(self, monkeypatch) -> None:
        httpx = pytest.importorskip("httpx")
        del httpx
        from openjarvis.core.registry import EngineRegistry
        from openjarvis.engine import _discovery

        entries = EngineRegistry._entries()
        saved = dict(entries)
        entries.clear()
        try:
            calls: list = []

            def _fake_make(key, config):
                calls.append(key)
                raise RuntimeError("no network in test")

            monkeypatch.setattr(_discovery, "_make_engine", _fake_make)
            from openjarvis.core.config import JarvisConfig

            _discovery.discover_engines(JarvisConfig())
            assert EngineRegistry.contains("nim"), (
                "discover_engines must enforce registration"
            )
            assert "nim" in calls
        finally:
            entries.clear()
            entries.update(saved)


class TestCredentialHygiene:
    MARKERS = ("API_KEY", "api_key", "SECRET", "passwd", "credential")

    def _sources(self):
        base = REPO / "src" / "openjarvis"
        return [
            base / "agents" / "rlm_worker.py",
            base / "agents" / "rlm_rpc.py",
            base / "sandbox" / "worker_launcher.py",
        ]

    def test_worker_sources_carry_no_credential_identifiers(self) -> None:
        for path in self._sources():
            text = path.read_text(encoding="utf-8")
            hits = [m for m in self.MARKERS if m in text]
            assert hits == [], f"{path.name}: {hits}"
