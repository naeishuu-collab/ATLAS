"""Host supply wiring trace pins (offline, static + construction proofs).

Records where host-owned routing supply actually exists today. Every
pin here fails loudly if a production construction site appears without
also wiring the shadow observer or egress authorizer supply.
"""

from __future__ import annotations

import ast
from pathlib import Path

import openjarvis


def _src(rel: str) -> str:
    return (Path(openjarvis.__file__).parent / rel).read_text(encoding="utf-8")


def _prod_sources() -> list[Path]:
    return [
        p for p in (Path(openjarvis.__file__).parent).rglob("*.py")
        if "tests" not in p.parts
    ]


def _construction_sites(cls_name: str) -> list[str]:
    """Return prod files that construct ``cls_name(...)``."""
    hits: list[str] = []
    for path in _prod_sources():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == cls_name):
                hits.append(f"{path.name}:{node.lineno}")
    return hits


# --- A. HOST CONSTRUCTION TRACE -----------------------------------------


def _files(cls_name: str) -> set[str]:
    return {hit.rsplit(":", 1)[0] for hit in _construction_sites(cls_name)}


def test_cloud_authorizer_is_built_only_by_the_host_supply_factory() -> None:
    """Supply now exists in exactly one place: the factory.

    No CLI/server/builder/executor site may mint an authorizer on its own;
    every engine/router entry point must receive one from host supply.
    """
    assert _files("CloudDispatchAuthorizer") == {"host_supply_factory.py"}


def test_registry_and_snapshot_are_built_only_by_the_host_supply_factory() -> None:
    """One construction site keeps host routing authority in one place."""
    assert _files("ModelCardRegistry") == {"host_supply_factory.py"}
    assert _files("build_snapshot") == {"host_supply_factory.py"}
    # Ledger fallback construction stays confined to the enforcement
    # points (engine adapters, direct router, LLM tool). It is only
    # reachable when dispatch is already denied for lack of a host seal,
    # so a new silent site is a signal, not an accident.
    assert _files("CloudDispatchLedger") <= {
        "host_supply_factory.py", "cloud.py", "cloud_router.py",
        "litellm.py", "nim.py", "_openai_compat.py", "llm_tool.py"}


def test_host_supply_path_is_the_only_supply_source() -> None:
    """The supply document is named by one env var, read by one loader."""
    from openjarvis.agents.host_supply_factory import (
        HOST_SUPPLY_PATH_ENV,
        load_host_supply_from_env,
    )

    assert HOST_SUPPLY_PATH_ENV == "JARVIS_HOST_SUPPLY_PATH"
    factory = _src("agents/host_supply_factory.py")
    assert "os.environ.get(HOST_SUPPLY_PATH_ENV" in factory
    # No wiring site may read the variable directly.
    for rel in ("system/builder.py", "system/core.py", "agents/executor.py",
                "cli/serve.py", "server/routes.py", "engine/cloud.py",
                "engine/ollama.py", "server/cloud_router.py"):
        assert "JARVIS_HOST_SUPPLY_PATH" not in _src(rel)
    assert callable(load_host_supply_from_env)


def test_cloud_engine_accepts_authorizer_kwargs() -> None:
    """The engine seam exists (owner-free surface); only supply is missing."""
    sig = ast.dump(ast.parse(_src("engine/cloud.py")))
    assert "authorizer" in sig and "dispatch_ledger" in sig


def test_router_stream_entry_exists_without_supply() -> None:
    """`stream_cloud` requires the grant; its prod caller passes none."""
    src = _src("server/cloud_router.py")
    assert "ROUTER_EGRESS_FLAG" in src
    assert "authorizer: Any = None" in src
    routes = _src("server/routes.py")
    assert "stream_cloud(" in routes
    # The call site supplies model/messages/temps only — no grant.
    call = routes[routes.index("stream_cloud("):][:160]
    assert "cloud_dispatch" not in call


# --- B. SHADOW SUPPLY SOURCE -------------------------------------------


def test_jarsv_system_has_no_shadow_supply_fields() -> None:
    """Shadow-first requires new host-owned fields; none exist yet."""
    core = _src("system/core.py")
    for field in ("shadow_observer", "model_card_registry",
                  "provider_snapshot", "shadow_observer_enabled"):
        assert field not in core


def test_shadow_observer_is_default_off_and_import_safe() -> None:
    from openjarvis.agents.shadow_observer import (
        SHADOW_OBSERVER_ENABLED,
        ShadowObserver,
    )

    assert SHADOW_OBSERVER_ENABLED is False
    assert ShadowObserver().enabled is False


def test_config_has_no_routing_supply_fields() -> None:
    """Supply comes from the host document, not from core config."""
    cfg = _src("core/config.py")
    for field in ("model_card", "provider_snapshot", "cloud_allowlist",
                  "egress_authorizer", "host_supply"):
        assert field not in cfg


# --- C. OWNER / CONFLICT ----------------------------------------------


def test_shared_runtime_files_are_already_dirty() -> None:
    """Documents the conflict surface: these files carry uncommitted
    parallel work, so any diff needs the owner's approval."""
    executor = _src("agents/executor.py")
    assert "model_gate" in executor  # prior seam already landed
    ollama = _src("engine/ollama.py")
    assert "OLLAMA_REMOTE_HOST_DENIED" in ollama  # parallel hardening


def test_router_policy_seam_remains_fail_open_and_frozen() -> None:
    executor = _src("agents/executor.py")
    assert "router_policy" in executor
    assert "pass  # Fall back to configured model" in executor
