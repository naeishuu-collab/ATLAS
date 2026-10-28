"""Server-lane shadow binding (offline, no network).

Proves the FASTAPI agent lane carries the factory-built host supply:

* _LightweightSystem binds the process-cached bundle from app state
* caching: two facades over one app state share one bundle (one load)
* no host document -> legacy facade (host_supply None)
* a misconfigured document fails closed (raise at facade construction)
* the serve lane's scheduler JarvisSystem site passes host_supply from
  the factory (static pin, mirroring the SystemBuilder runtime proof)
"""

from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from openjarvis.agents.host_supply_factory import (
    MODE_SHADOW_ONLY,
    HostSupplyError,
)


def _doc(tmp_path, **over) -> str:
    doc: dict = {
        "mode": MODE_SHADOW_ONLY,
        "shadow_enabled": True,
        "model_registry": [{"engine": "fake", "provider": "local",
                            "model": "fake-model",
                            "capabilities": ["TEXT"], "ctx_limit": 4096,
                            "cost_per_1k": 0.0, "latency_p50_ms": 50.0,
                            "is_cloud": False, "tier": 0}],
        "snapshot": {"status": [["fake", "local", "fake-model", True]],
                     "version": 1, "issued_at": time.time(),
                     "max_age_s": 600.0},
        "privacy_policy": {"default": "PUBLIC"},
    }
    doc.update(over)
    path = tmp_path / "host_supply_document.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return str(path)


def _runtime(**extra):
    return SimpleNamespace(
        bus=None,
        memory_backend=object(),
        channel_backend=None,
        channel_bridge=None,
        knowledge_db_path=None,
        capability_policy=None,
        rate_limiter=None,
        **extra,
    )


def test_lightweight_system_binds_supply_from_app_state(tmp_path,
                                                        monkeypatch):
    pytest.importorskip("fastapi")
    from openjarvis.server import agent_manager_routes as amr

    path = _doc(tmp_path)
    monkeypatch.setenv("JARVIS_HOST_SUPPLY_PATH", path)
    runtime = _runtime()
    system = amr._LightweightSystem(
        engine=object(), model="fake-model", config=None, runtime=runtime)
    bundle = system.host_supply
    assert bundle is not None
    assert bundle.shadow_observer.enabled is True
    assert bundle.cloud_authorizer is None  # shadow doc can never mint one


def test_lightweight_system_supply_is_cached_per_process_state(tmp_path,
                                                               monkeypatch):
    pytest.importorskip("fastapi")
    from openjarvis.server import agent_manager_routes as amr

    monkeypatch.setenv("JARVIS_HOST_SUPPLY_PATH", _doc(tmp_path))
    runtime = _runtime()
    s1 = amr._LightweightSystem(engine=object(), model="m",
                                config=None, runtime=runtime)
    s2 = amr._LightweightSystem(engine=object(), model="m",
                                config=None, runtime=runtime)
    assert s1.host_supply is s2.host_supply  # one load, one bundle


def test_lightweight_system_without_env_doc_stays_legacy(tmp_path,
                                                         monkeypatch):
    pytest.importorskip("fastapi")
    from openjarvis.server import agent_manager_routes as amr

    monkeypatch.delenv("JARVIS_HOST_SUPPLY_PATH", raising=False)
    system = amr._LightweightSystem(engine=object(), model="m",
                                    config=None, runtime=_runtime())
    assert system.host_supply is None


def test_lightweight_system_invalid_document_fails_closed(tmp_path,
                                                          monkeypatch):
    pytest.importorskip("fastapi")
    from openjarvis.server import agent_manager_routes as amr

    path = _doc(tmp_path, unknown_key=1)
    monkeypatch.setenv("JARVIS_HOST_SUPPLY_PATH", path)
    with pytest.raises(HostSupplyError) as excinfo:
        amr._LightweightSystem(engine=object(), model="m",
                               config=None, runtime=_runtime())
    assert excinfo.value.code == "HOST_CONFIG_INVALID"


def test_serve_lane_scheduler_site_passes_host_supply():
    """Static pin: the serve lane wires the factory supply at startup."""
    import pathlib

    import openjarvis as _pkg

    serve_src = pathlib.Path(_pkg.__file__).parent / "cli" / "serve.py"
    src = serve_src.read_text(encoding="utf-8")
    assert "host_supply = _load_shadow_host_supply(" in src    # hoisted load
    assert "host_supply=host_supply," in src  # scheduler site + create_app
