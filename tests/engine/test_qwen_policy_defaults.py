"""Regression tests for guarded Qwen production defaults."""

from __future__ import annotations

import httpx
import pytest
import respx

from openjarvis.engine import ollama as ollama_mod
from openjarvis.engine.ollama import OllamaEngine

HOST = "http://127.0.0.1:11434"
MODEL = "qwen3.5:9b"


def test_direct_engine_uses_guarded_qwen_defaults(monkeypatch) -> None:
    monkeypatch.setattr(ollama_mod, "_avail_ram_gb", lambda: 20.0)
    engine = OllamaEngine(host=HOST)
    with respx.mock:
        route = respx.post(HOST + "/api/chat").mock(
            return_value=httpx.Response(
                200, json={"message": {"content": "ok"}, "model": MODEL}
            )
        )
        engine.generate([], model=MODEL, max_tokens=8)
    payload = route.calls.last.request.content
    assert b'"keep_alive":"5m"' in payload
    assert b'"num_ctx":4096' in payload
    assert b'"num_thread":4' in payload


def test_direct_engine_denies_qwen_when_ram_is_unmeasurable(monkeypatch) -> None:
    monkeypatch.setattr(ollama_mod, "_avail_ram_gb", lambda: 0.0)
    engine = OllamaEngine(host=HOST)
    with respx.mock:
        route = respx.post(HOST + "/api/chat").mock(
            return_value=httpx.Response(
                200, json={"message": {"content": "must-not-send"}}
            )
        )
        with pytest.raises(ollama_mod.LocalModelResourceUnavailable):
            engine.generate([], model=MODEL, max_tokens=8)
    assert not route.called
