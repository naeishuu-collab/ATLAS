"""Deterministic Ollama loopback destination checks without network I/O."""

from __future__ import annotations

import socket

import pytest

from openjarvis.engine import ollama as ollama_mod
from openjarvis.engine.ollama import OllamaEngine
from openjarvis.server import cloud_router


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:11434",
        "https://127.0.0.1:11434",
        "http://[::1]:11434",
        "http://[::ffff:127.0.0.1]:11434",
    ],
)
def test_numeric_loopback_forms_remain_allowed(url: str) -> None:
    assert ollama_mod._is_loopback_host(url) is True
    assert ollama_mod._verified_loopback_url(url) is not None


@pytest.mark.parametrize(
    "url",
    [
        "http://192.0.2.1:11434",
        "http://[2001:db8::1]:11434",
        "http://2130706433:11434",
        "http://0x7f000001:11434",
        "http://127%2e0%2e0%2e1:11434",
        "http://user:pass@127.0.0.1:11434",
        "ftp://127.0.0.1:11434",
    ],
)
def test_ambiguous_or_remote_loopback_forms_are_denied(url: str) -> None:
    assert ollama_mod._is_loopback_host(url) is False
    with pytest.raises(ValueError, match="OLLAMA_REMOTE_HOST_DENIED"):
        OllamaEngine(host=url)


def test_localhost_is_resolved_and_pinned_to_numeric_loopback(monkeypatch) -> None:
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0)),
        ]

    monkeypatch.setattr(ollama_mod.socket, "getaddrinfo", fake_getaddrinfo)
    engine = OllamaEngine(host="http://localhost:11434")
    try:
        assert engine._host == "http://[::1]:11434"
        assert "localhost" not in str(engine._client.base_url)
        assert engine._client._trust_env is False
        async_client = engine._make_async_client()
        try:
            assert async_client._trust_env is False
        finally:
            import asyncio

            asyncio.run(async_client.aclose())
    finally:
        engine.close()


def test_non_loopback_localhost_resolution_is_denied(monkeypatch) -> None:
    monkeypatch.setattr(
        ollama_mod.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0))
        ],
    )
    assert ollama_mod._is_loopback_host("http://localhost:11434") is False
    with pytest.raises(ValueError, match="OLLAMA_REMOTE_HOST_DENIED"):
        OllamaEngine(host="http://localhost:11434")


def test_router_uses_the_same_pinned_localhost_policy(monkeypatch) -> None:
    monkeypatch.setenv("OLLAMA_HOST", "http://localhost:11434")
    monkeypatch.setattr(
        ollama_mod.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))
        ],
    )
    assert cloud_router._ollama_host() == "http://127.0.0.1:11434"
