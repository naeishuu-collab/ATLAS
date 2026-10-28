"""Tests for the MLX engine (OpenAI-compatible)."""

from __future__ import annotations

import httpx
import pytest
import respx

from openjarvis.core.registry import EngineRegistry
from openjarvis.core.types import Message, Role
from openjarvis.engine._base import EngineConnectionError
from openjarvis.engine.openai_compat_engines import MLXEngine
from tests.engine._compat_auth import arm_engine, g


@pytest.fixture()
def engine() -> MLXEngine:
    EngineRegistry.register_value("mlx", MLXEngine)
    return MLXEngine(host="http://testhost:8080")


class TestMLXGenerate:
    def test_generate_returns_content(
        self, engine: MLXEngine, monkeypatch
    ) -> None:
        arm_engine(engine, monkeypatch)
        with respx.mock:
            respx.post("http://testhost:8080/v1/chat/completions").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "choices": [
                            {
                                "message": {"content": "4"},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {
                            "prompt_tokens": 8,
                            "completion_tokens": 1,
                            "total_tokens": 9,
                        },
                        "model": "mlx-model",
                    },
                )
            )
            result = g(
                engine, [Message(role=Role.USER, content="2+2")], model="mlx-model"
            )
        assert result["content"] == "4"

    def test_generate_connection_error(
        self, engine: MLXEngine, monkeypatch
    ) -> None:
        arm_engine(engine, monkeypatch)
        with respx.mock:
            respx.post("http://testhost:8080/v1/chat/completions").mock(
                side_effect=httpx.ConnectError("refused")
            )
            with pytest.raises(EngineConnectionError):
                g(engine, [Message(role=Role.USER, content="Hi")], model="m")


class TestMLXHealth:
    def test_health_true(self, engine: MLXEngine) -> None:
        with respx.mock:
            respx.get("http://testhost:8080/v1/models").mock(
                return_value=httpx.Response(200, json={"data": []})
            )
            assert engine.health() is True

    def test_health_false(self, engine: MLXEngine) -> None:
        with respx.mock:
            respx.get("http://testhost:8080/v1/models").mock(
                side_effect=httpx.ConnectError("refused")
            )
            assert engine.health() is False
