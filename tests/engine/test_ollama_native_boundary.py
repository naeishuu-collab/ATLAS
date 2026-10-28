"""Nonphysical observability for the Ollama native tool-call boundary."""

from __future__ import annotations

import json
import os
from typing import Any

import httpx
import pytest

from openjarvis.core.execution import ModelCapabilityError, ToolRequirement
from openjarvis.core.types import Message, Role
from openjarvis.engine.ollama import OllamaEngine

_MODEL = "SparkLLM/Spark-X2.5-4B:latest"
_PROMPT = (
    'Call diagnostic_echo exactly once with value "ASTRA_TOOLCALL_PROBE". '
    "Do not answer in plain text."
)
_TOOL = {
    "type": "function",
    "function": {
        "name": "diagnostic_echo",
        "description": "Return the supplied diagnostic value without side effects.",
        "parameters": {
            "type": "object",
            "properties": {"value": {"type": "string"}},
            "required": ["value"],
            "additionalProperties": False,
        },
    },
}


def _messages() -> list[Message]:
    return [Message(role=Role.USER, content=_PROMPT)]


def test_remote_ollama_host_is_rejected_before_transport() -> None:
    with pytest.raises(ValueError, match="OLLAMA_REMOTE_HOST_DENIED"):
        OllamaEngine(host="https://remote.example")


def _mock_engine(responses: list[httpx.Response]):
    requests: list[dict[str, Any]] = []
    remaining = iter(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return next(remaining)

    engine = OllamaEngine(host="http://127.0.0.1:11434")
    engine._client.close()
    engine._client = httpx.Client(
        base_url="http://127.0.0.1:11434",
        transport=httpx.MockTransport(handler),
    )
    return engine, requests


def _generate(
    engine: OllamaEngine,
    *,
    tool_requirement: ToolRequirement = ToolRequirement.OPTIONAL,
) -> dict[str, Any]:
    return engine.generate(
        _messages(),
        model=_MODEL,
        temperature=0.7,
        max_tokens=128,
        tools=[_TOOL],
        tool_requirement=tool_requirement,
    )


def test_native_tool_call_is_preserved():
    engine, requests = _mock_engine(
        [
            httpx.Response(
                200,
                json={
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "call-probe",
                                "function": {
                                    "name": "diagnostic_echo",
                                    "arguments": {
                                        "value": "ASTRA_TOOLCALL_PROBE"
                                    },
                                },
                            }
                        ],
                    },
                    "model": _MODEL,
                },
            )
        ]
    )
    try:
        result = _generate(engine)
    finally:
        engine._client.close()

    assert requests[0]["tools"] == [_TOOL]
    assert requests[0]["think"] is False
    assert result["tool_calls"] == [
        {
            "id": "call-probe",
            "name": "diagnostic_echo",
            "arguments": '{"value": "ASTRA_TOOLCALL_PROBE"}',
        }
    ]


def test_plain_text_is_not_synthesized_as_a_tool_call():
    engine, requests = _mock_engine(
        [httpx.Response(200, json={"message": {"content": "plain"}})]
    )
    try:
        result = _generate(engine)
    finally:
        engine._client.close()

    assert "tools" in requests[0]
    assert result["content"] == "plain"
    assert "tool_calls" not in result


def test_legacy_xml_is_not_synthesized_as_a_tool_call():
    legacy = (
        '<action>observe</action>\n'
        '<parameter name="hwnd">123</parameter>'
    )
    engine, requests = _mock_engine(
        [httpx.Response(200, json={"message": {"content": legacy}})]
    )
    try:
        result = _generate(engine)
    finally:
        engine._client.close()

    assert "tools" in requests[0]
    assert result["content"] == legacy
    assert "tool_calls" not in result


def test_http_400_fallback_removes_tools_and_is_not_hidden():
    engine, requests = _mock_engine(
        [
            httpx.Response(400, json={"error": "tools not supported"}),
            httpx.Response(200, json={"message": {"content": "fallback"}}),
        ]
    )
    try:
        result = _generate(engine)
    finally:
        engine._client.close()

    assert len(requests) == 2
    assert requests[0]["tools"] == [_TOOL]
    assert "tools" not in requests[1]
    assert requests[1]["messages"] == requests[0]["messages"]
    assert requests[1]["options"] == requests[0]["options"]
    assert requests[1]["think"] == requests[0]["think"]
    assert result["content"] == "fallback"
    assert "tool_calls" not in result


def test_required_native_http_400_does_not_retry_without_tools():
    engine, requests = _mock_engine(
        [httpx.Response(400, json={"error": "tools not supported"})]
    )
    try:
        with pytest.raises(ModelCapabilityError) as error:
            _generate(engine, tool_requirement=ToolRequirement.REQUIRED_NATIVE)
    finally:
        engine._client.close()

    assert error.value.failure_code == "MODEL_CAPABILITY_INSUFFICIENT"
    assert error.value.retryable is False
    assert len(requests) == 1
    assert requests[0]["tools"] == [_TOOL]


def _capture_live_send(
    engine: OllamaEngine,
    records: list[dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_send = engine._client.send

    def send(request: httpx.Request, *args: Any, **kwargs: Any):
        payload = json.loads(request.content)
        record: dict[str, Any] = {
            "request": {
                "model": payload.get("model"),
                "messages": payload.get("messages"),
                "tools_present": bool(payload.get("tools")),
                "tool_names": [
                    item.get("function", {}).get("name")
                    for item in payload.get("tools", [])
                ],
                "tools": payload.get("tools"),
                "options": payload.get("options"),
                "think": payload.get("think"),
                "response_format": payload.get("format"),
            }
        }
        try:
            response = original_send(request, *args, **kwargs)
            response.read()
            record["status"] = response.status_code
            try:
                record["response"] = response.json()
            except ValueError:
                record["response"] = response.text
        except Exception as error:
            record["transport_error"] = f"{type(error).__name__}: {error}"
            records.append(record)
            raise
        records.append(record)
        return response

    monkeypatch.setattr(engine._client, "send", send)


@pytest.mark.skipif(
    os.environ.get("ASTRA_RUN_OLLAMA_NATIVE_PROBE") != "1",
    reason="Explicit nonphysical Ollama probe required",
)
def test_live_ollama_native_tool_probe(monkeypatch: pytest.MonkeyPatch):
    """One diagnostic inference; never executes a tool or physical action."""
    engine = OllamaEngine(timeout=180)
    records: list[dict[str, Any]] = []
    _capture_live_send(engine, records, monkeypatch)
    try:
        result = _generate(engine)
    finally:
        engine.close()

    last_response = records[-1].get("response", {}) if records else {}
    message = (
        last_response.get("message", {}) if isinstance(last_response, dict) else {}
    )
    raw_tool_calls = message.get("tool_calls", []) if isinstance(message, dict) else []
    first_status = records[0].get("status") if records else None
    fallback = (
        first_status == 400
        and len(records) >= 2
        and not records[1]["request"]["tools_present"]
    )
    if fallback:
        classification = "TOOLS_REMOVED_BY_HTTP_FALLBACK"
    elif raw_tool_calls:
        classification = "NATIVE_TOOL_CALL_SUCCESS"
    elif (
        isinstance(message, dict)
        and str(message.get("content", "")).lstrip().startswith("<action>")
    ):
        classification = "MODEL_RETURNED_LEGACY_FORMAT_WITH_TOOLS_PRESENT"
    elif isinstance(message, dict) and message.get("content"):
        classification = "MODEL_RETURNED_PLAIN_TEXT_WITH_TOOLS_PRESENT"
    else:
        classification = "OTHER"

    print(
        json.dumps(
            {
                "probe_count": 1,
                "classification": classification,
                "request_count": len(records),
                "fallback_triggered": fallback,
                "raw_message": message,
                "raw_tool_calls": raw_tool_calls,
                "adapter_normalized": {
                    "content": result.get("content"),
                    "tool_calls": result.get("tool_calls", []),
                    "finish_reason": result.get("finish_reason"),
                },
                "requests": records,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    assert records
