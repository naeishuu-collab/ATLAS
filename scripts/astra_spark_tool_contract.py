"""Bounded, non-mutating Spark tool-contract probe.

This script calls the production Ollama adapter and production ReAct parser,
but never executes a tool.  It is intentionally an explicit live probe rather
than a pytest test so a model call cannot enter the normal test suite.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass

from openjarvis.agents.native_react import REACT_SYSTEM_PROMPT, NativeReActAgent
from openjarvis.core.types import Message, Role
from openjarvis.engine.ollama import OllamaEngine
from openjarvis.tools._stubs import build_tool_descriptions
from openjarvis.tools.windows import WindowsActionTool, WindowsObserveTool

MODEL = "SparkLLM/Spark-X2.5-4B:latest"


@dataclass
class Proposal:
    sample: int
    category: str
    elapsed_seconds: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    raw_excerpt: str = ""
    action: str = ""
    action_value: str = ""
    error: str = ""


def _has_multiple_json_values(text: str) -> bool:
    """Detect a second top-level JSON value without accepting either value."""
    decoder = json.JSONDecoder()
    stripped = text.strip()
    if not stripped.startswith(("{", "[")):
        return False
    try:
        _, end = decoder.raw_decode(stripped)
    except json.JSONDecodeError:
        return False
    return bool(stripped[end:].lstrip().startswith(("{", "[")))


def _classify(raw: str, parser: NativeReActAgent) -> tuple[str, str, str]:
    parsed = parser._parse_response(raw)
    if parsed.get("parse_error"):
        category = (
            "multiple_json" if _has_multiple_json_values(raw) else "parser_reject"
        )
        return category, "", ""
    if parsed.get("final_answer"):
        return "final_answer", "", ""
    action = str(parsed.get("action", ""))
    if not action:
        return "no_action", "", ""
    try:
        arguments = json.loads(parsed.get("action_input") or "{}")
    except (TypeError, json.JSONDecodeError):
        return "parser_reject", action, ""
    if not isinstance(arguments, dict):
        return "parser_reject", action, ""
    if action == "windows_action":
        value = str(arguments.get("action", ""))
        if value not in {"click", "type_into"}:
            return "invalid_action", action, value
        required = {"observation_id", "target_id"}
        if not required.issubset(arguments):
            return "invalid_arguments", action, value
        return "valid_canonical", action, value
    if action == "windows_observe":
        return (
            "valid_canonical"
            if isinstance(arguments.get("hwnd"), int)
            else "invalid_arguments",
            action,
            "",
        )
    return "invalid_tool", action, ""


def _self_check() -> None:
    """Small executable check for the classifier's safety boundary."""
    engine = OllamaEngine(host="http://127.0.0.1:1", timeout=0.01)
    parser = NativeReActAgent(engine, MODEL)
    valid = json.dumps(
        {
            "action": "windows_action",
            "action_input": {
                "action": "type_into",
                "observation_id": "o",
                "target_id": "t",
                "value": "x",
            },
        }
    )
    invalid = valid.replace("type_into", "type")
    concatenated = '{"thought":"x"}{"action":"windows_action","action_input":{}}'
    assert _classify(valid, parser)[0] == "valid_canonical"
    assert _classify(invalid, parser)[0] == "invalid_action"
    assert _classify(concatenated, parser)[0] == "multiple_json"


def _prompt(tool_descriptions: str, *, strict: bool) -> list[Message]:
    system = REACT_SYSTEM_PROMPT.format(
        skill_examples="", tool_descriptions=tool_descriptions
    )
    if strict:
        system += (
            "\n\nCONTRACT PROBE: This is observation-only. Do not execute any tool. "
            "Return exactly one JSON object and nothing else. The only valid action "
            "value for windows_action edit replacement is exactly `type_into`; "
            "`type` is invalid. Use the supplied placeholder observation and target."
        )
        user = (
            "Prepare the canonical windows_action proposal for a previously observed, "
            "authorized disposable test editor. Do not call a tool and do not add a "
            "thought JSON object. Return one object with action=windows_action and "
            "action_input containing action=type_into, "
            "observation_id=OBSERVATION_PROBE, "
            "target_id=TARGET_PROBE, and value=ASTRA_SPARK_CONTRACT_PROBE."
        )
    else:
        user = (
            "A trusted runtime already observed and authorized a disposable edit "
            "control. Complete the requested edit now using observation_id "
            "OBSERVATION_PROBE and target_id TARGET_PROBE, setting its value to "
            "ASTRA_SPARK_CONTRACT_PROBE. Return the next tool action only."
        )
    return [
        Message(role=Role.SYSTEM, content=system),
        Message(role=Role.USER, content=user),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--mode", choices=("baseline", "strict"), default="baseline")
    args = parser.parse_args()
    if not 1 <= args.samples <= 20:
        parser.error("--samples must be between 1 and 20")
    _self_check()

    tools = [WindowsObserveTool(None), WindowsActionTool(None)]
    descriptions = build_tool_descriptions(tools)
    engine = OllamaEngine(timeout=180)
    react = NativeReActAgent(engine, args.model, tools=tools)
    messages = _prompt(descriptions, strict=args.mode == "strict")
    results: list[Proposal] = []
    for sample in range(1, args.samples + 1):
        started = time.perf_counter()
        try:
            response = engine.generate(
                messages,
                model=args.model,
                temperature=0.0,
                max_tokens=192,
                think=False,
            )
            raw = str(response.get("content", ""))
            usage = response.get("usage", {})
            category, action, action_value = _classify(raw, react)
            results.append(
                Proposal(
                    sample=sample,
                    category=category,
                    elapsed_seconds=round(time.perf_counter() - started, 3),
                    prompt_tokens=int(usage.get("prompt_tokens", 0) or 0),
                    completion_tokens=int(usage.get("completion_tokens", 0) or 0),
                    total_tokens=int(usage.get("total_tokens", 0) or 0),
                    raw_excerpt=" ".join(raw.split())[:300],
                    action=action,
                    action_value=action_value,
                )
            )
        except Exception as exc:  # bounded probe: classify, do not retry
            results.append(
                Proposal(
                    sample=sample,
                    category=(
                        "timeout"
                        if "timeout" in str(exc).lower()
                        else "engine_failure"
                    ),
                    elapsed_seconds=round(time.perf_counter() - started, 3),
                    error=f"{type(exc).__name__}: {exc}",
                )
            )

    counts = Counter(item.category for item in results)
    for category in (
        "valid_canonical",
        "invalid_action",
        "invalid_arguments",
        "invalid_tool",
        "parser_reject",
        "multiple_json",
        "timeout",
        "engine_failure",
        "no_action",
        "final_answer",
    ):
        counts.setdefault(category, 0)
    elapsed = [item.elapsed_seconds for item in results]
    print(json.dumps({
        "model": args.model,
        "mode": args.mode,
        "samples": args.samples,
        "retries": 0,
        "physical_tools_executed": 0,
        "counts": dict(sorted(counts.items())),
        "latency_seconds": {
            "min": min(elapsed),
            "max": max(elapsed),
            "mean": round(sum(elapsed) / len(elapsed), 3),
        },
        "proposals": [asdict(item) for item in results],
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
