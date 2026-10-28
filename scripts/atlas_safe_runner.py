"""Default-deny, manifest-driven pytest runner for ATLAS safe lanes.

This runner is deliberately narrower than pytest. It does not provide an
unsafe/physical opt-in; real helpers, GUI mutation, network, cloud, and OS
policy lanes belong to a separately approved runner.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = Path(__file__).with_name("atlas_safe_test_manifest.json")
DENIED_MARKER_EXPR = (
    "not cloud and not live and not live_channel and not hub "
    "and not live_external and not modal"
)
DEFAULT_TIMEOUT_SECONDS = 900
MAX_TIMEOUT_SECONDS = 3600


class SafeRunnerError(ValueError):
    """Raised when a request is outside the safe runner contract."""


def _rel_repo_path(value: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        path = REPO_ROOT / path
    try:
        relative = path.resolve().relative_to(REPO_ROOT)
    except ValueError as exc:
        raise SafeRunnerError(f"path outside repository: {value}") from exc
    return relative.as_posix()


def load_manifest() -> dict[str, Any]:
    try:
        payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafeRunnerError(f"cannot load safe manifest: {MANIFEST}") from exc
    if payload.get("unknown_policy") != "deny":
        raise SafeRunnerError("safe manifest must use unknown_policy=deny")
    if not isinstance(payload.get("profiles"), dict):
        raise SafeRunnerError("safe manifest profiles are invalid")
    return payload


def validate_profile_paths(profile: str) -> list[str]:
    manifest = load_manifest()
    profile_data = manifest["profiles"].get(profile)
    if not isinstance(profile_data, dict):
        raise SafeRunnerError(f"unknown safe profile: {profile}")
    raw_tests = profile_data.get("tests")
    if not isinstance(raw_tests, list) or not raw_tests:
        raise SafeRunnerError(f"safe profile has no explicit tests: {profile}")

    denied = tuple(
        str(item).replace("\\", "/").rstrip("/")
        for item in manifest.get("denied_path_prefixes", [])
    )
    result: list[str] = []
    for raw in raw_tests:
        relative = _rel_repo_path(str(raw))
        if not relative.startswith("tests/"):
            raise SafeRunnerError(f"safe profile is not a test path: {relative}")
        if any(relative == item or relative.startswith(item + "/") for item in denied):
            raise SafeRunnerError(f"manifest path is explicitly denied: {relative}")
        path = REPO_ROOT / relative
        if path.suffix != ".py" or not path.is_file():
            raise SafeRunnerError(
                f"safe test path is missing or not Python: {relative}"
            )
        if relative in result:
            raise SafeRunnerError(f"duplicate safe test path: {relative}")
        result.append(relative)
    return result


def _validate_output_path(value: str, *, name: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise SafeRunnerError(f"{name} must be absolute")
    resolved = path.resolve()
    if name == "basetemp":
        try:
            resolved.relative_to(REPO_ROOT)
        except ValueError:
            pass
        else:
            raise SafeRunnerError("basetemp must be outside the source repository")
    if name == "junitxml" and resolved.suffix.lower() != ".xml":
        raise SafeRunnerError("junitxml must have an .xml suffix")
    resolved.parent.mkdir(parents=True, exist_ok=True)
    return resolved


def build_command(
    profile: str,
    *,
    basetemp: str,
    junitxml: str,
    collect_only: bool = False,
) -> list[str]:
    tests = validate_profile_paths(profile)
    base = _validate_output_path(basetemp, name="basetemp")
    junit = _validate_output_path(junitxml, name="junitxml")
    command = [sys.executable, "-m", "pytest", "-q", "--strict-markers", *tests]
    command.extend(
        [
            "-k",
            "not real_helper",
            "-m",
            DENIED_MARKER_EXPR,
            "--basetemp",
            str(base),
            "--junitxml",
            str(junit),
        ]
    )
    if collect_only:
        command.append("--collect-only")
    return command


def build_safe_environment(runtime_home: Path) -> dict[str, str]:
    """Copy only non-secret process settings and force offline test defaults."""
    secret_suffixes = ("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")
    network_keys = {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "OPENROUTER_API_KEY",
    }
    environment = {
        key: value
        for key, value in os.environ.items()
        if key not in network_keys and not key.upper().endswith(secret_suffixes)
    }
    for key in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTEST_CURRENT_TEST"):
        environment.pop(key, None)
    environment.update(
        {
            "ASTRA_SAFE_RUNNER": "1",
            "CI": "1",
            "OPENJARVIS_NO_UPDATE_CHECK": "1",
            "OPENJARVIS_HOME": str(runtime_home),
            "PYTHONUTF8": "1",
        }
    )
    return environment


def validate_junit(path: Path) -> dict[str, int]:
    """Reject empty, duplicate, or forbidden JUnit results."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise SafeRunnerError(f"invalid JUnit output: {path}") from exc
    testcases = list(root.iter("testcase"))
    if not testcases:
        raise SafeRunnerError("JUnit contains no testcase elements")
    ids = [f"{item.get('classname', '')}::{item.get('name', '')}" for item in testcases]
    if len(ids) != len(set(ids)):
        raise SafeRunnerError("duplicate testcase ID detected in JUnit")
    forbidden = [item for item in ids if "real_helper" in item]
    if forbidden:
        raise SafeRunnerError("real_helper testcase was selected by safe runner")
    return {
        "cases": len(testcases),
        "failures": sum(item.find("failure") is not None for item in testcases),
        "errors": sum(item.find("error") is not None for item in testcases),
        "skipped": sum(item.find("skipped") is not None for item in testcases),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, help="explicit manifest profile")
    parser.add_argument(
        "--basetemp",
        required=True,
        help="absolute temp directory outside repo",
    )
    parser.add_argument("--junitxml", required=True, help="absolute JUnit output path")
    parser.add_argument("--runtime-home", help="absolute isolated OPENJARVIS_HOME")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--collect-only", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--include-real-helper",
        action="store_true",
        help="always rejected; real helpers require a separate approved lane",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.include_real_helper:
            raise SafeRunnerError(
                "real_helper is not executable by the safe runner; "
                "use a separately approved lane"
            )
        if args.timeout <= 0 or args.timeout > MAX_TIMEOUT_SECONDS:
            raise SafeRunnerError(
                f"timeout must be in (0, {MAX_TIMEOUT_SECONDS}] seconds"
            )
        command = build_command(
            args.profile,
            basetemp=args.basetemp,
            junitxml=args.junitxml,
            collect_only=args.collect_only,
        )
        if args.dry_run:
            print(
                json.dumps(
                    {"command": command, "denied_markers": DENIED_MARKER_EXPR},
                    indent=2,
                )
            )
            return 0

        runtime_path = (
            Path(args.runtime_home).expanduser()
            if args.runtime_home
            else Path(tempfile.mkdtemp(prefix="atlas-safe-runner-"))
        )
        runtime_resolved = runtime_path.resolve()
        if (
            not runtime_path.is_absolute()
            or runtime_resolved == REPO_ROOT
            or REPO_ROOT in runtime_resolved.parents
        ):
            raise SafeRunnerError(
                "runtime-home must be absolute and outside repository"
            )
        runtime_path.mkdir(parents=True, exist_ok=True)
        environment = build_safe_environment(runtime_path)
        collection = subprocess.run(
            [*command, "--collect-only"],
            cwd=REPO_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=args.timeout,
            check=False,
        )
        if collection.returncode != 0 or "real_helper" in collection.stdout:
            raise SafeRunnerError(
                "safe collection rejected "
                f"(exit={collection.returncode}, forbidden selection or import error)"
            )
        if args.collect_only:
            print(collection.stdout, end="")
            return 0

        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=args.timeout,
            check=False,
        )
        summary = validate_junit(Path(args.junitxml))
        print(
            json.dumps(
                {"exit_code": completed.returncode, **summary},
                sort_keys=True,
            )
        )
        # A failed test remains a failed test; there is intentionally no fallback run.
        return completed.returncode
    except (OSError, subprocess.TimeoutExpired, SafeRunnerError) as exc:
        print(f"ATLAS_SAFE_RUNNER_DENIED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
