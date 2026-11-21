"""Run the real ``jarvis serve`` command with an in-memory synthetic engine."""

from __future__ import annotations

import hashlib
import json
import sys
import threading
import time

from tests.agents.fake_engine import FakeEngine
from tests.integration.test_phase1_sprint15_controller_worker_e2e import (
    SyntheticEchoTool,
)

from openjarvis.core.registry import ToolRegistry

_mode = ""
_bootstrap = None
_hold_before_checkpoint = False


def _event(**value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def _fake_engine(_config, *_args, **_kwargs):
    engine = FakeEngine(
        [
            {
                "tool_calls": [
                    {
                        "id": "call-sprint15-synthetic-echo",
                        "name": "synthetic_echo",
                        "arguments": '{"value":"phase15"}',
                    }
                ]
            },
            {"content": "synthetic worker verified"},
        ]
    )
    if _mode == "a" and not _hold_before_checkpoint:
        original_generate = engine.generate

        def pause_before_first_tool(*args, **kwargs):
            if engine.call_count == 1:
                _event(event="checkpoint-ready")
                time.sleep(120)
            return original_generate(*args, **kwargs)

        engine.generate = pause_before_first_tool
    return "synthetic", engine


def _control_reader():
    while True:
        line = sys.stdin.readline()
        if not line:
            return
        try:
            value = json.loads(line)
            if value.get("operation") != "PROBE_OLD_EPOCH" or _bootstrap is None:
                continue
            try:
                _bootstrap.issue(value["binding"], validate_authority=lambda: None)
            except PermissionError:
                rejected = True
            else:
                rejected = False
            _event(event="old_epoch_rejected", rejected=rejected)
        except Exception:
            _event(event="control_error")


def main():
    global _bootstrap, _mode, _hold_before_checkpoint
    config = json.loads(sys.stdin.readline())
    _mode = config["mode"]
    _hold_before_checkpoint = config.get("hold_before_checkpoint", False)
    if _hold_before_checkpoint:
        from openjarvis.control.host_supervisor_broker import HostSupervisorClient

        execute_tool = HostSupervisorClient.execute_tool

        def hold_result(client, *args, **kwargs):
            result = execute_tool(client, *args, **kwargs)
            assert result.success
            _event(event="result-before-checkpoint")
            time.sleep(120)
            return result

        HostSupervisorClient.execute_tool = hold_result
    ToolRegistry._entries()["synthetic_echo"] = SyntheticEchoTool

    from openjarvis.control.host_supervisor_bootstrap import (
        HostSupervisorBootstrapClient,
    )

    original_bootstrap = HostSupervisorBootstrapClient.bootstrap

    def capture_bootstrap(client, *args, **kwargs):
        global _bootstrap
        _bootstrap = original_bootstrap(client, *args, **kwargs)
        principal = _bootstrap.principal
        _event(
            event="host_bootstrap",
            principal_id=principal.principal_id,
            session_fingerprint=hashlib.sha256(
                _bootstrap.session_id.encode("utf-8")
            ).hexdigest(),
        )
        return _bootstrap

    HostSupervisorBootstrapClient.bootstrap = capture_bootstrap
    import importlib

    serve_module = importlib.import_module("openjarvis.cli.serve")
    discovery = importlib.import_module("openjarvis.engine._discovery")
    serve_module.get_engine = _fake_engine
    serve_module.discover_engines = lambda _config: []
    serve_module.discover_models = lambda _engines: {}
    discovery.get_engine = _fake_engine
    threading.Thread(target=_control_reader, daemon=True).start()

    from openjarvis.cli import cli

    cli.main(
        args=[
            "--quiet",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(config["port"]),
            "--engine",
            "synthetic",
            "--model",
            "fake-model",
            "--host-bootstrap-pipe",
            config["pipe_name"],
            "--host-supervisor-pid",
            str(config["supervisor_pid"]),
            "--host-supervisor-created-filetime",
            str(config["supervisor_created_filetime"]),
        ],
        prog_name="jarvis",
        standalone_mode=True,
    )


if __name__ == "__main__":
    main()
