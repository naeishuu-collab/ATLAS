from __future__ import annotations

import hashlib
import os

from openjarvis.agents.executor import AgentExecutor
from openjarvis.agents.manager import AgentManager
from openjarvis.agents.plan import DurablePlan
from openjarvis.agents.verification import verify_artifact, verify_goal_artifacts
from openjarvis.core.events import EventBus


def _reference(path, content: bytes) -> dict:
    return {
        "type": "file",
        "path": str(path),
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def test_artifact_verification_checks_content_and_staleness(tmp_path):
    path = tmp_path / "report.txt"
    path.write_bytes(b"verified report")
    reference = _reference(path, b"verified report")
    assert verify_artifact(reference).status == "VERIFIED"

    path.write_bytes(b"different report")
    stale = verify_artifact(reference)
    assert stale.status == "STALE_ARTIFACT"
    assert stale.actual_sha256 != stale.expected_sha256


def test_artifact_changed_during_verification_is_stale(tmp_path, monkeypatch):
    path = tmp_path / "changing.txt"
    content = b"original content" * 256
    path.write_bytes(content)
    original_fstat = os.fstat
    before = path.stat()
    expected_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    calls = 0

    def change_before_final_stat(file_descriptor):
        nonlocal calls
        actual = original_fstat(file_descriptor)
        identity = (
            actual.st_dev,
            actual.st_ino,
            actual.st_size,
            actual.st_mtime_ns,
        )
        if identity == expected_identity:
            calls += 1
            if calls == 2:
                path.write_bytes(b"replaced during verification")
                return original_fstat(file_descriptor)
        return actual

    monkeypatch.setattr(
        "openjarvis.agents.verification.os.fstat", change_before_final_stat
    )
    result = verify_artifact(_reference(path, content))
    assert calls == 2
    assert result.status == "STALE_ARTIFACT"
    assert result.reason == "artifact changed during verification"


def test_missing_invalid_and_non_file_artifacts_do_not_verify(tmp_path):
    missing = tmp_path / "missing.txt"
    assert verify_artifact(_reference(missing, b"x")).status == "MISSING_ARTIFACT"
    assert verify_artifact({"type": "file", "path": "bad"}).status == (
        "VERIFICATION_UNAVAILABLE"
    )

    directory = tmp_path / "directory"
    directory.mkdir()
    assert verify_artifact(_reference(directory, b"")).status == "STALE_ARTIFACT"


def test_goal_requires_expected_artifact_and_all_artifacts_must_match(tmp_path):
    assert verify_goal_artifacts([]).status == "VERIFICATION_UNAVAILABLE"
    path = tmp_path / "result.txt"
    path.write_bytes(b"ok")
    verified = verify_goal_artifacts([_reference(path, b"ok")])
    assert verified.status == "VERIFIED"
    path.write_bytes(b"no")
    assert verify_goal_artifacts([_reference(path, b"ok")]).status == (
        "VERIFICATION_FAILED"
    )


def test_executor_goal_acceptance_requires_a_completed_durable_plan(tmp_path):
    manager = AgentManager(str(tmp_path / "acceptance.db"))
    agent = manager.create_agent(
        "artifact-acceptance",
        agent_type="orchestrator",
        config={"model": "fake-model", "instruction": "test"},
    )
    executor = AgentExecutor(manager, EventBus())
    try:
        manager.start_tick(agent["id"])
        manager.save_checkpoint(
            agent["id"],
            "artifact-acceptance-tick",
            {"lifecycle": "RUNNING", "resumable": True},
            {"execution_id": "artifact-acceptance-execution"},
        )
        checkpoint = manager.get_latest_checkpoint(agent["id"])
        assert checkpoint is not None
        artifact_path = tmp_path / "final.txt"
        artifact_path.write_bytes(b"complete")
        reference = _reference(artifact_path, b"complete")
        unavailable = executor.verify_goal_acceptance(
            agent["id"], expected_artifacts=[reference]
        )
        assert unavailable["status"] == "VERIFICATION_UNAVAILABLE"

        plan = DurablePlan.create(
            checkpoint["tool_state"]["execution_id"], "acceptance-plan"
        )
        node = plan.add_node(planner_node_id="step-1", kind="READ_ONLY")
        plan.activate(node.planner_node_id)
        incomplete_state = dict(checkpoint["tool_state"])
        incomplete_state["durable_plan"] = plan.to_dict()
        manager.save_checkpoint(
            agent["id"],
            checkpoint["tick_id"],
            checkpoint["conversation_state"],
            incomplete_state,
        )
        partial = executor.verify_goal_acceptance(
            agent["id"], expected_artifacts=[reference]
        )
        assert partial["status"] == "PARTIAL"

        plan.complete_read_only(node.planner_node_id)
        complete_state = dict(incomplete_state)
        complete_state["durable_plan"] = plan.to_dict()
        manager.save_checkpoint(
            agent["id"],
            checkpoint["tick_id"],
            checkpoint["conversation_state"],
            complete_state,
        )
        verified = executor.verify_goal_acceptance(
            agent["id"], expected_artifacts=[reference]
        )
        assert verified["status"] == "VERIFIED"
    finally:
        manager.close()
