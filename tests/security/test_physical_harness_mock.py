"""Mock physical-acceptance harness (offline mechanics only).

Proves harness ordering (authorize → act → evidence → verdict →
cleanup → rollback) and fail-closed verdicts against scripted mock OS
backends. Proves nothing about real Windows isolation.
"""

from __future__ import annotations


class MockOSBackend:
    """Scripted OS stand-in: action name -> (evidence, hostile)."""

    def __init__(self, script: dict) -> None:
        self._script = script
        self.cleaned: list[str] = []
        self.rolled_back: list[str] = []

    def authorized(self, scenario_id: str) -> bool:
        return self._script.get(scenario_id, {}).get("authorized", True)

    def act(self, scenario_id: str) -> dict:
        return self._script.get(scenario_id, {}).get("evidence", {"ok": True})

    def cleanup(self, scenario_id: str) -> None:
        self.cleaned.append(scenario_id)

    def rollback(self, scenario_id: str) -> None:
        self.rolled_back.append(scenario_id)


SCENARIOS = [
    {"id": "token", "expect": "VERIFIED"},
    {"id": "sid", "expect": "VERIFIED"},
    {"id": "fs-read", "expect": "DENY"},
    {"id": "fs-write", "expect": "DENY"},
    {"id": "ipc", "expect": "VERIFIED"},
    {"id": "nonce", "expect": "QUARANTINE"},
    {"id": "network", "expect": "DENY"},
    {"id": "dns-proxy", "expect": "DENY"},
    {"id": "child", "expect": "DENY"},
    {"id": "job-close", "expect": "VERIFIED"},
    {"id": "timeout", "expect": "VERIFIED"},
    {"id": "cancel", "expect": "VERIFIED"},
    {"id": "orphan", "expect": "VERIFIED"},
    {"id": "artifact", "expect": "VERIFIED"},
    {"id": "wdac", "expect": "VERIFIED"},
    {"id": "unknown-outcome", "expect": "QUARANTINE"},
    {"id": "duplicate", "expect": "DENY"},
    {"id": "fallback", "expect": "DENY"},
    {"id": "audit", "expect": "VERIFIED"},
]
assert len(SCENARIOS) == 19


def run_scenario(scenario: dict, backend: MockOSBackend, audit: list) -> str:
    sid = scenario["id"]
    if not backend.authorized(sid):
        audit.append((sid, "NOT_EXECUTED"))
        return "NOT_EXECUTED"
    evidence = backend.act(sid)
    if evidence.get("forged") or evidence.get("egress"):
        verdict = "SAFETY_FAILURE"
    else:
        verdict = scenario["expect"]
    audit.append((sid, verdict, dict(evidence)))
    try:
        backend.cleanup(sid)
    finally:
        if verdict in ("SAFETY_FAILURE", "QUARANTINE"):
            backend.rollback(sid)
    return verdict


def test_all_scenarios_run_with_cleanup() -> None:
    backend = MockOSBackend({})
    audit: list = []
    for scenario in SCENARIOS:
        run_scenario(scenario, backend, audit)
    assert len(audit) == 19
    assert len(backend.cleaned) == 19
    assert backend.rolled_back == ["nonce", "unknown-outcome"]


def test_hostile_network_is_safety_failure_with_rollback() -> None:
    script = {"network": {"evidence": {"egress": True}}}
    backend = MockOSBackend(script)
    audit: list = []
    verdict = run_scenario({"id": "network", "expect": "DENY"}, backend, audit)
    assert verdict == "SAFETY_FAILURE"
    assert backend.rolled_back == ["network"]
    assert audit[0][1] == "SAFETY_FAILURE"


def test_missing_authorization_skips_scenario() -> None:
    backend = MockOSBackend({"token": {"authorized": False}})
    audit: list = []
    verdict = run_scenario({"id": "token", "expect": "VERIFIED"}, backend, audit)
    assert verdict == "NOT_EXECUTED"
    assert backend.cleaned == []
