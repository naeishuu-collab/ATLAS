"""Dedicated Safety Authority regression (P0-2).

Proves an untrusted worker/proposal cannot bypass the host-side
authority boundary: broker session/nonce/capability gates plus the
host cloud-dispatch gate when the broker fronts a guarded engine.

NOTE: MutationIntent lives on the agent-executor/tool path, not the
cloud-egress boundary — dedicated MutationIntent test here is
NOT APPLICABLE BY DESIGN (see final report).

All transports fake/offline. No network.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx
import pytest

from openjarvis.agents.rlm_rpc import (
    HostLLMBroker,
    RLMRPCError,
)
from openjarvis.security.capabilities import CapabilityPolicy
from openjarvis.security.cloud_dispatch import (
    BudgetReservation,
    CloudDispatchAuthorizer,
    CloudDispatchRequest,
    ExplicitGrant,
    PrivacyClassification,
    PrivacyDenied,
    ProviderIdentity,
)
from openjarvis.security.dispatch_ledger import CloudDispatchLedger

SESSION = "session-auth"
NONCE = "nonce-auth"
AGENT = "worker-1"


class _Scanner:
    def scan(self, text: str):  # noqa: D102
        from types import SimpleNamespace

        return SimpleNamespace(findings=[])

    def redact(self, text: str):  # noqa: D102
        return text


class _FakePolicy:
    def __init__(self, grants: dict) -> None:
        self._grants = grants

    def list_agents(self):  # noqa: D102
        return list(self._grants)

    def list_grants(self, agent_id):  # noqa: D102
        from types import SimpleNamespace

        return [SimpleNamespace(capability=c) for c in self._grants.get(agent_id, [])]

    def check(self, agent_id, capability, resource=""):  # noqa: D102
        return capability in self._grants.get(agent_id, [])


def _broker_policy(*capabilities: str) -> CapabilityPolicy:
    policy = CapabilityPolicy(default_deny=True)
    for capability in capabilities:
        policy.grant(AGENT, capability)
    return policy


def _request(request_id: int = 1, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "protocol": "rlm-worker-v2",
        "type": "llm_rpc_request",
        "session_id": SESSION,
        "nonce": NONCE,
        "request_id": request_id,
        "parent_request_id": 1,
        "operation": "llm_query",
        "prompt": "hello",
        "deadline_ms": 2000,
    }
    base.update(kw)
    return base


class _FakeEngine:
    """Counting fake engine fronting the broker."""

    def __init__(self) -> None:
        self.calls = 0
        self._lock = threading.Lock()

    def generate(self, messages, *, model: str, **kw: Any):  # noqa: D102
        with self._lock:
            self.calls += 1
        return {"content": "host answer"}


def _broker(engine=None, policy=None) -> HostLLMBroker:
    broker = HostLLMBroker(
        engine or _FakeEngine(),
        model="m",
        temperature=0.0,
        max_tokens=16,
        capability_policy=(
            policy if policy is not None
            else _broker_policy("llm:query")
        ),
        agent_id=AGENT,
    )
    broker.bind_session(SESSION, NONCE)
    return broker


def _cloud_authz():
    return CloudDispatchAuthorizer(
        allowlist={("nim", "nim", "m")},
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"host": ["llm:cloud"]}),
        allowed_endpoints=frozenset({"https://nim.test"}),
    )


class TestGoldenAndCapability:
    def test_valid_request_single_engine_call(self) -> None:
        engine = _FakeEngine()
        broker = _broker(engine)
        resp = broker.handle_request(_request())
        assert resp["success"] is True
        assert resp["output"] == "host answer"
        assert engine.calls == 1

    def test_missing_capability_denies_no_engine_call(self) -> None:
        engine = _FakeEngine()
        broker = _broker(engine, _broker_policy())
        resp = broker.handle_request(_request())
        assert resp["success"] is False
        assert resp["error_code"] == "RPC_UNAUTHORIZED"
        assert engine.calls == 0

    def test_wrong_agent_capability_denies(self) -> None:
        # Grant belongs to another agent: broker's own agent is unauthorized.
        engine = _FakeEngine()
        other = CapabilityPolicy(default_deny=True)
        other.grant("someone-else", "llm:query")
        broker = _broker(engine, other)
        resp = broker.handle_request(_request())
        assert resp["success"] is False
        assert resp["error_code"] == "RPC_UNAUTHORIZED"
        assert engine.calls == 0


class TestSessionNonceBinding:
    def test_wrong_session_denies(self) -> None:
        engine = _FakeEngine()
        broker = _broker(engine)
        with pytest.raises(RLMRPCError) as ei:
            broker.handle_request(_request(session_id="attacker-session"))
        assert ei.value.error_code == "RPC_SESSION_MISMATCH"

    def test_wrong_nonce_denies(self) -> None:
        engine = _FakeEngine()
        broker = _broker(engine)
        with pytest.raises(RLMRPCError) as ei:
            broker.handle_request(_request(nonce="attacker-nonce"))
        assert ei.value.error_code == "RPC_NONCE_MISMATCH"

    def test_cross_session_replay_denies(self) -> None:
        # Valid request id/session-A material replayed into session-B ledger.
        engine = _FakeEngine()
        broker = _broker(engine)
        assert broker.handle_request(_request())["success"] is True
        broker.bind_session("session-B", "nonce-B")
        with pytest.raises(RLMRPCError) as ei:
            broker.handle_request(_request())
        assert ei.value.error_code == "RPC_SESSION_MISMATCH"
        assert engine.calls == 1


class TestWorkerCannotSelfAuthorizeCloud:
    def _guarded_nim(self, monkeypatch):
        from openjarvis.engine.nim import NIMEngine

        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _cloud_authz()
        eng = NIMEngine(
            host="https://nim.test", authorizer=authz,
            dispatch_ledger=CloudDispatchLedger(), session_id=SESSION,
        )
        eng._client = httpx.Client(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(
                    200,
                    json={
                        "choices": [
                            {
                                "message": {"content": "cloud"},
                                "finish_reason": "stop",
                            }
                        ],
                    },
                )
            ),
            base_url="https://nim.test",
        )
        return eng

    def test_worker_cloud_attempt_denied_zero_sends(
        self, monkeypatch
    ) -> None:
        # Broker invokes the guarded engine WITHOUT any host grant:
        # the worker cannot mint authority through the broker path.
        eng = self._guarded_nim(monkeypatch)
        sends: list = []
        orig_post = eng._client.post

        def counting_post(*a: Any, **k: Any):
            sends.append(1)
            return orig_post(*a, **k)

        eng._client.post = counting_post  # type: ignore[method-assign]
        broker = _broker(eng)
        resp = broker.handle_request(_request())
        assert resp["success"] is False
        assert sends == []
        assert list(eng._dispatch_ledger._entries.values()) == []

    def test_forged_sealed_payload_rejected_by_host(self) -> None:
        # Worker crafts a sealed-looking payload with a tampered digest:
        # host re-verification rejects it.
        import uuid

        from openjarvis.security.cloud_dispatch import AuthorizedPayload

        authz = _cloud_authz()
        live = authz.authorize(
            CloudDispatchRequest(
                classification=PrivacyClassification.INTERNAL,
                provider=ProviderIdentity(
                    engine="nim", provider="nim", model="m",
                    endpoint="https://nim.test",
                ),
                messages=({"role": "user", "content": "hello"},),
                grant=ExplicitGrant(
                    agent_id="host", capability="llm:cloud",
                    expires_at=time.time() + 600,
                ),
                budget=BudgetReservation(
                    est_prompt_tokens=2, max_tokens=8, ctx_limit=64
                ),
                session_id=SESSION,
                nonce=f"n-{uuid.uuid4().hex}",
            )
        )
        forged = AuthorizedPayload(
            dispatch_id=live.dispatch_id, provider=live.provider,
            redacted_messages=live.redacted_messages,
            digest="forged-digest",
            grant=live.grant, budget_id=live.budget_id,
            session_id=live.session_id, nonce=live.nonce,
        )
        with pytest.raises(PrivacyDenied):
            authz.verify_for_send(
                forged,
                [{"role": "user", "content": "hello"}],
                endpoint="https://nim.test",
            )


class TestDuplicateAndReplay:
    def test_sequential_duplicate_single_engine_call(self) -> None:
        engine = _FakeEngine()
        broker = _broker(engine)
        first = broker.handle_request(_request())
        second = broker.handle_request(_request())
        assert first["success"] and second["success"]
        assert engine.calls == 1

    def test_concurrent_duplicate_single_engine_call(self) -> None:
        # Best-effort race probe: same request id from 8 threads.
        # A failure here is defect proof (missing ledger lock), not flake.
        engine = _FakeEngine()
        broker = _broker(engine)
        errors: list = []

        def worker() -> None:
            try:
                broker.handle_request(_request())
            except RLMRPCError:
                pass
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(15.0)
        assert not errors
        assert engine.calls == 1, f"engine invoked {engine.calls}x"


class TestFlagOffThroughBroker:
    def test_guarded_engine_flag_off_denies(self, monkeypatch) -> None:
        monkeypatch.delenv("ASTRA_NIM_EGRESS", raising=False)
        from openjarvis.engine.nim import NIMEngine

        eng = NIMEngine(
            host="https://nim.test", authorizer=_cloud_authz(),
            dispatch_ledger=CloudDispatchLedger(), session_id=SESSION,
        )
        broker = _broker(eng)
        resp = broker.handle_request(_request())
        assert resp["success"] is False
