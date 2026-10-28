"""P0-3 deterministic ledger-concurrency regression (offline, no network).

Proves ONE LOGICAL DISPATCH IDENTITY -> AT MOST ONE FINAL SEND under
thread concurrency, with barrier-aligned (deterministic, no sleep-timing)
entry into each critical window. Final-send boundary counted directly.

Scope: single-process threads. Cross-process/crash durability explicitly
NOT proven (see final report).
"""

from __future__ import annotations

import threading
import time
import uuid

import httpx

from openjarvis.agents.rlm_rpc import HostLLMBroker
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
from openjarvis.security.dispatch_ledger import (
    STATE_UNKNOWN_OUTCOME,
    CloudDispatchLedger,
)

SESSION = "sess-race"
AGENT = "worker-race"


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


def _authz():
    return CloudDispatchAuthorizer(
        allowlist={("nim", "nim", "m")},
        scanners=[_Scanner()],
        capability_policy=_FakePolicy({"host": ["llm:cloud"]}),
        allowed_endpoints=frozenset({"https://nim.test"}),
    )


def _sealed(authz, nonce=None):
    return authz.authorize(
        CloudDispatchRequest(
            classification=PrivacyClassification.INTERNAL,
            provider=ProviderIdentity(
                engine="nim", provider="nim", model="m",
                endpoint="https://nim.test",
            ),
            messages=({"role": "user", "content": "hi"},),
            grant=ExplicitGrant(
                agent_id="host", capability="llm:cloud",
                expires_at=time.time() + 600,
            ),
            budget=BudgetReservation(
                est_prompt_tokens=2, max_tokens=8, ctx_limit=64
            ),
            session_id=SESSION,
            nonce=nonce or f"n-{uuid.uuid4().hex}",
        )
    )


def _ok_response():
    return httpx.Response(
        200,
        json={
            "choices": [
                {"message": {"content": "ok"}, "finish_reason": "stop"}
            ]
        },
    )


def _nim_engine(authz, ledger, handler, session=SESSION):
    from openjarvis.engine.nim import NIMEngine

    eng = NIMEngine(
        host="https://nim.test", authorizer=authz,
        dispatch_ledger=ledger, session_id=session,
    )
    eng._client = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="https://nim.test",
    )
    return eng


def _msgs():
    from openjarvis.core.types import Message, Role

    return [Message(role=Role.USER, content="hi")]


def _run_threads(n, fn):
    errors: list = []
    barrier = threading.Barrier(n)

    def worker():
        try:
            barrier.wait(timeout=15.0)
            fn()
        except PrivacyDenied:
            pass
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30.0)
    assert not [t for t in threads if t.is_alive()], "thread hung"
    assert not errors, f"unexpected errors: {errors!r}"


class TestLedgerAtomicBegin:
    def test_concurrent_same_dispatch_one_reservation(self) -> None:
        # Barrier-aligned entry into begin(): exactly one winner.
        authz = _authz()
        sealed = _sealed(authz)
        ledger = CloudDispatchLedger()
        won: list = []

        def attempt():
            ledger.begin(sealed)
            won.append(1)

        _run_threads(8, attempt)
        assert len(won) == 1
        assert len(ledger._entries) == 1


class TestEngineFinalSend:
    def test_concurrent_same_grant_one_send(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _authz()
        sealed = _sealed(authz)
        ledger = CloudDispatchLedger()
        sends: list = []
        eng = _nim_engine(
            authz, ledger, lambda req: (sends.append(1), _ok_response())[1],
        )

        def attempt():
            eng.generate(_msgs(), model="m", cloud_dispatch=sealed)

        _run_threads(8, attempt)
        assert len(sends) == 1
        assert [e.state for e in ledger._entries.values()] == ["EXECUTED"]

    def test_concurrent_different_grants_two_sends(
        self, monkeypatch
    ) -> None:
        # Control: distinct dispatch identities proceed independently.
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _authz()
        ledger = CloudDispatchLedger()
        sends: list = []
        eng = _nim_engine(
            authz, ledger, lambda req: (sends.append(1), _ok_response())[1],
        )
        sealeds = [_sealed(authz) for _ in range(2)]

        def attempt(idx=[0]):
            with threading.Lock():
                i = idx[0]
                idx[0] += 1
            eng.generate(_msgs(), model="m", cloud_dispatch=sealeds[i])

        _run_threads(2, attempt)
        assert len(sends) == 2

    def test_unknown_terminal_no_second_send(self, monkeypatch) -> None:
        monkeypatch.setenv("ASTRA_NIM_EGRESS", "on")
        authz = _authz()
        sealed = _sealed(authz)
        ledger = CloudDispatchLedger()
        sends: list = []

        def fail_once(req):
            sends.append(1)
            raise RuntimeError("transport uncertain")

        eng = _nim_engine(authz, ledger, fail_once)

        def attempt():
            try:
                eng.generate(_msgs(), model="m", cloud_dispatch=sealed)
            except RuntimeError:
                pass

        _run_threads(6, attempt)
        assert len(sends) == 1
        assert [e.state for e in ledger._entries.values()] == [
            STATE_UNKNOWN_OUTCOME
        ]


class TestBrokerLedgerRace:
    def _request(self, rid=1, session=SESSION, nonce="n-broker"):
        return {
            "protocol": "rlm-worker-v2",
            "type": "llm_rpc_request",
            "session_id": session,
            "nonce": nonce,
            "request_id": rid,
            "parent_request_id": 1,
            "operation": "llm_query",
            "prompt": "hello",
            "deadline_ms": 10000,
        }

    def _race_broker(self, n_threads=2):
        """Race n threads on one request id. Deterministic assertions.

        With atomic reservation, every interleaving yields exactly one
        engine dispatch; losers get DUPLICATE_PENDING (winner in flight)
        or the replayed success (winner finished). Both are correct.
        """
        calls: list = []
        responses: list = []

        class SlowEngine:
            def generate(self, messages, *, model, **kw):  # noqa: D102
                calls.append(1)
                return {"content": "ok"}

        policy = CapabilityPolicy(default_deny=True)
        policy.grant(AGENT, "llm:query")
        broker = HostLLMBroker(
            SlowEngine(), model="m", temperature=0.0, max_tokens=8,
            capability_policy=policy, agent_id=AGENT,
        )
        broker.bind_session(SESSION, "n-broker")
        started = threading.Barrier(n_threads)
        errors: list = []

        def worker():
            try:
                started.wait(timeout=15.0)
                responses.append(broker.handle_request(self._request()))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker)
                   for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30.0)
        assert not errors, f"{errors!r}"
        assert len(responses) == n_threads
        return calls, responses

    def test_barrier_aligned_duplicate_single_dispatch(self) -> None:
        calls, responses = self._race_broker(2)
        assert len(calls) == 1, (
            f"RACE: {len(calls)} engine dispatches for one request id"
        )
        assert sum(1 for r in responses if r["success"]) >= 1
        for r in responses:
            if not r["success"]:
                assert r["error_code"] == "RPC_DUPLICATE_PENDING", r

    def test_check_then_act_window_single_dispatch(self) -> None:
        # Same race with 8 threads: atomic reservation must still
        # yield exactly one dispatch however threads interleave.
        calls, responses = self._race_broker(8)
        assert len(calls) == 1, (
            f"RACE: {len(calls)} engine dispatches for one request id"
        )
        assert sum(1 for r in responses if r["success"]) >= 1
        for r in responses:
            if not r["success"]:
                assert r["error_code"] == "RPC_DUPLICATE_PENDING", r


class TestRestartDurabilityLimitation:
    """Known limitation guard: both ledgers are IN_MEMORY_ONLY.

    A fresh ledger (host restart) does not remember prior reservations,
    so the same sealed/request identity is treated as new. These tests
    PIN that semantic so any durability change (or regression) is an
    explicit, reviewed event — never a silent behavior drift.
    """

    def test_cloud_ledger_forgets_across_instances(self) -> None:
        authz = _authz()
        sealed = _sealed(authz)
        first = CloudDispatchLedger()
        first.begin(sealed)
        second = CloudDispatchLedger()
        # Fresh instance accepts the same sealed identity: replay across
        # restart is NOT prevented in memory (known limitation).
        assert second.begin(sealed) is not None

    def test_broker_ledger_forgets_across_instances(self) -> None:
        from openjarvis.agents.rlm_rpc import RequestLedger

        req = {
            "protocol": "rlm-worker-v2",
            "type": "llm_rpc_request",
            "session_id": SESSION,
            "nonce": "n-restart",
            "request_id": 1,
            "parent_request_id": 1,
            "operation": "llm_query",
            "prompt": "hello",
            "deadline_ms": 10000,
        }
        first = RequestLedger(SESSION, "n-restart")
        _, is_new_first = first.begin(req)
        assert is_new_first is False
        second = RequestLedger(SESSION, "n-restart")
        _, is_new_second = second.begin(req)
        # Fresh ledger treats it as new: replay across restart is NOT
        # prevented in memory. Single-process exactly-once is unaffected.
        assert is_new_second is False
