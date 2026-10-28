"""RLM RPC hardening negatives — supplements test_rlm_rpc.py (no overlap)."""

from __future__ import annotations

import threading
from typing import Any

import pytest

from openjarvis.agents.rlm_rpc import (
    RPC_MAX_FRAME_BYTES,
    STATE_EXECUTED,
    STATE_UNKNOWN_OUTCOME,
    HostLLMBroker,
    RequestLedger,
    RLMRPCError,
    decode_frame,
    encode_frame,
    validate_request,
)
from openjarvis.security.capabilities import CapabilityPolicy

SESSION = "session-harden"
NONCE = "nonce-harden"
AGENT = "rlm-harden"


def _request(request_id: int = 1, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "protocol": "rlm-worker-v2",
        "type": "llm_rpc_request",
        "session_id": SESSION,
        "nonce": NONCE,
        "request_id": request_id,
        "parent_request_id": 1,
        "operation": "llm_query",
        "deadline_ms": 500,
        "prompt": "hi",
    }
    base.update(kw)
    return base


def _policy(*caps: str) -> CapabilityPolicy:
    policy = CapabilityPolicy(default_deny=True)
    for cap in caps:
        policy.grant(AGENT, cap)
    return policy


def _broker(engine=None, **kw) -> HostLLMBroker:
    class _E:
        def __init__(self) -> None:
            self.calls = 0

        def generate(self, messages, **k):
            self.calls += 1
            return {"content": "ok"}

    broker = HostLLMBroker(
        engine or _E(),
        model="m",
        temperature=0.0,
        max_tokens=8,
        capability_policy=kw.pop(
            "policy", _policy("llm:query", "llm:batch")
        ),
        agent_id=AGENT,
    )
    broker.bind_session(SESSION, NONCE)
    return broker


class TestFrameHardening:
    def test_oversized_frame_rejected(self) -> None:
        big = _request(prompt="x" * (RPC_MAX_FRAME_BYTES + 1))
        with pytest.raises(RLMRPCError):
            encode_frame(big)
        with pytest.raises(RLMRPCError):
            decode_frame(b"x" * (RPC_MAX_FRAME_BYTES + 1))

    def test_invalid_json_variants_rejected(self) -> None:
        with pytest.raises(RLMRPCError):
            decode_frame(b"not json{")
        with pytest.raises(RLMRPCError):
            decode_frame(b"[1,2,3]")  # non-object root
        with pytest.raises(RLMRPCError):
            decode_frame(b'{"a":1,"a":2}')  # duplicate keys
        with pytest.raises(RLMRPCError):
            decode_frame(b"\xff\xfe invalid utf8")
        with pytest.raises(RLMRPCError):
            decode_frame("not-bytes")  # type: ignore[arg-type]

    def test_bool_ids_rejected(self) -> None:
        with pytest.raises(RLMRPCError):
            validate_request(
                _request(request_id=True),  # type: ignore[arg-type]
                session_id=SESSION,
                nonce=NONCE,
            )

    def test_deadline_bounds(self) -> None:
        with pytest.raises(RLMRPCError):
            validate_request(
                _request(deadline_ms=0), session_id=SESSION, nonce=NONCE
            )
        with pytest.raises(RLMRPCError):
            validate_request(
                _request(deadline_ms=30_001), session_id=SESSION, nonce=NONCE
            )


class TestSessionIsolation:
    def test_cross_session_no_leakage(self) -> None:
        a = RequestLedger("sess-a", NONCE)
        b = RequestLedger("sess-b", NONCE)
        req = _request(session_id="sess-a")
        entry_a, dup_a = a.begin(req)
        assert dup_a is False
        # Same request_id in another session is independent.
        other = dict(req, session_id="sess-b")
        entry_b, dup_b = b.begin(other)
        assert dup_b is False
        assert entry_a is not entry_b

    def test_nonce_replay_with_changed_payload_rejected(self) -> None:
        ledger = RequestLedger(SESSION, NONCE)
        entry, dup = ledger.begin(_request())
        assert dup is False
        with pytest.raises(RLMRPCError):
            ledger.begin(_request(prompt="changed"))
        assert entry.response is None

    def test_broker_session_mismatch_rejected(self) -> None:
        broker = _broker()
        bad = _request(session_id="other-session")
        with pytest.raises(RLMRPCError):
            broker.handle_request(bad)


class TestTerminationAndCancel:
    def test_worker_termination_mid_dispatch_is_unknown(self) -> None:
        started = threading.Event()
        release = threading.Event()

        class _Hang:
            def generate(self, messages, **k):
                started.set()
                assert release.wait(5.0)
                return {"content": "never"}

        broker = _broker(_Hang())
        cancel = threading.Event()
        box: list = []
        worker = threading.Thread(
            target=lambda: box.append(
                broker.handle_request(
                    _request(deadline_ms=10_000), cancel_event=cancel
                )
            )
        )
        worker.start()
        assert started.wait(5.0)
        cancel.set()  # terminated after dispatch started
        import time as _time

        _time.sleep(0.5)  # let the dispatch loop observe cancellation
        release.set()
        worker.join(10.0)
        assert box and box[0]["state"] == STATE_UNKNOWN_OUTCOME
        # A follow-up under a new id works; the old entry is not success.
        again = broker.handle_request(_request(request_id=2, deadline_ms=500))
        assert again["state"] == STATE_EXECUTED
        assert broker.ledger.entries[(SESSION, NONCE, 1)].state == (
            STATE_UNKNOWN_OUTCOME
        )

    def test_broker_cancel_before_dispatch_no_send(self) -> None:
        engine_calls: list = []

        class _E:
            def generate(self, messages, **k):
                engine_calls.append(1)
                return {"content": "ok"}

        broker = _broker(_E())
        cancel = threading.Event()
        cancel.set()
        out = broker.handle_request(_request(deadline_ms=500), cancel_event=cancel)
        assert out["state"] != STATE_EXECUTED
        assert engine_calls == []
