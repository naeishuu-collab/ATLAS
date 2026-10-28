"""Durable mutation quarantine, separate from model conversation memory.

Reservations are committed before dispatch. A crash leaves a reservation that
blocks later dispatch. No lease expiry or startup sweep can authorize replay.
Only trusted application code may reconcile after observing the real outcome.
Arguments and tool content are never stored here.
"""

from __future__ import annotations

import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from openjarvis.core.execution import MutationIntent

_SEMANTIC_STATES = frozenset(
    {
        "AUTHORIZED",
        "PREPARED",
        "EXECUTING",
        "EXECUTED",
        "VERIFIED",
        "FAILED",
        "UNKNOWN_OUTCOME",
        "NOT_EXECUTED",
    }
)


class ExecutionJournal:
    """SQLite reservations shared by executors with the same stable scope."""

    def __init__(self, path: str | Path) -> None:
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS tool_mutation_reservations (
                scope TEXT NOT NULL,
                tool TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                call_id TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (scope, tool)
            );
            CREATE TABLE IF NOT EXISTS tool_mutation_reconciliations (
                token TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                tool TEXT NOT NULL,
                call_id TEXT NOT NULL,
                resolution TEXT NOT NULL,
                evidence TEXT NOT NULL,
                reconciled_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS agent_cancellation_requests (
                scope TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                reason TEXT NOT NULL,
                timeout_kind TEXT NOT NULL DEFAULT '',
                requested_at REAL NOT NULL,
                acknowledged_at REAL,
                safe_boundary_at REAL,
                terminalized_at REAL
            );
            CREATE TABLE IF NOT EXISTS semantic_mutation_intents (
                scope TEXT NOT NULL,
                execution_id TEXT NOT NULL,
                step_id TEXT NOT NULL,
                mutation_intent_id TEXT NOT NULL,
                status TEXT NOT NULL,
                tool TEXT,
                token TEXT UNIQUE,
                call_id TEXT,
                evidence TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                PRIMARY KEY (scope, execution_id, step_id, mutation_intent_id)
            );
        """)
        columns = {
            row["name"]
            for row in self._conn.execute(
                "PRAGMA table_info(tool_mutation_reconciliations)"
            ).fetchall()
        }
        if "call_id" not in columns:
            self._conn.execute(
                "ALTER TABLE tool_mutation_reconciliations "
                "ADD COLUMN call_id TEXT NOT NULL DEFAULT ''"
            )
        self._conn.commit()

    @staticmethod
    def _validate_intent(scope: str, intent: MutationIntent) -> None:
        if not isinstance(scope, str) or not scope.strip():
            raise ValueError("A durable execution scope must be nonempty")
        if not isinstance(intent, MutationIntent):
            raise TypeError("A trusted MutationIntent is required")

    def authorize_intent(
        self, scope: str, intent: MutationIntent
    ) -> dict[str, Any]:
        """Persist controller authorization before a mutating tool call."""
        self._validate_intent(scope, intent)
        now = time.time()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT * FROM semantic_mutation_intents WHERE "
                    "scope=? AND execution_id=? AND step_id=? "
                    "AND mutation_intent_id=?",
                    (
                        scope,
                        intent.execution_id,
                        intent.step_id,
                        intent.mutation_intent_id,
                    ),
                ).fetchone()
                if row is None:
                    self._conn.execute(
                        "INSERT INTO semantic_mutation_intents "
                        "(scope,execution_id,step_id,mutation_intent_id,status,"
                        "created_at,updated_at) VALUES (?,?,?,?, 'AUTHORIZED',?,?)",
                        (
                            scope,
                            intent.execution_id,
                            intent.step_id,
                            intent.mutation_intent_id,
                            now,
                            now,
                        ),
                    )
                    row = self._conn.execute(
                        "SELECT * FROM semantic_mutation_intents WHERE "
                        "scope=? AND execution_id=? AND step_id=? "
                        "AND mutation_intent_id=?",
                        (
                            scope,
                            intent.execution_id,
                            intent.step_id,
                            intent.mutation_intent_id,
                        ),
                    ).fetchone()
                elif row["status"] != "AUTHORIZED":
                    self._conn.rollback()
                    raise ValueError(
                        "Mutation intent is already terminal or unresolved; "
                        "create a new controller-authorized intent"
                    )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return dict(row)

    def semantic_intent(
        self, scope: str, intent: MutationIntent
    ) -> dict[str, Any] | None:
        self._validate_intent(scope, intent)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM semantic_mutation_intents WHERE "
                "scope=? AND execution_id=? AND step_id=? "
                "AND mutation_intent_id=?",
                (
                    scope,
                    intent.execution_id,
                    intent.step_id,
                    intent.mutation_intent_id,
                ),
            ).fetchone()
        return dict(row) if row else None

    def semantic_step_exists(
        self, scope: str, execution_id: str, step_id: str
    ) -> bool:
        """Check whether a controller step ID was used in this execution."""
        if not isinstance(execution_id, str) or not execution_id.strip():
            raise ValueError("A durable execution ID must be nonempty")
        if not isinstance(step_id, str) or not step_id.strip():
            raise ValueError("A durable step ID must be nonempty")
        if not isinstance(scope, str) or not scope.strip():
            raise ValueError("A durable execution scope must be nonempty")
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM semantic_mutation_intents WHERE scope=? "
                "AND execution_id=? AND step_id=? LIMIT 1",
                (scope, execution_id, step_id),
            ).fetchone()
        return row is not None

    def reserve_intent(
        self,
        scope: str,
        tool: str,
        call_id: str,
        intent: MutationIntent,
    ) -> dict[str, Any]:
        """Atomically claim an authorized semantic intent for one invocation."""
        self._validate_intent(scope, intent)
        token = uuid.uuid4().hex
        now = time.time()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                cancelled = self._conn.execute(
                    "SELECT 1 FROM agent_cancellation_requests WHERE scope=?",
                    (scope,),
                ).fetchone()
                if cancelled is not None:
                    self._conn.rollback()
                    return {
                        "token": None,
                        "state": "NOT_EXECUTED",
                        "failure": "CANCELLATION",
                    }
                row = self._conn.execute(
                    "SELECT * FROM semantic_mutation_intents WHERE "
                    "scope=? AND execution_id=? AND step_id=? "
                    "AND mutation_intent_id=?",
                    (
                        scope,
                        intent.execution_id,
                        intent.step_id,
                        intent.mutation_intent_id,
                    ),
                ).fetchone()
                if row is None:
                    self._conn.rollback()
                    return {
                        "token": None,
                        "state": "NOT_EXECUTED",
                        "failure": "MISSING_TRUSTED_INTENT",
                    }
                pending = None
                if row["token"]:
                    pending = self._conn.execute(
                        "SELECT 1 FROM tool_mutation_reservations WHERE token=?",
                        (row["token"],),
                    ).fetchone()
                if row["status"] not in _SEMANTIC_STATES:
                    self._conn.rollback()
                    return {
                        "token": None,
                        "state": "UNKNOWN_OUTCOME",
                        "failure": "SEMANTIC_JOURNAL_INCONSISTENCY",
                    }
                if row["status"] == "AUTHORIZED" and (
                    row["token"] is not None
                    or row["call_id"] is not None
                    or pending is not None
                ):
                    self._conn.rollback()
                    return {
                        "token": None,
                        "state": "UNKNOWN_OUTCOME",
                        "failure": "SEMANTIC_JOURNAL_INCONSISTENCY",
                    }
                if row["status"] == "VERIFIED" and pending is not None:
                    self._conn.rollback()
                    return {
                        "token": None,
                        "state": "UNKNOWN_OUTCOME",
                        "failure": "SEMANTIC_JOURNAL_INCONSISTENCY",
                    }
                if row["status"] in {
                    "PREPARED",
                    "EXECUTING",
                    "EXECUTED",
                    "UNKNOWN_OUTCOME",
                } and pending is None:
                    self._conn.rollback()
                    return {
                        "token": None,
                        "state": "UNKNOWN_OUTCOME",
                        "failure": "SEMANTIC_JOURNAL_INCONSISTENCY",
                    }
                if row["status"] != "AUTHORIZED":
                    self._conn.rollback()
                    failure = (
                        "STEP_ALREADY_VERIFIED"
                        if row["status"] == "VERIFIED"
                        else "SEMANTIC_INTENT_UNRESOLVED"
                        if row["status"] in {
                            "PREPARED",
                            "EXECUTING",
                            "EXECUTED",
                            "UNKNOWN_OUTCOME",
                        }
                        else "SEMANTIC_INTENT_TERMINAL"
                    )
                    return {
                        "token": None,
                        "state": row["status"],
                        "failure": failure,
                    }
                try:
                    self._conn.execute(
                        "INSERT INTO tool_mutation_reservations "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (scope, tool, token, call_id, "PREPARED", now),
                    )
                except sqlite3.IntegrityError:
                    self._conn.rollback()
                    return {
                        "token": None,
                        "state": "UNKNOWN_OUTCOME",
                        "failure": "INVOCATION_QUARANTINE",
                    }
                self._conn.execute(
                    "UPDATE semantic_mutation_intents SET status='PREPARED', "
                    "tool=?, token=?, call_id=?, updated_at=? WHERE "
                    "scope=? AND execution_id=? AND step_id=? "
                    "AND mutation_intent_id=? AND status='AUTHORIZED'",
                    (
                        tool,
                        token,
                        call_id,
                        now,
                        scope,
                        intent.execution_id,
                        intent.step_id,
                        intent.mutation_intent_id,
                    ),
                )
                self._conn.commit()
                return {"token": token, "state": "PREPARED", "failure": None}
            except Exception:
                self._conn.rollback()
                raise

    def reserve(self, scope: str, tool: str, call_id: str) -> str | None:
        """Create a PREPARED claim unless cancellation/quarantine blocks it."""
        if not scope.strip():
            raise ValueError("A durable execution scope must be nonempty")
        token = uuid.uuid4().hex
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                cancelled = self._conn.execute(
                    "SELECT 1 FROM agent_cancellation_requests WHERE scope=?",
                    (scope,),
                ).fetchone()
                if cancelled is not None:
                    self._conn.rollback()
                    return None
                self._conn.execute(
                    "INSERT INTO tool_mutation_reservations VALUES (?, ?, ?, ?, ?, ?)",
                    (scope, tool, token, call_id, "PREPARED", time.time()),
                )
                self._conn.commit()
            except sqlite3.IntegrityError:
                self._conn.rollback()
                return None
            except Exception:
                self._conn.rollback()
                raise
        return token

    def begin_dispatch(self, token: str) -> bool:
        """Atomically order dispatch authorization against a cancel request.

        A successful commit is the linearization point: cancellation arriving
        afterwards cannot revoke an operation that may already be dispatching.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT * FROM tool_mutation_reservations WHERE token=?",
                    (token,),
                ).fetchone()
                if row is None or row["state"] != "PREPARED":
                    raise ValueError("Mutation is not in PREPARED state")
                semantic = self._conn.execute(
                    "SELECT * FROM semantic_mutation_intents WHERE token=?",
                    (token,),
                ).fetchone()
                if semantic is not None and semantic["status"] != "PREPARED":
                    raise ValueError("Semantic mutation intent is not PREPARED")
                cancelled = self._conn.execute(
                    "SELECT 1 FROM agent_cancellation_requests WHERE scope=?",
                    (row["scope"],),
                ).fetchone()
                if cancelled is not None:
                    self._record_not_dispatched(
                        row, "dispatch gate denied by cancellation request"
                    )
                    self._conn.commit()
                    return False
                self._conn.execute(
                    "UPDATE tool_mutation_reservations SET state='EXECUTING' "
                    "WHERE token=? AND state='PREPARED'",
                    (token,),
                )
                if semantic is not None:
                    self._conn.execute(
                        "UPDATE semantic_mutation_intents SET status='EXECUTING', "
                        "updated_at=? WHERE token=? AND status='PREPARED'",
                        (time.time(), token),
                    )
                self._conn.commit()
                return True
            except Exception:
                self._conn.rollback()
                raise

    def mark_not_dispatched(self, token: str, *, evidence: str) -> None:
        """Release a claim only when this process proves submit never occurred."""
        if not isinstance(evidence, str) or not evidence.strip():
            raise ValueError("NOT_EXECUTED needs evidence")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT * FROM tool_mutation_reservations WHERE token=?",
                    (token,),
                ).fetchone()
                if row is None or row["state"] not in {"PREPARED", "EXECUTING"}:
                    raise ValueError("Mutation cannot be proven NOT_EXECUTED")
                self._record_not_dispatched(row, evidence)
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def _record_not_dispatched(self, row: sqlite3.Row, evidence: str) -> None:
        self._conn.execute(
            "INSERT INTO tool_mutation_reconciliations "
            "(token, scope, tool, call_id, resolution, evidence, reconciled_at) "
            "VALUES (?, ?, ?, ?, 'NOT_EXECUTED', ?, ?)",
            (
                row["token"],
                row["scope"],
                row["tool"],
                row["call_id"],
                evidence,
                time.time(),
            ),
        )
        self._conn.execute(
            "DELETE FROM tool_mutation_reservations WHERE token=?", (row["token"],)
        )
        self._conn.execute(
            "UPDATE semantic_mutation_intents SET status='NOT_EXECUTED', "
            "evidence=?, updated_at=? WHERE token=?",
            (evidence, time.time(), row["token"]),
        )

    def finish(
        self,
        token: str,
        *,
        uncertain: bool,
        state: str | None = None,
    ) -> None:
        """Retain uncertainty and unverified canceled actions; release known work."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT * FROM tool_mutation_reservations WHERE token=?",
                    (token,),
                ).fetchone()
                if row is None:
                    raise ValueError("Unknown mutation reservation")
                semantic = self._conn.execute(
                    "SELECT * FROM semantic_mutation_intents WHERE token=?",
                    (token,),
                ).fetchone()
                cancelled = self._conn.execute(
                    "SELECT 1 FROM agent_cancellation_requests WHERE scope=?",
                    (row["scope"],),
                ).fetchone()
                if uncertain:
                    self._conn.execute(
                        "UPDATE tool_mutation_reservations SET state='UNKNOWN_OUTCOME' "
                        "WHERE token=?",
                        (token,),
                    )
                    semantic_state = "UNKNOWN_OUTCOME"
                elif cancelled is not None and state == "EXECUTED":
                    # The result arrived, but cancellation prevented follow-up
                    # verification. Keep this exact call for reconciliation.
                    self._conn.execute(
                        "UPDATE tool_mutation_reservations SET state='EXECUTED' "
                        "WHERE token=?",
                        (token,),
                    )
                    semantic_state = "EXECUTED"
                else:
                    if semantic is None:
                        self._conn.execute(
                            "DELETE FROM tool_mutation_reservations WHERE token=?",
                            (token,),
                        )
                    else:
                        semantic_state = (
                            "NOT_EXECUTED"
                            if state == "NOT_STARTED"
                            else state or "FAILED"
                        )
                        if semantic_state == "VERIFIED":
                            self._conn.execute(
                                "DELETE FROM tool_mutation_reservations WHERE token=?",
                                (token,),
                            )
                        elif semantic_state in {"EXECUTED", "UNKNOWN_OUTCOME"}:
                            self._conn.execute(
                                "UPDATE tool_mutation_reservations SET state=? "
                                "WHERE token=?",
                                (semantic_state, token),
                            )
                        else:
                            self._conn.execute(
                                "DELETE FROM tool_mutation_reservations WHERE token=?",
                                (token,),
                            )
                if semantic is not None:
                    if semantic_state not in _SEMANTIC_STATES:
                        semantic_state = "FAILED"
                    self._conn.execute(
                        "UPDATE semantic_mutation_intents SET status=?, updated_at=? "
                        "WHERE token=?",
                        (semantic_state, time.time(), token),
                    )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def request_cancellation(
        self,
        scope: str,
        *,
        reason: str = "user",
        timeout_kind: str = "",
    ) -> dict[str, Any]:
        if not scope.strip():
            raise ValueError("A durable execution scope must be nonempty")
        if reason not in {"user", "shutdown", "deadline", "timeout", "archive"}:
            raise ValueError("Unsupported cancellation reason")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT 1 FROM agent_cancellation_requests WHERE scope=?",
                    (scope,),
                ).fetchone()
                if row is None:
                    self._conn.execute(
                        "INSERT INTO agent_cancellation_requests "
                        "(scope,state,reason,timeout_kind,requested_at) "
                        "VALUES (?, 'REQUESTED', ?, ?, ?)",
                        (scope, reason, timeout_kind, time.time()),
                    )
                elif reason == "archive":
                    self._conn.execute(
                        "UPDATE agent_cancellation_requests SET reason='archive' "
                        "WHERE scope=?",
                        (scope,),
                    )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return self.cancellation_state(scope) or {}

    def advance_cancellation(self, scope: str, state: str) -> dict[str, Any] | None:
        timestamps = {
            "ACKNOWLEDGED": "acknowledged_at",
            "SAFE_BOUNDARY_REACHED": "safe_boundary_at",
            "TERMINALIZED": "terminalized_at",
        }
        order = {
            "REQUESTED": 1,
            "ACKNOWLEDGED": 2,
            "SAFE_BOUNDARY_REACHED": 3,
            "TERMINALIZED": 4,
        }
        if state not in order:
            raise ValueError("Invalid cancellation state")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT state FROM agent_cancellation_requests WHERE scope=?",
                    (scope,),
                ).fetchone()
                if row is None:
                    self._conn.commit()
                    return None
                if order[row["state"]] < order[state]:
                    column = timestamps[state]
                    self._conn.execute(
                        f"UPDATE agent_cancellation_requests SET state=?, "
                        f"{column}=COALESCE({column}, ?) WHERE scope=?",
                        (state, time.time(), scope),
                    )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return self.cancellation_state(scope)

    def cancellation_state(self, scope: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM agent_cancellation_requests WHERE scope=?", (scope,)
            ).fetchone()
        return dict(row) if row else None

    def clear_cancellation(self, scope: str) -> None:
        """Clear cancellation only for an explicit resume with no quarantine."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                pending = self._conn.execute(
                    "SELECT 1 FROM tool_mutation_reservations WHERE scope=? LIMIT 1",
                    (scope,),
                ).fetchone()
                if pending is not None:
                    raise ValueError("Mutation quarantine must be reconciled first")
                self._conn.execute(
                    "DELETE FROM agent_cancellation_requests WHERE scope=?", (scope,)
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def pending(self, scope: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM tool_mutation_reservations WHERE scope=? "
                "ORDER BY created_at",
                (scope,),
            ).fetchall()
        return [dict(row) for row in rows]

    def reconcile(
        self,
        token: str,
        *,
        resolution: str,
        evidence: str,
        worker_stopped: bool = False,
    ) -> None:
        """Record an observed result and release quarantine.

        This is a trusted control-plane API, never an LLM-callable tool.
        The caller must first ensure the original worker is no longer running
        and verify the external state. Resolution is either VERIFIED (the
        intended action occurred) or NOT_EXECUTED (safe to try a new action).
        """
        if resolution not in {"VERIFIED", "NOT_EXECUTED"}:
            raise ValueError("Reconciliation needs VERIFIED or NOT_EXECUTED")
        if not isinstance(evidence, str) or not evidence.strip():
            raise ValueError("Reconciliation requires observation evidence")
        if worker_stopped is not True:
            raise ValueError("Reconciliation requires a confirmed stopped worker")
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT * FROM tool_mutation_reservations WHERE token=?",
                (token,),
            ).fetchone()
            if row is None:
                raise ValueError("Unknown or already reconciled execution token")
            self._conn.execute(
                "INSERT INTO tool_mutation_reconciliations "
                "(token, scope, tool, call_id, resolution, evidence, reconciled_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    token,
                    row["scope"],
                    row["tool"],
                    row["call_id"],
                    resolution,
                    evidence,
                    time.time(),
                ),
            )
            self._conn.execute(
                "UPDATE semantic_mutation_intents SET status=?, evidence=?, "
                "updated_at=? WHERE token=?",
                (resolution, evidence, time.time(), token),
            )
            self._conn.execute(
                "DELETE FROM tool_mutation_reservations WHERE token=?",
                (token,),
            )

    def reconciliation(
        self, scope: str, tool: str, call_id: str
    ) -> dict[str, Any] | None:
        """Return recorded resolution for one exact dispatched call."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tool_mutation_reconciliations "
                "WHERE scope=? AND tool=? AND call_id=? "
                "ORDER BY reconciled_at DESC LIMIT 1",
                (scope, tool, call_id),
            ).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        with self._lock:
            self._conn.close()
