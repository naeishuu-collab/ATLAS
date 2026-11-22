"""Persistent agent lifecycle manager.

Composition layer — stores agent state in SQLite, delegates all computation
to the five existing primitives (Intelligence, Agent, Tools, Engine, Learning).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import sqlite3
import threading
import time
import uuid
from functools import wraps
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

from openjarvis.core.paths import get_config_dir

logger = logging.getLogger(__name__)

_CREATE_AGENTS = """\
CREATE TABLE IF NOT EXISTS managed_agents (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    agent_type      TEXT NOT NULL DEFAULT 'monitor_operative',
    config_json     TEXT NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'idle',
    summary_memory  TEXT NOT NULL DEFAULT '',
    created_at      REAL NOT NULL,
    updated_at      REAL NOT NULL
);
"""

_CREATE_TASKS = """\
CREATE TABLE IF NOT EXISTS agent_tasks (
    id              TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL REFERENCES managed_agents(id),
    description     TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    progress_json   TEXT NOT NULL DEFAULT '{}',
    findings_json   TEXT NOT NULL DEFAULT '[]',
    principal_id    TEXT,
    host_session_id TEXT,
    execution_attempt TEXT,
    state_version   INTEGER NOT NULL DEFAULT 0,
    checkpoint_id   TEXT,
    checkpoint_version INTEGER NOT NULL DEFAULT 0,
    required_tools_json TEXT NOT NULL DEFAULT '[]',
    completion_evidence_json TEXT NOT NULL DEFAULT '{}',
    cancellation_state TEXT NOT NULL DEFAULT 'ACTIVE',
    revocation_state TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at      REAL NOT NULL
);
"""

_CREATE_BINDINGS = """\
CREATE TABLE IF NOT EXISTS channel_bindings (
    id              TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL REFERENCES managed_agents(id),
    channel_type    TEXT NOT NULL,
    config_json     TEXT NOT NULL DEFAULT '{}',
    session_id      TEXT,
    routing_mode    TEXT NOT NULL DEFAULT 'dedicated'
);
"""

_CREATE_CHECKPOINTS = """\
CREATE TABLE IF NOT EXISTS agent_checkpoints (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES managed_agents(id),
    tick_id TEXT NOT NULL,
    conversation_state TEXT NOT NULL DEFAULT '{}',
    tool_state TEXT NOT NULL DEFAULT '{}',
    created_at REAL NOT NULL
);
"""

_CREATE_MESSAGES = """\
CREATE TABLE IF NOT EXISTS agent_messages (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES managed_agents(id),
    direction TEXT NOT NULL,
    content TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'queued',
    status TEXT NOT NULL DEFAULT 'pending',
    created_at REAL NOT NULL
);
"""

_CREATE_LEARNING_LOG = """\
CREATE TABLE IF NOT EXISTS agent_learning_log (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    description TEXT,
    data TEXT,
    created_at REAL NOT NULL
);
"""

# Rolling summary fed back into the next tick's prompt, so it stays bounded —
# but 2000 chars clipped real research reports mid-sentence (the findings the
# UI/CLI show come from here). 16k (~4k tokens) holds a full report while
# keeping per-tick prompt growth in check.
_SUMMARY_MAX = 16000


def _db_locked(func):
    """Serialize access to the connection shared by manager worker threads."""

    @wraps(func)
    def wrapped(self, *args, **kwargs):
        with self._db_lock:
            return func(self, *args, **kwargs)

    return wrapped


class AgentManager:
    """Persistent agent lifecycle manager with SQLite backing."""

    # A tick that hasn't touched its DB row in this many seconds is treated
    # as a zombie (its worker died without running end_tick). start_tick()
    # will overtake such a lock instead of refusing forever. The executor
    # bumps updated_at at start and on every tool/inference event, so a live
    # tick stays well under this window.
    _STALE_TICK_SECONDS = 600

    def __init__(self, db_path: str, *, clear_stale_running: bool = False) -> None:
        self._db_path = str(db_path)
        self._db_lock = threading.RLock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute(_CREATE_AGENTS)
        self._conn.execute(_CREATE_TASKS)
        self._conn.execute(_CREATE_BINDINGS)
        self._conn.executescript(_CREATE_CHECKPOINTS)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS agent_task_checkpoint_bindings ("
            "task_id TEXT PRIMARY KEY REFERENCES agent_tasks(id) ON DELETE CASCADE, "
            "checkpoint_id TEXT NOT NULL UNIQUE, "
            "agent_id TEXT NOT NULL, principal_id TEXT NOT NULL, "
            "attempt TEXT NOT NULL, mac TEXT NOT NULL)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS agent_task_checkpoint_history ("
            "task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE, "
            "version INTEGER NOT NULL, checkpoint_id TEXT NOT NULL UNIQUE, "
            "previous_mac TEXT NOT NULL, mac TEXT NOT NULL, "
            "PRIMARY KEY (task_id, version))"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS agent_task_authority ("
            "task_id TEXT PRIMARY KEY REFERENCES agent_tasks(id) ON DELETE CASCADE, "
            "agent_id TEXT NOT NULL, principal_id TEXT NOT NULL, "
            "attempt TEXT NOT NULL, "
            "owner_hash TEXT NOT NULL, epoch INTEGER NOT NULL, "
            "expires_at REAL NOT NULL, state TEXT NOT NULL)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS task_tool_journal ("
            "request_id TEXT PRIMARY KEY, tool_call_id TEXT NOT NULL UNIQUE, "
            "task_id TEXT NOT NULL REFERENCES agent_tasks(id), "
            "agent_id TEXT NOT NULL, principal_id TEXT NOT NULL, "
            "attempt TEXT NOT NULL, owner_hash TEXT NOT NULL, epoch INTEGER NOT NULL, "
            "worker_id TEXT NOT NULL, "
            "tool_name TEXT NOT NULL, arguments_sha256 TEXT NOT NULL, "
            "checkpoint_version INTEGER NOT NULL, deadline REAL NOT NULL, "
            "state TEXT NOT NULL CHECK(state IN "
            "('PREPARED','DISPATCHED','RESULT_RECORDED',"
            "'CHECKPOINTED','UNKNOWN_OUTCOME')), "
            "result_sha256 TEXT, result_success INTEGER, checkpointed_version INTEGER, "
            "created_at REAL NOT NULL, updated_at REAL NOT NULL, mac TEXT NOT NULL)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS task_tool_journal_heads ("
            "task_id TEXT PRIMARY KEY REFERENCES agent_tasks(id), "
            "agent_id TEXT NOT NULL, principal_id TEXT NOT NULL, "
            "attempt TEXT NOT NULL, "
            "owner_hash TEXT NOT NULL, epoch INTEGER NOT NULL, "
            "entry_count INTEGER NOT NULL, rows_sha256 TEXT NOT NULL, "
            "mac TEXT NOT NULL)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS task_tool_dispatch_claims ("
            "request_id TEXT PRIMARY KEY REFERENCES task_tool_journal(request_id), "
            "task_id TEXT NOT NULL, worker_id TEXT NOT NULL, epoch INTEGER NOT NULL, "
            "claimed_at REAL NOT NULL, mac TEXT NOT NULL)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS task_worker_exit_evidence ("
            "task_id TEXT NOT NULL, worker_id TEXT NOT NULL, payload TEXT NOT NULL, "
            "mac TEXT NOT NULL, PRIMARY KEY(task_id, worker_id))"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS agent_task_epoch_fences ("
            "task_id TEXT NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE, "
            "epoch INTEGER NOT NULL, payload TEXT NOT NULL, mac TEXT NOT NULL, "
            "PRIMARY KEY(task_id, epoch))"
        )
        self._conn.executescript(_CREATE_MESSAGES)
        self._conn.executescript(_CREATE_LEARNING_LOG)
        self._conn.commit()
        self._interrupted_agents: set[str] = set()
        self._recovery_requested_agents: set[str] = set()
        # Schema migrations for runtime columns
        _MIGRATIONS = [
            "ALTER TABLE managed_agents ADD COLUMN total_tokens INTEGER DEFAULT 0",
            "ALTER TABLE managed_agents ADD COLUMN total_cost REAL DEFAULT 0",
            "ALTER TABLE managed_agents ADD COLUMN total_runs INTEGER DEFAULT 0",
            "ALTER TABLE managed_agents ADD COLUMN last_run_at REAL",
            "ALTER TABLE managed_agents ADD COLUMN last_activity_at REAL",
            "ALTER TABLE managed_agents ADD COLUMN stall_retries INTEGER DEFAULT 0",
            "ALTER TABLE managed_agents ADD COLUMN current_activity TEXT DEFAULT ''",
            "ALTER TABLE managed_agents ADD COLUMN input_tokens INTEGER DEFAULT 0",
            "ALTER TABLE managed_agents ADD COLUMN output_tokens INTEGER DEFAULT 0",
            # JSON-encoded array of {tool, arguments, result, success, latency}
            "ALTER TABLE agent_messages ADD COLUMN tool_calls TEXT",
            "ALTER TABLE agent_tasks ADD COLUMN principal_id TEXT",
            "ALTER TABLE agent_tasks ADD COLUMN host_session_id TEXT",
            "ALTER TABLE agent_tasks ADD COLUMN execution_attempt TEXT",
            "ALTER TABLE agent_tasks ADD COLUMN state_version "
            "INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE agent_tasks ADD COLUMN checkpoint_id TEXT",
            "ALTER TABLE agent_tasks ADD COLUMN checkpoint_version "
            "INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE agent_tasks ADD COLUMN required_tools_json "
            "TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE agent_tasks ADD COLUMN completion_evidence_json "
            "TEXT NOT NULL DEFAULT '{}'",
            "ALTER TABLE agent_tasks ADD COLUMN cancellation_state "
            "TEXT NOT NULL DEFAULT 'ACTIVE'",
            "ALTER TABLE agent_tasks ADD COLUMN revocation_state "
            "TEXT NOT NULL DEFAULT 'ACTIVE'",
        ]
        for migration in _MIGRATIONS:
            try:
                self._conn.execute(migration)
            except sqlite3.OperationalError:
                pass  # Column already exists
        self._conn.commit()
        # Only the authoritative long-running process (the API server, which
        # owns the scheduler) may sweep running→idle on boot. Short-lived CLI
        # commands (`jarvis agents list/info/...`) and the SystemBuilder path
        # used by `run`/`ask` MUST NOT: they share this DB with a server that
        # may be mid-tick, and an unconditional sweep here flips an actively
        # running agent back to "idle" — which is exactly why `list` reported
        # "idle" while a tick was running elsewhere. Zombies left by a crashed
        # worker are recovered lazily by start_tick()'s stale-lock overtake.
        if clear_stale_running:
            self._clear_stale_running_state()
        from openjarvis.tools.execution_journal import ExecutionJournal

        self.execution_journal = ExecutionJournal(self._db_path)

    @_db_locked
    def _clear_stale_running_state(self) -> None:
        """Reset legacy, non-task agent ticks on an exclusive server startup.

        Tick worker threads are ``daemon=True`` — when the server process
        exits (SIGTERM, crash, restart), they die without running the
        ``finally`` clause that calls :meth:`end_tick`, leaving the DB row
        in ``running`` forever. The :meth:`start_tick` guard then rejects
        every subsequent run with "Agent is already running".

        Task-bound ticks are never cleared here: another process may still
        own the worker. Call this only from a process that owns legacy ticks.
        """
        # Task-bound workers require proof of ownership before lock recovery.
        eligible = (
            "status = 'running' AND NOT EXISTS (SELECT 1 FROM agent_tasks "
            "WHERE agent_tasks.agent_id = managed_agents.id AND "
            "agent_tasks.status = 'running' AND execution_attempt IS NOT NULL)"
        )
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self._conn.execute(
                f"SELECT id FROM managed_agents WHERE {eligible}"
            ).fetchall()
            cur = self._conn.execute(
                "UPDATE managed_agents SET status = 'idle', current_activity = '',"
                f" updated_at = ? WHERE {eligible}",
                (time.time(),),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        self._interrupted_agents.update(row["id"] for row in rows)
        if cur.rowcount:
            logger.info(
                "AgentManager: cleared stale 'running' status on %d agent(s)",
                cur.rowcount,
            )

    @_db_locked
    def is_restart_candidate(self, agent_id: str) -> bool:
        """Return whether startup or explicit recovery proved the old worker stopped."""
        return agent_id in self._interrupted_agents

    @_db_locked
    def clear_restart_candidate(self, agent_id: str) -> None:
        self._interrupted_agents.discard(agent_id)

    @_db_locked
    def is_recovery_requested(self, agent_id: str) -> bool:
        return agent_id in self._recovery_requested_agents

    @_db_locked
    def clear_recovery_request(self, agent_id: str) -> None:
        self._recovery_requested_agents.discard(agent_id)

    @_db_locked
    def close(self) -> None:
        self.execution_journal.close()
        self._conn.close()

    # ── Agent CRUD ────────────────────────────────────────────────

    @_db_locked
    def create_agent(
        self,
        name: str,
        agent_type: str = "monitor_operative",
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        agent_id = uuid.uuid4().hex[:12]
        now = time.time()
        config = dict(config or {})
        config_json = json.dumps(config)
        self._conn.execute(
            "INSERT INTO managed_agents"
            " (id, name, agent_type, config_json,"
            " status, summary_memory, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, 'idle', '', ?, ?)",
            (agent_id, name, agent_type, config_json, now, now),
        )
        self._conn.commit()
        return self.get_agent(agent_id)  # type: ignore[return-value]

    @_db_locked
    def list_agents(self, include_archived: bool = False) -> List[Dict[str, Any]]:
        query = "SELECT * FROM managed_agents"
        if not include_archived:
            query += " WHERE status != 'archived'"
        query += " ORDER BY updated_at DESC"
        rows = self._conn.execute(query).fetchall()
        return [self._row_to_agent(r) for r in rows]

    @_db_locked
    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT * FROM managed_agents WHERE id = ?", (agent_id,)
        ).fetchone()
        return self._row_to_agent(row) if row else None

    @_db_locked
    def update_agent(self, agent_id: str, **kwargs: Any) -> Dict[str, Any]:
        sets: List[str] = []
        vals: List[Any] = []
        for key in ("name", "agent_type", "status", "current_activity"):
            if key in kwargs:
                sets.append(f"{key} = ?")
                vals.append(kwargs[key])
        if "config" in kwargs:
            sets.append("config_json = ?")
            vals.append(json.dumps(kwargs["config"]))
        total_runs_increment = kwargs.get("total_runs_increment", 0)
        if total_runs_increment:
            sets.append("total_runs = total_runs + ?")
            vals.append(total_runs_increment)
            sets.append("last_run_at = ?")
            vals.append(time.time())
        total_cost_increment = kwargs.get("total_cost_increment", 0)
        if total_cost_increment:
            sets.append("total_cost = total_cost + ?")
            vals.append(total_cost_increment)
        total_tokens_increment = kwargs.get("total_tokens_increment", 0)
        if total_tokens_increment:
            sets.append("total_tokens = total_tokens + ?")
            vals.append(total_tokens_increment)
        input_tokens_increment = kwargs.get("input_tokens_increment", 0)
        if input_tokens_increment:
            sets.append("input_tokens = input_tokens + ?")
            vals.append(input_tokens_increment)
        output_tokens_increment = kwargs.get("output_tokens_increment", 0)
        if output_tokens_increment:
            sets.append("output_tokens = output_tokens + ?")
            vals.append(output_tokens_increment)
        if "last_activity_at" in kwargs:
            sets.append("last_activity_at = ?")
            vals.append(kwargs["last_activity_at"])
        if "stall_retries" in kwargs:
            sets.append("stall_retries = ?")
            vals.append(kwargs["stall_retries"])
        sets.append("updated_at = ?")
        vals.append(time.time())
        vals.append(agent_id)
        self._conn.execute(
            f"UPDATE managed_agents SET {', '.join(sets)} WHERE id = ?", vals
        )
        self._conn.commit()
        return self.get_agent(agent_id)  # type: ignore[return-value]

    @_db_locked
    def delete_agent(self, agent_id: str) -> dict[str, Any] | None:
        """Archive idle agents or request safe cancellation for running ones."""
        while True:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                agent = self._conn.execute(
                    "SELECT status FROM managed_agents WHERE id=?", (agent_id,)
                ).fetchone()
                if agent is None:
                    raise ValueError(f"Agent {agent_id} not found")
                if agent["status"] != "running":
                    pending = self._conn.execute(
                        "SELECT 1 FROM tool_mutation_reservations "
                        "WHERE scope=? LIMIT 1",
                        (agent_id,),
                    ).fetchone()
                    if pending is not None:
                        raise ValueError(
                            "Mutation recovery must be completed before archive"
                        )
                cursor = self._conn.execute(
                    "UPDATE managed_agents SET status='archived',updated_at=? "
                    "WHERE id=? AND status!='running'",
                    (time.time(), agent_id),
                )
                if cursor.rowcount:
                    self._conn.commit()
                    return None
                agent = self._conn.execute(
                    "SELECT status FROM managed_agents WHERE id=?", (agent_id,)
                ).fetchone()
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            if agent is None:
                raise ValueError(f"Agent {agent_id} not found")
            try:
                return self.request_cancellation(agent_id, reason="archive")
            except ValueError:
                # Tick completion raced the cancellation request.
                continue

    @_db_locked
    def pause_agent(self, agent_id: str) -> dict[str, Any] | None:
        """Pause immediately only when idle; running work stops cooperatively."""
        while True:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                agent = self._conn.execute(
                    "SELECT status FROM managed_agents WHERE id=?", (agent_id,)
                ).fetchone()
                if agent is None:
                    raise ValueError(f"Agent {agent_id} not found")
                if agent["status"] == "archived":
                    raise ValueError("An archived agent cannot be paused")
                cursor = self._conn.execute(
                    "UPDATE managed_agents SET status='paused',updated_at=? "
                    "WHERE id=? AND status!='running'",
                    (time.time(), agent_id),
                )
                if cursor.rowcount:
                    self._conn.commit()
                    return None
                agent = self._conn.execute(
                    "SELECT status FROM managed_agents WHERE id=?", (agent_id,)
                ).fetchone()
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            if agent is None:
                raise ValueError(f"Agent {agent_id} not found")
            try:
                return self.request_cancellation(agent_id, reason="user")
            except ValueError:
                # A concurrent tick completion changed the status after the
                # read. Retry the conditional pause against the new state.
                continue

    @_db_locked
    def resume_agent(self, agent_id: str) -> None:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            agent = self._conn.execute(
                "SELECT status FROM managed_agents WHERE id=?", (agent_id,)
            ).fetchone()
            if agent is None:
                raise ValueError(f"Agent {agent_id} not found")
            if agent["status"] == "archived":
                raise ValueError("An archived agent cannot be resumed")
            if agent["status"] == "running":
                raise ValueError("A running agent must reach a safe boundary first")
            pending = self._conn.execute(
                "SELECT 1 FROM tool_mutation_reservations WHERE scope=? LIMIT 1",
                (agent_id,),
            ).fetchone()
            if pending is not None:
                raise ValueError("Mutation recovery must be completed before resume")
            row = self._conn.execute(
                "SELECT id,conversation_state,tool_state FROM agent_checkpoints "
                "WHERE agent_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1",
                (agent_id,),
            ).fetchone()
            if row is not None:
                conversation = json.loads(row["conversation_state"])
                tool_state = json.loads(row["tool_state"])
                if (tool_state.get("recovery") or {}).get("required"):
                    raise ValueError(
                        "Mutation recovery must be completed before resume"
                    )
                if conversation.get("lifecycle") in {"CANCELLED", "TIMED_OUT"}:
                    conversation["lifecycle"] = "RUNNING"
                    conversation["resume_authorized"] = True
                    prior_cancellation = tool_state.pop("cancellation", None)
                    if prior_cancellation is not None:
                        history = list(tool_state.get("cancellation_history", []))
                        history.append(
                            {**prior_cancellation, "cleared_at": time.time()}
                        )
                        tool_state["cancellation_history"] = history
                    self._conn.execute(
                        "UPDATE agent_checkpoints SET conversation_state=?, "
                        "tool_state=? WHERE id=?",
                        (json.dumps(conversation), json.dumps(tool_state), row["id"]),
                    )
                    self._interrupted_agents.add(agent_id)
            self._conn.execute(
                "DELETE FROM agent_cancellation_requests WHERE scope=?", (agent_id,)
            )
            self._conn.execute(
                "UPDATE managed_agents SET status='idle',updated_at=? WHERE id=?",
                (time.time(), agent_id),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    @_db_locked
    def request_cancellation(
        self,
        agent_id: str,
        *,
        reason: str = "user",
        timeout_kind: str = "",
    ) -> dict[str, Any]:
        """Persist per-agent cancellation before notifying its active worker."""
        if reason not in {"user", "shutdown", "deadline", "timeout", "archive"}:
            raise ValueError("Unsupported cancellation reason")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            agent = self._conn.execute(
                "SELECT status FROM managed_agents WHERE id=?", (agent_id,)
            ).fetchone()
            if agent is None:
                raise ValueError(f"Agent {agent_id} not found")
            if agent["status"] != "running":
                raise ValueError("Agent is not running")
            now = time.time()
            self._conn.execute(
                "INSERT INTO agent_cancellation_requests "
                "(scope,state,reason,timeout_kind,requested_at) "
                "VALUES (?, 'REQUESTED', ?, ?, ?) "
                "ON CONFLICT(scope) DO UPDATE SET "
                "reason=CASE WHEN excluded.reason='archive' "
                "THEN 'archive' ELSE reason END",
                (agent_id, reason, timeout_kind, now),
            )
            row = self._conn.execute(
                "SELECT * FROM agent_cancellation_requests WHERE scope=?",
                (agent_id,),
            ).fetchone()
            checkpoint = self._conn.execute(
                "SELECT id,tool_state FROM agent_checkpoints WHERE agent_id=? "
                "ORDER BY created_at DESC,rowid DESC LIMIT 1",
                (agent_id,),
            ).fetchone()
            if checkpoint is not None:
                try:
                    state = json.loads(checkpoint["tool_state"])
                except (TypeError, json.JSONDecodeError):
                    state = None
                if isinstance(state, dict):
                    active = state.get("active_step")
                    if (
                        isinstance(active, dict)
                        and active.get("state") == "EXECUTED"
                        and active.get("execution_state") == "EXECUTED"
                        and active.get("effect") != "READ_ONLY"
                        and all(
                            isinstance(active.get(key), str) and active.get(key)
                            for key in ("tool", "call_id", "journal_token")
                        )
                    ):
                        # The tool result may have committed immediately before
                        # cancellation won the next planning boundary. Recreate
                        # its exact unverified claim so resume must reconcile it.
                        try:
                            self._conn.execute(
                                "INSERT INTO tool_mutation_reservations "
                                "(scope,tool,token,call_id,state,created_at) "
                                "VALUES (?,?,?,?, 'EXECUTED', ?) ",
                                (
                                    agent_id,
                                    active["tool"],
                                    active["journal_token"],
                                    active["call_id"],
                                    now,
                                ),
                            )
                        except sqlite3.IntegrityError:
                            # An existing quarantine remains authoritative. A
                            # different active action will fail exact identity
                            # matching during restore rather than being retargeted.
                            pass
                    state["cancellation"] = dict(row)
                    self._conn.execute(
                        "UPDATE agent_checkpoints SET tool_state=? WHERE id=?",
                        (json.dumps(state), checkpoint["id"]),
                    )
            self._conn.commit()
            return dict(row)
        except Exception:
            self._conn.rollback()
            raise

    @_db_locked
    def cancellation_state(self, agent_id: str) -> dict[str, Any] | None:
        return self.execution_journal.cancellation_state(agent_id)

    @_db_locked
    def advance_cancellation(self, agent_id: str, state: str) -> dict[str, Any] | None:
        cancellation = self.execution_journal.advance_cancellation(agent_id, state)
        if cancellation is None:
            return None
        checkpoint = self.get_latest_checkpoint(agent_id)
        if checkpoint is not None:
            tool_state = checkpoint.get("tool_state") or {}
            tool_state["cancellation"] = cancellation
            self._conn.execute(
                "UPDATE agent_checkpoints SET tool_state=? WHERE id=?",
                (json.dumps(tool_state), checkpoint["id"]),
            )
            self._conn.commit()
        return cancellation

    @_db_locked
    def _set_status(self, agent_id: str, status: str) -> None:
        self._conn.execute(
            "UPDATE managed_agents SET status = ?, updated_at = ? WHERE id = ?",
            (status, time.time(), agent_id),
        )
        self._conn.commit()

    # ── Tick concurrency guard ────────────────────────────────────

    @_db_locked
    def start_tick(self, agent_id: str) -> None:
        """Mark agent as running. Raises ValueError if already running.

        Legacy non-task ticks may be overtaken after ``_STALE_TICK_SECONDS``.
        Task-bound ticks require an explicit recovery authority instead.

        The state transition is a single conditional SQLite update.  The
        read-before-write approach is racy when two workers start together:
        both can observe ``idle`` and then mark the row ``running``.  The
        conditional update lets SQLite choose exactly one winner, including
        when workers use separate connections or processes.
        """
        while True:
            now = time.time()
            stale_before = now - self._STALE_TICK_SECONDS
            agent = self.get_agent(agent_id)
            if agent is None:
                return
            if agent["status"] == "archived":
                raise ValueError(f"Agent {agent_id} is archived")

            was_stale = (
                agent["status"] == "running"
                and (agent.get("updated_at") or 0) <= stale_before
            )
            cursor = self._conn.execute(
                "UPDATE managed_agents SET status = 'running', "
                "updated_at = ? WHERE id = ? AND "
                "status != 'archived' AND "
                "(status != 'running' OR (updated_at <= ? AND NOT EXISTS ("
                "SELECT 1 FROM agent_tasks WHERE agent_tasks.agent_id = "
                "managed_agents.id AND agent_tasks.status = 'running' "
                "AND execution_attempt IS NOT NULL)))",
                (now, agent_id, stale_before),
            )
            self._conn.commit()
            if cursor.rowcount:
                if was_stale:
                    age = time.time() - (agent.get("updated_at") or 0)
                    logger.warning(
                        "Agent %s: overtaking stale tick lock "
                        "(running, idle for %.0fs)",
                        agent_id,
                        age,
                    )
                return

            # Another connection acquired the lock after our read.  If that
            # lock is still fresh, this caller loses; if it ended between the
            # failed update and this read, retry so the caller never proceeds
            # without owning the tick lock.
            current = self.get_agent(agent_id)
            if current is None:
                return
            if current["status"] == "archived":
                raise ValueError(f"Agent {agent_id} is archived")
            if current["status"] == "running":
                age = time.time() - (current.get("updated_at") or 0)
                task_running = self._conn.execute(
                    "SELECT 1 FROM agent_tasks WHERE agent_id = ? "
                    "AND status = 'running' AND execution_attempt IS NOT NULL",
                    (agent_id,),
                ).fetchone()
                if age < self._STALE_TICK_SECONDS or task_running is not None:
                    raise ValueError(f"Agent {agent_id} is already executing a tick")

    @_db_locked
    def end_tick(self, agent_id: str) -> None:
        self._conn.execute(
            "UPDATE managed_agents SET status = CASE WHEN EXISTS ("
            "SELECT 1 FROM agent_cancellation_requests "
            "WHERE scope=managed_agents.id) THEN 'running' ELSE 'idle' END, "
            "current_activity = '', updated_at = ? "
            "WHERE id = ? AND status = 'running'",
            (time.time(), agent_id),
        )
        self._conn.commit()

    @_db_locked
    def complete_tick_if_not_cancelled(self, agent_id: str) -> bool:
        """Linearize normal completion against cancellation requests."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT status FROM managed_agents WHERE id=?", (agent_id,)
            ).fetchone()
            if row is None or row["status"] != "running":
                self._conn.rollback()
                return False
            cancellation = self._conn.execute(
                "SELECT 1 FROM agent_cancellation_requests WHERE scope=?",
                (agent_id,),
            ).fetchone()
            if cancellation is not None:
                self._conn.rollback()
                return False
            self._conn.execute(
                "UPDATE managed_agents SET status='idle',current_activity='',"
                "updated_at=? "
                "WHERE id=? AND status='running'",
                (time.time(), agent_id),
            )
            self._conn.commit()
            return True
        except Exception:
            self._conn.rollback()
            raise

    # ── Checkpoints ───────────────────────────────────────────────

    _CHECKPOINT_RETENTION = 5

    @_db_locked
    def save_checkpoint(
        self,
        agent_id: str,
        tick_id: str,
        conversation_state: dict,
        tool_state: dict,
    ) -> dict:
        cp_id = uuid4().hex[:16]
        now = time.time()
        self._conn.execute(
            "INSERT INTO agent_checkpoints"
            " (id, agent_id, tick_id, conversation_state, tool_state, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                cp_id,
                agent_id,
                tick_id,
                json.dumps(conversation_state),
                json.dumps(tool_state),
                now,
            ),
        )
        # Prune old checkpoints beyond retention limit
        self._conn.execute(
            "DELETE FROM agent_checkpoints WHERE agent_id = ? AND id NOT IN "
            "(SELECT id FROM agent_checkpoints WHERE agent_id = ?"
            " ORDER BY created_at DESC, rowid DESC LIMIT ?) "
            "AND id NOT IN (SELECT checkpoint_id FROM agent_task_checkpoint_bindings) "
            "AND id NOT IN (SELECT checkpoint_id FROM agent_task_checkpoint_history)",
            (agent_id, agent_id, self._CHECKPOINT_RETENTION),
        )
        self._conn.commit()
        return {
            "id": cp_id,
            "agent_id": agent_id,
            "tick_id": tick_id,
            "created_at": now,
        }

    @_db_locked
    def list_checkpoints(self, agent_id: str) -> list:
        rows = self._conn.execute(
            "SELECT * FROM agent_checkpoints"
            " WHERE agent_id = ? ORDER BY created_at DESC, rowid DESC",
            (agent_id,),
        ).fetchall()
        return [self._row_to_checkpoint(r) for r in rows]

    @_db_locked
    def get_latest_checkpoint(self, agent_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT * FROM agent_checkpoints"
            " WHERE agent_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (agent_id,),
        ).fetchone()
        return self._row_to_checkpoint(row) if row else None

    @staticmethod
    def _task_checkpoint_mac(
        key: bytes,
        task_id: str,
        agent_id: str,
        principal_id: str,
        attempt: str,
        checkpoint: dict,
        version: int = 1,
        previous_mac: str = "",
    ) -> str:
        fields = [task_id, agent_id, principal_id, attempt, checkpoint]
        if version > 1:
            fields.extend((version, previous_mac))
        payload = json.dumps(
            fields,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        return hmac.new(key, payload, hashlib.sha256).hexdigest()

    @_db_locked
    def bind_task_checkpoint(
        self,
        task_id: str,
        agent_id: str,
        principal: Any,
        authority: Any,
        checkpoint_id: str,
        attempt: str,
        *,
        integrity_key: bytes,
        expected_version: int = 0,
        worker_token: str | None = None,
        worker_epoch: int | None = None,
    ) -> int:
        """Bind checkpoint integrity; host-session messages wait for lease proof."""
        if (
            not isinstance(integrity_key, bytes)
            or len(integrity_key) < 32
            or not isinstance(attempt, str)
            or not attempt
            or type(expected_version) is not int
            or expected_version < 0
            or not callable(getattr(authority, "accepts", None))
            or not authority.accepts(principal)
        ):
            raise PermissionError("task checkpoint authority invalid")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            task = self._get_task(task_id, agent_id=agent_id)
            row = self._conn.execute(
                "SELECT * FROM agent_checkpoints WHERE id = ? AND agent_id = ?",
                (checkpoint_id, agent_id),
            ).fetchone()
            if task is None or row is None:
                raise PermissionError("task or checkpoint identity mismatch")
            if task["execution_attempt"] is not None and (
                task["status"] != "running"
                or task["execution_attempt"] != attempt
                or task["principal_id"] != principal.principal_id
            ):
                raise PermissionError("task execution identity mismatch")
            if task["execution_attempt"] is not None:
                self.validate_task_authority(
                    task_id,
                    agent_id,
                    principal,
                    authority,
                    attempt,
                    worker_token,
                    worker_epoch,
                )
            checkpoint = self._row_to_checkpoint(row)
            conversation_state = checkpoint["conversation_state"]
            state = checkpoint["tool_state"]
            if not isinstance(conversation_state, dict) or not isinstance(state, dict):
                raise PermissionError("task checkpoint binding mismatch")
            # shortcut: reject until Controller-verified lease proof reaches this API.
            session_tools = ("browser_navigate", "windows_action")
            messages = conversation_state.get("messages", [])
            if not isinstance(messages, list):
                raise PermissionError("task checkpoint binding mismatch")
            for message in messages:
                if not isinstance(message, dict):
                    raise PermissionError("task checkpoint binding mismatch")
                if message.get("name") in session_tools:
                    raise PermissionError("task checkpoint binding mismatch")
                calls = message.get("tool_calls") or []
                if not isinstance(calls, list) or any(
                    not isinstance(call, dict) or call.get("name") in session_tools
                    for call in calls
                ):
                    raise PermissionError("task checkpoint binding mismatch")
            if task["execution_attempt"] is not None and (
                not isinstance(state, dict) or state.get("worker_epoch") != worker_epoch
            ):
                raise PermissionError("task checkpoint worker epoch mismatch")
            if (
                conversation_state.get("task_id") != task_id
                or state.get("execution_id") != attempt
                or not isinstance(getattr(principal, "principal_id", None), str)
            ):
                raise PermissionError("task checkpoint binding mismatch")
            existing = self._conn.execute(
                "SELECT * FROM agent_task_checkpoint_bindings WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            previous_mac = ""
            version = 1
            if existing is None:
                if expected_version != 0:
                    raise PermissionError("stale checkpoint version")
            else:
                if (
                    existing["agent_id"] != agent_id
                    or (existing["principal_id"] != principal.principal_id)
                    or existing["attempt"] != attempt
                ):
                    raise PermissionError(
                        "task checkpoint attempt or identity mismatch"
                    )
                self.get_bound_task_checkpoint(
                    task_id, agent_id, principal, authority, integrity_key=integrity_key
                )
                history = self._conn.execute(
                    "SELECT MAX(version) FROM agent_task_checkpoint_history "
                    "WHERE task_id = ?",
                    (task_id,),
                ).fetchone()[0]
                current_version = history or 1
                if expected_version != current_version:
                    raise PermissionError("stale checkpoint version or already bound")
                if not history:
                    self._conn.execute(
                        "INSERT INTO agent_task_checkpoint_history "
                        "VALUES (?, 1, ?, '', ?)",
                        (task_id, existing["checkpoint_id"], existing["mac"]),
                    )
                previous_mac = existing["mac"]
                version = current_version + 1
            mac = self._task_checkpoint_mac(
                integrity_key,
                task_id,
                agent_id,
                principal.principal_id,
                attempt,
                checkpoint,
                version,
                previous_mac,
            )
            if not authority.accepts(principal):
                raise PermissionError("task checkpoint authority invalid")
            self._conn.execute(
                "INSERT INTO agent_task_checkpoint_history VALUES (?, ?, ?, ?, ?)",
                (task_id, version, checkpoint_id, previous_mac, mac),
            )
            if existing is None:
                self._conn.execute(
                    "INSERT INTO agent_task_checkpoint_bindings "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        task_id,
                        checkpoint_id,
                        agent_id,
                        principal.principal_id,
                        attempt,
                        mac,
                    ),
                )
            else:
                self._conn.execute(
                    "UPDATE agent_task_checkpoint_bindings "
                    "SET checkpoint_id = ?, mac = ? "
                    "WHERE task_id = ? AND checkpoint_id = ? AND mac = ?",
                    (
                        checkpoint_id,
                        mac,
                        task_id,
                        existing["checkpoint_id"],
                        previous_mac,
                    ),
                )
            self._conn.execute(
                "UPDATE agent_tasks SET checkpoint_id = ?, checkpoint_version = ? "
                "WHERE id = ? AND agent_id = ?",
                (checkpoint_id, version, task_id, agent_id),
            )
            self._conn.commit()
            return version
        except sqlite3.IntegrityError as exc:
            self._conn.rollback()
            raise PermissionError("task checkpoint already bound") from exc
        except Exception:
            self._conn.rollback()
            raise

    @_db_locked
    def get_bound_task_checkpoint(
        self,
        task_id: str,
        agent_id: str,
        principal: Any,
        authority: Any,
        *,
        integrity_key: bytes,
    ) -> dict:
        if (
            not isinstance(integrity_key, bytes)
            or len(integrity_key) < 32
            or not callable(getattr(authority, "accepts", None))
            or not authority.accepts(principal)
        ):
            raise PermissionError("task checkpoint authority invalid")
        link = self._conn.execute(
            "SELECT * FROM agent_task_checkpoint_bindings WHERE task_id = ? "
            "AND agent_id = ? AND principal_id = ?",
            (task_id, agent_id, getattr(principal, "principal_id", None)),
        ).fetchone()
        if link is None or self._get_task(task_id, agent_id=agent_id) is None:
            raise PermissionError("task checkpoint binding unavailable")
        history = self._conn.execute(
            "SELECT * FROM agent_task_checkpoint_history WHERE task_id = ? "
            "ORDER BY version",
            (task_id,),
        ).fetchall()
        if not history:
            history = [
                {
                    "version": 1,
                    "checkpoint_id": link["checkpoint_id"],
                    "previous_mac": "",
                    "mac": link["mac"],
                }
            ]
        previous_mac = ""
        checkpoint = None
        for version, entry in enumerate(history, 1):
            if entry["version"] != version or entry["previous_mac"] != previous_mac:
                raise PermissionError("task checkpoint chain mismatch")
            row = self._conn.execute(
                "SELECT * FROM agent_checkpoints WHERE id = ? AND agent_id = ?",
                (entry["checkpoint_id"], agent_id),
            ).fetchone()
            if row is None:
                raise PermissionError("task checkpoint binding unavailable")
            try:
                checkpoint = self._row_to_checkpoint(row)
                mac = self._task_checkpoint_mac(
                    integrity_key,
                    task_id,
                    agent_id,
                    principal.principal_id,
                    link["attempt"],
                    checkpoint,
                    version,
                    previous_mac,
                )
            except (ValueError, TypeError, KeyError) as exc:
                raise PermissionError("task checkpoint invalid") from exc
            if not hmac.compare_digest(mac, entry["mac"]):
                raise PermissionError("task checkpoint integrity mismatch")
            previous_mac = mac
        if link["checkpoint_id"] != history[-1][
            "checkpoint_id"
        ] or not hmac.compare_digest(link["mac"], previous_mac):
            raise PermissionError("task checkpoint chain mismatch")
        if not authority.accepts(principal):
            raise PermissionError("task checkpoint authority invalid")
        checkpoint["task_binding_version"] = len(history)
        return checkpoint

    @_db_locked
    def recover_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            checkpoint = self.get_latest_checkpoint(agent_id)
            cursor = self._conn.execute(
                "UPDATE managed_agents SET status = 'idle', updated_at = ? "
                "WHERE id = ? AND NOT EXISTS (SELECT 1 FROM agent_tasks "
                "WHERE agent_tasks.agent_id = managed_agents.id "
                "AND agent_tasks.status = 'running' "
                "AND execution_attempt IS NOT NULL)",
                (time.time(), agent_id),
            )
            if cursor.rowcount != 1 and self.get_agent(agent_id) is not None:
                raise ValueError("task worker recovery requires host authority")
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        if checkpoint is not None:
            self._interrupted_agents.add(agent_id)
            self._recovery_requested_agents.add(agent_id)
        return checkpoint

    @staticmethod
    def _row_to_checkpoint(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "agent_id": row["agent_id"],
            "tick_id": row["tick_id"],
            "conversation_state": json.loads(row["conversation_state"]),
            "tool_state": json.loads(row["tool_state"]),
            "created_at": row["created_at"],
        }

    # ── Summary memory ────────────────────────────────────────────

    @_db_locked
    def update_summary_memory(self, agent_id: str, summary: str) -> None:
        truncated = summary[:_SUMMARY_MAX]
        self._conn.execute(
            "UPDATE managed_agents SET summary_memory = ?, updated_at = ? WHERE id = ?",
            (truncated, time.time(), agent_id),
        )
        self._conn.commit()

    # ── Task CRUD ─────────────────────────────────────────────────

    @_db_locked
    def create_task(
        self,
        agent_id: str,
        description: str,
        status: str = "pending",
        *,
        required_tools: list[str] | None = None,
    ) -> Dict[str, Any]:
        required_tools = required_tools or []
        if not isinstance(required_tools, list) or any(
            not isinstance(name, str) or not name.strip() for name in required_tools
        ):
            raise ValueError("required tool names must be non-empty strings")
        required_tools = list(dict.fromkeys(name.strip() for name in required_tools))
        task_id = uuid.uuid4().hex[:12]
        now = time.time()
        self._conn.execute(
            "INSERT INTO agent_tasks "
            "(id, agent_id, description, status, required_tools_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (task_id, agent_id, description, status, json.dumps(required_tools), now),
        )
        self._conn.commit()
        return self._get_task(task_id)  # type: ignore[return-value]

    @_db_locked
    def start_task(
        self,
        task_id: str,
        agent_id: str,
        principal_id: str,
        host_session_id: str | None,
        *,
        expected_state_version: int = 0,
        worker_token: str | None = None,
    ) -> Dict[str, Any]:
        """Claim a pending task once and persist the Controller execution identity."""
        if (
            not all(
                isinstance(value, str) and value
                for value in (task_id, agent_id, principal_id)
            )
            or (host_session_id is not None and not isinstance(host_session_id, str))
            or type(expected_state_version) is not int
            or expected_state_version < 0
            or (
                worker_token is not None
                and (not isinstance(worker_token, str) or len(worker_token) < 32)
            )
        ):
            raise PermissionError("task execution identity is invalid")
        attempt = uuid.uuid4().hex
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = self._conn.execute(
                "UPDATE agent_tasks SET status = 'running', principal_id = ?, "
                "host_session_id = ?, execution_attempt = ?, state_version = "
                "state_version + 1, checkpoint_id = NULL, checkpoint_version = 0, "
                "completion_evidence_json = '{}', cancellation_state = 'ACTIVE', "
                "revocation_state = 'ACTIVE' WHERE id = ? AND agent_id = ? "
                "AND status = 'pending' AND state_version = ?",
                (
                    principal_id,
                    host_session_id,
                    attempt,
                    task_id,
                    agent_id,
                    expected_state_version,
                ),
            )
            if cursor.rowcount != 1:
                raise PermissionError("task state or execution attempt is stale")
            if worker_token is not None:
                self._conn.execute(
                    "INSERT INTO agent_task_authority "
                    "VALUES (?, ?, ?, ?, ?, 1, ?, 'ACTIVE')",
                    (
                        task_id,
                        agent_id,
                        principal_id,
                        attempt,
                        hashlib.sha256(worker_token.encode()).hexdigest(),
                        time.time() + 3600,
                    ),
                )
            self._conn.commit()
            return self._get_task(task_id, agent_id=agent_id)  # type: ignore[return-value]
        except Exception:
            self._conn.rollback()
            raise

    @_db_locked
    def validate_task_authority(
        self,
        task_id: str,
        agent_id: str,
        principal: Any,
        authority: Any,
        attempt: str,
        worker_token: str,
        epoch: int,
    ) -> None:
        """Validate a Controller-issued owner without transferring its authority."""
        if (
            not callable(getattr(authority, "accepts", None))
            or not authority.accepts(principal)
            or not isinstance(worker_token, str)
            or type(epoch) is not int
        ):
            raise PermissionError("task worker authority invalid")
        row = self._conn.execute(
            "SELECT a.owner_hash FROM agent_task_authority a "
            "JOIN agent_tasks t ON t.id = a.task_id AND t.agent_id = a.agent_id "
            "WHERE a.task_id = ? AND a.agent_id = ? AND a.principal_id = ? "
            "AND a.attempt = ? AND a.epoch = ? AND a.state = 'ACTIVE' "
            "AND a.expires_at > ? AND t.status = 'running' "
            "AND t.principal_id = a.principal_id AND t.execution_attempt = a.attempt "
            "AND t.cancellation_state = 'ACTIVE' AND t.revocation_state = 'ACTIVE' "
            "AND NOT EXISTS (SELECT 1 FROM agent_cancellation_requests "
            "WHERE scope = a.agent_id)",
            (task_id, agent_id, principal.principal_id, attempt, epoch, time.time()),
        ).fetchone()
        if (
            row is None
            or not hmac.compare_digest(
                row["owner_hash"], hashlib.sha256(worker_token.encode()).hexdigest()
            )
            or not authority.accepts(principal)
        ):
            raise PermissionError("task worker authority invalid or expired")

    @_db_locked
    def task_authority_binding(
        self,
        task_id: str,
        agent_id: str,
        principal: Any,
        authority: Any,
        attempt: str,
        worker_token: str,
        epoch: int,
    ) -> Dict[str, Any]:
        """Return only the live owner hash and lease for a host-owned worker."""
        self.validate_task_authority(
            task_id, agent_id, principal, authority, attempt, worker_token, epoch
        )
        row = self._conn.execute(
            "SELECT owner_hash, epoch, expires_at FROM agent_task_authority "
            "WHERE task_id = ? AND agent_id = ? AND principal_id = ? "
            "AND attempt = ? AND epoch = ? AND state = 'ACTIVE' AND expires_at > ?",
            (task_id, agent_id, principal.principal_id, attempt, epoch, time.time()),
        ).fetchone()
        if row is None:
            raise PermissionError("task worker authority invalid or expired")
        return {
            "owner_hash": row["owner_hash"],
            "epoch": row["epoch"],
            "lease_expires_at": row["expires_at"],
        }

    _TASK_TOOL_JOURNAL_FIELDS = (
        "request_id",
        "tool_call_id",
        "task_id",
        "agent_id",
        "principal_id",
        "attempt",
        "owner_hash",
        "epoch",
        "worker_id",
        "tool_name",
        "arguments_sha256",
        "checkpoint_version",
        "deadline",
        "state",
        "result_sha256",
        "result_success",
        "checkpointed_version",
        "created_at",
        "updated_at",
    )

    @classmethod
    def _task_tool_journal_mac(cls, key: bytes, row: dict) -> str:
        payload = json.dumps(
            [row[name] for name in cls._TASK_TOOL_JOURNAL_FIELDS],
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return hmac.new(
            key, b"atlas-task-tool-journal-v1\0" + payload, hashlib.sha256
        ).hexdigest()

    @staticmethod
    def _task_tool_head_mac(key: bytes, head: dict) -> str:
        payload = json.dumps(
            [
                head[name]
                for name in (
                    "task_id",
                    "agent_id",
                    "principal_id",
                    "attempt",
                    "owner_hash",
                    "epoch",
                    "entry_count",
                    "rows_sha256",
                )
            ],
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return hmac.new(
            key, b"atlas-task-tool-head-v1\0" + payload, hashlib.sha256
        ).hexdigest()

    def _task_tool_rows_digest(self, task_id: str, key: bytes) -> tuple[int, str]:
        # shortcut: scans all rows; use a signed chain for large tasks.
        rows = self._conn.execute(
            "SELECT * FROM task_tool_journal WHERE task_id=? ORDER BY request_id",
            (task_id,),
        ).fetchall()
        entries = []
        journal = {}
        for stored in rows:
            row = dict(stored)
            mac = row.pop("mac")
            if not isinstance(mac, str) or not hmac.compare_digest(
                mac, self._task_tool_journal_mac(key, row)
            ):
                raise PermissionError("task tool journal integrity invalid")
            entries.append((row["request_id"], mac))
            journal[row["request_id"]] = row
        claims = self._conn.execute(
            "SELECT * FROM task_tool_dispatch_claims "
            "WHERE task_id=? ORDER BY request_id",
            (task_id,),
        ).fetchall()
        for stored in claims:
            claim = dict(stored)
            mac = claim.pop("mac")
            row = journal.get(claim["request_id"])
            if (
                row is None
                or row["worker_id"] != claim["worker_id"]
                or row["epoch"] != claim["epoch"]
                or not isinstance(mac, str)
                or not hmac.compare_digest(mac, self._task_tool_claim_mac(key, claim))
            ):
                raise PermissionError("task tool dispatch claim integrity invalid")
            entries.append(("claim:" + claim["request_id"], mac))
        payload = json.dumps(entries, separators=(",", ":"), ensure_ascii=True)
        return len(entries), hashlib.sha256(payload.encode("ascii")).hexdigest()

    @staticmethod
    def _task_tool_claim_mac(key: bytes, claim: dict) -> str:
        payload = json.dumps(
            [
                claim[name]
                for name in (
                    "request_id",
                    "task_id",
                    "worker_id",
                    "epoch",
                    "claimed_at",
                )
            ],
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return hmac.new(
            key, b"atlas-task-dispatch-claim-v1\0" + payload, hashlib.sha256
        ).hexdigest()

    def _verify_task_tool_head(
        self,
        task_id: str,
        agent_id: str,
        principal_id: str,
        attempt: str,
        owner_hash: str,
        epoch: int,
        key: bytes,
    ) -> dict:
        found = self._conn.execute(
            "SELECT * FROM task_tool_journal_heads WHERE task_id=?", (task_id,)
        ).fetchone()
        if found is None:
            raise PermissionError("task tool journal head unavailable")
        head = dict(found)
        mac = head.pop("mac")
        count, digest = self._task_tool_rows_digest(task_id, key)
        if (
            head["agent_id"] != agent_id
            or head["principal_id"] != principal_id
            or head["attempt"] != attempt
            or head["owner_hash"] != owner_hash
            or head["epoch"] != epoch
            or head["entry_count"] != count
            or head["rows_sha256"] != digest
            or not isinstance(mac, str)
            or not hmac.compare_digest(mac, self._task_tool_head_mac(key, head))
        ):
            raise PermissionError("task tool journal head integrity invalid")
        return {**head, "mac": mac}

    def _refresh_task_tool_head(self, head: dict, key: bytes) -> None:
        old_mac = head.pop("mac")
        head["entry_count"], head["rows_sha256"] = self._task_tool_rows_digest(
            head["task_id"], key
        )
        mac = self._task_tool_head_mac(key, head)
        changed = self._conn.execute(
            "UPDATE task_tool_journal_heads SET entry_count=?, rows_sha256=?, mac=? "
            "WHERE task_id=? AND mac=?",
            (head["entry_count"], head["rows_sha256"], mac, head["task_id"], old_mac),
        )
        if changed.rowcount != 1:
            raise PermissionError("task tool journal head is stale")

    @_db_locked
    def validate_host_task_binding(
        self, principal: Any, authority: Any, binding: dict
    ) -> None:
        """Check a host-authorized session against current task authority."""
        if (
            not isinstance(binding, dict)
            or not callable(getattr(authority, "accepts", None))
            or not authority.accepts(principal)
            or binding.get("principal_id") != getattr(principal, "principal_id", None)
        ):
            raise PermissionError("host task authority invalid")
        row = self._conn.execute(
            "SELECT a.owner_hash FROM agent_task_authority a "
            "JOIN agent_tasks t ON t.id=a.task_id AND t.agent_id=a.agent_id "
            "WHERE a.task_id=? AND a.agent_id=? AND a.principal_id=? "
            "AND a.attempt=? AND a.epoch=? AND a.state='ACTIVE' "
            "AND a.expires_at>? AND t.status='running' "
            "AND t.principal_id=a.principal_id AND t.execution_attempt=a.attempt "
            "AND t.cancellation_state='ACTIVE' AND t.revocation_state='ACTIVE' "
            "AND NOT EXISTS (SELECT 1 FROM agent_cancellation_requests "
            "WHERE scope=a.agent_id)",
            (
                binding["task_id"],
                binding["agent_id"],
                binding["principal_id"],
                binding["attempt"],
                binding["epoch"],
                time.time(),
            ),
        ).fetchone()
        if (
            row is None
            or not hmac.compare_digest(row["owner_hash"], binding["owner_hash"])
            or not authority.accepts(principal)
        ):
            raise PermissionError("host task authority invalid")

    @_db_locked
    def claim_task_tool_dispatch(
        self,
        principal: Any,
        authority: Any,
        binding: dict,
        body: dict,
        *,
        integrity_key: bytes,
    ) -> None:
        """Durably claim an authenticated dispatch once before a host executes it."""
        from openjarvis.agents.tool_semantics import arguments_sha256

        if (
            not callable(getattr(authority, "accepts", None))
            or not authority.accepts(principal)
            or not isinstance(integrity_key, bytes)
            or len(integrity_key) < 32
            or not isinstance(binding, dict)
            or not isinstance(body, dict)
            or binding.get("principal_id") != getattr(principal, "principal_id", None)
            or body.get("kind") != "EXECUTE_TOOL"
            or body.get("binding") != binding
            or type(binding.get("epoch")) is not int
        ):
            raise PermissionError("task dispatch authorization invalid")
        data = body.get("payload")
        if (
            not isinstance(data, dict)
            or data.get("name") != "synthetic_echo"
            or not isinstance(data.get("params"), dict)
            or set(data["params"]) != {"value"}
            or not isinstance(data["params"]["value"], str)
        ):
            raise PermissionError("task dispatch tool invalid")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            now = time.time()
            self.validate_host_task_binding(principal, authority, binding)
            head = self._verify_task_tool_head(
                binding["task_id"],
                binding["agent_id"],
                binding["principal_id"],
                binding["attempt"],
                binding["owner_hash"],
                binding["epoch"],
                integrity_key,
            )
            row = self._conn.execute(
                "SELECT * FROM task_tool_journal WHERE request_id=?",
                (body["request_id"],),
            ).fetchone()
            task = self._get_task(binding["task_id"], agent_id=binding["agent_id"])
            checkpoint = self.get_bound_task_checkpoint(
                binding["task_id"],
                binding["agent_id"],
                principal,
                authority,
                integrity_key=integrity_key,
            )
            if (
                row is None
                or task is None
                or row["task_id"] != binding["task_id"]
                or row["agent_id"] != binding["agent_id"]
                or row["principal_id"] != binding["principal_id"]
                or row["attempt"] != binding["attempt"]
                or row["epoch"] != binding["epoch"]
                or row["owner_hash"] != binding["owner_hash"]
                or row["worker_id"] != binding["worker_id"]
                or row["tool_call_id"] != body["tool_call_id"]
                or row["tool_name"] != data["name"]
                or row["state"] != "DISPATCHED"
                or row["arguments_sha256"] != arguments_sha256(data["params"])
                or row["checkpoint_version"] != data.get("checkpoint_version")
                or task["checkpoint_version"] != row["checkpoint_version"]
                or checkpoint.get("task_binding_version") != row["checkpoint_version"]
                or checkpoint.get("id") != task["checkpoint_id"]
                or type(body.get("deadline")) not in (int, float)
                or not math.isfinite(body["deadline"])
                or body["deadline"] <= now
                or body["deadline"] > row["deadline"]
            ):
                raise PermissionError("task dispatch journal mismatch")
            claim = {
                "request_id": row["request_id"],
                "task_id": row["task_id"],
                "worker_id": row["worker_id"],
                "epoch": row["epoch"],
                "claimed_at": now,
            }
            self._conn.execute(
                "INSERT INTO task_tool_dispatch_claims "
                "(request_id,task_id,worker_id,epoch,claimed_at,mac) "
                "VALUES (?,?,?,?,?,?)",
                (*claim.values(), self._task_tool_claim_mac(integrity_key, claim)),
            )
            self._refresh_task_tool_head(head, integrity_key)
            if not authority.accepts(principal):
                raise PermissionError("task dispatch principal revoked")
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            self._conn.rollback()
            raise PermissionError("task dispatch already claimed") from exc
        except Exception:
            self._conn.rollback()
            raise

    @staticmethod
    def _host_worker_exit_mac(key: bytes, payload: str) -> str:
        return hmac.new(
            key,
            b"atlas-host-worker-exit-v1\0" + payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _task_epoch_fence_mac(key: bytes, payload: str) -> str:
        return hmac.new(
            key,
            b"atlas-task-epoch-fence-v1\0" + payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    @_db_locked
    def record_host_worker_exit(
        self,
        principal: Any,
        authority: Any,
        binding: dict,
        record: dict,
        verification_key: bytes,
        *,
        integrity_key: bytes,
        verify_os_exit: Callable[[dict], bool],
    ) -> None:
        """Persist an OS-verified, supervisor-authenticated stop observation."""
        from openjarvis.control.host_task_supervisor import verify_signed_exit_record

        if (
            not isinstance(integrity_key, bytes)
            or len(integrity_key) < 32
            or not callable(verify_os_exit)
            or not verify_signed_exit_record(record, verification_key, binding)
        ):
            raise PermissionError("host worker exit evidence invalid")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self.validate_host_task_binding(principal, authority, binding)
            self._verify_task_tool_head(
                binding["task_id"],
                binding["agent_id"],
                binding["principal_id"],
                binding["attempt"],
                binding["owner_hash"],
                binding["epoch"],
                integrity_key,
            )
            checkpoint = self.get_bound_task_checkpoint(
                binding["task_id"],
                binding["agent_id"],
                principal,
                authority,
                integrity_key=integrity_key,
            )
            if verify_os_exit(
                record["record"]["evidence"]
            ) is not True or not authority.accepts(principal):
                raise PermissionError("host worker exit not verified")
            payload = json.dumps(
                {
                    "version": 1,
                    "binding": binding,
                    "exit_record": record,
                    "checkpoint_id": checkpoint["id"],
                    "checkpoint_version": checkpoint["task_binding_version"],
                    "recorded_at": time.time(),
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            self._conn.execute(
                "INSERT INTO task_worker_exit_evidence(task_id,worker_id,payload,mac) "
                "VALUES (?,?,?,?)",
                (
                    binding["task_id"],
                    binding["worker_id"],
                    payload,
                    self._host_worker_exit_mac(integrity_key, payload),
                ),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            self._conn.rollback()
            raise PermissionError("host worker exit already recorded") from exc
        except Exception:
            self._conn.rollback()
            raise

    @_db_locked
    def read_host_worker_exit(
        self,
        principal: Any,
        authority: Any,
        binding: dict,
        verification_key: bytes,
        *,
        integrity_key: bytes,
    ) -> dict:
        """Read a durable exit record only with live authority and valid signatures."""
        from openjarvis.control.host_task_supervisor import verify_signed_exit_record

        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise PermissionError("host worker exit integrity key invalid")
        self._conn.execute("BEGIN")
        try:
            self.validate_host_task_binding(principal, authority, binding)
            self._verify_task_tool_head(
                binding["task_id"],
                binding["agent_id"],
                binding["principal_id"],
                binding["attempt"],
                binding["owner_hash"],
                binding["epoch"],
                integrity_key,
            )
            checkpoint = self.get_bound_task_checkpoint(
                binding["task_id"],
                binding["agent_id"],
                principal,
                authority,
                integrity_key=integrity_key,
            )
            row = self._conn.execute(
                "SELECT payload,mac FROM task_worker_exit_evidence "
                "WHERE task_id=? AND worker_id=?",
                (binding["task_id"], binding["worker_id"]),
            ).fetchone()
            if row is None or not hmac.compare_digest(
                row["mac"],
                self._host_worker_exit_mac(integrity_key, row["payload"]),
            ):
                raise PermissionError("host worker exit evidence unavailable")
            payload = json.loads(row["payload"])
            if (
                payload.get("version") != 1
                or payload.get("binding") != binding
                or payload.get("checkpoint_id") != checkpoint["id"]
                or payload.get("checkpoint_version")
                != checkpoint["task_binding_version"]
                or not verify_signed_exit_record(
                    payload.get("exit_record", {}), verification_key, binding
                )
                or not authority.accepts(principal)
            ):
                raise PermissionError("host worker exit evidence mismatch")
            self._conn.commit()
            return payload["exit_record"]
        except Exception:
            self._conn.rollback()
            raise

    @_db_locked
    def fence_task_authority_after_worker_exit(
        self,
        principal: Any,
        authority: Any,
        binding: dict,
        exit_record: dict,
        verification_key: bytes,
        *,
        integrity_key: bytes,
    ) -> int:
        """Fence a stopped owner without rewriting its authenticated journal."""
        from openjarvis.control.host_task_supervisor import verify_signed_exit_record

        if (
            not isinstance(binding, dict)
            or type(binding.get("epoch")) is not int
            or binding["epoch"] < 1
            or binding["epoch"] >= 0x7FFFFFFFFFFFFFFF
            or not isinstance(exit_record, dict)
            or not isinstance(verification_key, bytes)
            or len(verification_key) < 32
            or not isinstance(integrity_key, bytes)
            or len(integrity_key) < 32
            or not callable(getattr(authority, "accepts", None))
            or not authority.accepts(principal)
            or binding.get("principal_id") != getattr(principal, "principal_id", None)
            or not verify_signed_exit_record(exit_record, verification_key, binding)
        ):
            raise PermissionError("task epoch fence evidence invalid")

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self.validate_host_task_binding(principal, authority, binding)
            task = self._get_task(binding["task_id"], agent_id=binding["agent_id"])
            if (
                task is None
                or task["status"] != "running"
                or task["principal_id"] != binding["principal_id"]
                or task["execution_attempt"] != binding["attempt"]
            ):
                raise PermissionError("task epoch fence identity is stale")
            head = self._verify_task_tool_head(
                binding["task_id"],
                binding["agent_id"],
                binding["principal_id"],
                binding["attempt"],
                binding["owner_hash"],
                binding["epoch"],
                integrity_key,
            )
            checkpoint = self.get_bound_task_checkpoint(
                binding["task_id"],
                binding["agent_id"],
                principal,
                authority,
                integrity_key=integrity_key,
            )
            if (
                checkpoint.get("id") != task["checkpoint_id"]
                or checkpoint.get("task_binding_version") != task["checkpoint_version"]
                or self._conn.execute(
                    "SELECT 1 FROM task_tool_journal WHERE task_id=? "
                    "AND (owner_hash!=? OR epoch!=? OR state!='CHECKPOINTED') LIMIT 1",
                    (binding["task_id"], binding["owner_hash"], binding["epoch"]),
                ).fetchone()
                is not None
            ):
                raise PermissionError(
                    "task epoch fence journal or checkpoint unresolved"
                )

            evidence_row = self._conn.execute(
                "SELECT payload,mac FROM task_worker_exit_evidence "
                "WHERE task_id=? AND worker_id=?",
                (binding["task_id"], binding["worker_id"]),
            ).fetchone()
            if evidence_row is None or not hmac.compare_digest(
                evidence_row["mac"],
                self._host_worker_exit_mac(integrity_key, evidence_row["payload"]),
            ):
                raise PermissionError("task epoch fence exit evidence unavailable")
            durable = json.loads(evidence_row["payload"])
            evidence = exit_record["record"]["evidence"]
            if (
                durable.get("version") != 1
                or durable.get("binding") != binding
                or durable.get("exit_record") != exit_record
                or durable.get("checkpoint_id") != checkpoint["id"]
                or durable.get("checkpoint_version")
                != checkpoint["task_binding_version"]
                or evidence.get("job_exit_confirmed") is not True
                or evidence.get("process_wait_confirmed") is not True
            ):
                raise PermissionError("task epoch fence exit evidence mismatch")

            owner = self._conn.execute(
                "SELECT 1 FROM agent_task_authority "
                "WHERE task_id=? AND agent_id=? AND principal_id=? AND attempt=? "
                "AND owner_hash=? AND epoch=? AND state='ACTIVE' AND expires_at>?",
                (
                    binding["task_id"],
                    binding["agent_id"],
                    binding["principal_id"],
                    binding["attempt"],
                    binding["owner_hash"],
                    binding["epoch"],
                    time.time(),
                ),
            ).fetchone()
            if owner is None:
                raise PermissionError("task epoch fence owner changed")

            next_epoch = binding["epoch"] + 1
            next_owner_hash = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
            fence = {
                "version": 1,
                "task_id": binding["task_id"],
                "agent_id": binding["agent_id"],
                "principal_id": binding["principal_id"],
                "attempt": binding["attempt"],
                "previous_binding": binding,
                "previous_epoch": binding["epoch"],
                "epoch": next_epoch,
                "previous_owner_hash": binding["owner_hash"],
                "owner_hash": next_owner_hash,
                "journal_head_mac": head["mac"],
                "exit_evidence_mac": evidence_row["mac"],
                "exit_record_sha256": hashlib.sha256(
                    json.dumps(
                        exit_record,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                        allow_nan=False,
                    ).encode("ascii")
                ).hexdigest(),
                "checkpoint_id": checkpoint["id"],
                "checkpoint_version": checkpoint["task_binding_version"],
                "recorded_at": time.time(),
            }
            payload = json.dumps(
                fence,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            self._conn.execute(
                "INSERT INTO agent_task_epoch_fences(task_id,epoch,payload,mac) "
                "VALUES (?,?,?,?)",
                (
                    binding["task_id"],
                    next_epoch,
                    payload,
                    self._task_epoch_fence_mac(integrity_key, payload),
                ),
            )
            changed = self._conn.execute(
                "UPDATE agent_task_authority SET owner_hash=?,epoch=?,expires_at=?,"
                "state='FENCED' WHERE task_id=? AND agent_id=? AND principal_id=? "
                "AND attempt=? AND owner_hash=? AND epoch=? AND state='ACTIVE' "
                "AND expires_at>?",
                (
                    next_owner_hash,
                    next_epoch,
                    time.time(),
                    binding["task_id"],
                    binding["agent_id"],
                    binding["principal_id"],
                    binding["attempt"],
                    binding["owner_hash"],
                    binding["epoch"],
                    time.time(),
                ),
            )
            if changed.rowcount != 1:
                raise PermissionError("task epoch fence lost authority race")
            next_owner = self._conn.execute(
                "SELECT * FROM agent_task_authority WHERE task_id=?",
                (binding["task_id"],),
            ).fetchone()
            self._verify_task_journal_authority(
                task, next_owner, principal, authority, integrity_key
            )
            try:
                self.validate_host_task_binding(principal, authority, binding)
            except PermissionError:
                pass
            else:
                raise PermissionError("task epoch fence did not revoke old owner")
            self._conn.commit()
            return next_epoch
        except Exception:
            self._conn.rollback()
            raise

    @_db_locked
    def initialize_task_tool_journal(
        self,
        task_id: str,
        agent_id: str,
        principal: Any,
        authority: Any,
        attempt: str,
        worker_token: str,
        epoch: int,
        *,
        integrity_key: bytes,
    ) -> None:
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise PermissionError("task tool journal integrity key invalid")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            binding = self.task_authority_binding(
                task_id, agent_id, principal, authority, attempt, worker_token, epoch
            )
            count, digest = self._task_tool_rows_digest(task_id, integrity_key)
            if count:
                raise PermissionError("task tool journal already exists")
            head = {
                "task_id": task_id,
                "agent_id": agent_id,
                "principal_id": principal.principal_id,
                "attempt": attempt,
                "owner_hash": binding["owner_hash"],
                "epoch": epoch,
                "entry_count": count,
                "rows_sha256": digest,
            }
            self._conn.execute(
                "INSERT INTO task_tool_journal_heads "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (*head.values(), self._task_tool_head_mac(integrity_key, head)),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            self._conn.rollback()
            raise PermissionError("task tool journal head already exists") from exc
        except Exception:
            self._conn.rollback()
            raise

    @_db_locked
    def prepare_task_tool_journal(
        self,
        task_id: str,
        agent_id: str,
        principal: Any,
        authority: Any,
        attempt: str,
        worker_token: str,
        epoch: int,
        *,
        worker_id: str,
        request_id: str,
        tool_call_id: str,
        tool_name: str,
        arguments_sha256: str,
        deadline: float,
        integrity_key: bytes,
    ) -> int:
        """Reserve a task call before any authenticated worker dispatch."""
        if (
            not isinstance(integrity_key, bytes)
            or len(integrity_key) < 32
            or not all(
                isinstance(value, str) and 0 < len(value) <= 256 and value.isprintable()
                for value in (worker_id, request_id, tool_call_id, tool_name)
            )
            or not isinstance(arguments_sha256, str)
            or len(arguments_sha256) != 64
            or any(c not in "0123456789abcdef" for c in arguments_sha256)
            or type(deadline) not in (int, float)
            or not math.isfinite(deadline)
            or deadline <= time.time()
        ):
            raise PermissionError("task tool journal identity invalid")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            binding = self.task_authority_binding(
                task_id, agent_id, principal, authority, attempt, worker_token, epoch
            )
            head = self._verify_task_tool_head(
                task_id,
                agent_id,
                principal.principal_id,
                attempt,
                binding["owner_hash"],
                epoch,
                integrity_key,
            )
            if (
                self._conn.execute(
                    "SELECT 1 FROM task_tool_journal "
                    "WHERE request_id=? OR tool_call_id=?",
                    (request_id, tool_call_id),
                ).fetchone()
                is not None
            ):
                raise PermissionError("task tool request or call already exists")
            if (
                self._conn.execute(
                    "SELECT 1 FROM task_tool_journal WHERE task_id=? "
                    "AND state != 'CHECKPOINTED' LIMIT 1",
                    (task_id,),
                ).fetchone()
                is not None
            ):
                raise PermissionError("task tool journal requires reconciliation")
            task = self._get_task(task_id, agent_id=agent_id)
            if task is None or deadline > binding["lease_expires_at"]:
                raise PermissionError("task tool journal lease invalid")
            checkpoint = self.get_bound_task_checkpoint(
                task_id, agent_id, principal, authority, integrity_key=integrity_key
            )
            version = task["checkpoint_version"]
            if (
                version < 1
                or checkpoint.get("task_binding_version") != version
                or checkpoint.get("id") != task["checkpoint_id"]
            ):
                raise PermissionError("task tool journal checkpoint invalid")
            now = time.time()
            row = {
                "request_id": request_id,
                "tool_call_id": tool_call_id,
                "task_id": task_id,
                "agent_id": agent_id,
                "principal_id": principal.principal_id,
                "attempt": attempt,
                "owner_hash": binding["owner_hash"],
                "epoch": epoch,
                "worker_id": worker_id,
                "tool_name": tool_name,
                "arguments_sha256": arguments_sha256,
                "checkpoint_version": version,
                "deadline": float(deadline),
                "state": "PREPARED",
                "result_sha256": None,
                "result_success": None,
                "checkpointed_version": None,
                "created_at": now,
                "updated_at": now,
            }
            mac = self._task_tool_journal_mac(integrity_key, row)
            columns = self._TASK_TOOL_JOURNAL_FIELDS
            self._conn.execute(
                "INSERT INTO task_tool_journal (" + ",".join(columns) + ",mac) "
                "VALUES (" + ",".join("?" for _ in range(len(columns) + 1)) + ")",
                (*[row[name] for name in columns], mac),
            )
            self._refresh_task_tool_head(head, integrity_key)
            self._conn.commit()
            return version
        except sqlite3.IntegrityError as exc:
            self._conn.rollback()
            raise PermissionError("task tool request or call already exists") from exc
        except Exception:
            self._conn.rollback()
            raise

    @_db_locked
    def checkpoint_task_tool_journal(
        self,
        task_id: str,
        agent_id: str,
        principal: Any,
        authority: Any,
        attempt: str,
        worker_token: str,
        epoch: int,
        *,
        worker_id: str,
        request_id: str,
        integrity_key: bytes,
    ) -> None:
        """Bind a recorded result to an already signed task checkpoint."""
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise PermissionError("task tool journal integrity key invalid")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            binding = self.task_authority_binding(
                task_id, agent_id, principal, authority, attempt, worker_token, epoch
            )
            head = self._verify_task_tool_head(
                task_id,
                agent_id,
                principal.principal_id,
                attempt,
                binding["owner_hash"],
                epoch,
                integrity_key,
            )
            found = self._conn.execute(
                "SELECT * FROM task_tool_journal WHERE request_id=?", (request_id,)
            ).fetchone()
            if found is None:
                raise PermissionError("task tool journal record unavailable")
            row = dict(found)
            old_mac = row.pop("mac")
            task = self._get_task(task_id, agent_id=agent_id)
            checkpoint = self.get_bound_task_checkpoint(
                task_id, agent_id, principal, authority, integrity_key=integrity_key
            )
            messages = checkpoint.get("conversation_state", {}).get("messages", [])
            steps = checkpoint.get("tool_state", {}).get("completed_steps", [])
            if (
                task is None
                or row["task_id"] != task_id
                or row["agent_id"] != agent_id
                or row["principal_id"] != principal.principal_id
                or row["attempt"] != attempt
                or row["owner_hash"] != binding["owner_hash"]
                or row["epoch"] != epoch
                or row["worker_id"] != worker_id
                or row["state"] != "RESULT_RECORDED"
                or row["result_success"] != 1
                or row["checkpointed_version"] is not None
                or task["checkpoint_version"] <= row["checkpoint_version"]
                or checkpoint.get("id") != task["checkpoint_id"]
                or checkpoint.get("task_binding_version") != task["checkpoint_version"]
                or not isinstance(messages, list)
                or not isinstance(steps, list)
                or not any(
                    isinstance(message, dict)
                    and message.get("role") == "tool"
                    and message.get("name") == row["tool_name"]
                    and message.get("tool_call_id") == row["tool_call_id"]
                    and isinstance(message.get("content"), str)
                    and hashlib.sha256(message["content"].encode("utf-8")).hexdigest()
                    == row["result_sha256"]
                    for message in messages
                )
                or not any(
                    isinstance(step, dict)
                    and step.get("call_id") == row["tool_call_id"]
                    and step.get("tool") == row["tool_name"]
                    and step.get("state") == "EXECUTED"
                    and step.get("execution_state") == "EXECUTED"
                    for step in steps
                )
            ):
                raise PermissionError("task tool journal checkpoint mismatch")
            row.update(
                state="CHECKPOINTED",
                checkpointed_version=task["checkpoint_version"],
                updated_at=time.time(),
            )
            mac = self._task_tool_journal_mac(integrity_key, row)
            changed = self._conn.execute(
                "UPDATE task_tool_journal SET state=?, checkpointed_version=?, "
                "updated_at=?, mac=? WHERE request_id=? AND state=? AND mac=?",
                (
                    row["state"],
                    row["checkpointed_version"],
                    row["updated_at"],
                    mac,
                    request_id,
                    "RESULT_RECORDED",
                    old_mac,
                ),
            )
            if changed.rowcount != 1:
                raise PermissionError("task tool journal checkpoint is stale")
            self._refresh_task_tool_head(head, integrity_key)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    @_db_locked
    def transition_task_tool_journal(
        self,
        task_id: str,
        agent_id: str,
        principal: Any,
        authority: Any,
        attempt: str,
        worker_token: str,
        epoch: int,
        *,
        worker_id: str,
        request_id: str,
        expected: str,
        state: str,
        integrity_key: bytes,
        result_sha256: str | None = None,
        result_success: bool | None = None,
    ) -> None:
        allowed = {
            ("PREPARED", "DISPATCHED"),
            ("DISPATCHED", "RESULT_RECORDED"),
            ("DISPATCHED", "UNKNOWN_OUTCOME"),
        }
        if (
            (expected, state) not in allowed
            or not isinstance(integrity_key, bytes)
            or len(integrity_key) < 32
            or (
                state == "RESULT_RECORDED"
                and (
                    not isinstance(result_sha256, str)
                    or len(result_sha256) != 64
                    or any(c not in "0123456789abcdef" for c in result_sha256)
                    or type(result_success) is not bool
                )
            )
            or (
                state != "RESULT_RECORDED"
                and (result_sha256 is not None or result_success is not None)
            )
        ):
            raise PermissionError("task tool journal transition invalid")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            binding = self.task_authority_binding(
                task_id, agent_id, principal, authority, attempt, worker_token, epoch
            )
            head = self._verify_task_tool_head(
                task_id,
                agent_id,
                principal.principal_id,
                attempt,
                binding["owner_hash"],
                epoch,
                integrity_key,
            )
            found = self._conn.execute(
                "SELECT * FROM task_tool_journal WHERE request_id = ?", (request_id,)
            ).fetchone()
            if found is None:
                raise PermissionError("task tool journal record unavailable")
            row = dict(found)
            previous_mac = row.pop("mac")
            if (
                row["task_id"] != task_id
                or row["agent_id"] != agent_id
                or row["principal_id"] != principal.principal_id
                or row["attempt"] != attempt
                or row["epoch"] != epoch
                or row["owner_hash"] != binding["owner_hash"]
                or row["worker_id"] != worker_id
                or row["state"] != expected
                or (state == "DISPATCHED" and row["deadline"] <= time.time())
                or not hmac.compare_digest(
                    previous_mac, self._task_tool_journal_mac(integrity_key, row)
                )
            ):
                raise PermissionError("task tool journal integrity or owner mismatch")
            if state == "DISPATCHED":
                task = self._get_task(task_id, agent_id=agent_id)
                checkpoint = self.get_bound_task_checkpoint(
                    task_id, agent_id, principal, authority, integrity_key=integrity_key
                )
                if (
                    task is None
                    or task["checkpoint_version"] != row["checkpoint_version"]
                    or checkpoint.get("task_binding_version")
                    != row["checkpoint_version"]
                    or checkpoint.get("id") != task["checkpoint_id"]
                ):
                    raise PermissionError("task tool journal checkpoint is stale")
            row.update(
                state=state,
                updated_at=time.time(),
                result_sha256=result_sha256,
                result_success=int(result_success)
                if result_success is not None
                else None,
            )
            mac = self._task_tool_journal_mac(integrity_key, row)
            changed = self._conn.execute(
                "UPDATE task_tool_journal SET state=?, updated_at=?, result_sha256=?, "
                "result_success=?, mac=? WHERE request_id=? AND state=? AND mac=?",
                (
                    state,
                    row["updated_at"],
                    result_sha256,
                    row["result_success"],
                    mac,
                    request_id,
                    expected,
                    previous_mac,
                ),
            )
            if changed.rowcount != 1:
                raise PermissionError("task tool journal transition is stale")
            self._refresh_task_tool_head(head, integrity_key)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def _verify_task_journal_authority(
        self,
        task: Any,
        owner: Any,
        principal: Any,
        authority: Any,
        integrity_key: bytes,
    ) -> dict:
        head_row = self._conn.execute(
            "SELECT * FROM task_tool_journal_heads WHERE task_id=?", (task["id"],)
        ).fetchone()
        if head_row is None:
            raise PermissionError("task tool journal head unavailable")
        head = dict(head_row)
        if owner["epoch"] == head["epoch"] and hmac.compare_digest(
            owner["owner_hash"], head["owner_hash"]
        ):
            return self._verify_task_tool_head(
                task["id"],
                task["agent_id"],
                principal.principal_id,
                owner["attempt"],
                owner["owner_hash"],
                owner["epoch"],
                integrity_key,
            )

        fence_row = self._conn.execute(
            "SELECT payload,mac FROM agent_task_epoch_fences "
            "WHERE task_id=? AND epoch=?",
            (task["id"], owner["epoch"]),
        ).fetchone()
        if (
            fence_row is None
            or owner["state"] != "FENCED"
            or owner["epoch"] != head["epoch"] + 1
            or not hmac.compare_digest(
                fence_row["mac"],
                self._task_epoch_fence_mac(integrity_key, fence_row["payload"]),
            )
        ):
            raise PermissionError("task tool journal epoch fence invalid")
        try:
            fence = json.loads(fence_row["payload"])
            binding = fence["previous_binding"]
            verified_head = self._verify_task_tool_head(
                task["id"],
                task["agent_id"],
                principal.principal_id,
                owner["attempt"],
                head["owner_hash"],
                head["epoch"],
                integrity_key,
            )
            evidence_row = self._conn.execute(
                "SELECT payload,mac FROM task_worker_exit_evidence "
                "WHERE task_id=? AND worker_id=?",
                (task["id"], binding["worker_id"]),
            ).fetchone()
            checkpoint = self.get_bound_task_checkpoint(
                task["id"],
                task["agent_id"],
                principal,
                authority,
                integrity_key=integrity_key,
            )
            if evidence_row is None:
                raise PermissionError("task tool journal fence evidence unavailable")
            durable = json.loads(evidence_row["payload"])
            exit_record = durable["exit_record"]
            exit_digest = hashlib.sha256(
                json.dumps(
                    exit_record,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ).encode("ascii")
            ).hexdigest()
            journal_rows = self._conn.execute(
                "SELECT owner_hash,epoch,state FROM task_tool_journal WHERE task_id=?",
                (task["id"],),
            ).fetchall()
            if (
                fence.get("version") != 1
                or fence.get("task_id") != task["id"]
                or fence.get("agent_id") != task["agent_id"]
                or fence.get("principal_id") != principal.principal_id
                or fence.get("attempt") != owner["attempt"]
                or fence.get("previous_epoch") != head["epoch"]
                or fence.get("epoch") != owner["epoch"]
                or fence.get("previous_owner_hash") != head["owner_hash"]
                or fence.get("owner_hash") != owner["owner_hash"]
                or fence.get("journal_head_mac") != verified_head["mac"]
                or binding.get("task_id") != task["id"]
                or binding.get("agent_id") != task["agent_id"]
                or binding.get("principal_id") != principal.principal_id
                or binding.get("attempt") != owner["attempt"]
                or binding.get("epoch") != head["epoch"]
                or binding.get("owner_hash") != head["owner_hash"]
                or durable.get("binding") != binding
                or evidence_row["mac"] != fence.get("exit_evidence_mac")
                or not hmac.compare_digest(
                    evidence_row["mac"],
                    self._host_worker_exit_mac(integrity_key, evidence_row["payload"]),
                )
                or exit_digest != fence.get("exit_record_sha256")
                or fence.get("checkpoint_id") != checkpoint["id"]
                or fence.get("checkpoint_version") != checkpoint["task_binding_version"]
                or checkpoint["id"] != task["checkpoint_id"]
                or checkpoint["task_binding_version"] != task["checkpoint_version"]
                or any(
                    row["owner_hash"] != head["owner_hash"]
                    or row["epoch"] != head["epoch"]
                    or row["state"] != "CHECKPOINTED"
                    for row in journal_rows
                )
            ):
                raise PermissionError("task tool journal epoch fence binding invalid")
            return verified_head
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise PermissionError(
                "task tool journal epoch fence payload invalid"
            ) from exc

    @_db_locked
    def read_task_tool_journal(
        self,
        task_id: str,
        agent_id: str,
        principal: Any,
        authority: Any,
        *,
        integrity_key: bytes,
    ) -> list[dict]:
        """Verify persisted records; dispatched work remains uncertain on recovery."""
        if (
            not isinstance(integrity_key, bytes)
            or len(integrity_key) < 32
            or not callable(getattr(authority, "accepts", None))
            or not authority.accepts(principal)
        ):
            raise PermissionError("task tool journal reader unauthorized")
        self._conn.execute("BEGIN")
        try:
            task = self._get_task(task_id, agent_id=agent_id)
            owner = self._conn.execute(
                "SELECT * FROM agent_task_authority WHERE task_id=? AND agent_id=?",
                (task_id, agent_id),
            ).fetchone()
            if (
                task is None
                or owner is None
                or task["principal_id"] != principal.principal_id
                or owner["principal_id"] != principal.principal_id
                or owner["attempt"] != task["execution_attempt"]
            ):
                raise PermissionError("task tool journal reader mismatch")
            self._verify_task_journal_authority(
                task, owner, principal, authority, integrity_key
            )
            rows = [
                dict(row)
                for row in self._conn.execute(
                    "SELECT * FROM task_tool_journal WHERE task_id=? "
                    "ORDER BY created_at",
                    (task_id,),
                ).fetchall()
            ]
            for row in rows:
                row["recovery_state"] = (
                    "UNKNOWN_OUTCOME" if row["state"] == "DISPATCHED" else row["state"]
                )
            if not authority.accepts(principal):
                raise PermissionError("task tool journal reader unauthorized")
            self._conn.commit()
            return rows
        except Exception:
            self._conn.rollback()
            raise

    @_db_locked
    def renew_task_authority(
        self,
        task_id: str,
        agent_id: str,
        principal: Any,
        authority: Any,
        attempt: str,
        worker_token: str,
        epoch: int,
    ) -> None:
        """Renew only a still-valid worker; expiry never transfers ownership."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self.validate_task_authority(
                task_id, agent_id, principal, authority, attempt, worker_token, epoch
            )
            self._conn.execute(
                "UPDATE agent_task_authority SET expires_at = ? WHERE task_id = ?",
                (time.time() + 3600, task_id),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    @_db_locked
    def complete_task(
        self,
        task_id: str,
        agent_id: str,
        principal: Any,
        authority: Any,
        *,
        execution_attempt: str,
        expected_state_version: int,
        checkpoint_id: str,
        checkpoint_version: int,
        integrity_key: bytes,
        worker_token: str,
        worker_epoch: int,
        result_text: str,
        result_metadata: dict,
        tool_evidence: list[dict],
        worker_exit_evidence: dict,
        verify_worker_exit_evidence: Optional[Callable[[dict], bool]] = None,
    ) -> Dict[str, Any]:
        """Verify executor evidence and atomically complete a bound task."""
        if (
            not callable(getattr(authority, "accepts", None))
            or not authority.accepts(principal)
            or not isinstance(getattr(principal, "principal_id", None), str)
            or not isinstance(integrity_key, bytes)
            or len(integrity_key) < 32
            or not isinstance(result_text, str)
            or not result_text.strip()
            or not isinstance(result_metadata, dict)
            or result_metadata.get("recovery_required")
            or result_metadata.get("cancelled")
            or not isinstance(tool_evidence, list)
            or not tool_evidence
            or not isinstance(worker_exit_evidence, dict)
        ):
            raise PermissionError("controller completion evidence is invalid")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            task = self._get_task(task_id, agent_id=agent_id)
            if (
                task is None
                or task["status"] != "running"
                or task["principal_id"] != principal.principal_id
                or task["execution_attempt"] != execution_attempt
                or task["state_version"] != expected_state_version
                or task["checkpoint_id"] != checkpoint_id
                or task["checkpoint_version"] != checkpoint_version
                or self.cancellation_state(agent_id) is not None
            ):
                raise PermissionError("task completion identity or state is stale")
            self.validate_task_authority(
                task_id,
                agent_id,
                principal,
                authority,
                execution_attempt,
                worker_token,
                worker_epoch,
            )
            checkpoint = self.get_bound_task_checkpoint(
                task_id,
                agent_id,
                principal,
                authority,
                integrity_key=integrity_key,
            )
            worker_pid = worker_exit_evidence.get("worker_pid")
            worker_id = worker_exit_evidence.get("worker_instance_id")
            supervisor_pid = worker_exit_evidence.get("controller_pid")
            host_verified = False
            if supervisor_pid != os.getpid() and callable(verify_worker_exit_evidence):
                try:
                    host_verified = (
                        verify_worker_exit_evidence(worker_exit_evidence) is True
                    )
                except Exception:
                    host_verified = False
            if (
                worker_exit_evidence.get("task_id") != task_id
                or worker_exit_evidence.get("agent_id") != agent_id
                or worker_exit_evidence.get("principal_id") != principal.principal_id
                or worker_exit_evidence.get("attempt") != execution_attempt
                or type(worker_exit_evidence.get("epoch")) is not int
                or worker_exit_evidence.get("epoch") != worker_epoch
                or (supervisor_pid != os.getpid() and not host_verified)
                or type(supervisor_pid) is not int
                or supervisor_pid <= 0
                or type(worker_pid) is not int
                or worker_pid <= 0
                or worker_pid == os.getpid()
                or worker_pid == supervisor_pid
                or worker_exit_evidence.get("tool_execution_pid") != worker_pid
                or not isinstance(worker_id, str)
                or not worker_id
                or worker_exit_evidence.get("ipc_authenticated") is not True
                or worker_exit_evidence.get("job_exit_confirmed") is not True
                or worker_exit_evidence.get("process_wait_confirmed") is not True
                or type(worker_exit_evidence.get("exit_observed_at"))
                not in (int, float)
                or not math.isfinite(worker_exit_evidence["exit_observed_at"])
                or worker_exit_evidence["exit_observed_at"] <= 0
                or type(worker_exit_evidence.get("worker_exit_code")) is not int
                or worker_exit_evidence["worker_exit_code"] != 0
                or worker_exit_evidence.get("worker_forced_termination") is not False
            ):
                raise PermissionError("worker exit evidence invalid")
            conversation = checkpoint.get("conversation_state")
            tool_state = checkpoint.get("tool_state")
            if checkpoint.get("id") != checkpoint_id:
                raise PermissionError("task checkpoint identity mismatch")
            if checkpoint.get("task_binding_version") != checkpoint_version:
                raise PermissionError("task checkpoint version mismatch")
            if (
                not isinstance(conversation, dict)
                or conversation.get("task_id") != task_id
            ):
                raise PermissionError("task checkpoint task identity mismatch")
            if conversation.get("lifecycle") != "COMPLETED":
                raise PermissionError("task executor did not complete its checkpoint")
            if conversation.get("result") != result_text:
                raise PermissionError("task result differs from signed checkpoint")
            if (
                not isinstance(tool_state, dict)
                or tool_state.get("execution_id") != execution_attempt
            ):
                raise PermissionError("task checkpoint attempt mismatch")
            if tool_state.get("recovery") or tool_state.get("cancellation"):
                raise PermissionError(
                    "task checkpoint has unresolved recovery or cancellation"
                )
            messages = conversation.get("messages")
            if not isinstance(messages, list):
                raise PermissionError("checkpoint tool evidence is missing")
            checkpoint_results = {
                (
                    message.get("name"),
                    hashlib.sha256(
                        (message.get("content") or "").encode("utf-8")
                    ).hexdigest(),
                )
                for message in messages
                if isinstance(message, dict) and message.get("role") == "tool"
            }
            checkpoint_tool_names = {
                message.get("name")
                for message in messages
                if isinstance(message, dict) and message.get("role") == "tool"
            }
            completed_steps = tool_state.get("completed_steps")
            executed_tools = (
                {
                    step.get("tool")
                    for step in completed_steps
                    if isinstance(step, dict)
                    and step.get("state") == "EXECUTED"
                    and step.get("execution_state") == "EXECUTED"
                }
                if isinstance(completed_steps, list)
                else set()
            )
            successful = set()
            for item in tool_evidence:
                if (
                    not isinstance(item, dict)
                    or item.get("success") is not True
                    or not isinstance(item.get("tool_name"), str)
                    or not isinstance(item.get("result_sha256"), str)
                    or len(item["result_sha256"]) != 64
                    or item["tool_name"] not in checkpoint_tool_names
                    or item["tool_name"] not in executed_tools
                    or (
                        not item["tool_name"].startswith("windows_")
                        and (item["tool_name"], item["result_sha256"])
                        not in checkpoint_results
                    )
                ):
                    raise PermissionError("executor tool result is not checkpointed")
                successful.add(item["tool_name"])
            required = set(task["required_tools"])
            if not successful or not required.issubset(successful):
                raise PermissionError("required task operations were not verified")
            checkpoint_calls = {
                (
                    message.get("name"),
                    message.get("tool_call_id"),
                    hashlib.sha256(
                        (message.get("content") or "").encode("utf-8")
                    ).hexdigest(),
                )
                for message in messages
                if isinstance(message, dict) and message.get("role") == "tool"
            }
            self._verify_task_tool_head(
                task_id,
                agent_id,
                principal.principal_id,
                execution_attempt,
                hashlib.sha256(worker_token.encode()).hexdigest(),
                worker_epoch,
                integrity_key,
            )
            journal_rows = self._conn.execute(
                "SELECT * FROM task_tool_journal WHERE task_id = ?", (task_id,)
            ).fetchall()
            if not journal_rows or len(journal_rows) != len(tool_evidence):
                raise PermissionError("task tool journal is incomplete")
            for stored in journal_rows:
                row = dict(stored)
                old_mac = row.pop("mac")
                if (
                    row["agent_id"] != agent_id
                    or row["principal_id"] != principal.principal_id
                    or row["attempt"] != execution_attempt
                    or row["owner_hash"]
                    != hashlib.sha256(worker_token.encode()).hexdigest()
                    or row["epoch"] != worker_epoch
                    or row["worker_id"] != worker_id
                    or row["state"] != "CHECKPOINTED"
                    or row["result_success"] != 1
                    or type(row["checkpointed_version"]) is not int
                    or not (
                        row["checkpoint_version"]
                        < row["checkpointed_version"]
                        <= checkpoint_version
                    )
                    or (row["tool_name"], row["tool_call_id"], row["result_sha256"])
                    not in checkpoint_calls
                    or not hmac.compare_digest(
                        old_mac, self._task_tool_journal_mac(integrity_key, row)
                    )
                ):
                    raise PermissionError("task tool journal result mismatch")
            if not authority.accepts(principal):
                raise PermissionError("task principal was revoked")
            safe_evidence = {
                "result_sha256": hashlib.sha256(
                    result_text.encode("utf-8")
                ).hexdigest(),
                "tools": [
                    {
                        "tool_name": item["tool_name"],
                        "result_sha256": item["result_sha256"],
                    }
                    for item in tool_evidence
                ],
                "checkpoint_id": checkpoint_id,
                "checkpoint_version": checkpoint_version,
                "worker": {
                    "instance_id": worker_id,
                    "pid": worker_pid,
                    "controller_pid": os.getpid(),
                    "supervisor_pid": supervisor_pid,
                    "tool_execution_pid": worker_pid,
                    "job_exit_confirmed": True,
                    "process_wait_confirmed": True,
                    "exit_observed_at": worker_exit_evidence["exit_observed_at"],
                    "exit_code": 0,
                },
            }
            cursor = self._conn.execute(
                "UPDATE agent_tasks SET status = 'completed', state_version = "
                "state_version + 1, completion_evidence_json = ?, "
                "cancellation_state = 'NONE', revocation_state = 'NONE' "
                "WHERE id = ? AND agent_id = ? AND status = 'running' "
                "AND principal_id = ? AND execution_attempt = ? AND state_version = ?",
                (
                    json.dumps(safe_evidence, sort_keys=True),
                    task_id,
                    agent_id,
                    principal.principal_id,
                    execution_attempt,
                    expected_state_version,
                ),
            )
            if cursor.rowcount != 1:
                raise PermissionError("task completion compare-and-swap failed")
            self._conn.commit()
            return self._get_task(task_id, agent_id=agent_id)  # type: ignore[return-value]
        except Exception:
            self._conn.rollback()
            raise

    @_db_locked
    def fail_task(
        self,
        task_id: str,
        agent_id: str,
        execution_attempt: str,
        expected_state_version: int,
        *,
        status: str = "failed",
    ) -> bool:
        """Close a claimed task on failure without changing a newer attempt."""
        if status not in {"failed", "cancelled"}:
            raise ValueError("invalid terminal task status")
        cursor = self._conn.execute(
            "UPDATE agent_tasks SET status = ?, state_version = state_version + 1, "
            "cancellation_state = ? WHERE id = ? AND agent_id = ? "
            "AND status = 'running' AND execution_attempt = ? AND state_version = ?",
            (
                status,
                "CANCELLED" if status == "cancelled" else "ACTIVE",
                task_id,
                agent_id,
                execution_attempt,
                expected_state_version,
            ),
        )
        self._conn.commit()
        return cursor.rowcount == 1

    @_db_locked
    def list_tasks(
        self, agent_id: str, status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM agent_tasks WHERE agent_id = ?"
        params: List[Any] = [agent_id]
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_task(r) for r in rows]

    @_db_locked
    def update_task(
        self,
        task_id: str,
        *,
        agent_id: str | None = None,
        unclaimed_only: bool = False,
        **kwargs: Any,
    ) -> Optional[Dict[str, Any]]:
        sets: List[str] = []
        vals: List[Any] = []
        for key in ("description", "status"):
            if key in kwargs:
                sets.append(f"{key} = ?")
                vals.append(kwargs[key])
        if "progress" in kwargs:
            sets.append("progress_json = ?")
            vals.append(json.dumps(kwargs["progress"]))
        if "findings" in kwargs:
            sets.append("findings_json = ?")
            vals.append(json.dumps(kwargs["findings"]))
        if not sets:
            return self._get_task(task_id, agent_id=agent_id)
        vals.append(task_id)
        where = "id = ?"
        if agent_id is not None:
            where += " AND agent_id = ?"
            vals.append(agent_id)
        if unclaimed_only:
            where += " AND execution_attempt IS NULL"
        cursor = self._conn.execute(
            f"UPDATE agent_tasks SET {', '.join(sets)} WHERE {where}", vals
        )
        self._conn.commit()
        if cursor.rowcount != 1:
            return None
        return self._get_task(task_id, agent_id=agent_id)

    @_db_locked
    def delete_task(
        self,
        task_id: str,
        *,
        agent_id: str | None = None,
        unclaimed_only: bool = False,
    ) -> bool:
        condition = " AND execution_attempt IS NULL" if unclaimed_only else ""
        if agent_id is None:
            cursor = self._conn.execute(
                "DELETE FROM agent_tasks WHERE id = ?" + condition, (task_id,)
            )
        else:
            cursor = self._conn.execute(
                "DELETE FROM agent_tasks WHERE id = ? AND agent_id = ?" + condition,
                (task_id, agent_id),
            )
        self._conn.commit()
        return cursor.rowcount > 0

    @_db_locked
    def _get_task(
        self, task_id: str, *, agent_id: str | None = None
    ) -> Optional[Dict[str, Any]]:
        if agent_id is None:
            row = self._conn.execute(
                "SELECT * FROM agent_tasks WHERE id = ?", (task_id,)
            ).fetchone()
        else:
            row = self._conn.execute(
                "SELECT * FROM agent_tasks WHERE id = ? AND agent_id = ?",
                (task_id, agent_id),
            ).fetchone()
        return self._row_to_task(row) if row else None

    @_db_locked
    def bind_channel(
        self,
        agent_id: str,
        channel_type: str,
        config: Optional[Dict[str, Any]] = None,
        routing_mode: str = "dedicated",
    ) -> Dict[str, Any]:
        binding_id = uuid.uuid4().hex[:12]
        session_id = uuid.uuid4().hex[:16]
        config_json = json.dumps(config or {})
        self._conn.execute(
            "INSERT INTO channel_bindings "
            "(id, agent_id, channel_type, config_json, session_id, routing_mode) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (binding_id, agent_id, channel_type, config_json, session_id, routing_mode),
        )
        self._conn.commit()
        return self._get_binding(binding_id)  # type: ignore[return-value]

    @_db_locked
    def list_channel_bindings(self, agent_id: str) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM channel_bindings WHERE agent_id = ?", (agent_id,)
        ).fetchall()
        return [self._row_to_binding(r) for r in rows]

    @_db_locked
    def unbind_channel(self, binding_id: str) -> None:
        self._conn.execute("DELETE FROM channel_bindings WHERE id = ?", (binding_id,))
        self._conn.commit()

    @_db_locked
    def _get_binding(self, binding_id: str) -> Optional[Dict[str, Any]]:
        row = self._conn.execute(
            "SELECT * FROM channel_bindings WHERE id = ?", (binding_id,)
        ).fetchone()
        return self._row_to_binding(row) if row else None

    @_db_locked
    def find_binding_for_channel(
        self, channel_type: str, channel_id: str
    ) -> Optional[Dict[str, Any]]:
        """Find a dedicated binding for a specific channel."""
        rows = self._conn.execute(
            "SELECT * FROM channel_bindings WHERE channel_type = ?",
            (channel_type,),
        ).fetchall()
        for row in rows:
            binding = self._row_to_binding(row)
            config = binding.get("config", {})
            if config.get("channel") == channel_id:
                return binding
        return None

    # ── Templates ─────────────────────────────────────────────────

    @staticmethod
    def list_templates() -> List[Dict[str, Any]]:
        """Discover built-in and user templates."""
        import importlib.resources

        try:
            import tomllib
        except ModuleNotFoundError:
            import tomli as tomllib  # type: ignore[no-redef]

        templates: List[Dict[str, Any]] = []

        # Built-in templates
        try:
            tpl_dir = importlib.resources.files("openjarvis.agents") / "templates"
            for item in tpl_dir.iterdir():
                if str(item).endswith(".toml"):
                    data = tomllib.loads(item.read_text(encoding="utf-8"))
                    tpl = data.get("template", {})
                    tpl["source"] = "built-in"
                    templates.append(tpl)
        except Exception:
            pass

        # User templates
        user_dir = get_config_dir() / "templates"
        if user_dir.is_dir():
            for f in user_dir.glob("*.toml"):
                try:
                    data = tomllib.loads(f.read_text(encoding="utf-8"))
                    tpl = data.get("template", {})
                    tpl["source"] = "user"
                    templates.append(tpl)
                except Exception:
                    pass

        return templates

    def create_from_template(
        self, template_id: str, name: str, overrides: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create an agent from a template with optional overrides."""
        templates = self.list_templates()
        tpl = next((t for t in templates if t.get("id") == template_id), None)
        if not tpl:
            raise ValueError(f"Template not found: {template_id}")
        skip = {"id", "name", "description", "source"}
        config = {k: v for k, v in tpl.items() if k not in skip}
        if overrides:
            config.update(overrides)
        agent_type = config.pop("agent_type", "monitor_operative")

        # Expand system_prompt_template with instruction
        prompt_tpl = config.pop("system_prompt_template", "")
        if prompt_tpl:
            instruction = config.get("instruction", "")
            config["system_prompt"] = prompt_tpl.format(
                instruction=instruction or "(No specific instruction provided)",
            )

        return self.create_agent(name=name, agent_type=agent_type, config=config)

    # ── Message queue ─────────────────────────────────────────────

    @_db_locked
    def send_message(self, agent_id: str, content: str, mode: str = "queued") -> dict:
        msg_id = uuid4().hex[:16]
        now = time.time()
        _sql = (
            "INSERT INTO agent_messages"
            " (id, agent_id, direction, content, mode, status, created_at)"
            " VALUES (?, ?, 'user_to_agent', ?, ?, 'pending', ?)"
        )
        self._conn.execute(_sql, (msg_id, agent_id, content, mode, now))
        self._conn.commit()
        return {
            "id": msg_id,
            "agent_id": agent_id,
            "direction": "user_to_agent",
            "content": content,
            "mode": mode,
            "status": "pending",
            "created_at": now,
        }

    @_db_locked
    def store_agent_response(
        self,
        agent_id: str,
        content: str,
        tool_calls: Optional[list] = None,
    ) -> dict:
        """Store an agent-to-user response message.

        ``tool_calls`` is an optional list of ``{tool, arguments, result,
        success, latency}`` dicts captured during the turn. They are stored
        as JSON alongside the message so the UI can replay them after a
        page reload.
        """
        msg_id = uuid4().hex[:16]
        now = time.time()
        tool_calls_json = json.dumps(tool_calls) if tool_calls else None
        self._conn.execute(
            "INSERT INTO agent_messages"
            " (id, agent_id, direction, content, mode, status, created_at,"
            " tool_calls)"
            " VALUES (?, ?, 'agent_to_user', ?, 'immediate', 'delivered', ?, ?)",
            (msg_id, agent_id, content, now, tool_calls_json),
        )
        self._conn.commit()
        return {
            "id": msg_id,
            "agent_id": agent_id,
            "direction": "agent_to_user",
            "content": content,
            "mode": "immediate",
            "status": "delivered",
            "created_at": now,
            "tool_calls": tool_calls or None,
        }

    @_db_locked
    def list_messages(self, agent_id: str, limit: int = 50) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM agent_messages"
            " WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()
        return [self._row_to_message(r) for r in rows]

    @_db_locked
    def get_pending_messages(self, agent_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM agent_messages"
            " WHERE agent_id = ? AND direction = 'user_to_agent'"
            " AND status = 'pending' ORDER BY created_at ASC",
            (agent_id,),
        ).fetchall()
        return [self._row_to_message(r) for r in rows]

    @_db_locked
    def mark_message_delivered(self, message_id: str) -> None:
        self._conn.execute(
            "UPDATE agent_messages SET status = 'delivered' WHERE id = ?",
            (message_id,),
        )
        self._conn.commit()

    @_db_locked
    def add_agent_response(self, agent_id: str, content: str) -> dict:
        msg_id = uuid4().hex[:16]
        now = time.time()
        _sql = (
            "INSERT INTO agent_messages"
            " (id, agent_id, direction, content, mode, status, created_at)"
            " VALUES (?, ?, 'agent_to_user', ?, 'immediate', 'responded', ?)"
        )
        self._conn.execute(_sql, (msg_id, agent_id, content, now))
        self._conn.commit()
        return {
            "id": msg_id,
            "agent_id": agent_id,
            "direction": "agent_to_user",
            "content": content,
            "mode": "immediate",
            "status": "responded",
            "created_at": now,
        }

    @staticmethod
    def _row_to_message(row: sqlite3.Row) -> dict:
        tool_calls = None
        try:
            raw = row["tool_calls"]
        except (IndexError, KeyError):
            raw = None
        if raw:
            try:
                tool_calls = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                tool_calls = None
        return {
            "id": row["id"],
            "agent_id": row["agent_id"],
            "direction": row["direction"],
            "content": row["content"],
            "mode": row["mode"],
            "status": row["status"],
            "created_at": row["created_at"],
            "tool_calls": tool_calls,
        }

    # ── Learning log ──────────────────────────────────────────

    @_db_locked
    def add_learning_log(
        self,
        agent_id: str,
        event_type: str,
        description: str = "",
        data: dict | None = None,
    ) -> dict:
        log_id = uuid4().hex[:16]
        now = time.time()
        self._conn.execute(
            "INSERT INTO agent_learning_log"
            " (id, agent_id, event_type, description, data, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (log_id, agent_id, event_type, description, json.dumps(data or {}), now),
        )
        self._conn.commit()
        return {
            "id": log_id,
            "agent_id": agent_id,
            "event_type": event_type,
            "description": description,
            "data": data or {},
            "created_at": now,
        }

    @_db_locked
    def list_learning_log(self, agent_id: str, limit: int = 50) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM agent_learning_log"
            " WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()
        return [
            {
                "id": r["id"],
                "agent_id": r["agent_id"],
                "event_type": r["event_type"],
                "description": r["description"],
                "data": json.loads(r["data"] or "{}"),
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    # ── Row converters ────────────────────────────────────────────

    @staticmethod
    def _row_to_agent(row: sqlite3.Row) -> Dict[str, Any]:
        config_raw = row["config_json"]
        return {
            "id": row["id"],
            "name": row["name"],
            "agent_type": row["agent_type"],
            "config": json.loads(config_raw) if config_raw else {},
            "status": row["status"],
            "summary_memory": row["summary_memory"] or "",
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "total_tokens": row["total_tokens"] or 0,
            "total_cost": row["total_cost"] or 0.0,
            "total_runs": row["total_runs"] or 0,
            "last_run_at": row["last_run_at"],
            "last_activity_at": row["last_activity_at"],
            "stall_retries": row["stall_retries"] or 0,
            "current_activity": row["current_activity"] or "",
            "input_tokens": row["input_tokens"] or 0,
            "output_tokens": row["output_tokens"] or 0,
        }

    @staticmethod
    def _row_to_task(row: sqlite3.Row) -> Dict[str, Any]:
        progress_raw = row["progress_json"]
        findings_raw = row["findings_json"]
        return {
            "id": row["id"],
            "agent_id": row["agent_id"],
            "description": row["description"],
            "status": row["status"],
            "progress": json.loads(progress_raw) if progress_raw else {},
            "findings": json.loads(findings_raw) if findings_raw else [],
            "principal_id": row["principal_id"],
            "host_session_id": row["host_session_id"],
            "execution_attempt": row["execution_attempt"],
            "state_version": row["state_version"],
            "checkpoint_id": row["checkpoint_id"],
            "checkpoint_version": row["checkpoint_version"],
            "required_tools": json.loads(row["required_tools_json"] or "[]"),
            "completion_evidence": json.loads(row["completion_evidence_json"] or "{}"),
            "cancellation_state": row["cancellation_state"],
            "revocation_state": row["revocation_state"],
            "created_at": row["created_at"],
        }

    @staticmethod
    def _row_to_binding(row: sqlite3.Row) -> Dict[str, Any]:
        config_raw = row["config_json"]
        return {
            "id": row["id"],
            "agent_id": row["agent_id"],
            "channel_type": row["channel_type"],
            "config": json.loads(config_raw) if config_raw else {},
            "session_id": row["session_id"] or "",
            "routing_mode": row["routing_mode"] or "auto",
        }
