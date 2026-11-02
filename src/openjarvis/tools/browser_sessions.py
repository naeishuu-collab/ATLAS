"""Owner-bound browser sessions for trusted host controllers.

Agent and principal identities must come from the host, never tool arguments.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from openjarvis.tools.browser import _BrowserSession


@dataclass
class _Lease:
    session_id: str
    principal: str
    session: _BrowserSession
    expires: float
    lock: threading.RLock = field(default_factory=threading.RLock)


class BrowserSessionManager:
    """One context per agent; session IDs and owner identities are host-owned."""

    def __init__(self, *, ttl: float = 1800, max_sessions: int = 32):
        if not 0 < ttl <= 86400 or not 1 <= max_sessions <= 128:
            raise ValueError("Invalid browser session limits")
        self._ttl = ttl
        self._max_sessions = max_sessions
        self._sessions: dict[str, _Lease] = {}
        self._lock = threading.RLock()

    def open(self, agent: str, principal: str) -> str:
        if not isinstance(agent, str) or not agent.strip():
            raise ValueError("Agent identity required")
        if not isinstance(principal, str) or not principal.strip():
            raise ValueError("Principal identity required")
        with self._lock:
            lease = self._sessions.get(agent)
            if lease is not None:
                if lease.principal != principal:
                    raise PermissionError("Session owner mismatch")
                if time.monotonic() >= lease.expires:
                    raise PermissionError("Session expired; revoke before reopening")
                return lease.session_id
            if len(self._sessions) >= self._max_sessions:
                raise RuntimeError("Browser session capacity reached")
            lease = _Lease(
                secrets.token_urlsafe(32),
                principal,
                _BrowserSession(),
                time.monotonic() + self._ttl,
            )
            self._sessions[agent] = lease
            return lease.session_id

    def _owned(self, agent: str, principal: str, session_id: str) -> _Lease:
        with self._lock:
            lease = self._sessions.get(agent)
            if (
                lease is None
                or lease.principal != principal
                or not isinstance(session_id, str)
                or not secrets.compare_digest(lease.session_id, session_id)
            ):
                raise PermissionError("Session owner mismatch")
            return lease

    def run(self, agent: str, principal: str, session_id: str, fn: Callable):
        lease = self._owned(agent, principal, session_id)
        with lease.lock:
            if self._owned(agent, principal, session_id) is not lease:
                raise PermissionError("Session revoked")
            if time.monotonic() >= lease.expires:
                raise PermissionError("Session expired")
            return lease.session.run(lambda: fn(lease.session))

    def revoke(self, agent: str, principal: str, session_id: str) -> None:
        lease = self._owned(agent, principal, session_id)
        with lease.lock:
            with self._lock:
                if self._sessions.get(agent) is not lease:
                    raise PermissionError("Session revoked")
                del self._sessions[agent]
            try:
                lease.session.close()
            finally:
                lease.session._runner.shutdown()

    def cleanup_expired(self) -> int:
        with self._lock:
            expired = [
                (agent, lease.principal, lease.session_id)
                for agent, lease in self._sessions.items()
                if time.monotonic() >= lease.expires
            ]
        count = 0
        for owner in expired:
            try:
                self.revoke(*owner)
                count += 1
            except PermissionError:
                pass
        return count
