"""Persistent stores for automatically extracted long-term memory facts.

A *fact* is a short, durable statement worth remembering about the user
(e.g. ``"Prefers concise answers"``).  Facts are produced by the memory
service's background extractor and persisted here so they survive across
sessions.  The store is intentionally small and self-contained: it dedupes,
caps the total number of facts, and is safe to call from multiple threads.
"""

from __future__ import annotations

import errno
import json
import os
import sys
import tempfile
import threading
import time
import uuid
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, List

from openjarvis.core.paths import get_config_dir
from openjarvis.core.registry import FactStoreRegistry
from openjarvis.memory.scope import (
    PRIVACY_PRIVATE,
    PROVENANCE_MODEL_INFERENCE,
    SCOPE_AGENT,
    MemoryAuthorization,
    authorized_metadata,
    build_metadata,
)

if sys.platform != "win32":
    import fcntl


_WINDOWS_LOCK_RETRY_SECONDS = 0.01
_WINDOWS_LOCK_RETRY_ERRNOS = {errno.EACCES, errno.EAGAIN, errno.EDEADLK}
_WINDOWS_LOCK_RETRY_WINERRORS = {33}  # ERROR_LOCK_VIOLATION


def _lock_windows_blocking(
    file_obj: Any,
    *,
    locking_api: Any | None = None,
    retry_interval: float = _WINDOWS_LOCK_RETRY_SECONDS,
) -> None:
    """Acquire the first-byte Windows lock, retrying until it is available.

    ``msvcrt.LK_LOCK`` only retries a fixed number of times before raising.
    Use the non-blocking operation in our own retry loop so contention never
    turns an otherwise valid store operation into a spurious failure.
    """
    if locking_api is None:
        import msvcrt as locking_api

    while True:
        file_obj.seek(0)
        try:
            locking_api.locking(file_obj.fileno(), locking_api.LK_NBLCK, 1)
            return
        except OSError as exc:
            if (
                exc.errno not in _WINDOWS_LOCK_RETRY_ERRNOS
                and getattr(exc, "winerror", None) not in _WINDOWS_LOCK_RETRY_WINERRORS
            ):
                raise
            time.sleep(retry_interval)


def _unlock_windows(file_obj: Any, *, locking_api: Any | None = None) -> None:
    if locking_api is None:
        import msvcrt as locking_api

    file_obj.seek(0)
    locking_api.locking(file_obj.fileno(), locking_api.LK_UNLCK, 1)


def _default_fact_path() -> Path:
    """Return the env-aware default JSONL path for automatic memory facts."""
    return get_config_dir() / "memory_facts.jsonl"


# Provenance tiers, recorded on every fact.
TRUST_AUTO = "auto"  # auto-extracted and scanner-clean → recallable
TRUST_TRUSTED = "trusted"  # explicitly vouched for by the user
TRUST_UNTRUSTED = "untrusted"  # scanner flagged the text → quarantined

# "" is the legacy on-disk value, written before provenance existed. It stays
# recallable so upgrading does not silently erase a user's existing memory.
# Exported because the same tier vocabulary gates document recall in
# tools.storage.context — a second, drifting copy of this set would be a
# security bug waiting to happen.
RECALLABLE_TRUST_TIERS = frozenset({"", TRUST_AUTO, TRUST_TRUSTED})
_RECALLABLE_TIERS = RECALLABLE_TRUST_TIERS  # internal alias


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_optional_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@contextmanager
def _cross_process_lock(lock_path: Path) -> Iterator[None]:
    """Hold an exclusive, blocking OS-level lock on *lock_path*.

    ``threading.Lock`` only serializes within one process, so it cannot
    protect the load -> modify -> flush cycle when two separate
    ``LocalFactStore`` instances (e.g. in different processes) touch the
    same file (#755). This blocks until the lock is free rather than
    failing fast, since callers want to wait their turn, not error out.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    f = open(lock_path, "a+b")
    try:
        if sys.platform == "win32":
            # msvcrt locks a byte range; the file needs at least one byte
            # for the region at offset 0 to be lockable.
            f.seek(0, os.SEEK_END)
            if f.tell() == 0:
                f.write(b"\0")
                f.flush()
            _lock_windows_blocking(f)
        else:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if sys.platform == "win32":
                _unlock_windows(f)
            else:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    finally:
        f.close()


@dataclass(slots=True)
class Fact:
    """A single durable memory entry."""

    text: str
    source: str = ""
    created_at: float = 0.0
    # Provenance tier: one of the TRUST_* constants above ("" for legacy rows).
    trust: str = ""
    # Scope-aware fields. schema_version=0 identifies legacy rows and is never
    # treated as GLOBAL by the authorization filter.
    memory_id: str = ""
    owner_user_id: str = ""
    agent_id: str = ""
    task_id: str = ""
    session_id: str = ""
    scope: str = ""
    provenance: str = ""
    confidence: float = 0.0
    privacy: str = ""
    updated_at: float = 0.0
    expires_at: float | None = None
    supersedes: str = ""
    superseded_by: str = ""
    deleted: bool = False
    shared: bool = False
    schema_version: int = 0

    @property
    def trusted_for_recall(self) -> bool:
        """Whether this fact may be placed in model-facing context.

        Only ``untrusted`` — the tier the memory service assigns when the
        injection scanner flags a fact's own text — is withheld. Unknown
        future tiers fail closed rather than silently becoming prompt input.
        """
        if self.deleted or self.superseded_by:
            return False
        if self.expires_at not in (None, ""):
            try:
                if float(self.expires_at) <= time.time():
                    return False
            except (TypeError, ValueError):
                return False
        return (self.trust or "").strip().lower() in _RECALLABLE_TIERS

    def to_metadata(self) -> dict[str, Any]:
        """Return the persisted ownership/provenance view used by retrieval."""
        return {
            "memory_id": self.memory_id,
            "owner_user_id": self.owner_user_id,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "session_id": self.session_id,
            "scope": self.scope,
            "provenance": self.provenance,
            "confidence": self.confidence,
            "privacy": self.privacy,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
            "supersedes": self.supersedes,
            "superseded_by": self.superseded_by,
            "deleted": self.deleted,
            "shared": self.shared,
            "schema_version": self.schema_version,
            "trust": self.trust,
            "source": self.source,
        }


class FactStore(ABC):
    """Abstract persistent store for extracted memory facts."""

    @abstractmethod
    def add(self, text: str, source: str = "") -> bool:
        """Store *text* as a fact. Returns True if a new fact was stored."""

    def set_trust(self, index: int, trust: str) -> bool:
        """Set the provenance tier of the *index*-th fact (0-based) as returned
        by :meth:`list`. Returns True if a fact was updated."""
        raise NotImplementedError

    def add_many(self, texts: Iterable[str], source: str = "") -> int:
        """Store several facts, returning the count of newly stored ones."""
        added = 0
        for text in texts:
            if self.add(text, source=source):
                added += 1
        return added

    def add_with_trust(self, text: str, source: str = "", trust: str = "") -> bool:
        """Store a provenance-aware fact without breaking legacy backends.

        Third-party stores implementing the original ``add(text, source)``
        contract inherit this adapter. Recallable facts are stored normally;
        quarantined or unknown tiers are dropped because a backend that cannot
        persist provenance cannot safely retain them for model-facing recall.
        Provenance-aware stores should override this method.
        """
        if (trust or "").strip().lower() not in _RECALLABLE_TIERS:
            return False
        return self.add(text, source=source)

    def add_scoped(
        self,
        text: str,
        *,
        authorization: MemoryAuthorization,
        source: str = "",
        scope: str = SCOPE_AGENT,
        provenance: str = PROVENANCE_MODEL_INFERENCE,
        confidence: float = 0.0,
        privacy: str = PRIVACY_PRIVATE,
        expires_at: float | None = None,
        trust: str = TRUST_AUTO,
    ) -> str | None:
        """Store a row with explicit ownership metadata when supported."""
        raise NotImplementedError

    def delete(
        self,
        memory_id: str,
        *,
        authorization: MemoryAuthorization | None = None,
    ) -> bool:
        raise NotImplementedError

    def correct(
        self,
        memory_id: str,
        text: str,
        *,
        authorization: MemoryAuthorization,
        source: str = "",
        expires_at: float | None = None,
    ) -> str | None:
        raise NotImplementedError

    def add_many_with_trust(
        self,
        texts: Iterable[str],
        source: str = "",
        trust: str = "",
    ) -> int:
        """Store several provenance-aware facts."""
        return sum(
            bool(self.add_with_trust(text, source=source, trust=trust))
            for text in texts
        )

    def promote_reviewed(self, index: int, expected_text: str) -> bool:
        """Promote the reviewed fact at *index* when it still matches.

        The default preserves compatibility with third-party implementations;
        stores with concurrent writers should override this with an atomic
        identity check.
        """
        del expected_text
        return self.set_trust(index, TRUST_TRUSTED)

    @abstractmethod
    def list(self) -> List[Fact]:
        """Return all stored facts, oldest first."""

    @abstractmethod
    def clear(self) -> int:
        """Remove all stored facts, returning the number removed."""

    @abstractmethod
    def count(self) -> int:
        """Return the number of stored facts."""


@FactStoreRegistry.register("local")
class LocalFactStore(FactStore):
    """Append-only JSONL fact store on the local filesystem.

    Facts are kept human-readable (one JSON object per line) so they can be
    inspected or edited by hand.  Writes are atomic (temp file + rename) and
    guarded by a lock, so concurrent ``add`` calls from the extraction worker
    and ``list``/``clear`` from the CLI never corrupt the file.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        max_facts: int = 1000,
    ) -> None:
        max_facts = int(max_facts)
        if max_facts <= 0:
            raise ValueError(f"max_facts must be a positive integer, got {max_facts}")
        self._path = (
            Path(path).expanduser() if path is not None else _default_fact_path()
        )
        self._max_facts = max_facts
        self._lock = threading.Lock()
        self._facts: List[Fact] = self._load()

    # -- persistence --------------------------------------------------------

    def _load(self) -> List[Fact]:
        if not self._path.exists():
            return []
        facts: List[Fact] = []
        try:
            text = self._path.read_text(encoding="utf-8")
        except OSError:
            return []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue  # skip malformed lines rather than crashing
            fact_text = str(obj.get("text", "")).strip()
            if not fact_text:
                continue
            facts.append(
                Fact(
                    text=fact_text,
                    source=str(obj.get("source", "")),
                    created_at=_as_float(obj.get("created_at", 0.0)),
                    trust=str(obj.get("trust", "")),
                    memory_id=str(obj.get("memory_id", ""))
                    or uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        "openjarvis-fact:" + json.dumps(obj, sort_keys=True),
                    ).hex,
                    owner_user_id=str(obj.get("owner_user_id", "") or ""),
                    agent_id=str(obj.get("agent_id", "") or ""),
                    task_id=str(obj.get("task_id", "") or ""),
                    session_id=str(obj.get("session_id", "") or ""),
                    scope=str(obj.get("scope", "") or ""),
                    provenance=str(obj.get("provenance", "") or ""),
                    confidence=_as_float(obj.get("confidence", 0.0)),
                    privacy=str(obj.get("privacy", "") or ""),
                    updated_at=_as_float(
                        obj.get("updated_at", obj.get("created_at", 0.0))
                    ),
                    expires_at=_as_optional_float(obj.get("expires_at")),
                    supersedes=str(obj.get("supersedes", "") or ""),
                    superseded_by=str(obj.get("superseded_by", "") or ""),
                    deleted=bool(obj.get("deleted", False)),
                    shared=bool(obj.get("shared", False)),
                    schema_version=_as_int(obj.get("schema_version", 0)),
                )
            )
        return facts

    def _flush(self) -> None:
        """Atomically rewrite the JSONL file from the in-memory list."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = "".join(
            json.dumps(asdict(f), ensure_ascii=False) + "\n" for f in self._facts
        )
        # A fixed temp filename lets two concurrent writers interleave into
        # the same temp file before either os.replace() runs (#755); a
        # unique name per flush avoids that collision entirely.
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self._path.parent),
            prefix=self._path.name + ".",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_f:
                tmp_f.write(payload)
            os.replace(tmp_name, self._path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _lock_path(self) -> Path:
        return self._path.with_suffix(self._path.suffix + ".lock")

    def _sync_from_disk_locked(self) -> None:
        """Refresh in-memory facts from disk while holding ``self._lock``."""
        self._facts = self._load()

    # -- FactStore API ------------------------------------------------------

    def add(self, text: str, source: str = "", trust: str = "") -> bool:
        text = (text or "").strip()
        if not text:
            return False
        trust = (trust or "").strip().lower()
        with self._lock, _cross_process_lock(self._lock_path()):
            self._sync_from_disk_locked()
            lowered = text.lower()
            duplicate = next(
                (fact for fact in self._facts if fact.text.lower() == lowered),
                None,
            )
            if duplicate is not None:
                # A later hostile derivation must be able to quarantine an
                # older recallable copy. Never auto-promote in the opposite
                # direction; promotion requires explicit human review.
                if trust not in _RECALLABLE_TIERS and duplicate.trusted_for_recall:
                    duplicate.trust = trust or TRUST_UNTRUSTED
                    self._flush()
                return False  # dedupe
            self._facts.append(
                Fact(text=text, source=source, created_at=time.time(), trust=trust)
            )
            # Enforce the cap by evicting the oldest entries. max_facts is
            # always positive (validated in __init__), so this slice can't
            # hit Python's `list[-0:]` footgun, which returns the whole
            # list instead of emptying it.
            if len(self._facts) > self._max_facts:
                self._facts = self._facts[-self._max_facts :]
            self._flush()
        return True

    def add_with_trust(self, text: str, source: str = "", trust: str = "") -> bool:
        return self.add(text, source=source, trust=trust)

    def add_scoped(
        self,
        text: str,
        *,
        authorization: MemoryAuthorization,
        source: str = "",
        scope: str = SCOPE_AGENT,
        provenance: str = PROVENANCE_MODEL_INFERENCE,
        confidence: float = 0.0,
        privacy: str = PRIVACY_PRIVATE,
        expires_at: float | None = None,
        trust: str = TRUST_AUTO,
    ) -> str | None:
        text = (text or "").strip()
        if not text:
            return None
        metadata = build_metadata(
            authorization,
            scope=scope,
            provenance=provenance,
            confidence=confidence,
            privacy=privacy,
            expires_at=expires_at,
        )
        now = float(metadata["created_at"])
        memory_id = uuid.uuid4().hex
        fact = Fact(
            text=text,
            source=source,
            created_at=now,
            trust=(trust or TRUST_AUTO).strip().lower(),
            memory_id=memory_id,
            owner_user_id=str(metadata.get("owner_user_id") or ""),
            agent_id=str(metadata.get("agent_id") or ""),
            task_id=str(metadata.get("task_id") or ""),
            session_id=str(metadata.get("session_id") or ""),
            scope=str(metadata["scope"]),
            provenance=str(metadata["provenance"]),
            confidence=float(metadata["confidence"]),
            privacy=str(metadata["privacy"]),
            updated_at=now,
            expires_at=metadata.get("expires_at"),
            shared=bool(metadata.get("shared", False)),
            schema_version=1,
        )
        with self._lock, _cross_process_lock(self._lock_path()):
            self._sync_from_disk_locked()
            duplicate = next(
                (
                    existing
                    for existing in self._facts
                    if existing.text.lower() == text.lower()
                    and existing.scope == fact.scope
                    and existing.owner_user_id == fact.owner_user_id
                    and existing.agent_id == fact.agent_id
                    and existing.task_id == fact.task_id
                    and existing.session_id == fact.session_id
                    and not existing.deleted
                    and not existing.superseded_by
                ),
                None,
            )
            if duplicate is not None:
                return duplicate.memory_id
            self._facts.append(fact)
            if len(self._facts) > self._max_facts:
                self._facts = self._facts[-self._max_facts :]
            self._flush()
        return memory_id

    def delete(
        self,
        memory_id: str,
        *,
        authorization: MemoryAuthorization | None = None,
    ) -> bool:
        with self._lock, _cross_process_lock(self._lock_path()):
            self._sync_from_disk_locked()
            fact = next(
                (item for item in self._facts if item.memory_id == memory_id),
                None,
            )
            if fact is None:
                return False
            if fact.schema_version == 1:
                if not authorized_metadata(fact.to_metadata(), authorization):
                    return False
            elif authorization is not None:
                # An ownerless legacy row cannot be proven to belong to this
                # caller, even for deletion.
                return False
            fact.deleted = True
            fact.updated_at = time.time()
            self._flush()
        return True

    def correct(
        self,
        memory_id: str,
        text: str,
        *,
        authorization: MemoryAuthorization,
        source: str = "",
        expires_at: float | None = None,
    ) -> str | None:
        text = (text or "").strip()
        if not text:
            return None
        with self._lock, _cross_process_lock(self._lock_path()):
            self._sync_from_disk_locked()
            old = next(
                (item for item in self._facts if item.memory_id == memory_id),
                None,
            )
            if old is None or old.schema_version != 1 or not authorized_metadata(
                old.to_metadata(), authorization
            ):
                return None
            now = time.time()
            new_id = uuid.uuid4().hex
            new_fact = Fact(
                text=text,
                source=source or old.source,
                created_at=now,
                trust=TRUST_TRUSTED,
                memory_id=new_id,
                owner_user_id=old.owner_user_id,
                agent_id=old.agent_id,
                task_id=old.task_id,
                session_id=old.session_id,
                scope=old.scope,
                provenance="USER_CORRECTION",
                confidence=1.0,
                privacy=old.privacy,
                updated_at=now,
                expires_at=expires_at if expires_at is not None else old.expires_at,
                supersedes=old.memory_id,
                shared=old.shared,
                schema_version=1,
            )
            old.superseded_by = new_id
            old.deleted = True
            old.updated_at = now
            self._facts.append(new_fact)
            if len(self._facts) > self._max_facts:
                self._facts = self._facts[-self._max_facts :]
            self._flush()
        return new_id

    def list_authorized(
        self,
        authorization: MemoryAuthorization | None,
        *,
        now: float | None = None,
    ) -> List[Fact]:
        if authorization is None:
            return []
        return [
            fact
            for fact in self.list()
            if fact.trusted_for_recall
            and authorized_metadata(fact.to_metadata(), authorization, now=now)
        ]

    def set_trust(self, index: int, trust: str) -> bool:
        trust = (trust or "").strip().lower()
        if trust not in {TRUST_AUTO, TRUST_TRUSTED, TRUST_UNTRUSTED}:
            raise ValueError(f"Unknown fact trust tier: {trust!r}")
        with self._lock, _cross_process_lock(self._lock_path()):
            self._sync_from_disk_locked()
            if not 0 <= index < len(self._facts):
                return False
            self._facts[index].trust = trust
            self._flush()
        return True

    def promote_reviewed(self, index: int, expected_text: str) -> bool:
        """Atomically promote exactly the fact a user reviewed."""
        with self._lock, _cross_process_lock(self._lock_path()):
            self._sync_from_disk_locked()
            if not 0 <= index < len(self._facts):
                return False
            fact = self._facts[index]
            if fact.text != expected_text or fact.trusted_for_recall:
                return False
            fact.trust = TRUST_TRUSTED
            self._flush()
        return True

    def list(self) -> List[Fact]:
        with self._lock:
            self._sync_from_disk_locked()
            return list(self._facts)

    def clear(self) -> int:
        with self._lock, _cross_process_lock(self._lock_path()):
            self._sync_from_disk_locked()
            removed = len(self._facts)
            self._facts = []
            if self._path.exists():
                try:
                    self._path.unlink()
                except OSError:
                    self._flush()
        return removed

    def count(self) -> int:
        with self._lock:
            self._sync_from_disk_locked()
            return len(self._facts)

    @property
    def path(self) -> Path:
        """Filesystem location of the JSONL store."""
        return self._path


def _ensure_fact_store_backends_registered() -> None:
    """Restore built-in fact-store registrations if a test cleared registries."""
    if not FactStoreRegistry.contains("local"):
        FactStoreRegistry.register_value("local", LocalFactStore)


def create_fact_store(
    backend: str = "local",
    *,
    path: str | Path | None = None,
    max_facts: int = 1000,
) -> FactStore:
    """Construct a fact store for the configured *backend*.

    Only the ``"local"`` (on-disk JSONL) backend is supported today; the
    registry-backed constructor exists so additional backends can be added
    without changing the service or CLI wiring.
    """
    _ensure_fact_store_backends_registered()
    key = (backend or "local").strip().lower()
    if not FactStoreRegistry.contains(key):
        supported = ", ".join(FactStoreRegistry.keys())
        raise ValueError(
            f"Unknown memory backend '{backend}'. Supported backends: {supported}"
        )
    return FactStoreRegistry.create(key, path, max_facts=max_facts)


def load_configured_facts(
    config: Any,
    authorization: MemoryAuthorization | None = None,
) -> List[Fact]:
    """Load automatic-memory facts from *config* when the service is enabled.

    Context injection is also used by short-lived commands such as
    ``jarvis ask``, where no :class:`MemoryService` instance exists.  This
    helper gives those callers the same configured fact-store view without
    coupling them to the service lifecycle.
    """
    memory = getattr(config, "memory", None)
    if memory is None or not getattr(memory, "enabled", False):
        return []

    store = create_fact_store(
        getattr(memory, "backend", "local"),
        path=getattr(memory, "facts_path", None),
        max_facts=getattr(memory, "max_facts", 1000),
    )
    # This helper feeds short-lived model paths (ask, SDK, system
    # orchestrator). Keep the full list available through FactStore.list() for
    # auditing/CLI use, but never return quarantined facts for model recall.
    if authorization is not None:
        return [
            fact
            for fact in store.list()
            if fact.trusted_for_recall
            and authorized_metadata(fact.to_metadata(), authorization)
        ]
    return [fact for fact in store.list() if fact.trusted_for_recall]


__all__ = [
    "RECALLABLE_TRUST_TIERS",
    "TRUST_AUTO",
    "TRUST_TRUSTED",
    "TRUST_UNTRUSTED",
    "Fact",
    "FactStore",
    "LocalFactStore",
    "create_fact_store",
    "load_configured_facts",
]
