"""Option B staged immutable worker runtime — builder, manifest, verifier.

P0-4 implements ONLY deterministic staging + exact-tree verification of a
future worker runtime. Explicitly OUT of scope (not implemented here):

- ACL mutation / RX provisioning (no filesystem immutability claimed);
- AppContainer Profile creation, launch, or integration;
- production launcher consumption of the staged tree;
- manifest authenticity/signing (host-trust model: the trusted host
  builds and verifies; SHA-256 gives integrity, not authenticity).

Security posture enforced by this module (fail closed everywhere):

- the worker dependency closure is resolved from real source by AST
  (import-time requirements only; ``try/except ImportError`` branches
  are optional); any third-party requirement DENIES a READY runtime
  unless explicitly allowlisted by the caller (default: empty);
- only explicit file lists are staged — never a recursive copy of the
  repository root, user profile, or site-packages;
- symlinks / Windows reparse points in sources are refused; unexpected
  reparse points in the staged tree fail verification;
- manifest hashes are computed over STAGED bytes (copy-then-hash), so
  post-copy source mutation cannot invalidate staged semantics;
- a runtime is READY only when full exact-tree verification passes.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import posixpath
import shutil
import stat
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

SCHEMA_VERSION = 1
BUILDER_VERSION = "astra-p04.1"
MANIFEST_NAME = "manifest.json"
WORKER_ENTRY_DEFAULT = "openjarvis.agents.rlm_worker"

_ROLE_CPYTHON_EXE = "cpython-exe"
_ROLE_CPYTHON_DLL = "cpython-dll"
_ROLE_CPYTHON_STDLIB = "cpython-stdlib"
_ROLE_WORKER = "astra-worker"

# Top-level runtime DLLs/exe staged next to each other (Windows layout).
CPYTHON_TOP_FILES: Tuple[str, ...] = (
    "python.exe",
    "python311.dll",
    "python3.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
)
CPYTHON_STDLIB_DIRS: Tuple[str, ...] = ("Lib", "DLLs")
# Never staged: stdlib test packages, bytecode caches, site-packages.
STDLIB_SKIP_DIR_NAMES: FrozenSet[str] = frozenset(
    {"test", "tests", "__pycache__", "site-packages"}
)

# Worker-side credential hygiene (path/type policy; values never read).
_WORKER_CREDENTIAL_BASENAMES: FrozenSet[str] = frozenset({".env"})
_WORKER_CREDENTIAL_PREFIXES: Tuple[str, ...] = ("id_rsa",)
_WORKER_CREDENTIAL_SUBSTRINGS: Tuple[str, ...] = (
    "secret",
    "token",
    "credential",
    "api_key",
    "apikey",
    ".pem",
    ".key",
)
# Tree-wide high-confidence secret indicators (exact basename / suffix /
# prefix; deliberately NOT substring matching so stdlib ``secrets.py`` /
# ``token.py`` module names are unaffected).
_TREE_SENSITIVE_BASENAMES: FrozenSet[str] = frozenset({".env"})
_TREE_SENSITIVE_SUFFIXES: Tuple[str, ...] = (".pem", ".key")
_TREE_SENSITIVE_PREFIXES: Tuple[str, ...] = ("id_rsa",)

# Verifier rejects these directory names anywhere in the staged tree.
_FORBIDDEN_DIR_NAMES: FrozenSet[str] = frozenset(
    {".git", "tests", "test", "docs", "__pycache__", "site-packages"}
)

_REPARSE_POINT_BIT = 0x400  # Windows FILE_ATTRIBUTE_REPARSE_POINT


class StagedRuntimeError(RuntimeError):
    """Base failure: build/verification denied or impossible."""


class ThirdPartyBlocked(StagedRuntimeError):
    """Closure requires third-party packages: no READY runtime."""

    def __init__(self, requirements: Dict[str, Tuple[str, ...]]) -> None:
        self.requirements = requirements
        names = sorted(
            {pkg for pkgs in requirements.values() for pkg in pkgs}
        )
        super().__init__(
            "worker closure requires third-party packages: "
            + ", ".join(names)
        )


class CredentialBlocked(StagedRuntimeError):
    """A credential-like path would enter the staged runtime."""


class PathSafetyError(StagedRuntimeError):
    """Unsafe manifest/source path rejected."""


# --------------------------------------------------------------------------
# Closure resolution
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class ClosureResult:
    """Import-time dependency closure for a worker entry module."""

    entry: str
    # module name -> repo-relative posix source path
    modules: Dict[str, str]
    # module name -> tuple of required third-party top-level names
    third_party: Dict[str, Tuple[str, ...]]
    # optional (try/except ImportError-tolerated) openjarvis modules seen
    skipped_optional: Tuple[str, ...]


def _stdlib_names() -> FrozenSet[str]:
    names = getattr(sys, "stdlib_module_names", None)
    if names:
        return frozenset(names)
    return frozenset(
        {"os", "sys", "json", "re", "ast", "pathlib", "hashlib", "typing"}
    )


def _module_source(repo_src: Path, module: str) -> Optional[Path]:
    candidate = repo_src / (module.replace(".", "/") + ".py")
    if candidate.is_file():
        return candidate
    candidate = repo_src / module.replace(".", "/") / "__init__.py"
    if candidate.is_file():
        return candidate
    return None


def _top_level_imports(
    source: Path, module: str
) -> Tuple[Set[str], Set[str]]:
    """Return (required, optional) absolute import roots at module top level.

    Only statements in the module body count (function/lambda bodies are
    runtime-lazy). ``try`` blocks catching ImportError/ModuleNotFoundError
    (or bare/Exception) mark their imports optional.
    """
    tree = ast.parse(source.read_text(encoding="utf-8"))
    required: Set[str] = set()
    optional: Set[str] = set()
    for node in tree.body:
        target = required
        statements: List[ast.stmt] = [node]
        if isinstance(node, ast.Try):
            caught = any(
                handler.type is None
                or (
                    isinstance(handler.type, ast.Name)
                    and handler.type.id
                    in ("ImportError", "ModuleNotFoundError", "Exception")
                )
                or (
                    isinstance(handler.type, ast.Tuple)
                    and any(
                        isinstance(e, ast.Name)
                        and e.id
                        in ("ImportError", "ModuleNotFoundError", "Exception")
                        for e in handler.type.elts
                    )
                )
                for handler in node.handlers
            )
            target = optional if caught else required
            statements = list(node.body)
        for sub in statements:
            if isinstance(sub, ast.Import):
                for alias in sub.names:
                    target.add(alias.name)
            elif isinstance(sub, ast.ImportFrom):
                if sub.level:
                    base = module
                    for _ in range(sub.level):
                        base = base.rpartition(".")[0]
                    if sub.module:
                        full = f"{base}.{sub.module}" if base else sub.module
                        target.add(full)
                        for alias in sub.names:
                            if alias.name != "*":
                                target.add(f"{full}.{alias.name}")
                    else:
                        for alias in sub.names:
                            if alias.name != "*":
                                target.add(
                                    f"{base}.{alias.name}" if base else alias.name
                                )
                elif sub.module:
                    target.add(sub.module)
                    for alias in sub.names:
                        if alias.name != "*":
                            target.add(f"{sub.module}.{alias.name}")
    return required, optional


def resolve_closure(repo_src: Path, entry: str) -> ClosureResult:
    """Resolve the import-time closure of *entry* under *repo_src*.

    Includes parent package ``__init__`` files (they execute on import).
    Raises :class:`StagedRuntimeError` if a REQUIRED module is missing.
    """
    repo_src = Path(repo_src)
    stdlib = _stdlib_names()
    modules: Dict[str, str] = {}
    third: Dict[str, Set[str]] = {}
    skipped: Set[str] = set()
    queue: List[str] = [entry]

    def enqueue(name: str) -> None:
        if name not in modules and name not in queue:
            queue.append(name)

    def resolve_repo_module(name: str) -> Optional[str]:
        """Longest repo-resolvable module prefix of *name* (or None)."""
        if name.split(".")[0] in stdlib or name == "__future__":
            return None
        probe = name
        while probe:
            if _module_source(repo_src, probe) is not None:
                return probe
            probe = probe.rpartition(".")[0]
        return None

    def is_repo_module(name: str) -> bool:
        return resolve_repo_module(name) is not None

    while queue:
        module = queue.pop()
        if module in modules:
            continue
        source = _module_source(repo_src, module)
        if source is None:
            raise StagedRuntimeError(
                f"required module {module!r} not found under {repo_src}"
            )
        modules[module] = source.relative_to(repo_src).as_posix()
        parts = module.split(".")
        for i in range(1, len(parts)):
            enqueue(".".join(parts[:i]))
        required, optional = _top_level_imports(source, module)
        skipped.update(
            name for name in optional if is_repo_module(name)
        )
        for name in required:
            if name == "__future__" or name.split(".")[0] in stdlib:
                continue
            resolved = resolve_repo_module(name)
            if resolved is not None:
                enqueue(resolved)
            else:
                third.setdefault(module, set()).add(name.split(".")[0])
    return ClosureResult(
        entry=entry,
        modules=modules,
        third_party={k: tuple(sorted(v)) for k, v in third.items()},
        skipped_optional=tuple(sorted(skipped)),
    )


# --------------------------------------------------------------------------
# Path / credential / reparse policy
# --------------------------------------------------------------------------


def check_manifest_path(path: str) -> str:
    """Validate + normalize a manifest-relative posix path."""
    if not path or not isinstance(path, str):
        raise PathSafetyError(f"invalid manifest path: {path!r}")
    if "\\" in path:
        raise PathSafetyError(f"backslash separator rejected: {path!r}")
    if posixpath.isabs(path):
        raise PathSafetyError(f"absolute path rejected: {path!r}")
    if len(path) >= 2 and path[1] == ":":
        raise PathSafetyError(f"drive path rejected: {path!r}")
    normalized = posixpath.normpath(path)
    if normalized in (".", "..") or normalized.startswith("../"):
        raise PathSafetyError(f"traversal rejected: {path!r}")
    if normalized != path:
        raise PathSafetyError(f"non-canonical path rejected: {path!r}")
    return normalized


def _check_credential_name(relpath: str) -> None:
    lowered = relpath.lower()
    basename = posixpath.basename(lowered)
    if basename in _WORKER_CREDENTIAL_BASENAMES:
        raise CredentialBlocked(f"credential basename refused: {relpath!r}")
    if basename.startswith(_WORKER_CREDENTIAL_PREFIXES):
        raise CredentialBlocked(f"credential prefix refused: {relpath!r}")
    for marker in _WORKER_CREDENTIAL_SUBSTRINGS:
        if marker in lowered:
            raise CredentialBlocked(
                f"credential-like name refused: {relpath!r} (marker {marker!r})"
            )


def check_worker_source_path(relpath: str) -> str:
    """Gate a worker source relpath: safety + credential hygiene."""
    checked = check_manifest_path(relpath)
    _check_credential_name(checked)
    return checked


def _is_reparse(path: Path) -> bool:
    """Best-effort reparse-point/symlink detection (never follows links)."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    file_attrs = getattr(st, "st_file_attributes", 0) or 0
    return bool(file_attrs & _REPARSE_POINT_BIT)


def _is_sensitive_tree_name(basename: str) -> bool:
    lowered = basename.lower()
    if lowered in _TREE_SENSITIVE_BASENAMES:
        return True
    if lowered.startswith(_TREE_SENSITIVE_PREFIXES):
        return True
    return any(lowered.endswith(sfx) for sfx in _TREE_SENSITIVE_SUFFIXES)


# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FileRecord:
    path: str
    size: int
    sha256: str
    role: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "role": self.role,
        }


def sha256_file(path: Path) -> Tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
            size += len(chunk)
    return size, digest.hexdigest()


def tree_hash(records: Iterable[FileRecord]) -> str:
    lines = [
        f"{r.path}\t{r.size}\t{r.sha256}\t{r.role}" for r in records
    ]
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def build_manifest(
    *,
    entry: str,
    python_version: str,
    architecture: str,
    source_revision: str,
    records: List[FileRecord],
) -> Dict[str, object]:
    ordered = sorted(records, key=lambda r: r.path)
    manifest: Dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "builder_version": BUILDER_VERSION,
        "entry_module": entry,
        "python_version": python_version,
        "architecture": architecture,
        "source_revision": source_revision,
        "files": [r.as_dict() for r in ordered],
    }
    manifest["tree_hash"] = tree_hash(ordered)
    return manifest


def canonical_manifest_bytes(manifest: Dict[str, object]) -> bytes:
    return (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(
        "utf-8"
    )


def parse_manifest(data: bytes) -> Dict[str, object]:
    try:
        manifest = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StagedRuntimeError(f"manifest is not valid JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise StagedRuntimeError("manifest root must be an object")
    for key in (
        "schema_version",
        "builder_version",
        "entry_module",
        "python_version",
        "architecture",
        "source_revision",
        "files",
        "tree_hash",
    ):
        if key not in manifest:
            raise StagedRuntimeError(f"manifest missing field: {key}")
    if manifest["schema_version"] != SCHEMA_VERSION:
        raise StagedRuntimeError(
            f"unsupported manifest schema: {manifest['schema_version']!r}"
        )
    files = manifest["files"]
    if not isinstance(files, list) or not files:
        raise StagedRuntimeError("manifest files must be a non-empty list")
    seen: Set[str] = set()
    for item in files:
        if not isinstance(item, dict):
            raise StagedRuntimeError("manifest file entry must be an object")
        for key in ("path", "size", "sha256", "role"):
            if key not in item:
                raise StagedRuntimeError(
                    f"manifest file entry missing field: {key}"
                )
        normalized = check_manifest_path(str(item["path"]))
        if normalized in seen:
            raise StagedRuntimeError(
                f"manifest duplicate path: {item['path']!r}"
            )
        seen.add(normalized)
        if not isinstance(item["size"], int) or item["size"] < 0:
            raise StagedRuntimeError(
                f"manifest invalid size for {item['path']!r}"
            )
    return manifest


# --------------------------------------------------------------------------
# Staging
# --------------------------------------------------------------------------


def _current_python_version() -> str:
    v = sys.version_info
    return f"{v.major}.{v.minor}.{v.micro}"


@dataclass
class BuildResult:
    ready: bool
    root: Path
    manifest: Dict[str, object]
    tree_hash_value: str
    file_count: int
    total_bytes: int


def collect_cpython_files(python_home: Path) -> List[Tuple[Path, str, str]]:
    """Inventory (source, staged-relpath, role) for the CPython runtime."""
    python_home = Path(python_home)
    planned: List[Tuple[Path, str, str]] = []
    for name in CPYTHON_TOP_FILES:
        source = python_home / name
        if not source.is_file() or _is_reparse(source):
            raise StagedRuntimeError(
                f"CPython runtime file missing or reparse: {name}"
            )
        planned.append((source, f"runtime/{name}", _ROLE_CPYTHON_EXE))
    for dirname in CPYTHON_STDLIB_DIRS:
        basedir = python_home / dirname
        if not basedir.is_dir():
            raise StagedRuntimeError(
                f"CPython runtime dir missing: {dirname}"
            )
        for dirpath, dirnames, filenames in os.walk(basedir):
            dirnames[:] = sorted(
                d
                for d in dirnames
                if d not in STDLIB_SKIP_DIR_NAMES
                and not _is_reparse(Path(dirpath) / d)
            )
            for filename in sorted(filenames):
                source = Path(dirpath) / filename
                if _is_reparse(source):
                    raise StagedRuntimeError(
                        f"reparse point refused in CPython tree: {source}"
                    )
                rel = source.relative_to(python_home).as_posix()
                role = (
                    _ROLE_CPYTHON_DLL
                    if dirname == "DLLs"
                    else _ROLE_CPYTHON_STDLIB
                )
                planned.append((source, f"runtime/{rel}", role))
    if not planned:
        raise StagedRuntimeError("CPython inventory is empty")
    return planned


def collect_worker_files(
    repo_src: Path, closure: ClosureResult
) -> List[Tuple[Path, str, str]]:
    planned: List[Tuple[Path, str, str]] = []
    for module in sorted(closure.modules):
        rel = closure.modules[module]
        check_manifest_path(rel)
        _check_credential_name(rel)
        source = Path(repo_src) / rel
        if _is_reparse(source):
            raise StagedRuntimeError(
                f"reparse point refused in worker source: {rel}"
            )
        if not source.is_file():
            raise StagedRuntimeError(f"worker source vanished: {rel}")
        staged = f"worker/{rel}"
        check_manifest_path(staged)
        planned.append((source, staged, _ROLE_WORKER))
    if not planned:
        raise StagedRuntimeError("worker closure is empty")
    return planned


def inventory_runtime(
    python_home: Path, repo_src: Path, entry: str = WORKER_ENTRY_DEFAULT
) -> Dict[str, object]:
    """Dry-run metrics without copying (no READY claim)."""
    closure = resolve_closure(repo_src, entry)
    cpython = collect_cpython_files(python_home)
    worker = collect_worker_files(repo_src, closure)
    total = sum(s.stat().st_size for s, _, _ in cpython + worker)
    return {
        "entry": entry,
        "closure_modules": sorted(closure.modules),
        "closure_file_count": len(closure.modules),
        "third_party": closure.third_party,
        "skipped_optional": list(closure.skipped_optional),
        "cpython_file_count": len(cpython),
        "worker_file_count": len(worker),
        "total_files": len(cpython) + len(worker),
        "total_bytes": total,
    }


def _copy_staged(planned: List[Tuple[Path, str, str]], staging: Path) -> None:
    for source, rel, _role in planned:
        dest = staging / Path(*rel.split("/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Never follow symlinks; refuse them outright.
        if _is_reparse(source):
            raise StagedRuntimeError(f"reparse source refused: {source}")
        shutil.copyfile(source, dest)
        shutil.copystat(source, dest)


@dataclass
class VerifyResult:
    ok: bool
    errors: List[str] = field(default_factory=list)
    manifest: Optional[Dict[str, object]] = None
    tree_hash_value: str = ""
    file_count: int = 0
    total_bytes: int = 0


def verify_runtime(root: Path) -> VerifyResult:
    """Exact-tree verification: actual tree == manifest tree."""
    root = Path(root)
    errors: List[str] = []
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file():
        return VerifyResult(ok=False, errors=["manifest.json missing"])
    try:
        manifest = parse_manifest(manifest_path.read_bytes())
    except StagedRuntimeError as exc:
        return VerifyResult(ok=False, errors=[f"manifest invalid: {exc}"])
    expected = {
        str(item["path"]): item for item in manifest["files"]  # type: ignore[index]
    }
    actual: Dict[str, Path] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        for name in list(dirnames):
            full = current / name
            if _is_reparse(full):
                errors.append(f"reparse point in staged tree: {full}")
            if name in _FORBIDDEN_DIR_NAMES:
                rel_dir = full.relative_to(root).as_posix()
                errors.append(f"forbidden directory in staged tree: {rel_dir}")
        dirnames[:] = sorted(dirnames)
        for filename in filenames:
            full = current / filename
            if _is_reparse(full):
                errors.append(f"reparse point in staged tree: {full}")
                continue
            rel = full.relative_to(root).as_posix()
            if rel == MANIFEST_NAME:
                continue
            if rel in actual:
                errors.append(f"duplicate staged path: {rel}")
            actual[rel] = full
            if _is_sensitive_tree_name(filename):
                errors.append(f"sensitive filename in staged tree: {rel}")
    for rel in sorted(set(expected) - set(actual)):
        errors.append(f"missing staged file: {rel}")
    for rel in sorted(set(actual) - set(expected)):
        errors.append(f"unexpected staged file: {rel}")
    checked = 0
    total_bytes = 0
    for rel in sorted(set(expected) & set(actual)):
        item = expected[rel]
        size, digest = sha256_file(actual[rel])
        total_bytes += size
        checked += 1
        if size != item["size"]:
            errors.append(
                f"size mismatch: {rel} (manifest {item['size']}, actual {size})"
            )
        if digest != item["sha256"]:
            errors.append(f"hash mismatch: {rel}")
    records = [
        FileRecord(
            path=rel,
            size=int(expected[rel]["size"]),
            sha256=str(expected[rel]["sha256"]),
            role=str(expected[rel]["role"]),
        )
        for rel in sorted(set(expected) & set(actual))
    ]
    computed = tree_hash(records) if records else ""
    manifest_tree = str(manifest.get("tree_hash", ""))
    if records and computed != manifest_tree:
        errors.append("tree_hash mismatch: manifest tampered or inconsistent")
    entry_top = str(manifest.get("entry_module", "")).split(".")[0]
    worker_tops = {
        p.split("/")[1]
        for p in actual
        if p.startswith("worker/") and "/" in p[7:]
    }
    if not entry_top or worker_tops - {entry_top}:
        errors.append(
            f"worker tree escapes package confinement: {sorted(worker_tops)}"
        )
    return VerifyResult(
        ok=not errors,
        errors=errors,
        manifest=manifest,
        tree_hash_value=manifest_tree,
        file_count=checked,
        total_bytes=total_bytes,
    )


def runtime_ready(root: Path) -> bool:
    """Machine-readable READY gate: verification passes, nothing else."""
    return verify_runtime(root).ok


def build_runtime(
    dest: Path,
    *,
    python_home: Path,
    repo_src: Path,
    entry: str = WORKER_ENTRY_DEFAULT,
    source_revision: str = "unknown",
    python_version: Optional[str] = None,
    architecture: Optional[str] = None,
    allow_third_party: FrozenSet[str] = frozenset(),
) -> BuildResult:
    """Build, hash, manifest, self-verify, then atomically promote.

    Raises before copying anything when the closure needs non-allowlisted
    third-party packages. Any later failure removes the temporary staging
    directory; *dest* is created ONLY by atomic rename after successful
    self-verification, so a failed build never becomes READY.
    """
    dest = Path(dest)
    if dest.exists():
        raise StagedRuntimeError(f"destination already exists: {dest}")
    closure = resolve_closure(repo_src, entry)
    blocked = {
        module: tuple(p for p in pkgs if p not in allow_third_party)
        for module, pkgs in closure.third_party.items()
    }
    blocked = {k: v for k, v in blocked.items() if v}
    if blocked:
        raise ThirdPartyBlocked(blocked)
    planned = collect_cpython_files(python_home) + collect_worker_files(
        repo_src, closure
    )
    staging = dest.parent / f".{dest.name}.build-{uuid.uuid4().hex[:8]}"
    try:
        staging.mkdir(parents=True, exist_ok=False)
        _copy_staged(planned, staging)
        records: List[FileRecord] = []
        for _source, rel, role in planned:
            size, digest = sha256_file(staging / Path(*rel.split("/")))
            records.append(
                FileRecord(path=rel, size=size, sha256=digest, role=role)
            )
        manifest = build_manifest(
            entry=entry,
            python_version=python_version or _current_python_version(),
            architecture=architecture
            or os.environ.get("PROCESSOR_ARCHITECTURE", "unknown"),
            source_revision=source_revision,
            records=records,
        )
        (staging / MANIFEST_NAME).write_bytes(canonical_manifest_bytes(manifest))
        result = verify_runtime(staging)
        if not result.ok:
            raise StagedRuntimeError(
                "self-verification failed: " + "; ".join(result.errors[:5])
            )
        os.rename(staging, dest)
    except BaseException:
        try:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=False)
        except OSError as cleanup_exc:
            raise StagedRuntimeError(
                f"build failed AND staging cleanup failed: {cleanup_exc}"
            ) from cleanup_exc
        raise
    return BuildResult(
        ready=True,
        root=dest,
        manifest=manifest,
        tree_hash_value=str(manifest["tree_hash"]),
        file_count=len(records),
        total_bytes=sum(r.size for r in records),
    )
