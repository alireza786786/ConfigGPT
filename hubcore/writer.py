# -*- coding: utf-8 -*-
"""Atomic filesystem persistence for Phase 12 OutputBundles (Phase 13).

Turns an in-memory :class:`~hubcore.output.OutputBundle` into the files
the legacy pipeline published, under a caller-chosen output root. This is
the only phase allowed to touch the filesystem, and it is deliberately
narrow: it writes the bytes Phase 12 already produced, verbatim.

CONTRACT
* BYTE FIDELITY - each artifact is written as ``text.encode(encoding)``
  through a BINARY handle, so Phase 12's CRLF line contract survives
  untouched. A text-mode handle would translate every LF into CRLF on
  this platform and turn ``\\r\\n`` into ``\\r\\r\\n``; that is the single
  most likely persistence bug and it is pinned by tests.
* ATOMICITY - content goes to a uniquely named temporary file in the
  DESTINATION directory, is flushed and fsynced, then moved into place
  with ``os.replace``. A failure at any point leaves the previous file
  exactly as it was and no temporary file behind, so a reader can never
  observe a half-written artifact.
* IDEMPOTENCE - with ``skip_identical`` (the default) an artifact whose
  bytes already match is reported ``unchanged`` and not rewritten, so
  repeated runs are no-ops.
* CONTAINMENT - every artifact path is validated before use: absolute
  paths, drive-qualified paths, NUL bytes, empty / ``.`` / ``..``
  segments and colons are refused, and the resolved parent directory must
  stay inside the resolved output root. A destination that is itself a
  symlink is refused, so a hostile link cannot redirect a write outside
  the root.
* ALIAS SAFETY - two artifact paths that would land on the SAME file on a
  case-insensitive or trailing-character-stripping filesystem (Windows and
  macOS defaults), and reserved device names (``NUL``, ``CON``, ``COM1``,
  ...), are refused up front. Letting two artifacts race for one filename
  would silently lose one of them while still reporting success.
* ENCODING - the Phase 12 contract is UTF-8, so only UTF-8 (and its
  aliases) is accepted; no other codec can be selected.
* NO MANGLING - nothing is de-duplicated, re-encoded, normalised, renamed
  or deleted, and stale artifacts from an earlier run are NOT pruned
  (pruning is a product decision, not a writer's).

NOT IN THIS PHASE (deliberately): no network access of any kind (no DNS,
no HTTP, no URL fetch), no messaging integrations, no process spawning, no
``eval``/``exec``, no environment or secret reads, no clock usage, no CLI,
no scheduling/CI, no pruning, and no change to Phase 1-12 code.
Exceptions never carry file content, URLs or credentials - only the
relative path and a short reason code.
"""
from __future__ import annotations

import codecs
import errno
import ntpath
import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Optional

from hubcore.output import OutputBundle

__all__ = [
    "DEFAULT_ENCODING",
    "DEFAULT_ROOT",
    "TEMP_FILE_PREFIX",
    "TEMP_FILE_SUFFIX",
    "MAX_RELATIVE_PATH",
    "WriterPolicy",
    "OutputFile",
    "WrittenFile",
    "WriteOutcome",
    "WriterError",
    "UnsafeOutputPathError",
    "WriteFailedError",
    "validate_relative_path",
    "plan_outputs",
    "write_outputs",
    "write_text",
    "write_bytes",
]

DEFAULT_ENCODING = "utf-8"
DEFAULT_ROOT = "."
TEMP_FILE_PREFIX = ".hubcore-tmp-"
TEMP_FILE_SUFFIX = ".part"
MAX_RELATIVE_PATH = 512          # defensive cap on one artifact path

# Windows reserved device names: on such a system "NUL.txt" still names the
# NUL device, so a write can appear to succeed while the data is discarded.
# Refused on every platform so behaviour never depends on the host.
_RESERVED_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{i}" for i in range(10)}
    | {f"LPT{i}" for i in range(10)}
)

# artifact kinds produced from an OutputBundle (audit labels only)
KIND_ALL = "all"
KIND_ALL_BASE64 = "all_base64"
KIND_PROTOCOL = "protocol"
KIND_TRANSPORT = "transport"
KIND_COUNTRY = "country"
KIND_TIER = "tier"


# ----------------------------------------------------------------------
# errors (never carry content, URLs or credentials)
# ----------------------------------------------------------------------
class WriterError(ValueError):
    """Base class for writer contract failures."""


class UnsafeOutputPathError(WriterError):
    """An artifact path would leave the output root or is malformed."""


class WriteFailedError(WriterError):
    """A filesystem operation failed; the previous file was left intact."""

    def __init__(self, path: str, reason: str, operation: str = "write"):
        self.path = path
        self.reason = reason
        self.operation = operation
        super().__init__(f"failed to {operation} {path!r} ({reason})")


def _reason_for(exc: BaseException) -> str:
    """Short, content-free reason code for a filesystem failure."""
    if isinstance(exc, PermissionError):
        return "permission_denied"
    if isinstance(exc, IsADirectoryError):
        return "is_a_directory"
    if isinstance(exc, NotADirectoryError):
        return "not_a_directory"
    if isinstance(exc, FileExistsError):
        # a file where a directory belongs (os.makedirs(exist_ok=True))
        return "path_is_a_file"
    if isinstance(exc, FileNotFoundError):
        return "missing_directory"
    code = getattr(exc, "errno", None)
    if code == errno.ENOSPC:
        return "no_space"
    if code == errno.EROFS:
        return "read_only_filesystem"
    if code in (errno.ENAMETOOLONG,):
        return "name_too_long"
    if code == errno.EMFILE or code == errno.ENFILE:
        return "too_many_open_files"
    if isinstance(exc, OSError):
        return "io_error"
    return "unexpected_error"


# ----------------------------------------------------------------------
# policy / records
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class WriterPolicy:
    """Where and how the bundle is persisted (values are the defaults)."""

    root: str = DEFAULT_ROOT
    encoding: str = DEFAULT_ENCODING
    create_root: bool = True
    create_dirs: bool = True
    skip_identical: bool = True


@dataclass(frozen=True)
class OutputFile:
    """One planned artifact: its relative path, exact text and kind."""

    path: str          # validated, POSIX-style, relative
    text: str
    kind: str = KIND_ALL


@dataclass(frozen=True)
class WrittenFile:
    """Outcome for one artifact."""

    path: str
    size: int
    changed: bool


@dataclass(frozen=True)
class WriteOutcome:
    """Result of persisting one bundle."""

    root: str
    files: tuple = ()          # tuple[WrittenFile, ...]
    written: int = 0           # artifacts whose bytes changed on disk
    unchanged: int = 0         # artifacts already identical
    bytes_written: int = 0

    @property
    def total(self) -> int:
        return len(self.files)

    @property
    def paths(self) -> tuple:
        return tuple(item.path for item in self.files)


# ----------------------------------------------------------------------
# path validation (pure; no I/O)
# ----------------------------------------------------------------------
def validate_relative_path(relpath) -> str:
    """Return a canonical relative POSIX path or refuse it.

    Refused: non-text, empty, over-long, NUL bytes, absolute paths,
    drive-qualified paths (``C:\\x``), UNC/rooted forms, and any empty,
    ``.`` or ``..`` segment. A colon inside a segment is refused as well
    (drive letters and Windows alternate data streams).
    """
    if not isinstance(relpath, str):
        raise UnsafeOutputPathError("output path must be text")
    if not relpath:
        raise UnsafeOutputPathError("output path must not be empty")
    if len(relpath) > MAX_RELATIVE_PATH:
        raise UnsafeOutputPathError("output path is too long")
    if "\x00" in relpath:
        raise UnsafeOutputPathError("output path contains a NUL byte")
    text = relpath.replace("\\", "/")
    if text.startswith("/"):
        raise UnsafeOutputPathError("absolute output paths are refused")
    if ntpath.splitdrive(text)[0]:
        raise UnsafeOutputPathError("drive-qualified output paths are refused")
    parts = text.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise UnsafeOutputPathError(
                "output path must not contain empty, '.' or '..' segments")
        if ":" in part:
            raise UnsafeOutputPathError(
                "output path segment must not contain a colon")
        if part[-1] in (".", " "):
            # Windows strips trailing dots/spaces, so "a.txt." would alias
            # "a.txt" and two artifacts would share one file
            raise UnsafeOutputPathError(
                "output path segment must not end with a dot or a space")
        if part.split(".", 1)[0].upper() in _RESERVED_DEVICE_NAMES:
            raise UnsafeOutputPathError(
                "output path segment is a reserved device name")
    return PurePosixPath(*parts).as_posix()


def _is_within(root: str, path: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _join_inside(real_root: str, relpath: str) -> str:
    return os.path.join(real_root, *relpath.split("/"))


# ----------------------------------------------------------------------
# planning (pure; no I/O)
# ----------------------------------------------------------------------
def _bundle_artifacts(bundle: OutputBundle):
    """Every artifact of a bundle, in a deterministic order."""
    yield bundle.all_text, KIND_ALL, "all.txt"
    yield bundle.all_base64, KIND_ALL_BASE64, "all_b64.txt"
    for path, text in bundle.by_protocol.items():
        yield text, KIND_PROTOCOL, path
    for path, text in bundle.by_transport.items():
        yield text, KIND_TRANSPORT, path
    for group in bundle.by_country:
        yield group.text, KIND_COUNTRY, group.path
    for path, text in bundle.ping_tiers.items():
        yield text, KIND_TIER, path


def plan_outputs(bundle: OutputBundle) -> tuple:
    """Validate a bundle into an ordered tuple of :class:`OutputFile`.

    Pure: no directory is touched. Every path is validated here, so a
    bundle that somehow carried a hostile path can never reach the
    filesystem layer.
    """
    if not isinstance(bundle, OutputBundle):
        raise WriterError(
            f"bundle must be an OutputBundle (got {type(bundle).__name__})")
    files = []
    seen = set()
    folded = {}
    for text, kind, relpath in _bundle_artifacts(bundle):
        if not isinstance(text, str):
            raise WriterError(f"artifact {relpath!r} is not text")
        path = validate_relative_path(relpath)
        if path in seen:
            raise WriterError(f"duplicate output path: {path}")
        key = path.casefold()
        clash = folded.get(key)
        if clash is not None:
            # refused even on a case-sensitive host: the same bundle would
            # lose an artifact on Windows/macOS
            raise WriterError(
                f"output paths differ only by case: {clash!r} and {path!r}")
        seen.add(path)
        folded[key] = path
        files.append(OutputFile(path=path, text=text, kind=kind))
    return tuple(files)


# ----------------------------------------------------------------------
# policy validation
# ----------------------------------------------------------------------
def _validate_policy(policy) -> None:
    if not isinstance(policy, WriterPolicy):
        raise WriterError(
            f"policy must be a WriterPolicy (got {type(policy).__name__})")
    if not isinstance(policy.root, str) or not policy.root.strip():
        raise WriterError("policy.root must be a non-empty path")
    if not isinstance(policy.encoding, str):
        raise WriterError("policy.encoding must be text")
    try:
        resolved = codecs.lookup(policy.encoding).name
    except (LookupError, TypeError):
        raise WriterError(f"unknown encoding: {policy.encoding!r}")
    if resolved != "utf-8":
        # the Phase 12 line/encoding contract is UTF-8; no other codec is
        # selectable, so artifacts can never drift to another encoding
        raise WriterError(
            f"only UTF-8 is supported (got {policy.encoding!r})")


# ----------------------------------------------------------------------
# atomic single-artifact write
# ----------------------------------------------------------------------
def _makedirs(policy: WriterPolicy, path: str, relpath: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as exc:
        raise WriteFailedError(relpath, _reason_for(exc), "create directory")


def _containment_check(real_root: str, target: str, relpath: str) -> None:
    parent = os.path.dirname(target)
    real_parent = os.path.realpath(parent)
    if not _is_within(real_root, real_parent):
        raise UnsafeOutputPathError(
            f"output path escapes the output root: {relpath!r}")
    if os.path.islink(target):
        raise UnsafeOutputPathError(
            f"refusing to write through a symbolic link: {relpath!r}")


def _cleanup(temp_path: Optional[str]) -> None:
    if not temp_path:
        return
    try:
        os.unlink(temp_path)
    except OSError:
        pass          # best effort: never mask the original failure


def _close_fd(fd) -> None:
    """Close a raw descriptor, ignoring failures (used on failure paths)."""
    if fd is None:
        return
    try:
        os.close(fd)
    except OSError:
        pass


# One lock per resolved destination path, so two threads in this process
# can never race the same artifact. On Windows a concurrent
# ``os.replace`` onto one destination fails with a sharing violation
# (surfacing as permission_denied) even though every individual rename is
# atomic; serialising per target removes that self-inflicted failure while
# keeping cross-process behaviour safe (last writer wins, never a torn
# file). The table is bounded by the number of distinct artifact paths.
_LOCKS: dict = {}
_LOCKS_GUARD = threading.Lock()


def _target_lock(target: str) -> "threading.Lock":
    with _LOCKS_GUARD:
        lock = _LOCKS.get(target)
        if lock is None:
            lock = threading.Lock()
            _LOCKS[target] = lock
        return lock


def _same_bytes(target: str, data: bytes) -> bool:
    try:
        if os.path.getsize(target) != len(data):
            return False
        with open(target, "rb") as handle:
            return handle.read() == data
    except OSError:
        return False      # unreadable -> cannot skip, so rewrite


def write_bytes(policy: WriterPolicy, relpath: str, data: bytes) -> WrittenFile:
    """Atomically persist one artifact's raw bytes under ``policy.root``."""
    _validate_policy(policy)
    path = validate_relative_path(relpath)
    if not isinstance(data, (bytes, bytearray)):
        raise WriterError("artifact data must be bytes")

    payload = bytes(data)
    real_root = os.path.realpath(policy.root)
    parts = path.split("/")
    if policy.create_root:
        _makedirs(policy, real_root, path)
    if policy.create_dirs and len(parts) > 1:
        # only the SUB-directories are policy-controlled here; the root
        # itself is governed by create_root, so "create_root=False" on a
        # missing root still fails honestly instead of being created
        # implicitly as a side effect of creating a sub-directory
        _makedirs(policy, os.path.join(real_root, *parts[:-1]), path)

    target = _join_inside(real_root, path)
    _containment_check(real_root, target, path)

    with _target_lock(target):
        # re-check under the lock: a sibling thread may have just written
        # exactly these bytes
        if policy.skip_identical and os.path.exists(target) and _same_bytes(target, payload):
            return WrittenFile(path=path, size=len(payload), changed=False)
        _atomic_replace(target, path, payload)
    return WrittenFile(path=path, size=len(payload), changed=True)


def _atomic_replace(target: str, path: str, payload: bytes) -> None:
    """Write ``payload`` to a temp file then move it onto ``target``.

    Raises :class:`WriteFailedError` on any failure, leaving the previous
    ``target`` untouched and removing every temporary file created.
    """
    parent = os.path.dirname(target)
    temp_path = None
    try:
        fd, temp_path = tempfile.mkstemp(prefix=TEMP_FILE_PREFIX,
                                         suffix=TEMP_FILE_SUFFIX, dir=parent)
    except OSError as exc:
        raise WriteFailedError(path, _reason_for(exc), "create temporary file")

    handle = None
    try:
        try:
            handle = os.fdopen(fd, "wb")
        except BaseException as exc:
            # own the raw descriptor until it is wrapped: leaking it would
            # not only leak a handle, it would make the temporary file
            # impossible to delete on Windows (open files cannot be
            # unlinked), leaving debris next to the artifacts
            _close_fd(fd)
            fd = None               # never close a recycled descriptor number
            if isinstance(exc, OSError):
                raise WriteFailedError(path, _reason_for(exc), "open temporary file")
            raise
        fd = None
        try:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        except OSError as exc:
            raise WriteFailedError(path, _reason_for(exc), "write")
        finally:
            try:
                handle.close()
            except OSError:
                pass
            handle = None
        try:
            os.replace(temp_path, target)
        except OSError as exc:
            raise WriteFailedError(path, _reason_for(exc), "replace")
        temp_path = None            # moved into place: nothing to clean up
    finally:
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass
        _close_fd(fd)               # leaked only if wrapping was interrupted
        _cleanup(temp_path)


def write_text(policy: WriterPolicy, relpath: str, text: str) -> WrittenFile:
    """Atomically persist one artifact as encoded text (binary write)."""
    if not isinstance(text, str):
        raise WriterError("artifact text must be str")
    _validate_policy(policy)
    return write_bytes(policy, relpath, text.encode(policy.encoding))


# ----------------------------------------------------------------------
# whole-bundle write
# ----------------------------------------------------------------------
def write_outputs(bundle: OutputBundle, policy: Optional[WriterPolicy] = None) -> WriteOutcome:
    """Persist every artifact of a bundle under ``policy.root``.

    Idempotent: re-running with the same bundle reports every artifact as
    unchanged and rewrites nothing. Deterministic: artifacts are written in
    :func:`plan_outputs` order and their bytes are exactly the bundle's.
    """
    policy = policy or WriterPolicy()
    _validate_policy(policy)
    files = plan_outputs(bundle)

    written = []
    for item in files:
        written.append(write_text(policy, item.path, item.text))

    return WriteOutcome(
        root=policy.root,
        files=tuple(written),
        written=sum(1 for item in written if item.changed),
        unchanged=sum(1 for item in written if not item.changed),
        bytes_written=sum(item.size for item in written if item.changed),
    )
