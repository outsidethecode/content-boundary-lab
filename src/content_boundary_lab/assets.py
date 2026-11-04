"""Production-scoped asset access: the one query that decides which asset a caller can reach.

`get_asset_in_scope` binds, in a single parameterised SELECT, the asset, its real production, the production the request
named, the caller's verified (issuer, subject), a current and unrevoked engagement in that production, and the one
instant the request captured. An asset that is missing, belongs to another production, or is not one the caller is
currently engaged for gives the same answer (None), and the caller cannot tell which. There is no way in this package to
read an asset by its id alone: tests/guards/test_asset_scope.py fails if any other SQL touches the table.

This is the F-02 seam (M0 addendum, `get_asset_in_scope`). The vulnerable variant checks only the production in the URL
and then loads the asset by id; the reference never does, because the asset's own production_id is part of the same
statement as the caller's engagement in it. The role (may this engagement read assets at all) is the request flow's
authorisation, made in the same transaction on the same instant; this query does not repeat the policy.

The schema has no asset state, and none is invented here: M0's lifecycle states (SEALING, SCAN_PASSED, ACCEPTED,
PROMOTING, PROMOTED, INTEGRITY_FAILED) belong to deliveries, and quarantined bytes live in a separate root that this
module never reads. A row in `assets` is the readable set.

The write side (M1K). This module is also the only code that writes the trusted root, through a small set of primitives
that promotion.py orchestrates. Inside the root:

    <root>/.staging/<name>   bytes being verified into the trusted root, or verified and not yet published; <name> is the
                             promotion attempt's own server-made id (32 lowercase hexadecimal characters)
    <root>/<asset id>        the bytes of one asset; the key is the asset's own server-generated id

As in the quarantine root, every operation opens the root as a directory without following a symlink in its last component
and works relative to that descriptor with one basename that has been checked to be 32 lowercase hexadecimal characters
(or the fixed name `.staging`). No client text is ever a path component. A staged file is created with O_EXCL and mode
0600, and the bytes are counted and hashed as they are written, so what is reported is what the file holds. Publication
is a hard link that the kernel refuses when anything at all occupies the final name, so nothing is ever replaced, and the
staged name stays until the caller has committed. The only deletions are of a staged name and, by device and inode, of
the exact file a writer has just published; a file that was already there is never this module's to remove.

Assumptions, stated. The root is a local directory that untrusted users cannot write to, and its parent directories are
followed like any configured path. A hard link planted by someone who can already write into it is invisible to a
no-follow open. The file and the directory are synced before a publication is reported, which orders the writes; it does
not claim durability across a power failure on every filesystem (on macOS `fsync` does not force the drive's cache).
"""

import functools
import hashlib
import os
import re
import sqlite3
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from fastapi import Request
from fastapi.responses import Response

from content_boundary_lab import audit, authz, request_flow
from content_boundary_lab.clock import Clock
from content_boundary_lab.identity import VerifiedIdentity
from content_boundary_lab.settings import TrustedSettings
from content_boundary_lab.store import StoreError

PATH = "/productions/{production_id:path}/assets/{asset_id:path}"
_ID = re.compile(r"[0-9a-f]{32}")  # the shape of every id the store generates
_LOOKUP = (
    "SELECT a.id, a.production_id, a.display_name, a.created_at FROM assets AS a "
    "JOIN engagements AS e ON e.production_id = a.production_id "
    "JOIN subjects AS s ON s.id = e.subject_id "
    "WHERE a.id = ? AND a.production_id = ? AND s.issuer = ? AND s.subject = ? "
    "AND e.revoked_at IS NULL AND e.ends_at > ?"
)


@dataclass(frozen=True)
class Asset:
    """An asset the caller may read. display_name is metadata exactly as stored; it is never used to build a path."""

    id: str
    production_id: str
    display_name: str
    created_at: int


def _check_id(name: str, value: object) -> None:
    if type(value) is not str:
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not _ID.fullmatch(value):
        raise ValueError(f"{name} must be 32 lowercase hexadecimal characters")  # the value is never echoed


def get_asset_in_scope(
    conn: sqlite3.Connection, caller: VerifiedIdentity, production_id: str, asset_id: str, now_micros: int
) -> Asset | None:
    """The asset, if `caller` is currently engaged in the production that owns it and the request named that production.

    The caller owns the transaction (the request flow's BEGIN IMMEDIATE) and supplies the one instant of the request:
    this reads no clock, writes nothing, and neither commits nor rolls back. Malformed ids and instants are the caller's
    fault and raise before any SQL runs (TypeError or ValueError); they are not "not found".
    """
    if not isinstance(caller, VerifiedIdentity):
        raise TypeError("caller must be a VerifiedIdentity")
    _check_id("production_id", production_id)
    _check_id("asset_id", asset_id)
    if type(now_micros) is not int:
        raise TypeError("now_micros must be an int (a bool is not accepted)")
    if not conn.in_transaction:
        raise StoreError("an asset lookup must run inside the caller's transaction")
    row = conn.execute(_LOOKUP, (asset_id, production_id, caller.issuer, caller.subject, now_micros)).fetchone()
    return None if row is None else Asset(row[0], row[1], row[2], row[3])


class AssetStorageError(OSError):
    """The stored bytes of a trusted asset cannot be used as they are: an integrity failure, never a download."""


def open_asset_file(asset_root: Path, asset: Asset) -> request_flow.Download:
    """Open the bytes of `asset` under the trusted root, and hand over the open file. Ownership passes to the caller.

    The storage key is the asset's own id, one opaque basename (32 lowercase hexadecimal characters, which the schema
    guarantees for every row and this function checks again), so no path component can come from a request, a filename or
    a display name. The root is opened as a directory without following a symlink in its last component, the file is
    opened relative to that descriptor with no-follow and non-blocking flags (a named pipe cannot hold the request), and
    fstat on the descriptor that was opened decides whether it is a regular file. The size comes from that descriptor and
    the bytes are streamed from it: the path is never opened a second time, so a name replaced after this point changes
    nothing. The descriptor is closed on every failure here.

    A missing, unreadable, non-regular or symlinked entry raises (FileNotFoundError, PermissionError, OSError,
    AssetStorageError): a row that the lookup found but whose bytes cannot be used is an operational integrity failure.

    Assumptions, stated: the root is local, trusted configuration that untrusted users cannot write to; its parent
    directories are followed like any configured path; and a hard link planted by someone who can already write into the
    root is invisible to a no-follow open. Nothing here verifies the content against a hash: that is a later milestone's.
    """
    if not isinstance(asset_root, Path):
        raise TypeError("asset_root must be a Path")
    if not asset_root.is_absolute():
        raise ValueError("asset_root must be an absolute path")
    _check_id("asset_id", asset.id)
    if os.open not in os.supports_dir_fd:
        raise AssetStorageError("this platform cannot open a file relative to a directory descriptor")
    root_fd = os.open(asset_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(asset.id, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=root_fd)
    finally:
        os.close(root_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise AssetStorageError("the stored entry for an asset is not a regular file")
        handle = os.fdopen(fd, "rb")  # the file object now owns the descriptor
    except BaseException:
        os.close(fd)  # only reached while the descriptor is still ours
        raise
    return request_flow.Download(handle, info.st_size, asset.display_name)


def _read(ctx: request_flow.Context, asset_id: str, asset_root: Path) -> request_flow.Decision:
    """Look the asset up in scope, open its bytes, record the read, and hand the open file to the flow."""
    if not _ID.fullmatch(asset_id):  # the text is never looked up and never recorded as an object
        return request_flow.not_found(ctx, audit.AuditReason.INVALID_IDENTIFIER)
    asset = get_asset_in_scope(ctx.conn, ctx.caller, ctx.production_id, asset_id, ctx.now_micros)
    if asset is None:  # missing, in another production, or not one this caller is engaged for: one and the same answer
        return request_flow.not_found(
            ctx,
            audit.AuditReason.NOT_FOUND_OR_FORBIDDEN,
            object_type=audit.ObjectType.ASSET,
            object_id=asset_id,
        )
    download = open_asset_file(asset_root, asset)  # before anything is recorded: a missing file is never a successful read
    try:
        audit.record_event(
            ctx.conn,
            ctx.clock,
            audit.AuditAction.ASSET_READ,
            audit.Outcome.ALLOWED,
            actor=ctx.caller.as_actor(),
            production_id=ctx.production_id,
            object_type=audit.ObjectType.ASSET,
            object_id=asset.id,
        )
    except BaseException:
        download.close()  # the flow owns the file only once this function has returned it
        raise
    return request_flow.Decision(200, {}, download=download)


def build_endpoint(
    settings: TrustedSettings, clock: Clock, database_path: Path, asset_root: Path
) -> Callable[[str, str, Request], Response]:
    """The handler for GET .../assets/{asset_id}. The response is built by the flow, after the commit."""

    # A plain def, so the framework runs it in a worker thread: the SQLite connection is opened and used there.
    def read_asset(production_id: str, asset_id: str, request: Request) -> Response:
        return request_flow.handle(
            settings,
            clock,
            database_path,
            production_id=production_id,
            authorization=request_flow.authorization_value(request),
            action=authz.Action.READ_ASSET,
            operation=functools.partial(_read, asset_id=asset_id, asset_root=asset_root),
        )

    return read_asset


# --- writing the trusted root (M1K) ------------------------------------------------------------------------------------

STAGING = ".staging"
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_STAGED = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_BLOCK = 64 * 1024


class StagingTooLarge(Exception):
    """More bytes were written than the limit allows. Nothing of the chunk that crossed it was written."""


@dataclass(frozen=True)
class Written:
    """What a staged file holds: the number of bytes, their SHA-256 (hexadecimal), the staged name, device and inode.

    These are counted and hashed from the bytes as they were written and checked against the size of the file on disk,
    never copied from anyone's claim. device and inode identify the file: publishing adds a name for that same file, so
    afterwards they are how the writer, and only the writer, recognises it at the final name.
    """

    size: int
    sha256: str
    name: str
    device: int
    inode: int


@dataclass(frozen=True)
class Entry:
    """What is at a name in the trusted root, looked at without following anything.

    Two Entry values are equal only if they describe the same file in the same state: the same device and inode, and the
    same size, link count, modification time and status-change time. A file that was written to, touched, linked or
    unlinked, or replaced by another, is not equal to its earlier Entry.
    """

    regular: bool
    device: int
    inode: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


def _check_name(value: object) -> None:
    if type(value) is not str:
        raise TypeError(f"a trusted-root name must be a str, got {type(value).__name__}")
    if not _ID.fullmatch(value):
        raise ValueError("a trusted-root name must be 32 lowercase hexadecimal characters")  # the value is never echoed


def _check_limit(limit: object) -> None:
    if type(limit) is not int:
        raise TypeError(f"limit must be an int, got {type(limit).__name__}")  # a bool is not a size
    if limit < 1:
        raise ValueError("limit must be at least 1")


def _open_root_directory(root: Path) -> int:
    if not isinstance(root, Path):
        raise TypeError("the trusted root must be a Path")
    if not root.is_absolute():
        raise ValueError("the trusted root must be an absolute path")
    if os.open not in os.supports_dir_fd or os.link not in os.supports_dir_fd or os.link not in os.supports_follow_symlinks:
        raise AssetStorageError("this platform cannot open or link a file relative to a directory descriptor")
    return os.open(root, _DIRECTORY)


def _open_staging(root_fd: int, *, create: bool) -> int:
    if create:
        try:
            os.mkdir(STAGING, 0o700, dir_fd=root_fd)
        except FileExistsError:
            pass  # whatever is there is opened below, without following it
    return os.open(STAGING, _DIRECTORY, dir_fd=root_fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


class StagingFile:
    """A file being written into trusted staging: bounded, counted and hashed as it is written, removable. Use create()."""

    def __init__(self, root: Path, name: str, fd: int, limit: int) -> None:
        self.name = name
        self._root = root
        self._fd: int | None = fd
        self._limit = limit
        self._size = 0
        self._digest = hashlib.sha256()
        self._over = False
        self._finished = False

    @classmethod
    def create(cls, root: Path, name: str, limit: int) -> "StagingFile":
        """Stage a new, empty file under `name`, which must not exist: a name that is taken is never reused or overwritten."""
        _check_name(name)
        _check_limit(limit)
        root_fd = _open_root_directory(root)
        try:
            staging_fd = _open_staging(root_fd, create=True)
            try:
                fd = os.open(name, _STAGED, 0o600, dir_fd=staging_fd)
            finally:
                os.close(staging_fd)
        finally:
            os.close(root_fd)
        return cls(root, name, fd, limit)

    def write(self, chunk: bytes) -> None:
        """Append a chunk. The chunk that would cross the limit is not written at all."""
        if self._finished:
            raise RuntimeError("the staged file is finished")
        if self._over or self._size + len(chunk) > self._limit:
            self._over = True
            raise StagingTooLarge("more bytes than the limit allows")
        _write_all(self._fd, chunk)
        self._digest.update(chunk)  # the digest and the count are of what was handed to the file, all of which it took
        self._size += len(chunk)

    def finish(self) -> Written:
        """Flush and close the file, once, and say what it holds. The size is checked against the file on disk."""
        if self._finished:
            raise RuntimeError("the staged file is finished")
        if self._over:
            raise StagingTooLarge("more bytes than the limit allows")
        os.fsync(self._fd)
        info = os.fstat(self._fd)  # of the descriptor that was written, so no path is looked at again
        if info.st_size != self._size:
            raise AssetStorageError("the staged file is not the size of the bytes that were written to it")
        fd, self._fd, self._finished = self._fd, None, True
        os.close(fd)
        return Written(self._size, self._digest.hexdigest(), self.name, info.st_dev, info.st_ino)

    def discard(self) -> None:
        """Close the file if it is open and remove its staged name. It may be repeated; a file already gone is no error."""
        fd, self._fd = self._fd, None
        try:
            if fd is not None:
                os.close(fd)
        finally:
            remove_staged(self._root, self.name)


def publish_staged(root: Path, name: str, asset_id: str) -> None:
    """Give the staged regular file `name` the final name `asset_id`, only if nothing is at `asset_id`. It never replaces.

    The placement is a hard link made relative to the two directory descriptors, which the kernel refuses
    (FileExistsError) when anything at all occupies the destination: a regular file, a directory, a pipe, a symlink, even
    a dangling one. The occupant is then exactly as it was and so is the staged file. The staged name is kept, so the file
    is never without a name and the caller decides when to drop it (after its commit). The directory is synced after the
    link, so the new entry is ordered before whatever the caller does next.

    Only a caller that holds the writer lock in the transaction that moves its delivery out of PROMOTING calls this for an
    asset key. What it created is recognisable afterwards by Written.device and Written.inode, which is how
    remove_if_same_file() avoids ever deleting a file this writer did not place.
    """
    _check_name(name)
    _check_name(asset_id)
    root_fd = _open_root_directory(root)
    try:
        staging_fd = _open_staging(root_fd, create=False)
        try:
            if not stat.S_ISREG(os.stat(name, dir_fd=staging_fd, follow_symlinks=False).st_mode):
                raise AssetStorageError("the staged entry is not a regular file")
            os.link(name, asset_id, src_dir_fd=staging_fd, dst_dir_fd=root_fd, follow_symlinks=False)
            os.fsync(root_fd)
        finally:
            os.close(staging_fd)
    finally:
        os.close(root_fd)


def remove_staged(root: Path, name: str) -> bool:
    """Remove one staged name. True if there was one; a root or staging directory that is gone is not an error.

    A symlink at the name is removed itself and never followed.
    """
    _check_name(name)
    try:
        root_fd = _open_root_directory(root)
    except FileNotFoundError:
        return False
    try:
        try:
            staging_fd = _open_staging(root_fd, create=False)
        except FileNotFoundError:
            return False
        try:
            os.unlink(name, dir_fd=staging_fd)
            return True
        except FileNotFoundError:
            return False
        finally:
            os.close(staging_fd)
    finally:
        os.close(root_fd)


def remove_if_same_file(root: Path, asset_id: str, device: int, inode: int) -> bool:
    """Remove the entry at `asset_id` only if it is the regular file with this device and inode. True if removed.

    This is the only way to delete a file from a final name, and it exists for a writer to take back the file it has just
    published (identity from Written). Anything else at the name is left exactly as it is and reported by False: a
    different file, a symlink (even one that points at the right inode), a directory, a pipe, or nothing.
    """
    _check_name(asset_id)
    for label, value in (("device", device), ("inode", inode)):
        if type(value) is not int:
            raise TypeError(f"{label} must be an int, got {type(value).__name__}")
    root_fd = _open_root_directory(root)
    try:
        try:
            info = os.stat(asset_id, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (device, inode):
            return False
        os.unlink(asset_id, dir_fd=root_fd)
        return True
    finally:
        os.close(root_fd)


def look_at(root: Path, name: str, *, staged: bool = False) -> Entry | None:
    """What is at `name` in the root (or in its staging directory), or None if there is nothing. Nothing is followed."""
    _check_name(name)
    root_fd = _open_root_directory(root)
    try:
        directory_fd = root_fd
        if staged:
            try:
                directory_fd = _open_staging(root_fd, create=False)
            except FileNotFoundError:
                return None
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        finally:
            if directory_fd != root_fd:
                os.close(directory_fd)
        return _entry(info)
    finally:
        os.close(root_fd)


def _entry(info: os.stat_result) -> Entry:
    """The fingerprint of a file: kind, device, inode, links, size, and the two times a write cannot leave alone."""
    return Entry(stat.S_ISREG(info.st_mode), info.st_dev, info.st_ino, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@dataclass(frozen=True)
class Measured:
    """What was read from a file: its size and SHA-256, and the fingerprint of the very file they were read from."""

    size: int
    sha256: str
    entry: Entry


def measure(root: Path, name: str, *, staged: bool = False) -> Measured:
    """Hash and measure the whole of the regular file at `name`, through one no-follow descriptor, and fingerprint it.

    The size is the number of bytes actually read to the end, not a number the file system reports. The fingerprint is of
    the descriptor that was read (fstat), taken before the first byte and again after the last: if the file changed while
    it was read, or if the name no longer leads to that file when the read is done, the result is an error and not a
    measurement. A caller that later finds the same fingerprint at the name knows it is looking at the file that was
    measured. A symlink, a directory, a pipe or nothing at the name is an error (OSError or AssetStorageError).
    """
    _check_name(name)
    root_fd = _open_root_directory(root)
    directory_fd = root_fd
    fd = None
    try:
        if staged:
            directory_fd = _open_staging(root_fd, create=False)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise AssetStorageError("the entry is not a regular file")
        digest, count = hashlib.sha256(), 0
        while block := os.pread(fd, _READ_BLOCK, count):
            digest.update(block)
            count += len(block)
        after = os.fstat(fd)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if _entry(after) != _entry(before) or count != after.st_size or _entry(named) != _entry(after):
            raise AssetStorageError("the file changed while it was being measured, or the name no longer leads to it")
        return Measured(count, digest.hexdigest(), _entry(after))
    finally:
        if fd is not None:
            os.close(fd)
        if directory_fd != root_fd:
            os.close(directory_fd)
        os.close(root_fd)


def staged_names(root: Path) -> tuple[str, ...]:
    """The names in the staging directory, sorted, whatever they are; empty if there is no such directory."""
    root_fd = _open_root_directory(root)
    try:
        try:
            staging_fd = _open_staging(root_fd, create=False)
        except FileNotFoundError:
            return ()
        try:
            return tuple(sorted(os.listdir(staging_fd)))
        finally:
            os.close(staging_fd)
    finally:
        os.close(root_fd)
