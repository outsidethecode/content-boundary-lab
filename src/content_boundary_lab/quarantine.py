"""Quarantine storage: the one place client bytes are written, under names the server made, never followed out.

The quarantine root is a directory the application is configured with (Dependencies.quarantine_root). It is not the
trusted asset root, and no module that knows one knows the other (tests/guards/test_delivery_scope.py). Inside it:

    <root>/.incoming/<name>     bytes still arriving, or arrived and not yet moved; <name> is 32 random hex characters
    <root>/<storage key>        the bytes of one delivery in state UPLOADED or later; the key is the delivery's own
                                server-generated storage key (32 hex characters), never anything a client sent

Every operation opens the root as a directory without following a symlink in its last component and then works relative
to that descriptor with one basename that has been checked to be 32 lowercase hexadecimal characters (the fixed name
`.incoming` is the only other). No client filename, display name, URL text or request header ever becomes a path
component, so there is no `..`, separator or absolute path to resolve and nothing to sanitise. A staged file is made with
O_EXCL (a name that exists is never reused or overwritten) and mode 0600. Bytes are counted, and hashed, as they are
written, chunk by chunk: the limit is on the bytes that actually arrive, and the digest is of the bytes actually kept.
A platform that cannot open or link relative to a directory descriptor fails closed.

Placement never replaces. publish() links the staged file to the storage key, which fails if anything occupies the key,
and only then drops the staged name. A writer recognises the file it placed by its device and inode, and the only deletion
of a file at a storage key (remove_if_same_file) is of exactly that file: a file that was already there is never this
module's to remove, whatever the database says about its delivery.

Assumptions, stated. The root is a local directory that untrusted users cannot write to, and its parent directories are
followed like any configured path. A hard link planted by someone who can already write into it is invisible to a
no-follow open. Nothing here is durable across a power failure: the staged file is flushed before the rename, the
directory is not, and nothing claims otherwise. A network filesystem is not supported.
"""

import hashlib
import io
import os
import re
import secrets
import stat
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

INCOMING = ".incoming"
_NAME = re.compile(r"[0-9a-f]{32}")
_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_STAGED = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


class QuarantineError(OSError):
    """The quarantine directory cannot be used as it must be."""


class UploadTooLarge(Exception):
    """More bytes arrived than the limit allows. Nothing of the chunk that crossed it was written."""


@dataclass(frozen=True)
class Received:
    """What was written: the number of bytes, their SHA-256 (hexadecimal), and the staged file's server-made name.

    device and inode identify the file that was written (st_dev, st_ino). Placing it with publish() adds a name for that
    same file, so afterwards they are how the writer, and only the writer, can recognise its own file at the storage key.
    """

    size: int
    sha256: str
    name: str
    device: int
    inode: int


@dataclass(frozen=True)
class Contents:
    """What is in a quarantine root, sorted, without following anything.

    finals are the regular files named like a storage key; incoming are the regular files staged for upload, as
    (name, modification time in microseconds); foreign is everything else, including a staged-directory entry with a
    name the server never makes (shown as `.incoming/<name>`).
    """

    finals: tuple[str, ...]
    incoming: tuple[tuple[str, int], ...]
    foreign: tuple[str, ...]


def _check_name(value: object) -> None:
    if type(value) is not str:
        raise TypeError(f"a quarantine name must be a str, got {type(value).__name__}")
    if not _NAME.fullmatch(value):
        raise ValueError("a quarantine name must be 32 lowercase hexadecimal characters")  # the value is never echoed


def _check_limit(limit: object) -> None:
    if type(limit) is not int:
        raise TypeError(f"limit must be an int, got {type(limit).__name__}")  # a bool is not a size
    if limit < 1:
        raise ValueError("limit must be at least 1")


def _open_root(root: Path) -> int:
    if not isinstance(root, Path):
        raise TypeError("the quarantine root must be a Path")
    if not root.is_absolute():
        raise ValueError("the quarantine root must be an absolute path")
    if os.open not in os.supports_dir_fd or os.link not in os.supports_dir_fd or os.link not in os.supports_follow_symlinks:
        raise QuarantineError("this platform cannot open or link a file relative to a directory descriptor")
    return os.open(root, _DIRECTORY)


def _open_incoming(root_fd: int, *, create: bool) -> int:
    if create:
        try:
            os.mkdir(INCOMING, 0o700, dir_fd=root_fd)
        except FileExistsError:
            pass  # whatever is there is opened below, without following it
    return os.open(INCOMING, _DIRECTORY, dir_fd=root_fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


class IncomingFile:
    """A staged file being written: bounded, hashed as it is written, and removable. Make one with create()."""

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
    def create(cls, root: Path, limit: int) -> "IncomingFile":
        """Stage a new, empty file under a fresh server-made name. The root must exist; nothing outside it is touched."""
        _check_limit(limit)
        root_fd = _open_root(root)
        try:
            incoming_fd = _open_incoming(root_fd, create=True)
            try:
                name = secrets.token_hex(16)
                fd = os.open(name, _STAGED, 0o600, dir_fd=incoming_fd)
            finally:
                os.close(incoming_fd)
        finally:
            os.close(root_fd)
        return cls(root, name, fd, limit)

    def write(self, chunk: bytes) -> None:
        """Append a chunk. The limit counts the bytes that arrive: the chunk that would cross it is not written at all."""
        if self._finished:
            raise RuntimeError("the staged file is finished")
        if self._over or self._size + len(chunk) > self._limit:
            self._over = True
            raise UploadTooLarge("the upload is larger than the limit")
        _write_all(self._fd, chunk)
        self._digest.update(chunk)
        self._size += len(chunk)

    def finish(self) -> Received:
        """Flush and close the file, once, and say what it holds. Nothing more can be written afterwards."""
        if self._finished:
            raise RuntimeError("the staged file is finished")
        if self._over:
            raise UploadTooLarge("the upload is larger than the limit")
        os.fsync(self._fd)
        info = os.fstat(self._fd)  # of the descriptor that was written, so no path is looked at again
        fd, self._fd, self._finished = self._fd, None, True
        os.close(fd)
        return Received(self._size, self._digest.hexdigest(), self.name, info.st_dev, info.st_ino)

    def discard(self) -> None:
        """Close the file if it is open and remove it from staging. It may be repeated; a file already gone is no error."""
        fd, self._fd = self._fd, None
        try:
            if fd is not None:
                os.close(fd)
        finally:
            remove_staged(self._root, self.name)


def remove_staged(root: Path, name: str) -> bool:
    """Remove one staged file by name. True if there was one; a root or staging directory that is gone is not an error."""
    _check_name(name)
    try:
        root_fd = _open_root(root)
    except FileNotFoundError:
        return False
    try:
        try:
            incoming_fd = _open_incoming(root_fd, create=False)
        except FileNotFoundError:
            return False
        try:
            os.unlink(name, dir_fd=incoming_fd)
            return True
        except FileNotFoundError:
            return False
        finally:
            os.close(incoming_fd)
    finally:
        os.close(root_fd)


def publish(root: Path, name: str, storage_key: str) -> None:
    """Give the staged file `name` the name `storage_key`, only if nothing is at `storage_key`. It never replaces.

    The placement is a hard link made relative to the two directory descriptors, which the kernel refuses
    (FileExistsError) when anything at all occupies the destination: a regular file, a directory, a pipe, a symlink, even
    a dangling one. The occupant is then exactly as it was, and so is the staged file, which stays the caller's to
    discard. Only after the link exists is the staged name removed, so the file is never without a name, and a failure
    between the two steps leaves a complete file under both. The link and the staged file are in one filesystem by
    construction (staging is inside the root); a root whose staging directory is another mount fails closed (EXDEV), as
    does a filesystem without hard links.

    Only the caller that has just won the compare-and-set from INITIATED to UPLOADED, inside its transaction, calls this
    for a storage key. What it created is recognisable afterwards by Received.device and Received.inode, which is how
    remove_if_same_file() avoids ever deleting a file this writer did not place.
    """
    _check_name(name)
    _check_name(storage_key)
    root_fd = _open_root(root)
    try:
        incoming_fd = _open_incoming(root_fd, create=False)
        try:
            os.link(name, storage_key, src_dir_fd=incoming_fd, dst_dir_fd=root_fd, follow_symlinks=False)
            os.unlink(name, dir_fd=incoming_fd)
        finally:
            os.close(incoming_fd)
    finally:
        os.close(root_fd)


def remove_if_same_file(root: Path, storage_key: str, device: int, inode: int) -> bool:
    """Remove the entry at `storage_key` only if it is the regular file with this device and inode. True if removed.

    This is the only way to delete a file from a storage key, and it exists for a writer to take back the file it has
    just placed (identity from Received). Anything else at the key is left exactly as it is and reported by False: a
    different file, a symlink (even one that points at the right inode), a directory, a pipe, or nothing.
    """
    _check_name(storage_key)
    for label, value in (("device", device), ("inode", inode)):
        if type(value) is not int:
            raise TypeError(f"{label} must be an int, got {type(value).__name__}")
    root_fd = _open_root(root)
    try:
        try:
            info = os.stat(storage_key, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (device, inode):
            return False
        os.unlink(storage_key, dir_fd=root_fd)
        return True
    finally:
        os.close(root_fd)


def is_regular_file(root: Path, storage_key: str) -> bool:
    """Whether `storage_key` names a regular file, as the entry itself: a symlink, directory or pipe is not one."""
    _check_name(storage_key)
    root_fd = _open_root(root)
    try:
        return stat.S_ISREG(os.stat(storage_key, dir_fd=root_fd, follow_symlinks=False).st_mode)
    except FileNotFoundError:
        return False
    finally:
        os.close(root_fd)


def _classify(directory_fd: int, names: list[str]) -> tuple[list[str], list[tuple[str, int]], list[str]]:
    """(server-named regular files, their modification times in microseconds, everything else), nothing followed."""
    named, times, other = [], [], []
    for name in sorted(names):
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue  # gone since the listing
        if _NAME.fullmatch(name) and stat.S_ISREG(info.st_mode):
            named.append(name)
            times.append((name, info.st_mtime_ns // 1000))
        else:
            other.append(name)
    return named, times, other


def scan(root: Path) -> Contents:
    """What is in the root, for reconciliation. It creates, changes and follows nothing."""
    root_fd = _open_root(root)
    try:
        top = [name for name in os.listdir(root_fd) if name != INCOMING]
        finals, _, foreign = _classify(root_fd, top)
        incoming: list[tuple[str, int]] = []
        try:
            incoming_fd = _open_incoming(root_fd, create=False)
        except FileNotFoundError:
            incoming_fd = None
        if incoming_fd is not None:
            try:
                _, incoming, odd = _classify(incoming_fd, os.listdir(incoming_fd))
                foreign += [f"{INCOMING}/{name}" for name in odd]
            finally:
                os.close(incoming_fd)
        return Contents(tuple(finals), tuple(incoming), tuple(sorted(foreign)))
    finally:
        os.close(root_fd)


# --- reading a stored file back, to seal it (M1I) ---------------------------------------------------------------------
#
# One descriptor, opened once. It is opened without following a symlink and must be a regular file, by the opaque storage
# key under the validated root. Every read is `pread` at an explicit offset, so no pass depends on where an earlier one
# stopped and nothing is shared between the hashing pass, the signature look and the scanner's stream. The path is never
# opened a second time: what is hashed and what is scanned is the file this descriptor refers to, even if the name is
# replaced meanwhile. A digest of these bytes does not make them immutable: storage is mutable, so the check below can
# only notice a change that happened while the file was being inspected, and the promotion re-hash (F-04) stays necessary.


class QuarantineStorageError(QuarantineError):
    """The entry at a storage key is not a regular file."""


class QuarantineChanged(QuarantineError):
    """The stored file changed, or the name no longer leads to it, while it was being inspected."""


_STORED = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
READ_CHUNK = 64 * 1024


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """What identifies this file in this state: device, inode, size, and the two times a write cannot leave alone."""
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class _StoredStream(io.RawIOBase):
    """A read-only stream over a StoredFile from offset 0. It has its own position; closing it closes nothing else."""

    def __init__(self, stored: "StoredFile") -> None:
        super().__init__()
        self._stored = stored
        self._position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._position, io.SEEK_END: self._stored.size}[whence]
        self._position = max(0, base + offset)
        return self._position

    def readinto(self, buffer) -> int:
        data = self._stored._pread(len(buffer), self._position)
        buffer[: len(data)] = data
        self._position += len(data)
        return len(data)


class StoredFile:
    """A quarantined file opened for inspection. Make one with open_stored(); use it as a context manager."""

    def __init__(self, root_fd: int, name: str, fd: int, info: os.stat_result) -> None:
        self._root_fd: int | None = root_fd
        self._fd: int | None = fd
        self._name = name
        self._fingerprint = _fingerprint(info)
        self.size = info.st_size  # measured from the descriptor at the moment it was opened

    def _require_open(self) -> int:
        if self._fd is None:
            raise ValueError("the stored file is closed")
        return self._fd

    def _pread(self, count: int, offset: int) -> bytes:
        return os.pread(self._require_open(), count, offset)

    def chunks(self, chunk_size: int = READ_CHUNK) -> Iterator[bytes]:
        """The whole file, from offset 0, in blocks. A change noticed at the end of the pass is an error, not a result.

        It reads exactly the size measured at open. Fewer bytes, or any change since the file was opened (including more
        bytes appended), raises QuarantineChanged when the pass ends, so a digest made from it describes a file that did
        not change under it.
        """
        self._require_open()
        if type(chunk_size) is not int or chunk_size < 1:
            raise ValueError("chunk_size must be a positive int")
        offset = 0
        while offset < self.size:
            block = self._pread(min(chunk_size, self.size - offset), offset)
            if not block:
                break
            offset += len(block)
            yield block
        if offset != self.size:
            raise QuarantineChanged("the stored file is shorter than when it was opened")
        self.ensure_unchanged()

    def head(self, count: int) -> bytes:
        """At most `count` bytes from offset 0, for looking at a signature. It moves no position."""
        self._require_open()
        if type(count) is not int:
            raise TypeError(f"count must be an int, got {type(count).__name__}")
        if count < 0:
            raise ValueError("count must not be negative")
        return self._pread(min(count, self.size), 0)

    def scan_stream(self) -> BinaryIO:
        """A readable stream over the same descriptor, positioned at offset 0. The caller (a scanner) reads it to its end."""
        self._require_open()
        return _StoredStream(self)

    def ensure_unchanged(self) -> None:
        """Raise QuarantineChanged unless the file is as it was when opened and the name still leads to this very file."""
        fd = self._require_open()
        if _fingerprint(os.fstat(fd)) != self._fingerprint:
            raise QuarantineChanged("the stored file changed while it was being inspected")
        try:
            named = os.stat(self._name, dir_fd=self._root_fd, follow_symlinks=False)
        except FileNotFoundError:
            raise QuarantineChanged("the storage key no longer leads to the file that was inspected") from None
        if not stat.S_ISREG(named.st_mode) or (named.st_dev, named.st_ino) != self._fingerprint[:2]:
            raise QuarantineChanged("the storage key no longer leads to the file that was inspected")

    def close(self) -> None:
        fd, root_fd, self._fd, self._root_fd = self._fd, self._root_fd, None, None
        if fd is not None:
            os.close(fd)
        if root_fd is not None:
            os.close(root_fd)

    def __enter__(self) -> "StoredFile":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def open_stored(root: Path, storage_key: str) -> StoredFile:
    """Open the file stored under `storage_key` for inspection: no symlink followed, a regular file or an error.

    The key is the delivery's opaque storage key (32 lower-case hexadecimal characters), the only thing that names the
    file; the root is opened without following a symlink. The file is opened non-blocking, so a pipe cannot hold the
    request, and fstat on the descriptor that was opened decides whether it is a regular file. Raises FileNotFoundError,
    OSError (a symlink, a permission) or QuarantineStorageError; every descriptor opened is closed on failure.
    """
    _check_name(storage_key)
    root_fd = _open_root(root)
    try:
        fd = os.open(storage_key, _STORED, dir_fd=root_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise QuarantineStorageError("the stored entry is not a regular file")
        except BaseException:
            os.close(fd)
            raise
    except BaseException:
        os.close(root_fd)
        raise
    return StoredFile(root_fd, storage_key, fd, info)
