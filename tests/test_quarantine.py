"""The quarantine directory: bytes from a client are written only here, under names the server makes, never followed out.

These are the filesystem rules of ingest, tested without HTTP: a bounded, hashed, chunk-by-chunk writer into a staging
directory; a rename into the one flat namespace of storage keys; removal; and a listing for reconciliation. Every
path is built from a root descriptor and one opaque basename, so no client text can become a path component. Synthetic
bytes only.
"""

import hashlib
import os
import stat
from pathlib import Path

import pytest
from support.http_lab import OCCUPANTS, occupy

from content_boundary_lab import quarantine

KEY = "ab" * 16
OTHER_KEY = "cd" * 16
HOSTILE_NAMES = ["", "..", ".", "../x", "a/b", "/etc/passwd", ".incoming", "A" * 32, "a" * 31, "a" * 33, "a" * 31 + "\x00", "%2e%2e"]


def open_descriptors() -> int:
    return len(os.listdir("/dev/fd"))


@pytest.fixture
def root(tmp_path) -> Path:
    directory = tmp_path / "quarantine"
    directory.mkdir()
    return directory


def staged(root: Path) -> list[str]:
    staging = root / ".incoming"
    return sorted(entry.name for entry in staging.iterdir()) if staging.is_dir() else []


def received(root: Path, content: bytes, limit: int = 1 << 20) -> quarantine.Received:
    incoming = quarantine.IncomingFile.create(root, limit)
    incoming.write(content)
    return incoming.finish()


# --- the writer -----------------------------------------------------------------------------------------------------


def test_the_staging_file_has_a_server_made_name_and_is_private_to_the_owner(root):
    incoming = quarantine.IncomingFile.create(root, 100)
    try:
        assert len(incoming.name) == 32 and set(incoming.name) <= set("0123456789abcdef")
        assert staged(root) == [incoming.name]
        assert stat.S_IMODE((root / ".incoming").stat().st_mode) & 0o077 == 0
        assert stat.S_IMODE((root / ".incoming" / incoming.name).stat().st_mode) & 0o077 == 0
    finally:
        incoming.discard()
    assert staged(root) == []


def test_two_writers_never_share_a_name(root):
    writers = [quarantine.IncomingFile.create(root, 10) for _ in range(20)]
    try:
        assert len({writer.name for writer in writers}) == 20
    finally:
        for writer in writers:
            writer.discard()


@pytest.mark.parametrize("kind", OCCUPANTS)
def test_a_staged_name_that_is_already_taken_is_never_reused(tmp_path, root, monkeypatch, kind):
    """The names are random, so this cannot happen by chance; it is the exclusive create that makes it fail and not overwrite."""
    taken = "ef" * 16
    (root / ".incoming").mkdir()
    describe = occupy(root / ".incoming" / taken, tmp_path, kind)
    before = describe()
    monkeypatch.setattr(quarantine.secrets, "token_hex", lambda nbytes: taken)
    with pytest.raises(FileExistsError):
        quarantine.IncomingFile.create(root, 10)
    assert describe() == before  # whatever was there is exactly as it was
    assert staged(root) == [taken]  # and nothing else was created


@pytest.mark.parametrize(
    "chunks",
    [[b""], [b"a"], [b"x" * 10], [b"x", b"y" * 9], [b"", b"abc", b"", b"def"], [bytes(range(256)) * 3, b"\x00" * 5], [b"z"] * 40],
    ids=["empty", "one byte", "exactly the limit", "two chunks", "empty chunks between", "all byte values", "forty one-byte chunks"],
)
def test_the_size_and_digest_are_those_of_the_bytes_actually_written(root, chunks):
    incoming = quarantine.IncomingFile.create(root, 1000)
    for chunk in chunks:
        incoming.write(chunk)
    result = incoming.finish()
    content = b"".join(chunks)
    assert (result.size, result.sha256) == (len(content), hashlib.sha256(content).hexdigest())
    assert (root / ".incoming" / result.name).read_bytes() == content
    assert result.name == incoming.name


def test_the_limit_counts_bytes_as_they_arrive(root):
    exact = quarantine.IncomingFile.create(root, 10)
    exact.write(b"x" * 10)
    assert exact.finish().size == 10
    over = quarantine.IncomingFile.create(root, 10)
    over.write(b"x" * 10)
    with pytest.raises(quarantine.UploadTooLarge):
        over.write(b"y")
    over.discard()


def test_a_chunk_that_crosses_the_limit_writes_none_of_its_bytes_and_the_writer_stays_refused(root):
    incoming = quarantine.IncomingFile.create(root, 10)
    incoming.write(b"x" * 8)
    with pytest.raises(quarantine.UploadTooLarge):
        incoming.write(b"y" * 5)
    assert (root / ".incoming" / incoming.name).stat().st_size == 8
    with pytest.raises(quarantine.UploadTooLarge):  # once over, nothing more is accepted, not even an empty chunk
        incoming.write(b"")
    with pytest.raises(quarantine.UploadTooLarge):
        incoming.finish()
    incoming.discard()
    assert staged(root) == []


def test_a_finished_writer_accepts_nothing_more(root):
    incoming = quarantine.IncomingFile.create(root, 10)
    incoming.finish()
    with pytest.raises(RuntimeError, match="finished"):
        incoming.write(b"x")
    with pytest.raises(RuntimeError, match="finished"):
        incoming.finish()


def test_discarding_removes_only_its_own_file_and_can_be_repeated(root):
    keep = quarantine.IncomingFile.create(root, 10)
    drop = quarantine.IncomingFile.create(root, 10)
    drop.write(b"abc")
    drop.discard()
    drop.discard()
    assert staged(root) == [keep.name]
    keep.finish()
    keep.discard()  # after finish the staged file is still the writer's to remove
    assert staged(root) == []
    keep.discard()


def test_discarding_a_file_that_is_already_gone_is_not_an_error(root):
    incoming = quarantine.IncomingFile.create(root, 10)
    (root / ".incoming" / incoming.name).unlink()
    incoming.discard()


@pytest.mark.parametrize("limit", [0, -1, 2.5, "10", None, True])
def test_the_limit_must_be_a_positive_integer(root, limit):
    with pytest.raises((TypeError, ValueError)):
        quarantine.IncomingFile.create(root, limit)
    assert staged(root) == []


# --- where it may write ----------------------------------------------------------------------------------------------


def test_a_relative_root_is_refused(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "relative").mkdir()
    with pytest.raises(ValueError, match="absolute"):
        quarantine.IncomingFile.create(Path("relative"), 10)
    assert not (tmp_path / "relative" / ".incoming").exists()


def test_a_missing_root_is_not_created(tmp_path):
    with pytest.raises(FileNotFoundError):
        quarantine.IncomingFile.create(tmp_path / "absent", 10)
    assert not (tmp_path / "absent").exists()


def test_a_root_that_is_a_symlink_is_not_followed(tmp_path, root):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    link = tmp_path / "link"
    link.symlink_to(elsewhere)
    with pytest.raises(OSError):
        quarantine.IncomingFile.create(link, 10)
    assert list(elsewhere.iterdir()) == []


@pytest.mark.parametrize("function", ["publish", "remove", "scan", "is_regular_file"])
def test_every_operation_refuses_a_root_that_is_a_symlink(tmp_path, root, function):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / KEY).write_bytes(b"outside")
    link = tmp_path / "link"
    link.symlink_to(elsewhere)
    call = {
        "publish": lambda: quarantine.publish(link, "e" * 32, KEY),
        "remove": lambda: quarantine.remove_if_same_file(link, KEY, 1, 1),
        "scan": lambda: quarantine.scan(link),
        "is_regular_file": lambda: quarantine.is_regular_file(link, KEY),
    }[function]
    with pytest.raises(OSError):
        call()
    assert (elsewhere / KEY).read_bytes() == b"outside"


def test_a_staging_directory_that_is_a_symlink_is_not_followed(tmp_path, root):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (root / ".incoming").symlink_to(elsewhere)
    with pytest.raises(OSError):
        quarantine.IncomingFile.create(root, 10)
    assert list(elsewhere.iterdir()) == []


def test_a_staging_name_that_is_a_regular_file_is_refused(root):
    (root / ".incoming").write_bytes(b"not a directory")
    with pytest.raises(OSError):
        quarantine.IncomingFile.create(root, 10)
    assert (root / ".incoming").read_bytes() == b"not a directory"


# --- publishing, removing, listing ----------------------------------------------------------------------------------


def test_publishing_moves_the_staged_bytes_to_the_storage_key(root):
    result = received(root, b"synthetic bytes")
    quarantine.publish(root, result.name, KEY)
    assert (root / KEY).read_bytes() == b"synthetic bytes"
    assert staged(root) == []
    assert stat.S_ISREG((root / KEY).lstat().st_mode)
    info = (root / KEY).stat()
    assert info.st_nlink == 1  # one name only: the staged name was removed after the file was placed
    assert (info.st_dev, info.st_ino) == (result.device, result.inode)  # the placed file is the one that was written


@pytest.mark.parametrize("kind", OCCUPANTS)
def test_publishing_never_replaces_anything_that_is_already_there(tmp_path, root, kind):
    """Placement is no-clobber: whatever occupies the key, even a dangling symlink, is left exactly as it was."""
    describe = occupy(root / KEY, tmp_path, kind)
    before = describe()
    result = received(root, b"new bytes")
    with pytest.raises(FileExistsError):
        quarantine.publish(root, result.name, KEY)
    assert describe() == before
    assert staged(root) == [result.name]  # the caller's own staged file is still there, for the caller to discard
    assert (root / ".incoming" / result.name).read_bytes() == b"new bytes"
    if kind == "a symlink to a file outside":
        assert (tmp_path / "secret.txt").read_bytes() == b"outside the quarantine root"


def test_a_failed_placement_leaves_a_free_key_free(tmp_path, root):
    result = received(root, b"new bytes")
    with pytest.raises(FileNotFoundError):
        quarantine.publish(root, "e" * 32, KEY)  # nothing staged under that name
    assert not (root / KEY).exists() and not (root / KEY).is_symlink()
    quarantine.publish(root, result.name, KEY)  # and the real one still goes
    assert (root / KEY).read_bytes() == b"new bytes"


def test_publishing_onto_a_directory_fails_and_keeps_the_staged_file(root):
    (root / KEY).mkdir()
    result = received(root, b"data")
    with pytest.raises(OSError):
        quarantine.publish(root, result.name, KEY)
    assert staged(root) == [result.name] and (root / KEY).is_dir()


def test_publishing_something_that_was_never_staged_fails(root):
    with pytest.raises(FileNotFoundError):
        quarantine.publish(root, "e" * 32, KEY)
    assert not (root / KEY).exists()


@pytest.mark.parametrize("name", HOSTILE_NAMES, ids=repr)
def test_publish_refuses_names_that_are_not_server_made_before_it_touches_the_filesystem(root, name):
    result = received(root, b"data")
    with pytest.raises(ValueError):
        quarantine.publish(root, name, KEY)
    with pytest.raises(ValueError):
        quarantine.publish(root, result.name, name)
    assert staged(root) == [result.name] and quarantine.scan(root).finals == ()


def published(root, content=b"published bytes"):
    result = received(root, content)
    quarantine.publish(root, result.name, KEY)
    return result


def test_removing_deletes_the_file_that_was_published_and_nothing_is_left(root):
    result = published(root)
    assert quarantine.remove_if_same_file(root, KEY, result.device, result.inode) is True
    assert not (root / KEY).exists()
    assert quarantine.remove_if_same_file(root, KEY, result.device, result.inode) is False  # already gone


def test_removing_leaves_a_different_file_at_the_key_untouched(root):
    mine = published(root, b"what this request published")
    (root / KEY).unlink()
    (root / KEY).write_bytes(b"put there afterwards by someone else")  # same name, another inode
    assert quarantine.remove_if_same_file(root, KEY, mine.device, mine.inode) is False
    assert (root / KEY).read_bytes() == b"put there afterwards by someone else"


@pytest.mark.parametrize("kind", ["a dangling symlink", "a symlink to a file outside", "a directory", "a named pipe"])
def test_removing_never_touches_an_entry_that_is_not_a_regular_file(tmp_path, root, kind):
    mine = received(root, b"x")
    describe = occupy(root / KEY, tmp_path, kind)
    before = describe()
    assert quarantine.remove_if_same_file(root, KEY, mine.device, mine.inode) is False
    assert describe() == before


def test_a_symlink_to_the_published_file_is_not_the_published_file(tmp_path, root):
    mine = published(root)
    (root / KEY).rename(tmp_path / "moved")
    (root / KEY).symlink_to(tmp_path / "moved")  # points at the very inode, but the entry is a link
    assert quarantine.remove_if_same_file(root, KEY, mine.device, mine.inode) is False
    assert (root / KEY).is_symlink() and (tmp_path / "moved").read_bytes() == b"published bytes"


@pytest.mark.parametrize("bad", [(None, 1), (1, None), ("1", 1), (1, 1.5), (True, 1)])
def test_the_identity_must_be_two_integers(root, bad):
    with pytest.raises(TypeError):
        quarantine.remove_if_same_file(root, KEY, *bad)


def test_the_module_has_no_way_to_delete_a_final_file_unconditionally():
    assert not hasattr(quarantine, "remove")


@pytest.mark.parametrize("name", HOSTILE_NAMES, ids=repr)
def test_removal_and_the_regular_file_check_refuse_names_that_are_not_server_made(root, name):
    with pytest.raises(ValueError):
        quarantine.remove_if_same_file(root, name, 1, 1)
    with pytest.raises(ValueError):
        quarantine.is_regular_file(root, name)


def test_the_regular_file_check_is_true_only_for_a_regular_file_and_does_not_follow_links(tmp_path, root):
    (root / KEY).write_bytes(b"x")
    assert quarantine.is_regular_file(root, KEY) is True
    assert quarantine.is_regular_file(root, OTHER_KEY) is False  # absent
    (root / OTHER_KEY).symlink_to(root / KEY)
    assert quarantine.is_regular_file(root, OTHER_KEY) is False  # a link to a regular file is not one
    (root / ("ef" * 16)).mkdir()
    assert quarantine.is_regular_file(root, "ef" * 16) is False
    os.mkfifo(root / ("12" * 16))
    assert quarantine.is_regular_file(root, "12" * 16) is False


def test_scan_sorts_what_is_in_the_root_without_following_anything(tmp_path, root):
    (root / KEY).write_bytes(b"a")
    staged_file = quarantine.IncomingFile.create(root, 10)
    (root / "notes.txt").write_bytes(b"not ours")
    (root / ("Z" * 32)).write_bytes(b"capitals are not a storage key")
    (root / OTHER_KEY).symlink_to(tmp_path)
    (root / ("ef" * 16)).mkdir()
    listing = quarantine.scan(root)
    assert listing.finals == (KEY,)
    assert [name for name, _ in listing.incoming] == [staged_file.name]
    assert set(listing.foreign) == {"notes.txt", "Z" * 32, OTHER_KEY, "ef" * 16}
    assert isinstance(listing.incoming[0][1], int)  # modification time in microseconds
    staged_file.discard()


def test_scanning_an_empty_root_creates_nothing(root):
    listing = quarantine.scan(root)
    assert (listing.finals, listing.incoming, listing.foreign) == ((), (), ())
    assert list(root.iterdir()) == []


def test_no_descriptor_is_left_open_by_any_path_through_the_module(root):
    before = open_descriptors()
    result = received(root, b"data")
    quarantine.publish(root, result.name, KEY)
    quarantine.scan(root)
    quarantine.is_regular_file(root, KEY)
    quarantine.remove_if_same_file(root, KEY, result.device, result.inode)
    quarantine.remove_if_same_file(root, KEY, result.device, result.inode)
    failing = quarantine.IncomingFile.create(root, 3)
    with pytest.raises(quarantine.UploadTooLarge):
        failing.write(b"toolong")
    failing.discard()
    with pytest.raises(ValueError):
        quarantine.remove_if_same_file(root, "../x", 1, 1)
    with pytest.raises(OSError):
        quarantine.publish(root, "e" * 32, KEY)
    (root / KEY).write_bytes(b"occupied")
    with pytest.raises(FileExistsError):
        quarantine.publish(root, received(root, b"x").name, KEY)  # a refused placement closes what it opened
    assert open_descriptors() == before


# --- reading a stored file back for sealing (M1I) --------------------------------------------------------------------
#
# One descriptor is opened (no-follow, regular file only, by the opaque key under a validated root) and every read goes
# through it at an explicit offset, so no pass depends on where the last one stopped and the path is never reopened.


def store_file(root, content: bytes) -> None:
    (root / KEY).write_bytes(content)


@pytest.mark.parametrize("content", [b"", b"x", bytes(range(256)) * 600, b"z" * 65536, b"z" * 65537])
@pytest.mark.parametrize("size", [1, 7, 4096, 65536])
def test_the_stored_file_is_read_whole_in_chunks_and_its_size_is_measured_from_the_descriptor(root, content, size):
    store_file(root, content)
    with quarantine.open_stored(root, KEY) as stored:
        assert stored.size == len(content)
        pieces = list(stored.chunks(size))
        assert b"".join(pieces) == content and all(0 < len(piece) <= size for piece in pieces)


def test_every_pass_starts_at_the_beginning_whatever_the_last_one_did(root):
    content = bytes(range(256)) * 100
    store_file(root, content)
    with quarantine.open_stored(root, KEY) as stored:
        partial = stored.chunks(100)
        assert next(partial) == content[:100]  # an abandoned pass leaves nothing behind
        assert b"".join(stored.chunks()) == content
        assert stored.head(16) == content[:16]  # reading the head moves no position either
        assert b"".join(stored.chunks()) == content
        stream = stored.scan_stream()
        assert stream.tell() == 0 and stream.read() == content and stream.tell() == len(content)
        assert b"".join(stored.chunks()) == content and stored.scan_stream().tell() == 0


def test_the_head_is_at_most_what_is_asked_for_and_at_most_the_file(root):
    store_file(root, b"0123456789")
    with quarantine.open_stored(root, KEY) as stored:
        assert (stored.head(4), stored.head(10), stored.head(500), stored.head(0)) == (b"0123", b"0123456789", b"0123456789", b"")
        for bad in (-1, 1.5, "4", None, True):
            with pytest.raises((TypeError, ValueError)):
                stored.head(bad)


def test_a_scan_stream_reads_the_same_bytes_as_a_pass_and_closing_it_leaves_the_file_open(root):
    content = b"stream me " * 5000
    store_file(root, content)
    with quarantine.open_stored(root, KEY) as stored:
        stream = stored.scan_stream()
        assert [stream.read(7), stream.read(3)] == [content[:7], content[7:10]]
        stream.close()
        assert b"".join(stored.chunks()) == content  # the descriptor belongs to the stored file, not to the stream
        again = stored.scan_stream()
        assert again.read(5) == content[:5]


def test_a_closed_stored_file_refuses_every_read(root):
    store_file(root, b"data")
    with quarantine.open_stored(root, KEY) as stored:
        pass
    for call in (lambda: list(stored.chunks()), lambda: stored.head(1), stored.ensure_unchanged, stored.scan_stream):
        with pytest.raises(ValueError, match="closed"):
            call()


@pytest.mark.parametrize("kind", ["missing", "a symlink to a file", "a dangling symlink", "a directory", "a named pipe"])
def test_only_a_regular_file_is_ever_opened(tmp_path, root, kind):
    if kind == "a symlink to a file":
        (tmp_path / "secret.txt").write_bytes(b"outside the quarantine root")
        (root / KEY).symlink_to(tmp_path / "secret.txt")
    elif kind != "missing":
        occupy(root / KEY, tmp_path, kind)
    before = open_descriptors()
    with pytest.raises(OSError):  # no-follow, regular only, and a pipe cannot hold the reader
        quarantine.open_stored(root, KEY)
    assert open_descriptors() == before
    if kind == "a symlink to a file":
        assert (tmp_path / "secret.txt").read_bytes() == b"outside the quarantine root"


def test_the_root_must_be_absolute_and_not_a_symlink_and_the_key_must_be_server_made(tmp_path, root):
    store_file(root, b"data")
    (tmp_path / "link").symlink_to(root)
    with pytest.raises(OSError):
        quarantine.open_stored(tmp_path / "link", KEY)
    with pytest.raises(ValueError, match="absolute"):
        quarantine.open_stored(Path("relative"), KEY)
    for name in HOSTILE_NAMES:
        with pytest.raises(ValueError):
            quarantine.open_stored(root, name)


def test_the_opened_file_is_the_file_that_is_read_even_if_the_name_is_replaced_afterwards(root):
    store_file(root, b"the original bytes")
    with quarantine.open_stored(root, KEY) as stored:
        (root / KEY).unlink()
        (root / KEY).write_bytes(b"a different file under the same name")
        assert stored.scan_stream().read() == b"the original bytes"  # never reopened by path
        assert stored.head(8) == b"the orig"
        with pytest.raises(quarantine.QuarantineChanged):  # but the name no longer leads to what was inspected,
            stored.ensure_unchanged()
        with pytest.raises(quarantine.QuarantineChanged):  # so a pass that hashes it does not end as a result
            list(stored.chunks())


def test_an_unchanged_file_passes_the_check_however_often_it_is_read(root):
    store_file(root, b"unchanged " * 1000)
    with quarantine.open_stored(root, KEY) as stored:
        list(stored.chunks())
        stored.head(8)
        stored.scan_stream().read()
        stored.ensure_unchanged()
        stored.ensure_unchanged()


def append(root, data=b"more"):
    with (root / KEY).open("ab") as handle:
        handle.write(data)


CHANGES = {
    "bytes appended": lambda root: append(root),
    "the file truncated": lambda root: (root / KEY).write_bytes(b"short"),
    "the same size, other bytes": lambda root: (root / KEY).write_bytes(b"Y" * 3000),
    "only the modification time": lambda root: os.utime(root / KEY, (1, 1)),
}


@pytest.mark.parametrize("change", CHANGES)
def test_a_change_after_opening_is_detected_by_the_check(root, change):
    store_file(root, b"X" * 3000)
    with quarantine.open_stored(root, KEY) as stored:
        CHANGES[change](root)
        with pytest.raises(quarantine.QuarantineChanged):
            stored.ensure_unchanged()


@pytest.mark.parametrize("change", ["bytes appended", "the file truncated", "the same size, other bytes"])
def test_a_change_while_a_pass_is_running_fails_that_pass_at_its_end(root, change):
    store_file(root, b"X" * 3000)
    with quarantine.open_stored(root, KEY) as stored:
        passes = stored.chunks(1000)
        next(passes)
        CHANGES[change](root)
        with pytest.raises(quarantine.QuarantineChanged):
            list(passes)


def test_a_pass_that_reads_fewer_or_more_bytes_than_the_measured_size_is_an_error(root):
    store_file(root, b"X" * 3000)
    with quarantine.open_stored(root, KEY) as stored:
        (root / KEY).write_bytes(b"X" * 2000)  # shorter than the size measured at open
        with pytest.raises(quarantine.QuarantineChanged):
            list(stored.chunks())


def test_no_descriptor_is_left_open_by_reading_or_by_failing_to_read(root):
    store_file(root, b"data" * 1000)
    before = open_descriptors()
    with quarantine.open_stored(root, KEY) as stored:
        list(stored.chunks())
        stored.head(4)
        stream = stored.scan_stream()
        stream.read()
        stream.close()
        append(root)
        with pytest.raises(quarantine.QuarantineChanged):
            stored.ensure_unchanged()
    assert open_descriptors() == before
