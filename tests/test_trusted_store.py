"""assets.StagingFile, publish_staged, remove_staged, remove_if_same_file, look_at and measure: writing the trusted root.

M1K publishes verified bytes into the trusted asset root through exactly these primitives. The convention mirrors the
quarantine root's: everything is relative to a descriptor for the root, opened without following a symlink in its last
component, with basenames the server made (32 lowercase hexadecimal characters; the fixed name `.staging` is the only
other). A staged file is created with O_EXCL and mode 0600, counted and hashed as it is written, and published by a hard
link that fails if anything at all occupies the final name. The only deletions are of a staged name and of the exact file a
writer placed (device and inode). Content here is synthetic.
"""

import errno
import hashlib
import os
import stat
from pathlib import Path

import pytest
from support.http_lab import occupy

from content_boundary_lab import assets

NAME = "a" * 32
OTHER_NAME = "b" * 32
ASSET = "c" * 32
CONTENT = b"synthetic bytes to be trusted\n" * 40
OCCUPANTS = ["a regular file", "a dangling symlink", "a symlink to a file outside", "a directory", "a named pipe"]


@pytest.fixture
def root(tmp_path) -> Path:
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (tmp_path / "outside").mkdir()
    return trusted


def staged(root: Path, content: bytes = CONTENT, name: str = NAME) -> assets.Written:
    file = assets.StagingFile.create(root, name, limit=max(len(content), 1))
    file.write(content)
    return file.finish()


# --- staging a file ------------------------------------------------------------------------------------------------------


def test_a_staged_file_is_private_counted_and_hashed_as_it_is_written(root):
    file = assets.StagingFile.create(root, NAME, limit=len(CONTENT))
    for start in range(0, len(CONTENT), 100):
        file.write(CONTENT[start : start + 100])
    written = file.finish()
    path = root / ".staging" / NAME
    info = path.lstat()
    assert (written.size, written.sha256, written.name) == (len(CONTENT), hashlib.sha256(CONTENT).hexdigest(), NAME)
    assert (written.device, written.inode) == (info.st_dev, info.st_ino) and path.read_bytes() == CONTENT
    assert stat.S_IMODE(info.st_mode) == 0o600 and stat.S_IMODE((root / ".staging").stat().st_mode) == 0o700


def test_what_is_reported_is_what_the_file_holds_not_what_a_caller_says(root):
    written = staged(root)
    on_disk = (root / ".staging" / NAME).read_bytes()
    assert (written.size, written.sha256) == (len(on_disk), hashlib.sha256(on_disk).hexdigest())


def test_bytes_over_the_limit_are_not_written_and_the_file_cannot_be_finished(root):
    file = assets.StagingFile.create(root, NAME, limit=10)
    file.write(b"0123456789")
    with pytest.raises(assets.StagingTooLarge):
        file.write(b"x")
    assert (root / ".staging" / NAME).read_bytes() == b"0123456789"  # the chunk that crossed the limit left no trace
    with pytest.raises(assets.StagingTooLarge):
        file.finish()
    file.discard()
    assert not (root / ".staging" / NAME).exists()


def test_an_empty_file_can_be_staged_and_a_finished_file_takes_no_more_bytes(root):
    file = assets.StagingFile.create(root, NAME, limit=1)
    written = file.finish()
    assert (written.size, written.sha256) == (0, hashlib.sha256(b"").hexdigest())
    with pytest.raises(RuntimeError):
        file.write(b"x")
    with pytest.raises(RuntimeError):
        file.finish()


def test_discard_closes_removes_and_may_be_repeated(root):
    file = assets.StagingFile.create(root, NAME, limit=10)
    file.write(b"abc")
    file.discard()
    file.discard()
    assert not (root / ".staging" / NAME).exists()


def test_the_staging_directory_is_created_once_and_only_by_the_primitive(root):
    assert not (root / ".staging").exists()
    staged(root)
    staged(root, name=OTHER_NAME)
    assert sorted(path.name for path in (root / ".staging").iterdir()) == [NAME, OTHER_NAME]


@pytest.mark.parametrize("kind", OCCUPANTS)
def test_a_name_that_is_taken_is_never_reused_or_overwritten(root, tmp_path, kind):
    (root / ".staging").mkdir()
    describe = occupy(root / ".staging" / NAME, tmp_path / "outside", kind)
    before = describe()
    with pytest.raises(FileExistsError):
        assets.StagingFile.create(root, NAME, limit=10)
    assert describe() == before


def test_a_staging_directory_that_is_a_symlink_is_not_followed(root, tmp_path):
    (root / ".staging").symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(OSError) as refused:
        assets.StagingFile.create(root, NAME, limit=10)
    assert refused.value.errno in (errno.ELOOP, errno.ENOTDIR)
    assert list((tmp_path / "outside").iterdir()) == []


def test_a_staging_entry_that_is_a_regular_file_is_refused(root):
    (root / ".staging").write_bytes(b"not a directory")
    with pytest.raises(OSError):
        assets.StagingFile.create(root, NAME, limit=10)
    assert (root / ".staging").read_bytes() == b"not a directory"


def test_a_root_that_is_a_symlink_a_missing_root_or_a_relative_one_is_refused(root, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(OSError):
        assets.StagingFile.create(link, NAME, limit=10)
    with pytest.raises(FileNotFoundError):
        assets.StagingFile.create(tmp_path / "missing", NAME, limit=10)
    with pytest.raises(ValueError):
        assets.StagingFile.create(Path("relative"), NAME, limit=10)
    with pytest.raises(TypeError):
        assets.StagingFile.create(str(root), NAME, limit=10)
    assert not (root / ".staging").exists()


BAD_NAMES = ["", "A" * 32, "a" * 31, "a" * 33, "../" + "a" * 29, "a/" + "a" * 30, ".staging", "a" * 31 + "\n", "g" * 32, "a\x00" + "a" * 30]


@pytest.mark.parametrize("name", BAD_NAMES, ids=repr)
def test_only_names_the_server_makes_are_used(root, name):
    with pytest.raises(ValueError):
        assets.StagingFile.create(root, name, limit=10)
    staged(root)
    with pytest.raises(ValueError):
        assets.publish_staged(root, name, ASSET)
    with pytest.raises(ValueError):
        assets.publish_staged(root, NAME, name)
    with pytest.raises(ValueError):
        assets.remove_staged(root, name)
    with pytest.raises(ValueError):
        assets.remove_if_same_file(root, name, 1, 1)
    with pytest.raises(ValueError):
        assets.look_at(root, name)
    with pytest.raises(ValueError):
        assets.measure(root, name)


@pytest.mark.parametrize("name", [None, 7, b"a" * 32])
def test_a_name_must_be_a_str(root, name):
    with pytest.raises(TypeError):
        assets.StagingFile.create(root, name, limit=10)


@pytest.mark.parametrize("limit", [0, -1, True, 1.5, "10", None])
def test_the_limit_must_be_a_positive_int(root, limit):
    with pytest.raises((TypeError, ValueError)):
        assets.StagingFile.create(root, NAME, limit=limit)
    assert not (root / ".staging" / NAME).exists()


# --- publishing -----------------------------------------------------------------------------------------------------------


def test_publishing_gives_the_staged_file_its_final_name_and_keeps_the_staged_name(root):
    written = staged(root)
    assets.publish_staged(root, NAME, ASSET)
    final, staging = root / ASSET, root / ".staging" / NAME
    assert final.read_bytes() == CONTENT and staging.read_bytes() == CONTENT
    assert (final.lstat().st_dev, final.lstat().st_ino) == (written.device, written.inode) == (staging.lstat().st_dev, staging.lstat().st_ino)
    assert final.lstat().st_nlink == 2 and stat.S_ISREG(final.lstat().st_mode)  # one file, two names: never without a name


def test_publishing_makes_the_directory_entry_durable_before_it_returns(root, monkeypatch):
    staged(root)
    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(stat.S_ISDIR(os.fstat(fd).st_mode)), real(fd))[1])
    assets.publish_staged(root, NAME, ASSET)
    assert True in synced  # the root directory was synced after the link (M0 P3)


@pytest.mark.parametrize("kind", OCCUPANTS)
def test_publishing_never_replaces_whatever_is_at_the_final_name(root, tmp_path, kind):
    staged(root)
    describe = occupy(root / ASSET, tmp_path / "outside", kind)
    before = describe()
    with pytest.raises(FileExistsError):
        assets.publish_staged(root, NAME, ASSET)
    assert describe() == before  # the occupant is exactly as it was
    assert (root / ".staging" / NAME).read_bytes() == CONTENT  # and the staged file is still the caller's to discard
    assert (tmp_path / "outside" / "secret.txt").exists() is (kind == "a symlink to a file outside")


def test_publishing_a_staged_name_that_is_not_there_fails_and_creates_nothing(root):
    (root / ".staging").mkdir()
    with pytest.raises(FileNotFoundError):
        assets.publish_staged(root, NAME, ASSET)
    assert not (root / ASSET).exists() and not (root / ASSET).is_symlink()


@pytest.mark.parametrize("kind", ["a dangling symlink", "a symlink to a file outside", "a directory", "a named pipe"])
def test_publishing_refuses_a_staged_name_that_is_not_a_regular_file(root, tmp_path, kind):
    (root / ".staging").mkdir()
    describe = occupy(root / ".staging" / NAME, tmp_path / "outside", kind)
    before = describe()
    with pytest.raises(assets.AssetStorageError):
        assets.publish_staged(root, NAME, ASSET)
    assert not (root / ASSET).exists() and not (root / ASSET).is_symlink() and describe() == before


def test_a_final_name_is_not_taken_by_publishing_into_a_missing_root(tmp_path):
    with pytest.raises(FileNotFoundError):
        assets.publish_staged(tmp_path / "missing", NAME, ASSET)


# --- taking back ------------------------------------------------------------------------------------------------------------


def test_remove_staged_removes_one_staged_name_and_says_so(root):
    staged(root)
    assert assets.remove_staged(root, NAME) is True
    assert assets.remove_staged(root, NAME) is False
    assert not (root / ".staging" / NAME).exists()


def test_remove_staged_with_no_staging_directory_or_no_root_is_not_an_error(root, tmp_path):
    assert assets.remove_staged(root, NAME) is False
    assert assets.remove_staged(tmp_path / "missing", NAME) is False


def test_remove_staged_removes_a_symlink_itself_and_never_what_it_points_at(root, tmp_path):
    (root / ".staging").mkdir()
    (tmp_path / "outside" / "real").write_bytes(b"outside")
    (root / ".staging" / NAME).symlink_to(tmp_path / "outside" / "real")
    assert assets.remove_staged(root, NAME) is True
    assert (tmp_path / "outside" / "real").read_bytes() == b"outside"


def test_remove_if_same_file_removes_exactly_the_file_that_was_placed(root):
    written = staged(root)
    assets.publish_staged(root, NAME, ASSET)
    assert assets.remove_if_same_file(root, ASSET, written.device, written.inode) is True
    assert not (root / ASSET).exists()
    assert (root / ".staging" / NAME).read_bytes() == CONTENT  # the other name of the same file is not this function's


@pytest.mark.parametrize("kind", ["another file", "a symlink to the right inode", "a directory", "a named pipe", "nothing"])
def test_remove_if_same_file_leaves_everything_else_exactly_as_it_is(root, tmp_path, kind):
    written = staged(root)
    entry = root / ASSET
    if kind == "another file":
        entry.write_bytes(b"a file that was already there")
    elif kind == "a symlink to the right inode":
        entry.symlink_to(root / ".staging" / NAME)
    elif kind == "a directory":
        entry.mkdir()
    elif kind == "a named pipe":
        os.mkfifo(entry)
    before = None if kind == "nothing" else entry.lstat()
    assert assets.remove_if_same_file(root, ASSET, written.device, written.inode) is False
    if before is not None:
        assert entry.lstat().st_ino == before.st_ino and (entry.is_symlink() or entry.exists())
    assert (root / ".staging" / NAME).read_bytes() == CONTENT


@pytest.mark.parametrize("device", ["1", 1.0, None, True])
def test_the_identity_to_match_is_two_ints(root, device):
    with pytest.raises(TypeError):
        assets.remove_if_same_file(root, ASSET, device, 1)


# --- looking at an entry ------------------------------------------------------------------------------------------------------


def test_look_at_describes_an_entry_without_following_anything(root, tmp_path):
    written = staged(root)
    assets.publish_staged(root, NAME, ASSET)
    final = assets.look_at(root, ASSET)
    assert (final.regular, final.device, final.inode, final.links, final.size) == (True, written.device, written.inode, 2, len(CONTENT))
    assert assets.look_at(root, NAME, staged=True) == final  # one file under two names is one entry, times included
    assert assets.look_at(root, OTHER_NAME) is None and assets.look_at(root, OTHER_NAME, staged=True) is None
    (root / OTHER_NAME).symlink_to(root / ASSET)
    assert assets.look_at(root, OTHER_NAME).regular is False  # the symlink itself, not its target
    os.mkfifo(root / ("d" * 32))
    assert assets.look_at(root, "d" * 32).regular is False


def test_look_at_without_a_staging_directory_finds_nothing(root):
    assert assets.look_at(root, NAME, staged=True) is None


def test_measure_reads_a_regular_file_once_through_a_no_follow_descriptor(root):
    staged(root)
    assets.publish_staged(root, NAME, ASSET)
    for measured, name, staged_name in ((assets.measure(root, ASSET), ASSET, False), (assets.measure(root, NAME, staged=True), NAME, True)):
        assert (measured.size, measured.sha256) == (len(CONTENT), hashlib.sha256(CONTENT).hexdigest())
        assert measured.entry == assets.look_at(root, name, staged=staged_name)  # the identity of the file that was read


def test_an_entry_changes_when_the_file_is_changed_in_place_even_to_the_same_size(root):
    staged(root)
    assets.publish_staged(root, NAME, ASSET)
    before = assets.look_at(root, ASSET)
    with (root / ASSET).open("r+b") as handle:
        handle.write(b"X")  # the same size, the same inode
    after = assets.look_at(root, ASSET)
    assert (after.device, after.inode, after.size) == (before.device, before.inode, before.size)
    assert after != before and (after.modified_ns, after.changed_ns) != (before.modified_ns, before.changed_ns)


def test_a_file_that_changes_while_it_is_measured_is_an_error_and_not_a_result(root, monkeypatch):
    big = b"synthetic bytes\n" * 20000  # several blocks, so there is a middle to change in
    staged(root, big)
    assets.publish_staged(root, NAME, ASSET)
    real, calls = os.pread, []

    def changing(fd, count, offset):
        calls.append(offset)
        block = real(fd, count, offset)
        if len(calls) == 1:
            with (root / ASSET).open("r+b") as handle:  # after the first block was read
                handle.seek(len(big) - 1)
                handle.write(b"!")
        return block

    monkeypatch.setattr(os, "pread", changing)
    with pytest.raises(assets.AssetStorageError):
        assets.measure(root, ASSET)


@pytest.mark.parametrize("kind", ["a dangling symlink", "a symlink to a file outside", "a directory", "a named pipe", "nothing"])
def test_measure_refuses_what_is_not_a_regular_file_and_follows_nothing(root, tmp_path, kind):
    if kind != "nothing":
        occupy(root / ASSET, tmp_path / "outside", kind)
    with pytest.raises((OSError, assets.AssetStorageError)):
        assets.measure(root, ASSET)


# --- what the module is, and is not --------------------------------------------------------------------------------------


def test_the_write_side_deletes_only_staged_names_and_the_exact_file_it_placed():
    import ast

    source = Path(assets.__file__).read_text()
    tree = ast.parse(source)

    def functions_calling(module: str, attribute: str) -> set[str]:
        return {
            function.name
            for function in ast.walk(tree)
            if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
            for node in ast.walk(function)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == attribute
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == module
        }

    assert functions_calling("os", "unlink") == {"remove_staged", "remove_if_same_file"}
    assert functions_calling("os", "link") == {"publish_staged"}  # the no-clobber placement, in one place
    assert functions_calling("os", "rename") == set() and functions_calling("os", "replace") == set()
