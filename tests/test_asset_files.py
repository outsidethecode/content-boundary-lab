"""assets.open_asset_file: how the bytes of an asset are reached, and what cannot be reached through it.

The convention: an asset's bytes are one file in the trusted asset root, named by the asset's own id (32 lowercase
hexadecimal characters, which the schema's CHECK guarantees for every row), so the storage key is a single opaque
basename with no path component. The file is opened relative to a descriptor for the root, with no-follow semantics,
checked with fstat on the opened descriptor, and streamed from that same descriptor; the path is never opened twice.

Assumptions, which these tests state rather than hide: the root is local, trusted configuration that untrusted users cannot
write to, and the parent directories of the root are followed like any configured path. A hard link planted by someone who
can already write into the root is not something a no-follow open can see. Content here is synthetic.
"""

import ast
import errno
import inspect
import os
import sqlite3
import threading
from pathlib import Path

import pytest

from content_boundary_lab import assets, request_flow, store

ID = "a" * 32
CONTENT = b"synthetic trusted bytes\n" * 5000
SECRET = b"a secret outside the trusted root\n"


def asset(asset_id: str = ID, name: str = "reference.mov") -> assets.Asset:
    return assets.Asset(asset_id, "c" * 32, name, 1)


@pytest.fixture
def root(tmp_path) -> Path:
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    (trusted / ID).write_bytes(CONTENT)
    (tmp_path / "secret.txt").write_bytes(SECRET)
    return trusted


def open_descriptors() -> int:
    return len(os.listdir("/dev/fd"))


class NoLeak:
    """The number of open descriptors is the same after the block as before it."""

    def __enter__(self):
        open_descriptors()  # the first listing may open its own handles
        self.before = open_descriptors()

    def __exit__(self, *exc):
        assert open_descriptors() == self.before, "a file descriptor was left open"


# ------------------------------------------------------------------------------------------------------- the happy path


def test_a_regular_file_in_the_root_is_opened_for_download(root):
    download = assets.open_asset_file(root, asset(name="reference.mov"))
    try:
        assert isinstance(download, request_flow.Download)
        assert download.size == len(CONTENT) and download.filename == "reference.mov"
        assert download.file.tell() == 0 and not download.file.writable()
        assert download.file.read() == CONTENT
        assert os.get_inheritable(download.file.fileno()) is False  # a child process would not inherit it
    finally:
        download.close()
    assert download.file.closed
    download.close()  # idempotent


def test_the_stream_comes_from_the_descriptor_that_was_checked_and_not_from_the_path(root):
    download = assets.open_asset_file(root, asset())
    try:
        (root / "replacement").write_bytes(b"different bytes after authorisation\n")
        os.replace(root / "replacement", root / ID)  # the name now leads somewhere else...
        assert download.file.read() == CONTENT  # ...but the opened descriptor still reads what was checked
        assert download.size == len(CONTENT)
    finally:
        download.close()


def test_the_file_stays_readable_if_its_name_is_removed_after_the_open(root):
    download = assets.open_asset_file(root, asset())
    try:
        (root / ID).unlink()
        assert download.file.read() == CONTENT
    finally:
        download.close()


# --------------------------------------------------------------------------------------- one opaque basename, nothing else

HOSTILE_IDS = [
    "",
    "..",
    ".",
    "../" + "a" * 29,
    "../secret.txt",
    "/etc/passwd",
    "/" + "a" * 31,
    "a/b",
    ID + "/",
    ID + "/..",
    ID.upper(),
    ID[:-1],
    ID + "0",
    "\x00" + ID[1:],
    ID[:16] + "\x00" + ID[17:],
    "%2e%2e%2fsecret.txt",
    "~",
    ID + "\n",
    "é" * 32,
    "..\\" + "a" * 29,
]


@pytest.mark.parametrize("hostile", HOSTILE_IDS, ids=lambda value: ascii(value)[:28])
def test_an_id_that_is_not_a_plain_storage_key_is_refused_before_the_filesystem_is_touched(root, monkeypatch, hostile):
    def forbidden(*args, **kwargs):
        raise AssertionError("the filesystem was touched")

    monkeypatch.setattr(os, "open", forbidden)
    with pytest.raises(ValueError, match="asset_id") as error:
        assets.open_asset_file(root, asset(hostile))
    assert len(hostile) < 4 or hostile not in str(error.value)


@pytest.mark.parametrize("bad", [None, 12345, b"a" * 32], ids=lambda value: type(value).__name__)
def test_an_id_that_is_not_a_str_is_a_type_error(root, bad):
    with pytest.raises(TypeError, match="asset_id"):
        assets.open_asset_file(root, asset(bad))


def test_the_schema_does_not_allow_a_row_whose_id_could_be_a_path(tmp_path):
    # The storage convention rests on this: every asset id that reaches the opener is already 32 lowercase hex.
    path = tmp_path / "lab.sqlite3"
    store.initialise_schema(path)
    conn = store.connect(path)
    try:
        with store.transaction(conn):
            conn.execute("INSERT INTO productions (id, name, created_at) VALUES (?, 'P', 1)", ("d" * 32,))
        for bad in ("../secret.txt", "a/b", "/etc/passwd", ID.upper(), ID[:-1]):
            with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
                with store.transaction(conn):
                    conn.execute(
                        "INSERT INTO assets (id, production_id, display_name, created_at) VALUES (?, ?, 'x', 1)",
                        (bad, "d" * 32),
                    )
    finally:
        conn.close()


# ------------------------------------------------------------------------------- symlinks, non-regular files, the root


def test_a_symlink_in_the_root_is_refused_whether_it_points_outside_or_inside(root, tmp_path):
    other = "b" * 32
    (root / other).write_bytes(b"another asset\n")
    cases = {"outside": tmp_path / "secret.txt", "inside": root / other, "dangling": tmp_path / "nowhere"}
    for name, target in cases.items():
        (root / ID).unlink(missing_ok=True)
        (root / ID).symlink_to(target)
        with NoLeak():
            with pytest.raises(OSError) as error:
                assets.open_asset_file(root, asset())
        assert error.value.errno in {errno.ELOOP, errno.EMLINK}, name  # refused by no-follow, not by luck
    assert (tmp_path / "secret.txt").read_bytes() == SECRET


def test_a_directory_with_the_name_of_an_asset_is_refused(root):
    (root / ID).unlink()
    (root / ID).mkdir()
    with NoLeak():
        with pytest.raises(assets.AssetStorageError, match="regular file"):
            assets.open_asset_file(root, asset())


def test_a_named_pipe_is_refused_promptly_and_does_not_block_the_request(root):
    (root / ID).unlink()
    os.mkfifo(root / ID)
    outcome: list = []

    def attempt():
        try:
            assets.open_asset_file(root, asset())
        except BaseException as error:
            outcome.append(error)

    with NoLeak():
        worker = threading.Thread(target=attempt, daemon=True)
        worker.start()
        worker.join(5)
        assert not worker.is_alive(), "opening a named pipe blocked"
    assert len(outcome) == 1 and isinstance(outcome[0], assets.AssetStorageError)


def test_a_missing_file_is_an_integrity_failure_and_leaves_nothing_open(root):
    (root / ID).unlink()
    with NoLeak():
        with pytest.raises(FileNotFoundError):
            assets.open_asset_file(root, asset())


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file")
def test_an_unreadable_file_is_an_integrity_failure_and_leaves_nothing_open(root):
    (root / ID).chmod(0)
    try:
        with NoLeak():
            with pytest.raises(PermissionError):
                assets.open_asset_file(root, asset())
    finally:
        (root / ID).chmod(0o600)


def test_a_missing_root_and_a_root_that_is_a_file_fail_closed(tmp_path, root):
    with pytest.raises(FileNotFoundError):
        assets.open_asset_file(tmp_path / "no-such-root", asset())
    not_a_directory = tmp_path / "plain-file"
    not_a_directory.write_bytes(b"x")
    with NoLeak():
        with pytest.raises(NotADirectoryError):
            assets.open_asset_file(not_a_directory, asset())


def test_a_root_whose_last_component_is_a_symlink_is_refused(tmp_path, root):
    link = tmp_path / "link-to-trusted"
    link.symlink_to(root)
    with NoLeak():
        with pytest.raises(OSError) as error:
            assets.open_asset_file(link, asset())
    assert error.value.errno in {errno.ELOOP, errno.ENOTDIR}


def test_parent_directories_of_the_root_are_configuration_and_are_followed(tmp_path, root):
    # Documented assumption, not a claim of protection: an administrator may reach the root through a symlinked parent
    # (on macOS /var is one). Only the root's own final component and everything below it are opened without following.
    parent_link = tmp_path / "alias"
    parent_link.symlink_to(tmp_path)
    download = assets.open_asset_file(parent_link / "trusted", asset())
    download.close()


def test_a_relative_root_is_refused_because_it_would_depend_on_the_working_directory(root):
    with pytest.raises(ValueError, match="asset_root"):
        assets.open_asset_file(Path("trusted"), asset())
    with pytest.raises(TypeError, match="asset_root"):
        assets.open_asset_file(str(root), asset())


def test_a_platform_that_cannot_open_relative_to_a_descriptor_fails_closed_and_does_not_fall_back_to_a_path(root, monkeypatch):
    monkeypatch.setattr(os, "supports_dir_fd", set())
    calls = []
    real = os.open
    monkeypatch.setattr(os, "open", lambda *args, **kwargs: calls.append(args) or real(*args, **kwargs))
    with pytest.raises(assets.AssetStorageError, match="directory descriptor"):
        assets.open_asset_file(root, asset())
    assert calls == []


# ---------------------------------------------------------------------------------------------------- how it is written


def _function() -> ast.FunctionDef:
    return next(node for node in ast.parse(inspect.getsource(assets)).body if isinstance(node, ast.FunctionDef) and node.name == "open_asset_file")


def test_the_opener_uses_no_path_arithmetic_no_resolve_and_no_second_open():
    tree = _function()
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    attributes = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert "open" not in names  # not the builtin: a path is never opened by name
    assert not {"resolve", "realpath", "abspath", "join", "joinpath", "samefile"} & attributes
    assert not [node for node in ast.walk(tree) if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)]  # no `root / name`
    opens = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "open"]
    assert len(opens) == 2 and sum(any(k.arg == "dir_fd" for k in call.keywords) for call in opens) == 1
    assert {"O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK"} <= attributes
    assert {"fstat", "S_ISREG", "fdopen"} <= attributes
