"""The advisory lock on the quarantine root (M1M): what lets a maintenance pass know that no lab process is working.

Every lab process that reads or writes quarantine (the server, a promotion, a rescan) holds the root shared while it works;
reconciliation holds it exclusive. The lock belongs to the directory and to the process that holds it, so another process
is refused whatever path it names the directory by, and the kernel drops it when its holder ends, however it ends. These
tests use real child processes: an in-process lock would show nothing about two programs on one machine. Synthetic
directories only, no sleeps, no sockets.
"""

import errno
import signal
from pathlib import Path

import pytest
from support.processes import open_descriptors, other_process, refused

from content_boundary_lab import quarantine


@pytest.fixture
def root(tmp_path) -> Path:
    directory = tmp_path / "quarantine"
    directory.mkdir()
    return directory


# --- in one process ---------------------------------------------------------------------------------------------------------


def test_any_number_of_shared_holders_work_together(root):
    with quarantine.hold(root, exclusive=False), quarantine.hold(root, exclusive=False):
        pass


def test_an_exclusive_holder_refuses_every_other_holder_at_once(root):
    with quarantine.hold(root, exclusive=True):
        assert refused(root, exclusive=True)
        assert refused(root, exclusive=False)


def test_a_shared_holder_refuses_an_exclusive_one_and_only_that(root):
    with quarantine.hold(root, exclusive=False):
        assert refused(root, exclusive=True)
        with quarantine.hold(root, exclusive=False):
            pass


def test_the_lock_is_released_when_the_block_ends(root):
    with quarantine.hold(root, exclusive=True):
        pass
    with quarantine.hold(root, exclusive=True):
        pass


def test_the_lock_is_released_when_the_block_raises(root):
    with pytest.raises(ZeroDivisionError):
        with quarantine.hold(root, exclusive=True):
            1 / 0
    with quarantine.hold(root, exclusive=True):
        pass


def test_a_refusal_does_not_wait_and_leaks_no_descriptor(root):
    before = open_descriptors()
    with quarantine.hold(root, exclusive=True):
        for _ in range(20):
            assert refused(root, exclusive=True)
        during = open_descriptors()
    assert during == before + 1  # the one holder; every refused attempt closed its descriptor
    assert open_descriptors() == before


def test_holding_the_root_creates_nothing_and_changes_nothing_in_it(root):
    (root / ".incoming").mkdir()
    (root / ".incoming" / ("a" * 32)).write_bytes(b"synthetic")
    before = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
    state = (root.stat().st_mtime_ns, (root / ".incoming").stat().st_mtime_ns)
    with quarantine.hold(root, exclusive=True):
        pass
    assert sorted(str(path.relative_to(root)) for path in root.rglob("*")) == before
    assert (root.stat().st_mtime_ns, (root / ".incoming").stat().st_mtime_ns) == state


def test_another_name_for_the_same_directory_is_the_same_lock(tmp_path, root):
    (tmp_path / "elsewhere").mkdir()
    longer = tmp_path / "elsewhere" / ".." / "quarantine"
    with quarantine.hold(root, exclusive=True):
        assert refused(longer, exclusive=True)


def test_a_symlink_as_the_root_is_refused_and_nothing_is_locked(tmp_path, root):
    link = tmp_path / "link"
    link.symlink_to(root, target_is_directory=True)
    with pytest.raises(OSError):
        with quarantine.hold(link, exclusive=True):
            pytest.fail("a symlinked root must not be locked")
    with quarantine.hold(root, exclusive=True):  # the real directory was never locked by the attempt
        pass


@pytest.mark.parametrize("make", ["missing", "a file"])
def test_a_root_that_is_not_a_directory_is_refused(tmp_path, make):
    path = tmp_path / "nothing"
    if make == "a file":
        path.write_bytes(b"synthetic")
    with pytest.raises(OSError):
        with quarantine.hold(path, exclusive=False):
            pytest.fail("not a directory")


def test_a_relative_root_and_a_non_path_are_refused(root):
    with pytest.raises(ValueError):
        quarantine.hold(Path("relative"), exclusive=True).__enter__()
    with pytest.raises(TypeError):
        quarantine.hold(str(root), exclusive=True).__enter__()


def test_the_mode_must_be_a_real_bool(root):
    with pytest.raises(TypeError):
        quarantine.hold(root, exclusive=1).__enter__()


def test_a_filesystem_that_cannot_lock_fails_closed_and_closes_the_descriptor(root, monkeypatch):
    def cannot(fd, operation):
        raise OSError(errno.ENOLCK, "no locks available")

    monkeypatch.setattr(quarantine.fcntl, "flock", cannot)
    before = open_descriptors()
    with pytest.raises(quarantine.QuarantineError) as caught:
        with quarantine.hold(root, exclusive=False):
            pytest.fail("a root that cannot be locked must not be worked in")
    assert not isinstance(caught.value, quarantine.RootBusy)  # not "someone else has it": it cannot be told at all
    assert open_descriptors() == before


# --- between processes ------------------------------------------------------------------------------------------------------


def test_a_process_working_in_the_root_keeps_an_exclusive_holder_out(root):
    with other_process(root, "shared"):
        assert refused(root, exclusive=True)
        with quarantine.hold(root, exclusive=False):  # other workers are not kept out
            pass


def test_a_process_in_maintenance_keeps_every_worker_out(root):
    with other_process(root, "exclusive"):
        assert refused(root, exclusive=False)
        assert refused(root, exclusive=True)


def test_the_lock_is_released_when_its_holder_exits(root):
    with other_process(root, "exclusive") as child:
        assert refused(root, exclusive=False)
        child.stdin.close()
        child.wait(timeout=10)
    with quarantine.hold(root, exclusive=True):
        pass


def test_the_lock_is_released_when_its_holder_is_killed_so_a_crash_leaves_no_stale_lock(root):
    with other_process(root, "shared") as child:
        assert refused(root, exclusive=True)
        child.send_signal(signal.SIGKILL)
        child.wait(timeout=10)
    with quarantine.hold(root, exclusive=True):
        pass
