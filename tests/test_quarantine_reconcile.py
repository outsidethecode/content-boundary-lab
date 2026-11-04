"""Reconciling quarantine with the database after a crash or a failed cleanup.

A SQLite commit and a file placement are two operations, not one atomic step. The upload places the file before it
commits, so a crash can leave a file that no committed row claims, but never a committed UPLOADED row whose file was
never placed. Such a leftover cannot be told from a file planted by someone else (nothing recorded says whose it is), so
reconcile() does not delete it: it reports it as ambiguous for manual handling. It removes only old staged files, which
are the server's own scratch space, and it is a maintenance-window operation: it must not run while uploads are active.
Running it twice changes nothing more.
"""

import os
from datetime import timedelta

import pytest
from support.http_lab import THREAD_WAIT, Background, lab, make_lab, occupy, play, spy, writer_lock

from content_boundary_lab import ingest

STATES_AFTER_UPLOAD = ("UPLOADED", "SEALING", "REJECTED", "SCAN_FAILED", "SCAN_PASSED", "ACCEPTED", "PROMOTING", "PROMOTED", "INTEGRITY_FAILED")
HOUR = timedelta(hours=1)


def sweep(lab, min_age=HOUR):
    return ingest.reconcile(lab.clock, lab.path, lab.quarantine_root, min_age=min_age)


def plant(lab, name, content=b"synthetic", where=""):
    directory = lab.quarantine_root / where
    directory.mkdir(exist_ok=True)
    (directory / name).write_bytes(content)
    return directory / name


def age(lab, path, by):
    moment = (lab.clock.moment - by).timestamp()
    os.utime(path, (moment, moment))


def test_a_file_at_the_key_of_a_delivery_awaiting_content_is_reported_as_ambiguous_and_never_deleted(lab):
    """It may be what a crashed upload left, or something planted: nothing recorded can say, so it is for a person."""
    delivery = lab.seed_delivery("vendor-1")
    leftover = plant(lab, delivery.storage_key, b"whose is this? nothing recorded says")
    before = lab.delivery_row(delivery.id)
    report = sweep(lab)
    assert report.ambiguous == (delivery.storage_key,) and report.removed_incoming == ()
    assert leftover.read_bytes() == b"whose is this? nothing recorded says"
    assert lab.delivery_row(delivery.id) == before and before["state"] == "INITIATED"


@pytest.mark.parametrize("kind", ["a regular file", "a dangling symlink", "a directory", "a named pipe"])
def test_nothing_at_an_ambiguous_key_is_touched_whatever_it_is(lab, tmp_path, kind):
    delivery = lab.seed_delivery("vendor-1")
    describe = occupy(lab.quarantine_root / delivery.storage_key, tmp_path, kind)
    before = describe()
    report = sweep(lab, timedelta(0))
    assert describe() == before
    assert (delivery.storage_key in report.ambiguous) == (kind == "a regular file")  # the rest are reported as foreign
    assert delivery.storage_key in (*report.ambiguous, *report.foreign)


@pytest.mark.parametrize("state", STATES_AFTER_UPLOAD)
def test_the_file_of_an_uploaded_delivery_is_claimed_not_ambiguous_in_any_later_state(lab, state):
    delivery = lab.seed_delivery("vendor-1", state=state)
    kept = plant(lab, delivery.storage_key, b"the committed bytes")
    report = sweep(lab)
    assert report.ambiguous == () and report.missing == () and kept.read_bytes() == b"the committed bytes"


@pytest.mark.parametrize("state", STATES_AFTER_UPLOAD)
def test_a_committed_delivery_whose_file_is_gone_is_reported_and_nothing_is_invented(lab, state):
    delivery = lab.seed_delivery("vendor-1", state=state)
    before = lab.delivery_row(delivery.id)
    report = sweep(lab)
    assert report.missing == (delivery.id,)
    assert lab.delivery_row(delivery.id) == before and lab.quarantine_names() == []  # no state is changed, no file made


def test_a_delivery_still_awaiting_content_with_no_file_is_normal(lab):
    lab.seed_delivery("vendor-1")
    report = sweep(lab)
    assert (report.missing, report.ambiguous, report.removed_incoming) == ((), (), ())


def test_a_committed_delivery_whose_entry_is_not_a_regular_file_is_reported_as_missing(lab, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"outside")
    linked = lab.seed_delivery("vendor-1", state="UPLOADED")
    (lab.quarantine_root / linked.storage_key).symlink_to(secret)
    directory = lab.seed_delivery("vendor-1", state="UPLOADED")
    (lab.quarantine_root / directory.storage_key).mkdir()
    report = sweep(lab)
    assert set(report.missing) == {linked.id, directory.id}
    assert secret.read_bytes() == b"outside" and (lab.quarantine_root / directory.storage_key).is_dir()


def test_what_the_database_cannot_explain_is_reported_and_left_alone(lab, tmp_path):
    unreferenced = plant(lab, "ab" * 16, b"a 32-hex name that no delivery has")
    foreign = plant(lab, "notes.txt", b"someone else's file in a misconfigured root")
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"outside")
    (lab.quarantine_root / ("cd" * 16)).symlink_to(secret)
    odd = plant(lab, "odd.txt", b"not a staged name", where=".incoming")
    report = sweep(lab)
    assert report.unreferenced == ("ab" * 16,)
    assert set(report.foreign) == {"notes.txt", "cd" * 16, ".incoming/odd.txt"}
    assert report.ambiguous == () and report.removed_incoming == ()
    assert unreferenced.exists() and foreign.exists() and odd.exists() and secret.read_bytes() == b"outside"


def test_staged_files_are_removed_only_when_older_than_the_minimum_age(lab):
    old, boundary, young = "11" * 16, "22" * 16, "33" * 16
    for name, by in ((old, HOUR * 2), (boundary, HOUR), (young, HOUR - timedelta(seconds=1))):
        age(lab, plant(lab, name, where=".incoming"), by)
    report = sweep(lab)
    assert set(report.removed_incoming) == {old, boundary}  # an upload that is still arriving is not touched
    assert lab.incoming_names() == [young]


def test_the_sweep_is_idempotent(lab):
    delivery = lab.seed_delivery("vendor-1")
    plant(lab, delivery.storage_key)
    age(lab, plant(lab, "11" * 16, where=".incoming"), HOUR * 3)
    plant(lab, "ab" * 16)
    lab.seed_delivery("vendor-1", state="UPLOADED")
    first, second, third = sweep(lab), sweep(lab), sweep(lab)
    assert first.ambiguous == (delivery.storage_key,) and first.removed_incoming
    assert second == third
    assert second.removed_incoming == ()  # the only thing it ever removes is gone
    assert second.ambiguous == first.ambiguous and second.unreferenced == first.unreferenced
    assert second.missing == first.missing


def test_an_empty_or_unused_root_is_a_clean_report_and_creates_nothing(lab):
    report = sweep(lab)
    assert report == ingest.ReconcileReport((), (), (), (), ())
    assert list(lab.quarantine_root.iterdir()) == []


def test_the_state_is_read_again_under_the_writer_lock_so_an_upload_that_commits_first_is_not_reported(lab, spy):
    delivery = lab.seed_delivery("vendor-1")
    plant(lab, delivery.storage_key, b"bytes of an upload that is committing right now")
    with writer_lock(lab) as holder:
        sweeper = Background(lambda: sweep(lab))
        assert spy.begin_started.wait(THREAD_WAIT)  # the sweep is now waiting for the lock the upload holds
        holder.execute(
            "UPDATE deliveries SET state = 'UPLOADED', received_size = 7, received_sha256 = ?, uploaded_at = 5 WHERE id = ?",
            ("d" * 64, delivery.id),
        )
    report = sweeper.join()
    assert report.ambiguous == ()  # it saw UPLOADED, not INITIATED: not even a false report
    assert (lab.quarantine_root / delivery.storage_key).read_bytes() == b"bytes of an upload that is committing right now"


def test_reconcile_while_an_upload_is_arriving_can_interrupt_it_so_it_is_a_maintenance_window_operation(lab):
    """The observed interaction, not a protection: min_age is an age threshold, not proof that nobody is writing.

    The upload below has been quiet for two hours when reconcile runs. With a threshold under that age its staged file is
    removed from under it and the upload fails (a generic 500, the delivery still awaiting content, never a false
    UPLOADED); with a larger one it is left alone and completes. Nothing in reconcile can tell a stalled upload from one
    that is still going, which is why it must run only when no upload is active.
    """
    outcomes = {}
    for label, min_age, status in (("above the quiet time", timedelta(hours=3), 201), ("below the quiet time", timedelta(hours=1), 500)):
        delivery = lab.new_delivery()
        reports = []

        def quiet_for_two_hours_then_swept():
            for staged in (lab.quarantine_root / ".incoming").iterdir():
                age(lab, staged, timedelta(hours=2))
            reports.append(sweep(lab, min_age))

        client = lab.upload_client(delivery, [b"first half, ", quiet_for_two_hours_then_swept, b"second half"])
        play(lab.app, client)
        row = lab.delivery_row(delivery)
        outcomes[label] = (client.status, bool(reports[0].removed_incoming), row["state"])
        assert client.status == status
        assert (reports[0].removed_incoming != ()) == (status == 500)
        if status == 201:
            assert row["state"] == "UPLOADED" and (lab.quarantine_root / row["storage_key"]).read_bytes() == b"first half, second half"
        else:
            assert row["state"] == "INITIATED" and row["received_sha256"] is None  # a failed upload, never a false UPLOADED
            assert not (lab.quarantine_root / row["storage_key"]).exists() and lab.incoming_names() == []
    assert outcomes == {"above the quiet time": (201, False, "UPLOADED"), "below the quiet time": (500, True, "INITIATED")}


def test_the_sweep_needs_an_absolute_root_and_a_real_age(lab):
    with pytest.raises(ValueError, match="absolute"):
        ingest.reconcile(lab.clock, lab.path, lab.quarantine_root.relative_to(lab.quarantine_root.parent), min_age=HOUR)
    for bad in (None, 3600, -HOUR):
        with pytest.raises((TypeError, ValueError)):
            sweep(lab, bad)


def test_the_sweep_uses_the_injected_clock_and_removes_nothing_when_the_clock_is_before_the_files(lab):
    old = plant(lab, "11" * 16, where=".incoming")
    age(lab, old, timedelta(0))
    lab.clock.moment = lab.clock.moment - timedelta(days=1)  # the files are "from the future": nothing is old enough
    assert sweep(lab, timedelta(0)).removed_incoming == () and old.exists()


def test_the_sweep_never_follows_a_staging_symlink(lab, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / ("11" * 16)).write_bytes(b"outside")
    (lab.quarantine_root / ".incoming").symlink_to(elsewhere)
    with pytest.raises(OSError):
        sweep(lab, timedelta(0))
    assert (elsewhere / ("11" * 16)).read_bytes() == b"outside"
