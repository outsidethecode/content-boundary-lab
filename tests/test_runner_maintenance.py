"""M1M: the operator's maintenance commands, and the exclusion that keeps them off work in progress.

Reconciliation removes the server's own scratch files and finishes or reports what a crash left behind. Run during an
upload or a promotion it would damage that work, and the only thing that can tell the two apart is that nobody is working.
So the runner's commands tell each other what they are doing through the lock on the quarantine root (tests/test_root_
exclusion.py shows the lock itself); here the commands are run as separate programs against a lab that is, or is not, in the
middle of something. Nothing is scheduled, and nothing is recovered that cannot be proved to belong to the lab.
Synthetic data only.
"""

import json
import os
import time
from hashlib import sha256

import pytest
from support.http_lab import CLEAN_FILE, make_lab  # noqa: F401  (make_lab is a fixture)
from support.processes import other_process, run_runner
from support.scanners import ScriptedScanner
from support.workflow import World

from content_boundary_lab import promotion, runner
from content_boundary_lab.clock import SystemClock
from content_boundary_lab.scanner import ScannerUnavailable

H = sha256(CLEAN_FILE).hexdigest()
NAME = "a" * 32
LONG_AGO = time.time() - 2 * 24 * 3600


@pytest.fixture
def world(tmp_path) -> World:
    return World(tmp_path)


def reconcile_program(world: World, age: str = "0"):
    return run_runner("reconcile", *world.storage, "--min-age-seconds", age)


def upload_in_progress(world: World):
    """What an active upload leaves in quarantine while it is arriving: a staged file, here two days old on purpose."""
    incoming = world.quarantine / ".incoming"
    incoming.mkdir(mode=0o700, exist_ok=True)
    staged = incoming / NAME
    staged.write_bytes(b"synthetic bytes still arriving")
    os.utime(staged, (LONG_AGO, LONG_AGO))
    return staged


def half_promoted(world: World):
    """A promotion stopped after its copy: PROMOTING, with a complete staged file and no published one (M0 §5.4)."""
    delivery = world.accepted(CLEAN_FILE)
    promoting = promotion.begin(world.a, delivery, clock=SystemClock(), database_path=world.database)
    promotion.stage(promoting, quarantine_root=world.quarantine, asset_root=world.trusted)
    return delivery, promoting


# --- exclusion -----------------------------------------------------------------------------------------------------------------


def test_reconcile_cannot_start_while_the_server_serves_so_an_upload_in_progress_is_never_removed(world):
    staged = upload_in_progress(world)
    seen = {}

    def while_serving(app, host, port):
        seen["done"] = reconcile_program(world)  # a separate program, started while the server holds the root

    serving = ["--settings", str(world.settings), *world.storage, "--max-upload-bytes", "1024", "--port", "8123"]
    assert runner.main(["serve", *serving], server=while_serving) == 0
    done = seen["done"]
    assert done.returncode == 3 and "in use" in done.stderr and done.stdout == ""
    assert staged.read_bytes() == b"synthetic bytes still arriving"  # two days old and a minimum age of 0: only the lock kept it
    after = world.reconcile()  # the server has stopped
    assert after.code == 0 and after.result["quarantine"]["removed_incoming"] == [NAME] and not staged.exists()


def test_reconcile_cannot_start_beside_a_promotion_or_a_rescan_in_progress(world):
    staged = upload_in_progress(world)
    with other_process(world.quarantine, "shared"):  # any worker: a promotion, a rescan, a server
        done = reconcile_program(world)
    assert done.returncode == 3 and "in use" in done.stderr and staged.exists()


def test_a_promotion_cannot_start_during_reconciliation(world):
    delivery = world.accepted(CLEAN_FILE)
    with other_process(world.quarantine, "exclusive"):
        done = run_runner("promote", *world.storage, "--production-id", world.a, "--delivery-id", delivery)
    assert done.returncode == 3 and "in use" in done.stderr
    assert world.delivery(delivery)["state"] == "ACCEPTED" and world.trusted_tree() == []


def test_a_rescan_cannot_start_during_reconciliation(world):
    delivery = world.sealed(CLEAN_FILE)
    with other_process(world.quarantine, "exclusive"):
        done = run_runner("rescan", "--database", str(world.database), "--quarantine-root", str(world.quarantine), "--delivery-id", delivery)
    assert done.returncode == 3 and "in use" in done.stderr
    assert not any(row["action"] == "delivery.request_rejected" for row in world.audit())  # it did not even ask


def test_the_server_cannot_start_during_reconciliation(world):
    with other_process(world.quarantine, "exclusive"):
        served = []
        serving = ["--settings", str(world.settings), *world.storage, "--max-upload-bytes", "1024", "--port", "8123"]
        assert runner.main(["serve", *serving], server=lambda *call: served.append(call)) == runner.EXIT_REFUSED
    assert served == []


def test_promotions_run_beside_the_server_and_beside_each_other(world):
    first, second = world.accepted(CLEAN_FILE), world.accepted(CLEAN_FILE + b"more")
    with other_process(world.quarantine, "shared"):  # a server, or another promotion, is working
        done = run_runner("promote", *world.storage, "--production-id", world.a, "--delivery-id", first)
        assert done.returncode == 0, done.stderr
        assert world.promote(world.a, second).code == 0


def test_a_worker_that_is_killed_leaves_no_lock_so_reconciliation_can_follow_a_crash(world):
    with other_process(world.quarantine, "shared") as worker:
        assert reconcile_program(world).returncode == 3
        worker.kill()
        worker.wait()
    assert reconcile_program(world).returncode == 0


# --- recovery ------------------------------------------------------------------------------------------------------------------


def test_reconcile_finishes_a_promotion_a_crash_left_after_its_copy(world):
    delivery, promoting = half_promoted(world)
    assert world.delivery(delivery)["state"] == "PROMOTING"
    done = world.reconcile()
    assert done.code == 0 and done.result["promotion"]["completed"] == [delivery]
    assert world.delivery(delivery)["state"] == "PROMOTED"
    assert world.download("vendor_a", world.a, promoting.asset_id).content == CLEAN_FILE
    assert sorted(p.name for p in world.trusted.rglob("*") if p.is_file()) == [promoting.asset_id]  # no staged leftover


def test_reconcile_preserves_and_reports_a_file_it_cannot_explain_and_does_not_decide_for_it(world):
    delivery = world.accepted(CLEAN_FILE)
    promoting = promotion.begin(world.a, delivery, clock=SystemClock(), database_path=world.database)
    occupant = world.trusted / promoting.asset_id
    occupant.write_bytes(b"someone else's bytes")  # not provably this attempt's
    for _ in range(2):  # and doing it again changes nothing more
        done = world.reconcile()
        assert done.code == 0 and done.result["promotion"]["ambiguous"] == [delivery]
        assert occupant.read_bytes() == b"someone else's bytes"
        assert world.delivery(delivery)["state"] == "PROMOTING"
    assert world.rows("SELECT * FROM assets") == []  # nothing serves it
    assert world.download("vendor_a", world.a, promoting.asset_id).status_code in (403, 404)


def test_reconcile_reports_what_is_not_the_labs_and_leaves_it_alone(world):
    (world.quarantine / "notes.txt").write_bytes(b"not the lab's")
    (world.quarantine / ("b" * 32)).write_bytes(b"no delivery claims this")
    done = world.reconcile()
    assert done.result["quarantine"]["foreign"] == ["notes.txt"]
    assert done.result["quarantine"]["unreferenced"] == ["b" * 32]
    assert (world.quarantine / "notes.txt").exists() and (world.quarantine / ("b" * 32)).exists()


def test_reconcile_twice_leaves_the_same_state(world):
    upload_in_progress(world)
    half_promoted(world)
    first = world.reconcile()
    tree = (sorted(p.name for p in world.quarantine.rglob("*")), world.trusted_tree(), world.rows("SELECT id, state FROM deliveries"))
    second = world.reconcile()
    assert first.result["quarantine"]["removed_incoming"] == [NAME] and second.result["quarantine"]["removed_incoming"] == []
    assert (sorted(p.name for p in world.quarantine.rglob("*")), world.trusted_tree(), world.rows("SELECT id, state FROM deliveries")) == tree


def test_a_recent_staged_file_is_kept_when_a_minimum_age_is_asked_for(world):
    staged = upload_in_progress(world)
    os.utime(staged, None)  # written just now
    done = world.reconcile(min_age=3600)
    assert done.result["quarantine"]["removed_incoming"] == [] and staged.exists()


# --- A-J7: a delivery stranded in SEALING ------------------------------------------------------------------------------------


def strand(world: World, content: bytes) -> str:
    """A delivery whose seal ended before it recorded an outcome: UPLOADED -> SEALING and nothing after it."""
    delivery = world.declare("vendor_a", world.a, content)
    assert world.upload("vendor_a", world.a, delivery, content).status_code == 201
    import sqlite3

    conn = sqlite3.connect(world.database)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("UPDATE deliveries SET state = 'SEALING' WHERE id = ? AND state = 'UPLOADED'", (delivery,))
        conn.commit()
    finally:
        conn.close()
    return delivery


def test_a_delivery_stranded_in_sealing_is_listed_and_left_exactly_as_it_is(world):
    stranded = strand(world, CLEAN_FILE)
    before, verdicts, trail = world.delivery(stranded), world.rows("SELECT * FROM verdicts"), world.audit()
    done = world.reconcile()
    assert done.code == 0 and done.result["stranded_in_sealing"] == [stranded]
    assert world.delivery(stranded) == before  # not reset, not failed, not passed
    assert world.rows("SELECT * FROM verdicts") == verdicts == []  # no verdict was invented
    assert world.audit() == trail  # and nothing was recorded about a decision nobody made
    assert world.accept("coordinator_a", world.a, stranded, H).status_code == 409
    assert world.promote(world.a, stranded).code == 3


def test_a_lab_with_nothing_stranded_says_so(world):
    assert world.reconcile().result["stranded_in_sealing"] == []


# --- rescan, as the operator runs it -----------------------------------------------------------------------------------------


def rescan_program(lab, delivery_id: str):
    return run_runner("rescan", "--database", str(lab.path), "--quarantine-root", str(lab.quarantine_root), "--delivery-id", delivery_id)


def test_rescan_gives_a_failed_scan_another_go_under_the_rescan_system_actor(make_lab):
    lab = make_lab("rescan", ScriptedScanner(ScannerUnavailable()))
    delivery = lab.delivered(CLEAN_FILE)
    assert lab.seal(delivery).status_code == 502 and lab.delivery_row(delivery)["state"] == "SCAN_FAILED"
    done = rescan_program(lab, delivery)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout) == {"delivery_id": delivery, "reason": None, "state": "SCAN_PASSED"}
    last = lab.audit_rows()[-2:]
    assert [(row["action"], row["actor_issuer"], row["actor_subject"]) for row in last] == [
        ("delivery.rescan_started", "system:content-boundary-lab", "rescan"),
        ("delivery.scan_passed", "system:content-boundary-lab", "rescan"),
    ]
    assert last[-1]["engine_kind"] == "synthetic"
    assert lab.delivery_row(delivery)["sealed_sha256"] == H  # the sealed digest was the thing compared, and it was not replaced


def test_rescan_refuses_what_is_not_eligible_and_says_which_rule(world):
    delivery = world.sealed(CLEAN_FILE)  # SCAN_PASSED with a verdict that still counts on the real clock
    for argument, reason in ((delivery, "state_conflict"), ("not-an-id", "invalid_identifier"), ("0" * 32, "not_found_or_forbidden")):
        done = world.rescan(argument)
        assert done.code == 3 and reason in done.err, (argument, done.err)
    assert world.delivery(delivery)["state"] == "SCAN_PASSED"
