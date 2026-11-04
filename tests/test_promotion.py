"""Trusted promotion (M0 §2 step 7, Addendum §5.4): the F-04 reference.

The initiator is M0's "System job", so this is a system operation and not a route: `promotion.promote(production_id,
delivery_id, ...)` runs as the named system actor `system:content-boundary-lab` / `promote`, and a recovery pass
(`promotion.reconcile`) finishes or reports what a crash left. The protocol is M0's P1 to P4, with the order the reviewer
asked for inside P4:

    P1  compare-and-set ACCEPTED -> PROMOTING, recording the attempt id and the server-generated asset key
    P2  copy quarantine -> trusted/.staging/<attempt>, hashing and counting the bytes written, outside any transaction
    P3  link the verified staged file to trusted/<asset key>, no clobber                     } one short
    P4  insert the asset row, compare-and-set PROMOTING -> PROMOTED, one audit event, commit  } transaction

Real files, the real asset route for the download, and SQLite read back for every claim. Content here is synthetic.
"""

import errno
import os
import sqlite3
import threading
from types import SimpleNamespace

import pytest
from support.http_lab import (
    CLEAN_FILE,
    T0,
    THREAD_WAIT,
    Background,
    make_lab,
    occupy,
    sha256_hex,
    transaction_whose_commit_fails,
)
from support.scanners import CountingScanner

from content_boundary_lab import assets, audit, promotion, quarantine, store, trust
from content_boundary_lab.audit import AuditReason
from content_boundary_lab.clock import to_micros

HASH = sha256_hex(CLEAN_FILE)
SYSTEM_PROMOTE = ("system:content-boundary-lab", "promote")
OCCUPANTS = ["a regular file", "a dangling symlink", "a symlink to a file outside", "a directory", "a named pipe"]


# --- the harness: the steps, called one at a time ----------------------------------------------------------------------------


def parts(lab):
    return dict(clock=lab.clock, database_path=lab.path, quarantine_root=lab.quarantine_root, asset_root=lab.asset_root)


def promote(lab, delivery_id, production=None):
    return promotion.promote(production or lab.alpha, delivery_id, **parts(lab))


def begin(lab, delivery_id, production=None):  # P1
    return promotion.begin(production or lab.alpha, delivery_id, clock=lab.clock, database_path=lab.path)


def stage(lab, promoting):  # P2
    return promotion.stage(promoting, quarantine_root=lab.quarantine_root, asset_root=lab.asset_root)


def publish(lab, promoting, written):  # P3 and P4
    return promotion.publish(promoting, written, clock=lab.clock, database_path=lab.path, asset_root=lab.asset_root)


def fail(lab, promoting):  # P4, the failure branch
    return promotion.fail(promoting, clock=lab.clock, database_path=lab.path, asset_root=lab.asset_root)


def reconcile(lab):
    return promotion.reconcile(**parts(lab))


def trail(lab, since=0):
    return [(row["action"], row["outcome"], row["reason"]) for row in lab.audit_rows()[since:]]


def actors(lab, since=0):
    return {(row["actor_issuer"], row["actor_subject"]) for row in lab.audit_rows()[since:]}


@pytest.fixture
def rig(make_lab):
    scanner = CountingScanner()
    return SimpleNamespace(lab=make_lab("rig", scanner), scanner=scanner)


def flip_a_byte(path):
    data = bytearray(path.read_bytes())
    data[-1] ^= 0xFF
    path.write_bytes(bytes(data))


# --- the whole path --------------------------------------------------------------------------------------------------------


def test_an_accepted_delivery_becomes_a_trusted_asset_that_can_be_downloaded(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)  # declared, uploaded, sealed and accepted by the server's own routes
    before_tree, seeded, since = lab.trusted_tree(), len(lab.asset_rows()), len(lab.audit_rows())
    result = promote(lab, delivery)
    assert result == promotion.PromotionResult(delivery, "PROMOTED", result.asset_id)
    asset_id = result.asset_id
    row = lab.delivery_row(delivery)
    assert (row["state"], row["asset_id"], row["accepted_sha256"], row["sealed_sha256"]) == ("PROMOTED", asset_id, HASH, HASH)
    assert row["promotion_attempt"] not in (None, asset_id)
    (asset,) = lab.asset_rows()[seeded:]
    assert (asset["id"], asset["production_id"], asset["delivery_id"], asset["sha256"], asset["size"]) == (
        asset_id, lab.alpha, delivery, HASH, len(CLEAN_FILE),
    )  # fmt: skip
    assert asset["display_name"] == "shot-020.png" and asset["created_at"] == to_micros(T0)
    final = lab.asset_root / asset_id
    assert final.is_file() and not final.is_symlink() and final.read_bytes() == CLEAN_FILE and final.stat().st_mode & 0o777 == 0o600
    assert lab.trusted_tree() == sorted([*before_tree, asset_id, ".staging"])  # the file, and an empty staging directory
    assert list((lab.asset_root / ".staging").iterdir()) == []
    assert lab.stored_path(delivery).read_bytes() == CLEAN_FILE  # quarantine is not touched by promotion
    assert trail(lab, since) == [("delivery.promotion_started", "allowed", None), ("delivery.promoted", "recorded", None)]
    events = lab.audit_rows()[since:]
    assert actors(lab, since) == {SYSTEM_PROMOTE} and {event["engine_kind"] for event in events} == {None}
    assert {(e["production_id"], e["object_type"], e["object_id"]) for e in events} == {(lab.alpha, "delivery", delivery)}
    for subject in ("vendor-1", "coordinator-1"):  # the existing asset route serves it, unchanged
        downloaded = lab.download(asset_id, subject)
        assert downloaded.status_code == 200 and downloaded.content == CLEAN_FILE
        assert downloaded.headers["content-type"] == "application/octet-stream" and downloaded.headers["x-content-type-options"] == "nosniff"
        assert sha256_hex(downloaded.content) == HASH


def test_a_promoted_asset_is_readable_by_its_own_production_and_by_no_other(rig):
    lab = rig.lab
    asset_id = promote(lab, lab.accepted(CLEAN_FILE)).asset_id
    since = len(lab.audit_rows())
    assert lab.download(asset_id, "coordinator-1").status_code == 200
    assert lab.download(asset_id, "vendor-2", lab.alpha).status_code == 403  # a vendor of another production, through ours
    assert lab.download(asset_id, "vendor-2", lab.bravo).status_code == 404  # and through its own: the asset is not there
    assert lab.download(asset_id, "coordinator-2", lab.bravo).status_code == 404
    assert lab.download(asset_id, None).status_code == 401
    assert lab.download(".staging", "vendor-1").status_code == 404  # the staging directory is not an asset id
    assert [e["reason"] for e in lab.audit_rows()[since + 1 :]] == [
        "no_engagement", "not_found_or_forbidden", "not_found_or_forbidden", "invalid_credentials", "invalid_identifier",
    ]  # fmt: skip


def test_the_downloaded_bytes_are_the_bytes_whose_digest_was_verified_during_the_copy(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    copied = []
    real = promotion.copy_verified

    def recording(*args):
        copied.append(real(*args))
        return copied[-1]

    monkeypatch.setattr(promotion, "copy_verified", recording)
    result = promote(lab, delivery)
    (written,) = copied
    body = lab.download(result.asset_id).content
    assert (written.size, written.sha256) == (len(body), sha256_hex(body)) == (len(CLEAN_FILE), HASH)
    assert (lab.asset_root / result.asset_id).stat().st_ino == written.inode  # the verified file is the published file


def test_promotion_hashes_what_it_writes_and_does_not_borrow_the_digest_of_the_seal(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)

    def forbidden(*args, **kwargs):
        raise AssertionError("promotion must not ask the sealing gate for an identity")

    monkeypatch.setattr(trust, "content_identity", forbidden)
    monkeypatch.setattr(trust, "lookup_verdict", forbidden)
    assert promote(lab, delivery).state == "PROMOTED"


def test_promoting_again_is_a_no_op_that_returns_the_original_result(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    first = promote(lab, delivery)
    row, tree, assets_before, events = lab.delivery_row(delivery), lab.trusted_tree(), lab.asset_rows(), len(lab.audit_rows())
    assert promote(lab, delivery) == first
    assert (lab.delivery_row(delivery), lab.trusted_tree(), lab.asset_rows(), len(lab.audit_rows())) == (row, tree, assets_before, events)


def test_two_deliveries_of_the_same_bytes_become_two_assets_with_two_keys(rig):
    lab = rig.lab
    first, second = lab.accepted(CLEAN_FILE), lab.accepted(CLEAN_FILE)
    one, two = promote(lab, first), promote(lab, second)
    assert one.asset_id != two.asset_id and lab.download(one.asset_id).content == lab.download(two.asset_id).content == CLEAN_FILE


# --- who and what may be promoted -----------------------------------------------------------------------------------------


def test_a_delivery_of_another_production_is_not_promoted_through_this_one(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    before, tree, since = lab.delivery_row(delivery), lab.trusted_tree(), len(lab.audit_rows())
    with pytest.raises(promotion.PromotionRefused) as refused:
        promote(lab, delivery, production=lab.bravo)
    assert refused.value.reason is AuditReason.NOT_FOUND_OR_FORBIDDEN
    assert (lab.delivery_row(delivery), lab.trusted_tree()) == (before, tree)
    (event,) = lab.audit_rows()[since:]
    assert (event["action"], event["outcome"], event["reason"], event["production_id"], event["object_id"]) == (
        "delivery.request_rejected", "denied", "not_found_or_forbidden", lab.bravo, delivery,
    )  # fmt: skip
    assert (event["actor_issuer"], event["actor_subject"]) == SYSTEM_PROMOTE


@pytest.mark.parametrize(
    ("production", "delivery", "reason", "recorded"),
    [
        ("alpha", "f" * 32, AuditReason.NOT_FOUND_OR_FORBIDDEN, True),
        ("0" * 32, "delivery", AuditReason.NOT_FOUND_OR_FORBIDDEN, True),
        ("alpha", "A" * 32, AuditReason.INVALID_IDENTIFIER, False),
        ("alpha", "../" + "a" * 29, AuditReason.INVALID_IDENTIFIER, False),
        ("ALPHA-UPPER", "delivery", AuditReason.INVALID_IDENTIFIER, False),
        ("short", "delivery", AuditReason.INVALID_IDENTIFIER, False),
    ],
)
def test_a_missing_or_malformed_id_is_refused_and_recorded(rig, production, delivery, reason, recorded):
    lab = rig.lab
    real = lab.accepted(CLEAN_FILE)
    production_id = lab.production(production) if production != "0" * 32 else production
    delivery_id = real if delivery == "delivery" else delivery
    since = len(lab.audit_rows())
    with pytest.raises(promotion.PromotionRefused) as refused:
        promote(lab, delivery_id, production=production_id)
    assert refused.value.reason is reason
    (event,) = lab.audit_rows()[since:]
    assert (event["action"], event["reason"]) == ("delivery.request_rejected", reason.value)
    assert (event["object_id"] is not None) is recorded
    assert lab.delivery_row(real)["state"] == "ACCEPTED"


@pytest.mark.parametrize("state", ["INITIATED", "UPLOADED", "SEALING", "REJECTED", "SCAN_FAILED", "SCAN_PASSED", "PROMOTING", "INTEGRITY_FAILED"])
def test_only_an_accepted_delivery_is_promoted(rig, state):
    lab = rig.lab
    delivery = lab.seed_delivery("vendor-1", state=state)
    before, tree, since = lab.delivery_row(delivery.id), lab.trusted_tree(), len(lab.audit_rows())
    with pytest.raises(promotion.PromotionRefused) as refused:
        promote(lab, delivery.id)
    assert refused.value.reason is AuditReason.STATE_CONFLICT
    assert (lab.delivery_row(delivery.id), lab.trusted_tree(), len(lab.asset_rows())) == (before, tree, 3)
    assert trail(lab, since) == [("delivery.request_rejected", "denied", "state_conflict")]


def test_a_promoted_delivery_seeded_without_a_file_is_still_a_no_op(rig):
    lab = rig.lab
    delivery = lab.seed_delivery("vendor-1", state="PROMOTED")
    tree = lab.trusted_tree()
    result = promote(lab, delivery.id)
    assert result == promotion.PromotionResult(delivery.id, "PROMOTED", lab.delivery_row(delivery.id)["asset_id"])
    assert lab.trusted_tree() == tree and lab.audit_rows() == []


def test_an_accepted_delivery_whose_verdict_is_not_one_for_its_digest_is_refused(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    tree = lab.trusted_tree()
    monkeypatch.setattr(trust, "verdict_binding_problem", lambda *args: AuditReason.VERDICT_NOT_APPLICABLE)
    with pytest.raises(promotion.PromotionRefused) as refused:
        promote(lab, delivery)
    assert refused.value.reason is AuditReason.VERDICT_NOT_APPLICABLE
    assert lab.delivery_row(delivery)["state"] == "ACCEPTED" and lab.trusted_tree() == tree


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({}, None),
        ({"verdict": "detection"}, AuditReason.VERDICT_NOT_APPLICABLE),
        ({"sha256": "b" * 64, "scanned_sha256": "b" * 64}, AuditReason.VERDICT_NOT_APPLICABLE),
        ({"scanned_sha256": "b" * 64}, AuditReason.VERDICT_NOT_APPLICABLE),
        ({"engine_version": "2"}, None),  # which engine made it is acceptance's question and not promotion's
        ({"valid_until": 11}, None),  # and so is freshness: M0 records that validity is not rechecked at promotion
    ],
)
def test_promotion_asks_only_whether_the_verdict_is_a_no_detection_verdict_for_the_digest(changes, expected):
    base = dict(
        id="1" * 32, sha256=HASH, engine_id="e", engine_version="1", engine_kind="synthetic", policy_fingerprint="f" * 64,
        verdict="no_detection", scanned_sha256=HASH, scanned_at=10, valid_until=20,
    )  # fmt: skip
    record = trust.VerdictRecord(**{**base, **changes})
    assert trust.verdict_binding_problem(record, trust.ContentIdentity(HASH)) is expected
    assert trust.verdict_binding_problem(None, trust.ContentIdentity(HASH)) is AuditReason.VERDICT_NOT_APPLICABLE


# --- F-04: the bytes in quarantine are not the bytes that were accepted -------------------------------------------------------

CHANGES = {
    "a byte flipped": flip_a_byte,
    "bytes appended": lambda path: path.write_bytes(path.read_bytes() + b"appended after acceptance"),
    "one byte missing": lambda path: path.write_bytes(path.read_bytes()[:-1]),
    "another file of the same size": lambda path: path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * (len(CLEAN_FILE) - 8)),
    "emptied": lambda path: path.write_bytes(b""),
}


@pytest.mark.parametrize("change", CHANGES.values(), ids=list(CHANGES))
def test_bytes_changed_in_quarantine_after_acceptance_are_never_published(rig, change):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    change(lab.stored_path(delivery))
    tampered = lab.stored_path(delivery).read_bytes()
    before, tree, seeded, since = lab.delivery_row(delivery), lab.trusted_tree(), len(lab.asset_rows()), len(lab.audit_rows())
    result = promote(lab, delivery)
    assert result == promotion.PromotionResult(delivery, "INTEGRITY_FAILED", None)
    row = lab.delivery_row(delivery)
    assert row["state"] == "INTEGRITY_FAILED" and row["state_reason"] is None
    assert (row["accepted_sha256"], row["sealed_sha256"], row["sealed_size"], row["verdict_id"]) == (
        HASH, HASH, len(CLEAN_FILE), before["verdict_id"],
    )  # the accepted digest is not replaced and nothing is rebound to the bytes that were found
    assert len(lab.asset_rows()) == seeded and [e["delivery_id"] for e in lab.asset_rows() if e["delivery_id"]] == []
    assert lab.trusted_tree() == sorted([*tree, ".staging"]) and list((lab.asset_root / ".staging").iterdir()) == []
    assert lab.stored_path(delivery).read_bytes() == tampered  # promotion neither repaired nor removed what it found
    assert trail(lab, since) == [("delivery.promotion_started", "allowed", None), ("delivery.integrity_failed", "denied", "sealed_content_changed")]
    assert actors(lab, since) == {SYSTEM_PROMOTE}
    rows = str(lab.delivery_rows()) + str(lab.asset_rows()) + str(lab.verdict_rows()) + str(lab.audit_rows())
    assert sha256_hex(tampered) not in rows  # the digest of what was found is recorded nowhere
    assert lab.download(row["asset_id"]).status_code == 404  # the key that was reserved serves nothing


def test_a_delivery_that_failed_its_integrity_check_is_final(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    flip_a_byte(lab.stored_path(delivery))
    assert promote(lab, delivery).state == "INTEGRITY_FAILED"
    with pytest.raises(promotion.PromotionRefused) as refused:
        promote(lab, delivery)
    assert refused.value.reason is AuditReason.STATE_CONFLICT
    flip_a_byte(lab.stored_path(delivery))  # even bytes that now match again do not revive it
    with pytest.raises(promotion.PromotionRefused):
        promote(lab, delivery)
    assert lab.delivery_row(delivery)["state"] == "INTEGRITY_FAILED"


def test_a_file_changed_while_it_is_being_copied_cannot_get_past_the_digest(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    path = lab.stored_path(delivery)
    real = quarantine.StoredFile.chunks

    def changing_chunks(self, chunk_size=64 * 1024):
        blocks = real(self, 100)
        yield next(blocks)
        with path.open("r+b") as handle:  # after the first block was read, the rest of the file is changed
            handle.seek(len(CLEAN_FILE) - 50)
            handle.write(b"changed during the copy" + b"!" * 20)
        yield from blocks

    monkeypatch.setattr(quarantine.StoredFile, "chunks", changing_chunks)
    tree = lab.trusted_tree()
    assert promote(lab, delivery).state == "INTEGRITY_FAILED"
    assert lab.trusted_tree() == sorted([*tree, ".staging"]) and len(lab.asset_rows()) == 3


def test_a_file_that_changes_back_and_forth_is_judged_by_the_bytes_that_were_written(rig, monkeypatch):
    """Whatever is published has the accepted digest, because that is the digest of the bytes written, and only that."""
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    path = lab.stored_path(delivery)
    original = path.read_bytes()
    real = quarantine.StoredFile.chunks

    def touched_chunks(self, chunk_size=64 * 1024):
        yield from real(self, 100)
        path.write_bytes(b"something else entirely")  # after every byte was read and copied
        path.write_bytes(original)

    monkeypatch.setattr(quarantine.StoredFile, "chunks", touched_chunks)
    result = promote(lab, delivery)
    assert result.state == "PROMOTED"
    assert sha256_hex((lab.asset_root / result.asset_id).read_bytes()) == HASH


def storage_changes(lab, delivery, how):
    path = lab.stored_path(delivery)
    original = path.read_bytes()
    path.unlink()
    if how == "missing":
        return
    outside = lab.asset_root.parent / "outside"
    outside.mkdir(exist_ok=True)
    if how == "a symlink to a copy with the same bytes":
        (outside / "copy").write_bytes(original)
        path.symlink_to(outside / "copy")
    else:
        occupy(path, outside, how)


STORAGE = ["missing", "a symlink to a copy with the same bytes", "a dangling symlink", "a directory", "a named pipe"]


@pytest.mark.parametrize("how", STORAGE)
def test_a_missing_symlinked_or_non_regular_source_is_an_integrity_failure_and_publishes_nothing(rig, how):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    storage_changes(lab, delivery, how)
    tree, since = lab.trusted_tree(), len(lab.audit_rows())
    assert promote(lab, delivery).state == "INTEGRITY_FAILED"
    assert lab.trusted_tree() == tree and len(lab.asset_rows()) == 3  # the source was refused before anything was staged
    assert trail(lab, since)[-1] == ("delivery.integrity_failed", "denied", "sealed_content_changed")
    assert (lab.asset_root.parent / "outside" / "copy").exists() is (how == "a symlink to a copy with the same bytes")


def test_a_failure_to_copy_that_says_nothing_about_the_bytes_leaves_the_delivery_promoting_and_publishes_nothing(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    tree, since = lab.trusted_tree(), len(lab.audit_rows())
    calls = []
    real = assets.StagingFile.write

    def out_of_space(self, chunk):
        calls.append(len(chunk))
        if len(calls) == 2:
            raise OSError(errno.ENOSPC, "no space left on device")
        return real(self, chunk)

    monkeypatch.setattr(quarantine.StoredFile, "chunks", lambda self, chunk_size=64 * 1024: iter([CLEAN_FILE[:100], CLEAN_FILE[100:]]))
    monkeypatch.setattr(assets.StagingFile, "write", out_of_space)
    with pytest.raises(OSError) as error:
        promote(lab, delivery)
    assert error.value.errno == errno.ENOSPC
    monkeypatch.undo()
    row = lab.delivery_row(delivery)
    assert row["state"] == "PROMOTING" and len(lab.asset_rows()) == 3
    assert lab.trusted_tree() == sorted([*tree, ".staging"]) and list((lab.asset_root / ".staging").iterdir()) == []
    assert trail(lab, since) == [("delivery.promotion_started", "allowed", None)]  # no completion is claimed
    report = reconcile(lab)  # and the recovery pass finishes it
    assert report.completed == (delivery,) and lab.delivery_row(delivery)["state"] == "PROMOTED"
    assert lab.download(lab.delivery_row(delivery)["asset_id"]).content == CLEAN_FILE


def test_a_read_error_in_quarantine_leaves_the_delivery_promoting_and_publishes_nothing(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    def unreadable(self, count, offset):
        raise OSError(errno.EIO, "i/o error")

    monkeypatch.setattr(quarantine.StoredFile, "_pread", unreadable)
    with pytest.raises(OSError) as error:
        promote(lab, delivery)
    assert error.value.errno == errno.EIO
    monkeypatch.undo()
    assert lab.delivery_row(delivery)["state"] == "PROMOTING" and list((lab.asset_root / ".staging").iterdir()) == []
    assert reconcile(lab).completed == (delivery,)


# --- publication ------------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", OCCUPANTS)
def test_a_file_already_at_the_final_name_is_never_overwritten(rig, tmp_path, kind):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    (lab.asset_root.parent / "outside").mkdir(exist_ok=True)
    describe = occupy(lab.asset_root / promoting.asset_id, lab.asset_root.parent / "outside", kind)
    before = describe()
    written = stage(lab, promoting)
    seeded_names = {name: (lab.asset_root / name).read_bytes() for name in lab.assets.values()}
    with pytest.raises(FileExistsError):
        publish(lab, promoting, written)
    assert describe() == before  # the occupant is exactly as it was
    assert lab.delivery_row(delivery)["state"] == "PROMOTING" and len(lab.asset_rows()) == 3
    assert list((lab.asset_root / ".staging").iterdir()) == []  # the staged file we made is gone
    assert {name: (lab.asset_root / name).read_bytes() for name in lab.assets.values()} == seeded_names
    assert trail(lab)[-1] == ("delivery.promotion_started", "allowed", None)  # and no completion is claimed
    report = reconcile(lab)  # nothing about the occupant can be proved: it is reported, not touched
    assert report.ambiguous == (delivery,) and report.completed == () and describe() == before
    assert lab.delivery_row(delivery)["state"] == "PROMOTING"


def test_a_failed_audit_insert_leaves_no_asset_row_and_removes_only_the_file_this_promotion_published(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    written = stage(lab, promoting)
    seeded = {name: (lab.asset_root / name).read_bytes() for name in lab.assets.values()}
    since = len(lab.audit_rows())
    lab.make_audit_inserts_fail()
    with pytest.raises(sqlite3.DatabaseError):
        publish(lab, promoting, written)
    assert not (lab.asset_root / promoting.asset_id).exists() and list((lab.asset_root / ".staging").iterdir()) == []
    assert lab.delivery_row(delivery)["state"] == "PROMOTING" and len(lab.asset_rows()) == 3 and len(lab.audit_rows()) == since
    assert {name: (lab.asset_root / name).read_bytes() for name in lab.assets.values()} == seeded  # nobody else's file was touched
    lab.restore_audit_inserts()
    assert reconcile(lab).completed == (delivery,)  # nothing was lost by the failure
    assert lab.download(lab.delivery_row(delivery)["asset_id"]).content == CLEAN_FILE


def test_a_commit_that_fails_leaves_no_asset_row_and_no_published_file(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    written = stage(lab, promoting)
    since, real, calls = len(lab.audit_rows()), store.transaction, []

    def first_commit_fails(conn):
        calls.append(1)
        return transaction_whose_commit_fails(conn) if len(calls) == 1 else real(conn)

    monkeypatch.setattr(store, "transaction", first_commit_fails)
    with pytest.raises(sqlite3.OperationalError):
        publish(lab, promoting, written)
    monkeypatch.undo()
    assert not (lab.asset_root / promoting.asset_id).exists() and len(lab.asset_rows()) == 3 and len(lab.audit_rows()) == since
    assert lab.delivery_row(delivery)["state"] == "PROMOTING" and list((lab.asset_root / ".staging").iterdir()) == []
    assert lab.download(promoting.asset_id).status_code == 404  # no row, so no asset, whatever the disk held for a moment
    assert reconcile(lab).completed == (delivery,)


def test_cleanup_after_a_failure_never_removes_a_file_that_is_not_the_one_published(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    written = stage(lab, promoting)
    final = lab.asset_root / promoting.asset_id
    real = assets.publish_staged

    def publish_then_replace(root, name, asset_id):
        real(root, name, asset_id)
        final.unlink()  # something else swaps the file for another one before the transaction ends
        final.write_bytes(b"a different file that someone else put there")

    monkeypatch.setattr(assets, "publish_staged", publish_then_replace)
    lab.make_audit_inserts_fail()
    with pytest.raises(sqlite3.DatabaseError):
        publish(lab, promoting, written)
    monkeypatch.undo()
    assert final.read_bytes() == b"a different file that someone else put there"  # not ours, so not removed
    assert lab.delivery_row(delivery)["state"] == "PROMOTING" and len(lab.asset_rows()) == 3
    lab.restore_audit_inserts()
    assert reconcile(lab).ambiguous == (delivery,)  # and it is reported for a person to decide


# --- two promoters --------------------------------------------------------------------------------------------------------


def test_a_second_promotion_of_the_same_delivery_is_refused_while_the_first_is_copying(make_lab, monkeypatch):
    lab = make_lab("race", CountingScanner())
    delivery = lab.accepted(CLEAN_FILE)
    entered, release = threading.Event(), threading.Event()
    real = promotion.copy_verified

    def blocked(*args):
        entered.set()
        assert release.wait(THREAD_WAIT), "the test never released the copy"
        return real(*args)

    monkeypatch.setattr(promotion, "copy_verified", blocked)
    first = Background(lambda: promote(lab, delivery))
    assert entered.wait(THREAD_WAIT)  # the first is copying, with no transaction open
    assert lab.delivery_row(delivery)["state"] == "PROMOTING"
    with pytest.raises(promotion.PromotionRefused) as refused:
        promote(lab, delivery)  # would wait out the busy timeout if the copy held the writer lock
    assert refused.value.reason is AuditReason.STATE_CONFLICT
    release.set()
    result = first.join()
    assert result.state == "PROMOTED"
    assert len(lab.asset_rows()) == 4 and sum(1 for e in lab.audit_rows() if e["action"] == "delivery.promoted") == 1
    assert [name for name in lab.trusted_tree() if len(name) == 32 and name not in lab.assets.values()] == [result.asset_id]
    assert trail(lab)[-3:] == [
        ("delivery.promotion_started", "allowed", None),
        ("delivery.request_rejected", "denied", "state_conflict"),
        ("delivery.promoted", "recorded", None),
    ]


def test_promoters_racing_for_one_delivery_publish_one_asset(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    barrier = threading.Barrier(4)
    outcomes = []

    def go():
        barrier.wait(THREAD_WAIT)
        try:
            return promote(lab, delivery)
        except promotion.PromotionRefused as refused:
            return refused

    runners = [Background(go) for _ in range(4)]
    outcomes = [runner.join() for runner in runners]
    promoted = [o for o in outcomes if isinstance(o, promotion.PromotionResult)]
    assert promoted and {o.asset_id for o in promoted} == {lab.delivery_row(delivery)["asset_id"]}  # one asset, however it is told
    assert all(isinstance(o, promotion.PromotionResult) or o.reason is AuditReason.STATE_CONFLICT for o in outcomes)
    assert sum(1 for e in lab.audit_rows() if e["action"] == "delivery.promoted") == 1
    assert len([row for row in lab.asset_rows() if row["delivery_id"] == delivery]) == 1
    assert sum(1 for name in lab.trusted_tree() if len(name) == 32 and name not in lab.assets.values()) == 1
    assert list((lab.asset_root / ".staging").iterdir()) == []


# --- every place a crash can leave things (M0 §5.4), built with the step functions and no hooks -------------------------------


def test_after_p1_only_there_is_nothing_on_disk_and_the_recovery_pass_runs_the_rest(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    row = lab.delivery_row(delivery)
    assert (row["state"], row["promotion_attempt"], row["asset_id"]) == ("PROMOTING", promoting.attempt, promoting.asset_id)
    assert not (lab.asset_root / ".staging").exists() and not (lab.asset_root / promoting.asset_id).exists()
    report = reconcile(lab)
    assert report.completed == (delivery,) and lab.delivery_row(delivery)["asset_id"] == promoting.asset_id  # the same key
    assert lab.download(promoting.asset_id).content == CLEAN_FILE


def test_after_a_partial_copy_the_staged_file_is_removed_and_the_copy_is_made_again(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    (lab.asset_root / ".staging").mkdir(mode=0o700)  # the process died mid-copy: a half-written file stays under its name
    (lab.asset_root / ".staging" / promoting.attempt).write_bytes(CLEAN_FILE[:100])
    assert reconcile(lab).completed == (delivery,)
    assert lab.download(promoting.asset_id).content == CLEAN_FILE and list((lab.asset_root / ".staging").iterdir()) == []


def test_after_a_complete_copy_before_the_link_it_is_copied_and_verified_again(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    stage(lab, promoting)
    assert (lab.asset_root / ".staging" / promoting.attempt).read_bytes() == CLEAN_FILE
    flip_a_byte(lab.stored_path(delivery))  # and the source is no longer what was accepted: the leftover copy is not trusted
    report = reconcile(lab)
    assert report.failed == (delivery,) and lab.delivery_row(delivery)["state"] == "INTEGRITY_FAILED"
    assert len(lab.asset_rows()) == 3 and list((lab.asset_root / ".staging").iterdir()) == []


def test_after_the_link_before_the_staged_name_is_removed_the_target_is_verified_and_the_promotion_finished(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    written = stage(lab, promoting)
    assets.publish_staged(lab.asset_root, promoting.attempt, promoting.asset_id)  # P3 done, the process dies before P4
    assert (lab.asset_root / promoting.asset_id).stat().st_nlink == 2
    report = reconcile(lab)
    assert report.completed == (delivery,) and lab.delivery_row(delivery)["state"] == "PROMOTED"
    final = lab.asset_root / promoting.asset_id
    assert final.stat().st_ino == written.inode and final.stat().st_nlink == 1  # the very file that was verified
    assert list((lab.asset_root / ".staging").iterdir()) == [] and lab.download(promoting.asset_id).content == CLEAN_FILE


def test_after_the_link_and_the_removal_of_the_staged_name_the_target_is_verified_and_the_promotion_finished(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    stage(lab, promoting)
    assets.publish_staged(lab.asset_root, promoting.attempt, promoting.asset_id)
    assets.remove_staged(lab.asset_root, promoting.attempt)  # only the target is left, and the database says PROMOTING
    assert lab.download(promoting.asset_id).status_code == 404  # the database is authoritative, whatever is on disk
    assert reconcile(lab).completed == (delivery,)
    assert lab.download(promoting.asset_id).content == CLEAN_FILE


def test_a_target_whose_bytes_are_not_the_accepted_bytes_is_reported_and_left_alone(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    (lab.asset_root / promoting.asset_id).write_bytes(b"not the accepted bytes")  # nothing proves whose it is
    report = reconcile(lab)
    assert report.ambiguous == (delivery,) and report.completed == () and report.failed == ()
    assert (lab.asset_root / promoting.asset_id).read_bytes() == b"not the accepted bytes"
    assert lab.delivery_row(delivery)["state"] == "PROMOTING" and len(lab.asset_rows()) == 3


def test_a_target_that_is_a_second_name_for_a_file_elsewhere_is_reported_and_left_alone(rig, tmp_path):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    elsewhere = lab.asset_root.parent / "elsewhere"
    elsewhere.write_bytes(CLEAN_FILE)  # the right bytes, but the file also has another name outside the root
    os.link(elsewhere, lab.asset_root / promoting.asset_id)
    report = reconcile(lab)
    assert report.ambiguous == (delivery,) and lab.delivery_row(delivery)["state"] == "PROMOTING" and elsewhere.exists()


def test_a_target_and_a_staged_file_that_are_different_files_are_reported_and_left_alone(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    stage(lab, promoting)
    (lab.asset_root / promoting.asset_id).write_bytes(CLEAN_FILE)
    report = reconcile(lab)
    assert report.ambiguous == (delivery,) and lab.delivery_row(delivery)["state"] == "PROMOTING"
    assert (lab.asset_root / promoting.asset_id).read_bytes() == CLEAN_FILE


def test_a_published_file_that_no_longer_matches_its_own_verified_copy_is_reported_and_preserved(rig):
    """It is very probably ours (one file under the key and under the staged name), and it has changed since it was
    verified. It is neither adopted nor deleted: both names are left as found and a person decides."""
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    stage(lab, promoting)
    assets.publish_staged(lab.asset_root, promoting.attempt, promoting.asset_id)
    flip_a_byte(lab.asset_root / promoting.asset_id)  # the two names are one file, and it changed after it was verified
    changed = (lab.asset_root / promoting.asset_id).read_bytes()
    report = reconcile(lab)
    assert report.ambiguous == (delivery,) and report.failed == () and report.completed == ()
    assert lab.delivery_row(delivery)["state"] == "PROMOTING" and len(lab.asset_rows()) == 3
    assert (lab.asset_root / promoting.asset_id).read_bytes() == changed == (lab.asset_root / ".staging" / promoting.attempt).read_bytes()
    assert lab.download(promoting.asset_id).status_code == 404  # whatever is on disk, it is not an asset


# --- A-K2: adopting a file that is already at the reserved key ---------------------------------------------------------------
#
# M0 §5.4, the crash table: "Link done, before unlink | PROMOTING, target and staging | Delete staging, verify target, run
# P4" and "P3, before P4 | PROMOTING and target | Re-hash target. If equal to H, run P4 success. Otherwise move it out of
# trusted/ and run P4 failure." Recovery adopts a file only if it is the very file that was verified, from the first look
# to the transaction that writes the asset row; anything else is preserved and reported.


def plant(lab, promoting, content=CLEAN_FILE):
    path = lab.asset_root / promoting.asset_id
    path.write_bytes(content)
    return path


def adopted(lab, delivery, path, inode):
    row = lab.delivery_row(delivery)
    assert row["state"] == "PROMOTED" and path.stat().st_ino == inode and path.read_bytes() == CLEAN_FILE
    (asset,) = [r for r in lab.asset_rows() if r["delivery_id"] == delivery]
    assert (asset["id"], asset["sha256"], asset["size"]) == (row["asset_id"], HASH, len(CLEAN_FILE))
    assert lab.download(asset["id"]).content == CLEAN_FILE


def test_a_regular_single_name_file_with_exactly_the_accepted_bytes_at_the_key_is_adopted_as_it_is(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    path = plant(lab, promoting)
    inode, since = path.stat().st_ino, len(lab.audit_rows())
    assert reconcile(lab).completed == (delivery,)
    assert trail(lab, since) == [("delivery.promoted", "recorded", None)] and actors(lab, since) == {SYSTEM_PROMOTE}
    adopted(lab, delivery, path, inode)  # the same file: nothing was copied over it, and nothing was removed


def test_a_file_with_the_accepted_size_and_other_bytes_is_not_adopted_and_is_preserved(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    other = bytearray(CLEAN_FILE)
    other[len(other) // 2] ^= 0x01  # one bit, in the middle: the size, the signature and the first and last bytes are the same
    path = plant(lab, promoting, bytes(other))
    report = reconcile(lab)
    assert report.ambiguous == (delivery,) and report.completed == ()
    assert path.read_bytes() == bytes(other) and lab.delivery_row(delivery)["state"] == "PROMOTING" and len(lab.asset_rows()) == 3


@pytest.mark.parametrize("content", [CLEAN_FILE[:-1], CLEAN_FILE + b"x", b""], ids=["shorter", "longer", "empty"])
def test_a_file_of_another_size_is_not_adopted_and_is_preserved(rig, content):
    lab = rig.lab
    promoting = begin(lab, lab.accepted(CLEAN_FILE))
    path = plant(lab, promoting, content)
    assert reconcile(lab).ambiguous == (promoting.delivery_id,)
    assert path.read_bytes() == content and len(lab.asset_rows()) == 3


def swap_how(path, how):
    """Change what the name at the key leads to, after the file there was verified."""
    if how == "another file with other bytes":
        path.unlink()
        path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"y" * (len(CLEAN_FILE) - 8))
    elif how == "another file with the same bytes":
        path.unlink()
        path.write_bytes(CLEAN_FILE)  # the same content, a different file: the one that was verified is not the one there
    elif how == "the same file changed in place":
        with path.open("r+b") as handle:
            handle.write(b"Z")
    elif how == "the same file touched":
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))  # the same bytes, and a time that says it was written to
    else:
        raise ValueError(how)


SWAPS = ["another file with other bytes", "another file with the same bytes", "the same file changed in place", "the same file touched"]


@pytest.mark.parametrize("how", SWAPS)
def test_a_file_that_is_swapped_after_it_was_verified_is_not_adopted_and_no_row_is_written(rig, monkeypatch, how):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    path = plant(lab, promoting)
    real, since = assets.measure, len(lab.audit_rows())

    def measure_then_swap(root, name, **kwargs):
        measured = real(root, name, **kwargs)  # the file at the key is verified: it holds exactly the accepted bytes...
        swap_how(path, how)  # ...and then, before the transaction that would record it, the name leads somewhere else
        return measured

    monkeypatch.setattr(assets, "measure", measure_then_swap)
    report = reconcile(lab)
    assert report.ambiguous == (delivery,) and report.completed == ()
    assert lab.delivery_row(delivery)["state"] == "PROMOTING" and len(lab.asset_rows()) == 3 and len(lab.audit_rows()) == since
    assert path.exists()  # whatever is there is preserved, not deleted
    assert lab.download(promoting.asset_id).status_code == 404
    monkeypatch.undo()
    again = reconcile(lab)  # nothing was lost: a stable file with the accepted bytes is adopted the next time
    if how in ("another file with the same bytes", "the same file touched"):
        assert again.completed == (delivery,) and lab.delivery_row(delivery)["state"] == "PROMOTED"
    else:
        assert again.ambiguous == (delivery,) and lab.delivery_row(delivery)["state"] == "PROMOTING"


def test_the_file_the_name_leads_to_when_it_is_measured_must_be_the_one_that_was_looked_at(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    path = plant(lab, promoting)
    real = assets.look_at

    def look_then_swap(root, name, **kwargs):
        entry = real(root, name, **kwargs)
        if name == promoting.asset_id and entry is not None:
            path.unlink()
            path.write_bytes(CLEAN_FILE)  # between the first look and the open, the name is pointed at another file
        return entry

    monkeypatch.setattr(assets, "look_at", look_then_swap)
    assert reconcile(lab).ambiguous == (delivery,)
    assert lab.delivery_row(delivery)["state"] == "PROMOTING" and len(lab.asset_rows()) == 3 and path.read_bytes() == CLEAN_FILE


def test_a_published_file_that_has_a_third_name_is_reported_and_left_alone(rig, tmp_path):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    stage(lab, promoting)
    assets.publish_staged(lab.asset_root, promoting.attempt, promoting.asset_id)  # two names, as it should be
    os.link(lab.asset_root / promoting.asset_id, lab.asset_root.parent / "elsewhere")  # and a third that nothing here made
    report = reconcile(lab)
    assert report.ambiguous == (delivery,) and lab.delivery_row(delivery)["state"] == "PROMOTING" and len(lab.asset_rows()) == 3
    assert (lab.asset_root.parent / "elsewhere").read_bytes() == CLEAN_FILE


@pytest.mark.parametrize("kind", ["a symlink to a file outside", "a dangling symlink", "a directory"])
def test_a_staged_name_that_is_not_a_plain_file_is_never_removed_by_recovery(rig, kind):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    promoting = begin(lab, delivery)
    (lab.asset_root / ".staging").mkdir(mode=0o700)
    (lab.asset_root.parent / "outside").mkdir(exist_ok=True)
    describe = occupy(lab.asset_root / ".staging" / promoting.attempt, lab.asset_root.parent / "outside", kind)
    before = describe()
    report = reconcile(lab)
    assert report.ambiguous == (delivery,) and describe() == before
    assert lab.delivery_row(delivery)["state"] == "PROMOTING" and len(lab.asset_rows()) == 3


def test_the_leftover_name_of_a_failed_attempt_is_removed_only_if_it_is_a_plain_file(rig):
    lab = rig.lab
    first, second = lab.accepted(CLEAN_FILE), lab.accepted(CLEAN_FILE)
    attempts = {}
    for delivery in (first, second):
        flip_a_byte(lab.stored_path(delivery))
        assert promote(lab, delivery).state == "INTEGRITY_FAILED"
        attempts[delivery] = lab.delivery_row(delivery)["promotion_attempt"]
    (lab.asset_root.parent / "outside").mkdir(exist_ok=True)
    (lab.asset_root / ".staging" / attempts[first]).write_bytes(b"a leftover scratch file")
    describe = occupy(lab.asset_root / ".staging" / attempts[second], lab.asset_root.parent / "outside", "a symlink to a file outside")
    before = describe()
    report = reconcile(lab)
    assert report.removed_staging == (attempts[first],) and report.unreferenced == (attempts[second],)
    assert describe() == before and not (lab.asset_root / ".staging" / attempts[first]).exists()


def test_the_adoption_step_cannot_be_reached_without_a_verified_fingerprint(rig):
    lab = rig.lab
    promoting = begin(lab, lab.accepted(CLEAN_FILE))
    written = assets.Written(promoting.size, promoting.sha256, promoting.attempt, 1, 1)
    plant(lab, promoting)
    with pytest.raises(TypeError, match="verified"):
        promotion._complete(promoting, written, link=False, verified=None, **{k: v for k, v in parts(lab).items() if k != "quarantine_root"})
    assert lab.delivery_row(promoting.delivery_id)["state"] == "PROMOTING" and len(lab.asset_rows()) == 3 and lab.audit_rows()[-1]["action"] == "delivery.promotion_started"


def test_no_asset_row_is_written_for_bytes_that_fail_the_accepted_digest_by_any_route(rig):
    """Both routes to an asset row (the copy and the adoption) end in the same compare-and-set; a file that fails the
    comparison in either is never recorded, whatever the database holds."""
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    flip_a_byte(lab.stored_path(delivery))  # the copy route
    assert promote(lab, delivery).state == "INTEGRITY_FAILED"
    adopt = lab.accepted(CLEAN_FILE)  # the adoption route
    promoting = begin(lab, adopt)
    plant(lab, promoting, b"\x89PNG\r\n\x1a\n" + b"q" * (len(CLEAN_FILE) - 8))
    assert reconcile(lab).ambiguous == (adopt,)
    assert [r for r in lab.asset_rows() if r["delivery_id"]] == []


def test_the_recovery_pass_twice_gives_the_same_state(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    begin(lab, delivery)
    assert reconcile(lab).completed == (delivery,)
    state = (lab.delivery_rows(), lab.asset_rows(), lab.trusted_tree(), len(lab.audit_rows()))
    again = reconcile(lab)
    assert again == promotion.PromotionReport((), (), (), (), ())
    assert (lab.delivery_rows(), lab.asset_rows(), lab.trusted_tree(), len(lab.audit_rows())) == state


def test_a_staged_name_left_after_a_commit_is_removed_only_if_it_is_the_published_file(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    result = promote(lab, delivery)
    row = lab.delivery_row(delivery)
    os.link(lab.asset_root / result.asset_id, lab.asset_root / ".staging" / row["promotion_attempt"])  # the unlink after P4 never ran
    stranger = "9" * 32
    (lab.asset_root / ".staging" / stranger).write_bytes(b"nobody's")
    report = reconcile(lab)
    assert report.removed_staging == (row["promotion_attempt"],) and report.unreferenced == (stranger,)
    assert (lab.asset_root / ".staging" / stranger).read_bytes() == b"nobody's" and lab.download(result.asset_id).content == CLEAN_FILE


# --- A-K4: the record of a promotion --------------------------------------------------------------------------------------------
#
# M0 §5.4 P4: "compare-and-set PROMOTING → PROMOTED (or INTEGRITY_FAILED) and write the audit event." The event names the
# actor, the production and the delivery. The asset and the accepted digest are bound to that delivery by rows that the same
# transaction writes and that nothing can rewrite afterwards: these are the statements that would have to succeed for the
# association between the event, the delivery, the asset and the accepted digest to be changed.

TAMPERING = {
    "delete the asset row": "DELETE FROM assets WHERE id = :asset",
    "replace the asset row by an unbound one": "INSERT OR REPLACE INTO assets (id, production_id, display_name, created_at) VALUES (:asset, :production, 'x', 1)",
    "point the asset at other bytes": "UPDATE assets SET sha256 = :other WHERE id = :asset",
    "change the asset's size": "UPDATE assets SET size = size + 1 WHERE id = :asset",
    "point the asset at another delivery": "UPDATE assets SET delivery_id = NULL WHERE id = :asset",
    "give the asset another production": "UPDATE assets SET production_id = :elsewhere WHERE id = :asset",
    "give the delivery another asset": "UPDATE deliveries SET asset_id = :other_key WHERE id = :delivery",
    "forget the asset on the delivery": "UPDATE deliveries SET asset_id = NULL WHERE id = :delivery",
    "change the accepted digest": "UPDATE deliveries SET accepted_sha256 = :other WHERE id = :delivery",
    "move the delivery out of PROMOTED": "UPDATE deliveries SET state = 'INTEGRITY_FAILED' WHERE id = :delivery",
    "delete the delivery": "DELETE FROM deliveries WHERE id = :delivery",
    "rewrite the event": "UPDATE audit_events SET object_id = :other_key WHERE seq = :event",
    "delete the event": "DELETE FROM audit_events WHERE seq = :event",
    "replace the event": "INSERT OR REPLACE INTO audit_events (seq, at, action, outcome) VALUES (:event, 1, 'forged', 'recorded')",
}


@pytest.mark.parametrize("statement", TAMPERING.values(), ids=list(TAMPERING))
def test_nothing_the_application_can_run_rewrites_the_record_of_a_promotion(rig, statement):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    result = promote(lab, delivery)
    (event,) = [e for e in lab.audit_rows() if e["action"] == "delivery.promoted"]
    before = (lab.delivery_rows(), lab.asset_rows(), lab.audit_rows())
    values = {
        "asset": result.asset_id, "delivery": delivery, "event": event["seq"], "production": lab.alpha, "elsewhere": lab.bravo,
        "other": "0" * 64, "other_key": "0" * 32,
    }  # fmt: skip
    conn = store.connect(lab.path)  # the application's own kind of connection: authorizer, triggers, foreign keys
    try:
        with pytest.raises(sqlite3.DatabaseError):
            with store.transaction(conn):
                conn.execute(statement, values)
    finally:
        conn.close()
    assert (lab.delivery_rows(), lab.asset_rows(), lab.audit_rows()) == before


def test_the_event_the_delivery_the_asset_and_the_accepted_digest_agree_and_share_one_instant(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    result = promote(lab, delivery)
    row = lab.delivery_row(delivery)
    (event,) = [e for e in lab.audit_rows() if e["action"] == "delivery.promoted"]
    (asset,) = [a for a in lab.asset_rows() if a["delivery_id"] == delivery]
    assert (event["object_type"], event["object_id"], event["production_id"]) == ("delivery", delivery, lab.alpha)
    assert (asset["delivery_id"], asset["production_id"], asset["id"]) == (event["object_id"], event["production_id"], row["asset_id"])
    assert row["asset_id"] == result.asset_id and event["object_id"] == delivery
    assert asset["sha256"] == row["accepted_sha256"] == row["sealed_sha256"] == HASH and asset["size"] == row["sealed_size"] == len(CLEAN_FILE)
    assert event["at"] == asset["created_at"] == to_micros(T0)  # one transaction, one instant
    assert (event["actor_issuer"], event["actor_subject"], event["engine_kind"], event["reason"]) == (*SYSTEM_PROMOTE, None, None)


# --- who runs it, and nothing else -------------------------------------------------------------------------------------------


def test_every_event_of_a_promotion_is_the_promotion_jobs_and_no_route_starts_one(rig):
    lab = rig.lab
    delivery = lab.accepted(CLEAN_FILE)
    since = len(lab.audit_rows())
    promote(lab, delivery)
    assert actors(lab, since) == {SYSTEM_PROMOTE} and audit.SYSTEM_PROMOTE in audit.SYSTEM_ACTORS
    assert not any("promot" in getattr(route, "path", "") for route in lab.app.routes)
    for method in ("POST", "PUT", "GET"):
        assert lab.send(method, f"/productions/{lab.alpha}/deliveries/{delivery}/promote", subject="coordinator-1").status_code in (404, 405)


def test_the_promotion_steps_take_the_collaborators_they_name_and_nothing_a_caller_can_send(rig):
    import inspect

    assert set(inspect.signature(promotion.promote).parameters) == {
        "production_id", "delivery_id", "clock", "database_path", "quarantine_root", "asset_root",
    }  # fmt: skip
    lab = rig.lab
    with pytest.raises(TypeError, match="delivery_id"):
        promotion.promote(lab.alpha, 7, **parts(lab))
    with pytest.raises(TypeError, match="production_id"):
        promotion.promote(None, "a" * 32, **parts(lab))
    assert lab.audit_rows() == []


def test_the_reference_copies_and_verifies_in_one_function_and_the_staging_step_is_its_only_caller(rig):
    import ast
    from pathlib import Path

    tree = ast.parse(Path(promotion.__file__).read_text())
    callers = {
        function.name
        for function in ast.walk(tree)
        if isinstance(function, ast.FunctionDef)
        and any(isinstance(node, ast.Name) and node.id == "copy_verified" for node in ast.walk(function))
        and function.name != "copy_verified"
    }
    assert callers == {"stage"}
    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert "content_identity" not in names  # the seal's identity is not an input to the promotion-time check
