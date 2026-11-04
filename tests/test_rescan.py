"""The internal rescan (Addendum §5.2): SCAN_FAILED -> SEALING, SCAN_PASSED -> SEALING (verdict stale), SEALING -> INTEGRITY_FAILED.

There is no route to a rescan: it is a function for the operator's own code (like ingest.reconcile), run under the
lab's one bounded system actor, `system:content-boundary-lab` / `rescan`, and never as a vendor or a coordinator. It
re-enters the same gate for the same bytes: H is recomputed from the stored bytes by the same `content_identity()` and
compared with the sealed H, which no input can replace. Bytes that no longer hash to the sealed H are INTEGRITY_FAILED;
anything else goes through the cache and the scanner as a seal does. A delivery is eligible only while its seal has not
produced a verdict in force, so a verdict that is still good is never churned.
"""

import inspect
import sqlite3
from datetime import timedelta
from types import SimpleNamespace

import pytest
from support.http_lab import CLEAN_FILE, T0, THREAD_WAIT, Background, make_lab, sha256_hex
from support.scanners import BlockingScanner, CountingScanner, ScriptedScanner, engine_like

from content_boundary_lab import audit, request_flow, store, trust
from content_boundary_lab.audit import Actor, AuditAction, AuditReason, Outcome
from content_boundary_lab.clock import to_micros
from content_boundary_lab.scanner import ScannerUnavailable

HASH = sha256_hex(CLEAN_FILE)
VALID_FOR = timedelta(hours=24)
SYSTEM = ("system:content-boundary-lab", "rescan")


def rescan(lab, delivery_id, scanner=None):
    return trust.rescan(
        delivery_id, clock=lab.clock, database_path=lab.path, quarantine_root=lab.quarantine_root, scanner=scanner or lab.scanner
    )


def trail(lab, since=0):
    return [(row["action"], row["outcome"], row["reason"]) for row in lab.audit_rows()[since:]]


def actors(lab, since=0):
    return {(row["actor_issuer"], row["actor_subject"]) for row in lab.audit_rows()[since:]}


def failed_scan(make_lab_, name="failed"):
    """A lab whose first scan could not be made, and its delivery: SCAN_FAILED(unavailable) by the vendor's own seal."""
    lab = make_lab_(name, ScriptedScanner(ScannerUnavailable()))
    delivery = lab.delivered(CLEAN_FILE)
    assert lab.seal(delivery).status_code == 502
    assert lab.delivery_row(delivery)["state"] == "SCAN_FAILED"
    return lab, delivery


@pytest.fixture
def rig(make_lab):
    scanner = CountingScanner()
    return SimpleNamespace(lab=make_lab("rig", scanner), scanner=scanner)


# --- recovering from a failed scan ---------------------------------------------------------------------------------------


def test_a_failed_scan_is_rescanned_for_the_same_bytes_and_can_then_be_accepted(make_lab):
    lab, delivery = failed_scan(make_lab)
    sealed = lab.delivery_row(delivery)
    working = CountingScanner()
    since = len(lab.audit_rows())
    result = rescan(lab, delivery, working)
    assert result == trust.RescanResult(delivery, "SCAN_PASSED", None)
    row = lab.delivery_row(delivery)
    assert (row["state"], row["state_reason"]) == ("SCAN_PASSED", None)
    assert (row["sealed_size"], row["sealed_sha256"], row["receipt_matched"]) == (sealed["sealed_size"], sealed["sealed_sha256"], sealed["receipt_matched"])
    (verdict,) = lab.verdict_rows()
    assert (row["verdict_id"], verdict["delivery_id"], verdict["sha256"], verdict["verdict"]) == (verdict["id"], delivery, HASH, "no_detection")
    assert (verdict["scanned_at"], verdict["valid_until"]) == (to_micros(T0), to_micros(T0 + VALID_FOR))
    assert trail(lab, since) == [("delivery.rescan_started", "allowed", None), ("delivery.scan_passed", "recorded", None)]
    assert [row["engine_kind"] for row in lab.audit_rows()[since:]] == [None, "synthetic"]
    assert working.calls == 1 and working.offsets == [0]
    # the coordinator then sees the new evidence and accepts the digest they were shown
    shown = lab.inspect(delivery).json()
    assert (shown["state"], shown["sealed_sha256"], shown["verdict_in_force"]) == ("SCAN_PASSED", HASH, True)
    assert lab.accept(delivery, shown["sealed_sha256"]).status_code == 200


def test_every_event_of_a_rescan_is_the_system_actors_about_the_deliverys_own_production(make_lab):
    lab, delivery = failed_scan(make_lab)
    since = len(lab.audit_rows())
    rescan(lab, delivery, CountingScanner())
    events = lab.audit_rows()[since:]
    assert len(events) == 2 and actors(lab, since) == {SYSTEM}
    assert {(row["production_id"], row["object_type"], row["object_id"]) for row in events} == {(lab.alpha, "delivery", delivery)}
    assert audit.SYSTEM_RESCAN in audit.SYSTEM_ACTORS and (audit.SYSTEM_RESCAN.issuer, audit.SYSTEM_RESCAN.subject) == SYSTEM


def test_a_scan_that_fails_again_is_recorded_as_a_failure_again(make_lab):
    lab, delivery = failed_scan(make_lab)
    since = len(lab.audit_rows())
    result = rescan(lab, delivery, ScriptedScanner(ScannerUnavailable()))
    assert result == trust.RescanResult(delivery, "SCAN_FAILED", "unavailable")
    row = lab.delivery_row(delivery)
    assert (row["state"], row["state_reason"], row["verdict_id"]) == ("SCAN_FAILED", "unavailable", None)
    assert trail(lab, since) == [("delivery.rescan_started", "allowed", None), ("delivery.scan_failed", "recorded", "scanner_unavailable")]
    assert lab.verdict_rows() == [] and actors(lab, since) == {SYSTEM}
    assert rescan(lab, delivery, CountingScanner()).state == "SCAN_PASSED"  # and it can be tried again


def test_a_rescan_can_reuse_a_verdict_made_meanwhile_for_the_same_bytes_and_scanner(make_lab):
    scanner = ScriptedScanner(ScannerUnavailable(), None)  # the first scan fails; later ones are real
    lab = make_lab("meanwhile", scanner)
    failed = lab.delivered(CLEAN_FILE)
    assert lab.seal(failed).status_code == 502
    other = lab.sealed(CLEAN_FILE)  # the same bytes, sealed and scanned (and cached) in the meantime
    calls, since = scanner.calls, len(lab.audit_rows())
    result = rescan(lab, failed, scanner)
    assert result.state == "SCAN_PASSED" and scanner.calls == calls  # no second scan
    assert lab.delivery_row(failed)["verdict_id"] == lab.delivery_row(other)["verdict_id"]
    assert trail(lab, since) == [("delivery.rescan_started", "allowed", None), ("delivery.verdict_reused", "recorded", None)]


# --- recovering from a stale verdict -----------------------------------------------------------------------------------------


def test_a_stale_verdict_is_replaced_by_a_rescan_and_the_old_one_is_kept(rig):
    lab, scanner = rig.lab, rig.scanner
    delivery = lab.sealed(CLEAN_FILE)
    old = lab.verdict_rows()[0]
    later = T0 + VALID_FOR  # the first instant at which the verdict is no longer in force
    token = lab.token_at("coordinator-1", later)
    lab.clock.moment = later
    refused = lab.accept(delivery, HASH, token=token)
    assert (refused.status_code, refused.json()["reason"]) == (409, "verdict_stale")
    since = len(lab.audit_rows())
    result = rescan(lab, delivery)
    assert result == trust.RescanResult(delivery, "SCAN_PASSED", None)
    assert trail(lab, since) == [("delivery.rescan_started", "allowed", "verdict_stale"), ("delivery.scan_passed", "recorded", None)]
    new = [row for row in lab.verdict_rows() if row["id"] != old["id"]]
    assert len(new) == 1 and lab.verdict_rows()[0] == old  # the old verdict is kept for audit, as it was
    assert (new[0]["scanned_at"], new[0]["valid_until"]) == (to_micros(later), to_micros(later + VALID_FOR))
    assert lab.delivery_row(delivery)["verdict_id"] == new[0]["id"] and scanner.calls == 2
    assert lab.accept(delivery, HASH, token=token).status_code == 200


def test_a_verdict_from_an_engine_that_has_since_changed_is_rescanned_by_the_new_one(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    upgraded = CountingScanner(engine=engine_like(rig.scanner.engine, version="2"))
    since = len(lab.audit_rows())
    result = rescan(lab, delivery, upgraded)  # still within the first verdict's validity, but not its engine's
    assert result.state == "SCAN_PASSED" and upgraded.calls == 1
    assert trail(lab, since)[0] == ("delivery.rescan_started", "allowed", "verdict_stale")
    assert [row["engine_version"] for row in lab.verdict_rows()] == [rig.scanner.engine.version, "2"]


def test_a_verdict_that_is_still_in_force_is_not_rescanned(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before, verdicts, since = lab.delivery_row(delivery), lab.verdict_rows(), len(lab.audit_rows())
    with pytest.raises(trust.RescanRefused) as refused:
        rescan(lab, delivery)
    assert refused.value.reason is AuditReason.STATE_CONFLICT
    assert (lab.delivery_row(delivery), lab.verdict_rows(), rig.scanner.calls) == (before, verdicts, 1)
    assert trail(lab, since) == [("delivery.request_rejected", "denied", "state_conflict")]
    assert actors(lab, since) == {SYSTEM}


# --- bytes that are no longer the sealed bytes -------------------------------------------------------------------------------


def flip_a_byte(path):
    data = bytearray(path.read_bytes())
    data[-1] ^= 0xFF
    path.write_bytes(bytes(data))


CHANGES = {
    "a byte flipped": flip_a_byte,
    "bytes appended": lambda path: path.write_bytes(path.read_bytes() + b"appended"),
    "one byte missing": lambda path: path.write_bytes(path.read_bytes()[:-1]),
    "another file of the same size": lambda path: path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * (len(CLEAN_FILE) - 8)),
}


@pytest.mark.parametrize("change", CHANGES.values(), ids=list(CHANGES))
def test_bytes_that_no_longer_hash_to_the_sealed_digest_are_an_integrity_failure_not_a_scan(make_lab, change):
    lab, delivery = failed_scan(make_lab)
    before = lab.delivery_row(delivery)
    change(lab.stored_path(delivery))
    working = CountingScanner()
    since = len(lab.audit_rows())
    result = rescan(lab, delivery, working)
    assert result == trust.RescanResult(delivery, "INTEGRITY_FAILED", None)
    row = lab.delivery_row(delivery)
    assert (row["state"], row["state_reason"], row["verdict_id"]) == ("INTEGRITY_FAILED", None, None)
    assert (row["sealed_size"], row["sealed_sha256"]) == (before["sealed_size"], before["sealed_sha256"]) == (len(CLEAN_FILE), HASH)  # H is not replaced
    assert working.calls == 0 and lab.verdict_rows() == []
    assert trail(lab, since) == [("delivery.rescan_started", "allowed", None), ("delivery.integrity_failed", "denied", "sealed_content_changed")]
    assert [row["engine_kind"] for row in lab.audit_rows()[since:]] == [None, None] and actors(lab, since) == {SYSTEM}


def test_an_integrity_failure_is_final_and_is_shown_to_the_coordinator(make_lab):
    lab, delivery = failed_scan(make_lab)
    flip_a_byte(lab.stored_path(delivery))
    rescan(lab, delivery, CountingScanner())
    with pytest.raises(trust.RescanRefused):
        rescan(lab, delivery, CountingScanner())
    refused = lab.accept(delivery, HASH)
    assert (refused.status_code, refused.json()["reason"]) == (409, "state_conflict")
    shown = lab.inspect(delivery).json()
    assert (shown["state"], shown["sealed_sha256"]) == ("INTEGRITY_FAILED", HASH) and "verdict" not in shown


def test_a_stale_verdict_for_bytes_that_have_changed_is_an_integrity_failure_too(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    flip_a_byte(lab.stored_path(delivery))
    lab.clock.moment = T0 + VALID_FOR
    assert rescan(lab, delivery).state == "INTEGRITY_FAILED"
    assert rig.scanner.calls == 1  # only the original scan


def test_unchanged_bytes_pass_the_integrity_check_however_often_they_are_read(make_lab):
    lab, delivery = failed_scan(make_lab)
    path = lab.stored_path(delivery)
    path.write_bytes(path.read_bytes())  # rewritten with the same bytes: the digest, not the inode, is the identity
    assert rescan(lab, delivery, CountingScanner()).state == "SCAN_PASSED"


# --- the content identity is the server's, always ------------------------------------------------------------------------------


def test_a_rescan_takes_the_digest_from_the_stored_bytes_through_the_same_seam_and_keys_the_cache_on_it(make_lab, monkeypatch):
    lab, delivery = failed_scan(make_lab)
    seen = []
    real_identity, real_lookup = trust.content_identity, trust.lookup_verdict
    monkeypatch.setattr(trust, "content_identity", lambda *a: seen.append(("identity", type(a[0]).__name__)) or real_identity(*a))
    monkeypatch.setattr(trust, "lookup_verdict", lambda conn, identity, *a: seen.append(("lookup", identity)) or real_lookup(conn, identity, *a))
    rescan(lab, delivery, CountingScanner())
    assert seen == [("identity", "Delivery"), ("lookup", trust.ContentIdentity(HASH))]


def test_nothing_a_caller_can_send_selects_the_digest_a_rescan_trusts(make_lab):
    assert set(inspect.signature(trust.rescan).parameters) == {"delivery_id", "clock", "database_path", "quarantine_root", "scanner"}
    lab, delivery = failed_scan(make_lab)
    row = lab.delivery_row(delivery)
    assert row["sealed_sha256"] == row["declared_sha256"] == HASH  # the seal had already compared the declaration with H
    assert rescan(lab, delivery, CountingScanner()).state == "SCAN_PASSED"
    assert lab.delivery_row(delivery)["sealed_sha256"] == HASH


# --- what a rescan refuses ---------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "state",
    ["INITIATED", "UPLOADED", "SEALING", "REJECTED", "SCAN_PASSED", "ACCEPTED", "PROMOTING", "PROMOTED", "INTEGRITY_FAILED"],
)
def test_only_a_failed_scan_or_a_stale_verdict_is_rescanned(rig, state):
    lab = rig.lab
    delivery = lab.seed_delivery("vendor-1", state=state)  # a SCAN_PASSED one has a verdict in force
    before = lab.delivery_row(delivery.id)
    with pytest.raises(trust.RescanRefused) as refused:
        rescan(lab, delivery.id)
    assert refused.value.reason is AuditReason.STATE_CONFLICT
    assert lab.delivery_row(delivery.id) == before and rig.scanner.calls == 0
    assert trail(lab) == [("delivery.request_rejected", "denied", "state_conflict")]
    assert lab.audit_rows()[0]["production_id"] == lab.alpha and actors(lab) == {SYSTEM}


@pytest.mark.parametrize(
    ("delivery_id", "reason", "recorded_as_object"),
    [("f" * 32, AuditReason.NOT_FOUND_OR_FORBIDDEN, True), ("A" * 32, AuditReason.INVALID_IDENTIFIER, False), ("../x", AuditReason.INVALID_IDENTIFIER, False)],
)
def test_a_missing_or_malformed_delivery_is_refused(rig, delivery_id, reason, recorded_as_object):
    lab = rig.lab
    with pytest.raises(trust.RescanRefused) as refused:
        rescan(lab, delivery_id)
    assert refused.value.reason is reason
    (event,) = lab.audit_rows()
    assert (event["action"], event["outcome"], event["reason"], event["production_id"]) == ("delivery.request_rejected", "denied", reason.value, None)
    assert (event["object_id"] == delivery_id) is recorded_as_object and (event["actor_issuer"], event["actor_subject"]) == SYSTEM


def test_a_rescan_needs_the_collaborators_it_names(rig):
    lab = rig.lab
    with pytest.raises(TypeError, match="delivery_id"):
        trust.rescan(7, clock=lab.clock, database_path=lab.path, quarantine_root=lab.quarantine_root, scanner=lab.scanner)
    with pytest.raises(TypeError, match="scanner"):
        trust.rescan("a" * 32, clock=lab.clock, database_path=lab.path, quarantine_root=lab.quarantine_root, scanner=object())
    assert lab.audit_rows() == []


# --- failure, concurrency and atomicity ------------------------------------------------------------------------------------------


def test_a_missing_file_leaves_the_delivery_in_sealing_as_a_seal_does_and_a_second_rescan_is_refused(make_lab):
    """Documented limit: recovering a delivery stranded in SEALING needs a lease or an age rule, which M1J does not decide."""
    lab, delivery = failed_scan(make_lab)
    lab.stored_path(delivery).unlink()
    since = len(lab.audit_rows())
    with pytest.raises(FileNotFoundError):
        rescan(lab, delivery, CountingScanner())
    assert lab.delivery_row(delivery)["state"] == "SEALING"
    assert trail(lab, since) == [("delivery.rescan_started", "allowed", None)]  # the start stands; no outcome is invented
    with pytest.raises(trust.RescanRefused) as refused:
        rescan(lab, delivery, CountingScanner())
    assert refused.value.reason is AuditReason.STATE_CONFLICT


def test_two_rescans_of_one_delivery_cannot_both_run(make_lab):
    lab, delivery = failed_scan(make_lab)
    blocking = BlockingScanner()
    first = Background(lambda: rescan(lab, delivery, blocking))
    assert blocking.entered.wait(THREAD_WAIT)  # the first is inside its scan, holding no writer lock
    assert lab.delivery_row(delivery)["state"] == "SEALING"
    with pytest.raises(trust.RescanRefused) as refused:
        rescan(lab, delivery, CountingScanner())
    assert refused.value.reason is AuditReason.STATE_CONFLICT
    blocking.release.set()
    assert first.join().state == "SCAN_PASSED"
    assert trail(lab)[-3:] == [
        ("delivery.rescan_started", "allowed", None),
        ("delivery.request_rejected", "denied", "state_conflict"),
        ("delivery.scan_passed", "recorded", None),
    ]
    assert len(lab.verdict_rows()) == 1


def test_a_rescan_and_a_vendor_seal_cannot_both_move_one_delivery(make_lab):
    lab, delivery = failed_scan(make_lab)
    blocking = BlockingScanner()
    first = Background(lambda: rescan(lab, delivery, blocking))
    assert blocking.entered.wait(THREAD_WAIT)
    sealed = lab.seal(delivery)  # the vendor's seal of a delivery that is not UPLOADED
    assert (sealed.status_code, sealed.json()) == (409, {"detail": "Delivery is not ready to be sealed"})
    blocking.release.set()
    assert first.join().state == "SCAN_PASSED"


def test_an_outcome_that_cannot_be_recorded_leaves_no_verdict_and_no_passing_state(make_lab):
    lab, delivery = failed_scan(make_lab)
    inner = CountingScanner()

    def scan_then_break_the_audit_log(stream):
        reply = inner.scan(stream, timeout_seconds=1.0)
        lab.make_audit_inserts_fail()  # the next audit insert, which is the outcome's, cannot be made
        return reply

    with pytest.raises(sqlite3.DatabaseError):
        rescan(lab, delivery, ScriptedScanner(scan_then_break_the_audit_log))
    row = lab.delivery_row(delivery)
    assert (row["state"], row["verdict_id"]) == ("SEALING", None) and lab.verdict_rows() == []
    assert trail(lab)[-1] == ("delivery.rescan_started", "allowed", None)


def test_a_rescan_whose_start_cannot_be_recorded_changes_nothing(make_lab):
    lab, delivery = failed_scan(make_lab)
    before, events = lab.delivery_row(delivery), len(lab.audit_rows())
    lab.make_audit_inserts_fail()
    working = CountingScanner()
    with pytest.raises(sqlite3.DatabaseError):
        rescan(lab, delivery, working)
    assert lab.delivery_row(delivery) == before and len(lab.audit_rows()) == events and working.calls == 0


# --- the system actor is not a way in --------------------------------------------------------------------------------------------


def test_a_token_naming_the_system_issuer_authenticates_nobody(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before = lab.delivery_row(delivery)
    for path_method in (("GET", lab.seal_path(delivery)), ("POST", lab.accept_path(delivery))):
        token = lab.token("rescan", iss=SYSTEM[0])
        response = lab.send(path_method[0], path_method[1], token=token, json={"sealed_sha256": HASH})
        assert response.status_code == 401
    assert lab.delivery_row(delivery) == before
    assert {row["reason"] for row in lab.audit_rows()[-2:]} == {"invalid_credentials"}


def test_no_route_starts_a_rescan(rig):
    lab = rig.lab
    paths = {getattr(route, "path", "") for route in lab.app.routes}
    assert not any("rescan" in path for path in paths)


# --- the system flow ------------------------------------------------------------------------------------------------------------


def record_one(ctx):
    audit.record_event(
        ctx.conn, ctx.clock, AuditAction.DELIVERY_REQUEST_REJECTED, Outcome.DENIED, actor=ctx.actor, production_id=ctx.production_id,
        reason=AuditReason.STATE_CONFLICT,
    )
    return request_flow.Decision(409, {"detail": "x"})


def run(lab, operation, actor=audit.SYSTEM_RESCAN, production_id=None):
    return request_flow.run_system(lab.clock, lab.path, actor=actor, production_id=production_id, operation=operation)


def test_the_system_flow_gives_the_operation_the_actor_the_production_and_one_instant(rig):
    lab = rig.lab
    seen = []
    reads = lab.clock.calls
    decision = run(lab, lambda ctx: (seen.append(ctx), record_one(ctx))[1], production_id=lab.alpha)
    (ctx,) = seen
    assert (ctx.actor, ctx.production_id, ctx.now_micros) == (audit.SYSTEM_RESCAN, lab.alpha, to_micros(T0))
    assert lab.clock.calls == reads + 1 and decision.status == 409
    assert trail(lab) == [("delivery.request_rejected", "denied", "state_conflict")]


@pytest.mark.parametrize("actor", [Actor("https://issuer.example", "rescan"), Actor("system:content-boundary-lab", "other"), None, "rescan"])
def test_the_system_flow_runs_only_as_a_named_system_actor(rig, actor):
    with pytest.raises((TypeError, ValueError), match="system actor"):
        run(rig.lab, record_one, actor=actor)
    assert rig.lab.audit_rows() == []


def test_the_system_flow_commits_exactly_one_event_or_nothing(rig):
    lab = rig.lab

    def two(ctx):
        record_one(ctx)
        return record_one(ctx)

    def none(ctx):
        ctx.conn.execute("INSERT INTO productions (id, name, created_at) VALUES (?, 'X', 1)", ("9" * 32,))
        return request_flow.Decision(200, {})

    for operation in (two, none):
        with pytest.raises(request_flow.AuditCountError):
            run(lab, operation)
    assert lab.audit_rows() == []
    conn = store.connect(lab.path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM productions WHERE id = ?", ("9" * 32,)).fetchone()[0] == 0
    finally:
        conn.close()


def test_a_failure_in_the_system_flow_propagates_and_releases_the_connection_and_the_lock(rig):
    lab = rig.lab

    def explode(ctx):
        record_one(ctx)
        raise RuntimeError("simulated")

    with pytest.raises(RuntimeError, match="simulated"):
        run(lab, explode)
    assert lab.audit_rows() == []
    probe = sqlite3.connect(lab.path, timeout=0, isolation_level=None)
    try:
        probe.execute("BEGIN IMMEDIATE")  # raises if a write transaction were still open
        probe.execute("ROLLBACK")
    finally:
        probe.close()
