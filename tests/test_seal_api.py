"""POST /productions/{id}/deliveries/{id}/seal: the vendor closes a delivery and the server decides (M0 §2 step 5, F-03).

Real HTTP behaviour on synthetic files and the shipped synthetic scanner (or the doubles in tests/support/scanners.py).
The decision follows M0's order, and its one authoritative digest H comes from `trust.content_identity` alone (O-1,
Option A): measured size, then H against the declared SHA-256, then the file signature, then the scan cache keyed on H
and the scanner's identity, then the scanner on a miss. The declared hash is only ever compared with H.
"""

import logging
import os
import sqlite3
from datetime import timedelta
from types import SimpleNamespace

import pytest
from support import token_issuer as tokens
from support.http_lab import (
    CLEAN_FILE,
    MARKER_FILE,
    PNG_SIGNATURE,
    STATE_ROUTES,
    T0,
    THREAD_WAIT,
    ZIP_FILE,
    Background,
    assert_released,
    generic,
    lab,
    make_lab,
    occupy,
    sha256_hex,
    spy,
    transaction_whose_commit_fails,
)
from support.scanners import BlockingScanner, CountingScanner, ScriptedScanner, UpgradingScanner, engine_like

from content_boundary_lab import audit, quarantine, request_flow, store, trust
from content_boundary_lab.clock import to_micros
from content_boundary_lab.scanner import (
    LabSyntheticMarkerScanner,
    ScanResult,
    ScannerBadResponse,
    ScannerError,
    ScannerTimeout,
    ScannerUnavailable,
    Verdict,
)

VALID_FOR = timedelta(hours=24)  # a lab assumption (A8): how long a verdict may be reused
SEALED_AT = to_micros(T0)
NOT_READY = {"detail": "Delivery is not ready to be sealed"}


def trail(lab, since=0):
    return [(row["action"], row["outcome"], row["reason"]) for row in lab.audit_rows()[since:]]


def utc(moment):
    return request_flow.utc_text(to_micros(moment))


@pytest.fixture
def rig(make_lab):
    """An application whose scanner is the real stub behind a call counter."""
    scanner = CountingScanner()
    return SimpleNamespace(lab=make_lab("rig", scanner), scanner=scanner)


def engine_json(scanner):
    return {"id": scanner.engine.id, "version": scanner.engine.version, "kind": scanner.engine.kind}


def untouched(lab, delivery_id, *, state="UPLOADED"):
    row = lab.delivery_row(delivery_id)
    assert row["state"] == state and row["sealed_sha256"] is None and row["verdict_id"] is None
    assert lab.verdict_rows() == []


def append_to(path, data=b" appended after it was inspected"):
    with path.open("ab") as handle:
        handle.write(data)


def watch(monkeypatch, name):
    """Record each call to trust.<name> and still make it."""
    calls, real = [], getattr(trust, name)

    def recording(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(trust, name, recording)
    return calls


# --- the decision that reaches SCAN_PASSED ------------------------------------------------------------------------------


def test_content_that_matches_what_was_declared_is_scanned_and_reaches_scan_passed(rig):
    lab, scanner = rig.lab, rig.scanner
    delivery = lab.delivered(CLEAN_FILE)
    since = len(lab.audit_rows())
    response = lab.seal(delivery)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "delivery_id": delivery, "state": "SCAN_PASSED", "sealed_size": len(CLEAN_FILE), "sealed_sha256": sha256_hex(CLEAN_FILE),
        "engine": engine_json(scanner), "verdict_valid_until": utc(T0 + VALID_FOR),
    }  # fmt: skip
    row = lab.delivery_row(delivery)
    assert (row["state"], row["state_reason"], row["sealed_size"], row["sealed_sha256"], row["receipt_matched"]) == (
        "SCAN_PASSED", None, len(CLEAN_FILE), sha256_hex(CLEAN_FILE), 1,
    )  # fmt: skip
    (verdict,) = lab.verdict_rows()
    assert verdict["id"] == row["verdict_id"] and verdict["delivery_id"] == delivery
    assert (verdict["sha256"], verdict["scanned_sha256"], verdict["verdict"]) == (sha256_hex(CLEAN_FILE), sha256_hex(CLEAN_FILE), "no_detection")
    assert (verdict["engine_id"], verdict["engine_version"], verdict["engine_kind"], verdict["policy_fingerprint"]) == (
        scanner.engine.id, scanner.engine.version, "synthetic", scanner.engine.policy_fingerprint,
    )  # fmt: skip
    assert (verdict["scanned_at"], verdict["valid_until"]) == (SEALED_AT, to_micros(T0 + VALID_FOR))
    assert trail(lab, since) == [("delivery.seal_started", "allowed", None), ("delivery.scan_passed", "recorded", None)]
    assert scanner.calls == 1


def test_the_scanner_is_given_the_stored_bytes_from_the_start_and_the_approved_timeout(rig):
    delivery = rig.lab.delivered(CLEAN_FILE)
    assert rig.lab.seal(delivery).status_code == 200
    assert rig.scanner.offsets == [0]  # the hashing pass before it did not leave the stream part-way
    assert rig.scanner.timeouts == [trust.SCAN_TIMEOUT_SECONDS] == [30.0]  # a lab assumption (A8)
    assert rig.scanner.results[0].scanned_sha256 == sha256_hex(CLEAN_FILE)  # it read all of them, and said what it read


def test_sealing_closes_writes_by_state(rig):
    delivery = rig.lab.delivered(CLEAN_FILE)
    assert rig.lab.seal(delivery).status_code == 200
    again = rig.lab.upload(delivery, b"a replacement after sealing")
    assert again.status_code == 409 and again.json() == {"detail": "Delivery is not awaiting content"}
    assert rig.lab.stored_path(delivery).read_bytes() == CLEAN_FILE


# --- who may seal, and what ----------------------------------------------------------------------------------------------

DENIED = {
    "no credentials": dict(subject=None, status=401, reason="invalid_credentials"),
    "a coordinator": dict(subject="coordinator-1", status=403, reason="role_not_permitted"),
    "a vendor of another production": dict(subject="vendor-2", status=403, reason="no_engagement"),
    "the owner through another production's url": dict(subject="vendor-1", production="bravo", status=403, reason="no_engagement"),
    "another production's vendor through its own url": dict(subject="vendor-2", production="bravo", status=404, reason="not_found_or_forbidden"),
    "another vendor of the same production": dict(subject="dual-1", status=404, reason="not_found_or_forbidden"),
}  # fmt: skip


@pytest.mark.parametrize("case", DENIED.values(), ids=list(DENIED))
def test_only_the_vendor_that_owns_the_delivery_can_seal_it(rig, case):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    since = len(lab.audit_rows())
    production = lab.production(case["production"]) if "production" in case else None
    response = lab.seal(delivery, case["subject"], production)
    assert response.status_code == case["status"]
    assert trail(lab, since) == [("access.denied", "denied", case["reason"])]
    untouched(lab, delivery)
    assert rig.scanner.calls == 0


@pytest.mark.parametrize("delivery_id", ["f" * 32, "A" * 32, "a" * 31, "../" + "a" * 29, "assets/" + "a" * 32, "' OR '1'='1"])
def test_a_missing_or_malformed_delivery_is_the_same_404(rig, delivery_id):
    response = rig.lab.seal(delivery_id)
    assert response.status_code == 404 and response.json() == {"detail": "Not found"}
    assert rig.scanner.calls == 0


def test_a_revoked_engagement_seals_nothing(rig):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    token = lab.token("vendor-1")
    lab.revoke("vendor", at=T0 + timedelta(seconds=30))
    lab.clock.moment = T0 + timedelta(seconds=60)
    generic(lab.seal(delivery, None, token=token), 403)
    untouched(lab, delivery)
    assert rig.scanner.calls == 0 and trail(lab)[-1] == ("access.denied", "denied", "engagement_revoked")


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])  # GET is the coordinator's inspection (M1J, test_acceptance_api.py)
def test_only_post_and_the_coordinators_get_are_accepted_on_the_seal_path(rig, method):
    delivery = rig.lab.delivered(CLEAN_FILE)
    assert rig.lab.send(method, rig.lab.seal_path(delivery), subject="vendor-1").status_code == 405
    untouched(rig.lab, delivery)


# --- state, retries and races --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("state", [state for state in STATE_ROUTES if state != "UPLOADED"])
def test_only_an_uploaded_delivery_can_be_sealed(rig, state):
    lab = rig.lab
    delivery = lab.seed_delivery("vendor-1", state=state)
    before = lab.delivery_row(delivery.id)
    response = lab.seal(delivery.id)
    assert response.status_code == 409 and response.json() == NOT_READY
    assert trail(lab) == [("delivery.request_rejected", "denied", "state_conflict")]
    assert lab.delivery_row(delivery.id) == before and rig.scanner.calls == 0


def test_a_second_seal_is_refused_and_does_not_scan_again(rig):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    assert lab.seal(delivery).status_code == 200
    again = lab.seal(delivery)
    assert again.status_code == 409 and again.json() == NOT_READY
    assert rig.scanner.calls == 1 and len(lab.verdict_rows()) == 1


def test_a_failed_seal_is_not_retried_by_the_vendor(make_lab):
    scanner = ScriptedScanner(ScannerUnavailable())
    lab = make_lab("retry", scanner)
    delivery = lab.delivered(CLEAN_FILE)
    assert lab.seal(delivery).status_code == 502
    assert lab.seal(delivery).json() == NOT_READY  # only an internal rescan re-enters the gate (Addendum §5.2 row 5)
    assert scanner.calls == 1


def test_two_seals_of_one_delivery_cannot_both_complete_and_the_scan_holds_no_writer_lock(make_lab):
    scanner = BlockingScanner()
    lab = make_lab("race", scanner)
    delivery = lab.delivered(CLEAN_FILE)
    first = Background(lambda: lab.seal(delivery))
    assert scanner.entered.wait(THREAD_WAIT)  # the first seal is inside the scanner
    assert lab.delivery_row(delivery)["state"] == "SEALING"
    second = lab.seal(delivery)  # would wait out the busy timeout, then fail, if the scan held the writer lock
    assert second.status_code == 409 and second.json() == NOT_READY
    scanner.release.set()
    done = first.join()
    assert done.status_code == 200 and lab.delivery_row(delivery)["state"] == "SCAN_PASSED"
    assert scanner.calls == 1 and len(lab.verdict_rows()) == 1
    assert trail(lab)[-3:] == [
        ("delivery.seal_started", "allowed", None),
        ("delivery.request_rejected", "denied", "state_conflict"),
        ("delivery.scan_passed", "recorded", None),
    ]


def test_a_seal_whose_first_transaction_does_not_commit_inspects_nothing(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    opened = []
    real_open = quarantine.open_stored
    monkeypatch.setattr(quarantine, "open_stored", lambda *args: (opened.append(args), real_open(*args))[1])
    monkeypatch.setattr(store, "transaction", transaction_whose_commit_fails)
    generic(lab.seal(delivery), 500)
    monkeypatch.undo()
    assert opened == [] and rig.scanner.calls == 0
    untouched(lab, delivery)
    assert lab.seal(delivery).status_code == 200  # nothing was lost by the failure


# --- the order of the decision -------------------------------------------------------------------------------------------


def wire(monkeypatch, events):
    """Record the steps of the gate in the order they happen, around the real functions."""
    for name, label in (("content_identity", "identity"), ("detect_signature", "signature"), ("lookup_verdict", "lookup")):
        real = getattr(trust, name)
        monkeypatch.setattr(trust, name, lambda *a, _real=real, _label=label, **k: (events.append(_label), _real(*a, **k))[1])
    real_scan = LabSyntheticMarkerScanner.scan
    monkeypatch.setattr(LabSyntheticMarkerScanner, "scan", lambda self, stream, **k: (events.append("scan"), real_scan(self, stream, **k))[1])


@pytest.mark.parametrize(
    ("content", "declared", "expected", "outcome"),
    [
        (CLEAN_FILE, {}, ["identity", "signature", "lookup", "scan"], 200),
        (CLEAN_FILE, {"declared_sha256": "c" * 64}, ["identity"], 422),
        (CLEAN_FILE, {"declared_size": 3}, ["identity"], 422),
        (ZIP_FILE, {}, ["identity", "signature"], 422),
        (MARKER_FILE, {"declared_sha256": "c" * 64}, ["identity"], 422),
    ],
    ids=["a match", "a declared hash that is wrong", "a declared size that is wrong", "an unsupported type", "a marker file with a wrong hash"],
)
def test_the_gate_takes_its_steps_in_the_approved_order_and_stops_at_the_first_refusal(lab, monkeypatch, content, declared, expected, outcome):
    delivery = lab.delivered(content, **declared)
    events = []
    wire(monkeypatch, events)
    assert lab.seal(delivery).status_code == outcome
    assert events == expected


def test_a_cache_hit_stops_after_the_lookup(lab, monkeypatch):
    first, second = lab.delivered(CLEAN_FILE), lab.delivered(CLEAN_FILE)
    assert lab.seal(first).status_code == 200
    events = []
    wire(monkeypatch, events)
    assert lab.seal(second).status_code == 200
    assert events == ["identity", "signature", "lookup"]  # no scan


@pytest.mark.parametrize(
    "declared",
    [{"declared_sha256": "c" * 64}, {"declared_size": 7}, {"declared_size": len(CLEAN_FILE) + 1}, {"declared_sha256": "c" * 64, "declared_size": 7}],
    ids=["hash", "size smaller", "size larger", "both"],
)
def test_a_declaration_that_does_not_describe_the_bytes_is_rejected_before_the_cache_and_the_scanner(rig, monkeypatch, declared):
    lab = rig.lab
    lab.seed_verdict(sha256_hex(CLEAN_FILE))  # even a valid cached verdict for the real digest is not consulted
    delivery = lab.delivered(CLEAN_FILE, **declared)
    lookups = watch(monkeypatch, "lookup_verdict")
    since = len(lab.audit_rows())
    response = lab.seal(delivery)
    assert response.status_code == 422
    assert response.json() == {
        "delivery_id": delivery, "state": "REJECTED", "reason": "checksum_mismatch",
        "sealed_size": len(CLEAN_FILE), "sealed_sha256": sha256_hex(CLEAN_FILE),
    }  # fmt: skip
    row = lab.delivery_row(delivery)
    assert (row["state"], row["state_reason"], row["verdict_id"]) == ("REJECTED", "checksum_mismatch", None)
    assert (row["sealed_size"], row["sealed_sha256"]) == (len(CLEAN_FILE), sha256_hex(CLEAN_FILE))  # what the server saw
    assert rig.scanner.calls == 0 and lookups == [] and len(lab.verdict_rows()) == 1  # only the one seeded above
    assert trail(lab, since) == [("delivery.seal_started", "allowed", None), ("delivery.rejected", "denied", "checksum_mismatch")]


def test_a_mismatch_is_reported_before_an_unsupported_type_when_a_file_is_both(rig):
    lab = rig.lab
    delivery = lab.delivered(ZIP_FILE, declared_size=len(ZIP_FILE) + 5, declared_sha256="c" * 64)
    assert lab.seal(delivery).json()["reason"] == "checksum_mismatch"  # not unsupported_type, though it is both


def test_a_corrupted_upload_is_caught_by_the_declared_hash_and_an_intact_one_is_not(rig):
    """Corruption in transit is what the declaration is for."""
    lab = rig.lab
    good = lab.delivered(CLEAN_FILE)
    flipped = bytearray(CLEAN_FILE)
    flipped[100] ^= 0xFF  # one corrupted byte, as if damaged on the way
    damaged = lab.delivered(bytes(flipped), declared_sha256=sha256_hex(CLEAN_FILE), declared_size=len(CLEAN_FILE))
    assert lab.seal(good).status_code == 200
    assert lab.seal(damaged).json()["reason"] == "checksum_mismatch"


SIGNATURES = {
    "png": PNG_SIGNATURE,
    "jpeg": b"\xff\xd8\xff\xe0",
    "quicktime": b"\x00\x00\x00\x14ftypqt  ",
    "mp4": b"\x00\x00\x00\x18ftypisom",
    "wav": b"RIFF\x24\x00\x00\x00WAVE",
    "openexr": b"\x76\x2f\x31\x01",
    "matroska": b"\x1a\x45\xdf\xa3",
}


@pytest.mark.parametrize("name", SIGNATURES)
def test_each_allowed_signature_is_accepted(rig, name):
    delivery = rig.lab.delivered(SIGNATURES[name] + b"synthetic payload " * 8)
    assert rig.lab.seal(delivery).status_code == 200


@pytest.mark.parametrize(
    "content",
    [ZIP_FILE, b"", b"plain text, not a media file\n" * 5, PNG_SIGNATURE[:4], b"RIFF\x24\x00\x00\x00AVI " + b"x" * 20, b"\x00" * 64, b"MZ" + b"\x00" * 60],
    ids=["an archive", "an empty file", "text", "a truncated signature", "RIFF of another kind", "NUL bytes", "an executable header"],
)
def test_a_signature_that_is_not_on_the_allowlist_is_rejected_without_a_scan(rig, monkeypatch, content):
    lab = rig.lab
    delivery = lab.delivered(content)
    lookups = watch(monkeypatch, "lookup_verdict")
    response = lab.seal(delivery)
    assert response.status_code == 422 and response.json()["reason"] == "unsupported_type"
    assert lab.delivery_row(delivery)["state_reason"] == "unsupported_type"
    assert rig.scanner.calls == 0 and lookups == [] and lab.verdict_rows() == []
    assert trail(lab)[-1] == ("delivery.rejected", "denied", "unsupported_type")


def test_the_signature_is_read_from_the_content_and_not_from_what_the_vendor_said(rig):
    lab = rig.lab
    lies = lab.delivered(CLEAN_FILE, declared_media_type="application/zip", display_name="archive.zip")
    archive = lab.delivered(ZIP_FILE, declared_media_type="image/png", display_name="picture.png")
    assert lab.seal(lies).status_code == 200
    assert lab.seal(archive).json()["reason"] == "unsupported_type"


# --- the verdict cache -----------------------------------------------------------------------------------------------------


def test_a_verdict_made_in_one_production_is_reused_in_another_and_the_response_says_when_it_was_made(rig):
    """A limitation, recorded as TM-34: the cache is keyed on content and engine and not on the production (M0), so the
    second production's vendor learns that identical bytes were scanned elsewhere, and when, without any timing."""
    lab, scanner = rig.lab, rig.scanner
    first, second = lab.delivered(CLEAN_FILE), lab.delivered(CLEAN_FILE, "vendor-2", lab.bravo)
    assert lab.seal(first).status_code == 200
    lab.clock.moment = T0 + timedelta(hours=1)
    later = tokens.NOW + 3600
    response = lab.seal(second, None, lab.bravo, token=lab.token("vendor-2", iat=later, nbf=later, exp=later + 300))
    assert response.status_code == 200 and scanner.calls == 1
    assert response.json()["verdict_valid_until"] == utc(T0 + VALID_FOR)  # the first production's scan, not this one's hour


def test_a_valid_unexpired_no_detection_verdict_for_the_same_digest_and_scanner_is_reused_without_a_scan(rig):
    lab, scanner = rig.lab, rig.scanner
    first, second = lab.delivered(CLEAN_FILE), lab.delivered(CLEAN_FILE)
    assert lab.seal(first).status_code == 200
    lab.clock.moment = T0 + timedelta(hours=1)
    later = tokens.NOW + 3600  # a token that is valid an hour on; the first one has long since expired
    token = lab.token("vendor-1", iat=later, nbf=later, exp=later + 300)
    since = len(lab.audit_rows())
    response = lab.seal(second, None, token=token)
    assert response.status_code == 200 and scanner.calls == 1
    (verdict,) = lab.verdict_rows()  # no new row: the first scan's is the one in force
    assert lab.delivery_row(second)["verdict_id"] == verdict["id"] == lab.delivery_row(first)["verdict_id"]
    assert response.json()["verdict_valid_until"] == utc(T0 + VALID_FOR)  # reuse does not extend it (Addendum §5.2 row 6)
    assert trail(lab, since) == [("delivery.seal_started", "allowed", None), ("delivery.verdict_reused", "recorded", None)]
    assert lab.delivery_row(second)["state"] == "SCAN_PASSED"


def test_the_cache_is_for_the_content_not_for_the_path_the_name_or_the_file(rig):
    lab = rig.lab
    first = lab.delivered(CLEAN_FILE, display_name="one-name.png")
    second = lab.delivered(CLEAN_FILE, display_name="another-name.png", declared_media_type="image/x-other")
    assert lab.stored_path(first) != lab.stored_path(second)
    assert os.stat(lab.stored_path(first)).st_ino != os.stat(lab.stored_path(second)).st_ino
    assert lab.seal(first).status_code == lab.seal(second).status_code == 200
    assert rig.scanner.calls == 1


def test_different_content_is_a_cache_miss(rig):
    lab = rig.lab
    lab.seal(lab.delivered(CLEAN_FILE))
    other = lab.delivered(PNG_SIGNATURE + b"different synthetic payload " * 10)
    assert lab.seal(other).status_code == 200 and rig.scanner.calls == 2 and len(lab.verdict_rows()) == 2


def seeded_cases(lab):
    real = lab.scanner.engine
    return {
        "another content digest": dict(sha256="9" * 64),
        "another engine": dict(engine=engine_like(real, id="another-engine")),
        "another engine version": dict(engine=engine_like(real, version=real.version + ".1")),
        "an older engine version": dict(engine=engine_like(real, version="0")),
        "another policy fingerprint": dict(engine=engine_like(real, policy_fingerprint="e" * 64)),
        "an expired verdict": dict(valid_until=to_micros(T0) - 1),
        "a verdict that expires this very instant": dict(valid_until=to_micros(T0)),
        "a detection": dict(verdict="detection"),
    }


@pytest.mark.parametrize("case", list(seeded_cases(SimpleNamespace(scanner=LabSyntheticMarkerScanner()))))
def test_a_cached_verdict_that_is_not_for_this_content_this_scanner_and_this_moment_is_not_reused(rig, case):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    changes = dict(seeded_cases(lab)[case])
    lab.seed_verdict(changes.pop("sha256", sha256_hex(CLEAN_FILE)), **changes)
    old = lab.verdict_rows()
    response = lab.seal(delivery)
    assert response.status_code == 200 and rig.scanner.calls == 1  # a miss: scanned
    rows = lab.verdict_rows()
    assert rows[: len(old)] == old and len(rows) == len(old) + 1  # the old one is kept for audit and never applied
    assert lab.delivery_row(delivery)["verdict_id"] == rows[-1]["id"] != old[0]["id"]
    assert trail(lab)[-1] == ("delivery.scan_passed", "recorded", None)


def test_a_verdict_one_microsecond_from_expiry_is_still_reused(rig):
    lab = rig.lab
    lab.seed_verdict(sha256_hex(CLEAN_FILE), valid_until=to_micros(T0) + 1)
    assert lab.seal(lab.delivered(CLEAN_FILE)).status_code == 200 and rig.scanner.calls == 0


def test_a_detection_is_recorded_and_never_reused(rig):
    lab = rig.lab
    first, second = lab.delivered(MARKER_FILE), lab.delivered(MARKER_FILE)
    response = lab.seal(first)
    assert response.status_code == 422
    assert response.json() == {
        "delivery_id": first, "state": "REJECTED", "reason": "detection", "sealed_size": len(MARKER_FILE),
        "sealed_sha256": sha256_hex(MARKER_FILE), "engine": engine_json(rig.scanner),
    }  # fmt: skip
    (verdict,) = lab.verdict_rows()
    assert verdict["verdict"] == "detection" and lab.delivery_row(first)["verdict_id"] == verdict["id"]
    assert trail(lab)[-1] == ("delivery.rejected", "denied", "detection")
    assert lab.seal(second).json()["reason"] == "detection"
    assert rig.scanner.calls == 2 and len(lab.verdict_rows()) == 2  # scanned again, not turned into a pass


def test_what_the_scanner_found_is_what_is_recorded_for_the_bytes_it_was_given(rig):
    lab = rig.lab
    clean, marked = lab.delivered(CLEAN_FILE), lab.delivered(MARKER_FILE)
    lab.seal(clean)
    lab.seal(marked)
    verdicts = {row["sha256"]: row["verdict"] for row in lab.verdict_rows()}
    assert verdicts == {sha256_hex(CLEAN_FILE): "no_detection", sha256_hex(MARKER_FILE): "detection"}


# --- scanner failures: fail closed, no verdict, no cache ----------------------------------------------------------------

FAILURES = {
    "unavailable": ScannerUnavailable("down"),
    "timeout": ScannerTimeout("took too long"),
    "bad_response": ScannerBadResponse("nonsense"),
}


@pytest.mark.parametrize("reason", FAILURES)
def test_a_scanner_that_fails_leaves_the_delivery_scan_failed_with_no_verdict(make_lab, reason):
    scanner = ScriptedScanner(FAILURES[reason])
    lab = make_lab("failing", scanner)
    delivery = lab.delivered(CLEAN_FILE)
    since = len(lab.audit_rows())
    response = lab.seal(delivery)
    assert response.status_code == 502
    assert response.json() == {
        "delivery_id": delivery, "state": "SCAN_FAILED", "reason": reason,
        "sealed_size": len(CLEAN_FILE), "sealed_sha256": sha256_hex(CLEAN_FILE),
    }  # fmt: skip
    row = lab.delivery_row(delivery)
    assert (row["state"], row["state_reason"], row["verdict_id"], row["sealed_sha256"]) == ("SCAN_FAILED", reason, None, sha256_hex(CLEAN_FILE))
    assert lab.verdict_rows() == [] and scanner.calls == 1
    assert trail(lab, since) == [("delivery.seal_started", "allowed", None), ("delivery.scan_failed", "recorded", f"scanner_{reason}")]


MALFORMED = {
    "nothing": lambda stream: None,
    "a dictionary": lambda stream: {"verdict": "no_detection", "scanned_sha256": sha256_hex(CLEAN_FILE)},
    "a verdict called clean": lambda stream: SimpleNamespace(verdict="clean", scanned_sha256=sha256_hex(CLEAN_FILE)),
    "a verdict in capitals": lambda stream: SimpleNamespace(verdict="NO_DETECTION", scanned_sha256=sha256_hex(CLEAN_FILE)),
    "no digest": lambda stream: SimpleNamespace(verdict=Verdict.NO_DETECTION, scanned_sha256=None),
    "a digest in capitals": lambda stream: SimpleNamespace(verdict=Verdict.NO_DETECTION, scanned_sha256=sha256_hex(CLEAN_FILE).upper()),
    "a short digest": lambda stream: SimpleNamespace(verdict=Verdict.NO_DETECTION, scanned_sha256="abc"),
    "a digest of bytes": lambda stream: SimpleNamespace(verdict=Verdict.NO_DETECTION, scanned_sha256=bytes.fromhex(sha256_hex(CLEAN_FILE))),
    "a verdict as a bare string": lambda stream: "no_detection",
}


@pytest.mark.parametrize("reply", MALFORMED)
def test_a_malformed_reply_is_a_bad_response_and_is_never_a_verdict(make_lab, reply):
    scanner = ScriptedScanner(MALFORMED[reply])
    lab = make_lab("malformed", scanner)
    delivery = lab.delivered(CLEAN_FILE)
    response = lab.seal(delivery)
    assert response.status_code == 502 and response.json()["reason"] == "bad_response"
    assert lab.delivery_row(delivery)["state"] == "SCAN_FAILED" and lab.verdict_rows() == []


def test_a_verdict_is_never_recorded_under_an_engine_other_than_the_one_that_began_the_scan(make_lab):
    """A scanner upgraded while it scans: which engine made the verdict is not known, so it is not a verdict at all."""
    scanner = UpgradingScanner(engine_like(version="2"))
    lab = make_lab("upgrade", scanner)
    delivery = lab.delivered(CLEAN_FILE)
    response = lab.seal(delivery)
    assert response.status_code == 502 and response.json()["reason"] == "bad_response"
    row = lab.delivery_row(delivery)
    assert row["state"] == "SCAN_FAILED" and row["verdict_id"] is None and lab.verdict_rows() == []
    assert scanner.calls == 1


def test_a_scanner_that_reports_the_digest_of_other_bytes_fails_closed_even_with_a_no_detection_verdict(make_lab):
    scanner = ScriptedScanner(lambda stream: ScanResult(Verdict.NO_DETECTION, sha256_hex(b"some other bytes entirely")))
    lab = make_lab("liar", scanner)
    delivery = lab.delivered(CLEAN_FILE)
    response = lab.seal(delivery)
    assert response.status_code == 502 and response.json()["reason"] == "bad_response"
    row = lab.delivery_row(delivery)
    assert row["state"] == "SCAN_FAILED" and row["verdict_id"] is None and lab.verdict_rows() == []


def test_a_detection_with_a_mismatching_digest_is_a_failure_and_not_a_rejection(make_lab):
    scanner = ScriptedScanner(lambda stream: ScanResult(Verdict.DETECTION, sha256_hex(b"not these bytes")))
    lab = make_lab("liar-detects", scanner)
    delivery = lab.delivered(CLEAN_FILE)
    assert lab.seal(delivery).json()["state"] == "SCAN_FAILED" and lab.verdict_rows() == []


def test_a_failed_scan_is_never_cached_so_the_same_content_is_scanned_again(make_lab):
    scanner = ScriptedScanner(ScannerTimeout("slow"), None)  # fails once, then behaves
    lab = make_lab("again", scanner)
    first, second = lab.delivered(CLEAN_FILE), lab.delivered(CLEAN_FILE)
    assert lab.seal(first).json()["state"] == "SCAN_FAILED"
    assert lab.verdict_rows() == []
    assert lab.seal(second).json()["state"] == "SCAN_PASSED"
    assert scanner.calls == 2 and len(lab.verdict_rows()) == 1


@pytest.mark.parametrize("error", [RuntimeError("a bug in the scanner"), ScannerError("a scanner failure of no approved kind"), MemoryError()], ids=repr)
def test_any_other_scanner_exception_leaves_the_delivery_in_sealing_and_is_a_generic_500(make_lab, caplog, error):
    scanner = ScriptedScanner(error)
    lab = make_lab("bug", scanner)
    delivery = lab.delivered(CLEAN_FILE)
    since = len(lab.audit_rows())
    with caplog.at_level(logging.ERROR):
        response = lab.seal(delivery)
    generic(response, 500)
    assert "scanner" not in response.text and any(record.levelno == logging.ERROR for record in caplog.records)
    row = lab.delivery_row(delivery)
    assert row["state"] == "SEALING" and row["verdict_id"] is None and row["sealed_sha256"] is None
    assert lab.verdict_rows() == [] and trail(lab, since) == [("delivery.seal_started", "allowed", None)]
    assert lab.seal(delivery).json() == NOT_READY  # not sealed again behind the vendor's back; recovery is internal


# --- the stored file: fail closed, never silently sealed ------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["missing", "a symlink to a file", "a dangling symlink", "a directory", "a named pipe"])
def test_a_stored_file_that_is_missing_or_not_a_regular_file_cannot_be_sealed(rig, tmp_path, kind):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    path = lab.stored_path(delivery)
    path.unlink()
    if kind == "a symlink to a file":
        (tmp_path / "secret.txt").write_bytes(PNG_SIGNATURE + b"outside the quarantine root")
        path.symlink_to(tmp_path / "secret.txt")
    elif kind != "missing":
        occupy(path, tmp_path, kind)
    since = len(lab.audit_rows())
    generic(lab.seal(delivery), 500)
    row = lab.delivery_row(delivery)
    assert row["state"] == "SEALING" and row["sealed_sha256"] is None and row["verdict_id"] is None
    assert rig.scanner.calls == 0 and lab.verdict_rows() == []
    assert trail(lab, since) == [("delivery.seal_started", "allowed", None)]  # started, and nothing says it ended well
    if kind == "a symlink to a file":
        assert (tmp_path / "secret.txt").read_bytes() == PNG_SIGNATURE + b"outside the quarantine root"


def test_bytes_that_changed_between_the_hash_and_the_scan_are_not_sealed(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    real = trust.content_identity

    def hashed_then_changed(delivery_row, stored):
        identity = real(delivery_row, stored)
        append_to(lab.stored_path(delivery))
        return identity

    monkeypatch.setattr(trust, "content_identity", hashed_then_changed)
    response = lab.seal(delivery)
    assert response.status_code == 502 and response.json()["reason"] == "bad_response"  # the scanner read other bytes than H
    assert lab.delivery_row(delivery)["state"] == "SCAN_FAILED" and lab.verdict_rows() == []


def test_a_file_changed_while_it_was_being_hashed_cannot_be_sealed(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)

    def changed_during(delivery_row, stored):
        passes = stored.chunks(64)
        next(passes)
        append_to(lab.stored_path(delivery))
        list(passes)  # the pass notices at its end
        raise AssertionError("the pass should have failed")

    monkeypatch.setattr(trust, "content_identity", changed_during)
    generic(lab.seal(delivery), 500)
    assert lab.delivery_row(delivery)["state"] == "SEALING" and rig.scanner.calls == 0 and lab.verdict_rows() == []


CHANGES_AFTER_THE_SCAN = {
    "bytes appended": lambda path: append_to(path),
    "same size, other bytes": lambda path: path.write_bytes(b"Y" * len(CLEAN_FILE)),
    "only the modification time": lambda path: os.utime(path, (1, 1)),
    "the name replaced by another file": lambda path: (path.unlink(), path.write_bytes(CLEAN_FILE)),
}


@pytest.mark.parametrize("change", CHANGES_AFTER_THE_SCAN)
def test_a_file_that_changes_after_the_scan_read_it_is_not_recorded_as_sealed(make_lab, change):
    """The scanner reads and judges the real bytes correctly; the file changes before the verdict could be recorded."""
    scanner = ScriptedScanner()
    lab = make_lab("late", scanner)
    delivery = lab.delivered(CLEAN_FILE)
    real = LabSyntheticMarkerScanner()

    def read_then_change(stream):
        result = real.scan(stream, timeout_seconds=30.0)
        CHANGES_AFTER_THE_SCAN[change](lab.stored_path(delivery))
        return result

    scanner.steps = [read_then_change]
    since = len(lab.audit_rows())
    generic(lab.seal(delivery), 500)
    row = lab.delivery_row(delivery)
    assert row["state"] == "SEALING" and row["verdict_id"] is None and lab.verdict_rows() == []
    assert trail(lab, since) == [("delivery.seal_started", "allowed", None)]


def test_a_difference_from_the_intake_receipt_is_a_diagnostic_and_not_a_gate_or_an_event(rig, caplog):
    """The receipt (received_sha256) is not a second source of identity: H decides, the difference is only noted."""
    lab = rig.lab
    other = PNG_SIGNATURE + b"the bytes that are in quarantine at seal time, not the ones that arrived\n" * 3
    delivery = lab.delivered(CLEAN_FILE, declared_size=len(other), declared_sha256=sha256_hex(other))
    lab.stored_path(delivery).write_bytes(other)  # replaced out of band between the upload and the seal
    since = len(lab.audit_rows())
    with caplog.at_level(logging.WARNING):
        response = lab.seal(delivery)
    assert response.status_code == 200 and response.json()["sealed_sha256"] == sha256_hex(other)
    row = lab.delivery_row(delivery)
    assert row["sealed_sha256"] == sha256_hex(other) != row["received_sha256"] and row["receipt_matched"] == 0
    assert any(delivery in record.getMessage() and record.levelno == logging.WARNING for record in caplog.records)
    assert sha256_hex(other) not in caplog.text and row["received_sha256"] not in caplog.text  # bounded: no digests in the log
    assert trail(lab, since) == [("delivery.seal_started", "allowed", None), ("delivery.scan_passed", "recorded", None)]


# --- the database: no successful state without its record ----------------------------------------------------------------


def only_started(lab, delivery, since):
    row = lab.delivery_row(delivery)
    assert row["state"] == "SEALING" and row["verdict_id"] is None and row["sealed_sha256"] is None
    assert lab.verdict_rows() == [] and trail(lab, since) == [("delivery.seal_started", "allowed", None)]


def test_a_commit_that_fails_after_a_scan_leaves_no_successful_state_and_no_verdict(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    since = len(lab.audit_rows())
    real, calls = store.transaction, []

    def second_commit_fails(conn):
        calls.append(1)
        return transaction_whose_commit_fails(conn) if len(calls) == 2 else real(conn)

    monkeypatch.setattr(store, "transaction", second_commit_fails)
    generic(lab.seal(delivery), 500)
    assert len(calls) == 2 and rig.scanner.calls == 1  # the scan happened; the record did not commit
    only_started(lab, delivery, since)


def test_a_failure_to_audit_the_outcome_rolls_back_the_verdict_and_the_state(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    since = len(lab.audit_rows())
    real = audit.record_event

    def failing(conn, clock, action, *args, **kwargs):
        if action is audit.AuditAction.DELIVERY_SCAN_PASSED:
            raise sqlite3.OperationalError("audit insert failed")
        return real(conn, clock, action, *args, **kwargs)

    monkeypatch.setattr(audit, "record_event", failing)
    generic(lab.seal(delivery), 500)
    only_started(lab, delivery, since)  # the verdict row was inserted in that transaction, and went with it


def test_a_failure_to_write_the_verdict_leaves_no_successful_state(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    since = len(lab.audit_rows())

    def failing(*args, **kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store, "add_verdict", failing)
    generic(lab.seal(delivery), 500)
    only_started(lab, delivery, since)


def test_a_failed_rejection_record_leaves_the_delivery_sealing_and_not_rejected(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE, declared_sha256="c" * 64)
    since = len(lab.audit_rows())
    real = audit.record_event

    def failing(conn, clock, action, *args, **kwargs):
        if action is audit.AuditAction.DELIVERY_REJECTED:
            raise sqlite3.OperationalError("audit insert failed")
        return real(conn, clock, action, *args, **kwargs)

    monkeypatch.setattr(audit, "record_event", failing)
    generic(lab.seal(delivery), 500)
    only_started(lab, delivery, since)


def test_the_seal_is_two_short_transactions_with_the_inspection_between_them(lab, spy, monkeypatch):
    delivery = lab.delivered(CLEAN_FILE)
    real_scan = LabSyntheticMarkerScanner.scan
    monkeypatch.setattr(LabSyntheticMarkerScanner, "scan", lambda self, stream, **k: (spy.events.append("SCAN"), real_scan(self, stream, **k))[1])
    spy.events.clear()
    assert lab.seal(delivery).status_code == 200
    events = spy.events
    begins = [i for i, event in enumerate(events) if event == "BEGIN IMMEDIATE"]
    commits = [i for i, event in enumerate(events) if event == "COMMIT"]
    assert len(begins) == len(commits) == 2 and events.count("AUTHENTICATE") == 1
    assert begins[0] < commits[0] < events.index("SCAN") < begins[1] < commits[1]  # the scan holds no transaction
    assert not any(event.startswith(("INSERT", "UPDATE", "DELETE")) for event in events[commits[0] + 1 : begins[1]])  # and writes nothing
    assert_released(lab, spy)


# --- the engine kind in the audit trail (M0 Addendum §5.3) -------------------------------------------------------------------


def kinds(lab, since=0):
    return [(row["action"], row["reason"], row["engine_kind"]) for row in lab.audit_rows()[since:]]


def test_every_verdict_bearing_seal_event_records_the_scanners_kind_and_no_other_event_does(rig):
    lab = rig.lab
    passed, reused = lab.delivered(CLEAN_FILE), lab.delivered(CLEAN_FILE)
    detected = lab.delivered(MARKER_FILE)
    mismatched = lab.delivered(CLEAN_FILE, declared_sha256="c" * 64)
    unsupported = lab.delivered(ZIP_FILE)
    since = len(lab.audit_rows())
    for delivery in (passed, reused, detected, mismatched, unsupported):
        lab.seal(delivery)
    assert kinds(lab, since) == [
        ("delivery.seal_started", None, None),
        ("delivery.scan_passed", None, "synthetic"),
        ("delivery.seal_started", None, None),
        ("delivery.verdict_reused", None, "synthetic"),
        ("delivery.seal_started", None, None),
        ("delivery.rejected", "detection", "synthetic"),  # the one rejection that is about a verdict
        ("delivery.seal_started", None, None),
        ("delivery.rejected", "checksum_mismatch", None),  # no scanner was involved
        ("delivery.seal_started", None, None),
        ("delivery.rejected", "unsupported_type", None),
    ]


@pytest.mark.parametrize("reason", FAILURES)
def test_a_scan_that_could_not_give_a_verdict_records_the_configured_scanners_kind_and_no_verdict_id(make_lab, reason):
    lab = make_lab("failing-kind", ScriptedScanner(FAILURES[reason]))
    delivery = lab.delivered(CLEAN_FILE)
    since = len(lab.audit_rows())
    lab.seal(delivery)
    assert kinds(lab, since)[-1] == ("delivery.scan_failed", f"scanner_{reason}", "synthetic")
    assert lab.delivery_row(delivery)["verdict_id"] is None and lab.verdict_rows() == []  # nothing invented


def test_events_that_are_not_about_a_verdict_leave_the_engine_kind_null(rig):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    lab.seal(delivery, "coordinator-1")  # a denial
    lab.seal("f" * 32)  # a missing delivery
    assert lab.audit_rows()  # declaration, upload start and completion, and the two refusals
    assert all(row["engine_kind"] is None for row in lab.audit_rows())


# --- F-03: the declared hash never becomes the identity of the bytes ------------------------------------------------------


def test_f03_a_marked_file_that_declares_the_hash_of_a_scanned_clean_file_is_rejected_by_the_checksum_comparison(rig, monkeypatch):
    lab, scanner = rig.lab, rig.scanner
    clean = lab.delivered(CLEAN_FILE)
    assert lab.seal(clean).status_code == 200 and scanner.calls == 1
    cached = lab.verdict_rows()
    lookups = watch(monkeypatch, "lookup_verdict")
    malicious = lab.delivered(MARKER_FILE, declared_sha256=sha256_hex(CLEAN_FILE))  # an allowed signature, the clean file's hash
    since = len(lab.audit_rows())
    response = lab.seal(malicious)
    assert response.status_code == 422
    assert response.json()["reason"] == "checksum_mismatch" and response.json()["sealed_sha256"] == sha256_hex(MARKER_FILE)
    assert scanner.calls == 1 and lookups == [] and lab.verdict_rows() == cached  # the cache was never consulted, nor changed
    row = lab.delivery_row(malicious)
    assert (row["state"], row["verdict_id"]) == ("REJECTED", None)
    assert row["declared_sha256"] == sha256_hex(CLEAN_FILE) != row["sealed_sha256"]
    assert trail(lab, since)[-1] == ("delivery.rejected", "denied", "checksum_mismatch")


def test_the_cache_is_looked_up_with_the_digest_of_the_bytes_and_never_with_a_string_the_vendor_sent(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    lookups = watch(monkeypatch, "lookup_verdict")
    lab.seal(delivery)
    ((conn, identity, engine, now),) = lookups
    assert type(identity) is trust.ContentIdentity and identity.sha256 == sha256_hex(CLEAN_FILE)
    assert engine == rig.scanner.engine and now == SEALED_AT
    with pytest.raises(TypeError):
        trust.lookup_verdict(conn, sha256_hex(CLEAN_FILE), engine, now)  # a bare declared string is not an identity


def test_the_gate_takes_its_digest_from_content_identity_alone(make_lab, monkeypatch):
    """O-1, Option A: one authoritative value is compared, looked up, bound to the verdict and sealed. Nothing else is."""
    value = sha256_hex(b"neither the declared bytes nor any bytes that were uploaded")
    scanner = ScriptedScanner(lambda stream: ScanResult(Verdict.NO_DETECTION, value))
    lab = make_lab("one-digest", scanner)
    delivery = lab.delivered(CLEAN_FILE, declared_sha256=value)
    lookups = watch(monkeypatch, "lookup_verdict")
    monkeypatch.setattr(trust, "content_identity", lambda delivery_row, stored: trust.ContentIdentity(value))
    response = lab.seal(delivery)
    assert response.status_code == 200 and response.json()["sealed_sha256"] == value
    row = lab.delivery_row(delivery)
    (verdict,) = lab.verdict_rows()
    assert row["sealed_sha256"] == verdict["sha256"] == verdict["scanned_sha256"] == value
    assert [call[1].sha256 for call in lookups] == [value]
    assert row["received_sha256"] == sha256_hex(CLEAN_FILE) and row["receipt_matched"] == 0  # a diagnostic, not a second gate


def test_the_digest_of_a_sealed_delivery_is_the_digest_of_the_bytes_in_quarantine(rig):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    lab.seal(delivery)
    assert lab.delivery_row(delivery)["sealed_sha256"] == sha256_hex(lab.stored_path(delivery).read_bytes())


def test_sealing_does_not_change_the_bytes_or_the_name_they_are_kept_under(rig):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    path, before = lab.stored_path(delivery), lab.stored_path(delivery).stat()
    lab.seal(delivery)
    after = path.stat()
    assert (after.st_ino, after.st_size, after.st_mtime_ns) == (before.st_ino, before.st_size, before.st_mtime_ns)
    assert lab.quarantine_names() == [path.name] and path.read_bytes() == CLEAN_FILE


def test_quarantined_bytes_are_still_never_served_after_sealing(rig):
    lab = rig.lab
    delivery = lab.delivered(CLEAN_FILE)
    lab.seal(delivery)
    for name in (delivery, lab.delivery_row(delivery)["storage_key"]):
        assert lab.send("GET", f"/productions/{lab.alpha}/assets/{name}", subject="vendor-1").status_code == 404
