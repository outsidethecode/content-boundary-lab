"""GET and POST /productions/{id}/deliveries/{id}/seal|accept: the coordinator inspects the sealing result and accepts a digest.

M0 §2 steps 6 and 7 (M1J). Inspection shows a coordinator the delivery's authoritative sealed digest H and the scanner
evidence behind it. Acceptance is bound to H: the coordinator names the digest they inspected and the server accepts only
if, in the same transaction that changes the state, H is still that digest, the attached verdict is a no_detection
verdict for H by an engine, version, kind and policy the server still accepts, the verdict has not expired at the instant
the transaction read from the clock, and the delivery's vendor has not been revoked (A9). Real HTTP behaviour on synthetic
files; every row is read back from SQLite.
"""

import threading
from datetime import timedelta
from types import SimpleNamespace

import pytest
from support.http_lab import (
    CLEAN_FILE,
    MARKER_FILE,
    SEEDED_DIGEST,
    T0,
    THREAD_WAIT,
    Background,
    generic,
    make_lab,
    observable,
    sha256_hex,
    transaction_whose_commit_fails,
)
from support.scanners import CountingScanner, engine_like

from content_boundary_lab import quarantine, request_flow, store, trust
from content_boundary_lab.audit import AuditReason
from content_boundary_lab.clock import to_micros
from content_boundary_lab.scanner import EngineIdentity

VALID_FOR = timedelta(hours=24)  # a lab assumption (A8): how long a verdict may be reused
HASH = sha256_hex(CLEAN_FILE)
MICROSECOND = timedelta(microseconds=1)
FIELDS_OF_AN_INSPECTION = {
    "delivery_id", "state", "reason", "sealed_size", "sealed_sha256", "verdict", "engine", "policy_fingerprint",
    "verdict_scanned_at", "verdict_valid_until", "verdict_in_force", "accepted_sha256", "accepted_at",
}  # fmt: skip


def refusal(reason):
    return {"detail": "Delivery cannot be accepted", "reason": reason}


def utc(moment):
    return request_flow.utc_text(to_micros(moment))


def trail(lab, since=0):
    return [(row["action"], row["outcome"], row["reason"]) for row in lab.audit_rows()[since:]]


def engine_json(scanner):
    return {"id": scanner.engine.id, "version": scanner.engine.version, "kind": scanner.engine.kind}


@pytest.fixture
def rig(make_lab):
    """An application whose scanner is the real stub behind a call counter."""
    scanner = CountingScanner()
    return SimpleNamespace(lab=make_lab("rig", scanner), scanner=scanner)


def at(lab, moment, subject="coordinator-1"):
    """Set the application's clock to `moment` and return a token for `subject` that is valid then."""
    lab.clock.moment = moment
    return lab.token_at(subject, moment)


def unchanged(lab, delivery_id, before):
    assert lab.delivery_row(delivery_id) == before


# --- what a coordinator sees ---------------------------------------------------------------------------------------------


def test_a_coordinator_sees_the_sealed_digest_the_size_and_the_scanner_evidence(rig):
    lab, scanner = rig.lab, rig.scanner
    delivery = lab.sealed(CLEAN_FILE)
    since = len(lab.audit_rows())
    response = lab.inspect(delivery)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "delivery_id": delivery, "state": "SCAN_PASSED", "sealed_size": len(CLEAN_FILE), "sealed_sha256": HASH,
        "verdict": "no_detection", "engine": engine_json(scanner), "policy_fingerprint": scanner.engine.policy_fingerprint,
        "verdict_scanned_at": utc(T0), "verdict_valid_until": utc(T0 + VALID_FOR), "verdict_in_force": True,
    }  # fmt: skip
    (event,) = lab.audit_rows()[since:]
    assert (event["action"], event["outcome"], event["reason"], event["engine_kind"]) == ("delivery.viewed", "allowed", None, "synthetic")
    assert (event["actor_issuer"], event["actor_subject"], event["production_id"]) == ("https://issuer.example", "coordinator-1", lab.alpha)
    assert (event["object_type"], event["object_id"]) == ("delivery", delivery)


def test_inspecting_changes_nothing_reads_no_file_and_calls_no_scanner(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before, verdicts, calls = lab.delivery_row(delivery), lab.verdict_rows(), rig.scanner.calls
    opened = []
    monkeypatch.setattr(quarantine, "open_stored", lambda *args: opened.append(args))
    assert lab.inspect(delivery).status_code == 200
    assert (lab.delivery_row(delivery), lab.verdict_rows(), rig.scanner.calls, opened) == (before, verdicts, calls, [])


def test_a_detection_is_shown_with_its_verdict_and_the_engine_that_made_it(rig):
    lab, scanner = rig.lab, rig.scanner
    delivery = lab.delivered(MARKER_FILE)
    assert lab.seal(delivery).status_code == 422
    response = lab.inspect(delivery)
    assert response.status_code == 200
    assert response.json() == {
        "delivery_id": delivery, "state": "REJECTED", "reason": "detection", "sealed_size": len(MARKER_FILE),
        "sealed_sha256": sha256_hex(MARKER_FILE), "verdict": "detection", "engine": engine_json(scanner),
        "policy_fingerprint": scanner.engine.policy_fingerprint, "verdict_scanned_at": utc(T0),
        "verdict_valid_until": utc(T0 + VALID_FOR), "verdict_in_force": False,
    }  # fmt: skip
    assert lab.audit_rows()[-1]["engine_kind"] == "synthetic"


STATE_FIELDS = {  # what exists in each state, and so what is shown
    "INITIATED": {"delivery_id", "state"},
    "UPLOADED": {"delivery_id", "state"},
    "SEALING": {"delivery_id", "state"},
    "REJECTED": {"delivery_id", "state", "reason", "sealed_size", "sealed_sha256"},
    "SCAN_FAILED": {"delivery_id", "state", "reason", "sealed_size", "sealed_sha256"},
    "INTEGRITY_FAILED": {"delivery_id", "state", "sealed_size", "sealed_sha256"},
    "SCAN_PASSED": {
        "delivery_id", "state", "sealed_size", "sealed_sha256", "verdict", "engine", "policy_fingerprint",
        "verdict_scanned_at", "verdict_valid_until", "verdict_in_force",
    },
}  # fmt: skip
for _state in ("ACCEPTED", "PROMOTING", "PROMOTED"):
    STATE_FIELDS[_state] = STATE_FIELDS["SCAN_PASSED"] | {"accepted_sha256", "accepted_at"}


@pytest.mark.parametrize("state", list(STATE_FIELDS))
def test_an_inspection_shows_exactly_what_exists_in_the_deliverys_state(rig, state):
    lab = rig.lab
    delivery = lab.seed_delivery("vendor-1", state=state)
    response = lab.inspect(delivery.id)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == STATE_FIELDS[state] <= FIELDS_OF_AN_INSPECTION
    assert (body["delivery_id"], body["state"]) == (delivery.id, state)
    if "sealed_sha256" in body:
        assert (body["sealed_size"], body["sealed_sha256"]) == (7, SEEDED_DIGEST)
    if "accepted_sha256" in body:
        assert body["accepted_sha256"] == SEEDED_DIGEST
    if "verdict" in body:
        assert (body["verdict"], body["engine"], body["verdict_in_force"]) == ("no_detection", engine_json(rig.scanner), True)


def test_an_inspection_says_when_the_verdict_is_no_longer_in_force(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    expires = T0 + VALID_FOR
    shown = {}
    for label, moment in (("before", expires - MICROSECOND), ("at", expires), ("after", expires + MICROSECOND)):
        body = lab.inspect(delivery, token=at(lab, moment)).json()
        shown[label] = (body["state"], body["verdict_in_force"], body["verdict_valid_until"])
    assert shown == {
        "before": ("SCAN_PASSED", True, utc(expires)),
        "at": ("SCAN_PASSED", False, utc(expires)),  # valid_until is the first instant at which it is no longer in force
        "after": ("SCAN_PASSED", False, utc(expires)),
    }


def test_an_inspection_after_acceptance_shows_the_acceptance(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    assert lab.accept(delivery, HASH).status_code == 200
    body = lab.inspect(delivery).json()
    assert (body["state"], body["accepted_sha256"], body["accepted_at"]) == ("ACCEPTED", HASH, utc(T0))


# --- who may inspect and accept, and in which production -------------------------------------------------------------------

DENIED = {
    "no credentials": dict(subject=None, status=401, reason="invalid_credentials"),
    "the vendor that owns the delivery": dict(subject="vendor-1", status=403, reason="role_not_permitted"),
    "another vendor of the production": dict(subject="dual-1", status=403, reason="role_not_permitted"),
    "a vendor of another production": dict(subject="vendor-2", status=403, reason="no_engagement"),
    "a coordinator of another production through its url": dict(subject="coordinator-2", production="bravo", status=404, reason="not_found_or_forbidden"),
    "a coordinator of another production through the delivery's url": dict(subject="coordinator-2", status=403, reason="no_engagement"),
    "the coordinator through another production's url": dict(subject="coordinator-1", production="bravo", status=403, reason="no_engagement"),
}  # fmt: skip


@pytest.mark.parametrize("case", DENIED.values(), ids=list(DENIED))
def test_only_a_coordinator_of_the_deliverys_production_can_inspect_it(rig, case):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    since = len(lab.audit_rows())
    production = lab.production(case["production"]) if "production" in case else None
    response = lab.inspect(delivery, case["subject"], production)
    assert response.status_code == case["status"]
    assert trail(lab, since) == [("access.denied", "denied", case["reason"])]
    assert "sealed_sha256" not in response.text and HASH not in response.text


@pytest.mark.parametrize("case", DENIED.values(), ids=list(DENIED))
def test_only_a_coordinator_of_the_deliverys_production_can_accept_it(rig, case):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before = lab.delivery_row(delivery)
    since = len(lab.audit_rows())
    production = lab.production(case["production"]) if "production" in case else None
    response = lab.accept(delivery, HASH, case["subject"], production)
    assert response.status_code == case["status"]
    assert trail(lab, since) == [("access.denied", "denied", case["reason"])]
    unchanged(lab, delivery, before)


def test_a_vendor_cannot_accept_its_own_delivery(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before = lab.delivery_row(delivery)
    response = lab.accept(delivery, HASH, "vendor-1")
    generic(response, 403)
    assert lab.audit_rows()[-1]["reason"] == "role_not_permitted"
    unchanged(lab, delivery, before)


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "PATCH"])
def test_only_post_is_accepted_on_the_accept_path(rig, method):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before = lab.delivery_row(delivery)
    assert lab.send(method, lab.accept_path(delivery), subject="coordinator-1", json={"sealed_sha256": HASH}).status_code == 405
    unchanged(lab, delivery, before)


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "POST"])
def test_only_get_is_the_inspection_on_the_seal_path_and_post_stays_the_vendors(rig, method):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before = lab.delivery_row(delivery)
    response = lab.send(method, lab.seal_path(delivery), subject="coordinator-1")
    assert response.status_code == (403 if method == "POST" else 405)  # a coordinator cannot seal; no other method exists
    unchanged(lab, delivery, before)


def test_a_coordinator_of_two_productions_cannot_reach_one_through_the_other(rig):
    lab = rig.lab
    lab.engage("coordinator-2", lab.alpha, "coordinator")  # coordinator-2 now manages both productions
    in_bravo = lab.seed_delivery("vendor-2", production=lab.bravo, state="SCAN_PASSED")
    before = lab.delivery_row(in_bravo.id)
    through_alpha = lab.inspect(in_bravo.id, "coordinator-2", lab.alpha)
    assert (through_alpha.status_code, through_alpha.json()) == (404, {"detail": "Not found"})
    refused = lab.accept(in_bravo.id, SEEDED_DIGEST, "coordinator-2", lab.alpha)
    assert (refused.status_code, refused.json()) == (404, {"detail": "Not found"})
    unchanged(lab, in_bravo.id, before)
    assert lab.inspect(in_bravo.id, "coordinator-2", lab.bravo).status_code == 200
    assert lab.accept(in_bravo.id, SEEDED_DIGEST, "coordinator-2", lab.bravo).status_code == 200  # through its own: allowed


def test_a_missing_delivery_and_another_productions_delivery_look_the_same_to_a_coordinator(rig):
    lab = rig.lab
    lab.engage("coordinator-2", lab.alpha, "coordinator")
    elsewhere = lab.seed_delivery("vendor-2", production=lab.bravo, state="SCAN_PASSED")
    for ask in (
        lambda delivery_id: lab.inspect(delivery_id, "coordinator-2", lab.alpha),
        lambda delivery_id: lab.accept(delivery_id, SEEDED_DIGEST, "coordinator-2", lab.alpha),
    ):
        since = len(lab.audit_rows())
        exists, missing = ask(elsewhere.id), ask("f" * 32)
        assert observable(exists) == observable(missing) and exists.status_code == 404
        first, second = lab.audit_rows()[since:]
        for row in (first, second):
            assert (row["action"], row["outcome"], row["reason"], row["production_id"]) == ("access.denied", "denied", "not_found_or_forbidden", lab.alpha)
        assert {key: value for key, value in first.items() if key not in ("seq", "object_id")} == {
            key: value for key, value in second.items() if key not in ("seq", "object_id")
        }
    assert lab.delivery_row(elsewhere.id)["state"] == "SCAN_PASSED"


@pytest.mark.parametrize("delivery_id", ["A" * 32, "a" * 31, "../" + "a" * 29, "' OR '1'='1", "%00"])
def test_a_malformed_delivery_id_is_the_same_404(rig, delivery_id):
    lab = rig.lab
    for response in (lab.inspect(delivery_id), lab.accept(delivery_id, HASH)):
        assert (response.status_code, response.json()) == (404, {"detail": "Not found"})
    assert {row["reason"] for row in lab.audit_rows()} == {"invalid_identifier"}
    assert all(row["object_id"] is None for row in lab.audit_rows())


def test_an_id_shaped_like_an_asset_path_is_answered_by_the_asset_route_and_no_delivery_is_looked_up(rig):
    """The asset route is registered first and its `:path` parameters are greedy, as they have been since M1G: a GET for
    .../deliveries/assets/<id>/seal is an asset request for the production `<alpha>/deliveries`, which is not a production."""
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    since = len(lab.audit_rows())
    generic(lab.inspect("assets/" + delivery), 403)
    assert trail(lab, since) == [("access.denied", "denied", "invalid_identifier")]
    assert lab.accept("assets/" + delivery, HASH).status_code == 404  # accepting is a POST, which that route does not take


def test_a_revoked_coordinator_can_neither_inspect_nor_accept(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before = lab.delivery_row(delivery)
    assert lab.inspect(delivery).status_code == 200
    lab.revoke("coordinator", at=T0 + timedelta(seconds=30))
    token = at(lab, T0 + timedelta(seconds=60))
    generic(lab.inspect(delivery, token=token), 403)
    generic(lab.accept(delivery, HASH, token=token), 403)
    assert trail(lab)[-2:] == [("access.denied", "denied", "engagement_revoked")] * 2
    unchanged(lab, delivery, before)


# --- accepting ----------------------------------------------------------------------------------------------------------------


def test_a_coordinator_accepts_the_digest_they_inspected(rig):
    lab, scanner = rig.lab, rig.scanner
    delivery = lab.sealed(CLEAN_FILE)
    seen = lab.inspect(delivery).json()["sealed_sha256"]
    since, calls = len(lab.audit_rows()), scanner.calls
    response = lab.accept(delivery, seen)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "delivery_id": delivery, "state": "ACCEPTED", "accepted_sha256": HASH, "accepted_at": utc(T0),
        "engine": engine_json(scanner), "verdict_valid_until": utc(T0 + VALID_FOR),
    }  # fmt: skip
    row = lab.delivery_row(delivery)
    assert (row["state"], row["accepted_sha256"], row["accepted_at"], row["accepted_by"]) == (
        "ACCEPTED", HASH, to_micros(T0), lab.subject_id("coordinator-1"),
    )  # fmt: skip
    assert row["accepted_sha256"] == row["sealed_sha256"] == HASH and row["state_reason"] is None
    (event,) = lab.audit_rows()[since:]
    assert (event["action"], event["outcome"], event["reason"], event["engine_kind"]) == ("delivery.accepted", "allowed", None, "synthetic")
    assert (event["actor_subject"], event["production_id"], event["object_type"], event["object_id"]) == ("coordinator-1", lab.alpha, "delivery", delivery)
    assert scanner.calls == calls and len(lab.verdict_rows()) == 1


def test_who_accepted_is_the_verified_caller_and_nothing_in_the_request_can_name_someone_else(rig):
    lab = rig.lab
    lab.engage("coordinator-2", lab.alpha, "coordinator")
    first, second = lab.sealed(CLEAN_FILE), lab.sealed(CLEAN_FILE)
    before = lab.delivery_row(first)
    forged = lab.send(
        "POST", lab.accept_path(first), subject="coordinator-2", json={"sealed_sha256": HASH, "accepted_by": lab.subject_id("coordinator-1")}
    )
    assert (forged.status_code, forged.json()) == (400, {"detail": "Invalid request", "field": "body"})
    unchanged(lab, first, before)
    assert lab.accept(first, HASH, "coordinator-2", headers={"X-Accepted-By": "coordinator-1"}).status_code == 200
    assert lab.accept(second, HASH, "coordinator-1").status_code == 200
    assert lab.delivery_row(first)["accepted_by"] == lab.subject_id("coordinator-2")
    assert lab.delivery_row(second)["accepted_by"] == lab.subject_id("coordinator-1")


def test_accepting_reads_no_file_because_the_bytes_are_checked_at_promotion(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    lab.stored_path(delivery).unlink()  # M0 §5.4: "after scan, before accept" is not checked at accept
    opened = []
    monkeypatch.setattr(quarantine, "open_stored", lambda *args: opened.append(args))
    assert lab.accept(delivery, HASH).status_code == 200 and opened == []


def test_the_acceptance_is_final_and_a_second_one_is_refused(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    assert lab.accept(delivery, HASH).status_code == 200
    first = lab.delivery_row(delivery)
    since = len(lab.audit_rows())
    again = lab.accept(delivery, HASH)
    assert (again.status_code, again.json()) == (409, refusal("state_conflict"))
    assert trail(lab, since) == [("delivery.acceptance_refused", "denied", "state_conflict")]
    unchanged(lab, delivery, first)


@pytest.mark.parametrize("state", ["INITIATED", "UPLOADED", "SEALING", "REJECTED", "SCAN_FAILED", "ACCEPTED", "PROMOTING", "PROMOTED", "INTEGRITY_FAILED"])
def test_only_a_delivery_in_scan_passed_can_be_accepted(rig, state):
    lab = rig.lab
    delivery = lab.seed_delivery("vendor-1", state=state)
    before = lab.delivery_row(delivery.id)
    response = lab.accept(delivery.id, SEEDED_DIGEST)
    assert (response.status_code, response.json()) == (409, refusal("state_conflict"))
    assert trail(lab) == [("delivery.acceptance_refused", "denied", "state_conflict")]
    assert lab.audit_rows()[0]["engine_kind"] is None
    unchanged(lab, delivery.id, before)


WRONG_DIGESTS = {
    "another digest": sha256_hex(b"other bytes"),
    "all zeros": "0" * 64,
    "the digest with one character changed": HASH[:-1] + ("0" if HASH[-1] != "0" else "1"),
    "the digest of the first half of the file": sha256_hex(CLEAN_FILE[: len(CLEAN_FILE) // 2]),
}


@pytest.mark.parametrize("digest", WRONG_DIGESTS.values(), ids=list(WRONG_DIGESTS))
def test_a_digest_other_than_the_sealed_one_is_refused(rig, digest):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before = lab.delivery_row(delivery)
    since = len(lab.audit_rows())
    response = lab.accept(delivery, digest)
    assert (response.status_code, response.json()) == (409, refusal("digest_mismatch"))
    assert trail(lab, since) == [("delivery.acceptance_refused", "denied", "digest_mismatch")]
    assert lab.audit_rows()[-1]["engine_kind"] is None
    unchanged(lab, delivery, before)  # the digest in the request neither became H nor was recorded anywhere
    assert digest not in str(lab.audit_rows()) + str(lab.verdict_rows())


BAD_BODIES = {
    "no body": (b"", "body"),
    "not json": (b"sealed_sha256", "body"),
    "a list": (b"[]", "body"),
    "an empty object": (b"{}", "body"),
    "another member name": (('{"sha256": "%s"}' % HASH).encode(), "body"),
    "an extra member": (('{"sealed_sha256": "%s", "force": true}' % HASH).encode(), "body"),
    "a repeated member": (('{"sealed_sha256": "%s", "sealed_sha256": "%s"}' % (HASH, HASH)).encode(), "body"),
    "not utf-8": (b'{"sealed_sha256": "\xff"}', "body"),
    "a number": (b'{"sealed_sha256": 5}', "sealed_sha256"),
    "null": (b'{"sealed_sha256": null}', "sealed_sha256"),
    "an empty string": (b'{"sealed_sha256": ""}', "sealed_sha256"),
    "a short digest": (('{"sealed_sha256": "%s"}' % HASH[:-1]).encode(), "sealed_sha256"),
    "a long digest": (('{"sealed_sha256": "%s0"}' % HASH).encode(), "sealed_sha256"),
    "a digest in capitals": (('{"sealed_sha256": "%s"}' % HASH.upper()).encode(), "sealed_sha256"),
    "a digest that is not hexadecimal": (('{"sealed_sha256": "%s"}' % ("g" * 64)).encode(), "sealed_sha256"),
    "a digest with a trailing space": (('{"sealed_sha256": "%s "}' % HASH).encode(), "sealed_sha256"),
}


@pytest.mark.parametrize("case", BAD_BODIES.values(), ids=list(BAD_BODIES))
def test_a_malformed_body_is_refused_and_changes_nothing(rig, case):
    body, field = case
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before = lab.delivery_row(delivery)
    since = len(lab.audit_rows())
    response = lab.send("POST", lab.accept_path(delivery), subject="coordinator-1", content=body)
    assert (response.status_code, response.json()) == (400, {"detail": "Invalid request", "field": field})
    assert trail(lab, since) == [("delivery.acceptance_refused", "denied", "invalid_request")]
    unchanged(lab, delivery, before)


def test_an_oversized_body_is_refused_with_413_after_authorisation(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before = lab.delivery_row(delivery)
    big = b'{"sealed_sha256": "' + b"a" * (request_flow.MAX_BODY_BYTES + 1) + b'"}'
    since = len(lab.audit_rows())
    response = lab.send("POST", lab.accept_path(delivery), subject="coordinator-1", content=big)
    assert (response.status_code, response.json()) == (413, {"detail": "Payload too large"})
    assert trail(lab, since) == [("delivery.acceptance_refused", "denied", "payload_too_large")]
    generic(lab.send("POST", lab.accept_path(delivery), subject="vendor-1", content=big), 403)  # the 403 never depends on the body
    unchanged(lab, delivery, before)


def test_the_target_is_looked_up_before_the_body_is_judged(rig):
    """A body error must not tell a caller whether a delivery they cannot reach exists."""
    lab = rig.lab
    lab.engage("coordinator-2", lab.alpha, "coordinator")
    elsewhere = lab.seed_delivery("vendor-2", production=lab.bravo, state="SCAN_PASSED")
    for body in (b"", b"[]", b'{"sealed_sha256": 5}'):
        for target in (elsewhere.id, "f" * 32):
            response = lab.send("POST", lab.accept_path(target, lab.alpha), subject="coordinator-2", content=body)
            assert (response.status_code, response.json()) == (404, {"detail": "Not found"})


# --- the verdict at the instant of acceptance --------------------------------------------------------------------------------

EDGE = {
    "one microsecond before it expires": (-MICROSECOND, 200),
    "the instant it expires": (timedelta(0), 409),
    "one microsecond after": (MICROSECOND, 409),
    "a day after": (timedelta(days=1), 409),
}


@pytest.mark.parametrize("edge", EDGE.values(), ids=list(EDGE))
def test_a_verdict_is_acceptable_until_valid_until_and_not_at_it(make_lab, edge):
    offset, status = edge
    scanner = CountingScanner()
    lab = make_lab("edge", scanner)
    delivery = lab.sealed(CLEAN_FILE)
    valid_until = lab.verdict_rows()[0]["valid_until"]
    assert valid_until == to_micros(T0 + VALID_FOR)
    before = lab.delivery_row(delivery)
    since = len(lab.audit_rows())
    now = T0 + VALID_FOR + offset
    response = lab.accept(delivery, HASH, token=at(lab, now))
    assert response.status_code == status
    if status == 200:
        assert lab.delivery_row(delivery)["accepted_at"] == to_micros(now) < valid_until
        assert trail(lab, since) == [("delivery.accepted", "allowed", None)]
    else:
        assert response.json() == refusal("verdict_stale")
        assert trail(lab, since) == [("delivery.acceptance_refused", "denied", "verdict_stale")]
        assert lab.audit_rows()[-1]["engine_kind"] == "synthetic"
        unchanged(lab, delivery, before)  # the state is not moved to anything; only an internal rescan re-enters the gate
    assert scanner.calls == 1


def test_a_delivery_that_once_reached_scan_passed_is_not_acceptable_merely_for_that(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    assert lab.delivery_row(delivery)["state"] == "SCAN_PASSED"
    refused = lab.accept(delivery, HASH, token=at(lab, T0 + VALID_FOR + timedelta(hours=1)))
    assert (refused.status_code, refused.json()) == (409, refusal("verdict_stale"))
    assert lab.delivery_row(delivery)["state"] == "SCAN_PASSED"  # still what the seal said; the acceptance said no


def test_the_instant_that_decides_the_expiry_is_the_instant_that_is_recorded(make_lab):
    """One clock read for the whole transaction: a later read would be after the expiry, and the record would disagree."""
    lab = make_lab("one-read", CountingScanner())
    delivery = lab.sealed(CLEAN_FILE)
    last_good = T0 + VALID_FOR - MICROSECOND
    token = at(lab, last_good)
    lab.clock.step = timedelta(seconds=10)  # every read of the clock moves it on
    reads = lab.clock.calls
    response = lab.accept(delivery, HASH, token=token)
    assert response.status_code == 200
    assert lab.clock.calls == reads + 1  # the request read the clock once
    assert lab.delivery_row(delivery)["accepted_at"] == to_micros(last_good)
    assert lab.audit_rows()[-1]["at"] == to_micros(last_good)


ENGINE_CHANGES = {
    "another engine": {"id": "lab-another-engine"},
    "another version of the engine": {"version": "2"},
    "another policy fingerprint": {"policy_fingerprint": "e" * 64},
}


@pytest.mark.parametrize("changes", ENGINE_CHANGES.values(), ids=list(ENGINE_CHANGES))
def test_a_verdict_from_another_engine_version_or_policy_is_not_acceptable(rig, changes):
    lab = rig.lab
    lab.seed_verdict(SEEDED_DIGEST, engine=engine_like(lab.scanner, **changes))  # in force, but not this scanner's
    delivery = lab.seed_delivery("vendor-1", state="SCAN_PASSED")
    before = lab.delivery_row(delivery.id)
    response = lab.accept(delivery.id, SEEDED_DIGEST)
    assert (response.status_code, response.json()) == (409, refusal("verdict_stale"))
    assert trail(lab) == [("delivery.acceptance_refused", "denied", "verdict_stale")]
    assert lab.audit_rows()[0]["engine_kind"] == "synthetic"
    unchanged(lab, delivery.id, before)


def test_a_verdict_from_this_scanner_is_acceptable_when_seeded_the_same_way(rig):
    lab = rig.lab
    lab.seed_verdict(SEEDED_DIGEST)
    delivery = lab.seed_delivery("vendor-1", state="SCAN_PASSED")
    assert lab.accept(delivery.id, SEEDED_DIGEST).status_code == 200


def test_the_scanner_the_server_runs_now_decides_which_verdicts_still_count(make_lab):
    """The same database, a scanner that has been upgraded since the seal: its old verdicts are kept and not applied."""
    old = CountingScanner()
    lab = make_lab("upgrade", old)
    delivery = lab.sealed(CLEAN_FILE)
    assert lab.inspect(delivery).json()["verdict_in_force"] is True
    old.engine = engine_like(old.engine, version="2")  # read from the scanner at each request, not once at start-up
    refused = lab.accept(delivery, HASH)
    assert (refused.status_code, refused.json()) == (409, refusal("verdict_stale"))
    assert lab.inspect(delivery).json()["verdict_in_force"] is False


class _Record:
    """The verdict_problem cases that the database's own constraints keep out of a real delivery."""

    ENGINE = EngineIdentity(id="lab-synthetic-marker", version="1", kind="synthetic", policy_fingerprint="f" * 64)
    BASE = dict(
        id="1" * 32, sha256=HASH, engine_id="lab-synthetic-marker", engine_version="1", engine_kind="synthetic",
        policy_fingerprint="f" * 64, verdict="no_detection", scanned_sha256=HASH, scanned_at=10, valid_until=20,
    )  # fmt: skip


def problem(*, now=19, sealed=HASH, **changes):
    record = trust.VerdictRecord(**{**_Record.BASE, **changes})
    return trust.verdict_problem(record, trust.ContentIdentity(sealed), _Record.ENGINE, now)


def test_a_verdict_in_force_has_no_problem():
    assert problem() is None and problem(now=10) is None and problem(now=19) is None


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"now": 20}, AuditReason.VERDICT_STALE),  # valid_until is the first instant at which it is no longer in force
        ({"now": 21}, AuditReason.VERDICT_STALE),
        ({"now": 2**62}, AuditReason.VERDICT_STALE),
        ({"engine_id": "other"}, AuditReason.VERDICT_STALE),
        ({"engine_version": "2"}, AuditReason.VERDICT_STALE),
        ({"engine_version": "1 "}, AuditReason.VERDICT_STALE),  # exact equality, not a normalised or an ordered comparison
        ({"engine_kind": "other"}, AuditReason.VERDICT_STALE),
        ({"policy_fingerprint": "e" * 64}, AuditReason.VERDICT_STALE),
        ({"sha256": "b" * 64, "scanned_sha256": "b" * 64}, AuditReason.VERDICT_NOT_APPLICABLE),  # a verdict for other bytes
        ({"scanned_sha256": "b" * 64}, AuditReason.VERDICT_NOT_APPLICABLE),  # a scanner that looked at other bytes
        ({"verdict": "detection"}, AuditReason.VERDICT_NOT_APPLICABLE),
        ({"verdict": "clean"}, AuditReason.VERDICT_NOT_APPLICABLE),
        ({"verdict": "NO_DETECTION"}, AuditReason.VERDICT_NOT_APPLICABLE),
        ({"sealed": "b" * 64}, AuditReason.VERDICT_NOT_APPLICABLE),  # the verdict is not for this delivery's H
    ],
)
def test_a_verdict_that_is_not_in_force_says_why(changes, expected):
    assert problem(**changes) is expected


def test_a_delivery_with_no_verdict_has_a_verdict_that_does_not_apply():
    assert trust.verdict_problem(None, trust.ContentIdentity(HASH), _Record.ENGINE, 19) is AuditReason.VERDICT_NOT_APPLICABLE


def test_not_applicable_is_reported_before_stale_when_both_are_true():
    assert problem(now=99, verdict="detection") is AuditReason.VERDICT_NOT_APPLICABLE
    assert problem(now=99, engine_version="2", sha256="b" * 64, scanned_sha256="b" * 64) is AuditReason.VERDICT_NOT_APPLICABLE


@pytest.mark.parametrize("bad_now", [True, 19.0, "19", None])
def test_the_instant_must_be_an_integer_of_microseconds(bad_now):
    with pytest.raises(TypeError, match="now_micros"):
        problem(now=bad_now)


def test_the_sealed_digest_must_be_a_server_computed_identity_not_a_string():
    with pytest.raises(TypeError, match="ContentIdentity"):
        trust.verdict_problem(trust.VerdictRecord(**_Record.BASE), HASH, _Record.ENGINE, 19)


# --- A9: the delivery's vendor ----------------------------------------------------------------------------------------------


def test_a_revoked_vendors_deliveries_can_no_longer_be_accepted(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before = lab.delivery_row(delivery)
    lab.revoke("vendor", at=T0 + timedelta(seconds=30))
    token = at(lab, T0 + timedelta(seconds=60))
    since = len(lab.audit_rows())
    response = lab.accept(delivery, HASH, token=token)
    assert (response.status_code, response.json()) == (409, refusal("engagement_revoked"))
    assert trail(lab, since) == [("delivery.acceptance_refused", "denied", "engagement_revoked")]
    assert lab.audit_rows()[-1]["engine_kind"] is None
    unchanged(lab, delivery, before)
    assert lab.inspect(delivery, token=token).json()["state"] == "SCAN_PASSED"  # the coordinator can still see it


def test_a_revoked_vendors_other_deliveries_are_refused_and_another_vendors_are_not(rig):
    lab = rig.lab
    revoked_vendor, other_vendor = lab.sealed(CLEAN_FILE), lab.sealed(CLEAN_FILE, "dual-1")
    lab.revoke("vendor", at=T0 + timedelta(seconds=30))
    token = at(lab, T0 + timedelta(seconds=60))
    assert lab.accept(revoked_vendor, HASH, token=token).status_code == 409
    assert lab.accept(other_vendor, HASH, token=token).status_code == 200


def test_the_natural_expiry_of_the_vendors_engagement_does_not_block_acceptance(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE, "short-1")  # short-1's engagement ends 100 seconds after T0
    later = T0 + timedelta(seconds=200)
    coordinator_token = at(lab, later)
    vendor_token = lab.token_at("short-1", later)
    assert lab.upload(delivery, b"", token=vendor_token).status_code == 403  # the vendor's own actions have stopped
    assert lab.audit_rows()[-1]["reason"] == "engagement_expired"
    response = lab.accept(delivery, HASH, token=coordinator_token)
    assert response.status_code == 200 and lab.delivery_row(delivery)["state"] == "ACCEPTED"


def test_a_revocation_after_the_acceptance_does_not_undo_it(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    assert lab.accept(delivery, HASH).status_code == 200
    lab.revoke("vendor", at=T0 + timedelta(seconds=30))
    assert lab.delivery_row(delivery)["state"] == "ACCEPTED"


# --- one change, or none ---------------------------------------------------------------------------------------------------------


def test_two_simultaneous_acceptances_make_one_state_change_and_one_event(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    since = len(lab.audit_rows())
    barrier = threading.Barrier(2)

    def go():
        barrier.wait(THREAD_WAIT)
        return lab.accept(delivery, HASH)

    first, second = Background(go), Background(go)
    answers = sorted((first.join().status_code, second.join().status_code))
    assert answers == [200, 409]
    assert sorted(trail(lab, since)) == [("delivery.acceptance_refused", "denied", "state_conflict"), ("delivery.accepted", "allowed", None)]
    row = lab.delivery_row(delivery)
    assert (row["state"], row["accepted_sha256"]) == ("ACCEPTED", HASH)


def test_an_acceptance_and_a_wrong_digest_acceptance_at_once_cannot_both_win(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    barrier = threading.Barrier(2)

    def go(digest):
        barrier.wait(THREAD_WAIT)
        return lab.accept(delivery, digest).status_code

    right, wrong = Background(lambda: go(HASH)), Background(lambda: go(WRONG_DIGESTS["another digest"]))
    assert sorted((right.join(), wrong.join())) == [200, 409]
    assert lab.delivery_row(delivery)["accepted_sha256"] == HASH


def test_a_failing_audit_insert_rolls_the_acceptance_back(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before, events = lab.delivery_row(delivery), len(lab.audit_rows())
    lab.make_audit_inserts_fail()
    generic(lab.accept(delivery, HASH), 500)
    unchanged(lab, delivery, before)
    assert lab.delivery_row(delivery)["accepted_sha256"] is None and len(lab.audit_rows()) == events


def test_a_commit_that_fails_leaves_the_delivery_awaiting_acceptance(rig, monkeypatch):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    before, events = lab.delivery_row(delivery), len(lab.audit_rows())
    monkeypatch.setattr(store, "transaction", transaction_whose_commit_fails)
    generic(lab.accept(delivery, HASH), 500)
    monkeypatch.undo()
    unchanged(lab, delivery, before)
    assert len(lab.audit_rows()) == events
    assert lab.accept(delivery, HASH).status_code == 200  # nothing was lost by the failure


def test_an_inspection_whose_audit_insert_fails_shows_nothing(rig):
    lab = rig.lab
    delivery = lab.sealed(CLEAN_FILE)
    lab.make_audit_inserts_fail()
    response = lab.inspect(delivery)
    generic(response, 500)
    assert HASH not in response.text
