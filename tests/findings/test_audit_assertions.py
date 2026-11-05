"""M3: audit and logging assertions for the four findings (M0 §9, ASVS 16.3.2 and 16.5.3).

The audit trail has to say what actually happened. A denial must not look like a read, a cache reuse must not look like a scan,
a refused promotion must not look like a publication, and a denial of a revoked vendor must name the vendor, the production and
the reason. Where a decision cannot be audited it is not committed: the request fails with the generic 500 and changes nothing,
which is a different thing from a committed denial, and both are shown. Nothing in a response or an audit row may carry a token,
the lab's marker, a raw request value or an internal error. All reference behaviour; synthetic data only.
"""

import json
import sqlite3
from datetime import timedelta

import pytest

from content_boundary_lab import promotion
from content_boundary_lab.scanner import MARKER
from labs.world import ACCEPTED_V1, CLEAN, MARKED, SUBSTITUTED_V2, T0, World, digest

SYSTEM = ("system:content-boundary-lab", "promote")


def events_since(world: World, mark: int) -> list[dict]:
    return world.audit()[mark:]


def accepted(world: World) -> str:
    delivery = world.delivered("alpha_vendor", "alpha", ACCEPTED_V1)
    assert world.seal("alpha_vendor", "alpha", delivery).status == 200
    assert world.accept("alpha_coordinator", "alpha", delivery, digest(ACCEPTED_V1)).status == 200
    return delivery


# --- F-02: a denied read is a denial, never a read ---------------------------------------------------------------------------


def test_a_denied_cross_production_read_records_one_denial_and_no_successful_read(tmp_path):
    world = World(tmp_path)
    mark = len(world.audit())
    refused = world.read_asset("alpha_vendor", "alpha", "bravo")
    [denial] = events_since(world, mark)
    assert refused.status == 404
    assert (denial["action"], denial["outcome"], denial["reason"]) == ("access.denied", "denied", "not_found_or_forbidden")
    assert (denial["actor_subject"], denial["production_id"]) == ("vendor-alpha-1", world.production["alpha"])
    assert (denial["object_type"], denial["object_id"]) == ("asset", world.asset["bravo"])
    assert not [e for e in world.audit() if e["action"] == "asset.read"]  # the bytes were never read, and nothing says they were


def test_a_permitted_read_records_exactly_one_read_of_the_asset_it_returned(tmp_path):
    world = World(tmp_path)
    mark = len(world.audit())
    assert world.read_asset("dual_vendor", "bravo", "bravo").status == 200
    [read] = events_since(world, mark)
    assert (read["action"], read["outcome"], read["reason"]) == ("asset.read", "allowed", None)
    assert (read["actor_subject"], read["production_id"], read["object_id"]) == ("vendor-dual-1", world.production["bravo"], world.asset["bravo"])


# --- F-03: a cache reuse is not a scan --------------------------------------------------------------------------------------


def test_a_cache_reuse_is_recorded_as_a_reuse_and_a_new_scan_as_a_scan(tmp_path):
    world = World(tmp_path)
    first = world.delivered("alpha_vendor", "alpha", CLEAN)
    assert world.seal("alpha_vendor", "alpha", first).status == 200
    second = world.delivered("alpha_vendor", "alpha", CLEAN)
    assert world.seal("alpha_vendor", "alpha", second).status == 200
    last = {d: [e for e in world.audit() if e["object_id"] == d][-1] for d in (first, second)}
    assert (last[first]["action"], last[first]["engine_kind"]) == ("delivery.scan_passed", "synthetic")
    assert (last[second]["action"], last[second]["engine_kind"]) == ("delivery.verdict_reused", "synthetic")
    assert world.scanner.calls == 1  # and the count agrees with the trail: one scan, one reuse


def test_a_declared_checksum_mismatch_is_a_rejection_with_no_scan_event_and_a_detection_is_a_verdict_bearing_rejection(tmp_path):
    world = World(tmp_path)
    clean = world.delivered("alpha_vendor", "alpha", CLEAN)
    world.seal("alpha_vendor", "alpha", clean)
    attack = world.delivered("alpha_vendor", "alpha", MARKED, sha256=digest(CLEAN), size=len(MARKED))
    world.seal("alpha_vendor", "alpha", attack)
    truthful = world.delivered("alpha_vendor", "alpha", MARKED)
    world.seal("alpha_vendor", "alpha", truthful)
    trail = lambda d: [(e["action"], e["reason"], e["engine_kind"]) for e in world.audit() if e["object_id"] == d]  # noqa: E731
    assert trail(attack)[-1] == ("delivery.rejected", "checksum_mismatch", None)  # not about a verdict: no engine is named
    assert not [a for a, _, _ in trail(attack) if a in {"delivery.scan_passed", "delivery.verdict_reused"}]
    assert trail(truthful)[-1] == ("delivery.rejected", "detection", "synthetic")  # about a verdict: the engine is named


# --- F-04: a failed promotion never records a publication -------------------------------------------------------------------


def test_a_refused_promotion_records_the_refusal_and_never_a_publication(tmp_path):
    world = World(tmp_path)
    delivery = accepted(world)
    world.stored_file(delivery).write_bytes(SUBSTITUTED_V2)  # the finding's assumed capability
    baseline = world.trusted_files()
    assert world.promote("alpha", delivery).state == "INTEGRITY_FAILED"
    mine = [(e["action"], e["actor_issuer"], e["actor_subject"], e["reason"]) for e in world.audit() if e["object_id"] == delivery]
    assert mine[-2:] == [
        ("delivery.promotion_started", *SYSTEM, None),
        ("delivery.integrity_failed", *SYSTEM, "sealed_content_changed"),
    ]
    assert not [e for e in world.audit() if e["action"] == "delivery.promoted"]
    assert world.rows("SELECT COUNT(*) AS n FROM assets WHERE delivery_id = ?", delivery)[0]["n"] == 0 and world.trusted_files() == baseline


def test_a_successful_promotion_records_one_publication_and_the_asset_it_made(tmp_path):
    world = World(tmp_path)
    delivery = accepted(world)
    result = world.promote("alpha", delivery)
    published = [e for e in world.audit() if e["action"] == "delivery.promoted"]
    assert result.state == "PROMOTED" and [(e["object_id"], e["actor_subject"]) for e in published] == [(delivery, "promote")]
    assert world.rows("SELECT id FROM assets WHERE delivery_id = ?", delivery) == [{"id": result.asset_id}]


# --- F-06: a revoked user's denials name the user, the production and the reason ---------------------------------------------


def test_a_revoked_vendors_denied_requests_are_recorded_with_who_where_and_why(tmp_path):
    world = World(tmp_path)
    alpha = world.production["alpha"]
    token = world.token("alpha_vendor")
    mark = len(world.audit())
    revoked = world.revoke("alpha_coordinator", "alpha", "alpha_vendor")
    [revocation] = events_since(world, mark)
    assert revoked.status == 200 and (revocation["action"], revocation["actor_subject"], revocation["object_id"]) == (
        "engagement.revoked", "coordinator-alpha-1", world.engagement[("alpha_vendor", "alpha")]
    )  # fmt: skip
    for method, path, options in (
        ("GET", f"/productions/{alpha}/engagement", {}),
        ("POST", f"/productions/{alpha}/deliveries", {"json": {"display_name": "a.png", "declared_media_type": "image/png", "declared_size": 1, "declared_sha256": "a" * 64}}),
    ):
        mark = len(world.audit())
        assert world.call(method, path, token=token, **options).status == 403
        [denial] = events_since(world, mark)  # one event for one request, and it is the denial
        assert (denial["action"], denial["outcome"], denial["reason"]) == ("access.denied", "denied", "engagement_revoked")
        assert (denial["actor_subject"], denial["production_id"], denial["object_id"]) == ("vendor-alpha-1", alpha, None)
    assert world.rows("SELECT COUNT(*) AS n FROM deliveries")[0]["n"] == 0


def test_an_engagement_that_has_ended_is_recorded_as_ended_and_a_missing_token_as_an_unauthenticated_denial(tmp_path):
    world = World(tmp_path)
    path = f"/productions/{world.production['alpha']}/engagement"
    token = world.token("short_vendor")
    world.clock.set(T0 + timedelta(seconds=300))
    mark = len(world.audit())
    assert world.call("GET", path, token=token).status == 403
    [ended] = events_since(world, mark)
    assert (ended["reason"], ended["actor_subject"]) == ("engagement_expired", "vendor-short-1")
    mark = len(world.audit())
    assert world.call("GET", path).status == 401
    [anonymous] = events_since(world, mark)
    assert (anonymous["action"], anonymous["reason"], anonymous["actor_subject"], anonymous["production_id"]) == ("access.denied", "invalid_credentials", None, None)


# --- committed decisions and failures that cannot be audited ----------------------------------------------------------------

GENERIC_500 = {"detail": "Internal server error"}


def test_a_read_that_cannot_be_audited_returns_no_bytes_and_the_generic_500(tmp_path):
    world = World(tmp_path)
    world.break_audit()
    permitted, refused = world.read_asset("alpha_vendor", "alpha", "alpha"), world.read_asset("alpha_vendor", "alpha", "bravo")
    assert (permitted.status, permitted.json()) == (500, GENERIC_500) and (refused.status, refused.json()) == (500, GENERIC_500)
    assert world.audit() == []  # and nothing was recorded, in either case


def test_a_revocation_that_cannot_be_audited_is_not_committed(tmp_path):
    world = World(tmp_path)
    world.break_audit()
    assert world.revoke("alpha_coordinator", "alpha", "alpha_vendor").status == 500
    assert world.rows("SELECT revoked_at FROM engagements WHERE id = ?", world.engagement[("alpha_vendor", "alpha")]) == [{"revoked_at": None}]


def test_a_seal_that_cannot_be_audited_leaves_the_delivery_awaiting_its_seal_and_the_scanner_unasked(tmp_path):
    world = World(tmp_path)
    delivery = world.delivered("alpha_vendor", "alpha", CLEAN)
    world.break_audit()
    assert world.seal("alpha_vendor", "alpha", delivery).status == 500
    assert world.delivery_row(delivery)["state"] == "UPLOADED" and world.scanner.calls == 0


def test_a_promotion_whose_publication_cannot_be_audited_publishes_nothing_and_stays_promoting(tmp_path):
    world = World(tmp_path)
    delivery = accepted(world)
    started = promotion.begin(world.production["alpha"], delivery, clock=world.clock, database_path=world.database)
    written = promotion.stage(started, quarantine_root=world.quarantine, asset_root=world.trusted)
    world.break_audit()  # the intent was recorded; the publication cannot be
    with pytest.raises(sqlite3.OperationalError, match="database or disk is full"):  # the audit insert's own failure, not another
        promotion.publish(started, written, clock=world.clock, database_path=world.database, asset_root=world.trusted)
    assert world.delivery_row(delivery)["state"] == "PROMOTING"
    assert world.rows("SELECT COUNT(*) AS n FROM assets WHERE delivery_id = ?", delivery)[0]["n"] == 0
    assert not (world.trusted / started.asset_id).exists()  # nothing at the asset's key, and the staged file is gone
    assert not [e for e in world.audit() if e["action"] == "delivery.promoted"]


# --- what must not appear in a response or an audit row ----------------------------------------------------------------------


def test_no_token_marker_request_value_path_or_internal_error_appears_in_any_response_or_audit_row(tmp_path, caplog):
    world = World(tmp_path)
    caplog.set_level("DEBUG")
    # a wide run: successes, denials of every kind, a detection, a promotion refused, and requests that cannot be audited
    clean = world.delivered("alpha_vendor", "alpha", CLEAN)
    world.seal("alpha_vendor", "alpha", clean)
    attack = world.delivered("alpha_vendor", "alpha", MARKED, sha256=digest(CLEAN), size=len(MARKED))
    world.seal("alpha_vendor", "alpha", attack)
    detected = world.delivered("alpha_vendor", "alpha", MARKED)
    world.seal("alpha_vendor", "alpha", detected)
    swapped = accepted(world)
    world.stored_file(swapped).write_bytes(SUBSTITUTED_V2)
    world.promote("alpha", swapped)
    world.read_asset("alpha_vendor", "alpha", "alpha")
    world.read_asset("alpha_vendor", "alpha", "bravo")
    world.call("GET", world.asset_path("alpha", "alpha"), token="not.a.token")
    world.call("POST", f"/productions/{world.production['alpha']}/deliveries", "alpha_vendor", json={"display_name": "SECRET-NAME.png", "declared_size": -1})
    world.revoke("alpha_coordinator", "alpha", "alpha_vendor")
    world.read_asset("alpha_vendor", "alpha", "alpha")
    (tmp_path / "errors").mkdir()
    errors = World(tmp_path / "errors")  # a second world whose audit is broken
    errors.break_audit()
    errors.read_asset("alpha_vendor", "alpha", "alpha")
    errors.revoke("alpha_coordinator", "alpha", "alpha_vendor")

    replies = [reply for w in (world, errors) for reply in w.replies]
    responses = "\n".join(reply.body.decode("utf-8", "replace") + json.dumps(reply.headers) for reply in replies)
    audit = json.dumps(world.audit() + errors.audit())
    for seen in ("Not authenticated", "Not found", "Forbidden", "Internal server error", "detection", "checksum_mismatch"):
        assert seen in responses, seen  # the scan is looking at the responses of every kind it is meant to
    for seen in ("access.denied", "delivery.rejected", "delivery.integrity_failed", "engagement.revoked", "asset.read"):
        assert seen in audit, seen  # and at an audit trail that holds the events it is meant to
    assert len(replies) >= 20 and len(world.tokens) >= 10  # the run made about two dozen requests; the scan saw all of them
    secrets = {
        "a token": [t for w in (world, errors) for t in w.tokens],
        "a token's signature": [t.split(".")[2] for w in (world, errors) for t in w.tokens],
        "a token's payload": [t.split(".")[1] for w in (world, errors) for t in w.tokens],
        "the lab marker": [MARKER.decode()],
        "a path": [str(tmp_path), "/private/", "/var/folders"],
        "an internal error": ["Traceback", "sqlite3", "OperationalError", "IntegrityError", "SQLITE_", "ContentChanged", "AssetStorageError"],
        "a request value": ["SECRET-NAME.png", "shot-030.png"],
    }
    for what, needles in secrets.items():
        for needle in needles:
            assert needle not in responses, f"{what} appears in a response"
            assert needle not in audit, f"{what} appears in an audit row"
    log = caplog.text
    assert not [t for w in (world, errors) for t in w.tokens if t in log] and MARKER.decode() not in log  # nor in what is logged
