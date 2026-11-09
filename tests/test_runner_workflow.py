"""M1M: the whole workflow through the composed application, as the lab's users and its operator run it.

A vendor declares a delivery and uploads into quarantine; the server seals and scans it; the coordinator inspects it and
accepts the specific digest H; the system job promotes it; an authorised caller downloads the exact accepted bytes. Every
step is a request to the application the runner composed, with a token the development issuer signed, on the real clock,
or one of the runner's own commands. The negative cases are the ones the design promises: a revoked engagement, another
production's asset, content that trips the scanner, a checksum that does not match, and bytes swapped after acceptance.
Synthetic data only.
"""

import os
from hashlib import sha256

import pytest
from support.http_lab import CLEAN_FILE
from support.processes import run_runner
from support.workflow import World

from content_boundary_lab.scanner import MARKER

H = sha256(CLEAN_FILE).hexdigest()
ISSUER = "https://dev-issuer.lab.example"
VENDOR = (ISSUER, "dev-vendor-a")
COORDINATOR = (ISSUER, "dev-coordinator-a")
SYSTEM_PROMOTE = ("system:content-boundary-lab", "promote")


@pytest.fixture
def world(tmp_path) -> World:
    return World(tmp_path)


def files(world: World) -> list[str]:
    """Every regular file under the trusted root: staged names and published assets, relative."""
    return sorted(str(p.relative_to(world.trusted)) for p in world.trusted.rglob("*") if p.is_file())


# --- the whole path ----------------------------------------------------------------------------------------------------------


def test_a_vendors_bytes_reach_an_authorised_caller_exactly_as_the_coordinator_accepted_them(world):
    delivery = world.declare("vendor_a", world.a, CLEAN_FILE)
    assert world.upload("vendor_a", world.a, delivery, CLEAN_FILE).status_code == 201
    assert world.quarantine.joinpath(world.delivery(delivery)["storage_key"]).read_bytes() == CLEAN_FILE

    sealed = world.seal("vendor_a", world.a, delivery)
    assert sealed.status_code == 200
    assert sealed.json()["sealed_sha256"] == H and sealed.json()["engine"]["kind"] == "synthetic"

    inspected = world.inspect("coordinator_a", world.a, delivery)
    assert inspected.status_code == 200 and inspected.json()["state"] == "SCAN_PASSED"
    assert world.accept("coordinator_a", world.a, delivery, H).status_code == 200
    assert files(world) == []  # accepted is not promoted: nothing is trusted yet

    promoted = world.promote(world.a, delivery)
    assert promoted.code == 0 and promoted.result["state"] == "PROMOTED"
    asset = promoted.result["asset_id"]
    assert files(world) == [asset]

    for reader in ("vendor_a", "coordinator_a"):
        got = world.download(reader, world.a, asset)
        assert got.status_code == 200 and got.content == CLEAN_FILE and sha256(got.content).hexdigest() == H
    row = world.delivery(delivery)
    [stored] = world.rows("SELECT * FROM assets WHERE id = ?", asset)
    assert (row["state"], row["accepted_sha256"], row["asset_id"]) == ("PROMOTED", H, asset)
    assert (stored["delivery_id"], stored["sha256"], stored["production_id"]) == (delivery, H, world.a)


def test_the_audit_trail_names_who_did_each_step_and_the_system_job_by_its_own_name(world):
    delivery = world.accepted(CLEAN_FILE)
    world.promote(world.a, delivery)
    assert [(action, issuer, subject) for action, issuer, subject, *_ in world.events(delivery)] == [
        ("delivery.initiated", *VENDOR),
        ("delivery.upload_started", *VENDOR),
        ("delivery.uploaded", *VENDOR),
        ("delivery.seal_started", *VENDOR),
        ("delivery.scan_passed", *VENDOR),
        ("delivery.accepted", *COORDINATOR),
        ("delivery.promotion_started", *SYSTEM_PROMOTE),
        ("delivery.promoted", *SYSTEM_PROMOTE),
    ]
    kinds = {row["action"]: row["engine_kind"] for row in world.audit() if row["object_id"] == delivery}
    assert kinds["delivery.scan_passed"] == kinds["delivery.accepted"] == "synthetic"  # a verdict-bearing event names its engine


def test_promoting_again_returns_the_same_asset_and_changes_nothing(world):
    delivery = world.accepted(CLEAN_FILE)
    first = world.promote(world.a, delivery)
    trail = world.audit()
    second = world.promote(world.a, delivery)
    assert second.code == 0 and second.result == first.result
    assert world.audit() == trail and files(world) == [first.result["asset_id"]]


def test_the_same_workflow_as_separate_programs(world):
    """`promote` and `reconcile` run as `python -I -m content_boundary_lab.runner`, as an operator runs them."""
    delivery = world.accepted(CLEAN_FILE)
    done = run_runner("promote", *world.storage, "--production-id", world.a, "--delivery-id", delivery)
    assert done.returncode == 0, done.stderr
    assert '"state": "PROMOTED"' in done.stdout
    assert world.download("vendor_a", world.a, world.delivery(delivery)["asset_id"]).content == CLEAN_FILE
    done = run_runner("reconcile", *world.storage, "--min-age-seconds", "0")
    assert done.returncode == 0, done.stderr


# --- who may do what -----------------------------------------------------------------------------------------------------------


def test_nothing_is_served_without_a_token_from_the_trusted_issuer(world):
    delivery = world.accepted(CLEAN_FILE)
    asset = world.promote(world.a, delivery).result["asset_id"]
    assert world.download(None, world.a, asset).status_code == 401
    other = world.dev.parent / "other" / ".dev"  # another setup: the same issuer text, a different key
    other.parent.mkdir()
    world.tool.setup(other)
    token = world.tool.mint(other, world.subjects["vendor_a"], 600)
    assert world.client.get(f"/productions/{world.a}/assets/{asset}", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_another_productions_vendor_cannot_tell_a_real_asset_from_one_that_does_not_exist(world):
    asset = world.promote(world.a, world.accepted(CLEAN_FILE)).result["asset_id"]
    nothing = "0" * 32
    for production in (world.a, world.b):
        real, absent = world.download("vendor_b", production, asset), world.download("vendor_b", production, nothing)
        assert (real.status_code, real.content) == (absent.status_code, absent.content), production
        assert real.status_code in (403, 404) and CLEAN_FILE[:20] not in real.content
    assert world.download("vendor_b", world.b, asset).status_code != 200


def test_another_productions_coordinator_cannot_accept_or_inspect_a_delivery(world):
    delivery = world.sealed(CLEAN_FILE)
    for production in (world.a, world.b):
        assert world.accept("coordinator_b", production, delivery, H).status_code in (403, 404)
        assert world.inspect("coordinator_b", production, delivery).status_code in (403, 404)
    assert world.delivery(delivery)["state"] == "SCAN_PASSED"


def test_a_vendor_cannot_accept_its_own_delivery(world):
    delivery = world.sealed(CLEAN_FILE)
    assert world.accept("vendor_a", world.a, delivery, H).status_code == 403
    assert world.delivery(delivery)["state"] == "SCAN_PASSED"


def test_a_revoked_engagement_loses_the_download_on_the_next_request_and_the_coordinator_keeps_it(world):
    asset = world.promote(world.a, world.accepted(CLEAN_FILE)).result["asset_id"]
    assert world.download("vendor_a", world.a, asset).status_code == 200
    assert world.revoke("coordinator_a", world.a, "vendor_a").status_code == 200
    refused = world.download("vendor_a", world.a, asset)
    assert refused.status_code == 403 and CLEAN_FILE[:20] not in refused.content
    assert world.download("coordinator_a", world.a, asset).status_code == 200


def test_a_delivery_of_a_vendor_revoked_before_acceptance_cannot_be_accepted_or_promoted(world):
    delivery = world.sealed(CLEAN_FILE)
    assert world.revoke("coordinator_a", world.a, "vendor_a").status_code == 200
    refused = world.accept("coordinator_a", world.a, delivery, H)
    assert refused.status_code == 409 and refused.json()["reason"] == "engagement_revoked"
    promoted = world.promote(world.a, delivery)
    assert promoted.code == 3 and "state_conflict" in promoted.err
    assert world.delivery(delivery)["state"] == "SCAN_PASSED" and files(world) == []


# --- what the gate refuses ------------------------------------------------------------------------------------------------------


def test_content_that_trips_the_scanner_is_rejected_and_can_never_be_accepted_or_promoted(world):
    bad = CLEAN_FILE + MARKER
    delivery = world.declare("vendor_a", world.a, bad)
    assert world.upload("vendor_a", world.a, delivery, bad).status_code == 201
    sealed = world.seal("vendor_a", world.a, delivery)
    assert sealed.status_code == 422 and sealed.json()["reason"] == "detection" and sealed.json()["engine"]["kind"] == "synthetic"
    assert world.delivery(delivery)["state"] == "REJECTED"
    assert world.accept("coordinator_a", world.a, delivery, sha256(bad).hexdigest()).status_code == 409
    assert world.promote(world.a, delivery).code == 3
    assert files(world) == [] and world.delivery(delivery)["state"] == "REJECTED"


def test_a_declared_checksum_that_does_not_match_the_bytes_is_rejected_before_any_scan(world):
    delivery = world.declare("vendor_a", world.a, CLEAN_FILE, declared_sha256="d" * 64)
    assert world.upload("vendor_a", world.a, delivery, CLEAN_FILE).status_code == 201
    sealed = world.seal("vendor_a", world.a, delivery)
    assert sealed.status_code == 422 and sealed.json()["reason"] == "checksum_mismatch"
    assert world.delivery(delivery)["state"] == "REJECTED"
    assert world.rows("SELECT * FROM verdicts") == []  # the scanner was never asked
    assert world.accept("coordinator_a", world.a, delivery, H).status_code == 409
    assert world.promote(world.a, delivery).code == 3 and files(world) == []


def test_the_coordinator_must_name_the_digest_the_server_computed(world):
    delivery = world.sealed(CLEAN_FILE)
    refused = world.accept("coordinator_a", world.a, delivery, "e" * 64)
    assert refused.status_code == 409 and refused.json()["reason"] == "digest_mismatch"
    assert world.delivery(delivery)["state"] == "SCAN_PASSED"


def test_bytes_swapped_in_quarantine_after_acceptance_are_never_promoted(world):
    delivery = world.accepted(CLEAN_FILE)
    swapped = CLEAN_FILE.replace(b"synthetic", b"tampered!")
    assert len(swapped) == len(CLEAN_FILE) and swapped != CLEAN_FILE
    stored = world.stored(delivery)
    stored.write_bytes(swapped)  # the assumed capability of F-04: something else can write quarantine
    promoted = world.promote(world.a, delivery)
    assert promoted.code == 3 and promoted.result["state"] == "INTEGRITY_FAILED" and promoted.result["asset_id"] is None
    assert files(world) == []  # nothing under the trusted root, and no staging file left behind
    assert world.delivery(delivery)["state"] == "INTEGRITY_FAILED"
    assert world.rows("SELECT * FROM assets") == []
    assert ("delivery.integrity_failed", *SYSTEM_PROMOTE, "denied", "sealed_content_changed") in world.events(delivery)
    assert world.delivery(delivery)["accepted_sha256"] == H  # the record of what was accepted is untouched
    again = world.promote(world.a, delivery)
    assert again.code == 3 and files(world) == []  # and a repeat does not publish it either


def test_a_file_replaced_by_a_link_after_acceptance_is_never_promoted(world):
    delivery = world.accepted(CLEAN_FILE)
    stored = world.stored(delivery)
    elsewhere = world.quarantine.parent / "elsewhere.bin"
    elsewhere.write_bytes(CLEAN_FILE)  # the same bytes, so only the link can be what stops it
    stored.unlink()
    stored.symlink_to(elsewhere)
    promoted = world.promote(world.a, delivery)
    assert promoted.code == 3 and promoted.result["state"] == "INTEGRITY_FAILED" and files(world) == []


def test_a_delivery_that_is_not_accepted_or_not_of_this_production_is_not_promoted(world):
    sealed = world.sealed(CLEAN_FILE)
    assert world.promote(world.a, sealed).code == 3
    accepted = world.accepted(CLEAN_FILE)
    assert world.promote(world.b, accepted).code == 3  # a delivery of another production is the same refusal as a missing one
    assert world.promote(world.a, "not-an-id").code == 3
    assert world.delivery(accepted)["state"] == "ACCEPTED" and files(world) == []


# --- IR-05: the gate looks at the signature; the name is the vendor's -------------------------------------------------------------
# A file that starts with the PNG signature is allowed whatever it is called. These two tests pin what the application does
# about that, and what it does not: they are evidence for the written risk (docs/threat-model.md TM-39), not a new control.

POLYGLOT = b"\x89PNG\r\n\x1a\n" + b"\n<p>synthetic text after a PNG signature; nothing executable</p>\n"


def test_a_png_signature_under_an_html_name_is_still_served_only_as_an_attachment_of_unknown_type(world):
    """No header here lets a browser interpret the bytes: an octet-stream that must not be sniffed and is offered for saving."""
    delivery = world.sealed(POLYGLOT, display_name="shot-031.html", declared_media_type="image/png")
    assert world.accept("coordinator_a", world.a, delivery, sha256(POLYGLOT).hexdigest()).status_code == 200
    asset = world.promote(world.a, delivery).result["asset_id"]
    got = world.download("vendor_a", world.a, asset)
    assert got.status_code == 200 and got.content == POLYGLOT
    assert got.headers["content-type"] == "application/octet-stream"  # not text/html, and not image/png either
    assert got.headers["x-content-type-options"] == "nosniff"
    assert got.headers["cache-control"] == "no-store"
    assert got.headers["content-disposition"] == "attachment; filename=\"shot-031.html\"; filename*=UTF-8''shot-031.html"


def test_the_coordinator_is_not_shown_the_name_or_the_declared_type_when_deciding_to_accept(world):
    """The remaining risk, stated as a fact: the extension the vendor chose is what the recipient's desktop will use, and the
    decision to accept is made on the digest and the verdict, without the name. The application does not compare the two."""
    delivery = world.sealed(POLYGLOT, display_name="shot-031.html", declared_media_type="image/png")
    view = world.inspect("coordinator_a", world.a, delivery).json()
    assert view["state"] == "SCAN_PASSED"
    assert not {"display_name", "declared_media_type", "media_type", "filename"} & set(view)
    assert world.delivery(delivery)["display_name"] == "shot-031.html"  # kept as declared; only its download spelling is cleaned


def test_the_composed_application_serves_no_documentation_and_only_the_approved_routes(world):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert world.client.get(path).status_code == 404
    assert os.path.isdir(world.trusted) and world.host == "127.0.0.1"
