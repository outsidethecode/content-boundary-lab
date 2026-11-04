"""POST /productions/{id}/deliveries: a vendor declares a delivery (M0 §2 step 3). Real HTTP behaviour, synthetic data.

The declaration is metadata: a display name, a declared size, a declared SHA-256 and a media type. It makes a row in
state INITIATED owned by the caller and creates no file. Nothing in the body can choose the production, the owner, the
state or a storage key, and nothing in it is a path.
"""

import json
import re
import sqlite3
from datetime import timedelta

import pytest
from support import token_issuer as tokens
from support.http_lab import DELIVERY, SHORT_END, T0, UPLOAD_LIMIT, assert_released, generic, lab, make_lab, spy

HEX32 = re.compile(r"[0-9a-f]{32}")


def trail(lab, since=0):
    return [(row["action"], row["outcome"], row["reason"]) for row in lab.audit_rows()[since:]]


def subject_id(lab, subject):
    raw = sqlite3.connect(lab.path)
    try:
        return raw.execute("SELECT id FROM subjects WHERE issuer = ? AND subject = ?", (tokens.ISSUER, subject)).fetchone()[0]
    finally:
        raw.close()


def post_raw(lab, content, subject="vendor-1"):
    return lab.send("POST", lab.deliveries_path(), subject=subject, content=content, headers={"Content-Type": "application/json"})


# --- the success path ---------------------------------------------------------------------------------------------


def test_a_vendor_declares_a_delivery_in_its_own_production(lab):
    response = lab.initiate("vendor-1")
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert set(body) == {"delivery_id", "state"} and body["state"] == "INITIATED" and HEX32.fullmatch(body["delivery_id"])
    stored = lab.delivery_row(body["delivery_id"])
    assert stored["state"] == "INITIATED" and stored["production_id"] == lab.alpha
    assert stored["owner_subject_id"] == subject_id(lab, "vendor-1")
    assert (stored["display_name"], stored["declared_size"], stored["declared_sha256"], stored["declared_media_type"]) == (
        DELIVERY["display_name"], DELIVERY["declared_size"], DELIVERY["declared_sha256"], DELIVERY["declared_media_type"],
    )  # fmt: skip
    assert (stored["received_size"], stored["received_sha256"], stored["uploaded_at"]) == (None, None, None)
    assert HEX32.fullmatch(stored["storage_key"]) and stored["storage_key"] != stored["id"]
    assert stored["storage_key"] not in response.text  # the vendor never learns where its bytes will go


def test_the_declaration_is_one_audit_event_about_the_delivery(lab):
    delivery_id = lab.new_delivery("vendor-1")
    (event,) = lab.audit_rows()
    assert {key: event[key] for key in ("action", "outcome", "actor_issuer", "actor_subject", "production_id", "object_type", "object_id", "reason")} == {
        "action": "delivery.initiated", "outcome": "allowed", "actor_issuer": tokens.ISSUER, "actor_subject": "vendor-1",
        "production_id": lab.alpha, "object_type": "delivery", "object_id": delivery_id, "reason": None,
    }  # fmt: skip
    assert event["at"] == lab.delivery_row(delivery_id)["created_at"]  # one instant for the whole request


def test_a_declaration_creates_no_file_anywhere(lab, tmp_path):
    before = {str(path) for path in tmp_path.rglob("*")}
    lab.new_delivery(display_name="shot-010.mov")
    assert {str(path) for path in tmp_path.rglob("*")} == before  # the display name is metadata: it names no file
    assert lab.quarantine_names() == [] and lab.incoming_names() == []


def test_identical_declarations_are_separate_deliveries_because_a_declared_hash_is_not_an_identity(lab):
    first, second = lab.new_delivery(), lab.new_delivery()
    rows = lab.delivery_rows()
    assert first != second and len(rows) == 2
    assert rows[0]["storage_key"] != rows[1]["storage_key"] and rows[0]["declared_sha256"] == rows[1]["declared_sha256"]


@pytest.mark.parametrize(
    "fields",
    [
        {"declared_size": 0},
        {"declared_size": UPLOAD_LIMIT},
        {"display_name": "x"},
        {"display_name": "n" * 200},
        {"display_name": "ショット-010 v2.mov"},
        {"display_name": "a..b"},
        {"display_name": "..hidden"},
        {"declared_media_type": "application/octet-stream"},
        {"declared_media_type": "video/x-matroska"},
        {"declared_media_type": "application/vnd.api+json"},
    ],
    ids=repr,
)
def test_values_at_the_edges_of_what_is_valid_are_accepted_as_they_are(lab, fields):
    delivery_id = lab.new_delivery(**fields)
    stored = lab.delivery_row(delivery_id)
    assert all(stored[key] == value for key, value in fields.items())  # kept exactly: never trimmed, folded or normalised


# --- who may declare, and where ---------------------------------------------------------------------------------------

DENIED = {
    "a coordinator": ("coordinator-1", "alpha", "role_not_permitted"),
    "a vendor with no engagement in the production": ("vendor-1", "bravo", "no_engagement"),
    "a vendor of another production": ("vendor-2", "alpha", "no_engagement"),
    "a subject with no engagement at all": ("outsider-1", "alpha", "no_engagement"),
    "a subject unknown to the store": ("nobody-at-all", "alpha", "no_engagement"),
    "an upper-case production id": ("vendor-1", "ALPHA-UPPER", "invalid_identifier"),
    "a short production id": ("vendor-1", "ALPHA-SHORT", "invalid_identifier"),
    "an injected production id": ("vendor-1", "ALPHA-INJECTED", "invalid_identifier"),
    "a production that does not exist": ("vendor-1", "f" * 32, "no_engagement"),
}


@pytest.mark.parametrize(("subject", "production", "reason"), DENIED.values(), ids=list(DENIED))
def test_only_a_vendor_engaged_in_the_production_in_the_url_may_declare(lab, subject, production, reason):
    response = lab.initiate(subject, lab.production(production))
    generic(response, 403)
    assert [row["reason"] for row in lab.audit_rows()] == [reason] and lab.audit_rows()[0]["action"] == "access.denied"
    assert lab.delivery_rows() == [] and lab.quarantine_names() == []


def test_claims_in_the_token_do_not_grant_anything(lab):
    response = lab.initiate("vendor-2", lab.alpha, role="coordinator", productions=[lab.alpha, lab.bravo], scope="deliveries:write")
    generic(response, 403)
    assert lab.delivery_rows() == []


def test_a_caller_engaged_in_both_productions_declares_in_the_production_of_the_url_only(lab):
    first = lab.new_delivery("dual-1", lab.alpha)
    second = lab.new_delivery("dual-1", lab.bravo)
    assert lab.delivery_row(first)["production_id"] == lab.alpha
    assert lab.delivery_row(second)["production_id"] == lab.bravo


@pytest.mark.parametrize("credentials", ["none", "garbage"])
def test_an_unauthenticated_request_is_a_401_that_declares_nothing(lab, credentials):
    response = lab.initiate(None) if credentials == "none" else lab.initiate(None, token="not-a-token")
    generic(response, 401)
    assert response.headers["www-authenticate"] == "Bearer"
    assert trail(lab) == [("access.denied", "denied", "invalid_credentials")] and lab.delivery_rows() == []


def test_a_revoked_engagement_declares_nothing_even_with_a_token_that_is_still_valid(lab):
    token = lab.token("vendor-1")
    lab.revoke("vendor", at=T0 + timedelta(seconds=30))
    lab.clock.moment = T0 + timedelta(seconds=60)
    generic(lab.initiate(None, token=token), 403)
    assert trail(lab) == [("access.denied", "denied", "engagement_revoked")] and lab.delivery_rows() == []


def test_an_engagement_that_has_ended_declares_nothing_from_the_instant_it_ends(lab):
    lab.clock.moment = SHORT_END - timedelta(microseconds=1)
    assert lab.initiate("short-1").status_code == 201
    lab.clock.moment = SHORT_END
    generic(lab.initiate("short-1"), 403)
    assert trail(lab)[-1] == ("access.denied", "denied", "engagement_expired") and len(lab.delivery_rows()) == 1


# --- what the body may contain -----------------------------------------------------------------------------------------

BAD_FIELDS = {
    "empty display name": ("display_name", ""),
    "display name over 200 characters": ("display_name", "x" * 201),
    "display name that climbs": ("display_name", "../../trusted/evil.mov"),
    "display name with a slash": ("display_name", "a/b.mov"),
    "display name with a backslash": ("display_name", "a\\b.mov"),
    "display name that is a dot": ("display_name", "."),
    "display name that is two dots": ("display_name", ".."),
    "display name with a tab": ("display_name", "tab\there"),
    "display name with a NUL": ("display_name", "nul\x00byte"),
    "display name with a newline": ("display_name", "line\nbreak"),
    "display name with a bidirectional override": ("display_name", "gnp.‮mov"),
    "display name that is a number": ("display_name", 5),
    "display name that is null": ("display_name", None),
    "display name that is a list": ("display_name", ["a"]),
    "negative size": ("declared_size", -1),
    "size as text": ("declared_size", "100"),
    "size as a fraction": ("declared_size", 1.5),
    "size as a float that is whole": ("declared_size", 100.0),
    "size as a boolean": ("declared_size", True),
    "size as null": ("declared_size", None),
    "size past SQLite's integers": ("declared_size", 2**63),
    "size past the upload limit": ("declared_size", UPLOAD_LIMIT + 1),
    "size beyond any machine": ("declared_size", 10**30),
    "hash in capitals": ("declared_sha256", "A" * 64),
    "hash one character short": ("declared_sha256", "c" * 63),
    "hash one character long": ("declared_sha256", "c" * 65),
    "hash that is not hexadecimal": ("declared_sha256", "g" * 64),
    "hash with a trailing newline": ("declared_sha256", "c" * 64 + "\n"),
    "empty hash": ("declared_sha256", ""),
    "hash as a number": ("declared_sha256", 5),
    "empty media type": ("declared_media_type", ""),
    "media type without a subtype": ("declared_media_type", "video"),
    "media type with an empty subtype": ("declared_media_type", "video/"),
    "media type with an empty type": ("declared_media_type", "/mp4"),
    "media type with a space": ("declared_media_type", "a b/c"),
    "media type with parameters": ("declared_media_type", "video/mp4; codecs=x"),
    "media type with a newline": ("declared_media_type", "video/mp4\n"),
    "media type over any sensible length": ("declared_media_type", "x/" + "y" * 300),
    "media type as null": ("declared_media_type", None),
}


@pytest.mark.parametrize(("field", "value"), BAD_FIELDS.values(), ids=list(BAD_FIELDS))
def test_an_invalid_member_is_a_400_that_names_only_the_member_and_declares_nothing(lab, field, value):
    response = lab.initiate("vendor-1", fields={field: value})
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid request", "field": field}
    assert trail(lab) == [("delivery.request_rejected", "denied", "invalid_request")]
    assert lab.delivery_rows() == [] and lab.quarantine_names() == []
    (event,) = lab.audit_rows()
    assert event["object_id"] is None and event["production_id"] == lab.alpha  # the rejected text is recorded nowhere


def test_a_display_name_with_a_lone_surrogate_is_refused_as_the_display_name(lab):
    escaped = b'{"display_name":"lone\\ud800surrogate","declared_size":1,"declared_sha256":"' + b"c" * 64 + b'","declared_media_type":"a/b"}'
    response = post_raw(lab, escaped)
    assert response.status_code == 400 and response.json() == {"detail": "Invalid request", "field": "display_name"}
    assert lab.delivery_rows() == []


ALL = {"display_name": "a.mov", "declared_size": 1, "declared_sha256": "c" * 64, "declared_media_type": "a/b"}
BAD_BODIES = {
    "nothing": b"",
    "not JSON": b"not json",
    "an array": b"[]",
    "a string": b'"x"',
    "null": b"null",
    "an empty object": b"{}",
    "a member missing: display_name": json.dumps({k: v for k, v in ALL.items() if k != "display_name"}).encode(),
    "a member missing: declared_size": json.dumps({k: v for k, v in ALL.items() if k != "declared_size"}).encode(),
    "a member missing: declared_sha256": json.dumps({k: v for k, v in ALL.items() if k != "declared_sha256"}).encode(),
    "a member missing: declared_media_type": json.dumps({k: v for k, v in ALL.items() if k != "declared_media_type"}).encode(),
    "an extra member: production_id": json.dumps({**ALL, "production_id": "f" * 32}).encode(),
    "an extra member: owner": json.dumps({**ALL, "owner": "vendor-2"}).encode(),
    "an extra member: state": json.dumps({**ALL, "state": "SCAN_PASSED"}).encode(),
    "an extra member: storage_key": json.dumps({**ALL, "storage_key": "../../trusted/x"}).encode(),
    "an extra member: id": json.dumps({**ALL, "id": "f" * 32}).encode(),
    "an extra member: received_sha256": json.dumps({**ALL, "received_sha256": "c" * 64}).encode(),
    "a repeated member": b'{"display_name":"a","display_name":"b","declared_size":1,"declared_sha256":"' + b"c" * 64 + b'","declared_media_type":"a/b"}',
    "NaN": b'{"display_name":"a","declared_size":NaN,"declared_sha256":"' + b"c" * 64 + b'","declared_media_type":"a/b"}',
    "bytes that are not UTF-8": b"\xff\xfe\x00",
    "nesting that is too deep": b"[" * 2000 + b"]" * 2000,
}


@pytest.mark.parametrize("content", BAD_BODIES.values(), ids=list(BAD_BODIES))
def test_a_body_that_is_not_exactly_the_four_members_is_a_400_and_nothing_in_it_is_acted_on(lab, content):
    response = post_raw(lab, content)
    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid request", "field": "body"}
    assert trail(lab) == [("delivery.request_rejected", "denied", "invalid_request")]
    assert lab.delivery_rows() == [] and lab.quarantine_names() == []


def test_a_body_over_the_small_limit_is_a_413_only_after_the_caller_is_known(lab):
    big = json.dumps({**ALL, "display_name": "x" * 6000}).encode()
    response = post_raw(lab, big)
    assert response.status_code == 413 and response.json() == {"detail": "Payload too large"}
    assert trail(lab) == [("delivery.request_rejected", "denied", "payload_too_large")] and lab.delivery_rows() == []
    unauthenticated = lab.send("POST", lab.deliveries_path(), content=big)
    generic(unauthenticated, 401)  # the size of a body never changes who is refused first
    generic(lab.send("POST", lab.deliveries_path(), subject="coordinator-1", content=big), 403)
    assert lab.delivery_rows() == []


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE", "PATCH"])
def test_only_post_is_accepted_on_the_declaration_path_and_only_put_on_the_content_path(lab, method):
    assert lab.send(method, lab.deliveries_path(), subject="vendor-1").status_code == 405
    assert lab.send("POST", lab.content_path("a" * 32), subject="vendor-1").status_code == 405
    assert lab.audit_rows() == [] and lab.delivery_rows() == []


# --- the order of the work, and failure --------------------------------------------------------------------------------


def test_a_declaration_runs_in_the_shared_order_in_one_transaction(lab, spy):
    assert lab.initiate("vendor-1").status_code == 201
    events = spy.events
    insert_delivery = next(i for i, e in enumerate(events) if e.startswith("INSERT INTO deliveries"))
    insert_audit = next(i for i, e in enumerate(events) if e.startswith("INSERT INTO audit_events"))
    assert events.index("BEGIN IMMEDIATE") < events.index("CLOCK") < events.index("AUTHENTICATE") < insert_delivery < insert_audit
    assert events.count("BEGIN IMMEDIATE") == 1 and events.count("COMMIT") == 1 and events.index("COMMIT") > insert_audit
    assert events.count("CLOCK") == 1 and lab.clock.calls == 1
    assert_released(lab, spy)


def test_a_failure_to_record_the_declaration_declares_nothing(lab, spy):
    lab.make_audit_inserts_fail()
    generic(lab.initiate("vendor-1"), 500)
    assert lab.delivery_rows() == [] and lab.audit_rows() == []
    assert_released(lab, spy)
