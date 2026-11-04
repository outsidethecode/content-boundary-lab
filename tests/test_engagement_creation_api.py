"""POST /productions/{production_id}/engagements: a coordinator engages an existing subject in its own production.

Through the real application: the TestClient, a SQLite file per test and ephemeral keys (tests/support/http_lab.py).
The order every request keeps is BEGIN IMMEDIATE, one clock snapshot, authenticate, authorise, validate and mutate,
audit, COMMIT, respond. Interleavings use thread events, never sleeps.
"""

import asyncio
import json
import logging
import threading
from datetime import datetime, timedelta
from urllib.parse import quote

import pytest
from support import token_issuer as tokens
from support.http_lab import (
    OTHER_ISSUER,
    REAL_CONNECT,
    SHORT_END,
    T0,
    THREAD_WAIT,
    Background,
    FixedClock,
    assert_released,
    generic,
    lab,
    make_lab,
    observable,
    spy,
    transaction_whose_commit_fails,
    writer_lock,
)

from content_boundary_lab import store
from content_boundary_lab.clock import to_micros

MAX_LIFETIME = timedelta(days=90)
MICRO = timedelta(microseconds=1)
MARKER = "SECRET-MARKER-1f3a"  # text that must never come back out of the server, in a response or an audit row
FIELDS = {"body", "subject", "role", "ends_at"}


def iso(moment: datetime) -> str:
    text = moment.strftime("%Y-%m-%dT%H:%M:%S")
    return (text + f".{moment.microsecond:06d}" if moment.microsecond else text) + "Z"


def path_for(lab, production: str | None = None) -> str:
    return f"/productions/{quote(production or lab.alpha, safe='')}/engagements"


def body(**overrides) -> dict:
    members = {"subject": "outsider-1", "role": "vendor", "ends_at": iso(T0 + timedelta(days=30))}
    members.update(overrides)
    return {name: value for name, value in members.items() if value is not ...}  # ... removes a member


def create(lab, payload=None, *, subject="coordinator-1", production=None, raw: bytes | None = None, **kwargs):
    """POST with a valid token for `subject` (none if None). `raw` sends exactly those bytes instead of JSON."""
    if raw is not None:
        return lab.send("POST", path_for(lab, production), subject=subject, content=raw, **kwargs)
    return lab.send("POST", path_for(lab, production), subject=subject, json=body() if payload is None else payload, **kwargs)


def engagement(lab, engagement_id: str) -> dict | None:
    conn = REAL_CONNECT(lab.path)
    try:
        row = conn.execute(
            "SELECT e.id, s.issuer, s.subject, e.production_id, e.role, e.created_at, e.ends_at, e.revoked_at "
            "FROM engagements AS e JOIN subjects AS s ON s.id = e.subject_id WHERE e.id = ?",
            (engagement_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def event(lab, *, action, outcome, reason=None, actor="coordinator-1", object_id=None, at=T0, seq=1, production=None):
    return {
        "seq": seq,
        "at": to_micros(at),
        "actor_issuer": tokens.ISSUER if actor else None,
        "actor_subject": actor,
        "action": action,
        "outcome": outcome,
        "production_id": production or lab.alpha,
        "object_type": "engagement" if object_id else None,
        "object_id": object_id,
        "reason": reason,
        "engine_kind": None,
    }


def rejected(lab, reason, **kwargs) -> dict:
    return event(lab, action="engagement.request_rejected", outcome="denied", reason=reason, **kwargs)


def assert_rejected(lab, response, status, detail, reason, before, at=T0) -> None:
    assert response.status_code == status and response.json()["detail"] == detail
    assert response.headers["cache-control"] == "no-store"
    assert lab.audit_rows() == [rejected(lab, reason, at=at)]
    assert lab.engagement_rows() == before  # nothing was created


# ------------------------------------------------------------------------------------------------ the happy path


def test_a_coordinator_creates_a_vendor_engagement(lab):
    before = lab.engagement_rows()
    response = create(lab)
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store" and response.headers["content-type"] == "application/json"
    content = response.json()
    assert set(content) == {"engagement_id", "subject", "role", "ends_at"}
    assert (content["subject"], content["role"], content["ends_at"]) == ("outsider-1", "vendor", "2026-12-03T12:00:00.000000Z")
    row = engagement(lab, content["engagement_id"])
    assert row == {
        "id": content["engagement_id"],
        "issuer": tokens.ISSUER,
        "subject": "outsider-1",
        "production_id": lab.alpha,
        "role": "vendor",
        "created_at": to_micros(T0),  # the captured request instant
        "ends_at": to_micros(T0 + timedelta(days=30)),
        "revoked_at": None,
    }
    assert len(lab.engagement_rows()) == len(before) + 1
    assert lab.audit_rows() == [
        event(lab, action="engagement.created", outcome="allowed", object_id=content["engagement_id"])
    ]
    # The new vendor can see its engagement with its own token.
    assert lab.get(lab.alpha, "outsider-1").json() == {"role": "vendor", "ends_at": "2026-12-03T12:00:00.000000Z"}


def test_a_coordinator_creates_another_coordinator_who_can_then_manage_engagements(lab):
    response = create(lab, body(role="coordinator"))
    assert response.status_code == 201 and response.json()["role"] == "coordinator"
    # outsider-1 is now a coordinator of ALPHA and engages vendor-2 (who works on BRAVO) there.
    second = create(lab, body(subject="vendor-2"), subject="outsider-1")
    assert second.status_code == 201 and second.json()["subject"] == "vendor-2"
    assert lab.get(lab.alpha, "vendor-2").json()["role"] == "vendor"


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("2026-12-03T12:00:00Z", "2026-12-03T12:00:00.000000Z"),
        ("2026-12-03T12:00:00.5Z", "2026-12-03T12:00:00.500000Z"),
        ("2026-12-03T12:00:00.123456Z", "2026-12-03T12:00:00.123456Z"),
        ("2026-12-03T12:00:00.000001Z", "2026-12-03T12:00:00.000001Z"),
    ],
)
def test_the_end_time_keeps_its_microsecond_precision(lab, text, shown):
    response = create(lab, body(ends_at=text))
    assert response.status_code == 201 and response.json()["ends_at"] == shown
    stored = engagement(lab, response.json()["engagement_id"])["ends_at"]
    assert stored == to_micros(datetime.fromisoformat(text.replace("Z", "+00:00")))


# --------------------------------------------------------------------------- who may create, and what comes first


@pytest.mark.parametrize(
    ("caller", "reason"),
    [("vendor-1", "role_not_permitted"), ("outsider-1", "no_engagement"), ("coordinator-2", "no_engagement")],
    ids=["a vendor of the production", "no engagement at all", "a coordinator of another production"],
)
def test_only_a_coordinator_of_the_production_may_create(lab, caller, reason):
    before = lab.engagement_rows()
    generic(create(lab, subject=caller), 403)
    assert lab.engagement_rows() == before
    [row] = lab.audit_rows()
    assert (row["action"], row["outcome"], row["reason"], row["actor_subject"]) == ("access.denied", "denied", reason, caller)


def test_a_revoked_coordinator_may_no_longer_create(lab):
    lab.revoke("coordinator")
    generic(create(lab), 403)
    assert [row["reason"] for row in lab.audit_rows()] == ["engagement_revoked"]


def test_claims_in_the_token_do_not_make_a_vendor_a_coordinator(lab):
    generic(create(lab, subject="vendor-1", role="coordinator", scope="manage_engagements", productions=[lab.alpha]), 403)
    assert [row["reason"] for row in lab.audit_rows()] == ["role_not_permitted"]


def test_an_invalid_production_in_the_url_is_a_403_and_not_a_missing_page(lab):
    generic(create(lab, production="NOT-AN-ID"), 403)
    assert lab.audit_rows() == [
        {**event(lab, action="access.denied", outcome="denied", reason="invalid_identifier"), "production_id": None}
    ]


BODIES_THAT_MUST_NOT_MATTER = {
    "a valid body": json.dumps(body()).encode(),
    "garbage": f"not json {MARKER}".encode(),
    "an oversized body": b"x" * 100_000,
}


@pytest.mark.parametrize("content", BODIES_THAT_MUST_NOT_MATTER.values(), ids=list(BODIES_THAT_MUST_NOT_MATTER))
def test_authentication_and_authorisation_are_decided_before_the_body_is_judged(lab, content):
    generic(create(lab, subject=None, raw=content), 401)  # no credentials: 401, never 400 or 413
    generic(create(lab, subject="vendor-1", raw=content), 403)  # not a coordinator: 403, never 400 or 413
    generic(create(lab, subject="outsider-1", raw=content), 403)
    assert [(row["reason"], row["actor_subject"]) for row in lab.audit_rows()] == [
        ("invalid_credentials", None),
        ("role_not_permitted", "vendor-1"),
        ("no_engagement", "outsider-1"),
    ]
    assert MARKER not in repr(lab.audit_rows())


def test_every_refusal_looks_the_same_whatever_the_body(lab):
    shapes = {observable(create(lab, subject="vendor-1", raw=content)) for content in BODIES_THAT_MUST_NOT_MATTER.values()}
    assert len(shapes) == 1


# ------------------------------------------------------------------------------------------------ the target subject


@pytest.mark.parametrize(
    "subject",
    ["nobody-at-all", "foreign-only", "Outsider-1", "outsider-1 ", "outsider-%", "outsider-1' OR '1'='1", "x" * 512],
    ids=["unknown", "exists under another issuer only", "other letter case", "trailing space", "wildcard", "SQL punctuation", "long"],
)
def test_the_subject_must_already_exist_under_the_callers_issuer(lab, subject):
    before = lab.engagement_rows()
    response = create(lab, body(subject=subject))
    assert_rejected(lab, response, 400, "Invalid request", "invalid_request", before)
    assert response.json()["field"] == "subject"


@pytest.mark.parametrize(
    "subject",
    ["", " ", "x" * 513, "two\nlines", "nul\x00byte", "‮right-to-left", 5, None, ["outsider-1"]],
    ids=["empty", "space", "too long", "newline", "NUL", "bidi override", "number", "null", "list"],
)
def test_a_subject_that_is_not_a_well_formed_string_is_refused_before_any_lookup(lab, subject):
    before = lab.engagement_rows()
    response = create(lab, body(subject=subject))
    assert_rejected(lab, response, 400, "Invalid request", "invalid_request", before)
    assert response.json()["field"] == "subject"


def test_a_subject_known_only_under_another_issuer_cannot_be_engaged_by_naming_that_issuer(lab):
    before = lab.engagement_rows()
    response = create(lab, {**body(subject="foreign-only"), "issuer": OTHER_ISSUER})  # the body's issuer is not read
    assert_rejected(lab, response, 400, "Invalid request", "invalid_request", before)
    assert response.json()["field"] == "body"  # an unexpected member


def test_the_production_comes_from_the_url_and_never_from_the_body(lab):
    before = lab.engagement_rows()
    response = create(lab, {**body(), "production_id": lab.bravo})
    assert_rejected(lab, response, 400, "Invalid request", "invalid_request", before)
    assert response.json()["field"] == "body"
    assert not [row for row in lab.engagement_rows() if row[2] == lab.bravo and row not in before]


# --------------------------------------------------------------------------------------------------- role and expiry


@pytest.mark.parametrize("role", ["admin", "Vendor", "VENDOR", " vendor", "vendor\n", "coordinator ", "", None, 5, ["vendor"]])
def test_only_the_vendor_and_coordinator_roles_are_accepted(lab, role):
    before = lab.engagement_rows()
    response = create(lab, body(role=role))
    assert_rejected(lab, response, 400, "Invalid request", "invalid_request", before)
    assert response.json()["field"] == "role"


INVALID_END_TIMES = [
    "",
    "2026-12-03",
    "2026-12-03T12:00:00",
    "2026-12-03T12:00:00+00:00",
    "2026-12-03T12:00:00-00:00",
    "2026-12-03T12:00:00z",
    "2026-12-03 12:00:00Z",
    " 2026-12-03T12:00:00Z",
    "2026-12-03T12:00:00Z ",
    "2026-12-03T12:00:00Z\n",
    "2026-12-03T12:00:00.Z",
    "2026-12-03T12:00:00.1234567Z",
    "2026-13-03T12:00:00Z",
    "2026-02-30T12:00:00Z",
    "2026-12-03T24:00:00Z",
    "2026-12-03T12:60:00Z",
    "2026-12-03T12:00:60Z",
    "0000-12-03T12:00:00Z",
    "10000-12-03T12:00:00Z",
    "２０２６-12-03T12:00:00Z",  # full-width digits
    "2026-12-03T12:00:00.1e3Z",
    "1796299200",
    "tomorrow",
    5,
    None,
    ["2026-12-03T12:00:00Z"],
]


@pytest.mark.parametrize("ends_at", INVALID_END_TIMES, ids=lambda value: ascii(value)[:34])
def test_the_end_time_must_be_a_strict_utc_timestamp(lab, ends_at):
    before = lab.engagement_rows()
    response = create(lab, body(ends_at=ends_at))
    assert_rejected(lab, response, 400, "Invalid request", "invalid_request", before)
    assert response.json()["field"] == "ends_at"


def test_the_end_time_is_mandatory(lab):
    before = lab.engagement_rows()
    response = create(lab, body(ends_at=...))
    assert_rejected(lab, response, 400, "Invalid request", "invalid_request", before)
    assert response.json()["field"] == "body"  # a missing member


@pytest.mark.parametrize("moment", [T0, T0 + timedelta(microseconds=1_234_567)], ids=["on a whole second", "mid-second"])
@pytest.mark.parametrize(
    ("offset", "status"),
    [
        (MAX_LIFETIME, 201),
        (MAX_LIFETIME + MICRO, 400),
        (MAX_LIFETIME - MICRO, 201),
        (MICRO, 201),
        (timedelta(0), 400),
        (-MICRO, 400),
        (timedelta(days=-30), 400),
        (timedelta(days=3000), 400),
    ],
    ids=["exactly 90 days", "90 days and 1 microsecond", "90 days less 1 microsecond", "1 microsecond ahead", "now", "1 microsecond ago", "a month ago", "years ahead"],
)
def test_the_end_time_is_later_than_the_request_instant_and_at_most_exactly_90_days_after_it(lab, moment, offset, status):
    lab.clock.moment = moment
    response = create(lab, body(ends_at=iso(moment + offset)))
    assert response.status_code == status
    if status == 201:
        assert engagement(lab, response.json()["engagement_id"])["created_at"] == to_micros(moment)
    else:
        assert response.json()["field"] == "ends_at"
        assert [row["reason"] for row in lab.audit_rows()] == ["invalid_request"]


def test_the_cap_is_measured_from_the_one_instant_the_request_captured(lab):
    lab.clock.step = timedelta(seconds=1)  # a second read of the clock would see a later instant
    assert create(lab, body(ends_at=iso(T0 + MAX_LIFETIME))).status_code == 201
    assert lab.clock.calls == 1
    [row] = lab.audit_rows()
    assert row["at"] == to_micros(T0)


# -------------------------------------------------------------------------------------------------------- duplicates


def test_an_active_engagement_is_a_conflict_and_changes_nothing(lab):
    before = lab.engagement_rows()
    response = create(lab, body(subject="vendor-1", role="coordinator"))  # would also be an escalation
    assert_rejected(lab, response, 409, "Engagement already exists", "engagement_exists", before)


def test_an_expired_engagement_cannot_be_recreated(lab):
    lab.clock.moment = SHORT_END + timedelta(seconds=1)  # short-1's engagement ended; coordinator-1's token still lives
    before = lab.engagement_rows()
    response = create(lab, body(subject="short-1", ends_at=iso(lab.clock.moment + timedelta(days=30))))
    assert_rejected(lab, response, 409, "Engagement already exists", "engagement_exists", before, at=lab.clock.moment)
    assert lab.get(lab.alpha, "short-1").status_code == 403  # and it stays expired


def test_a_revoked_engagement_cannot_be_recreated(lab):
    lab.revoke("vendor")
    before = lab.engagement_rows()
    response = create(lab, body(subject="vendor-1"))
    assert_rejected(lab, response, 409, "Engagement already exists", "engagement_exists", before)
    assert lab.get(lab.alpha, "vendor-1").status_code == 403


def test_a_coordinator_cannot_re_engage_itself(lab):
    before = lab.engagement_rows()
    response = create(lab, body(subject="coordinator-1", role="coordinator"))
    assert_rejected(lab, response, 409, "Engagement already exists", "engagement_exists", before)


def test_the_same_subject_may_be_engaged_in_another_production(lab):
    assert create(lab, body(subject="vendor-2")).status_code == 201  # vendor-2 already works on BRAVO


# ------------------------------------------------------------------------------------- malformed and oversized bodies

VALID_JSON = json.dumps(body()).encode()
BAD_BODIES = {
    "empty": (b"", "body"),
    "not json": (f"not json {MARKER}".encode(), "body"),
    "an array": (f'["{MARKER}"]'.encode(), "body"),
    "a string": (f'"{MARKER}"'.encode(), "body"),
    "null": (b"null", "body"),
    "a number": (b"42", "body"),
    "truncated": (VALID_JSON[:-5], "body"),
    "invalid UTF-8": (b"\xff\xfe" + MARKER.encode(), "body"),
    "a byte order mark": (b"\xef\xbb\xbf" + VALID_JSON, "body"),
    "a repeated member": (
        f'{{"subject":"{MARKER}","subject":"outsider-1","role":"vendor","ends_at":"{iso(T0 + timedelta(days=30))}"}}'.encode(),
        "body",
    ),
    "NaN": (b'{"subject":"outsider-1","role":"vendor","ends_at":NaN}', "body"),
    "very deep nesting": (b"[" * 1500 + b"]" * 1500, "body"),
    "an unexpected member": (json.dumps({**body(), "extra": MARKER}).encode(), "body"),
    "a missing member": (json.dumps(body(role=...)).encode(), "body"),
    "a subject that is not a string": (json.dumps(body(subject=5)).encode(), "subject"),
}


@pytest.mark.parametrize("case", BAD_BODIES)
def test_a_malformed_body_is_a_400_after_authentication_and_authorisation_and_is_audited_without_its_text(lab, caplog, case):
    content, field = BAD_BODIES[case]
    before = lab.engagement_rows()
    with caplog.at_level(logging.DEBUG):
        response = create(lab, raw=content)
    assert_rejected(lab, response, 400, "Invalid request", "invalid_request", before)
    assert response.json()["field"] == field
    assert MARKER not in response.text and MARKER not in repr(lab.audit_rows()) and MARKER not in caplog.text


def _padded(length: int) -> bytes:
    return VALID_JSON + b" " * (length - len(VALID_JSON))


def test_a_body_of_exactly_4_kib_is_accepted(lab):
    assert create(lab, raw=_padded(4096)).status_code == 201


@pytest.mark.parametrize("size", [4097, 5000, 1_000_000])
def test_a_larger_body_is_a_413_after_authentication_and_authorisation_and_is_audited(lab, size):
    before = lab.engagement_rows()
    response = create(lab, raw=_padded(size))
    assert_rejected(lab, response, 413, "Payload too large", "payload_too_large", before)


# ------------------------------------------------------------------------- the byte limit is on the streamed bytes


def stream(lab, chunks, *, token, declared_length=None):
    """POST to the application as ASGI messages, so that the test controls exactly what is streamed and how much is read."""
    queue, pulled = list(chunks), {"messages": 0, "bytes": 0}

    async def receive():
        pulled["messages"] += 1
        if not queue:
            return {"type": "http.disconnect"}
        chunk = queue.pop(0)
        pulled["bytes"] += len(chunk)
        return {"type": "http.request", "body": chunk, "more_body": bool(queue)}

    sent = []

    async def send(message):
        sent.append(message)

    headers = [(b"content-type", b"application/json")]
    if declared_length is not None:
        headers.append((b"content-length", str(declared_length).encode()))
    if token:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    path = path_for(lab)
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http",
        "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "", "headers": headers,
        "client": ("testclient", 50000), "server": ("testserver", 80),
    }  # fmt: skip
    asyncio.run(lab.app(scope, receive, send))
    status = next(message["status"] for message in sent if message["type"] == "http.response.start")
    content = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    return status, json.loads(content), pulled


def test_the_limit_counts_the_bytes_actually_streamed_not_the_declared_length(lab):
    chunks = [b" " * 1024] * 1000  # a megabyte, while the header claims ten bytes
    status, content, pulled = stream(lab, chunks, token=lab.token("coordinator-1"), declared_length=10)
    assert (status, content) == (413, {"detail": "Payload too large"})
    assert pulled["bytes"] <= 4096 + 1024 and pulled["messages"] <= 6  # it stopped reading as soon as the cap was crossed
    assert [row["reason"] for row in lab.audit_rows()] == ["payload_too_large"]


def test_a_huge_declared_length_does_not_reject_a_body_that_is_small(lab):
    status, content, _ = stream(lab, [VALID_JSON], token=lab.token("coordinator-1"), declared_length=999_999_999)
    assert status == 201 and content["subject"] == "outsider-1"


def test_an_oversized_stream_gets_the_401_or_403_first_and_is_still_read_only_up_to_the_cap(lab):
    chunks = [b" " * 1024] * 1000
    status, content, pulled = stream(lab, chunks, token=None, declared_length=10)
    assert (status, content) == (401, {"detail": "Not authenticated"}) and pulled["bytes"] <= 4096 + 1024
    status, content, pulled = stream(lab, chunks, token=lab.token("vendor-1"), declared_length=10)
    assert (status, content) == (403, {"detail": "Forbidden"}) and pulled["bytes"] <= 4096 + 1024
    assert [row["reason"] for row in lab.audit_rows()] == ["invalid_credentials", "role_not_permitted"]


def test_the_body_is_read_before_the_writer_lock_is_taken(lab, spy):
    # A client that is slow to send its body must not hold the lock: nothing has begun until the body is in.
    seen = {}

    async def run():
        received = {"count": 0}

        async def receive():
            received["count"] += 1
            if received["count"] == 1:
                seen["begins_before_the_body_is_complete"] = spy.events.count("BEGIN IMMEDIATE")
                return {"type": "http.request", "body": VALID_JSON[:10], "more_body": True}
            seen["begins_before_the_last_chunk"] = spy.events.count("BEGIN IMMEDIATE")
            return {"type": "http.request", "body": VALID_JSON[10:], "more_body": False}

        sent = []

        async def send(message):
            sent.append(message)

        path = path_for(lab)
        headers = [(b"authorization", f"Bearer {lab.token('coordinator-1')}".encode())]
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "scheme": "http",
                 "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "", "headers": headers,
                 "client": ("t", 1), "server": ("s", 80)}  # fmt: skip
        await lab.app(scope, receive, send)
        return next(m["status"] for m in sent if m["type"] == "http.response.start")

    assert asyncio.run(run()) == 201
    assert seen == {"begins_before_the_body_is_complete": 0, "begins_before_the_last_chunk": 0}


# -------------------------------------------------------------------- atomicity, one audit event, and one clock read


def test_if_the_audit_record_cannot_be_written_the_engagement_is_not_created(lab, spy):
    lab.make_audit_inserts_fail()
    before = lab.engagement_rows()
    response = create(lab)
    generic(response, 500)
    assert lab.engagement_rows() == before and lab.audit_rows() == []
    inserts = [event for event in spy.events if event.startswith("INSERT")]
    assert inserts[0].startswith("INSERT INTO engagements")  # the engagement really was inserted, then rolled back
    assert "ROLLBACK" in spy.events and "COMMIT" not in spy.events
    assert_released(lab, spy)


def test_if_the_commit_fails_the_engagement_is_not_created_and_not_reported(lab, spy, monkeypatch):
    monkeypatch.setattr(store, "transaction", transaction_whose_commit_fails)
    before = lab.engagement_rows()
    generic(create(lab), 500)
    assert lab.engagement_rows() == before and lab.audit_rows() == []
    assert_released(lab, spy)


OUTCOMES = {
    "201 created": (lambda lab: create(lab), 201),
    "400 malformed": (lambda lab: create(lab, raw=b"{"), 400),
    "400 unknown subject": (lambda lab: create(lab, body(subject="nobody")), 400),
    "409 duplicate": (lambda lab: create(lab, body(subject="vendor-1")), 409),
    "413 oversized": (lambda lab: create(lab, raw=b" " * 5000), 413),
    "401 no credentials": (lambda lab: create(lab, subject=None), 401),
    "403 not a coordinator": (lambda lab: create(lab, subject="vendor-1"), 403),
}


@pytest.mark.parametrize("case", OUTCOMES)
def test_every_committed_decision_has_exactly_one_audit_event_on_the_one_clock_read(lab, case):
    send, status = OUTCOMES[case]
    lab.clock.step = timedelta(seconds=1)
    response = send(lab)
    assert response.status_code == status and response.headers["cache-control"] == "no-store"
    [row] = lab.audit_rows()
    assert row["at"] == to_micros(T0) and lab.clock.calls == 1


def test_the_order_is_lock_clock_authenticate_authorise_mutate_audit_check_commit(lab, spy):
    assert create(lab).status_code == 201
    kinds = [event.split(" ")[0] if event not in {"CLOCK", "AUTHENTICATE"} else event for event in spy.events]
    assert kinds == [
        "BEGIN",  # BEGIN IMMEDIATE: the writer lock
        "CLOCK",  # the one read of the clock
        "SELECT",  # where the audit count starts
        "AUTHENTICATE",
        "SELECT",  # authorisation: the coordinator's engagement in the URL's production
        "SELECT",  # the subject
        "SELECT",  # a duplicate?
        "INSERT",  # the engagement
        "INSERT",  # its audit event
        "SELECT",  # exactly one audit event?
        "COMMIT",
    ]
    assert spy.events.count("BEGIN IMMEDIATE") == 1 and spy.events.count("CLOCK") == 1


# ------------------------------------------------------------------------------------------------------ concurrency


def test_two_simultaneous_creations_for_the_same_subject_give_one_201_and_one_409(lab, spy):
    inside, release, first = threading.Event(), threading.Event(), [True]

    def pause_the_first_request():
        if first[0]:
            first[0] = False
            inside.set()
            assert release.wait(THREAD_WAIT)

    lab.clock.hooks.append(pause_the_first_request)
    one = Background(lambda: create(lab))
    assert inside.wait(THREAD_WAIT)  # request one holds the writer lock
    two = Background(lambda: create(lab))
    assert spy.begin_signals[1].wait(THREAD_WAIT)  # and request two is waiting for it
    release.set()
    assert (one.join().status_code, two.join().status_code) == (201, 409)
    assert len([row for row in lab.engagement_rows() if row[0] not in lab.engagements.values()]) == 1  # one new engagement
    assert [(row["action"], row["reason"]) for row in lab.audit_rows()] == [
        ("engagement.created", None),
        ("engagement.request_rejected", "engagement_exists"),
    ]
    assert_released(lab, spy)


def test_a_creation_that_waits_behind_the_revocation_of_its_own_coordinator_is_refused(lab, spy):
    with writer_lock(lab) as holder:
        request = Background(lambda: create(lab))
        assert spy.begin_signals[0].wait(THREAD_WAIT)
        store.revoke_engagement(holder, FixedClock(T0), lab.engagements["coordinator"])
    generic(request.join(), 403)  # decided after the wait, on the committed revocation
    assert [row["reason"] for row in lab.audit_rows()] == ["engagement_revoked"]
    assert not [row for row in lab.engagement_rows() if row[0] not in lab.engagements.values()]


def test_a_request_that_waited_for_the_lock_judges_the_end_time_on_the_instant_after_the_wait(lab, spy):
    with writer_lock(lab):
        request = Background(lambda: create(lab, body(ends_at=iso(T0 + timedelta(seconds=10)))))
        assert spy.begin_signals[0].wait(THREAD_WAIT)
        lab.clock.moment = T0 + timedelta(seconds=30)  # time passes while it waits
    response = request.join()  # ten seconds ahead of the time before the wait, but behind the instant it really ran at
    assert response.status_code == 400 and response.json()["field"] == "ends_at"
    assert [row["at"] for row in lab.audit_rows()] == [to_micros(T0 + timedelta(seconds=30))]


# ---------------------------------------------------------------------------------------------- the route's surface


@pytest.mark.parametrize("method", ["GET", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_other_methods_are_refused_without_touching_the_database(lab, method):
    response = lab.send(method, path_for(lab), subject="coordinator-1")
    assert response.status_code == 405
    assert lab.audit_rows() == [] and lab.clock.calls == 0


def test_the_end_of_the_path_cannot_smuggle_a_production(lab):
    response = lab.send("POST", f"/productions/{lab.alpha}/extra/engagements", subject="coordinator-1", json=body())
    generic(response, 403)  # the production in the URL is "<alpha>/extra", which is not an identifier
    assert [row["reason"] for row in lab.audit_rows()] == ["invalid_identifier"]


def test_a_token_signed_by_another_key_is_refused(lab):
    other = tokens.new_key("key-1")
    generic(lab.send("POST", path_for(lab), token=tokens.mint(other, sub="coordinator-1"), json=body()), 401)
    assert [row["reason"] for row in lab.audit_rows()] == ["invalid_credentials"]
