"""GET /productions/{production_id}/engagement: the first authenticated route, tested through the real application.

Everything is real except the clock and the keys: a FastAPI app behind the TestClient, a SQLite file per test, ES256
tokens from ephemeral keys, and an injected clock that counts its reads. Where a test needs an exact interleaving
(a request waiting for the writer lock while a revocation commits, or the other way round) threads are coordinated
with events, never with sleeps.
"""

import ast
import inspect
import logging
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from support import token_issuer as tokens
from support.http_lab import (  # the harness (and its fixtures) moved to tests/support/http_lab.py unchanged
    LONG_END,
    LOGGER,
    MICRO_END,
    OTHER_ISSUER,
    REAL_CONNECT,
    SEEDED_AT,
    SHORT_END,
    T0,
    THREAD_WAIT,
    UTC,
    Background,
    FixedClock,
    Lab,
    RecordingClock,
    Spy,
    assert_released,
    denial,
    generic,
    is_closed,
    lab,
    make_lab,
    observable,
    spy,
    transaction_whose_commit_fails,
    writer_lock,
)

from content_boundary_lab import audit, authz, engagements, identity, management, request_flow, store
from content_boundary_lab.app import Dependencies, create_app
from content_boundary_lab.clock import to_micros
from content_boundary_lab.scanner import LabSyntheticMarkerScanner


# ----------------------------------------------------------------------------------------------- the fixtures


def test_the_fixture_clock_is_the_instant_the_default_token_becomes_valid():
    assert to_micros(T0) == tokens.NOW * 1_000_000


def test_the_handler_is_synchronous_so_it_runs_in_the_thread_pool(lab):
    [route] = [route for route in lab.app.routes if getattr(route, "path", "").endswith("/engagement")]
    assert not inspect.iscoroutinefunction(route.endpoint)


# --------------------------------------------------------------------------------------------------- success


@pytest.mark.parametrize(
    ("subject", "role", "ends_at"),
    [
        ("vendor-1", "vendor", "2026-12-03T12:00:00.000000Z"),
        ("coordinator-1", "coordinator", "2026-12-03T12:00:00.000000Z"),
        ("micro-1", "vendor", "2026-12-03T12:00:00.123456Z"),
    ],
)
def test_an_engaged_caller_sees_its_own_role_and_end_time(lab, subject, role, ends_at):
    response = lab.get(lab.alpha, subject)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {"role": role, "ends_at": ends_at}


def test_the_response_holds_nothing_but_the_role_and_the_end_time(lab):
    response = lab.get(lab.alpha)
    assert set(response.json()) == {"role", "ends_at"}
    for private in (lab.alpha, lab.bravo, *lab.engagements.values(), "vendor-1", tokens.ISSUER, "ALPHA"):
        assert private not in response.text
        assert all(private not in value for value in response.headers.values())


def test_a_successful_view_is_recorded_once_against_the_authorised_engagement(lab):
    lab.get(lab.alpha)
    assert lab.audit_rows() == [
        {
            "seq": 1,
            "at": to_micros(T0),
            "actor_issuer": tokens.ISSUER,
            "actor_subject": "vendor-1",
            "action": "engagement.viewed",
            "outcome": "allowed",
            "production_id": lab.alpha,
            "object_type": "engagement",
            "object_id": lab.engagements["vendor"],
            "reason": None,
            "engine_kind": None,
        }
    ]


def test_the_view_is_committed_before_the_response_is_returned(lab):
    response = lab.get(lab.alpha)
    assert response.status_code == 200
    assert [row["action"] for row in lab.audit_rows()] == ["engagement.viewed"]


def test_a_coordinator_sees_its_own_engagement_and_no_one_elses(lab):
    assert lab.get(lab.alpha, "coordinator-1").json()["role"] == "coordinator"
    generic(lab.get(lab.bravo, "coordinator-1"), 403)


def test_the_query_string_cannot_change_whose_engagement_is_shown(lab):
    response = lab.get(lab.alpha, params={"role": "coordinator", "subject": "coordinator-1", "production_id": lab.bravo})
    assert response.json()["role"] == "vendor"
    [row] = lab.audit_rows()
    assert (row["actor_subject"], row["production_id"]) == ("vendor-1", lab.alpha)


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_other_methods_are_refused_without_touching_the_database(lab, method):
    response = lab.request(method, lab.alpha, headers={"Authorization": f"Bearer {lab.token()}"})
    assert response.status_code == 405
    assert lab.audit_rows() == []
    assert lab.clock.calls == 0


# ------------------------------------------------------------------------------------ authentication failures

NOW = tokens.NOW


def _hs256_with_the_public_key(lab: Lab) -> str:
    secret = tokens.public_key_secrets(lab.key)["SubjectPublicKeyInfo PEM"]
    return tokens.hs256(secret, tokens.default_header("key-1", alg="HS256"), tokens.default_claims(sub="vendor-1"))


BAD_CREDENTIALS = {
    "no header": lambda lab: None,
    "empty value": lambda lab: "",
    "another scheme": lambda lab: "Basic dXNlcjpwYXNz",
    "scheme without a token": lambda lab: "Bearer ",
    "lower-case scheme": lambda lab: "bearer " + lab.token(),
    "not a token": lambda lab: "Bearer not-a-token",
    "two segments": lambda lab: "Bearer " + ".".join(lab.token().split(".")[:2]),
    "token with trailing space": lambda lab: "Bearer " + lab.token() + " ",
    "signed by another key": lambda lab: "Bearer " + tokens.mint(tokens.new_key("key-1"), sub="vendor-1"),
    "unknown key id": lambda lab: "Bearer " + tokens.mint(tokens.new_key("other-kid"), sub="vendor-1"),
    "expired": lambda lab: "Bearer " + lab.token(iat=NOW - 600, nbf=NOW - 600, exp=NOW - 300),
    "not yet valid": lambda lab: "Bearer " + lab.token(iat=NOW + 600, nbf=NOW + 600, exp=NOW + 900),
    "wrong audience": lambda lab: "Bearer " + lab.token(aud="https://another.example"),
    "wrong issuer": lambda lab: "Bearer " + lab.token(iss="https://another-issuer.example"),
    "missing subject": lambda lab: "Bearer " + lab.token(sub=tokens.MISSING),
    "no signature": lambda lab: "Bearer " + lab.token().rsplit(".", 1)[0] + ".",
    "HS256 keyed with the public key": lambda lab: "Bearer " + _hs256_with_the_public_key(lab),
    "unsecured alg none": lambda lab: "Bearer "
    + tokens.with_signature(
        tokens.default_header("key-1", alg="none"), tokens.default_claims(sub="vendor-1"), b"\x00" * 64
    ),
}


@pytest.mark.parametrize("case", BAD_CREDENTIALS)
def test_bad_credentials_get_a_generic_401_and_one_anonymous_denial(lab, case):
    authorization = BAD_CREDENTIALS[case](lab)
    headers = {} if authorization is None else {"Authorization": authorization}
    response = lab.request("GET", lab.alpha, headers=headers)
    generic(response, 401)
    assert response.headers["www-authenticate"] == "Bearer"
    assert lab.audit_rows() == [
        {
            "seq": 1,
            "at": to_micros(T0),
            "actor_issuer": None,
            "actor_subject": None,
            "action": "access.denied",
            "outcome": "denied",
            "production_id": None,
            "object_type": None,
            "object_id": None,
            "reason": "invalid_credentials",
            "engine_kind": None,
        }
    ]


def test_every_authentication_failure_looks_the_same_to_the_client(lab):
    seen = set()
    for build in BAD_CREDENTIALS.values():
        authorization = build(lab)
        headers = {} if authorization is None else {"Authorization": authorization}
        seen.add(observable(lab.request("GET", lab.alpha, headers=headers)))
    assert len(seen) == 1


def test_authentication_failures_leave_no_token_and_no_failure_detail_in_the_audit_record(lab):
    secret_token = lab.token(iat=NOW - 600, nbf=NOW - 600, exp=NOW - 300)  # expired
    lab.get(lab.alpha, token=secret_token)
    [row] = lab.audit_rows()
    text = repr(row)
    assert not any(segment in text for segment in secret_token.split("."))
    assert not any(failure.value in text for failure in identity.AuthFailure)


@pytest.mark.parametrize("production", ["alpha", "f" * 32, "NOT-AN-ID", ""])
def test_a_failed_authentication_reveals_nothing_about_the_production(lab, production):
    reference = observable(lab.request("GET", lab.alpha))
    assert observable(lab.request("GET", lab.production(production))) == reference
    assert all(row["production_id"] is None for row in lab.audit_rows())


def test_a_bad_credential_is_answered_before_a_bad_production_identifier(lab):
    generic(lab.request("GET", "NOT-AN-ID"), 401)
    assert [row["reason"] for row in lab.audit_rows()] == ["invalid_credentials"]


def test_two_authorization_headers_are_refused_even_if_both_are_valid(lab):
    good = f"Bearer {lab.token()}"
    response = lab.client.get(
        f"/productions/{lab.alpha}/engagement", headers=[("Authorization", good), ("Authorization", good)]
    )
    generic(response, 401)


SPOOFED = {
    "X-Authenticated-User": "vendor-1",
    "X-Forwarded-User": "vendor-1",
    "X-Remote-User": "vendor-1",
    "X-User": "vendor-1",
    "X-Role": "coordinator",
    "Remote-User": "vendor-1",
    "Cookie": "user=vendor-1; role=coordinator; session=vendor-1",
}


def test_identity_headers_and_cookies_are_never_credentials(lab):
    generic(lab.get(lab.alpha, None, headers=SPOOFED), 401)
    assert [row["actor_subject"] for row in lab.audit_rows()] == [None]


def test_identity_headers_do_not_change_who_a_verified_caller_is(lab):
    generic(lab.get(lab.alpha, "outsider-1", headers=SPOOFED), 403)
    assert lab.audit_rows() == [denial("outsider-1", lab.alpha, "no_engagement")]


# ------------------------------------------------------------------------------------- authorisation failures

DENIALS = [
    ("a known subject with no engagement", "outsider-1", "alpha", "no_engagement"),
    ("a subject the database has never seen", "never-provisioned", "alpha", "no_engagement"),
    ("engaged in another production only", "vendor-2", "alpha", "no_engagement"),
    ("a production that does not exist", "vendor-1", "f" * 32, "no_engagement"),
    ("the same subject under another issuer is engaged here, this issuer is not", "vendor-1", "bravo", "no_engagement"),
    ("the subject in another letter case", "Vendor-1", "alpha", "no_engagement"),
    ("a subject with SQL punctuation", "vendor-1' OR '1'='1", "alpha", "no_engagement"),
    ("a subject with a wildcard", "vendor-%", "alpha", "no_engagement"),
]


@pytest.mark.parametrize(("label", "subject", "production", "reason"), DENIALS, ids=[d[0] for d in DENIALS])
def test_a_caller_without_an_engagement_gets_a_generic_403_and_one_denial(lab, label, subject, production, reason):
    production_id = lab.production(production)
    generic(lab.get(production_id, subject), 403)
    assert lab.audit_rows() == [denial(subject, production_id, reason)]


def test_a_revoked_engagement_is_refused_at_once(lab):
    lab.revoke("vendor")
    generic(lab.get(lab.alpha), 403)
    assert lab.audit_rows() == [denial("vendor-1", lab.alpha, "engagement_revoked")]


def test_an_expired_engagement_is_refused(lab):
    lab.clock.moment = SHORT_END
    generic(lab.get(lab.alpha, "short-1"), 403)
    assert lab.audit_rows() == [denial("short-1", lab.alpha, "engagement_expired", at=SHORT_END)]


def test_revocation_is_reported_before_expiry(lab):
    lab.revoke("short")
    lab.clock.moment = SHORT_END
    generic(lab.get(lab.alpha, "short-1"), 403)
    assert [row["reason"] for row in lab.audit_rows()] == ["engagement_revoked"]


INVALID_IDENTIFIERS = [
    "",
    "A" * 32,
    "0" * 31,
    "0" * 33,
    "g" * 32,
    "%" * 32,
    "é" * 32,
    "a/b",
    "0" * 32 + "/",
    "a b",
    "carriage\rreturn",
    "nul\x00byte",
    "x" * 5000,
    "ALPHA-UPPER",
    "ALPHA-SHORT",
    "ALPHA-LONG",
    "ALPHA-SPACED",
    "ALPHA-INJECTED",
]


@pytest.mark.parametrize("invalid", INVALID_IDENTIFIERS, ids=lambda value: ascii(value)[:30])
def test_an_invalid_production_identifier_is_a_403_and_is_never_recorded_as_an_object(lab, invalid):
    production_id = lab.production(invalid)
    generic(lab.get(production_id), 403)
    [row] = lab.audit_rows()
    assert row == denial("vendor-1", None, "invalid_identifier")
    if len(production_id) > 8:
        assert production_id not in repr(row)


def test_a_path_the_router_cannot_match_is_a_404_before_the_handler_and_decides_nothing(lab):
    # The router's `.*` does not match a newline, so this is simply not the engagement route (as /nothing is not).
    response = lab.get("line\nbreak")
    assert response.status_code == 404
    assert (lab.clock.calls, lab.audit_rows()) == (0, [])


def test_missing_forbidden_revoked_and_expired_are_indistinguishable_to_the_client(lab):
    lab.revoke("vendor2")
    lab.clock.moment = SHORT_END
    responses = [
        lab.get(lab.alpha, "outsider-1"),  # exists, not engaged
        lab.get("f" * 32, "vendor-1"),  # does not exist
        lab.get(lab.bravo, "vendor-2"),  # revoked
        lab.get(lab.alpha, "short-1"),  # expired
        lab.get(lab.production("ALPHA-UPPER")),  # invalid
        lab.get(lab.bravo, "vendor-1"),  # engaged only under another issuer
    ]
    assert {observable(response) for response in responses} == {observable(responses[0])}
    assert responses[0].status_code == 403
    assert [row["reason"] for row in lab.audit_rows()] == [
        "no_engagement",
        "no_engagement",
        "engagement_revoked",
        "engagement_expired",
        "invalid_identifier",
        "no_engagement",
    ]


CLAIMS = [
    {"role": "coordinator"},
    {"roles": ["coordinator", "admin"]},
    {"scope": "manage_engagements engagements:read"},
    {"permissions": ["manage_engagements"]},
    {"is_admin": True, "groups": ["admins"]},
    {"engagement": {"role": "coordinator", "ends_at": "2099-01-01T00:00:00.000000Z"}},
]


@pytest.mark.parametrize("claims", CLAIMS, ids=lambda claims: ",".join(claims))
def test_token_claims_change_nothing_for_an_engaged_caller(lab, claims):
    response = lab.get(lab.alpha, productions=[lab.alpha, lab.bravo], **claims)
    assert response.json() == {"role": "vendor", "ends_at": "2026-12-03T12:00:00.000000Z"}
    generic(lab.get(lab.bravo, productions=[lab.alpha, lab.bravo], **claims), 403)


@pytest.mark.parametrize("claims", CLAIMS, ids=lambda claims: ",".join(claims))
def test_token_claims_grant_nothing_to_a_caller_without_an_engagement(lab, claims):
    generic(lab.get(lab.alpha, "outsider-1", productions=[lab.alpha], **claims), 403)
    generic(lab.get(lab.alpha, "never-provisioned", productions=[lab.alpha], **claims), 403)
    lab.revoke("vendor")
    generic(lab.get(lab.alpha, "vendor-1", productions=[lab.alpha], **claims), 403)


# --------------------------------------------------------------------------------- F-06: revocation, reference


def test_f06_the_same_valid_token_works_before_a_revocation_and_is_refused_after_it(lab):
    token = lab.token()
    settings = tokens.trusted_settings(lab.key)
    assert lab.get(lab.alpha, token=token).json()["role"] == "vendor"

    lab.revoke("vendor", at=T0 + timedelta(seconds=30))
    lab.clock.moment = T0 + timedelta(seconds=60)

    # The token is exactly as good as it was: it authenticates, it has not expired and it was not reissued.
    still_authentic = identity.authenticate(f"Bearer {token}", settings, FixedClock(lab.clock.moment))
    assert (still_authentic.issuer, still_authentic.subject) == (tokens.ISSUER, "vendor-1")
    generic(lab.get(lab.alpha, token=token), 403)
    assert [(row["action"], row["outcome"], row["reason"]) for row in lab.audit_rows()] == [
        ("engagement.viewed", "allowed", None),
        ("access.denied", "denied", "engagement_revoked"),
    ]


def test_f06_a_revocation_only_affects_the_revoked_engagement(lab):
    lab.revoke("vendor")
    generic(lab.get(lab.alpha, "vendor-1"), 403)
    assert lab.get(lab.alpha, "coordinator-1").status_code == 200
    assert lab.get(lab.bravo, "vendor-2").status_code == 200


# ------------------------------------------------------------------------------------------------------ time


@pytest.mark.parametrize(
    ("moment", "status"),
    [
        (SHORT_END - timedelta(microseconds=1), 200),
        (SHORT_END, 403),
        (SHORT_END + timedelta(microseconds=1), 403),
        (SHORT_END + timedelta(seconds=100), 403),
    ],
    ids=["one microsecond before", "exactly at the end", "one microsecond after", "long after"],
)
def test_an_engagement_ends_exactly_at_its_end_time(lab, moment, status):
    lab.clock.moment = moment
    assert lab.get(lab.alpha, "short-1").status_code == status


@pytest.mark.parametrize(
    ("offset", "status"),
    [(-1, 401), (0, 200), (299_999_999, 200), (300_000_000, 401), (300_000_001, 401)],
    ids=["a microsecond before it is valid", "from its start", "its last microsecond", "at its expiry", "after it"],
)
def test_token_expiry_is_judged_on_the_request_instant(lab, offset, status):
    lab.clock.moment = T0 + timedelta(microseconds=offset)
    assert lab.get(lab.alpha).status_code == status


OUTCOMES = {
    "success": lambda lab: lab.get(lab.alpha),
    "bad credentials": lambda lab: lab.get(lab.alpha, None),
    "no engagement": lambda lab: lab.get(lab.alpha, "outsider-1"),
    "invalid identifier": lambda lab: lab.get("NOT-AN-ID"),
}


@pytest.mark.parametrize("outcome", OUTCOMES)
def test_the_clock_is_read_exactly_once_per_handled_request(lab, outcome):
    lab.clock.step = timedelta(seconds=1)  # a second read would see a different instant
    OUTCOMES[outcome](lab)
    assert lab.clock.calls == 1
    [row] = lab.audit_rows()
    assert row["at"] == to_micros(T0)


def test_the_clock_is_read_after_the_writer_lock_is_taken_and_before_anything_is_decided(lab, spy):
    assert lab.get(lab.alpha).status_code == 200
    events = spy.events
    assert events[:2] == ["BEGIN IMMEDIATE", "CLOCK"]
    assert events[2].startswith("SELECT COALESCE(MAX(seq), 0) FROM audit_events")  # where the audit count starts
    assert events[3] == "AUTHENTICATE"
    assert events.count("CLOCK") == events.count("AUTHENTICATE") == events.count("BEGIN IMMEDIATE") == 1
    assert "FROM engagements" in events[4]
    assert events[5].startswith("INSERT INTO audit_events")
    assert events[6].startswith("SELECT COUNT(*) FROM audit_events WHERE seq > ")  # the count check, before the commit
    assert events[7:] == ["COMMIT"]


def test_a_failed_authentication_is_decided_after_the_lock_and_never_queries_engagements(lab, spy):
    assert lab.get(lab.alpha, None).status_code == 401
    assert [event.split(" ")[0] for event in spy.events] == [
        "BEGIN",
        "CLOCK",
        "SELECT",  # the audit count's starting point
        "AUTHENTICATE",
        "INSERT",
        "SELECT",  # the audit count
        "COMMIT",
    ]
    assert not any("FROM engagements" in event for event in spy.events)


def test_an_invalid_identifier_is_denied_without_querying_engagements(lab, spy):
    assert lab.get("NOT-AN-ID").status_code == 403
    assert [event.split(" ")[0] for event in spy.events] == [
        "BEGIN",
        "CLOCK",
        "SELECT",
        "AUTHENTICATE",
        "INSERT",
        "SELECT",
        "COMMIT",
    ]
    assert not any("FROM engagements" in event for event in spy.events)


def test_one_instant_is_shared_by_authentication_authorisation_and_the_audit_record(lab, spy):
    lab.clock.step = timedelta(seconds=1)
    assert lab.get(lab.alpha).status_code == 200
    [auth_clock], [audit_clock] = spy.auth_clocks, spy.audit_clocks
    assert auth_clock is audit_clock
    assert auth_clock is not lab.clock
    assert [auth_clock.now(), auth_clock.now()] == [T0, T0]  # the adapter answers; it does not read any clock
    assert lab.clock.calls == 1
    assert spy.decision_instants == [to_micros(T0)]


def test_the_connection_is_opened_in_the_thread_that_uses_it(lab, spy):
    assert lab.get(lab.alpha).status_code == 200
    assert spy.connect_threads and threading.get_ident() not in spy.connect_threads


def test_a_request_waiting_for_the_writer_lock_does_not_use_the_time_before_the_wait(lab, spy):
    with writer_lock(lab):
        request = Background(lambda: lab.get(lab.alpha, "short-1"))
        assert spy.begin_started.wait(THREAD_WAIT)  # the request is trying to take the lock
        assert lab.clock.calls == 0  # and has read no clock yet
        lab.clock.moment = SHORT_END  # time passes while it waits
    generic(request.join(), 403)  # at the pre-wait instant the engagement would still have been valid
    assert lab.clock.calls == 1
    assert lab.audit_rows() == [denial("short-1", lab.alpha, "engagement_expired", at=SHORT_END)]


def test_a_token_that_expires_while_the_request_waits_for_the_lock_is_refused(lab, spy):
    with writer_lock(lab):
        request = Background(lambda: lab.get(lab.alpha))
        assert spy.begin_started.wait(THREAD_WAIT)
        lab.clock.moment = T0 + timedelta(seconds=300)
    generic(request.join(), 401)
    assert [row["at"] for row in lab.audit_rows()] == [to_micros(T0 + timedelta(seconds=300))]


# ------------------------------------------------------------------------------- transactions and revocation


def test_a_revocation_committed_while_a_request_waits_is_seen_by_that_request(lab, spy):
    with writer_lock(lab) as holder:
        request = Background(lambda: lab.get(lab.alpha))
        assert spy.begin_started.wait(THREAD_WAIT)
        store.revoke_engagement(holder, FixedClock(T0), lab.engagements["vendor"])
    generic(request.join(), 403)  # a request that read the engagement before waiting would have said 200
    assert [row["reason"] for row in lab.audit_rows()] == ["engagement_revoked"]


def test_a_revocation_waits_for_a_request_that_already_holds_the_lock(lab):
    inside, release, revoking_started = threading.Event(), threading.Event(), threading.Event()

    def pause() -> None:
        inside.set()
        assert release.wait(THREAD_WAIT)

    def revoke() -> None:
        conn = REAL_CONNECT(lab.path)
        conn.set_trace_callback(lambda sql: revoking_started.set() if sql.startswith("BEGIN IMMEDIATE") else None)
        try:
            with store.transaction(conn):
                assert store.revoke_engagement(conn, FixedClock(T0), lab.engagements["vendor"])
        finally:
            conn.close()

    lab.clock.hooks.append(pause)
    request = Background(lambda: lab.get(lab.alpha))
    assert inside.wait(THREAD_WAIT)  # the request holds the writer lock and has just read its clock
    lab.clock.hooks.clear()
    revoking = Background(revoke)
    assert revoking_started.wait(THREAD_WAIT)
    assert revoking.running  # the revocation cannot commit while the request holds the lock
    release.set()
    assert request.join().status_code == 200  # the request ran entirely before the revocation
    revoking.join()
    generic(lab.get(lab.alpha), 403)  # and the next request after the commit sees it
    assert [row["action"] for row in lab.audit_rows()] == ["engagement.viewed", "access.denied"]


def test_a_request_that_cannot_get_the_lock_is_a_generic_503_that_decides_nothing(lab, spy, monkeypatch):
    monkeypatch.setattr(store, "BUSY_TIMEOUT_SECONDS", 0.05)
    authenticated = []
    real_authenticate = identity.authenticate
    monkeypatch.setattr(identity, "authenticate", lambda *args: authenticated.append(1) or real_authenticate(*args))
    with writer_lock(lab):
        for subject in ("vendor-1", "outsider-1", None):  # nothing is learned, whoever asks
            generic(lab.get(lab.alpha, subject), 503)
        assert spy.connections and all(is_closed(conn) for conn in spy.connections)
    assert authenticated == []  # no signature was verified before the lock was held
    assert lab.clock.calls == 0
    assert lab.audit_rows() == []
    assert lab.get(lab.alpha).status_code == 200  # and the same caller is served once the lock is free
    assert_released(lab, spy)


def test_a_database_that_cannot_be_opened_is_a_generic_500_without_the_path(tmp_path, caplog):
    missing = tmp_path / "does-not-exist.sqlite3"
    app = create_app(
        Dependencies(
            settings=tokens.trusted_settings(tokens.new_key()),
            clock=FixedClock(T0),
            database_path=missing,
            asset_root=tmp_path / "assets",
            quarantine_root=tmp_path / "quarantine",
            max_upload_bytes=1024,
            scanner=LabSyntheticMarkerScanner(),
        )
    )
    with TestClient(app) as client, caplog.at_level(logging.ERROR, logger=LOGGER):
        response = client.get(f"/productions/{'0' * 32}/engagement")
    generic(response, 500)
    assert str(tmp_path) not in response.text and "does-not-exist" not in response.text
    assert not missing.exists()  # the application never creates a database
    assert [record.name for record in caplog.records] == [LOGGER]


def test_a_database_with_a_different_schema_is_a_generic_500(lab):
    raw = sqlite3.connect(lab.path, isolation_level=None)
    try:
        raw.execute("CREATE TABLE unexpected (x)")
    finally:
        raw.close()
    response = lab.get(lab.alpha)
    generic(response, 500)
    assert "schema" not in response.text and "unexpected" not in response.text


# --------------------------------------------------------------------------- audit and commit failures


FAILING_OUTCOMES = {
    "a successful view": (lambda lab: lab.get(lab.alpha), ("vendor-1",)),
    "an authentication failure": (lambda lab: lab.get(lab.alpha, None), ()),
    "an authorisation failure": (lambda lab: lab.get(lab.alpha, "outsider-1"), ("outsider-1",)),
    "an invalid identifier": (lambda lab: lab.get("NOT-AN-ID"), ("vendor-1",)),
}


@pytest.mark.parametrize("outcome", FAILING_OUTCOMES)
def test_if_the_audit_record_cannot_be_written_nothing_is_decided(lab, spy, caplog, outcome):
    send, secrets = FAILING_OUTCOMES[outcome]
    lab.make_audit_inserts_fail()
    with caplog.at_level(logging.ERROR, logger=LOGGER):
        response = send(lab)
    generic(response, 500)
    assert response.headers.get("www-authenticate") is None
    for leaked in ("audit", "sqlite", "disk", "full", str(lab.path), "role", "ends_at", "vendor", *secrets):
        assert leaked not in response.text
    assert lab.audit_rows() == []
    assert_released(lab, spy)
    assert [record.name for record in caplog.records] == [LOGGER]
    assert caplog.records[0].exc_info is not None  # the failure is logged, not swallowed


def test_if_the_commit_fails_the_decision_is_not_returned(lab, spy, monkeypatch, caplog):
    monkeypatch.setattr(store, "transaction", transaction_whose_commit_fails)
    token = lab.token()
    with caplog.at_level(logging.ERROR, logger=LOGGER):
        for production, authorization in ((lab.alpha, token), ("NOT-AN-ID", token), (lab.alpha, "")):
            response = lab.client.get(f"/productions/{production}/engagement", headers={"Authorization": f"Bearer {authorization}"})
            generic(response, 500)
    assert lab.audit_rows() == []
    assert token not in caplog.text
    assert_released(lab, spy)


@pytest.mark.parametrize("outcome", ["success", "bad credentials", "no engagement"])
def test_the_connection_is_closed_and_nothing_is_left_open_on_every_path(lab, spy, outcome):
    OUTCOMES[outcome](lab)
    assert len(spy.connections) == 1
    assert_released(lab, spy)


def test_a_clock_that_fails_is_a_generic_500_with_nothing_committed(lab, spy):
    def explode() -> None:
        raise RuntimeError("clock unavailable")

    lab.clock.hooks.append(explode)
    generic(lab.get(lab.alpha), 500)
    assert lab.audit_rows() == []
    assert_released(lab, spy)


def test_a_clock_without_a_time_zone_is_a_generic_500(lab, spy):
    lab.clock.moment = datetime(2026, 11, 3, 12)  # naive
    generic(lab.get(lab.alpha), 500)
    assert lab.audit_rows() == []
    assert_released(lab, spy)


# ----------------------------------------------------------------------------------------------------- caching


def assert_no_store(response) -> None:
    assert response.headers.get_list("cache-control") == ["no-store"]  # one header, exactly this value


HANDLER_RESPONSES = {
    "200 a successful view": (lambda lab: lab.get(lab.alpha), 200),
    "401 no credentials": (lambda lab: lab.get(lab.alpha, None), 401),
    "401 an expired token": (lambda lab: lab.get(lab.alpha, token=BAD_CREDENTIALS["expired"](lab)[7:]), 401),
    "403 no engagement": (lambda lab: lab.get(lab.alpha, "outsider-1"), 403),
    "403 an invalid identifier": (lambda lab: lab.get("NOT-AN-ID"), 403),
    "403 revoked": (lambda lab: (lab.revoke("vendor"), lab.get(lab.alpha))[1], 403),
    "403 expired": (lambda lab: (setattr(lab.clock, "moment", SHORT_END), lab.get(lab.alpha, "short-1"))[1], 403),
}


@pytest.mark.parametrize("case", HANDLER_RESPONSES)
def test_successful_and_denied_responses_are_not_to_be_stored(lab, case):
    send, status = HANDLER_RESPONSES[case]
    response = send(lab)
    assert response.status_code == status
    assert_no_store(response)
    assert response.headers.get("www-authenticate") == ("Bearer" if status == 401 else None)  # the challenge is kept


def test_a_500_from_a_failed_audit_write_is_not_to_be_stored(lab):
    lab.make_audit_inserts_fail()
    response = lab.get(lab.alpha)
    generic(response, 500)
    assert_no_store(response)


def test_a_500_from_a_failed_commit_is_not_to_be_stored(lab, monkeypatch):
    monkeypatch.setattr(store, "transaction", transaction_whose_commit_fails)
    response = lab.get(lab.alpha)
    generic(response, 500)
    assert_no_store(response)


def test_a_500_from_an_unopenable_database_is_not_to_be_stored(tmp_path):
    app = create_app(
        Dependencies(
            settings=tokens.trusted_settings(tokens.new_key()),
            clock=FixedClock(T0),
            database_path=tmp_path / "does-not-exist.sqlite3",
            asset_root=tmp_path / "assets",
            quarantine_root=tmp_path / "quarantine",
            max_upload_bytes=1024,
            scanner=LabSyntheticMarkerScanner(),
        )
    )
    with TestClient(app) as client:
        response = client.get(f"/productions/{'0' * 32}/engagement")
    generic(response, 500)
    assert_no_store(response)


def test_a_503_from_a_busy_database_is_not_to_be_stored(lab, monkeypatch):
    monkeypatch.setattr(store, "BUSY_TIMEOUT_SECONDS", 0.05)
    with writer_lock(lab):
        response = lab.get(lab.alpha)
    generic(response, 503)
    assert_no_store(response)


def test_the_header_is_added_by_the_handler_and_not_to_the_frameworks_own_answers(lab):
    # An unmatched path and a wrong method are answered by the framework before the handler runs. They are outside the
    # handler's one-audit-event-per-decision guarantee, and they carry no header from this slice (no middleware).
    for response in (lab.get("line\nbreak"), lab.request("POST", lab.alpha), lab.client.get("/nothing")):
        assert response.status_code in {404, 405}
        assert "cache-control" not in response.headers
    assert lab.audit_rows() == []


# ------------------------------------------------------------------------------------- the shared request flow
# The management routes will give request_flow.handle() their own action and operation. These tests drive it directly
# with a stand-in operation, so that what a later endpoint relies on is checked here and not only through the GET.


class Calls:
    """A stand-in operation that remembers what it was given and, as every operation must, appends one audit event."""

    def __init__(self, decision=None, fail: Exception | None = None) -> None:
        self.contexts: list[request_flow.Context] = []
        self.seen: list[dict] = []
        self.decision = decision or request_flow.Decision(200, {"done": "yes"})
        self.fail = fail

    def __call__(self, ctx: request_flow.Context) -> request_flow.Decision:
        self.contexts.append(ctx)
        self.seen.append({"in_transaction": ctx.conn.in_transaction, "instants": [ctx.clock.now(), ctx.clock.now()]})
        if self.fail is not None:
            raise self.fail
        append_audit_events(ctx, 1)
        return self.decision


def run_flow(lab: Lab, operation, *, action=authz.Action.MANAGE_ENGAGEMENTS, subject="coordinator-1", **kwargs):
    token = lab.token(subject) if subject else None
    return request_flow.handle(
        tokens.trusted_settings(lab.key),
        lab.clock,
        lab.path,
        production_id=kwargs.pop("production_id", lab.alpha),
        authorization=f"Bearer {token}" if token else None,
        action=action,
        operation=operation,
    )


def test_the_flow_authorises_the_action_the_endpoint_names(lab):
    operation = Calls()
    assert run_flow(lab, operation, subject="coordinator-1").status_code == 200  # may manage engagements
    assert len(operation.contexts) == 1
    refused = run_flow(lab, operation, subject="vendor-1")  # a vendor may view its own engagement, not manage any
    assert refused.status_code == 403 and len(operation.contexts) == 1  # the operation did not run
    assert run_flow(lab, operation, action=authz.Action.VIEW_OWN_ENGAGEMENT, subject="vendor-1").status_code == 200
    denials = [row for row in lab.audit_rows() if row["action"] == "access.denied"]
    assert [(row["reason"], row["actor_subject"]) for row in denials] == [("role_not_permitted", "vendor-1")]
    assert len(lab.audit_rows()) == 3  # the operation's own event twice, and the flow's denial between them


@pytest.mark.parametrize("subject", [None, "outsider-1"], ids=["no credentials", "no engagement"])
def test_the_operation_never_runs_for_a_caller_who_failed_authentication_or_authorisation(lab, subject):
    operation = Calls()
    response = run_flow(lab, operation, subject=subject)
    assert response.status_code == (401 if subject is None else 403)
    assert operation.contexts == []
    assert len(lab.audit_rows()) == 1  # the flow recorded the denial itself


def test_the_operation_gets_the_open_transaction_the_caller_and_one_fixed_instant(lab):
    lab.clock.step = timedelta(seconds=1)
    operation = Calls()
    run_flow(lab, operation, subject="coordinator-1")
    [ctx], [seen] = operation.contexts, operation.seen
    assert seen["in_transaction"] is True  # the writer lock is held while it runs
    assert seen["instants"] == [T0, T0]  # the fixed instant, however often it is read
    assert lab.clock.calls == 1
    assert ctx.now_micros == to_micros(T0) and ctx.production_id == lab.alpha
    assert (ctx.caller.issuer, ctx.caller.subject) == (tokens.ISSUER, "coordinator-1")
    assert (ctx.grant.engagement_id, ctx.grant.role) == (lab.engagements["coordinator"], "coordinator")
    assert is_closed(ctx.conn)  # and the flow closed the connection when it was done


def test_an_operation_that_fails_rolls_back_the_whole_request_and_gives_a_generic_500(lab, caplog):
    def writes_then_fails(ctx):
        audit.record_event(
            ctx.conn, ctx.clock, audit.AuditAction.ENGAGEMENT_VIEWED, audit.Outcome.ALLOWED, actor=ctx.caller.as_actor()
        )
        raise RuntimeError("the operation failed after writing")

    with caplog.at_level(logging.ERROR, logger=LOGGER):
        response = run_flow(lab, writes_then_fails)
    assert response.status_code == 500 and response.body == b'{"detail":"Internal server error"}'
    assert lab.audit_rows() == []  # what the operation wrote went with the transaction
    assert [record.name for record in caplog.records] == [LOGGER] and caplog.records[0].exc_info is not None


def append_audit_events(ctx: request_flow.Context, times: int) -> None:
    for _ in range(times):
        audit.record_event(
            ctx.conn, ctx.clock, audit.AuditAction.ENGAGEMENT_VIEWED, audit.Outcome.ALLOWED, actor=ctx.caller.as_actor()
        )


@pytest.mark.parametrize("times", [0, 2, 3], ids=["none", "two", "three"])
def test_an_operation_that_appends_no_or_several_audit_events_is_rolled_back_with_a_generic_500(lab, spy, caplog, times):
    def revokes_and_audits_wrongly(ctx):
        store.revoke_engagement_in_production(ctx.conn, ctx.production_id, lab.engagements["vendor"], ctx.now_micros)
        append_audit_events(ctx, times)
        return request_flow.Decision(200, {"done": "yes"})

    before = lab.engagement_rows()
    with caplog.at_level(logging.ERROR, logger=LOGGER):
        response = run_flow(lab, revokes_and_audits_wrongly)
    assert response.status_code == 500 and response.body == b'{"detail":"Internal server error"}'
    assert response.headers["cache-control"] == "no-store"
    assert lab.audit_rows() == []  # the events it did append went with the rollback
    assert lab.engagement_rows() == before  # and so did the state change
    assert "ROLLBACK" in spy.events and "COMMIT" not in spy.events
    [record] = caplog.records
    assert record.exc_info[0] is request_flow.AuditCountError
    assert str(record.exc_info[1]) == f"a request must append exactly one audit event, found {times}"
    assert_released(lab, spy)


def test_an_operation_that_appends_exactly_one_audit_event_commits_with_its_change(lab, spy):
    def revokes_and_audits(ctx):
        store.revoke_engagement_in_production(ctx.conn, ctx.production_id, lab.engagements["vendor"], ctx.now_micros)
        append_audit_events(ctx, 1)
        return request_flow.Decision(200, {"done": "yes"})

    assert run_flow(lab, revokes_and_audits).status_code == 200
    assert len(lab.audit_rows()) == 1
    assert [row[6] for row in lab.engagement_rows() if row[0] == lab.engagements["vendor"]] == [to_micros(T0)]
    assert spy.events[-1] == "COMMIT" and "ROLLBACK" not in spy.events


def test_the_audit_count_ignores_events_from_earlier_requests(lab):
    assert lab.get(lab.alpha).status_code == 200  # an earlier request leaves one event behind

    def audits_once(ctx):
        append_audit_events(ctx, 1)
        return request_flow.Decision(200, {"done": "yes"})

    assert run_flow(lab, audits_once).status_code == 200  # counted from this request's own starting point
    assert len(lab.audit_rows()) == 2


def test_the_flow_adds_no_store_to_the_operations_answer_and_keeps_its_own_headers(lab):
    operation = Calls(request_flow.Decision(201, {"created": "yes"}, {"X-Example": "kept"}))
    response = run_flow(lab, operation)
    assert response.status_code == 201
    assert response.headers.getlist("cache-control") == ["no-store"] and response.headers["x-example"] == "kept"


# ------------------------------------------------------------------------- isolation and the application contract


def test_two_applications_share_no_state(make_lab):
    first, second = make_lab("first"), make_lab("second")
    token = first.token()
    assert first.get(first.alpha, token=token).status_code == 200
    # Another application has another key and another database: the same token and production mean nothing there.
    generic(second.get(first.alpha, token=token), 401)
    generic(second.get(first.alpha), 403)  # a valid token for second, but its database has no such production
    first.revoke("vendor")
    generic(first.get(first.alpha, token=token), 403)
    assert second.get(second.alpha).status_code == 200  # a revocation in one database does not reach the other
    assert [row["action"] for row in first.audit_rows()] == ["engagement.viewed", "access.denied"]
    assert [row["action"] for row in second.audit_rows()] == ["access.denied", "access.denied", "engagement.viewed"]


def test_the_application_registers_only_the_approved_routes_and_serves_no_documentation(lab):
    paths = {getattr(route, "path", None) for route in lab.app.routes}
    assert paths == {  # the GET, the two coordinator routes, the asset read and the two ingest routes (own test files)
        "/productions/{production_id:path}/engagement",
        "/productions/{production_id:path}/engagements",
        "/productions/{production_id:path}/engagements/{engagement_id:path}/revoke",
        "/productions/{production_id:path}/assets/{asset_id:path}",
        "/productions/{production_id:path}/deliveries",
        "/productions/{production_id:path}/deliveries/{delivery_id:path}/content",
        "/productions/{production_id:path}/deliveries/{delivery_id:path}/seal",
    }
    for path in ("/docs", "/redoc", "/openapi.json", "/"):
        assert lab.client.get(path).status_code == 404


def _source(module) -> ast.Module:
    return ast.parse(Path(inspect.getsourcefile(module)).read_text())


def _attributes(tree: ast.Module) -> list[str]:
    return [node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)]


def _imports(tree: ast.Module) -> set[str]:
    imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    return imports | {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}


TIME_SOURCES = {"utcnow", "today", "time", "time_ns", "monotonic", "perf_counter", "SystemClock"}


def test_the_endpoint_handler_is_the_one_registered_by_the_endpoint_module(lab):
    [route] = [route for route in lab.app.routes if getattr(route, "path", "").endswith("/engagement")]
    assert inspect.getsourcefile(route.endpoint) == inspect.getsourcefile(engagements)


def test_the_request_flow_reads_the_injected_clock_once_and_no_other_time_source():
    tree = _source(request_flow)
    attributes = _attributes(tree)
    assert attributes.count("now") == 1  # `clock.now()`; the per-request adapter's `def now` only returns its instant
    assert not TIME_SOURCES & set(attributes)
    assert not {"time", "os", "sys"} & _imports(tree)


# What only the shared flow may do, so that no endpoint can reorder, skip or repeat a step of it.
FLOW_ONLY = {"connect", "transaction", "authenticate", "authorize_engagement", "commit", "rollback", "execute", "close", "now"}


def test_the_endpoint_module_does_none_of_the_flow_itself():
    tree = _source(engagements)
    assert not FLOW_ONLY & set(_attributes(tree))
    assert not TIME_SOURCES & set(_attributes(tree))
    assert not {"time", "os", "sys", "sqlite3"} & _imports(tree)
    imported_names = {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) for alias in node.names}
    assert "request_flow" in imported_names  # it hands the request to the shared flow


def test_the_management_module_does_none_of_the_flow_itself_though_it_may_run_its_own_selects():
    tree = _source(management)
    assert not (FLOW_ONLY - {"execute"}) & set(_attributes(tree))  # it reads subjects and engagements through ctx.conn
    assert not TIME_SOURCES & set(_attributes(tree))
    assert not {"time", "os", "sys", "sqlite3"} & _imports(tree)
    imported_names = {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) for alias in node.names}
    assert "request_flow" in imported_names


@pytest.mark.parametrize(
    "module", [request_flow, engagements, management], ids=["request_flow", "engagements", "management"]
)
def test_the_module_keeps_no_mutable_global_state(module):
    tree = _source(module)
    assert not [node for node in ast.walk(tree) if isinstance(node, (ast.Global, ast.Nonlocal))]
    mutable = (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)
    module_level = [
        node.value for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None
    ]
    assert not [value for value in module_level if isinstance(value, mutable)]
