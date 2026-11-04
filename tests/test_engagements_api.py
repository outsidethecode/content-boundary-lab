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
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from support import token_issuer as tokens

from content_boundary_lab import audit, authz, engagements, identity, request_flow, store
from content_boundary_lab.app import Dependencies, create_app
from content_boundary_lab.clock import to_micros

UTC = timezone.utc
T0 = datetime(2026, 11, 3, 12, tzinfo=UTC)  # the instant the default test token becomes valid (tokens.NOW)
SEEDED_AT = T0 - timedelta(days=1)
LONG_END = T0 + timedelta(days=30)
SHORT_END = T0 + timedelta(seconds=100)  # inside the default token's five minutes of life
MICRO_END = LONG_END + timedelta(microseconds=123456)
OTHER_ISSUER = "https://other-issuer.example"
GENERIC = {
    401: {"detail": "Not authenticated"},
    403: {"detail": "Forbidden"},
    500: {"detail": "Internal server error"},
    503: {"detail": "Service unavailable"},
}
LOGGER = "content_boundary_lab.request_flow"  # failures are logged by the shared request flow
REAL_CONNECT = store.connect  # the tests' own connections must not go through the spy
THREAD_WAIT = 10


class FixedClock:
    def __init__(self, moment: datetime) -> None:
        self.moment = moment

    def now(self) -> datetime:
        return self.moment


class RecordingClock:
    """The application's injected clock: counts reads, can advance after each read and can run hooks inside one."""

    def __init__(self, moment: datetime) -> None:
        self.moment = moment
        self.step = timedelta(0)
        self.calls = 0
        self.hooks: list = []

    def now(self) -> datetime:
        self.calls += 1
        for hook in list(self.hooks):
            hook()
        moment = self.moment
        self.moment += self.step
        return moment


class Background:
    """Run a callable in a thread and collect its result; a failure in the thread is re-raised by join()."""

    def __init__(self, target) -> None:
        self.result = None
        self.error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, args=(target,), daemon=True)
        self._thread.start()

    def _run(self, target) -> None:
        try:
            self.result = target()
        except BaseException as error:  # reported to the test by join()
            self.error = error

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    def join(self):
        self._thread.join(THREAD_WAIT)
        assert not self._thread.is_alive(), "the background work did not finish"
        if self.error is not None:
            raise self.error
        return self.result


class Lab:
    """One application, its database and its trusted key, with a small cast of subjects and engagements."""

    def __init__(self, directory: Path, name: str = "lab") -> None:
        self.path = directory / f"{name}.sqlite3"
        self.key = tokens.new_key("key-1")
        self.clock = RecordingClock(T0)
        self.engagements: dict[str, str] = {}
        store.initialise_schema(self.path)
        self._seed()
        self.app = create_app(
            Dependencies(settings=tokens.trusted_settings(self.key), clock=self.clock, database_path=self.path)
        )
        self.client = TestClient(self.app)

    def _seed(self) -> None:
        seeding = FixedClock(SEEDED_AT)
        conn = REAL_CONNECT(self.path)
        try:
            with store.transaction(conn):
                self.alpha = store.add_production(conn, seeding, "ALPHA")
                self.bravo = store.add_production(conn, seeding, "BRAVO")
                for key, issuer, subject, production, role, ends_at in [
                    ("vendor", tokens.ISSUER, "vendor-1", self.alpha, "vendor", LONG_END),
                    ("coordinator", tokens.ISSUER, "coordinator-1", self.alpha, "coordinator", LONG_END),
                    ("vendor2", tokens.ISSUER, "vendor-2", self.bravo, "vendor", LONG_END),
                    # the same subject text under another issuer is a different person
                    ("foreign", OTHER_ISSUER, "vendor-1", self.bravo, "vendor", LONG_END),
                    ("short", tokens.ISSUER, "short-1", self.alpha, "vendor", SHORT_END),
                    ("micro", tokens.ISSUER, "micro-1", self.alpha, "vendor", MICRO_END),
                ]:
                    subject_id = store.add_subject(conn, seeding, issuer, subject, subject)
                    self.engagements[key] = store.add_engagement(conn, seeding, subject_id, production, role, ends_at)
                store.add_subject(conn, seeding, tokens.ISSUER, "outsider-1", "Outsider")  # no engagement
        finally:
            conn.close()

    def production(self, name: str) -> str:
        """A production id, or a derived invalid form of a real one, or the text itself."""
        derived = {
            "alpha": self.alpha,
            "bravo": self.bravo,
            "ALPHA-UPPER": self.alpha.upper(),
            "ALPHA-SHORT": self.alpha[:-1],
            "ALPHA-LONG": self.alpha + "0",
            "ALPHA-SPACED": " " + self.alpha,
            "ALPHA-INJECTED": self.alpha + "' OR '1'='1",
        }
        return derived.get(name, name)

    def token(self, subject: str = "vendor-1", **claims) -> str:
        return tokens.mint(self.key, **{"sub": subject, **claims})

    def request(self, method: str, production: str, *, headers=None, params=None):
        url = f"/productions/{quote(production, safe='')}/engagement"
        return self.client.request(method, url, headers=headers, params=params)

    def get(self, production: str, subject: str | None = "vendor-1", *, token=None, headers=None, params=None, **claims):
        """GET with a valid token for `subject` (none if subject is None), or with exactly `token`."""
        sent = dict(headers or {})
        if token is None and subject is not None:
            token = self.token(subject, **claims)
        if token is not None:
            sent["Authorization"] = f"Bearer {token}"
        return self.request("GET", production, headers=sent, params=params)

    def audit_rows(self) -> list[dict]:
        conn = REAL_CONNECT(self.path)
        try:
            return [dict(row) for row in conn.execute("SELECT * FROM audit_events ORDER BY seq")]
        finally:
            conn.close()

    def revoke(self, key: str, at: datetime = T0 + timedelta(seconds=1)) -> None:
        conn = REAL_CONNECT(self.path)
        try:
            with store.transaction(conn):
                assert store.revoke_engagement(conn, FixedClock(at), self.engagements[key])
        finally:
            conn.close()

    def make_audit_inserts_fail(self) -> None:
        """The next audit insert hits the end of the AUTOINCREMENT range, a real SQLite failure, without any schema change."""
        raw = sqlite3.connect(self.path, isolation_level=None)
        try:
            raw.execute("DELETE FROM sqlite_sequence WHERE name = 'audit_events'")
            raw.execute("INSERT INTO sqlite_sequence (name, seq) VALUES ('audit_events', 9223372036854775807)")
        finally:
            raw.close()


class Spy:
    """What the handler did, in order: SQL statements (traced), clock reads, authentication, the clocks it passed on."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.connections: list[sqlite3.Connection] = []
        self.connect_threads: list[int] = []
        self.begin_started = threading.Event()
        self.auth_clocks: list = []
        self.audit_clocks: list = []
        self.decision_instants: list[int] = []


@pytest.fixture
def make_lab(tmp_path):
    labs: list[Lab] = []

    def make(name: str = "lab") -> Lab:
        labs.append(Lab(tmp_path, name))
        return labs[-1]

    yield make
    for lab in labs:
        lab.client.close()


@pytest.fixture
def lab(make_lab) -> Lab:
    return make_lab()


@pytest.fixture
def spy(lab, monkeypatch) -> Spy:
    spy = Spy()
    real_authenticate, real_authorize, real_record = identity.authenticate, authz.authorize_engagement, audit.record_event

    def trace(statement: str) -> None:
        if spy.events and spy.events[-1] == statement:
            return  # SQLite traces a statement again for each trigger it fires (the audit INSERT fires one)
        spy.events.append(statement)
        if statement.startswith("BEGIN IMMEDIATE"):
            spy.begin_started.set()

    def connect(path):
        conn = REAL_CONNECT(path)
        spy.connections.append(conn)
        spy.connect_threads.append(threading.get_ident())
        conn.set_trace_callback(trace)
        return conn

    def authenticate(authorization, settings, clock):
        spy.events.append("AUTHENTICATE")
        spy.auth_clocks.append(clock)
        return real_authenticate(authorization, settings, clock)

    def authorize(conn, who, production_id, action, now_micros):
        spy.decision_instants.append(now_micros)
        return real_authorize(conn, who, production_id, action, now_micros)

    def record(conn, clock, *args, **kwargs):
        spy.audit_clocks.append(clock)
        return real_record(conn, clock, *args, **kwargs)

    lab.clock.hooks.append(lambda: spy.events.append("CLOCK"))
    monkeypatch.setattr(store, "connect", connect)
    monkeypatch.setattr(identity, "authenticate", authenticate)
    monkeypatch.setattr(authz, "authorize_engagement", authorize)
    monkeypatch.setattr(audit, "record_event", record)
    return spy


def generic(response, status: int) -> None:
    assert response.status_code == status
    assert response.json() == GENERIC[status]


def observable(response) -> tuple:
    """Everything a client can see of a response."""
    return (response.status_code, tuple(sorted(response.headers.items())), response.content)


def is_closed(conn: sqlite3.Connection) -> bool:
    try:
        conn.execute("SELECT 1")
    except sqlite3.ProgrammingError:
        return True
    return False


def assert_released(lab: Lab, spy: Spy) -> None:
    """Every connection the handler opened is closed and no write transaction is left open."""
    assert spy.connections and all(is_closed(conn) for conn in spy.connections)
    probe = sqlite3.connect(lab.path, timeout=0, isolation_level=None)
    try:
        probe.execute("BEGIN IMMEDIATE")  # raises "database is locked" if a transaction were still open
        probe.execute("ROLLBACK")
    finally:
        probe.close()


@contextmanager
def transaction_whose_commit_fails(conn: sqlite3.Connection):
    """A stand-in for store.transaction() whose COMMIT fails: nothing is made durable and the error propagates."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    conn.rollback()
    raise sqlite3.OperationalError("disk I/O error")


@contextmanager
def writer_lock(lab: Lab):
    holder = REAL_CONNECT(lab.path)
    try:
        with store.transaction(holder):
            yield holder
    finally:
        holder.close()


def denial(subject: str, production_id: str | None, reason: str, *, at: datetime = T0) -> dict:
    return {
        "seq": 1,
        "at": to_micros(at),
        "actor_issuer": tokens.ISSUER,
        "actor_subject": subject,
        "action": "access.denied",
        "outcome": "denied",
        "production_id": production_id,
        "object_type": None,
        "object_id": None,
        "reason": reason,
    }


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
    assert events[:3] == ["BEGIN IMMEDIATE", "CLOCK", "AUTHENTICATE"]
    assert events.count("CLOCK") == events.count("AUTHENTICATE") == events.count("BEGIN IMMEDIATE") == 1
    assert "FROM engagements" in events[3]
    assert events[4].startswith("INSERT INTO audit_events")
    assert events[5:] == ["COMMIT"]


def test_a_failed_authentication_is_decided_after_the_lock_and_never_queries_engagements(lab, spy):
    assert lab.get(lab.alpha, None).status_code == 401
    assert [event.split(" ")[0] for event in spy.events] == ["BEGIN", "CLOCK", "AUTHENTICATE", "INSERT", "COMMIT"]


def test_an_invalid_identifier_is_denied_without_querying_engagements(lab, spy):
    assert lab.get("NOT-AN-ID").status_code == 403
    assert [event.split(" ")[0] for event in spy.events] == ["BEGIN", "CLOCK", "AUTHENTICATE", "INSERT", "COMMIT"]


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
    app = create_app(Dependencies(settings=tokens.trusted_settings(tokens.new_key()), clock=FixedClock(T0), database_path=missing))
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
    """A stand-in operation that remembers what it was given, and records no audit event of its own."""

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
    assert [row["reason"] for row in lab.audit_rows()] == ["role_not_permitted"]
    assert lab.audit_rows()[0]["actor_subject"] == "vendor-1"


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


def test_the_application_registers_only_the_engagement_route_and_serves_no_documentation(lab):
    paths = {getattr(route, "path", None) for route in lab.app.routes}
    assert paths == {"/productions/{production_id:path}/engagement"}
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


@pytest.mark.parametrize("module", [request_flow, engagements], ids=["request_flow", "engagements"])
def test_the_module_keeps_no_mutable_global_state(module):
    tree = _source(module)
    assert not [node for node in ast.walk(tree) if isinstance(node, (ast.Global, ast.Nonlocal))]
    mutable = (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.DictComp, ast.SetComp)
    module_level = [
        node.value for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None
    ]
    assert not [value for value in module_level if isinstance(value, mutable)]
