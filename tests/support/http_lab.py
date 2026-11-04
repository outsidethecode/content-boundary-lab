"""Test-only HTTP harness: the real application behind the TestClient, a SQLite file per test, ephemeral keys.

Everything is real except the clock and the keys: a FastAPI app, a SQLite file per test, ES256 tokens from ephemeral
keys, and an injected clock that counts its reads. Where a test needs an exact interleaving (a request waiting for the
writer lock while another commits) threads are coordinated with events, never with sleeps. Nothing under src/ imports
this module and it is not packaged.
"""

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient
from support import token_issuer as tokens

from content_boundary_lab import audit, authz, identity, store
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
                    ("coordinator2", tokens.ISSUER, "coordinator-2", self.bravo, "coordinator", LONG_END),
                    # the same subject text under another issuer is a different person
                    ("foreign", OTHER_ISSUER, "vendor-1", self.bravo, "vendor", LONG_END),
                    ("short", tokens.ISSUER, "short-1", self.alpha, "vendor", SHORT_END),
                    ("micro", tokens.ISSUER, "micro-1", self.alpha, "vendor", MICRO_END),
                ]:
                    subject_id = store.add_subject(conn, seeding, issuer, subject, subject)
                    self.engagements[key] = store.add_engagement(conn, seeding, subject_id, production, role, ends_at)
                store.add_subject(conn, seeding, tokens.ISSUER, "outsider-1", "Outsider")  # no engagement
                store.add_subject(conn, seeding, OTHER_ISSUER, "foreign-only", "Foreign")  # exists, but not for our issuer
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

    def send(self, method: str, path: str, *, subject=None, token=None, headers=None, content=None, json=None, **claims):
        """Any request to any path, with a valid token for `subject` (none if None) or exactly `token`."""
        sent = dict(headers or {})
        if token is None and subject is not None:
            token = self.token(subject, **claims)
        if token is not None:
            sent["Authorization"] = f"Bearer {token}"
        return self.client.request(method, path, headers=sent, content=content, json=json)

    def audit_rows(self) -> list[dict]:
        conn = REAL_CONNECT(self.path)
        try:
            return [dict(row) for row in conn.execute("SELECT * FROM audit_events ORDER BY seq")]
        finally:
            conn.close()

    def engagement_rows(self) -> list[tuple]:
        """Every engagement row exactly as stored, for before/after comparisons."""
        conn = REAL_CONNECT(self.path)
        try:
            query = "SELECT id, subject_id, production_id, role, created_at, ends_at, revoked_at FROM engagements ORDER BY id"
            return [tuple(row) for row in conn.execute(query)]
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
        self.begin_started = threading.Event()  # set when the first BEGIN IMMEDIATE starts
        self.begin_signals = [threading.Event() for _ in range(4)]  # signal i is set when the (i+1)th one starts
        self._begins = 0
        self._lock = threading.Lock()
        self.auth_clocks: list = []
        self.audit_clocks: list = []
        self.decision_instants: list[int] = []

    def note_begin(self) -> None:
        with self._lock:
            index, self._begins = self._begins, self._begins + 1
        self.begin_started.set()
        if index < len(self.begin_signals):
            self.begin_signals[index].set()


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

    def connect(path):
        conn = REAL_CONNECT(path)
        spy.connections.append(conn)
        spy.connect_threads.append(threading.get_ident())
        last: list[str] = []  # per connection, so that two requests' statements are never mistaken for repeats

        def trace(statement: str) -> None:
            if last and last[-1] == statement:
                return  # SQLite traces a statement again for each trigger it fires (the audit INSERT fires one)
            last[:] = [statement]
            spy.events.append(statement)
            if statement.startswith("BEGIN IMMEDIATE"):
                spy.note_begin()

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
