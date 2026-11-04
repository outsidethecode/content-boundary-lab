"""Test-only HTTP harness: the real application behind the TestClient, a SQLite file per test, ephemeral keys.

Everything is real except the clock and the keys: a FastAPI app, a SQLite file per test, ES256 tokens from ephemeral
keys, and an injected clock that counts its reads. Where a test needs an exact interleaving (a request waiting for the
writer lock while another commits) threads are coordinated with events, never with sleeps. Nothing under src/ imports
this module and it is not packaged.
"""

import asyncio
import contextlib
import hashlib
import inspect
import os
import sqlite3
import stat
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
UPLOAD_LIMIT = 64 * 1024  # the harness application's cap on upload bytes; small, so that tests can exceed it cheaply
DELIVERY = {  # a valid initiation body; the declared hash is deliberately not the hash of any test content
    "display_name": "shot-010.mov",
    "declared_size": 2500,
    "declared_sha256": "c" * 64,
    "declared_media_type": "video/quicktime",
}
# One valid route from INITIATED to every lifecycle state (Addendum §5.2), for seeding deliveries in a given state.
STATE_ROUTES = {
    "INITIATED": (),
    "UPLOADED": ("UPLOADED",),
    "SEALING": ("UPLOADED", "SEALING"),
    "REJECTED": ("UPLOADED", "SEALING", "REJECTED"),
    "SCAN_FAILED": ("UPLOADED", "SEALING", "SCAN_FAILED"),
    "SCAN_PASSED": ("UPLOADED", "SEALING", "SCAN_PASSED"),
    "ACCEPTED": ("UPLOADED", "SEALING", "SCAN_PASSED", "ACCEPTED"),
    "PROMOTING": ("UPLOADED", "SEALING", "SCAN_PASSED", "ACCEPTED", "PROMOTING"),
    "PROMOTED": ("UPLOADED", "SEALING", "SCAN_PASSED", "ACCEPTED", "PROMOTING", "PROMOTED"),
    "INTEGRITY_FAILED": ("UPLOADED", "SEALING", "INTEGRITY_FAILED"),
}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


OCCUPANTS = ["a regular file", "a dangling symlink", "a symlink to a file outside", "a directory", "a named pipe"]


def occupy(entry: Path, outside: Path, kind: str):
    """Put something at `entry` and return a function that describes it exactly, to prove that it was not touched.

    The description is the kind of entry, its inode, and its content or link target (never read from a pipe).
    `outside` is a directory for the file that a symlink points at.
    """
    if kind == "a regular file":
        entry.write_bytes(b"an unexpected file that was already here")
    elif kind == "a dangling symlink":
        entry.symlink_to(outside / "nowhere")
    elif kind == "a symlink to a file outside":
        (outside / "secret.txt").write_bytes(b"outside the quarantine root")
        entry.symlink_to(outside / "secret.txt")
    elif kind == "a directory":
        entry.mkdir()
    elif kind == "a named pipe":
        os.mkfifo(entry)
    else:
        raise ValueError(kind)

    def describe():
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode):
            content = os.readlink(entry)
        elif stat.S_ISREG(info.st_mode):
            content = entry.read_bytes()
        else:
            content = None
        return stat.S_IFMT(info.st_mode), info.st_ino, content

    return describe


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
        self.asset_root = directory / f"{name}-trusted"  # the trusted asset root: one file per asset, named by its id
        self.quarantine_root = directory / f"{name}-quarantine"  # configured as the ingest root; nothing serves from it
        self.asset_root.mkdir()
        self.quarantine_root.mkdir()
        self.key = tokens.new_key("key-1")
        self.clock = RecordingClock(T0)
        self.engagements: dict[str, str] = {}
        self.assets: dict[str, str] = {}  # asset ids by short name
        self.asset_content: dict[str, bytes] = {}  # the synthetic bytes of each
        store.initialise_schema(self.path)
        self._seed()
        self.app = create_app(
            Dependencies(
                settings=tokens.trusted_settings(self.key),
                clock=self.clock,
                database_path=self.path,
                asset_root=self.asset_root,
                quarantine_root=self.quarantine_root,
                max_upload_bytes=UPLOAD_LIMIT,
            )
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
                dual = store.add_subject(conn, seeding, tokens.ISSUER, "dual-1", "Dual")  # a vendor on both productions
                self.engagements["dual_alpha"] = store.add_engagement(conn, seeding, dual, self.alpha, "vendor", LONG_END)
                self.engagements["dual_bravo"] = store.add_engagement(conn, seeding, dual, self.bravo, "vendor", LONG_END)
                for short, production, display_name in (
                    ("alpha", self.alpha, "alpha-reference.mov"),
                    ("alpha_two", self.alpha, "alpha-two.wav"),
                    ("bravo", self.bravo, "bravo-unreleased.mov"),
                ):
                    self.assets[short] = store.add_asset(conn, seeding, production, display_name)
        finally:
            conn.close()
        for short, asset_id in self.assets.items():  # synthetic bytes, different for every asset
            self.asset_content[short] = f"synthetic content of {short}\n".encode() * 4000
            (self.asset_root / asset_id).write_bytes(self.asset_content[short])

    def add_asset(self, production: str, display_name: str, content: bytes | None = b"synthetic\n" * 100) -> str:
        """A new asset row, and (unless content is None) its bytes under the trusted root."""
        conn = REAL_CONNECT(self.path)
        try:
            with store.transaction(conn):
                asset_id = store.add_asset(conn, FixedClock(SEEDED_AT), production, display_name)
        finally:
            conn.close()
        if content is not None:
            (self.asset_root / asset_id).write_bytes(content)
        return asset_id

    # --- deliveries (M1H) -----------------------------------------------------------------------------------------

    def deliveries_path(self, production: str | None = None) -> str:
        return f"/productions/{quote(production or self.alpha, safe='')}/deliveries"

    def content_path(self, delivery_id: str, production: str | None = None) -> str:
        return f"{self.deliveries_path(production)}/{quote(delivery_id, safe='')}/content"

    def initiate(self, subject: str | None = "vendor-1", production: str | None = None, *, fields=None, **options):
        """POST a valid initiation (DELIVERY, with `fields` replacing members) as `subject`."""
        return self.send("POST", self.deliveries_path(production), subject=subject, json={**DELIVERY, **(fields or {})}, **options)

    def new_delivery(self, subject: str = "vendor-1", production: str | None = None, **fields) -> str:
        response = self.initiate(subject, production, fields=fields)
        assert response.status_code == 201, response.text
        return response.json()["delivery_id"]

    def upload(self, delivery_id: str, content=b"", subject: str | None = "vendor-1", production: str | None = None, **options):
        return self.send("PUT", self.content_path(delivery_id, production), subject=subject, content=content, **options)

    def upload_client(self, delivery_id, chunks, *, subject="vendor-1", token=None, production=None, then="complete", length=None, **kwargs):
        """A scripted ASGI peer that PUTs `chunks` (bytes, or callables run between chunks) and then `then`.

        `length` is the Content-Length it claims (a str is sent as it is, to claim nonsense); no credentials are sent if
        `subject` and `token` are both None.
        """
        headers = []
        if token is None and subject is not None:
            token = self.token(subject)
        if token is not None:
            headers.append((b"authorization", f"Bearer {token}".encode()))
        if length is not None:
            headers.append((b"content-length", str(length).encode()))
        return Client(method="PUT", path=self.content_path(delivery_id, production), headers=headers, inbound=list(chunks), then=then, **kwargs)

    def delivery_rows(self) -> list[dict]:
        conn = REAL_CONNECT(self.path)
        try:
            return [dict(row) for row in conn.execute("SELECT * FROM deliveries ORDER BY rowid")]
        finally:
            conn.close()

    def delivery_row(self, delivery_id: str) -> dict:
        (row,) = [row for row in self.delivery_rows() if row["id"] == delivery_id]
        return row

    def seed_delivery(self, subject: str = "vendor-1", production: str | None = None, state: str = "INITIATED", **fields):
        """A delivery row made directly in the store (not through the API), moved to `state` by valid steps only."""
        values = {**DELIVERY, **fields}
        conn = REAL_CONNECT(self.path)
        try:
            with store.transaction(conn):
                owner = conn.execute("SELECT id FROM subjects WHERE issuer = ? AND subject = ?", (tokens.ISSUER, subject)).fetchone()[0]
                created = store.add_delivery(conn, FixedClock(SEEDED_AT), production or self.alpha, owner, values["display_name"], values["declared_size"], values["declared_sha256"], values["declared_media_type"])
                for step in STATE_ROUTES[state]:
                    conn.execute(
                        "UPDATE deliveries SET state = ?, received_size = 7, received_sha256 = ?, uploaded_at = ? WHERE id = ?",
                        (step, "d" * 64, to_micros(SEEDED_AT), created.id),
                    )
        finally:
            conn.close()
        return created

    def quarantine_names(self) -> list[str]:
        """Every entry directly in the quarantine root except the staging directory."""
        return sorted(entry.name for entry in self.quarantine_root.iterdir() if entry.name != ".incoming")

    def incoming_names(self) -> list[str]:
        staging = self.quarantine_root / ".incoming"
        return sorted(entry.name for entry in staging.iterdir()) if staging.is_dir() else []

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


class Client:
    """A scripted ASGI peer: what it receives, how it fails, and what the server sent. Drives a response or a whole app."""

    def __init__(self, *, path="/", headers=(), method="GET", disconnect=False, delay=0.0, fail_at=None, block_at=None, on_chunk=None, inbound=None, then="complete") -> None:
        self.messages: list[dict] = []
        self.disconnect, self.delay, self.fail_at, self.block_at, self.on_chunk = disconnect, delay, fail_at, block_at, on_chunk
        # A request body for an upload: bytes are sent as chunks, a callable is run (and awaited if it returns an awaitable)
        # between chunks, and `then` says how the body ends: "complete", "disconnect" or "hang".
        self.inbound = None if inbound is None else list(inbound)
        self.then = then
        self.delivered = 0  # how many chunks the application has asked for and been given
        self.scope = {
            "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1", "method": method,
            "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"", "root_path": "",
            "headers": list(headers), "client": ("testclient", 50000), "server": ("testserver", 80),
        }  # fmt: skip
        self.chunks = 0

    async def receive(self):
        if self.inbound is not None:
            while self.inbound:
                item = self.inbound.pop(0)
                if callable(item):
                    outcome = item()
                    if inspect.isawaitable(outcome):
                        await outcome
                    continue
                self.delivered += 1
                return {"type": "http.request", "body": item, "more_body": True}
            if self.then == "complete":
                return {"type": "http.request", "body": b"", "more_body": False}
            if self.then == "disconnect":
                return {"type": "http.disconnect"}
        if self.disconnect:
            return {"type": "http.disconnect"}
        await asyncio.sleep(3600)

    async def send(self, message):
        self.messages.append(message)
        if self.delay:
            await asyncio.sleep(self.delay)
        if message["type"] == "http.response.start":
            if self.fail_at == "start":
                raise OSError("the client went away before the first byte")
            if self.block_at == "start":
                await asyncio.sleep(3600)
        elif message.get("body"):
            self.chunks += 1
            if self.on_chunk:
                self.on_chunk(self.chunks)
            if self.fail_at == f"chunk{self.chunks}":
                raise OSError("the client went away mid-stream")
            if self.block_at == f"chunk{self.chunks}":
                await asyncio.sleep(3600)

    @property
    def status(self):
        return next((m["status"] for m in self.messages if m["type"] == "http.response.start"), None)

    @property
    def headers(self) -> dict[str, str]:
        start = next(m for m in self.messages if m["type"] == "http.response.start")
        return {name.decode(): value.decode() for name, value in start["headers"]}

    @property
    def body(self) -> bytes:
        return b"".join(m.get("body", b"") for m in self.messages if m["type"] == "http.response.body")


def play(target, client: Client, *, expect=None):
    """Call `target` (a response, or a whole application) as ASGI. `expect` is the exception the server should see."""
    if expect is None:
        asyncio.run(target(client.scope, client.receive, client.send))
    else:
        with pytest.raises(expect):
            asyncio.run(target(client.scope, client.receive, client.send))


def play_together(target, *clients: Client) -> None:
    """Run several scripted peers against one application at once, in one event loop."""

    async def main():
        # A peer that waits for another that never moves must fail the test, not hang the suite.
        await asyncio.wait_for(asyncio.gather(*(target(client.scope, client.receive, client.send) for client in clients)), THREAD_WAIT)

    asyncio.run(main())


def play_and_cancel(target, client: Client, until=None):
    """Cancel the ASGI call once the client has begun to block, as a server does when a connection is dropped.

    "Begun to block" is, by default, that the server has sent something; `until(client)` says it otherwise (for example
    that an upload has been given its first chunk).
    """

    async def main():
        task = asyncio.ensure_future(target(client.scope, client.receive, client.send))
        while not (until(client) if until else client.messages):
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    asyncio.run(main())


def assert_one_start_and_no_replacement(client: Client) -> None:
    assert [m["type"] for m in client.messages].count("http.response.start") <= 1
    assert all(m["status"] == 200 for m in client.messages if m["type"] == "http.response.start")  # never a replacement 500


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
