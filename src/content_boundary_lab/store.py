"""SQLite data foundation: schema, connections and transactions (stdlib sqlite3 only).

The engagements table is the server-side authority for roles, expiry and revocation, but this module makes no
authorisation decisions (M1F). connect() is the one way application code gets a connection: it refuses a schema that
differs from the one initialise_schema() creates and installs a default-deny authorizer. Both are described, with
their limits, in docs/decisions.md (AM-13).
"""

import re
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal, NamedTuple

from content_boundary_lab.clock import Clock, to_micros

SCHEMA_VERSION = 1
MINIMUM_SQLITE = (3, 37, 0)  # STRICT tables
BUSY_TIMEOUT_SECONDS = 5.0  # lab assumption: how long a connection waits for a lock before "database is locked"

Role = Literal["coordinator", "vendor"]


class StoreError(RuntimeError):
    """The database or SQLite cannot be used as configured."""


class SchemaVersionError(StoreError):
    """The database does not have the supported schema version."""


class SchemaIntegrityError(StoreError):
    """The database schema is not the one this version of the code creates: objects are missing, added or modified."""


class DeliveryState(StrEnum):
    """The delivery lifecycle of the M0 addendum (§5.2), in its order. Only the deliveries table holds one.

    M1H moves a delivery from INITIATED to UPLOADED. The rest are the later milestones' (seal, trust gate, acceptance,
    promotion), listed here so that the database already refuses any state or step the design does not have.
    """

    INITIATED = "INITIATED"
    UPLOADED = "UPLOADED"
    SEALING = "SEALING"
    REJECTED = "REJECTED"
    SCAN_FAILED = "SCAN_FAILED"
    SCAN_PASSED = "SCAN_PASSED"
    ACCEPTED = "ACCEPTED"
    PROMOTING = "PROMOTING"
    PROMOTED = "PROMOTED"
    INTEGRITY_FAILED = "INTEGRITY_FAILED"


_S = DeliveryState
# Every change of state the design allows. PROMOTING -> PROMOTING (reconcile after a crash) leaves the state as it is.
DELIVERY_TRANSITIONS: frozenset[tuple[DeliveryState, DeliveryState]] = frozenset(
    {
        (_S.INITIATED, _S.UPLOADED),
        (_S.UPLOADED, _S.SEALING),
        (_S.SEALING, _S.REJECTED),
        (_S.SEALING, _S.SCAN_FAILED),
        (_S.SEALING, _S.SCAN_PASSED),
        (_S.SEALING, _S.INTEGRITY_FAILED),
        (_S.SCAN_FAILED, _S.SEALING),
        (_S.SCAN_PASSED, _S.SEALING),
        (_S.SCAN_PASSED, _S.ACCEPTED),
        (_S.ACCEPTED, _S.PROMOTING),
        (_S.PROMOTING, _S.PROMOTED),
        (_S.PROMOTING, _S.INTEGRITY_FAILED),
    }
)


# One complete initial schema, applied in one transaction by initialise_schema(). Times are INTEGER microseconds
# since the Unix epoch, UTC. There are no migrations: any other schema version is refused.
_SCHEMA: tuple[str, ...] = (
    """CREATE TABLE productions (
        id TEXT NOT NULL PRIMARY KEY CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
        name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
        created_at INTEGER NOT NULL
    ) STRICT""",
    """CREATE TABLE subjects (
        id INTEGER PRIMARY KEY,
        issuer TEXT NOT NULL CHECK (length(issuer) BETWEEN 1 AND 512),
        subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
        display_name TEXT NOT NULL CHECK (length(display_name) <= 200),
        created_at INTEGER NOT NULL,
        UNIQUE (issuer, subject)
    ) STRICT""",
    """CREATE TABLE engagements (
        id TEXT NOT NULL PRIMARY KEY CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
        subject_id INTEGER NOT NULL REFERENCES subjects (id) ON DELETE RESTRICT,
        production_id TEXT NOT NULL REFERENCES productions (id) ON DELETE RESTRICT,
        role TEXT NOT NULL CHECK (role IN ('coordinator', 'vendor')),
        created_at INTEGER NOT NULL,
        ends_at INTEGER NOT NULL,
        revoked_at INTEGER,
        UNIQUE (subject_id, production_id),
        CHECK (ends_at > created_at),
        CHECK (revoked_at IS NULL OR revoked_at >= created_at)
    ) STRICT""",
    """CREATE TABLE assets (
        id TEXT NOT NULL PRIMARY KEY CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
        production_id TEXT NOT NULL REFERENCES productions (id) ON DELETE RESTRICT,
        display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
        created_at INTEGER NOT NULL
    ) STRICT""",
    "CREATE INDEX assets_by_production ON assets (production_id)",
    # A delivery is one vendor's declaration of bytes to be sent (M0 §2). It is owned by the subject that made it, in
    # one production, and its lifecycle state lives here and nowhere else (assets have no state). The storage key is
    # the server's own name for the quarantined bytes: never shown to a client, never derived from anything it sent.
    # The declared_* columns are the client's claims, kept for later consistency checks and display; the received_*
    # columns are what the server measured while the bytes arrived, written once with the move to UPLOADED. The state
    # list and the transition pairs below are Addendum §5.2, written out again and checked by tests/test_delivery_store.py.
    """CREATE TABLE deliveries (
        id TEXT NOT NULL PRIMARY KEY CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
        production_id TEXT NOT NULL REFERENCES productions (id) ON DELETE RESTRICT,
        owner_subject_id INTEGER NOT NULL REFERENCES subjects (id) ON DELETE RESTRICT,
        storage_key TEXT NOT NULL UNIQUE CHECK (length(storage_key) = 32 AND storage_key NOT GLOB '*[^0-9a-f]*'),
        display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
        declared_size INTEGER NOT NULL CHECK (declared_size >= 0),
        declared_sha256 TEXT NOT NULL CHECK (length(declared_sha256) = 64 AND declared_sha256 NOT GLOB '*[^0-9a-f]*'),
        declared_media_type TEXT NOT NULL CHECK (length(declared_media_type) BETWEEN 1 AND 255),
        state TEXT NOT NULL CHECK (state IN (
            'INITIATED', 'UPLOADED', 'SEALING', 'REJECTED', 'SCAN_FAILED',
            'SCAN_PASSED', 'ACCEPTED', 'PROMOTING', 'PROMOTED', 'INTEGRITY_FAILED'
        )),
        created_at INTEGER NOT NULL,
        uploaded_at INTEGER,
        received_size INTEGER CHECK (received_size >= 0),
        received_sha256 TEXT CHECK (length(received_sha256) = 64 AND received_sha256 NOT GLOB '*[^0-9a-f]*'),
        sealed_size INTEGER CHECK (sealed_size >= 0),
        sealed_sha256 TEXT CHECK (length(sealed_sha256) = 64 AND sealed_sha256 NOT GLOB '*[^0-9a-f]*'),
        receipt_matched INTEGER CHECK (receipt_matched IN (0, 1)),
        state_reason TEXT,
        verdict_id TEXT REFERENCES verdicts (id) ON DELETE RESTRICT,
        CHECK ((state = 'INITIATED') = (received_sha256 IS NULL)),
        CHECK ((received_sha256 IS NULL) = (received_size IS NULL) AND (received_sha256 IS NULL) = (uploaded_at IS NULL)),
        CHECK ((sealed_sha256 IS NULL) = (sealed_size IS NULL) AND (sealed_sha256 IS NULL) = (receipt_matched IS NULL)),
        CHECK (state NOT IN ('INITIATED', 'UPLOADED') OR sealed_sha256 IS NULL),
        CHECK (state IN ('INITIATED', 'UPLOADED', 'SEALING') OR sealed_sha256 IS NOT NULL),
        CHECK (
            (state = 'REJECTED' AND state_reason IS NOT NULL AND state_reason IN ('checksum_mismatch', 'unsupported_type', 'detection'))
            OR (state = 'SCAN_FAILED' AND state_reason IS NOT NULL AND state_reason IN ('unavailable', 'timeout', 'bad_response'))
            OR (state NOT IN ('REJECTED', 'SCAN_FAILED') AND state_reason IS NULL)
        ),
        CHECK (state != 'SCAN_PASSED' OR verdict_id IS NOT NULL)
    ) STRICT""",
    # A delivery is created in INITIATED and never deleted, replaced or renamed (INSERT OR REPLACE would delete a row
    # without firing the delete trigger, so a BEFORE INSERT guard rejects any insert that collides on id, rowid or
    # storage key). Its identity and ownership never change. Its state moves only along an arrow of the lifecycle, and
    # the receipt is written once, with the move out of INITIATED.
    """CREATE TRIGGER deliveries_start_as_initiated BEFORE INSERT ON deliveries
    WHEN NEW.state != 'INITIATED'
    BEGIN SELECT RAISE(ABORT, 'a delivery starts as INITIATED'); END""",
    """CREATE TRIGGER deliveries_are_not_replaced BEFORE INSERT ON deliveries
    WHEN EXISTS (SELECT 1 FROM deliveries WHERE id = NEW.id OR rowid = NEW.rowid OR storage_key = NEW.storage_key)
    BEGIN SELECT RAISE(ABORT, 'deliveries are not replaced'); END""",
    """CREATE TRIGGER deliveries_are_kept BEFORE DELETE ON deliveries
    BEGIN SELECT RAISE(ABORT, 'deliveries are kept'); END""",
    """CREATE TRIGGER deliveries_identity_is_fixed BEFORE UPDATE ON deliveries
    WHEN NEW.id IS NOT OLD.id OR NEW.production_id IS NOT OLD.production_id
        OR NEW.owner_subject_id IS NOT OLD.owner_subject_id OR NEW.storage_key IS NOT OLD.storage_key
        OR NEW.display_name IS NOT OLD.display_name OR NEW.declared_size IS NOT OLD.declared_size
        OR NEW.declared_sha256 IS NOT OLD.declared_sha256 OR NEW.declared_media_type IS NOT OLD.declared_media_type
        OR NEW.created_at IS NOT OLD.created_at OR NEW.rowid IS NOT OLD.rowid
    BEGIN SELECT RAISE(ABORT, 'delivery identity is fixed'); END""",
    """CREATE TRIGGER deliveries_follow_the_lifecycle BEFORE UPDATE ON deliveries
    WHEN NEW.state != OLD.state AND (OLD.state, NEW.state) NOT IN (VALUES
        ('INITIATED', 'UPLOADED'), ('UPLOADED', 'SEALING'), ('SEALING', 'REJECTED'), ('SEALING', 'SCAN_FAILED'),
        ('SEALING', 'SCAN_PASSED'), ('SEALING', 'INTEGRITY_FAILED'), ('SCAN_FAILED', 'SEALING'),
        ('SCAN_PASSED', 'SEALING'), ('SCAN_PASSED', 'ACCEPTED'), ('ACCEPTED', 'PROMOTING'),
        ('PROMOTING', 'PROMOTED'), ('PROMOTING', 'INTEGRITY_FAILED')
    )
    BEGIN SELECT RAISE(ABORT, 'delivery state change is not in the lifecycle'); END""",
    """CREATE TRIGGER deliveries_receipt_is_final BEFORE UPDATE ON deliveries
    WHEN OLD.received_sha256 IS NOT NULL AND (
        NEW.received_sha256 IS NOT OLD.received_sha256 OR NEW.received_size IS NOT OLD.received_size
        OR NEW.uploaded_at IS NOT OLD.uploaded_at
    )
    BEGIN SELECT RAISE(ABORT, 'delivery receipt is final'); END""",
    # M1I. The seal (what the server measured and hashed in quarantine at seal time: the authoritative digest H, the size
    # and whether they agree with the intake receipt) is written once, with the move out of SEALING, and never changed. A
    # delivery enters SCAN_PASSED only with a no_detection verdict that is bound to its own sealed digest, so no code path,
    # whatever it believes, can write a passing scan without a valid verdict row (Addendum §5.2).
    """CREATE TRIGGER deliveries_seal_is_final BEFORE UPDATE ON deliveries
    WHEN OLD.sealed_sha256 IS NOT NULL AND (
        NEW.sealed_sha256 IS NOT OLD.sealed_sha256 OR NEW.sealed_size IS NOT OLD.sealed_size
        OR NEW.receipt_matched IS NOT OLD.receipt_matched
    )
    BEGIN SELECT RAISE(ABORT, 'delivery seal is final'); END""",
    """CREATE TRIGGER deliveries_pass_needs_a_matching_verdict BEFORE UPDATE ON deliveries
    WHEN NEW.state = 'SCAN_PASSED' AND OLD.state != 'SCAN_PASSED' AND NOT EXISTS (
        SELECT 1 FROM verdicts AS v
        WHERE v.id = NEW.verdict_id AND v.sha256 = NEW.sealed_sha256 AND v.verdict = 'no_detection'
    )
    BEGIN SELECT RAISE(ABORT, 'a delivery passes the scan only with a no_detection verdict bound to its sealed digest'); END""",
    # A scanner verdict is bound to the digest of the bytes it was made for, by the engine and policy that made it, and is
    # kept for audit for good: it is never changed, deleted or replaced. Whether one may be reused is decided when it is
    # read (same digest, engine, version, kind and policy, a no_detection verdict, not expired), never by editing it.
    """CREATE TABLE verdicts (
        id TEXT NOT NULL PRIMARY KEY CHECK (length(id) = 32 AND id NOT GLOB '*[^0-9a-f]*'),
        sha256 TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
        engine_id TEXT NOT NULL CHECK (length(engine_id) BETWEEN 1 AND 100),
        engine_version TEXT NOT NULL CHECK (length(engine_version) BETWEEN 1 AND 100),
        engine_kind TEXT NOT NULL CHECK (engine_kind IN ('synthetic')),
        policy_fingerprint TEXT NOT NULL CHECK (length(policy_fingerprint) BETWEEN 1 AND 128),
        verdict TEXT NOT NULL CHECK (verdict IN ('no_detection', 'detection')),
        scanned_sha256 TEXT NOT NULL CHECK (scanned_sha256 = sha256),
        scanned_at INTEGER NOT NULL CHECK (scanned_at >= 0),
        valid_until INTEGER NOT NULL,
        delivery_id TEXT REFERENCES deliveries (id) ON DELETE RESTRICT,
        CHECK (valid_until > scanned_at)
    ) STRICT""",
    "CREATE INDEX verdicts_by_content ON verdicts (sha256, engine_id, engine_version, policy_fingerprint)",
    """CREATE TRIGGER verdicts_are_immutable BEFORE UPDATE ON verdicts
    BEGIN SELECT RAISE(ABORT, 'verdicts are immutable'); END""",
    """CREATE TRIGGER verdicts_are_kept BEFORE DELETE ON verdicts
    BEGIN SELECT RAISE(ABORT, 'verdicts are kept'); END""",
    """CREATE TRIGGER verdicts_are_not_replaced BEFORE INSERT ON verdicts
    WHEN EXISTS (SELECT 1 FROM verdicts WHERE id = NEW.id OR rowid = NEW.rowid)
    BEGIN SELECT RAISE(ABORT, 'verdicts are not replaced'); END""",
    # No foreign keys here: an event about a missing object must still be recordable.
    """CREATE TABLE audit_events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        at INTEGER NOT NULL,
        actor_issuer TEXT,
        actor_subject TEXT,
        action TEXT NOT NULL,
        outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied', 'recorded')),
        production_id TEXT,
        object_type TEXT,
        object_id TEXT CHECK (length(object_id) <= 128),
        reason TEXT,
        engine_kind TEXT CHECK (engine_kind IN ('synthetic')),
        CHECK ((actor_issuer IS NULL) = (actor_subject IS NULL))
    ) STRICT""",
    # Audit rows can be added, never changed. INSERT OR REPLACE would delete a row without firing the delete
    # trigger, so a BEFORE INSERT guard rejects any insert whose seq already exists.
    """CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
    BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END""",
    """CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
    BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END""",
    """CREATE TRIGGER audit_events_no_overwrite BEFORE INSERT ON audit_events
    WHEN EXISTS (SELECT 1 FROM audit_events WHERE seq = NEW.seq)
    BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END""",
    # Once revoked_at is set the whole engagement row is immutable: it cannot be updated at all (not even to the same
    # value), deleted or replaced. REPLACE deletes a conflicting row without firing delete triggers, so an insert or
    # update that would collide with a revoked row on id, rowid or (subject_id, production_id) is rejected up front.
    """CREATE TRIGGER engagements_revocation_is_final BEFORE UPDATE ON engagements
    WHEN OLD.revoked_at IS NOT NULL
    BEGIN SELECT RAISE(ABORT, 'engagement revocation is final'); END""",
    """CREATE TRIGGER engagements_revoked_rows_are_kept BEFORE DELETE ON engagements
    WHEN OLD.revoked_at IS NOT NULL
    BEGIN SELECT RAISE(ABORT, 'engagement revocation is final'); END""",
    """CREATE TRIGGER engagements_revoked_rows_are_not_replaced BEFORE INSERT ON engagements
    WHEN EXISTS (
        SELECT 1 FROM engagements WHERE revoked_at IS NOT NULL
        AND (id = NEW.id OR rowid = NEW.rowid OR (subject_id = NEW.subject_id AND production_id = NEW.production_id))
    )
    BEGIN SELECT RAISE(ABORT, 'engagement revocation is final'); END""",
    """CREATE TRIGGER engagements_revoked_rows_are_not_overwritten_by_update BEFORE UPDATE ON engagements
    WHEN EXISTS (
        SELECT 1 FROM engagements WHERE revoked_at IS NOT NULL AND rowid != OLD.rowid
        AND (id = NEW.id OR rowid = NEW.rowid OR (subject_id = NEW.subject_id AND production_id = NEW.production_id))
    )
    BEGIN SELECT RAISE(ABORT, 'engagement revocation is final'); END""",
    # A subject's verified identity never changes. Otherwise a revoked person could be given a new subject row by
    # renaming the old one and re-adding the original (issuer, subject). display_name is metadata and may change.
    """CREATE TRIGGER subjects_identity_is_fixed BEFORE UPDATE OF issuer, subject ON subjects
    WHEN NEW.issuer IS NOT OLD.issuer OR NEW.subject IS NOT OLD.subject
    BEGIN SELECT RAISE(ABORT, 'subject identity is fixed'); END""",
    "PRAGMA user_version = 1",
)


# Application connections run under a default-deny authorizer. It decides on SQLite's action codes and on object
# names, never on SQL text. It governs the connections handed out by connect(): code that holds one can replace it,
# and the audit triggers in the schema are a separate barrier. UPDATE and DELETE are permitted on the business tables
# because their invariants are held by constraints and triggers; the audit table accepts INSERT only. The engine's own
# upkeep of sqlite_sequence is not reported to the authorizer, so every write to a sqlite_* table is refused.
_ALWAYS_PERMITTED = frozenset(
    {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_TRANSACTION,
        sqlite3.SQLITE_SAVEPOINT,
        sqlite3.SQLITE_RECURSIVE,
    }
)
_DATA_CHANGES = frozenset({sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE})
_READABLE_PRAGMAS = frozenset({"foreign_keys", "user_version", "busy_timeout"})
_DENIED_FUNCTIONS = frozenset({"load_extension"})
_AUDIT_TABLE = "audit_events"


def _authorize(action: int, arg1: str | None, arg2: str | None, database: str | None, source: str | None) -> int:
    """The authorizer callback: SQLITE_OK or SQLITE_DENY for one action of a statement being compiled."""
    if action in _ALWAYS_PERMITTED:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION:
        return sqlite3.SQLITE_DENY if (arg2 or "").lower() in _DENIED_FUNCTIONS else sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA:  # a bare read of a setting the store relies on; a value or argument is a write
        return sqlite3.SQLITE_OK if arg2 is None and (arg1 or "").lower() in _READABLE_PRAGMAS else sqlite3.SQLITE_DENY
    if action in _DATA_CHANGES and arg1 is not None:
        table = arg1.lower()
        if table.startswith("sqlite_") or (table == _AUDIT_TABLE and action != sqlite3.SQLITE_INSERT):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY  # DDL, ATTACH, ANALYZE, REINDEX, VACUUM and any action code a later SQLite adds


_SCHEMA_OBJECTS = "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"


def _reference_schema() -> list[tuple]:
    """Every schema object that _SCHEMA creates, read back from a scratch in-memory database (about 0.3 ms)."""
    reference = sqlite3.connect(":memory:")
    try:
        for statement in _SCHEMA:
            reference.execute(statement)
        return [tuple(row) for row in reference.execute(_SCHEMA_OBJECTS)]
    finally:
        reference.close()


def _names(keys: set[tuple[str, str]]) -> str:
    shown = [ascii(f"{kind} {name}")[:60] for kind, name in sorted(keys)[:3]]
    return ", ".join(shown) + (f" and {len(keys) - 3} more" if len(keys) > 3 else "")


def _describe_drift(expected: list[tuple], actual: list[tuple]) -> str:
    """Which objects differ, by type and name only: bounded, with no definitions and control characters escaped."""
    wanted = {(kind, name): rest for kind, name, *rest in expected}
    found = {(kind, name): rest for kind, name, *rest in actual}
    differences = {
        "missing": wanted.keys() - found.keys(),
        "unexpected": found.keys() - wanted.keys(),
        "modified": {key for key in wanted.keys() & found.keys() if wanted[key] != found[key]},
    }
    parts = [f"{label} {_names(keys)}" for label, keys in differences.items() if keys]
    return f"database schema does not match version {SCHEMA_VERSION} ({'; '.join(parts) or 'duplicate entries'})"


def _verify_schema(conn: sqlite3.Connection) -> None:
    """Compare every object in the database with the reference. This is a check at the moment of the call only."""
    expected = _reference_schema()
    actual = [tuple(row) for row in conn.execute(_SCHEMA_OBJECTS)]
    if actual != expected:
        raise SchemaIntegrityError(_describe_drift(expected, actual))


def _open(path: Path, *, create: bool) -> sqlite3.Connection:
    """A configured connection. Foreign keys are enabled, and verified, before any transaction begins."""
    if sqlite3.sqlite_version_info < MINIMUM_SQLITE:
        needed = ".".join(map(str, MINIMUM_SQLITE))
        raise StoreError(f"SQLite {sqlite3.sqlite_version} is too old: STRICT tables need {needed} or newer")
    uri = Path(path).resolve().as_uri() + ("?mode=rwc" if create else "?mode=rw")
    conn = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=BUSY_TIMEOUT_SECONDS)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        row = conn.execute("PRAGMA foreign_keys").fetchone()
        if row is None or row[0] != 1:
            raise StoreError("SQLite did not enable foreign key enforcement")
    except BaseException:
        conn.close()
        raise
    return conn


def _unsupported(version: int) -> str:
    return f"database schema version {version} is not supported (expected {SCHEMA_VERSION})"


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """One write transaction: BEGIN IMMEDIATE, then COMMIT, or ROLLBACK if the block raises."""
    if conn.in_transaction:
        raise StoreError("a transaction is already open on this connection")
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def initialise_schema(path: Path) -> None:
    """Create the schema in a new, empty database.

    A database already at the supported version is only verified, never repaired; any other version is refused.
    """
    conn = _open(path, create=True)
    try:
        with transaction(conn):
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version == SCHEMA_VERSION:
                _verify_schema(conn)
                return
            if version != 0:
                raise SchemaVersionError(_unsupported(version))
            if conn.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0]:
                raise SchemaVersionError("database is not empty and has no schema version; refusing to initialise it")
            for statement in _SCHEMA:
                conn.execute(statement)
    finally:
        conn.close()


def connect(path: Path) -> sqlite3.Connection:
    """An application connection to an existing, initialised database. It never creates or upgrades one.

    The schema version and every schema object must match what initialise_schema() creates, otherwise the connection
    is closed and an error raised. The authorizer is installed only after that check.
    """
    conn = _open(path, create=False)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version != SCHEMA_VERSION:
            raise SchemaVersionError(_unsupported(version))
        _verify_schema(conn)
        conn.set_authorizer(_authorize)
    except BaseException:
        conn.close()
        raise
    return conn


def _new_id() -> str:
    return uuid.uuid4().hex


def add_production(conn: sqlite3.Connection, clock: Clock, name: str) -> str:
    production_id = _new_id()
    conn.execute(
        "INSERT INTO productions (id, name, created_at) VALUES (?, ?, ?)",
        (production_id, name, to_micros(clock.now())),
    )
    return production_id


def add_subject(conn: sqlite3.Connection, clock: Clock, issuer: str, subject: str, display_name: str) -> int:
    """Record a verified (issuer, subject) identity. display_name is metadata, never an authority."""
    cursor = conn.execute(
        "INSERT INTO subjects (issuer, subject, display_name, created_at) VALUES (?, ?, ?, ?)",
        (issuer, subject, display_name, to_micros(clock.now())),
    )
    return cursor.lastrowid


def add_engagement(
    conn: sqlite3.Connection, clock: Clock, subject_id: int, production_id: str, role: Role, ends_at: datetime
) -> str:
    engagement_id = _new_id()
    conn.execute(
        "INSERT INTO engagements (id, subject_id, production_id, role, created_at, ends_at) VALUES (?, ?, ?, ?, ?, ?)",
        (engagement_id, subject_id, production_id, role, to_micros(clock.now()), to_micros(ends_at)),
    )
    return engagement_id


def revoke_engagement(conn: sqlite3.Connection, clock: Clock, engagement_id: str) -> bool:
    """Set the revocation time once. True if this call revoked it; False if it was already revoked or is missing.

    This is unscoped: it names no production, so it revokes the engagement with this id wherever it is. It is unsuitable
    for any id a request controls, and only the seeding code and the tests of this module may call it; request code
    uses revoke_engagement_in_production (tests/guards/test_revocation_scope.py enforces that). It will be removed when
    its remaining test call sites are migrated.
    """
    cursor = conn.execute(
        "UPDATE engagements SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        (to_micros(clock.now()), engagement_id),
    )
    return cursor.rowcount == 1


class RevocationStatus(StrEnum):
    """What revoke_engagement_in_production did."""

    REVOKED = "revoked"  # this call set revoked_at
    ALREADY_REVOKED = "already_revoked"  # in this production, revoked earlier; nothing was changed
    NOT_FOUND = "not_found"  # no engagement with this id in this production (it may exist in another)


@dataclass(frozen=True)
class Revocation:
    """revoked_at is in microseconds: the original time for ALREADY_REVOKED, and None only for NOT_FOUND."""

    status: RevocationStatus
    revoked_at: int | None


_ID = re.compile(r"[0-9a-f]{32}")  # the shape of every id this module generates


def _check_id(name: str, value: object) -> None:
    if type(value) is not str:
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not _ID.fullmatch(value):
        raise ValueError(f"{name} must be 32 lowercase hexadecimal characters")  # the value is never echoed


def revoke_engagement_in_production(
    conn: sqlite3.Connection, production_id: str, engagement_id: str, now_micros: int
) -> Revocation:
    """Revoke one engagement of one production, at the instant the caller supplies.

    The production is part of the UPDATE that mutates, so an engagement of another production is never reached: its id
    under this production's id gives NOT_FOUND, exactly as an id that does not exist does, and nothing changes. An
    engagement already revoked here is left as it is and reported with its original time.

    The caller owns the transaction (use store.transaction(), and authorise the caller for this production in the same
    one): this function never commits or rolls back, reads no clock, and raises StoreError outside a transaction.
    Malformed ids raise TypeError or ValueError before any SQL runs.
    """
    _check_id("production_id", production_id)
    _check_id("engagement_id", engagement_id)
    if type(now_micros) is not int:
        raise TypeError("now_micros must be an int (a bool is not accepted)")
    if not conn.in_transaction:
        raise StoreError("a revocation must run inside the caller's transaction")
    cursor = conn.execute(
        "UPDATE engagements SET revoked_at = ? WHERE id = ? AND production_id = ? AND revoked_at IS NULL",
        (now_micros, engagement_id, production_id),
    )
    if cursor.rowcount == 1:
        return Revocation(RevocationStatus.REVOKED, now_micros)
    row = conn.execute(
        "SELECT revoked_at FROM engagements WHERE id = ? AND production_id = ?", (engagement_id, production_id)
    ).fetchone()
    if row is None:
        return Revocation(RevocationStatus.NOT_FOUND, None)
    if row[0] is None:  # the UPDATE changed nothing, yet the engagement is active: never report that as a repeat
        raise StoreError("an active engagement was not revoked by the update")
    return Revocation(RevocationStatus.ALREADY_REVOKED, row[0])


class NewDelivery(NamedTuple):
    """The ids of a delivery that was just created. The storage key stays inside the server."""

    id: str
    storage_key: str


def add_delivery(
    conn: sqlite3.Connection,
    clock: Clock,
    production_id: str,
    subject_id: int,
    display_name: str,
    declared_size: int,
    declared_sha256: str,
    declared_media_type: str,
) -> NewDelivery:
    """Record a vendor's declaration as a delivery in INITIATED, owned by `subject_id` in `production_id`.

    The id and the storage key are generated here, independently of each other and of every argument. The declared
    values are the client's claims: metadata for later checks and display, never a key, a path or an identity. The
    caller validates them and authorises the subject for the production in the same transaction (ingest.py does).
    """
    delivery_id, storage_key = _new_id(), _new_id()
    conn.execute(
        "INSERT INTO deliveries (id, production_id, owner_subject_id, storage_key, display_name, declared_size, "
        "declared_sha256, declared_media_type, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'INITIATED', ?)",
        (
            delivery_id,
            production_id,
            subject_id,
            storage_key,
            display_name,
            declared_size,
            declared_sha256,
            declared_media_type,
            to_micros(clock.now()),
        ),
    )
    return NewDelivery(delivery_id, storage_key)


def add_verdict(
    conn: sqlite3.Connection,
    *,
    sha256: str,
    engine_id: str,
    engine_version: str,
    engine_kind: str,
    policy_fingerprint: str,
    verdict: str,
    scanned_sha256: str,
    scanned_at: int,
    valid_until: int,
    delivery_id: str | None = None,
) -> str:
    """Record a scanner's verdict, bound to the digest `sha256` of the bytes it was made for, and return its id.

    The id is generated here. `scanned_sha256` is what the scanner said it read: the schema accepts the row only if it is
    the same digest, so a verdict row cannot exist for bytes the scanner did not report on. Times are microseconds; the
    verdict is valid until `valid_until`. The row can never be changed or removed afterwards (triggers).
    """
    verdict_id = _new_id()
    conn.execute(
        "INSERT INTO verdicts (id, sha256, engine_id, engine_version, engine_kind, policy_fingerprint, verdict, "
        "scanned_sha256, scanned_at, valid_until, delivery_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            verdict_id,
            sha256,
            engine_id,
            engine_version,
            engine_kind,
            policy_fingerprint,
            verdict,
            scanned_sha256,
            scanned_at,
            valid_until,
            delivery_id,
        ),
    )
    return verdict_id


def add_asset(conn: sqlite3.Connection, clock: Clock, production_id: str, display_name: str) -> str:
    """display_name is metadata only; it is never used to build a filesystem path."""
    asset_id = _new_id()
    conn.execute(
        "INSERT INTO assets (id, production_id, display_name, created_at) VALUES (?, ?, ?, ?)",
        (asset_id, production_id, display_name, to_micros(clock.now())),
    )
    return asset_id
