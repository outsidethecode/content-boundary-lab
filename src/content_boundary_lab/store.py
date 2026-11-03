"""SQLite data foundation: schema, connections and transactions (stdlib sqlite3 only).

The engagements table is the server-side authority for roles, expiry and revocation, but this module makes no
authorisation decisions (M1F). connect() is the one way application code gets a connection: it refuses a schema that
differs from the one initialise_schema() creates and installs a default-deny authorizer. Both are described, with
their limits, in docs/decisions.md (AM-13).
"""

import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Literal

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
    """Set the revocation time once. True if this call revoked it; False if it was already revoked or is missing."""
    cursor = conn.execute(
        "UPDATE engagements SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        (to_micros(clock.now()), engagement_id),
    )
    return cursor.rowcount == 1


def add_asset(conn: sqlite3.Connection, clock: Clock, production_id: str, display_name: str) -> str:
    """display_name is metadata only; it is never used to build a filesystem path."""
    asset_id = _new_id()
    conn.execute(
        "INSERT INTO assets (id, production_id, display_name, created_at) VALUES (?, ?, ?, ?)",
        (asset_id, production_id, display_name, to_micros(clock.now())),
    )
    return asset_id
