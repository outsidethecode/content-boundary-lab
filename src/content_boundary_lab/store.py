"""SQLite data foundation: schema, connections and transactions (stdlib sqlite3 only).

The engagements table is the server-side authority for roles, expiry and revocation, but this module makes no
authorisation decisions (M1F). The audit writing API and the application-connection authorizer are M1D-3.
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
    """Create the schema in a new, empty database. Idempotent for the supported version, otherwise refuses."""
    conn = _open(path, create=True)
    try:
        with transaction(conn):
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version == SCHEMA_VERSION:
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
    """An application connection to an existing, initialised database. It never creates or upgrades one."""
    conn = _open(path, create=False)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version != SCHEMA_VERSION:
            raise SchemaVersionError(_unsupported(version))
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
