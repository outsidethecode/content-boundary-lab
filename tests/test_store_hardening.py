"""Connection hardening: the schema check and the authorizer on application connections, and what they do not claim."""

import shutil
import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from content_boundary_lab import audit, store
from content_boundary_lab.audit import Actor, AuditAction, ObjectType, Outcome

T0 = datetime(2026, 11, 3, 12, tzinfo=timezone.utc)
ISSUER = "https://idp.example"
ACTOR = Actor(ISSUER, "coordinator-1")
INSERT_ASSET = "INSERT INTO assets (id, production_id, display_name, created_at) VALUES (?, ?, 'x', 1)"
OK = sqlite3.SQLITE_OK
DENY = sqlite3.SQLITE_DENY
TRIGGERS = [
    "audit_events_no_update",
    "audit_events_no_delete",
    "audit_events_no_overwrite",
    "engagements_revocation_is_final",
    "engagements_revoked_rows_are_kept",
    "engagements_revoked_rows_are_not_replaced",
    "engagements_revoked_rows_are_not_overwritten_by_update",
    "subjects_identity_is_fixed",
]


class FixedClock:
    def now(self):
        return T0


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "lab.sqlite3"


@pytest.fixture
def clock():
    return FixedClock()


@pytest.fixture
def conn(db_path):
    store.initialise_schema(db_path)
    connection = store.connect(db_path)
    yield connection
    connection.close()


def _tamper(db_path, *statements):
    """Change the database file through a separate raw connection, as anything with file access could."""
    raw = sqlite3.connect(db_path)
    for statement in statements:
        raw.execute(statement)
    raw.commit()
    raw.close()


def _seed(connection, clock):
    """One of each kind of row, and one audit event."""
    production = store.add_production(connection, clock, "ALPHA (synthetic)")
    subject = store.add_subject(connection, clock, ISSUER, "vendor-1", "Vendor One (synthetic)")
    engagement = store.add_engagement(connection, clock, subject, production, "vendor", T0 + timedelta(days=30))
    asset = store.add_asset(connection, clock, production, "Plate 1 (synthetic)")
    with store.transaction(connection):
        seq = audit.record_event(
            connection, clock, AuditAction.ENGAGEMENT_CREATED, Outcome.RECORDED, actor=ACTOR, production_id=production
        )
    return SimpleNamespace(production=production, subject=subject, engagement=engagement, asset=asset, seq=seq)


def _snapshot(connection):
    """Everything a refused statement must leave alone."""
    return {
        "schema": [
            tuple(r) for r in connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY 1, 2")
        ],
        "audit": [tuple(r) for r in connection.execute("SELECT * FROM audit_events ORDER BY seq")],
        "counters": [tuple(r) for r in connection.execute("SELECT name, seq FROM sqlite_sequence ORDER BY name")],
        "row counts": tuple(
            connection.execute(
                "SELECT (SELECT COUNT(*) FROM productions), (SELECT COUNT(*) FROM subjects), "
                "(SELECT COUNT(*) FROM engagements), (SELECT COUNT(*) FROM assets)"
            ).fetchone()
        ),
        "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
        "foreign_keys": connection.execute("PRAGMA foreign_keys").fetchone()[0],
    }


# --- the schema check when a connection is opened ----------------------------------------------------------------

AUDIT_TABLE_WITHOUT_CHECKS = (
    "CREATE TABLE audit_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, actor_issuer TEXT, "
    "actor_subject TEXT, action TEXT NOT NULL, outcome TEXT NOT NULL, production_id TEXT, object_type TEXT, "
    "object_id TEXT, reason TEXT) STRICT"
)
DRIFT = {
    "extra table": ["CREATE TABLE extra (x)"],
    "extra table with a name that resembles an internal one": ["CREATE TABLE sqlitex_extra (x)"],
    "extra index": ["CREATE INDEX extra_index ON assets (display_name)"],
    "extra view": ["CREATE VIEW extra_view AS SELECT 1"],
    "extra trigger": ["CREATE TRIGGER extra_trigger AFTER INSERT ON audit_events BEGIN SELECT 1; END"],
    "statistics table added by ANALYZE": ["ANALYZE"],
    "index dropped": ["DROP INDEX assets_by_production"],
    "column added": ["ALTER TABLE assets ADD COLUMN extra TEXT"],
    "column renamed": ["ALTER TABLE assets RENAME COLUMN display_name TO label"],
    "table re-created without STRICT": [
        "DROP TABLE assets",
        "CREATE TABLE assets (id TEXT NOT NULL PRIMARY KEY, production_id TEXT NOT NULL, display_name TEXT NOT NULL, "
        "created_at INTEGER NOT NULL)",
    ],
    "audit table re-created without its CHECK constraints": ["DROP TABLE audit_events", AUDIT_TABLE_WITHOUT_CHECKS],
    "trigger replaced by one that does nothing": [
        "DROP TRIGGER audit_events_no_update",
        "CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events WHEN 0 BEGIN SELECT 1; END",
    ],
    "trigger text edited through writable_schema": [
        "PRAGMA writable_schema = ON",
        "UPDATE sqlite_master SET sql = replace(sql, 'append-only', 'appendable') "
        "WHERE name = 'audit_events_no_delete'",
    ],
    "table definition edited through writable_schema": [
        "PRAGMA writable_schema = ON",
        "UPDATE sqlite_master SET sql = replace(sql, '''recorded'')', '''recorded'', ''x'')') "
        "WHERE name = 'audit_events'",
    ],
    **{f"trigger {name} dropped": [f"DROP TRIGGER {name}"] for name in TRIGGERS},
}


def test_a_refused_schema_is_a_store_error():
    assert issubclass(store.SchemaIntegrityError, store.StoreError)
    assert not issubclass(store.SchemaIntegrityError, store.SchemaVersionError)


@pytest.mark.parametrize("statements", DRIFT.values(), ids=list(DRIFT))
def test_schema_drift_is_refused_when_a_connection_is_opened(db_path, statements):
    store.initialise_schema(db_path)
    store.connect(db_path).close()  # the untouched database is accepted
    _tamper(db_path, *statements)
    with pytest.raises(store.SchemaIntegrityError, match="schema") as caught:
        store.connect(db_path)
    assert len(str(caught.value)) < 600  # bounded: it names objects, it does not dump their definitions


def test_a_correct_user_version_alone_is_not_enough(db_path):
    _tamper(db_path, "PRAGMA user_version = 1")
    with pytest.raises(store.SchemaIntegrityError, match="schema"):
        store.connect(db_path)
    _tamper(db_path, "CREATE TABLE somebody_elses (x)")
    with pytest.raises(store.SchemaIntegrityError, match="schema"):
        store.connect(db_path)


def _watch_connections(monkeypatch):
    """Record every connection sqlite3.connect hands out from now on."""
    opened = []
    real_connect = sqlite3.connect

    def spy(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", spy)
    return opened


def _assert_all_closed(opened):
    assert opened
    for connection in opened:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")


@pytest.mark.parametrize("failure", ["wrong version", "schema drift"])
def test_a_refused_connection_is_closed_and_never_returned(db_path, monkeypatch, failure):
    store.initialise_schema(db_path)
    _tamper(db_path, "PRAGMA user_version = 2" if failure == "wrong version" else "CREATE TABLE extra (x)")
    opened = _watch_connections(monkeypatch)
    with pytest.raises(store.StoreError):
        store.connect(db_path)
    _assert_all_closed(opened)


def test_schema_initialisation_still_works_and_its_result_is_accepted(db_path, clock):
    store.initialise_schema(db_path)
    application = store.connect(db_path)
    _seed(application, clock)
    store.initialise_schema(db_path)  # idempotent, even while an application connection is open
    application.close()
    again = store.connect(db_path)
    assert again.execute("SELECT COUNT(*) FROM productions").fetchone()[0] == 1
    again.close()


def test_reinitialising_an_intact_database_succeeds_and_changes_nothing(db_path, conn, clock):
    _seed(conn, clock)
    before, before_bytes = _snapshot(conn), db_path.read_bytes()
    store.initialise_schema(db_path)
    assert _snapshot(conn) == before
    assert db_path.read_bytes() == before_bytes


@pytest.mark.parametrize("statements", DRIFT.values(), ids=list(DRIFT))
def test_reinitialising_a_drifted_database_is_refused_and_does_not_repair_or_adopt_it(db_path, statements):
    store.initialise_schema(db_path)
    _tamper(db_path, *statements)
    damaged = db_path.read_bytes()
    with pytest.raises(store.SchemaIntegrityError, match="schema"):
        store.initialise_schema(db_path)
    assert db_path.read_bytes() == damaged  # nothing was repaired, rewritten or adopted
    with pytest.raises(store.SchemaIntegrityError):
        store.connect(db_path)  # and the damaged database is still refused


def test_reinitialising_a_database_that_only_has_the_version_set_is_refused(db_path):
    _tamper(db_path, "PRAGMA user_version = 1")
    with pytest.raises(store.SchemaIntegrityError, match="schema"):
        store.initialise_schema(db_path)
    raw = sqlite3.connect(db_path)
    assert raw.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0] == 0  # no schema was created for it
    raw.close()


def test_a_refused_reinitialisation_closes_its_connection(db_path, monkeypatch):
    store.initialise_schema(db_path)
    _tamper(db_path, "CREATE TABLE extra (x)")
    opened = _watch_connections(monkeypatch)
    with pytest.raises(store.SchemaIntegrityError):
        store.initialise_schema(db_path)
    _assert_all_closed(opened)


# --- what the schema check does not claim ------------------------------------------------------------------------


def test_an_open_connection_does_not_notice_a_later_change_to_the_file(db_path, conn, clock):
    """The check runs when a connection is opened. It is not a monitor of the file."""
    _tamper(db_path, "DROP TRIGGER audit_events_no_delete")
    seeded = _seed(conn, clock)  # the open connection carries on normally
    assert conn.execute("SELECT COUNT(*) FROM engagements WHERE id = ?", (seeded.engagement,)).fetchone()[0] == 1
    with pytest.raises(store.SchemaIntegrityError):
        store.connect(db_path)  # the next connection is where the drift is found


def test_changes_to_data_that_leave_the_schema_unchanged_are_not_detected(db_path, conn, clock):
    _seed(conn, clock)
    conn.close()
    raw = sqlite3.connect(db_path)
    trigger_sql = raw.execute("SELECT sql FROM sqlite_master WHERE name = 'audit_events_no_update'").fetchone()[0]
    raw.execute("DROP TRIGGER audit_events_no_update")
    raw.execute("UPDATE audit_events SET action = 'forged'")
    raw.execute(trigger_sql)  # the same definition put back
    raw.commit()
    raw.close()
    reopened = store.connect(db_path)  # accepted: only the schema is compared
    assert reopened.execute("SELECT action FROM audit_events").fetchone()[0] == "forged"
    reopened.close()


def test_replacing_the_database_with_an_older_valid_copy_is_not_detected(db_path, tmp_path, conn, clock):
    _seed(conn, clock)
    conn.close()
    older = tmp_path / "older.sqlite3"
    shutil.copy(db_path, older)
    newer = store.connect(db_path)
    store.add_production(newer, clock, "BRAVO (synthetic)")
    newer.close()
    shutil.copy(older, db_path)
    restored = store.connect(db_path)
    assert restored.execute("SELECT COUNT(*) FROM productions").fetchone()[0] == 1  # the later production is gone
    restored.close()


# --- the authorizer: what still works ----------------------------------------------------------------------------


def test_normal_store_and_audit_operations_work_on_a_hardened_connection(conn, clock):
    seeded = _seed(conn, clock)
    with store.transaction(conn):
        assert store.revoke_engagement(conn, clock, seeded.engagement)  # an approved business-state UPDATE
        conn.execute("UPDATE subjects SET display_name = ? WHERE id = ?", ("Renamed (synthetic)", seeded.subject))
        conn.execute("SAVEPOINT inner")
        conn.execute(INSERT_ASSET, ("a" * 32, seeded.production))
        conn.execute("ROLLBACK TO inner")
        conn.execute("RELEASE inner")
        appended = audit.record_event(
            conn,
            clock,
            AuditAction.ENGAGEMENT_REVOKED,
            Outcome.RECORDED,
            actor=ACTOR,
            production_id=seeded.production,
            object_type=ObjectType.ENGAGEMENT,
            object_id=seeded.engagement,
        )
    assert appended == seeded.seq + 1
    revoked_at, display_name = conn.execute(
        "SELECT e.revoked_at, s.display_name FROM engagements e JOIN subjects s ON s.id = e.subject_id WHERE e.id = ?",
        (seeded.engagement,),
    ).fetchone()
    assert revoked_at is not None and display_name == "Renamed (synthetic)"
    assert conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 1  # the savepoint was rolled back
    assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 2
    recursive = "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3) SELECT SUM(i) FROM n"
    assert conn.execute(recursive).fetchone()[0] == 6
    assert conn.execute("SELECT name FROM sqlite_master WHERE name = 'assets'").fetchone()[0] == "assets"


@pytest.mark.parametrize(
    "statement", ["PRAGMA foreign_keys", "PRAGMA FOREIGN_KEYS", "pragma main.user_version", "PRAGMA busy_timeout"]
)
def test_reading_the_settings_the_store_depends_on_is_permitted(conn, statement):
    assert conn.execute(statement).fetchone()[0] in {0, 1, 5000}


def test_every_application_connection_is_hardened(db_path, conn):
    other = store.connect(db_path)
    for connection in (conn, other):
        with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
            connection.execute("DROP TABLE assets")
    other.close()


# --- the authorizer: what is refused -----------------------------------------------------------------------------

REFUSED = {
    "DROP TRIGGER on the audit table": "DROP TRIGGER audit_events_no_update",
    "DROP TRIGGER on engagements": "DROP TRIGGER engagements_revocation_is_final",
    "DROP TABLE audit_events": "DROP TABLE audit_events",
    "DROP TABLE assets": "DROP TABLE assets",
    "DROP INDEX": "DROP INDEX assets_by_production",
    "ALTER TABLE RENAME TO": "ALTER TABLE audit_events RENAME TO moved",
    "ALTER TABLE ADD COLUMN": "ALTER TABLE assets ADD COLUMN extra TEXT",
    "ALTER TABLE DROP COLUMN": "ALTER TABLE assets DROP COLUMN created_at",
    "ALTER TABLE RENAME COLUMN": "ALTER TABLE assets RENAME COLUMN display_name TO label",
    "CREATE TABLE": "CREATE TABLE extra (x)",
    "CREATE TEMP TABLE": "CREATE TEMP TABLE extra (x)",
    "CREATE VIEW": "CREATE VIEW extra_view AS SELECT 1",
    "CREATE TEMP VIEW": "CREATE TEMP VIEW extra_view AS SELECT 1",
    "CREATE INDEX": "CREATE INDEX extra_index ON assets (display_name)",
    "CREATE TRIGGER": "CREATE TRIGGER extra_trigger AFTER INSERT ON audit_events BEGIN SELECT 1; END",
    "CREATE TEMP TRIGGER": "CREATE TEMP TRIGGER extra_trigger AFTER INSERT ON main.audit_events BEGIN SELECT 1; END",
    "REINDEX": "REINDEX",
    "ANALYZE": "ANALYZE",
    "VACUUM": "VACUUM",
    "ATTACH DATABASE": "ATTACH DATABASE ':memory:' AS other",
    "PRAGMA foreign_keys = OFF": "PRAGMA foreign_keys = OFF",
    "PRAGMA foreign_keys = OFF, other case": "pragma Foreign_Keys = off",
    "PRAGMA defer_foreign_keys = ON": "PRAGMA defer_foreign_keys = ON",
    "PRAGMA recursive_triggers = ON": "PRAGMA recursive_triggers = ON",
    "PRAGMA ignore_check_constraints = ON": "PRAGMA ignore_check_constraints = ON",
    "PRAGMA writable_schema = ON": "PRAGMA writable_schema = ON",
    "PRAGMA trusted_schema = ON": "PRAGMA trusted_schema = ON",
    "PRAGMA user_version = 2": "PRAGMA user_version = 2",
    "PRAGMA journal_mode = OFF": "PRAGMA journal_mode = OFF",
    "PRAGMA busy_timeout = 0": "PRAGMA busy_timeout = 0",
    "PRAGMA with an argument": "PRAGMA table_info(audit_events)",
    "UPDATE sqlite_sequence": "UPDATE sqlite_sequence SET seq = 0",
    "UPDATE sqlite_sequence, other case": "UPDATE SQLITE_SEQUENCE SET seq = 0",
    "DELETE FROM sqlite_sequence": "DELETE FROM sqlite_sequence",
    "INSERT INTO sqlite_sequence": "INSERT INTO sqlite_sequence (name, seq) VALUES ('extra', 5)",
}


@pytest.mark.parametrize("statement", REFUSED.values(), ids=list(REFUSED))
def test_structural_changes_dangerous_pragmas_and_internal_tables_are_refused(conn, clock, statement):
    _seed(conn, clock)
    before = _snapshot(conn)
    with pytest.raises(sqlite3.DatabaseError, match="not authorized|authorization denied"):
        conn.execute(statement)
    assert _snapshot(conn) == before


@pytest.mark.parametrize("statement", REFUSED.values(), ids=list(REFUSED))
def test_the_same_statements_run_once_the_authorizer_is_removed(conn, clock, statement):
    """So the refusals above come from the authorizer, not from a typing mistake in the statement."""
    _seed(conn, clock)
    conn.set_authorizer(None)
    conn.execute(statement)


def test_a_direct_write_to_the_schema_table_is_refused(conn):
    with pytest.raises(sqlite3.DatabaseError, match="not authorized|may not be modified"):
        conn.execute("UPDATE sqlite_master SET sql = ''")


def test_foreign_key_enforcement_cannot_be_switched_off(conn, clock):
    seeded = _seed(conn, clock)
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        conn.execute("PRAGMA foreign_keys = OFF")
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        conn.execute(INSERT_ASSET, ("b" * 32, "c" * 32))
    assert seeded.asset


AUDIT_MUTATIONS = {
    "UPDATE": "UPDATE audit_events SET action = 'forged'",
    "UPDATE, schema-qualified and in other case": "UPDATE main.AUDIT_EVENTS SET action = 'forged'",
    "UPDATE through an alias": 'UPDATE "audit_events" AS a SET action = \'forged\'',
    "UPDATE OR REPLACE": "UPDATE OR REPLACE audit_events SET action = 'forged'",
    "DELETE": "DELETE FROM audit_events",
    "DELETE, schema-qualified and in other case": 'DELETE FROM main."Audit_Events"',
    "upsert that updates": (
        "INSERT INTO audit_events (seq, at, action, outcome) VALUES (1, 1, 'forged', 'recorded') "
        "ON CONFLICT (seq) DO UPDATE SET action = 'forged'"
    ),
}


@pytest.mark.parametrize("statement", AUDIT_MUTATIONS.values(), ids=list(AUDIT_MUTATIONS))
def test_direct_changes_to_audit_events_are_refused(conn, clock, statement):
    _seed(conn, clock)
    before = _snapshot(conn)
    with pytest.raises(sqlite3.DatabaseError, match="not authorized"):
        conn.execute(statement)
    assert _snapshot(conn) == before


@pytest.mark.parametrize("statement", AUDIT_MUTATIONS.values(), ids=list(AUDIT_MUTATIONS))
def test_the_audit_triggers_hold_without_the_authorizer(conn, clock, statement):
    """The authorizer is not the only barrier: with it removed, the schema triggers still refuse."""
    _seed(conn, clock)
    before = _snapshot(conn)
    conn.set_authorizer(None)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute(statement)
    assert _snapshot(conn) == before


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT OR REPLACE INTO audit_events (seq, at, action, outcome) VALUES (1, 1, 'forged', 'recorded')",
        "INSERT OR IGNORE INTO audit_events (seq, at, action, outcome) VALUES (1, 1, 'forged', 'recorded')",
        "INSERT INTO audit_events (seq, at, action, outcome) VALUES (1, 1, 'forged', 'recorded')",
    ],
    ids=["REPLACE", "IGNORE", "plain insert with an existing seq"],
)
def test_an_insert_that_would_overwrite_an_audit_row_is_stopped_by_the_trigger(conn, clock, statement):
    """INSERT is permitted for audit appends, so the collision guard trigger is what refuses these."""
    _seed(conn, clock)
    before = _snapshot(conn)
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        conn.execute(statement)
    assert _snapshot(conn) == before


def test_business_tables_keep_their_trigger_protection_under_the_authorizer(conn, clock):
    seeded = _seed(conn, clock)
    with store.transaction(conn):
        store.revoke_engagement(conn, clock, seeded.engagement)
    with pytest.raises(sqlite3.IntegrityError, match="revocation is final"):
        conn.execute("UPDATE engagements SET ends_at = ends_at + 1 WHERE id = ?", (seeded.engagement,))
    with pytest.raises(sqlite3.IntegrityError, match="identity is fixed"):
        conn.execute("UPDATE subjects SET subject = 'someone-else' WHERE id = ?", (seeded.subject,))


def test_replacing_the_authorizer_is_possible_for_code_that_holds_the_connection(db_path, conn):
    """A stated limit: the authorizer governs the connections the store hands out, not code that can reach them."""
    conn.set_authorizer(None)
    conn.execute("DROP TRIGGER audit_events_no_update")
    with pytest.raises(store.SchemaIntegrityError):
        store.connect(db_path)  # the drift is found by the next connection, not prevented


# --- the policy itself, by SQLite action code --------------------------------------------------------------------

DATA_ACTIONS = {
    "SELECT": (sqlite3.SQLITE_SELECT, None, None, OK),
    "READ a table": (sqlite3.SQLITE_READ, "audit_events", "action", OK),
    "READ the schema table": (sqlite3.SQLITE_READ, "sqlite_master", "sql", OK),
    "INSERT into a business table": (sqlite3.SQLITE_INSERT, "assets", None, OK),
    "INSERT into audit_events": (sqlite3.SQLITE_INSERT, "audit_events", None, OK),
    "UPDATE a business table": (sqlite3.SQLITE_UPDATE, "engagements", "revoked_at", OK),
    "UPDATE audit_events": (sqlite3.SQLITE_UPDATE, "audit_events", "action", DENY),
    "UPDATE audit_events in other case": (sqlite3.SQLITE_UPDATE, "AUDIT_EVENTS", "action", DENY),
    "DELETE from audit_events": (sqlite3.SQLITE_DELETE, "audit_events", None, DENY),
    "INSERT into sqlite_sequence": (sqlite3.SQLITE_INSERT, "sqlite_sequence", None, DENY),
    "UPDATE sqlite_sequence": (sqlite3.SQLITE_UPDATE, "sqlite_sequence", "seq", DENY),
    "DELETE from the schema table": (sqlite3.SQLITE_DELETE, "sqlite_master", None, DENY),
    "UPDATE the temporary schema table": (sqlite3.SQLITE_UPDATE, "sqlite_temp_master", "sql", DENY),
    "BEGIN": (sqlite3.SQLITE_TRANSACTION, "BEGIN", None, OK),
    "RELEASE": (sqlite3.SQLITE_SAVEPOINT, "RELEASE", "inner", OK),
    "recursive query": (sqlite3.SQLITE_RECURSIVE, None, None, OK),
    "an ordinary function": (sqlite3.SQLITE_FUNCTION, None, "lower", OK),
    "load_extension": (sqlite3.SQLITE_FUNCTION, None, "load_extension", DENY),
    "load_extension in other case": (sqlite3.SQLITE_FUNCTION, None, "LOAD_EXTENSION", DENY),
    "PRAGMA foreign_keys read": (sqlite3.SQLITE_PRAGMA, "foreign_keys", None, OK),
    "PRAGMA FOREIGN_KEYS read": (sqlite3.SQLITE_PRAGMA, "FOREIGN_KEYS", None, OK),
    "PRAGMA user_version read": (sqlite3.SQLITE_PRAGMA, "user_version", None, OK),
    "PRAGMA busy_timeout read": (sqlite3.SQLITE_PRAGMA, "busy_timeout", None, OK),
    "PRAGMA foreign_keys write": (sqlite3.SQLITE_PRAGMA, "foreign_keys", "OFF", DENY),
    "PRAGMA user_version write": (sqlite3.SQLITE_PRAGMA, "user_version", "2", DENY),
    "PRAGMA writable_schema": (sqlite3.SQLITE_PRAGMA, "writable_schema", None, DENY),
    "PRAGMA with an argument": (sqlite3.SQLITE_PRAGMA, "table_info", "audit_events", DENY),
    "an action code added by a later SQLite": (9999, None, None, DENY),
}


@pytest.mark.parametrize(("action", "arg1", "arg2", "expected"), DATA_ACTIONS.values(), ids=list(DATA_ACTIONS))
def test_the_policy_decides_by_action_code_and_object_name(action, arg1, arg2, expected):
    assert store._authorize(action, arg1, arg2, "main", None) == expected


STRUCTURAL_ACTIONS = [
    "CREATE_INDEX",
    "CREATE_TABLE",
    "CREATE_TEMP_INDEX",
    "CREATE_TEMP_TABLE",
    "CREATE_TEMP_TRIGGER",
    "CREATE_TEMP_VIEW",
    "CREATE_TRIGGER",
    "CREATE_VIEW",
    "CREATE_VTABLE",
    "DROP_INDEX",
    "DROP_TABLE",
    "DROP_TEMP_INDEX",
    "DROP_TEMP_TABLE",
    "DROP_TEMP_TRIGGER",
    "DROP_TEMP_VIEW",
    "DROP_TRIGGER",
    "DROP_VIEW",
    "DROP_VTABLE",
    "ALTER_TABLE",
    "ATTACH",
    "DETACH",
    "ANALYZE",
    "REINDEX",
]


@pytest.mark.parametrize("name", STRUCTURAL_ACTIONS)
def test_every_structural_action_is_refused(name):
    assert store._authorize(getattr(sqlite3, f"SQLITE_{name}"), "audit_events", None, "main", None) == DENY
