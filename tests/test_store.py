"""Store checks: schema, connections, constraints, transactions, revocation and audit triggers."""

import ast
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from content_boundary_lab import store
from content_boundary_lab.clock import to_micros

UTC = timezone.utc
T0 = datetime(2026, 11, 3, 12, 0, 0, tzinfo=UTC)
LATER = T0 + timedelta(days=30)
ISSUER = "https://idp.example"
MISSING_ID = "0" * 32
TABLES = {"productions", "subjects", "engagements", "assets", "deliveries", "verdicts", "audit_events"}
TRIGGERS = {
    "deliveries_seal_is_final",
    "deliveries_pass_needs_a_matching_verdict",
    "deliveries_acceptance_needs_a_matching_verdict",
    "deliveries_acceptance_is_final",
    "verdicts_are_not_replaced",
    "verdicts_are_kept",
    "verdicts_are_immutable",
    "deliveries_start_as_initiated",
    "deliveries_are_not_replaced",
    "deliveries_are_kept",
    "deliveries_identity_is_fixed",
    "deliveries_follow_the_lifecycle",
    "deliveries_receipt_is_final",
    "audit_events_no_update",
    "audit_events_no_delete",
    "audit_events_no_overwrite",
    "engagements_revocation_is_final",
    "engagements_revoked_rows_are_kept",
    "engagements_revoked_rows_are_not_replaced",
    "engagements_revoked_rows_are_not_overwritten_by_update",
    "subjects_identity_is_fixed",
}
INSERT_AUDIT = "INSERT INTO audit_events (at, action, outcome) VALUES (?, ?, ?)"
INSERT_ENGAGEMENT = (
    "INSERT OR REPLACE INTO engagements (id, subject_id, production_id, role, created_at, ends_at) VALUES (?, ?, ?, ?, ?, ?)"
)
INSERT_ENGAGEMENT_AT_ROWID = (
    "INSERT OR REPLACE INTO engagements (rowid, id, subject_id, production_id, role, created_at, ends_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?)"
)


class ManualClock:
    """Deterministic test clock (the same shape as the one in tests/test_clock.py)."""

    def __init__(self, start):
        self._now = start

    def now(self):
        return self._now

    def advance(self, delta):
        self._now += delta


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "lab.sqlite3"


@pytest.fixture
def clock():
    return ManualClock(T0)


@pytest.fixture
def conn(db_path):
    store.initialise_schema(db_path)
    connection = store.connect(db_path)
    yield connection
    connection.close()


def _scalar(connection, sql, *params):
    return connection.execute(sql, params).fetchone()[0]


def _schema_sql(connection):
    return [tuple(row) for row in connection.execute("SELECT type, name, sql FROM sqlite_master ORDER BY name")]


def _world(connection, clock):
    alpha = store.add_production(connection, clock, "ALPHA (synthetic)")
    bravo = store.add_production(connection, clock, "BRAVO (synthetic)")
    vendor = store.add_subject(connection, clock, ISSUER, "vendor-1", "Vendor One (synthetic)")
    coordinator = store.add_subject(connection, clock, ISSUER, "coordinator-1", "Coordinator One (synthetic)")
    contractor = store.add_subject(connection, clock, ISSUER, "contractor-1", "Contractor One (synthetic)")
    engagement = store.add_engagement(connection, clock, vendor, alpha, "vendor", LATER)
    return SimpleNamespace(
        alpha=alpha, bravo=bravo, vendor=vendor, coordinator=coordinator, contractor=contractor, engagement=engagement
    )


def _audit(connection, action="test.event"):
    return connection.execute(INSERT_AUDIT, (to_micros(T0), action, "recorded")).lastrowid


def _engagements(connection):
    return [tuple(row) for row in connection.execute("SELECT rowid, * FROM engagements ORDER BY rowid")]


# --- schema and versioning ---------------------------------------------------------------------------------------


def test_schema_is_created_in_a_fresh_database(db_path):
    store.initialise_schema(db_path)
    raw = sqlite3.connect(db_path)
    strict_by_table = {row[1]: row[5] for row in raw.execute("PRAGMA table_list") if not row[1].startswith("sqlite_")}
    assert strict_by_table == dict.fromkeys(TABLES, 1)
    assert {row[0] for row in raw.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")} == TRIGGERS
    assert raw.execute("SELECT 1 FROM sqlite_master WHERE name = 'assets_by_production'").fetchone()
    assert raw.execute("PRAGMA user_version").fetchone()[0] == store.SCHEMA_VERSION == 1
    raw.close()


def test_initialisation_is_idempotent(db_path, clock):
    store.initialise_schema(db_path)
    first = store.connect(db_path)
    production_id = store.add_production(first, clock, "ALPHA")
    before = _schema_sql(first)
    first.close()
    store.initialise_schema(db_path)
    second = store.connect(db_path)
    assert _schema_sql(second) == before
    assert _scalar(second, "SELECT name FROM productions WHERE id = ?", production_id) == "ALPHA"
    second.close()


@pytest.mark.parametrize("statement", ["PRAGMA user_version = 2", "PRAGMA user_version = 99", "PRAGMA user_version = -1"])
def test_unknown_schema_version_is_rejected(db_path, statement):
    store.initialise_schema(db_path)
    raw = sqlite3.connect(db_path)
    raw.execute(statement)
    raw.close()
    with pytest.raises(store.SchemaVersionError, match="version"):
        store.connect(db_path)
    with pytest.raises(store.SchemaVersionError, match="version"):
        store.initialise_schema(db_path)


def test_a_non_empty_unversioned_database_is_not_adopted(db_path):
    raw = sqlite3.connect(db_path)
    raw.execute("CREATE TABLE somebody_elses (x)")
    raw.commit()
    raw.close()
    with pytest.raises(store.SchemaVersionError, match="not empty"):
        store.initialise_schema(db_path)
    raw = sqlite3.connect(db_path)
    assert {row[0] for row in raw.execute("SELECT name FROM sqlite_master")} == {"somebody_elses"}
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 0
    raw.close()


def test_connect_does_not_create_or_initialise_a_database(db_path):
    with pytest.raises(sqlite3.OperationalError):
        store.connect(db_path)
    assert not db_path.exists()
    db_path.touch()
    with pytest.raises(store.SchemaVersionError):
        store.connect(db_path)
    raw = sqlite3.connect(db_path)
    assert raw.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0] == 0
    raw.close()


@pytest.mark.parametrize("keep", [2, len(store._SCHEMA)], ids=["fails-after-two-tables", "fails-after-the-version-pragma"])
def test_failed_schema_initialisation_leaves_nothing_behind(db_path, monkeypatch, keep):
    monkeypatch.setattr(store, "_SCHEMA", (*store._SCHEMA[:keep], "CREATE TABLE broken ("))
    with pytest.raises(sqlite3.OperationalError):
        store.initialise_schema(db_path)
    raw = sqlite3.connect(db_path)
    assert raw.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0] == 0
    assert raw.execute("PRAGMA user_version").fetchone()[0] == 0
    raw.close()
    monkeypatch.undo()
    store.initialise_schema(db_path)


def test_old_sqlite_versions_are_refused(db_path, monkeypatch):
    store.initialise_schema(db_path)
    monkeypatch.setattr(sqlite3, "sqlite_version_info", (3, 36, 0))
    with pytest.raises(store.StoreError, match="3.37"):
        store.connect(db_path)
    with pytest.raises(store.StoreError, match="3.37"):
        store.initialise_schema(db_path)


# --- connections -------------------------------------------------------------------------------------------------


def test_foreign_keys_are_enabled_on_every_application_connection(db_path):
    store.initialise_schema(db_path)
    connections = [store.connect(db_path) for _ in range(3)]
    for connection in connections:
        assert _scalar(connection, "PRAGMA foreign_keys") == 1
        assert not connection.in_transaction
        connection.close()


def test_application_connections_have_a_finite_busy_timeout(conn):
    assert 0 < store.BUSY_TIMEOUT_SECONDS < 60
    assert _scalar(conn, "PRAGMA busy_timeout") == int(store.BUSY_TIMEOUT_SECONDS * 1000)


# --- referential integrity and types -----------------------------------------------------------------------------


def test_orphan_engagements_and_assets_cannot_be_inserted(conn, clock):
    world = _world(conn, clock)
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        store.add_engagement(conn, clock, world.coordinator, MISSING_ID, "coordinator", LATER)
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        store.add_engagement(conn, clock, 9999, world.alpha, "vendor", LATER)
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        store.add_asset(conn, clock, MISSING_ID, "Plate 001")
    assert _scalar(conn, "SELECT COUNT(*) FROM engagements") == 1
    assert _scalar(conn, "SELECT COUNT(*) FROM assets") == 0


def test_referenced_parents_cannot_be_deleted(conn, clock):
    world = _world(conn, clock)
    store.add_asset(conn, clock, world.bravo, "Plate 001")
    for sql, key in [
        ("DELETE FROM productions WHERE id = ?", world.alpha),  # referenced by an engagement
        ("DELETE FROM productions WHERE id = ?", world.bravo),  # referenced by an asset
        ("DELETE FROM subjects WHERE id = ?", world.vendor),  # referenced by an engagement
    ]:
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            conn.execute(sql, (key,))
    assert conn.execute("DELETE FROM subjects WHERE id = ?", (world.coordinator,)).rowcount == 1  # control: unreferenced


@pytest.mark.parametrize(
    ("sql", "params"),
    [
        ("INSERT INTO productions (id, name, created_at) VALUES (?, ?, ?)", ("a" * 32, "ALPHA", "yesterday")),
        ("INSERT INTO productions (id, name, created_at) VALUES (?, ?, ?)", ("a" * 32, "ALPHA", 1.5)),
        ("INSERT INTO productions (id, name, created_at) VALUES (?, ?, ?)", ("a" * 32, b"ALPHA", 1)),
    ],
    ids=["text-in-integer-column", "fraction-in-integer-column", "blob-in-text-column"],
)
def test_strict_tables_reject_invalid_storage_types(conn, sql, params):
    with pytest.raises(sqlite3.IntegrityError, match="cannot store"):
        conn.execute(sql, params)


def test_timestamps_are_stored_as_integer_microseconds(conn, clock):
    store.add_production(conn, clock, "ALPHA")
    assert conn.execute("SELECT typeof(created_at), created_at FROM productions").fetchone()[:] == ("integer", to_micros(T0))


# --- uniqueness and value constraints ----------------------------------------------------------------------------


def test_duplicate_identities_are_rejected(conn, clock):
    store.add_subject(conn, clock, ISSUER, "vendor-1", "Vendor One")
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        store.add_subject(conn, clock, ISSUER, "vendor-1", "Someone Else")
    store.add_subject(conn, clock, ISSUER, "vendor-2", "Vendor Two")  # control: other subject
    store.add_subject(conn, clock, "https://other-idp.example", "vendor-1", "Vendor One")  # control: other issuer


def test_one_engagement_per_subject_and_production(conn, clock):
    world = _world(conn, clock)
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
        store.add_engagement(conn, clock, world.vendor, world.alpha, "coordinator", LATER + timedelta(days=1))
    store.add_engagement(conn, clock, world.vendor, world.bravo, "vendor", LATER)  # control: other production
    store.add_engagement(conn, clock, world.coordinator, world.alpha, "coordinator", LATER)  # control: other subject


CONSTRAINT_VIOLATIONS = {
    "unknown role": lambda c, k, w: store.add_engagement(c, k, w.coordinator, w.bravo, "admin", LATER),
    "role is case-sensitive": lambda c, k, w: store.add_engagement(c, k, w.coordinator, w.bravo, "Vendor", LATER),
    "ends at creation time": lambda c, k, w: store.add_engagement(c, k, w.coordinator, w.bravo, "vendor", T0),
    "ends before creation": lambda c, k, w: store.add_engagement(
        c, k, w.coordinator, w.bravo, "vendor", T0 - timedelta(microseconds=1)
    ),
    "empty production name": lambda c, k, w: store.add_production(c, k, ""),
    "overlong production name": lambda c, k, w: store.add_production(c, k, "x" * 201),
    "empty asset name": lambda c, k, w: store.add_asset(c, k, w.alpha, ""),
    "empty issuer": lambda c, k, w: store.add_subject(c, k, "", "someone", "Someone"),
    "empty subject": lambda c, k, w: store.add_subject(c, k, ISSUER, "", "Someone"),
    "overlong display name": lambda c, k, w: store.add_subject(c, k, ISSUER, "someone", "x" * 201),
}


@pytest.mark.parametrize("violate", CONSTRAINT_VIOLATIONS.values(), ids=list(CONSTRAINT_VIOLATIONS))
def test_check_constraints_reject_invalid_values(conn, clock, violate):
    world = _world(conn, clock)
    with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
        violate(conn, clock, world)


def test_an_engagement_may_end_one_microsecond_after_it_is_created(conn, clock):
    world = _world(conn, clock)
    store.add_engagement(conn, clock, world.coordinator, world.bravo, "coordinator", T0 + timedelta(microseconds=1))


def test_a_naive_end_time_is_rejected_before_anything_is_written(conn, clock):
    world = _world(conn, clock)
    with pytest.raises(ValueError, match="timezone-aware"):
        store.add_engagement(conn, clock, world.coordinator, world.bravo, "vendor", datetime(2030, 1, 1))
    assert _scalar(conn, "SELECT COUNT(*) FROM engagements") == 1


@pytest.mark.parametrize("bad_id", ["not-a-uuid", "A" * 32, "a" * 31, "a" * 33, "g" * 32, ""])
def test_identifiers_must_be_server_style_lowercase_hex(conn, bad_id):
    with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
        conn.execute("INSERT INTO productions (id, name, created_at) VALUES (?, ?, ?)", (bad_id, "ALPHA", 1))


def test_asset_to_production_relationships_are_preserved(conn, clock):
    world = _world(conn, clock)
    in_alpha = [store.add_asset(conn, clock, world.alpha, name) for name in ("Plate 001", "Plate 002")]
    in_bravo = store.add_asset(conn, clock, world.bravo, "Plate 001")
    rows = {row["id"]: row["production_id"] for row in conn.execute("SELECT id, production_id FROM assets")}
    assert rows == {in_alpha[0]: world.alpha, in_alpha[1]: world.alpha, in_bravo: world.bravo}
    assert _scalar(conn, "SELECT p.name FROM assets a JOIN productions p ON p.id = a.production_id WHERE a.id = ?", in_bravo) == (
        "BRAVO (synthetic)"
    )


# --- revocation is final -----------------------------------------------------------------------------------------


def test_revocation_can_be_set_once_and_never_cleared_or_changed(conn, clock):
    world = _world(conn, clock)
    clock.advance(timedelta(days=1))
    assert store.revoke_engagement(conn, clock, world.engagement) is True
    revoked_at = _scalar(conn, "SELECT revoked_at FROM engagements WHERE id = ?", world.engagement)
    assert revoked_at == to_micros(T0 + timedelta(days=1))
    clock.advance(timedelta(days=1))
    assert store.revoke_engagement(conn, clock, world.engagement) is False  # already revoked: nothing changes
    for sql in [
        "UPDATE engagements SET revoked_at = NULL WHERE id = ?",
        "UPDATE engagements SET revoked_at = revoked_at + 1 WHERE id = ?",
        "UPDATE OR REPLACE engagements SET revoked_at = NULL WHERE id = ?",
    ]:
        with pytest.raises(sqlite3.IntegrityError, match="revocation is final"):
            conn.execute(sql, (world.engagement,))
    assert _scalar(conn, "SELECT revoked_at FROM engagements WHERE id = ?", world.engagement) == revoked_at
    with pytest.raises(sqlite3.IntegrityError, match="revocation is final"):  # even an update that changes nothing
        conn.execute("UPDATE engagements SET revoked_at = revoked_at WHERE id = ?", (world.engagement,))


def test_a_missing_engagement_cannot_be_revoked(conn, clock):
    assert store.revoke_engagement(conn, clock, MISSING_ID) is False


def test_revocation_cannot_precede_creation_but_may_equal_it(conn, clock):
    world = _world(conn, clock)
    clock.advance(timedelta(microseconds=-1))
    with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
        store.revoke_engagement(conn, clock, world.engagement)
    clock.advance(timedelta(microseconds=1))
    assert store.revoke_engagement(conn, clock, world.engagement) is True


def test_a_revoked_engagement_cannot_be_deleted_or_replaced(conn, clock):
    world = _world(conn, clock)
    other = store.add_engagement(conn, clock, world.coordinator, world.alpha, "coordinator", LATER)
    store.revoke_engagement(conn, clock, world.engagement)
    rowid = _scalar(conn, "SELECT rowid FROM engagements WHERE id = ?", world.engagement)
    row = (to_micros(T0), to_micros(LATER))
    attempts = [
        ("DELETE FROM engagements WHERE id = ?", (world.engagement,)),
        (INSERT_ENGAGEMENT, (world.engagement, world.vendor, world.alpha, "vendor", *row)),  # same id
        (INSERT_ENGAGEMENT, ("b" * 32, world.vendor, world.alpha, "vendor", *row)),  # same subject and production
        (INSERT_ENGAGEMENT_AT_ROWID, (rowid, "c" * 32, world.contractor, world.bravo, "vendor", *row)),  # same rowid only
        ("UPDATE OR REPLACE engagements SET subject_id = ? WHERE id = ?", (world.vendor, other)),  # moved onto the pair
        ("UPDATE OR REPLACE engagements SET id = ? WHERE id = ?", (world.engagement, other)),  # moved onto the id
        ("UPDATE OR REPLACE engagements SET rowid = ? WHERE id = ?", (rowid, other)),  # moved onto the rowid
    ]
    before = _engagements(conn)
    for sql, params in attempts:
        with pytest.raises(sqlite3.IntegrityError, match="revocation is final"):
            conn.execute(sql, params)
        assert _engagements(conn) == before  # the revoked row, and everything else, is exactly as it was


REVOKED_ROW_UPDATES = {
    "production_id": lambda c, w: c.execute("UPDATE engagements SET production_id = ? WHERE id = ?", (w.bravo, w.engagement)),
    "subject_id": lambda c, w: c.execute("UPDATE engagements SET subject_id = ? WHERE id = ?", (w.contractor, w.engagement)),
    "id": lambda c, w: c.execute("UPDATE engagements SET id = ? WHERE id = ?", ("d" * 32, w.engagement)),
    "role": lambda c, w: c.execute("UPDATE engagements SET role = 'coordinator' WHERE id = ?", (w.engagement,)),
    "ends_at": lambda c, w: c.execute("UPDATE engagements SET ends_at = ends_at + 1 WHERE id = ?", (w.engagement,)),
    "created_at": lambda c, w: c.execute("UPDATE engagements SET created_at = created_at - 1 WHERE id = ?", (w.engagement,)),
    "revoked_at cleared": lambda c, w: c.execute("UPDATE engagements SET revoked_at = NULL WHERE id = ?", (w.engagement,)),
    "revoked_at changed": lambda c, w: c.execute("UPDATE engagements SET revoked_at = revoked_at + 1 WHERE id = ?", (w.engagement,)),
    "update that changes nothing": lambda c, w: c.execute("UPDATE engagements SET role = role WHERE id = ?", (w.engagement,)),
}


@pytest.mark.parametrize("update", REVOKED_ROW_UPDATES.values(), ids=list(REVOKED_ROW_UPDATES))
def test_a_revoked_engagement_cannot_be_updated_at_all(conn, clock, update):
    world = _world(conn, clock)
    store.revoke_engagement(conn, clock, world.engagement)
    before = _engagements(conn)
    with pytest.raises(sqlite3.IntegrityError, match="revocation is final"):
        update(conn, world)
    assert _engagements(conn) == before


def test_a_revoked_pair_cannot_be_freed_by_moving_the_revoked_row(conn, clock):
    world = _world(conn, clock)
    store.revoke_engagement(conn, clock, world.engagement)
    before = _engagements(conn)
    for move in (REVOKED_ROW_UPDATES["production_id"], REVOKED_ROW_UPDATES["subject_id"]):
        with pytest.raises(sqlite3.IntegrityError, match="revocation is final"):
            move(conn, world)
    with pytest.raises(sqlite3.IntegrityError, match="revocation is final"):
        store.add_engagement(conn, clock, world.vendor, world.alpha, "vendor", LATER)  # the original pair is still taken
    assert _engagements(conn) == before
    unrevoked = "SELECT COUNT(*) FROM engagements WHERE subject_id = ? AND production_id = ? AND revoked_at IS NULL"
    assert _scalar(conn, unrevoked, world.vendor, world.alpha) == 0


def test_an_unrevoked_engagement_can_still_be_updated_and_then_revoked(conn, clock):
    world = _world(conn, clock)
    update = "UPDATE engagements SET ends_at = ? WHERE id = ?"
    assert conn.execute(update, (to_micros(LATER) + 1, world.engagement)).rowcount == 1
    assert store.revoke_engagement(conn, clock, world.engagement) is True
    with pytest.raises(sqlite3.IntegrityError, match="revocation is final"):
        conn.execute(update, (to_micros(LATER), world.engagement))


def test_a_subjects_verified_identity_cannot_change(conn, clock):
    world = _world(conn, clock)
    before = [tuple(row) for row in conn.execute("SELECT * FROM subjects ORDER BY id")]
    for sql in [
        "UPDATE subjects SET subject = 'renamed' WHERE id = ?",
        "UPDATE subjects SET issuer = 'https://other.example' WHERE id = ?",
        "UPDATE OR REPLACE subjects SET subject = 'renamed' WHERE id = ?",
    ]:
        with pytest.raises(sqlite3.IntegrityError, match="identity is fixed"):
            conn.execute(sql, (world.vendor,))
    assert [tuple(row) for row in conn.execute("SELECT * FROM subjects ORDER BY id")] == before
    with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):  # so the identity cannot be added a second time either
        store.add_subject(conn, clock, ISSUER, "vendor-1", "Vendor again")
    assert conn.execute("UPDATE subjects SET display_name = ? WHERE id = ?", ("New display name", world.vendor)).rowcount == 1


# --- transactions ------------------------------------------------------------------------------------------------


def test_a_failed_transaction_rolls_back_every_change(conn, clock):
    with pytest.raises(RuntimeError, match="boom"):
        with store.transaction(conn):
            store.add_production(conn, clock, "ALPHA")
            store.add_subject(conn, clock, ISSUER, "vendor-1", "Vendor One")
            raise RuntimeError("boom")
    assert _scalar(conn, "SELECT COUNT(*) FROM productions") == 0
    assert _scalar(conn, "SELECT COUNT(*) FROM subjects") == 0
    assert not conn.in_transaction


def test_a_database_error_rolls_back_earlier_statements_in_the_transaction(conn, clock):
    with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
        with store.transaction(conn):
            store.add_production(conn, clock, "ALPHA")
            store.add_asset(conn, clock, MISSING_ID, "orphan")
    assert _scalar(conn, "SELECT COUNT(*) FROM productions") == 0
    assert not conn.in_transaction


def test_transactions_do_not_nest(conn):
    with store.transaction(conn):
        with pytest.raises(store.StoreError, match="already open"):
            with store.transaction(conn):
                pass
        assert conn.in_transaction
    assert not conn.in_transaction


def test_other_connections_see_only_committed_changes(db_path, conn, clock):
    reader = store.connect(db_path)
    with store.transaction(conn):
        store.add_production(conn, clock, "ALPHA")
        assert _scalar(reader, "SELECT COUNT(*) FROM productions") == 0  # written, not yet committed
    assert _scalar(reader, "SELECT COUNT(*) FROM productions") == 1
    reader.close()


def test_a_revocation_is_visible_to_the_next_statement_on_another_connection_once_committed(db_path, conn, clock):
    world = _world(conn, clock)
    reader = store.connect(db_path)
    active = "SELECT COUNT(*) FROM engagements WHERE id = ? AND revoked_at IS NULL"
    assert _scalar(reader, active, world.engagement) == 1
    with store.transaction(conn):
        store.revoke_engagement(conn, clock, world.engagement)
        assert _scalar(reader, active, world.engagement) == 1  # not committed yet
    assert _scalar(reader, active, world.engagement) == 0
    reader.close()


# --- audit table triggers ----------------------------------------------------------------------------------------


def test_audit_events_reject_update_delete_and_overwrite(conn):
    # This tests the trigger layer on its own. The connection's authorizer would refuse the UPDATE and DELETE
    # statements first (tests/test_store_hardening.py covers that), so it is removed for this test.
    conn.set_authorizer(None)
    seq = _audit(conn)
    original = [tuple(row) for row in conn.execute("SELECT * FROM audit_events")]
    attempts = [
        ("UPDATE audit_events SET action = 'forged' WHERE seq = ?", (seq,)),
        ("UPDATE OR REPLACE audit_events SET action = 'forged' WHERE seq = ?", (seq,)),
        ("DELETE FROM audit_events WHERE seq = ?", (seq,)),
        ("DELETE FROM audit_events", ()),
        ("INSERT OR REPLACE INTO audit_events (seq, at, action, outcome) VALUES (?, 1, 'forged', 'recorded')", (seq,)),
        ("INSERT OR IGNORE INTO audit_events (seq, at, action, outcome) VALUES (?, 1, 'forged', 'recorded')", (seq,)),
        ("INSERT INTO audit_events (seq, at, action, outcome) VALUES (?, 1, 'forged', 'recorded')", (seq,)),
        (
            "INSERT INTO audit_events (seq, at, action, outcome) VALUES (?, 1, 'forged', 'recorded') "
            "ON CONFLICT (seq) DO UPDATE SET action = 'forged'",
            (seq,),
        ),
    ]
    for sql, params in attempts:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            conn.execute(sql, params)
    assert [tuple(row) for row in conn.execute("SELECT * FROM audit_events")] == original
    assert _audit(conn) == seq + 1  # appending still works, and seq keeps increasing


def test_audit_event_values_are_constrained(conn):
    bad_rows = [
        ("INSERT INTO audit_events (at, action, outcome) VALUES (1, 'a', 'maybe')", ()),
        ("INSERT INTO audit_events (at, action, outcome, actor_issuer) VALUES (1, 'a', 'recorded', 'iss')", ()),
        ("INSERT INTO audit_events (at, action, outcome, actor_subject) VALUES (1, 'a', 'recorded', 'sub')", ()),
        ("INSERT INTO audit_events (at, action, outcome, object_id) VALUES (1, 'a', 'recorded', ?)", ("x" * 129,)),
    ]
    for sql, params in bad_rows:
        with pytest.raises(sqlite3.IntegrityError, match="CHECK"):
            conn.execute(sql, params)
    conn.execute(
        "INSERT INTO audit_events (at, action, outcome, actor_issuer, actor_subject, object_id) "
        "VALUES (1, 'a', 'denied', 'iss', 'sub', ?)",
        ("x" * 128,),
    )
    assert _scalar(conn, "SELECT COUNT(*) FROM audit_events") == 1


# --- parameterised SQL -------------------------------------------------------------------------------------------


def test_values_are_bound_as_parameters_not_spliced_into_sql(conn, clock):
    hostile = "Robert'); DROP TABLE productions; --"
    production_id = store.add_production(conn, clock, hostile)
    subject_id = store.add_subject(conn, clock, ISSUER, hostile, hostile)
    assert _scalar(conn, "SELECT name FROM productions WHERE id = ?", production_id) == hostile
    assert _scalar(conn, "SELECT subject FROM subjects WHERE id = ?", subject_id) == hostile
    assert _scalar(conn, "SELECT COUNT(*) FROM productions") == 1


def _non_literal_sql(source):
    """Line numbers of execute* calls whose SQL is not a string literal, a module-level string constant,
    or a loop variable over a module-level tuple of strings."""
    tree = ast.parse(source)

    def is_text(value):
        return isinstance(value, ast.Constant) and isinstance(value.value, str)

    constants = set()
    for node in tree.body:
        targets, value = (node.targets, node.value) if isinstance(node, ast.Assign) else (
            ([node.target], node.value) if isinstance(node, ast.AnnAssign) else ([], None)
        )
        if is_text(value) or (isinstance(value, ast.Tuple) and all(is_text(item) for item in value.elts)):
            constants |= {t.id for t in targets if isinstance(t, ast.Name)}
    loop_variables = {
        node.target.id
        for node in ast.walk(tree)
        if isinstance(node, ast.For)
        and isinstance(node.target, ast.Name)
        and isinstance(node.iter, ast.Name)
        and node.iter.id in constants
    }
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"execute", "executemany", "executescript"}:
                sql = node.args[0] if node.args else None
                if not (is_text(sql) or (isinstance(sql, ast.Name) and (sql.id in constants or sql.id in loop_variables))):
                    bad.append(node.lineno)
    return bad


def test_every_statement_in_the_store_is_a_literal_or_a_module_constant():
    assert _non_literal_sql(Path(store.__file__).read_text()) == []


@pytest.mark.parametrize(
    "source",
    ['c.execute(f"SELECT {x}")', 'c.execute("SELECT " + x)', "c.execute(query)", 'c.execute("SELECT %s" % x)'],
)
def test_the_sql_check_flags_spliced_statements(source):
    assert _non_literal_sql(source) != []
