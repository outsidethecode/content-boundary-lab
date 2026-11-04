"""The deliveries table: M0's states and transitions, fixed identity and ownership, a write-once receipt, hostile values.

The lifecycle below is copied from Addendum §5.2 on purpose and not imported from the code: the schema is checked
against the design, not against itself. M1H uses INITIATED and INITIATED -> UPLOADED; the other states exist so that
the later milestones (seal, trust gate, acceptance, promotion) cannot skip a step the design does not allow.
"""

import itertools
import re
import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from support.http_lab import STATE_ROUTES

from content_boundary_lab import store
from content_boundary_lab.clock import to_micros

UTC = timezone.utc
T0 = datetime(2026, 11, 3, 12, tzinfo=UTC)
ISSUER = "https://idp.example"
SHA = "a" * 64
OTHER_SHA = "b" * 64
HEX32 = re.compile(r"[0-9a-f]{32}")

STATES = (
    "INITIATED",
    "UPLOADED",
    "SEALING",
    "REJECTED",
    "SCAN_FAILED",
    "SCAN_PASSED",
    "ACCEPTED",
    "PROMOTING",
    "PROMOTED",
    "INTEGRITY_FAILED",
)
TRANSITIONS = frozenset(
    {
        ("INITIATED", "UPLOADED"),
        ("UPLOADED", "SEALING"),
        ("SEALING", "REJECTED"),
        ("SEALING", "SCAN_FAILED"),
        ("SEALING", "SCAN_PASSED"),
        ("SEALING", "INTEGRITY_FAILED"),
        ("SCAN_FAILED", "SEALING"),
        ("SCAN_PASSED", "SEALING"),
        ("SCAN_PASSED", "ACCEPTED"),
        ("ACCEPTED", "PROMOTING"),
        ("PROMOTING", "PROMOTED"),
        ("PROMOTING", "INTEGRITY_FAILED"),
    }
)  # PROMOTING -> PROMOTING (reconcile after a crash) leaves the state as it is, so it is not a change of state
PAIRS = list(itertools.product(STATES, STATES))
INSERT = (
    "INSERT INTO deliveries (id, production_id, owner_subject_id, storage_key, display_name, declared_size, "
    "declared_sha256, declared_media_type, state, created_at, uploaded_at, received_size, received_sha256) "
    "VALUES (:id, :production_id, :owner_subject_id, :storage_key, :display_name, :declared_size, :declared_sha256, "
    ":declared_media_type, :state, :created_at, :uploaded_at, :received_size, :received_sha256)"
)


class FixedClock:
    def __init__(self, moment):
        self.moment = moment

    def now(self):
        return self.moment


@pytest.fixture
def world(tmp_path):
    path = tmp_path / "lab.sqlite3"
    store.initialise_schema(path)
    conn = store.connect(path)
    clock = FixedClock(T0)
    with store.transaction(conn):
        alpha, bravo = store.add_production(conn, clock, "ALPHA"), store.add_production(conn, clock, "BRAVO")
        vendor = store.add_subject(conn, clock, ISSUER, "vendor-1", "Vendor")
        other = store.add_subject(conn, clock, ISSUER, "vendor-2", "Other")
    yield SimpleNamespace(conn=conn, clock=clock, alpha=alpha, bravo=bravo, vendor=vendor, other=other, path=path)
    conn.close()


def new_delivery(world, **overrides):
    arguments = {
        "production_id": world.alpha,
        "subject_id": world.vendor,
        "display_name": "clip.mov",
        "declared_size": 1000,
        "declared_sha256": SHA,
        "declared_media_type": "video/quicktime",
        **overrides,
    }
    return store.add_delivery(world.conn, world.clock, **arguments)


def row(world, delivery_id):
    return dict(world.conn.execute("SELECT * FROM deliveries WHERE id = ?", (delivery_id,)).fetchone())


def advance(world, delivery_id, state):
    """Set the state the way a milestone would: the receipt is written together with the first step out of INITIATED."""
    if state == "INITIATED":
        world.conn.execute("UPDATE deliveries SET state = 'INITIATED' WHERE id = ?", (delivery_id,))
        return
    world.conn.execute(
        "UPDATE deliveries SET state = ?, received_size = 7, received_sha256 = ?, uploaded_at = 5 WHERE id = ?",
        (state, SHA, delivery_id),
    )


def at(world, delivery_id, state):
    for step in STATE_ROUTES[state]:
        advance(world, delivery_id, step)
    assert row(world, delivery_id)["state"] == state


def insert_raw(world, **overrides):
    values = {
        "id": "1" * 32,
        "production_id": world.alpha,
        "owner_subject_id": world.vendor,
        "storage_key": "2" * 32,
        "display_name": "clip.mov",
        "declared_size": 1000,
        "declared_sha256": SHA,
        "declared_media_type": "video/quicktime",
        "state": "INITIATED",
        "created_at": 1,
        "uploaded_at": None,
        "received_size": None,
        "received_sha256": None,
        **overrides,
    }
    world.conn.execute(INSERT, values)
    return values["id"]


# --- the design's states and transitions -------------------------------------------------------------------------


def test_the_states_are_exactly_the_ten_of_the_design_in_its_order():
    assert tuple(state.value for state in store.DeliveryState) == STATES


def test_the_transitions_are_exactly_the_design_s():
    assert {(a.value, b.value) for a, b in store.DELIVERY_TRANSITIONS} == TRANSITIONS


def test_a_new_delivery_is_initiated_owned_by_its_vendor_and_has_no_receipt(world):
    created = new_delivery(world)
    stored = row(world, created.id)
    assert (stored["state"], stored["production_id"], stored["owner_subject_id"]) == ("INITIATED", world.alpha, world.vendor)
    assert (stored["received_size"], stored["received_sha256"], stored["uploaded_at"]) == (None, None, None)
    assert (stored["declared_size"], stored["declared_sha256"], stored["created_at"]) == (1000, SHA, to_micros(T0))
    assert HEX32.fullmatch(created.id) and HEX32.fullmatch(created.storage_key) and created.id != created.storage_key


def test_storage_keys_and_ids_are_server_generated_and_never_repeat(world):
    made = [new_delivery(world) for _ in range(40)]
    assert len({d.id for d in made}) == len({d.storage_key for d in made}) == 40
    assert not {d.id for d in made} & {d.storage_key for d in made}


@pytest.mark.parametrize(("start", "end"), PAIRS, ids=[f"{a} to {b}" for a, b in PAIRS])
def test_a_change_of_state_is_possible_only_where_the_design_has_an_arrow(world, start, end):
    created = new_delivery(world)
    at(world, created.id, start)
    if (start, end) in TRANSITIONS:
        advance(world, created.id, end)
        assert row(world, created.id)["state"] == end
    elif start == end:
        advance(world, created.id, end)  # not a change of state; PROMOTING -> PROMOTING is the design's reconcile step
        assert row(world, created.id)["state"] == start
    else:
        with pytest.raises(sqlite3.IntegrityError, match="lifecycle"):
            advance(world, created.id, end)
        assert row(world, created.id)["state"] == start


@pytest.mark.parametrize("state", STATES[1:])
def test_a_delivery_can_only_begin_as_initiated(world, state):
    with pytest.raises(sqlite3.IntegrityError, match="INITIATED"):
        insert_raw(world, state=state, uploaded_at=5, received_size=7, received_sha256=SHA)
    assert world.conn.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 0


@pytest.mark.parametrize("state", ["SEALED", "initiated", "Initiated", "CLEAN", "INITIATED ", "", "DROP TABLE x"])
def test_a_state_outside_the_design_is_refused(world, state):
    with pytest.raises(sqlite3.IntegrityError):
        insert_raw(world, state=state)
    created = new_delivery(world)
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute("UPDATE deliveries SET state = ? WHERE id = ?", (state, created.id))
    assert row(world, created.id)["state"] == "INITIATED"


# --- identity and ownership never change -------------------------------------------------------------------------

IDENTITY_CHANGES = {
    "id": "f" * 32,
    "production_id": "BRAVO",
    "owner_subject_id": "OTHER",
    "storage_key": "e" * 32,
    "display_name": "other.mov",
    "declared_size": 1,
    "declared_sha256": OTHER_SHA,
    "declared_media_type": "audio/wav",
    "created_at": 1,
    "rowid": 99,
}


@pytest.mark.parametrize("column", IDENTITY_CHANGES)
@pytest.mark.parametrize("state", ["INITIATED", "UPLOADED", "SCAN_PASSED", "PROMOTED"])
def test_identity_and_ownership_never_change_in_any_state(world, column, state):
    created = new_delivery(world)
    at(world, created.id, state)
    value = {"BRAVO": world.bravo, "OTHER": world.other}.get(IDENTITY_CHANGES[column], IDENTITY_CHANGES[column])
    before = row(world, created.id)
    with pytest.raises(sqlite3.IntegrityError, match="identity"):
        world.conn.execute(f"UPDATE deliveries SET {column} = ? WHERE id = ?", (value, created.id))
    assert row(world, created.id) == before


def test_an_update_that_changes_nothing_is_not_a_change_of_identity(world):
    created = new_delivery(world)
    world.conn.execute("UPDATE deliveries SET display_name = display_name, storage_key = storage_key WHERE id = ?", (created.id,))


def test_a_delivery_is_never_deleted(world):
    created = new_delivery(world)
    with pytest.raises(sqlite3.IntegrityError, match="kept"):
        world.conn.execute("DELETE FROM deliveries WHERE id = ?", (created.id,))
    with pytest.raises(sqlite3.IntegrityError, match="kept"):
        world.conn.execute("DELETE FROM deliveries")
    assert row(world, created.id)["state"] == "INITIATED"


@pytest.mark.parametrize("collide", ["id", "storage_key", "rowid"])
def test_a_delivery_is_never_replaced_by_another_insert(world, collide):
    created = new_delivery(world)
    at(world, created.id, "SCAN_PASSED")
    before = row(world, created.id)
    rowid = world.conn.execute("SELECT rowid FROM deliveries WHERE id = ?", (created.id,)).fetchone()[0]
    values = {"id": "1" * 32, "storage_key": "2" * 32}
    if collide == "id":
        values["id"] = created.id
    elif collide == "storage_key":
        values["storage_key"] = created.storage_key
    statement = INSERT.replace("INSERT INTO", "INSERT OR REPLACE INTO")
    parameters = {
        "production_id": world.alpha, "owner_subject_id": world.vendor, "display_name": "x", "declared_size": 1,
        "declared_sha256": SHA, "declared_media_type": "a/b", "state": "INITIATED", "created_at": 1, "uploaded_at": None,
        "received_size": None, "received_sha256": None, **values,
    }  # fmt: skip
    if collide == "rowid":
        statement = statement.replace("(id,", "(rowid, id,").replace("(:id,", "(:rowid, :id,")
        parameters["rowid"] = rowid
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute(statement, parameters)
    assert row(world, created.id) == before  # an earlier delivery cannot be reset to INITIATED by writing it again


# --- the receipt ---------------------------------------------------------------------------------------------------


def test_the_receipt_is_written_once_and_never_changed(world):
    created = new_delivery(world)
    at(world, created.id, "UPLOADED")
    before = row(world, created.id)
    for column, value in (("received_size", 8), ("received_sha256", OTHER_SHA), ("uploaded_at", 6)):
        with pytest.raises(sqlite3.IntegrityError):
            world.conn.execute(f"UPDATE deliveries SET {column} = ? WHERE id = ?", (value, created.id))
    for column in ("received_size", "received_sha256", "uploaded_at"):
        with pytest.raises(sqlite3.IntegrityError):
            world.conn.execute(f"UPDATE deliveries SET {column} = NULL WHERE id = ?", (created.id,))
    assert row(world, created.id) == before


def test_the_receipt_and_the_state_always_agree(world):
    created = new_delivery(world)
    with pytest.raises(sqlite3.IntegrityError):  # leaving INITIATED without a receipt
        world.conn.execute("UPDATE deliveries SET state = 'UPLOADED' WHERE id = ?", (created.id,))
    with pytest.raises(sqlite3.IntegrityError):  # a receipt on a delivery that is still INITIATED
        world.conn.execute("UPDATE deliveries SET received_size = 7, received_sha256 = ?, uploaded_at = 5 WHERE id = ?", (SHA, created.id))
    with pytest.raises(sqlite3.IntegrityError):  # half a receipt
        world.conn.execute("UPDATE deliveries SET state = 'UPLOADED', received_size = 7 WHERE id = ?", (created.id,))
    assert row(world, created.id)["state"] == "INITIATED"


# --- hostile values --------------------------------------------------------------------------------------------------

HOSTILE = {
    "an id that climbs": ("id", "../" + "a" * 29),
    "an id in capitals": ("id", "A" * 32),
    "an id one character short": ("id", "a" * 31),
    "an id one character long": ("id", "a" * 33),
    "an id with a NUL": ("id", "a" * 31 + "\x00"),
    "an empty id": ("id", ""),
    "a storage key that is a path": ("storage_key", "/etc/passwd" + "a" * 21),
    "a storage key with a separator": ("storage_key", "a/b" + "c" * 29),
    "a storage key in capitals": ("storage_key", "B" * 32),
    "a storage key that is the staging directory": ("storage_key", ".incoming"),
    "an uppercase declared hash": ("declared_sha256", "A" * 64),
    "a short declared hash": ("declared_sha256", "a" * 63),
    "a long declared hash": ("declared_sha256", "a" * 65),
    "a declared hash that is not hex": ("declared_sha256", "g" * 64),
    "an empty display name": ("display_name", ""),
    "a display name over 200 characters": ("display_name", "x" * 201),
    "an empty media type": ("declared_media_type", ""),
    "a media type over 255 characters": ("declared_media_type", "x" * 256),
    "a negative declared size": ("declared_size", -1),
    "a declared size that is text": ("declared_size", "twelve"),  # "12" would be coerced to 12 by SQLite, so it is not text
    "an unknown production": ("production_id", "9" * 32),
    "an unknown owner": ("owner_subject_id", 9999),
    "a null owner": ("owner_subject_id", None),
}


@pytest.mark.parametrize(("column", "value"), HOSTILE.values(), ids=list(HOSTILE))
def test_values_outside_the_shapes_the_schema_allows_are_refused(world, column, value):
    with pytest.raises(sqlite3.IntegrityError):
        insert_raw(world, **{column: value})
    assert world.conn.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 0


def test_the_boundary_values_are_accepted(world):
    insert_raw(world, display_name="x", declared_size=0, declared_media_type="a/b")
    insert_raw(
        world,
        id="3" * 32,
        storage_key="4" * 32,
        display_name="x" * 200,
        declared_size=2**63 - 1,
        declared_media_type="m" * 255,
    )
    assert world.conn.execute("SELECT COUNT(*) FROM deliveries").fetchone()[0] == 2


def test_a_storage_key_belongs_to_one_delivery(world):
    insert_raw(world)
    with pytest.raises(sqlite3.IntegrityError):
        insert_raw(world, id="3" * 32)  # the same storage key under a different id


def test_a_database_without_the_deliveries_table_is_refused_at_connection(world):
    world.conn.close()
    raw = sqlite3.connect(world.path)
    raw.execute("DROP TABLE deliveries")
    raw.close()
    with pytest.raises(store.SchemaIntegrityError, match="deliveries"):
        store.connect(world.path)


def test_the_schema_version_is_unchanged_because_the_initial_schema_is_still_the_only_one():
    assert store.SCHEMA_VERSION == 1
