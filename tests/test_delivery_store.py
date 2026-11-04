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
ATTEMPT, OTHER_ATTEMPT = "c" * 32, "d" * 32
ASSET, OTHER_ASSET = "e" * 32, "f" * 32
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
        verdict = add_verdict(conn)  # a no_detection verdict for SHA, which every delivery below is sealed with
    yield SimpleNamespace(conn=conn, clock=clock, alpha=alpha, bravo=bravo, vendor=vendor, other=other, path=path, verdict=verdict)
    conn.close()


def add_verdict(conn, **overrides):
    values = {
        "sha256": SHA, "engine_id": "lab-synthetic-marker", "engine_version": "1", "engine_kind": "synthetic",
        "policy_fingerprint": "f" * 64, "verdict": "no_detection", "scanned_sha256": SHA, "scanned_at": 10, "valid_until": 20,
        **overrides,
    }  # fmt: skip
    return store.add_verdict(conn, **values)


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


SEALED_STATES = ("REJECTED", "SCAN_FAILED", "SCAN_PASSED", "ACCEPTED", "PROMOTING", "PROMOTED", "INTEGRITY_FAILED")
WITH_VERDICT = ("SCAN_PASSED", "ACCEPTED", "PROMOTING", "PROMOTED")
ACCEPTED_STATES = ("ACCEPTED", "PROMOTING", "PROMOTED")
REASONS = {"REJECTED": "checksum_mismatch", "SCAN_FAILED": "timeout"}


def advance(world, delivery_id, state):
    """Set the state the way a milestone would: the receipt with the first step out of INITIATED, the seal and the
    reason and the verdict with the step into a state that needs them. Only the lifecycle trigger can refuse these."""
    if state == "INITIATED":
        world.conn.execute("UPDATE deliveries SET state = 'INITIATED' WHERE id = ?", (delivery_id,))
        return
    sealed = state in SEALED_STATES
    accepted = state in ACCEPTED_STATES
    promoting = state in ("PROMOTING", "PROMOTED")
    if state == "PROMOTED" and row(world, delivery_id)["state"] == "PROMOTING":
        add_asset_for(world, delivery_id)  # the database refuses PROMOTED without the asset it names
    world.conn.execute(
        "UPDATE deliveries SET state = ?, received_size = 7, received_sha256 = ?, uploaded_at = 5, "
        "sealed_size = COALESCE(?, sealed_size), sealed_sha256 = COALESCE(?, sealed_sha256), "
        "receipt_matched = COALESCE(?, receipt_matched), state_reason = ?, verdict_id = COALESCE(?, verdict_id), "
        "accepted_sha256 = COALESCE(?, accepted_sha256), accepted_at = COALESCE(?, accepted_at), "
        "accepted_by = COALESCE(?, accepted_by), promotion_attempt = COALESCE(?, promotion_attempt), "
        "asset_id = COALESCE(?, asset_id) WHERE id = ?",
        (
            state, SHA, 7 if sealed else None, SHA if sealed else None, 1 if sealed else None,
            REASONS.get(state), world.verdict if state in WITH_VERDICT else None,
            SHA if accepted else None, 6 if accepted else None, world.vendor if accepted else None,
            ATTEMPT if promoting else None, ASSET if promoting else None, delivery_id,
        ),
    )  # fmt: skip


def add_asset_for(world, delivery, **overrides):
    """The trusted asset row of a delivery, written the way promotion writes it (the delivery must be PROMOTING)."""
    values = {
        "id": ASSET, "production_id": world.alpha, "display_name": "clip.mov", "created_at": 9,
        "delivery_id": delivery, "sha256": SHA, "size": 7, **overrides,
    }  # fmt: skip
    world.conn.execute(
        "INSERT INTO assets (id, production_id, display_name, created_at, delivery_id, sha256, size) "
        "VALUES (:id, :production_id, :display_name, :created_at, :delivery_id, :sha256, :size)",
        values,
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


# --- M1I: the seal, the reason and the verdict on a delivery, and the verdicts table ----------------------------------
#
# These extend the one initial schema (no migration). The lifecycle names and arrows are untouched; what is new is that
# the database refuses a state that needs a seal, a reason or a verdict when it has none, and a SCAN_PASSED that is not
# bound to a no_detection verdict for its own sealed digest.


def sealing(world):
    created = new_delivery(world)
    at(world, created.id, "SEALING")
    return created


def test_a_new_delivery_has_no_seal_no_reason_and_no_verdict(world):
    created = new_delivery(world)
    stored = row(world, created.id)
    assert all(stored[column] is None for column in ("sealed_size", "sealed_sha256", "receipt_matched", "state_reason", "verdict_id"))


@pytest.mark.parametrize("state", ["INITIATED", "UPLOADED"])
def test_nothing_is_sealed_before_sealing_begins(world, state):
    created = new_delivery(world)
    at(world, created.id, state)
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute(
            "UPDATE deliveries SET sealed_size = 7, sealed_sha256 = ?, receipt_matched = 1 WHERE id = ?", (SHA, created.id)
        )


@pytest.mark.parametrize("state", ["REJECTED", "SCAN_FAILED", "SCAN_PASSED", "INTEGRITY_FAILED"])
def test_leaving_sealing_requires_the_sealed_digest_and_size(world, state):
    created = sealing(world)
    verdict = world.verdict if state == "SCAN_PASSED" else None
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute(
            "UPDATE deliveries SET state = ?, state_reason = ?, verdict_id = ? WHERE id = ?", (state, REASONS.get(state), verdict, created.id)
        )
    assert row(world, created.id)["state"] == "SEALING"


@pytest.mark.parametrize(
    "assignment",
    [
        "sealed_size = 7",
        "sealed_sha256 = '%s'" % SHA,
        "receipt_matched = 1",
        "sealed_size = 7, sealed_sha256 = '%s'" % SHA,  # the diagnostic is part of the seal
        "sealed_size = 7, sealed_sha256 = '%s', receipt_matched = 2" % SHA,
        "sealed_size = 7, sealed_sha256 = '%s', receipt_matched = -1" % SHA,
        "sealed_size = -1, sealed_sha256 = '%s', receipt_matched = 1" % SHA,
        "sealed_size = 7, sealed_sha256 = '%s', receipt_matched = 1" % SHA.upper(),
        "sealed_size = 7, sealed_sha256 = 'abc', receipt_matched = 1",
    ],
)
def test_a_seal_is_the_size_the_digest_and_the_diagnostic_together_and_well_formed(world, assignment):
    created = sealing(world)
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute(f"UPDATE deliveries SET state = 'REJECTED', state_reason = 'checksum_mismatch', {assignment} WHERE id = ?", (created.id,))
    assert row(world, created.id)["state"] == "SEALING"


def test_the_seal_is_written_once_and_never_changed(world):
    created = new_delivery(world)
    at(world, created.id, "REJECTED")
    before = row(world, created.id)
    for assignment, value in (("sealed_size", 8), ("sealed_sha256", OTHER_SHA), ("receipt_matched", 0)):
        with pytest.raises(sqlite3.IntegrityError, match="seal"):
            world.conn.execute(f"UPDATE deliveries SET {assignment} = ? WHERE id = ?", (value, created.id))
        with pytest.raises(sqlite3.IntegrityError):
            world.conn.execute(f"UPDATE deliveries SET {assignment} = NULL WHERE id = ?", (created.id,))
    world.conn.execute("UPDATE deliveries SET sealed_size = 7, sealed_sha256 = ?, receipt_matched = 1 WHERE id = ?", (SHA, created.id))
    assert row(world, created.id) == before  # writing the same values is not a change


@pytest.mark.parametrize(
    ("state", "reason"),
    [("REJECTED", "checksum_mismatch"), ("REJECTED", "unsupported_type"), ("REJECTED", "detection"),
     ("SCAN_FAILED", "unavailable"), ("SCAN_FAILED", "timeout"), ("SCAN_FAILED", "bad_response")],
)  # fmt: skip
def test_the_approved_reasons_are_accepted_for_their_own_state(world, state, reason):
    created = sealing(world)
    world.conn.execute(
        "UPDATE deliveries SET state = ?, state_reason = ?, sealed_size = 7, sealed_sha256 = ?, receipt_matched = 1 WHERE id = ?",
        (state, reason, SHA, created.id),
    )
    assert row(world, created.id)["state_reason"] == reason


@pytest.mark.parametrize(
    ("state", "reason"),
    [("REJECTED", "timeout"), ("REJECTED", "bad_response"), ("SCAN_FAILED", "detection"), ("SCAN_FAILED", "checksum_mismatch"),
     ("REJECTED", None), ("SCAN_FAILED", None), ("REJECTED", "clean"), ("REJECTED", ""), ("SCAN_FAILED", "TIMEOUT"),
     ("REJECTED", "checksum_mismatch "), ("REJECTED", "no_detection")],
)  # fmt: skip
def test_a_rejection_or_a_failure_needs_the_reason_that_belongs_to_it(world, state, reason):
    created = sealing(world)
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute(
            "UPDATE deliveries SET state = ?, state_reason = ?, sealed_size = 7, sealed_sha256 = ?, receipt_matched = 1 WHERE id = ?",
            (state, reason, SHA, created.id),
        )


@pytest.mark.parametrize("state", ["SEALING", "SCAN_PASSED"])
def test_no_other_state_carries_a_reason(world, state):
    created = new_delivery(world)
    at(world, created.id, state)
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute("UPDATE deliveries SET state_reason = 'timeout' WHERE id = ?", (created.id,))


def test_scan_passed_needs_a_no_detection_verdict_bound_to_the_sealed_digest(world):
    created = sealing(world)
    enter = "UPDATE deliveries SET state = 'SCAN_PASSED', sealed_size = 7, sealed_sha256 = ?, receipt_matched = 1, verdict_id = ? WHERE id = ?"
    elsewhere = add_verdict(world.conn, sha256=OTHER_SHA, scanned_sha256=OTHER_SHA)
    detection = add_verdict(world.conn, verdict="detection")
    for verdict_id, why in ((None, "no verdict"), ("0" * 32, "no such verdict"), (elsewhere, "a verdict for other bytes"), (detection, "a detection")):
        with pytest.raises(sqlite3.IntegrityError):
            world.conn.execute(enter, (SHA, verdict_id, created.id))
        assert row(world, created.id)["state"] == "SEALING", why
    world.conn.execute(enter, (SHA, world.verdict, created.id))
    assert row(world, created.id)["state"] == "SCAN_PASSED"


def test_a_detection_may_be_recorded_against_its_own_verdict_and_the_digest_of_the_bytes(world):
    created = sealing(world)
    detection = add_verdict(world.conn, verdict="detection")
    world.conn.execute(
        "UPDATE deliveries SET state = 'REJECTED', state_reason = 'detection', sealed_size = 7, sealed_sha256 = ?, receipt_matched = 1, verdict_id = ? WHERE id = ?",
        (SHA, detection, created.id),
    )
    assert row(world, created.id)["verdict_id"] == detection


# --- M1J: the acceptance record ----------------------------------------------------------------------------------------------
#
# A coordinator's acceptance is bound to the sealed digest. The database refuses an acceptance record before SCAN_PASSED, a
# state that needs one without it, a digest that is not the sealed one, a change to the record once written, and entry into
# ACCEPTED without a no_detection verdict bound to the delivery's own sealed digest.

ACCEPT = (
    "UPDATE deliveries SET state = 'ACCEPTED', accepted_sha256 = :sha256, accepted_at = :at, accepted_by = :by, "
    "verdict_id = :verdict WHERE id = :id"
)


def accept(world, delivery_id, **overrides):
    values = {"sha256": SHA, "at": 7, "by": world.other, "verdict": world.verdict, "id": delivery_id, **overrides}
    return world.conn.execute(ACCEPT, values)


def passed(world):
    created = new_delivery(world)
    at(world, created.id, "SCAN_PASSED")
    return created


def test_a_new_delivery_has_no_acceptance_record(world):
    stored = row(world, new_delivery(world).id)
    assert all(stored[column] is None for column in ("accepted_sha256", "accepted_at", "accepted_by"))


@pytest.mark.parametrize("state", ["INITIATED", "UPLOADED", "SEALING", "REJECTED", "SCAN_FAILED", "SCAN_PASSED"])
def test_nothing_is_accepted_before_it_is_accepted(world, state):
    created = new_delivery(world)
    at(world, created.id, state)
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute(
            "UPDATE deliveries SET accepted_sha256 = ?, accepted_at = 7, accepted_by = ? WHERE id = ?", (SHA, world.vendor, created.id)
        )
    assert row(world, created.id)["accepted_sha256"] is None


def test_a_valid_acceptance_binds_the_sealed_digest_the_time_and_the_coordinator(world):
    created = passed(world)
    accept(world, created.id)
    stored = row(world, created.id)
    assert (stored["state"], stored["accepted_sha256"], stored["accepted_at"], stored["accepted_by"]) == ("ACCEPTED", SHA, 7, world.other)
    assert stored["accepted_sha256"] == stored["sealed_sha256"]


ACCEPTANCE_HOSTILE = {
    "no time": {"at": None},
    "no coordinator": {"by": None},
    "no digest": {"sha256": None},
    "a digest other than the sealed one": {"sha256": OTHER_SHA},
    "a digest in capitals": {"sha256": SHA.upper()},
    "a digest that is too short": {"sha256": "a" * 63},
    "a coordinator who does not exist": {"by": 9999},
    "a negative time": {"at": -1},
}


@pytest.mark.parametrize("changes", ACCEPTANCE_HOSTILE.values(), ids=list(ACCEPTANCE_HOSTILE))
def test_an_acceptance_must_be_whole_well_formed_and_for_the_sealed_digest(world, changes):
    created = passed(world)
    with pytest.raises(sqlite3.IntegrityError):
        accept(world, created.id, **changes)
    assert row(world, created.id)["state"] == "SCAN_PASSED"


def test_accepted_is_refused_without_an_acceptance_record(world):
    created = passed(world)
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute("UPDATE deliveries SET state = 'ACCEPTED' WHERE id = ?", (created.id,))
    assert row(world, created.id)["state"] == "SCAN_PASSED"


@pytest.mark.parametrize("state", ACCEPTED_STATES)
def test_the_acceptance_record_is_written_once_and_never_changed(world, state):
    created = new_delivery(world)
    at(world, created.id, state)
    before = row(world, created.id)
    for column, value in (("accepted_sha256", OTHER_SHA), ("accepted_at", 8), ("accepted_by", world.other), ("verdict_id", None)):
        with pytest.raises(sqlite3.IntegrityError):
            world.conn.execute(f"UPDATE deliveries SET {column} = ? WHERE id = ?", (value, created.id))
    for column in ("accepted_sha256", "accepted_at", "accepted_by"):
        with pytest.raises(sqlite3.IntegrityError):
            world.conn.execute(f"UPDATE deliveries SET {column} = NULL WHERE id = ?", (created.id,))
    world.conn.execute(
        "UPDATE deliveries SET accepted_sha256 = ?, accepted_at = 6, accepted_by = ? WHERE id = ?", (SHA, world.vendor, created.id)
    )
    assert row(world, created.id) == before  # writing the same values is not a change


def test_entering_accepted_needs_a_no_detection_verdict_bound_to_the_sealed_digest(world):
    elsewhere = add_verdict(world.conn, sha256=OTHER_SHA, scanned_sha256=OTHER_SHA)
    detection = add_verdict(world.conn, verdict="detection")
    for verdict_id, why in ((None, "no verdict"), (elsewhere, "a verdict for other bytes"), (detection, "a detection"), ("0" * 32, "no such verdict")):
        created = passed(world)
        with pytest.raises(sqlite3.IntegrityError):
            accept(world, created.id, verdict=verdict_id)
        assert row(world, created.id)["state"] == "SCAN_PASSED", why
    created = passed(world)
    accept(world, created.id)
    assert row(world, created.id)["state"] == "ACCEPTED"


def test_a_delivery_that_failed_its_integrity_check_may_or_may_not_have_been_accepted(world):
    never_accepted, was_accepted = new_delivery(world), new_delivery(world)
    at(world, never_accepted.id, "INTEGRITY_FAILED")  # by a rescan, from SEALING
    at(world, was_accepted.id, "PROMOTING")
    world.conn.execute("UPDATE deliveries SET state = 'INTEGRITY_FAILED' WHERE id = ?", (was_accepted.id,))
    assert row(world, never_accepted.id)["accepted_sha256"] is None
    assert row(world, was_accepted.id)["accepted_sha256"] == SHA


def test_a_rescan_returns_a_delivery_to_sealing_with_its_seal_and_without_its_verdict(world):
    for start in ("SCAN_FAILED", "SCAN_PASSED"):
        created = new_delivery(world)
        at(world, created.id, start)
        world.conn.execute(
            "UPDATE deliveries SET state = 'SEALING', state_reason = NULL, verdict_id = NULL WHERE id = ?", (created.id,)
        )
        stored = row(world, created.id)
        assert (stored["state"], stored["sealed_sha256"], stored["verdict_id"], stored["state_reason"]) == ("SEALING", SHA, None, None)


# --- M1K: the promotion record, and the asset a delivery becomes ------------------------------------------------------------
#
# Promotion records, with the move out of ACCEPTED, the attempt id and the server-generated key the asset will have (P1);
# it writes the asset row and the move to PROMOTED together (P4). The database refuses a record outside PROMOTING and after,
# half a record, a change to it, PROMOTED without the asset it names, and an asset that names a delivery which is not
# PROMOTING for exactly that asset, production, digest and size.

BEGIN = "UPDATE deliveries SET state = 'PROMOTING', promotion_attempt = :attempt, asset_id = :asset WHERE id = :id"


def accepted_delivery(world):
    created = new_delivery(world)
    at(world, created.id, "ACCEPTED")
    return created


def begin_promotion(world, delivery_id, **overrides):
    return world.conn.execute(BEGIN, {"attempt": ATTEMPT, "asset": ASSET, "id": delivery_id, **overrides})


def test_a_new_delivery_has_no_promotion_record(world):
    stored = row(world, new_delivery(world).id)
    assert stored["promotion_attempt"] is None and stored["asset_id"] is None


@pytest.mark.parametrize("state", ["INITIATED", "UPLOADED", "SEALING", "REJECTED", "SCAN_FAILED", "SCAN_PASSED", "ACCEPTED"])
def test_nothing_is_promoted_before_it_is_promoting(world, state):
    created = new_delivery(world)
    at(world, created.id, state)
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute(
            "UPDATE deliveries SET promotion_attempt = ?, asset_id = ? WHERE id = ?", (ATTEMPT, ASSET, created.id)
        )
    assert row(world, created.id)["promotion_attempt"] is None


def test_promotion_begins_with_the_attempt_and_the_key_of_the_asset(world):
    created = accepted_delivery(world)
    begin_promotion(world, created.id)
    stored = row(world, created.id)
    assert (stored["state"], stored["promotion_attempt"], stored["asset_id"]) == ("PROMOTING", ATTEMPT, ASSET)
    assert stored["accepted_sha256"] == stored["sealed_sha256"] == SHA


PROMOTION_HOSTILE = {
    "no attempt": {"attempt": None},
    "no asset key": {"asset": None},
    "an attempt in capitals": {"attempt": ATTEMPT.upper()},
    "a short attempt": {"attempt": ATTEMPT[:-1]},
    "an asset key that is not hexadecimal": {"asset": "g" * 32},
    "an asset key with a path in it": {"asset": "../" + "a" * 29},
    "an asset key that is too long": {"asset": ASSET + "0"},
}


@pytest.mark.parametrize("changes", PROMOTION_HOSTILE.values(), ids=list(PROMOTION_HOSTILE))
def test_an_attempt_and_an_asset_key_come_together_and_well_formed(world, changes):
    created = accepted_delivery(world)
    with pytest.raises(sqlite3.IntegrityError):
        begin_promotion(world, created.id, **changes)
    assert row(world, created.id)["state"] == "ACCEPTED"


def test_two_deliveries_never_share_an_attempt_or_an_asset_key(world):
    first, second = accepted_delivery(world), accepted_delivery(world)
    begin_promotion(world, first.id)
    for changes in ({"asset": OTHER_ASSET}, {"attempt": OTHER_ATTEMPT}):  # each of the pair repeated
        with pytest.raises(sqlite3.IntegrityError):
            begin_promotion(world, second.id, **changes)
    assert row(world, second.id)["state"] == "ACCEPTED"


def test_promoting_needs_the_promotion_record(world):
    created = accepted_delivery(world)
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute("UPDATE deliveries SET state = 'PROMOTING' WHERE id = ?", (created.id,))
    assert row(world, created.id)["state"] == "ACCEPTED"


def promoting(world):
    created = new_delivery(world)
    at(world, created.id, "PROMOTING")
    return created


@pytest.mark.parametrize("state", ["PROMOTING", "PROMOTED", "INTEGRITY_FAILED"])
def test_the_promotion_record_is_written_once_and_never_changed(world, state):
    created = new_delivery(world)
    at(world, created.id, "PROMOTING")
    if state == "PROMOTED":
        add_asset_for(world, created.id)
        world.conn.execute("UPDATE deliveries SET state = 'PROMOTED' WHERE id = ?", (created.id,))
    elif state == "INTEGRITY_FAILED":
        world.conn.execute("UPDATE deliveries SET state = 'INTEGRITY_FAILED' WHERE id = ?", (created.id,))
    before = row(world, created.id)
    for column, value in (("promotion_attempt", OTHER_ATTEMPT), ("asset_id", OTHER_ASSET), ("promotion_attempt", None), ("asset_id", None)):
        with pytest.raises(sqlite3.IntegrityError):
            world.conn.execute(f"UPDATE deliveries SET {column} = ? WHERE id = ?", (value, created.id))
    world.conn.execute("UPDATE deliveries SET promotion_attempt = ?, asset_id = ? WHERE id = ?", (ATTEMPT, ASSET, created.id))
    assert row(world, created.id) == before  # writing the same values is not a change
    assert before["accepted_sha256"] == SHA


def test_a_delivery_that_failed_while_promoting_keeps_its_record_and_one_that_failed_sealing_has_none(world):
    sealing_failure, promotion_failure = new_delivery(world), promoting(world)
    at(world, sealing_failure.id, "INTEGRITY_FAILED")
    world.conn.execute("UPDATE deliveries SET state = 'INTEGRITY_FAILED' WHERE id = ?", (promotion_failure.id,))
    assert row(world, sealing_failure.id)["promotion_attempt"] is None
    assert (row(world, promotion_failure.id)["promotion_attempt"], row(world, promotion_failure.id)["asset_id"]) == (ATTEMPT, ASSET)


def test_promoted_needs_the_asset_it_names_and_not_before(world):
    created = promoting(world)
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute("UPDATE deliveries SET state = 'PROMOTED' WHERE id = ?", (created.id,))
    assert row(world, created.id)["state"] == "PROMOTING"
    add_asset_for(world, created.id)
    world.conn.execute("UPDATE deliveries SET state = 'PROMOTED' WHERE id = ?", (created.id,))
    assert row(world, created.id)["state"] == "PROMOTED"


ASSET_HOSTILE = {
    "an asset key other than the one reserved": {"id": OTHER_ASSET},
    "another production": {"production_id": "bravo"},
    "another digest": {"sha256": OTHER_SHA},
    "another size": {"size": 8},
    "a digest in capitals": {"sha256": SHA.upper()},
    "a negative size": {"size": -1},
    "a delivery that does not exist": {"delivery_id": "9" * 32},
}


@pytest.mark.parametrize("changes", ASSET_HOSTILE.values(), ids=list(ASSET_HOSTILE))
def test_an_asset_from_a_delivery_must_be_exactly_the_one_that_delivery_reserved(world, changes):
    created = promoting(world)
    if changes.get("production_id") == "bravo":
        changes = {**changes, "production_id": world.bravo}
    with pytest.raises(sqlite3.IntegrityError):
        add_asset_for(world, created.id, **changes)
    assert world.conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0


@pytest.mark.parametrize("state", ["ACCEPTED", "PROMOTED", "INTEGRITY_FAILED"])
def test_an_asset_is_written_only_while_its_delivery_is_promoting(world, state):
    created = accepted_delivery(world) if state == "ACCEPTED" else promoting(world)
    if state == "PROMOTED":
        add_asset_for(world, created.id)
        world.conn.execute("UPDATE deliveries SET state = 'PROMOTED' WHERE id = ?", (created.id,))
    elif state == "INTEGRITY_FAILED":
        world.conn.execute("UPDATE deliveries SET state = 'INTEGRITY_FAILED' WHERE id = ?", (created.id,))
    count = world.conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    with pytest.raises(sqlite3.IntegrityError):
        add_asset_for(world, created.id, id=OTHER_ASSET if state == "PROMOTED" else ASSET)
    assert world.conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == count


def test_one_delivery_becomes_one_asset(world):
    created = promoting(world)
    add_asset_for(world, created.id)
    with pytest.raises(sqlite3.IntegrityError):
        add_asset_for(world, created.id)


def test_an_asset_that_came_from_a_delivery_is_never_rebound(world):
    created = promoting(world)
    add_asset_for(world, created.id)
    for column, value in (("sha256", OTHER_SHA), ("size", 8), ("delivery_id", None), ("production_id", world.bravo), ("sha256", None)):
        with pytest.raises(sqlite3.IntegrityError):
            world.conn.execute(f"UPDATE assets SET {column} = ? WHERE id = ?", (value, ASSET))
    world.conn.execute("UPDATE assets SET sha256 = ?, size = 7 WHERE id = ?", (SHA, ASSET))  # the same values: not a change


def bound_asset(world):
    created = promoting(world)
    add_asset_for(world, created.id)
    return created


def test_an_asset_that_came_from_a_delivery_is_never_deleted(world):
    bound_asset(world)
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute("DELETE FROM assets WHERE id = ?", (ASSET,))
    assert world.conn.execute("SELECT COUNT(*) FROM assets WHERE id = ?", (ASSET,)).fetchone()[0] == 1


def test_a_seeded_asset_can_still_be_deleted_because_nothing_binds_it(world):
    seeded = store.add_asset(world.conn, world.clock, world.alpha, "seed.mov")
    world.conn.execute("DELETE FROM assets WHERE id = ?", (seeded,))
    assert world.conn.execute("SELECT COUNT(*) FROM assets WHERE id = ?", (seeded,)).fetchone()[0] == 0


REPLACEMENTS = {
    "by an unbound asset with the same id": "INSERT OR REPLACE INTO assets (id, production_id, display_name, created_at) VALUES ('%s', '%s', 'x', 1)",
    "by an unbound asset at the same row": "INSERT OR REPLACE INTO assets (rowid, id, production_id, display_name, created_at) VALUES (1, '%s', '%s', 'x', 1)",
}


@pytest.mark.parametrize("statement", REPLACEMENTS.values(), ids=list(REPLACEMENTS))
def test_an_asset_that_came_from_a_delivery_is_never_replaced(world, statement):
    bound_asset(world)
    before = dict(world.conn.execute("SELECT * FROM assets WHERE id = ?", (ASSET,)).fetchone())
    other_id = OTHER_ASSET if "rowid" in statement else ASSET
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute(statement % (other_id, world.alpha))
    assert dict(world.conn.execute("SELECT * FROM assets WHERE id = ?", (ASSET,)).fetchone()) == before


def test_an_asset_that_came_from_a_delivery_is_never_replaced_by_one_for_the_same_delivery(world):
    created = bound_asset(world)
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute(
            "INSERT OR REPLACE INTO assets (id, production_id, display_name, created_at, delivery_id, sha256, size) VALUES (?, ?, 'x', 1, ?, ?, 7)",
            (OTHER_ASSET, world.alpha, created.id, SHA),
        )
    assert [r[0] for r in world.conn.execute("SELECT id FROM assets")] == [ASSET]


def test_an_asset_that_was_not_bound_when_it_was_written_cannot_be_bound_to_a_delivery_afterwards(world):
    seeded = store.add_asset(world.conn, world.clock, world.alpha, "seed.mov")
    created = promoting(world)
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute(
            "UPDATE assets SET delivery_id = ?, sha256 = ?, size = 7 WHERE id = ?", (created.id, SHA, seeded)
        )  # the insert-time rule must not be bypassable by an update
    stored = dict(world.conn.execute("SELECT * FROM assets WHERE id = ?", (seeded,)).fetchone())
    assert (stored["delivery_id"], stored["sha256"], stored["size"]) == (None, None, None)


def test_a_seeded_asset_has_no_delivery_digest_or_size_and_cannot_have_just_some(world):
    seeded = store.add_asset(world.conn, world.clock, world.alpha, "seed.mov")
    stored = dict(world.conn.execute("SELECT * FROM assets WHERE id = ?", (seeded,)).fetchone())
    assert (stored["delivery_id"], stored["sha256"], stored["size"]) == (None, None, None)
    created = promoting(world)
    for changes in ({"sha256": None}, {"size": None}, {"delivery_id": None}):
        with pytest.raises(sqlite3.IntegrityError):
            add_asset_for(world, created.id, **changes)


VERDICT_HOSTILE = {
    "a digest in capitals": {"sha256": "A" * 64, "scanned_sha256": "A" * 64},
    "a short digest": {"sha256": "a" * 63, "scanned_sha256": "a" * 63},
    "a digest that is not hexadecimal": {"sha256": "g" * 64, "scanned_sha256": "g" * 64},
    "a scanner digest that is not the digest it is bound to": {"scanned_sha256": OTHER_SHA},
    "no engine id": {"engine_id": ""},
    "no engine version": {"engine_version": ""},
    "no policy fingerprint": {"policy_fingerprint": ""},
    "an engine kind outside the vocabulary": {"engine_kind": "real"},
    "an engine kind that claims to be clean": {"engine_kind": "clean"},
    "a verdict called clean": {"verdict": "clean"},
    "a verdict called safe": {"verdict": "safe"},
    "a verdict in capitals": {"verdict": "NO_DETECTION"},
    "a verdict that expires when it begins": {"scanned_at": 20, "valid_until": 20},
    "a verdict that expired before it began": {"scanned_at": 20, "valid_until": 10},
    "a negative scan time": {"scanned_at": -1},
    "an origin delivery that does not exist": {"delivery_id": "9" * 32},
}


@pytest.mark.parametrize("changes", VERDICT_HOSTILE.values(), ids=list(VERDICT_HOSTILE))
def test_a_verdict_must_be_bound_to_its_digest_and_labelled_with_the_engine_that_made_it(world, changes):
    before = world.conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
    with pytest.raises(sqlite3.IntegrityError):
        add_verdict(world.conn, **changes)
    assert world.conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0] == before


def test_a_verdict_keeps_exactly_what_it_was_given_and_has_a_server_made_id(world):
    verdict_id = add_verdict(world.conn, sha256=OTHER_SHA, scanned_sha256=OTHER_SHA, engine_version="2", scanned_at=100, valid_until=300)
    stored = dict(world.conn.execute("SELECT * FROM verdicts WHERE id = ?", (verdict_id,)).fetchone())
    assert HEX32.fullmatch(verdict_id) and stored["id"] == verdict_id
    assert (stored["sha256"], stored["engine_version"], stored["engine_kind"], stored["scanned_at"], stored["valid_until"]) == (OTHER_SHA, "2", "synthetic", 100, 300)
    assert len({add_verdict(world.conn) for _ in range(20)}) == 20


def test_a_verdict_can_never_be_changed_deleted_or_replaced(world):
    before = dict(world.conn.execute("SELECT * FROM verdicts WHERE id = ?", (world.verdict,)).fetchone())
    for column, value in (("valid_until", 10**15), ("verdict", "detection"), ("engine_version", "9"), ("sha256", OTHER_SHA), ("id", "e" * 32)):
        with pytest.raises(sqlite3.IntegrityError, match="verdict"):
            world.conn.execute(f"UPDATE verdicts SET {column} = ? WHERE id = ?", (value, world.verdict))
    with pytest.raises(sqlite3.IntegrityError, match="verdict"):
        world.conn.execute("UPDATE verdicts SET valid_until = valid_until WHERE id = ?", (world.verdict,))  # not even a no-op
    with pytest.raises(sqlite3.IntegrityError, match="verdict"):
        world.conn.execute("DELETE FROM verdicts")
    with pytest.raises(sqlite3.IntegrityError):
        world.conn.execute(
            "INSERT OR REPLACE INTO verdicts (id, sha256, engine_id, engine_version, engine_kind, policy_fingerprint, verdict, "
            "scanned_sha256, scanned_at, valid_until) VALUES (?, ?, 'x', 'x', 'synthetic', 'x', 'detection', ?, 1, 2)",
            (world.verdict, SHA, SHA),
        )
    assert dict(world.conn.execute("SELECT * FROM verdicts WHERE id = ?", (world.verdict,)).fetchone()) == before
