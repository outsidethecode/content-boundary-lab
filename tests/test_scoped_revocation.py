"""store.revoke_engagement_in_production: a revocation that can only reach engagements of the production it names.

The point of these tests is one property: a coordinator authorised for ALPHA cannot revoke an engagement of BRAVO by
presenting BRAVO's engagement id with ALPHA's production id. They run against the real hardened store, a SQLite file
per test, and identities produced by the real verifier. Nothing here goes through HTTP (that is the next stage).
"""

import ast
import inspect
import sqlite3
from dataclasses import FrozenInstanceError, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from support import token_issuer as tokens

from content_boundary_lab import identity, store
from content_boundary_lab.authz import Action, AuthorizationDenied, authorize_engagement
from content_boundary_lab.clock import to_micros

UTC = timezone.utc
T0 = datetime(2026, 11, 3, 12, tzinfo=UTC)
NOW = to_micros(T0)
LATER = NOW + 3_600_000_000  # an hour on
SEEDED_AT = T0 - timedelta(days=1)
KEY = tokens.new_key("key-1")


class Fixed:
    def __init__(self, moment: datetime) -> None:
        self.moment = moment

    def now(self) -> datetime:
        return self.moment


@dataclass
class World:
    path: Path
    conn: sqlite3.Connection
    alpha: str
    bravo: str
    e: dict[str, str]  # engagement ids by subject name

    def rows(self) -> list[tuple]:
        """Every engagement row, exactly as stored."""
        query = "SELECT id, subject_id, production_id, role, created_at, ends_at, revoked_at FROM engagements ORDER BY id"
        return [tuple(row) for row in self.conn.execute(query)]

    def revoked_at(self, subject: str) -> int | None:
        return self.conn.execute("SELECT revoked_at FROM engagements WHERE id = ?", (self.e[subject],)).fetchone()[0]


@pytest.fixture
def world(tmp_path) -> World:
    path = tmp_path / "lab.sqlite3"
    store.initialise_schema(path)
    conn = store.connect(path)
    seeding = Fixed(SEEDED_AT)
    ends = T0 + timedelta(days=30)
    ids: dict[str, str] = {}
    with store.transaction(conn):
        alpha, bravo = store.add_production(conn, seeding, "ALPHA"), store.add_production(conn, seeding, "BRAVO")
        for subject, production, role in (
            ("coordinator-a", alpha, "coordinator"),
            ("vendor-a", alpha, "vendor"),
            ("other-a", alpha, "vendor"),
            ("coordinator-b", bravo, "coordinator"),
            ("vendor-b", bravo, "vendor"),
        ):
            subject_id = store.add_subject(conn, seeding, tokens.ISSUER, subject, subject)
            ids[subject] = store.add_engagement(conn, seeding, subject_id, production, role, ends)
    yield World(path, conn, alpha, bravo, ids)
    conn.close()


def revoke(world: World, production: str, engagement: str, now: int = NOW):
    """One caller-owned transaction around the function under test."""
    with store.transaction(world.conn):
        return store.revoke_engagement_in_production(world.conn, production, engagement, now)


def verified(subject: str):
    token = tokens.mint(KEY, sub=subject)
    return identity.authenticate(f"Bearer {token}", tokens.trusted_settings(KEY), Fixed(T0))


def traced(conn: sqlite3.Connection) -> list[str]:
    """Collect the data statements the connection runs from now on, not the caller's own COMMIT or ROLLBACK.

    SQLite traces a statement again for each trigger it fires, so a repeat of the previous statement is dropped.
    """
    statements: list[str] = []

    def collect(sql: str) -> None:
        if sql not in {"COMMIT", "ROLLBACK"} and (not statements or statements[-1] != sql):
            statements.append(sql)

    conn.set_trace_callback(collect)
    return statements


def function_tree() -> ast.FunctionDef:
    tree = ast.parse(inspect.getsource(store.revoke_engagement_in_production))
    return tree.body[0]


# ------------------------------------------------------------------------- the property: no cross-production reach


def test_an_alpha_coordinator_cannot_revoke_a_bravo_engagement_with_bravos_id_under_alphas_production(world):
    before = world.rows()
    with store.transaction(world.conn):
        coordinator = verified("coordinator-a")
        grant = authorize_engagement(world.conn, coordinator, world.alpha, Action.MANAGE_ENGAGEMENTS, NOW)
        result = store.revoke_engagement_in_production(world.conn, world.alpha, world.e["vendor-b"], NOW)
    assert grant.role == "coordinator"  # the caller really is authorised to manage ALPHA
    assert result.status == "not_found" and result.revoked_at is None
    assert world.revoked_at("vendor-b") is None  # BRAVO's engagement is still active
    assert world.rows() == before  # and nothing anywhere changed
    with store.transaction(world.conn):  # BRAVO's vendor can still be authorised
        assert authorize_engagement(world.conn, verified("vendor-b"), world.bravo, Action.VIEW_OWN_ENGAGEMENT, NOW)


def test_the_unscoped_function_is_the_hazard_the_scoped_one_replaces(world):
    # Documented, not endorsed: this is why request-controlled ids must never reach store.revoke_engagement (the
    # source guard enforces it). When that function is removed, this test goes with it.
    with store.transaction(world.conn):
        assert store.revoke_engagement(world.conn, Fixed(T0), world.e["vendor-b"]) is True
    assert world.revoked_at("vendor-b") is not None  # no production was named, so none could protect BRAVO


def test_a_bravo_engagement_that_is_already_revoked_is_still_not_found_under_alpha(world):
    revoke(world, world.bravo, world.e["vendor-b"])
    # Not ALREADY_REVOKED: that would tell an ALPHA caller something about BRAVO.
    assert revoke(world, world.alpha, world.e["vendor-b"], LATER) == revoke(world, world.alpha, "f" * 32, LATER)


@pytest.mark.parametrize(
    "target",
    ["missing id", "bravo's id under alpha", "alpha's id under bravo", "no such production", "neither exists"],
)
def test_missing_and_wrong_production_targets_give_the_same_result(world, target):
    production, engagement = {
        "missing id": (world.alpha, "f" * 32),
        "bravo's id under alpha": (world.alpha, world.e["vendor-b"]),
        "alpha's id under bravo": (world.bravo, world.e["vendor-a"]),
        "no such production": ("e" * 32, world.e["vendor-a"]),
        "neither exists": ("e" * 32, "f" * 32),
    }[target]
    before = world.rows()
    result = revoke(world, production, engagement)
    assert result == revoke(world, world.alpha, "f" * 32)  # one and the same value as a plain miss
    assert (result.status, result.revoked_at) == ("not_found", None)
    assert world.rows() == before


# -------------------------------------------------------------------------------------------------- the happy path


def test_revoking_the_right_engagement_in_the_right_production_works(world):
    before = world.rows()
    result = revoke(world, world.alpha, world.e["vendor-a"])
    assert (result.status, result.revoked_at) == ("revoked", NOW)
    assert world.revoked_at("vendor-a") == NOW
    changed = [(old, new) for old, new in zip(before, world.rows(), strict=True) if old != new]
    assert [new[0] for _, new in changed] == [world.e["vendor-a"]]  # exactly one row changed
    with store.transaction(world.conn):  # and the F-06 consequence is visible to authorisation
        with pytest.raises(AuthorizationDenied) as denied:
            authorize_engagement(world.conn, verified("vendor-a"), world.alpha, Action.VIEW_OWN_ENGAGEMENT, LATER)
    assert denied.value.reason == "engagement_revoked"


def test_other_engagements_in_the_same_production_are_not_touched(world):
    revoke(world, world.alpha, world.e["vendor-a"])
    for subject in ("coordinator-a", "other-a", "coordinator-b", "vendor-b"):
        assert world.revoked_at(subject) is None


def test_a_coordinator_may_be_revoked_like_anyone_else(world):
    assert revoke(world, world.alpha, world.e["coordinator-a"]).status == "revoked"  # who may do it is the caller's policy


def test_repeating_a_revocation_reports_the_original_time_and_changes_nothing(world):
    first = revoke(world, world.alpha, world.e["vendor-a"], NOW)
    after_first = world.rows()
    second = revoke(world, world.alpha, world.e["vendor-a"], LATER)
    third = revoke(world, world.alpha, world.e["vendor-a"], LATER + 1)
    assert first.status == "revoked"
    assert (second.status, second.revoked_at) == ("already_revoked", NOW)  # the original instant, not LATER
    assert (third.status, third.revoked_at) == ("already_revoked", NOW)
    assert world.rows() == after_first


def test_a_repeat_inside_the_same_transaction_is_also_a_repeat(world):
    with store.transaction(world.conn):
        first = store.revoke_engagement_in_production(world.conn, world.alpha, world.e["vendor-a"], NOW)
        second = store.revoke_engagement_in_production(world.conn, world.alpha, world.e["vendor-a"], LATER)
    assert (first.status, second.status, second.revoked_at) == ("revoked", "already_revoked", NOW)


def test_the_result_is_an_immutable_value_with_exactly_three_statuses():
    assert {status.value for status in store.RevocationStatus} == {"revoked", "already_revoked", "not_found"}
    result = store.Revocation(store.RevocationStatus.NOT_FOUND, None)
    with pytest.raises(FrozenInstanceError):
        result.revoked_at = 1  # type: ignore[misc]


# ------------------------------------------------------------------------------------ arguments and transactions

BAD_IDS = [
    "",
    "A" * 32,
    "0" * 31,
    "0" * 33,
    "g" * 32,
    " " + "0" * 31,
    "0" * 32 + "\n",
    "0" * 32 + "' OR '1'='1",
    "é" * 32,
]


@pytest.mark.parametrize("position", ["production_id", "engagement_id"])
@pytest.mark.parametrize("bad", BAD_IDS, ids=lambda value: ascii(value)[:24])
def test_an_id_that_is_not_32_lowercase_hex_characters_is_rejected_before_any_sql(world, position, bad):
    ids = {"production_id": world.alpha, "engagement_id": world.e["vendor-a"], position: bad}
    before = world.rows()
    with store.transaction(world.conn):
        statements = traced(world.conn)
        with pytest.raises(ValueError, match=position) as error:
            store.revoke_engagement_in_production(world.conn, ids["production_id"], ids["engagement_id"], NOW)
    world.conn.set_trace_callback(None)
    assert len(bad) < 4 or bad not in str(error.value)  # a rejected value is never echoed
    assert statements == [] and world.rows() == before


@pytest.mark.parametrize("position", ["production_id", "engagement_id"])
@pytest.mark.parametrize("bad", [None, 12345, b"0" * 32, ["0" * 32]], ids=lambda value: type(value).__name__)
def test_an_id_that_is_not_a_str_is_a_type_error(world, position, bad):
    ids = {"production_id": world.alpha, "engagement_id": world.e["vendor-a"], position: bad}
    with store.transaction(world.conn):
        with pytest.raises(TypeError, match=position):
            store.revoke_engagement_in_production(world.conn, ids["production_id"], ids["engagement_id"], NOW)
    assert world.revoked_at("vendor-a") is None


@pytest.mark.parametrize("bad", [True, False, 1.0, float(NOW), "1", str(NOW), None], ids=repr)
def test_the_instant_must_be_a_real_int_and_not_a_bool(world, bad):
    with store.transaction(world.conn):
        statements = traced(world.conn)
        with pytest.raises(TypeError, match="now_micros"):
            store.revoke_engagement_in_production(world.conn, world.alpha, world.e["vendor-a"], bad)
    world.conn.set_trace_callback(None)
    assert statements == [] and world.revoked_at("vendor-a") is None


def test_a_call_outside_a_transaction_is_refused_and_runs_no_sql(world):
    statements = traced(world.conn)
    with pytest.raises(store.StoreError, match="transaction"):
        store.revoke_engagement_in_production(world.conn, world.alpha, world.e["vendor-a"], NOW)
    world.conn.set_trace_callback(None)
    assert statements == [] and world.revoked_at("vendor-a") is None


# ------------------------------------------------------------------------------ the clock, SQL and transactions


def test_the_function_takes_the_instant_from_its_caller_and_reads_no_clock(world):
    assert list(inspect.signature(store.revoke_engagement_in_production).parameters) == [
        "conn",
        "production_id",
        "engagement_id",
        "now_micros",
    ]
    distinctive = to_micros(datetime(2031, 1, 2, 3, 4, 5, 123456, tzinfo=UTC))  # nothing like the real time
    assert revoke(world, world.alpha, world.e["vendor-a"], distinctive).revoked_at == distinctive
    assert world.revoked_at("vendor-a") == distinctive
    names = {node.attr for node in ast.walk(function_tree()) if isinstance(node, ast.Attribute)}
    names |= {node.id for node in ast.walk(function_tree()) if isinstance(node, ast.Name)}
    assert not {"now", "time", "utcnow", "today", "monotonic", "clock", "datetime", "SystemClock"} & names


def test_the_update_binds_the_engagement_id_and_the_actual_production_together(world):
    with store.transaction(world.conn):
        statements = traced(world.conn)
        store.revoke_engagement_in_production(world.conn, world.alpha, world.e["vendor-a"], NOW)
    world.conn.set_trace_callback(None)
    [update] = statements  # a successful revocation is one statement
    assert update.startswith("UPDATE engagements SET revoked_at = ")
    assert f"id = '{world.e['vendor-a']}' AND production_id = '{world.alpha}' AND revoked_at IS NULL" in update


def test_every_statement_is_constant_text_with_bound_values(world):
    for call in (node for node in ast.walk(function_tree()) if isinstance(node, ast.Call)):
        if isinstance(call.func, ast.Attribute) and call.func.attr == "execute":
            assert isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)  # no f-string, no +
            assert isinstance(call.args[1], ast.Tuple)  # the values travel separately


def test_a_miss_looks_up_the_same_pair_so_it_can_tell_nothing_extra(world):
    with store.transaction(world.conn):
        statements = traced(world.conn)
        store.revoke_engagement_in_production(world.conn, world.alpha, world.e["vendor-b"], NOW)
    world.conn.set_trace_callback(None)
    assert [sql.split(" ")[0] for sql in statements] == ["UPDATE", "SELECT"]
    assert all(world.alpha in sql and world.e["vendor-b"] in sql for sql in statements)


def test_the_function_neither_commits_nor_rolls_back(world):
    with store.transaction(world.conn):
        store.revoke_engagement_in_production(world.conn, world.alpha, world.e["vendor-a"], NOW)
        assert world.conn.in_transaction  # still the caller's transaction
        reader = store.connect(world.path)
        try:  # another connection cannot see an uncommitted revocation
            assert reader.execute("SELECT revoked_at FROM engagements WHERE id = ?", (world.e["vendor-a"],)).fetchone()[0] is None
        finally:
            reader.close()
    assert world.revoked_at("vendor-a") == NOW  # the caller's commit made it durable
    calls = {node.func.attr for node in ast.walk(function_tree()) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)}
    assert not {"commit", "rollback", "close"} & calls


def test_the_caller_can_roll_the_revocation_back(world):
    before = world.rows()
    with pytest.raises(RuntimeError, match="audit failed"):
        with store.transaction(world.conn):
            assert store.revoke_engagement_in_production(world.conn, world.alpha, world.e["vendor-a"], NOW).status == "revoked"
            raise RuntimeError("audit failed")  # a later step of the caller's request fails
    assert world.rows() == before


def refuse_updates_of(world: World, subject: str) -> None:
    """Make any UPDATE of this engagement fail inside SQLite (a trigger made on a plain connection; the ids are hexadecimal).

    Until M4-20 an instant earlier than `created_at` was the way to make this function's statement fail, through the
    schema's CHECK; the function now stores `created_at` instead, so a failing statement has to be made another way.
    """
    raw = sqlite3.connect(world.path, isolation_level=None)  # not store.connect: it would refuse the altered schema
    try:
        raw.execute(
            f"CREATE TRIGGER refuse_the_update BEFORE UPDATE ON engagements WHEN NEW.id = '{world.e[subject]}' "
            "BEGIN SELECT RAISE(ABORT, 'refused'); END"
        )
    finally:
        raw.close()


def test_an_error_leaves_no_partial_mutation(world):
    before = world.rows()
    refuse_updates_of(world, "other-a")
    with pytest.raises(sqlite3.IntegrityError, match="refused"):
        with store.transaction(world.conn):
            assert store.revoke_engagement_in_production(world.conn, world.alpha, world.e["vendor-a"], NOW).status == "revoked"
            store.revoke_engagement_in_production(world.conn, world.alpha, world.e["other-a"], NOW)
    assert world.rows() == before  # the first revocation went with the failed transaction


def test_a_failing_statement_changes_nothing_even_before_the_caller_rolls_back(world):
    refuse_updates_of(world, "vendor-a")
    with store.transaction(world.conn):
        with pytest.raises(sqlite3.IntegrityError, match="refused"):
            store.revoke_engagement_in_production(world.conn, world.alpha, world.e["vendor-a"], NOW)
        assert world.revoked_at("vendor-a") is None


def test_an_instant_before_the_creation_is_stored_as_the_creation_instant(world):
    created = to_micros(SEEDED_AT)
    result = revoke(world, world.alpha, world.e["vendor-a"], created - 1)  # a clock that stepped back
    assert (result.status, result.revoked_at) == (store.RevocationStatus.REVOKED, created)
    assert world.revoked_at("vendor-a") == created


@pytest.mark.parametrize("offset", [0, 1, 3_600_000_000], ids=["at creation", "one microsecond after", "an hour after"])
def test_the_creation_instant_and_every_later_instant_are_stored_as_given(world, offset):
    created = to_micros(SEEDED_AT)
    result = revoke(world, world.alpha, world.e["vendor-a"], created + offset)
    assert (result.status, result.revoked_at) == (store.RevocationStatus.REVOKED, created + offset)
    assert world.revoked_at("vendor-a") == created + offset


def test_a_zero_row_update_that_leaves_an_unrevoked_row_is_an_error_not_a_repeat(tmp_path):
    # A BEFORE UPDATE trigger that ignores the change makes the UPDATE affect no rows although the engagement is active.
    # Reporting ALREADY_REVOKED for it would be false, so the function must raise.
    path = tmp_path / "ignored.sqlite3"
    store.initialise_schema(path)
    conn = store.connect(path)
    seeding = Fixed(SEEDED_AT)
    with store.transaction(conn):
        production = store.add_production(conn, seeding, "ALPHA")
        subject_id = store.add_subject(conn, seeding, tokens.ISSUER, "vendor-a", "vendor-a")
        engagement = store.add_engagement(conn, seeding, subject_id, production, "vendor", T0 + timedelta(days=1))
    conn.close()
    raw = sqlite3.connect(path, isolation_level=None)  # not store.connect: it would refuse the altered schema
    try:
        raw.execute("CREATE TRIGGER ignore_updates BEFORE UPDATE ON engagements BEGIN SELECT RAISE(IGNORE); END")
        raw.execute("BEGIN IMMEDIATE")
        with pytest.raises(store.StoreError) as error:
            store.revoke_engagement_in_production(raw, production, engagement, NOW)
        raw.execute("ROLLBACK")
        assert raw.execute("SELECT revoked_at FROM engagements").fetchone()[0] is None
    finally:
        raw.close()
    assert production not in str(error.value) and engagement not in str(error.value)


# --------------------------------------------------------------------------------------------- documentation


def test_the_unscoped_function_says_it_is_unsuitable_for_request_controlled_ids():
    doc = inspect.getdoc(store.revoke_engagement)
    assert "unscoped" in doc.lower() and "revoke_engagement_in_production" in doc
