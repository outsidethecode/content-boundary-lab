"""assets.get_asset_in_scope: one statement binds the asset, its real production, the requested production and the
caller's current engagement, on the one instant the request captured.

The property: asking for BRAVO's asset through ALPHA's URL finds nothing, even for a caller who is engaged in both
productions. Authorising only against the production in the URL and then loading the asset by its id would find it
(that is F-02). These tests run against the real hardened store, with identities from the real verifier.
"""

import ast
import inspect
import sqlite3
from dataclasses import FrozenInstanceError, dataclass
from datetime import datetime, timedelta, timezone

import pytest
from support import token_issuer as tokens

from content_boundary_lab import assets, identity, store
from content_boundary_lab.clock import to_micros

UTC = timezone.utc
T0 = datetime(2026, 11, 3, 12, tzinfo=UTC)
NOW = to_micros(T0)
SEEDED_AT = T0 - timedelta(days=1)
SHORT_END = T0 + timedelta(seconds=100)
LONG_END = T0 + timedelta(days=30)
OTHER_ISSUER = "https://other-issuer.example"
KEY = tokens.new_key("key-1")


class Fixed:
    def __init__(self, moment):
        self.moment = moment

    def now(self):
        return self.moment


@dataclass
class World:
    conn: sqlite3.Connection
    alpha: str
    bravo: str
    assets: dict[str, str]  # by short name

    def rows(self) -> list[tuple]:
        return [tuple(row) for row in self.conn.execute("SELECT id, production_id, display_name, created_at FROM assets ORDER BY id")]


def verified(subject: str):
    token = tokens.mint(KEY, sub=subject)
    return identity.authenticate(f"Bearer {token}", tokens.trusted_settings(KEY), Fixed(T0))


@pytest.fixture
def world(tmp_path) -> World:
    path = tmp_path / "lab.sqlite3"
    store.initialise_schema(path)
    conn = store.connect(path)
    seeding = Fixed(SEEDED_AT)
    with store.transaction(conn):
        alpha, bravo = store.add_production(conn, seeding, "ALPHA"), store.add_production(conn, seeding, "BRAVO")
        found = {
            "alpha_ref": store.add_asset(conn, seeding, alpha, "alpha-reference.mov"),
            "alpha_two": store.add_asset(conn, seeding, alpha, "alpha-two.wav"),
            "bravo_secret": store.add_asset(conn, seeding, bravo, 'bravo "unreleased";\r\n.mov'),
        }
        for issuer, subject, engaged in [
            (tokens.ISSUER, "vendor-a", [(alpha, "vendor", LONG_END)]),
            (tokens.ISSUER, "coordinator-a", [(alpha, "coordinator", LONG_END)]),
            (tokens.ISSUER, "vendor-ab", [(alpha, "vendor", LONG_END), (bravo, "vendor", LONG_END)]),
            (tokens.ISSUER, "vendor-b", [(bravo, "vendor", LONG_END)]),
            (tokens.ISSUER, "revoked-a", [(alpha, "vendor", LONG_END)]),
            (tokens.ISSUER, "expiring-a", [(alpha, "vendor", SHORT_END)]),
            (tokens.ISSUER, "outsider", []),
            (OTHER_ISSUER, "only-other", [(alpha, "vendor", LONG_END)]),  # engaged, but under another issuer
        ]:
            subject_id = store.add_subject(conn, seeding, issuer, subject, subject)
            for production, role, ends_at in engaged:
                engagement = store.add_engagement(conn, seeding, subject_id, production, role, ends_at)
                if subject == "revoked-a":
                    store.revoke_engagement(conn, Fixed(T0 - timedelta(hours=1)), engagement)
    yield World(conn, alpha, bravo, found)
    conn.close()


def lookup(world: World, subject: str, production: str, asset: str, now: int = NOW):
    """The function under test in its own caller-owned transaction, as a route would call it."""
    with store.transaction(world.conn):
        return assets.get_asset_in_scope(world.conn, verified(subject), production, asset, now)


# ---------------------------------------------------------------------------- what an engaged caller can reach


def test_an_engaged_caller_finds_an_asset_of_the_production(world):
    found = lookup(world, "vendor-a", world.alpha, world.assets["alpha_ref"])
    assert found == assets.Asset(world.assets["alpha_ref"], world.alpha, "alpha-reference.mov", to_micros(SEEDED_AT))


def test_the_display_name_comes_back_exactly_as_stored(world):
    found = lookup(world, "vendor-b", world.bravo, world.assets["bravo_secret"])
    assert found.display_name == 'bravo "unreleased";\r\n.mov'  # sanitising is for the download header, not for storage


@pytest.mark.parametrize("subject", ["vendor-a", "coordinator-a"])
def test_the_lookup_does_not_look_at_the_role(world, subject):
    # Which role may read is the request flow's decision (authz.POLICY, READ_ASSET). The lookup binds the engagement.
    assert lookup(world, subject, world.alpha, world.assets["alpha_ref"]) is not None


def test_the_result_is_an_immutable_value():
    found = assets.Asset("a" * 32, "b" * 32, "name", 1)
    with pytest.raises(FrozenInstanceError):
        found.display_name = "other"  # type: ignore[misc]


# ------------------------------------------------------------------------- the F-02 property: no cross-production reach


def test_an_alpha_vendor_cannot_find_a_bravo_asset_through_alphas_url(world):
    before = world.rows()
    assert lookup(world, "vendor-a", world.alpha, world.assets["bravo_secret"]) is None
    assert world.rows() == before


def test_nor_through_bravos_url_because_it_has_no_engagement_there(world):
    assert lookup(world, "vendor-a", world.bravo, world.assets["bravo_secret"]) is None
    assert lookup(world, "vendor-a", world.bravo, world.assets["alpha_ref"]) is None


@pytest.mark.parametrize(
    ("asset", "production", "found"),
    [
        ("alpha_ref", "alpha", True),
        ("bravo_secret", "bravo", True),
        ("bravo_secret", "alpha", False),  # engaged in ALPHA, and engaged in BRAVO, but this asset is not in ALPHA
        ("alpha_ref", "bravo", False),
    ],
    ids=["alpha asset, alpha url", "bravo asset, bravo url", "bravo asset, alpha url", "alpha asset, bravo url"],
)
def test_a_caller_engaged_in_both_productions_still_gets_only_the_asset_the_url_names_the_production_of(world, asset, production, found):
    # The URL's production alone would authorise the caller. The asset's own production must be the one asked for.
    result = lookup(world, "vendor-ab", getattr(world, production), world.assets[asset])
    assert (result is not None) is found
    if found:
        assert result.production_id == getattr(world, production)


def test_a_production_that_does_not_exist_finds_nothing(world):
    assert lookup(world, "vendor-a", "e" * 32, world.assets["alpha_ref"]) is None


def test_an_asset_that_does_not_exist_finds_nothing_exactly_as_a_foreign_one_does(world):
    assert lookup(world, "vendor-a", world.alpha, "f" * 32) is lookup(world, "vendor-a", world.alpha, world.assets["bravo_secret"]) is None


# ------------------------------------------------------------------------------- the caller's current engagement


def test_a_caller_with_no_engagement_finds_nothing(world):
    assert lookup(world, "outsider", world.alpha, world.assets["alpha_ref"]) is None


def test_a_subject_engaged_only_under_another_issuer_finds_nothing(world):
    assert lookup(world, "only-other", world.alpha, world.assets["alpha_ref"]) is None  # the verified issuer is ours


def test_a_revoked_engagement_finds_nothing(world):
    assert lookup(world, "revoked-a", world.alpha, world.assets["alpha_ref"]) is None


@pytest.mark.parametrize(
    ("moment", "found"),
    [(SHORT_END - timedelta(microseconds=1), True), (SHORT_END, False), (SHORT_END + timedelta(microseconds=1), False)],
    ids=["one microsecond before the end", "exactly at the end", "one microsecond after"],
)
def test_the_end_of_the_engagement_is_judged_on_the_instant_the_caller_supplies(world, moment, found):
    assert (lookup(world, "expiring-a", world.alpha, world.assets["alpha_ref"], to_micros(moment)) is not None) is found


def test_a_revocation_committed_before_the_lookup_is_seen_by_it(world):
    assert lookup(world, "vendor-a", world.alpha, world.assets["alpha_ref"]) is not None
    with store.transaction(world.conn):
        engagement = world.conn.execute(
            "SELECT e.id FROM engagements e JOIN subjects s ON s.id = e.subject_id WHERE s.subject = 'vendor-a'"
        ).fetchone()[0]
        store.revoke_engagement(world.conn, Fixed(T0), engagement)
    assert lookup(world, "vendor-a", world.alpha, world.assets["alpha_ref"]) is None


# ---------------------------------------------------------------------------------- one statement, bound values only


def test_one_parameterised_statement_binds_every_condition(world):
    with store.transaction(world.conn):
        statements: list[str] = []
        world.conn.set_trace_callback(lambda sql: statements.append(sql) if not statements or statements[-1] != sql else None)
        assets.get_asset_in_scope(world.conn, verified("vendor-a"), world.alpha, world.assets["alpha_ref"], NOW)
        world.conn.set_trace_callback(None)
    statements = [sql for sql in statements if sql not in {"COMMIT", "ROLLBACK"}]
    [sql] = statements
    assert sql.startswith("SELECT a.id, a.production_id, a.display_name, a.created_at FROM assets AS a")
    for bound in (world.assets["alpha_ref"], world.alpha, tokens.ISSUER, "vendor-a", str(NOW)):
        assert bound in sql
    for condition in ("e.production_id = a.production_id", "e.revoked_at IS NULL", "e.ends_at >"):
        assert condition in sql


def test_the_statement_is_constant_text_and_the_function_reads_no_clock():
    tree = ast.parse(inspect.getsource(assets.get_asset_in_scope))
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if isinstance(call.func, ast.Attribute) and call.func.attr == "execute":
            assert isinstance(call.args[0], ast.Name) and call.args[0].id == "_LOOKUP"  # a module constant, never built
            assert isinstance(call.args[1], ast.Tuple)
    names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)} | {
        node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
    }
    assert not {"now", "time", "utcnow", "today", "clock", "datetime", "SystemClock"} & names
    assert list(inspect.signature(assets.get_asset_in_scope).parameters) == [
        "conn",
        "caller",
        "production_id",
        "asset_id",
        "now_micros",
    ]


def test_the_lookup_writes_nothing_and_neither_commits_nor_rolls_back(world):
    before = world.rows()
    with store.transaction(world.conn):
        assets.get_asset_in_scope(world.conn, verified("vendor-a"), world.alpha, world.assets["alpha_ref"], NOW)
        assert world.conn.in_transaction
    assert world.rows() == before
    calls = {
        node.func.attr
        for node in ast.walk(ast.parse(inspect.getsource(assets.get_asset_in_scope)))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not {"commit", "rollback", "close"} & calls


# ------------------------------------------------------------------------------------------- arguments are validated

BAD_IDS = ["", "A" * 32, "0" * 31, "0" * 33, "g" * 32, " " + "0" * 31, "0" * 32 + "\n", "%" * 32, "0" * 32 + "' OR '1'='1", "é" * 32]


@pytest.mark.parametrize("position", ["production_id", "asset_id"])
@pytest.mark.parametrize("bad", BAD_IDS, ids=lambda value: ascii(value)[:24])
def test_an_id_that_is_not_32_lowercase_hex_characters_is_rejected_before_any_sql(world, position, bad):
    ids = {"production_id": world.alpha, "asset_id": world.assets["alpha_ref"], position: bad}
    statements: list[str] = []
    with store.transaction(world.conn):
        world.conn.set_trace_callback(lambda sql: statements.append(sql) if sql not in {"COMMIT", "ROLLBACK"} else None)
        with pytest.raises(ValueError, match=position) as error:
            assets.get_asset_in_scope(world.conn, verified("vendor-a"), ids["production_id"], ids["asset_id"], NOW)
        world.conn.set_trace_callback(None)
    assert statements == []
    assert len(bad) < 4 or bad not in str(error.value)  # a rejected value is never echoed


@pytest.mark.parametrize("bad", [None, 12345, b"0" * 32, ["0" * 32]], ids=lambda value: type(value).__name__)
def test_an_id_that_is_not_a_str_is_a_type_error(world, bad):
    with store.transaction(world.conn):
        with pytest.raises(TypeError, match="asset_id"):
            assets.get_asset_in_scope(world.conn, verified("vendor-a"), world.alpha, bad, NOW)


@pytest.mark.parametrize("bad", [True, False, 1.0, float(NOW), str(NOW), None], ids=repr)
def test_the_instant_must_be_a_real_int_and_not_a_bool(world, bad):
    with store.transaction(world.conn):
        with pytest.raises(TypeError, match="now_micros"):
            assets.get_asset_in_scope(world.conn, verified("vendor-a"), world.alpha, world.assets["alpha_ref"], bad)


@pytest.mark.parametrize("caller", [None, ("https://issuer.example", "vendor-a"), "vendor-a", object()], ids=lambda c: type(c).__name__)
def test_only_a_verified_identity_is_accepted_as_the_caller(world, caller):
    with store.transaction(world.conn):
        with pytest.raises(TypeError, match="caller"):
            assets.get_asset_in_scope(world.conn, caller, world.alpha, world.assets["alpha_ref"], NOW)


def test_a_call_outside_a_transaction_is_refused_and_runs_no_sql(world):
    statements: list[str] = []
    world.conn.set_trace_callback(statements.append)
    with pytest.raises(store.StoreError, match="transaction"):
        assets.get_asset_in_scope(world.conn, verified("vendor-a"), world.alpha, world.assets["alpha_ref"], NOW)
    world.conn.set_trace_callback(None)
    assert statements == []


# --------------------------------------------------------------------------------------------- the asset state model


def test_the_schema_has_no_asset_state_so_none_is_invented(world):
    # M0's lifecycle states (SEALING, SCAN_PASSED, ACCEPTED, PROMOTING, PROMOTED, INTEGRITY_FAILED) belong to
    # deliveries, which arrive with M1H to M1K. A row in `assets` is the readable set; there is no state to test.
    [definition] = world.conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'assets'").fetchone()
    assert "state" not in definition.lower() and "status" not in definition.lower()
