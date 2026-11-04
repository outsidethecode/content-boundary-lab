"""Engagement authorisation: what a verified identity may do in a production, decided from SQLite alone.

Identities come from the real verifier (tests/support/token_issuer.py), so each one is exactly what a request would
carry into authorisation. Every decision runs inside store.transaction(), as the caller must arrange.
"""

import ast
import dataclasses
import inspect
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest
from support import token_issuer as tokens

from content_boundary_lab import authz, identity, store
from content_boundary_lab.audit import Actor, AuditReason
from content_boundary_lab.authz import Action, AuthorizationDenied, AuthorizedEngagement, authorize_engagement
from content_boundary_lab.clock import to_micros

UTC = timezone.utc
T0 = datetime(2026, 11, 3, 12, tzinfo=UTC)  # the instant of tokens.NOW
NOW = to_micros(T0)
ENDS = to_micros(T0 + timedelta(days=30))
ISSUER = tokens.ISSUER
OTHER_ISSUER = "https://other-issuer.example"
KEY = tokens.new_key("key-1")
VIEW, MANAGE = Action.VIEW_OWN_ENGAGEMENT, Action.MANAGE_ENGAGEMENTS
READ_ASSET = Action.READ_ASSET
INITIATE, UPLOAD = Action.INITIATE_DELIVERY, Action.UPLOAD_DELIVERY  # M0 §2 steps 3 and 4: the vendor's, no one else's
SEAL = Action.SEAL_DELIVERY  # step 5, "Vendor → server": the vendor's too; accepting is the coordinator's (M1J)
REVOKED, EXPIRED = AuditReason.ENGAGEMENT_REVOKED, AuditReason.ENGAGEMENT_EXPIRED
NO_ENGAGEMENT, NOT_PERMITTED = AuditReason.NO_ENGAGEMENT, AuditReason.ROLE_NOT_PERMITTED
INVALID_IDENTIFIER = AuditReason.INVALID_IDENTIFIER


class ManualClock:
    def __init__(self, moment):
        self.moment = moment

    def now(self):
        return self.moment


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "lab.sqlite3"


@pytest.fixture
def conn(db_path):
    store.initialise_schema(db_path)
    connection = store.connect(db_path)
    yield connection
    connection.close()


def _world(conn):
    """Two productions and five subjects; every engagement ends 30 days after T0."""
    clock = ManualClock(T0)
    alpha = store.add_production(conn, clock, "ALPHA (synthetic)")
    bravo = store.add_production(conn, clock, "BRAVO (synthetic)")
    ids = {}
    for key, issuer, subject, production, role in [
        ("vendor", ISSUER, "vendor-1", alpha, "vendor"),
        ("coordinator", ISSUER, "coordinator-1", alpha, "coordinator"),
        ("vendor2", ISSUER, "vendor-2", bravo, "vendor"),
        ("foreign", OTHER_ISSUER, "vendor-1", bravo, "vendor"),  # the same subject string under another issuer
    ]:
        subject_id = store.add_subject(conn, clock, issuer, subject, f"{subject} (synthetic)")
        ids[key] = store.add_engagement(conn, clock, subject_id, production, role, T0 + timedelta(days=30))
    store.add_subject(conn, clock, ISSUER, "outsider-1", "Outsider (synthetic)")  # a subject with no engagement
    return SimpleNamespace(alpha=alpha, bravo=bravo, engagement=ids)


def _who(subject, issuer=ISSUER, **claims):
    """A VerifiedIdentity obtained the only way there is: by authenticating a signed token."""
    settings = tokens.trusted_settings(KEY, issuer=issuer)
    token = tokens.mint(KEY, iss=issuer, sub=subject, **claims)
    return identity.authenticate("Bearer " + token, settings, ManualClock(T0))


def _decide(conn, who, production, action=VIEW, now=NOW):
    with store.transaction(conn):
        return authorize_engagement(conn, who, production, action, now)


def _denial(conn, who, production, action=VIEW, now=NOW):
    with pytest.raises(AuthorizationDenied) as caught:
        _decide(conn, who, production, action, now)
    return caught.value


def _traced(conn, call):
    """Run `call` inside the caller's open transaction; return the SQL it ran and any exception it raised."""
    seen, error = [], None
    conn.set_trace_callback(seen.append)
    try:
        call()
    except Exception as caught:  # the test inspects it
        error = caught
    finally:
        conn.set_trace_callback(None)
    return seen, error


def _counts(conn):
    return list(
        conn.execute(
            "SELECT (SELECT COUNT(*) FROM productions), (SELECT COUNT(*) FROM subjects), "
            "(SELECT COUNT(*) FROM engagements), (SELECT COUNT(*) FROM assets), (SELECT COUNT(*) FROM audit_events)"
        ).fetchone()
    )


def _revoke(conn, engagement_id, seconds=60):
    with store.transaction(conn):
        assert store.revoke_engagement(conn, ManualClock(T0 + timedelta(seconds=seconds)), engagement_id)


# --- the policy --------------------------------------------------------------------------------------------------


def test_the_policy_is_small_closed_and_read_only():
    assert set(Action) == {VIEW, MANAGE, READ_ASSET, INITIATE, UPLOAD, SEAL}
    assert dict(authz.POLICY) == {
        "coordinator": {VIEW, MANAGE, READ_ASSET},
        "vendor": {VIEW, READ_ASSET, INITIATE, UPLOAD, SEAL},
    }
    assert isinstance(authz.POLICY, MappingProxyType)
    with pytest.raises(TypeError):
        authz.POLICY["vendor"] = frozenset(Action)


@pytest.mark.parametrize(
    ("subject", "role", "action", "permitted"),
    [
        ("coordinator-1", "coordinator", VIEW, True),
        ("coordinator-1", "coordinator", MANAGE, True),
        ("vendor-1", "vendor", VIEW, True),
        ("vendor-1", "vendor", MANAGE, False),
        ("coordinator-1", "coordinator", READ_ASSET, True),
        ("vendor-1", "vendor", READ_ASSET, True),
        ("vendor-1", "vendor", INITIATE, True),
        ("vendor-1", "vendor", UPLOAD, True),
        ("coordinator-1", "coordinator", INITIATE, False),
        ("coordinator-1", "coordinator", UPLOAD, False),
        ("vendor-1", "vendor", SEAL, True),
        ("coordinator-1", "coordinator", SEAL, False),
    ],
    ids=[
        "coordinator views",
        "coordinator manages",
        "vendor views",
        "vendor may not manage",
        "coordinator reads assets",
        "vendor reads assets",
        "vendor initiates a delivery",
        "vendor uploads to a delivery",
        "coordinator may not initiate a delivery",
        "coordinator may not upload to a delivery",
        "vendor seals a delivery",
        "coordinator may not seal a delivery",
    ],
)
def test_the_role_policy_is_enforced_for_every_action(conn, subject, role, action, permitted):
    world = _world(conn)
    if permitted:
        assert _decide(conn, _who(subject), world.alpha, action).role == role
    else:
        assert _denial(conn, _who(subject), world.alpha, action).reason is NOT_PERMITTED


def test_a_role_the_policy_does_not_know_is_denied(conn, monkeypatch):
    world = _world(conn)
    monkeypatch.setattr(authz, "POLICY", MappingProxyType({"coordinator": frozenset(Action)}))
    assert _denial(conn, _who("vendor-1"), world.alpha).reason is NOT_PERMITTED


# --- a current engagement ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["vendor", "coordinator"])
def test_a_current_engagement_authorises_viewing_it(conn, key):
    world = _world(conn)
    result = _decide(conn, _who(f"{key}-1"), world.alpha)
    assert (result.engagement_id, result.role, result.ends_at) == (world.engagement[key], key, ENDS)
    assert [field.name for field in dataclasses.fields(result)] == ["engagement_id", "role", "ends_at"]


def test_an_authorised_result_cannot_be_built_by_accident(conn):
    result = _decide(conn, _who("vendor-1"), _world(conn).alpha)
    with pytest.raises(TypeError):
        AuthorizedEngagement("a" * 32, "coordinator", ENDS)
    with pytest.raises(TypeError):
        AuthorizedEngagement("a" * 32, "coordinator", ENDS, _proof=object())
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.role = "coordinator"
    with pytest.raises((TypeError, ValueError)):
        dataclasses.replace(result, role="coordinator")


# --- the lookup is scoped to the verified identity and the production --------------------------------------------


def test_the_same_subject_is_denied_on_a_production_it_is_not_engaged_in(conn):
    world = _world(conn)
    assert _denial(conn, _who("vendor-1"), world.bravo).reason is NO_ENGAGEMENT


def test_another_subjects_engagement_grants_nothing(conn):
    world = _world(conn)
    assert _denial(conn, _who("outsider-1"), world.alpha).reason is NO_ENGAGEMENT
    assert _denial(conn, _who("vendor-2"), world.alpha).reason is NO_ENGAGEMENT  # engaged on BRAVO only
    assert _decide(conn, _who("vendor-2"), world.bravo).role == "vendor"


def test_the_same_subject_string_under_another_issuer_is_a_different_principal(conn):
    world = _world(conn)
    foreign = _who("vendor-1", issuer=OTHER_ISSUER)
    assert _denial(conn, foreign, world.alpha).reason is NO_ENGAGEMENT  # the ALPHA vendor belongs to ISSUER
    assert _decide(conn, foreign, world.bravo).engagement_id == world.engagement["foreign"]
    assert _denial(conn, _who("vendor-1"), world.bravo).reason is NO_ENGAGEMENT  # and not the other way round
    assert _denial(conn, _who("vendor-1", issuer="https://third.example"), world.alpha).reason is NO_ENGAGEMENT


@pytest.mark.parametrize(
    ("subject", "issuer"),
    [
        ("Vendor-1", ISSUER),
        ("VENDOR-1", ISSUER),
        ("vendor-1 ", ISSUER),
        (" vendor-1", ISSUER),
        ("vendor-1", ISSUER.upper()),
        ("vendor-1", ISSUER + "/"),
        ("vendor-1", ISSUER + ".evil"),
    ],
    ids=["capitalised", "upper case", "trailing space", "leading space", "issuer upper", "issuer slash", "issuer long"],
)
def test_the_subject_and_issuer_are_matched_exactly(conn, subject, issuer):
    world = _world(conn)
    assert _denial(conn, _who(subject, issuer=issuer), world.alpha).reason is NO_ENGAGEMENT


def test_unknown_subjects_and_productions_are_denied_and_look_alike(conn):
    world = _world(conn)
    unknown_subject = _denial(conn, _who("never-provisioned"), world.alpha)
    unknown_production = _denial(conn, _who("vendor-1"), "f" * 32)
    no_engagement = _denial(conn, _who("vendor-1"), world.bravo)  # a production that exists, without an engagement
    assert {error.reason for error in (unknown_subject, unknown_production, no_engagement)} == {NO_ENGAGEMENT}
    assert str(unknown_production) == str(no_engagement)  # nothing tells an unknown production from an unengaged one


def test_the_lookup_is_one_parameterised_query_bound_to_the_identity_and_the_production(conn):
    world = _world(conn)
    who = _who("vendor-1")
    with store.transaction(conn):
        statements, error = _traced(conn, lambda: authorize_engagement(conn, who, world.alpha, VIEW, NOW))
    assert error is None and len(statements) == 1 and statements[0].lstrip().upper().startswith("SELECT")
    assert all(value in statements[0] for value in (f"'{ISSUER}'", "'vendor-1'", f"'{world.alpha}'"))
    assert "LIKE" not in statements[0].upper()


@pytest.mark.parametrize(
    "subject",
    ["vendor-1' OR '1'='1", "vendor-%", "%", "_endor-1", "vendor-1'; DROP TABLE engagements; --", "vendor-1\\"],
    ids=["quote injection", "trailing wildcard", "lone wildcard", "one-character wildcard", "statement", "backslash"],
)
def test_punctuation_in_an_identity_cannot_widen_the_lookup(conn, subject):
    world = _world(conn)
    before = _counts(conn)
    assert _denial(conn, _who(subject), world.alpha).reason is NO_ENGAGEMENT
    assert _counts(conn) == before


def test_a_registered_subject_with_sql_punctuation_matches_only_itself(conn):
    world = _world(conn)
    clock = ManualClock(T0)
    name = "o'brien\"; DROP TABLE engagements; --"
    subject_id = store.add_subject(conn, clock, ISSUER, name, "Punctuated (synthetic)")
    engagement_id = store.add_engagement(conn, clock, subject_id, world.alpha, "vendor", T0 + timedelta(days=1))
    assert _decide(conn, _who(name), world.alpha).engagement_id == engagement_id
    assert conn.execute("SELECT COUNT(*) FROM engagements").fetchone()[0] == 5  # the table is still there


def _bad_identifiers(real):
    return {
        "empty": "",
        "31 characters": real[:-1],
        "33 characters": real + "0",
        "upper case": real.upper(),
        "a trailing space": real + " ",
        "a leading space": " " + real,
        "a trailing newline": real + "\n",
        "quote injection": "' OR '1'='1",
        "an appended statement": real + "' OR 1=1 --",
        "wildcards": "%" * 32,
        "one-character wildcards": "_" * 32,
        "a path": "../" * 10 + "ab",
        "None": None,
        "an integer": 12345,
        "bytes": real.encode(),
    }


@pytest.mark.parametrize("name", list(_bad_identifiers("a" * 32)))
def test_an_invalid_production_identifier_is_denied_without_querying(conn, name):
    world = _world(conn)
    bad = _bad_identifiers(world.alpha)[name]
    who = _who("vendor-1")
    with store.transaction(conn):
        statements, error = _traced(conn, lambda: authorize_engagement(conn, who, bad, VIEW, NOW))
    assert isinstance(error, AuthorizationDenied) and error.reason is INVALID_IDENTIFIER
    assert statements == []  # the database was never asked


# --- revocation --------------------------------------------------------------------------------------------------


def test_a_revoked_engagement_is_denied_as_soon_as_the_revocation_commits(conn, db_path):
    world = _world(conn)
    other = store.connect(db_path)
    who = _who("vendor-1")
    assert _decide(conn, who, world.alpha) and _decide(other, who, world.alpha)
    _revoke(conn, world.engagement["vendor"])
    for connection in (conn, other):
        assert _denial(connection, who, world.alpha).reason is REVOKED
    other.close()


def test_a_revocation_that_has_not_committed_is_not_yet_visible_to_another_connection(conn, db_path):
    world = _world(conn)
    other = store.connect(db_path)
    who = _who("vendor-1")
    conn.execute("BEGIN IMMEDIATE")
    assert store.revoke_engagement(conn, ManualClock(T0 + timedelta(seconds=60)), world.engagement["vendor"])
    other.execute("BEGIN")  # a plain read transaction: the writer's uncommitted change is invisible to it
    try:
        assert authorize_engagement(other, who, world.alpha, VIEW, NOW).role == "vendor"
    finally:
        other.rollback()
    conn.commit()
    assert _denial(other, who, world.alpha).reason is REVOKED  # the first transaction to begin after the commit
    other.close()


def test_the_decision_sees_its_own_transactions_uncommitted_revocation(conn):
    world = _world(conn)
    with pytest.raises(AuthorizationDenied) as caught:
        with store.transaction(conn):
            store.revoke_engagement(conn, ManualClock(T0), world.engagement["vendor"])
            authorize_engagement(conn, _who("vendor-1"), world.alpha, VIEW, NOW)
    assert caught.value.reason is REVOKED
    row = conn.execute("SELECT revoked_at FROM engagements WHERE id = ?", (world.engagement["vendor"],)).fetchone()
    assert row[0] is None  # the denial rolled the caller's transaction back, as it would any exception


def test_a_revoked_engagement_stays_denied_while_the_same_token_still_authenticates(conn):
    world = _world(conn)
    settings = tokens.trusted_settings(KEY)
    token = tokens.mint(KEY, sub="vendor-1")  # valid from NOW for five minutes
    first = identity.authenticate("Bearer " + token, settings, ManualClock(T0))
    assert _decide(conn, first, world.alpha).role == "vendor"
    _revoke(conn, world.engagement["vendor"], seconds=60)
    later = ManualClock(T0 + timedelta(seconds=61))
    assert identity.authenticate("Bearer " + token, settings, later) == first  # still cryptographically valid
    assert _denial(conn, first, world.alpha, now=to_micros(later.moment)).reason is REVOKED


def test_revocation_is_reported_before_expiry_and_expiry_before_role(conn):
    world = _world(conn)
    vendor = _who("vendor-1")
    assert _denial(conn, vendor, world.alpha, MANAGE, ENDS + 1).reason is EXPIRED  # expiry beats the role check
    _revoke(conn, world.engagement["vendor"])
    assert _denial(conn, vendor, world.alpha, MANAGE, ENDS + 1).reason is REVOKED  # revocation beats both
    assert _denial(conn, vendor, world.alpha, MANAGE, NOW).reason is REVOKED


def test_an_invalid_identifier_is_reported_before_anything_else(conn):
    _world(conn)
    assert _denial(conn, _who("never-provisioned"), "not-an-id", MANAGE, ENDS + 1).reason is INVALID_IDENTIFIER


# --- expiry ------------------------------------------------------------------------------------------------------


def test_exactly_one_microsecond_before_expiry_is_permitted(conn):
    world = _world(conn)
    assert _decide(conn, _who("vendor-1"), world.alpha, now=ENDS - 1).role == "vendor"
    assert _decide(conn, _who("coordinator-1"), world.alpha, MANAGE, now=ENDS - 1).role == "coordinator"


@pytest.mark.parametrize(
    "now", [ENDS, ENDS + 1, ENDS + 10**12], ids=["exactly at expiry", "one microsecond after", "long after"]
)
def test_at_and_after_expiry_the_engagement_is_denied(conn, now):
    world = _world(conn)
    assert _denial(conn, _who("vendor-1"), world.alpha, now=now).reason is EXPIRED
    assert _denial(conn, _who("coordinator-1"), world.alpha, MANAGE, now=now).reason is EXPIRED


def test_expiry_is_judged_before_the_role_at_the_boundary(conn):
    world = _world(conn)
    vendor = _who("vendor-1")
    assert _denial(conn, vendor, world.alpha, MANAGE, ENDS - 1).reason is NOT_PERMITTED
    assert _denial(conn, vendor, world.alpha, MANAGE, ENDS).reason is EXPIRED


def test_the_decision_depends_only_on_the_supplied_instant(conn):
    world = _world(conn)
    vendor = _who("vendor-1")
    outcomes = []
    for now in (0, NOW, ENDS - 1, ENDS, ENDS - 1):  # the same question asked at different instants, in any order
        try:
            _decide(conn, vendor, world.alpha, now=now)
            outcomes.append("allowed")
        except AuthorizationDenied as denied:
            outcomes.append(denied.reason.value)
    assert outcomes == ["allowed", "allowed", "allowed", "engagement_expired", "allowed"]


# --- arguments and the caller's transaction ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad", [True, False, 1.5, float(NOW), str(NOW), None, str(NOW).encode(), [NOW]], ids=lambda value: repr(value)[:20]
)
def test_the_decision_instant_must_be_an_integer_and_not_a_boolean(conn, bad):
    world = _world(conn)
    with store.transaction(conn), pytest.raises(TypeError, match="now_micros"):
        authorize_engagement(conn, _who("vendor-1"), world.alpha, VIEW, bad)


def test_only_a_verified_identity_is_accepted(conn):
    world = _world(conn)
    impostors = [
        {"issuer": ISSUER, "subject": "vendor-1"},
        (ISSUER, "vendor-1"),
        "vendor-1",
        None,
        SimpleNamespace(issuer=ISSUER, subject="vendor-1"),
        Actor(ISSUER, "vendor-1"),
    ]
    for impostor in impostors:
        with store.transaction(conn), pytest.raises(TypeError, match="identity"):
            authorize_engagement(conn, impostor, world.alpha, VIEW, NOW)


@pytest.mark.parametrize("action", ["view_own_engagement", None, AuditReason.NO_ENGAGEMENT, 0], ids=repr)
def test_only_a_known_action_is_accepted(conn, action):
    world = _world(conn)
    with store.transaction(conn), pytest.raises(TypeError, match="action"):
        authorize_engagement(conn, _who("vendor-1"), world.alpha, action, NOW)


def test_only_a_database_connection_is_accepted():
    for impostor in (None, "lab.sqlite3", object()):
        with pytest.raises(TypeError, match="conn"):
            authorize_engagement(impostor, SimpleNamespace(), "a" * 32, VIEW, NOW)


def test_a_missing_transaction_is_rejected_before_anything_is_read(conn):
    world = _world(conn)
    who = _who("vendor-1")
    assert not conn.in_transaction
    with pytest.raises(store.StoreError, match="transaction"):
        authorize_engagement(conn, who, world.alpha, VIEW, NOW)
    with pytest.raises(store.StoreError, match="transaction"):
        authorize_engagement(conn, who, "not-an-id", VIEW, NOW)  # the contract is checked first, even for bad input
    assert not conn.in_transaction  # and nothing opened one
    _decide(conn, who, world.alpha)
    with pytest.raises(store.StoreError, match="transaction"):  # after a commit, too
        authorize_engagement(conn, who, world.alpha, VIEW, NOW)


def test_authorisation_never_commits_or_rolls_back_the_callers_transaction(conn, db_path):
    world = _world(conn)
    who = _who("vendor-1")
    other = store.connect(db_path)
    with pytest.raises(RuntimeError, match="caller rolls back"):
        with store.transaction(conn):
            store.add_production(conn, ManualClock(T0), "CHARLIE (uncommitted)")
            authorize_engagement(conn, who, world.alpha, VIEW, NOW)  # allowed
            with pytest.raises(AuthorizationDenied):
                authorize_engagement(conn, who, world.bravo, VIEW, NOW)  # denied
            assert conn.in_transaction  # neither call ended it
            assert other.execute("SELECT COUNT(*) FROM productions").fetchone()[0] == 2  # and neither committed it
            raise RuntimeError("caller rolls back")
    assert conn.execute("SELECT COUNT(*) FROM productions").fetchone()[0] == 2  # the caller's rollback still worked
    with store.transaction(conn):
        store.add_production(conn, ManualClock(T0), "DELTA (committed)")
        authorize_engagement(conn, who, world.alpha, VIEW, NOW)
    assert other.execute("SELECT COUNT(*) FROM productions").fetchone()[0] == 3  # and the caller's commit worked
    other.close()


def test_authorisation_issues_a_single_select_and_nothing_that_ends_a_transaction(conn):
    world = _world(conn)
    _revoke(conn, world.engagement["coordinator"])
    cases = [
        (_who("vendor-1"), world.alpha, VIEW, NOW),  # allowed
        (_who("outsider-1"), world.alpha, VIEW, NOW),  # no engagement
        (_who("coordinator-1"), world.alpha, VIEW, NOW),  # revoked
        (_who("vendor-1"), world.alpha, VIEW, ENDS),  # expired
        (_who("vendor-1"), world.alpha, MANAGE, NOW),  # role not permitted
    ]
    for who, production, action, now in cases:
        with store.transaction(conn):
            statements, _ = _traced(conn, lambda: authorize_engagement(conn, who, production, action, now))
        assert len(statements) == 1 and statements[0].lstrip().upper().startswith("SELECT")


def test_authorisation_never_opens_a_connection_of_its_own(conn, monkeypatch):
    world = _world(conn)
    who = _who("vendor-1")

    def refuse(*args, **kwargs):
        raise AssertionError("authorisation must not open a database connection")

    monkeypatch.setattr(sqlite3, "connect", refuse)
    monkeypatch.setattr(store, "connect", refuse)
    monkeypatch.setattr(store, "_open", refuse)
    assert _decide(conn, who, world.alpha).role == "vendor"
    assert _denial(conn, who, world.bravo).reason is NO_ENGAGEMENT


def test_authorisation_writes_nothing(conn):
    world = _world(conn)
    before = _counts(conn)
    engagements_before = [tuple(row) for row in conn.execute("SELECT * FROM engagements ORDER BY id")]
    for who in (_who("vendor-1"), _who("coordinator-1"), _who("outsider-1")):
        for production in (world.alpha, world.bravo, "not-an-id"):
            for action in Action:
                for now in (NOW, ENDS):
                    try:
                        _decide(conn, who, production, action, now)
                    except AuthorizationDenied:
                        pass
    assert _counts(conn) == before and before[-1] == 0  # no audit row either: recording is the caller's job
    assert [tuple(row) for row in conn.execute("SELECT * FROM engagements ORDER BY id")] == engagements_before


# --- nothing else is an authority --------------------------------------------------------------------------------


def test_token_carried_roles_scopes_permissions_and_productions_grant_nothing(conn):
    world = _world(conn)
    claims = {
        "role": "coordinator",
        "roles": ["coordinator", "admin"],
        "scope": "manage_engagements view_own_engagement",
        "permissions": {"manage_engagements": True},
        "productions": [world.bravo, world.alpha],
        "production_id": world.bravo,
    }
    vendor = _who("vendor-1", **claims)
    assert vendor == _who("vendor-1")  # the claims are not in the identity, so authorisation cannot see them
    assert _decide(conn, vendor, world.alpha).role == "vendor"
    assert _denial(conn, vendor, world.alpha, MANAGE).reason is NOT_PERMITTED
    assert _denial(conn, vendor, world.bravo).reason is NO_ENGAGEMENT
    stranger = _who("never-provisioned", **claims)
    assert _denial(conn, stranger, world.alpha).reason is NO_ENGAGEMENT
    assert _denial(conn, stranger, world.bravo, MANAGE).reason is NO_ENGAGEMENT


def test_the_function_takes_no_claims_only_an_identity_and_a_decision_instant():
    parameters = list(inspect.signature(authorize_engagement).parameters)
    assert parameters == ["conn", "identity", "production_id", "action", "now_micros"]


class _Untouchable:
    def _fail(self, *args, **kwargs):
        raise AssertionError("authorisation consulted the environment")

    __getitem__ = __contains__ = __iter__ = __len__ = get = keys = items = copy = _fail


def test_authorisation_reads_no_environment_variable(conn, monkeypatch):
    world = _world(conn)
    who = _who("vendor-1")
    with monkeypatch.context() as patched:
        patched.setattr(os, "environ", _Untouchable())
        assert _decide(conn, who, world.alpha).role == "vendor"


def test_the_module_imports_nothing_that_reads_tokens_environment_or_clocks():
    tree = ast.parse(Path(authz.__file__).read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            imported.add(node.module)
    roots = {name.split(".")[0] for name in imported}
    assert not roots & {"jwt", "json", "os", "sys", "time", "datetime", "base64", "cryptography", "random"}
    assert {name for name in imported if name.startswith("content_boundary_lab")} <= {
        "content_boundary_lab.audit",
        "content_boundary_lab.identity",
        "content_boundary_lab.store",
    }  # no settings and no clock module


# --- the denial ---------------------------------------------------------------------------------------------------


def test_a_denial_names_only_a_bounded_reason(conn):
    world = _world(conn)
    error = _denial(conn, _who("MARKERvalue-subject"), world.alpha)
    assert str(error) == "authorisation denied: no_engagement"
    assert "MARKER" not in repr(error) and error.__cause__ is None


def test_the_denial_reasons_are_exactly_the_five_authorisation_outcomes():
    assert authz.DENIAL_REASONS == {INVALID_IDENTIFIER, NO_ENGAGEMENT, REVOKED, EXPIRED, NOT_PERMITTED}
    for reason in authz.DENIAL_REASONS:
        assert AuthorizationDenied(reason).reason is reason


@pytest.mark.parametrize(
    "reason",
    [AuditReason.NOT_FOUND_OR_FORBIDDEN, AuditReason.INVALID_CREDENTIALS, "no_engagement", None],
    ids=repr,
)
def test_a_denial_cannot_carry_any_other_reason(reason):
    with pytest.raises(ValueError):
        AuthorizationDenied(reason)
