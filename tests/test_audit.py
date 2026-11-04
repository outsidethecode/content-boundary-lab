"""Audit API checks: typed vocabulary, actor shape, one append inside the caller's transaction, atomicity."""

import dataclasses
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from content_boundary_lab import audit, store
from content_boundary_lab.audit import Actor, AuditAction, AuditReason, EngineKind, ObjectType, Outcome
from content_boundary_lab.clock import to_micros
from content_boundary_lab.scanner import KINDS

UTC = timezone.utc
T0 = datetime(2026, 11, 3, 12, 0, 0, 123457, tzinfo=UTC)  # 1793707200123457 microseconds since the epoch
ISSUER = "https://idp.example"
ACTOR = Actor(ISSUER, "coordinator-1")
VOCABULARY = {
    AuditAction: {
        "engagement.created",
        "engagement.revoked",
        "engagement.revoke_repeated",
        "engagement.request_rejected",
        "engagement.viewed",
        "access.denied",
        "asset.read",
        "delivery.initiated",
        "delivery.request_rejected",
        "delivery.upload_started",
        "delivery.uploaded",
        "delivery.upload_failed",
        "delivery.seal_started",
        "delivery.scan_passed",
        "delivery.verdict_reused",
        "delivery.rejected",
        "delivery.scan_failed",
        "delivery.viewed",
        "delivery.accepted",
        "delivery.acceptance_refused",
        "delivery.rescan_started",
        "delivery.integrity_failed",
        "delivery.promotion_started",
        "delivery.promoted",
    },
    AuditReason: {
        "no_engagement",
        "engagement_expired",
        "engagement_revoked",
        "role_not_permitted",
        "not_found_or_forbidden",
        "invalid_identifier",
        "invalid_credentials",
        "invalid_request",
        "engagement_exists",
        "payload_too_large",
        "state_conflict",
        "upload_interrupted",
        "checksum_mismatch",
        "unsupported_type",
        "detection",
        "scanner_unavailable",
        "scanner_timeout",
        "scanner_bad_response",
        "verdict_stale",
        "verdict_not_applicable",
        "digest_mismatch",
        "sealed_content_changed",
    },
    ObjectType: {"production", "engagement", "asset", "subject", "delivery"},
    Outcome: {"allowed", "denied", "recorded"},
    EngineKind: {"synthetic"},  # the kinds M0 permits (Addendum §5.3); a real engine would be a reviewed addition
}


class ManualClock:
    """Deterministic test clock (the same shape as the ones in tests/test_clock.py and tests/test_store.py)."""

    def __init__(self, start):
        self._now = start

    def now(self):
        return self._now

    def set(self, moment):
        self._now = moment


class NaiveClock:
    def now(self):
        return datetime(2026, 11, 3, 12)


class NotADatetimeClock:
    def now(self):
        return 1793707200


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


@pytest.fixture
def reader(db_path, conn):
    connection = store.connect(db_path)
    yield connection
    connection.close()


def _events(connection):
    return [dict(row) for row in connection.execute("SELECT * FROM audit_events ORDER BY seq")]


def _count(connection):
    return connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]


def _revoked_at(connection, engagement_id):
    return connection.execute("SELECT revoked_at FROM engagements WHERE id = ?", (engagement_id,)).fetchone()[0]


def _engagement(connection, clock):
    production = store.add_production(connection, clock, "ALPHA (synthetic)")
    subject = store.add_subject(connection, clock, ISSUER, "vendor-1", "Vendor One (synthetic)")
    engagement = store.add_engagement(connection, clock, subject, production, "vendor", T0 + timedelta(days=30))
    return engagement, production


def _record(connection, clock, **overrides):
    """record_event with a valid default event; overrides replace or add keyword values."""
    arguments = {"action": AuditAction.ACCESS_DENIED, "outcome": Outcome.DENIED, "actor": ACTOR}
    arguments.update(overrides)
    return audit.record_event(connection, clock, arguments.pop("action"), arguments.pop("outcome"), **arguments)


def _revoke_and_audit(connection, clock, engagement_id, production_id, *, after_revoke=None, after_audit=None):
    """The shape of a real workflow: a state change and its audit event in one store.transaction()."""
    with store.transaction(connection):
        store.revoke_engagement(connection, clock, engagement_id)
        if after_revoke:
            after_revoke()
        audit.record_event(
            connection,
            clock,
            AuditAction.ENGAGEMENT_REVOKED,
            Outcome.RECORDED,
            actor=ACTOR,
            production_id=production_id,
            object_type=ObjectType.ENGAGEMENT,
            object_id=engagement_id,
        )
        if after_audit:
            after_audit()


def _fail():
    raise RuntimeError("simulated failure")


# --- the vocabulary ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("vocabulary", VOCABULARY, ids=lambda kind: kind.__name__)
def test_each_vocabulary_is_closed_documented_and_bounded(vocabulary):
    assert {member.value for member in vocabulary} == VOCABULARY[vocabulary]
    assert vocabulary.__doc__
    for member in vocabulary:
        assert len(member.value) <= 64
        assert re.fullmatch(r"[a-z][a-z0-9_.]*", member.value)


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        (AuditAction, "engagement.deleted"),
        (AuditAction, "ENGAGEMENT.CREATED"),
        (AuditAction, ""),
        (AuditReason, "because I said so"),
        (ObjectType, "file"),
        (Outcome, "maybe"),
    ],
)
def test_codes_outside_the_vocabulary_cannot_be_constructed(kind, value):
    with pytest.raises(ValueError):
        kind(value)


def test_every_outcome_is_accepted_by_the_database(conn, clock):
    with store.transaction(conn):
        for outcome in Outcome:
            _record(conn, clock, outcome=outcome)
    assert [event["outcome"] for event in _events(conn)] == [outcome.value for outcome in Outcome]


# --- the actor ---------------------------------------------------------------------------------------------------


def test_an_actor_is_a_frozen_value_with_bounded_fields():
    assert ACTOR == Actor(ISSUER, "coordinator-1")
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(ACTOR, "subject", "someone-else")
    Actor("i" * 512, "s" * 512)
    with pytest.raises(ValueError, match="issuer"):
        Actor("i" * 513, "subject")
    with pytest.raises(ValueError, match="subject"):
        Actor("issuer", "s" * 513)


@pytest.mark.parametrize(
    ("value", "error"),
    [
        ("", ValueError),
        ("MARKER\x00", ValueError),
        ("MARKER\n", ValueError),
        ("MARKER\t", ValueError),
        ("MARKER\x7f", ValueError),
        ("MARKER\x85", ValueError),
        ("MARKER\ud800", ValueError),
        ("MARKER\N{RIGHT-TO-LEFT OVERRIDE}", ValueError),
        ("MARKER\N{ZERO WIDTH SPACE}", ValueError),
        ("MARKER\N{LINE SEPARATOR}", ValueError),
        ("MARKER\N{PARAGRAPH SEPARATOR}", ValueError),
        (b"MARKER", TypeError),
        (17, TypeError),
        (None, TypeError),
    ],
    ids=[
        "empty",
        "NUL",
        "newline",
        "tab",
        "DEL",
        "C1-control",
        "lone-surrogate",
        "bidi-override-U+202E",
        "zero-width-space-U+200B",
        "line-separator-U+2028",
        "paragraph-separator-U+2029",
        "bytes",
        "int",
        "None",
    ],
)
@pytest.mark.parametrize("field", ["issuer", "subject"])
def test_an_actor_rejects_malformed_fields_without_echoing_them(field, value, error):
    fields = {"issuer": ISSUER, "subject": "someone", field: value}
    with pytest.raises(error, match=field) as caught:
        Actor(**fields)
    assert "MARKER" not in str(caught.value)


def test_an_incomplete_identity_pair_is_rejected():
    with pytest.raises(TypeError):
        Actor(ISSUER)
    with pytest.raises(TypeError):
        Actor(subject="someone")


@pytest.mark.parametrize(
    "not_an_actor",
    [(ISSUER, "someone"), {"issuer": ISSUER, "subject": "someone"}, "someone", SimpleNamespace(issuer=ISSUER, subject="x")],
    ids=["tuple", "dict", "string", "look-alike-object"],
)
def test_record_event_accepts_only_a_real_actor_or_none(conn, clock, not_an_actor):
    with store.transaction(conn):
        with pytest.raises(TypeError, match="actor"):
            _record(conn, clock, actor=not_an_actor)
    assert _count(conn) == 0


def test_the_actor_argument_cannot_be_forgotten(conn, clock):
    with store.transaction(conn):
        with pytest.raises(TypeError, match="actor"):
            audit.record_event(conn, clock, AuditAction.ACCESS_DENIED, Outcome.DENIED)
    assert _count(conn) == 0


# --- what an event records ---------------------------------------------------------------------------------------


def test_an_event_records_every_field_exactly(conn, clock):
    with store.transaction(conn):
        seq = _record(
            conn,
            clock,
            action=AuditAction.ACCESS_DENIED,
            outcome=Outcome.DENIED,
            production_id="a" * 32,
            object_type=ObjectType.ASSET,
            object_id="b" * 32,
            reason=AuditReason.NOT_FOUND_OR_FORBIDDEN,
        )
    assert _events(conn) == [
        {
            "seq": seq,
            "at": 1793707200123457,
            "actor_issuer": ISSUER,
            "actor_subject": "coordinator-1",
            "action": "access.denied",
            "outcome": "denied",
            "production_id": "a" * 32,
            "object_type": "asset",
            "object_id": "b" * 32,
            "reason": "not_found_or_forbidden",
            "engine_kind": None,  # an access denial is not about a scanner verdict
        }
    ]


# --- the engine kind (M0 Addendum §5.3: engine.kind appears in every verdict-bearing audit event) ------------------------
#
# One small constrained column, never free text. It is required on the events that are about a scanner's verdict or about
# a scan that could not produce one (the configured scanner's kind), forbidden on every other event, and NULL for them.

DELIVERY = {"object_type": ObjectType.DELIVERY, "object_id": "d" * 32}
VERDICT_BEARING = {
    "a scan that passed": (AuditAction.DELIVERY_SCAN_PASSED, Outcome.RECORDED, None),
    "a verdict reused": (AuditAction.DELIVERY_VERDICT_REUSED, Outcome.RECORDED, None),
    "a scan that failed (timeout)": (AuditAction.DELIVERY_SCAN_FAILED, Outcome.RECORDED, AuditReason.SCANNER_TIMEOUT),
    "a scan that failed (unavailable)": (AuditAction.DELIVERY_SCAN_FAILED, Outcome.RECORDED, AuditReason.SCANNER_UNAVAILABLE),
    "a scan that failed (bad response)": (AuditAction.DELIVERY_SCAN_FAILED, Outcome.RECORDED, AuditReason.SCANNER_BAD_RESPONSE),
    "a detection": (AuditAction.DELIVERY_REJECTED, Outcome.DENIED, AuditReason.DETECTION),
    "an acceptance": (AuditAction.DELIVERY_ACCEPTED, Outcome.ALLOWED, None),
    "an acceptance refused for a stale verdict": (AuditAction.DELIVERY_ACCEPTANCE_REFUSED, Outcome.DENIED, AuditReason.VERDICT_STALE),
    "an acceptance refused for a verdict that does not apply": (
        AuditAction.DELIVERY_ACCEPTANCE_REFUSED, Outcome.DENIED, AuditReason.VERDICT_NOT_APPLICABLE
    ),
}  # fmt: skip
NOT_VERDICT_BEARING = {
    "an access denial": (AuditAction.ACCESS_DENIED, Outcome.DENIED, AuditReason.NO_ENGAGEMENT),
    "an engagement created": (AuditAction.ENGAGEMENT_CREATED, Outcome.ALLOWED, None),
    "an asset read": (AuditAction.ASSET_READ, Outcome.ALLOWED, None),
    "a delivery declared": (AuditAction.DELIVERY_INITIATED, Outcome.ALLOWED, None),
    "an upload started": (AuditAction.DELIVERY_UPLOAD_STARTED, Outcome.ALLOWED, None),
    "an upload completed": (AuditAction.DELIVERY_UPLOADED, Outcome.ALLOWED, None),
    "a seal started": (AuditAction.DELIVERY_SEAL_STARTED, Outcome.ALLOWED, None),
    "a request rejected": (AuditAction.DELIVERY_REQUEST_REJECTED, Outcome.DENIED, AuditReason.STATE_CONFLICT),
    "a checksum mismatch": (AuditAction.DELIVERY_REJECTED, Outcome.DENIED, AuditReason.CHECKSUM_MISMATCH),
    "an unsupported type": (AuditAction.DELIVERY_REJECTED, Outcome.DENIED, AuditReason.UNSUPPORTED_TYPE),
    "an acceptance refused for the state": (AuditAction.DELIVERY_ACCEPTANCE_REFUSED, Outcome.DENIED, AuditReason.STATE_CONFLICT),
    "an acceptance refused for the digest": (AuditAction.DELIVERY_ACCEPTANCE_REFUSED, Outcome.DENIED, AuditReason.DIGEST_MISMATCH),
    "an acceptance refused for a revoked vendor": (AuditAction.DELIVERY_ACCEPTANCE_REFUSED, Outcome.DENIED, AuditReason.ENGAGEMENT_REVOKED),
    "an acceptance refused for an invalid request": (AuditAction.DELIVERY_ACCEPTANCE_REFUSED, Outcome.DENIED, AuditReason.INVALID_REQUEST),
    "a rescan started": (AuditAction.DELIVERY_RESCAN_STARTED, Outcome.ALLOWED, None),
    "a rescan started for a stale verdict": (AuditAction.DELIVERY_RESCAN_STARTED, Outcome.ALLOWED, AuditReason.VERDICT_STALE),
    "an integrity failure": (AuditAction.DELIVERY_INTEGRITY_FAILED, Outcome.DENIED, AuditReason.SEALED_CONTENT_CHANGED),
    "a promotion started": (AuditAction.DELIVERY_PROMOTION_STARTED, Outcome.ALLOWED, None),
    "a delivery promoted": (AuditAction.DELIVERY_PROMOTED, Outcome.RECORDED, None),
}


def test_the_engine_kinds_are_exactly_the_kinds_the_scanner_contract_permits():
    assert {kind.value for kind in EngineKind} == set(KINDS) == {"synthetic"}


@pytest.mark.parametrize("case", VERDICT_BEARING.values(), ids=list(VERDICT_BEARING))
def test_a_verdict_bearing_event_records_the_engine_kind(conn, clock, case):
    action, outcome, reason = case
    with store.transaction(conn):
        _record(conn, clock, action=action, outcome=outcome, reason=reason, engine_kind=EngineKind.SYNTHETIC, **DELIVERY)
    (event,) = _events(conn)
    assert event["engine_kind"] == "synthetic" and event["action"] == action.value


@pytest.mark.parametrize("case", VERDICT_BEARING.values(), ids=list(VERDICT_BEARING))
def test_a_verdict_bearing_event_without_the_engine_kind_is_refused_and_writes_nothing(conn, clock, case):
    action, outcome, reason = case
    with pytest.raises(ValueError, match="engine_kind"), store.transaction(conn):
        _record(conn, clock, action=action, outcome=outcome, reason=reason, **DELIVERY)
    assert _events(conn) == []


@pytest.mark.parametrize("case", NOT_VERDICT_BEARING.values(), ids=list(NOT_VERDICT_BEARING))
def test_an_event_that_is_not_about_a_verdict_stores_null_and_refuses_an_engine_kind(conn, clock, case):
    action, outcome, reason = case
    with store.transaction(conn):
        _record(conn, clock, action=action, outcome=outcome, reason=reason)
    assert _events(conn)[0]["engine_kind"] is None
    with pytest.raises(ValueError, match="engine_kind"), store.transaction(conn):
        _record(conn, clock, action=action, outcome=outcome, reason=reason, engine_kind=EngineKind.SYNTHETIC)
    assert len(_events(conn)) == 1


@pytest.mark.parametrize("value", ["synthetic", "real", "clean", "", 1, b"synthetic", True, ["synthetic"]], ids=repr)
def test_the_engine_kind_must_be_a_member_of_the_closed_vocabulary_not_a_string(conn, clock, value):
    with pytest.raises(TypeError, match="engine_kind"), store.transaction(conn):
        _record(conn, clock, action=AuditAction.DELIVERY_SCAN_PASSED, outcome=Outcome.RECORDED, engine_kind=value)
    assert _events(conn) == []


@pytest.mark.parametrize("value", ["real", "SYNTHETIC", "synthetic ", "clean", "safe", "", "x" * 200, "synthetic'; --"])
def test_the_database_refuses_any_engine_kind_outside_the_vocabulary_even_when_written_directly(conn, value):
    with pytest.raises(sqlite3.IntegrityError), store.transaction(conn):
        conn.execute("INSERT INTO audit_events (at, action, outcome, engine_kind) VALUES (1, 'x', 'recorded', ?)", (value,))
    with store.transaction(conn):  # NULL and the one permitted value are accepted
        conn.execute("INSERT INTO audit_events (at, action, outcome, engine_kind) VALUES (1, 'x', 'recorded', NULL)")
        conn.execute("INSERT INTO audit_events (at, action, outcome, engine_kind) VALUES (1, 'x', 'recorded', 'synthetic')")


def test_an_event_with_an_engine_kind_stays_append_only(conn, clock):
    with store.transaction(conn):
        seq = _record(conn, clock, action=AuditAction.DELIVERY_SCAN_PASSED, outcome=Outcome.RECORDED, engine_kind=EngineKind.SYNTHETIC)
    before = _events(conn)
    for statement in (
        "UPDATE audit_events SET engine_kind = NULL WHERE seq = ?",
        "UPDATE audit_events SET engine_kind = 'synthetic' WHERE seq = ?",
        "DELETE FROM audit_events WHERE seq = ?",
    ):
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute(statement, (seq,))
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute(
            "INSERT OR REPLACE INTO audit_events (seq, at, action, outcome) VALUES (?, 1, 'forged', 'recorded')", (seq,)
        )
    assert _events(conn) == before


@pytest.mark.parametrize("kind", [None, EngineKind.SYNTHETIC], ids=["no verdict shown", "a verdict shown"])
def test_viewing_a_delivery_records_the_engine_kind_when_a_verdict_is_shown_and_only_then(conn, clock, kind):
    with store.transaction(conn):
        _record(conn, clock, action=AuditAction.DELIVERY_VIEWED, outcome=Outcome.ALLOWED, engine_kind=kind, **DELIVERY)
    (event,) = _events(conn)
    assert event["engine_kind"] == (kind.value if kind else None)


# --- M1J: the one bounded system actor (the internal rescan) --------------------------------------------------------------
#
# A rescan is neither a vendor's nor a coordinator's act, so it is recorded under its own named identity in a namespace
# no token issuer can have. record_event refuses that namespace to anybody else, and refuses the system actor anything
# but the events a rescan produces: it cannot accept, view, read an asset or manage an engagement.

SYSTEM_ALLOWED = {
    "a rescan started": (AuditAction.DELIVERY_RESCAN_STARTED, Outcome.ALLOWED, None, None),
    "a rescan started for a stale verdict": (AuditAction.DELIVERY_RESCAN_STARTED, Outcome.ALLOWED, AuditReason.VERDICT_STALE, None),
    "a scan that passed": (AuditAction.DELIVERY_SCAN_PASSED, Outcome.RECORDED, None, EngineKind.SYNTHETIC),
    "a verdict reused": (AuditAction.DELIVERY_VERDICT_REUSED, Outcome.RECORDED, None, EngineKind.SYNTHETIC),
    "a detection": (AuditAction.DELIVERY_REJECTED, Outcome.DENIED, AuditReason.DETECTION, EngineKind.SYNTHETIC),
    "a scan that failed": (AuditAction.DELIVERY_SCAN_FAILED, Outcome.RECORDED, AuditReason.SCANNER_TIMEOUT, EngineKind.SYNTHETIC),
    "an integrity failure": (AuditAction.DELIVERY_INTEGRITY_FAILED, Outcome.DENIED, AuditReason.SEALED_CONTENT_CHANGED, None),
    "a refused rescan": (AuditAction.DELIVERY_REQUEST_REJECTED, Outcome.DENIED, AuditReason.STATE_CONFLICT, None),
}  # fmt: skip
SYSTEM_ACTIONS = frozenset(case[0] for case in SYSTEM_ALLOWED.values())


def test_the_system_actors_are_named_identities_in_a_namespace_no_issuer_can_have():
    assert audit.SYSTEM_RESCAN == Actor("system:content-boundary-lab", "rescan")
    assert audit.SYSTEM_PROMOTE == Actor("system:content-boundary-lab", "promote")  # M1K: M0's "System job" for step 7
    assert audit.SYSTEM_ACTORS == frozenset({audit.SYSTEM_RESCAN, audit.SYSTEM_PROMOTE})
    assert all(actor.issuer.startswith(audit.SYSTEM_ISSUER_PREFIX) for actor in audit.SYSTEM_ACTORS)


# --- M1K: the promotion job is a second named system actor with its own, separate events ------------------------------------

PROMOTE_ALLOWED = {
    "a promotion started": (AuditAction.DELIVERY_PROMOTION_STARTED, Outcome.ALLOWED, None),
    "a delivery promoted": (AuditAction.DELIVERY_PROMOTED, Outcome.RECORDED, None),
    "an integrity failure": (AuditAction.DELIVERY_INTEGRITY_FAILED, Outcome.DENIED, AuditReason.SEALED_CONTENT_CHANGED),
    "a refused promotion": (AuditAction.DELIVERY_REQUEST_REJECTED, Outcome.DENIED, AuditReason.STATE_CONFLICT),
}
PROMOTE_ACTIONS = frozenset(case[0] for case in PROMOTE_ALLOWED.values())


@pytest.mark.parametrize("case", PROMOTE_ALLOWED.values(), ids=list(PROMOTE_ALLOWED))
def test_the_promotion_job_may_record_the_events_of_a_promotion(conn, clock, case):
    action, outcome, reason = case
    with store.transaction(conn):
        _record(conn, clock, action=action, outcome=outcome, reason=reason, actor=audit.SYSTEM_PROMOTE, **DELIVERY)
    (event,) = _events(conn)
    assert (event["actor_issuer"], event["actor_subject"], event["action"]) == ("system:content-boundary-lab", "promote", action.value)
    assert event["engine_kind"] is None  # a promotion is not about a scanner verdict


@pytest.mark.parametrize("action", [action for action in AuditAction if action not in PROMOTE_ACTIONS], ids=lambda action: action.value)
def test_the_promotion_job_may_record_nothing_else(conn, clock, action):
    kind = EngineKind.SYNTHETIC if action in (AuditAction.DELIVERY_ACCEPTED, AuditAction.DELIVERY_VIEWED) else None
    with pytest.raises(ValueError, match="system actor"), store.transaction(conn):
        _record(conn, clock, action=action, outcome=Outcome.ALLOWED, actor=audit.SYSTEM_PROMOTE, engine_kind=kind, **DELIVERY)
    assert _events(conn) == []


@pytest.mark.parametrize("action", [AuditAction.DELIVERY_PROMOTION_STARTED, AuditAction.DELIVERY_PROMOTED])
def test_the_rescan_may_not_record_a_promotion(conn, clock, action):
    with pytest.raises(ValueError, match="system actor"), store.transaction(conn):
        _record(conn, clock, action=action, outcome=Outcome.ALLOWED, actor=audit.SYSTEM_RESCAN, **DELIVERY)
    assert _events(conn) == []


@pytest.mark.parametrize("case", SYSTEM_ALLOWED.values(), ids=list(SYSTEM_ALLOWED))
def test_the_system_actor_may_record_the_events_of_a_rescan(conn, clock, case):
    action, outcome, reason, kind = case
    with store.transaction(conn):
        _record(conn, clock, action=action, outcome=outcome, reason=reason, engine_kind=kind, actor=audit.SYSTEM_RESCAN, **DELIVERY)
    (event,) = _events(conn)
    assert (event["actor_issuer"], event["actor_subject"], event["action"]) == ("system:content-boundary-lab", "rescan", action.value)


@pytest.mark.parametrize("action", [action for action in AuditAction if action not in SYSTEM_ACTIONS], ids=lambda action: action.value)
def test_the_system_actor_may_record_nothing_else(conn, clock, action):
    kind = EngineKind.SYNTHETIC if action in (AuditAction.DELIVERY_ACCEPTED, AuditAction.DELIVERY_VIEWED) else None
    with pytest.raises(ValueError, match="system actor"), store.transaction(conn):
        _record(conn, clock, action=action, outcome=Outcome.ALLOWED, actor=audit.SYSTEM_RESCAN, engine_kind=kind, **DELIVERY)
    assert _events(conn) == []


@pytest.mark.parametrize(
    ("issuer", "subject"),
    [
        ("system:content-boundary-lab", "somebody"),  # the namespace, under another name
        ("system:other", "rescan"),
        ("system:", "rescan"),
        ("system:content-boundary-lab:", "rescan"),
        ("system:content-boundary-lab ", "rescan"),
        ("SYSTEM:content-boundary-lab", "rescan"),  # the namespace is compared without regard to case
        ("System:Content-Boundary-Lab", "rescan"),
    ],
)
def test_nobody_else_may_use_the_system_namespace(conn, clock, issuer, subject):
    impostor = Actor(issuer, subject)  # an Actor only checks the shape of a pair, as before
    with pytest.raises(ValueError, match="system actor"), store.transaction(conn):
        _record(conn, clock, action=AuditAction.DELIVERY_RESCAN_STARTED, outcome=Outcome.ALLOWED, actor=impostor, **DELIVERY)
    assert _events(conn) == []


def test_an_ordinary_issuer_that_merely_resembles_the_namespace_is_not_the_system(conn, clock):
    with store.transaction(conn):
        _record(conn, clock, actor=Actor("https://system.example", "rescan"))
        _record(conn, clock, actor=Actor("systematic", "rescan"))
    assert len(_events(conn)) == 2


def test_the_engine_kind_is_one_of_the_columns_the_schema_check_protects(db_path, conn):
    conn.close()
    raw = sqlite3.connect(db_path)
    raw.execute("ALTER TABLE audit_events DROP COLUMN engine_kind")
    raw.close()
    with pytest.raises(store.SchemaIntegrityError, match="audit_events"):
        store.connect(db_path)


def test_an_unauthenticated_event_stores_null_actor_fields(conn, clock):
    with store.transaction(conn):
        _record(conn, clock, actor=None, reason=AuditReason.NO_ENGAGEMENT)
    (event,) = _events(conn)
    assert event["actor_issuer"] is None and event["actor_subject"] is None
    assert event["production_id"] is None and event["object_type"] is None and event["object_id"] is None
    assert event["reason"] == "no_engagement"


def test_a_malformed_external_identifier_is_recorded_as_invalid_identifier_with_no_object_id(conn, clock):
    with store.transaction(conn):
        with pytest.raises(ValueError, match="object_id"):
            _record(conn, clock, object_type=ObjectType.ASSET, object_id="../../" + "x" * 500)
        _record(conn, clock, object_type=ObjectType.ASSET, object_id=None, reason=AuditReason.INVALID_IDENTIFIER)
    (event,) = _events(conn)
    assert event["object_id"] is None and event["reason"] == "invalid_identifier" and event["object_type"] == "asset"


def test_sequence_numbers_increase_and_match_the_returned_value(conn, clock):
    with store.transaction(conn):
        first = _record(conn, clock)
        second = _record(conn, clock)
    with store.transaction(conn):
        third = _record(conn, clock)
    assert isinstance(first, int) and first < second < third
    assert [event["seq"] for event in _events(conn)] == [first, second, third]


def test_stored_timestamps_match_the_injected_clock_exactly(conn, clock):
    moments = [T0, T0 + timedelta(microseconds=1), T0 + timedelta(days=3, microseconds=999_999)]
    for moment in moments:
        clock.set(moment)
        with store.transaction(conn):
            _record(conn, clock)
    assert [event["at"] for event in _events(conn)] == [to_micros(moment) for moment in moments]
    assert _events(conn)[0]["at"] == 1793707200123457
    clock.set(T0.astimezone(timezone(timedelta(hours=5, minutes=30))))  # the same instant, another offset
    with store.transaction(conn):
        _record(conn, clock)
    assert _events(conn)[-1]["at"] == 1793707200123457


ORDINARY_IDENTITIES = [
    "José García",
    "山田 太郎",
    "Ægir Þórsson",
    "مريم",
    "\N{LATIN SMALL LETTER E WITH ACUTE}",
    "e\N{COMBINING ACUTE ACCENT}",  # the same letter as a base character and a combining accent: not normalised
    "O'Brien <o.brien+lab@example.com>",
    "smile \U0001f642",
    "  padded  ",
    "Mixed-Case",
    "a" * 512,
]


def test_ordinary_unicode_identities_are_accepted_and_stored_verbatim(conn, clock):
    with store.transaction(conn):
        for text in ORDINARY_IDENTITIES:
            _record(conn, clock, actor=Actor(text, text))
    stored = [(event["actor_issuer"], event["actor_subject"]) for event in _events(conn)]
    assert stored == [(text, text) for text in ORDINARY_IDENTITIES]  # nothing stripped, folded or normalised


def test_values_are_bound_as_parameters_not_spliced_into_sql(conn, clock):
    punctuation = ["x'); DROP TABLE audit_events; --", 'a" OR 1=1 --', "50%_off\\", "'; UPDATE engagements SET role = 'x"]
    with store.transaction(conn):
        for text in punctuation:
            _record(conn, clock, actor=Actor(text, text))
    assert [(event["actor_issuer"], event["actor_subject"]) for event in _events(conn)] == [(t, t) for t in punctuation]
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"productions", "subjects", "engagements", "assets", "audit_events"} <= tables


# --- rejected input: nothing is written --------------------------------------------------------------------------

BAD_TYPED_VALUES = {
    "action as a plain string": {"action": "engagement.created"},
    "action of the wrong enum": {"action": AuditReason.NO_ENGAGEMENT},
    "action None": {"action": None},
    "outcome as a plain string": {"outcome": "recorded"},
    "outcome of the wrong enum": {"outcome": AuditAction.ASSET_READ},
    "reason as a plain string": {"reason": "no_engagement"},
    "reason as free text": {"reason": "the caller typed whatever they liked"},
    "reason of the wrong enum": {"reason": ObjectType.ASSET},
    "object_type as a plain string": {"object_type": "asset"},
    "object_type of the wrong enum": {"object_type": Outcome.ALLOWED},
}


@pytest.mark.parametrize("overrides", BAD_TYPED_VALUES.values(), ids=list(BAD_TYPED_VALUES))
def test_codes_must_be_typed_vocabulary_members_not_strings(conn, clock, overrides):
    with store.transaction(conn):
        with pytest.raises(TypeError, match=next(iter(overrides))):
            _record(conn, clock, **overrides)
    assert _count(conn) == 0


HEX_IDENTIFIER = "0123456789abcdef" * 2
BAD_STORE_IDENTIFIERS = {
    "empty": "",
    "31 characters": "a" * 31,
    "33 characters": "a" * 33,
    "129 characters": "a" * 129,
    "10000 characters": "a" * 10_000,
    "uppercase": HEX_IDENTIFIER.upper(),
    "one uppercase letter": "a" * 31 + "A",
    "not hexadecimal": "g" * 32,
    "dashed UUID text": "01234567-89ab-cdef-0123-456789abcdef",
    "braced UUID text": "{" + HEX_IDENTIFIER + "}",
    "URN UUID text": "urn:uuid:" + HEX_IDENTIFIER,
    "trailing newline": HEX_IDENTIFIER + "\n",
    "leading space": " " + HEX_IDENTIFIER[1:],
    "NUL": HEX_IDENTIFIER[:31] + "\x00",
    "lone surrogate": HEX_IDENTIFIER[:31] + "\ud800",
    "full-width digits": "\N{FULLWIDTH DIGIT ZERO}" * 32,
    "path-like": "../../etc/passwd",
    "path-like, 32 characters": "../" * 10 + "ab",
    "SQL punctuation": "x'); DROP TABLE audit_events; --",
    "a subject identifier": "1",
}
STORE_IDENTIFIER_FIELDS = [
    ("production_id", {}),
    ("object_id", {"object_type": ObjectType.PRODUCTION}),
    ("object_id", {"object_type": ObjectType.ENGAGEMENT}),
    ("object_id", {"object_type": ObjectType.ASSET}),
]
STORE_IDENTIFIER_FIELD_IDS = ["production_id", "production object_id", "engagement object_id", "asset object_id"]


@pytest.mark.parametrize(("field", "extra"), STORE_IDENTIFIER_FIELDS, ids=STORE_IDENTIFIER_FIELD_IDS)
@pytest.mark.parametrize("value", BAD_STORE_IDENTIFIERS.values(), ids=list(BAD_STORE_IDENTIFIERS))
def test_a_store_identifier_must_be_32_lowercase_hexadecimal_characters(conn, clock, field, extra, value):
    with store.transaction(conn):
        with pytest.raises(ValueError, match=field) as caught:
            _record(conn, clock, **{field: value}, **extra)
    assert not value or value not in str(caught.value)  # the rejected value is not echoed back
    assert _count(conn) == 0


@pytest.mark.parametrize(("field", "extra"), STORE_IDENTIFIER_FIELDS, ids=STORE_IDENTIFIER_FIELD_IDS)
@pytest.mark.parametrize("value", [b"a" * 32, 12345, 1.5, True], ids=["bytes", "int", "float", "bool"])
def test_a_store_identifier_must_be_a_str(conn, clock, field, extra, value):
    with store.transaction(conn):
        with pytest.raises(TypeError, match=field):
            _record(conn, clock, **{field: value}, **extra)
    assert _count(conn) == 0


@pytest.mark.parametrize("value", ["0" * 32, "f" * 32, HEX_IDENTIFIER], ids=["all-zero", "all-f", "mixed"])
def test_valid_store_identifiers_are_accepted_and_stored_unchanged(conn, clock, value):
    kinds = (ObjectType.PRODUCTION, ObjectType.ENGAGEMENT, ObjectType.ASSET)
    with store.transaction(conn):
        for kind in kinds:
            _record(conn, clock, production_id=value, object_type=kind, object_id=value)
    stored = [(event["production_id"], event["object_type"], event["object_id"]) for event in _events(conn)]
    assert stored == [(value, kind.value, value) for kind in kinds]


BAD_SUBJECT_IDENTIFIERS = {
    "empty": "",
    "zero": "0",
    "leading zero": "01",
    "negative": "-1",
    "plus sign": "+1",
    "leading space": " 1",
    "trailing space": "1 ",
    "trailing newline": "1\n",
    "decimal point": "1.0",
    "exponent": "1e3",
    "hexadecimal": "0x10",
    "digit separator": "1_000",
    "Arabic-Indic digit": "\N{ARABIC-INDIC DIGIT ONE}",
    "full-width digit": "\N{FULLWIDTH DIGIT ONE}",
    "ASCII digit then Arabic-Indic digit": "1\N{ARABIC-INDIC DIGIT TWO}",  # int() would read this as 12
    "one past the largest SQLite integer": "9223372036854775808",
    "20 digits": "9" * 20,
    "10000 digits": "1" * 10_000,
    "a store identifier": HEX_IDENTIFIER,
    "path-like": "../1",
}


@pytest.mark.parametrize("value", BAD_SUBJECT_IDENTIFIERS.values(), ids=list(BAD_SUBJECT_IDENTIFIERS))
def test_a_subject_identifier_must_be_a_canonical_positive_decimal_integer(conn, clock, value):
    with store.transaction(conn):
        with pytest.raises(ValueError, match="object_id") as caught:
            _record(conn, clock, object_type=ObjectType.SUBJECT, object_id=value)
    assert not value or value not in str(caught.value)
    assert _count(conn) == 0


def test_a_subject_identifier_must_be_a_str(conn, clock):
    with store.transaction(conn):
        with pytest.raises(TypeError, match="object_id"):
            _record(conn, clock, object_type=ObjectType.SUBJECT, object_id=5)
    assert _count(conn) == 0


@pytest.mark.parametrize("value", ["1", "9", "10", "42", "9223372036854775807"], ids=str)
def test_valid_subject_identifiers_are_accepted_and_stored_unchanged(conn, clock, value):
    with store.transaction(conn):
        _record(conn, clock, object_type=ObjectType.SUBJECT, object_id=value)
    assert [event["object_id"] for event in _events(conn)] == [value]


def test_an_object_id_requires_an_object_type(conn, clock):
    with store.transaction(conn):
        with pytest.raises(ValueError, match="object_type") as caught:
            _record(conn, clock, object_id=HEX_IDENTIFIER)
    assert HEX_IDENTIFIER not in str(caught.value)
    assert _count(conn) == 0


def test_an_object_type_without_an_object_id_is_allowed_for_an_invalid_identifier_denial(conn, clock):
    with store.transaction(conn):
        for kind in ObjectType:
            _record(conn, clock, object_type=kind, object_id=None, reason=AuditReason.INVALID_IDENTIFIER)
        _record(conn, clock, object_type=None, object_id=None, reason=AuditReason.INVALID_IDENTIFIER)
    assert [event["object_type"] for event in _events(conn)] == [kind.value for kind in ObjectType] + [None]
    assert {event["object_id"] for event in _events(conn)} == {None}


def test_an_append_outside_a_transaction_is_rejected_and_writes_nothing(conn, clock):
    assert not conn.in_transaction
    with pytest.raises(store.StoreError, match="transaction"):
        _record(conn, clock)
    assert not conn.in_transaction and _count(conn) == 0
    with store.transaction(conn):
        _record(conn, clock)
    with pytest.raises(store.StoreError, match="transaction"):  # after a commit, too
        _record(conn, clock)
    assert _count(conn) == 1


def test_a_rejected_append_leaves_the_callers_transaction_and_earlier_work_intact(conn, clock):
    engagement_id, production_id = _engagement(conn, clock)
    with store.transaction(conn):
        store.revoke_engagement(conn, clock, engagement_id)
        with pytest.raises(ValueError, match="object_id"):
            _record(conn, clock, object_type=ObjectType.ASSET, object_id="x" * 129)
        assert conn.in_transaction  # nothing was committed or rolled back on the caller's behalf
    assert _revoked_at(conn, engagement_id) is not None  # the caller's own commit still applied its work
    assert _count(conn) == 0


@pytest.mark.parametrize(
    ("clock_to_use", "error", "message"),
    [(NaiveClock(), ValueError, "timezone-aware"), (NotADatetimeClock(), TypeError, "datetime")],
    ids=["naive-datetime", "not-a-datetime"],
)
def test_an_invalid_clock_value_fails_the_whole_transaction(conn, clock, clock_to_use, error, message):
    engagement_id, production_id = _engagement(conn, clock)
    with pytest.raises(error, match=message):
        with store.transaction(conn):
            store.revoke_engagement(conn, clock, engagement_id)
            _record(conn, clock_to_use)
    assert not conn.in_transaction
    assert _revoked_at(conn, engagement_id) is None and _count(conn) == 0


# --- atomicity of a state change and its audit event -------------------------------------------------------------


def test_a_state_change_and_its_audit_event_become_visible_together(conn, reader, clock):
    engagement_id, production_id = _engagement(conn, clock)
    clock.set(T0 + timedelta(days=1))

    def nothing_visible_yet():
        assert _revoked_at(reader, engagement_id) is None and _count(reader) == 0
        assert conn.in_transaction  # record_event neither committed nor rolled back

    _revoke_and_audit(conn, clock, engagement_id, production_id, after_audit=nothing_visible_yet)
    assert _revoked_at(reader, engagement_id) == to_micros(T0 + timedelta(days=1))
    (event,) = _events(reader)
    assert event["action"] == "engagement.revoked" and event["object_id"] == engagement_id
    assert event["at"] == to_micros(T0 + timedelta(days=1))


def test_a_failure_after_the_state_change_but_before_the_audit_insert_rolls_back_the_change(conn, reader, clock):
    engagement_id, production_id = _engagement(conn, clock)
    with pytest.raises(RuntimeError, match="simulated"):
        _revoke_and_audit(conn, clock, engagement_id, production_id, after_revoke=_fail)
    assert not conn.in_transaction
    assert _revoked_at(conn, engagement_id) is None and _count(conn) == 0
    assert _revoked_at(reader, engagement_id) is None and _count(reader) == 0


def test_a_failing_audit_insert_rolls_back_the_state_change(db_path, conn, reader, clock):
    engagement_id, production_id = _engagement(conn, clock)
    raw = sqlite3.connect(db_path)  # make this one insert fail inside the database, as a full disk or a lock would
    raw.execute(
        "CREATE TRIGGER refuse_revocation_events BEFORE INSERT ON audit_events WHEN NEW.action = 'engagement.revoked' "
        "BEGIN SELECT RAISE(ABORT, 'audit insert refused'); END"
    )
    raw.commit()
    raw.close()
    with pytest.raises(sqlite3.IntegrityError, match="audit insert refused"):
        _revoke_and_audit(conn, clock, engagement_id, production_id)
    assert not conn.in_transaction
    assert _revoked_at(conn, engagement_id) is None and _count(conn) == 0
    assert _revoked_at(reader, engagement_id) is None and _count(reader) == 0


def test_a_failure_after_the_audit_insert_rolls_back_both(conn, reader, clock):
    engagement_id, production_id = _engagement(conn, clock)
    with pytest.raises(RuntimeError, match="simulated"):
        _revoke_and_audit(conn, clock, engagement_id, production_id, after_audit=_fail)
    assert not conn.in_transaction
    assert _revoked_at(conn, engagement_id) is None and _count(conn) == 0
    assert _revoked_at(reader, engagement_id) is None and _count(reader) == 0


def test_a_denial_without_a_state_change_commits_in_its_own_short_transaction(conn, reader, clock):
    with store.transaction(conn):
        _record(conn, clock, reason=AuditReason.ENGAGEMENT_EXPIRED, object_type=ObjectType.ASSET, object_id="c" * 32)
        assert _count(reader) == 0
    assert [event["reason"] for event in _events(reader)] == ["engagement_expired"]
