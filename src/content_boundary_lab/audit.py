"""Transactional audit events: a closed vocabulary, a shape-checked actor and one append inside the caller's transaction.

record_event() never commits or rolls back, and it does not make any mutation audited by itself: each workflow calls
it in the same store.transaction() as its state change, so the two commit or fail together.
"""

import re
import sqlite3
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from content_boundary_lab.clock import Clock, to_micros
from content_boundary_lab.store import StoreError

MAX_ACTOR_LENGTH = 512  # the same bound as the subjects table
MAX_SUBJECT_ID = 2**63 - 1  # the largest SQLite INTEGER PRIMARY KEY
# Controls, lone surrogates, format characters (such as the bidirectional overrides) and line or paragraph separators.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cs", "Cf", "Zl", "Zp"})
_STORE_ID = re.compile(r"[0-9a-f]{32}")  # productions, engagements and assets, as the store generates them
_SUBJECT_ID = re.compile(r"[1-9][0-9]{0,18}")  # subjects: a canonical positive decimal integer


class AuditAction(StrEnum):
    """What happened. Closed: adding a member is a reviewed change (lowercase, at most 64 characters)."""

    ENGAGEMENT_CREATED = "engagement.created"
    ENGAGEMENT_REVOKED = "engagement.revoked"
    ENGAGEMENT_REVOKE_REPEATED = "engagement.revoke_repeated"  # a repeat of a revocation: nothing was changed
    ENGAGEMENT_REQUEST_REJECTED = "engagement.request_rejected"  # an authorised request refused as invalid or a duplicate
    ENGAGEMENT_VIEWED = "engagement.viewed"
    ACCESS_DENIED = "access.denied"
    ASSET_READ = "asset.read"
    DELIVERY_INITIATED = "delivery.initiated"  # a vendor's declaration was stored as a delivery in INITIATED
    DELIVERY_REQUEST_REJECTED = "delivery.request_rejected"  # an authorised delivery request refused before any byte was kept
    DELIVERY_UPLOAD_STARTED = "delivery.upload_started"  # committed admission to begin receiving; not that any byte arrived
    DELIVERY_UPLOADED = "delivery.uploaded"  # the bytes are in quarantine and the move to UPLOADED committed with this event
    DELIVERY_UPLOAD_FAILED = "delivery.upload_failed"  # a started upload that did not end in UPLOADED (decided or abandoned)
    DELIVERY_SEAL_STARTED = "delivery.seal_started"  # committed move to SEALING; the server will now inspect the bytes
    DELIVERY_SCAN_PASSED = "delivery.scan_passed"  # SCAN_PASSED on a verdict the scanner just made: no_detection, nothing more
    DELIVERY_VERDICT_REUSED = "delivery.verdict_reused"  # SCAN_PASSED on a cached verdict for the same digest and scanner
    DELIVERY_REJECTED = "delivery.rejected"  # REJECTED: a mismatch, an unsupported type or a detection (the reason says which)
    DELIVERY_SCAN_FAILED = "delivery.scan_failed"  # SCAN_FAILED: the scanner could not give a verdict (the reason says why)
    DELIVERY_VIEWED = "delivery.viewed"  # a coordinator inspected a delivery's sealing result
    DELIVERY_ACCEPTED = "delivery.accepted"  # SCAN_PASSED -> ACCEPTED: a coordinator accepted the sealed digest
    DELIVERY_ACCEPTANCE_REFUSED = "delivery.acceptance_refused"  # an authorised acceptance that the delivery or the request failed
    DELIVERY_RESCAN_STARTED = "delivery.rescan_started"  # SCAN_FAILED or SCAN_PASSED -> SEALING, by the internal rescan
    DELIVERY_INTEGRITY_FAILED = "delivery.integrity_failed"  # INTEGRITY_FAILED: the bytes no longer hash to the sealed digest


class AuditReason(StrEnum):
    """Why an access was refused. Closed machine codes; never request text."""

    NO_ENGAGEMENT = "no_engagement"
    ENGAGEMENT_EXPIRED = "engagement_expired"
    ENGAGEMENT_REVOKED = "engagement_revoked"
    ROLE_NOT_PERMITTED = "role_not_permitted"
    NOT_FOUND_OR_FORBIDDEN = "not_found_or_forbidden"  # one code for both, so the record does not distinguish them
    INVALID_IDENTIFIER = "invalid_identifier"
    INVALID_CREDENTIALS = "invalid_credentials"  # a failed authentication; the AuthFailure detail is not recorded
    INVALID_REQUEST = "invalid_request"  # a body or field that failed validation; which one, and its text, are not recorded
    ENGAGEMENT_EXISTS = "engagement_exists"  # the subject already has an engagement in the production, in any state
    PAYLOAD_TOO_LARGE = "payload_too_large"  # a body over the limit; its size and content are not recorded
    STATE_CONFLICT = "state_conflict"  # the delivery was not (or was no longer) in the state the request needs
    UPLOAD_INTERRUPTED = "upload_interrupted"  # the client went away before the end of its body
    CHECKSUM_MISMATCH = "checksum_mismatch"  # the measured size or the server's SHA-256 is not what the vendor declared
    UNSUPPORTED_TYPE = "unsupported_type"  # the content's signature is not on the allowlist
    DETECTION = "detection"  # the scanner reported a detection for the bytes
    SCANNER_UNAVAILABLE = "scanner_unavailable"  # the scanner could not be used
    SCANNER_TIMEOUT = "scanner_timeout"  # the scanner did not answer in time
    SCANNER_BAD_RESPONSE = "scanner_bad_response"  # the scanner's reply was malformed or described other bytes
    VERDICT_STALE = "verdict_stale"  # the verdict has expired, or is from an engine, version or policy no longer in use
    VERDICT_NOT_APPLICABLE = "verdict_not_applicable"  # there is no no_detection verdict for the sealed digest to rely on
    DIGEST_MISMATCH = "digest_mismatch"  # the digest a coordinator named is not the delivery's sealed digest
    SEALED_CONTENT_CHANGED = "sealed_content_changed"  # the stored bytes no longer hash to the sealed digest and size


class ObjectType(StrEnum):
    """The kind of object an event is about."""

    PRODUCTION = "production"
    ENGAGEMENT = "engagement"
    ASSET = "asset"
    SUBJECT = "subject"
    DELIVERY = "delivery"


class Outcome(StrEnum):
    """The result; the values are the ones the audit_events CHECK constraint accepts."""

    ALLOWED = "allowed"
    DENIED = "denied"
    RECORDED = "recorded"


class EngineKind(StrEnum):
    """The kind of scanner engine an event is about (M0 Addendum §5.3). Closed, and the same set the scanner contract and
    the audit_events CHECK constraint accept: the shipped scanner is `synthetic`. A real engine would be a reviewed addition."""

    SYNTHETIC = "synthetic"


# engine.kind appears in every verdict-bearing audit event (Addendum §5.3). An event is verdict-bearing if it is about a
# scanner's verdict, or about a scan that could not give one (then the kind is the configured scanner's), or if it relies
# on a verdict (an acceptance, and an acceptance refused because of the verdict). It is required on those events and
# refused on every other, so the column is NULL everywhere else and is never free text. An inspection shows a verdict
# when the delivery has one, so there the kind is allowed when a verdict is shown and not otherwise required.
_KIND_REQUIRED_ACTIONS = frozenset(
    {
        AuditAction.DELIVERY_SCAN_PASSED,
        AuditAction.DELIVERY_VERDICT_REUSED,
        AuditAction.DELIVERY_SCAN_FAILED,
        AuditAction.DELIVERY_ACCEPTED,
    }
)
_KIND_REQUIRED_BY_REASON = {
    AuditAction.DELIVERY_REJECTED: frozenset({AuditReason.DETECTION}),
    AuditAction.DELIVERY_ACCEPTANCE_REFUSED: frozenset({AuditReason.VERDICT_STALE, AuditReason.VERDICT_NOT_APPLICABLE}),
}
_KIND_OPTIONAL_ACTIONS = frozenset({AuditAction.DELIVERY_VIEWED})


def _check_engine_kind(action: AuditAction, reason: AuditReason | None, engine_kind: EngineKind | None) -> None:
    if action in _KIND_OPTIONAL_ACTIONS:
        return
    required = action in _KIND_REQUIRED_ACTIONS or reason in _KIND_REQUIRED_BY_REASON.get(action, ())
    if required and engine_kind is None:
        raise ValueError("an event about a scanner verdict needs its engine_kind")
    if not required and engine_kind is not None:
        raise ValueError("engine_kind is for events about a scanner verdict only")


def _check_text(name: str, value: object, limit: int) -> None:
    """Shape rules: a non-empty str within the limit, without control, surrogate, format or separator characters.

    The value is never echoed in an error message, and it is never trimmed, folded, normalised or truncated.
    """
    _require_str(name, value)
    if not value:
        raise ValueError(f"{name} must not be empty")
    if len(value) > limit:
        raise ValueError(f"{name} is longer than {limit} characters")
    if any(unicodedata.category(char) in _FORBIDDEN_CATEGORIES for char in value):
        raise ValueError(f"{name} contains a control, surrogate, format or separator character")


def _require_str(name: str, value: object) -> None:
    if type(value) is not str:
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")


def _check_pattern(name: str, value: object, pattern: re.Pattern[str], description: str) -> None:
    """The whole value must match; it is never echoed, trimmed, case-folded or reinterpreted."""
    _require_str(name, value)
    if not pattern.fullmatch(value):
        raise ValueError(f"{name} must be {description}")


@dataclass(frozen=True)
class Actor:
    """An issuer and subject pair. This checks the SHAPE of the identity only.

    It does not establish that a token was verified or that the identity is authentic; that boundary is M1E's.
    """

    issuer: str
    subject: str

    def __post_init__(self) -> None:
        _check_text("issuer", self.issuer, MAX_ACTOR_LENGTH)
        _check_text("subject", self.subject, MAX_ACTOR_LENGTH)


# The lab's own acts (an internal rescan, M1J) are neither a vendor's nor a coordinator's, so they are recorded under a
# named identity that no verified token can carry: settings refuses a trusted issuer in this namespace, and this module
# refuses the namespace to everyone but the named system actors, each for its own events only. It is a convention in the
# audit trail and a bound on what may be recorded under it; it is not a credential and authenticates nothing.
SYSTEM_ISSUER_PREFIX = "system:"
SYSTEM_RESCAN = Actor("system:content-boundary-lab", "rescan")
SYSTEM_ACTORS = frozenset({SYSTEM_RESCAN})
_SYSTEM_ACTIONS = MappingProxyType(
    {
        SYSTEM_RESCAN: frozenset(
            {
                AuditAction.DELIVERY_RESCAN_STARTED,
                AuditAction.DELIVERY_SCAN_PASSED,
                AuditAction.DELIVERY_VERDICT_REUSED,
                AuditAction.DELIVERY_REJECTED,
                AuditAction.DELIVERY_SCAN_FAILED,
                AuditAction.DELIVERY_INTEGRITY_FAILED,
                AuditAction.DELIVERY_REQUEST_REJECTED,  # a rescan that was asked for and refused
            }
        )
    }
)


def _check_system_actor(actor: Actor | None, action: AuditAction) -> None:
    if actor is None or not actor.issuer.casefold().startswith(SYSTEM_ISSUER_PREFIX):
        return
    allowed = _SYSTEM_ACTIONS.get(actor)
    if allowed is None:
        raise ValueError("the system namespace belongs to the named system actors")
    if action not in allowed:
        raise ValueError("a system actor may record only the events of its own work")


def _require_type(name: str, value: object, kind: type, *, optional: bool = False) -> None:
    if value is None and optional:
        return
    if not isinstance(value, kind):
        raise TypeError(f"{name} must be of type {kind.__name__}, got {type(value).__name__}")


def _check_production_id(production_id: object) -> None:
    if production_id is not None:
        _check_pattern("production_id", production_id, _STORE_ID, "32 lowercase hexadecimal characters")


def _check_object_id(object_type: ObjectType | None, object_id: object) -> None:
    if object_id is None:
        return
    if object_type is None:
        raise ValueError("object_id requires object_type")
    if object_type is ObjectType.SUBJECT:
        _check_pattern("object_id", object_id, _SUBJECT_ID, "a canonical positive decimal integer")
        if int(object_id) > MAX_SUBJECT_ID:
            raise ValueError("object_id is larger than the largest SQLite integer")
    else:
        _check_pattern("object_id", object_id, _STORE_ID, "32 lowercase hexadecimal characters")


def record_event(
    conn: sqlite3.Connection,
    clock: Clock,
    action: AuditAction,
    outcome: Outcome,
    *,
    actor: Actor | None,
    production_id: str | None = None,
    object_type: ObjectType | None = None,
    object_id: str | None = None,
    reason: AuditReason | None = None,
    engine_kind: EngineKind | None = None,
) -> int:
    """Append one audit event inside the caller's open transaction and return its sequence number.

    actor=None records an unauthenticated event. Invalid input is rejected before any SQL runs. If the insert itself
    fails, the error propagates and the caller's transaction fails with it: there is no best-effort fallback.

    engine_kind is required on the events that are about a scanner verdict (a scan that passed, a verdict reused, a scan
    that could not give a verdict, a detection, an acceptance, an acceptance refused because of the verdict) and refused on
    every other event; an inspection may carry it. See _check_engine_kind.

    An actor in the `system:` namespace must be one of SYSTEM_ACTORS and may record only that actor's own events.

    production_id and an object_id for a production, engagement or asset are 32 lowercase hexadecimal characters, as
    the store generates them; a subject's object_id is a canonical positive decimal integer; object_id needs an
    object_type. Nothing is truncated, normalised or reinterpreted. For an external identifier that is malformed or
    oversized, record object_id=None with AuditReason.INVALID_IDENTIFIER.
    """
    _require_type("action", action, AuditAction)
    _require_type("outcome", outcome, Outcome)
    _require_type("actor", actor, Actor, optional=True)
    _require_type("object_type", object_type, ObjectType, optional=True)
    _require_type("reason", reason, AuditReason, optional=True)
    _require_type("engine_kind", engine_kind, EngineKind, optional=True)
    _check_production_id(production_id)
    _check_object_id(object_type, object_id)
    _check_system_actor(actor, action)
    _check_engine_kind(action, reason, engine_kind)
    if not conn.in_transaction:
        raise StoreError("an audit event must be recorded inside the caller's transaction")
    cursor = conn.execute(
        "INSERT INTO audit_events (at, actor_issuer, actor_subject, action, outcome, production_id, object_type, "
        "object_id, reason, engine_kind) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            to_micros(clock.now()),
            actor.issuer if actor else None,
            actor.subject if actor else None,
            action.value,
            outcome.value,
            production_id,
            object_type.value if object_type else None,
            object_id,
            reason.value if reason else None,
            engine_kind.value if engine_kind else None,
        ),
    )
    return cursor.lastrowid
