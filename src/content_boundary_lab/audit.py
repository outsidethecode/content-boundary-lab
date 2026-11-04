"""Transactional audit events: a closed vocabulary, a shape-checked actor and one append inside the caller's transaction.

record_event() never commits or rolls back, and it does not make any mutation audited by itself: each workflow calls
it in the same store.transaction() as its state change, so the two commit or fail together.
"""

import re
import sqlite3
import unicodedata
from dataclasses import dataclass
from enum import StrEnum

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


class ObjectType(StrEnum):
    """The kind of object an event is about."""

    PRODUCTION = "production"
    ENGAGEMENT = "engagement"
    ASSET = "asset"
    SUBJECT = "subject"


class Outcome(StrEnum):
    """The result; the values are the ones the audit_events CHECK constraint accepts."""

    ALLOWED = "allowed"
    DENIED = "denied"
    RECORDED = "recorded"


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
) -> int:
    """Append one audit event inside the caller's open transaction and return its sequence number.

    actor=None records an unauthenticated event. Invalid input is rejected before any SQL runs. If the insert itself
    fails, the error propagates and the caller's transaction fails with it: there is no best-effort fallback.

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
    _check_production_id(production_id)
    _check_object_id(object_type, object_id)
    if not conn.in_transaction:
        raise StoreError("an audit event must be recorded inside the caller's transaction")
    cursor = conn.execute(
        "INSERT INTO audit_events (at, actor_issuer, actor_subject, action, outcome, production_id, object_type, "
        "object_id, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        ),
    )
    return cursor.lastrowid
