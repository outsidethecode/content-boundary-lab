"""Server-side engagement authorisation: what a verified identity may do in a production, decided from SQLite alone.

authorize_engagement() looks up the engagement of one verified (issuer, subject) in one production and decides, in this
order: invalid production identifier, no subject or engagement, revoked, expired (now >= ends_at), role lacks the
action. Anything else is refused by default. Every refusal is an AuthorizationDenied whose reason is a member of the
audit vocabulary; success is an AuthorizedEngagement, which cannot be built without passing every check.

The role, the end date and the revocation come only from the engagements row. Nothing a token carried (a role, scope,
permission or production claim) can reach this function: it takes a VerifiedIdentity, which holds an issuer and a
subject and nothing else. It reads no clock (the caller supplies the decision instant), no environment variable and no
configuration, opens no connection, and never commits or rolls back.

The caller owns the transaction. For the ordering guarantee that a revocation is seen by every request that begins after
its commit, that transaction must be store.transaction() (BEGIN IMMEDIATE). This function can only check that some
transaction is open; it cannot tell BEGIN IMMEDIATE from a deferred BEGIN. It also records no audit event: the caller
does, in the same transaction.
"""

import re
import sqlite3
from dataclasses import KW_ONLY, InitVar, dataclass
from enum import StrEnum
from types import MappingProxyType

from content_boundary_lab.audit import AuditReason
from content_boundary_lab.identity import VerifiedIdentity
from content_boundary_lab.store import StoreError


class Action(StrEnum):
    """What a caller asks to do in a production. Closed: adding a member is a reviewed change."""

    VIEW_OWN_ENGAGEMENT = "view_own_engagement"
    MANAGE_ENGAGEMENTS = "manage_engagements"  # create and revoke engagements in the production


# The actions each engagement role may take. A role that is not listed may take none.
POLICY = MappingProxyType(
    {
        "coordinator": frozenset({Action.VIEW_OWN_ENGAGEMENT, Action.MANAGE_ENGAGEMENTS}),
        "vendor": frozenset({Action.VIEW_OWN_ENGAGEMENT}),
    }
)
DENIAL_REASONS = frozenset(
    {
        AuditReason.INVALID_IDENTIFIER,
        AuditReason.NO_ENGAGEMENT,
        AuditReason.ENGAGEMENT_REVOKED,
        AuditReason.ENGAGEMENT_EXPIRED,
        AuditReason.ROLE_NOT_PERMITTED,
    }
)

_PRODUCTION_ID = re.compile(r"[0-9a-f]{32}")  # the shape of every id the store generates
_LOOKUP = (
    "SELECT e.id, e.role, e.ends_at, e.revoked_at FROM engagements AS e "
    "JOIN subjects AS s ON s.id = e.subject_id "
    "WHERE s.issuer = ? AND s.subject = ? AND e.production_id = ?"
)


class AuthorizationDenied(Exception):
    """Access was refused. The reason is for the audit record, never for a client; the message holds nothing else."""

    def __init__(self, reason: AuditReason) -> None:
        if not isinstance(reason, AuditReason) or reason not in DENIAL_REASONS:
            raise ValueError("an authorisation denial carries one of the five authorisation reasons")
        super().__init__(f"authorisation denied: {reason.value}")
        self.reason = reason


# Only authorize_engagement() holds this. It discourages building an AuthorizedEngagement by accident; it is not a
# security boundary, because any Python code in the process can import it.
_AUTHORIZED = object()


@dataclass(frozen=True)
class AuthorizedEngagement:
    """The engagement that allowed a request: its id, the role it grants and when it ends (microseconds, UTC)."""

    engagement_id: str
    role: str
    ends_at: int
    _: KW_ONLY
    _proof: InitVar[object]

    def __post_init__(self, _proof: object) -> None:
        if _proof is not _AUTHORIZED:
            raise TypeError("an AuthorizedEngagement comes only from authorize_engagement()")


def authorize_engagement(
    conn: sqlite3.Connection, identity: VerifiedIdentity, production_id: str, action: Action, now_micros: int
) -> AuthorizedEngagement:
    """Authorise `action` for `identity` in `production_id` at `now_micros`, or raise AuthorizationDenied.

    A wrong argument type, or a call outside a transaction, is a fault of the caller and raises TypeError or StoreError;
    a production_id that is not a store identifier is input and is denied.
    """
    if not isinstance(conn, sqlite3.Connection):
        raise TypeError("conn must be an sqlite3.Connection")
    if not isinstance(identity, VerifiedIdentity):
        raise TypeError("identity must be a VerifiedIdentity")
    if not isinstance(action, Action):
        raise TypeError("action must be an Action")
    if type(now_micros) is not int:
        raise TypeError("now_micros must be an int (a bool is not accepted)")
    if not conn.in_transaction:
        raise StoreError("authorisation must run inside the caller's transaction")
    if type(production_id) is not str or not _PRODUCTION_ID.fullmatch(production_id):
        raise AuthorizationDenied(AuditReason.INVALID_IDENTIFIER)
    row = conn.execute(_LOOKUP, (identity.issuer, identity.subject, production_id)).fetchone()
    if row is None:
        raise AuthorizationDenied(AuditReason.NO_ENGAGEMENT)
    engagement_id, role, ends_at, revoked_at = row[0], row[1], row[2], row[3]
    if revoked_at is not None:
        raise AuthorizationDenied(AuditReason.ENGAGEMENT_REVOKED)
    if now_micros >= ends_at:
        raise AuthorizationDenied(AuditReason.ENGAGEMENT_EXPIRED)
    if action not in POLICY.get(role, frozenset()):
        raise AuthorizationDenied(AuditReason.ROLE_NOT_PERMITTED)
    return AuthorizedEngagement(engagement_id, role, ends_at, _proof=_AUTHORIZED)
