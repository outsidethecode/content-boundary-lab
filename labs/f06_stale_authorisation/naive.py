"""NAIVE FIXES, INCOMPLETE (F-06). Not the reference. Never imported by src/.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

`jwt_validity_only` is the fix that checks the token again: it still believes the `productions` claim, and refuses once the
token is past its expiry. The reference's verifier has already refused every token that is not valid, so this changes nothing:
a valid signature and an unexpired token prove who the caller is and that the token is current, and say nothing about whether
an engagement granted earlier is still active.

`revocation_but_not_the_end_date` is the fix that does look at the engagement store, every request, and checks that the
engagement was not revoked, and forgets that an engagement also ends. It is right on the first request after a revocation and
wrong on the first request at the end date, which is why the matrix has the instants either side of the boundary.
"""

from content_boundary_lab.audit import AuditReason
from content_boundary_lab.authz import _AUTHORIZED, _LOOKUP, POLICY, AuthorizationDenied, AuthorizedEngagement
from labs.carrier import CARRIED


def jwt_validity_only(conn, identity, production_id, action, now_micros):
    claims = CARRIED.get()
    if now_micros >= claims["exp"] * 1_000_000:
        raise AuthorizationDenied(AuditReason.ENGAGEMENT_EXPIRED)
    role = (claims.get("productions") or {}).get(production_id)
    if role is None:
        raise AuthorizationDenied(AuditReason.NO_ENGAGEMENT)
    if action not in POLICY.get(role, frozenset()):
        raise AuthorizationDenied(AuditReason.ROLE_NOT_PERMITTED)
    return AuthorizedEngagement("0" * 32, role, claims["exp"] * 1_000_000, _proof=_AUTHORIZED)


def revocation_but_not_the_end_date(conn, identity, production_id, action, now_micros):
    row = conn.execute(_LOOKUP, (identity.issuer, identity.subject, production_id)).fetchone()
    if row is None:
        raise AuthorizationDenied(AuditReason.NO_ENGAGEMENT)
    engagement_id, role, ends_at, revoked_at = row[0], row[1], row[2], row[3]
    if revoked_at is not None:
        raise AuthorizationDenied(AuditReason.ENGAGEMENT_REVOKED)
    if action not in POLICY.get(role, frozenset()):
        raise AuthorizationDenied(AuditReason.ROLE_NOT_PERMITTED)
    return AuthorizedEngagement(engagement_id, role, ends_at, _proof=_AUTHORIZED)
