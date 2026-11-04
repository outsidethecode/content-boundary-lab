"""INTENTIONALLY VULNERABLE (F-06). The default application does not contain this. Never imported by src/.

Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

The single mistake: authorisation comes from the `productions` claim that the identity provider baked into the token when it
issued it, the way group claims are often used, instead of from the engagement store at the time of the request. The token
is verified in full first (that is the reference's own work); what it says about the productions the bearer may use is then
believed until it expires, so revoking the engagement, or reaching its end date, changes nothing. The reference twin is
`authz.authorize_engagement`, which looks the engagement up on every request and ignores every claim but identity.
"""

from content_boundary_lab.audit import AuditReason
from content_boundary_lab.authz import _AUTHORIZED, POLICY, AuthorizationDenied, AuthorizedEngagement
from labs.carrier import CARRIED


def authorize_engagement(conn, identity, production_id, action, now_micros):
    claims = CARRIED.get()
    role = (claims.get("productions") or {}).get(production_id)
    if role is None:
        raise AuthorizationDenied(AuditReason.NO_ENGAGEMENT)
    if action not in POLICY.get(role, frozenset()):
        raise AuthorizationDenied(AuditReason.ROLE_NOT_PERMITTED)
    return AuthorizedEngagement("0" * 32, role, claims["exp"] * 1_000_000, _proof=_AUTHORIZED)
