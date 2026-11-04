"""F-06 remediation matrix: revocation and expiry at their exact boundaries, claims as authority, and an intact verifier.

The original condition is authorisation from a claim baked into the token. What must keep working is every request of an
active engagement, whatever the token claims. The security condition is that a request is served only while the engagement is
active at the instant it starts (not revoked; `now < ends_at`), and that the token is evidence of identity and nothing more.
The T rows show the verifier is not what differs: in every variant a damaged token is a 401.
"""

from datetime import timedelta

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from content_boundary_lab import authz
from labs.f06_stale_authorisation import SEAM, naive
from labs.matrix import Matrix, Row, Variant
from labs.seam import seam
from labs.world import ISSUER, KID, T0, World

ENDS = T0 + timedelta(seconds=300)  # the short vendor's engagement ends exactly here


def _engagement(w: World) -> str:
    return f"/productions/{w.production['alpha']}/engagement"


def _get(w: World, who: str, **options):
    return w.call("GET", _engagement(w), who, **options)


def _declare(w: World, token: str):
    body = {"display_name": "shot-050.png", "declared_media_type": "image/png", "declared_size": 10, "declared_sha256": "a" * 64}
    return w.call("POST", f"/productions/{w.production['alpha']}/deliveries", token=token, json=body)


def _x1(w):
    token = w.token("alpha_vendor")
    assert w.revoke("alpha_coordinator", "alpha", "alpha_vendor").status == 200  # the clock is not moved: the very next request
    return _get(w, None, token=token).status == 403


def _x2(w):
    token = w.token("alpha_vendor")
    assert w.revoke("alpha_coordinator", "alpha", "alpha_vendor").status == 200
    before = w.rows("SELECT COUNT(*) AS n FROM deliveries")[0]["n"]
    return _declare(w, token).status == 403 and w.rows("SELECT COUNT(*) AS n FROM deliveries")[0]["n"] == before


def _at(w: World, moment) -> int:
    token = w.token("short_vendor")
    w.clock.set(moment)
    return _get(w, None, token=token).status


def _x5(w):
    other = w.token("bravo_vendor", claims={"productions": {w.production["alpha"]: "vendor"}})
    return _get(w, None, token=other).status == 403


def _x6(w):
    token = w.token("alpha_vendor", claims={"productions": {w.production["alpha"]: "coordinator"}})
    return w.call("POST", f"/productions/{w.production['alpha']}/engagements", token=token, json={}).status == 403


def _x7(w):
    delivery = w.delivered("alpha_vendor", "alpha", b"\x89PNG\r\n\x1a\n" + b"synthetic\n" * 20)
    assert w.revoke("alpha_coordinator", "alpha", "alpha_vendor").status == 200
    return w.seal("alpha_vendor", "alpha", delivery).status != 200 and w.delivery_row(delivery)["state"] == "UPLOADED"


def _x8(w):
    return w.call("GET", f"/productions/{w.production['bravo']}/engagement", "alpha_vendor").status == 403


def _claimless(w):
    return _get(w, None, token=w.token("alpha_vendor", claims={"productions": {}})).status == 200


def _tampered(damage):
    def holds(w):
        return _get(w, None, token=damage(w)).status == 401

    return holds


def _none_algorithm(w):
    payload = jwt.decode(w.token("alpha_vendor"), options={"verify_signature": False})
    return jwt.encode(payload, None, algorithm="none", headers={"kid": KID, "typ": "at+jwt"})


def _now(w) -> int:
    return int(w.clock.now().timestamp())


def _t7(w):
    reply = _get(w, "alpha_vendor", headers={"X-Authenticated-User": "coordinator-alpha-1"})
    return reply.status == 200 and reply.json()["role"] == "vendor"


ROWS = (
    Row("L1", "legitimate", "a vendor with an active engagement asks for its engagement", lambda w: _get(w, "alpha_vendor").status == 200, False),
    Row("L2", "legitimate", "a vendor with an active engagement declares a delivery", lambda w: _declare(w, w.token("alpha_vendor")).status == 201),
    Row("L3", "legitimate", "a coordinator asks for its engagement", lambda w: _get(w, "alpha_coordinator").status == 200, False),
    Row("L4", "legitimate", "authorisation does not depend on the token's claims: a token with none still works", _claimless, False),
    Row("L5", "legitimate", "the last instant of an engagement (one microsecond before its end) is served", lambda w: _at(w, ENDS - timedelta(microseconds=1)) == 200),
    Row("X1", "exploit", "the original exploit: the same token, the first request after the revocation", _x1),
    Row("X2", "exploit", "the same token declares a delivery after the revocation: refused, and no row is made", _x2),
    Row("X3", "boundary", "exactly at the end date (now = ends_at) the engagement is over", lambda w: _at(w, ENDS) == 403),
    Row("X4", "boundary", "one microsecond after the end date it is still over", lambda w: _at(w, ENDS + timedelta(microseconds=1)) == 403),
    Row("X5", "boundary", "a token whose claim names a production the subject has no engagement in grants nothing", _x5),
    Row("X6", "boundary", "a token whose claim names a higher role grants nothing: the role comes from the store", _x6),
    Row("X7", "boundary", "a delivery uploaded before the revocation cannot be sealed after it", _x7),
    Row("X8", "boundary", "an ALPHA vendor's valid token is refused on the BRAVO production", _x8, False),
    Row("T1", "boundary", "a token with the algorithm 'none' is a 401", _tampered(_none_algorithm), False),
    Row("T2", "boundary", "a token signed by another key is a 401", _tampered(lambda w: w.token("alpha_vendor", key=ec.generate_private_key(ec.SECP256R1()))), False),
    Row("T3", "boundary", "a token from another issuer is a 401", _tampered(lambda w: w.token("alpha_vendor", claims={"iss": "https://other.example"})), False),
    Row("T4", "boundary", "a token for another audience is a 401", _tampered(lambda w: w.token("alpha_vendor", claims={"aud": "https://other.example"})), False),
    Row("T5", "boundary", "an expired token is a 401", _tampered(lambda w: w.token("alpha_vendor", claims={"iat": _now(w) - 100, "nbf": _now(w) - 100, "exp": _now(w) - 1})), False),
    Row("T6", "boundary", "a token not yet valid (nbf in the future) is a 401", _tampered(lambda w: w.token("alpha_vendor", claims={"iat": _now(w) + 60, "nbf": _now(w) + 60, "exp": _now(w) + 360})), False),
    Row("T7", "boundary", "a valid vendor token with a coordinator's name in a header acts as the vendor", _t7, False),
)
assert ISSUER  # the T rows damage the claims of a token the world issued


def build() -> Matrix:
    jwt_only = seam("F-06", authz, "authorize_engagement", naive.jwt_validity_only)
    store_without_end = seam("F-06", authz, "authorize_engagement", naive.revocation_but_not_the_end_date)
    return Matrix(
        "F-06",
        "Authorisation snapshot in a long-lived token",
        ROWS,
        (
            Variant("R", "the reference"),
            Variant("V", "the seeded variant (labs/f06_stale_authorisation/vulnerable.py)", (SEAM,), frozenset({"L4", "X1", "X2", "X3", "X4", "X5", "X6"}), "authorises from the token's claim: revocation, the end date and the role all come from the past, and a token with no claim is refused"),
            Variant("N1", "naive fix: the token is checked again for validity; the claim is still believed", (jwt_only,), frozenset({"L4", "X1", "X2", "X3", "X4", "X5", "X6"}), "the same rows as the seeded variant: a valid signature and an unexpired token do not show that a granted engagement is still active"),
            Variant("N2", "naive fix: the store is read each request and revocation is checked, the end date is not", (store_without_end,), frozenset({"X3", "X4"}), "right on the first request after a revocation and wrong from the end date on: only the exact-boundary rows tell"),
        ),
    )
