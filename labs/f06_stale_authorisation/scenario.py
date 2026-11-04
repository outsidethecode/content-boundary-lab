"""F-06, the attacker's steps: a vendor whose engagement ends while its signed token is still good.

Nothing here is vulnerable. The token is signed by the stand-in identity provider, verifies the same way in both variants, and
carries a `productions` claim (the productions the vendor was engaged in when it was issued). Between the first request and
the second the coordinator revokes the engagement (and, in a second case, the engagement reaches its end date).

The resources used are the two that only the engagement decision guards: the vendor's own engagement, and the declaration of a
new delivery. The asset route is deliberately not the measure: its lookup re-checks the engagement in the same SQL statement
(the F-02 control), so it stays closed after a revocation in both variants, which the scenario records.
"""

from content_boundary_lab import identity
from labs.demo import Observed
from labs.world import CLEAN, World, digest


def _declare(world: World, token: str):
    body = {"display_name": "shot-040.png", "declared_media_type": "image/png", "declared_size": len(CLEAN), "declared_sha256": digest(CLEAN)}
    return world.call("POST", f"/productions/{world.production['alpha']}/deliveries", token=token, json=body)


def _deliveries(world: World) -> int:
    return world.rows("SELECT COUNT(*) AS n FROM deliveries")[0]["n"]


def run(world: World) -> Observed:
    o = Observed()
    alpha = world.production["alpha"]
    engagement = f"/productions/{alpha}/engagement"

    token = world.token("alpha_vendor")
    mine = world.call("GET", engagement, token=token)
    first = _declare(world, token)
    o.step("a vendor with an active ALPHA engagement asks for its engagement and declares a delivery, with its signed token", f"{mine.status} {mine.json().get('role')}; {first.status} declared")

    revoked = world.revoke("alpha_coordinator", "alpha", "alpha_vendor")
    o.step("the ALPHA coordinator revokes that vendor's engagement", f"{revoked.status} {revoked.json().get('status')}")

    verified = identity.authenticate(f"Bearer {token}", world.settings, world.clock)
    o.step("the SAME token still verifies, as the same subject", f"signature, issuer, audience and times are good for {verified.subject}")
    before = _deliveries(world)
    again = world.call("GET", engagement, token=token)  # THE EXPLOIT: the very same token, after the revocation
    event = world.audit()[-1]
    declared = _declare(world, token)
    o.step("the vendor asks for its engagement with that token", f"{again.status} {again.json().get('role', again.json().get('detail'))}")
    o.step("what the audit trail recorded for that request", f"{event['action']} {event['outcome']}{' (' + event['reason'] + ')' if event['reason'] else ''}, by {event['actor_subject']}")
    o.step("the vendor declares another delivery with that token", f"{declared.status}; deliveries created after the revocation: {_deliveries(world) - before}")
    asset = world.read_asset(None, "alpha", "alpha", token=token)
    o.step("it asks for an ALPHA asset (the asset lookup re-checks the engagement itself: the F-02 control)", f"{asset.status}, never the bytes")

    short = world.token("short_vendor")
    before_end = world.call("GET", engagement, token=short)
    world.clock.advance(301)  # the engagement was to end five minutes in; the token is good for ten
    after_end = world.call("GET", engagement, token=short)
    end_event = world.audit()[-1]
    o.step("a vendor whose engagement ends in five minutes asks for it, then asks again 301 seconds later (past the end date, inside the token's life)", f"{before_end.status}, then {after_end.status}")

    claimed = world.token("bravo_vendor", claims={"productions": {alpha: "vendor"}})  # the claim names ALPHA; the engagement is BRAVO only
    over = world.call("GET", engagement, token=claimed)
    o.step("a BRAVO-only vendor presents a token whose claim names ALPHA, and asks for its ALPHA engagement", f"{over.status} {over.json().get('role', over.json().get('detail'))}")

    o.facts |= {
        "mine_status": mine.status,
        "first_declared_status": first.status,
        "revoke_status": revoked.status,
        "token_still_verifies": verified.subject == world.subject("alpha_vendor"),
        "after_revoke_engagement_status": again.status,
        "after_revoke_declare_status": declared.status,
        "deliveries_created_after_revocation": _deliveries(world) - before,
        "asset_after_revoke_status": asset.status,
        "audit_action": event["action"],
        "audit_reason": event["reason"],
        "audit_actor": event["actor_subject"],
        "before_end_status": before_end.status,
        "after_end_status": after_end.status,
        "after_end_reason": end_event["reason"],
        "claim_status": over.status,
    }
    return o


def exploited(facts: dict) -> bool:
    """The violation: requests that began after the revocation were served from the token's snapshot."""
    return facts["after_revoke_engagement_status"] == 200 and facts["after_revoke_declare_status"] == 201
