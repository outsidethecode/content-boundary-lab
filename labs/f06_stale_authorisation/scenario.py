"""F-06, the attacker's steps: a vendor whose engagement ends while its signed token is still good.

Nothing here is vulnerable. The token is signed by the stand-in identity provider, verifies the same way in both variants, and
carries a `productions` claim (the productions the vendor was engaged in when it was issued). Between the first request and
the second the coordinator revokes the engagement (and, in a second case, the engagement reaches its end date).

The resources used are the two that only the engagement decision guards: the vendor's own engagement, and the declaration of a
new delivery. The asset route is deliberately not the measure: its lookup re-checks the engagement in the same SQL statement
(the F-02 control), so it stays closed after a revocation in both variants, which the scenario records.
"""

from datetime import timedelta

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

    coordinator = _coordinator_path(world, o)

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
    } | coordinator
    return o


def _coordinator_path(world: World, o: Observed) -> dict:
    """The same flaw for a coordinator, whose decisions create authority: what the short window leaves behind outlives it.

    A coordinator's engagement is revoked (the lab has no studio-administrator actor, so the coordinator revokes itself, which
    the reference allows: the mechanism is the same when another coordinator does it). Its token is still good. Used once with
    the seeded function in force, the token makes an engagement for another subject, a database row that the reference
    honours like any other. Then the reference is put back (`labs.seam.restored`), the token expires, and the new subject
    asks for what it was given. The window is at most ten minutes; the grant is up to ninety days.
    """
    from content_boundary_lab import authz
    from labs.f06_stale_authorisation import SEAM
    from labs.seam import restored

    alpha, route = world.production["alpha"], f"/productions/{world.production['alpha']}/engagements"
    own = f"/productions/{alpha}/engagement"
    token = world.token("alpha_coordinator")  # issued while the coordinator is engaged: it will carry the claim of that moment
    revoked = world.revoke("alpha_coordinator", "alpha", "alpha_coordinator")
    o.step("the ALPHA coordinator's own engagement is revoked, while a token it was issued a moment ago is still good", f"{revoked.status} {revoked.json().get('status')}")

    world.clock.advance(60)
    ends_at = (world.clock.now() + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
    accomplice = world.subject("bravo_vendor")  # a subject the identity provider already knows, engaged in BRAVO only
    created = world.call("POST", route, token=token, json={"subject": accomplice, "role": "coordinator", "ends_at": ends_at})  # THE EXPLOIT
    event = world.audit()[-1]
    rows = world.rows(
        "SELECT e.role, e.ends_at - e.created_at AS lifetime FROM engagements AS e JOIN subjects AS s ON s.id = e.subject_id "
        "WHERE s.subject = ? AND e.production_id = ?",
        accomplice,
        alpha,
    )
    o.step("the revoked coordinator, with that same token, makes a 90-day ALPHA coordinator engagement for another subject", f"{created.status}; engagements now held by that subject in ALPHA: {len(rows)}")
    o.step("what the audit trail recorded for that request", f"{event['action']} {event['outcome']}{' (' + event['reason'] + ')' if event['reason'] else ''}, by {event['actor_subject']}")

    with restored(SEAM):  # from here the application is the reference, in both runs
        reference_in_force = authz.authorize_engagement is SEAM.reference
        after_restore = world.call("GET", own, token=token)
        o.step("the reference is back in force; the revoked coordinator's token, still good, asks for its engagement", f"{after_restore.status} {after_restore.json().get('detail', after_restore.json().get('role'))}")
        world.clock.advance(601)  # past the end of any token the reference accepts: the window is over
        after_expiry = world.call("GET", own, token=token)
        o.step("ten minutes later the same token is used again", f"{after_expiry.status}: the token has expired, so any window it gave is over")
        later = world.call("GET", own, "bravo_vendor")  # a fresh token for the other subject: its own claims name BRAVO only
        o.step("the other subject, with a fresh token, asks for its ALPHA engagement (the reference decides, from the database)", f"{later.status} {later.json().get('role', later.json().get('detail'))}")
        asset = world.read_asset("bravo_vendor", "alpha", "alpha")
        o.step("it asks for ALPHA's unreleased asset", f"{asset.status}, {len(asset.body)} bytes" if asset.status == 200 else f"{asset.status}, never the bytes")

    return {
        "coordinator_revoke_status": revoked.status,
        "coordinator_enrol_status": created.status,
        "coordinator_enrolled_rows": len(rows),
        "coordinator_enrol_actor": event["actor_subject"],
        "coordinator_enrol_audit": (event["action"], event["outcome"], event["reason"]),
        "coordinator_token_after_restore": after_restore.status,
        "coordinator_token_after_expiry": after_expiry.status,
        "follow_up_authoriser_was_reference": reference_in_force,
        "accomplice_engagement_status": later.status,
        "accomplice_role": later.json().get("role"),
        "accomplice_grant_days": rows[0]["lifetime"] // 86_400_000_000 if rows else None,
        "accomplice_asset_status": asset.status,
        "accomplice_asset_bytes": len(asset.body) if asset.status == 200 else 0,
    }


def exploited(facts: dict) -> bool:
    """The violation: requests that began after the revocation were served from the token's snapshot."""
    return facts["after_revoke_engagement_status"] == 200 and facts["after_revoke_declare_status"] == 201


def outlived_the_window(facts: dict) -> bool:
    """The consequence for a coordinator: an engagement made inside the window is honoured after the window and after the fix."""
    return facts["coordinator_enrol_status"] == 201 and facts["accomplice_engagement_status"] == 200 and facts["coordinator_token_after_expiry"] == 401
