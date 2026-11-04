"""F-06: authorisation snapshot in a long-lived token (M0 §5; CWE-863; ASVS 5.0.0 8.3.2, 7.4.2, 9.2.1).

The same scenario runs against the reference application and against the application with only
`authz.authorize_engagement` replaced by the seeded twin, which authorises from the `productions` claim of the token. In both
the token is signed by the same key and verifies the same way; what differs is what the application does about the
engagement the coordinator revoked, or that has ended, while the token is still good. Synthetic data only.
"""

from support.findings import variants

from labs import f06_stale_authorisation as f06
from labs.seam import applied
from labs.world import World

case = variants(f06)


def seeded(variant: str) -> bool:
    return variant == "vulnerable"


def test_the_exploit_succeeds_on_the_seeded_variant_and_is_blocked_by_the_reference(case):
    variant, facts, _ = case
    assert f06.scenario.exploited(facts) is seeded(variant)
    assert facts["after_revoke_engagement_status"] == (200 if seeded(variant) else 403)


def test_before_the_revocation_both_variants_serve_the_vendor_and_the_revocation_itself_succeeds(case):
    _, facts, _ = case
    assert (facts["mine_status"], facts["first_declared_status"], facts["revoke_status"]) == (200, 201, 200)


def test_the_token_is_valid_on_both_sides_so_the_difference_is_authorisation_not_authentication(case):
    variant, facts, _ = case
    assert facts["token_still_verifies"]  # the reference's own verifier accepts it after the revocation
    assert facts["after_revoke_engagement_status"] != 401 and facts["after_revoke_declare_status"] != 401
    assert facts["audit_actor"] == "vendor-alpha-1"  # the request was attributed to the verified subject in both
    if seeded(variant):
        assert (facts["audit_action"], facts["audit_reason"]) == ("engagement.viewed", None)  # an ordinary view, by a revoked vendor
    else:
        assert (facts["audit_action"], facts["audit_reason"]) == ("access.denied", "engagement_revoked")


def test_the_state_changes_a_revoked_vendor_can_make_follow_the_same_decision(case):
    variant, facts, world = case
    assert facts["after_revoke_declare_status"] == (201 if seeded(variant) else 403)
    assert facts["deliveries_created_after_revocation"] == (1 if seeded(variant) else 0)


def test_the_asset_route_stays_closed_in_both_because_its_lookup_rechecks_the_engagement(case):
    """Defence in depth that is not F-06's: the seeded decision alone does not reach the asset bytes, and it is not made to."""
    variant, facts, _ = case
    assert facts["asset_after_revoke_status"] == (404 if seeded(variant) else 403)  # refused by the lookup, or earlier by the decision


def test_an_engagement_that_has_ended_is_honoured_by_the_reference_and_ignored_by_the_seeded_variant(case):
    variant, facts, _ = case
    assert facts["before_end_status"] == 200  # inside the engagement, both serve
    assert facts["after_end_status"] == (200 if seeded(variant) else 403)  # 301 seconds on: past the end date, inside the token's life
    if not seeded(variant):
        assert facts["after_end_reason"] == "engagement_expired"


def test_a_token_that_claims_a_production_it_has_no_engagement_in_grants_nothing_in_the_reference(case):
    variant, facts, _ = case
    assert facts["claim_status"] == (200 if seeded(variant) else 403)


def test_the_window_is_the_life_of_the_token_and_no_longer(tmp_path):
    """The seeded twin is stale only while the token is good: after it expires the request is a 401, seeded or not."""
    world = World(tmp_path)
    token = world.token("alpha_vendor")
    assert world.revoke("alpha_coordinator", "alpha", "alpha_vendor").status == 200
    path = f"/productions/{world.production['alpha']}/engagement"
    with applied(f06.SEAM):
        assert world.call("GET", path, token=token).status == 200
        world.clock.advance(601)  # the reference caps a token at ten minutes
        assert world.call("GET", path, token=token).status == 401
