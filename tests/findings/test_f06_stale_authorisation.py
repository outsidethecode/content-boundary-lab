"""F-06: authorisation snapshot in a long-lived token (M0 §5; CWE-863; ASVS 5.0.0 8.3.2, 7.4.2, 9.2.1).

The same scenario runs against the reference application and against the application with only
`authz.authorize_engagement` replaced by the seeded twin, which authorises from the `productions` claim of the token. In both
the token is signed by the same key and verifies the same way; what differs is what the application does about the
engagement the coordinator revoked, or that has ended, while the token is still good. Synthetic data only.
"""

import pytest
from support.findings import variants

from labs import f06_stale_authorisation as f06
from labs.seam import applied, restored
from labs.world import ALPHA_ASSET, World

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


# --- the coordinator path (IR-11): the window is short, what is made in it is not ---------------------------------------------


def test_a_revoked_coordinator_whose_token_is_still_good_can_enrol_another_subject_only_in_the_seeded_variant(case):
    variant, facts, _ = case
    assert facts["coordinator_revoke_status"] == 200  # the revocation itself succeeded, in both
    assert facts["coordinator_enrol_status"] == (201 if seeded(variant) else 403)
    assert facts["coordinator_enrolled_rows"] == (1 if seeded(variant) else 0)
    assert f06.scenario.outlived_the_window(facts) is seeded(variant)


def test_the_enrolment_is_attributed_to_the_revoked_coordinator_and_looks_like_any_other_creation_in_the_seeded_variant(case):
    variant, facts, _ = case
    assert facts["coordinator_enrol_actor"] == "coordinator-alpha-1"  # the verified subject, in both
    expected = ("engagement.created", "allowed", None) if seeded(variant) else ("access.denied", "denied", "engagement_revoked")
    assert facts["coordinator_enrol_audit"] == expected


def test_with_the_normal_authoriser_back_the_same_token_is_refused_while_it_is_good_and_a_401_after(case):
    """Both variants, and the same: the window was the seeded decision, not the token. The token itself was never the problem."""
    _, facts, _ = case
    assert facts["coordinator_token_after_restore"] == 403
    assert facts["coordinator_token_after_expiry"] == 401


def test_the_enrolled_subject_keeps_legitimate_database_backed_access_after_the_window_and_after_the_fix(case):
    variant, facts, world = case
    if seeded(variant):
        assert (facts["accomplice_engagement_status"], facts["accomplice_role"]) == (200, "coordinator")
        assert facts["accomplice_grant_days"] == 90  # the cap: ninety days from a request made in a window of at most ten minutes
        assert facts["accomplice_asset_status"] == 200 and facts["accomplice_asset_bytes"] == len(ALPHA_ASSET)
    else:
        assert facts["accomplice_engagement_status"] == 403 and facts["accomplice_role"] is None
        assert facts["accomplice_asset_status"] == 403
    rows = world.rows("SELECT e.role, e.revoked_at FROM engagements AS e JOIN subjects AS s ON s.id = e.subject_id "
                      "WHERE s.subject = ? AND e.production_id = ?", world.subject("bravo_vendor"), world.production["alpha"])
    assert rows == ([{"role": "coordinator", "revoked_at": None}] if seeded(variant) else [])  # an ordinary row, revoked by no one


def test_the_enrolled_subject_is_judged_by_the_reference_alone_and_the_seeded_function_is_not_needed_again(case):
    """The follow-up requests ran with the reference back in force (labs.seam.restored): the grant stands on its own."""
    variant, facts, _ = case
    assert facts["follow_up_authoriser_was_reference"] is True


def test_the_seam_is_the_same_single_function_in_the_coordinator_scenario():
    assert f06.SEAM.where == "content_boundary_lab.authz.authorize_engagement"  # no second seam and no changed reference function


def test_restoring_the_reference_inside_a_block_puts_back_whatever_was_in_force_and_never_installs_a_twin():
    reference, twin = f06.SEAM.reference, f06.SEAM.vulnerable
    assert getattr(f06.SEAM.module, f06.SEAM.name) is reference
    with restored(f06.SEAM):  # nothing applied: nothing to put back, and the reference stays
        assert getattr(f06.SEAM.module, f06.SEAM.name) is reference
    with applied(f06.SEAM):
        assert getattr(f06.SEAM.module, f06.SEAM.name) is twin
        with restored(f06.SEAM):
            assert getattr(f06.SEAM.module, f06.SEAM.name) is reference
        assert getattr(f06.SEAM.module, f06.SEAM.name) is twin  # the exploit's function is back in force
    assert getattr(f06.SEAM.module, f06.SEAM.name) is reference


def test_restoring_the_reference_is_undone_even_when_the_block_fails():
    with applied(f06.SEAM):
        with pytest.raises(RuntimeError):
            with restored(f06.SEAM):
                raise RuntimeError("fault")
        assert getattr(f06.SEAM.module, f06.SEAM.name) is f06.SEAM.vulnerable
    assert getattr(f06.SEAM.module, f06.SEAM.name) is f06.SEAM.reference


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
