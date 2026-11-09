"""F-02: object access checks the parent, not the child (M0 §5; CWE-639; ASVS 5.0.0 8.2.2, 8.4.1).

The same scenario runs against the reference application and against the application with only `assets.get_asset_in_scope`
replaced by the seeded twin. The attacker is a vendor engaged only in ALPHA; the target is an unreleased BRAVO asset; the
only thing the attacker does is ask for it through the ALPHA url. Synthetic data only, inside pytest's tmp_path.
"""

import pytest
from support.findings import variants

from content_boundary_lab import assets
from labs import f02_parent_check as f02
from labs.seam import applied, seam
from labs.world import BRAVO_ASSET

case = variants(f02)


def seeded(variant: str) -> bool:
    return variant == "vulnerable"


def test_the_exploit_succeeds_on_the_seeded_variant_and_is_blocked_by_the_reference(case):
    variant, facts, _ = case
    assert f02.scenario.exploited(facts) is seeded(variant)
    assert (facts["exploit_status"], facts["exploit_leaked"]) == ((200, True) if seeded(variant) else (404, False))


def test_the_reference_refuses_exactly_as_it_would_for_an_asset_that_does_not_exist(case):
    variant, facts, _ = case
    assert facts["missing_status"] == 404
    assert facts["indistinguishable_from_missing"] is not seeded(variant)  # the seeded variant answers, so it cannot be mistaken for it


def test_the_flaw_is_the_scope_of_the_object_and_nothing_else_the_rest_of_the_checks_still_hold(case):
    _, facts, _ = case
    assert facts["legit_status"] == 200 and facts["legit_intact"]  # a legitimate read works in both
    assert facts["bravo_url_status"] == 403  # the engagement on the url's production is still checked
    assert facts["anonymous_status"] == 401  # and so is the token


def test_a_caller_engaged_in_both_productions_still_cannot_reach_bravos_asset_through_the_alpha_url(case):
    variant, facts, _ = case
    assert (facts["dual_alpha_status"], facts["dual_alpha_leaked"]) == ((200, True) if seeded(variant) else (404, False))
    assert (facts["dual_bravo_status"], facts["dual_bravo_intact"]) == (200, True)  # through the BRAVO url it is theirs, in both


def test_a_coordinator_is_in_the_same_position_as_a_vendor(case):
    variant, facts, _ = case
    assert (facts["coordinator_status"], facts["coordinator_leaked"]) == ((200, True) if seeded(variant) else (404, False))


def test_the_audit_trail_shows_the_difference(case):
    variant, facts, _ = case
    assert facts["audit_production_is_alpha"] and facts["audit_object_is_bravo_asset"]
    if seeded(variant):  # a read of BRAVO's asset, recorded as an ordinary read in ALPHA
        assert (facts["audit_action"], facts["audit_reason"]) == ("asset.read", None)
    else:
        assert (facts["audit_action"], facts["audit_reason"]) == ("access.denied", "not_found_or_forbidden")
    assert facts["trusted_unchanged"]  # reading changes nothing in the trusted root


def test_a_naive_fix_that_checks_the_assets_own_production_but_not_the_url_still_binds_the_asset_to_the_wrong_production_for_a_caller_engaged_in_both(tmp_path):
    """The fix that asks only 'is the caller engaged where the asset lives?' repairs the vendor case and not this one."""
    from labs.world import World

    def naive(conn, caller, production_id, asset_id, now_micros):
        row = conn.execute(
            "SELECT a.id, a.production_id, a.display_name, a.created_at FROM assets AS a "
            "JOIN engagements AS e ON e.production_id = a.production_id JOIN subjects AS s ON s.id = e.subject_id "
            "WHERE a.id = ? AND s.issuer = ? AND s.subject = ? AND e.revoked_at IS NULL AND e.ends_at > ?",
            (asset_id, caller.issuer, caller.subject, now_micros),
        ).fetchone()  # engaged in the asset's real production: but the url's production is never compared with it
        return None if row is None else assets.Asset(*row)

    twin = seam("F-02", assets, "get_asset_in_scope", naive)
    world = World(tmp_path)
    with applied(twin):
        vendor_only_alpha = world.read_asset("alpha_vendor", "alpha", "bravo")
        engaged_in_both = world.read_asset("dual_vendor", "alpha", "bravo")
    assert vendor_only_alpha.status == 404  # the headline case is repaired
    assert (engaged_in_both.status, engaged_in_both.body) == (200, BRAVO_ASSET)  # the url/asset-owner relationship is not: a wrong
    # binding, and no disclosure beyond entitlement, because this caller is engaged in BRAVO as well
