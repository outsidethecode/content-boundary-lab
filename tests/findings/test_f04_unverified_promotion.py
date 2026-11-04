"""F-04: promotion trusts a mutable reference, not the accepted bytes (M0 §5.4; CWE-367; ASVS 5.0.0 15.4.2, 2.3.1, 2.3.3).

The same scenario runs against the reference application and against the application with only `promotion.copy_verified`
replaced by the seeded twin, which copies without comparing what it wrote with the accepted digest. A delivery is accepted
bound to H1; the quarantined object is then replaced by different bytes of the same length (an ASSUMED capability: the lab
does not show that any real deployment lets something write quarantine after the seal); the promotion job runs.
Synthetic data only, inside pytest's tmp_path.
"""

from support.findings import variants

from labs import f04_unverified_promotion as f04

case = variants(f04)


def seeded(variant: str) -> bool:
    return variant == "vulnerable"


def test_the_exploit_succeeds_on_the_seeded_variant_and_is_blocked_by_the_reference(case):
    variant, facts, _ = case
    assert f04.scenario.exploited(facts) is seeded(variant)
    assert facts["promotion_state"] == ("PROMOTED" if seeded(variant) else "INTEGRITY_FAILED")


def test_the_trusted_store_receives_the_substituted_bytes_only_in_the_seeded_variant(case):
    variant, facts, _ = case
    assert facts["length_unchanged"]  # the swap is the same length, so a size check alone could not see it
    assert facts["asset_created"] is seeded(variant)
    assert (facts["new_trusted_files"] != []) is seeded(variant)
    assert facts["trusted_is_substituted"] is seeded(variant)
    assert facts["trusted_contains_marker"] is seeded(variant)
    assert facts["trusted_digest_is_accepted"] is False  # in neither variant are the accepted bytes what is published


def test_the_record_still_says_the_accepted_digest_while_the_bytes_are_not_those_in_the_seeded_variant(case):
    variant, facts, world = case
    assert facts["accepted_digest_is_h1"]  # the acceptance is untouched in both
    assert facts["asset_record_digest_is_accepted"] is seeded(variant)  # the lie: an asset row for H1 that holds H2
    assert facts["download_is_substituted"] is seeded(variant)
    assert facts["delivery_state"] == ("PROMOTED" if seeded(variant) else "INTEGRITY_FAILED")


def test_the_audit_trail_attributes_the_outcome_to_the_promotion_job_in_both(case):
    variant, facts, world = case
    last = "delivery.promoted" if seeded(variant) else "delivery.integrity_failed"
    assert facts["events"][-1] == last
    actors = {(e["actor_issuer"], e["actor_subject"]) for e in world.audit() if e["action"] == last}
    assert actors == {("system:content-boundary-lab", "promote")}


def test_baseline_the_api_refuses_a_write_after_the_seal_in_both_variants(case):
    """F-04 does not claim the API allows writes after the seal; the fix does not rest on this check alone."""
    _, facts, _ = case
    assert facts["late_write_status"] == 409
    assert facts["sealed_state"] == "SCAN_PASSED" and facts["accepted_state"] == "ACCEPTED"


def test_no_staging_file_is_left_behind_by_either_variant(case):
    _, _, world = case
    assert not [name for name in world.trusted_files() if name.startswith(".staging/")]
